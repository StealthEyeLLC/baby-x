import { createPublicKey, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../../core.ts';
import { RootTrustError } from './errors.ts';
import {
  verifyConsistencyProof,
  verifyInclusionProof,
  verifySigstoreBundle,
  verifySignedCheckpoint,
  verifySlsaProvenance,
} from './crypto.ts';
import { OciSkillResolver, type ResolvedOciBundle } from './oci.ts';
import { trustProviders } from './providers.ts';
import {
  ROOT_TRUST_PROVIDER_VERSION,
  ROOT_TRUST_SCHEMA_VERSION,
  manifestHex,
  normalizeBundleCache,
  normalizeBundleResolve,
  normalizeBundleVerify,
  normalizeProvenanceVerify,
  normalizeTransparencyStatus,
  normalizeTransparencyVerify,
  trustRequestDigest,
} from './schemas.ts';
import {
  RootTrustStore,
  sealTrustRecord,
  type BundleRecord,
  type ProvenanceVerificationRecord,
  type SignatureVerificationRecord,
  type TransparencyMonitorRecord,
} from './store.ts';

interface RootTrustServiceOptions {
  stateRoot: string;
  now?: () => string;
}

const IDEMPOTENCY = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;

function fail(code: string, message: string, details: JsonObject = {}): never { throw new RootTrustError(code, message, details); }
function owner(context: RuntimeExecutionContext): string {
  if (context.authorityClass !== undefined && context.authorityClass !== 'unrestricted-owner') fail('root_trust_authority_denied', 'unrestricted-owner authority is required');
  const principal = context.subject ?? 'stealtheye-owner';
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(principal)) fail('root_trust_invalid_request', 'owner principal is invalid');
  return principal;
}
function idempotency(context: RuntimeExecutionContext): string {
  const key = context.idempotencyKey;
  if (typeof key !== 'string' || !IDEMPOTENCY.test(key)) fail('root_trust_idempotency_required', 'a bounded idempotency key is required');
  return sha256(key);
}
function newId(prefix: string): string { return `${prefix}_${randomUUID().replaceAll('-', '')}`; }
function keyDigest(publicKeyPem: string): string { return sha256(createPublicKey(publicKeyPem).export({ format: 'der', type: 'spki' }) as Buffer); }
function ensureOwner(recordOwner: string, principal: string): void { if (recordOwner !== principal) fail('root_trust_owner_conflict', 'record belongs to another owner'); }

function publicBundle(record: BundleRecord): JsonObject {
  return {
    schemaVersion: record.schemaVersion,
    providerVersion: record.providerVersion,
    bundleId: record.bundleId,
    ownerPrincipal: record.ownerPrincipal,
    sourceKind: record.sourceKind,
    registry: record.registry,
    repository: record.repository,
    discoveryReferenceDigest: record.discoveryReferenceDigest,
    manifestDigest: record.manifestDigest,
    manifestMediaType: record.manifestMediaType,
    configDigest: record.configDigest,
    configMediaType: record.configMediaType,
    layerDigests: record.layerDigests,
    layerMediaTypes: record.layerMediaTypes,
    size: record.size,
    contentVerified: record.contentVerified,
    executionEligible: record.executionEligible,
    cacheState: record.cacheState,
    cachePathDigest: record.cachePathDigest,
    cacheDigest: record.cacheDigest,
    signatureState: record.signatureState,
    signatureVerificationId: record.signatureVerificationId,
    provenanceState: record.provenanceState,
    provenanceVerificationId: record.provenanceVerificationId,
    sequence: record.sequence,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    recordDigest: record.recordDigest,
    mutableTagExecutionAllowed: false,
  };
}
function publicTransparency(record: TransparencyMonitorRecord): JsonObject {
  return {
    schemaVersion: record.schemaVersion,
    providerVersion: record.providerVersion,
    transparencyRecordId: record.transparencyRecordId,
    logId: record.logId,
    state: record.state,
    treeSize: record.treeSize,
    rootHash: record.rootHash,
    checkpointDigest: record.checkpointDigest,
    signerKeyId: record.signerKeyId,
    checkpointIssuedAt: record.checkpointIssuedAt,
    lastVerifiedAt: record.lastVerifiedAt,
    maximumCheckpointAgeSeconds: record.maximumCheckpointAgeSeconds,
    entryDigests: record.entryDigests,
    criticalConflict: record.criticalConflict,
    conflictDigest: record.conflictDigest,
    sequence: record.sequence,
    recordDigest: record.recordDigest,
    publicMonitorEnabled: false,
  };
}

export class RootTrustService {
  private readonly store: RootTrustStore;
  private readonly resolver: OciSkillResolver;
  private readonly cacheRoot: string;
  private readonly now: () => string;

  constructor(private readonly options: RootTrustServiceOptions) {
    this.store = new RootTrustStore(options.stateRoot);
    this.cacheRoot = join(options.stateRoot, 'root-platform', 'trust', 'cache', 'sha256');
    this.resolver = new OciSkillResolver(this.cacheRoot);
    this.now = options.now ?? (() => new Date().toISOString());
    this.reconcile();
  }

  describe(): JsonObject {
    return {
      schemaVersion: ROOT_TRUST_SCHEMA_VERSION,
      providerVersion: ROOT_TRUST_PROVIDER_VERSION,
      providers: trustProviders().map((provider) => ({ ...provider.definition, ...provider.probe() })),
      executionIdentity: 'exact-oci-manifest-digest',
      mutableTags: 'discovery-only',
      publicKeylessInfrastructureRequired: false,
      proofAuthority: 'existing-baby-x-proof-authority',
    };
  }

  bundleResolve(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = normalizeBundleResolve(payloadValue);
    const principal = owner(context);
    const idem = idempotency(context);
    const digestOfRequest = trustRequestDigest('babyx.root.bundle.resolve', principal, payload as unknown as JsonObject);
    const resolved = this.resolver.resolve(payload);
    const existing = this.store.findBundleByManifest(resolved.manifestDigest);
    if (existing !== undefined) {
      ensureOwner(existing.ownerPrincipal, principal);
      let durable = existing;
      if (resolved.executionEligible && !existing.executionEligible) {
        durable = this.store.putBundle({
          ...existing,
          sourceKind: resolved.sourceKind,
          registry: resolved.registry,
          repository: resolved.repository,
          sourceReference: resolved.resolvedReference,
          sourceLayoutPath: resolved.layoutPath,
          contentVerified: resolved.contentVerified,
          executionEligible: true,
          sequence: existing.sequence + 1,
          updatedAt: this.now(),
        });
      }
      const claimed = this.store.createBundle(`bundle:${principal}:${idem}`, digestOfRequest, durable);
      return { bundle: publicBundle(claimed.record), replayed: true, discoveredByMutableTag: !resolved.executionEligible };
    }
    const createdAt = this.now();
    const candidate = sealTrustRecord<BundleRecord>({
      schemaVersion: ROOT_TRUST_SCHEMA_VERSION,
      providerVersion: ROOT_TRUST_PROVIDER_VERSION,
      bundleId: newId('bnd'),
      ownerPrincipal: principal,
      creationRequestDigest: digestOfRequest,
      sequence: 1,
      createdAt,
      updatedAt: createdAt,
      sourceKind: resolved.sourceKind,
      registry: resolved.registry,
      repository: resolved.repository,
      discoveryReferenceDigest: resolved.discoveryReferenceDigest,
      sourceReference: resolved.resolvedReference,
      sourceLayoutPath: resolved.layoutPath,
      manifestDigest: resolved.manifestDigest,
      manifestMediaType: resolved.manifestMediaType,
      configDigest: resolved.configDigest,
      configMediaType: resolved.configMediaType,
      layerDigests: resolved.layerDigests,
      layerMediaTypes: resolved.layerMediaTypes,
      size: resolved.size,
      contentVerified: resolved.contentVerified,
      executionEligible: resolved.executionEligible,
      cacheState: 'UNCACHED',
      cachePathDigest: null,
      cacheDigest: null,
      signatureState: 'UNVERIFIED',
      signatureVerificationId: null,
      provenanceState: 'UNVERIFIED',
      provenanceVerificationId: null,
    });
    const created = this.store.createBundle(`bundle:${principal}:${idem}`, digestOfRequest, candidate);
    return { bundle: publicBundle(created.record), replayed: created.replayed, discoveredByMutableTag: !resolved.executionEligible };
  }

  bundleVerify(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = normalizeBundleVerify(payloadValue);
    const principal = owner(context);
    const idem = idempotency(context);
    const digestOfRequest = trustRequestDigest('babyx.root.bundle.verify', principal, payload as unknown as JsonObject);
    let bundle = this.store.getBundle(payload.bundleId);
    ensureOwner(bundle.ownerPrincipal, principal);
    if (!bundle.executionEligible) fail('root_bundle_mutable_reference_rejected', 'mutable-tag discovery cannot be verified as execution identity');
    try {
      const result = verifySigstoreBundle(bundle.manifestDigest, payload.signatureBundle, payload.trustPolicy, Date.parse(this.now()));
      if (payload.trustPolicy.requireTransparency) {
        for (const entry of payload.signatureBundle.verificationMaterial.tlogEntries) {
          const monitor = this.store.findTransparencyByLog(entry.logId);
          if (monitor === undefined || monitor.state !== 'VERIFIED' || monitor.criticalConflict || monitor.checkpointDigest !== entry.checkpointDigest || !monitor.entryDigests.includes(entry.entryDigest)) {
            fail('root_bundle_transparency_unverified', 'signature transparency entry is not backed by a current verified monitor record', { logId: entry.logId, entryDigest: entry.entryDigest });
          }
        }
      }
      const verifiedAt = this.now();
      const candidate = sealTrustRecord<SignatureVerificationRecord>({
        schemaVersion: ROOT_TRUST_SCHEMA_VERSION,
        providerVersion: ROOT_TRUST_PROVIDER_VERSION,
        signatureVerificationId: newId('sig'),
        ownerPrincipal: principal,
        creationRequestDigest: digestOfRequest,
        sequence: 1,
        createdAt: verifiedAt,
        updatedAt: verifiedAt,
        bundleId: bundle.bundleId,
        manifestDigest: bundle.manifestDigest,
        state: 'VERIFIED',
        verificationKind: result.verificationKind,
        signerDigest: result.signerDigest,
        signatureBundleDigest: result.signatureBundleDigest,
        trustPolicyDigest: sha256(canonicalize(payload.trustPolicy)),
        transparencyEntryDigests: result.transparencyEntryDigests,
        verifiedAt,
      });
      const created = this.store.createSignature(`signature:${principal}:${idem}`, digestOfRequest, candidate);
      bundle = this.store.putBundle({ ...bundle, signatureState: 'VERIFIED', signatureVerificationId: created.record.signatureVerificationId, sequence: bundle.sequence + 1, updatedAt: verifiedAt });
      return { bundle: publicBundle(bundle), signatureVerification: created.record, replayed: created.replayed };
    } catch (error) {
      if (error instanceof RootTrustError && bundle.signatureState !== 'FAILED') this.store.putBundle({ ...bundle, signatureState: 'FAILED', sequence: bundle.sequence + 1, updatedAt: this.now() });
      throw error;
    }
  }

  bundleCache(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = normalizeBundleCache(payloadValue);
    const principal = owner(context);
    idempotency(context);
    let bundle = this.store.getBundle(payload.bundleId);
    ensureOwner(bundle.ownerPrincipal, principal);
    if (bundle.cacheState === 'CACHED') return { bundle: publicBundle(bundle), replayed: true };
    if (!bundle.executionEligible) fail('root_bundle_mutable_reference_rejected', 'mutable-tag discovery cannot be cached as execution identity');
    try {
      const resolved = this.resolver.resolve({ reference: bundle.sourceReference, expectedManifestDigest: bundle.manifestDigest, discoveryOnly: false });
      this.assertResolvedMatches(bundle, resolved);
      const cached = this.resolver.cache(resolved);
      bundle = this.store.putBundle({
        ...bundle,
        contentVerified: true,
        cacheState: 'CACHED',
        cachePathDigest: sha256(cached.cachePath),
        cacheDigest: cached.cacheDigest,
        sequence: bundle.sequence + 1,
        updatedAt: this.now(),
      });
      return { bundle: publicBundle(bundle), replayed: false };
    } catch (error) {
      this.store.putBundle({ ...bundle, cacheState: 'CACHE_FAILED', sequence: bundle.sequence + 1, updatedAt: this.now() });
      throw error;
    }
  }

  provenanceVerify(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = normalizeProvenanceVerify(payloadValue);
    const principal = owner(context);
    const idem = idempotency(context);
    const digestOfRequest = trustRequestDigest('babyx.root.provenance.verify', principal, payload as unknown as JsonObject);
    let bundle = this.store.getBundle(payload.bundleId);
    ensureOwner(bundle.ownerPrincipal, principal);
    if (!bundle.executionEligible) fail('root_bundle_mutable_reference_rejected', 'mutable-tag discovery cannot receive trusted provenance');
    if (!payload.expected.products.some((entry) => entry.digest === manifestHex(bundle.manifestDigest))) fail('root_provenance_product_mismatch', 'expected products do not bind the exact OCI manifest digest');
    try {
      const result = verifySlsaProvenance(payload.envelope, payload.verificationKeyPem, payload.expected);
      const verifiedAt = this.now();
      const candidate = sealTrustRecord<ProvenanceVerificationRecord>({
        schemaVersion: ROOT_TRUST_SCHEMA_VERSION,
        providerVersion: ROOT_TRUST_PROVIDER_VERSION,
        provenanceVerificationId: newId('prv'),
        ownerPrincipal: principal,
        creationRequestDigest: digestOfRequest,
        sequence: 1,
        createdAt: verifiedAt,
        updatedAt: verifiedAt,
        bundleId: bundle.bundleId,
        manifestDigest: bundle.manifestDigest,
        state: 'VERIFIED',
        envelopeDigest: result.envelopeDigest,
        statementDigest: result.statementDigest,
        signerDigest: result.signerDigest,
        predicateType: result.predicateType,
        expectationDigest: sha256(canonicalize(payload.expected)),
        verifiedAt,
      });
      const created = this.store.createProvenance(`provenance:${principal}:${idem}`, digestOfRequest, candidate);
      bundle = this.store.putBundle({ ...bundle, provenanceState: 'VERIFIED', provenanceVerificationId: created.record.provenanceVerificationId, sequence: bundle.sequence + 1, updatedAt: verifiedAt });
      return { bundle: publicBundle(bundle), provenanceVerification: created.record, replayed: created.replayed };
    } catch (error) {
      if (error instanceof RootTrustError && bundle.provenanceState !== 'FAILED') this.store.putBundle({ ...bundle, provenanceState: 'FAILED', sequence: bundle.sequence + 1, updatedAt: this.now() });
      throw error;
    }
  }

  transparencyVerify(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = normalizeTransparencyVerify(payloadValue);
    const principal = owner(context);
    const idem = idempotency(context);
    const digestOfRequest = trustRequestDigest('babyx.root.transparency.verify', principal, payload as unknown as JsonObject);
    const verifiedAt = this.now();
    if (payload.checkpoint.signerKeyId !== keyDigest(payload.checkpointPublicKeyPem)) fail('root_transparency_signer_mismatch', 'checkpoint signerKeyId does not match the verification key');
    if (!verifySignedCheckpoint(payload.checkpoint, payload.checkpointPublicKeyPem)) fail('root_transparency_checkpoint_signature_invalid', 'signed transparency checkpoint verification failed');
    const ageSeconds = Math.floor((Date.parse(verifiedAt) - Date.parse(payload.checkpoint.issuedAt)) / 1_000);
    const checkpointDigest = sha256(canonicalize(payload.checkpoint));
    const prior = this.store.findTransparencyByLog(payload.logId);
    if (prior?.criticalConflict === true) {
      fail('root_transparency_conflict', 'transparency log has an unresolved critical conflict', { transparencyRecordId: prior.transparencyRecordId, conflictDigest: prior.conflictDigest });
    }
    if (ageSeconds < -5 || ageSeconds > payload.maximumCheckpointAgeSeconds) {
      const stale = this.persistTransparency(prior, principal, idem, digestOfRequest, payload, checkpointDigest, verifiedAt, 'STALE', false, null);
      throw new RootTrustError('root_transparency_checkpoint_stale', 'transparency checkpoint is outside the freshness window', { transparencyRecordId: stale.transparencyRecordId, ageSeconds });
    }
    if (!verifyInclusionProof(payload.entryDigest, payload.inclusionProof, payload.checkpoint.rootHash)) fail('root_transparency_inclusion_failure', 'transparency inclusion proof verification failed');
    if (prior !== undefined) {
      ensureOwner(prior.ownerPrincipal, principal);
      const regressed = payload.checkpoint.treeSize < prior.treeSize;
      const sameSizeConflict = payload.checkpoint.treeSize === prior.treeSize && payload.checkpoint.rootHash !== prior.rootHash;
      const missingOrInvalidConsistency = payload.checkpoint.treeSize > prior.treeSize
        && (payload.consistencyProof === null || !verifyConsistencyProof(prior.treeSize, payload.checkpoint.treeSize, prior.rootHash, payload.checkpoint.rootHash, payload.consistencyProof));
      if (regressed || sameSizeConflict || missingOrInvalidConsistency) {
        const conflictDigest = sha256(canonicalize({ prior: { treeSize: prior.treeSize, rootHash: prior.rootHash }, next: payload.checkpoint, consistencyProof: payload.consistencyProof }));
        const conflicted = this.store.putTransparency({ ...prior, state: 'CONFLICT', criticalConflict: true, conflictDigest, sequence: prior.sequence + 1, updatedAt: verifiedAt, lastVerifiedAt: verifiedAt });
        throw new RootTrustError(regressed || sameSizeConflict ? 'root_transparency_conflict' : 'root_transparency_consistency_failure', 'transparency monitor detected a critical checkpoint conflict', { transparencyRecordId: conflicted.transparencyRecordId, conflictDigest });
      }
    }
    const record = this.persistTransparency(prior, principal, idem, digestOfRequest, payload, checkpointDigest, verifiedAt, 'VERIFIED', false, null);
    return { transparency: publicTransparency(record), replayed: prior !== undefined && prior.checkpointDigest === checkpointDigest && prior.entryDigests.includes(payload.entryDigest) };
  }

  transparencyStatus(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = normalizeTransparencyStatus(payloadValue);
    const principal = owner(context);
    this.reconcile();
    const record = this.store.findTransparencyByLog(payload.logId);
    if (record === undefined) fail('root_transparency_not_found', 'transparency monitor record was not found', { logId: payload.logId });
    ensureOwner(record.ownerPrincipal, principal);
    return { transparency: publicTransparency(record) };
  }

  reconcile(): JsonObject {
    const observedAt = this.now();
    let cachesVerified = 0;
    let cachesFailed = 0;
    let monitorsStale = 0;
    for (const bundle of this.store.scanBundles()) {
      if (bundle.cacheState !== 'CACHED') continue;
      const cachePath = join(this.cacheRoot, manifestHex(bundle.manifestDigest));
      try {
        if (!existsSync(cachePath)) throw new Error('cache absent');
        const resolved = this.resolver.resolve({ reference: `oci-layout:${cachePath}@${bundle.manifestDigest}`, expectedManifestDigest: bundle.manifestDigest, discoveryOnly: false });
        this.assertResolvedMatches(bundle, resolved);
        cachesVerified += 1;
      } catch {
        this.store.putBundle({ ...bundle, cacheState: 'CACHE_FAILED', contentVerified: false, sequence: bundle.sequence + 1, updatedAt: observedAt });
        cachesFailed += 1;
      }
    }
    for (const monitor of this.store.scanTransparency()) {
      if (monitor.state === 'VERIFIED' && Date.parse(observedAt) - Date.parse(monitor.checkpointIssuedAt) > monitor.maximumCheckpointAgeSeconds * 1_000) {
        this.store.putTransparency({ ...monitor, state: 'STALE', sequence: monitor.sequence + 1, updatedAt: observedAt });
        monitorsStale += 1;
      }
    }
    return { operation: 'babyx.root.trust.reconcile', observedAt, cachesVerified, cachesFailed, monitorsStale };
  }

  private persistTransparency(
    prior: TransparencyMonitorRecord | undefined,
    principal: string,
    idem: string,
    digestOfRequest: string,
    payload: ReturnType<typeof normalizeTransparencyVerify>,
    checkpointDigest: string,
    verifiedAt: string,
    state: TransparencyMonitorRecord['state'],
    criticalConflict: boolean,
    conflictDigest: string | null,
  ): TransparencyMonitorRecord {
    const entryDigests = [...new Set([...(prior?.entryDigests ?? []), payload.entryDigest])].sort();
    if (prior !== undefined) {
      ensureOwner(prior.ownerPrincipal, principal);
      if (prior.checkpointDigest === checkpointDigest && prior.entryDigests.includes(payload.entryDigest) && prior.state === state) return prior;
      return this.store.putTransparency({
        ...prior,
        state,
        treeSize: payload.checkpoint.treeSize,
        rootHash: payload.checkpoint.rootHash,
        checkpointDigest,
        signerKeyId: payload.checkpoint.signerKeyId,
        checkpointIssuedAt: payload.checkpoint.issuedAt,
        lastVerifiedAt: verifiedAt,
        maximumCheckpointAgeSeconds: payload.maximumCheckpointAgeSeconds,
        entryDigests,
        criticalConflict,
        conflictDigest,
        sequence: prior.sequence + 1,
        updatedAt: verifiedAt,
      });
    }
    const candidate = sealTrustRecord<TransparencyMonitorRecord>({
      schemaVersion: ROOT_TRUST_SCHEMA_VERSION,
      providerVersion: ROOT_TRUST_PROVIDER_VERSION,
      transparencyRecordId: newId('trn'),
      ownerPrincipal: principal,
      creationRequestDigest: digestOfRequest,
      sequence: 1,
      createdAt: verifiedAt,
      updatedAt: verifiedAt,
      logId: payload.logId,
      state,
      treeSize: payload.checkpoint.treeSize,
      rootHash: payload.checkpoint.rootHash,
      checkpointDigest,
      signerKeyId: payload.checkpoint.signerKeyId,
      checkpointIssuedAt: payload.checkpoint.issuedAt,
      lastVerifiedAt: verifiedAt,
      maximumCheckpointAgeSeconds: payload.maximumCheckpointAgeSeconds,
      entryDigests,
      criticalConflict,
      conflictDigest,
    });
    return this.store.createTransparency(`transparency:${principal}:${idem}`, digestOfRequest, candidate).record;
  }

  private assertResolvedMatches(record: BundleRecord, resolved: ResolvedOciBundle): void {
    const expected = {
      manifestDigest: record.manifestDigest,
      configDigest: record.configDigest,
      layerDigests: record.layerDigests,
      layerMediaTypes: record.layerMediaTypes,
    };
    const observed = {
      manifestDigest: resolved.manifestDigest,
      configDigest: resolved.configDigest,
      layerDigests: resolved.layerDigests,
      layerMediaTypes: resolved.layerMediaTypes,
    };
    if (canonicalize(expected) !== canonicalize(observed)) fail('root_bundle_content_conflict', 'resolved OCI content no longer matches the durable bundle record');
  }
}
