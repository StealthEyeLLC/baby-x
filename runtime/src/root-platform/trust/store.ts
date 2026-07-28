import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../../storage/record-store.ts';
import { RootTrustError } from './errors.ts';
import { ROOT_TRUST_PROVIDER_VERSION, ROOT_TRUST_SCHEMA_VERSION } from './schemas.ts';

interface TrustBaseRecord extends JsonObject {
  schemaVersion: typeof ROOT_TRUST_SCHEMA_VERSION;
  providerVersion: typeof ROOT_TRUST_PROVIDER_VERSION;
  ownerPrincipal: string;
  creationRequestDigest: string;
  sequence: number;
  createdAt: string;
  updatedAt: string;
  recordDigest: string;
}

export interface BundleRecord extends TrustBaseRecord {
  bundleId: string;
  sourceKind: 'LOCAL_OCI_LAYOUT' | 'REMOTE_REGISTRY';
  registry: string;
  repository: string;
  discoveryReferenceDigest: string;
  sourceReference: string;
  sourceLayoutPath: string | null;
  manifestDigest: string;
  manifestMediaType: string;
  configDigest: string;
  configMediaType: string;
  layerDigests: string[];
  layerMediaTypes: string[];
  size: number;
  contentVerified: boolean;
  executionEligible: boolean;
  cacheState: 'UNCACHED' | 'CACHED' | 'CACHE_FAILED';
  cachePathDigest: string | null;
  cacheDigest: string | null;
  signatureState: 'UNVERIFIED' | 'VERIFIED' | 'REVOKED' | 'FAILED';
  signatureVerificationId: string | null;
  provenanceState: 'UNVERIFIED' | 'VERIFIED' | 'FAILED';
  provenanceVerificationId: string | null;
}

export interface SignatureVerificationRecord extends TrustBaseRecord {
  signatureVerificationId: string;
  bundleId: string;
  manifestDigest: string;
  state: 'VERIFIED' | 'REVOKED' | 'FAILED';
  verificationKind: 'KEYED' | 'KEYLESS';
  signerDigest: string;
  signatureBundleDigest: string;
  trustPolicyDigest: string;
  transparencyEntryDigests: string[];
  verifiedAt: string;
}

export interface ProvenanceVerificationRecord extends TrustBaseRecord {
  provenanceVerificationId: string;
  bundleId: string;
  manifestDigest: string;
  state: 'VERIFIED' | 'FAILED';
  envelopeDigest: string;
  statementDigest: string;
  signerDigest: string;
  predicateType: string;
  expectationDigest: string;
  verifiedAt: string;
}

export interface TransparencyMonitorRecord extends TrustBaseRecord {
  transparencyRecordId: string;
  logId: string;
  state: 'VERIFIED' | 'STALE' | 'CONFLICT';
  treeSize: number;
  rootHash: string;
  checkpointDigest: string;
  signerKeyId: string;
  checkpointIssuedAt: string;
  lastVerifiedAt: string;
  maximumCheckpointAgeSeconds: number;
  entryDigests: string[];
  criticalConflict: boolean;
  conflictDigest: string | null;
}

type TrustRecord = BundleRecord | SignatureVerificationRecord | ProvenanceVerificationRecord | TransparencyMonitorRecord;

type RecordIdField = 'bundleId' | 'signatureVerificationId' | 'provenanceVerificationId' | 'transparencyRecordId';

function unsigned<T extends TrustRecord>(record: T): JsonObject {
  const { recordDigest: _digest, ...value } = record;
  return value;
}
export function sealTrustRecord<T extends TrustRecord>(record: Omit<T, 'recordDigest'>): T {
  return { ...(record as unknown as T), recordDigest: sha256(canonicalize(record as unknown as JsonObject)) };
}
export function verifyTrustRecord(record: TrustRecord): boolean {
  return record.schemaVersion === ROOT_TRUST_SCHEMA_VERSION
    && record.providerVersion === ROOT_TRUST_PROVIDER_VERSION
    && record.recordDigest === sha256(canonicalize(unsigned(record)));
}
function recordId(record: TrustRecord): string {
  if ('bundleId' in record) return record.bundleId;
  if ('signatureVerificationId' in record) return record.signatureVerificationId;
  if ('provenanceVerificationId' in record) return record.provenanceVerificationId;
  return record.transparencyRecordId;
}
function requireValid<T extends TrustRecord>(record: T): T {
  if (!verifyTrustRecord(record)) throw new RootTrustError('root_trust_integrity_failure', 'trust sidecar record failed digest verification', { recordId: recordId(record) });
  return structuredClone(record);
}
function createWithClaim<T extends TrustRecord>(
  store: DurableRecordStore<T>,
  claims: DurableClaimStore<T>,
  claimKey: string,
  requestDigest: string,
  id: string,
  candidate: T,
): { record: T; replayed: boolean } {
  const existing = claims.get(claimKey);
  if (existing !== undefined) {
    if (existing.requestDigest !== requestDigest) throw new RootTrustError('root_trust_idempotency_conflict', 'idempotency key is bound to a different request');
    if (!store.has(existing.recordId)) store.create(existing.recordId, existing.record);
    return { record: requireValid(store.get(existing.recordId)), replayed: true };
  }
  const claim = claims.claim(claimKey, requestDigest, id, candidate);
  if (claim.requestDigest !== requestDigest) throw new RootTrustError('root_trust_idempotency_conflict', 'idempotency key is bound to a different request');
  if (!store.has(claim.recordId) && !store.create(claim.recordId, claim.record)) throw new RootTrustError('root_trust_integrity_failure', 'durable trust record could not be created');
  return { record: requireValid(store.get(claim.recordId)), replayed: claim.recordId !== id };
}
function getRecord<T extends TrustRecord>(store: DurableRecordStore<T>, id: string, code: string, message: string): T {
  try { return requireValid(store.get(id)); }
  catch (error) {
    if (error instanceof RootTrustError) throw error;
    throw new RootTrustError(code, message, { recordId: id });
  }
}
function putRecord<T extends TrustRecord>(store: DurableRecordStore<T>, idField: RecordIdField, record: T): T {
  const sealed = sealTrustRecord<T>(unsigned(record) as Omit<T, 'recordDigest'>);
  store.put(String(sealed[idField]), sealed);
  return requireValid(sealed);
}

export class RootTrustStore {
  private readonly bundles: DurableRecordStore<BundleRecord>;
  private readonly signatures: DurableRecordStore<SignatureVerificationRecord>;
  private readonly provenance: DurableRecordStore<ProvenanceVerificationRecord>;
  private readonly transparency: DurableRecordStore<TransparencyMonitorRecord>;
  private readonly bundleClaims: DurableClaimStore<BundleRecord>;
  private readonly signatureClaims: DurableClaimStore<SignatureVerificationRecord>;
  private readonly provenanceClaims: DurableClaimStore<ProvenanceVerificationRecord>;
  private readonly transparencyClaims: DurableClaimStore<TransparencyMonitorRecord>;

  constructor(root: string) {
    const base = join(root, 'root-platform', 'trust');
    this.bundles = new DurableRecordStore(join(base, 'bundles'));
    this.signatures = new DurableRecordStore(join(base, 'signatures'));
    this.provenance = new DurableRecordStore(join(base, 'provenance'));
    this.transparency = new DurableRecordStore(join(base, 'transparency'));
    this.bundleClaims = new DurableClaimStore(join(base, 'claims', 'bundles'));
    this.signatureClaims = new DurableClaimStore(join(base, 'claims', 'signatures'));
    this.provenanceClaims = new DurableClaimStore(join(base, 'claims', 'provenance'));
    this.transparencyClaims = new DurableClaimStore(join(base, 'claims', 'transparency'));
  }

  createBundle(key: string, digest: string, record: BundleRecord): { record: BundleRecord; replayed: boolean } { return createWithClaim(this.bundles, this.bundleClaims, key, digest, record.bundleId, record); }
  createSignature(key: string, digest: string, record: SignatureVerificationRecord): { record: SignatureVerificationRecord; replayed: boolean } { return createWithClaim(this.signatures, this.signatureClaims, key, digest, record.signatureVerificationId, record); }
  createProvenance(key: string, digest: string, record: ProvenanceVerificationRecord): { record: ProvenanceVerificationRecord; replayed: boolean } { return createWithClaim(this.provenance, this.provenanceClaims, key, digest, record.provenanceVerificationId, record); }
  createTransparency(key: string, digest: string, record: TransparencyMonitorRecord): { record: TransparencyMonitorRecord; replayed: boolean } { return createWithClaim(this.transparency, this.transparencyClaims, key, digest, record.transparencyRecordId, record); }

  getBundle(id: string): BundleRecord { return getRecord(this.bundles, id, 'root_bundle_not_found', 'OCI Skill bundle record was not found'); }
  getSignature(id: string): SignatureVerificationRecord { return getRecord(this.signatures, id, 'root_signature_verification_not_found', 'signature verification record was not found'); }
  getProvenance(id: string): ProvenanceVerificationRecord { return getRecord(this.provenance, id, 'root_provenance_verification_not_found', 'provenance verification record was not found'); }
  getTransparency(id: string): TransparencyMonitorRecord { return getRecord(this.transparency, id, 'root_transparency_not_found', 'transparency monitor record was not found'); }

  putBundle(record: BundleRecord): BundleRecord { return putRecord(this.bundles, 'bundleId', record); }
  putSignature(record: SignatureVerificationRecord): SignatureVerificationRecord { return putRecord(this.signatures, 'signatureVerificationId', record); }
  putProvenance(record: ProvenanceVerificationRecord): ProvenanceVerificationRecord { return putRecord(this.provenance, 'provenanceVerificationId', record); }
  putTransparency(record: TransparencyMonitorRecord): TransparencyMonitorRecord { return putRecord(this.transparency, 'transparencyRecordId', record); }

  findBundleByManifest(manifestDigest: string): BundleRecord | undefined {
    const match = this.bundles.scan((record) => record.manifestDigest === manifestDigest, 0, 2).records[0];
    return match === undefined ? undefined : requireValid(match);
  }
  findTransparencyByLog(logId: string): TransparencyMonitorRecord | undefined {
    const match = this.transparency.scan((record) => record.logId === logId, 0, 2).records[0];
    return match === undefined ? undefined : requireValid(match);
  }
  scanBundles(): BundleRecord[] { return this.bundles.scan(() => true, 0, 10_000).records.map((record) => requireValid(record)); }
  scanTransparency(): TransparencyMonitorRecord[] { return this.transparency.scan(() => true, 0, 10_000).records.map((record) => requireValid(record)); }
}
