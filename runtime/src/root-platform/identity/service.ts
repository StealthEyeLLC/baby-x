import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../../core.ts';
import { SecretProvider } from '../../secrets/provider.ts';
import { RootIdentityError } from './errors.ts';
import { hardwareTpmSupport, identityProviders, verifySoftwareAttestationQuote } from './providers.ts';
import {
  ROOT_IDENTITY_PROVIDER_VERSION,
  ROOT_IDENTITY_SCHEMA_VERSION,
  ROOT_TRUST_DOMAIN,
  normalizeAttestationChallenge,
  normalizeAttestationGet,
  normalizeAttestationVerify,
  normalizeIdentityGet,
  normalizeIdentityIssue,
  normalizeIdentityRevoke,
  normalizeSecretLease,
  normalizeSecretRevoke,
  requestDigest,
  selectorMatches,
  type WorkloadSelector,
} from './schemas.ts';
import {
  RootIdentityStore,
  sealIdentityRecord,
  type AttestationChallengeRecord,
  type AttestationRecord,
  type SecretLeaseRecord,
  type WorkloadIdentityRecord,
} from './store.ts';

interface RootIdentityServiceOptions {
  stateRoot: string;
  now?: () => string;
  secretProvider?: SecretProvider;
}

interface Idempotency { digest: string; }

const IDEMPOTENCY = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const MAX_SECRET_BYTES = 1024 * 1024;

function owner(context: RuntimeExecutionContext): string {
  if (context.authorityClass !== undefined && context.authorityClass !== 'unrestricted-owner') throw new RootIdentityError('root_identity_authority_denied', 'unrestricted-owner authority is required');
  const principal = context.subject ?? 'stealtheye-owner';
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(principal)) throw new RootIdentityError('root_identity_invalid_request', 'owner principal is invalid');
  return principal;
}

function idempotency(context: RuntimeExecutionContext): Idempotency {
  const raw = context.idempotencyKey;
  if (typeof raw !== 'string' || !IDEMPOTENCY.test(raw)) throw new RootIdentityError('root_identity_idempotency_required', 'a bounded idempotency key is required');
  return { digest: sha256(raw) };
}

function addSeconds(timestamp: string, seconds: number): string { return new Date(Date.parse(timestamp) + seconds * 1_000).toISOString(); }
function newId(prefix: string): string { return `${prefix}_${randomUUID().replaceAll('-', '')}`; }
function stateConflict(message: string, details: JsonObject = {}): never { throw new RootIdentityError('root_identity_state_conflict', message, details); }
function unavailable(message: string, details: JsonObject = {}): never { throw new RootIdentityError('root_identity_provider_unavailable', message, details); }
function samePcrs(expected: readonly { index: number; value: string }[], actual: readonly { index: number; value: string }[]): boolean {
  const observed = new Map(actual.map((entry) => [entry.index, entry.value]));
  return expected.every((entry) => observed.get(entry.index) === entry.value);
}
function materialPaths(root: string, identityId: string): { keyPath: string; certificatePath: string } {
  return { keyPath: join(root, `${identityId}.key`), certificatePath: join(root, `${identityId}.crt`) };
}
function targetSelectors(kind: string, id: string, transactionId: string): WorkloadSelector[] {
  if (kind === 'SYSTEMD_UNIT') return [{ type: 'systemd_unit', value: id }];
  if (kind === 'MICROVM') return [{ type: 'vm_id', value: id }];
  if (kind === 'HOST_ENVELOPE') return [{ type: 'transaction_id', value: transactionId }];
  return [{ type: 'cgroup', value: id }];
}
function publicIdentity(record: WorkloadIdentityRecord): JsonObject {
  return {
    schemaVersion: record.schemaVersion,
    providerVersion: record.providerVersion,
    identityId: record.identityId,
    ownerPrincipal: record.ownerPrincipal,
    attestationId: record.attestationId,
    issuerProviderId: record.issuerProviderId,
    trustDomain: record.trustDomain,
    spiffeId: record.spiffeId,
    transactionId: record.transactionId,
    skillBundleDigest: record.skillBundleDigest,
    grantDigest: record.grantDigest,
    selectors: record.selectors,
    state: record.state,
    sequence: record.sequence,
    certificatePem: record.certificatePem,
    certificateDigest: record.certificateDigest,
    privateKeyReferenceDigest: record.privateKeyReferenceDigest,
    issuedAt: record.issuedAt,
    expiresAt: record.expiresAt,
    revokedAt: record.revokedAt,
    reasonDigest: record.reasonDigest,
    recordDigest: record.recordDigest,
  };
}
function publicLease(record: SecretLeaseRecord): JsonObject {
  return {
    schemaVersion: record.schemaVersion,
    providerVersion: record.providerVersion,
    leaseId: record.leaseId,
    ownerPrincipal: record.ownerPrincipal,
    identityId: record.identityId,
    attestationId: record.attestationId,
    transactionId: record.transactionId,
    skillBundleDigest: record.skillBundleDigest,
    grantDigest: record.grantDigest,
    providerId: record.providerId,
    secretReferenceDigest: record.secretReferenceDigest,
    secretMaterialDigest: record.secretMaterialDigest,
    target: record.target,
    state: record.state,
    sequence: record.sequence,
    issuedAt: record.issuedAt,
    expiresAt: record.expiresAt,
    revokedAt: record.revokedAt,
    reasonDigest: record.reasonDigest,
    recordDigest: record.recordDigest,
    secretValueReturned: false,
  };
}

export class RootIdentityService {
  private readonly store: RootIdentityStore;
  private readonly now: () => string;
  private readonly secretProvider: SecretProvider;
  private readonly materialsRoot: string;

  constructor(private readonly options: RootIdentityServiceOptions) {
    this.store = new RootIdentityStore(options.stateRoot);
    this.now = options.now ?? (() => new Date().toISOString());
    this.secretProvider = options.secretProvider ?? new SecretProvider();
    this.materialsRoot = join(options.stateRoot, 'root-platform', 'identity', 'materials');
    mkdirSync(this.materialsRoot, { recursive: true, mode: 0o700 });
    this.reconcile();
  }

  describe(): JsonObject {
    return {
      operation: 'babyx.root.attestation.get',
      schemaVersion: ROOT_IDENTITY_SCHEMA_VERSION,
      providerVersion: ROOT_IDENTITY_PROVIDER_VERSION,
      trustDomain: ROOT_TRUST_DOMAIN,
      providers: identityProviders().map((provider) => ({ ...provider.definition, ...provider.probe() })),
      secretValuesReturned: false,
      privateKeysReturned: false,
      restartBehavior: 'durable_record_reconciliation_and_expiry_cleanup',
    };
  }

  attestationChallenge(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = normalizeAttestationChallenge(payloadValue);
    const principal = owner(context);
    const idem = idempotency(context);
    const provider = identityProviders().find((entry) => entry.definition.providerId === payload.providerId);
    if (provider === undefined) unavailable('attestation provider is not registered', { providerId: payload.providerId });
    const observation = provider.probe();
    if (payload.providerId === 'hardware-tpm' && observation.supportState !== 'SUPPORTED') unavailable('hardware TPM attestation is unavailable on this host', { providerId: payload.providerId, supportState: observation.supportState, health: observation.health });
    const normalized = payload as unknown as JsonObject;
    const digestOfRequest = requestDigest('babyx.root.attestation.challenge', principal, normalized);
    const createdAt = this.now();
    const candidate = sealIdentityRecord<AttestationChallengeRecord>({
      schemaVersion: ROOT_IDENTITY_SCHEMA_VERSION,
      providerVersion: ROOT_IDENTITY_PROVIDER_VERSION,
      challengeId: newId('atc'),
      ownerPrincipal: principal,
      providerId: payload.providerId,
      nonce: sha256(canonicalize({ random: randomUUID(), createdAt, principal, providerId: payload.providerId })),
      pcrSelection: payload.pcrSelection,
      state: 'PENDING',
      sequence: 1,
      creationRequestDigest: digestOfRequest,
      createdAt,
      expiresAt: addSeconds(createdAt, payload.ttlSeconds),
      usedAt: null,
      attestationId: null,
    });
    const created = this.store.createChallenge(`challenge:${principal}:${idem.digest}`, digestOfRequest, candidate);
    return { challenge: created.record, replayed: created.replayed, provider: { providerId: payload.providerId, supportState: observation.supportState, health: observation.health } };
  }

  attestationVerify(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    this.reconcile();
    const payload = normalizeAttestationVerify(payloadValue);
    const principal = owner(context);
    const idem = idempotency(context);
    const normalized = payload as unknown as JsonObject;
    const digestOfRequest = requestDigest('babyx.root.attestation.verify', principal, normalized);
    let challenge = this.store.getChallenge(payload.challengeId);
    if (challenge.ownerPrincipal !== principal) throw new RootIdentityError('root_identity_owner_conflict', 'attestation challenge belongs to another owner');
    const recovered = this.store.findAttestationByChallenge(challenge.challengeId);
    if (recovered !== undefined) {
      if (recovered.creationRequestDigest !== digestOfRequest) throw new RootIdentityError('root_attestation_nonce_replay', 'attestation challenge was already consumed by another verification');
      if (challenge.state !== 'VERIFIED' || challenge.attestationId !== recovered.attestationId) challenge = this.store.putChallenge({ ...challenge, state: 'VERIFIED', usedAt: recovered.verifiedAt, attestationId: recovered.attestationId, sequence: challenge.sequence + 1 });
      return { attestation: recovered, challenge, replayed: true };
    }
    const verifiedAt = this.now();
    if (challenge.state !== 'PENDING') stateConflict('attestation challenge is not pending', { challengeId: challenge.challengeId, state: challenge.state });
    if (Date.parse(challenge.expiresAt) <= Date.parse(verifiedAt)) {
      this.store.putChallenge({ ...challenge, state: 'EXPIRED', sequence: challenge.sequence + 1 });
      throw new RootIdentityError('root_attestation_stale', 'attestation challenge has expired');
    }
    if (payload.quote.providerId !== challenge.providerId) throw new RootIdentityError('root_attestation_provider_conflict', 'quote provider does not match challenge provider');
    if (payload.quote.nonce !== challenge.nonce) throw new RootIdentityError('root_attestation_nonce_mismatch', 'quote nonce does not match the challenge');
    if (!challenge.pcrSelection.every((index) => payload.quote.pcrs.some((entry) => entry.index === index))) throw new RootIdentityError('root_attestation_pcr_mismatch', 'quote does not contain every requested PCR');
    const ageSeconds = Math.floor((Date.parse(verifiedAt) - Date.parse(payload.quote.observedAt)) / 1_000);
    if (ageSeconds < -5 || ageSeconds > payload.policy.maxAgeSeconds) throw new RootIdentityError('root_attestation_stale', 'attestation quote is outside the freshness window', { ageSeconds, maximumAgeSeconds: payload.policy.maxAgeSeconds });
    if (!samePcrs(payload.policy.expectedPcrs, payload.quote.pcrs)) throw new RootIdentityError('root_attestation_pcr_mismatch', 'attestation PCR values do not match policy');
    if (payload.policy.requireMeasuredBoot && payload.quote.eventLogDigest === null) throw new RootIdentityError('root_attestation_measurement_missing', 'measured-boot evidence is required');
    if (payload.policy.requireIma && payload.quote.imaDigest === null) throw new RootIdentityError('root_attestation_measurement_missing', 'IMA evidence is required');
    if (payload.quote.providerId === 'software-tpm-fixture') {
      if (!verifySoftwareAttestationQuote(payload.quote)) throw new RootIdentityError('root_attestation_signature_invalid', 'software TPM fixture quote signature is invalid');
    } else {
      const support = hardwareTpmSupport();
      if (support.supportState !== 'SUPPORTED') unavailable('hardware TPM quote verification is unavailable', { supportState: support.supportState, health: support.health });
      throw new RootIdentityError('root_attestation_signature_invalid', 'hardware TPM quote envelope is not accepted without provider-native verification evidence');
    }
    const attestationId = newId('atv');
    const quoteDigest = sha256(canonicalize(payload.quote));
    const policyDigest = sha256(canonicalize(payload.policy));
    const candidate = sealIdentityRecord<AttestationRecord>({
      schemaVersion: ROOT_IDENTITY_SCHEMA_VERSION,
      providerVersion: ROOT_IDENTITY_PROVIDER_VERSION,
      attestationId,
      challengeId: challenge.challengeId,
      ownerPrincipal: principal,
      providerId: payload.quote.providerId,
      state: 'VERIFIED',
      sequence: 1,
      creationRequestDigest: digestOfRequest,
      quoteDigest,
      policyDigest,
      pcrs: payload.quote.pcrs,
      pcrDigest: sha256(canonicalize(payload.quote.pcrs)),
      eventLogDigest: payload.quote.eventLogDigest,
      imaDigest: payload.quote.imaDigest,
      bootId: payload.quote.bootId,
      attestationKeyId: payload.quote.attestationKeyId,
      measuredBootVerified: payload.quote.eventLogDigest !== null,
      imaVerified: payload.quote.imaDigest !== null,
      freshnessSeconds: Math.max(0, ageSeconds),
      verifiedAt,
      expiresAt: new Date(Math.min(Date.parse(challenge.expiresAt), Date.parse(addSeconds(payload.quote.observedAt, payload.policy.maxAgeSeconds)))).toISOString(),
    });
    const created = this.store.createAttestation(`attestation:${principal}:${idem.digest}`, digestOfRequest, candidate);
    challenge = this.store.putChallenge({ ...challenge, state: 'VERIFIED', usedAt: created.record.verifiedAt, attestationId: created.record.attestationId, sequence: challenge.sequence + 1 });
    return { attestation: created.record, challenge, replayed: created.replayed };
  }

  attestationGet(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    this.reconcile();
    const payload = normalizeAttestationGet(payloadValue);
    const principal = owner(context);
    if (payload.challengeId !== undefined) {
      const challenge = this.store.getChallenge(payload.challengeId);
      if (challenge.ownerPrincipal !== principal) throw new RootIdentityError('root_identity_owner_conflict', 'attestation challenge belongs to another owner');
      return { challenge };
    }
    const attestation = this.store.getAttestation(payload.attestationId as string);
    if (attestation.ownerPrincipal !== principal) throw new RootIdentityError('root_identity_owner_conflict', 'attestation belongs to another owner');
    return { attestation };
  }

  identityIssue(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    this.reconcile();
    const payload = normalizeIdentityIssue(payloadValue);
    const principal = owner(context);
    const idem = idempotency(context);
    const digestOfRequest = requestDigest('babyx.root.identity.issue', principal, payload as unknown as JsonObject);
    const attestation = this.store.getAttestation(payload.attestationId);
    const issuedAt = this.now();
    if (attestation.ownerPrincipal !== principal) throw new RootIdentityError('root_identity_owner_conflict', 'attestation belongs to another owner');
    if (attestation.state !== 'VERIFIED' || Date.parse(attestation.expiresAt) <= Date.parse(issuedAt)) throw new RootIdentityError('root_attestation_stale', 'fresh verified attestation is required');
    const issuer = identityProviders().find((entry) => entry.definition.providerId === payload.issuerProviderId);
    if (issuer === undefined) unavailable('identity issuer provider is not registered', { issuerProviderId: payload.issuerProviderId });
    const issuerObservation = issuer.probe();
    if (payload.issuerProviderId === 'spire-workload-api' && issuerObservation.supportState !== 'SUPPORTED') unavailable('SPIRE Workload API is unavailable', { supportState: issuerObservation.supportState, health: issuerObservation.health });
    if (payload.issuerProviderId === 'sovereign-x509-svid' && !['SUPPORTED', 'EXPERIMENTAL'].includes(issuerObservation.supportState)) unavailable('sovereign X.509-SVID issuer is unavailable', { supportState: issuerObservation.supportState, health: issuerObservation.health });
    const identityId = newId('wid');
    const spiffeId = `spiffe://${ROOT_TRUST_DOMAIN}/workload/${identityId}`;
    const paths = materialPaths(this.materialsRoot, identityId);
    let certificatePem = '';
    try {
      if (payload.issuerProviderId === 'spire-workload-api') unavailable('SPIRE issuance requires an enrolled and selector-bound workload registration', { issuerProviderId: payload.issuerProviderId });
      const result = spawnSync('/usr/bin/openssl', [
        'req', '-new', '-newkey', 'ed25519', '-nodes', '-x509', '-days', '1',
        '-subj', `/CN=${identityId}`,
        '-addext', `subjectAltName=URI:${spiffeId}`,
        '-keyout', paths.keyPath,
        '-out', paths.certificatePath,
      ], { encoding: 'utf8', timeout: 10_000 });
      if (result.status !== 0) throw new RootIdentityError('root_identity_issuance_failed', 'OpenSSL could not issue the sovereign X.509-SVID', { status: result.status, stderrDigest: sha256(result.stderr ?? '') });
      chmodSync(paths.keyPath, 0o600);
      chmodSync(paths.certificatePath, 0o644);
      certificatePem = readFileSync(paths.certificatePath, 'utf8');
      const candidate = sealIdentityRecord<WorkloadIdentityRecord>({
        schemaVersion: ROOT_IDENTITY_SCHEMA_VERSION,
        providerVersion: ROOT_IDENTITY_PROVIDER_VERSION,
        identityId,
        ownerPrincipal: principal,
        attestationId: payload.attestationId,
        issuerProviderId: payload.issuerProviderId,
        trustDomain: ROOT_TRUST_DOMAIN,
        spiffeId,
        transactionId: payload.transactionId,
        skillBundleDigest: payload.skillBundleDigest,
        grantDigest: payload.grantDigest,
        selectors: payload.selectors,
        state: 'ACTIVE',
        sequence: 1,
        creationRequestDigest: digestOfRequest,
        certificatePem,
        certificateDigest: sha256(certificatePem),
        privateKeyReferenceDigest: sha256(paths.keyPath),
        issuedAt,
        expiresAt: new Date(Math.min(Date.parse(attestation.expiresAt), Date.parse(addSeconds(issuedAt, payload.ttlSeconds)))).toISOString(),
        revokedAt: null,
        reasonDigest: null,
      });
      const created = this.store.createIdentity(`identity:${principal}:${idem.digest}`, digestOfRequest, candidate);
      if (created.record.identityId !== identityId) {
        rmSync(paths.keyPath, { force: true });
        rmSync(paths.certificatePath, { force: true });
      }
      return { identity: publicIdentity(created.record), replayed: created.replayed, issuer: { providerId: payload.issuerProviderId, supportState: issuerObservation.supportState } };
    } catch (error) {
      if (existsSync(paths.keyPath)) rmSync(paths.keyPath, { force: true });
      if (existsSync(paths.certificatePath)) rmSync(paths.certificatePath, { force: true });
      throw error;
    }
  }

  identityGet(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    this.reconcile();
    const payload = normalizeIdentityGet(payloadValue);
    const principal = owner(context);
    const identity = this.store.getIdentity(payload.identityId);
    if (identity.ownerPrincipal !== principal) throw new RootIdentityError('root_identity_owner_conflict', 'workload identity belongs to another owner');
    return { identity: publicIdentity(identity) };
  }

  identityRevoke(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    this.reconcile();
    const payload = normalizeIdentityRevoke(payloadValue);
    const principal = owner(context);
    idempotency(context);
    let identity = this.store.getIdentity(payload.identityId);
    if (identity.ownerPrincipal !== principal) throw new RootIdentityError('root_identity_owner_conflict', 'workload identity belongs to another owner');
    if (identity.state === 'REVOKED') {
      if (identity.reasonDigest !== payload.reasonDigest) stateConflict('workload identity is already revoked for another reason');
      return { identity: publicIdentity(identity), replayed: true };
    }
    if (identity.sequence !== payload.expectedSequence) stateConflict('identity expected sequence does not match', { expected: payload.expectedSequence, actual: identity.sequence });
    const revokedAt = this.now();
    identity = this.store.putIdentity({ ...identity, state: 'REVOKED', sequence: identity.sequence + 1, revokedAt, reasonDigest: payload.reasonDigest });
    this.removeIdentityMaterials(identity.identityId);
    for (const lease of this.store.scanLeases().filter((record) => record.identityId === identity.identityId && record.state === 'ACTIVE')) this.store.putLease({ ...lease, state: 'REVOKED', sequence: lease.sequence + 1, revokedAt, reasonDigest: payload.reasonDigest });
    return { identity: publicIdentity(identity), replayed: false };
  }

  secretLease(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    this.reconcile();
    const payload = normalizeSecretLease(payloadValue);
    const principal = owner(context);
    const idem = idempotency(context);
    const digestOfRequest = requestDigest('babyx.root.secret.lease', principal, payload as unknown as JsonObject);
    const now = this.now();
    const identity = this.store.getIdentity(payload.identityId);
    const attestation = this.store.getAttestation(payload.attestationId);
    if (identity.ownerPrincipal !== principal || attestation.ownerPrincipal !== principal) throw new RootIdentityError('root_identity_owner_conflict', 'identity or attestation belongs to another owner');
    if (identity.state !== 'ACTIVE' || Date.parse(identity.expiresAt) <= Date.parse(now)) throw new RootIdentityError('root_identity_expired', 'an active workload identity is required');
    if (attestation.state !== 'VERIFIED' || Date.parse(attestation.expiresAt) <= Date.parse(now)) throw new RootIdentityError('root_attestation_stale', 'fresh verified attestation is required');
    if (identity.attestationId !== payload.attestationId || identity.transactionId !== payload.transactionId || identity.skillBundleDigest !== payload.skillBundleDigest || identity.grantDigest !== payload.grantDigest) throw new RootIdentityError('root_secret_lease_denied', 'lease bindings do not match the workload identity');
    if (payload.target.kind === 'HOST_ENVELOPE' && payload.target.id !== payload.transactionId) throw new RootIdentityError('root_secret_lease_denied', 'host-envelope target must equal transactionId');
    if (!selectorMatches(targetSelectors(payload.target.kind, payload.target.id, payload.transactionId), identity.selectors)) throw new RootIdentityError('root_secret_lease_denied', 'workload selectors do not authorize the requested target');
    if (!existsSync(payload.secretReference)) throw new RootIdentityError('root_secret_reference_unavailable', 'secret reference is unavailable');
    const stat = statSync(payload.secretReference);
    if (!stat.isFile() || stat.size > MAX_SECRET_BYTES) throw new RootIdentityError('root_secret_reference_unavailable', 'secret reference must be a bounded regular file', { maximumBytes: MAX_SECRET_BYTES });
    const secret = this.secretProvider.read(payload.secretReference);
    try {
      if (secret.length > MAX_SECRET_BYTES) throw new RootIdentityError('root_secret_reference_unavailable', 'secret exceeds the maximum size');
      const issuedAt = now;
      const candidate = sealIdentityRecord<SecretLeaseRecord>({
        schemaVersion: ROOT_IDENTITY_SCHEMA_VERSION,
        providerVersion: ROOT_IDENTITY_PROVIDER_VERSION,
        leaseId: newId('sls'),
        ownerPrincipal: principal,
        identityId: payload.identityId,
        attestationId: payload.attestationId,
        transactionId: payload.transactionId,
        skillBundleDigest: payload.skillBundleDigest,
        grantDigest: payload.grantDigest,
        providerId: 'local-secret-reference',
        secretReferenceDigest: sha256(payload.secretReference),
        secretMaterialDigest: sha256(secret),
        target: payload.target,
        state: 'ACTIVE',
        sequence: 1,
        creationRequestDigest: digestOfRequest,
        issuedAt,
        expiresAt: new Date(Math.min(Date.parse(identity.expiresAt), Date.parse(attestation.expiresAt), Date.parse(addSeconds(issuedAt, payload.ttlSeconds)))).toISOString(),
        revokedAt: null,
        reasonDigest: null,
      });
      const created = this.store.createLease(`secret-lease:${principal}:${idem.digest}`, digestOfRequest, candidate);
      return { lease: publicLease(created.record), replayed: created.replayed };
    } finally { secret.fill(0); }
  }

  secretRevoke(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    this.reconcile();
    const payload = normalizeSecretRevoke(payloadValue);
    const principal = owner(context);
    idempotency(context);
    let lease = this.store.getLease(payload.leaseId);
    if (lease.ownerPrincipal !== principal) throw new RootIdentityError('root_identity_owner_conflict', 'secret lease belongs to another owner');
    if (lease.state === 'REVOKED') {
      if (lease.reasonDigest !== payload.reasonDigest) stateConflict('secret lease is already revoked for another reason');
      return { lease: publicLease(lease), replayed: true };
    }
    if (lease.sequence !== payload.expectedSequence) stateConflict('secret lease expected sequence does not match', { expected: payload.expectedSequence, actual: lease.sequence });
    const revokedAt = this.now();
    lease = this.store.putLease({ ...lease, state: 'REVOKED', sequence: lease.sequence + 1, revokedAt, reasonDigest: payload.reasonDigest });
    return { lease: publicLease(lease), replayed: false };
  }

  reconcile(): JsonObject {
    const now = this.now();
    let challengesExpired = 0;
    let attestationsExpired = 0;
    let identitiesExpired = 0;
    let leasesExpired = 0;
    for (const challenge of this.store.scanChallenges()) {
      if (challenge.state === 'PENDING' && Date.parse(challenge.expiresAt) <= Date.parse(now)) { this.store.putChallenge({ ...challenge, state: 'EXPIRED', sequence: challenge.sequence + 1 }); challengesExpired += 1; }
    }
    for (const attestation of this.store.scanAttestations()) {
      if (attestation.state === 'VERIFIED' && Date.parse(attestation.expiresAt) <= Date.parse(now)) { this.store.putAttestation({ ...attestation, state: 'EXPIRED', sequence: attestation.sequence + 1 }); attestationsExpired += 1; }
    }
    for (const identity of this.store.scanIdentities()) {
      if (identity.state === 'ACTIVE' && Date.parse(identity.expiresAt) <= Date.parse(now)) { this.store.putIdentity({ ...identity, state: 'EXPIRED', sequence: identity.sequence + 1 }); this.removeIdentityMaterials(identity.identityId); identitiesExpired += 1; }
    }
    for (const lease of this.store.scanLeases()) {
      const identity = this.tryIdentity(lease.identityId);
      const attestation = this.tryAttestation(lease.attestationId);
      const invalidOwner = identity === null || attestation === null || identity.state !== 'ACTIVE' || attestation.state !== 'VERIFIED';
      if (lease.state === 'ACTIVE' && (Date.parse(lease.expiresAt) <= Date.parse(now) || invalidOwner)) { this.store.putLease({ ...lease, state: 'EXPIRED', sequence: lease.sequence + 1 }); leasesExpired += 1; }
    }
    this.removeOrphanMaterials();
    return { operation: 'babyx.root.identity.reconcile', observedAt: now, challengesExpired, attestationsExpired, identitiesExpired, leasesExpired };
  }

  private tryIdentity(identityId: string): WorkloadIdentityRecord | null { try { return this.store.getIdentity(identityId); } catch { return null; } }
  private tryAttestation(attestationId: string): AttestationRecord | null { try { return this.store.getAttestation(attestationId); } catch { return null; } }
  private removeIdentityMaterials(identityId: string): void { const paths = materialPaths(this.materialsRoot, identityId); rmSync(paths.keyPath, { force: true }); rmSync(paths.certificatePath, { force: true }); }
  private removeOrphanMaterials(): void {
    const active = new Set(this.store.scanIdentities().filter((record) => record.state === 'ACTIVE').map((record) => record.identityId));
    for (const name of readdirSync(this.materialsRoot)) {
      const match = /^(wid_[a-f0-9]{32})\.(?:key|crt)$/u.exec(name);
      if (match !== null && !active.has(match[1] as string)) rmSync(join(this.materialsRoot, name), { force: true });
    }
  }
}
