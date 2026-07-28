import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../../storage/record-store.ts';
import { RootIdentityError } from './errors.ts';
import { ROOT_IDENTITY_PROVIDER_VERSION, ROOT_IDENTITY_SCHEMA_VERSION, type PcrValue, type RootIdentityProviderId, type RootSvidIssuerId, type SecretLeaseTarget, type WorkloadSelector } from './schemas.ts';

export interface AttestationChallengeRecord extends JsonObject {
  schemaVersion: typeof ROOT_IDENTITY_SCHEMA_VERSION;
  providerVersion: typeof ROOT_IDENTITY_PROVIDER_VERSION;
  challengeId: string;
  ownerPrincipal: string;
  providerId: RootIdentityProviderId;
  nonce: string;
  pcrSelection: number[];
  state: 'PENDING' | 'VERIFIED' | 'EXPIRED';
  sequence: number;
  creationRequestDigest: string;
  createdAt: string;
  expiresAt: string;
  usedAt: string | null;
  attestationId: string | null;
  recordDigest: string;
}

export interface AttestationRecord extends JsonObject {
  schemaVersion: typeof ROOT_IDENTITY_SCHEMA_VERSION;
  providerVersion: typeof ROOT_IDENTITY_PROVIDER_VERSION;
  attestationId: string;
  challengeId: string;
  ownerPrincipal: string;
  providerId: RootIdentityProviderId;
  state: 'VERIFIED' | 'REVOKED' | 'EXPIRED';
  sequence: number;
  creationRequestDigest: string;
  quoteDigest: string;
  policyDigest: string;
  pcrs: PcrValue[];
  pcrDigest: string;
  eventLogDigest: string | null;
  imaDigest: string | null;
  bootId: string;
  attestationKeyId: string;
  measuredBootVerified: boolean;
  imaVerified: boolean;
  freshnessSeconds: number;
  verifiedAt: string;
  expiresAt: string;
  recordDigest: string;
}

export interface WorkloadIdentityRecord extends JsonObject {
  schemaVersion: typeof ROOT_IDENTITY_SCHEMA_VERSION;
  providerVersion: typeof ROOT_IDENTITY_PROVIDER_VERSION;
  identityId: string;
  ownerPrincipal: string;
  attestationId: string;
  issuerProviderId: RootSvidIssuerId;
  trustDomain: string;
  spiffeId: string;
  transactionId: string;
  skillBundleDigest: string;
  grantDigest: string;
  selectors: WorkloadSelector[];
  state: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  sequence: number;
  creationRequestDigest: string;
  certificatePem: string;
  certificateDigest: string;
  privateKeyReferenceDigest: string;
  issuedAt: string;
  expiresAt: string;
  revokedAt: string | null;
  reasonDigest: string | null;
  recordDigest: string;
}

export interface SecretLeaseRecord extends JsonObject {
  schemaVersion: typeof ROOT_IDENTITY_SCHEMA_VERSION;
  providerVersion: typeof ROOT_IDENTITY_PROVIDER_VERSION;
  leaseId: string;
  ownerPrincipal: string;
  identityId: string;
  attestationId: string;
  transactionId: string;
  skillBundleDigest: string;
  grantDigest: string;
  providerId: 'local-secret-reference';
  secretReferenceDigest: string;
  secretMaterialDigest: string;
  target: SecretLeaseTarget;
  state: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  sequence: number;
  creationRequestDigest: string;
  issuedAt: string;
  expiresAt: string;
  revokedAt: string | null;
  reasonDigest: string | null;
  recordDigest: string;
}

type IdentityRecord = AttestationChallengeRecord | AttestationRecord | WorkloadIdentityRecord | SecretLeaseRecord;

function withoutDigest<T extends IdentityRecord>(record: T): JsonObject { const { recordDigest: _digest, ...unsigned } = record; return unsigned; }
export function computeIdentityRecordDigest(record: IdentityRecord): string { return sha256(canonicalize(withoutDigest(record))); }
export function sealIdentityRecord<T extends IdentityRecord>(record: Omit<T, 'recordDigest'>): T {
  const candidate = record as unknown as T;
  return { ...candidate, recordDigest: sha256(canonicalize(record as unknown as JsonObject)) };
}
export function verifyIdentityRecord(record: IdentityRecord): boolean {
  return record.schemaVersion === ROOT_IDENTITY_SCHEMA_VERSION && record.providerVersion === ROOT_IDENTITY_PROVIDER_VERSION && record.recordDigest === computeIdentityRecordDigest(record);
}

function identityRecordId(record: IdentityRecord): string {
  if ('leaseId' in record) return record.leaseId;
  if ('identityId' in record) return record.identityId;
  if ('attestationId' in record && typeof record.attestationId === 'string') return record.attestationId;
  return record.challengeId;
}

function requireValid<T extends IdentityRecord>(record: T): T {
  if (!verifyIdentityRecord(record)) throw new RootIdentityError('root_identity_integrity_failure', 'identity sidecar record failed digest verification', { recordId: identityRecordId(record) });
  return structuredClone(record);
}

function createWithClaim<T extends IdentityRecord>(
  store: DurableRecordStore<T>,
  claims: DurableClaimStore<T>,
  key: string,
  requestDigest: string,
  recordId: string,
  candidate: T,
): { record: T; replayed: boolean } {
  const existing = claims.get(key);
  if (existing !== undefined) {
    if (existing.requestDigest !== requestDigest) throw new RootIdentityError('root_identity_idempotency_conflict', 'idempotency key is bound to a different request');
    if (!store.has(existing.recordId)) store.create(existing.recordId, existing.record);
    return { record: requireValid(store.get(existing.recordId)), replayed: true };
  }
  const claim = claims.claim(key, requestDigest, recordId, candidate);
  if (claim.requestDigest !== requestDigest) throw new RootIdentityError('root_identity_idempotency_conflict', 'idempotency key is bound to a different request');
  if (!store.has(claim.recordId) && !store.create(claim.recordId, claim.record)) throw new RootIdentityError('root_identity_integrity_failure', 'durable identity record could not be created');
  return { record: requireValid(store.get(claim.recordId)), replayed: claim.recordId !== recordId };
}

export class RootIdentityStore {
  private readonly challenges: DurableRecordStore<AttestationChallengeRecord>;
  private readonly attestations: DurableRecordStore<AttestationRecord>;
  private readonly identities: DurableRecordStore<WorkloadIdentityRecord>;
  private readonly leases: DurableRecordStore<SecretLeaseRecord>;
  private readonly challengeClaims: DurableClaimStore<AttestationChallengeRecord>;
  private readonly attestationClaims: DurableClaimStore<AttestationRecord>;
  private readonly identityClaims: DurableClaimStore<WorkloadIdentityRecord>;
  private readonly leaseClaims: DurableClaimStore<SecretLeaseRecord>;

  constructor(root: string) {
    const base = join(root, 'root-platform', 'identity');
    this.challenges = new DurableRecordStore(join(base, 'challenges'));
    this.attestations = new DurableRecordStore(join(base, 'attestations'));
    this.identities = new DurableRecordStore(join(base, 'identities'));
    this.leases = new DurableRecordStore(join(base, 'secret-leases'));
    this.challengeClaims = new DurableClaimStore(join(base, 'claims', 'challenges'));
    this.attestationClaims = new DurableClaimStore(join(base, 'claims', 'attestations'));
    this.identityClaims = new DurableClaimStore(join(base, 'claims', 'identities'));
    this.leaseClaims = new DurableClaimStore(join(base, 'claims', 'secret-leases'));
  }

  createChallenge(key: string, requestDigest: string, record: AttestationChallengeRecord): { record: AttestationChallengeRecord; replayed: boolean } { return createWithClaim(this.challenges, this.challengeClaims, key, requestDigest, record.challengeId, record); }
  createAttestation(key: string, requestDigest: string, record: AttestationRecord): { record: AttestationRecord; replayed: boolean } { return createWithClaim(this.attestations, this.attestationClaims, key, requestDigest, record.attestationId, record); }
  createIdentity(key: string, requestDigest: string, record: WorkloadIdentityRecord): { record: WorkloadIdentityRecord; replayed: boolean } { return createWithClaim(this.identities, this.identityClaims, key, requestDigest, record.identityId, record); }
  createLease(key: string, requestDigest: string, record: SecretLeaseRecord): { record: SecretLeaseRecord; replayed: boolean } { return createWithClaim(this.leases, this.leaseClaims, key, requestDigest, record.leaseId, record); }

  getChallenge(id: string): AttestationChallengeRecord { try { return requireValid(this.challenges.get(id)); } catch (error) { if (error instanceof RootIdentityError) throw error; throw new RootIdentityError('root_attestation_not_found', 'attestation challenge was not found', { challengeId: id }); } }
  getAttestation(id: string): AttestationRecord { try { return requireValid(this.attestations.get(id)); } catch (error) { if (error instanceof RootIdentityError) throw error; throw new RootIdentityError('root_attestation_not_found', 'attestation verification was not found', { attestationId: id }); } }
  getIdentity(id: string): WorkloadIdentityRecord { try { return requireValid(this.identities.get(id)); } catch (error) { if (error instanceof RootIdentityError) throw error; throw new RootIdentityError('root_identity_not_found', 'workload identity was not found', { identityId: id }); } }
  getLease(id: string): SecretLeaseRecord { try { return requireValid(this.leases.get(id)); } catch (error) { if (error instanceof RootIdentityError) throw error; throw new RootIdentityError('root_secret_lease_not_found', 'secret lease was not found', { leaseId: id }); } }

  putChallenge(record: AttestationChallengeRecord): AttestationChallengeRecord { const sealed = sealIdentityRecord<AttestationChallengeRecord>(withoutDigest(record) as Omit<AttestationChallengeRecord, 'recordDigest'>); this.challenges.put(record.challengeId, sealed); return requireValid(sealed); }
  putAttestation(record: AttestationRecord): AttestationRecord { const sealed = sealIdentityRecord<AttestationRecord>(withoutDigest(record) as Omit<AttestationRecord, 'recordDigest'>); this.attestations.put(record.attestationId, sealed); return requireValid(sealed); }
  putIdentity(record: WorkloadIdentityRecord): WorkloadIdentityRecord { const sealed = sealIdentityRecord<WorkloadIdentityRecord>(withoutDigest(record) as Omit<WorkloadIdentityRecord, 'recordDigest'>); this.identities.put(record.identityId, sealed); return requireValid(sealed); }
  putLease(record: SecretLeaseRecord): SecretLeaseRecord { const sealed = sealIdentityRecord<SecretLeaseRecord>(withoutDigest(record) as Omit<SecretLeaseRecord, 'recordDigest'>); this.leases.put(record.leaseId, sealed); return requireValid(sealed); }

  findAttestationByChallenge(challengeId: string): AttestationRecord | undefined {
    const match = this.attestations.scan((record) => record.challengeId === challengeId, 0, 2).records[0];
    return match === undefined ? undefined : requireValid(match);
  }
  scanChallenges(): AttestationChallengeRecord[] { return this.challenges.scan(() => true, 0, 10_000).records.map((record) => requireValid(record)); }
  scanAttestations(): AttestationRecord[] { return this.attestations.scan(() => true, 0, 10_000).records.map((record) => requireValid(record)); }
  scanIdentities(): WorkloadIdentityRecord[] { return this.identities.scan(() => true, 0, 10_000).records.map((record) => requireValid(record)); }
  scanLeases(): SecretLeaseRecord[] { return this.leases.scan(() => true, 0, 10_000).records.map((record) => requireValid(record)); }
}
