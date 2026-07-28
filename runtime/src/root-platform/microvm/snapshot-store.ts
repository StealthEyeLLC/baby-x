import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../../storage/record-store.ts';
import { MicrovmError } from './errors.ts';

export const SNAPSHOT_SCHEMA_VERSION = '1.0.0' as const;
export const POOL_SCHEMA_VERSION = '1.0.0' as const;
export type SnapshotStatus = 'CREATING' | 'READY' | 'FAILED' | 'REVOKED' | 'EXPIRED';
export type PoolStatus = 'HEALTHY' | 'DEGRADED' | 'FAILED' | 'EXPIRED';

export interface MicrovmSnapshotRecord extends JsonObject {
  schemaVersion: typeof SNAPSHOT_SCHEMA_VERSION;
  snapshotId: string;
  ownerPrincipal: string;
  status: SnapshotStatus;
  sequence: number;
  requestDigest: string;
  idempotencyKeyDigest: string;
  sourceVmId: string;
  sourceTransactionId: string;
  providerVersion: string;
  firecrackerDigest: string;
  cpuArchitecture: string;
  cpuFingerprint: string;
  kernelDigest: string;
  baseRootImageDigest: string;
  writableDiskDigest: string | null;
  memoryDigest: string | null;
  vmStateDigest: string | null;
  memoryPath: string;
  vmStatePath: string;
  diskPath: string;
  guestCid: number;
  vcpuCount: number;
  memoryMiB: number;
  skillBundleDigest: string;
  grantDigest: string;
  policyDigest: string;
  vsockResetRequired: true;
  networkResetRequired: true;
  rngReseedingRequired: true;
  vmGenIdHandling: 'FIRECRACKER_LOAD_UPDATES';
  credentialAbsence: {
    taskStateEmpty: boolean;
    guestTokenCleared: boolean;
    guestIdentityCleared: boolean;
    hostTokenAbsent: boolean;
    diskTokenAbsent: boolean;
    verifiedAt: string | null;
    verificationDigest: string | null;
  };
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  revokedAt: string | null;
  error: { code: string; message: string } | null;
  priorRecordDigest: string | null;
  recordDigest: string;
}

export interface PoolLease extends JsonObject {
  vmId: string;
  transactionId: string;
  ownerPrincipal: string;
  acquiredAt: string;
}

export interface MicrovmPoolRecord extends JsonObject {
  schemaVersion: typeof POOL_SCHEMA_VERSION;
  poolId: string;
  ownerPrincipal: string;
  snapshotId: string;
  sequence: number;
  status: PoolStatus;
  desiredWarmCount: number;
  maximumWarmCount: number;
  availableVmIds: string[];
  leases: PoolLease[];
  failedCount: number;
  generation: number;
  health: JsonObject;
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  priorRecordDigest: string | null;
  recordDigest: string;
}

interface SnapshotClaim extends JsonObject { snapshotId: string }
interface PoolClaim extends JsonObject { poolId: string }
interface PoolActionClaim extends JsonObject { action: 'RECONCILE' | 'ACQUIRE' | 'RELEASE'; poolId: string; vmId: string | null }

function unsigned<T extends JsonObject>(record: T, digestKey: string): JsonObject {
  const clone = { ...record } as Record<string, unknown>;
  delete clone[digestKey];
  return clone as JsonObject;
}

export function verifySnapshotRecord(record: MicrovmSnapshotRecord): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (record.schemaVersion !== SNAPSHOT_SCHEMA_VERSION) errors.push('schema version mismatch');
  if (!/^mvs_[a-f0-9]{32}$/u.test(record.snapshotId)) errors.push('snapshot identifier mismatch');
  if (!Number.isSafeInteger(record.sequence) || record.sequence < 1) errors.push('sequence mismatch');
  if (record.recordDigest !== sha256(canonicalize(unsigned(record, 'recordDigest')))) errors.push('record digest mismatch');
  return { valid: errors.length === 0, errors };
}

export function verifyPoolRecord(record: MicrovmPoolRecord): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (record.schemaVersion !== POOL_SCHEMA_VERSION) errors.push('schema version mismatch');
  if (!/^mvp_[a-f0-9]{32}$/u.test(record.poolId)) errors.push('pool identifier mismatch');
  if (!Number.isSafeInteger(record.sequence) || record.sequence < 1) errors.push('sequence mismatch');
  if (record.maximumWarmCount !== 1 || record.desiredWarmCount < 0 || record.desiredWarmCount > 1) errors.push('pool limit mismatch');
  if (record.recordDigest !== sha256(canonicalize(unsigned(record, 'recordDigest')))) errors.push('record digest mismatch');
  return { valid: errors.length === 0, errors };
}

export class SnapshotPoolStore {
  private readonly snapshots: DurableRecordStore<MicrovmSnapshotRecord>;
  private readonly pools: DurableRecordStore<MicrovmPoolRecord>;
  private readonly snapshotClaims: DurableClaimStore<SnapshotClaim>;
  private readonly poolClaims: DurableClaimStore<PoolClaim>;
  private readonly poolActionClaims: DurableClaimStore<PoolActionClaim>;
  private readonly now: () => string;

  constructor(stateRoot: string, options: { now?: () => string } = {}) {
    const root = join(stateRoot, 'root-platform', 'microvm');
    this.snapshots = new DurableRecordStore<MicrovmSnapshotRecord>(join(root, 'snapshots'));
    this.pools = new DurableRecordStore<MicrovmPoolRecord>(join(root, 'pools'));
    this.snapshotClaims = new DurableClaimStore<SnapshotClaim>(join(root, 'snapshot-idempotency'));
    this.poolClaims = new DurableClaimStore<PoolClaim>(join(root, 'pool-idempotency'));
    this.poolActionClaims = new DurableClaimStore<PoolActionClaim>(join(root, 'pool-action-idempotency'));
    this.now = options.now ?? (() => new Date().toISOString());
  }

  claimSnapshot(ownerPrincipal: string, idempotencyKey: string, requestDigest: string): { snapshotId: string; replayed: boolean } {
    const key = `${ownerPrincipal}:${idempotencyKey}`;
    const prior = this.snapshotClaims.get(key);
    if (prior !== undefined) {
      if (prior.requestDigest !== requestDigest) throw new MicrovmError('microvm_idempotency_conflict', 'idempotency key belongs to another snapshot request');
      return { snapshotId: prior.record.snapshotId, replayed: true };
    }
    const snapshotId = `mvs_${randomUUID().replaceAll('-', '')}`;
    const claim = this.snapshotClaims.claim(key, requestDigest, snapshotId, { snapshotId });
    if (claim.requestDigest !== requestDigest) throw new MicrovmError('microvm_idempotency_conflict', 'idempotency key belongs to another snapshot request');
    return { snapshotId: claim.record.snapshotId, replayed: false };
  }

  createSnapshot(record: MicrovmSnapshotRecord): void {
    const verification = verifySnapshotRecord(record);
    if (!verification.valid) throw new MicrovmError('microvm_ambiguous', 'snapshot record is invalid', { errors: verification.errors });
    if (!this.snapshots.create(record.snapshotId, record)) throw new MicrovmError('microvm_state_conflict', 'snapshot record already exists');
  }

  getSnapshot(snapshotId: string): MicrovmSnapshotRecord {
    let record: MicrovmSnapshotRecord;
    try { record = this.snapshots.get(snapshotId); }
    catch { throw new MicrovmError('microvm_not_found', `snapshot not found: ${snapshotId}`); }
    const verification = verifySnapshotRecord(record);
    if (!verification.valid) throw new MicrovmError('microvm_ambiguous', 'snapshot record integrity failed', { snapshotId, errors: verification.errors });
    return structuredClone(record);
  }

  transitionSnapshot(snapshotId: string, status: SnapshotStatus, patch: Partial<MicrovmSnapshotRecord>): MicrovmSnapshotRecord {
    const prior = this.getSnapshot(snapshotId);
    const base = { ...prior, ...structuredClone(patch), status, sequence: prior.sequence + 1, updatedAt: this.now(), priorRecordDigest: prior.recordDigest };
    const { recordDigest: _old, ...unsignedRecord } = base;
    const next = { ...unsignedRecord, recordDigest: sha256(canonicalize(unsignedRecord as JsonObject)) } as MicrovmSnapshotRecord;
    const verification = verifySnapshotRecord(next);
    if (!verification.valid) throw new MicrovmError('microvm_ambiguous', 'snapshot transition is invalid', { errors: verification.errors });
    this.snapshots.put(snapshotId, next);
    return structuredClone(next);
  }

  listSnapshots(ownerPrincipal: string): MicrovmSnapshotRecord[] {
    return this.snapshots.scan((record) => record.ownerPrincipal === ownerPrincipal, 0, 10_000).records.sort((a, b) => a.snapshotId.localeCompare(b.snapshotId)).map((record) => this.getSnapshot(record.snapshotId));
  }

  claimPool(ownerPrincipal: string, idempotencyKey: string, requestDigest: string): { poolId: string; replayed: boolean } {
    const key = `${ownerPrincipal}:${idempotencyKey}`;
    const prior = this.poolClaims.get(key);
    if (prior !== undefined) {
      if (prior.requestDigest !== requestDigest) throw new MicrovmError('microvm_idempotency_conflict', 'idempotency key belongs to another pool request');
      return { poolId: prior.record.poolId, replayed: true };
    }
    const poolId = `mvp_${randomUUID().replaceAll('-', '')}`;
    const claim = this.poolClaims.claim(key, requestDigest, poolId, { poolId });
    if (claim.requestDigest !== requestDigest) throw new MicrovmError('microvm_idempotency_conflict', 'idempotency key belongs to another pool request');
    return { poolId: claim.record.poolId, replayed: false };
  }

  getPoolAction(ownerPrincipal: string, idempotencyKey: string): { requestDigest: string; record: PoolActionClaim } | undefined {
    const claim = this.poolActionClaims.get(`${ownerPrincipal}:${idempotencyKey}`);
    if (claim === undefined) return undefined;
    return { requestDigest: claim.requestDigest, record: structuredClone(claim.record) };
  }

  claimPoolAction(ownerPrincipal: string, idempotencyKey: string, requestDigest: string, result: PoolActionClaim): PoolActionClaim {
    const claim = this.poolActionClaims.claim(`${ownerPrincipal}:${idempotencyKey}`, requestDigest, `${result.poolId}:${result.action}:${sha256(idempotencyKey).slice(0, 16)}`, result);
    if (claim.requestDigest !== requestDigest) throw new MicrovmError('microvm_idempotency_conflict', 'idempotency key belongs to another pool action');
    return structuredClone(claim.record);
  }

  createPool(record: MicrovmPoolRecord): void {
    const verification = verifyPoolRecord(record);
    if (!verification.valid) throw new MicrovmError('microvm_ambiguous', 'pool record is invalid', { errors: verification.errors });
    if (!this.pools.create(record.poolId, record)) throw new MicrovmError('microvm_state_conflict', 'pool record already exists');
  }

  getPool(poolId: string): MicrovmPoolRecord {
    let record: MicrovmPoolRecord;
    try { record = this.pools.get(poolId); }
    catch { throw new MicrovmError('microvm_not_found', `pool not found: ${poolId}`); }
    const verification = verifyPoolRecord(record);
    if (!verification.valid) throw new MicrovmError('microvm_ambiguous', 'pool record integrity failed', { poolId, errors: verification.errors });
    return structuredClone(record);
  }

  updatePool(poolId: string, patch: Partial<MicrovmPoolRecord>): MicrovmPoolRecord {
    const prior = this.getPool(poolId);
    const base = { ...prior, ...structuredClone(patch), sequence: prior.sequence + 1, updatedAt: this.now(), priorRecordDigest: prior.recordDigest };
    const { recordDigest: _old, ...unsignedRecord } = base;
    const next = { ...unsignedRecord, recordDigest: sha256(canonicalize(unsignedRecord as JsonObject)) } as MicrovmPoolRecord;
    const verification = verifyPoolRecord(next);
    if (!verification.valid) throw new MicrovmError('microvm_ambiguous', 'pool transition is invalid', { errors: verification.errors });
    this.pools.put(poolId, next);
    return structuredClone(next);
  }

  listPools(ownerPrincipal: string): MicrovmPoolRecord[] {
    return this.pools.scan((record) => record.ownerPrincipal === ownerPrincipal, 0, 10_000).records.sort((a, b) => a.poolId.localeCompare(b.poolId)).map((record) => this.getPool(record.poolId));
  }

  allPools(): MicrovmPoolRecord[] {
    return this.pools.scan(() => true, 0, 10_000).records.sort((a, b) => a.poolId.localeCompare(b.poolId)).map((record) => this.getPool(record.poolId));
  }

  verify(): JsonObject {
    const snapshotScan = this.snapshots.scan(() => true, 0, 10_000);
    const poolScan = this.pools.scan(() => true, 0, 10_000);
    const invalidSnapshots = snapshotScan.records.filter((record) => !verifySnapshotRecord(record).valid).map((record) => record.snapshotId);
    const invalidPools = poolScan.records.filter((record) => !verifyPoolRecord(record).valid).map((record) => record.poolId);
    return { ok: snapshotScan.corruptRecordIds.length === 0 && poolScan.corruptRecordIds.length === 0 && invalidSnapshots.length === 0 && invalidPools.length === 0, snapshots: snapshotScan.records.length, pools: poolScan.records.length, corruptSnapshotIds: snapshotScan.corruptRecordIds, corruptPoolIds: poolScan.corruptRecordIds, invalidSnapshots, invalidPools };
  }
}

export function initialSnapshotRecord(input: Omit<MicrovmSnapshotRecord, 'schemaVersion' | 'sequence' | 'status' | 'createdAt' | 'updatedAt' | 'priorRecordDigest' | 'recordDigest'> & { now: string }): MicrovmSnapshotRecord {
  const { now, ...values } = input;
  const base = { schemaVersion: SNAPSHOT_SCHEMA_VERSION, ...values, status: 'CREATING' as const, sequence: 1, createdAt: now, updatedAt: now, priorRecordDigest: null };
  return { ...base, recordDigest: sha256(canonicalize(base)) } as MicrovmSnapshotRecord;
}

export function initialPoolRecord(input: { poolId: string; ownerPrincipal: string; snapshotId: string; desiredWarmCount: number; expiresAt: string; now: string }): MicrovmPoolRecord {
  const base = { schemaVersion: POOL_SCHEMA_VERSION, poolId: input.poolId, ownerPrincipal: input.ownerPrincipal, snapshotId: input.snapshotId, sequence: 1, status: 'DEGRADED' as const, desiredWarmCount: input.desiredWarmCount, maximumWarmCount: 1, availableVmIds: [], leases: [], failedCount: 0, generation: 1, health: { ok: false, reason: 'not_reconciled', maximumWarmCountReason: 'firecracker_v1_15_snapshot_guest_cid_is_immutable' }, createdAt: input.now, updatedAt: input.now, expiresAt: input.expiresAt, priorRecordDigest: null };
  return { ...base, recordDigest: sha256(canonicalize(base)) } as MicrovmPoolRecord;
}
