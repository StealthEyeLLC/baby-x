import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../storage/record-store.ts';
import { RootPlatformError } from './errors.ts';
import type { ProviderDescriptor } from './schemas.ts';

export const PROVIDER_RECONCILIATION_SCHEMA_VERSION = '1.0.0' as const;

export interface ProviderReconciliationRecord extends JsonObject {
  schemaVersion: typeof PROVIDER_RECONCILIATION_SCHEMA_VERSION;
  reconciliationId: string;
  providerId: string;
  ownerPrincipal: string;
  sequence: number;
  requestDigest: string;
  idempotencyKeyDigest: string;
  priorRecordDigest: string | null;
  providerDescriptor: ProviderDescriptor;
  observedAt: string;
  recordDigest: string;
}

function withoutDigest(record: ProviderReconciliationRecord): JsonObject {
  const { recordDigest: _recordDigest, ...unsigned } = record;
  return unsigned;
}

export function verifyProviderReconciliationRecord(record: ProviderReconciliationRecord): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (record.schemaVersion !== PROVIDER_RECONCILIATION_SCHEMA_VERSION) errors.push('schema version mismatch');
  if (record.providerId !== record.providerDescriptor.providerId) errors.push('provider identity mismatch');
  if (!Number.isSafeInteger(record.sequence) || record.sequence < 1) errors.push('sequence is invalid');
  if (record.recordDigest !== sha256(canonicalize(withoutDigest(record)))) errors.push('record digest mismatch');
  return { valid: errors.length === 0, errors };
}

function principal(context: RuntimeExecutionContext): string {
  const value = context.subject ?? 'stealtheye-owner';
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(value)) throw new RootPlatformError('root_platform_invalid_request', 'owner principal is invalid');
  return value;
}

function idempotency(context: RuntimeExecutionContext): { key: string; digest: string } {
  const key = context.idempotencyKey;
  if (typeof key !== 'string' || key.length < 8 || key.length > 256 || key.includes('\0')) throw new RootPlatformError('root_platform_idempotency_required', 'a bounded idempotency key is required');
  return { key, digest: sha256(key) };
}

export class ProviderReconciliationStore {
  private readonly records: DurableRecordStore<ProviderReconciliationRecord>;
  private readonly claims: DurableClaimStore<ProviderReconciliationRecord>;
  private readonly now: () => string;

  constructor(stateRoot: string, options: { now?: () => string } = {}) {
    const root = join(stateRoot, 'root-platform', 'provider-reconciliations');
    this.records = new DurableRecordStore<ProviderReconciliationRecord>(join(root, 'history'));
    this.claims = new DurableClaimStore<ProviderReconciliationRecord>(join(root, 'idempotency'));
    this.now = options.now ?? (() => new Date().toISOString());
  }

  latest(providerId: string): ProviderReconciliationRecord | null {
    const records = this.records.scan((record) => record.providerId === providerId, 0, 10_000).records;
    return records.sort((left, right) => right.sequence - left.sequence)[0] ?? null;
  }

  reconcile(provider: ProviderDescriptor, context: RuntimeExecutionContext): ProviderReconciliationRecord {
    const ownerPrincipal = principal(context);
    const idem = idempotency(context);
    const normalizedRequest = { providerId: provider.providerId, descriptorDigest: provider.descriptorDigest };
    const requestDigest = sha256(canonicalize({ operation: 'babyx.root.provider.reconcile', ownerPrincipal, payload: normalizedRequest }));
    const prior = this.latest(provider.providerId);
    const candidateBase = {
      schemaVersion: PROVIDER_RECONCILIATION_SCHEMA_VERSION,
      reconciliationId: `prr_${randomUUID().replaceAll('-', '')}`,
      providerId: provider.providerId,
      ownerPrincipal,
      sequence: (prior?.sequence ?? 0) + 1,
      requestDigest,
      idempotencyKeyDigest: idem.digest,
      priorRecordDigest: prior?.recordDigest ?? null,
      providerDescriptor: structuredClone(provider),
      observedAt: this.now(),
    };
    const candidate = { ...candidateBase, recordDigest: sha256(canonicalize(candidateBase)) } as ProviderReconciliationRecord;
    const claimKey = `${ownerPrincipal}:${idem.key}`;
    const claimed = this.claims.claim(claimKey, requestDigest, candidate.reconciliationId, candidate);
    if (claimed.requestDigest !== requestDigest) throw new RootPlatformError('root_platform_idempotency_conflict', 'idempotency key already belongs to a different provider reconciliation', { providerId: provider.providerId });
    const record = claimed.record;
    const verification = verifyProviderReconciliationRecord(record);
    if (!verification.valid) throw new RootPlatformError('root_platform_integrity_failure', 'provider reconciliation claim is invalid', { errors: verification.errors });
    if (!this.records.has(claimed.recordId) && !this.records.create(claimed.recordId, record)) throw new RootPlatformError('root_platform_integrity_failure', 'provider reconciliation record could not be recovered');
    return structuredClone(record);
  }

  list(providerId: string | undefined, offset: number, limit: number): JsonObject {
    const scan = this.records.scan((record) => providerId === undefined || record.providerId === providerId, offset, limit);
    return { reconciliations: scan.records, offset, limit, total: scan.total, nextOffset: scan.nextOffset, corruptRecordIds: scan.corruptRecordIds };
  }
}
