import { closeSync, constants, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { randomUUID } from 'node:crypto';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../storage/record-store.ts';
import { SecretProvider } from '../secrets/provider.ts';
import { RootFabricError, contextPrincipal, digest, idempotency, identifier, integer, strictObject, text, timestamp, type RootExecutionProvider } from './model.ts';

export const ROOT_CREDENTIAL_SCHEMA_VERSION = '1.0.0' as const;
export type RootCredentialState = 'REQUESTED' | 'AUTHORIZED' | 'LEASED' | 'DELIVERED' | 'REVOKED' | 'EXPIRED' | 'CLEANED' | 'FAILED';

export interface RootCredentialLease extends JsonObject {
  schemaVersion: typeof ROOT_CREDENTIAL_SCHEMA_VERSION;
  leaseId: string;
  credentialReference: string;
  provider: RootExecutionProvider;
  skillBundleDigest: string;
  grantDigest: string;
  transactionId: string;
  stepId: string;
  principalDigest: string;
  targetType: 'UNIT' | 'MACHINE';
  targetId: string;
  purpose: string;
  issuedAt: string;
  expiresAt: string;
  maximumTtlMs: number;
  revocationBehavior: 'FREEZE' | 'CANCEL_AND_ROLLBACK' | 'ALLOW_TO_FINISH';
  state: RootCredentialState;
  deliveredAt: string | null;
  deliveryPath: string | null;
  revokedAt: string | null;
  cleanedAt: string | null;
  metadataDigest: string;
  eventSequence: number;
  eventHeadDigest: string | null;
  events: RootCredentialEvent[];
  recordDigest: string;
}

export interface RootCredentialEvent extends JsonObject {
  sequence: number;
  operation: string;
  priorState: RootCredentialState | null;
  nextState: RootCredentialState;
  occurredAt: string;
  requestDigest: string;
  previousEventDigest: string | null;
  eventDigest: string;
}

const SECRET_KEY = /(?:secret|token|password|private.?key|cookie|authorization|credential|bearer|connection.?string)/iu;
const TERMINAL = new Set<RootCredentialState>(['REVOKED', 'EXPIRED', 'CLEANED', 'FAILED']);

function unsigned(record: RootCredentialLease): JsonObject {
  const { recordDigest: _recordDigest, ...rest } = record;
  return rest;
}
function eventUnsigned(event: RootCredentialEvent): JsonObject {
  const { eventDigest: _eventDigest, ...rest } = event;
  return rest;
}
function seal(record: Omit<RootCredentialLease, 'recordDigest'>): RootCredentialLease {
  return { ...record, recordDigest: sha256(canonicalize(record)) };
}
function verify(record: RootCredentialLease): boolean {
  if (record.recordDigest !== sha256(canonicalize(unsigned(record)))) return false;
  let previous: string | null = null;
  let previousState: RootCredentialState | null = null;
  for (let index = 0; index < record.events.length; index += 1) {
    const event = record.events[index]!;
    if (event.sequence !== index + 1 || event.previousEventDigest !== previous || event.priorState !== previousState || event.eventDigest !== sha256(canonicalize(eventUnsigned(event)))) return false;
    previous = event.eventDigest;
    previousState = event.nextState;
  }
  return record.eventSequence === record.events.length && record.eventHeadDigest === previous && record.state === previousState;
}

function append(record: RootCredentialLease | null, operation: string, nextState: RootCredentialState, occurredAt: string, requestDigest: string, patch: JsonObject): RootCredentialLease {
  const sequence = (record?.eventSequence ?? 0) + 1;
  const eventBase = { sequence, operation, priorState: record?.state ?? null, nextState, occurredAt, requestDigest, previousEventDigest: record?.eventHeadDigest ?? null };
  const event: RootCredentialEvent = { ...eventBase, eventDigest: sha256(canonicalize(eventBase)) };
  const base = record === null ? patch : { ...unsigned(record), ...patch };
  return seal({ ...base, state: nextState, eventSequence: sequence, eventHeadDigest: event.eventDigest, events: [...(record?.events ?? []), event] } as Omit<RootCredentialLease, 'recordDigest'>);
}

function confinedDeliveryRoot(rootValue: string): string {
  if (!isAbsolute(rootValue)) throw new RootFabricError('credential_delivery_failed', 'credential delivery root must be absolute');
  mkdirSync(rootValue, { recursive: true, mode: 0o700 });
  const root = realpathSync(rootValue);
  const info = statSync(root);
  if (!info.isDirectory() || (info.mode & 0o077) !== 0) throw new RootFabricError('credential_delivery_failed', 'credential delivery root permissions are not private');
  return root;
}

function safeLeasePath(root: string, leaseId: string): string {
  const candidate = resolve(root, leaseId, 'credential');
  const rel = relative(root, candidate);
  if (rel === '' || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new RootFabricError('credential_delivery_failed', 'credential delivery path escapes the delivery root');
  return candidate;
}

function requestDigest(operation: string, principalDigest: string, payload: JsonObject): string {
  return sha256(canonicalize({ operation, principalDigest, payload }));
}

export function redactSecrets(value: unknown, key = ''): unknown {
  if (SECRET_KEY.test(key)) return '[REDACTED]';
  if (typeof value === 'string') {
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/u.test(value)) return '[REDACTED]';
    if (/^(?:Bearer\s+)?[A-Za-z0-9_./+=:-]{32,}$/u.test(value)) return '[REDACTED]';
    if (/^[a-z][a-z0-9+.-]*:\/\/[^\s/:]+:[^\s/@]+@/iu.test(value)) return '[REDACTED]';
    return value;
  }
  if (Array.isArray(value)) return value.map((entry) => redactSecrets(entry, key));
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([childKey, child]) => [childKey, redactSecrets(child, childKey)]));
  return value;
}

export class RootCredentialService {
  private readonly records: DurableRecordStore<RootCredentialLease>;
  private readonly claims: DurableClaimStore<RootCredentialLease>;
  private readonly deliveryRoot: string;
  private readonly now: () => string;

  constructor(stateRoot: string, private readonly secrets: SecretProvider = new SecretProvider(), options: { deliveryRoot?: string; now?: () => string } = {}) {
    const root = join(stateRoot, 'root-fabric', 'credentials');
    this.records = new DurableRecordStore(join(root, 'leases'));
    this.claims = new DurableClaimStore(join(root, 'claims'));
    this.deliveryRoot = confinedDeliveryRoot(options.deliveryRoot ?? '/run/baby-x/root-credentials');
    this.now = options.now ?? (() => new Date().toISOString());
  }

  lease(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'credential lease payload', ['credentialReference', 'provider', 'skillBundleDigest', 'grantDigest', 'transactionId', 'stepId', 'targetType', 'targetId', 'purpose', 'expiresAt', 'maximumTtlMs', 'transactionDeadline', 'operationDeadline', 'revocationBehavior', 'authorized']);
    const occurredAt = this.now();
    const principal = contextPrincipal(context, occurredAt);
    const idem = idempotency(context);
    const provider = text(payload.provider, 'provider', 32);
    if (provider !== 'HOST_ENVELOPE' && provider !== 'DISPOSABLE_MACHINE') throw new RootFabricError('unsupported_provider', 'credential provider binding is unsupported');
    const targetType = text(payload.targetType, 'targetType', 16);
    if (targetType !== 'UNIT' && targetType !== 'MACHINE') throw new RootFabricError('invalid_request', 'targetType must be UNIT or MACHINE');
    const revocationBehavior = text(payload.revocationBehavior, 'revocationBehavior', 32);
    if (!['FREEZE', 'CANCEL_AND_ROLLBACK', 'ALLOW_TO_FINISH'].includes(revocationBehavior)) throw new RootFabricError('invalid_request', 'revocationBehavior is invalid');
    if (payload.authorized !== true) throw new RootFabricError('policy_denied', 'credential lease requires an explicit authorization decision');
    const expiresAt = timestamp(payload.expiresAt, 'expiresAt');
    const transactionDeadline = timestamp(payload.transactionDeadline, 'transactionDeadline');
    const operationDeadline = timestamp(payload.operationDeadline, 'operationDeadline');
    const maximumTtlMs = integer(payload.maximumTtlMs, 'maximumTtlMs', 1_000, 3_600_000);
    const maximumExpiry = Math.min(Date.parse(transactionDeadline), Date.parse(operationDeadline), Date.parse(occurredAt) + maximumTtlMs);
    if (Date.parse(expiresAt) > maximumExpiry || Date.parse(expiresAt) <= Date.parse(occurredAt)) throw new RootFabricError('credential_unavailable', 'credential lease expiry exceeds its transaction, operation, or provider bound');
    const normalized = {
      credentialReference: text(payload.credentialReference, 'credentialReference', 4_096), provider: provider as RootExecutionProvider,
      skillBundleDigest: digest(payload.skillBundleDigest, 'skillBundleDigest'), grantDigest: digest(payload.grantDigest, 'grantDigest'),
      transactionId: identifier(payload.transactionId, 'transactionId'), stepId: identifier(payload.stepId, 'stepId'),
      targetType: targetType as 'UNIT' | 'MACHINE', targetId: identifier(payload.targetId, 'targetId'), purpose: text(payload.purpose, 'purpose', 512),
      expiresAt, maximumTtlMs, revocationBehavior: revocationBehavior as RootCredentialLease['revocationBehavior'],
    };
    const request = requestDigest('babyx.root.credential.lease', principal.principalDigest, normalized);
    const claimKey = `${principal.principalDigest}:${idem.key}`;
    const existing = this.claims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another credential lease');
      if (!this.records.has(existing.recordId)) this.records.create(existing.recordId, existing.record);
      return { lease: this.records.get(existing.recordId), replayed: true };
    }
    const leaseId = `crl_${randomUUID().replaceAll('-', '')}`;
    const metadata = { ...normalized, leaseId, principalDigest: principal.principalDigest, issuedAt: occurredAt };
    const requested = append(null, 'babyx.root.credential.lease', 'REQUESTED', occurredAt, request, {
      schemaVersion: ROOT_CREDENTIAL_SCHEMA_VERSION, leaseId, ...normalized, principalDigest: principal.principalDigest, issuedAt: occurredAt,
      state: 'REQUESTED', deliveredAt: null, deliveryPath: null, revokedAt: null, cleanedAt: null, metadataDigest: sha256(canonicalize(metadata)),
      eventSequence: 0, eventHeadDigest: null, events: [],
    });
    const authorized = append(requested, 'babyx.root.credential.authorize', 'AUTHORIZED', occurredAt, request, {});
    const leased = append(authorized, 'babyx.root.credential.lease', 'LEASED', occurredAt, request, {});
    const claim = this.claims.claim(claimKey, request, leaseId, leased);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another credential lease');
    if (!this.records.has(claim.recordId)) this.records.create(claim.recordId, claim.record);
    return { lease: this.records.get(claim.recordId), replayed: claim.recordId !== leaseId };
  }

  deliver(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'credential deliver payload', ['leaseId', 'transactionId', 'stepId', 'skillBundleDigest', 'grantDigest', 'targetType', 'targetId']);
    const principal = contextPrincipal(context, this.now());
    const record = this.read(identifier(payload.leaseId, 'leaseId'));
    this.assertBinding(record, payload, principal.principalDigest);
    if (record.state === 'DELIVERED') return { lease: record, deliveryPath: record.deliveryPath, replayed: true };
    if (record.state !== 'LEASED') throw new RootFabricError('credential_delivery_failed', `credential lease state ${record.state} cannot be delivered`);
    if (Date.parse(record.expiresAt) <= Date.parse(this.now())) return { lease: this.expire(record), deliveryPath: null, replayed: false };
    const secret = this.secrets.read(record.credentialReference);
    const path = safeLeasePath(this.deliveryRoot, record.leaseId);
    const directory = dirname(path);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const directoryInfo = lstatSync(directory);
    if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink() || (directoryInfo.mode & 0o077) !== 0) throw new RootFabricError('credential_delivery_failed', 'credential delivery directory is not private');
    const fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o400);
    try { writeFileSync(fd, secret); fsyncSync(fd); } finally { closeSync(fd); secret.fill(0); }
    const info = lstatSync(path);
    if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077) !== 0) throw new RootFabricError('credential_delivery_failed', 'credential delivery file is not private');
    const occurredAt = this.now();
    const request = requestDigest('babyx.root.credential.deliver', principal.principalDigest, payload);
    const next = append(record, 'babyx.root.credential.deliver', 'DELIVERED', occurredAt, request, { deliveredAt: occurredAt, deliveryPath: path });
    this.records.put(record.leaseId, next);
    return { lease: next, deliveryPath: path, replayed: false };
  }

  get(payloadValue: unknown): JsonObject {
    const payload = strictObject(payloadValue, 'credential get payload', ['leaseId']);
    return { lease: this.refresh(this.read(identifier(payload.leaseId, 'leaseId'))) };
  }

  list(payloadValue: unknown): JsonObject {
    const payload = strictObject(payloadValue ?? {}, 'credential list payload', ['state', 'transactionId', 'offset', 'limit']);
    const state = payload.state === undefined ? undefined : text(payload.state, 'state', 32) as RootCredentialState;
    const transactionId = payload.transactionId === undefined ? undefined : identifier(payload.transactionId, 'transactionId');
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, 10_000_000);
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, 200);
    const scan = this.records.scan((record) => (state === undefined || this.refresh(record).state === state) && (transactionId === undefined || record.transactionId === transactionId), offset, limit);
    return { leases: scan.records.filter(verify).map((record) => this.refresh(record)), offset, limit, total: scan.total, nextOffset: scan.nextOffset, corruptRecordIds: scan.corruptRecordIds };
  }

  revoke(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'credential revoke payload', ['leaseId', 'reason']);
    const principal = contextPrincipal(context, this.now());
    const record = this.read(identifier(payload.leaseId, 'leaseId'));
    if (record.principalDigest !== principal.principalDigest) throw new RootFabricError('principal_mismatch', 'credential lease principal mismatch');
    if (record.state === 'REVOKED' || record.state === 'CLEANED') return { lease: record, replayed: true };
    const occurredAt = this.now();
    const next = append(record, 'babyx.root.credential.revoke', 'REVOKED', occurredAt, requestDigest('babyx.root.credential.revoke', principal.principalDigest, payload), { revokedAt: occurredAt, revocationReason: text(payload.reason, 'reason', 1_024) });
    this.records.put(record.leaseId, next);
    return { lease: this.cleanRecord(next, principal.principalDigest, 'revocation cleanup'), replayed: false };
  }

  clean(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'credential clean payload', ['leaseId', 'reason']);
    const principal = contextPrincipal(context, this.now());
    const record = this.read(identifier(payload.leaseId, 'leaseId'));
    if (record.principalDigest !== principal.principalDigest) throw new RootFabricError('principal_mismatch', 'credential lease principal mismatch');
    return { lease: this.cleanRecord(record, principal.principalDigest, text(payload.reason ?? 'credential cleanup', 'reason', 1_024)), replayed: record.state === 'CLEANED' };
  }

  active(limit = 4_096): RootCredentialLease[] {
    return this.records.scan((record) => !TERMINAL.has(this.refresh(record).state), 0, limit).records.filter(verify).map((record) => this.refresh(record));
  }

  recover(): JsonObject {
    let expired = 0; let cleaned = 0; const failures: string[] = [];
    for (const record of this.records.scan(() => true, 0, 10_000).records) {
      try {
        const refreshed = this.refresh(record);
        if (refreshed.state === 'EXPIRED') expired += 1;
        if (['REVOKED', 'EXPIRED', 'FAILED'].includes(refreshed.state) && refreshed.state !== 'CLEANED') { this.cleanRecord(refreshed, refreshed.principalDigest, 'startup recovery cleanup'); cleaned += 1; }
      } catch (error) { failures.push(`${record.leaseId}:${error instanceof Error ? error.message : 'unknown error'}`); }
    }
    return { expired, cleaned, failures, ok: failures.length === 0 };
  }

  verifyNoSecretMaterial(value: unknown): boolean {
    const serialized = canonicalize(value);
    return !/-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer\s+[A-Za-z0-9_=-]{16,}|(?:password|token|secret)\s*[:=]\s*[^\s,}]+/iu.test(serialized);
  }

  private assertBinding(record: RootCredentialLease, payload: JsonObject, principalDigest: string): void {
    if (record.principalDigest !== principalDigest || record.transactionId !== payload.transactionId || record.stepId !== payload.stepId || record.skillBundleDigest !== payload.skillBundleDigest || record.grantDigest !== payload.grantDigest || record.targetType !== payload.targetType || record.targetId !== payload.targetId) throw new RootFabricError('principal_mismatch', 'credential lease binding mismatch');
  }

  private refresh(record: RootCredentialLease): RootCredentialLease {
    if (!verify(record)) throw new RootFabricError('corrupt_record', 'credential lease integrity failed');
    if (!TERMINAL.has(record.state) && Date.parse(record.expiresAt) <= Date.parse(this.now())) return this.expire(record);
    return record;
  }

  private expire(record: RootCredentialLease): RootCredentialLease {
    if (record.state === 'EXPIRED' || record.state === 'CLEANED') return record;
    const occurredAt = this.now();
    const next = append(record, 'babyx.root.credential.expire', 'EXPIRED', occurredAt, sha256(canonicalize({ leaseId: record.leaseId, expiresAt: record.expiresAt })), {});
    this.records.put(record.leaseId, next);
    return next;
  }

  private cleanRecord(record: RootCredentialLease, principalDigest: string, reason: string): RootCredentialLease {
    if (record.state === 'CLEANED') return record;
    if (record.deliveryPath !== null) {
      const expected = safeLeasePath(this.deliveryRoot, record.leaseId);
      if (record.deliveryPath !== expected) throw new RootFabricError('cleanup_failed', 'credential delivery path does not match the lease identity');
      rmSync(dirname(expected), { recursive: true, force: true });
      if (existsSync(expected) || existsSync(dirname(expected))) throw new RootFabricError('cleanup_failed', 'credential delivery path remains after cleanup');
    }
    const occurredAt = this.now();
    const next = append(record, 'babyx.root.credential.clean', 'CLEANED', occurredAt, requestDigest('babyx.root.credential.clean', principalDigest, { leaseId: record.leaseId, reason }), { cleanedAt: occurredAt, deliveryPath: null });
    this.records.put(record.leaseId, next);
    return next;
  }

  private read(leaseId: string): RootCredentialLease {
    try { const record = this.records.get(leaseId); if (!verify(record)) throw new RootFabricError('corrupt_record', 'credential lease integrity failed'); return record; }
    catch (error) { if (error instanceof RootFabricError) throw error; throw new RootFabricError('credential_unavailable', 'credential lease not found', { leaseId }); }
  }
}
