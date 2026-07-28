import { randomUUID } from 'node:crypto';
import { closeSync, constants, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../storage/record-store.ts';
import { SecretProvider } from '../secrets/provider.ts';
import { RootFabricError, contextPrincipal, digest, idempotency, identifier, integer, strictObject, text, timestamp, type RootExecutionProvider } from './model.ts';

export const ROOT_CREDENTIAL_SCHEMA_VERSION = '1.1.0' as const;
export type RootCredentialState = 'REQUESTED' | 'AUTHORIZED' | 'LEASED' | 'DELIVERED' | 'REVOKED' | 'EXPIRED' | 'CLEANED' | 'FAILED';
export type RootCredentialRevocationBehavior = 'FREEZE' | 'CANCEL_AND_ROLLBACK' | 'ALLOW_TO_FINISH';

export interface CredentialAuthorizationBinding extends JsonObject {
  transactionId: string;
  stepId: string;
  ownerPrincipalId: string;
  ownerPrincipalDigest: string;
  credentialReference: string;
  provider: RootExecutionProvider;
  providerId: string;
  providerVersion: string;
  providerProfileDigest: string;
  skillBundleDigest: string;
  grantId: string;
  grantDigest: string;
  policyDecisionDigest: string;
  policyVersion: string;
  transactionSequence: number;
  fencingToken: number;
  targetType: 'UNIT' | 'MACHINE';
  targetId: string;
  purpose: string;
  transactionDeadline: string;
  operationDeadline: string;
  maximumTtlMs: number;
  revocationBehavior: RootCredentialRevocationBehavior;
  authorizationDigest: string;
}

export interface CredentialAuthority {
  resolve(input: { transactionId: string; stepId: string; credentialReference: string; principalId: string; principalDigest: string; occurredAt: string }): CredentialAuthorizationBinding;
  assertCurrent(lease: RootCredentialLease, input: { principalId: string; principalDigest: string; occurredAt: string }): void;
}

export interface RootCredentialLease extends JsonObject {
  schemaVersion: typeof ROOT_CREDENTIAL_SCHEMA_VERSION;
  leaseId: string;
  credentialReference: string;
  provider: RootExecutionProvider;
  providerId: string;
  providerVersion: string;
  providerProfileDigest: string;
  skillBundleDigest: string;
  grantId: string;
  grantDigest: string;
  policyDecisionDigest: string;
  policyVersion: string;
  transactionId: string;
  stepId: string;
  transactionSequence: number;
  fencingToken: number;
  ownerPrincipalId: string;
  principalDigest: string;
  targetType: 'UNIT' | 'MACHINE';
  targetId: string;
  purpose: string;
  transactionDeadline: string;
  operationDeadline: string;
  authorizationDigest: string;
  issuedAt: string;
  expiresAt: string;
  maximumTtlMs: number;
  revocationBehavior: RootCredentialRevocationBehavior;
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

interface CredentialMutationResult extends JsonObject {
  schemaVersion: '1.0.0';
  operation: 'DELIVER' | 'REVOKE' | 'CLEAN';
  leaseId: string;
  principalDigest: string;
  requestDigest: string;
  priorRecordDigest: string;
  next: RootCredentialLease;
  cleanupPath: string | null;
  resultDigest: string;
}

const TERMINAL = new Set<RootCredentialState>(['REVOKED', 'EXPIRED', 'CLEANED', 'FAILED']);
const DENY_CREDENTIAL_AUTHORITY: CredentialAuthority = {
  resolve() { throw new RootFabricError('credential_unavailable', 'authoritative credential binding is unavailable'); },
  assertCurrent() { throw new RootFabricError('credential_unavailable', 'authoritative credential binding is unavailable'); },
};

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
  if (record.schemaVersion !== ROOT_CREDENTIAL_SCHEMA_VERSION || record.recordDigest !== sha256(canonicalize(unsigned(record)))) return false;
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
function append(record: RootCredentialLease | null, operation: string, nextState: RootCredentialState, occurredAt: string, requestDigestValue: string, patch: JsonObject): RootCredentialLease {
  const sequence = (record?.eventSequence ?? 0) + 1;
  const eventBase = { sequence, operation, priorState: record?.state ?? null, nextState, occurredAt, requestDigest: requestDigestValue, previousEventDigest: record?.eventHeadDigest ?? null };
  const event: RootCredentialEvent = { ...eventBase, eventDigest: sha256(canonicalize(eventBase)) };
  const base = record === null ? patch : { ...unsigned(record), ...patch };
  return seal({ ...base, state: nextState, eventSequence: sequence, eventHeadDigest: event.eventDigest, events: [...(record?.events ?? []), event] } as Omit<RootCredentialLease, 'recordDigest'>);
}
function mutationUnsigned(result: CredentialMutationResult): JsonObject {
  const { resultDigest: _resultDigest, ...rest } = result;
  return rest;
}
function sealMutation(result: Omit<CredentialMutationResult, 'resultDigest'>): CredentialMutationResult {
  return { ...result, resultDigest: sha256(canonicalize(result)) };
}
function verifyMutation(result: CredentialMutationResult): boolean {
  return result.schemaVersion === '1.0.0' && result.resultDigest === sha256(canonicalize(mutationUnsigned(result))) && verify(result.next);
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
  const secretKey = /(?:secret|token|password|private.?key|cookie|authorization|credential|bearer|connection.?string)/iu;
  if (secretKey.test(key)) return '[REDACTED]';
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
  private readonly leaseClaims: DurableClaimStore<RootCredentialLease>;
  private readonly mutationClaims: DurableClaimStore<CredentialMutationResult>;
  private readonly deliveryRoot: string;
  private readonly now: () => string;
  private readonly authority: CredentialAuthority;

  constructor(stateRoot: string, private readonly secrets: SecretProvider = new SecretProvider(), options: { deliveryRoot?: string; now?: () => string; authority?: CredentialAuthority } = {}) {
    const root = join(stateRoot, 'root-fabric', 'credentials');
    this.records = new DurableRecordStore(join(root, 'leases'));
    this.leaseClaims = new DurableClaimStore(join(root, 'claims'));
    this.mutationClaims = new DurableClaimStore(join(root, 'mutation-claims'));
    this.deliveryRoot = confinedDeliveryRoot(options.deliveryRoot ?? '/run/baby-x/root-credentials');
    this.now = options.now ?? (() => new Date().toISOString());
    this.authority = options.authority ?? DENY_CREDENTIAL_AUTHORITY;
  }

  lease(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'credential lease payload', ['credentialReference', 'transactionId', 'stepId', 'requestedTtlMs']);
    const occurredAt = this.now();
    const principal = contextPrincipal(context, occurredAt);
    const idem = idempotency(context);
    const credentialReference = text(payload.credentialReference, 'credentialReference', 4_096);
    const transactionId = identifier(payload.transactionId, 'transactionId');
    const stepId = identifier(payload.stepId, 'stepId');
    const binding = this.authority.resolve({ transactionId, stepId, credentialReference, principalId: principal.principalId, principalDigest: principal.principalDigest, occurredAt });
    this.assertResolvedBinding(binding, { transactionId, stepId, credentialReference, principalId: principal.principalId, principalDigest: principal.principalDigest });
    const requestedTtlMs = integer(payload.requestedTtlMs ?? 60_000, 'requestedTtlMs', 1_000, 3_600_000);
    const maximumTtlMs = integer(binding.maximumTtlMs, 'maximumTtlMs', 1_000, 3_600_000);
    const maximumExpiry = Math.min(Date.parse(binding.transactionDeadline), Date.parse(binding.operationDeadline), Date.parse(occurredAt) + maximumTtlMs, Date.parse(occurredAt) + requestedTtlMs);
    if (!Number.isFinite(maximumExpiry) || maximumExpiry <= Date.parse(occurredAt)) throw new RootFabricError('credential_unavailable', 'credential lease has no valid authoritative lifetime');
    const expiresAt = new Date(maximumExpiry).toISOString();
    const normalized = {
      credentialReference,
      provider: binding.provider,
      providerId: identifier(binding.providerId, 'providerId'),
      providerVersion: text(binding.providerVersion, 'providerVersion', 64),
      providerProfileDigest: digest(binding.providerProfileDigest, 'providerProfileDigest'),
      skillBundleDigest: digest(binding.skillBundleDigest, 'skillBundleDigest'),
      grantId: identifier(binding.grantId, 'grantId'),
      grantDigest: digest(binding.grantDigest, 'grantDigest'),
      policyDecisionDigest: digest(binding.policyDecisionDigest, 'policyDecisionDigest'),
      policyVersion: text(binding.policyVersion, 'policyVersion', 64),
      transactionId,
      stepId,
      transactionSequence: integer(binding.transactionSequence, 'transactionSequence', 1, 10_000_000),
      fencingToken: integer(binding.fencingToken, 'fencingToken', 1, Number.MAX_SAFE_INTEGER),
      ownerPrincipalId: identifier(binding.ownerPrincipalId, 'ownerPrincipalId'),
      targetType: binding.targetType,
      targetId: identifier(binding.targetId, 'targetId'),
      purpose: text(binding.purpose, 'purpose', 512),
      transactionDeadline: timestamp(binding.transactionDeadline, 'transactionDeadline'),
      operationDeadline: timestamp(binding.operationDeadline, 'operationDeadline'),
      authorizationDigest: digest(binding.authorizationDigest, 'authorizationDigest'),
      expiresAt,
      maximumTtlMs,
      revocationBehavior: binding.revocationBehavior,
    };
    const request = requestDigest('babyx.root.credential.lease', principal.principalDigest, normalized);
    const claimKey = `${principal.principalDigest}:${idem.key}`;
    const existing = this.leaseClaims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another credential lease');
      if (!this.records.has(existing.recordId)) this.records.create(existing.recordId, existing.record);
      return { lease: this.refresh(this.records.get(existing.recordId)), replayed: true };
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
    const claim = this.leaseClaims.claim(claimKey, request, leaseId, leased);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another credential lease');
    if (!this.records.has(claim.recordId)) this.records.create(claim.recordId, claim.record);
    return { lease: this.refresh(this.records.get(claim.recordId)), replayed: claim.recordId !== leaseId };
  }

  deliver(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'credential deliver payload', ['leaseId']);
    const occurredAt = this.now();
    const principal = contextPrincipal(context, occurredAt);
    const idem = idempotency(context);
    const record = this.read(identifier(payload.leaseId, 'leaseId'));
    this.assertOwner(record, principal.principalId, principal.principalDigest);
    this.authority.assertCurrent(record, { principalId: principal.principalId, principalDigest: principal.principalDigest, occurredAt });
    const request = requestDigest('babyx.root.credential.deliver', principal.principalDigest, { leaseId: record.leaseId });
    const claimKey = `${record.leaseId}:deliver:${principal.principalDigest}:${idem.digest}`;
    const existing = this.mutationClaims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another credential delivery');
      const recovered = this.recoverMutation(existing.record);
      return { lease: recovered, deliveryPath: recovered.deliveryPath, replayed: true };
    }
    if (record.state !== 'LEASED') {
      if (record.state === 'DELIVERED') return { lease: record, deliveryPath: record.deliveryPath, replayed: true };
      throw new RootFabricError('credential_delivery_failed', `credential lease state ${record.state} cannot be delivered`);
    }
    if (Date.parse(record.expiresAt) <= Date.parse(occurredAt)) return { lease: this.expire(record), deliveryPath: null, replayed: false };
    const path = safeLeasePath(this.deliveryRoot, record.leaseId);
    if (existsSync(path) || existsSync(dirname(path))) throw new RootFabricError('credential_delivery_failed', 'credential delivery path already exists without a durable delivery claim');
    const next = append(record, 'babyx.root.credential.deliver', 'DELIVERED', occurredAt, request, { deliveredAt: occurredAt, deliveryPath: path });
    const result = sealMutation({ schemaVersion: '1.0.0', operation: 'DELIVER', leaseId: record.leaseId, principalDigest: principal.principalDigest, requestDigest: request, priorRecordDigest: record.recordDigest, next, cleanupPath: null });
    const claim = this.mutationClaims.claim(claimKey, request, record.leaseId, result);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another credential delivery');
    const recovered = this.recoverMutation(claim.record);
    return { lease: recovered, deliveryPath: recovered.deliveryPath, replayed: false };
  }

  get(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'credential get payload', ['leaseId']);
    const principal = contextPrincipal(context, this.now());
    const lease = this.refresh(this.read(identifier(payload.leaseId, 'leaseId')));
    this.assertOwner(lease, principal.principalId, principal.principalDigest);
    return { lease };
  }

  list(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue ?? {}, 'credential list payload', ['state', 'transactionId', 'offset', 'limit']);
    const principal = contextPrincipal(context, this.now());
    const state = payload.state === undefined ? undefined : text(payload.state, 'state', 32) as RootCredentialState;
    const transactionId = payload.transactionId === undefined ? undefined : identifier(payload.transactionId, 'transactionId');
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, 10_000_000);
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, 200);
    const scan = this.records.scan((record) => record.principalDigest === principal.principalDigest && (state === undefined || this.refresh(record).state === state) && (transactionId === undefined || record.transactionId === transactionId), offset, limit);
    return { leases: scan.records.filter(verify).map((record) => this.refresh(record)), offset, limit, total: scan.total, nextOffset: scan.nextOffset, corruptRecordIds: scan.corruptRecordIds };
  }

  revoke(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'credential revoke payload', ['leaseId', 'reason']);
    const occurredAt = this.now();
    const principal = contextPrincipal(context, occurredAt);
    const idem = idempotency(context);
    const record = this.read(identifier(payload.leaseId, 'leaseId'));
    this.assertOwner(record, principal.principalId, principal.principalDigest);
    const reason = text(payload.reason, 'reason', 1_024);
    const request = requestDigest('babyx.root.credential.revoke', principal.principalDigest, { leaseId: record.leaseId, reason });
    const claimKey = `${record.leaseId}:revoke:${principal.principalDigest}:${idem.digest}`;
    const existing = this.mutationClaims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another credential revocation');
      return { lease: this.recoverMutation(existing.record), replayed: true };
    }
    const revoked = record.state === 'REVOKED' || record.state === 'CLEANED' ? record : append(record, 'babyx.root.credential.revoke', 'REVOKED', occurredAt, request, { revokedAt: occurredAt, revocationReason: reason });
    const next = revoked.state === 'CLEANED' ? revoked : append(revoked, 'babyx.root.credential.clean', 'CLEANED', occurredAt, request, { cleanedAt: occurredAt, deliveryPath: null });
    const result = sealMutation({ schemaVersion: '1.0.0', operation: 'REVOKE', leaseId: record.leaseId, principalDigest: principal.principalDigest, requestDigest: request, priorRecordDigest: record.recordDigest, next, cleanupPath: record.deliveryPath });
    const claim = this.mutationClaims.claim(claimKey, request, record.leaseId, result);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another credential revocation');
    return { lease: this.recoverMutation(claim.record), replayed: false };
  }

  clean(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'credential clean payload', ['leaseId', 'reason']);
    const occurredAt = this.now();
    const principal = contextPrincipal(context, occurredAt);
    const idem = idempotency(context);
    const record = this.read(identifier(payload.leaseId, 'leaseId'));
    this.assertOwner(record, principal.principalId, principal.principalDigest);
    const reason = text(payload.reason ?? 'credential cleanup', 'reason', 1_024);
    const request = requestDigest('babyx.root.credential.clean', principal.principalDigest, { leaseId: record.leaseId, reason });
    const claimKey = `${record.leaseId}:clean:${principal.principalDigest}:${idem.digest}`;
    const existing = this.mutationClaims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another credential cleanup');
      return { lease: this.recoverMutation(existing.record), replayed: true };
    }
    const next = record.state === 'CLEANED' ? record : append(record, 'babyx.root.credential.clean', 'CLEANED', occurredAt, request, { cleanedAt: occurredAt, deliveryPath: null, cleanupReason: reason });
    const result = sealMutation({ schemaVersion: '1.0.0', operation: 'CLEAN', leaseId: record.leaseId, principalDigest: principal.principalDigest, requestDigest: request, priorRecordDigest: record.recordDigest, next, cleanupPath: record.deliveryPath });
    const claim = this.mutationClaims.claim(claimKey, request, record.leaseId, result);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another credential cleanup');
    return { lease: this.recoverMutation(claim.record), replayed: false };
  }

  active(limit = 4_096): RootCredentialLease[] {
    return this.records.scan((record) => !TERMINAL.has(this.refresh(record).state), 0, limit).records.filter(verify).map((record) => this.refresh(record));
  }

  recover(): JsonObject {
    let mutationsRecovered = 0; let expired = 0; let cleaned = 0; const failures: string[] = [];
    try {
      for (const claim of this.mutationClaims.scan(10_000)) {
        try { this.recoverMutation(claim.record); mutationsRecovered += 1; }
        catch (error) { failures.push(`${claim.recordId}:${error instanceof Error ? error.message : 'unknown mutation recovery error'}`); }
      }
    } catch (error) { failures.push(`mutation-claims:${error instanceof Error ? error.message : 'unknown claim scan error'}`); }
    for (const record of this.records.scan(() => true, 0, 10_000).records) {
      try {
        const refreshed = this.refresh(record);
        if (refreshed.state === 'EXPIRED') expired += 1;
        if (['REVOKED', 'EXPIRED', 'FAILED'].includes(refreshed.state) && refreshed.state !== 'CLEANED') { this.cleanInternal(refreshed, 'startup recovery cleanup'); cleaned += 1; }
      } catch (error) { failures.push(`${record.leaseId}:${error instanceof Error ? error.message : 'unknown error'}`); }
    }
    return { mutationsRecovered, expired, cleaned, failures, ok: failures.length === 0 };
  }

  verifyNoSecretMaterial(value: unknown): boolean {
    const serialized = canonicalize(value);
    return !/-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer\s+[A-Za-z0-9_=-]{16,}|(?:password|token|secret)\s*[:=]\s*[^\s,}]+/iu.test(serialized);
  }

  private assertResolvedBinding(binding: CredentialAuthorizationBinding, expected: { transactionId: string; stepId: string; credentialReference: string; principalId: string; principalDigest: string }): void {
    if (binding.transactionId !== expected.transactionId || binding.stepId !== expected.stepId || binding.credentialReference !== expected.credentialReference || binding.ownerPrincipalId !== expected.principalId || binding.ownerPrincipalDigest !== expected.principalDigest) throw new RootFabricError('principal_mismatch', 'credential authority returned a mismatched binding');
    if (!['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'].includes(binding.provider)) throw new RootFabricError('unsupported_provider', 'credential authority returned an unsupported provider');
    if ((binding.provider === 'HOST_ENVELOPE' && binding.targetType !== 'UNIT') || (binding.provider === 'DISPOSABLE_MACHINE' && binding.targetType !== 'MACHINE')) throw new RootFabricError('credential_unavailable', 'credential target type does not match the authoritative provider');
    if (!['FREEZE', 'CANCEL_AND_ROLLBACK', 'ALLOW_TO_FINISH'].includes(binding.revocationBehavior)) throw new RootFabricError('credential_unavailable', 'credential revocation behavior is invalid');
  }

  private assertOwner(record: RootCredentialLease, principalId: string, principalDigest: string): void {
    if (record.ownerPrincipalId !== principalId || record.principalDigest !== principalDigest) throw new RootFabricError('principal_mismatch', 'credential lease principal mismatch');
  }

  private recoverMutation(result: CredentialMutationResult): RootCredentialLease {
    if (!verifyMutation(result)) throw new RootFabricError('corrupt_record', 'credential mutation claim integrity failed');
    const live = this.read(result.leaseId);
    if (live.recordDigest !== result.priorRecordDigest && live.recordDigest !== result.next.recordDigest) {
      if (live.state === 'CLEANED' || (result.operation === 'DELIVER' && ['REVOKED', 'EXPIRED', 'CLEANED'].includes(live.state))) return live;
      throw new RootFabricError('transaction_state_conflict', 'credential mutation claim conflicts with authoritative lease state');
    }
    if (result.operation === 'DELIVER') {
      if (live.state === 'CLEANED' || live.state === 'REVOKED' || live.state === 'EXPIRED') return live;
      this.ensureDelivered(result.next);
    } else this.removeDeliveryPath(result.cleanupPath, result.leaseId);
    if (live.recordDigest === result.priorRecordDigest) this.records.put(result.leaseId, result.next);
    return this.read(result.leaseId);
  }

  private ensureDelivered(record: RootCredentialLease): void {
    const path = safeLeasePath(this.deliveryRoot, record.leaseId);
    if (record.deliveryPath !== path) throw new RootFabricError('credential_delivery_failed', 'credential delivery claim path does not match the lease identity');
    const directory = dirname(path);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const directoryInfo = lstatSync(directory);
    if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink() || (directoryInfo.mode & 0o077) !== 0) throw new RootFabricError('credential_delivery_failed', 'credential delivery directory is not private');
    if (!existsSync(path)) {
      const secret = this.secrets.read(record.credentialReference);
      const fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o400);
      try { writeFileSync(fd, secret); fsyncSync(fd); } finally { closeSync(fd); secret.fill(0); }
    }
    const info = lstatSync(path);
    if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077) !== 0) throw new RootFabricError('credential_delivery_failed', 'credential delivery file is not private');
  }

  private removeDeliveryPath(path: string | null, leaseId: string): void {
    if (path === null) return;
    const expected = safeLeasePath(this.deliveryRoot, leaseId);
    if (path !== expected) throw new RootFabricError('cleanup_failed', 'credential delivery path does not match the lease identity');
    rmSync(dirname(expected), { recursive: true, force: true });
    if (existsSync(expected) || existsSync(dirname(expected))) throw new RootFabricError('cleanup_failed', 'credential delivery path remains after cleanup');
  }

  private refresh(record: RootCredentialLease): RootCredentialLease {
    if (!verify(record)) throw new RootFabricError('corrupt_record', 'credential lease integrity failed');
    if (!TERMINAL.has(record.state) && Date.parse(record.expiresAt) <= Date.parse(this.now())) return this.expire(record);
    return record;
  }

  private expire(record: RootCredentialLease): RootCredentialLease {
    if (record.state === 'EXPIRED' || record.state === 'CLEANED') return record;
    this.removeDeliveryPath(record.deliveryPath, record.leaseId);
    const occurredAt = this.now();
    const next = append(record, 'babyx.root.credential.expire', 'EXPIRED', occurredAt, sha256(canonicalize({ leaseId: record.leaseId, expiresAt: record.expiresAt })), { deliveryPath: null });
    this.records.put(record.leaseId, next);
    return next;
  }

  private cleanInternal(record: RootCredentialLease, reason: string): RootCredentialLease {
    if (record.state === 'CLEANED') return record;
    this.removeDeliveryPath(record.deliveryPath, record.leaseId);
    const occurredAt = this.now();
    const next = append(record, 'babyx.root.credential.clean', 'CLEANED', occurredAt, requestDigest('babyx.root.credential.clean', record.principalDigest, { leaseId: record.leaseId, reason }), { cleanedAt: occurredAt, deliveryPath: null, cleanupReason: reason });
    this.records.put(record.leaseId, next);
    return next;
  }

  private read(leaseId: string): RootCredentialLease {
    try { const record = this.records.get(leaseId); if (!verify(record)) throw new RootFabricError('corrupt_record', 'credential lease integrity failed'); return record; }
    catch (error) { if (error instanceof RootFabricError) throw error; throw new RootFabricError('credential_unavailable', 'credential lease not found', { leaseId }); }
  }
}
