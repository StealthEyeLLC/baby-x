import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../storage/record-store.ts';

export const ROOT_TRANSACTION_SCHEMA_VERSION = '1.0.0' as const;
export const ROOT_TRANSACTION_PROVIDER_VERSION = 'transactional-root-authority@1' as const;

export const ROOT_TRANSACTION_STATES = [
  'REQUESTED',
  'AUTHORIZED',
  'EXECUTING',
  'VERIFYING',
  'COMMIT_READY',
  'COMMITTED',
  'ROLLBACK_REQUESTED',
  'ROLLED_BACK',
  'FAILED',
  'AMBIGUOUS',
] as const;

export type RootTransactionState = typeof ROOT_TRANSACTION_STATES[number];
export type RootObservationPhase = 'execution' | 'verification' | 'rollback';
export type RootObservationStatus = 'succeeded' | 'failed' | 'ambiguous';

export type RootAuthorityErrorCode =
  | 'root_invalid_request'
  | 'root_not_found'
  | 'root_idempotency_required'
  | 'root_idempotency_conflict'
  | 'root_sequence_conflict'
  | 'root_state_conflict'
  | 'root_authorization_expired'
  | 'root_integrity_failure'
  | 'root_commit_not_ready';

export class RootAuthorityError extends Error {
  constructor(readonly code: RootAuthorityErrorCode, message: string, readonly details: JsonObject = {}) {
    super(message);
    this.name = 'RootAuthorityError';
  }
}

export interface RootSourceIdentity extends JsonObject {
  repository: string;
  branch: string;
  commit: string;
  tree: string;
}

export interface RootIntent extends JsonObject {
  purpose: string;
  mutationDigest: string;
  targetDigest: string;
  rollbackDigest: string;
  requiredAuthorities: string[];
  requiredVerifications: string[];
}

export interface RootAuthorization extends JsonObject {
  decisionDigest: string;
  authorizedAt: string;
  expiresAt: string;
  authorizedBy: string;
}

export interface RootObservation extends JsonObject {
  sequence: number;
  phase: RootObservationPhase;
  status: RootObservationStatus;
  authority: string;
  reference: string;
  observationDigest: string;
  observedAt: string;
}

export interface RootTransactionEvent extends JsonObject {
  schemaVersion: typeof ROOT_TRANSACTION_SCHEMA_VERSION;
  transactionId: string;
  sequence: number;
  operation: string;
  priorState: RootTransactionState | null;
  nextState: RootTransactionState;
  requestDigest: string;
  idempotencyKeyDigest: string;
  occurredAt: string;
  previousEventDigest: string | null;
  eventDigest: string;
}

export interface RootTransactionRecord extends JsonObject {
  schemaVersion: typeof ROOT_TRANSACTION_SCHEMA_VERSION;
  providerVersion: typeof ROOT_TRANSACTION_PROVIDER_VERSION;
  transactionId: string;
  transactionKind: 'ROOT_MUTATION';
  ownerPrincipal: string;
  creationRequestDigest: string;
  creationIdempotencyKeyDigest: string;
  source: RootSourceIdentity;
  intent: RootIntent;
  state: RootTransactionState;
  sequence: number;
  createdAt: string;
  updatedAt: string;
  authorization: RootAuthorization | null;
  observations: RootObservation[];
  commit: JsonObject | null;
  rollback: JsonObject | null;
  events: RootTransactionEvent[];
  eventCount: number;
  eventHeadDigest: string;
  recordDigest: string;
}

const DIGEST = /^[a-f0-9]{64}$/u;
const GIT_ID = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const STATE_SET = new Set<string>(ROOT_TRANSACTION_STATES);
const PHASE_SET = new Set<string>(['execution', 'verification', 'rollback']);
const STATUS_SET = new Set<string>(['succeeded', 'failed', 'ambiguous']);

function object(value: unknown, field: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new RootAuthorityError('root_invalid_request', `${field} must be an object`);
  return value as JsonObject;
}

function allowed(value: JsonObject, field: string, keys: readonly string[]): void {
  const permitted = new Set(keys);
  const unknown = Object.keys(value).filter((key) => !permitted.has(key));
  if (unknown.length > 0) throw new RootAuthorityError('root_invalid_request', `${field} contains unsupported properties`, { properties: unknown });
}

function text(value: unknown, field: string, maximum = 1_024): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || value.includes('\0')) throw new RootAuthorityError('root_invalid_request', `${field} must be a bounded non-empty NUL-free string`);
  return value;
}

function identifier(value: unknown, field: string): string {
  const normalized = text(value, field, 256);
  if (!IDENTIFIER.test(normalized)) throw new RootAuthorityError('root_invalid_request', `${field} is invalid`);
  return normalized;
}

function digest(value: unknown, field: string): string {
  const normalized = text(value, field, 64);
  if (!DIGEST.test(normalized)) throw new RootAuthorityError('root_invalid_request', `${field} must be a lowercase SHA-256 digest`);
  return normalized;
}

function gitIdentity(value: unknown, field: string): string {
  const normalized = text(value, field, 64);
  if (!GIT_ID.test(normalized)) throw new RootAuthorityError('root_invalid_request', `${field} must be a lowercase Git object identity`);
  return normalized;
}

function integer(value: unknown, field: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new RootAuthorityError('root_invalid_request', `${field} must be a safe integer between ${minimum} and ${maximum}`);
  return Number(value);
}

function stringSet(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64) throw new RootAuthorityError('root_invalid_request', `${field} must be a non-empty bounded string array`);
  const normalized = value.map((entry, index) => identifier(entry, `${field}[${index}]`));
  if (new Set(normalized).size !== normalized.length) throw new RootAuthorityError('root_invalid_request', `${field} must not contain duplicates`);
  return [...normalized].sort();
}

function timestamp(value: unknown, field: string): string {
  const normalized = text(value, field, 64);
  const parsed = Date.parse(normalized);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== normalized) throw new RootAuthorityError('root_invalid_request', `${field} must be an exact ISO-8601 UTC timestamp`);
  return normalized;
}

function owner(context: RuntimeExecutionContext): string {
  const principal = context.subject ?? 'stealtheye-owner';
  return identifier(principal, 'owner principal');
}

function idempotency(context: RuntimeExecutionContext): { key: string; digest: string } {
  const key = context.idempotencyKey;
  if (typeof key !== 'string' || key.length < 8 || key.length > 256 || key.includes('\0')) throw new RootAuthorityError('root_idempotency_required', 'a bounded idempotency key is required');
  return { key, digest: sha256(key) };
}

function normalizeSource(value: unknown): RootSourceIdentity {
  const source = object(value, 'source');
  allowed(source, 'source', ['repository', 'branch', 'commit', 'tree']);
  return {
    repository: text(source.repository, 'source.repository', 256),
    branch: text(source.branch, 'source.branch', 256),
    commit: gitIdentity(source.commit, 'source.commit'),
    tree: gitIdentity(source.tree, 'source.tree'),
  };
}

function normalizeIntent(value: unknown): RootIntent {
  const intent = object(value, 'intent');
  allowed(intent, 'intent', ['purpose', 'mutationDigest', 'targetDigest', 'rollbackDigest', 'requiredAuthorities', 'requiredVerifications']);
  return {
    purpose: text(intent.purpose, 'intent.purpose', 256),
    mutationDigest: digest(intent.mutationDigest, 'intent.mutationDigest'),
    targetDigest: digest(intent.targetDigest, 'intent.targetDigest'),
    rollbackDigest: digest(intent.rollbackDigest, 'intent.rollbackDigest'),
    requiredAuthorities: stringSet(intent.requiredAuthorities, 'intent.requiredAuthorities'),
    requiredVerifications: stringSet(intent.requiredVerifications, 'intent.requiredVerifications'),
  };
}

function requestDigest(operation: string, payload: JsonObject, principal: string): string {
  return sha256(canonicalize({ operation, payload, principal }));
}

function eventWithoutDigest(event: RootTransactionEvent): JsonObject {
  const { eventDigest: _eventDigest, ...unsigned } = event;
  return unsigned;
}

function recordWithoutDigest(record: RootTransactionRecord): JsonObject {
  const { recordDigest: _recordDigest, ...unsigned } = record;
  return unsigned;
}

function sealRecord(record: Omit<RootTransactionRecord, 'recordDigest'>): RootTransactionRecord {
  const unsigned = record as unknown as JsonObject;
  return { ...record, recordDigest: sha256(canonicalize(unsigned)) } as RootTransactionRecord;
}

function appendEvent(
  current: RootTransactionRecord | null,
  operation: string,
  nextState: RootTransactionState,
  digestOfRequest: string,
  idempotencyKeyDigest: string,
  occurredAt: string,
  patch: JsonObject,
): RootTransactionRecord {
  const sequence = (current?.sequence ?? 0) + 1;
  const eventBase: Omit<RootTransactionEvent, 'eventDigest'> = {
    schemaVersion: ROOT_TRANSACTION_SCHEMA_VERSION,
    transactionId: current?.transactionId ?? text(patch.transactionId, 'transactionId', 256),
    sequence,
    operation,
    priorState: current?.state ?? null,
    nextState,
    requestDigest: digestOfRequest,
    idempotencyKeyDigest,
    occurredAt,
    previousEventDigest: current?.eventHeadDigest ?? null,
  };
  const event: RootTransactionEvent = { ...eventBase, eventDigest: sha256(canonicalize(eventBase)) };
  const base = current === null ? patch : { ...recordWithoutDigest(current), ...patch };
  return sealRecord({
    ...base,
    state: nextState,
    sequence,
    updatedAt: occurredAt,
    events: [...(current?.events ?? []), event],
    eventCount: sequence,
    eventHeadDigest: event.eventDigest,
  } as Omit<RootTransactionRecord, 'recordDigest'>);
}

function state(value: unknown): RootTransactionState {
  if (typeof value !== 'string' || !STATE_SET.has(value)) throw new RootAuthorityError('root_invalid_request', 'state is invalid');
  return value as RootTransactionState;
}

export interface RootRecordVerification extends JsonObject {
  valid: boolean;
  errors: string[];
  transactionId: string;
  state: RootTransactionState;
  sequence: number;
  eventHeadDigest: string;
  recordDigest: string;
  computedRecordDigest: string;
}

export function verifyRootTransactionRecord(record: RootTransactionRecord): RootRecordVerification {
  const errors: string[] = [];
  const computedRecordDigest = sha256(canonicalize(recordWithoutDigest(record)));
  if (record.schemaVersion !== ROOT_TRANSACTION_SCHEMA_VERSION) errors.push('schema version mismatch');
  if (record.providerVersion !== ROOT_TRANSACTION_PROVIDER_VERSION) errors.push('provider version mismatch');
  if (record.transactionKind !== 'ROOT_MUTATION') errors.push('transaction kind mismatch');
  if (!IDENTIFIER.test(record.transactionId)) errors.push('transaction ID invalid');
  if (!STATE_SET.has(record.state)) errors.push('state invalid');
  if (record.recordDigest !== computedRecordDigest) errors.push('record digest mismatch');
  if (!Array.isArray(record.events)) errors.push('event ledger missing');
  if (!Array.isArray(record.observations)) errors.push('observations missing');
  const events = Array.isArray(record.events) ? record.events : [];
  let previousDigest: string | null = null;
  let previousState: RootTransactionState | null = null;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (event.sequence !== index + 1) errors.push(`event ${index + 1} sequence mismatch`);
    if (event.transactionId !== record.transactionId) errors.push(`event ${index + 1} transaction mismatch`);
    if (event.previousEventDigest !== previousDigest) errors.push(`event ${index + 1} previous digest mismatch`);
    if (event.priorState !== previousState) errors.push(`event ${index + 1} prior state mismatch`);
    const computed = sha256(canonicalize(eventWithoutDigest(event)));
    if (event.eventDigest !== computed) errors.push(`event ${index + 1} digest mismatch`);
    previousDigest = event.eventDigest;
    previousState = event.nextState;
  }
  if (record.sequence !== events.length) errors.push('record sequence does not match event ledger');
  if (record.eventCount !== events.length) errors.push('event count mismatch');
  if (record.eventHeadDigest !== previousDigest) errors.push('event head digest mismatch');
  if (record.state !== previousState) errors.push('record state does not match event ledger');
  for (const observation of Array.isArray(record.observations) ? record.observations : []) {
    if (!Number.isSafeInteger(observation.sequence) || observation.sequence < 1 || observation.sequence > record.sequence) errors.push('observation sequence invalid');
    if (!PHASE_SET.has(observation.phase)) errors.push('observation phase invalid');
    if (!STATUS_SET.has(observation.status)) errors.push('observation status invalid');
    if (!DIGEST.test(observation.observationDigest)) errors.push('observation digest invalid');
  }
  return {
    valid: errors.length === 0,
    errors,
    transactionId: record.transactionId,
    state: state(record.state),
    sequence: record.sequence,
    eventHeadDigest: record.eventHeadDigest,
    recordDigest: record.recordDigest,
    computedRecordDigest,
  };
}

function assertIntegrity(record: RootTransactionRecord): void {
  const verification = verifyRootTransactionRecord(record);
  if (!verification.valid) throw new RootAuthorityError('root_integrity_failure', 'transaction record integrity verification failed', { transactionId: record.transactionId, errors: verification.errors });
}

function summary(record: RootTransactionRecord): JsonObject {
  return {
    transactionId: record.transactionId,
    ownerPrincipal: record.ownerPrincipal,
    state: record.state,
    sequence: record.sequence,
    sourceCommit: record.source.commit,
    sourceTree: record.source.tree,
    purpose: record.intent.purpose,
    updatedAt: record.updatedAt,
    recordDigest: record.recordDigest,
  };
}

export class TransactionalRootAuthorityService {
  private readonly records: DurableRecordStore<RootTransactionRecord>;
  private readonly claims: DurableClaimStore<RootTransactionRecord>;
  private readonly now: () => string;

  constructor(readonly stateRoot: string, options: { now?: () => string } = {}) {
    const root = join(stateRoot, 'root-authority');
    this.records = new DurableRecordStore<RootTransactionRecord>(join(root, 'transactions'));
    this.claims = new DurableClaimStore<RootTransactionRecord>(join(root, 'idempotency'));
    this.now = options.now ?? (() => new Date().toISOString());
  }

  describe(): JsonObject {
    return {
      operation: 'babyx.root.describe',
      schemaVersion: ROOT_TRANSACTION_SCHEMA_VERSION,
      providerVersion: ROOT_TRANSACTION_PROVIDER_VERSION,
      transactionKinds: ['ROOT_MUTATION'],
      states: ROOT_TRANSACTION_STATES,
      authority: 'coordination-only',
      executesCommands: false,
      ownsJobs: false,
      ownsMachines: false,
      ownsArtifacts: false,
      ownsDeployment: false,
      invariants: [
        'exact-source-identity',
        'caller-key-idempotency',
        'expected-sequence-transitions',
        'digest-chained-event-ledger',
        'verification-before-commit',
        'observed-rollback-only',
      ],
    };
  }

  create(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = object(payloadValue, 'transaction create payload');
    allowed(payload, 'transaction create payload', ['source', 'intent']);
    const source = normalizeSource(payload.source);
    const intent = normalizeIntent(payload.intent);
    const principal = owner(context);
    const idem = idempotency(context);
    const normalized = { source, intent };
    const digestOfRequest = requestDigest('babyx.root.transaction.create', normalized, principal);
    const claimKey = `create:${principal}:${idem.digest}`;
    const existing = this.claims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== digestOfRequest) throw new RootAuthorityError('root_idempotency_conflict', 'idempotency key is already bound to a different create request');
      if (!this.records.has(existing.recordId)) this.records.create(existing.recordId, existing.record);
      const replay = this.records.get(existing.recordId);
      assertIntegrity(replay);
      return { transaction: replay, replayed: true };
    }
    const transactionId = `rtx_${randomUUID().replaceAll('-', '')}`;
    const createdAt = this.now();
    const candidate = appendEvent(null, 'babyx.root.transaction.create', 'REQUESTED', digestOfRequest, idem.digest, createdAt, {
      schemaVersion: ROOT_TRANSACTION_SCHEMA_VERSION,
      providerVersion: ROOT_TRANSACTION_PROVIDER_VERSION,
      transactionId,
      transactionKind: 'ROOT_MUTATION',
      ownerPrincipal: principal,
      creationRequestDigest: digestOfRequest,
      creationIdempotencyKeyDigest: idem.digest,
      source,
      intent,
      state: 'REQUESTED',
      sequence: 0,
      createdAt,
      updatedAt: createdAt,
      authorization: null,
      observations: [],
      commit: null,
      rollback: null,
      events: [],
      eventCount: 0,
      eventHeadDigest: '',
    });
    const claim = this.claims.claim(claimKey, digestOfRequest, transactionId, candidate);
    if (claim.requestDigest !== digestOfRequest) throw new RootAuthorityError('root_idempotency_conflict', 'idempotency key is already bound to a different create request');
    if (!this.records.has(claim.recordId) && !this.records.create(claim.recordId, claim.record)) throw new RootAuthorityError('root_integrity_failure', 'transaction record could not be created');
    const record = this.records.get(claim.recordId);
    assertIntegrity(record);
    return { transaction: record, replayed: claim.recordId !== transactionId };
  }

  get(payloadValue: unknown): JsonObject {
    const payload = object(payloadValue, 'transaction get payload');
    allowed(payload, 'transaction get payload', ['transactionId']);
    const record = this.read(identifier(payload.transactionId, 'transactionId'));
    return { transaction: record, integrity: verifyRootTransactionRecord(record) };
  }

  list(payloadValue: unknown): JsonObject {
    const payload = object(payloadValue ?? {}, 'transaction list payload');
    allowed(payload, 'transaction list payload', ['state', 'ownerPrincipal', 'offset', 'limit']);
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, 10_000_000);
    const limit = payload.limit === undefined ? 100 : integer(payload.limit, 'limit', 1, 1_000);
    const requestedState = payload.state === undefined ? undefined : state(payload.state);
    const requestedOwner = payload.ownerPrincipal === undefined ? undefined : identifier(payload.ownerPrincipal, 'ownerPrincipal');
    const page = this.records.scan((record) => (requestedState === undefined || record.state === requestedState) && (requestedOwner === undefined || record.ownerPrincipal === requestedOwner), offset, limit);
    const invalidRecordIds: string[] = [];
    const transactions = page.records.flatMap((record) => {
      const verification = verifyRootTransactionRecord(record);
      if (!verification.valid) { invalidRecordIds.push(record.transactionId); return []; }
      return [summary(record)];
    });
    return {
      transactions,
      offset: page.offset,
      limit: page.limit,
      total: page.total,
      nextOffset: page.nextOffset,
      corruptRecordIds: page.corruptRecordIds,
      invalidRecordIds,
    };
  }

  authorize(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    return this.mutate('babyx.root.transaction.authorize', payloadValue, context, ['transactionId', 'expectedSequence', 'decisionDigest', 'expiresAt'], (record, payload, occurredAt, digestOfRequest, idemDigest) => {
      this.requireState(record, ['REQUESTED']);
      const expiresAt = timestamp(payload.expiresAt, 'expiresAt');
      if (Date.parse(expiresAt) <= Date.parse(occurredAt)) throw new RootAuthorityError('root_invalid_request', 'authorization expiry must be in the future');
      if (Date.parse(expiresAt) - Date.parse(occurredAt) > 30 * 24 * 60 * 60 * 1_000) throw new RootAuthorityError('root_invalid_request', 'authorization expiry may not exceed 30 days');
      return appendEvent(record, 'babyx.root.transaction.authorize', 'AUTHORIZED', digestOfRequest, idemDigest, occurredAt, {
        authorization: {
          decisionDigest: digest(payload.decisionDigest, 'decisionDigest'),
          authorizedAt: occurredAt,
          expiresAt,
          authorizedBy: owner(context),
        },
      });
    });
  }

  begin(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    return this.mutate('babyx.root.transaction.begin', payloadValue, context, ['transactionId', 'expectedSequence'], (record, _payload, occurredAt, digestOfRequest, idemDigest) => {
      this.requireState(record, ['AUTHORIZED']);
      if (record.authorization === null || Date.parse(record.authorization.expiresAt) < Date.parse(occurredAt)) throw new RootAuthorityError('root_authorization_expired', 'transaction authorization has expired');
      return appendEvent(record, 'babyx.root.transaction.begin', 'EXECUTING', digestOfRequest, idemDigest, occurredAt, {});
    });
  }

  observe(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    return this.mutate('babyx.root.transaction.observe', payloadValue, context, ['transactionId', 'expectedSequence', 'phase', 'status', 'authority', 'reference', 'observationDigest'], (record, payload, occurredAt, digestOfRequest, idemDigest) => {
      const phaseValue = text(payload.phase, 'phase', 32) as RootObservationPhase;
      const statusValue = text(payload.status, 'status', 32) as RootObservationStatus;
      if (!PHASE_SET.has(phaseValue)) throw new RootAuthorityError('root_invalid_request', 'phase is invalid');
      if (!STATUS_SET.has(statusValue)) throw new RootAuthorityError('root_invalid_request', 'status is invalid');
      const authority = identifier(payload.authority, 'authority');
      if (!record.intent.requiredAuthorities.includes(authority)) throw new RootAuthorityError('root_invalid_request', 'observation authority is not bound to the transaction intent', { authority });
      const observation: RootObservation = {
        sequence: record.sequence + 1,
        phase: phaseValue,
        status: statusValue,
        authority,
        reference: text(payload.reference, 'reference', 1_024),
        observationDigest: digest(payload.observationDigest, 'observationDigest'),
        observedAt: occurredAt,
      };
      let nextState: RootTransactionState;
      if (phaseValue === 'execution') {
        this.requireState(record, ['EXECUTING']);
        nextState = statusValue === 'succeeded' ? 'VERIFYING' : statusValue === 'failed' ? 'FAILED' : 'AMBIGUOUS';
      } else if (phaseValue === 'verification') {
        this.requireState(record, ['VERIFYING']);
        nextState = statusValue === 'succeeded' ? 'COMMIT_READY' : statusValue === 'failed' ? 'FAILED' : 'AMBIGUOUS';
      } else {
        this.requireState(record, ['ROLLBACK_REQUESTED']);
        nextState = statusValue === 'succeeded' ? 'ROLLED_BACK' : 'AMBIGUOUS';
      }
      return appendEvent(record, 'babyx.root.transaction.observe', nextState, digestOfRequest, idemDigest, occurredAt, {
        observations: [...record.observations, observation],
        ...(phaseValue === 'rollback' ? { rollback: { ...(record.rollback ?? {}), outcome: statusValue, observationDigest: observation.observationDigest, completedAt: occurredAt } } : {}),
      });
    });
  }

  commit(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    return this.mutate('babyx.root.transaction.commit', payloadValue, context, ['transactionId', 'expectedSequence', 'commitDigest', 'verificationDigest'], (record, payload, occurredAt, digestOfRequest, idemDigest) => {
      this.requireState(record, ['COMMIT_READY']);
      const latest = record.observations.at(-1);
      const verificationDigest = digest(payload.verificationDigest, 'verificationDigest');
      if (latest === undefined || latest.phase !== 'verification' || latest.status !== 'succeeded' || latest.observationDigest !== verificationDigest) throw new RootAuthorityError('root_commit_not_ready', 'commit requires the exact latest successful verification observation');
      const observedVerificationAuthorities = new Set(record.observations.filter((entry) => entry.phase === 'verification' && entry.status === 'succeeded').map((entry) => entry.authority));
      const missing = record.intent.requiredVerifications.filter((required) => !observedVerificationAuthorities.has(required));
      if (missing.length > 0) throw new RootAuthorityError('root_commit_not_ready', 'required verification authorities have not all succeeded', { missing });
      return appendEvent(record, 'babyx.root.transaction.commit', 'COMMITTED', digestOfRequest, idemDigest, occurredAt, {
        commit: {
          commitDigest: digest(payload.commitDigest, 'commitDigest'),
          verificationDigest,
          committedAt: occurredAt,
        },
      });
    });
  }

  rollback(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    return this.mutate('babyx.root.transaction.rollback', payloadValue, context, ['transactionId', 'expectedSequence', 'rollbackDigest', 'reasonDigest'], (record, payload, occurredAt, digestOfRequest, idemDigest) => {
      this.requireState(record, ['REQUESTED', 'AUTHORIZED', 'EXECUTING', 'VERIFYING', 'COMMIT_READY', 'COMMITTED', 'FAILED', 'AMBIGUOUS']);
      const rollbackDigest = digest(payload.rollbackDigest, 'rollbackDigest');
      if (rollbackDigest !== record.intent.rollbackDigest) throw new RootAuthorityError('root_invalid_request', 'rollback digest does not match the transaction intent');
      return appendEvent(record, 'babyx.root.transaction.rollback', 'ROLLBACK_REQUESTED', digestOfRequest, idemDigest, occurredAt, {
        rollback: {
          rollbackDigest,
          reasonDigest: digest(payload.reasonDigest, 'reasonDigest'),
          requestedAt: occurredAt,
          requestedFromState: record.state,
        },
      });
    });
  }

  events(payloadValue: unknown): JsonObject {
    const payload = object(payloadValue, 'transaction events payload');
    allowed(payload, 'transaction events payload', ['transactionId', 'offset', 'limit']);
    const record = this.read(identifier(payload.transactionId, 'transactionId'));
    const verification = verifyRootTransactionRecord(record);
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, 10_000_000);
    const limit = payload.limit === undefined ? 100 : integer(payload.limit, 'limit', 1, 1_000);
    const events = record.events.slice(offset, offset + limit);
    return { events, offset, limit, total: record.events.length, nextOffset: offset + events.length < record.events.length ? offset + events.length : null, integrity: verification };
  }

  verify(payloadValue: unknown): JsonObject {
    const payload = object(payloadValue, 'transaction verify payload');
    allowed(payload, 'transaction verify payload', ['transactionId']);
    return verifyRootTransactionRecord(this.read(identifier(payload.transactionId, 'transactionId')));
  }

  private read(transactionId: string): RootTransactionRecord {
    try { return this.records.get(transactionId); }
    catch (error) {
      if (error instanceof Error && error.message === 'record not found') throw new RootAuthorityError('root_not_found', 'transaction not found', { transactionId });
      throw error;
    }
  }

  private requireState(record: RootTransactionRecord, allowedStates: readonly RootTransactionState[]): void {
    if (!allowedStates.includes(record.state)) throw new RootAuthorityError('root_state_conflict', `transaction state ${record.state} does not permit this operation`, { state: record.state, allowedStates });
  }

  private mutate(
    operation: string,
    payloadValue: unknown,
    context: RuntimeExecutionContext,
    keys: readonly string[],
    transition: (record: RootTransactionRecord, payload: JsonObject, occurredAt: string, digestOfRequest: string, idempotencyKeyDigest: string) => RootTransactionRecord,
  ): JsonObject {
    const payload = object(payloadValue, `${operation} payload`);
    allowed(payload, `${operation} payload`, keys);
    const transactionId = identifier(payload.transactionId, 'transactionId');
    const expectedSequence = integer(payload.expectedSequence, 'expectedSequence', 1, 10_000_000);
    const principal = owner(context);
    const idem = idempotency(context);
    const digestOfRequest = requestDigest(operation, payload, principal);
    const claimKey = `${transactionId}:${operation}:${idem.digest}`;
    const existing = this.claims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== digestOfRequest || existing.recordId !== transactionId) throw new RootAuthorityError('root_idempotency_conflict', 'idempotency key is already bound to a different request');
      const live = this.read(transactionId);
      assertIntegrity(live);
      if (live.sequence < existing.record.sequence) this.records.put(transactionId, existing.record);
      const replay = this.read(transactionId);
      assertIntegrity(replay);
      return { transaction: replay, replayed: true };
    }
    const current = this.read(transactionId);
    assertIntegrity(current);
    if (current.ownerPrincipal !== principal) throw new RootAuthorityError('root_state_conflict', 'transaction owner principal mismatch');
    if (current.sequence !== expectedSequence) throw new RootAuthorityError('root_sequence_conflict', 'expected sequence does not match authoritative transaction sequence', { expectedSequence, actualSequence: current.sequence });
    const candidate = transition(current, payload, this.now(), digestOfRequest, idem.digest);
    assertIntegrity(candidate);
    const claim = this.claims.claim(claimKey, digestOfRequest, transactionId, candidate);
    if (claim.requestDigest !== digestOfRequest || claim.recordId !== transactionId) throw new RootAuthorityError('root_idempotency_conflict', 'idempotency key is already bound to a different request');
    const live = this.read(transactionId);
    if (live.sequence === expectedSequence) this.records.put(transactionId, claim.record);
    else if (live.sequence === claim.record.sequence && live.recordDigest !== claim.record.recordDigest) throw new RootAuthorityError('root_sequence_conflict', 'transaction sequence was committed with different content');
    else if (live.sequence < claim.record.sequence) throw new RootAuthorityError('root_sequence_conflict', 'transaction sequence changed before durable commit');
    const committed = this.read(transactionId);
    assertIntegrity(committed);
    return { transaction: committed, replayed: claim.record.recordDigest !== candidate.recordDigest };
  }
}
