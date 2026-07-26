import { randomUUID } from 'node:crypto';
import {
  closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync,
  renameSync, rmSync, statSync, writeSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { canonicalize, sha256, type JsonObject } from '../core.ts';
import {
  TRANSACTION_INDEX_SCHEMA_VERSION,
  TRANSACTION_LEASE_SCHEMA_VERSION,
  TRANSACTION_STATES,
  TRANSACTION_TERMINAL_STATES,
  TransactionError,
  assertTransactionEvent,
  assertTransactionId,
  assertTransactionLease,
  assertTransactionRecord,
  assertTransactionTransition,
  createTransactionEvent,
  transactionRecordDigest,
  type DurableTransactionRecordV1,
  type TransactionControllerLeaseV1,
  type TransactionEventDraft,
  type TransactionEventV1,
  type TransactionState,
} from './schemas.ts';

export interface TransactionStoreOptions {
  now?: () => string;
  beforeWrite?: (kind: 'record' | 'event' | 'pending' | 'index' | 'lease', path: string) => void;
}

export interface TransactionRecordScan {
  records: DurableTransactionRecordV1[];
  corrupt: { path: string; code: string; message: string }[];
  scanned: number;
  truncated: boolean;
}

export interface TransactionIndexVerification {
  valid: boolean;
  ownerValid: boolean;
  stateValid: boolean;
  idempotencyValid: boolean;
  recordsDigest: string;
  recordCount: number;
}

export interface TransactionStartupVerification extends JsonObject {
  recoveredPending: number;
  corruptPending: { path: string; message: string }[];
  indexes: TransactionIndexVerification;
  repairedIndexes: boolean;
  corruptRecords: { path: string; code: string; message: string }[];
}

export interface TransactionMutationDetails {
  operation: string;
  phase: string;
  requestDigest: string;
  idempotencyKey?: string | null;
  occurredAt?: string;
  machineId?: string | null;
  jobIds?: string[];
  candidateId?: string | null;
  candidateTree?: string | null;
  observationDigest?: string | null;
}

export interface TransactionRecordPatch {
  lifecycle?: Partial<DurableTransactionRecordV1['lifecycle']>;
  source?: Partial<DurableTransactionRecordV1['source']>;
  policy?: Partial<DurableTransactionRecordV1['policy']>;
  execution?: Partial<DurableTransactionRecordV1['execution']>;
  candidate?: Partial<DurableTransactionRecordV1['candidate']>;
  evidence?: Partial<DurableTransactionRecordV1['evidence']>;
  cleanup?: Partial<DurableTransactionRecordV1['cleanup']>;
  environment?: Partial<DurableTransactionRecordV1['environment']>;
  error?: DurableTransactionRecordV1['error'];
}

interface TransactionPendingMutationV1 extends JsonObject {
  schemaVersion: '1.0.0';
  transactionId: string;
  priorRecordDigest: string | null;
  nextRecord: DurableTransactionRecordV1;
  event: TransactionEventV1;
  preparedAt: string;
}

interface OwnerIndexV1 extends JsonObject {
  schemaVersion: typeof TRANSACTION_INDEX_SCHEMA_VERSION;
  recordsDigest: string;
  byOwnerDigest: Record<string, string[]>;
}

interface StateIndexV1 extends JsonObject {
  schemaVersion: typeof TRANSACTION_INDEX_SCHEMA_VERSION;
  recordsDigest: string;
  byState: Record<string, string[]>;
}

interface IdempotencyIndexV1 extends JsonObject {
  schemaVersion: typeof TRANSACTION_INDEX_SCHEMA_VERSION;
  recordsDigest: string;
  byKeyDigest: Record<string, string>;
}

function storeError(code: string, message: string, details: Readonly<Record<string, unknown>> = {}): TransactionError {
  return new TransactionError(code, message, details);
}

function parseJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8')) as unknown;
}

function regularFile(path: string): boolean {
  try { return statSync(path).isFile(); } catch { return false; }
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function mergeRecord(current: DurableTransactionRecordV1, patch: TransactionRecordPatch): DurableTransactionRecordV1 {
  return {
    ...current,
    lifecycle: { ...current.lifecycle, ...(patch.lifecycle ?? {}) },
    source: { ...current.source, ...(patch.source ?? {}) },
    policy: { ...current.policy, ...(patch.policy ?? {}) },
    execution: { ...current.execution, ...(patch.execution ?? {}) },
    candidate: { ...current.candidate, ...(patch.candidate ?? {}) },
    evidence: { ...current.evidence, ...(patch.evidence ?? {}) },
    cleanup: { ...current.cleanup, ...(patch.cleanup ?? {}) },
    environment: { ...current.environment, ...(patch.environment ?? {}) },
    error: patch.error === undefined ? current.error : patch.error,
  };
}

export class DurableTransactionStore {
  private readonly recordsRoot: string;
  private readonly eventsRoot: string;
  private readonly pendingRoot: string;
  private readonly indexesRoot: string;
  private readonly leasesRoot: string;
  private readonly now: () => string;
  private readonly beforeWrite?: TransactionStoreOptions['beforeWrite'];

  constructor(readonly root: string, options: TransactionStoreOptions = {}) {
    this.recordsRoot = join(root, 'records');
    this.eventsRoot = join(root, 'events');
    this.pendingRoot = join(root, 'pending');
    this.indexesRoot = join(root, 'indexes');
    this.leasesRoot = join(root, 'leases');
    for (const path of [root, this.recordsRoot, this.eventsRoot, this.pendingRoot, this.indexesRoot, this.leasesRoot]) mkdirSync(path, { recursive: true, mode: 0o700 });
    this.now = options.now ?? (() => new Date().toISOString());
    this.beforeWrite = options.beforeWrite;
  }

  private recordPath(transactionId: string): string { return join(this.recordsRoot, `${assertTransactionId(transactionId)}.json`); }
  private pendingPath(transactionId: string): string { return join(this.pendingRoot, `${assertTransactionId(transactionId)}.json`); }
  private leasePath(transactionId: string): string { return join(this.leasesRoot, `${assertTransactionId(transactionId)}.json`); }
  private eventDirectory(transactionId: string): string { return join(this.eventsRoot, assertTransactionId(transactionId)); }
  private eventPath(event: TransactionEventV1): string { return join(this.eventDirectory(event.transactionId), `${String(event.nextSequence).padStart(16, '0')}-${event.eventDigest}.json`); }

  private atomicWrite(path: string, value: unknown, kind: 'record' | 'event' | 'pending' | 'index' | 'lease', exclusive = false): void {
    this.beforeWrite?.(kind, path);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const bytes = Buffer.from(`${canonicalize(value)}\n`, 'utf8');
    if (exclusive) {
      const fd = openSync(path, 'wx', 0o600);
      try { writeSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
      const directory = openSync(dirname(path), 'r');
      try { fsyncSync(directory); } finally { closeSync(directory); }
      return;
    }
    const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
    const fd = openSync(temporary, 'wx', 0o600);
    try { writeSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(temporary, path);
    const directory = openSync(dirname(path), 'r');
    try { fsyncSync(directory); } finally { closeSync(directory); }
  }

  private appendEvent(eventValue: TransactionEventV1): void {
    const event = assertTransactionEvent(eventValue);
    const path = this.eventPath(event);
    if (existsSync(path)) {
      const existing = assertTransactionEvent(parseJson(path));
      if (existing.eventDigest !== event.eventDigest) throw storeError('transaction_event_conflict', 'event path contains conflicting durable truth', { transactionId: event.transactionId, sequence: event.nextSequence });
      return;
    }
    this.atomicWrite(path, event, 'event', true);
  }

  get(transactionId: string): DurableTransactionRecordV1 {
    const path = this.recordPath(transactionId);
    if (!regularFile(path)) throw storeError('transaction_not_found', 'transaction not found', { transactionId });
    try { return assertTransactionRecord(parseJson(path)); }
    catch (error) { throw storeError('transaction_record_corrupt', 'authoritative transaction record is corrupt', { transactionId, cause: error instanceof Error ? error.message : String(error) }); }
  }

  scan(limit = 10_000): TransactionRecordScan {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100_000) throw storeError('transaction_invalid_request', 'scan limit must be between 1 and 100000');
    const files = readdirSync(this.recordsRoot).filter((name) => name.endsWith('.json')).sort((left, right) => left.localeCompare(right));
    const selected = files.slice(0, limit);
    const records: DurableTransactionRecordV1[] = [];
    const corrupt: TransactionRecordScan['corrupt'] = [];
    for (const name of selected) {
      const path = join(this.recordsRoot, name);
      try { records.push(assertTransactionRecord(parseJson(path))); }
      catch (error) { corrupt.push({ path, code: 'transaction_record_corrupt', message: error instanceof Error ? error.message : String(error) }); }
    }
    return { records: records.sort((left, right) => left.transactionId.localeCompare(right.transactionId)), corrupt, scanned: selected.length, truncated: files.length > selected.length };
  }

  list(): DurableTransactionRecordV1[] {
    return this.scan(100_000).records;
  }

  private findIdempotent(ownerPrincipal: string, idempotencyKey: string): DurableTransactionRecordV1 | undefined {
    return this.list().find((record) => record.ownerPrincipal === ownerPrincipal && record.idempotencyKey === idempotencyKey);
  }

  create(recordValue: DurableTransactionRecordV1, details: TransactionMutationDetails): DurableTransactionRecordV1 {
    const record = assertTransactionRecord(recordValue);
    const existing = this.findIdempotent(record.ownerPrincipal, record.idempotencyKey);
    if (existing !== undefined) {
      if (existing.creationRequestDigest !== record.creationRequestDigest) throw storeError('transaction_idempotency_conflict', 'idempotency key was already used for a different creation request', { transactionId: existing.transactionId });
      return existing;
    }
    if (existsSync(this.recordPath(record.transactionId))) throw storeError('transaction_identity_conflict', 'transaction ID already exists', { transactionId: record.transactionId });
    const event = createTransactionEvent({
      transactionId: record.transactionId, ownerPrincipal: record.ownerPrincipal, operation: details.operation, phase: details.phase,
      priorState: null, nextState: record.lifecycle.persistedState, priorSequence: 0, nextSequence: record.lifecycle.stateSequence,
      requestDigest: details.requestDigest, idempotencyKey: details.idempotencyKey ?? record.idempotencyKey,
      occurredAt: details.occurredAt ?? record.lifecycle.createdAt, previousEventDigest: null,
      machineId: details.machineId ?? null, jobIds: details.jobIds ?? [], candidateId: details.candidateId ?? null,
      candidateTree: details.candidateTree ?? null, observationDigest: details.observationDigest ?? null,
    });
    const withTail = assertTransactionRecord({ ...record, evidence: { ...record.evidence, eventTailDigest: event.eventDigest } });
    this.commitMutation(null, withTail, event);
    return withTail;
  }

  update(transactionId: string, expectedSequence: number, details: TransactionMutationDetails, patch: TransactionRecordPatch = {}): DurableTransactionRecordV1 {
    return this.mutate(transactionId, expectedSequence, undefined, details, patch);
  }

  transition(transactionId: string, expectedSequence: number, nextState: TransactionState, details: TransactionMutationDetails, patch: TransactionRecordPatch = {}): DurableTransactionRecordV1 {
    return this.mutate(transactionId, expectedSequence, nextState, details, patch);
  }

  private mutate(transactionId: string, expectedSequence: number, requestedState: TransactionState | undefined, details: TransactionMutationDetails, patch: TransactionRecordPatch): DurableTransactionRecordV1 {
    const current = this.get(transactionId);
    if (current.lifecycle.stateSequence !== expectedSequence) throw storeError('transaction_stale_sequence', 'expected sequence does not match durable transaction truth', { expectedSequence, actualSequence: current.lifecycle.stateSequence });
    if (current.lifecycle.terminal) throw storeError('transaction_terminal', 'terminal transactions cannot mutate', { transactionId, state: current.lifecycle.persistedState });
    const nextState = requestedState ?? current.lifecycle.persistedState;
    if (requestedState !== undefined) assertTransactionTransition(current.lifecycle.persistedState, requestedState);
    const occurredAt = details.occurredAt ?? this.now();
    const terminal = (TRANSACTION_TERMINAL_STATES as readonly string[]).includes(nextState);
    let next = mergeRecord(current, patch);
    next = {
      ...next,
      lifecycle: {
        ...next.lifecycle,
        persistedState: nextState,
        desiredState: patch.lifecycle?.desiredState ?? next.lifecycle.desiredState,
        stateSequence: current.lifecycle.stateSequence + 1,
        terminal,
        updatedAt: occurredAt,
        completedAt: terminal ? occurredAt : null,
      },
    };
    const event = createTransactionEvent({
      transactionId, ownerPrincipal: current.ownerPrincipal, operation: details.operation, phase: details.phase,
      priorState: current.lifecycle.persistedState, nextState, priorSequence: current.lifecycle.stateSequence, nextSequence: current.lifecycle.stateSequence + 1,
      requestDigest: details.requestDigest, idempotencyKey: details.idempotencyKey ?? null, occurredAt,
      previousEventDigest: current.evidence.eventTailDigest, machineId: details.machineId ?? null, jobIds: details.jobIds ?? [],
      candidateId: details.candidateId ?? next.candidate.candidateId, candidateTree: details.candidateTree ?? next.candidate.candidateTree,
      observationDigest: details.observationDigest ?? null,
    });
    next = assertTransactionRecord({ ...next, evidence: { ...next.evidence, eventTailDigest: event.eventDigest } });
    this.commitMutation(current, next, event);
    return next;
  }

  private commitMutation(prior: DurableTransactionRecordV1 | null, next: DurableTransactionRecordV1, event: TransactionEventV1): void {
    const pending: TransactionPendingMutationV1 = {
      schemaVersion: '1.0.0', transactionId: next.transactionId,
      priorRecordDigest: prior === null ? null : transactionRecordDigest(prior), nextRecord: next, event, preparedAt: this.now(),
    };
    const pendingPath = this.pendingPath(next.transactionId);
    this.atomicWrite(pendingPath, pending, 'pending');
    this.atomicWrite(this.recordPath(next.transactionId), next, 'record');
    this.appendEvent(event);
    rmSync(pendingPath, { force: true });
    this.rebuildIndexes();
  }

  private parsePending(path: string): TransactionPendingMutationV1 {
    const value = parseJson(path);
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw storeError('transaction_pending_corrupt', 'pending mutation must be an object');
    const item = value as Record<string, unknown>;
    const keys = ['schemaVersion', 'transactionId', 'priorRecordDigest', 'nextRecord', 'event', 'preparedAt'];
    if (Object.keys(item).some((key) => !keys.includes(key)) || keys.some((key) => !(key in item)) || item.schemaVersion !== '1.0.0') throw storeError('transaction_pending_corrupt', 'pending mutation schema is incompatible');
    const nextRecord = assertTransactionRecord(item.nextRecord);
    const event = assertTransactionEvent(item.event);
    if (nextRecord.transactionId !== event.transactionId || nextRecord.evidence.eventTailDigest !== event.eventDigest) throw storeError('transaction_pending_corrupt', 'pending mutation identities conflict');
    const priorRecordDigest = item.priorRecordDigest === null ? null : String(item.priorRecordDigest);
    if (priorRecordDigest !== null && !/^[a-f0-9]{64}$/u.test(priorRecordDigest)) throw storeError('transaction_pending_corrupt', 'pending prior digest is invalid');
    return { schemaVersion: '1.0.0', transactionId: assertTransactionId(item.transactionId), priorRecordDigest, nextRecord, event, preparedAt: String(item.preparedAt) };
  }

  recoverPending(limit = 1_000): { recovered: number; corrupt: { path: string; message: string }[] } {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) throw storeError('transaction_invalid_request', 'pending recovery limit is out of bounds');
    const files = readdirSync(this.pendingRoot).filter((name) => name.endsWith('.json')).sort((left, right) => left.localeCompare(right)).slice(0, limit);
    let recovered = 0;
    const corrupt: { path: string; message: string }[] = [];
    for (const name of files) {
      const path = join(this.pendingRoot, name);
      try {
        const pending = this.parsePending(path);
        const recordPath = this.recordPath(pending.transactionId);
        if (existsSync(recordPath)) {
          const current = assertTransactionRecord(parseJson(recordPath));
          const currentDigest = transactionRecordDigest(current);
          const nextDigest = transactionRecordDigest(pending.nextRecord);
          if (currentDigest !== nextDigest) {
            if (pending.priorRecordDigest === null || currentDigest !== pending.priorRecordDigest) throw storeError('transaction_pending_conflict', 'pending mutation conflicts with authoritative record', { transactionId: pending.transactionId });
            this.atomicWrite(recordPath, pending.nextRecord, 'record');
          }
        } else {
          if (pending.priorRecordDigest !== null) throw storeError('transaction_pending_conflict', 'pending update lost its authoritative prior record', { transactionId: pending.transactionId });
          this.atomicWrite(recordPath, pending.nextRecord, 'record');
        }
        this.appendEvent(pending.event);
        rmSync(path, { force: true });
        recovered += 1;
      } catch (error) {
        corrupt.push({ path, message: error instanceof Error ? error.message : String(error) });
      }
    }
    if (recovered > 0) this.rebuildIndexes();
    return { recovered, corrupt };
  }

  events(transactionId: string, offset = 0, limit = 100): TransactionEventV1[] {
    assertTransactionId(transactionId);
    if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) throw storeError('transaction_invalid_request', 'event offset or limit is out of bounds');
    const directory = this.eventDirectory(transactionId);
    if (!existsSync(directory)) return [];
    const files = readdirSync(directory).filter((name) => name.endsWith('.json')).sort((left, right) => left.localeCompare(right));
    const all = files.map((name) => assertTransactionEvent(parseJson(join(directory, name))));
    let previous: TransactionEventV1 | undefined;
    for (const event of all) {
      if (previous === undefined) {
        if (event.priorSequence !== 0 || event.previousEventDigest !== null) throw storeError('transaction_event_chain_corrupt', 'transaction genesis event is invalid', { transactionId });
      } else if (event.priorSequence !== previous.nextSequence || event.previousEventDigest !== previous.eventDigest) {
        throw storeError('transaction_event_chain_corrupt', 'transaction event chain is discontinuous', { transactionId, eventId: event.eventId });
      }
      previous = event;
    }
    return all.slice(offset, offset + limit);
  }

  private expectedIndexes(records = this.list()): { owner: OwnerIndexV1; state: StateIndexV1; idempotency: IdempotencyIndexV1 } {
    const ordered = [...records].sort((left, right) => left.transactionId.localeCompare(right.transactionId));
    const recordsDigest = sha256(canonicalize(ordered.map((record) => ({ transactionId: record.transactionId, recordDigest: transactionRecordDigest(record) }))));
    const byOwnerDigest: Record<string, string[]> = {};
    const byState: Record<string, string[]> = Object.fromEntries(TRANSACTION_STATES.map((state) => [state, []])) as Record<string, string[]>;
    const byKeyDigest: Record<string, string> = {};
    for (const record of ordered) {
      const ownerDigest = sha256(record.ownerPrincipal);
      byOwnerDigest[ownerDigest] = sortedUnique([...(byOwnerDigest[ownerDigest] ?? []), record.transactionId]);
      byState[record.lifecycle.persistedState] = sortedUnique([...(byState[record.lifecycle.persistedState] ?? []), record.transactionId]);
      byKeyDigest[sha256(canonicalize({ ownerPrincipal: record.ownerPrincipal, idempotencyKey: record.idempotencyKey }))] = record.transactionId;
    }
    return {
      owner: { schemaVersion: TRANSACTION_INDEX_SCHEMA_VERSION, recordsDigest, byOwnerDigest },
      state: { schemaVersion: TRANSACTION_INDEX_SCHEMA_VERSION, recordsDigest, byState },
      idempotency: { schemaVersion: TRANSACTION_INDEX_SCHEMA_VERSION, recordsDigest, byKeyDigest },
    };
  }

  rebuildIndexes(): TransactionIndexVerification {
    const expected = this.expectedIndexes();
    this.atomicWrite(join(this.indexesRoot, 'owner.json'), expected.owner, 'index');
    this.atomicWrite(join(this.indexesRoot, 'state.json'), expected.state, 'index');
    this.atomicWrite(join(this.indexesRoot, 'idempotency.json'), expected.idempotency, 'index');
    return { valid: true, ownerValid: true, stateValid: true, idempotencyValid: true, recordsDigest: expected.owner.recordsDigest, recordCount: this.list().length };
  }

  verifyIndexes(): TransactionIndexVerification {
    const records = this.list();
    const expected = this.expectedIndexes(records);
    const compare = (path: string, value: unknown): boolean => {
      try { return canonicalize(parseJson(path)) === canonicalize(value); } catch { return false; }
    };
    const ownerValid = compare(join(this.indexesRoot, 'owner.json'), expected.owner);
    const stateValid = compare(join(this.indexesRoot, 'state.json'), expected.state);
    const idempotencyValid = compare(join(this.indexesRoot, 'idempotency.json'), expected.idempotency);
    return { valid: ownerValid && stateValid && idempotencyValid, ownerValid, stateValid, idempotencyValid, recordsDigest: expected.owner.recordsDigest, recordCount: records.length };
  }

  initialize(): TransactionStartupVerification {
    const pending = this.recoverPending();
    const scan = this.scan(100_000);
    const before = this.verifyIndexes();
    if (!before.valid) this.rebuildIndexes();
    const indexes = this.verifyIndexes();
    return { recoveredPending: pending.recovered, corruptPending: pending.corrupt, indexes, repairedIndexes: !before.valid, corruptRecords: scan.corrupt };
  }

  newLeaseId(): string { return `tl_${randomUUID().replaceAll('-', '')}`; }

  activeLease(transactionId: string): TransactionControllerLeaseV1 | null {
    const path = this.leasePath(transactionId);
    if (!existsSync(path)) return null;
    try { return assertTransactionLease(parseJson(path)); }
    catch (error) { throw storeError('transaction_lease_corrupt', 'transaction controller lease is corrupt', { transactionId, cause: error instanceof Error ? error.message : String(error) }); }
  }

  acquireLease(leaseValue: TransactionControllerLeaseV1, observation: { observedAt: string; currentControllerAbsent: boolean }): TransactionControllerLeaseV1 {
    const requested = assertTransactionLease(leaseValue);
    const record = this.get(requested.transactionId);
    if (record.ownerPrincipal !== requested.ownerPrincipal) throw storeError('transaction_wrong_principal', 'lease principal does not own the transaction');
    const existing = this.activeLease(requested.transactionId);
    if (existing !== null) {
      if (existing.leaseId === requested.leaseId && existing.controllerId === requested.controllerId && existing.hostBootId === requested.hostBootId) return existing;
      const observedAt = Date.parse(observation.observedAt);
      const expiresAt = Date.parse(existing.expiresAt);
      if (!Number.isFinite(observedAt) || observedAt <= expiresAt) throw storeError('transaction_lease_overlap', 'a live transaction controller lease already exists', { leaseId: existing.leaseId });
      if (!observation.currentControllerAbsent) throw storeError('transaction_lease_takeover_unproven', 'stale lease takeover requires positive controller absence proof', { leaseId: existing.leaseId });
      requested.takeoverFromLeaseId = existing.leaseId;
    }
    this.atomicWrite(this.leasePath(requested.transactionId), requested, 'lease');
    return requested;
  }

  renewLease(transactionId: string, leaseId: string, ownerPrincipal: string, controllerId: string, hostBootId: string, renewedAt: string, expiresAt: string): TransactionControllerLeaseV1 {
    const current = this.activeLease(transactionId);
    if (current === null || current.leaseId !== leaseId || current.ownerPrincipal !== ownerPrincipal || current.controllerId !== controllerId || current.hostBootId !== hostBootId) throw storeError('transaction_lease_conflict', 'transaction lease renewal identity does not match');
    if (Date.parse(expiresAt) <= Date.parse(renewedAt)) throw storeError('transaction_invalid_request', 'renewed lease expiry must be after renewal time');
    const next = assertTransactionLease({ ...current, renewedAt, expiresAt });
    this.atomicWrite(this.leasePath(transactionId), next, 'lease');
    return next;
  }

  releaseLease(transactionId: string, leaseId: string, ownerPrincipal: string, controllerId: string): boolean {
    const current = this.activeLease(transactionId);
    if (current === null) return false;
    if (current.leaseId !== leaseId || current.ownerPrincipal !== ownerPrincipal || current.controllerId !== controllerId) throw storeError('transaction_lease_conflict', 'transaction lease release identity does not match');
    rmSync(this.leasePath(transactionId), { force: true });
    return true;
  }
}
