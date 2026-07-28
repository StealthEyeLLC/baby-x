import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../storage/record-store.ts';
import { RootFabricError, contextPrincipal, digest, idempotency, identifier, integer, object, strictObject, stringArray, text, timestamp, type ObservationCompleteness } from './model.ts';

export const ROOT_OBSERVATION_SCHEMA_VERSION = '1.1.0' as const;
export type RootObservationKind = 'PROCESS' | 'FILESYSTEM' | 'SERVICE' | 'MOUNT' | 'NETWORK' | 'ACCOUNTING' | 'OBSERVER';
export type RootObservationSource = 'EBPF' | 'BPFTRACE' | 'SYSTEMD' | 'PROC' | 'PIDFD' | 'PROCESS_WRAPPER' | 'PACKET_CAPTURE' | 'TARGET_READBACK' | 'BOUNDED_LOG';

export interface RootObservationEvent extends JsonObject {
  schemaVersion: typeof ROOT_OBSERVATION_SCHEMA_VERSION;
  eventId: string;
  sessionId: string;
  sequence: number;
  transactionId: string;
  stepId: string;
  kind: RootObservationKind;
  source: RootObservationSource;
  occurredAt: string;
  cgroupId: string | null;
  unitName: string | null;
  machineId: string | null;
  processId: number | null;
  processStartTime: string | null;
  bootId: string | null;
  data: JsonObject;
  previousEventDigest: string | null;
  eventDigest: string;
}

export interface RootObservationSession extends JsonObject {
  schemaVersion: typeof ROOT_OBSERVATION_SCHEMA_VERSION;
  sessionId: string;
  ownerPrincipalDigest: string;
  transactionId: string;
  stepId: string;
  provider: string;
  transactionSequence: number;
  fencingToken: number;
  transactionDeadline: string;
  operationDeadline: string;
  executionBindingDigest: string;
  unitNames: string[];
  machineIds: string[];
  processIdentities: JsonObject[];
  requiredKinds: RootObservationKind[];
  requiredSources: RootObservationSource[];
  fallbackSources: RootObservationSource[];
  state: 'ACTIVE' | 'FINALIZED' | 'FAILED';
  completeness: ObservationCompleteness;
  maxEvents: number;
  maxBytes: number;
  maxDurationMs: number;
  startedAt: string;
  deadline: string;
  finalizedAt: string | null;
  events: RootObservationEvent[];
  eventCount: number;
  eventHeadDigest: string | null;
  inlineBytes: number;
  droppedEvents: number;
  overflow: boolean;
  sourceStatus: JsonObject;
  artifactIds: string[];
  summaryDigest: string | null;
  recordDigest: string;
}


export interface ObservationTransactionBinding extends JsonObject {
  transactionId: string;
  stepId: string;
  ownerPrincipalDigest: string;
  provider: string;
  transactionSequence: number;
  fencingToken: number;
  transactionDeadline: string;
  operationDeadline: string;
  executionBindingDigest: string;
  unitNames: string[];
  machineIds: string[];
  processIdentities: JsonObject[];
}

export interface ObservationAuthority {
  resolve(input: { transactionId: string; stepId: string; principalId: string; principalDigest: string; occurredAt: string }): ObservationTransactionBinding;
  assertEvent(binding: ObservationTransactionBinding, eventIdentity: JsonObject): void;
}

interface ObservationMutationResult extends JsonObject {
  mutation: 'RECORD' | 'FINALIZE';
  priorRecordDigest: string;
  next: RootObservationSession;
  accepted: boolean | null;
  dropped: boolean | null;
  reason: string | null;
  event: RootObservationEvent | null;
}

const DENY_OBSERVATION_AUTHORITY: ObservationAuthority = {
  resolve() { throw new RootFabricError('observation_unavailable', 'authoritative transaction observation binding is unavailable'); },
  assertEvent() { throw new RootFabricError('observation_unavailable', 'authoritative transaction observation binding is unavailable'); },
};

interface ObservationArtifactAuthority {
  spill(name: string, value: JsonObject, metadata: JsonObject): Promise<{ artifactId: string }>;
}

const KINDS = new Set<RootObservationKind>(['PROCESS', 'FILESYSTEM', 'SERVICE', 'MOUNT', 'NETWORK', 'ACCOUNTING', 'OBSERVER']);
const SOURCES = new Set<RootObservationSource>(['EBPF', 'BPFTRACE', 'SYSTEMD', 'PROC', 'PIDFD', 'PROCESS_WRAPPER', 'PACKET_CAPTURE', 'TARGET_READBACK', 'BOUNDED_LOG']);
const SECRET_KEY = /(?:secret|token|password|private.?key|cookie|authorization|credential|bearer|connection.?string)/iu;

function unsigned(record: RootObservationSession): JsonObject {
  const { recordDigest: _recordDigest, ...rest } = record;
  return rest;
}

function seal(record: Omit<RootObservationSession, 'recordDigest'>): RootObservationSession {
  return { ...record, recordDigest: sha256(canonicalize(record)) };
}

function verify(record: RootObservationSession): boolean {
  if (record.recordDigest !== sha256(canonicalize(unsigned(record)))) return false;
  let previous: string | null = null;
  for (let index = 0; index < record.events.length; index += 1) {
    const event = record.events[index]!;
    if (event.sequence !== index + 1 || event.previousEventDigest !== previous || event.eventDigest !== sha256(canonicalize(eventUnsigned(event)))) return false;
    previous = event.eventDigest;
  }
  return record.eventCount === record.events.length && record.eventHeadDigest === previous;
}


export function redactObservation(value: unknown, key = ''): unknown {
  if (SECRET_KEY.test(key)) return '[REDACTED]';
  if (typeof value === 'string') {
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/u.test(value)) return '[REDACTED]';
    if (/^(?:Bearer\s+)?[A-Za-z0-9_=-]{32,}$/u.test(value)) return '[REDACTED]';
    return value.length > 65_536 ? `${value.slice(0, 65_536)}[TRUNCATED]` : value;
  }
  if (Array.isArray(value)) return value.slice(0, 4_096).map((entry) => redactObservation(entry, key));
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value as Record<string, unknown>).slice(0, 4_096).map(([childKey, child]) => [childKey, redactObservation(child, childKey)]));
  return value;
}

function kind(value: unknown, field: string): RootObservationKind {
  const normalized = text(value, field, 32) as RootObservationKind;
  if (!KINDS.has(normalized)) throw new RootFabricError('invalid_request', `${field} is invalid`);
  return normalized;
}

function source(value: unknown, field: string): RootObservationSource {
  const normalized = text(value, field, 32) as RootObservationSource;
  if (!SOURCES.has(normalized)) throw new RootFabricError('invalid_request', `${field} is invalid`);
  return normalized;
}

function kindList(value: unknown, field: string): RootObservationKind[] {
  return stringArray(value, field, 7, false).map((entry) => kind(entry, field)).sort();
}

function sourceList(value: unknown, field: string, allowEmpty = true): RootObservationSource[] {
  return stringArray(value, field, SOURCES.size, allowEmpty).map((entry) => source(entry, field)).sort();
}


function normalizedSourceStatus(value: unknown): JsonObject {
  const redacted = redactObservation(object(value, 'sourceStatus')) as JsonObject;
  const entries = Object.entries(redacted);
  if (entries.length > SOURCES.size) throw new RootFabricError('invalid_request', 'sourceStatus contains too many sources');
  const result: JsonObject = {};
  for (const [key, statusValue] of entries) {
    const normalizedSource = source(key, `sourceStatus.${key}`);
    const status = text(statusValue, `sourceStatus.${key}`, 32);
    if (!['AVAILABLE', 'UNAVAILABLE', 'DEGRADED', 'FAILED'].includes(status)) throw new RootFabricError('invalid_request', `sourceStatus.${key} is invalid`);
    result[normalizedSource] = status;
  }
  return result;
}

function eventUnsigned(event: RootObservationEvent): JsonObject {
  const { eventDigest: _eventDigest, ...rest } = event;
  return rest;
}

export class RootObservationService {
  private readonly records: DurableRecordStore<RootObservationSession>;
  private readonly startClaims: DurableClaimStore<RootObservationSession>;
  private readonly mutationClaims: DurableClaimStore<ObservationMutationResult>;
  private readonly now: () => string;
  private readonly authority: ObservationAuthority;

  constructor(stateRoot: string, private readonly artifacts?: ObservationArtifactAuthority, options: { now?: () => string; authority?: ObservationAuthority } = {}) {
    const root = join(stateRoot, 'root-fabric', 'observations');
    this.records = new DurableRecordStore(join(root, 'sessions'));
    this.startClaims = new DurableClaimStore(join(root, 'claims'));
    this.mutationClaims = new DurableClaimStore(join(root, 'mutation-claims'));
    this.now = options.now ?? (() => new Date().toISOString());
    this.authority = options.authority ?? DENY_OBSERVATION_AUTHORITY;
  }

  start(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'observation start payload', ['transactionId', 'stepId', 'requiredKinds', 'requiredSources', 'fallbackSources', 'maxEvents', 'maxBytes', 'maxDurationMs']);
    const occurredAt = this.now();
    const principal = contextPrincipal(context, occurredAt);
    const idem = idempotency(context);
    const transactionId = identifier(payload.transactionId, 'transactionId');
    const stepId = identifier(payload.stepId, 'stepId');
    const binding = this.authority.resolve({ transactionId, stepId, principalId: principal.principalId, principalDigest: principal.principalDigest, occurredAt });
    if (binding.transactionId !== transactionId || binding.stepId !== stepId || binding.ownerPrincipalDigest !== principal.principalDigest) throw new RootFabricError('principal_mismatch', 'observation authority returned a mismatched binding');
    const requestedDurationMs = integer(payload.maxDurationMs ?? 300_000, 'maxDurationMs', 1_000, 3_600_000);
    const authoritativeDeadline = Math.min(Date.parse(binding.transactionDeadline), Date.parse(binding.operationDeadline));
    const maxDurationMs = Math.min(requestedDurationMs, authoritativeDeadline - Date.parse(occurredAt));
    if (!Number.isSafeInteger(maxDurationMs) || maxDurationMs < 1_000) throw new RootFabricError('deadline_exceeded', 'observation deadline is unavailable');
    const normalized = {
      transactionId, stepId, provider: text(binding.provider, 'provider', 32),
      transactionSequence: integer(binding.transactionSequence, 'transactionSequence', 1, 10_000_000), fencingToken: integer(binding.fencingToken, 'fencingToken', 1, Number.MAX_SAFE_INTEGER),
      transactionDeadline: timestamp(binding.transactionDeadline, 'transactionDeadline'), operationDeadline: timestamp(binding.operationDeadline, 'operationDeadline'),
      executionBindingDigest: digest(binding.executionBindingDigest, 'executionBindingDigest'), unitNames: stringArray(binding.unitNames, 'unitNames', 128), machineIds: stringArray(binding.machineIds, 'machineIds', 256), processIdentities: binding.processIdentities.map((entry) => object(entry, 'processIdentity')),
      requiredKinds: kindList(payload.requiredKinds, 'requiredKinds'), requiredSources: sourceList(payload.requiredSources, 'requiredSources'), fallbackSources: sourceList(payload.fallbackSources ?? [], 'fallbackSources'),
      maxEvents: integer(payload.maxEvents ?? 10_000, 'maxEvents', 1, 100_000), maxBytes: integer(payload.maxBytes ?? 8_388_608, 'maxBytes', 1_024, 67_108_864), maxDurationMs,
    };
    const request = sha256(canonicalize({ operation: 'babyx.root.observation.start', principal: principal.principalDigest, normalized }));
    const claimKey = `${principal.principalDigest}:${idem.key}`;
    const existing = this.startClaims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another observation start');
      if (!this.records.has(existing.recordId)) this.records.create(existing.recordId, existing.record);
      return { session: this.records.get(existing.recordId), replayed: true };
    }
    const sessionId = `obs_${randomUUID().replaceAll('-', '')}`;
    const record = seal({ schemaVersion: ROOT_OBSERVATION_SCHEMA_VERSION, sessionId, ownerPrincipalDigest: principal.principalDigest, ...normalized, state: 'ACTIVE', completeness: 'UNAVAILABLE', startedAt: occurredAt, deadline: new Date(Date.parse(occurredAt) + normalized.maxDurationMs).toISOString(), finalizedAt: null, events: [], eventCount: 0, eventHeadDigest: null, inlineBytes: 0, droppedEvents: 0, overflow: false, sourceStatus: {}, artifactIds: [], summaryDigest: null });
    const claim = this.startClaims.claim(claimKey, request, sessionId, record);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another observation start');
    if (!this.records.has(claim.recordId)) this.records.create(claim.recordId, claim.record);
    return { session: this.records.get(claim.recordId), replayed: claim.recordId !== sessionId };
  }

  get(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'observation get payload', ['sessionId', 'offset', 'limit']);
    const record = this.read(identifier(payload.sessionId, 'sessionId'));
    const principal = contextPrincipal(context, this.now());
    const idem = idempotency(context);
    if (principal.principalDigest !== record.ownerPrincipalDigest) throw new RootFabricError('principal_mismatch', 'observation owner mismatch');
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, 10_000_000);
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, 200);
    const events = record.events.slice(offset, offset + limit);
    return { session: { ...record, events }, offset, limit, total: record.events.length, nextOffset: offset + events.length < record.events.length ? offset + events.length : null };
  }

  record(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'observation record payload', ['sessionId', 'transactionId', 'stepId', 'kind', 'source', 'occurredAt', 'cgroupId', 'unitName', 'machineId', 'processId', 'processStartTime', 'bootId', 'data']);
    const record = this.read(identifier(payload.sessionId, 'sessionId'));
    const principal = contextPrincipal(context, this.now());
    const idem = idempotency(context);
    if (principal.principalDigest !== record.ownerPrincipalDigest) throw new RootFabricError('principal_mismatch', 'observation owner mismatch');
    if (record.state !== 'ACTIVE') throw new RootFabricError('transaction_state_conflict', 'observation session is not active');
    if (record.transactionId !== payload.transactionId || record.stepId !== payload.stepId) throw new RootFabricError('principal_mismatch', 'observation correlation does not match the session');
    const now = this.now();
    const expired = Date.parse(record.deadline) <= Date.parse(now);
    const eventKind = kind(payload.kind, 'kind');
    const eventSource = source(payload.source, 'source');
    const redacted = redactObservation(object(payload.data, 'data')) as JsonObject;
    const request = sha256(canonicalize({ operation: 'babyx.root.observation.record', principal: principal.principalDigest, payload: { ...payload, data: redacted } }));
    const claimKey = `${record.sessionId}:record:${principal.principalDigest}:${idem.digest}`;
    const existingClaim = this.mutationClaims.get(claimKey);
    if (existingClaim !== undefined) {
      if (existingClaim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another observation record');
      const result = existingClaim.record;
      const live = this.recoverClaimedMutation(record.sessionId, result);
      return { accepted: result.accepted, dropped: result.dropped, reason: result.reason, event: result.event, session: { sessionId: live.sessionId, eventCount: live.eventCount, inlineBytes: live.inlineBytes, droppedEvents: live.droppedEvents, completeness: live.completeness }, replayed: true };
    }
    const base = {
      schemaVersion: ROOT_OBSERVATION_SCHEMA_VERSION, eventId: `obe_${randomUUID().replaceAll('-', '')}`, sessionId: record.sessionId,
      sequence: record.eventCount + 1, transactionId: record.transactionId, stepId: record.stepId, kind: eventKind, source: eventSource,
      occurredAt: payload.occurredAt === undefined ? now : timestamp(payload.occurredAt, 'occurredAt'),
      cgroupId: payload.cgroupId === null || payload.cgroupId === undefined ? null : text(payload.cgroupId, 'cgroupId', 256),
      unitName: payload.unitName === null || payload.unitName === undefined ? null : identifier(payload.unitName, 'unitName'),
      machineId: payload.machineId === null || payload.machineId === undefined ? null : identifier(payload.machineId, 'machineId'),
      processId: payload.processId === null || payload.processId === undefined ? null : integer(payload.processId, 'processId', 1, 2 ** 31 - 1),
      processStartTime: payload.processStartTime === null || payload.processStartTime === undefined ? null : text(payload.processStartTime, 'processStartTime', 128),
      bootId: payload.bootId === null || payload.bootId === undefined ? null : identifier(payload.bootId, 'bootId'), data: redacted, previousEventDigest: record.eventHeadDigest,
    };
    this.authority.assertEvent(record, { unitName: base.unitName, machineId: base.machineId, processId: base.processId, processStartTime: base.processStartTime, bootId: base.bootId, cgroupId: base.cgroupId });
    const event: RootObservationEvent = { ...base, eventDigest: sha256(canonicalize(base)) };
    const bytes = Buffer.byteLength(canonicalize(event));
    if (expired || record.events.length >= record.maxEvents || record.inlineBytes + bytes > record.maxBytes) {
      const next = seal({ ...unsigned(record), droppedEvents: record.droppedEvents + 1, overflow: true, completeness: record.events.length === 0 ? 'UNAVAILABLE' : 'PARTIAL' } as Omit<RootObservationSession, 'recordDigest'>);
      const reason = expired ? 'duration_limit' : record.events.length >= record.maxEvents ? 'event_limit' : 'byte_limit';
      const result: ObservationMutationResult = { mutation: 'RECORD', priorRecordDigest: record.recordDigest, next, accepted: false, dropped: true, reason, event: null };
      const claim = this.mutationClaims.claim(claimKey, request, record.sessionId, result);
      if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another observation record');
      if (this.read(record.sessionId).recordDigest !== record.recordDigest) throw new RootFabricError('transaction_state_conflict', 'observation changed before record commit');
      this.records.put(record.sessionId, next);
      return { accepted: false, dropped: true, reason, session: next, replayed: false };
    }
    const next = seal({ ...unsigned(record), events: [...record.events, event], eventCount: record.eventCount + 1, eventHeadDigest: event.eventDigest, inlineBytes: record.inlineBytes + bytes, completeness: 'PARTIAL' } as Omit<RootObservationSession, 'recordDigest'>);
    const result: ObservationMutationResult = { mutation: 'RECORD', priorRecordDigest: record.recordDigest, next, accepted: true, dropped: false, reason: null, event };
    const claim = this.mutationClaims.claim(claimKey, request, record.sessionId, result);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another observation record');
    if (this.read(record.sessionId).recordDigest !== record.recordDigest) throw new RootFabricError('transaction_state_conflict', 'observation changed before record commit');
    this.records.put(record.sessionId, next);
    return { accepted: true, dropped: false, event, session: { sessionId: next.sessionId, eventCount: next.eventCount, inlineBytes: next.inlineBytes, droppedEvents: next.droppedEvents, completeness: next.completeness }, replayed: false };
  }

  async finalize(payloadValue: unknown, context: RuntimeExecutionContext): Promise<JsonObject> {
    const payload = strictObject(payloadValue, 'observation finalize payload', ['sessionId', 'sourceStatus', 'spill']);
    const record = this.read(identifier(payload.sessionId, 'sessionId'));
    const principal = contextPrincipal(context, this.now());
    const idem = idempotency(context);
    if (principal.principalDigest !== record.ownerPrincipalDigest) throw new RootFabricError('principal_mismatch', 'observation owner mismatch');
    const sourceStatus = normalizedSourceStatus(payload.sourceStatus);
    const request = sha256(canonicalize({ operation: 'babyx.root.observation.finalize', principal: principal.principalDigest, sessionId: record.sessionId, sourceStatus, spill: payload.spill === true }));
    const claimKey = `${record.sessionId}:finalize:${principal.principalDigest}:${idem.digest}`;
    const existingClaim = this.mutationClaims.get(claimKey);
    if (existingClaim !== undefined) { if (existingClaim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another observation finalize'); return { session: this.recoverClaimedMutation(record.sessionId, existingClaim.record), replayed: true }; }
    if (record.state === 'FINALIZED') return { session: record, replayed: true };
    const observedKinds = new Set(record.events.map((event) => event.kind));
    const observedSources = new Set(record.events.map((event) => event.source));
    const kindsComplete = record.requiredKinds.every((required) => observedKinds.has(required));
    const sourcesComplete = record.requiredSources.every((required) => observedSources.has(required) && sourceStatus[required] === 'AVAILABLE');
    const fallbackUsed = record.requiredSources.some((required) => !observedSources.has(required)) && record.fallbackSources.some((fallback) => observedSources.has(fallback));
    let completeness: ObservationCompleteness = record.events.length === 0 ? 'UNAVAILABLE' : record.droppedEvents > 0 || !kindsComplete ? 'PARTIAL' : fallbackUsed || !sourcesComplete ? 'DEGRADED' : 'COMPLETE';
    const artifactIds = [...record.artifactIds];
    if (payload.spill === true && this.artifacts !== undefined && record.events.length > 0) {
      const artifact = await this.artifacts.spill(`root-observation-${record.sessionId}`, { events: record.events }, { transactionId: record.transactionId, stepId: record.stepId, sessionId: record.sessionId });
      artifactIds.push(artifact.artifactId);
    }
    const finalizedAt = this.now();
    const summary = { transactionId: record.transactionId, stepId: record.stepId, eventCount: record.eventCount, droppedEvents: record.droppedEvents, completeness, observedKinds: [...observedKinds].sort(), observedSources: [...observedSources].sort(), sourceStatus, artifactIds };
    const next = seal({ ...unsigned(record), state: 'FINALIZED', completeness, finalizedAt, sourceStatus, artifactIds, summaryDigest: sha256(canonicalize(summary)) } as Omit<RootObservationSession, 'recordDigest'>);
    const result: ObservationMutationResult = { mutation: 'FINALIZE', priorRecordDigest: record.recordDigest, next, accepted: null, dropped: null, reason: null, event: null };
    const claim = this.mutationClaims.claim(claimKey, request, record.sessionId, result);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another observation finalize');
    if (this.read(record.sessionId).recordDigest !== record.recordDigest) throw new RootFabricError('transaction_state_conflict', 'observation changed before finalize commit');
    this.records.put(record.sessionId, next);
    return { session: next, replayed: false };
  }

  active(limit = 4_096): RootObservationSession[] { return this.records.scan((record) => record.state === 'ACTIVE', 0, limit).records.filter(verify); }
  fail(sessionId: string, reason: string): RootObservationSession {
    const record = this.read(sessionId);
    const next = seal({ ...unsigned(record), state: 'FAILED', completeness: record.events.length === 0 ? 'UNAVAILABLE' : 'PARTIAL', finalizedAt: this.now(), sourceStatus: { ...record.sourceStatus, failure: text(reason, 'reason', 1_024) }, summaryDigest: sha256(canonicalize({ reason, sessionId })) } as Omit<RootObservationSession, 'recordDigest'>);
    this.records.put(sessionId, next); return next;
  }

  private recoverClaimedMutation(sessionId: string, result: ObservationMutationResult): RootObservationSession {
    const live = this.read(sessionId);
    if (live.recordDigest === result.next.recordDigest) return live;
    if (live.recordDigest === result.priorRecordDigest) {
      this.records.put(sessionId, result.next);
      return this.read(sessionId);
    }
    const descendant = live.eventCount >= result.next.eventCount
      && live.droppedEvents >= result.next.droppedEvents
      && result.next.events.every((event, index) => live.events[index]?.eventDigest === event.eventDigest)
      && (result.next.state === 'ACTIVE' || live.state === result.next.state);
    if (!descendant) throw new RootFabricError('transaction_state_conflict', 'observation mutation claim conflicts with authoritative session state');
    return live;
  }

  private read(sessionId: string): RootObservationSession {
    try { const record = this.records.get(sessionId); if (!verify(record)) throw new RootFabricError('corrupt_record', 'observation record integrity failed'); return record; }
    catch (error) { if (error instanceof RootFabricError) throw error; throw new RootFabricError('observation_unavailable', 'observation session not found', { sessionId }); }
  }
}
