import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../storage/record-store.ts';
import { RootFabricError, contextPrincipal, digest, idempotency, identifier, integer, object, strictObject, stringArray, text, timestamp, type ObservationCompleteness } from './model.ts';

export const ROOT_OBSERVATION_SCHEMA_VERSION = '1.0.0' as const;
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
  eventDigest: string;
}

export interface RootObservationSession extends JsonObject {
  schemaVersion: typeof ROOT_OBSERVATION_SCHEMA_VERSION;
  sessionId: string;
  ownerPrincipalDigest: string;
  transactionId: string;
  stepId: string;
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
  inlineBytes: number;
  droppedEvents: number;
  overflow: boolean;
  sourceStatus: JsonObject;
  artifactIds: string[];
  summaryDigest: string | null;
  recordDigest: string;
}

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
  return record.recordDigest === sha256(canonicalize(unsigned(record))) && record.events.every((event, index) => event.sequence === index + 1 && event.eventDigest === sha256(canonicalize(eventUnsigned(event))));
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

function eventUnsigned(event: RootObservationEvent): JsonObject {
  const { eventDigest: _eventDigest, ...rest } = event;
  return rest;
}

export class RootObservationService {
  private readonly records: DurableRecordStore<RootObservationSession>;
  private readonly claims: DurableClaimStore<RootObservationSession>;
  private readonly now: () => string;

  constructor(stateRoot: string, private readonly artifacts?: ObservationArtifactAuthority, options: { now?: () => string } = {}) {
    const root = join(stateRoot, 'root-fabric', 'observations');
    this.records = new DurableRecordStore(join(root, 'sessions'));
    this.claims = new DurableClaimStore(join(root, 'claims'));
    this.now = options.now ?? (() => new Date().toISOString());
  }

  start(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'observation start payload', ['transactionId', 'stepId', 'requiredKinds', 'requiredSources', 'fallbackSources', 'maxEvents', 'maxBytes', 'maxDurationMs']);
    const occurredAt = this.now();
    const principal = contextPrincipal(context, occurredAt);
    const idem = idempotency(context);
    const normalized = {
      transactionId: identifier(payload.transactionId, 'transactionId'), stepId: identifier(payload.stepId, 'stepId'),
      requiredKinds: kindList(payload.requiredKinds, 'requiredKinds'), requiredSources: sourceList(payload.requiredSources, 'requiredSources'), fallbackSources: sourceList(payload.fallbackSources ?? [], 'fallbackSources'),
      maxEvents: integer(payload.maxEvents ?? 10_000, 'maxEvents', 1, 100_000), maxBytes: integer(payload.maxBytes ?? 8_388_608, 'maxBytes', 1_024, 67_108_864), maxDurationMs: integer(payload.maxDurationMs ?? 300_000, 'maxDurationMs', 1_000, 3_600_000),
    };
    const request = sha256(canonicalize({ operation: 'babyx.root.observation.start', principal: principal.principalDigest, normalized }));
    const claimKey = `${principal.principalDigest}:${idem.key}`;
    const existing = this.claims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another observation start');
      if (!this.records.has(existing.recordId)) this.records.create(existing.recordId, existing.record);
      return { session: this.records.get(existing.recordId), replayed: true };
    }
    const sessionId = `obs_${randomUUID().replaceAll('-', '')}`;
    const record = seal({ schemaVersion: ROOT_OBSERVATION_SCHEMA_VERSION, sessionId, ownerPrincipalDigest: principal.principalDigest, ...normalized, state: 'ACTIVE', completeness: 'UNAVAILABLE', startedAt: occurredAt, deadline: new Date(Date.parse(occurredAt) + normalized.maxDurationMs).toISOString(), finalizedAt: null, events: [], eventCount: 0, inlineBytes: 0, droppedEvents: 0, overflow: false, sourceStatus: {}, artifactIds: [], summaryDigest: null });
    const claim = this.claims.claim(claimKey, request, sessionId, record);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another observation start');
    if (!this.records.has(claim.recordId)) this.records.create(claim.recordId, claim.record);
    return { session: this.records.get(claim.recordId), replayed: claim.recordId !== sessionId };
  }

  get(payloadValue: unknown): JsonObject {
    const payload = strictObject(payloadValue, 'observation get payload', ['sessionId', 'offset', 'limit']);
    const record = this.read(identifier(payload.sessionId, 'sessionId'));
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, 10_000_000);
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, 200);
    const events = record.events.slice(offset, offset + limit);
    return { session: { ...record, events }, offset, limit, total: record.events.length, nextOffset: offset + events.length < record.events.length ? offset + events.length : null };
  }

  record(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'observation record payload', ['sessionId', 'transactionId', 'stepId', 'kind', 'source', 'occurredAt', 'cgroupId', 'unitName', 'machineId', 'processId', 'processStartTime', 'bootId', 'data']);
    const record = this.read(identifier(payload.sessionId, 'sessionId'));
    const principal = contextPrincipal(context, this.now());
    if (principal.principalDigest !== record.ownerPrincipalDigest) throw new RootFabricError('principal_mismatch', 'observation owner mismatch');
    if (record.state !== 'ACTIVE') throw new RootFabricError('transaction_state_conflict', 'observation session is not active');
    if (record.transactionId !== payload.transactionId || record.stepId !== payload.stepId) throw new RootFabricError('principal_mismatch', 'observation correlation does not match the session');
    const now = this.now();
    const expired = Date.parse(record.deadline) <= Date.parse(now);
    const eventKind = kind(payload.kind, 'kind');
    const eventSource = source(payload.source, 'source');
    const redacted = redactObservation(object(payload.data, 'data')) as JsonObject;
    const base = {
      schemaVersion: ROOT_OBSERVATION_SCHEMA_VERSION, eventId: `obe_${randomUUID().replaceAll('-', '')}`, sessionId: record.sessionId,
      sequence: record.eventCount + 1, transactionId: record.transactionId, stepId: record.stepId, kind: eventKind, source: eventSource,
      occurredAt: payload.occurredAt === undefined ? now : timestamp(payload.occurredAt, 'occurredAt'),
      cgroupId: payload.cgroupId === null || payload.cgroupId === undefined ? null : text(payload.cgroupId, 'cgroupId', 256),
      unitName: payload.unitName === null || payload.unitName === undefined ? null : identifier(payload.unitName, 'unitName'),
      machineId: payload.machineId === null || payload.machineId === undefined ? null : identifier(payload.machineId, 'machineId'),
      processId: payload.processId === null || payload.processId === undefined ? null : integer(payload.processId, 'processId', 1, 2 ** 31 - 1),
      processStartTime: payload.processStartTime === null || payload.processStartTime === undefined ? null : text(payload.processStartTime, 'processStartTime', 128),
      bootId: payload.bootId === null || payload.bootId === undefined ? null : identifier(payload.bootId, 'bootId'), data: redacted,
    };
    const event: RootObservationEvent = { ...base, eventDigest: sha256(canonicalize(base)) };
    const bytes = Buffer.byteLength(canonicalize(event));
    if (expired || record.events.length >= record.maxEvents || record.inlineBytes + bytes > record.maxBytes) {
      const next = seal({ ...unsigned(record), droppedEvents: record.droppedEvents + 1, overflow: true, completeness: record.events.length === 0 ? 'UNAVAILABLE' : 'PARTIAL' } as Omit<RootObservationSession, 'recordDigest'>);
      this.records.put(record.sessionId, next);
      return { accepted: false, dropped: true, reason: expired ? 'duration_limit' : record.events.length >= record.maxEvents ? 'event_limit' : 'byte_limit', session: next };
    }
    const next = seal({ ...unsigned(record), events: [...record.events, event], eventCount: record.eventCount + 1, inlineBytes: record.inlineBytes + bytes, completeness: 'PARTIAL' } as Omit<RootObservationSession, 'recordDigest'>);
    this.records.put(record.sessionId, next);
    return { accepted: true, event, session: { sessionId: next.sessionId, eventCount: next.eventCount, inlineBytes: next.inlineBytes, droppedEvents: next.droppedEvents, completeness: next.completeness } };
  }

  async finalize(payloadValue: unknown, context: RuntimeExecutionContext): Promise<JsonObject> {
    const payload = strictObject(payloadValue, 'observation finalize payload', ['sessionId', 'sourceStatus', 'spill']);
    const record = this.read(identifier(payload.sessionId, 'sessionId'));
    const principal = contextPrincipal(context, this.now());
    if (principal.principalDigest !== record.ownerPrincipalDigest) throw new RootFabricError('principal_mismatch', 'observation owner mismatch');
    if (record.state === 'FINALIZED') return { session: record, replayed: true };
    const sourceStatus = object(payload.sourceStatus, 'sourceStatus');
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
    this.records.put(record.sessionId, next);
    return { session: next, replayed: false };
  }

  active(limit = 4_096): RootObservationSession[] { return this.records.scan((record) => record.state === 'ACTIVE', 0, limit).records.filter(verify); }
  fail(sessionId: string, reason: string): RootObservationSession {
    const record = this.read(sessionId);
    const next = seal({ ...unsigned(record), state: 'FAILED', completeness: record.events.length === 0 ? 'UNAVAILABLE' : 'PARTIAL', finalizedAt: this.now(), sourceStatus: { ...record.sourceStatus, failure: text(reason, 'reason', 1_024) }, summaryDigest: sha256(canonicalize({ reason, sessionId })) } as Omit<RootObservationSession, 'recordDigest'>);
    this.records.put(sessionId, next); return next;
  }

  private read(sessionId: string): RootObservationSession {
    try { const record = this.records.get(sessionId); if (!verify(record)) throw new RootFabricError('corrupt_record', 'observation record integrity failed'); return record; }
    catch (error) { if (error instanceof RootFabricError) throw error; throw new RootFabricError('observation_unavailable', 'observation session not found', { sessionId }); }
  }
}
