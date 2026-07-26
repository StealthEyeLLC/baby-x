import { randomUUID } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { canonicalize, sha256, type JsonObject } from '../core.ts';
import {
  RELEASE_SCHEMA_VERSION,
  ReleaseSchemaError,
  assertNoRawSecrets,
  validateReleaseRecord,
} from './schemas.ts';

export type ReleaseStoreErrorCode =
  | 'release_invalid_request'
  | 'release_record_not_found'
  | 'release_record_corrupt'
  | 'release_event_corrupt'
  | 'release_index_corrupt'
  | 'release_pending_corrupt'
  | 'release_stale_sequence'
  | 'release_wrong_principal'
  | 'release_idempotency_conflict'
  | 'release_controller_conflict'
  | 'release_stale_controller_unproven'
  | 'release_ambiguous_mutation';

export class ReleaseStoreError extends Error {
  readonly code: ReleaseStoreErrorCode;
  readonly details: JsonObject;
  constructor(code: ReleaseStoreErrorCode, message: string, details: JsonObject = {}) {
    super(message);
    this.name = 'ReleaseStoreError';
    this.code = code;
    this.details = details;
  }
}

export type ReleaseStoreFaultStage =
  | 'after_pending_write'
  | 'after_record_write'
  | 'after_event_write'
  | 'after_pending_commit';

export interface ReleaseStoreOptions {
  faultInjector?: (stage: ReleaseStoreFaultStage, context: JsonObject) => void;
}

export interface ReleaseMutationInput {
  schemaId: string;
  recordId: string;
  ownerPrincipal: string;
  expectedSequence: number;
  idempotencyKey: string;
  requestDigest: string;
  operation: string;
  phase: string;
  record: JsonObject;
  occurredAt?: string;
  childJobIds?: string[];
  artifactReferences?: JsonObject[];
  receiptReferences?: string[];
  observationDigest?: string;
}

export interface LeaseObservation {
  now?: string;
  currentBootId?: string;
  existingControllerAbsent: boolean;
}

export interface ReleaseIndexes extends JsonObject {
  schemaVersion: typeof RELEASE_SCHEMA_VERSION;
  bySchema: Record<string, string[]>;
  byOwner: Record<string, string[]>;
  byState: Record<string, string[]>;
  byService: Record<string, string[]>;
  byRelease: Record<string, string[]>;
  byRoute: Record<string, string[]>;
}

interface IdempotencyEntry extends JsonObject {
  keyDigest: string;
  requestDigest: string;
  schemaId: string;
  recordId: string;
  mutationId: string;
  eventDigest: string;
  committedAt: string;
}

interface IdempotencyIndex extends JsonObject {
  schemaVersion: typeof RELEASE_SCHEMA_VERSION;
  entries: Record<string, IdempotencyEntry>;
}

interface MutationAction extends JsonObject {
  kind: 'RECORD_REPLACEMENT';
  schemaId: string;
  recordId: string;
  candidateDigest: string;
  candidateRecord: JsonObject;
  event: JsonObject;
}

interface StartupDiagnostic extends JsonObject {
  kind: 'record' | 'event' | 'pending' | 'index' | 'lease';
  identity: string;
  code: string;
  message: string;
}

export interface ReleaseStartupReport extends JsonObject {
  processedRecords: number;
  recoveredPending: number;
  deferredRecords: number;
  deferredPending: number;
  corrupt: number;
  ambiguous: number;
  recoveryRequired: number;
  repairedIndexes: boolean;
  bounded: boolean;
  diagnostics: StartupDiagnostic[];
}

export interface ReleaseStoreVerification extends JsonObject {
  valid: boolean;
  records: number;
  events: number;
  pending: number;
  leases: number;
  indexesMatch: boolean;
  idempotencyMatch: boolean;
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const MAX_SCAN = 10_000;

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function jsonClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function safeSegment(value: string, name: string): string {
  if (!IDENTIFIER.test(value) || value === '.' || value === '..' || value.includes('/')) {
    throw new ReleaseStoreError('release_invalid_request', `${name} must be a safe identifier`, { [name]: value });
  }
  return value;
}

function assertDigest(value: string, name: string): void {
  if (!DIGEST.test(value)) throw new ReleaseStoreError('release_invalid_request', `${name} must be a lowercase SHA-256 digest`);
}

function assertSequence(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new ReleaseStoreError('release_invalid_request', `${name} must be a non-negative safe integer`);
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, 'r');
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function durableWrite(path: string, value: JsonObject): void {
  const parent = dirname(path);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(temporary, 'wx', 0o600);
    writeFileSync(descriptor, `${canonicalize(value)}\n`, { encoding: 'utf8' });
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, path);
    fsyncDirectory(parent);
  } catch (error) {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch { /* best effort after write failure */ }
    }
    try { unlinkSync(temporary); } catch { /* absent or already renamed */ }
    throw error;
  }
}

function durableRemove(path: string): void {
  if (!existsSync(path)) return;
  unlinkSync(path);
  fsyncDirectory(dirname(path));
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8')) as unknown;
}

function emptyIndexes(): ReleaseIndexes {
  return {
    schemaVersion: RELEASE_SCHEMA_VERSION,
    bySchema: {},
    byOwner: {},
    byState: {},
    byService: {},
    byRelease: {},
    byRoute: {},
  };
}

function emptyIdempotency(): IdempotencyIndex {
  return { schemaVersion: RELEASE_SCHEMA_VERSION, entries: {} };
}

function sortedUnique(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function recordRef(schemaId: string, recordId: string): string {
  return `${schemaId}:${recordId}`;
}

function stringProperty(record: JsonObject, key: string): string | undefined {
  return typeof record[key] === 'string' ? record[key] as string : undefined;
}

function recordState(record: JsonObject): string {
  return stringProperty(record, 'state') ?? stringProperty(record, 'desiredState') ?? 'PERSISTED';
}

function recordSequence(record: JsonObject): number | undefined {
  const value = record.sequence;
  return Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : undefined;
}

function ownerOf(record: JsonObject): string | undefined {
  return stringProperty(record, 'ownerPrincipal');
}

function eventDigest(event: JsonObject): string {
  const unsigned = { ...event };
  delete unsigned.eventDigest;
  return sha256(canonicalize(unsigned));
}

function pendingState(pending: JsonObject, state: string, occurredAt: string, extras: JsonObject = {}): JsonObject {
  return validateReleaseRecord('PendingMutationV1', {
    ...pending,
    ...extras,
    state,
    updatedAt: occurredAt,
  });
}

function normalizeError(error: unknown, fallbackCode: ReleaseStoreErrorCode): ReleaseStoreError {
  if (error instanceof ReleaseStoreError) return error;
  if (error instanceof ReleaseSchemaError) {
    return new ReleaseStoreError(fallbackCode, error.message, { schemaCode: error.code, path: error.path });
  }
  return new ReleaseStoreError(fallbackCode, error instanceof Error ? error.message : String(error));
}

function readDirectoryNames(path: string, suffix: string): string[] {
  if (!existsSync(path)) return [];
  return readdirSync(path).filter((name) => name.endsWith(suffix)).sort();
}

export class ReleaseApplianceStore {
  private readonly recordsRoot: string;
  private readonly eventsRoot: string;
  private readonly pendingRoot: string;
  private readonly leasesRoot: string;
  private readonly quarantineRoot: string;
  private readonly indexesPath: string;
  private readonly idempotencyPath: string;
  private readonly faultInjector?: ReleaseStoreOptions['faultInjector'];

  constructor(readonly root: string, options: ReleaseStoreOptions = {}) {
    this.recordsRoot = join(root, 'records');
    this.eventsRoot = join(root, 'events');
    this.pendingRoot = join(root, 'pending');
    this.leasesRoot = join(root, 'leases');
    this.quarantineRoot = join(root, 'quarantine');
    this.indexesPath = join(root, 'indexes.json');
    this.idempotencyPath = join(root, 'idempotency.json');
    this.faultInjector = options.faultInjector;
    for (const path of [root, this.recordsRoot, this.eventsRoot, this.pendingRoot, this.leasesRoot, this.quarantineRoot]) {
      mkdirSync(path, { recursive: true, mode: 0o700 });
    }
    if (!existsSync(this.indexesPath)) durableWrite(this.indexesPath, emptyIndexes());
    if (!existsSync(this.idempotencyPath)) durableWrite(this.idempotencyPath, emptyIdempotency());
  }

  private inject(stage: ReleaseStoreFaultStage, context: JsonObject): void {
    this.faultInjector?.(stage, jsonClone(context));
  }

  private schemaRoot(schemaId: string): string {
    return join(this.recordsRoot, safeSegment(schemaId, 'schemaId'));
  }

  private recordPath(schemaId: string, recordId: string): string {
    return join(this.schemaRoot(schemaId), `${safeSegment(recordId, 'recordId')}.json`);
  }

  private eventDirectory(schemaId: string, recordId: string): string {
    return join(this.eventsRoot, safeSegment(schemaId, 'schemaId'), safeSegment(recordId, 'recordId'));
  }

  private eventPath(schemaId: string, recordId: string, sequence: number): string {
    assertSequence(sequence, 'sequence');
    return join(this.eventDirectory(schemaId, recordId), `${String(sequence).padStart(12, '0')}.json`);
  }

  private pendingPath(mutationId: string): string {
    return join(this.pendingRoot, `${safeSegment(mutationId, 'mutationId')}.json`);
  }

  private leasePath(resourceType: string, resourceId: string): string {
    return join(this.leasesRoot, safeSegment(resourceType, 'resourceType'), `${safeSegment(resourceId, 'resourceId')}.json`);
  }

  private quarantinePath(kind: string, identity: string): string {
    return join(this.quarantineRoot, safeSegment(kind, 'kind'), `${sha256(identity)}.json`);
  }

  private readIndexes(): ReleaseIndexes {
    try {
      const value = readJson(this.indexesPath);
      if (!isObject(value) || value.schemaVersion !== RELEASE_SCHEMA_VERSION) throw new Error('unsupported indexes schema');
      for (const key of ['bySchema', 'byOwner', 'byState', 'byService', 'byRelease', 'byRoute']) {
        if (!isObject(value[key])) throw new Error(`indexes.${key} must be an object`);
      }
      return value as ReleaseIndexes;
    } catch (error) {
      throw new ReleaseStoreError('release_index_corrupt', error instanceof Error ? error.message : 'release indexes are corrupt');
    }
  }

  private readIdempotency(): IdempotencyIndex {
    try {
      const value = readJson(this.idempotencyPath);
      if (!isObject(value) || value.schemaVersion !== RELEASE_SCHEMA_VERSION || !isObject(value.entries)) throw new Error('idempotency index schema is invalid');
      return value as IdempotencyIndex;
    } catch (error) {
      throw new ReleaseStoreError('release_index_corrupt', error instanceof Error ? error.message : 'release idempotency index is corrupt');
    }
  }

  private writeRecord(schemaId: string, recordId: string, record: JsonObject): void {
    durableWrite(this.recordPath(schemaId, recordId), record);
  }

  private writePending(pending: JsonObject): void {
    durableWrite(this.pendingPath(String(pending.mutationId)), pending);
  }

  private writeEvent(schemaId: string, recordId: string, event: JsonObject): void {
    const sequence = Number(event.nextSequence);
    const path = this.eventPath(schemaId, recordId, sequence);
    if (existsSync(path)) {
      const existing = this.readEventFile(path, schemaId, recordId);
      if (canonicalize(existing) !== canonicalize(event)) {
        throw new ReleaseStoreError('release_event_corrupt', 'event sequence is already occupied by different bytes', { schemaId, recordId, sequence });
      }
      return;
    }
    durableWrite(path, event);
  }

  private quarantine(kind: StartupDiagnostic['kind'], identity: string, error: ReleaseStoreError): void {
    const marker: JsonObject = {
      schemaVersion: RELEASE_SCHEMA_VERSION,
      kind,
      identity,
      code: error.code,
      message: error.message.slice(0, 1024),
      detailsDigest: sha256(canonicalize(error.details)),
      detectedAt: new Date().toISOString(),
    };
    durableWrite(this.quarantinePath(kind, identity), marker);
  }

  private readEventFile(path: string, schemaId: string, recordId: string): JsonObject {
    try {
      const event = validateReleaseRecord('EventRecordV1', readJson(path));
      if (event.parentType !== schemaId || event.parentId !== recordId) throw new Error('event parent identity mismatch');
      if (eventDigest(event) !== event.eventDigest) throw new Error('event digest mismatch');
      return event;
    } catch (error) {
      throw normalizeError(error, 'release_event_corrupt');
    }
  }

  getRecord(schemaId: string, recordId: string): JsonObject {
    const path = this.recordPath(schemaId, recordId);
    if (!existsSync(path)) throw new ReleaseStoreError('release_record_not_found', 'release record not found', { schemaId, recordId });
    try { return validateReleaseRecord(schemaId, readJson(path)); }
    catch (error) { throw normalizeError(error, 'release_record_corrupt'); }
  }

  hasRecord(schemaId: string, recordId: string): boolean {
    return existsSync(this.recordPath(schemaId, recordId));
  }

  listRecordIdentities(limit = MAX_SCAN): { schemaId: string; recordId: string }[] {
    assertSequence(limit, 'limit');
    if (limit < 1 || limit > MAX_SCAN) throw new ReleaseStoreError('release_invalid_request', 'record list limit is out of bounds');
    const identities: { schemaId: string; recordId: string }[] = [];
    for (const schemaId of readDirectoryNames(this.recordsRoot, '')) {
      const schemaPath = join(this.recordsRoot, schemaId);
      for (const name of readDirectoryNames(schemaPath, '.json')) {
        identities.push({ schemaId, recordId: name.slice(0, -5) });
        if (identities.length >= limit) return identities;
      }
    }
    return identities;
  }

  events(schemaId: string, recordId: string, offset = 0, limit = 1_000): JsonObject[] {
    assertSequence(offset, 'offset');
    assertSequence(limit, 'limit');
    if (limit < 1 || limit > MAX_SCAN) throw new ReleaseStoreError('release_invalid_request', 'event limit is out of bounds');
    const directory = this.eventDirectory(schemaId, recordId);
    const names = readDirectoryNames(directory, '.json');
    const events: JsonObject[] = [];
    let previousDigest: string | undefined;
    let expectedSequence = 1;
    for (const name of names) {
      const event = this.readEventFile(join(directory, name), schemaId, recordId);
      if (event.priorSequence !== expectedSequence - 1 || event.nextSequence !== expectedSequence) {
        throw new ReleaseStoreError('release_event_corrupt', 'event sequence is not contiguous', { schemaId, recordId, expectedSequence });
      }
      if (event.previousEventDigest !== previousDigest) {
        throw new ReleaseStoreError('release_event_corrupt', 'event digest chain is not contiguous', { schemaId, recordId, expectedSequence });
      }
      events.push(event);
      previousDigest = String(event.eventDigest);
      expectedSequence += 1;
    }
    return events.slice(offset, offset + limit);
  }

  private allEvents(schemaId: string, recordId: string): JsonObject[] {
    const directory = this.eventDirectory(schemaId, recordId);
    const names = readDirectoryNames(directory, '.json');
    if (names.length > MAX_SCAN) throw new ReleaseStoreError('release_event_corrupt', 'event stream exceeds bounded verification limit', { schemaId, recordId, count: names.length });
    return this.events(schemaId, recordId, 0, Math.max(1, names.length));
  }

  private currentSequence(schemaId: string, recordId: string): number {
    const events = this.allEvents(schemaId, recordId);
    const sequence = events.length === 0 ? 0 : Number(events.at(-1)?.nextSequence);
    if (this.hasRecord(schemaId, recordId)) {
      const record = this.getRecord(schemaId, recordId);
      const persisted = recordSequence(record);
      if (persisted !== undefined && persisted !== sequence) {
        throw new ReleaseStoreError('release_event_corrupt', 'record sequence does not match event tail', { schemaId, recordId, recordSequence: persisted, eventSequence: sequence });
      }
    }
    return sequence;
  }

  private createEvent(input: ReleaseMutationInput, priorState: string, nextState: string, priorSequence: number, previousEventDigest: string | undefined): JsonObject {
    const occurredAt = input.occurredAt ?? new Date().toISOString();
    const nextSequence = priorSequence + 1;
    const unsigned: JsonObject = {
      schemaVersion: RELEASE_SCHEMA_VERSION,
      eventId: `evt_${sha256(canonicalize({ schemaId: input.schemaId, recordId: input.recordId, nextSequence, requestDigest: input.requestDigest })).slice(0, 40)}`,
      parentType: input.schemaId,
      parentId: input.recordId,
      ownerPrincipal: input.ownerPrincipal,
      operation: input.operation,
      phase: input.phase,
      priorState,
      nextState,
      priorSequence,
      nextSequence,
      requestDigest: input.requestDigest,
      idempotencyKey: input.idempotencyKey,
      occurredAt,
      ...(previousEventDigest === undefined ? {} : { previousEventDigest }),
      childJobIds: input.childJobIds ?? [],
      ...(input.observationDigest === undefined ? {} : { observationDigest: input.observationDigest }),
      artifactReferences: input.artifactReferences ?? [],
      receiptReferences: input.receiptReferences ?? [],
    };
    return validateReleaseRecord('EventRecordV1', { ...unsigned, eventDigest: eventDigest(unsigned) });
  }

  private idempotencyReplay(input: ReleaseMutationInput): JsonObject | undefined {
    const keyDigest = sha256(input.idempotencyKey);
    const entry = this.readIdempotency().entries[keyDigest];
    if (entry === undefined) return undefined;
    if (entry.requestDigest !== input.requestDigest) {
      throw new ReleaseStoreError('release_idempotency_conflict', 'idempotency key was already used with a different request digest', {
        schemaId: entry.schemaId,
        recordId: entry.recordId,
      });
    }
    return this.getRecord(entry.schemaId, entry.recordId);
  }

  private prepareMutation(input: ReleaseMutationInput): JsonObject {
    safeSegment(input.schemaId, 'schemaId');
    safeSegment(input.recordId, 'recordId');
    safeSegment(input.ownerPrincipal, 'ownerPrincipal');
    safeSegment(input.idempotencyKey, 'idempotencyKey');
    safeSegment(input.operation, 'operation');
    safeSegment(input.phase, 'phase');
    assertDigest(input.requestDigest, 'requestDigest');
    assertSequence(input.expectedSequence, 'expectedSequence');
    assertNoRawSecrets(input.record);
    const candidate = validateReleaseRecord(input.schemaId, input.record);
    const currentSequence = this.currentSequence(input.schemaId, input.recordId);
    if (currentSequence !== input.expectedSequence) {
      throw new ReleaseStoreError('release_stale_sequence', 'expected sequence does not match durable state', {
        expectedSequence: input.expectedSequence,
        actualSequence: currentSequence,
        schemaId: input.schemaId,
        recordId: input.recordId,
      });
    }
    const current = this.hasRecord(input.schemaId, input.recordId) ? this.getRecord(input.schemaId, input.recordId) : undefined;
    const existingOwner = current === undefined ? undefined : ownerOf(current);
    if (existingOwner !== undefined && existingOwner !== input.ownerPrincipal) {
      throw new ReleaseStoreError('release_wrong_principal', 'owner principal does not match authoritative record', { expectedOwner: existingOwner });
    }
    const candidateOwner = ownerOf(candidate);
    if (candidateOwner !== undefined && candidateOwner !== input.ownerPrincipal) {
      throw new ReleaseStoreError('release_wrong_principal', 'candidate owner principal does not match mutation principal', { candidateOwner });
    }
    const candidateSequence = recordSequence(candidate);
    if (candidateSequence !== undefined && candidateSequence !== input.expectedSequence + 1) {
      throw new ReleaseStoreError('release_stale_sequence', 'candidate record sequence must advance exactly once', { candidateSequence, expectedSequence: input.expectedSequence });
    }
    const existingEvents = this.allEvents(input.schemaId, input.recordId);
    const previous = existingEvents.at(-1);
    const event = this.createEvent(
      input,
      current === undefined ? 'ABSENT' : recordState(current),
      recordState(candidate),
      input.expectedSequence,
      previous === undefined ? undefined : String(previous.eventDigest),
    );
    const mutationId = `mut_${sha256(canonicalize({ idempotencyKey: input.idempotencyKey, requestDigest: input.requestDigest })).slice(0, 40)}`;
    const action: MutationAction = {
      kind: 'RECORD_REPLACEMENT',
      schemaId: input.schemaId,
      recordId: input.recordId,
      candidateDigest: sha256(canonicalize(candidate)),
      candidateRecord: candidate,
      event,
    };
    return validateReleaseRecord('PendingMutationV1', {
      schemaVersion: RELEASE_SCHEMA_VERSION,
      mutationId,
      parentType: input.schemaId,
      parentId: input.recordId,
      ownerPrincipal: input.ownerPrincipal,
      operation: input.operation,
      expectedSequence: input.expectedSequence,
      nextSequence: input.expectedSequence + 1,
      idempotencyKey: input.idempotencyKey,
      requestDigest: input.requestDigest,
      desiredState: recordState(candidate),
      externalAction: action,
      state: 'PREPARED',
      preparedAt: String(event.occurredAt),
      updatedAt: String(event.occurredAt),
    });
  }

  private readPendingFile(path: string): JsonObject {
    try { return validateReleaseRecord('PendingMutationV1', readJson(path)); }
    catch (error) { throw normalizeError(error, 'release_pending_corrupt'); }
  }

  getPending(mutationId: string): JsonObject | undefined {
    const path = this.pendingPath(mutationId);
    return existsSync(path) ? this.readPendingFile(path) : undefined;
  }

  listPending(limit = 1_000): JsonObject[] {
    assertSequence(limit, 'limit');
    if (limit < 1 || limit > MAX_SCAN) throw new ReleaseStoreError('release_invalid_request', 'pending list limit is out of bounds');
    return readDirectoryNames(this.pendingRoot, '.json').slice(0, limit).map((name) => this.readPendingFile(join(this.pendingRoot, name)));
  }

  private actionFrom(pending: JsonObject): MutationAction {
    const action = pending.externalAction;
    if (!isObject(action) || action.kind !== 'RECORD_REPLACEMENT' || typeof action.schemaId !== 'string' || typeof action.recordId !== 'string' || typeof action.candidateDigest !== 'string' || !isObject(action.candidateRecord) || !isObject(action.event)) {
      throw new ReleaseStoreError('release_pending_corrupt', 'pending mutation action is invalid', { mutationId: pending.mutationId });
    }
    return action as MutationAction;
  }

  private updateDerivedIndexes(record: JsonObject, schemaId: string, recordId: string, event: JsonObject): void {
    let indexes: ReleaseIndexes;
    let idempotency: IdempotencyIndex;
    try { indexes = this.readIndexes(); } catch { indexes = emptyIndexes(); }
    try { idempotency = this.readIdempotency(); } catch { idempotency = emptyIdempotency(); }
    const ref = recordRef(schemaId, recordId);
    const removeRef = (map: Record<string, string[]>): Record<string, string[]> => Object.fromEntries(
      Object.entries(map).map(([key, refs]) => [key, refs.filter((value) => value !== ref)]).filter(([, refs]) => refs.length > 0),
    );
    indexes = {
      schemaVersion: RELEASE_SCHEMA_VERSION,
      bySchema: removeRef(indexes.bySchema),
      byOwner: removeRef(indexes.byOwner),
      byState: removeRef(indexes.byState),
      byService: removeRef(indexes.byService),
      byRelease: removeRef(indexes.byRelease),
      byRoute: removeRef(indexes.byRoute),
    };
    const add = (map: Record<string, string[]>, key: string | undefined): void => {
      if (key !== undefined) map[key] = sortedUnique([...(map[key] ?? []), ref]);
    };
    add(indexes.bySchema, schemaId);
    add(indexes.byOwner, ownerOf(record));
    add(indexes.byState, recordState(record));
    add(indexes.byService, stringProperty(record, 'serviceId'));
    add(indexes.byRelease, stringProperty(record, 'releaseId'));
    add(indexes.byRoute, stringProperty(record, 'routeId'));
    const keyDigest = sha256(String(event.idempotencyKey));
    idempotency.entries[keyDigest] = {
      keyDigest,
      requestDigest: String(event.requestDigest),
      schemaId,
      recordId,
      mutationId: `mut_${sha256(canonicalize({ idempotencyKey: event.idempotencyKey, requestDigest: event.requestDigest })).slice(0, 40)}`,
      eventDigest: String(event.eventDigest),
      committedAt: String(event.occurredAt),
    };
    durableWrite(this.indexesPath, indexes);
    durableWrite(this.idempotencyPath, idempotency);
  }

  private commitPending(pendingValue: JsonObject): JsonObject {
    const pending = validateReleaseRecord('PendingMutationV1', pendingValue);
    const action = this.actionFrom(pending);
    const schemaId = String(action.schemaId);
    const recordId = String(action.recordId);
    const candidate = validateReleaseRecord(schemaId, action.candidateRecord);
    if (sha256(canonicalize(candidate)) !== action.candidateDigest) throw new ReleaseStoreError('release_pending_corrupt', 'pending candidate digest does not match candidate record', { mutationId: pending.mutationId });
    const event = validateReleaseRecord('EventRecordV1', action.event);
    if (eventDigest(event) !== event.eventDigest) throw new ReleaseStoreError('release_pending_corrupt', 'pending event digest is invalid', { mutationId: pending.mutationId });
    if (pending.ownerPrincipal !== event.ownerPrincipal || pending.requestDigest !== event.requestDigest || pending.idempotencyKey !== event.idempotencyKey) {
      throw new ReleaseStoreError('release_pending_corrupt', 'pending mutation identity does not match event identity', { mutationId: pending.mutationId });
    }
    const expectedSequence = Number(pending.expectedSequence);
    const nextSequence = Number(pending.nextSequence);
    const existingEvents = this.allEvents(schemaId, recordId);
    const existingEvent = existingEvents.find((item) => item.nextSequence === nextSequence);
    let recordMatches = false;
    if (this.hasRecord(schemaId, recordId)) {
      const durable = this.getRecord(schemaId, recordId);
      recordMatches = sha256(canonicalize(durable)) === action.candidateDigest;
    }
    const actualSequence = existingEvents.length === 0 ? 0 : Number(existingEvents.at(-1)?.nextSequence);
    if (!recordMatches) {
      if (actualSequence !== expectedSequence) {
        throw new ReleaseStoreError('release_ambiguous_mutation', 'durable state advanced beyond pending mutation without matching candidate bytes', { schemaId, recordId, expectedSequence, actualSequence });
      }
      this.writeRecord(schemaId, recordId, candidate);
      recordMatches = true;
      this.inject('after_record_write', { mutationId: pending.mutationId, schemaId, recordId });
    }
    if (existingEvent === undefined) {
      if (actualSequence !== expectedSequence) {
        throw new ReleaseStoreError('release_ambiguous_mutation', 'event tail advanced without the pending mutation event', { schemaId, recordId, expectedSequence, actualSequence });
      }
      this.writeEvent(schemaId, recordId, event);
      this.inject('after_event_write', { mutationId: pending.mutationId, schemaId, recordId });
    } else if (canonicalize(existingEvent) !== canonicalize(event)) {
      throw new ReleaseStoreError('release_ambiguous_mutation', 'event sequence contains a different mutation', { schemaId, recordId, nextSequence });
    }
    const committedAt = new Date().toISOString();
    const committed = pendingState(pending, 'COMMITTED', committedAt);
    this.writePending(committed);
    this.inject('after_pending_commit', { mutationId: pending.mutationId, schemaId, recordId });
    this.updateDerivedIndexes(candidate, schemaId, recordId, event);
    return candidate;
  }

  applyMutation(inputValue: ReleaseMutationInput): JsonObject {
    const input = jsonClone(inputValue);
    const replay = this.idempotencyReplay(input);
    if (replay !== undefined) return replay;
    const pending = this.prepareMutation(input);
    const path = this.pendingPath(String(pending.mutationId));
    if (existsSync(path)) {
      const existing = this.readPendingFile(path);
      if (existing.requestDigest !== pending.requestDigest || existing.idempotencyKey !== pending.idempotencyKey) {
        throw new ReleaseStoreError('release_idempotency_conflict', 'pending idempotency identity conflicts with request', { mutationId: pending.mutationId });
      }
      return this.commitPending(existing);
    }
    this.writePending(pending);
    this.inject('after_pending_write', { mutationId: pending.mutationId, schemaId: input.schemaId, recordId: input.recordId });
    return this.commitPending(pending);
  }

  markPendingReadbackRequired(mutationId: string, observationDigest?: string): JsonObject {
    const pending = this.getPending(mutationId);
    if (pending === undefined) throw new ReleaseStoreError('release_record_not_found', 'pending mutation not found', { mutationId });
    const updated = pendingState(pending, 'READBACK_REQUIRED', new Date().toISOString(), observationDigest === undefined ? {} : { observationDigest });
    this.writePending(updated);
    return updated;
  }

  resolvePendingAfterReadback(mutationId: string, observationDigest: string, actionObserved: boolean): JsonObject {
    assertDigest(observationDigest, 'observationDigest');
    const pending = this.getPending(mutationId);
    if (pending === undefined) throw new ReleaseStoreError('release_record_not_found', 'pending mutation not found', { mutationId });
    if (pending.state !== 'READBACK_REQUIRED' && pending.state !== 'SIDE_EFFECT_STARTED') {
      throw new ReleaseStoreError('release_invalid_request', 'pending mutation is not awaiting readback', { mutationId, state: pending.state });
    }
    if (!actionObserved) {
      const aborted = pendingState(pending, 'ABORTED', new Date().toISOString(), { observationDigest });
      this.writePending(aborted);
      return aborted;
    }
    const committing = pendingState(pending, 'COMMITTING', new Date().toISOString(), { observationDigest });
    this.writePending(committing);
    this.commitPending(committing);
    return this.getPending(mutationId) as JsonObject;
  }

  recoverPending(mutationId: string): JsonObject {
    const pending = this.getPending(mutationId);
    if (pending === undefined) throw new ReleaseStoreError('release_record_not_found', 'pending mutation not found', { mutationId });
    if (pending.state === 'COMMITTED' || pending.state === 'ABORTED') return pending;
    if (pending.state === 'SIDE_EFFECT_STARTED' || pending.state === 'READBACK_REQUIRED' || pending.state === 'AMBIGUOUS') {
      throw new ReleaseStoreError('release_ambiguous_mutation', 'pending mutation requires positive external readback', { mutationId, state: pending.state });
    }
    const committing = pending.state === 'COMMITTING' ? pending : pendingState(pending, 'COMMITTING', new Date().toISOString());
    if (pending.state !== 'COMMITTING') this.writePending(committing);
    this.commitPending(committing);
    return this.getPending(mutationId) as JsonObject;
  }

  acquireLease(leaseValue: JsonObject, observation: LeaseObservation): JsonObject {
    const lease = validateReleaseRecord('ControllerLeaseV1', leaseValue);
    const resourceType = String(lease.resourceType);
    const resourceId = String(lease.resourceId);
    const path = this.leasePath(resourceType, resourceId);
    if (existsSync(path)) {
      let existing: JsonObject;
      try { existing = validateReleaseRecord('ControllerLeaseV1', readJson(path)); }
      catch (error) { throw normalizeError(error, 'release_record_corrupt'); }
      if (existing.leaseId === lease.leaseId && existing.ownerPrincipal === lease.ownerPrincipal && existing.observationDigest === lease.observationDigest) return existing;
      const now = Date.parse(observation.now ?? new Date().toISOString());
      const live = existing.state === 'ACTIVE' && Date.parse(String(existing.expiresAt)) > now;
      if (live) throw new ReleaseStoreError('release_controller_conflict', 'resource already has a live controller lease', { resourceType, resourceId, leaseId: existing.leaseId });
      if (!observation.existingControllerAbsent) {
        throw new ReleaseStoreError('release_stale_controller_unproven', 'stale controller absence was not positively established', { resourceType, resourceId, leaseId: existing.leaseId });
      }
    }
    durableWrite(path, lease);
    return lease;
  }

  getLease(resourceType: string, resourceId: string): JsonObject | undefined {
    const path = this.leasePath(resourceType, resourceId);
    if (!existsSync(path)) return undefined;
    try { return validateReleaseRecord('ControllerLeaseV1', readJson(path)); }
    catch (error) { throw normalizeError(error, 'release_record_corrupt'); }
  }

  releaseLease(resourceType: string, resourceId: string, leaseId: string, ownerPrincipal: string, observationDigest: string, occurredAt = new Date().toISOString()): JsonObject | undefined {
    assertDigest(observationDigest, 'observationDigest');
    const current = this.getLease(resourceType, resourceId);
    if (current === undefined) return undefined;
    if (current.leaseId !== leaseId || current.ownerPrincipal !== ownerPrincipal) {
      throw new ReleaseStoreError('release_controller_conflict', 'lease identity or owner principal does not match', { resourceType, resourceId, leaseId });
    }
    const released = validateReleaseRecord('ControllerLeaseV1', {
      ...current,
      state: 'RELEASED',
      sequence: Number(current.sequence) + 1,
      expiresAt: occurredAt,
      observationDigest,
    });
    durableWrite(this.leasePath(resourceType, resourceId), released);
    return released;
  }

  private scanRecordIdentities(): { schemaId: string; recordId: string }[] {
    const identities: { schemaId: string; recordId: string }[] = [];
    for (const schemaId of readDirectoryNames(this.recordsRoot, '')) {
      const schemaPath = join(this.recordsRoot, schemaId);
      for (const name of readDirectoryNames(schemaPath, '.json')) identities.push({ schemaId, recordId: name.slice(0, -5) });
    }
    return identities;
  }

  rebuildDerivedIndexes(write = true, limit = MAX_SCAN): { indexes: ReleaseIndexes; idempotency: IdempotencyIndex; records: number; events: number; truncated: boolean } {
    assertSequence(limit, 'limit');
    if (limit < 1 || limit > MAX_SCAN) throw new ReleaseStoreError('release_invalid_request', 'rebuild limit is out of bounds');
    const identities = this.scanRecordIdentities();
    const selected = identities.slice(0, limit);
    const indexes = emptyIndexes();
    const idempotency = emptyIdempotency();
    let eventCount = 0;
    for (const { schemaId, recordId } of selected) {
      const record = this.getRecord(schemaId, recordId);
      const ref = recordRef(schemaId, recordId);
      const add = (map: Record<string, string[]>, key: string | undefined): void => {
        if (key !== undefined) map[key] = sortedUnique([...(map[key] ?? []), ref]);
      };
      add(indexes.bySchema, schemaId);
      add(indexes.byOwner, ownerOf(record));
      add(indexes.byState, recordState(record));
      add(indexes.byService, stringProperty(record, 'serviceId'));
      add(indexes.byRelease, stringProperty(record, 'releaseId'));
      add(indexes.byRoute, stringProperty(record, 'routeId'));
      const events = this.allEvents(schemaId, recordId);
      eventCount += events.length;
      const finalEvent = events.at(-1);
      if (finalEvent === undefined) throw new ReleaseStoreError('release_event_corrupt', 'authoritative record has no event stream', { schemaId, recordId });
      const persistedSequence = recordSequence(record);
      if (persistedSequence !== undefined && persistedSequence !== finalEvent.nextSequence) {
        throw new ReleaseStoreError('release_event_corrupt', 'record sequence does not match final event', { schemaId, recordId });
      }
      for (const event of events) {
        const key = event.idempotencyKey;
        if (typeof key !== 'string') continue;
        const keyDigest = sha256(key);
        const existing = idempotency.entries[keyDigest];
        if (existing !== undefined && existing.requestDigest !== event.requestDigest) {
          throw new ReleaseStoreError('release_idempotency_conflict', 'event history contains conflicting idempotency use', { schemaId, recordId });
        }
        idempotency.entries[keyDigest] = {
          keyDigest,
          requestDigest: String(event.requestDigest),
          schemaId,
          recordId,
          mutationId: `mut_${sha256(canonicalize({ idempotencyKey: key, requestDigest: event.requestDigest })).slice(0, 40)}`,
          eventDigest: String(event.eventDigest),
          committedAt: String(event.occurredAt),
        };
      }
    }
    const truncated = identities.length > limit;
    if (write && !truncated) {
      durableWrite(this.indexesPath, indexes);
      durableWrite(this.idempotencyPath, idempotency);
    }
    return { indexes, idempotency, records: selected.length, events: eventCount, truncated };
  }

  verifyAndRepairIndexes(limit = MAX_SCAN): ReleaseStoreVerification & { repairedIndexes: boolean } {
    const rebuilt = this.rebuildDerivedIndexes(false, limit);
    if (rebuilt.truncated) throw new ReleaseStoreError('release_invalid_request', 'cannot verify indexes with a truncated record scan', { limit });
    let indexesMatch = false;
    let idempotencyMatch = false;
    try { indexesMatch = canonicalize(this.readIndexes()) === canonicalize(rebuilt.indexes); } catch { indexesMatch = false; }
    try { idempotencyMatch = canonicalize(this.readIdempotency()) === canonicalize(rebuilt.idempotency); } catch { idempotencyMatch = false; }
    const repairedIndexes = !indexesMatch || !idempotencyMatch;
    if (repairedIndexes) {
      durableWrite(this.indexesPath, rebuilt.indexes);
      durableWrite(this.idempotencyPath, rebuilt.idempotency);
      indexesMatch = true;
      idempotencyMatch = true;
    }
    return {
      valid: true,
      records: rebuilt.records,
      events: rebuilt.events,
      pending: readDirectoryNames(this.pendingRoot, '.json').length,
      leases: this.leaseCount(),
      indexesMatch,
      idempotencyMatch,
      repairedIndexes,
    };
  }

  private leaseCount(): number {
    let count = 0;
    for (const resourceType of readDirectoryNames(this.leasesRoot, '')) count += readDirectoryNames(join(this.leasesRoot, resourceType), '.json').length;
    return count;
  }

  verify(limit = MAX_SCAN): ReleaseStoreVerification {
    const rebuilt = this.rebuildDerivedIndexes(false, limit);
    if (rebuilt.truncated) throw new ReleaseStoreError('release_invalid_request', 'verification record scan was truncated', { limit });
    const indexesMatch = canonicalize(this.readIndexes()) === canonicalize(rebuilt.indexes);
    const idempotencyMatch = canonicalize(this.readIdempotency()) === canonicalize(rebuilt.idempotency);
    if (!indexesMatch || !idempotencyMatch) throw new ReleaseStoreError('release_index_corrupt', 'derived indexes do not match authoritative records and events', { indexesMatch, idempotencyMatch });
    return {
      valid: true,
      records: rebuilt.records,
      events: rebuilt.events,
      pending: readDirectoryNames(this.pendingRoot, '.json').length,
      leases: this.leaseCount(),
      indexesMatch,
      idempotencyMatch,
    };
  }

  startupScan(recordLimit = 1_000, pendingLimit = 1_000): ReleaseStartupReport {
    assertSequence(recordLimit, 'recordLimit');
    assertSequence(pendingLimit, 'pendingLimit');
    if (recordLimit < 1 || recordLimit > MAX_SCAN || pendingLimit < 1 || pendingLimit > MAX_SCAN) {
      throw new ReleaseStoreError('release_invalid_request', 'startup scan limits are out of bounds');
    }
    const diagnostics: StartupDiagnostic[] = [];
    const identities = this.scanRecordIdentities();
    let processedRecords = 0;
    let corrupt = 0;
    for (const identity of identities.slice(0, recordLimit)) {
      try {
        this.getRecord(identity.schemaId, identity.recordId);
        this.allEvents(identity.schemaId, identity.recordId);
        processedRecords += 1;
      } catch (error) {
        const normalized = normalizeError(error, 'release_record_corrupt');
        corrupt += 1;
        const key = `${identity.schemaId}:${identity.recordId}`;
        diagnostics.push({ kind: normalized.code === 'release_event_corrupt' ? 'event' : 'record', identity: key, code: normalized.code, message: normalized.message.slice(0, 1024) });
        this.quarantine(normalized.code === 'release_event_corrupt' ? 'event' : 'record', key, normalized);
      }
    }
    const pendingNames = readDirectoryNames(this.pendingRoot, '.json');
    let recoveredPending = 0;
    let ambiguous = 0;
    let recoveryRequired = 0;
    for (const name of pendingNames.slice(0, pendingLimit)) {
      const mutationId = name.slice(0, -5);
      try {
        const pending = this.readPendingFile(join(this.pendingRoot, name));
        if (pending.state === 'COMMITTED' || pending.state === 'ABORTED') continue;
        if (pending.state === 'SIDE_EFFECT_STARTED' || pending.state === 'READBACK_REQUIRED' || pending.state === 'AMBIGUOUS') {
          ambiguous += 1;
          diagnostics.push({ kind: 'pending', identity: mutationId, code: 'release_ambiguous_mutation', message: 'positive readback is required before recovery' });
          continue;
        }
        this.recoverPending(mutationId);
        recoveredPending += 1;
      } catch (error) {
        const normalized = normalizeError(error, 'release_pending_corrupt');
        if (normalized.code === 'release_ambiguous_mutation') ambiguous += 1;
        else { corrupt += 1; this.quarantine('pending', mutationId, normalized); }
        recoveryRequired += 1;
        diagnostics.push({ kind: 'pending', identity: mutationId, code: normalized.code, message: normalized.message.slice(0, 1024) });
      }
    }
    const deferredRecords = Math.max(0, identities.length - recordLimit);
    const deferredPending = Math.max(0, pendingNames.length - pendingLimit);
    let repairedIndexes = false;
    if (deferredRecords === 0 && corrupt === 0) {
      try { repairedIndexes = this.verifyAndRepairIndexes(recordLimit).repairedIndexes; }
      catch (error) {
        const normalized = normalizeError(error, 'release_index_corrupt');
        diagnostics.push({ kind: 'index', identity: 'derived', code: normalized.code, message: normalized.message.slice(0, 1024) });
        recoveryRequired += 1;
      }
    }
    return {
      processedRecords,
      recoveredPending,
      deferredRecords,
      deferredPending,
      corrupt,
      ambiguous,
      recoveryRequired,
      repairedIndexes,
      bounded: deferredRecords > 0 || deferredPending > 0,
      diagnostics,
    };
  }

  removeCommittedPending(mutationId: string): void {
    const pending = this.getPending(mutationId);
    if (pending === undefined) return;
    if (pending.state !== 'COMMITTED' && pending.state !== 'ABORTED') throw new ReleaseStoreError('release_invalid_request', 'only terminal pending records may be removed', { mutationId, state: pending.state });
    durableRemove(this.pendingPath(mutationId));
  }

  resetDerivedIndexesForTest(): void {
    durableWrite(this.indexesPath, emptyIndexes());
    durableWrite(this.idempotencyPath, emptyIdempotency());
  }

  derivedIndexPaths(): { indexesPath: string; idempotencyPath: string } {
    return { indexesPath: this.indexesPath, idempotencyPath: this.idempotencyPath };
  }

  authoritativeRecordPath(schemaId: string, recordId: string): string {
    return this.recordPath(schemaId, recordId);
  }

  authoritativeEventPath(schemaId: string, recordId: string, sequence: number): string {
    return this.eventPath(schemaId, recordId, sequence);
  }
}
