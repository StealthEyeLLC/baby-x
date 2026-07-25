import { randomUUID } from 'node:crypto';
import { appendFileSync, existsSync, fsyncSync, mkdirSync, openSync, closeSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { AtomicStore, canonicalize, sha256, type JsonObject } from '../core.ts';
import { MachineServiceError } from './errors.ts';
import {
  MACHINE_SCHEMA_VERSION,
  assertDisposableMachineRecord,
  assertMachineControllerLease,
  assertMachineEvent,
  assertMachineTombstone,
  createMachineEvent,
  type DisposableMachineRecordV1,
  type MachineControllerLeaseV1,
  type MachineDesiredState,
  type MachineEventDraft,
  type MachineEventV1,
  type MachineState,
  type MachineTombstoneV1,
} from './schemas.ts';
import { assertMachineTransition, isTerminalMachineState } from './states.ts';

interface MachineIndexes extends JsonObject {
  byName: Record<string, string>;
  byDataset: Record<string, string>;
  byRoot: Record<string, string>;
  byState: Record<string, string[]>;
}

interface MachineIdempotencyEntry {
  keyDigest: string;
  requestDigest: string;
  machineId: string;
  createdAt: string;
}

interface MachineIdempotencyState extends JsonObject {
  entries: Record<string, MachineIdempotencyEntry>;
}

export interface MachineEventDetails {
  operation: string;
  phase: string;
  kind: string;
  message: string;
  requestDigest?: string;
  idempotencyKey?: string;
  controllerLeaseId?: string;
  jobId?: string;
  artifactId?: string;
  proofReference?: string;
  observationDigest?: string;
  occurredAt?: string;
}

export interface MachineLeaseObservation {
  currentBootId: string;
  existingOwnerAlive?: boolean;
  now?: string;
}

export interface MachineStoreVerification {
  valid: boolean;
  records: number;
  events: number;
  tombstones: number;
  indexesMatch: boolean;
}

function emptyIndexes(): MachineIndexes {
  return { byName: {}, byDataset: {}, byRoot: {}, byState: {} };
}

function jsonObject(value: unknown): JsonObject {
  return value as JsonObject;
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, 'r');
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

export class DisposableMachineStore {
  private readonly recordsRoot: string;
  private readonly eventsRoot: string;
  private readonly leasesRoot: string;
  private readonly tombstonesRoot: string;
  private readonly indexes: AtomicStore<MachineIndexes>;
  private readonly idempotency: AtomicStore<MachineIdempotencyState>;

  constructor(readonly root: string) {
    this.recordsRoot = join(root, 'records');
    this.eventsRoot = join(root, 'events');
    this.leasesRoot = join(root, 'leases');
    this.tombstonesRoot = join(root, 'tombstones');
    for (const path of [this.recordsRoot, this.eventsRoot, this.leasesRoot, this.tombstonesRoot]) mkdirSync(path, { recursive: true, mode: 0o700 });
    this.indexes = new AtomicStore(join(root, 'indexes.json'), emptyIndexes());
    this.idempotency = new AtomicStore(join(root, 'idempotency.json'), { entries: {} });
  }

  private recordPath(machineId: string): string { return join(this.recordsRoot, `${machineId}.json`); }
  private eventPath(machineId: string): string { return join(this.eventsRoot, `${machineId}.jsonl`); }
  private leasePath(machineId: string): string { return join(this.leasesRoot, `${machineId}.json`); }
  private tombstonePath(machineId: string): string { return join(this.tombstonesRoot, `${machineId}.json`); }

  private writeRecord(record: DisposableMachineRecordV1): void {
    new AtomicStore(this.recordPath(record.machineId), jsonObject(record)).write(jsonObject(record));
  }

  private writeLease(lease: MachineControllerLeaseV1): void {
    new AtomicStore(this.leasePath(lease.machineId), jsonObject(lease)).write(jsonObject(lease));
  }

  private writeTombstone(tombstone: MachineTombstoneV1): void {
    new AtomicStore(this.tombstonePath(tombstone.machineId), jsonObject(tombstone)).write(jsonObject(tombstone));
  }

  private appendEvent(event: MachineEventV1): void {
    const path = this.eventPath(event.machineId);
    const existed = existsSync(path);
    appendFileSync(path, `${canonicalize(event)}\n`, { encoding: 'utf8', mode: 0o600 });
    const descriptor = openSync(path, 'r');
    try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
    if (!existed) fsyncDirectory(this.eventsRoot);
  }

  private assertIndexClaimsAvailable(record: DisposableMachineRecordV1): void {
    const current = this.indexes.read();
    const conflicts: [MachineServiceError['code'], string | undefined, string][] = [
      ['machine_name_conflict', current.byName[record.machineName], record.machineName],
      ['machine_dataset_conflict', current.byDataset[record.clone.dataset], record.clone.dataset],
      ['machine_root_conflict', current.byRoot[record.clone.mountpoint], record.clone.mountpoint],
    ];
    for (const [code, owner, resource] of conflicts) {
      if (owner !== undefined && owner !== record.machineId) throw new MachineServiceError(code, `machine resource is already owned: ${resource}`, { resource, owner });
    }
  }

  private reserveIndexes(record: DisposableMachineRecordV1): void {
    this.indexes.update((current) => {
      const claims: [string | undefined, string][] = [
        [current.byName[record.machineName], record.machineName],
        [current.byDataset[record.clone.dataset], record.clone.dataset],
        [current.byRoot[record.clone.mountpoint], record.clone.mountpoint],
      ];
      for (const [owner, resource] of claims) {
        if (owner !== undefined && owner !== record.machineId) throw new MachineServiceError('machine_index_corrupt', `machine resource ownership changed after validation: ${resource}`, { resource, owner, machineId: record.machineId });
      }
      const byState = Object.fromEntries(
        Object.entries(current.byState)
          .map(([state, ids]) => [state, ids.filter((id) => id !== record.machineId)] as const)
          .filter(([, ids]) => ids.length > 0),
      );
      if (!isTerminalMachineState(record.lifecycle.persistedState)) byState[record.lifecycle.persistedState] = [...(byState[record.lifecycle.persistedState] ?? []), record.machineId].sort();
      return {
        byName: isTerminalMachineState(record.lifecycle.persistedState) ? Object.fromEntries(Object.entries(current.byName).filter(([, id]) => id !== record.machineId)) : { ...current.byName, [record.machineName]: record.machineId },
        byDataset: isTerminalMachineState(record.lifecycle.persistedState) ? Object.fromEntries(Object.entries(current.byDataset).filter(([, id]) => id !== record.machineId)) : { ...current.byDataset, [record.clone.dataset]: record.machineId },
        byRoot: isTerminalMachineState(record.lifecycle.persistedState) ? Object.fromEntries(Object.entries(current.byRoot).filter(([, id]) => id !== record.machineId)) : { ...current.byRoot, [record.clone.mountpoint]: record.machineId },
        byState,
      };
    });
  }

  private eventFrom(record: DisposableMachineRecordV1, priorState: MachineState | undefined, offset: number, details: MachineEventDetails, previousEventDigest?: string): MachineEventV1 {
    const draft: MachineEventDraft = {
      schemaVersion: MACHINE_SCHEMA_VERSION,
      machineId: record.machineId,
      offset,
      stateSequence: record.lifecycle.stateSequence,
      ...(priorState === undefined ? {} : { priorState }),
      nextState: record.lifecycle.persistedState,
      desiredState: record.lifecycle.desiredState,
      operation: details.operation,
      phase: details.phase,
      kind: details.kind,
      message: details.message,
      ...(details.requestDigest === undefined ? {} : { requestDigest: details.requestDigest }),
      ...(details.idempotencyKey === undefined ? {} : { idempotencyKey: details.idempotencyKey }),
      ...(details.controllerLeaseId === undefined ? {} : { controllerLeaseId: details.controllerLeaseId }),
      ...(details.jobId === undefined ? {} : { jobId: details.jobId }),
      ...(details.artifactId === undefined ? {} : { artifactId: details.artifactId }),
      ...(details.proofReference === undefined ? {} : { proofReference: details.proofReference }),
      ...(details.observationDigest === undefined ? {} : { observationDigest: details.observationDigest }),
      ...(previousEventDigest === undefined ? {} : { previousEventDigest }),
      occurredAt: details.occurredAt ?? new Date().toISOString(),
    };
    return createMachineEvent(draft);
  }

  create(recordValue: unknown, details: MachineEventDetails): DisposableMachineRecordV1 {
    const record = assertDisposableMachineRecord(recordValue);
    if (record.lifecycle.persistedState !== 'REQUESTED' || record.lifecycle.stateSequence !== 1) throw new MachineServiceError('machine_state_conflict', 'new machine records must begin at REQUESTED sequence 1');
    if (existsSync(this.tombstonePath(record.machineId))) throw new MachineServiceError('machine_tombstone_conflict', 'machine identity has already been destroyed and cannot be reused', { machineId: record.machineId });
    const keyDigest = sha256(record.creationIdempotencyKey);
    const replay = this.idempotency.read().entries[keyDigest];
    if (replay !== undefined) {
      if (replay.requestDigest !== record.creationRequestDigest) throw new MachineServiceError('machine_idempotency_conflict', 'idempotency key was already used with a different request digest', { machineId: replay.machineId });
      return this.get(replay.machineId);
    }
    if (existsSync(this.recordPath(record.machineId))) throw new MachineServiceError('machine_state_conflict', 'machine record already exists', { machineId: record.machineId });
    this.assertIndexClaimsAvailable(record);
    const event = this.eventFrom(record, undefined, 0, details);
    this.appendEvent(event);
    this.writeRecord(record);
    this.idempotency.update((current) => ({ entries: { ...current.entries, [keyDigest]: { keyDigest, requestDigest: record.creationRequestDigest, machineId: record.machineId, createdAt: event.occurredAt } } }));
    this.reserveIndexes(record);
    return record;
  }

  get(machineId: string): DisposableMachineRecordV1 {
    const path = this.recordPath(machineId);
    if (!existsSync(path)) throw new MachineServiceError('machine_not_found', 'machine record not found', { machineId });
    try { return assertDisposableMachineRecord(JSON.parse(readFileSync(path, 'utf8')) as unknown); }
    catch (error) {
      if (error instanceof MachineServiceError && error.code === 'machine_record_corrupt') throw error;
      throw new MachineServiceError('machine_record_corrupt', error instanceof Error ? error.message : 'machine record could not be decoded', { machineId });
    }
  }

  getByName(machineName: string): DisposableMachineRecordV1 {
    const machineId = this.indexes.read().byName[machineName];
    if (machineId === undefined) throw new MachineServiceError('machine_not_found', 'machine record not found by name', { machineName });
    return this.get(machineId);
  }

  list(): DisposableMachineRecordV1[] {
    return readdirSync(this.recordsRoot).filter((name: string) => name.endsWith('.json')).sort().map((name: string) => this.get(name.slice(0, -5)));
  }

  private readAllEvents(machineId: string): MachineEventV1[] {
    const path = this.eventPath(machineId);
    if (!existsSync(path)) return [];
    const lines = readFileSync(path, 'utf8').split('\n').filter((line: string) => line.length > 0);
    const events: MachineEventV1[] = [];
    let previousDigest: string | undefined;
    for (const [index, line] of lines.entries()) {
      let parsed: unknown;
      try { parsed = JSON.parse(line) as unknown; }
      catch { throw new MachineServiceError('machine_event_corrupt', 'machine event contains invalid JSON', { machineId, offset: index }); }
      let event: MachineEventV1;
      try { event = assertMachineEvent(parsed); }
      catch (error) {
        if (error instanceof MachineServiceError && error.code === 'machine_event_corrupt') throw error;
        throw new MachineServiceError('machine_event_corrupt', error instanceof Error ? error.message : 'machine event could not be decoded', { machineId, offset: index });
      }
      if (event.machineId !== machineId || event.offset !== index || event.previousEventDigest !== previousDigest) throw new MachineServiceError('machine_event_corrupt', 'machine event chain is not monotonic', { machineId, offset: index });
      events.push(event);
      previousDigest = event.eventDigest;
    }
    return events;
  }

  events(machineId: string, offset = 0, limit = 100): MachineEventV1[] {
    if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) throw new MachineServiceError('machine_invalid_request', 'event pagination is out of bounds');
    return this.readAllEvents(machineId).slice(offset, offset + limit);
  }

  transition(machineId: string, expectedSequence: number, nextState: MachineState, desiredState: MachineDesiredState, details: MachineEventDetails, patch: Partial<DisposableMachineRecordV1> = {}): DisposableMachineRecordV1 {
    const current = this.get(machineId);
    const nextSequence = assertMachineTransition(current.lifecycle.persistedState, nextState, current.lifecycle.stateSequence, expectedSequence);
    const occurredAt = details.occurredAt ?? new Date().toISOString();
    const candidate = assertDisposableMachineRecord({
      ...current,
      ...patch,
      machineId: current.machineId,
      machineName: current.machineName,
      providerId: current.providerId,
      creationIdempotencyKey: current.creationIdempotencyKey,
      creationRequestDigest: current.creationRequestDigest,
      source: current.source,
      clone: current.clone,
      lifecycle: {
        ...current.lifecycle,
        ...(patch.lifecycle ?? {}),
        desiredState,
        persistedState: nextState,
        stateSequence: nextSequence,
        terminal: isTerminalMachineState(nextState),
        updatedAt: occurredAt,
        ...(nextState === 'DESTROYED' ? { destroyedAt: occurredAt } : {}),
      },
    });
    const allEvents = this.readAllEvents(machineId);
    const priorEvent = allEvents.at(-1);
    const event = this.eventFrom(candidate, current.lifecycle.persistedState, allEvents.length, { ...details, occurredAt }, priorEvent?.eventDigest);
    this.appendEvent(event);
    this.writeRecord(candidate);
    this.reserveIndexes(candidate);
    return candidate;
  }

  acquireLease(leaseValue: unknown, observation: MachineLeaseObservation): MachineControllerLeaseV1 {
    const lease = assertMachineControllerLease(leaseValue);
    const path = this.leasePath(lease.machineId);
    if (existsSync(path)) {
      const existing = assertMachineControllerLease(JSON.parse(readFileSync(path, 'utf8')) as unknown);
      if (existing.leaseId === lease.leaseId && existing.requestDigest === lease.requestDigest) return existing;
      const now = Date.parse(observation.now ?? new Date().toISOString());
      const oldBoot = existing.hostBootId !== observation.currentBootId;
      const expiredAndDead = Date.parse(existing.expiresAt) <= now && observation.existingOwnerAlive === false;
      if (!oldBoot && !expiredAndDead) throw new MachineServiceError('machine_controller_conflict', 'machine already has an active controller lease', { machineId: lease.machineId, leaseId: existing.leaseId });
    }
    this.writeLease(lease);
    return lease;
  }

  getLease(machineId: string): MachineControllerLeaseV1 | undefined {
    const path = this.leasePath(machineId);
    return existsSync(path) ? assertMachineControllerLease(JSON.parse(readFileSync(path, 'utf8')) as unknown) : undefined;
  }

  releaseLease(machineId: string, leaseId: string): void {
    const existing = this.getLease(machineId);
    if (existing === undefined) return;
    if (existing.leaseId !== leaseId) throw new MachineServiceError('machine_controller_conflict', 'controller lease identity does not match', { machineId, leaseId, actualLeaseId: existing.leaseId });
    rmSync(this.leasePath(machineId), { force: true });
    fsyncDirectory(this.leasesRoot);
  }

  createTombstone(machineId: string): MachineTombstoneV1 {
    const record = this.get(machineId);
    if (record.lifecycle.persistedState !== 'DESTROYED' || !record.cleanup.completed || record.lifecycle.destroyedAt === undefined) throw new MachineServiceError('machine_state_conflict', 'only completely cleaned DESTROYED machines may be tombstoned', { machineId });
    const finalEvent = this.readAllEvents(machineId).at(-1);
    if (finalEvent === undefined) throw new MachineServiceError('machine_event_corrupt', 'cannot tombstone a machine without events', { machineId });
    const tombstone = assertMachineTombstone({
      schemaVersion: MACHINE_SCHEMA_VERSION,
      machineId,
      machineName: record.machineName,
      ownerPrincipal: record.ownerPrincipal,
      sourceSnapshot: record.source.snapshot,
      cloneDataset: record.clone.dataset,
      creationRequestDigest: record.creationRequestDigest,
      destroyedAt: record.lifecycle.destroyedAt,
      finalEventDigest: finalEvent.eventDigest,
      cleanupEvidenceReferences: record.cleanup.retainedEvidence,
    });
    this.writeTombstone(tombstone);
    return tombstone;
  }

  getTombstone(machineId: string): MachineTombstoneV1 | undefined {
    const path = this.tombstonePath(machineId);
    return existsSync(path) ? assertMachineTombstone(JSON.parse(readFileSync(path, 'utf8')) as unknown) : undefined;
  }

  rebuildIndexes(write = true): MachineIndexes {
    const rebuilt = emptyIndexes();
    for (const record of this.list()) {
      if (isTerminalMachineState(record.lifecycle.persistedState)) continue;
      const claims: [Record<string, string>, string, string, 'machine_name_conflict' | 'machine_dataset_conflict' | 'machine_root_conflict'][] = [
        [rebuilt.byName, record.machineName, record.machineId, 'machine_name_conflict'],
        [rebuilt.byDataset, record.clone.dataset, record.machineId, 'machine_dataset_conflict'],
        [rebuilt.byRoot, record.clone.mountpoint, record.machineId, 'machine_root_conflict'],
      ];
      for (const [index, resource, machineId, code] of claims) {
        const owner = index[resource];
        if (owner !== undefined && owner !== machineId) throw new MachineServiceError(code, 'duplicate resource ownership found while rebuilding indexes', { resource, owner, machineId });
        index[resource] = machineId;
      }
      rebuilt.byState[record.lifecycle.persistedState] = [...(rebuilt.byState[record.lifecycle.persistedState] ?? []), record.machineId].sort();
    }
    if (write) this.indexes.write(rebuilt);
    return rebuilt;
  }

  verify(): MachineStoreVerification {
    let eventCount = 0;
    for (const record of this.list()) {
      const events = this.readAllEvents(record.machineId);
      eventCount += events.length;
      const finalEvent = events.at(-1);
      if (finalEvent === undefined || finalEvent.stateSequence !== record.lifecycle.stateSequence || finalEvent.nextState !== record.lifecycle.persistedState) throw new MachineServiceError('machine_event_corrupt', 'machine record does not match its final event', { machineId: record.machineId });
    }
    const recordIds = new Set(this.list().map((record) => record.machineId));
    for (const eventName of readdirSync(this.eventsRoot).filter((name: string) => name.endsWith('.jsonl'))) {
      const machineId = eventName.slice(0, -6);
      if (!recordIds.has(machineId)) throw new MachineServiceError('machine_event_corrupt', 'orphan machine event stream has no authoritative record', { machineId });
    }
    const tombstones = readdirSync(this.tombstonesRoot).filter((name: string) => name.endsWith('.json')).map((name: string) => assertMachineTombstone(JSON.parse(readFileSync(join(this.tombstonesRoot, name), 'utf8')) as unknown));
    const rebuilt = this.rebuildIndexes(false);
    const indexesMatch = canonicalize(rebuilt) === canonicalize(this.indexes.read());
    if (!indexesMatch) throw new MachineServiceError('machine_index_corrupt', 'machine indexes do not match validated records');
    for (const entry of Object.values(this.idempotency.read().entries)) {
      const record = this.get(entry.machineId);
      if (record.creationRequestDigest !== entry.requestDigest || sha256(record.creationIdempotencyKey) !== entry.keyDigest) throw new MachineServiceError('machine_index_corrupt', 'machine idempotency index is inconsistent', { machineId: entry.machineId });
    }
    return { valid: true, records: this.list().length, events: eventCount, tombstones: tombstones.length, indexesMatch };
  }

  newLeaseId(): string {
    return `mxl_${randomUUID()}`;
  }
}
