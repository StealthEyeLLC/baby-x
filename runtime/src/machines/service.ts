import { hostname } from 'node:os';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { Executor, JobManager, canonicalize, sha256, type JsonObject, type ProcessIdentity } from '../core.ts';
import { ArtifactManager } from '../artifacts/manager.ts';
import { processIdentity as readProcessIdentity } from '../process/identity.ts';
import { DisposableMachineManager } from './disposable.ts';
import { MachineExecutionController, type MachineArtifactAuthority, type MachineJobAuthority } from './execution.ts';
import { MachineManager } from './manager.ts';
import { MachineServiceError } from './errors.ts';
import {
  assertMachineId,
  assertMachineName,
  machineCreationDigest,
  machineLaunchDigest,
  newMachineId,
  normalizeMachineCreateRequest,
  normalizeMachineServiceConfig,
  ownershipMarker,
  ownershipProperties,
  type MachineServiceConfig,
  type NormalizedMachineCreateRequestV1,
} from './identity.ts';
import { DisposableMachineObserver, type CloneDatasetObservation } from './observe.ts';
import {
  MACHINE_PROVIDER_ID,
  MACHINE_SCHEMA_VERSION,
  MACHINE_STATES,
  canonicalMachineEvidence,
  type DisposableMachineRecordV1,
  type MachineEventV1,
  type MachineState,
} from './schemas.ts';
import { DisposableMachineStore } from './store.ts';

export interface MachineOperationContext {
  idempotencyKey?: string;
  subject?: string;
  authorityClass?: string;
}

export interface DisposableMachineServiceOptions {
  stateRoot: string;
  executor?: Pick<Executor, 'run'>;
  config?: Partial<MachineServiceConfig>;
  now?: () => string;
  machineIdFactory?: () => string;
  hostIdentity?: { hostname: string; machineIdSha256: string; bootId: string };
  jobs?: MachineJobAuthority;
  artifacts?: MachineArtifactAuthority;
  sleep?: (milliseconds: number) => Promise<void>;
  processIdentity?: (pid: number) => ProcessIdentity;
}

interface MachineListRequest {
  ownerPrincipal?: string;
  state?: MachineState;
  providerId?: string;
  parentObjectiveId?: string;
  parentCertificationId?: string;
  parentCandidateId?: string;
  createdBefore?: string;
  createdAfter?: string;
  expiresBefore?: string;
  expiresAfter?: string;
  terminal?: boolean;
  offset?: number;
  limit?: number;
}

function requiredContext(context: MachineOperationContext): { idempotencyKey: string; subject: string } {
  if (typeof context.idempotencyKey !== 'string' || context.idempotencyKey.length < 8 || context.idempotencyKey.length > 256 || context.idempotencyKey.includes('\0')) {
    throw new MachineServiceError('machine_invalid_request', 'a bounded idempotencyKey is required for machine mutation');
  }
  if (typeof context.subject !== 'string' || context.subject.length === 0 || context.subject.includes('\0')) throw new MachineServiceError('machine_invalid_request', 'authenticated subject is required');
  return { idempotencyKey: context.idempotencyKey, subject: context.subject };
}

function positiveBound(value: unknown, field: string, fallback: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || Number(value) < 0 || Number(value) > maximum) throw new MachineServiceError('machine_invalid_request', `${field} is out of bounds`, { maximum });
  return Number(value);
}

function assertReadKeys(payload: JsonObject, allowed: readonly string[]): void {
  const allowedSet = new Set(allowed);
  const unsupported = Object.keys(payload).filter((key) => !allowedSet.has(key));
  if (unsupported.length > 0) throw new MachineServiceError('machine_invalid_request', 'read request contains unsupported properties', { properties: unsupported });
}

function optionalReadText(value: unknown, field: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) throw new MachineServiceError('machine_invalid_request', `${field} must be a non-empty NUL-free string`);
  return value;
}

function optionalReadTimestamp(value: unknown, field: string): number | undefined {
  const candidate = optionalReadText(value, field);
  if (candidate === undefined) return undefined;
  const parsed = Date.parse(candidate);
  if (!Number.isFinite(parsed)) throw new MachineServiceError('machine_invalid_request', `${field} must be an ISO timestamp`);
  return parsed;
}

function optionalReadBoolean(value: unknown, field: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'boolean') throw new MachineServiceError('machine_invalid_request', `${field} must be a boolean`);
  return value;
}

function readContextSubject(context: MachineOperationContext): string {
  if (typeof context.subject !== 'string' || context.subject.length === 0 || context.subject.includes('\0')) throw new MachineServiceError('machine_invalid_request', 'authenticated subject is required');
  return context.subject;
}

function authorizeRead(record: DisposableMachineRecordV1, context: MachineOperationContext): void {
  if (context.authorityClass === 'unrestricted-owner') return;
  if (record.ownerPrincipal !== readContextSubject(context)) throw new MachineServiceError('machine_not_found', 'machine not found');
}

function publicEvent(event: MachineEventV1): JsonObject {
  return JSON.parse(canonicalMachineEvidence(event)) as JsonObject;
}

function hostIdentity(): { hostname: string; machineIdSha256: string; bootId: string } {
  const machineIdentity = existsSync('/etc/machine-id') ? readFileSync('/etc/machine-id') : Buffer.from(hostname());
  const bootId = existsSync('/proc/sys/kernel/random/boot_id') ? readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim() : 'unknown';
  return { hostname: hostname(), machineIdSha256: sha256(machineIdentity), bootId };
}

function publicRecord(record: DisposableMachineRecordV1): JsonObject {
  return JSON.parse(canonicalMachineEvidence(record)) as JsonObject;
}

function summary(record: DisposableMachineRecordV1): JsonObject {
  return {
    machineId: record.machineId,
    machineName: record.machineName,
    ownerPrincipal: record.ownerPrincipal,
    providerId: record.providerId,
    sourceSnapshot: record.source.snapshot,
    cloneDataset: record.clone.dataset,
    mountpoint: record.clone.mountpoint,
    desiredState: record.lifecycle.desiredState,
    persistedState: record.lifecycle.persistedState,
    observedState: record.lifecycle.observedState,
    stateSequence: record.lifecycle.stateSequence,
    terminal: record.lifecycle.terminal,
    createdAt: record.lifecycle.createdAt,
    updatedAt: record.lifecycle.updatedAt,
    ...(record.lifecycle.expiresAt === undefined ? {} : { expiresAt: record.lifecycle.expiresAt }),
  };
}

function commandEvidence(result: { exitCode: number | null; signal: string | null; stdoutSha256: string; stderrSha256: string; startedAt: string; completedAt: string }): JsonObject {
  return { exitCode: result.exitCode, signal: result.signal, stdoutSha256: result.stdoutSha256, stderrSha256: result.stderrSha256, startedAt: result.startedAt, completedAt: result.completedAt };
}

function exactCloneMatches(record: DisposableMachineRecordV1, observation: CloneDatasetObservation): boolean {
  if (observation.status !== 'present') return false;
  const expected = ownershipProperties(record.machineId, record.creationRequestDigest, record.ownerPrincipal);
  return observation.origin === record.source.snapshot
    && observation.mountpoint === record.clone.mountpoint
    && Object.entries(expected).every(([name, value]) => observation.properties[name] === value);
}

function initialRecord(
  request: NormalizedMachineCreateRequestV1,
  idempotencyKey: string,
  requestDigest: string,
  machineId: string,
  now: string,
  host: { hostname: string; machineIdSha256: string; bootId: string },
): DisposableMachineRecordV1 {
  return {
    schemaVersion: MACHINE_SCHEMA_VERSION,
    machineId,
    machineName: request.machineName,
    providerId: MACHINE_PROVIDER_ID,
    ownerPrincipal: request.ownerPrincipal,
    ...(request.authorityReference === undefined ? {} : { authorityReference: request.authorityReference }),
    ...(request.parentObjectiveId === undefined ? {} : { parentObjectiveId: request.parentObjectiveId }),
    ...(request.parentCertificationId === undefined ? {} : { parentCertificationId: request.parentCertificationId }),
    ...(request.parentCandidateId === undefined ? {} : { parentCandidateId: request.parentCandidateId }),
    creationIdempotencyKey: idempotencyKey,
    creationRequestDigest: requestDigest,
    source: { kind: 'zfs-snapshot', snapshot: request.source.snapshot, dataset: request.source.dataset, observedAt: now },
    clone: {
      dataset: request.clone.dataset,
      mountpoint: request.clone.mountpoint,
      expectedRootPrefix: request.clone.expectedRootPrefix,
      ownershipMarker: ownershipMarker(machineId, requestDigest),
    },
    launch: { ...request.launch, normalizedDigest: machineLaunchDigest(request) },
    lifecycle: {
      desiredState: 'CLONED', persistedState: 'REQUESTED', observedState: 'NOT_OBSERVED', stateSequence: 1,
      terminal: false, createdAt: now, updatedAt: now,
      ...(request.expiresAt === undefined ? {} : { expiresAt: request.expiresAt }),
    },
    host: { hostname: host.hostname, machineIdSha256: host.machineIdSha256, bootIdAtCreate: host.bootId },
    observations: { dataset: 'unknown', snapshot: 'unknown', mountpoint: 'unknown', machinectl: 'unknown', process: 'unknown', rootPath: 'unknown' },
    activeJobIds: [], protectedJobIds: [], artifactIds: [], proofReferences: [],
    cleanup: {
      requested: false, stopAttempted: false, stopVerified: false, datasetDestroyAttempted: false,
      datasetAbsentVerified: false, rootAbsentVerified: false, machineAbsentVerified: false,
      processAbsentVerified: false, completed: false, retainedEvidence: [],
    },
  };
}

export class DisposableMachineService {
  readonly config: MachineServiceConfig;
  readonly store: DisposableMachineStore;
  private readonly executor: Pick<Executor, 'run'>;
  private readonly provider: DisposableMachineManager;
  private readonly observer: DisposableMachineObserver;
  private readonly now: () => string;
  private readonly machineIdFactory: () => string;
  private readonly host: { hostname: string; machineIdSha256: string; bootId: string };
  private readonly execution: MachineExecutionController;

  constructor(options: DisposableMachineServiceOptions) {
    this.config = normalizeMachineServiceConfig(options.config);
    this.executor = options.executor ?? new Executor();
    this.provider = new DisposableMachineManager(this.executor);
    this.observer = new DisposableMachineObserver(this.executor);
    this.store = new DisposableMachineStore(join(options.stateRoot, 'machine-service'));
    this.now = options.now ?? (() => new Date().toISOString());
    this.machineIdFactory = options.machineIdFactory ?? newMachineId;
    this.host = options.hostIdentity ?? hostIdentity();
    const jobs = options.jobs ?? new JobManager(join(options.stateRoot, 'jobs'));
    const artifacts = options.artifacts ?? new ArtifactManager(join(options.stateRoot, 'artifacts'));
    this.execution = new MachineExecutionController({
      store: this.store,
      observer: this.observer,
      manager: new MachineManager(this.executor),
      jobs,
      artifacts,
      config: this.config,
      now: this.now,
      sleep: options.sleep,
      processIdentity: options.processIdentity ?? readProcessIdentity,
      hostBootId: this.host.bootId,
    });
  }

  describe(): JsonObject {
    return {
      operation: 'babyx.machine.describe',
      available: existsSync('/usr/sbin/zfs') && existsSync('/usr/bin/machinectl'),
      service: 'baby-x-disposable-machine-service', schemaVersion: MACHINE_SCHEMA_VERSION,
      providerId: MACHINE_PROVIDER_ID,
      lifecycleAuthority: 'disposable-machine-service',
      executionAuthority: 'baby-x-durable-jobs',
      operations: ['babyx.machine.describe', 'babyx.machine.create', 'babyx.machine.get', 'babyx.machine.list', 'babyx.machine.events', 'babyx.machine.status', 'babyx.machine.start', 'babyx.machine.exec', 'babyx.machine.shell'],
      checkpoint: 'C',
      supportedLifecycle: ['REQUESTED', 'CLONING', 'CLONED', 'STARTING', 'READY', 'EXECUTING', 'FAILED', 'DEGRADED', 'AMBIGUOUS'],
      unavailableUntilLaterCheckpoints: ['stop', 'destroy', 'reconcile', 'gc', 'certify', 'policy', 'race'],
      limits: { defaultListLimit: this.config.defaultListLimit, maximumListLimit: this.config.maximumListLimit, maximumEventLimit: this.config.maximumEventLimit, readinessTimeoutMs: this.config.readinessTimeoutMs, readinessPollIntervalMs: this.config.readinessPollIntervalMs },
      configuredRoots: { sourceSnapshotRoots: [...this.config.sourceSnapshotRoots], cloneDatasetRoots: [...this.config.cloneDatasetRoots], machineRoot: this.config.machineRoot },
    };
  }

  async create(payload: unknown, context: MachineOperationContext): Promise<JsonObject> {
    const authenticated = requiredContext(context);
    const request = normalizeMachineCreateRequest(payload, authenticated.subject, this.config);
    const requestDigest = machineCreationDigest(request);
    const candidateId = this.machineIdFactory();
    const createdAt = this.now();
    const candidate = initialRecord(request, authenticated.idempotencyKey, requestDigest, candidateId, createdAt, this.host);
    const record = this.store.create(candidate, {
      operation: 'babyx.machine.create', phase: 'request', kind: 'machine.requested', message: 'machine creation intent persisted',
      requestDigest, idempotencyKey: authenticated.idempotencyKey, occurredAt: createdAt,
    });
    const replayed = record.machineId !== candidateId;
    if (replayed && record.lifecycle.persistedState === 'CLONED') return { operation: 'babyx.machine.create', machine: publicRecord(record), replayed: true };
    if (!['REQUESTED', 'CLONING'].includes(record.lifecycle.persistedState)) return { operation: 'babyx.machine.create', machine: publicRecord(record), replayed: true, continuationRequired: true };

    const leaseId = this.store.newLeaseId();
    this.store.acquireLease({
      schemaVersion: MACHINE_SCHEMA_VERSION, leaseId, machineId: record.machineId, operation: 'babyx.machine.create',
      ownerPrincipal: authenticated.subject, requestDigest, acquiredAt: createdAt,
      expiresAt: new Date(Date.parse(createdAt) + this.config.leaseDurationMs).toISOString(), hostBootId: this.host.bootId,
    }, { currentBootId: this.host.bootId, existingOwnerAlive: false, now: createdAt });
    try {
      const source = this.observer.requireProviderObservation(await this.observer.source(record.source.snapshot), 'source snapshot');
      if (source.status === 'absent') throw new MachineServiceError('machine_source_not_found', 'source snapshot does not exist', { snapshot: record.source.snapshot });
      if (source.guid === undefined || source.creationTxg === undefined) throw new MachineServiceError('machine_readback_mismatch', 'source snapshot identity readback is incomplete', { snapshot: record.source.snapshot });
      if (request.source.expectedGuid !== undefined && request.source.expectedGuid !== source.guid) throw new MachineServiceError('machine_source_mismatch', 'source snapshot GUID differs from the requested identity', { expectedGuid: request.source.expectedGuid, actualGuid: source.guid });

      let current = record;
      if (current.lifecycle.persistedState === 'REQUESTED') {
        current = this.store.transition(current.machineId, current.lifecycle.stateSequence, 'CLONING', 'CLONED', {
          operation: 'babyx.machine.create', phase: 'clone-intent', kind: 'machine.cloning', message: 'clone intent persisted before provider mutation',
          requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, occurredAt: this.now(),
        }, { source: { ...current.source, snapshotGuid: source.guid, creationTxg: source.creationTxg, observedAt: source.observedAt } });
      }

      const before = this.observer.requireProviderObservation(await this.observer.clone(current.clone.dataset), 'clone dataset');
      if (before.status === 'present' && !exactCloneMatches(current, before)) {
        const ambiguous = this.store.transition(current.machineId, current.lifecycle.stateSequence, 'AMBIGUOUS', 'CLONED', {
          operation: 'babyx.machine.create', phase: 'pre-clone-observation', kind: 'machine.identity-conflict',
          message: 'pre-existing clone dataset is not exactly owned by this machine', requestDigest,
          idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, occurredAt: this.now(),
        }, { observations: { ...current.observations, dataset: 'present-conflict', mountpoint: before.mountpoint === current.clone.mountpoint ? 'present-matching' : 'present-conflict', observedAt: before.observedAt } });
        throw new MachineServiceError('machine_identity_ambiguous', 'clone dataset already exists without exact ownership proof', { machineId: ambiguous.machineId, dataset: ambiguous.clone.dataset });
      }

      let cloneCommand: JsonObject | undefined;
      if (before.status === 'absent') {
        try {
          const instance = await this.provider.create({
            id: current.machineName, baseSnapshot: current.source.snapshot, dataset: current.clone.dataset, root: current.clone.mountpoint,
            ownershipProperties: ownershipProperties(current.machineId, current.creationRequestDigest, current.ownerPrincipal),
          });
          cloneCommand = { instance: { id: instance.id, dataset: instance.dataset, root: instance.root, baseSnapshot: instance.baseSnapshot, state: instance.state } };
        } catch (error) {
          throw new MachineServiceError('machine_clone_failed', error instanceof Error ? error.message : 'clone provider failed', { machineId: current.machineId });
        }
      }

      const after = this.observer.requireProviderObservation(await this.observer.clone(current.clone.dataset), 'clone dataset readback');
      if (!exactCloneMatches(current, after) || after.guid === undefined) throw new MachineServiceError('machine_readback_mismatch', 'clone command did not produce the exact durable identity', { machineId: current.machineId, dataset: current.clone.dataset, command: cloneCommand });
      if (!existsSync(current.clone.mountpoint) || realpathSync(current.clone.mountpoint) !== current.clone.mountpoint) throw new MachineServiceError('machine_readback_mismatch', 'clone root path is absent or not canonical after clone', { mountpoint: current.clone.mountpoint });

      const observations = {
        dataset: 'present-matching' as const, snapshot: 'present-matching' as const, mountpoint: 'present-matching' as const,
        machinectl: 'absent' as const, process: 'absent' as const, rootPath: 'present-matching' as const,
        observedAt: after.observedAt,
      };
      const completed = this.store.transition(current.machineId, current.lifecycle.stateSequence, 'CLONED', 'CLONED', {
        operation: 'babyx.machine.create', phase: 'clone-readback', kind: 'machine.cloned', message: 'clone identity and ownership readback verified',
        requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId,
        observationDigest: sha256(canonicalize(observations)), occurredAt: this.now(),
      }, {
        source: { ...current.source, snapshotGuid: source.guid, creationTxg: source.creationTxg, observedAt: source.observedAt },
        clone: { ...current.clone, datasetGuid: after.guid },
        observations: { ...observations, observationDigest: sha256(canonicalize(observations)) },
        host: { ...current.host, lastObservedBootId: this.host.bootId },
      });
      return { operation: 'babyx.machine.create', machine: publicRecord(completed), replayed, providerEvidence: { source: commandEvidence(source.command), clone: commandEvidence(after.command) } };
    } finally {
      this.store.releaseLease(record.machineId, leaseId);
    }
  }

  get(payload: JsonObject, context: MachineOperationContext): JsonObject {
    assertReadKeys(payload, ['machineId', 'machineName']);
    const machineId = payload.machineId === undefined ? undefined : assertMachineId(payload.machineId);
    const machineName = payload.machineName === undefined ? undefined : assertMachineName(payload.machineName);
    if ((machineId === undefined) === (machineName === undefined)) throw new MachineServiceError('machine_invalid_request', 'exactly one of machineId or machineName is required');
    const record = machineId === undefined ? this.store.getByName(machineName as string) : this.store.get(machineId);
    authorizeRead(record, context);
    return { operation: 'babyx.machine.get', machine: publicRecord(record) };
  }

  list(payload: JsonObject = {}, context: MachineOperationContext): JsonObject {
    assertReadKeys(payload, [
      'ownerPrincipal', 'state', 'providerId', 'parentObjectiveId', 'parentCertificationId', 'parentCandidateId',
      'createdBefore', 'createdAfter', 'expiresBefore', 'expiresAfter', 'terminal', 'offset', 'limit',
    ]);
    const request = payload as MachineListRequest;
    const requestedOwner = optionalReadText(request.ownerPrincipal, 'ownerPrincipal');
    const subject = context.authorityClass === 'unrestricted-owner' ? undefined : readContextSubject(context);
    if (subject !== undefined && requestedOwner !== undefined && requestedOwner !== subject) throw new MachineServiceError('machine_not_found', 'machine owner scope is not accessible');
    const ownerPrincipal = subject ?? requestedOwner;
    const stateText = optionalReadText(request.state, 'state');
    if (stateText !== undefined && !MACHINE_STATES.includes(stateText as MachineState)) throw new MachineServiceError('machine_invalid_request', 'state is invalid', { state: stateText });
    const providerId = optionalReadText(request.providerId, 'providerId');
    const parentObjectiveId = optionalReadText(request.parentObjectiveId, 'parentObjectiveId');
    const parentCertificationId = optionalReadText(request.parentCertificationId, 'parentCertificationId');
    const parentCandidateId = optionalReadText(request.parentCandidateId, 'parentCandidateId');
    const createdBefore = optionalReadTimestamp(request.createdBefore, 'createdBefore');
    const createdAfter = optionalReadTimestamp(request.createdAfter, 'createdAfter');
    const expiresBefore = optionalReadTimestamp(request.expiresBefore, 'expiresBefore');
    const expiresAfter = optionalReadTimestamp(request.expiresAfter, 'expiresAfter');
    const terminal = optionalReadBoolean(request.terminal, 'terminal');
    const offset = positiveBound(request.offset, 'offset', 0, Number.MAX_SAFE_INTEGER);
    const limit = positiveBound(request.limit, 'limit', this.config.defaultListLimit, this.config.maximumListLimit);
    const filtered = this.store.list().filter((record) => {
      const createdAt = Date.parse(record.lifecycle.createdAt);
      const expiresAt = record.lifecycle.expiresAt === undefined ? undefined : Date.parse(record.lifecycle.expiresAt);
      return (ownerPrincipal === undefined || record.ownerPrincipal === ownerPrincipal)
        && (stateText === undefined || record.lifecycle.persistedState === stateText)
        && (providerId === undefined || record.providerId === providerId)
        && (parentObjectiveId === undefined || record.parentObjectiveId === parentObjectiveId)
        && (parentCertificationId === undefined || record.parentCertificationId === parentCertificationId)
        && (parentCandidateId === undefined || record.parentCandidateId === parentCandidateId)
        && (createdBefore === undefined || createdAt < createdBefore)
        && (createdAfter === undefined || createdAt > createdAfter)
        && (expiresBefore === undefined || (expiresAt !== undefined && expiresAt < expiresBefore))
        && (expiresAfter === undefined || (expiresAt !== undefined && expiresAt > expiresAfter))
        && (terminal === undefined || record.lifecycle.terminal === terminal);
    }).sort((left, right) => left.machineId.localeCompare(right.machineId));
    const records = filtered.slice(offset, offset + limit).map(summary);
    return {
      operation: 'babyx.machine.list', machines: records, offset, limit, total: filtered.length,
      nextOffset: offset + records.length < filtered.length ? offset + records.length : null,
    };
  }

  events(payload: JsonObject, context: MachineOperationContext): JsonObject {
    assertReadKeys(payload, ['machineId', 'offset', 'limit']);
    const machineId = assertMachineId(payload.machineId);
    const record = this.store.get(machineId);
    authorizeRead(record, context);
    const offset = positiveBound(payload.offset, 'offset', 0, Number.MAX_SAFE_INTEGER);
    const limit = positiveBound(payload.limit, 'limit', Math.min(100, this.config.maximumEventLimit), this.config.maximumEventLimit);
    const events = this.store.events(machineId, offset, limit).map(publicEvent);
    return { operation: 'babyx.machine.events', machineId, events, offset, limit, nextOffset: events.length === limit ? offset + events.length : null };
  }

  start(payload: JsonObject, context: MachineOperationContext): Promise<JsonObject> {
    return this.execution.start(payload, context);
  }

  exec(payload: JsonObject, context: MachineOperationContext): Promise<JsonObject> {
    return this.execution.exec(payload, context);
  }

  shell(payload: JsonObject, context: MachineOperationContext): Promise<JsonObject> {
    return this.execution.shell(payload, context);
  }

  async status(payload: JsonObject, context: MachineOperationContext): Promise<JsonObject> {
    assertReadKeys(payload, ['machineId', 'includeJobs', 'includeRecentEvents']);
    const machineId = assertMachineId(payload.machineId);
    const includeJobs = optionalReadBoolean(payload.includeJobs, 'includeJobs') ?? false;
    const includeRecentEvents = optionalReadBoolean(payload.includeRecentEvents, 'includeRecentEvents') ?? false;
    const record = this.store.get(machineId);
    authorizeRead(record, context);
    const observed = await this.observer.status(record);
    const recommendedAction = observed.observedState === 'CONFLICT' ? 'manual identity review required'
      : observed.observedState === 'UNKNOWN' ? 'retry observation or reconcile when provider access is restored'
      : observed.observedState === record.lifecycle.observedState ? 'none'
      : 'reconcile persisted and observed state';
    const allEvents = includeRecentEvents ? this.store.events(machineId, 0, 1_000) : [];
    return {
      operation: 'babyx.machine.status', machine: summary(record),
      persisted: { state: record.lifecycle.persistedState, desiredState: record.lifecycle.desiredState, sequence: record.lifecycle.stateSequence },
      observed: { state: observed.observedState, observations: observed.observations },
      agreement: observed.observedState === record.lifecycle.observedState,
      discrepancies: observed.discrepancies.slice(0, 100), recommendedAction,
      ...(includeJobs ? { jobs: { activeJobIds: [...record.activeJobIds], protectedJobIds: [...record.protectedJobIds] } } : {}),
      ...(includeRecentEvents ? { recentEvents: allEvents.slice(-20).map(publicEvent) } : {}),
    };
  }

}
