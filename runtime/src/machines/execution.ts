import { existsSync } from 'node:fs';
import { isAbsolute, normalize } from 'node:path';
import { canonicalize, sha256, type JobRecord, type JsonObject, type ProcessIdentity } from '../core.ts';
import type { ArtifactManager } from '../artifacts/manager.ts';
import { MachineManager } from './manager.ts';
import { MachineServiceError } from './errors.ts';
import type { MachineOperationContext } from './service.ts';
import { assertMachineId, type MachineServiceConfig } from './identity.ts';
import { DisposableMachineObserver, type MachineStatusObservation } from './observe.ts';
import { canonicalMachineEvidence, type DisposableMachineRecordV1, type MachineEventV1 } from './schemas.ts';
import { assertExpectedMachineSequence } from './states.ts';
import { DisposableMachineStore } from './store.ts';

export interface MachineJobAuthority {
  start(operation: string, payload: JsonObject): JobRecord;
  get(id: string): JobRecord;
  onChange(listener: (record: JobRecord) => void | Promise<void>): () => void;
}

export interface MachineArtifactAuthority extends Pick<ArtifactManager, 'create'> {}

export interface MachineExecutionControllerOptions {
  store: DisposableMachineStore;
  observer: DisposableMachineObserver;
  manager: MachineManager;
  jobs: MachineJobAuthority;
  artifacts?: MachineArtifactAuthority;
  config: MachineServiceConfig;
  now: () => string;
  sleep?: (milliseconds: number) => Promise<void>;
  processIdentity: (pid: number) => ProcessIdentity;
  hostBootId: string;
}

function requiredMutationContext(context: MachineOperationContext): { idempotencyKey: string; subject: string } {
  if (typeof context.idempotencyKey !== 'string' || context.idempotencyKey.length < 8 || context.idempotencyKey.length > 256 || context.idempotencyKey.includes('\0')) {
    throw new MachineServiceError('machine_invalid_request', 'a bounded idempotencyKey is required for machine mutation');
  }
  if (typeof context.subject !== 'string' || context.subject.length === 0 || context.subject.includes('\0')) throw new MachineServiceError('machine_invalid_request', 'authenticated subject is required');
  return { idempotencyKey: context.idempotencyKey, subject: context.subject };
}

function assertAllowedKeys(payload: JsonObject, allowed: readonly string[]): void {
  const permitted = new Set(allowed);
  const unsupported = Object.keys(payload).filter((key) => !permitted.has(key));
  if (unsupported.length > 0) throw new MachineServiceError('machine_invalid_request', 'mutation request contains unsupported properties', { properties: unsupported });
}

function requiredSequence(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1) throw new MachineServiceError('machine_invalid_request', 'expectedSequence must be a positive safe integer');
  return Number(value);
}

function optionalPositiveInteger(value: unknown, field: string): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || Number(value) < 1) throw new MachineServiceError('machine_invalid_request', `${field} must be a positive safe integer`);
  return Number(value);
}

function optionalText(value: unknown, field: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) throw new MachineServiceError('machine_invalid_request', `${field} must be a non-empty NUL-free string`);
  return value;
}

function exactArgv(value: unknown, field = 'argv'): string[] {
  if (!Array.isArray(value) || value.length === 0) throw new MachineServiceError('machine_invalid_request', `${field} must be a non-empty array`);
  return value.map((entry, index) => {
    if (typeof entry !== 'string' || entry.length === 0 || entry.includes('\0')) throw new MachineServiceError('machine_invalid_request', `${field}[${index}] must be a non-empty NUL-free string`);
    return entry;
  });
}

function exactEnvironment(value: unknown): JsonObject {
  if (value === undefined) return {};
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new MachineServiceError('machine_invalid_request', 'env must be an object');
  const result: JsonObject = {};
  for (const [name, entry] of Object.entries(value as Record<string, unknown>)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) || typeof entry !== 'string' || entry.includes('\0')) throw new MachineServiceError('machine_invalid_request', `env.${name} is invalid`);
    result[name] = entry;
  }
  return result;
}

function exactCwd(value: unknown): string {
  const cwd = value === undefined ? '/' : optionalText(value, 'cwd') as string;
  if (!isAbsolute(cwd) || normalize(cwd) !== cwd) throw new MachineServiceError('machine_invalid_request', 'cwd must be a normalized absolute path inside the machine');
  return cwd;
}

function authorize(record: DisposableMachineRecordV1, context: MachineOperationContext): void {
  if (context.authorityClass === 'unrestricted-owner') return;
  if (record.ownerPrincipal !== context.subject) throw new MachineServiceError('machine_not_found', 'machine not found');
}

function publicMachine(record: DisposableMachineRecordV1): JsonObject {
  return JSON.parse(canonicalMachineEvidence(record)) as JsonObject;
}

function publicJob(record: JobRecord): JsonObject {
  return {
    id: record.id,
    operation: record.operation,
    status: record.status,
    target: record.target,
    argv: record.argv,
    cwd: record.cwd,
    createdAt: record.createdAt,
    startedAt: record.startedAt,
    ...(record.completedAt === undefined ? {} : { completedAt: record.completedAt }),
    ...(record.exitCode === undefined ? {} : { exitCode: record.exitCode }),
    ...(record.signal === undefined ? {} : { signal: record.signal }),
    ...(record.timeoutMs === undefined ? {} : { timeoutMs: record.timeoutMs }),
  };
}

function mutationDigest(operation: string, payload: JsonObject): string {
  return sha256(canonicalMachineEvidence({ operation, payload }));
}

function completeProcessIdentity(identity: ProcessIdentity, expectedPid: number, bootId: string): DisposableMachineRecordV1['processIdentity'] {
  if (identity.pid !== expectedPid || identity.processStartTime === undefined || identity.executablePath === undefined || identity.bootId === undefined) {
    throw new MachineServiceError('machine_process_conflict', 'machine leader process identity is incomplete or mismatched', { expectedPid, actualPid: identity.pid });
  }
  if (identity.bootId !== bootId) throw new MachineServiceError('machine_process_conflict', 'machine leader belongs to a different boot identity', { expectedBootId: bootId, actualBootId: identity.bootId });
  return {
    pid: identity.pid,
    ...(identity.pgid === undefined ? {} : { pgid: identity.pgid }),
    processStartTime: identity.processStartTime,
    executablePath: identity.executablePath,
    bootId: identity.bootId,
  };
}

function sameProcessIdentity(left: DisposableMachineRecordV1['processIdentity'], right: DisposableMachineRecordV1['processIdentity']): boolean {
  return left !== undefined && right !== undefined
    && left.pid === right.pid
    && left.processStartTime === right.processStartTime
    && left.executablePath === right.executablePath
    && left.bootId === right.bootId;
}

function resultDigest(value: unknown): string {
  return sha256(canonicalize(value));
}

function latestReplay(events: MachineEventV1[], operation: string, idempotencyKey: string, requestDigest: string): MachineEventV1 | undefined {
  const matches = events.filter((event) => event.operation === operation && event.idempotencyKey === idempotencyKey);
  if (matches.some((event) => event.requestDigest !== requestDigest)) throw new MachineServiceError('machine_idempotency_conflict', 'idempotency key was reused with a different mutation request');
  return matches.at(-1);
}

export class MachineExecutionController {
  private readonly sleep: (milliseconds: number) => Promise<void>;

  constructor(private readonly options: MachineExecutionControllerOptions) {
    this.sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    options.jobs.onChange((job) => this.jobChanged(job));
  }

  private launchArgv(record: DisposableMachineRecordV1): string[] {
    const environment: Record<string, string> = {};
    for (const entry of record.launch.environment) {
      if (entry.secretReference !== undefined) throw new MachineServiceError('machine_launch_failed', 'launch contains an unresolved secret reference', { name: entry.name });
      if (entry.value !== undefined) environment[entry.name] = entry.value;
    }
    return this.options.manager.launchArgv({
      definition: { name: record.machineName, class: 'disposable-experiment', root: record.clone.mountpoint, imageKind: 'directory', properties: {} },
      boot: record.launch.boot,
      privateNetwork: record.launch.networkMode === 'none' || record.launch.networkMode === 'private',
      networkVeth: record.launch.networkMode === 'private',
      readOnly: record.launch.readOnlyRoot,
      binds: record.launch.binds.map((bind) => ({ source: bind.source, destination: bind.destination, readOnly: bind.mode === 'ro' })),
      environment,
      properties: record.launch.properties.map((property) => `${property.name}=${property.value}`),
      extraArgs: record.launch.command ?? ['--'],
    });
  }

  private async exactRunningIdentity(record: DisposableMachineRecordV1, observation?: MachineStatusObservation): Promise<{ observation: MachineStatusObservation; identity: DisposableMachineRecordV1['processIdentity'] }> {
    const status = observation ?? await this.options.observer.status(record);
    if (status.observedState === 'UNKNOWN') throw new MachineServiceError('machine_provider_unavailable', 'machine runtime observation is unavailable');
    if (status.observedState === 'CONFLICT') throw new MachineServiceError('machine_process_conflict', 'machine runtime identity conflicts with the durable record', { discrepancies: status.discrepancies });
    if (status.observedState !== 'RUNNING') throw new MachineServiceError('machine_readiness_failed', 'machine is not observed running', { observedState: status.observedState });
    const properties = status.machine.properties;
    if (properties.Name !== record.machineName || properties.RootDirectory !== record.clone.mountpoint) throw new MachineServiceError('machine_process_conflict', 'machinectl identity does not match the durable machine', { name: properties.Name, rootDirectory: properties.RootDirectory });
    const leader = Number(properties.Leader);
    if (!Number.isSafeInteger(leader) || leader < 1) throw new MachineServiceError('machine_process_conflict', 'machinectl did not return a valid leader PID');
    let identity: ProcessIdentity;
    try { identity = this.options.processIdentity(leader); }
    catch (error) { throw new MachineServiceError('machine_process_conflict', error instanceof Error ? error.message : 'machine leader process identity is unavailable', { leader }); }
    return { observation: status, identity: completeProcessIdentity(identity, leader, this.options.hostBootId) };
  }

  private async waitReady(record: DisposableMachineRecordV1, timeoutMs: number, launchJobId?: string): Promise<{ observation: MachineStatusObservation; identity: DisposableMachineRecordV1['processIdentity'] }> {
    const attempts = Math.max(1, Math.ceil(timeoutMs / this.options.config.readinessPollIntervalMs) + 1);
    let last: MachineStatusObservation | undefined;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      if (launchJobId !== undefined) {
        const job = this.options.jobs.get(launchJobId);
        if (job.status !== 'running') throw new MachineServiceError('machine_launch_failed', 'machine launch job terminated before readiness', { jobId: launchJobId, status: job.status, exitCode: job.exitCode, signal: job.signal });
      }
      last = await this.options.observer.status(record);
      if (last.observedState === 'CONFLICT') throw new MachineServiceError('machine_process_conflict', 'machine identity conflicted during readiness', { discrepancies: last.discrepancies });
      if (last.observedState === 'RUNNING') return this.exactRunningIdentity(record, last);
      if (attempt + 1 < attempts) await this.sleep(this.options.config.readinessPollIntervalMs);
    }
    throw new MachineServiceError('machine_readiness_failed', 'machine did not become ready within the bounded readiness window', { timeoutMs, observedState: last?.observedState ?? 'UNKNOWN' });
  }

  private acquireLease(record: DisposableMachineRecordV1, operation: string, principal: string, requestDigest: string): string {
    const leaseId = this.options.store.newLeaseId();
    const acquiredAt = this.options.now();
    this.options.store.acquireLease({
      schemaVersion: '1.0.0', leaseId, machineId: record.machineId, operation, ownerPrincipal: principal,
      requestDigest, acquiredAt, expiresAt: new Date(Date.parse(acquiredAt) + this.options.config.leaseDurationMs).toISOString(), hostBootId: this.options.hostBootId,
    }, { currentBootId: this.options.hostBootId, existingOwnerAlive: false, now: acquiredAt });
    return leaseId;
  }

  async start(payload: JsonObject, context: MachineOperationContext): Promise<JsonObject> {
    assertAllowedKeys(payload, ['machineId', 'expectedSequence', 'readinessTimeoutMs', 'reason']);
    const authenticated = requiredMutationContext(context);
    const machineId = assertMachineId(payload.machineId);
    const expectedSequence = requiredSequence(payload.expectedSequence);
    const timeoutMs = optionalPositiveInteger(payload.readinessTimeoutMs, 'readinessTimeoutMs') ?? this.options.config.readinessTimeoutMs;
    optionalText(payload.reason, 'reason');
    let record = this.options.store.get(machineId);
    authorize(record, context);
    const requestDigest = mutationDigest('babyx.machine.start', payload);
    const replay = latestReplay(this.options.store.events(record.machineId, 0, 1_000), 'babyx.machine.start', authenticated.idempotencyKey, requestDigest);
    if (replay !== undefined && record.lifecycle.persistedState === 'READY') {
      const response = { operation: 'babyx.machine.start', machine: publicMachine(record), jobId: replay.jobId ?? null, noOp: true, replayed: true, eventOffset: replay.offset };
      return { ...response, resultDigest: resultDigest(response), artifactReferences: [] };
    }
    assertExpectedMachineSequence(record.lifecycle.stateSequence, expectedSequence);

    if (record.lifecycle.persistedState === 'READY' || record.lifecycle.persistedState === 'EXECUTING') {
      const running = await this.exactRunningIdentity(record);
      if (record.processIdentity !== undefined && !sameProcessIdentity(record.processIdentity, running.identity)) throw new MachineServiceError('machine_process_conflict', 'running machine process identity differs from the durable record');
      const response = { operation: 'babyx.machine.start', machine: publicMachine(record), jobId: null, noOp: true, replayed: false, eventOffset: this.options.store.events(record.machineId, 0, 1_000).length - 1 };
      return { ...response, resultDigest: resultDigest(response), artifactReferences: [] };
    }
    if (!['CLONED', 'STOPPED', 'STARTING'].includes(record.lifecycle.persistedState)) throw new MachineServiceError('machine_state_conflict', 'machine is not in a start-compatible state', { state: record.lifecycle.persistedState });

    const resumingStart = record.lifecycle.persistedState === 'STARTING';
    const leaseId = this.acquireLease(record, 'babyx.machine.start', authenticated.subject, requestDigest);
    try {
      const before = await this.options.observer.status(record);
      if (resumingStart && before.observedState === 'RUNNING') {
        const ready = await this.exactRunningIdentity(record, before);
        const completed = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'READY', 'READY', {
          operation: 'babyx.machine.start', phase: 'restart-adoption', kind: 'machine.ready', message: 'existing healthy machine adopted after controller restart',
          requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId,
          observationDigest: ready.observation.observations.observationDigest, occurredAt: this.options.now(),
        }, {
          processIdentity: ready.identity, observations: ready.observation.observations,
          lifecycle: { ...record.lifecycle, observedState: 'RUNNING' },
          host: { ...record.host, lastObservedBootId: this.options.hostBootId },
        });
        const eventOffset = this.options.store.events(completed.machineId, 0, 1_000).length - 1;
        const response = { operation: 'babyx.machine.start', machine: publicMachine(completed), jobId: null, noOp: true, replayed: false, eventOffset };
        return { ...response, resultDigest: resultDigest(response), artifactReferences: [] };
      }
      if (record.lifecycle.persistedState !== 'STARTING') {
        if (before.observedState === 'UNKNOWN') throw new MachineServiceError('machine_provider_unavailable', 'pre-start observation is unavailable');
        if (before.observedState === 'CONFLICT' || before.observedState === 'RUNNING') throw new MachineServiceError('machine_process_conflict', 'machine name, root, or process is already occupied', { observedState: before.observedState, discrepancies: before.discrepancies });
        if (!['CLONE_ONLY', 'STOPPED_INTACT'].includes(before.observedState)) throw new MachineServiceError('machine_readback_mismatch', 'clone/root identity is not intact before start', { observedState: before.observedState });
        record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'STARTING', 'READY', {
          operation: 'babyx.machine.start', phase: 'start-intent', kind: 'machine.starting', message: 'startup intent persisted before launch',
          requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, observationDigest: before.observations.observationDigest, occurredAt: this.options.now(),
        }, { observations: before.observations, lifecycle: { ...record.lifecycle, observedState: before.observedState } });
      }

      let launchJobId = resumingStart
        ? this.options.store.events(record.machineId, 0, 1_000).filter((event) => event.operation === 'babyx.machine.start' && event.jobId !== undefined).at(-1)?.jobId
        : undefined;
      if (launchJobId === undefined) {
        let argv: string[];
        try { argv = this.launchArgv(record); }
        catch (error) {
          const failed = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'FAILED', 'READY', {
            operation: 'babyx.machine.start', phase: 'launch-prepare', kind: 'machine.launch-failed', message: error instanceof Error ? error.message : 'launch preparation failed',
            requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, occurredAt: this.options.now(),
          }, { lastError: { code: 'machine_launch_failed', message: error instanceof Error ? error.message : 'launch preparation failed', phase: 'launch-prepare', retryable: false, destructiveRecoveryAllowed: false, artifactReferences: [], occurredAt: this.options.now() } });
          throw new MachineServiceError('machine_launch_failed', 'machine launch preparation failed', { machineId: failed.machineId });
        }
        const launchJob = this.options.jobs.start('babyx.machine.start', {
          argv, cwd: '/', target: { kind: 'host' },
          metadata: { machineService: true, kind: 'start', machineId: record.machineId, machineName: record.machineName, launchDigest: record.launch.normalizedDigest },
        });
        launchJobId = launchJob.id;
        record = this.options.store.update(record.machineId, record.lifecycle.stateSequence, {
          operation: 'babyx.machine.start', phase: 'launch-submit', kind: 'machine.launch-submitted', message: 'startup submitted to the existing durable job authority',
          requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, jobId: launchJob.id, occurredAt: this.options.now(),
        });
      }

      let ready: Awaited<ReturnType<MachineExecutionController['waitReady']>>;
      try { ready = await this.waitReady(record, timeoutMs, launchJobId); }
      catch (error) {
        const code = error instanceof MachineServiceError ? error.code : 'machine_readiness_failed';
        const nextState = code === 'machine_process_conflict' ? 'AMBIGUOUS' : 'FAILED';
        const failed = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, nextState, 'READY', {
          operation: 'babyx.machine.start', phase: 'readiness', kind: 'machine.readiness-failed', message: error instanceof Error ? error.message : 'machine readiness failed',
          requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, jobId: launchJobId, occurredAt: this.options.now(),
        }, { lastError: { code, message: error instanceof Error ? error.message : 'machine readiness failed', phase: 'readiness', retryable: code !== 'machine_process_conflict', destructiveRecoveryAllowed: false, artifactReferences: [], occurredAt: this.options.now() } });
        throw new MachineServiceError(code, error instanceof Error ? error.message : 'machine readiness failed', { machineId: failed.machineId, jobId: launchJobId });
      }

      const completed = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'READY', 'READY', {
        operation: 'babyx.machine.start', phase: 'readiness', kind: 'machine.ready', message: 'machine identity and readiness verified',
        requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, jobId: launchJobId,
        observationDigest: ready.observation.observations.observationDigest, occurredAt: this.options.now(),
      }, {
        processIdentity: ready.identity,
        observations: ready.observation.observations,
        lifecycle: { ...record.lifecycle, observedState: 'RUNNING' },
        host: { ...record.host, lastObservedBootId: this.options.hostBootId },
      });
      const eventOffset = this.options.store.events(completed.machineId, 0, 1_000).length - 1;
      const response = { operation: 'babyx.machine.start', machine: publicMachine(completed), jobId: launchJobId, noOp: false, replayed: replay !== undefined, eventOffset };
      return { ...response, resultDigest: resultDigest(response), artifactReferences: [] };
    } finally {
      this.options.store.releaseLease(record.machineId, leaseId);
    }
  }

  async exec(payload: JsonObject, context: MachineOperationContext, operation = 'babyx.machine.exec'): Promise<JsonObject> {
    const allowed = operation === 'babyx.machine.shell'
      ? ['machineId', 'expectedSequence', 'script', 'cwd', 'env', 'timeoutMs', 'outputLimitBytes', 'artifactPolicy', 'reason']
      : ['machineId', 'expectedSequence', 'argv', 'cwd', 'env', 'timeoutMs', 'outputLimitBytes', 'artifactPolicy', 'reason'];
    assertAllowedKeys(payload, allowed);
    const authenticated = requiredMutationContext(context);
    const machineId = assertMachineId(payload.machineId);
    const expectedSequence = requiredSequence(payload.expectedSequence);
    const argv = operation === 'babyx.machine.shell'
      ? ['/usr/bin/bash', '-lc', optionalText(payload.script, 'script') as string]
      : exactArgv(payload.argv);
    const cwd = exactCwd(payload.cwd);
    const env = exactEnvironment(payload.env);
    const timeoutMs = optionalPositiveInteger(payload.timeoutMs, 'timeoutMs');
    const outputLimitBytes = optionalPositiveInteger(payload.outputLimitBytes, 'outputLimitBytes');
    optionalText(payload.reason, 'reason');
    const artifactPolicy = payload.artifactPolicy === undefined ? {} : payload.artifactPolicy;
    if (artifactPolicy === null || typeof artifactPolicy !== 'object' || Array.isArray(artifactPolicy)) throw new MachineServiceError('machine_invalid_request', 'artifactPolicy must be an object');
    const captureStreams = (artifactPolicy as Record<string, unknown>).captureStreams === true;
    if (Object.keys(artifactPolicy as Record<string, unknown>).some((key) => key !== 'captureStreams')) throw new MachineServiceError('machine_invalid_request', 'artifactPolicy contains unsupported properties');

    let record = this.options.store.get(machineId);
    authorize(record, context);
    const requestDigest = mutationDigest(operation, payload);
    const replay = latestReplay(this.options.store.events(record.machineId, 0, 1_000), operation, authenticated.idempotencyKey, requestDigest);
    if (replay?.jobId !== undefined) {
      const job = this.options.jobs.get(replay.jobId);
      const response = { operation, machine: publicMachine(record), job: publicJob(job), jobId: job.id, noOp: true, replayed: true, eventOffset: replay.offset };
      return { ...response, resultDigest: resultDigest(response), artifactReferences: [] };
    }
    assertExpectedMachineSequence(record.lifecycle.stateSequence, expectedSequence);
    if (!['READY', 'EXECUTING'].includes(record.lifecycle.persistedState)) throw new MachineServiceError('machine_state_conflict', 'machine is not ready for execution', { state: record.lifecycle.persistedState });
    const running = await this.exactRunningIdentity(record);
    if (!sameProcessIdentity(record.processIdentity, running.identity)) throw new MachineServiceError('machine_process_conflict', 'machine leader process identity differs from the durable record');

    const job = this.options.jobs.start(operation, {
      argv, cwd, env, target: { kind: 'machine', machine: record.machineName },
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
      metadata: {
        machineService: true, kind: 'exec', machineId: record.machineId, machineName: record.machineName,
        requestDigest, idempotencyKey: authenticated.idempotencyKey, captureStreams,
        ...(outputLimitBytes === undefined ? {} : { outputLimitBytes }),
      },
    });
    const nextJobs = [...new Set([...record.activeJobIds, job.id])].sort();
    if (record.lifecycle.persistedState === 'READY') {
      record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'EXECUTING', 'READY', {
        operation, phase: 'job-submit', kind: 'machine.job-started', message: 'machine-targeted command submitted to the existing durable job authority',
        requestDigest, idempotencyKey: authenticated.idempotencyKey, jobId: job.id, observationDigest: running.observation.observations.observationDigest, occurredAt: this.options.now(),
      }, { activeJobIds: nextJobs, observations: running.observation.observations, lifecycle: { ...record.lifecycle, observedState: 'RUNNING' } });
    } else {
      record = this.options.store.update(record.machineId, record.lifecycle.stateSequence, {
        operation, phase: 'job-submit', kind: 'machine.job-started', message: 'concurrent machine-targeted command submitted to the existing durable job authority',
        requestDigest, idempotencyKey: authenticated.idempotencyKey, jobId: job.id, occurredAt: this.options.now(),
      }, { activeJobIds: nextJobs });
    }
    const eventOffset = this.options.store.events(record.machineId, 0, 1_000).length - 1;
    const response = { operation, machine: publicMachine(record), job: publicJob(job), jobId: job.id, noOp: false, replayed: false, eventOffset };
    return { ...response, resultDigest: resultDigest(response), artifactReferences: [] };
  }

  shell(payload: JsonObject, context: MachineOperationContext): Promise<JsonObject> {
    return this.exec(payload, context, 'babyx.machine.shell');
  }

  private async jobChanged(job: JobRecord): Promise<void> {
    if (job.status === 'running' || job.metadata?.machineService !== true || job.metadata?.kind !== 'exec' || typeof job.metadata.machineId !== 'string') return;
    const machineId = job.metadata.machineId;
    let record: DisposableMachineRecordV1;
    try { record = this.options.store.get(machineId); }
    catch { return; }
    if (!record.activeJobIds.includes(job.id)) return;

    const artifactIds: string[] = [];
    if (job.metadata.captureStreams === true && this.options.artifacts !== undefined) {
      for (const [stream, path] of [['stdout', job.stdoutPath], ['stderr', job.stderrPath]] as const) {
        if (!existsSync(path)) continue;
        try {
          const artifact = this.options.artifacts.create(`machine-${machineId}-${job.id}-${stream}`, path, { machineId, jobId: job.id, stream });
          if (typeof artifact.id === 'string') artifactIds.push(artifact.id);
        } catch {}
      }
    }

    for (let attempt = 0; attempt < 2; attempt += 1) {
      record = this.options.store.get(machineId);
      if (!record.activeJobIds.includes(job.id)) return;
      const remaining = record.activeJobIds.filter((id) => id !== job.id);
      const allArtifacts = [...new Set([...record.artifactIds, ...artifactIds])].sort();
      const details = {
        operation: String(job.operation), phase: 'job-complete', kind: job.status === 'completed' ? 'machine.job-completed' : 'machine.job-failed',
        message: job.status === 'completed' ? 'machine-targeted job completed' : 'machine-targeted job failed',
        requestDigest: typeof job.metadata.requestDigest === 'string' ? job.metadata.requestDigest : undefined,
        idempotencyKey: typeof job.metadata.idempotencyKey === 'string' ? job.metadata.idempotencyKey : undefined,
        jobId: job.id, occurredAt: this.options.now(),
      };
      try {
        if (remaining.length > 0) {
          this.options.store.update(machineId, record.lifecycle.stateSequence, details, { activeJobIds: remaining, artifactIds: allArtifacts });
          return;
        }
        const observed = await this.options.observer.status(record);
        if (observed.observedState === 'RUNNING') {
          const identity = await this.exactRunningIdentity(record, observed);
          if (!sameProcessIdentity(record.processIdentity, identity.identity)) throw new MachineServiceError('machine_process_conflict', 'machine identity changed while a job completed');
          this.options.store.transition(machineId, record.lifecycle.stateSequence, 'READY', 'READY', details, {
            activeJobIds: [], artifactIds: allArtifacts, observations: observed.observations,
            lifecycle: { ...record.lifecycle, observedState: 'RUNNING' },
          });
        } else {
          this.options.store.transition(machineId, record.lifecycle.stateSequence, 'DEGRADED', 'READY', details, {
            activeJobIds: [], artifactIds: allArtifacts, observations: observed.observations,
            lifecycle: { ...record.lifecycle, observedState: observed.observedState },
            lastError: { code: 'machine_job_failed', message: 'machine was not healthy when the final active job completed', phase: 'job-complete', retryable: true, destructiveRecoveryAllowed: false, artifactReferences: artifactIds, occurredAt: this.options.now() },
          });
        }
        return;
      } catch {
        if (attempt === 1) return;
      }
    }
  }
}
