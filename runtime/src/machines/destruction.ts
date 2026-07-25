import { existsSync, mkdirSync, readdirSync, realpathSync, rmdirSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, sep } from 'node:path';
import { canonicalize, sha256, type JsonObject, type ProcessIdentity } from '../core.ts';
import type { MachineArtifactAuthority } from './execution.ts';
import { DisposableMachineManager } from './disposable.ts';
import { MachineServiceError } from './errors.ts';
import { assertMachineId, ownershipProperties, type MachineServiceConfig } from './identity.ts';
import { MachineManager } from './manager.ts';
import { DisposableMachineObserver, type CloneDatasetObservation, type MachineStatusObservation, type SourceSnapshotObservation } from './observe.ts';
import { canonicalMachineEvidence, type DisposableMachineRecordV1, type MachineEventV1, type MachineTombstoneV1 } from './schemas.ts';
import type { MachineOperationContext } from './service.ts';
import { assertExpectedMachineSequence } from './states.ts';
import { DisposableMachineStore } from './store.ts';

export interface MachineDestructionControllerOptions {
  store: DisposableMachineStore;
  observer: DisposableMachineObserver;
  provider: DisposableMachineManager;
  manager: MachineManager;
  artifacts?: MachineArtifactAuthority;
  config: MachineServiceConfig;
  now: () => string;
  sleep?: (milliseconds: number) => Promise<void>;
  processIdentity: (pid: number) => ProcessIdentity;
  killProcessGroup?: (pgid: number) => void;
  hostBootId: string;
  evidenceRoot: string;
}

interface VerifiedStopped {
  observation: MachineStatusObservation;
  processAbsent: true;
}

interface OwnershipProof {
  source: SourceSnapshotObservation;
  clone: CloneDatasetObservation;
  descendants: string[];
}

function requiredContext(context: MachineOperationContext): { idempotencyKey: string; subject: string } {
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

function optionalBoolean(value: unknown, field: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'boolean') throw new MachineServiceError('machine_invalid_request', `${field} must be a boolean`);
  return value;
}

function optionalText(value: unknown, field: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) throw new MachineServiceError('machine_invalid_request', `${field} must be a non-empty NUL-free string`);
  return value;
}

function authorize(record: DisposableMachineRecordV1, context: MachineOperationContext): void {
  if (context.authorityClass === 'unrestricted-owner') return;
  if (record.ownerPrincipal !== context.subject) throw new MachineServiceError('machine_not_found', 'machine not found');
}

function digest(operation: string, payload: JsonObject): string {
  return sha256(canonicalMachineEvidence({ operation, payload }));
}

function publicMachine(record: DisposableMachineRecordV1): JsonObject {
  return JSON.parse(canonicalMachineEvidence(record)) as JsonObject;
}

function latestReplay(events: MachineEventV1[], operation: string, idempotencyKey: string, requestDigest: string): MachineEventV1 | undefined {
  const matches = events.filter((event) => event.operation === operation && event.idempotencyKey === idempotencyKey);
  if (matches.some((event) => event.requestDigest !== requestDigest)) throw new MachineServiceError('machine_idempotency_conflict', 'idempotency key was reused with a different mutation request');
  return matches.at(-1);
}

function decodeBase64(value: string): string {
  try { return Buffer.from(value, 'base64').toString('utf8'); } catch { return ''; }
}

function strictlyBelow(path: string, root: string): boolean {
  const relation = relative(root, path);
  return relation.length > 0 && relation !== '..' && !relation.startsWith(`..${sep}`) && !isAbsolute(relation);
}

function datasetStrictlyWithin(dataset: string, root: string): boolean {
  return dataset.startsWith(`${root}/`);
}

function sameIdentity(recorded: DisposableMachineRecordV1['processIdentity'], actual: ProcessIdentity): boolean {
  return recorded !== undefined
    && recorded.pid === actual.pid
    && recorded.processStartTime === actual.processStartTime
    && recorded.executablePath === actual.executablePath
    && recorded.bootId === actual.bootId;
}

function observationsForStopped(observation: MachineStatusObservation): DisposableMachineRecordV1['observations'] {
  return { ...observation.observations, process: 'absent' };
}

export class MachineDestructionController {
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly killProcessGroup: (pgid: number) => void;

  constructor(private readonly options: MachineDestructionControllerOptions) {
    this.sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    this.killProcessGroup = options.killProcessGroup ?? ((pgid) => process.kill(-pgid, 'SIGKILL'));
    mkdirSync(options.evidenceRoot, { recursive: true, mode: 0o700 });
  }

  private processAbsent(record: DisposableMachineRecordV1): boolean {
    if (record.processIdentity === undefined) return true;
    try {
      const actual = this.options.processIdentity(record.processIdentity.pid);
      return !sameIdentity(record.processIdentity, actual);
    } catch {
      return true;
    }
  }

  private exactProcess(record: DisposableMachineRecordV1): ProcessIdentity {
    if (record.processIdentity === undefined) throw new MachineServiceError('machine_process_conflict', 'durable process identity is absent');
    let actual: ProcessIdentity;
    try { actual = this.options.processIdentity(record.processIdentity.pid); }
    catch { throw new MachineServiceError('machine_process_conflict', 'durable machine process is no longer observable'); }
    if (!sameIdentity(record.processIdentity, actual)) throw new MachineServiceError('machine_process_conflict', 'observed process identity differs from the durable machine process');
    return actual;
  }

  private assertJobsPermitTeardown(record: DisposableMachineRecordV1): void {
    if (record.protectedJobIds.length > 0) throw new MachineServiceError('machine_protected_job_active', 'protected jobs block machine teardown', { protectedJobIds: record.protectedJobIds });
    if (record.activeJobIds.length > 0) throw new MachineServiceError('machine_job_active', 'active jobs block machine teardown', { activeJobIds: record.activeJobIds });
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

  private async verifiedStopped(record: DisposableMachineRecordV1): Promise<VerifiedStopped | undefined> {
    const observation = await this.options.observer.status(record);
    if (observation.observedState === 'UNKNOWN') throw new MachineServiceError('machine_provider_unavailable', 'machine stop observation is unavailable');
    if (observation.observedState === 'CONFLICT') throw new MachineServiceError('machine_process_conflict', 'machine identity conflicts with the durable record', { discrepancies: observation.discrepancies });
    const machineStopped = observation.machine.status === 'absent' || observation.machine.status === 'stopped';
    if (!machineStopped || !this.processAbsent(record)) return undefined;
    return { observation, processAbsent: true };
  }

  private async waitStopped(record: DisposableMachineRecordV1, timeoutMs: number): Promise<VerifiedStopped | undefined> {
    const attempts = Math.max(1, Math.ceil(timeoutMs / this.options.config.stopPollIntervalMs) + 1);
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const stopped = await this.verifiedStopped(record);
      if (stopped !== undefined) return stopped;
      if (attempt + 1 < attempts) await this.sleep(this.options.config.stopPollIntervalMs);
    }
    return undefined;
  }

  async stop(payload: JsonObject, context: MachineOperationContext): Promise<JsonObject> {
    assertAllowedKeys(payload, ['machineId', 'expectedSequence', 'gracefulTimeoutMs', 'forceAfterTimeout', 'reason']);
    const authenticated = requiredContext(context);
    const machineId = assertMachineId(payload.machineId);
    const expectedSequence = requiredSequence(payload.expectedSequence);
    const gracefulTimeoutMs = optionalPositiveInteger(payload.gracefulTimeoutMs, 'gracefulTimeoutMs') ?? this.options.config.stopGracefulTimeoutMs;
    const forceAfterTimeout = optionalBoolean(payload.forceAfterTimeout, 'forceAfterTimeout') ?? false;
    optionalText(payload.reason, 'reason');
    let record = this.options.store.get(machineId);
    authorize(record, context);
    const requestDigest = digest('babyx.machine.stop', payload);
    const replay = latestReplay(this.options.store.events(machineId, 0, 1_000), 'babyx.machine.stop', authenticated.idempotencyKey, requestDigest);

    if (record.lifecycle.persistedState === 'STOPPED' || record.lifecycle.persistedState === 'DESTROYED') {
      const stopped = await this.verifiedStopped(record);
      if (stopped === undefined) throw new MachineServiceError('machine_process_conflict', 'persisted stopped state is not positively verified');
      const response = { operation: 'babyx.machine.stop', machine: publicMachine(record), noOp: true, replayed: replay !== undefined, eventOffset: replay?.offset ?? this.options.store.events(machineId, 0, 1_000).length - 1 };
      return { ...response, resultDigest: sha256(canonicalize(response)), artifactReferences: [] };
    }
    if (!(replay !== undefined && record.lifecycle.persistedState === 'STOPPING')) assertExpectedMachineSequence(record.lifecycle.stateSequence, expectedSequence);
    this.assertJobsPermitTeardown(record);
    if (!['READY', 'EXECUTING', 'DEGRADED', 'FAILED', 'STARTING', 'STOPPING'].includes(record.lifecycle.persistedState)) throw new MachineServiceError('machine_state_conflict', 'machine is not in a stop-compatible state', { state: record.lifecycle.persistedState });

    const leaseId = this.acquireLease(record, 'babyx.machine.stop', authenticated.subject, requestDigest);
    try {
      const alreadyStopped = await this.verifiedStopped(record);
      if (alreadyStopped !== undefined) {
        if (record.lifecycle.persistedState !== 'STOPPING') {
          record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'STOPPING', 'STOPPED', {
            operation: 'babyx.machine.stop', phase: 'verified-stop-intent', kind: 'machine.stopping', message: 'stop intent persisted for an already-absent machine before final readback',
            requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, observationDigest: alreadyStopped.observation.observations.observationDigest, occurredAt: this.options.now(),
          }, { cleanup: { ...record.cleanup, requested: true, requestedAt: record.cleanup.requestedAt ?? this.options.now(), stopAttempted: false }, observations: alreadyStopped.observation.observations });
        }
        const completed = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'STOPPED', 'STOPPED', {
          operation: 'babyx.machine.stop', phase: 'stop-readback', kind: 'machine.stopped', message: 'machine and exact process absence verified',
          requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, observationDigest: alreadyStopped.observation.observations.observationDigest, occurredAt: this.options.now(),
        }, { processIdentity: undefined, observations: observationsForStopped(alreadyStopped.observation), cleanup: { ...record.cleanup, requested: true, stopVerified: true }, lifecycle: { ...record.lifecycle, observedState: 'STOPPED_INTACT', stoppedAt: this.options.now() } });
        const response = { operation: 'babyx.machine.stop', machine: publicMachine(completed), noOp: true, replayed: replay !== undefined, eventOffset: this.options.store.events(machineId, 0, 1_000).length - 1 };
        return { ...response, resultDigest: sha256(canonicalize(response)), artifactReferences: [] };
      }

      const status = await this.options.observer.status(record);
      if (status.observedState !== 'RUNNING') throw new MachineServiceError('machine_stop_failed', 'machine is neither exact-running nor positively stopped', { observedState: status.observedState });
      this.exactProcess(record);
      if (record.lifecycle.persistedState !== 'STOPPING') {
        record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'STOPPING', 'STOPPED', {
          operation: 'babyx.machine.stop', phase: 'stop-intent', kind: 'machine.stopping', message: 'stop intent persisted before provider mutation',
          requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, observationDigest: status.observations.observationDigest, occurredAt: this.options.now(),
        }, { cleanup: { ...record.cleanup, requested: true, requestedAt: record.cleanup.requestedAt ?? this.options.now(), stopAttempted: true }, observations: status.observations });
      }

      const terminate = await this.options.manager.lifecycle('terminate', record.machineName);
      let stopped = await this.waitStopped(record, gracefulTimeoutMs);
      let forced = false;
      if (stopped === undefined && forceAfterTimeout) {
        const actual = this.exactProcess(record);
        const pgid = actual.pgid ?? record.processIdentity?.pgid;
        if (!Number.isSafeInteger(pgid) || Number(pgid) < 1) throw new MachineServiceError('machine_process_conflict', 'exact process group identity is unavailable for bounded escalation');
        this.killProcessGroup(Number(pgid));
        forced = true;
        stopped = await this.waitStopped(record, gracefulTimeoutMs);
      }
      if (stopped === undefined) {
        const failed = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'FAILED', 'STOPPED', {
          operation: 'babyx.machine.stop', phase: 'stop-readback', kind: 'machine.stop-failed', message: 'machine or exact process remained after bounded stop policy',
          requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, occurredAt: this.options.now(),
        }, { cleanup: { ...record.cleanup, requested: true, stopAttempted: true, stopVerified: false }, lastError: { code: 'machine_stop_failed', message: 'machine or exact process remained after bounded stop policy', phase: 'stop-readback', retryable: true, destructiveRecoveryAllowed: false, commandExitCode: terminate.exitCode ?? undefined, signal: terminate.signal ?? undefined, artifactReferences: [], occurredAt: this.options.now() } });
        throw new MachineServiceError('machine_stop_failed', 'machine stop could not be positively verified', { machineId: failed.machineId, forced });
      }

      const completed = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'STOPPED', 'STOPPED', {
        operation: 'babyx.machine.stop', phase: 'stop-readback', kind: 'machine.stopped', message: 'machine and exact process absence verified',
        requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, observationDigest: stopped.observation.observations.observationDigest, occurredAt: this.options.now(),
      }, {
        processIdentity: undefined, observations: observationsForStopped(stopped.observation),
        cleanup: { ...record.cleanup, requested: true, stopAttempted: true, stopVerified: true },
        lifecycle: { ...record.lifecycle, observedState: 'STOPPED_INTACT', stoppedAt: this.options.now() },
      });
      const response = { operation: 'babyx.machine.stop', machine: publicMachine(completed), noOp: false, replayed: replay !== undefined, forced, terminateExitCode: terminate.exitCode, eventOffset: this.options.store.events(machineId, 0, 1_000).length - 1 };
      return { ...response, resultDigest: sha256(canonicalize(response)), artifactReferences: [] };
    } finally {
      this.options.store.releaseLease(record.machineId, leaseId);
    }
  }

  private async ownershipProof(record: DisposableMachineRecordV1, allowAbsentClone: boolean): Promise<OwnershipProof> {
    if (record.clone.dataset === record.source.dataset || record.clone.dataset === record.source.snapshot || record.clone.dataset.includes('@')) {
      throw new MachineServiceError('machine_ownership_mismatch', 'clone dataset is not distinct from the immutable source');
    }
    if (!this.options.config.cloneDatasetRoots.some((root) => datasetStrictlyWithin(record.clone.dataset, root))) throw new MachineServiceError('machine_ownership_mismatch', 'clone dataset is outside configured ownership roots');
    if (!strictlyBelow(record.clone.mountpoint, this.options.config.machineRoot)) throw new MachineServiceError('machine_ownership_mismatch', 'clone root is outside the configured machine root');

    const source = this.options.observer.requireProviderObservation(await this.options.observer.source(record.source.snapshot), 'source snapshot');
    if (source.status !== 'present' || source.guid === undefined || source.guid !== record.source.snapshotGuid) throw new MachineServiceError('machine_source_mismatch', 'immutable source snapshot identity is absent or changed');
    const clone = this.options.observer.requireProviderObservation(await this.options.observer.clone(record.clone.dataset), 'clone dataset');
    if (clone.status === 'absent' && allowAbsentClone) return { source, clone, descendants: [] };
    if (clone.status !== 'present') throw new MachineServiceError('machine_ownership_mismatch', 'clone dataset is absent before authorized destruction');
    const expected = ownershipProperties(record.machineId, record.creationRequestDigest, record.ownerPrincipal);
    const exact = clone.guid === record.clone.datasetGuid
      && clone.origin === record.source.snapshot
      && clone.mountpoint === record.clone.mountpoint
      && Object.entries(expected).every(([key, value]) => clone.properties[key] === value);
    if (!exact) throw new MachineServiceError('machine_ownership_mismatch', 'clone dataset ownership or immutable identity does not match the durable record');

    const descendantsResult = await this.options.provider.listDescendants(record.clone.dataset);
    if (descendantsResult.exitCode !== 0) throw new MachineServiceError('machine_provider_unavailable', 'clone descendant observation failed', { exitCode: descendantsResult.exitCode, stderrSha256: descendantsResult.stderrSha256 });
    const descendants = decodeBase64(descendantsResult.stdout).split('\n').map((entry) => entry.trim()).filter(Boolean);
    if (descendants.length !== 1 || descendants[0] !== record.clone.dataset) throw new MachineServiceError('machine_dependency_conflict', 'clone dataset has recursive children or conflicting descendants', { descendants: descendants.slice(0, 100) });
    return { source, clone, descendants };
  }

  private retainEvidence(record: DisposableMachineRecordV1, proof: OwnershipProof, operation: string): string[] {
    if (this.options.artifacts === undefined) return [...record.cleanup.retainedEvidence];
    const events = this.options.store.events(record.machineId, 0, 1_000);
    const evidence = {
      schemaVersion: '1.0.0', operation, retainedAt: this.options.now(), machine: JSON.parse(canonicalMachineEvidence(record)),
      events: JSON.parse(canonicalMachineEvidence(events)),
      ownership: {
        source: { snapshot: proof.source.snapshot, guid: proof.source.guid, creationTxg: proof.source.creationTxg, observedAt: proof.source.observedAt },
        clone: { dataset: proof.clone.dataset, guid: proof.clone.guid, origin: proof.clone.origin, mountpoint: proof.clone.mountpoint, properties: proof.clone.properties, observedAt: proof.clone.observedAt },
        descendants: proof.descendants,
      },
    };
    const path = join(this.options.evidenceRoot, `${record.machineId}-${record.lifecycle.stateSequence}-${sha256(canonicalize(evidence)).slice(0, 16)}.json`);
    writeFileSync(path, `${canonicalize(evidence)}\n`, { mode: 0o600, flag: 'wx' });
    const artifact = this.options.artifacts.create(`machine-${record.machineId}-cleanup-evidence`, path, { machineId: record.machineId, operation, stateSequence: record.lifecycle.stateSequence });
    return typeof artifact.id === 'string' ? [...new Set([...record.cleanup.retainedEvidence, artifact.id])].sort() : [...record.cleanup.retainedEvidence];
  }

  private rootReleased(record: DisposableMachineRecordV1): boolean {
    const root = record.clone.mountpoint;
    if (!existsSync(root)) return true;
    if (!strictlyBelow(root, this.options.config.machineRoot)) return false;
    try {
      if (realpathSync(root) !== root || readdirSync(root).length !== 0) return false;
      rmdirSync(root);
      return !existsSync(root);
    } catch {
      return false;
    }
  }

  private async verifyDestroyed(record: DisposableMachineRecordV1): Promise<{ source: SourceSnapshotObservation; observation: MachineStatusObservation; rootAbsent: boolean; processAbsent: boolean }> {
    const source = this.options.observer.requireProviderObservation(await this.options.observer.source(record.source.snapshot), 'source snapshot post-destroy');
    if (source.status !== 'present' || source.guid !== record.source.snapshotGuid) throw new MachineServiceError('machine_source_mismatch', 'source snapshot changed during clone cleanup');
    const observation = await this.options.observer.status(record);
    if (observation.observedState === 'UNKNOWN') throw new MachineServiceError('machine_provider_unavailable', 'post-destroy observation is unavailable');
    if (observation.clone.status !== 'absent') throw new MachineServiceError('machine_cleanup_failed', 'clone dataset absence was not positively verified', { cloneStatus: observation.clone.status });
    if (observation.machine.status !== 'absent') throw new MachineServiceError('machine_cleanup_failed', 'machine absence was not positively verified', { machineStatus: observation.machine.status });
    const processAbsent = this.processAbsent(record);
    if (!processAbsent) throw new MachineServiceError('machine_cleanup_failed', 'exact machine process absence was not positively verified');
    const mount = await this.options.provider.mountpoint(record.clone.mountpoint);
    if (mount.exitCode === 0) throw new MachineServiceError('machine_cleanup_failed', 'machine root remains mounted after clone destruction');
    const rootAbsent = this.rootReleased(record);
    if (!rootAbsent) throw new MachineServiceError('machine_cleanup_failed', 'machine root remains non-empty or conflicting after clone destruction');
    return { source, observation, rootAbsent, processAbsent };
  }

  async destroy(payload: JsonObject, context: MachineOperationContext): Promise<JsonObject> {
    assertAllowedKeys(payload, ['machineId', 'expectedSequence', 'stopIfRunning', 'forceStop', 'stopTimeoutMs', 'reason']);
    const authenticated = requiredContext(context);
    const machineId = assertMachineId(payload.machineId);
    const expectedSequence = requiredSequence(payload.expectedSequence);
    const stopIfRunning = optionalBoolean(payload.stopIfRunning, 'stopIfRunning') ?? false;
    const forceStop = optionalBoolean(payload.forceStop, 'forceStop') ?? false;
    const stopTimeoutMs = optionalPositiveInteger(payload.stopTimeoutMs, 'stopTimeoutMs') ?? this.options.config.stopGracefulTimeoutMs;
    optionalText(payload.reason, 'reason');
    let record = this.options.store.get(machineId);
    authorize(record, context);
    const requestDigest = digest('babyx.machine.destroy', payload);
    const replay = latestReplay(this.options.store.events(machineId, 0, 1_000), 'babyx.machine.destroy', authenticated.idempotencyKey, requestDigest);

    if (record.lifecycle.persistedState === 'DESTROYED') {
      await this.verifyDestroyed(record);
      const tombstone = this.options.store.getTombstone(machineId) ?? this.options.store.createTombstone(machineId);
      const response = { operation: 'babyx.machine.destroy', machine: publicMachine(record), tombstone, noOp: true, replayed: replay !== undefined, eventOffset: replay?.offset ?? this.options.store.events(machineId, 0, 1_000).length - 1 };
      return { ...response, resultDigest: sha256(canonicalize(response)), artifactReferences: record.cleanup.retainedEvidence };
    }
    if (!(replay !== undefined && record.lifecycle.persistedState === 'DESTROYING')) assertExpectedMachineSequence(record.lifecycle.stateSequence, expectedSequence);
    this.assertJobsPermitTeardown(record);

    const observed = await this.options.observer.status(record);
    if (observed.observedState === 'RUNNING') {
      if (!stopIfRunning) throw new MachineServiceError('machine_state_conflict', 'running machine requires stopIfRunning authorization before destroy');
      await this.stop({ machineId, expectedSequence: record.lifecycle.stateSequence, gracefulTimeoutMs: stopTimeoutMs, forceAfterTimeout: forceStop, reason: 'destroy prerequisite' }, {
        ...context, idempotencyKey: `${authenticated.idempotencyKey}:stop`,
      });
      record = this.options.store.get(machineId);
    } else if (observed.observedState === 'CONFLICT') {
      try { await this.ownershipProof(record, false); }
      catch (error) {
        if (error instanceof MachineServiceError) throw error;
        throw new MachineServiceError('machine_ownership_mismatch', error instanceof Error ? error.message : 'clone ownership proof failed');
      }
      throw new MachineServiceError('machine_identity_ambiguous', 'conflicting machine or root identity blocks destruction', { discrepancies: observed.discrepancies });
    } else if (observed.observedState === 'UNKNOWN') {
      throw new MachineServiceError('machine_provider_unavailable', 'pre-destroy observation is unavailable');
    }
    this.assertJobsPermitTeardown(record);
    if (!this.processAbsent(record)) throw new MachineServiceError('machine_process_conflict', 'exact process is still present before destruction');
    if (!['CLONED', 'STOPPED', 'FAILED', 'DEGRADED', 'DESTROYING'].includes(record.lifecycle.persistedState)) throw new MachineServiceError('machine_state_conflict', 'machine is not in a destroy-compatible state', { state: record.lifecycle.persistedState });

    const leaseId = this.acquireLease(record, 'babyx.machine.destroy', authenticated.subject, requestDigest);
    try {
      let proof = await this.ownershipProof(record, record.lifecycle.persistedState === 'DESTROYING');
      let retainedEvidence = record.cleanup.retainedEvidence;
      if (record.lifecycle.persistedState !== 'DESTROYING') {
        retainedEvidence = this.retainEvidence(record, proof, 'babyx.machine.destroy');
        record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'DESTROYING', 'DESTROYED', {
          operation: 'babyx.machine.destroy', phase: 'destroy-intent', kind: 'machine.destroying', message: 'destroy intent and retained evidence persisted before provider mutation',
          requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, occurredAt: this.options.now(),
        }, {
          cleanup: { ...record.cleanup, requested: true, requestedAt: record.cleanup.requestedAt ?? this.options.now(), stopVerified: true, retainedEvidence },
          lifecycle: { ...record.lifecycle, desiredState: 'DESTROYED' },
        });
      }

      let unmountExitCode: number | null | undefined;
      let destroyExitCode: number | null | undefined;
      let datasetDestroyAttempted = record.cleanup.datasetDestroyAttempted;
      let verified;
      try {
        if (proof.clone.status === 'present') {
          const mount = await this.options.provider.mountpoint(record.clone.mountpoint);
          if (mount.exitCode === 0) {
            const unmount = await this.options.provider.unmount(record.clone.mountpoint);
            unmountExitCode = unmount.exitCode;
            if (unmount.exitCode !== 0) throw new MachineServiceError('machine_cleanup_failed', 'owned clone root could not be unmounted', { exitCode: unmount.exitCode, stderrSha256: unmount.stderrSha256 });
          }
          datasetDestroyAttempted = true;
          const destroy = await this.options.provider.destroyClone(record.clone.dataset);
          destroyExitCode = destroy.exitCode;
          proof = await this.ownershipProof(record, true);
          if (proof.clone.status !== 'absent') throw new MachineServiceError('machine_cleanup_failed', 'exact non-recursive clone destruction was not positively verified', { exitCode: destroy.exitCode, stderrSha256: destroy.stderrSha256 });
        }
        verified = await this.verifyDestroyed(record);
      } catch (error) {
        const occurredAt = this.options.now();
        const recovery = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'RECOVERY_REQUIRED', 'DESTROYED', {
          operation: 'babyx.machine.destroy', phase: 'destroy-readback', kind: 'machine.cleanup-incomplete', message: error instanceof Error ? error.message : 'cleanup readback failed',
          requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, occurredAt,
        }, {
          cleanup: { ...record.cleanup, datasetDestroyAttempted, retainedEvidence },
          lastError: { code: error instanceof MachineServiceError ? error.code : 'machine_cleanup_failed', message: error instanceof Error ? error.message : 'cleanup readback failed', phase: 'destroy-readback', retryable: true, destructiveRecoveryAllowed: false, artifactReferences: retainedEvidence, occurredAt },
        });
        throw new MachineServiceError('machine_cleanup_failed', 'machine cleanup could not be positively verified', { machineId: recovery.machineId });
      }

      const destroyedAt = this.options.now();
      const completed = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'DESTROYED', 'DESTROYED', {
        operation: 'babyx.machine.destroy', phase: 'destroy-readback', kind: 'machine.destroyed', message: 'dataset, root, machine, and exact process absence positively verified',
        requestDigest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId, observationDigest: verified.observation.observations.observationDigest, occurredAt: destroyedAt,
      }, {
        processIdentity: undefined,
        activeJobIds: [],
        observations: { ...verified.observation.observations, dataset: 'absent', mountpoint: 'absent', machinectl: 'absent', process: 'absent', rootPath: 'absent' },
        cleanup: {
          ...record.cleanup, requested: true, stopAttempted: record.cleanup.stopAttempted, stopVerified: true,
          datasetDestroyAttempted: true, datasetAbsentVerified: true, rootAbsentVerified: true,
          machineAbsentVerified: true, processAbsentVerified: true, completed: true, completedAt: destroyedAt, retainedEvidence,
        },
        lifecycle: { ...record.lifecycle, desiredState: 'DESTROYED', observedState: 'ABSENT', destroyedAt },
      });
      const tombstone: MachineTombstoneV1 = this.options.store.createTombstone(machineId);
      const response = { operation: 'babyx.machine.destroy', machine: publicMachine(completed), tombstone, noOp: false, replayed: replay !== undefined, unmountExitCode: unmountExitCode ?? null, destroyExitCode: destroyExitCode ?? null, eventOffset: this.options.store.events(machineId, 0, 1_000).length - 1 };
      return { ...response, resultDigest: sha256(canonicalize(response)), artifactReferences: retainedEvidence };
    } finally {
      this.options.store.releaseLease(record.machineId, leaseId);
    }
  }
}
