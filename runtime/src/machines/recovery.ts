import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject, type ProcessIdentity } from '../core.ts';
import { MachineDestructionController } from './destruction.ts';
import type { MachineArtifactAuthority } from './execution.ts';
import { DisposableMachineManager } from './disposable.ts';
import { MachineServiceError } from './errors.ts';
import { assertMachineId, ownershipProperties, type MachineServiceConfig } from './identity.ts';
import { DisposableMachineObserver, type MachineStatusObservation } from './observe.ts';
import {
  MACHINE_PROVIDER_ID,
  canonicalMachineEvidence,
  type DisposableMachineRecordV1,
  type MachineControllerLeaseV1,
  type MachineEventV1,
  type MachineState,
} from './schemas.ts';
import type { MachineOperationContext } from './service.ts';
import { assertExpectedMachineSequence, isMachineState } from './states.ts';
import { DisposableMachineStore } from './store.ts';

export interface MachineRecoveryControllerOptions {
  store: DisposableMachineStore;
  observer: DisposableMachineObserver;
  provider: DisposableMachineManager;
  destruction: MachineDestructionController;
  config: MachineServiceConfig;
  now: () => string;
  processIdentity: (pid: number) => ProcessIdentity;
  hostBootId: string;
  artifacts?: MachineArtifactAuthority;
  evidenceRoot: string;
  monotonicNow?: () => number;
}

type ReconcileClassification = 'consistent' | 'recoverable' | 'ambiguous' | 'lost' | 'destroyed' | 'deferred' | 'unknown';

interface ReconcileResult extends JsonObject {
  machineId: string;
  beforeState: MachineState;
  afterState: MachineState;
  classification: ReconcileClassification;
  action: string;
  changed: boolean;
  dryRun: boolean;
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
  if (unsupported.length > 0) throw new MachineServiceError('machine_invalid_request', 'request contains unsupported properties', { properties: unsupported });
}

function optionalBoolean(value: unknown, field: string, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') throw new MachineServiceError('machine_invalid_request', `${field} must be a boolean`);
  return value;
}

function optionalPositiveInteger(value: unknown, field: string, fallback: number, maximum = 1_000): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > maximum) throw new MachineServiceError('machine_invalid_request', `${field} must be between 1 and ${maximum}`);
  return Number(value);
}

function requiredSequence(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1) throw new MachineServiceError('machine_invalid_request', 'expectedSequence must be a positive safe integer');
  return Number(value);
}

function optionalText(value: unknown, field: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) throw new MachineServiceError('machine_invalid_request', `${field} must be a non-empty NUL-free string`);
  return value;
}

function optionalTimestamp(value: unknown, field: string): number | undefined {
  const text = optionalText(value, field);
  if (text === undefined) return undefined;
  const parsed = Date.parse(text);
  if (!Number.isFinite(parsed)) throw new MachineServiceError('machine_invalid_request', `${field} must be an ISO timestamp`);
  return parsed;
}

function authorize(record: DisposableMachineRecordV1, context: MachineOperationContext): void {
  if (context.authorityClass === 'unrestricted-owner') return;
  if (record.ownerPrincipal !== context.subject) throw new MachineServiceError('machine_not_found', 'machine not found');
}

function publicRecord(record: DisposableMachineRecordV1): JsonObject {
  return JSON.parse(canonicalMachineEvidence(record)) as JsonObject;
}

function requestDigest(operation: string, payload: JsonObject): string {
  return sha256(canonicalMachineEvidence({ operation, payload }));
}

function latestReplay(events: MachineEventV1[], operation: string, key: string, digest: string): MachineEventV1 | undefined {
  const matches = events.filter((event) => event.operation === operation && event.idempotencyKey === key);
  if (matches.some((event) => event.requestDigest !== digest)) throw new MachineServiceError('machine_idempotency_conflict', 'idempotency key was reused with a different request');
  return matches.at(-1);
}

function internalKey(parent: string, operation: string, machineId: string): string {
  return `${operation}:${sha256(`${parent}:${machineId}`).slice(0, 40)}`;
}

function decode(result: { stdout: string }): string {
  try { return Buffer.from(result.stdout, 'base64').toString('utf8'); } catch { return ''; }
}

function completeIdentity(record: DisposableMachineRecordV1, observation: MachineStatusObservation, readIdentity: (pid: number) => ProcessIdentity, bootId: string): DisposableMachineRecordV1['processIdentity'] {
  const leader = Number(observation.machine.properties.Leader);
  if (!Number.isSafeInteger(leader) || leader < 1) throw new MachineServiceError('machine_process_conflict', 'machinectl leader PID is unavailable');
  if (observation.machine.properties.Name !== record.machineName || observation.machine.properties.RootDirectory !== record.clone.mountpoint) {
    throw new MachineServiceError('machine_process_conflict', 'machinectl identity differs from the durable machine');
  }
  let identity: ProcessIdentity;
  try { identity = readIdentity(leader); }
  catch { throw new MachineServiceError('machine_process_conflict', 'machine leader process identity is unavailable'); }
  if (identity.pid !== leader || identity.processStartTime === undefined || identity.executablePath === undefined || !exactMachineLeaderExecutable(identity.executablePath) || identity.bootId !== bootId) {
    throw new MachineServiceError('machine_process_conflict', 'machine leader process identity is incomplete or belongs to another boot');
  }
  return {
    pid: identity.pid,
    ...(identity.pgid === undefined ? {} : { pgid: identity.pgid }),
    processStartTime: identity.processStartTime,
    executablePath: identity.executablePath,
    bootId: identity.bootId,
  };
}

function sameProcessIdentity(expected: DisposableMachineRecordV1['processIdentity'], actual: ProcessIdentity): boolean {
  return expected !== undefined
    && expected.pid === actual.pid
    && expected.processStartTime === actual.processStartTime
    && expected.executablePath === actual.executablePath
    && expected.bootId === actual.bootId;
}

function exactMachineLeaderExecutable(path: string): boolean {
  return /\/(?:systemd|systemd-nspawn)$/u.test(path);
}

function exactClone(record: DisposableMachineRecordV1, observation: MachineStatusObservation): boolean {
  if (observation.clone.status !== 'present') return false;
  const expected = ownershipProperties(record.machineId, record.creationRequestDigest, record.ownerPrincipal);
  return observation.clone.origin === record.source.snapshot
    && observation.clone.mountpoint === record.clone.mountpoint
    && (record.clone.datasetGuid === undefined || observation.clone.guid === record.clone.datasetGuid)
    && Object.entries(expected).every(([name, value]) => observation.clone.properties[name] === value);
}

function leaseStatus(lease: MachineControllerLeaseV1 | undefined, now: number, bootId: string): 'none' | 'live' | 'stale' {
  if (lease === undefined) return 'none';
  if (lease.hostBootId !== undefined && lease.hostBootId !== bootId) return 'stale';
  if (Date.parse(lease.expiresAt) <= now) return 'stale';
  return 'live';
}

export class MachineRecoveryController {
  private readonly monotonicNow: () => number;

  constructor(private readonly options: MachineRecoveryControllerOptions) {
    this.monotonicNow = options.monotonicNow ?? (() => Date.now());
    mkdirSync(options.evidenceRoot, { recursive: true, mode: 0o700 });
  }

  async initialize(context: MachineOperationContext): Promise<JsonObject> {
    let storeVerification: JsonObject | undefined;
    let storeError: JsonObject | undefined;
    try { storeVerification = this.options.store.verifyAndRepairIndexes() as unknown as JsonObject; }
    catch (error) {
      storeError = {
        code: error instanceof MachineServiceError ? error.code : 'machine_record_corrupt',
        message: error instanceof Error ? error.message : 'machine store verification failed',
      };
    }
    const reconciled = await this.reconcile({ limit: this.options.config.startupReconcileLimit, timeBudgetMs: this.options.config.startupReconcileTimeBudgetMs, reason: 'startup reconciliation' }, context);
    return { ...reconciled, startup: true, storeVerification: storeVerification ?? null, storeError: storeError ?? null };
  }

  async reconcile(payload: JsonObject, context: MachineOperationContext): Promise<JsonObject> {
    assertAllowedKeys(payload, ['machineId', 'limit', 'timeBudgetMs', 'dryRun', 'reason']);
    const authenticated = requiredContext(context);
    const machineId = payload.machineId === undefined ? undefined : assertMachineId(payload.machineId);
    const limit = optionalPositiveInteger(payload.limit, 'limit', this.options.config.startupReconcileLimit);
    const timeBudgetMs = optionalPositiveInteger(payload.timeBudgetMs, 'timeBudgetMs', this.options.config.startupReconcileTimeBudgetMs, 300_000);
    const dryRun = optionalBoolean(payload.dryRun, 'dryRun', false);
    optionalText(payload.reason, 'reason');
    const scan = machineId === undefined ? this.options.store.scan(1_000) : { records: [this.options.store.get(machineId)], errors: [], total: 1, truncated: false };
    const eligible = scan.records.filter((record) => context.authorityClass === 'unrestricted-owner' || record.ownerPrincipal === authenticated.subject);
    const selected = eligible.slice(0, limit);
    const started = this.monotonicNow();
    const results: JsonObject[] = [];
    let timeBudgetExhausted = false;
    for (const record of selected) {
      if (this.monotonicNow() - started >= timeBudgetMs) { timeBudgetExhausted = true; break; }
      try {
        authorize(record, context);
        results.push(await this.reconcileOne(record, dryRun, context, payload));
      } catch (error) {
        let afterState = record.lifecycle.persistedState;
        try { afterState = this.options.store.get(record.machineId).lifecycle.persistedState; } catch {}
        results.push({ machineId: record.machineId, beforeState: record.lifecycle.persistedState, afterState, classification: error instanceof MachineServiceError && ['machine_identity_ambiguous', 'machine_process_conflict', 'machine_ownership_mismatch'].includes(error.code) ? 'ambiguous' : 'unknown', action: 'error', changed: false, dryRun, error: { code: error instanceof MachineServiceError ? error.code : 'machine_reconcile_failed', message: error instanceof Error ? error.message : 'reconciliation failed' } });
      }
    }
    const recordErrors = context.authorityClass === 'unrestricted-owner' ? scan.errors : [];
    const remainingDeferred = Math.max(0, eligible.length - results.length);
    return { operation: 'babyx.machine.reconcile', dryRun, limit, timeBudgetMs, processed: results.length, totalEligible: eligible.length, remainingDeferred, timeBudgetExhausted, scanTruncated: scan.truncated, recordErrors, results };
  }

  private async reconcileOne(recordValue: DisposableMachineRecordV1, dryRun: boolean, context: MachineOperationContext, request: JsonObject): Promise<ReconcileResult> {
    let record = this.options.store.get(recordValue.machineId);
    const beforeState = record.lifecycle.persistedState;
    const digest = requestDigest('babyx.machine.reconcile', { ...request, machineId: record.machineId });
    const key = internalKey(context.idempotencyKey as string, 'reconcile', record.machineId);
    const replay = latestReplay(this.options.store.events(record.machineId, 0, 1_000), 'babyx.machine.reconcile', key, digest);
    if (replay !== undefined) return { machineId: record.machineId, beforeState, afterState: record.lifecycle.persistedState, classification: 'consistent', action: 'idempotent-replay', changed: false, dryRun };

    const lease = this.options.store.getLease(record.machineId);
    const currentLeaseStatus = leaseStatus(lease, Date.parse(this.options.now()), this.options.hostBootId);
    if (currentLeaseStatus === 'live') return { machineId: record.machineId, beforeState, afterState: record.lifecycle.persistedState, classification: 'deferred', action: 'live-controller-lease', changed: false, dryRun };
    if (currentLeaseStatus === 'stale' && lease !== undefined && !dryRun) this.options.store.releaseLease(record.machineId, lease.leaseId);

    const observed = await this.options.observer.status(record);
    if (observed.observedState === 'UNKNOWN') {
      if (!dryRun) record = this.options.store.update(record.machineId, record.lifecycle.stateSequence, {
        operation: 'babyx.machine.reconcile', phase: 'classification', kind: 'machine.reconcile-unknown', message: 'provider observation unavailable; automatic mutation blocked',
        requestDigest: digest, idempotencyKey: key, observationDigest: observed.observations.observationDigest, occurredAt: this.options.now(),
      }, { observations: observed.observations, lastError: { code: 'machine_provider_unavailable', message: 'provider observation unavailable during reconciliation', phase: 'classification', retryable: true, destructiveRecoveryAllowed: false, artifactReferences: [], occurredAt: this.options.now() } });
      return { machineId: record.machineId, beforeState, afterState: record.lifecycle.persistedState, classification: 'unknown', action: 'defer-unavailable-observation', changed: !dryRun, dryRun };
    }
    if (observed.observedState === 'CONFLICT') {
      if (!dryRun && record.lifecycle.persistedState !== 'AMBIGUOUS') record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'AMBIGUOUS', record.lifecycle.desiredState, {
        operation: 'babyx.machine.reconcile', phase: 'classification', kind: 'machine.reconcile-ambiguous', message: 'identity conflict blocks automatic recovery and destruction',
        requestDigest: digest, idempotencyKey: key, observationDigest: observed.observations.observationDigest, occurredAt: this.options.now(),
      }, { observations: observed.observations, lastError: { code: 'machine_identity_ambiguous', message: observed.discrepancies.join('; ') || 'identity conflict', phase: 'classification', retryable: false, destructiveRecoveryAllowed: false, artifactReferences: [], occurredAt: this.options.now() } });
      return { machineId: record.machineId, beforeState, afterState: dryRun ? beforeState : this.options.store.get(record.machineId).lifecycle.persistedState, classification: 'ambiguous', action: 'block-automatic-recovery', changed: !dryRun && beforeState !== 'AMBIGUOUS', dryRun };
    }
    if (observed.source.status !== 'present'
      || (record.source.expectedSnapshotGuid !== undefined && observed.source.guid !== record.source.expectedSnapshotGuid)
      || (record.source.snapshotGuid !== undefined && observed.source.guid !== record.source.snapshotGuid)) {
      if (!dryRun && record.lifecycle.persistedState !== 'LOST') record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'LOST', record.lifecycle.desiredState, {
        operation: 'babyx.machine.reconcile', phase: 'classification', kind: 'machine.reconcile-lost', message: 'immutable source snapshot is absent or changed',
        requestDigest: digest, idempotencyKey: key, observationDigest: observed.observations.observationDigest, occurredAt: this.options.now(),
      }, { observations: observed.observations });
      return { machineId: record.machineId, beforeState, afterState: dryRun ? beforeState : this.options.store.get(record.machineId).lifecycle.persistedState, classification: 'lost', action: 'mark-lost', changed: !dryRun && beforeState !== 'LOST', dryRun };
    }

    if (observed.observedState === 'RUNNING' && record.processIdentity !== undefined && ['READY', 'EXECUTING', 'STOPPING'].includes(record.lifecycle.persistedState)) {
      let actual: ProcessIdentity | undefined;
      try { actual = this.options.processIdentity(record.processIdentity.pid); } catch {}
      if (actual === undefined || !sameProcessIdentity(record.processIdentity, actual) || actual.bootId !== this.options.hostBootId || actual.executablePath === undefined || !exactMachineLeaderExecutable(actual.executablePath)) {
        if (!dryRun && record.lifecycle.persistedState !== 'AMBIGUOUS') record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'AMBIGUOUS', record.lifecycle.desiredState, {
          operation: 'babyx.machine.reconcile', phase: 'process-identity', kind: 'machine.reconcile-ambiguous', message: 'persisted process identity does not exactly match the live machine process', requestDigest: digest, idempotencyKey: key, observationDigest: observed.observations.observationDigest, occurredAt: this.options.now(),
        }, { observations: { ...observed.observations, process: 'present-conflict' }, lastError: { code: 'machine_process_conflict', message: 'PID, start time, executable, or boot identity differs from the durable binding', phase: 'process-identity', retryable: false, destructiveRecoveryAllowed: false, artifactReferences: [], occurredAt: this.options.now() } });
        return { machineId: record.machineId, beforeState, afterState: dryRun ? beforeState : 'AMBIGUOUS', classification: 'ambiguous', action: 'block-stale-process-adoption', changed: !dryRun && beforeState !== 'AMBIGUOUS', dryRun };
      }
    }

    if (record.lifecycle.persistedState === 'DESTROYED') {
      const destroyed = observed.observedState === 'ABSENT';
      if (!destroyed && !dryRun) record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'RECOVERY_REQUIRED', 'DESTROYED', {
        operation: 'babyx.machine.reconcile', phase: 'destroyed-readback', kind: 'machine.cleanup-incomplete', message: 'persisted DESTROYED state no longer has complete absence evidence',
        requestDigest: digest, idempotencyKey: key, observationDigest: observed.observations.observationDigest, occurredAt: this.options.now(),
      }, { observations: observed.observations });
      return { machineId: record.machineId, beforeState, afterState: dryRun ? beforeState : this.options.store.get(record.machineId).lifecycle.persistedState, classification: destroyed ? 'destroyed' : 'recoverable', action: destroyed ? 'verify-destroyed' : 'require-cleanup-recovery', changed: !dryRun && !destroyed, dryRun };
    }

    if (['REQUESTED', 'CLONING'].includes(record.lifecycle.persistedState)) {
      if (observed.observedState === 'CLONE_ONLY' && exactClone(record, observed)) {
        if (!dryRun) {
          if (record.lifecycle.persistedState === 'REQUESTED') record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'CLONING', 'CLONED', {
            operation: 'babyx.machine.reconcile', phase: 'create-adoption', kind: 'machine.cloning', message: 'exact existing clone adopted as interrupted create intent', requestDigest: digest, idempotencyKey: key, occurredAt: this.options.now(),
          }, { observations: observed.observations });
          record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'CLONED', 'CLONED', {
            operation: 'babyx.machine.reconcile', phase: 'create-readback', kind: 'machine.cloned', message: 'interrupted create converged from exact clone identity', requestDigest: digest, idempotencyKey: key, observationDigest: observed.observations.observationDigest, occurredAt: this.options.now(),
          }, { source: { ...record.source, snapshotGuid: observed.source.guid, creationTxg: observed.source.creationTxg, observedAt: observed.source.observedAt }, clone: { ...record.clone, datasetGuid: observed.clone.guid }, observations: observed.observations, lifecycle: { ...record.lifecycle, observedState: 'CLONE_ONLY' } });
        }
        return { machineId: record.machineId, beforeState, afterState: dryRun ? beforeState : 'CLONED', classification: 'recoverable', action: 'adopt-exact-clone', changed: !dryRun, dryRun };
      }
      if (observed.observedState === 'ABSENT') {
        if (dryRun) return { machineId: record.machineId, beforeState, afterState: beforeState, classification: 'recoverable', action: 'resume-clone', changed: false, dryRun };
        if (record.lifecycle.persistedState === 'REQUESTED') record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'CLONING', 'CLONED', {
          operation: 'babyx.machine.reconcile', phase: 'clone-intent', kind: 'machine.cloning', message: 'interrupted create clone intent restored before provider mutation', requestDigest: digest, idempotencyKey: key, occurredAt: this.options.now(),
        });
        await this.options.provider.create({ id: record.machineName, baseSnapshot: record.source.snapshot, dataset: record.clone.dataset, root: record.clone.mountpoint, ownershipProperties: ownershipProperties(record.machineId, record.creationRequestDigest, record.ownerPrincipal) });
        const readback = await this.options.observer.status(record);
        if (readback.observedState !== 'CLONE_ONLY' || !exactClone(record, readback) || readback.clone.guid === undefined) throw new MachineServiceError('machine_readback_mismatch', 'resumed clone did not produce exact identity');
        record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'CLONED', 'CLONED', {
          operation: 'babyx.machine.reconcile', phase: 'clone-readback', kind: 'machine.cloned', message: 'interrupted create resumed and exact clone readback verified', requestDigest: digest, idempotencyKey: key, observationDigest: readback.observations.observationDigest, occurredAt: this.options.now(),
        }, { clone: { ...record.clone, datasetGuid: readback.clone.guid }, observations: readback.observations, lifecycle: { ...record.lifecycle, observedState: 'CLONE_ONLY' } });
        return { machineId: record.machineId, beforeState, afterState: 'CLONED', classification: 'recoverable', action: 'resume-clone', changed: true, dryRun };
      }
    }

    if (record.lifecycle.persistedState === 'STARTING') {
      if (observed.observedState === 'RUNNING') {
        const identity = completeIdentity(record, observed, this.options.processIdentity, this.options.hostBootId);
        if (!dryRun) record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'READY', 'READY', {
          operation: 'babyx.machine.reconcile', phase: 'start-adoption', kind: 'machine.ready', message: 'interrupted start adopted from exact running identity', requestDigest: digest, idempotencyKey: key, observationDigest: observed.observations.observationDigest, occurredAt: this.options.now(),
        }, { processIdentity: identity, observations: observed.observations, lifecycle: { ...record.lifecycle, observedState: 'RUNNING' }, host: { ...record.host, lastObservedBootId: this.options.hostBootId } });
        return { machineId: record.machineId, beforeState, afterState: dryRun ? beforeState : 'READY', classification: 'recoverable', action: 'adopt-running-machine', changed: !dryRun, dryRun };
      }
      if (['CLONE_ONLY', 'STOPPED_INTACT'].includes(observed.observedState)) {
        if (!dryRun) record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'FAILED', 'READY', {
          operation: 'babyx.machine.reconcile', phase: 'start-readback', kind: 'machine.start-failed', message: 'interrupted start has no running machine', requestDigest: digest, idempotencyKey: key, observationDigest: observed.observations.observationDigest, occurredAt: this.options.now(),
        }, { observations: observed.observations, lastError: { code: 'machine_launch_failed', message: 'launch disappeared before readiness', phase: 'start-readback', retryable: true, destructiveRecoveryAllowed: false, artifactReferences: [], occurredAt: this.options.now() } });
        return { machineId: record.machineId, beforeState, afterState: dryRun ? beforeState : 'FAILED', classification: 'recoverable', action: 'mark-start-failed', changed: !dryRun, dryRun };
      }
    }

    if (record.lifecycle.persistedState === 'STOPPING') {
      if (observed.observedState === 'STOPPED_INTACT') {
        if (!dryRun) record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'STOPPED', 'STOPPED', {
          operation: 'babyx.machine.reconcile', phase: 'stop-adoption', kind: 'machine.stopped', message: 'interrupted stop converged from positive absence evidence', requestDigest: digest, idempotencyKey: key, observationDigest: observed.observations.observationDigest, occurredAt: this.options.now(),
        }, { processIdentity: undefined, observations: observed.observations, cleanup: { ...record.cleanup, stopVerified: true }, lifecycle: { ...record.lifecycle, observedState: 'STOPPED_INTACT', stoppedAt: this.options.now() } });
        return { machineId: record.machineId, beforeState, afterState: dryRun ? beforeState : 'STOPPED', classification: 'recoverable', action: 'adopt-stopped-machine', changed: !dryRun, dryRun };
      }
      if (observed.observedState === 'RUNNING') {
        if (dryRun) return { machineId: record.machineId, beforeState, afterState: beforeState, classification: 'recoverable', action: 'resume-stop', changed: false, dryRun };
        const result = await this.options.destruction.stop({ machineId: record.machineId, expectedSequence: record.lifecycle.stateSequence, gracefulTimeoutMs: this.options.config.stopGracefulTimeoutMs, forceAfterTimeout: false, reason: 'reconcile interrupted stop' }, { ...context, idempotencyKey: internalKey(context.idempotencyKey as string, 'stop', record.machineId) });
        const current = this.options.store.get(record.machineId);
        return { machineId: record.machineId, beforeState, afterState: current.lifecycle.persistedState, classification: 'recoverable', action: 'resume-stop', changed: true, dryRun };
      }
    }

    if (record.lifecycle.persistedState === 'EXPIRED' || record.lifecycle.persistedState === 'DESTROYING' || (record.lifecycle.persistedState === 'RECOVERY_REQUIRED' && record.lifecycle.desiredState === 'DESTROYED')) {
      if (dryRun) return { machineId: record.machineId, beforeState, afterState: beforeState, classification: 'recoverable', action: 'resume-destroy', changed: false, dryRun };
      await this.options.destruction.destroy({ machineId: record.machineId, expectedSequence: record.lifecycle.stateSequence, stopIfRunning: true, forceStop: false, stopTimeoutMs: this.options.config.stopGracefulTimeoutMs, reason: 'reconcile desired destruction' }, { ...context, idempotencyKey: internalKey(context.idempotencyKey as string, 'destroy', record.machineId) });
      const current = this.options.store.get(record.machineId);
      return { machineId: record.machineId, beforeState, afterState: current.lifecycle.persistedState, classification: current.lifecycle.persistedState === 'DESTROYED' ? 'destroyed' : 'recoverable', action: 'resume-destroy', changed: true, dryRun };
    }

    if (record.lifecycle.persistedState === 'EXECUTING' && record.activeJobIds.length === 0 && observed.observedState === 'RUNNING') {
      if (!dryRun) record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'READY', 'READY', {
        operation: 'babyx.machine.reconcile', phase: 'job-adoption', kind: 'machine.ready', message: 'machine had no active durable jobs and returned to READY', requestDigest: digest, idempotencyKey: key, observationDigest: observed.observations.observationDigest, occurredAt: this.options.now(),
      }, { observations: observed.observations, lifecycle: { ...record.lifecycle, observedState: 'RUNNING' } });
      return { machineId: record.machineId, beforeState, afterState: dryRun ? beforeState : 'READY', classification: 'recoverable', action: 'clear-empty-executing-state', changed: !dryRun, dryRun };
    }

    if (['READY', 'EXECUTING'].includes(record.lifecycle.persistedState) && observed.observedState !== 'RUNNING') {
      if (!dryRun) record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'DEGRADED', record.lifecycle.desiredState, {
        operation: 'babyx.machine.reconcile', phase: 'runtime-readback', kind: 'machine.degraded', message: 'persisted running state is not observed running', requestDigest: digest, idempotencyKey: key, observationDigest: observed.observations.observationDigest, occurredAt: this.options.now(),
      }, { observations: observed.observations, lifecycle: { ...record.lifecycle, observedState: observed.observedState } });
      return { machineId: record.machineId, beforeState, afterState: dryRun ? beforeState : 'DEGRADED', classification: 'recoverable', action: 'mark-degraded', changed: !dryRun, dryRun };
    }

    if (!dryRun) record = this.options.store.update(record.machineId, record.lifecycle.stateSequence, {
      operation: 'babyx.machine.reconcile', phase: 'consistent-readback', kind: 'machine.reconciled', message: 'persisted and observed machine state classified as consistent', requestDigest: digest, idempotencyKey: key, observationDigest: observed.observations.observationDigest, occurredAt: this.options.now(),
    }, { observations: observed.observations, lifecycle: { ...record.lifecycle, observedState: observed.observedState }, host: { ...record.host, lastObservedBootId: this.options.hostBootId } });
    return { machineId: record.machineId, beforeState, afterState: record.lifecycle.persistedState, classification: 'consistent', action: 'refresh-observation', changed: !dryRun, dryRun };
  }

  expire(payload: JsonObject, context: MachineOperationContext): JsonObject {
    assertAllowedKeys(payload, ['machineId', 'expectedSequence', 'reason']);
    const authenticated = requiredContext(context);
    const machineId = assertMachineId(payload.machineId);
    const expectedSequence = optionalPositiveInteger(payload.expectedSequence, 'expectedSequence', 0, Number.MAX_SAFE_INTEGER);
    optionalText(payload.reason, 'reason');
    let record = this.options.store.get(machineId);
    authorize(record, context);
    const digest = requestDigest('babyx.machine.expire', payload);
    const replay = latestReplay(this.options.store.events(machineId, 0, 1_000), 'babyx.machine.expire', authenticated.idempotencyKey, digest);
    if (record.lifecycle.persistedState === 'EXPIRED' || record.lifecycle.persistedState === 'DESTROYED') return { operation: 'babyx.machine.expire', machine: publicRecord(record), noOp: true, replayed: replay !== undefined };
    assertExpectedMachineSequence(record.lifecycle.stateSequence, expectedSequence);
    if (record.lifecycle.expiresAt === undefined || Date.parse(record.lifecycle.expiresAt) > Date.parse(this.options.now())) throw new MachineServiceError('machine_state_conflict', 'machine retention deadline has not expired');
    if (record.protectedJobIds.length > 0) throw new MachineServiceError('machine_protected_job_active', 'protected jobs block expiration', { protectedJobIds: record.protectedJobIds });
    record = this.options.store.transition(record.machineId, record.lifecycle.stateSequence, 'EXPIRED', 'DESTROYED', {
      operation: 'babyx.machine.expire', phase: 'retention', kind: 'machine.expired', message: 'retention deadline converted to desired DESTROYED state', requestDigest: digest, idempotencyKey: authenticated.idempotencyKey, occurredAt: this.options.now(),
    }, { lifecycle: { ...record.lifecycle, desiredState: 'DESTROYED' } });
    return { operation: 'babyx.machine.expire', machine: publicRecord(record), noOp: false, replayed: false };
  }

  async gc(payload: JsonObject, context: MachineOperationContext): Promise<JsonObject> {
    assertAllowedKeys(payload, ['dryRun', 'limit', 'olderThan', 'states', 'reason']);
    const authenticated = requiredContext(context);
    const dryRun = optionalBoolean(payload.dryRun, 'dryRun', true);
    const limit = optionalPositiveInteger(payload.limit, 'limit', this.options.config.garbageCollectionLimit);
    const olderThan = optionalTimestamp(payload.olderThan, 'olderThan');
    optionalText(payload.reason, 'reason');
    let states: Set<string> | undefined;
    if (payload.states !== undefined) {
      if (!Array.isArray(payload.states) || payload.states.length === 0 || payload.states.some((value) => !isMachineState(value))) throw new MachineServiceError('machine_invalid_request', 'states must be a non-empty array of supported machine states');
      states = new Set(payload.states as string[]);
    }
    const candidates: JsonObject[] = [];
    const exclusions: JsonObject[] = [];
    const actions: JsonObject[] = [];
    const scan = this.options.store.scan(1_000);
    const records = scan.records.filter((record) => context.authorityClass === 'unrestricted-owner' || record.ownerPrincipal === authenticated.subject);
    for (const record of records) {
      if (candidates.length >= limit) break;
      const reasons: string[] = [];
      if (record.lifecycle.desiredState !== 'DESTROYED' && record.lifecycle.persistedState !== 'EXPIRED') reasons.push('retention-does-not-request-destruction');
      if (states !== undefined && !states.has(record.lifecycle.persistedState)) reasons.push('state-filter');
      if (olderThan !== undefined && Date.parse(record.lifecycle.updatedAt) >= olderThan) reasons.push('age-filter');
      if (record.activeJobIds.length > 0) reasons.push('active-jobs');
      if (record.protectedJobIds.length > 0) reasons.push('protected-jobs');
      const lease = this.options.store.getLease(record.machineId);
      if (leaseStatus(lease, Date.parse(this.options.now()), this.options.hostBootId) === 'live') reasons.push('live-controller-lease');
      let observation: MachineStatusObservation | undefined;
      try { observation = await this.options.observer.status(record); }
      catch (error) {
        exclusions.push({ machineId: record.machineId, state: record.lifecycle.persistedState, reasons: ['observation-failed'], error: { code: error instanceof MachineServiceError ? error.code : 'machine_gc_failed', message: error instanceof Error ? error.message : 'observation failed' } });
        continue;
      }
      if (observation.observedState === 'UNKNOWN') reasons.push('unknown-observation');
      if (observation.observedState === 'CONFLICT') reasons.push('ambiguous-identity');
      if (observation.source.status !== 'present' || (record.source.snapshotGuid !== undefined && observation.source.guid !== record.source.snapshotGuid)) reasons.push('source-unverified');
      if (reasons.length > 0) {
        exclusions.push({ machineId: record.machineId, state: record.lifecycle.persistedState, reasons });
        continue;
      }
      candidates.push({ machineId: record.machineId, state: record.lifecycle.persistedState, observedState: observation.observedState, ownershipEvidence: { dataset: observation.clone.status, source: observation.source.status } });
      if (!dryRun) {
        try {
          const preflight = await this.reconcileOne(record, true, { ...context, idempotencyKey: internalKey(authenticated.idempotencyKey, 'gc-reconcile', record.machineId) }, { machineId: record.machineId, dryRun: true, reason: 'garbage collection preflight' });
          if (['ambiguous', 'lost', 'unknown', 'deferred'].includes(preflight.classification)) throw new MachineServiceError('machine_state_conflict', 'garbage-collection reconciliation did not authorize teardown', { classification: preflight.classification });
          const current = this.options.store.get(record.machineId);
          const result = await this.options.destruction.destroy({ machineId: current.machineId, expectedSequence: current.lifecycle.stateSequence, stopIfRunning: true, forceStop: false, stopTimeoutMs: this.options.config.stopGracefulTimeoutMs, reason: 'garbage collection candidate' }, { ...context, idempotencyKey: internalKey(authenticated.idempotencyKey, 'gc-destroy', current.machineId) });
          actions.push({ machineId: current.machineId, status: 'completed', reconciliation: preflight, result });
        } catch (error) {
          actions.push({ machineId: record.machineId, status: 'failed', error: { code: error instanceof MachineServiceError ? error.code : 'machine_gc_failed', message: error instanceof Error ? error.message : 'garbage collection failed' } });
        }
      }
    }
    const mayInspectGlobalOrphans = context.authorityClass === 'unrestricted-owner';
    const orphans = mayInspectGlobalOrphans ? await this.scanOrphanDatasets(limit, records) : [];
    const orphanProcesses = mayInspectGlobalOrphans ? await this.scanOrphanProcesses(limit, records) : [];
    return {
      operation: 'babyx.machine.gc', dryRun, limit, candidates, exclusions,
      recordErrors: context.authorityClass === 'unrestricted-owner' ? scan.errors : [],
      orphans, orphanProcesses, actions,
    };
  }

  async diagnostics(payload: JsonObject, context: MachineOperationContext): Promise<JsonObject> {
    assertAllowedKeys(payload, ['machineId', 'expectedSequence', 'maxEvents', 'maxJobReferences', 'reason']);
    const authenticated = requiredContext(context);
    const machineId = assertMachineId(payload.machineId);
    const expectedSequence = requiredSequence(payload.expectedSequence);
    const maxEvents = optionalPositiveInteger(payload.maxEvents, 'maxEvents', Math.min(100, this.options.config.maximumEventLimit), this.options.config.maximumEventLimit);
    const maxJobReferences = optionalPositiveInteger(payload.maxJobReferences, 'maxJobReferences', 100, 200);
    optionalText(payload.reason, 'reason');
    let record = this.options.store.get(machineId);
    authorize(record, context);
    const digest = requestDigest('babyx.machine.diagnostics', payload);
    const replay = latestReplay(this.options.store.events(machineId, 0, 1_000), 'babyx.machine.diagnostics', authenticated.idempotencyKey, digest);
    if (replay !== undefined) return { operation: 'babyx.machine.diagnostics', machineId, replayed: true, artifactReference: replay.artifactId ?? null, evidenceDigest: replay.proofReference ?? null };
    assertExpectedMachineSequence(record.lifecycle.stateSequence, expectedSequence);
    const leaseId = this.acquireLease(record, 'babyx.machine.diagnostics', authenticated.subject, digest);
    try {
      const observation = await this.options.observer.status(record);
      const eventCount = this.options.store.events(machineId, 0, 1_000).length;
      const events = this.options.store.events(machineId, Math.max(0, eventCount - maxEvents), maxEvents);
      const lease = this.options.store.getLease(machineId);
      const eventTail = events.at(-1);
      const evidence = {
        schemaVersion: '1.0.0', operation: 'babyx.machine.diagnostics', capturedAt: this.options.now(),
        machine: { machineId, machineName: record.machineName, stateSequence: record.lifecycle.stateSequence, persistedState: record.lifecycle.persistedState, desiredState: record.lifecycle.desiredState, recordDigest: sha256(canonicalMachineEvidence(record)) },
        eventChain: { included: events.length, tailDigest: eventTail?.eventDigest ?? null, events: events.map((event) => ({ offset: event.offset, stateSequence: event.stateSequence, priorState: event.priorState, nextState: event.nextState, operation: event.operation, phase: event.phase, kind: event.kind, occurredAt: event.occurredAt, eventDigest: event.eventDigest, previousEventDigest: event.previousEventDigest })) },
        observations: { state: observation.observedState, set: observation.observations, discrepancies: observation.discrepancies.slice(0, 50), source: { status: observation.source.status, snapshot: observation.source.snapshot, guid: observation.source.guid, creationTxg: observation.source.creationTxg, observedAt: observation.source.observedAt, exitCode: observation.source.command.exitCode, stderrSha256: observation.source.command.stderrSha256 }, clone: { status: observation.clone.status, dataset: observation.clone.dataset, guid: observation.clone.guid, origin: observation.clone.origin, mountpoint: observation.clone.mountpoint, properties: observation.clone.properties, observedAt: observation.clone.observedAt, exitCode: observation.clone.command.exitCode, stderrSha256: observation.clone.command.stderrSha256 }, machine: { status: observation.machine.status, properties: observation.machine.properties, observedAt: observation.machine.observedAt, exitCode: observation.machine.command.exitCode, stderrSha256: observation.machine.command.stderrSha256 } },
        processIdentity: record.processIdentity ?? null,
        controllerLease: lease === undefined ? null : { leaseId: lease.leaseId, operation: lease.operation, ownerPrincipal: lease.ownerPrincipal, acquiredAt: lease.acquiredAt, expiresAt: lease.expiresAt, hostBootId: lease.hostBootId },
        classification: record.recovery ?? { classification: observation.observedState, recommendedAction: observation.observedState === 'UNKNOWN' ? 'defer until provider observation is available' : 'review persisted and observed truth', automaticActionAllowed: false, observedAt: observation.observations.observedAt ?? this.options.now(), evidenceReferences: [] },
        jobs: { active: record.activeJobIds.slice(0, maxJobReferences), protected: record.protectedJobIds.slice(0, maxJobReferences) },
        evidenceReferences: { artifacts: record.artifactIds.slice(0, maxJobReferences), proofs: record.proofReferences.slice(0, maxJobReferences), cleanup: record.cleanup.retainedEvidence.slice(0, maxJobReferences) },
      };
      const canonical = `${canonicalMachineEvidence(evidence)}\n`;
      if (Buffer.byteLength(canonical) > 1_048_576) throw new MachineServiceError('machine_invalid_request', 'diagnostic evidence exceeds the one-megabyte bound');
      const evidenceDigest = sha256(canonical);
      let artifactReference: string | undefined;
      if (this.options.artifacts !== undefined) {
        const evidencePath = join(this.options.evidenceRoot, `${machineId}-${record.lifecycle.stateSequence}-${evidenceDigest.slice(0, 16)}.json`);
        if (!existsSync(evidencePath)) writeFileSync(evidencePath, canonical, { mode: 0o600, flag: 'wx' });
        else if (sha256(readFileSync(evidencePath)) !== evidenceDigest) throw new MachineServiceError('machine_record_corrupt', 'existing diagnostic evidence path has conflicting content');
        try {
          const artifact = this.options.artifacts.create(`machine-${machineId}-diagnostics`, evidencePath, { machineId, stateSequence: record.lifecycle.stateSequence, evidenceDigest });
          if (typeof artifact.id === 'string') artifactReference = artifact.id;
        } finally {
          rmSync(evidencePath, { force: true });
        }
      }
      record = this.options.store.update(machineId, record.lifecycle.stateSequence, {
        operation: 'babyx.machine.diagnostics', phase: 'evidence', kind: 'machine.diagnostics-captured', message: 'bounded redacted diagnostic evidence captured through the artifact authority',
        requestDigest: digest, idempotencyKey: authenticated.idempotencyKey, controllerLeaseId: leaseId,
        ...(artifactReference === undefined ? {} : { artifactId: artifactReference }), proofReference: evidenceDigest, observationDigest: observation.observations.observationDigest, occurredAt: this.options.now(),
      }, { artifactIds: artifactReference === undefined ? record.artifactIds : [...new Set([...record.artifactIds, artifactReference])].sort() });
      return { operation: 'babyx.machine.diagnostics', machineId, stateSequence: record.lifecycle.stateSequence, replayed: false, evidenceDigest, artifactReference: artifactReference ?? null, ...(artifactReference === undefined ? { inline: JSON.parse(canonical) as JsonObject } : {}) };
    } finally {
      this.options.store.releaseLease(machineId, leaseId);
    }
  }

  private acquireLease(record: DisposableMachineRecordV1, operation: string, principal: string, digest: string): string {
    const leaseId = this.options.store.newLeaseId();
    const acquiredAt = this.options.now();
    this.options.store.acquireLease({ schemaVersion: '1.0.0', leaseId, machineId: record.machineId, operation, ownerPrincipal: principal, requestDigest: digest, acquiredAt, expiresAt: new Date(Date.parse(acquiredAt) + this.options.config.leaseDurationMs).toISOString(), hostBootId: this.options.hostBootId }, { currentBootId: this.options.hostBootId, existingOwnerAlive: false, now: acquiredAt });
    return leaseId;
  }

  private async scanOrphanDatasets(limit: number, records: DisposableMachineRecordV1[]): Promise<JsonObject[]> {
    const known = new Set(records.map((record) => record.clone.dataset));
    const orphans: JsonObject[] = [];
    for (const root of this.options.config.cloneDatasetRoots) {
      if (orphans.length >= limit) break;
      const listed = await this.options.provider.listDescendants(root);
      if (listed.exitCode !== 0) {
        orphans.push({ datasetRoot: root, classification: 'unknown', action: 'exclude', reason: 'provider-list-failed', exitCode: listed.exitCode, stderrSha256: listed.stderrSha256 });
        continue;
      }
      const datasets = decode(listed).split('\n').map((value) => value.trim()).filter(Boolean);
      for (const dataset of datasets) {
        if (dataset === root || known.has(dataset) || orphans.length >= limit) continue;
        const observation = await this.options.observer.clone(dataset);
        const providerMarker = observation.status === 'present' && observation.properties['com.stealtheye.babyx:provider'] === MACHINE_PROVIDER_ID;
        orphans.push({ dataset, classification: observation.status === 'unknown' ? 'unknown' : providerMarker ? 'service-marker-unbound' : 'foreign', action: 'exclude', reason: observation.status === 'unknown' ? 'provider-observation-unavailable' : providerMarker ? 'no-durable-record' : 'ownership-not-proven' });
      }
    }
    return orphans;
  }

  private async scanOrphanProcesses(limit: number, records: DisposableMachineRecordV1[]): Promise<JsonObject[]> {
    const known = new Set(records.map((record) => record.machineName));
    const listed = await this.options.observer.listMachines(limit);
    if (listed.status === 'unknown') return [{ classification: 'unknown', action: 'exclude', reason: 'machinectl-list-unavailable', exitCode: listed.command.exitCode, stderrSha256: listed.command.stderrSha256 }];
    return listed.machineNames.filter((name) => !known.has(name)).slice(0, limit).map((machineName) => ({ machineName, classification: 'unbound-machine-name', action: 'exclude', reason: 'durable-ownership-not-proven' }));
  }

}
