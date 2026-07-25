import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime } from '../../dist/runtime/core.js';
import { MachineRecoveryController } from '../../dist/runtime/machines/recovery.js';
import { normalizeMachineServiceConfig, ownershipProperties } from '../../dist/runtime/machines/identity.js';
import { DisposableMachineStore } from '../../dist/runtime/machines/store.js';
import { MachineServiceError } from '../../dist/runtime/machines/errors.js';
import { makeRecord, creationEvent } from './_disposable-machine-store-fixture.mjs';

function commandResult(argv, exitCode = 0, stdout = '', stderr = '') {
  return {
    argv, target: { kind: 'host' }, cwd: '/', startedAt: '2026-07-25T16:00:00.000Z', completedAt: '2026-07-25T16:00:00.001Z',
    durationMs: 1, exitCode, signal: null,
    stdout: Buffer.from(stdout).toString('base64'), stderr: Buffer.from(stderr).toString('base64'),
    stdoutSha256: 'a'.repeat(64), stderrSha256: 'b'.repeat(64),
  };
}

function observations(overrides = {}) {
  return {
    dataset: 'present-matching', snapshot: 'present-matching', mountpoint: 'present-matching',
    machinectl: 'absent', process: 'absent', rootPath: 'present-matching',
    observedAt: '2026-07-25T16:00:00.000Z', observationDigest: 'd'.repeat(64),
    ...overrides,
  };
}

function statusFor(record, state, overrides = {}) {
  const running = state === 'RUNNING';
  const absent = state === 'ABSENT';
  const cloneAbsent = absent || overrides.cloneAbsent === true;
  const cloneProperties = ownershipProperties(record.machineId, record.creationRequestDigest, record.ownerPrincipal);
  const source = overrides.source ?? {
    status: 'present', snapshot: record.source.snapshot, dataset: record.source.dataset,
    guid: record.source.snapshotGuid ?? '111222333', creationTxg: record.source.creationTxg ?? '444555',
    observedAt: '2026-07-25T16:00:00.000Z', command: commandResult(['/usr/sbin/zfs', 'get']),
  };
  const clone = cloneAbsent ? {
    status: 'absent', dataset: record.clone.dataset, properties: {}, observedAt: '2026-07-25T16:00:00.000Z', command: commandResult(['/usr/sbin/zfs', 'get'], 1, '', 'dataset does not exist'),
  } : {
    status: 'present', dataset: record.clone.dataset, guid: record.clone.datasetGuid ?? '777888999',
    origin: record.source.snapshot, mountpoint: record.clone.mountpoint, properties: cloneProperties,
    observedAt: '2026-07-25T16:00:00.000Z', command: commandResult(['/usr/sbin/zfs', 'get']),
  };
  const machine = running ? {
    status: 'running', properties: { Name: record.machineName, State: 'running', RootDirectory: record.clone.mountpoint, Leader: '4242' },
    observedAt: '2026-07-25T16:00:00.000Z', command: commandResult(['/usr/bin/machinectl']),
  } : {
    status: 'absent', properties: {}, observedAt: '2026-07-25T16:00:00.000Z', command: commandResult(['/usr/bin/machinectl'], 1, '', 'no such machine'),
  };
  const observationSet = state === 'RUNNING'
    ? observations({ machinectl: 'running-matching', process: 'running-matching' })
    : state === 'ABSENT'
      ? observations({ dataset: 'absent', mountpoint: 'absent', rootPath: 'absent' })
      : observations();
  return {
    observations: observationSet,
    observedState: state,
    discrepancies: overrides.discrepancies ?? [],
    source, clone, machine,
  };
}

class FakeObserver {
  states = new Map();
  cloneObservations = new Map();
  statusCalls = [];
  machineNames = [];
  machineListUnknown = false;
  machineListCalls = 0;

  set(machineId, value) { this.states.set(machineId, value); }
  async status(record) {
    this.statusCalls.push(record.machineId);
    const value = this.states.get(record.machineId);
    if (typeof value === 'function') return value(record);
    return value ?? statusFor(record, 'CLONE_ONLY');
  }
  async listMachines(limit = 1_000) {
    this.machineListCalls += 1;
    if (this.machineListUnknown) return { status: 'unknown', machineNames: [], observedAt: '2026-07-25T16:00:00.000Z', command: commandResult(['/usr/bin/machinectl', '--no-pager', '--no-legend', 'list'], 1, '', 'machinectl unavailable') };
    return { status: 'available', machineNames: this.machineNames.slice(0, limit), observedAt: '2026-07-25T16:00:00.000Z', command: commandResult(['/usr/bin/machinectl', '--no-pager', '--no-legend', 'list']) };
  }
  async clone(dataset) {
    return this.cloneObservations.get(dataset) ?? {
      status: 'present', dataset, guid: '999', origin: 'pool/foreign@snap', mountpoint: `/foreign/${dataset.replaceAll('/', '-')}`,
      properties: {}, observedAt: '2026-07-25T16:00:00.000Z', command: commandResult(['/usr/sbin/zfs', 'get']),
    };
  }
}

class FakeProvider {
  createCalls = [];
  listCalls = [];
  descendants = new Map();
  constructor(observer) { this.observer = observer; }
  async create(request) {
    this.createCalls.push(structuredClone(request));
    return { id: request.id, dataset: request.dataset, root: request.root, baseSnapshot: request.baseSnapshot, state: 'created' };
  }
  async listDescendants(root) {
    this.listCalls.push(root);
    const values = this.descendants.get(root) ?? [root];
    return commandResult(['/usr/sbin/zfs', 'list', root], 0, `${values.join('\n')}\n`);
  }
}

class FakeDestruction {
  stopCalls = [];
  destroyCalls = [];
  constructor(store, observer) { this.store = store; this.observer = observer; }
  async stop(payload, context) {
    this.stopCalls.push({ payload: structuredClone(payload), context: structuredClone(context) });
    let record = this.store.get(payload.machineId);
    if (record.lifecycle.persistedState !== 'STOPPING') {
      record = this.store.transition(record.machineId, record.lifecycle.stateSequence, 'STOPPING', 'STOPPED', {
        operation: 'babyx.machine.stop', phase: 'stop-intent', kind: 'machine.stopping', message: 'fake normal stop', occurredAt: '2026-07-25T16:00:01.000Z',
      });
    }
    record = this.store.transition(record.machineId, record.lifecycle.stateSequence, 'STOPPED', 'STOPPED', {
      operation: 'babyx.machine.stop', phase: 'stop-readback', kind: 'machine.stopped', message: 'fake normal stop complete', occurredAt: '2026-07-25T16:00:02.000Z',
    }, { processIdentity: undefined, lifecycle: { ...record.lifecycle, observedState: 'STOPPED_INTACT' } });
    this.observer.set(record.machineId, statusFor(record, 'STOPPED_INTACT'));
    return { operation: 'babyx.machine.stop', machineId: record.machineId };
  }
  async destroy(payload, context) {
    this.destroyCalls.push({ payload: structuredClone(payload), context: structuredClone(context) });
    let record = this.store.get(payload.machineId);
    if (record.lifecycle.persistedState !== 'DESTROYING') {
      record = this.store.transition(record.machineId, record.lifecycle.stateSequence, 'DESTROYING', 'DESTROYED', {
        operation: 'babyx.machine.destroy', phase: 'destroy-intent', kind: 'machine.destroying', message: 'fake normal destroy', occurredAt: '2026-07-25T16:00:03.000Z',
      });
    }
    record = this.store.transition(record.machineId, record.lifecycle.stateSequence, 'DESTROYED', 'DESTROYED', {
      operation: 'babyx.machine.destroy', phase: 'destroy-readback', kind: 'machine.destroyed', message: 'fake normal destroy complete', occurredAt: '2026-07-25T16:00:04.000Z',
    }, { lifecycle: { ...record.lifecycle, desiredState: 'DESTROYED', observedState: 'ABSENT' }, cleanup: { ...record.cleanup, completed: true, datasetAbsentVerified: true, rootAbsentVerified: true, machineAbsentVerified: true, processAbsentVerified: true } });
    this.observer.set(record.machineId, statusFor(record, 'ABSENT'));
    return { operation: 'babyx.machine.destroy', machineId: record.machineId };
  }
}

function seededRecord(root, state, overrides = {}) {
  const machineName = overrides.machineName ?? 'machine-1';
  const machineId = overrides.machineId ?? 'mx_machine0001';
  const machineRoot = join(root, 'machines');
  const record = makeRecord({ machineId, machineName, cloneDataset: `pool/runs/${machineName}`, mountpoint: join(machineRoot, machineName), idempotencyKey: `create-${machineId}` });
  return {
    ...record,
    clone: { ...record.clone, expectedRootPrefix: machineRoot, datasetGuid: overrides.datasetGuid ?? '777888999' },
    lifecycle: {
      ...record.lifecycle,
      desiredState: overrides.desiredState ?? (state === 'EXPIRED' || state === 'DESTROYING' || state === 'RECOVERY_REQUIRED' ? 'DESTROYED' : state === 'REQUESTED' || state === 'CLONING' ? 'CLONED' : 'READY'),
      persistedState: state,
      observedState: overrides.observedState ?? 'NOT_OBSERVED',
      stateSequence: overrides.stateSequence ?? 1,
      expiresAt: overrides.expiresAt,
      terminal: state === 'DESTROYED' || state === 'LOST',
      updatedAt: overrides.updatedAt ?? record.lifecycle.updatedAt,
    },
    processIdentity: overrides.processIdentity,
    activeJobIds: overrides.activeJobIds ?? [],
    protectedJobIds: overrides.protectedJobIds ?? [],
  };
}

class FakeArtifacts {
  created = [];
  create(name, sourcePath, metadata) {
    const content = readFileSync(sourcePath, 'utf8');
    const artifact = { id: `artifact-${this.created.length + 1}`, name, sourcePath, metadata, content };
    this.created.push(artifact);
    return artifact;
  }
}

function fixture(t, configOverrides = {}, controllerOverrides = {}) {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-recovery-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const store = new DisposableMachineStore(join(root, 'machine-service'));
  const observer = new FakeObserver();
  const provider = new FakeProvider(observer);
  const destruction = new FakeDestruction(store, observer);
  const config = normalizeMachineServiceConfig({
    sourceSnapshotRoots: ['pool/base'], cloneDatasetRoots: ['pool/runs'], machineRoot: join(root, 'machines'),
    startupReconcileLimit: 2, garbageCollectionLimit: 3, ...configOverrides,
  });
  let tick = 0;
  const controller = new MachineRecoveryController({
    store, observer, provider, destruction, config,
    now: controllerOverrides.now ?? (() => `2026-07-25T16:00:${String(tick++).padStart(2, '0')}.000Z`),
    processIdentity: controllerOverrides.processIdentity ?? ((pid) => ({ pid, pgid: pid, processStartTime: '100', executablePath: '/usr/lib/systemd/systemd', bootId: 'boot-2' })),
    hostBootId: controllerOverrides.hostBootId ?? 'boot-2',
    evidenceRoot: join(root, 'evidence'),
    artifacts: controllerOverrides.artifacts,
    monotonicNow: controllerOverrides.monotonicNow,
  });
  return { root, store, observer, provider, destruction, controller, config };
}

function addRecord(f, record) {
  const target = record.lifecycle.persistedState;
  const initial = JSON.parse(JSON.stringify({
    ...record,
    processIdentity: undefined,
    activeJobIds: [],
    protectedJobIds: [],
    lifecycle: {
      ...record.lifecycle,
      persistedState: 'REQUESTED',
      observedState: 'NOT_OBSERVED',
      stateSequence: 1,
      terminal: false,
    },
  }));
  f.store.create(initial, creationEvent(initial));
  const paths = {
    REQUESTED: [],
    CLONING: ['CLONING'],
    CLONED: ['CLONING', 'CLONED'],
    STARTING: ['CLONING', 'CLONED', 'STARTING'],
    READY: ['CLONING', 'CLONED', 'STARTING', 'READY'],
    EXECUTING: ['CLONING', 'CLONED', 'STARTING', 'READY', 'EXECUTING'],
    STOPPING: ['CLONING', 'CLONED', 'STARTING', 'READY', 'STOPPING'],
    STOPPED: ['CLONING', 'CLONED', 'STARTING', 'READY', 'STOPPING', 'STOPPED'],
    EXPIRED: ['CLONING', 'CLONED', 'EXPIRED'],
    DESTROYING: ['CLONING', 'CLONED', 'DESTROYING'],
    DESTROYED: ['CLONING', 'CLONED', 'DESTROYING', 'DESTROYED'],
    RECOVERY_REQUIRED: ['RECOVERY_REQUIRED'],
    DEGRADED: ['DEGRADED'],
    FAILED: ['FAILED'],
    LOST: ['LOST'],
    AMBIGUOUS: ['AMBIGUOUS'],
    UNKNOWN: ['UNKNOWN'],
  };
  const path = paths[target];
  if (path === undefined) throw new Error(`unsupported seeded state: ${target}`);
  let current = f.store.get(record.machineId);
  for (const [index, state] of path.entries()) {
    const final = index === path.length - 1;
    current = f.store.transition(current.machineId, current.lifecycle.stateSequence, state, record.lifecycle.desiredState, {
      operation: 'test.seed', phase: 'seed', kind: `test.seed.${state.toLowerCase()}`, message: `seed ${state}`,
      occurredAt: `2026-07-25T15:59:${String(index).padStart(2, '0')}.000Z`,
    }, final ? {
      processIdentity: record.processIdentity,
      activeJobIds: record.activeJobIds,
      protectedJobIds: record.protectedJobIds,
      cleanup: record.cleanup,
      observations: record.observations,
      lifecycle: { ...record.lifecycle, desiredState: record.lifecycle.desiredState, observedState: record.lifecycle.observedState },
    } : {});
  }
  return f.store.get(record.machineId);
}

const ownerContext = { idempotencyKey: 'reconcile-request-1', subject: 'owner:test', authorityClass: 'unrestricted-owner' };
const machineError = (code) => (error) => error instanceof MachineServiceError && error.code === code;

test('interrupted create converges by adopting an exact clone or safely resuming a missing clone', async (t) => {
  const adopted = fixture(t);
  const cloning = addRecord(adopted, seededRecord(adopted.root, 'CLONING'));
  adopted.observer.set(cloning.machineId, statusFor(cloning, 'CLONE_ONLY'));
  const result = await adopted.controller.reconcile({ machineId: cloning.machineId }, ownerContext);
  assert.equal(result.results[0].action, 'adopt-exact-clone');
  assert.equal(adopted.store.get(cloning.machineId).lifecycle.persistedState, 'CLONED');
  assert.equal(adopted.provider.createCalls.length, 0);

  const resumed = fixture(t);
  const requested = addRecord(resumed, seededRecord(resumed.root, 'REQUESTED'));
  resumed.observer.set(requested.machineId, (record) => statusFor(record, resumed.provider.createCalls.length === 0 ? 'ABSENT' : 'CLONE_ONLY'));
  const resumedResult = await resumed.controller.reconcile({ machineId: requested.machineId }, { ...ownerContext, idempotencyKey: 'reconcile-resume-create' });
  assert.equal(resumedResult.results[0].action, 'resume-clone');
  assert.equal(resumed.provider.createCalls.length, 1);
  assert.equal(resumed.store.get(requested.machineId).lifecycle.persistedState, 'CLONED');
});

test('controller restart during start adopts exact process identity and duplicate reconcile is idempotent', async (t) => {
  const f = fixture(t);
  const starting = addRecord(f, seededRecord(f.root, 'STARTING'));
  f.observer.set(starting.machineId, statusFor(starting, 'RUNNING'));
  const first = await f.controller.reconcile({ machineId: starting.machineId, reason: 'restart' }, ownerContext);
  assert.equal(first.results[0].action, 'adopt-running-machine');
  const ready = f.store.get(starting.machineId);
  assert.equal(ready.lifecycle.persistedState, 'READY');
  assert.equal(ready.processIdentity.pid, 4242);
  const eventCount = f.store.events(starting.machineId, 0, 100).length;
  const replay = await f.controller.reconcile({ machineId: starting.machineId, reason: 'restart' }, ownerContext);
  assert.equal(replay.results[0].action, 'idempotent-replay');
  assert.equal(f.store.events(starting.machineId, 0, 100).length, eventCount);
});

test('interrupted stop and partial destroy resume through the normal teardown authority', async (t) => {
  const stoppedFixture = fixture(t);
  const stopping = addRecord(stoppedFixture, seededRecord(stoppedFixture.root, 'STOPPING', { processIdentity: { pid: 4242, pgid: 4242, processStartTime: '100', executablePath: '/usr/lib/systemd/systemd', bootId: 'boot-2' } }));
  stoppedFixture.observer.set(stopping.machineId, statusFor(stopping, 'STOPPED_INTACT'));
  const stopped = await stoppedFixture.controller.reconcile({ machineId: stopping.machineId }, ownerContext);
  assert.equal(stopped.results[0].action, 'adopt-stopped-machine');
  assert.equal(stoppedFixture.store.get(stopping.machineId).lifecycle.persistedState, 'STOPPED');

  const destroyFixture = fixture(t);
  const recovery = addRecord(destroyFixture, seededRecord(destroyFixture.root, 'RECOVERY_REQUIRED', { desiredState: 'DESTROYED' }));
  destroyFixture.observer.set(recovery.machineId, statusFor(recovery, 'CLONE_ONLY'));
  const destroyed = await destroyFixture.controller.reconcile({ machineId: recovery.machineId }, { ...ownerContext, idempotencyKey: 'reconcile-partial-destroy' });
  assert.equal(destroyed.results[0].action, 'resume-destroy');
  assert.equal(destroyFixture.destruction.destroyCalls.length, 1);
  assert.equal(destroyFixture.store.get(recovery.machineId).lifecycle.persistedState, 'DESTROYED');
});

test('stale leases are released, live leases defer, and startup scan is bounded', async (t) => {
  const f = fixture(t, { startupReconcileLimit: 2 });
  const first = addRecord(f, seededRecord(f.root, 'CLONED', { machineId: 'mx_machine0001', machineName: 'machine-1' }));
  const second = addRecord(f, seededRecord(f.root, 'CLONED', { machineId: 'mx_machine0002', machineName: 'machine-2' }));
  const third = addRecord(f, seededRecord(f.root, 'CLONED', { machineId: 'mx_machine0003', machineName: 'machine-3' }));
  for (const record of [first, second, third]) f.observer.set(record.machineId, statusFor(record, 'CLONE_ONLY'));
  f.store.acquireLease({ schemaVersion: '1.0.0', leaseId: 'lease-stale', machineId: first.machineId, operation: 'test', ownerPrincipal: 'owner:test', requestDigest: 'c'.repeat(64), acquiredAt: '2026-07-25T14:00:00.000Z', expiresAt: '2026-07-25T15:00:00.000Z', hostBootId: 'boot-1' }, { currentBootId: 'boot-1', existingOwnerAlive: false, now: '2026-07-25T14:00:00.000Z' });
  f.store.acquireLease({ schemaVersion: '1.0.0', leaseId: 'lease-live', machineId: second.machineId, operation: 'test', ownerPrincipal: 'owner:test', requestDigest: 'c'.repeat(64), acquiredAt: '2026-07-25T16:00:00.000Z', expiresAt: '2026-07-25T17:00:00.000Z', hostBootId: 'boot-2' }, { currentBootId: 'boot-2', existingOwnerAlive: true, now: '2026-07-25T16:00:00.000Z' });
  const initialized = await f.controller.initialize({ ...ownerContext, idempotencyKey: 'startup-reconcile-boot-2' });
  assert.equal(initialized.processed, 2);
  assert.equal(f.store.getLease(first.machineId), undefined);
  assert.equal(initialized.results.find((entry) => entry.machineId === second.machineId).classification, 'deferred');
  assert.equal(f.observer.statusCalls.includes(third.machineId), false);
});

test('expiration changes desired state only; GC dry-run explains exclusions and live GC delegates to destroy', async (t) => {
  const f = fixture(t);
  const expiredRecord = addRecord(f, seededRecord(f.root, 'STOPPED', { expiresAt: '2026-07-25T15:00:00.000Z', observedState: 'STOPPED_INTACT' }));
  f.observer.set(expiredRecord.machineId, statusFor(expiredRecord, 'STOPPED_INTACT'));
  const expired = f.controller.expire({ machineId: expiredRecord.machineId, expectedSequence: expiredRecord.lifecycle.stateSequence, reason: 'retention' }, { ...ownerContext, idempotencyKey: 'expire-machine-1' });
  assert.equal(expired.machine.lifecycle.persistedState, 'EXPIRED');
  assert.equal(expired.machine.lifecycle.desiredState, 'DESTROYED');
  assert.equal(f.destruction.destroyCalls.length, 0);

  const protectedRecord = addRecord(f, seededRecord(f.root, 'EXPIRED', { machineId: 'mx_machine0002', machineName: 'machine-2', protectedJobIds: ['job-protected'] }));
  f.observer.set(protectedRecord.machineId, statusFor(protectedRecord, 'STOPPED_INTACT'));
  const dryRun = await f.controller.gc({ dryRun: true, limit: 3 }, { ...ownerContext, idempotencyKey: 'gc-dry-run' });
  assert.equal(dryRun.candidates.some((entry) => entry.machineId === expiredRecord.machineId), true);
  assert.equal(dryRun.exclusions.find((entry) => entry.machineId === protectedRecord.machineId).reasons.includes('protected-jobs'), true);
  assert.equal(f.destruction.destroyCalls.length, 0);

  const live = await f.controller.gc({ dryRun: false, limit: 3 }, { ...ownerContext, idempotencyKey: 'gc-live-run' });
  assert.equal(live.actions.find((entry) => entry.machineId === expiredRecord.machineId).status, 'completed');
  assert.equal(f.destruction.destroyCalls.length, 1);
  assert.equal(f.store.get(expiredRecord.machineId).lifecycle.persistedState, 'DESTROYED');
});

test('ambiguous resources are never destroyed and neighboring orphans are classified without adoption', async (t) => {
  const f = fixture(t);
  const ambiguous = addRecord(f, seededRecord(f.root, 'EXPIRED'));
  f.observer.set(ambiguous.machineId, statusFor(ambiguous, 'CONFLICT', { discrepancies: ['ownership mismatch'] }));
  const reconciled = await f.controller.reconcile({ machineId: ambiguous.machineId }, { ...ownerContext, idempotencyKey: 'reconcile-ambiguous' });
  assert.equal(reconciled.results[0].classification, 'ambiguous');
  assert.equal(f.destruction.destroyCalls.length, 0);

  f.provider.descendants.set('pool/runs', ['pool/runs', 'pool/runs/foreign', 'pool/runs/unbound']);
  f.observer.cloneObservations.set('pool/runs/unbound', {
    status: 'present', dataset: 'pool/runs/unbound', guid: '999', origin: 'pool/base@golden-v1', mountpoint: '/foreign/unbound',
    properties: { 'com.stealtheye.babyx:provider': 'zfs-nspawn-disposable@1' }, observedAt: '2026-07-25T16:00:00.000Z', command: commandResult(['/usr/sbin/zfs', 'get']),
  });
  const gc = await f.controller.gc({ dryRun: true, limit: 3 }, { ...ownerContext, idempotencyKey: 'gc-orphan-scan' });
  assert.equal(gc.orphans.find((entry) => entry.dataset === 'pool/runs/foreign').classification, 'foreign');
  assert.equal(gc.orphans.find((entry) => entry.dataset === 'pool/runs/unbound').classification, 'service-marker-unbound');
  assert.ok(gc.orphans.every((entry) => entry.action === 'exclude'));
  assert.equal(f.destruction.destroyCalls.length, 0);
});

test('expiration rejects early retention and protected evidence', (t) => {
  const f = fixture(t);
  const early = addRecord(f, seededRecord(f.root, 'STOPPED', { expiresAt: '2026-07-26T15:00:00.000Z' }));
  assert.throws(() => f.controller.expire({ machineId: early.machineId, expectedSequence: early.lifecycle.stateSequence }, { ...ownerContext, idempotencyKey: 'expire-too-early' }), machineError('machine_state_conflict'));

  const protectedRecord = addRecord(f, seededRecord(f.root, 'STOPPED', { machineId: 'mx_machine0002', machineName: 'machine-2', expiresAt: '2026-07-25T15:00:00.000Z', protectedJobIds: ['job-protected'] }));
  assert.throws(() => f.controller.expire({ machineId: protectedRecord.machineId, expectedSequence: protectedRecord.lifecycle.stateSequence }, { ...ownerContext, idempotencyKey: 'expire-protected' }), machineError('machine_protected_job_active'));
});

test('startup reconciliation obeys both record and elapsed-time bounds', async (t) => {
  const moments = [0, 0, 10, 10];
  const f = fixture(t, { startupReconcileLimit: 10, startupReconcileTimeBudgetMs: 5 }, { monotonicNow: () => moments.shift() ?? 10 });
  addRecord(f, seededRecord(f.root, 'CLONED', { machineId: 'mx_timebudget01', machineName: 'time-budget-1' }));
  addRecord(f, seededRecord(f.root, 'CLONED', { machineId: 'mx_timebudget02', machineName: 'time-budget-2' }));
  const result = await f.controller.initialize({ ...ownerContext, idempotencyKey: 'startup-time-budget' });
  assert.equal(result.startup, true);
  assert.equal(result.processed, 1);
  assert.equal(result.remainingDeferred, 1);
  assert.equal(result.timeBudgetExhausted, true);
  assert.deepEqual(f.observer.statusCalls, ['mx_timebudget01']);
});

test('startup repairs derived indexes only and isolates corrupt authoritative records', async (t) => {
  const f = fixture(t, { startupReconcileLimit: 10 });
  const good = addRecord(f, seededRecord(f.root, 'CLONED', { machineId: 'mx_indexgood01', machineName: 'index-good' }));
  writeFileSync(join(f.store.root, 'indexes.json'), '{"byDataset":{},"byName":{},"byRoot":{},"byState":{}}\n');
  const repaired = await f.controller.initialize({ ...ownerContext, idempotencyKey: 'startup-index-repair' });
  assert.equal(repaired.storeVerification.repairedIndexes, true);
  assert.equal(f.store.getByName(good.machineName).machineId, good.machineId);

  writeFileSync(join(f.store.root, 'records', 'mx_corrupt0001.json'), '{not-json\n');
  const isolated = await f.controller.initialize({ ...ownerContext, idempotencyKey: 'startup-corrupt-isolation' });
  assert.equal(isolated.processed, 1);
  assert.equal(isolated.recordErrors.length, 1);
  assert.equal(isolated.recordErrors[0].machineId, 'mx_corrupt0001');
  assert.equal(isolated.storeError.code, 'machine_record_corrupt');
  assert.equal(f.store.get(good.machineId).machineId, good.machineId);
  assert.equal(f.store.getByName(good.machineName).machineId, good.machineId);
});

test('provider and machinectl unavailability defer without fabricated absence or destruction', async (t) => {
  const f = fixture(t);
  const record = addRecord(f, seededRecord(f.root, 'EXPIRED', { machineId: 'mx_providerunk1', machineName: 'provider-unknown' }));
  f.observer.set(record.machineId, statusFor(record, 'UNKNOWN', {
    source: { status: 'unknown', snapshot: record.source.snapshot, dataset: record.source.dataset, properties: {}, observedAt: '2026-07-25T16:00:00.000Z', command: commandResult(['/usr/sbin/zfs', 'get'], 1, '', 'provider unavailable') },
  }));
  f.observer.machineListUnknown = true;
  const reconcile = await f.controller.reconcile({ machineId: record.machineId }, { ...ownerContext, idempotencyKey: 'provider-unknown-reconcile' });
  assert.equal(reconcile.results[0].classification, 'unknown');
  assert.equal(reconcile.results[0].action, 'defer-unavailable-observation');
  assert.equal(f.store.get(record.machineId).lifecycle.persistedState, 'EXPIRED');
  const gc = await f.controller.gc({ dryRun: false, limit: 3 }, { ...ownerContext, idempotencyKey: 'provider-unknown-gc' });
  assert.equal(f.destruction.destroyCalls.length, 0);
  assert.ok(gc.exclusions.find((entry) => entry.machineId === record.machineId).reasons.includes('unknown-observation'));
  assert.equal(gc.orphanProcesses[0].classification, 'unknown');
});

test('stale PID, host boot, start time, and executable identity block adoption', async (t) => {
  const persisted = { pid: 4242, pgid: 4242, processStartTime: '100', executablePath: '/usr/lib/systemd/systemd', bootId: 'boot-2' };
  const f = fixture(t, {}, { processIdentity: (pid) => ({ pid, pgid: pid, processStartTime: '101', executablePath: '/usr/bin/sleep', bootId: 'boot-old' }) });
  const record = addRecord(f, seededRecord(f.root, 'READY', { machineId: 'mx_stalepid001', machineName: 'stale-pid', processIdentity: persisted }));
  f.observer.set(record.machineId, statusFor(record, 'RUNNING'));
  const result = await f.controller.reconcile({ machineId: record.machineId }, { ...ownerContext, idempotencyKey: 'stale-process-reconcile' });
  assert.equal(result.results[0].classification, 'ambiguous');
  assert.equal(result.results[0].action, 'block-stale-process-adoption');
  assert.equal(f.store.get(record.machineId).lifecycle.persistedState, 'AMBIGUOUS');
  assert.equal(f.destruction.stopCalls.length, 0);
  assert.equal(f.destruction.destroyCalls.length, 0);
});

test('diagnostics are bounded, redacted, artifact-backed, sequence-aware, and replayable', async (t) => {
  const artifacts = new FakeArtifacts();
  const f = fixture(t, {}, { artifacts });
  const record = addRecord(f, seededRecord(f.root, 'CLONED', { machineId: 'mx_diagnostic01', machineName: 'diagnostic' }));
  const observed = statusFor(record, 'CLONE_ONLY');
  observed.clone.properties = { ...observed.clone.properties, accessToken: 'super-secret-value' };
  f.observer.set(record.machineId, observed);
  const payload = { machineId: record.machineId, expectedSequence: record.lifecycle.stateSequence, maxEvents: 5, maxJobReferences: 5, reason: 'test diagnostic capture' };
  const first = await f.controller.diagnostics(payload, { ...ownerContext, idempotencyKey: 'diagnostics-capture-1' });
  assert.equal(first.replayed, false);
  assert.equal(first.artifactReference, 'artifact-1');
  assert.equal(artifacts.created.length, 1);
  assert.equal(existsSync(artifacts.created[0].sourcePath), false);
  assert.ok(Buffer.byteLength(artifacts.created[0].content) < 1_048_576);
  assert.doesNotMatch(artifacts.created[0].content, /super-secret-value/u);
  assert.match(artifacts.created[0].content, /\[REDACTED\]/u);
  const after = f.store.get(record.machineId);
  assert.equal(after.lifecycle.stateSequence, record.lifecycle.stateSequence + 1);
  assert.ok(after.artifactIds.includes('artifact-1'));
  const replay = await f.controller.diagnostics(payload, { ...ownerContext, idempotencyKey: 'diagnostics-capture-1' });
  assert.equal(replay.replayed, true);
  assert.equal(replay.artifactReference, 'artifact-1');
  assert.equal(artifacts.created.length, 1);
});

test('GC validates state filters and classifies unbound machine processes without acting on names', async (t) => {
  const f = fixture(t);
  f.observer.machineNames = ['foreign-machine', 'neighbor-machine'];
  await assert.rejects(() => f.controller.gc({ dryRun: true, states: ['NOT_A_STATE'] }, { ...ownerContext, idempotencyKey: 'invalid-gc-state' }), machineError('machine_invalid_request'));
  await assert.rejects(() => f.controller.reconcile({ timeBudgetMs: 300_001 }, { ...ownerContext, idempotencyKey: 'invalid-time-budget' }), machineError('machine_invalid_request'));
  const gc = await f.controller.gc({ dryRun: true, limit: 2 }, { ...ownerContext, idempotencyKey: 'orphan-process-scan' });
  assert.deepEqual(gc.orphanProcesses.map((entry) => entry.machineName), ['foreign-machine', 'neighbor-machine']);
  assert.ok(gc.orphanProcesses.every((entry) => entry.action === 'exclude'));
  assert.equal(f.destruction.stopCalls.length, 0);
  assert.equal(f.destruction.destroyCalls.length, 0);
});

test('public runtime registry routes recovery operations through one startup promise', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-runtime-routing-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const runtime = new BabyXRuntime({ stateRoot: root });
  const calls = [];
  const fake = {
    reconcile: async (payload, context) => { calls.push(['reconcile', payload, context]); return { operation: 'babyx.machine.reconcile' }; },
    expire: (payload, context) => { calls.push(['expire', payload, context]); return { operation: 'babyx.machine.expire' }; },
    gc: async (payload, context) => { calls.push(['gc', payload, context]); return { operation: 'babyx.machine.gc' }; },
    diagnostics: async (payload, context) => { calls.push(['diagnostics', payload, context]); return { operation: 'babyx.machine.diagnostics' }; },
    stop: async (payload, context) => { calls.push(['stop', payload, context]); return { operation: 'babyx.machine.stop' }; },
    destroy: async (payload, context) => { calls.push(['destroy', payload, context]); return { operation: 'babyx.machine.destroy' }; },
  };
  let releaseStartup;
  runtime.machineServiceInstance = fake;
  runtime.machineServiceInitializePromise = new Promise((resolve) => { releaseStartup = resolve; });
  const context = { idempotencyKey: 'public-route', subject: 'owner:test', authorityClass: 'unrestricted-owner' };
  const pending = Promise.all([
    runtime.execute('babyx.machine.reconcile', { limit: 1 }, context),
    runtime.execute('babyx.machine.gc', { dryRun: true }, context),
  ]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls.length, 0);
  releaseStartup({ startup: true });
  await pending;
  await runtime.execute('babyx.machine.expire', { machineId: 'mx_publicroute1' }, context);
  await runtime.execute('babyx.machine.diagnostics', { machineId: 'mx_publicroute1' }, context);
  await runtime.execute('babyx.machine.stop', { machineId: 'mx_publicroute1', expectedSequence: 1 }, context);
  await runtime.execute('babyx.machine.destroy', { machineId: 'mx_publicroute1', expectedSequence: 2 }, context);
  assert.deepEqual(calls.map(([name]) => name), ['reconcile', 'gc', 'expire', 'diagnostics', 'stop', 'destroy']);
  const names = new Set(runtime.describe().operations.map((definition) => definition.operation));
  for (const name of ['babyx.machine.reconcile', 'babyx.machine.expire', 'babyx.machine.gc', 'babyx.machine.diagnostics', 'babyx.machine.stop', 'babyx.machine.destroy']) assert.ok(names.has(name));
});

test('owner-scoped GC never enumerates global orphan datasets or machine names', async (t) => {
  const f = fixture(t);
  f.provider.descendants.set('pool/runs', ['pool/runs', 'pool/runs/foreign-neighbor']);
  f.observer.machineNames = ['foreign-machine'];
  const result = await f.controller.gc(
    { dryRun: true, limit: 3 },
    { idempotencyKey: 'owner-scope-gc-1', subject: 'owner:test', authorityClass: 'owner' },
  );
  assert.deepEqual(result.orphans, []);
  assert.deepEqual(result.orphanProcesses, []);
  assert.equal(f.provider.listCalls.length, 0);
  assert.equal(f.observer.machineListCalls, 0);
});

test('legacy clone with missing source identity is repaired only from exact ownership readback', async (t) => {
  const f = fixture(t);
  const legacy = seededRecord(f.root, 'CLONED', { machineId: 'mx_legacyexact1', machineName: 'legacy-exact' });
  legacy.source = { ...legacy.source, snapshotGuid: undefined, creationTxg: undefined };
  addRecord(f, legacy);
  f.observer.set(legacy.machineId, statusFor(legacy, 'CLONE_ONLY', {
    source: {
      status: 'present', snapshot: legacy.source.snapshot, dataset: legacy.source.dataset,
      guid: '111222333', creationTxg: '444555', observedAt: '2026-07-25T16:00:00.000Z',
      command: commandResult(['/usr/sbin/zfs', 'get']),
    },
  }));
  const result = await f.controller.reconcile(
    { machineId: legacy.machineId, reason: 'repair exact legacy source identity' },
    { ...ownerContext, idempotencyKey: 'repair-legacy-source-exact' },
  );
  assert.equal(result.results[0].classification, 'consistent');
  assert.equal(result.results[0].action, 'repair-source-identity');
  const repaired = f.store.get(legacy.machineId);
  assert.equal(repaired.source.snapshotGuid, '111222333');
  assert.equal(repaired.source.creationTxg, '444555');

  const conflict = seededRecord(f.root, 'CLONED', { machineId: 'mx_legacyconflict1', machineName: 'legacy-conflict' });
  conflict.source = { ...conflict.source, snapshotGuid: undefined, creationTxg: undefined };
  addRecord(f, conflict);
  const conflicting = statusFor(conflict, 'CLONE_ONLY', {
    source: {
      status: 'present', snapshot: conflict.source.snapshot, dataset: conflict.source.dataset,
      guid: '111222333', creationTxg: '444555', observedAt: '2026-07-25T16:00:00.000Z',
      command: commandResult(['/usr/sbin/zfs', 'get']),
    },
  });
  conflicting.clone.properties = {};
  f.observer.set(conflict.machineId, conflicting);
  const blocked = await f.controller.reconcile(
    { machineId: conflict.machineId, reason: 'block non-exact legacy source repair' },
    { ...ownerContext, idempotencyKey: 'repair-legacy-source-conflict' },
  );
  assert.equal(blocked.results[0].classification, 'ambiguous');
  assert.equal(f.store.get(conflict.machineId).source.snapshotGuid, undefined);
});
