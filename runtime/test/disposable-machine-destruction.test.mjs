import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DisposableMachineService } from '../../dist/runtime/machines/service.js';
import { MachineServiceError } from '../../dist/runtime/machines/errors.js';

function commandResult(argv, exitCode = 0, stdout = '', stderr = '') {
  return {
    argv, target: { kind: 'host' }, cwd: '/', startedAt: '2026-07-25T15:00:00.000Z', completedAt: '2026-07-25T15:00:00.001Z',
    durationMs: 1, exitCode, signal: null,
    stdout: Buffer.from(stdout).toString('base64'), stderr: Buffer.from(stderr).toString('base64'),
    stdoutSha256: 'a'.repeat(64), stderrSha256: 'b'.repeat(64),
  };
}

class FakeProviderExecutor {
  calls = [];
  dataset = null;
  running = false;
  processAlive = false;
  processStartTime = '100';
  mounted = false;
  terminateStops = true;
  unmountFails = false;
  destroyLeavesDataset = false;
  destroyExitCode = 0;
  descendants = null;
  sourceGuid = '111222333';

  constructor(root) { this.root = root; }

  async run(payload) {
    const argv = payload.argv;
    this.calls.push(argv);
    if (argv[0] === '/usr/sbin/zfs' && argv[1] === 'get' && argv.at(-1).includes('@')) {
      return commandResult(argv, 0, `guid\t${this.sourceGuid}\ncreatetxg\t444555\n`);
    }
    if (argv[0] === '/usr/sbin/zfs' && argv[1] === 'get') {
      if (this.dataset === null) return commandResult(argv, 1, '', 'dataset does not exist');
      return commandResult(argv, 0, [
        `guid\t${this.dataset.guid}`,
        `origin\t${this.dataset.origin}`,
        `mountpoint\t${this.dataset.mountpoint}`,
        ...Object.entries(this.dataset.properties).map(([name, value]) => `${name}\t${value}`),
      ].join('\n') + '\n');
    }
    if (argv[0] === '/usr/sbin/zfs' && argv[1] === 'clone') {
      const properties = {};
      for (let index = 2; index < argv.length - 2; index += 2) {
        assert.equal(argv[index], '-o');
        const pair = argv[index + 1];
        const equals = pair.indexOf('=');
        properties[pair.slice(0, equals)] = pair.slice(equals + 1);
      }
      const origin = argv.at(-2);
      const dataset = argv.at(-1);
      const mountpoint = properties.mountpoint;
      delete properties.mountpoint;
      mkdirSync(mountpoint, { recursive: true });
      this.dataset = { dataset, origin, mountpoint, properties, guid: '777888999' };
      this.mounted = true;
      return commandResult(argv);
    }
    if (argv[0] === '/usr/sbin/zfs' && argv[1] === 'list') {
      if (this.dataset === null) return commandResult(argv, 1, '', 'dataset does not exist');
      const names = this.descendants ?? [this.dataset.dataset];
      return commandResult(argv, 0, `${names.join('\n')}\n`);
    }
    if (argv[0] === '/usr/sbin/zfs' && argv[1] === 'destroy') {
      if (!this.destroyLeavesDataset && this.destroyExitCode === 0) this.dataset = null;
      return commandResult(argv, this.destroyExitCode, '', this.destroyExitCode === 0 ? '' : 'destroy failed');
    }
    if (argv[0] === '/usr/bin/machinectl' && argv[1] === '--no-pager') {
      if (!this.running) return commandResult(argv, 1, '', 'no such machine');
      return commandResult(argv, 0, `Name=machine-1\nState=running\nRootDirectory=${this.root}\nLeader=4242\n`);
    }
    if (argv[0] === '/usr/bin/machinectl' && argv[1] === 'terminate') {
      if (this.terminateStops) { this.running = false; this.processAlive = false; }
      return commandResult(argv);
    }
    if (argv[0] === '/usr/bin/mountpoint') return commandResult(argv, this.mounted ? 0 : 1, '', this.mounted ? '' : 'not a mountpoint');
    if (argv[0] === '/usr/bin/umount') {
      if (this.unmountFails) return commandResult(argv, 1, '', 'busy');
      this.mounted = false;
      return commandResult(argv);
    }
    throw new Error(`unexpected provider argv: ${JSON.stringify(argv)}`);
  }

  count(predicate) { return this.calls.filter(predicate).length; }
}

class FakeJobs {
  records = new Map();
  listeners = new Set();
  next = 1;

  constructor(root, provider) { this.root = root; this.provider = provider; mkdirSync(root, { recursive: true }); }
  onChange(listener) { this.listeners.add(listener); return () => this.listeners.delete(listener); }
  get(id) { const record = this.records.get(id); if (!record) throw new Error('job not found'); return structuredClone(record); }
  start(operation, payload) {
    const id = `job-${this.next++}`;
    const stdoutPath = join(this.root, `${id}.stdout`);
    const stderrPath = join(this.root, `${id}.stderr`);
    writeFileSync(stdoutPath, ''); writeFileSync(stderrPath, '');
    const record = {
      id, operation, status: 'running', target: payload.target, argv: payload.argv, cwd: payload.cwd,
      createdAt: '2026-07-25T15:00:00.000Z', startedAt: '2026-07-25T15:00:00.000Z',
      pid: 9001, pgid: 9001, stdoutPath, stderrPath,
      ...(payload.metadata === undefined ? {} : { metadata: payload.metadata }),
    };
    this.records.set(id, record);
    if (operation === 'babyx.machine.start') { this.provider.running = true; this.provider.processAlive = true; }
    return structuredClone(record);
  }
}

class FakeArtifacts {
  created = [];
  create(name, sourcePath, metadata) {
    assert.equal(existsSync(sourcePath), true);
    const artifact = { id: `artifact-${this.created.length + 1}`, name, sourcePath, metadata };
    this.created.push(artifact);
    return artifact;
  }
}

function request(machineRoot) {
  return {
    schemaVersion: '1.0.0', machineName: 'machine-1', ownerPrincipal: 'owner:test',
    source: { kind: 'zfs-snapshot', snapshot: 'pool/base/noble@golden-v1', expectedGuid: '111222333' },
    clone: { dataset: 'pool/runs/machine-1', mountpoint: join(machineRoot, 'machine-1'), expectedRootPrefix: machineRoot },
    launch: { boot: true, networkMode: 'none', readOnlyRoot: false, binds: [], environment: [], properties: [] },
  };
}

function fixture(t, providerOverrides = {}) {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-destroy-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const machineRoot = join(root, 'machines');
  mkdirSync(machineRoot, { recursive: true });
  const provider = new FakeProviderExecutor(join(machineRoot, 'machine-1'));
  Object.assign(provider, providerOverrides);
  const jobs = new FakeJobs(join(root, 'jobs'), provider);
  const artifacts = new FakeArtifacts();
  const forcedGroups = [];
  let tick = 0;
  const options = {
    stateRoot: root, executor: provider, jobs, artifacts,
    config: {
      sourceSnapshotRoots: ['pool/base'], cloneDatasetRoots: ['pool/runs'], machineRoot,
      readinessTimeoutMs: 3, readinessPollIntervalMs: 1, stopGracefulTimeoutMs: 2, stopPollIntervalMs: 1,
    },
    now: () => `2026-07-25T15:00:${String(tick++).padStart(2, '0')}.000Z`,
    machineIdFactory: () => 'mx_machine00000001',
    hostIdentity: { hostname: 'test-host', machineIdSha256: '1'.repeat(64), bootId: 'boot-1' },
    sleep: async () => {},
    processIdentity: (pid) => {
      if (!provider.processAlive) throw new Error('process absent');
      return { pid, pgid: 4242, processStartTime: provider.processStartTime, executablePath: '/usr/lib/systemd/systemd', bootId: 'boot-1' };
    },
    killProcessGroup: (pgid) => { forcedGroups.push(pgid); provider.running = false; provider.processAlive = false; },
  };
  return { root, machineRoot, provider, jobs, artifacts, forcedGroups, service: new DisposableMachineService(options), options };
}

const createContext = { idempotencyKey: 'create-machine-1', subject: 'owner:test', authorityClass: 'unrestricted-owner' };
const startContext = { idempotencyKey: 'start-machine-1', subject: 'owner:test', authorityClass: 'unrestricted-owner' };
const stopContext = { idempotencyKey: 'stop-machine-1', subject: 'owner:test', authorityClass: 'unrestricted-owner' };
const destroyContext = { idempotencyKey: 'destroy-machine-1', subject: 'owner:test', authorityClass: 'unrestricted-owner' };
const machineError = (code) => (error) => error instanceof MachineServiceError && error.code === code;

async function createCloned(f) {
  const created = await f.service.create(request(f.machineRoot), createContext);
  assert.equal(created.machine.lifecycle.persistedState, 'CLONED');
  return created.machine;
}

async function createReady(f) {
  const cloned = await createCloned(f);
  const started = await f.service.start({ machineId: cloned.machineId, expectedSequence: cloned.lifecycle.stateSequence, readinessTimeoutMs: 3 }, startContext);
  assert.equal(started.machine.lifecycle.persistedState, 'READY');
  return started.machine;
}

test('graceful stop persists intent, verifies exact absence, and replays as a verified no-op', async (t) => {
  const f = fixture(t);
  const ready = await createReady(f);
  const payload = { machineId: ready.machineId, expectedSequence: ready.lifecycle.stateSequence, gracefulTimeoutMs: 2, forceAfterTimeout: false, reason: 'test stop' };
  const stopped = await f.service.stop(payload, stopContext);
  assert.equal(stopped.machine.lifecycle.persistedState, 'STOPPED');
  assert.equal(stopped.machine.lifecycle.observedState, 'STOPPED_INTACT');
  assert.equal(stopped.machine.processIdentity, undefined);
  assert.equal(stopped.machine.cleanup.stopVerified, true);
  assert.equal(f.provider.count((argv) => argv[0] === '/usr/bin/machinectl' && argv[1] === 'terminate'), 1);
  assert.deepEqual(f.service.store.events(ready.machineId, 0, 100).slice(-2).map((event) => event.kind), ['machine.stopping', 'machine.stopped']);

  const replay = await f.service.stop(payload, stopContext);
  assert.equal(replay.noOp, true);
  assert.equal(replay.replayed, true);
  assert.equal(f.provider.count((argv) => argv[0] === '/usr/bin/machinectl' && argv[1] === 'terminate'), 1);
});

test('already-absent stop remains auditable, and force escalation uses only the exact process group', async (t) => {
  const absent = fixture(t);
  const ready = await createReady(absent);
  absent.provider.running = false; absent.provider.processAlive = false;
  const verified = await absent.service.stop(
    { machineId: ready.machineId, expectedSequence: ready.lifecycle.stateSequence },
    { ...stopContext, idempotencyKey: 'stop-already-absent' },
  );
  assert.equal(verified.machine.lifecycle.persistedState, 'STOPPED');
  assert.equal(absent.provider.count((argv) => argv[1] === 'terminate'), 0);
  assert.deepEqual(absent.service.store.events(ready.machineId, 0, 100).slice(-2).map((event) => event.kind), ['machine.stopping', 'machine.stopped']);

  const forced = fixture(t, { terminateStops: false });
  const running = await createReady(forced);
  const result = await forced.service.stop(
    { machineId: running.machineId, expectedSequence: running.lifecycle.stateSequence, gracefulTimeoutMs: 1, forceAfterTimeout: true },
    { ...stopContext, idempotencyKey: 'stop-force-exact-process' },
  );
  assert.equal(result.forced, true);
  assert.deepEqual(forced.forcedGroups, [4242]);
  assert.equal(result.machine.lifecycle.persistedState, 'STOPPED');
});

test('stale PID identity and active or protected jobs block teardown before destructive action', async (t) => {
  const stale = fixture(t);
  const ready = await createReady(stale);
  stale.provider.processStartTime = '101';
  await assert.rejects(
    () => stale.service.stop({ machineId: ready.machineId, expectedSequence: ready.lifecycle.stateSequence }, stopContext),
    machineError('machine_process_conflict'),
  );
  assert.equal(stale.provider.count((argv) => argv[1] === 'terminate'), 0);
  assert.deepEqual(stale.forcedGroups, []);

  const active = fixture(t);
  const activeReady = await createReady(active);
  const activeRecord = active.service.store.get(activeReady.machineId);
  active.service.store.update(activeReady.machineId, activeRecord.lifecycle.stateSequence, {
    operation: 'test.seed', phase: 'seed', kind: 'test.active-job', message: 'seed active job', occurredAt: '2026-07-25T15:10:00.000Z',
  }, { activeJobIds: ['job-active'] });
  const activeCurrent = active.service.store.get(activeReady.machineId);
  await assert.rejects(
    () => active.service.stop({ machineId: activeReady.machineId, expectedSequence: activeCurrent.lifecycle.stateSequence }, { ...stopContext, idempotencyKey: 'stop-active-job' }),
    machineError('machine_job_active'),
  );

  const protectedFixture = fixture(t);
  const cloned = await createCloned(protectedFixture);
  const protectedRecord = protectedFixture.service.store.get(cloned.machineId);
  protectedFixture.service.store.update(cloned.machineId, protectedRecord.lifecycle.stateSequence, {
    operation: 'test.seed', phase: 'seed', kind: 'test.protected-job', message: 'seed protected job', occurredAt: '2026-07-25T15:10:01.000Z',
  }, { protectedJobIds: ['job-protected'] });
  const protectedCurrent = protectedFixture.service.store.get(cloned.machineId);
  await assert.rejects(
    () => protectedFixture.service.destroy({ machineId: cloned.machineId, expectedSequence: protectedCurrent.lifecycle.stateSequence }, destroyContext),
    machineError('machine_protected_job_active'),
  );
  assert.equal(protectedFixture.provider.count((argv) => argv[0] === '/usr/sbin/zfs' && argv[1] === 'destroy'), 0);
});

test('destroy retains evidence, uses exact non-recursive ZFS destruction, verifies every absence, and tombstones', async (t) => {
  const f = fixture(t);
  const cloned = await createCloned(f);
  const payload = { machineId: cloned.machineId, expectedSequence: cloned.lifecycle.stateSequence, stopIfRunning: false, reason: 'test destroy' };
  const destroyed = await f.service.destroy(payload, destroyContext);
  assert.equal(destroyed.machine.lifecycle.persistedState, 'DESTROYED');
  assert.equal(destroyed.machine.lifecycle.observedState, 'ABSENT');
  assert.equal(destroyed.machine.cleanup.completed, true);
  assert.equal(destroyed.machine.cleanup.datasetAbsentVerified, true);
  assert.equal(destroyed.machine.cleanup.rootAbsentVerified, true);
  assert.equal(destroyed.machine.cleanup.machineAbsentVerified, true);
  assert.equal(destroyed.machine.cleanup.processAbsentVerified, true);
  assert.equal(f.provider.dataset, null);
  assert.equal(existsSync(join(f.machineRoot, 'machine-1')), false);
  assert.equal(f.artifacts.created.length, 1);
  assert.deepEqual(destroyed.artifactReferences, ['artifact-1']);
  assert.equal(destroyed.tombstone.machineId, cloned.machineId);
  assert.ok(f.service.store.getTombstone(cloned.machineId));

  const destroyArgv = f.provider.calls.find((argv) => argv[0] === '/usr/sbin/zfs' && argv[1] === 'destroy');
  assert.deepEqual(destroyArgv, ['/usr/sbin/zfs', 'destroy', 'pool/runs/machine-1']);
  assert.equal(destroyArgv.includes('-r'), false);
  const descendantArgv = f.provider.calls.find((argv) => argv[0] === '/usr/sbin/zfs' && argv[1] === 'list');
  assert.deepEqual(descendantArgv, ['/usr/sbin/zfs', 'list', '-H', '-o', 'name', '-r', '-t', 'all', 'pool/runs/machine-1']);
  assert.equal(f.provider.calls.some((argv) => argv[0] === '/usr/sbin/zfs' && argv[1] === 'destroy' && argv.at(-1).includes('@')), false);

  const replay = await f.service.destroy(payload, destroyContext);
  assert.equal(replay.noOp, true);
  assert.equal(replay.replayed, true);
  assert.equal(f.provider.count((argv) => argv[0] === '/usr/sbin/zfs' && argv[1] === 'destroy'), 1);
});

test('destroy refuses wrong ownership, changed dataset identity, and recursive children', async (t) => {
  const wrongOwner = fixture(t);
  const cloned = await createCloned(wrongOwner);
  wrongOwner.provider.dataset.properties['com.stealtheye.babyx:owner-principal'] = 'owner:foreign';
  await assert.rejects(
    () => wrongOwner.service.destroy({ machineId: cloned.machineId, expectedSequence: cloned.lifecycle.stateSequence }, destroyContext),
    machineError('machine_ownership_mismatch'),
  );
  assert.equal(wrongOwner.provider.count((argv) => argv[1] === 'destroy'), 0);

  const wrongGuid = fixture(t);
  const clonedGuid = await createCloned(wrongGuid);
  wrongGuid.provider.dataset.guid = '999000111';
  await assert.rejects(
    () => wrongGuid.service.destroy({ machineId: clonedGuid.machineId, expectedSequence: clonedGuid.lifecycle.stateSequence }, { ...destroyContext, idempotencyKey: 'destroy-wrong-guid' }),
    machineError('machine_ownership_mismatch'),
  );

  const child = fixture(t);
  const clonedChild = await createCloned(child);
  child.provider.descendants = ['pool/runs/machine-1', 'pool/runs/machine-1/child', 'pool/runs/machine-1@snapshot'];
  await assert.rejects(
    () => child.service.destroy({ machineId: clonedChild.machineId, expectedSequence: clonedChild.lifecycle.stateSequence }, { ...destroyContext, idempotencyKey: 'destroy-child-dependency' }),
    machineError('machine_dependency_conflict'),
  );
  assert.equal(child.provider.count((argv) => argv[1] === 'destroy'), 0);
});

test('running destroy requires explicit stop authorization and then uses the normal stop path', async (t) => {
  const f = fixture(t);
  const ready = await createReady(f);
  await assert.rejects(
    () => f.service.destroy({ machineId: ready.machineId, expectedSequence: ready.lifecycle.stateSequence }, destroyContext),
    machineError('machine_state_conflict'),
  );
  const destroyed = await f.service.destroy(
    { machineId: ready.machineId, expectedSequence: ready.lifecycle.stateSequence, stopIfRunning: true, forceStop: false, stopTimeoutMs: 2 },
    { ...destroyContext, idempotencyKey: 'destroy-with-stop' },
  );
  assert.equal(destroyed.machine.lifecycle.persistedState, 'DESTROYED');
  assert.equal(f.provider.count((argv) => argv[0] === '/usr/bin/machinectl' && argv[1] === 'terminate'), 1);
  assert.equal(f.provider.count((argv) => argv[0] === '/usr/sbin/zfs' && argv[1] === 'destroy'), 1);
});

test('zero-exit destroy without dataset absence never records DESTROYED or creates a tombstone', async (t) => {
  const f = fixture(t, { destroyLeavesDataset: true });
  const cloned = await createCloned(f);
  await assert.rejects(
    () => f.service.destroy({ machineId: cloned.machineId, expectedSequence: cloned.lifecycle.stateSequence }, destroyContext),
    machineError('machine_cleanup_failed'),
  );
  const current = f.service.store.get(cloned.machineId);
  assert.equal(current.lifecycle.persistedState, 'RECOVERY_REQUIRED');
  assert.equal(current.cleanup.completed, false);
  assert.equal(f.service.store.getTombstone(cloned.machineId), undefined);
  assert.equal(f.provider.dataset.dataset, 'pool/runs/machine-1');
});

test('describe exposes Checkpoint H without claiming certification completion', (t) => {
  const f = fixture(t);
  const described = f.service.describe();
  assert.equal(described.checkpoint, 'H');
  assert.ok(described.operations.includes('babyx.machine.stop'));
  assert.ok(described.operations.includes('babyx.machine.destroy'));
  assert.equal(described.unavailableUntilLaterCheckpoints.includes('stop'), false);
  assert.equal(described.unavailableUntilLaterCheckpoints.includes('reconcile'), false);
  assert.ok(described.operations.includes('babyx.machine.reconcile'));
  assert.ok(described.operations.includes('babyx.machine.expire'));
  assert.ok(described.operations.includes('babyx.machine.gc'));
  assert.equal(described.unavailableUntilLaterCheckpoints.includes('certify'), false);
  assert.equal(described.unavailableUntilLaterCheckpoints.includes('policy'), false);
  assert.equal(described.unavailableUntilLaterCheckpoints.includes('race'), false);
});


test('unmount failure persists RECOVERY_REQUIRED and never attempts dataset destruction', async (t) => {
  const f = fixture(t, { unmountFails: true });
  const cloned = await createCloned(f);
  await assert.rejects(
    () => f.service.destroy({ machineId: cloned.machineId, expectedSequence: cloned.lifecycle.stateSequence }, { ...destroyContext, idempotencyKey: 'destroy-unmount-failure' }),
    machineError('machine_cleanup_failed'),
  );
  const current = f.service.store.get(cloned.machineId);
  assert.equal(current.lifecycle.persistedState, 'RECOVERY_REQUIRED');
  assert.equal(current.cleanup.completed, false);
  assert.equal(current.cleanup.datasetDestroyAttempted, false);
  assert.equal(f.provider.count((argv) => argv[0] === '/usr/sbin/zfs' && argv[1] === 'destroy'), 0);
  assert.equal(f.service.store.getTombstone(cloned.machineId), undefined);
});
