import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { JobManager } from '../../dist/runtime/core.js';
import { DisposableMachineService } from '../../dist/runtime/machines/service.js';
import { MachineServiceError } from '../../dist/runtime/machines/errors.js';
import { codeTransactionMachineExecutionRequest } from '../../dist/runtime/transactions/code-driver.js';
import { makeRecord } from './_transaction-fixture.mjs';

function commandResult(argv, exitCode = 0, stdout = '', stderr = '') {
  return {
    argv, target: { kind: 'host' }, cwd: '/', startedAt: '2026-07-25T14:00:00.000Z', completedAt: '2026-07-25T14:00:00.001Z',
    durationMs: 1, exitCode, signal: null,
    stdout: Buffer.from(stdout).toString('base64'), stderr: Buffer.from(stderr).toString('base64'),
    stdoutSha256: 'a'.repeat(64), stderrSha256: 'b'.repeat(64),
  };
}

class FakeProviderExecutor {
  calls = [];
  dataset = null;
  running = false;
  startBehavior = 'ready';
  conflictName = null;
  conflictRoot = null;
  machineUnknown = false;

  constructor(root) { this.root = root; }

  async run(payload) {
    const argv = payload.argv;
    this.calls.push(argv);
    if (argv[0] === '/usr/sbin/zfs' && argv[1] === 'get' && argv.at(-1).includes('@')) {
      return commandResult(argv, 0, 'guid\t111222333\ncreatetxg\t444555\n');
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
      return commandResult(argv);
    }
    if (argv[0] === '/usr/bin/machinectl') {
      if (this.machineUnknown) return commandResult(argv, 1, '', 'bus unavailable');
      if (!this.running) return commandResult(argv, 1, '', 'no such machine');
      const name = this.conflictName ?? 'machine-1';
      const root = this.conflictRoot ?? this.root;
      return commandResult(argv, 0, `Name=${name}\nState=running\nRootDirectory=${root}\nLeader=4242\n`);
    }
    throw new Error(`unexpected provider argv: ${JSON.stringify(argv)}`);
  }
}

class FakeJobs {
  records = new Map();
  listeners = new Set();
  next = 1;

  constructor(root, provider) {
    this.root = root;
    this.provider = provider;
    mkdirSync(root, { recursive: true });
  }

  onChange(listener) { this.listeners.add(listener); return () => this.listeners.delete(listener); }

  start(operation, payload) {
    const id = `job-${this.next++}`;
    const stdoutPath = join(this.root, `${id}.stdout`);
    const stderrPath = join(this.root, `${id}.stderr`);
    writeFileSync(stdoutPath, '');
    writeFileSync(stderrPath, '');
    const record = {
      id, operation, status: 'running', target: payload.target, argv: payload.argv, cwd: payload.cwd,
      createdAt: '2026-07-25T14:00:00.000Z', startedAt: '2026-07-25T14:00:00.000Z',
      pid: 9000 + this.next, pgid: 9000 + this.next, stdoutPath, stderrPath,
      ...(payload.metadata === undefined ? {} : { metadata: payload.metadata }),
      ...(payload.timeoutMs === undefined ? {} : { timeoutMs: payload.timeoutMs }),
    };
    this.records.set(id, record);
    if (operation === 'babyx.machine.start') {
      if (this.provider.startBehavior === 'ready') this.provider.running = true;
      if (this.provider.startBehavior === 'wrong-root') {
        this.provider.running = true;
        this.provider.conflictRoot = `${this.provider.root}-foreign`;
      }
      if (this.provider.startBehavior === 'wrong-name') {
        this.provider.running = true;
        this.provider.conflictName = 'foreign-machine';
      }
    }
    return structuredClone(record);
  }

  get(id) {
    const record = this.records.get(id);
    if (!record) throw new Error('job not found');
    return structuredClone(record);
  }

  async complete(id, { exitCode = 0, signal = null, stdout = '', stderr = '' } = {}) {
    const current = this.records.get(id);
    if (!current) throw new Error('job not found');
    writeFileSync(current.stdoutPath, stdout);
    writeFileSync(current.stderrPath, stderr);
    const record = {
      ...current,
      status: signal || exitCode !== 0 ? 'failed' : 'completed',
      exitCode,
      signal,
      completedAt: '2026-07-25T14:00:59.000Z',
    };
    this.records.set(id, record);
    for (const listener of this.listeners) await listener(structuredClone(record));
    return structuredClone(record);
  }

  count(operation) { return [...this.records.values()].filter((record) => record.operation === operation).length; }
}

class FakeArtifacts {
  created = [];
  create(name, sourcePath, metadata) {
    const artifact = { id: `artifact-${this.created.length + 1}`, name, sourcePath, metadata };
    this.created.push(artifact);
    return artifact;
  }
}

function machineRequest(machineRoot) {
  return {
    schemaVersion: '1.0.0', machineName: 'machine-1', ownerPrincipal: 'owner:test',
    source: { kind: 'zfs-snapshot', snapshot: 'pool/base/noble@golden-v1', expectedGuid: '111222333' },
    clone: { dataset: 'pool/runs/machine-1', mountpoint: join(machineRoot, 'machine-1'), expectedRootPrefix: machineRoot },
    launch: {
      boot: true, networkMode: 'none', readOnlyRoot: false, binds: [], environment: [],
      properties: [{ name: 'MemoryMax', value: '1G' }],
    },
  };
}

function fixture(t, overrides = {}) {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-execution-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const machineRoot = join(root, 'machines');
  mkdirSync(machineRoot, { recursive: true });
  const provider = new FakeProviderExecutor(join(machineRoot, 'machine-1'));
  Object.assign(provider, overrides.provider ?? {});
  const jobs = new FakeJobs(join(root, 'fake-jobs'), provider);
  const artifacts = new FakeArtifacts();
  let tick = 0;
  let processStartTime = '100';
  let processExecutable = overrides.processExecutable ?? '/usr/lib/systemd/systemd';
  const processExecutables = [...(overrides.processExecutables ?? [])];
  let processIdentityCalls = 0;
  let sleepCalls = 0;
  const options = {
    stateRoot: root,
    executor: provider,
    jobs,
    artifacts,
    config: {
      sourceSnapshotRoots: ['pool/base'], cloneDatasetRoots: ['pool/runs'], machineRoot,
      readinessTimeoutMs: 3, readinessPollIntervalMs: 1,
    },
    now: () => `2026-07-25T14:00:${String(tick++).padStart(2, '0')}.000Z`,
    machineIdFactory: () => 'mx_machine00000001',
    hostIdentity: { hostname: 'test-host', machineIdSha256: '1'.repeat(64), bootId: 'boot-1' },
    sleep: async () => { sleepCalls += 1; },
    processIdentity: (pid) => {
      const executablePath = processExecutables.length === 0 ? processExecutable : processExecutables[Math.min(processIdentityCalls, processExecutables.length - 1)];
      processIdentityCalls += 1;
      return { pid, pgid: pid, processStartTime, executablePath, bootId: 'boot-1' };
    },
  };
  const service = new DisposableMachineService(options);
  return {
    root, machineRoot, provider, jobs, artifacts, service, options,
    setProcessStartTime: (value) => { processStartTime = value; },
    setProcessExecutable: (value) => { processExecutable = value; },
    processIdentityCalls: () => processIdentityCalls,
    sleepCalls: () => sleepCalls,
  };
}

const createContext = { idempotencyKey: 'create-machine-1', subject: 'owner:test', authorityClass: 'unrestricted-owner' };
const startContext = { idempotencyKey: 'start-machine-1', subject: 'owner:test', authorityClass: 'unrestricted-owner' };
const machineError = (code) => (error) => error instanceof MachineServiceError && error.code === code;

async function createCloned(f) {
  const created = await f.service.create(machineRequest(f.machineRoot), createContext);
  assert.equal(created.machine.lifecycle.persistedState, 'CLONED');
  return created.machine;
}

async function createReady(f) {
  const cloned = await createCloned(f);
  const payload = { machineId: cloned.machineId, expectedSequence: cloned.lifecycle.stateSequence, readinessTimeoutMs: 3, reason: 'focused test' };
  const started = await f.service.start(payload, startContext);
  assert.equal(started.machine.lifecycle.persistedState, 'READY');
  return { started, payload };
}

test('start uses the existing durable job authority, verifies identity, and replays exactly', async (t) => {
  const f = fixture(t);
  const cloned = await createCloned(f);
  const payload = { machineId: cloned.machineId, expectedSequence: cloned.lifecycle.stateSequence, readinessTimeoutMs: 3, reason: 'start' };
  const started = await f.service.start(payload, startContext);
  assert.equal(started.operation, 'babyx.machine.start');
  assert.equal(started.machine.lifecycle.persistedState, 'READY');
  assert.equal(started.machine.lifecycle.observedState, 'RUNNING');
  assert.equal(started.machine.processIdentity.pid, 4242);
  assert.equal(started.machine.processIdentity.processStartTime, '100');
  assert.equal(f.jobs.count('babyx.machine.start'), 1);
  const launch = f.jobs.get(started.jobId);
  assert.deepEqual(launch.target, { kind: 'host' });
  assert.equal(launch.argv[0], '/usr/bin/systemd-nspawn');
  assert.ok(launch.argv.includes('--machine=machine-1'));
  assert.ok(launch.argv.includes(`--directory=${join(f.machineRoot, 'machine-1')}`));
  assert.ok(launch.argv.includes('--private-network'));
  assert.ok(launch.argv.includes('--property=MemoryMax=1G'));

  const replay = await f.service.start(payload, startContext);
  assert.equal(replay.replayed, true);
  assert.equal(replay.noOp, true);
  assert.equal(replay.jobId, started.jobId);
  assert.equal(f.jobs.count('babyx.machine.start'), 1);

  const current = f.service.store.get(cloned.machineId);
  const healthyNoOp = await f.service.start(
    { machineId: cloned.machineId, expectedSequence: current.lifecycle.stateSequence, reason: 'already ready' },
    { ...startContext, idempotencyKey: 'start-machine-ready-noop' },
  );
  assert.equal(healthyNoOp.noOp, true);
  assert.equal(f.jobs.count('babyx.machine.start'), 1);
});

test('start waits for the exact requested leader after the nspawn launcher exec transition', async (t) => {
  const f = fixture(t, { processExecutables: ['/usr/bin/systemd-nspawn', '/usr/lib/systemd/systemd'] });
  const request = machineRequest(f.machineRoot);
  request.launch = { ...request.launch, boot: false, command: ['/usr/lib/systemd/systemd', '--unit=basic.target'] };
  const created = await f.service.create(request, { ...createContext, idempotencyKey: 'create-machine-launcher-transition' });
  const started = await f.service.start(
    { machineId: created.machine.machineId, expectedSequence: created.machine.lifecycle.stateSequence, readinessTimeoutMs: 3, reason: 'wait for launcher exec' },
    { ...startContext, idempotencyKey: 'start-machine-launcher-transition' },
  );
  assert.equal(started.machine.lifecycle.persistedState, 'READY');
  assert.equal(started.machine.processIdentity.executablePath, '/usr/lib/systemd/systemd');
  assert.equal(f.processIdentityCalls(), 2);
  assert.equal(f.sleepCalls(), 1);
});

test('start rejects a non-launcher executable that differs from the requested leader', async (t) => {
  const f = fixture(t, { processExecutable: '/usr/bin/sleep' });
  const request = machineRequest(f.machineRoot);
  request.launch = { ...request.launch, boot: false, command: ['/usr/lib/systemd/systemd', '--unit=basic.target'] };
  const created = await f.service.create(request, { ...createContext, idempotencyKey: 'create-machine-wrong-leader' });
  await assert.rejects(
    () => f.service.start(
      { machineId: created.machine.machineId, expectedSequence: created.machine.lifecycle.stateSequence, readinessTimeoutMs: 3 },
      { ...startContext, idempotencyKey: 'start-machine-wrong-leader' },
    ),
    machineError('machine_process_conflict'),
  );
  assert.equal(f.service.store.get(created.machine.machineId).lifecycle.persistedState, 'AMBIGUOUS');
});

test('start rejects stale sequence and conflicting pre-existing machine identity without launching', async (t) => {
  const f = fixture(t);
  const cloned = await createCloned(f);
  await assert.rejects(
    () => f.service.start({ machineId: cloned.machineId, expectedSequence: 2 }, startContext),
    (error) => error?.code === 'machine_sequence_conflict',
  );
  f.provider.running = true;
  f.provider.conflictRoot = `${f.provider.root}-foreign`;
  await assert.rejects(
    () => f.service.start({ machineId: cloned.machineId, expectedSequence: cloned.lifecycle.stateSequence }, { ...startContext, idempotencyKey: 'start-conflict-root' }),
    machineError('machine_process_conflict'),
  );
  assert.equal(f.jobs.count('babyx.machine.start'), 0);
  assert.equal(f.service.store.get(cloned.machineId).lifecycle.persistedState, 'CLONED');
});

test('bounded readiness failure is explicit and never reports READY', async (t) => {
  const f = fixture(t, { provider: { startBehavior: 'never' } });
  const cloned = await createCloned(f);
  await assert.rejects(
    () => f.service.start({ machineId: cloned.machineId, expectedSequence: cloned.lifecycle.stateSequence, readinessTimeoutMs: 2 }, startContext),
    machineError('machine_readiness_failed'),
  );
  const failed = f.service.store.get(cloned.machineId);
  assert.equal(failed.lifecycle.persistedState, 'FAILED');
  assert.equal(failed.lifecycle.observedState, 'CLONE_ONLY');
  assert.equal(f.jobs.count('babyx.machine.start'), 1);
});

test('controller restart adopts an exact healthy STARTING machine without duplicate launch', async (t) => {
  const f = fixture(t);
  const cloned = await createCloned(f);
  const starting = f.service.store.transition(cloned.machineId, cloned.lifecycle.stateSequence, 'STARTING', 'READY', {
    operation: 'babyx.machine.start', phase: 'start-intent', kind: 'machine.starting', message: 'simulated persisted start before restart',
    requestDigest: 'a'.repeat(64), idempotencyKey: 'prior-start-intent', occurredAt: '2026-07-25T14:00:20.000Z',
  });
  f.provider.running = true;
  const restarted = new DisposableMachineService(f.options);
  const adopted = await restarted.start(
    { machineId: cloned.machineId, expectedSequence: starting.lifecycle.stateSequence, reason: 'restart adoption' },
    { ...startContext, idempotencyKey: 'restart-adopt-running' },
  );
  assert.equal(adopted.machine.lifecycle.persistedState, 'READY');
  assert.equal(adopted.noOp, true);
  assert.equal(adopted.jobId, null);
  assert.equal(f.jobs.count('babyx.machine.start'), 0);
});

test('exec and shell target the exact machine through existing jobs, support concurrency, failures, and artifacts', async (t) => {
  const f = fixture(t);
  const { started } = await createReady(f);
  const machineId = started.machine.machineId;
  let current = f.service.store.get(machineId);
  const firstPayload = {
    machineId, expectedSequence: current.lifecycle.stateSequence,
    argv: ['/usr/bin/printf', '%s', 'alpha'], cwd: '/work', env: { MODE: 'test' }, timeoutMs: 1000,
    outputLimitBytes: 4096, artifactPolicy: { captureStreams: true }, reason: 'first command',
  };
  const firstContext = { idempotencyKey: 'exec-machine-first', subject: 'owner:test', authorityClass: 'unrestricted-owner' };
  const first = await f.service.exec(firstPayload, firstContext);
  assert.equal(first.machine.lifecycle.persistedState, 'EXECUTING');
  const firstJob = f.jobs.get(first.jobId);
  assert.deepEqual(firstJob.target, { kind: 'machine-process', machine: 'machine-1', processIdentity: { pid: 4242, pgid: 4242, processStartTime: '100', executablePath: '/usr/lib/systemd/systemd', bootId: 'boot-1' } });
  assert.deepEqual(firstJob.argv, ['/usr/bin/printf', '%s', 'alpha']);
  assert.equal(firstJob.cwd, '/work');
  assert.equal(firstJob.timeoutMs, 1000);
  assert.equal(firstJob.metadata.machineService, true);
  assert.equal(firstJob.metadata.outputLimitBytes, 4096);

  current = f.service.store.get(machineId);
  const second = await f.service.shell(
    { machineId, expectedSequence: current.lifecycle.stateSequence, script: 'printf beta', artifactPolicy: { captureStreams: true } },
    { idempotencyKey: 'shell-machine-second', subject: 'owner:test', authorityClass: 'unrestricted-owner' },
  );
  const secondJob = f.jobs.get(second.jobId);
  assert.deepEqual(secondJob.target, { kind: 'machine-process', machine: 'machine-1', processIdentity: { pid: 4242, pgid: 4242, processStartTime: '100', executablePath: '/usr/lib/systemd/systemd', bootId: 'boot-1' } });
  assert.deepEqual(secondJob.argv, ['/usr/bin/bash', '-lc', 'printf beta']);
  assert.equal(f.service.store.get(machineId).activeJobIds.length, 2);

  await f.jobs.complete(first.jobId, { exitCode: 7, stdout: 'alpha-out', stderr: 'alpha-error' });
  let afterFirst = f.service.store.get(machineId);
  assert.equal(afterFirst.lifecycle.persistedState, 'EXECUTING');
  assert.deepEqual(afterFirst.activeJobIds, [second.jobId]);

  await f.jobs.complete(second.jobId, { stdout: 'beta-out' });
  const complete = f.service.store.get(machineId);
  assert.equal(complete.lifecycle.persistedState, 'READY');
  assert.deepEqual(complete.activeJobIds, []);
  assert.equal(complete.artifactIds.length, 4);
  assert.equal(f.artifacts.created.length, 4);
  assert.ok(f.service.store.events(machineId, 0, 100).some((event) => event.kind === 'machine.job-failed'));
  assert.ok(f.service.store.events(machineId, 0, 100).some((event) => event.kind === 'machine.job-completed'));

  const replay = await f.service.exec(firstPayload, firstContext);
  assert.equal(replay.replayed, true);
  assert.equal(replay.jobId, first.jobId);
  assert.equal(f.jobs.count('babyx.machine.exec'), 1);
});

test('stale leader process identity blocks machine execution before job submission', async (t) => {
  const f = fixture(t);
  const { started } = await createReady(f);
  const machineId = started.machine.machineId;
  f.setProcessStartTime('101');
  const current = f.service.store.get(machineId);
  await assert.rejects(
    () => f.service.exec(
      { machineId, expectedSequence: current.lifecycle.stateSequence, argv: ['/usr/bin/true'] },
      { idempotencyKey: 'exec-stale-leader', subject: 'owner:test', authorityClass: 'unrestricted-owner' },
    ),
    machineError('machine_process_conflict'),
  );
  assert.equal(f.jobs.count('babyx.machine.exec'), 0);
});

test('describe exposes the current checkpoint without claiming later lifecycle authority', (t) => {
  const f = fixture(t);
  const described = f.service.describe();
  assert.equal(described.checkpoint, 'H');
  assert.ok(described.operations.includes('babyx.machine.start'));
  assert.ok(described.operations.includes('babyx.machine.exec'));
  assert.equal(described.unavailableUntilLaterCheckpoints.includes('destroy'), false);
  assert.equal(described.unavailableUntilLaterCheckpoints.includes('reconcile'), false);
  assert.ok(described.operations.includes('babyx.machine.reconcile'));
  assert.ok(described.operations.includes('babyx.machine.diagnostics'));
  assert.equal(described.unavailableUntilLaterCheckpoints.includes('certify'), false);
  assert.equal(described.unavailableUntilLaterCheckpoints.includes('policy'), false);
  assert.equal(described.unavailableUntilLaterCheckpoints.includes('race'), false);
  assert.equal(described.unavailableUntilLaterCheckpoints.includes('start'), false);
});


test('the real durable JobManager preserves metadata, emits changes, and enforces timeout cancellation', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-real-jobs-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const jobs = new JobManager(root);
  const changes = [];
  jobs.onChange((record) => { changes.push({ id: record.id, status: record.status }); });

  const completedStart = jobs.start('babyx.machine.exec', {
    argv: ['/usr/bin/printf', '%s', 'job-output'], cwd: '/', target: { kind: 'host' },
    metadata: { machineService: true, machineId: 'mx_machine00000001' },
  });
  let completed = completedStart;
  for (let attempt = 0; attempt < 200 && completed.status === 'running'; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
    completed = jobs.get(completedStart.id);
  }
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(completed.status, 'completed');
  assert.equal(completed.metadata.machineId, 'mx_machine00000001');
  assert.equal(completed.exitCode, 0);
  assert.ok(changes.some((entry) => entry.id === completed.id && entry.status === 'running'));
  assert.ok(changes.some((entry) => entry.id === completed.id && entry.status === 'completed'));

  const timedStart = jobs.start('babyx.machine.exec', {
    argv: ['/usr/bin/bash', '-lc', 'sleep 5'], cwd: '/', target: { kind: 'host' }, timeoutMs: 20,
    metadata: { machineService: true, machineId: 'mx_machine00000001' },
  });
  let timed = timedStart;
  for (let attempt = 0; attempt < 400 && timed.status === 'running'; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
    timed = jobs.get(timedStart.id);
  }
  assert.equal(timed.status, 'failed');
  assert.equal(timed.signal, 'SIGTERM');
  assert.equal(timed.timeoutMs, 20);
});


test('stale expected source GUID remains durable and startup reconciliation cannot create a clone', async (t) => {
  const f = fixture(t);
  const request = machineRequest(f.machineRoot);
  request.source.expectedGuid = 'stale-guid';
  await assert.rejects(() => f.service.create(request, { ...createContext, idempotencyKey: 'create-stale-source-guid' }), machineError('machine_source_mismatch'));
  const record = f.service.store.get('mx_machine00000001');
  assert.equal(record.lifecycle.persistedState, 'REQUESTED');
  assert.equal(record.source.expectedSnapshotGuid, 'stale-guid');
  assert.equal(f.provider.dataset, null);
  const reconciled = await f.service.reconcile({ machineId: record.machineId, reason: 'restart after source mismatch' }, { idempotencyKey: 'reconcile-stale-source-guid', subject: 'owner:test', authorityClass: 'unrestricted-owner' });
  assert.equal(reconciled.results[0].classification, 'lost');
  assert.equal(f.service.store.get(record.machineId).lifecycle.persistedState, 'LOST');
  assert.equal(f.provider.dataset, null);
});

test('transaction adapter emits the strict machine execution contract and unknown fields remain rejected', async (t) => {
  const f = fixture(t);
  const { started } = await createReady(f);
  const record = makeRecord();
  const request = codeTransactionMachineExecutionRequest(
    record,
    started.machine,
    'mutation',
    'mutation-action-0',
    ['/usr/bin/printf', '%s', 'adapter-ok'],
    '/work',
    1_234,
  );

  assert.deepEqual(Object.keys(request).sort(), [
    'argv', 'artifactPolicy', 'cwd', 'env', 'expectedSequence', 'machineId', 'outputLimitBytes', 'reason', 'timeoutMs',
  ]);
  assert.equal('transactionBinding' in request, false);
  assert.equal(request.machineId, started.machine.machineId);
  assert.equal(request.expectedSequence, started.machine.lifecycle.stateSequence);
  assert.deepEqual(request.argv, ['/usr/bin/printf', '%s', 'adapter-ok']);
  assert.equal(request.cwd, '/work');
  assert.deepEqual(request.env, {});
  assert.equal(request.timeoutMs, 1_234);
  assert.equal(request.outputLimitBytes, record.code.mutationPlan.resourceBounds.outputLimitBytes);
  assert.deepEqual(request.artifactPolicy, { captureStreams: true });
  assert.match(request.reason, new RegExp(`${record.transactionId} mutation mutation-action-0`, 'u'));

  const accepted = await f.service.exec(request, {
    idempotencyKey: 'transaction-adapter-machine-exec-0001',
    subject: 'owner:test',
    authorityClass: 'unrestricted-owner',
  });
  assert.equal(typeof accepted.jobId, 'string');
  assert.equal(f.jobs.count('babyx.machine.exec'), 1);
  const job = f.jobs.get(accepted.jobId);
  assert.deepEqual(job.argv, request.argv);
  assert.equal(job.cwd, request.cwd);
  assert.equal(job.timeoutMs, request.timeoutMs);
  assert.equal(job.metadata.outputLimitBytes, request.outputLimitBytes);

  await assert.rejects(
    () => f.service.exec(
      { ...request, transactionBinding: { transactionId: record.transactionId } },
      { idempotencyKey: 'transaction-adapter-machine-exec-0002', subject: 'owner:test', authorityClass: 'unrestricted-owner' },
    ),
    (error) => error instanceof MachineServiceError
      && error.code === 'machine_invalid_request'
      && error.details.properties.includes('transactionBinding'),
  );
});
