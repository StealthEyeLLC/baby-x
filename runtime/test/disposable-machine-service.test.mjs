import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DisposableMachineService } from '../../dist/runtime/machines/service.js';
import { MachineServiceError } from '../../dist/runtime/machines/errors.js';
import { OPERATION_DEFINITIONS } from '../../dist/runtime/operations/definitions.js';

function result(argv, exitCode = 0, stdout = '', stderr = '') {
  return {
    argv, target: { kind: 'host' }, cwd: '/', startedAt: '2026-07-25T12:00:00.000Z', completedAt: '2026-07-25T12:00:00.001Z',
    durationMs: 1, exitCode, signal: null,
    stdout: Buffer.from(stdout).toString('base64'), stderr: Buffer.from(stderr).toString('base64'),
    stdoutSha256: 'a'.repeat(64), stderrSha256: 'b'.repeat(64),
  };
}

class FakeMachineExecutor {
  calls = [];
  dataset = null;
  sourceMissing = false;
  sourceUnknown = false;
  foreignDataset = false;
  cloneFailure = false;
  readbackMismatch = false;
  machineUnknown = false;

  constructor(root) { this.root = root; }

  async run(payload) {
    const argv = payload.argv;
    this.calls.push(argv);
    if (argv[0] === '/usr/sbin/zfs' && argv[1] === 'get' && argv.at(-1).includes('@')) {
      if (this.sourceMissing) return result(argv, 1, '', 'dataset does not exist');
      if (this.sourceUnknown) return result(argv, 1, '', 'permission denied');
      return result(argv, 0, 'guid\t111222333\ncreatetxg\t444555\n');
    }
    if (argv[0] === '/usr/sbin/zfs' && argv[1] === 'get') {
      if (this.foreignDataset && this.dataset === null) {
        return result(argv, 0, `guid\t999\norigin\tpool/other@snap\nmountpoint\t${this.root}\ncom.stealtheye.babyx:machine-id\tmx_foreign0001\n`);
      }
      if (this.dataset === null) return result(argv, 1, '', 'dataset does not exist');
      const properties = { ...this.dataset.properties };
      if (this.readbackMismatch) properties['com.stealtheye.babyx:request-digest'] = '0'.repeat(64);
      return result(argv, 0, [
        `guid\t${this.dataset.guid}`,
        `origin\t${this.dataset.origin}`,
        `mountpoint\t${this.dataset.mountpoint}`,
        ...Object.entries(properties).map(([name, value]) => `${name}\t${value}`),
      ].join('\n') + '\n');
    }
    if (argv[0] === '/usr/sbin/zfs' && argv[1] === 'clone') {
      if (this.cloneFailure) return result(argv, 2, '', 'clone failed');
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
      return result(argv);
    }
    if (argv[0] === '/usr/bin/machinectl') return this.machineUnknown ? result(argv, 1, '', 'bus unavailable') : result(argv, 1, '', 'no such machine');
    throw new Error(`unexpected argv: ${JSON.stringify(argv)}`);
  }
}

function fixture(t, overrides = {}) {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-service-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const machineRoot = join(root, 'machines');
  mkdirSync(machineRoot, { recursive: true });
  const executor = new FakeMachineExecutor(join(machineRoot, 'machine-1'));
  Object.assign(executor, overrides);
  let next = 1;
  const service = new DisposableMachineService({
    stateRoot: root,
    executor,
    config: { sourceSnapshotRoots: ['pool/base'], cloneDatasetRoots: ['pool/runs'], machineRoot, defaultListLimit: 2, maximumListLimit: 3, maximumEventLimit: 5 },
    now: () => `2026-07-25T12:00:0${next++}.000Z`,
    machineIdFactory: () => 'mx_machine00000001',
    hostIdentity: { hostname: 'test-host', machineIdSha256: '1'.repeat(64), bootId: 'boot-1' },
  });
  return { root, machineRoot, executor, service };
}

function request(machineRoot, overrides = {}) {
  return {
    schemaVersion: '1.0.0', machineName: 'machine-1', ownerPrincipal: 'owner:test', parentObjectiveId: 'objective-1',
    source: { kind: 'zfs-snapshot', snapshot: 'pool/base/noble@golden-v1', expectedGuid: '111222333' },
    clone: { dataset: 'pool/runs/machine-1', mountpoint: join(machineRoot, 'machine-1'), expectedRootPrefix: machineRoot },
    launch: {
      boot: true, networkMode: 'none', readOnlyRoot: false, binds: [],
      environment: [{ name: 'TOKEN', secretReference: 'secret:test-token', redacted: true }], properties: [],
    },
    ...overrides,
  };
}

const context = { idempotencyKey: 'create-machine-1', subject: 'owner:test', authorityClass: 'unrestricted-owner' };
const machineError = (code) => (error) => error instanceof MachineServiceError && error.code === code;

test('create persists intent, uses exact ownership argv, verifies readback, and replays without provider mutation', async (t) => {
  const { service, executor, machineRoot } = fixture(t);
  const created = await service.create(request(machineRoot), context);
  assert.equal(created.machine.machineId, 'mx_machine00000001');
  assert.equal(created.machine.lifecycle.persistedState, 'CLONED');
  assert.equal(created.machine.lifecycle.stateSequence, 3);
  assert.equal(created.machine.source.snapshotGuid, '111222333');
  assert.equal(created.machine.clone.datasetGuid, '777888999');
  assert.equal(created.machine.launch.environment[0].value, undefined);
  assert.equal(created.machine.launch.environment[0].secretReference, 'secret:test-token');
  const cloneArgv = executor.calls.find((argv) => argv[0] === '/usr/sbin/zfs' && argv[1] === 'clone');
  assert.deepEqual(cloneArgv.slice(0, 4), ['/usr/sbin/zfs', 'clone', '-o', `mountpoint=${join(machineRoot, 'machine-1')}`]);
  assert.equal(cloneArgv.at(-2), 'pool/base/noble@golden-v1');
  assert.equal(cloneArgv.at(-1), 'pool/runs/machine-1');
  assert.ok(cloneArgv.includes('com.stealtheye.babyx:machine-id=mx_machine00000001'));
  assert.ok(cloneArgv.includes('com.stealtheye.babyx:provider=zfs-nspawn-disposable@1'));
  const callCount = executor.calls.length;
  const replay = await service.create(request(machineRoot), context);
  assert.equal(replay.replayed, true);
  assert.equal(replay.machine.machineId, 'mx_machine00000001');
  assert.equal(executor.calls.length, callCount);
});

test('idempotency key reuse with a different normalized request is rejected', async (t) => {
  const { service, machineRoot } = fixture(t);
  await service.create(request(machineRoot), context);
  const changed = request(machineRoot, { parentObjectiveId: 'objective-2' });
  await assert.rejects(() => service.create(changed, context), machineError('machine_idempotency_conflict'));
});

test('missing or unavailable source snapshot never invokes clone', async (t) => {
  const missing = fixture(t, { sourceMissing: true });
  await assert.rejects(() => missing.service.create(request(missing.machineRoot), context), machineError('machine_source_not_found'));
  assert.equal(missing.executor.calls.some((argv) => argv[1] === 'clone'), false);
  assert.equal(missing.service.store.list()[0].lifecycle.persistedState, 'REQUESTED');

  const unknown = fixture(t, { sourceUnknown: true });
  await assert.rejects(() => unknown.service.create(request(unknown.machineRoot), context), machineError('machine_provider_unavailable'));
  assert.equal(unknown.executor.calls.some((argv) => argv[1] === 'clone'), false);
});

test('pre-existing foreign dataset becomes explicit AMBIGUOUS and is never adopted', async (t) => {
  const { service, executor, machineRoot } = fixture(t, { foreignDataset: true });
  await assert.rejects(() => service.create(request(machineRoot), context), machineError('machine_identity_ambiguous'));
  assert.equal(executor.calls.some((argv) => argv[1] === 'clone'), false);
  const durable = service.store.list()[0];
  assert.equal(durable.lifecycle.persistedState, 'AMBIGUOUS');
  assert.equal(durable.observations.dataset, 'present-conflict');
});

test('clone failure and zero-exit readback mismatch remain explicit failures', async (t) => {
  const failed = fixture(t, { cloneFailure: true });
  await assert.rejects(() => failed.service.create(request(failed.machineRoot), context), machineError('machine_clone_failed'));
  assert.equal(failed.service.store.list()[0].lifecycle.persistedState, 'CLONING');

  const mismatch = fixture(t, { readbackMismatch: true });
  await assert.rejects(() => mismatch.service.create(request(mismatch.machineRoot), context), machineError('machine_readback_mismatch'));
  assert.equal(mismatch.service.store.list()[0].lifecycle.persistedState, 'CLONING');
});

test('strict validation rejects option injection, untrusted roots, unknown properties, and premature start', async (t) => {
  const { service, machineRoot } = fixture(t);
  await assert.rejects(() => service.create(request(machineRoot, { machineName: '--all' }), context), machineError('machine_invalid_request'));
  await assert.rejects(() => service.create(request(machineRoot, { clone: { dataset: 'pool/foreign/machine', mountpoint: join(machineRoot, 'machine-1'), expectedRootPrefix: machineRoot } }), context), machineError('machine_dataset_conflict'));
  await assert.rejects(() => service.create(request(machineRoot, { clone: { dataset: 'pool/runs', mountpoint: join(machineRoot, 'machine-1'), expectedRootPrefix: machineRoot } }), context), machineError('machine_dataset_conflict'));
  await assert.rejects(() => service.create({ ...request(machineRoot), unsupported: true }, context), machineError('machine_invalid_request'));
  await assert.rejects(() => service.create({ ...request(machineRoot), startImmediately: true }, context), machineError('machine_invalid_request'));
});

test('get, bounded list, events, and truthful status expose the canonical service surface', async (t) => {
  const { service, executor, machineRoot } = fixture(t);
  await service.create(request(machineRoot), context);
  assert.equal(service.get({ machineId: 'mx_machine00000001' }, context).machine.machineName, 'machine-1');
  assert.equal(service.get({ machineName: 'machine-1' }, context).machine.machineId, 'mx_machine00000001');
  const listed = service.list({ ownerPrincipal: 'owner:test', providerId: 'zfs-nspawn-disposable@1', createdAfter: '2026-07-25T11:00:00.000Z', createdBefore: '2026-07-25T13:00:00.000Z', terminal: false, limit: 1 }, context);
  assert.equal(listed.total, 1);
  assert.equal(listed.machines.length, 1);
  assert.throws(() => service.list({ limit: 4 }, context), machineError('machine_invalid_request'));
  const events = service.events({ machineId: 'mx_machine00000001', limit: 5 }, context);
  assert.deepEqual(events.events.map((event) => event.stateSequence), [1, 2, 3]);
  assert.throws(() => service.get({ machineName: 'machine-1' }, { subject: 'owner:other', authorityClass: 'owner' }), machineError('machine_not_found'));
  assert.throws(() => service.list({ ownerPrincipal: 'owner:other' }, { subject: 'owner:test', authorityClass: 'owner' }), machineError('machine_not_found'));
  const status = await service.status({ machineId: 'mx_machine00000001', includeJobs: true, includeRecentEvents: true }, context);
  assert.equal(status.observed.state, 'CLONE_ONLY');
  assert.equal(status.observed.observations.dataset, 'present-matching');
  assert.deepEqual(status.jobs, { activeJobIds: [], protectedJobIds: [] });
  assert.equal(status.recentEvents.length, 3);
  executor.dataset.properties['com.stealtheye.babyx:owner-principal'] = 'owner:other';
  const conflict = await service.status({ machineId: 'mx_machine00000001', includeJobs: true, includeRecentEvents: true }, context);
  assert.equal(conflict.observed.state, 'CONFLICT');
  assert.match(conflict.recommendedAction, /manual identity review/u);
  executor.dataset.properties['com.stealtheye.babyx:owner-principal'] = 'owner:test';
  executor.machineUnknown = true;
  const unknown = await service.status({ machineId: 'mx_machine00000001', includeJobs: true, includeRecentEvents: true }, context);
  assert.equal(unknown.observed.state, 'UNKNOWN');
});

test('machine event and status catalog entries are read-only', () => {
  const definitions = new Map(OPERATION_DEFINITIONS.map((definition) => [definition.operation, definition]));
  assert.equal(definitions.get('babyx.machine.events').mutation, false);
  assert.equal(definitions.get('babyx.machine.status').mutation, false);
});
