import test from 'node:test';
import assert from 'node:assert/strict';
import { MachineManager } from '../../dist/runtime/machines/manager.js';

class RecordingExecutor {
  calls = [];
  async run(payload) {
    this.calls.push(payload);
    return { argv: payload.argv, target: payload.target ?? { kind: 'host' }, cwd: '/', startedAt: '', completedAt: '', durationMs: 0, exitCode: 0, signal: null, stdout: '', stderr: '', stdoutSha256: '', stderrSha256: '' };
  }
}

const definition = { name: 'arena-1', class: 'adversarial-arena', root: '/var/lib/machines/arena-template', imageKind: 'directory', properties: {} };

test('nspawn launch uses exact argv for root, binds, network and properties', async () => {
  const executor = new RecordingExecutor();
  const manager = new MachineManager(executor);
  await manager.launch({
    definition,
    privateNetwork: true,
    networkVeth: true,
    readOnly: true,
    binds: [{ source: '/srv/input', destination: '/work/input', readOnly: true }],
    environment: { CASE_ID: 'alpha beta' },
    properties: ['MemoryMax=2G'],
  });
  assert.deepEqual(executor.calls[0].argv, [
    '/usr/bin/systemd-nspawn', '--quiet', '--machine=arena-1', '--directory=/var/lib/machines/arena-template', '--boot', '--private-network', '--network-veth', '--read-only', '--bind-ro=/srv/input:/work/input', '--setenv=CASE_ID=alpha beta', '--property=MemoryMax=2G', '--',
  ]);
});

test('machine execution delegates through typed machine target', async () => {
  const executor = new RecordingExecutor();
  const manager = new MachineManager(executor);
  await manager.shell('arena-1', ['/usr/bin/printf', '%s', 'x;$(false)']);
  assert.deepEqual(executor.calls[0].target, { kind: 'machine', machine: 'arena-1' });
  assert.deepEqual(executor.calls[0].argv, ['/usr/bin/printf', '%s', 'x;$(false)']);
});

test('machine lifecycle and copy operations reject option injection', async () => {
  const manager = new MachineManager(new RecordingExecutor());
  await assert.rejects(() => manager.lifecycle('terminate', '--all'), /machine name/);
  await assert.rejects(() => manager.copyIn('arena-1', 'relative', '/tmp/x'), /absolute/);
  await assert.rejects(() => manager.launch({ definition: { ...definition, root: 'relative' } }), /absolute/);
});

test('adoption parses machinectl show properties without claiming readiness', async () => {
  const executor = new RecordingExecutor();
  executor.run = async function (payload) {
    this.calls.push(payload);
    return { argv: payload.argv, target: { kind: 'host' }, cwd: '/', startedAt: '', completedAt: '', durationMs: 0, exitCode: 0, signal: null, stdout: 'Name=arena-1\nState=running\nLeader=123\n', stderr: '', stdoutSha256: '', stderrSha256: '' };
  };
  const result = await new MachineManager(executor).adopt('arena-1');
  assert.equal(result.found, true);
  assert.equal(result.properties.State, 'running');
  assert.equal(result.properties.Leader, '123');
});
