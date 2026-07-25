import test from 'node:test';
import assert from 'node:assert/strict';
import { DisposableMachineManager } from '../../dist/runtime/machines/disposable.js';

class RecordingExecutor {
  calls = [];
  async run(payload) {
    this.calls.push(payload);
    const argv = payload.argv;
    const isAbsentDataset = argv[0] === '/usr/sbin/zfs' && argv[1] === 'list';
    const isUnmounted = argv[0] === '/usr/bin/mountpoint';
    return {
      argv,
      target: payload.target ?? { kind: 'host' },
      cwd: '/', startedAt: '', completedAt: '', durationMs: 0,
      exitCode: isAbsentDataset || isUnmounted ? 1 : 0,
      signal: null, stdout: '', stderr: '', stdoutSha256: '', stderrSha256: '',
    };
  }
}

test('disposable machine composes ZFS clone, nspawn launch, machine exec and verified cleanup', async () => {
  const executor = new RecordingExecutor();
  const manager = new DisposableMachineManager(executor);
  const created = await manager.create({
    id: 'race-1',
    baseSnapshot: 'babycert/base/noble@golden-v1',
    dataset: 'babycert/runs/race-1',
    root: '/var/lib/baby-x/machines/race-1',
  });
  assert.equal(created.state, 'created');
  assert.deepEqual(executor.calls[0].argv, ['/usr/sbin/zfs', 'clone', '-o', 'mountpoint=/var/lib/baby-x/machines/race-1', 'babycert/base/noble@golden-v1', 'babycert/runs/race-1']);

  const running = await manager.launch(created, { boot: false, extraArgs: ['/bin/true'] });
  assert.equal(running.state, 'running');
  assert.deepEqual(executor.calls[1].argv, ['/usr/bin/systemd-nspawn', '--quiet', '--machine=race-1', '--directory=/var/lib/baby-x/machines/race-1', '/bin/true']);

  await manager.exec('race-1', ['/usr/bin/printf', '%s', 'ok']);
  assert.deepEqual(executor.calls[2].target, { kind: 'machine', machine: 'race-1' });

  const cleanup = await manager.destroy(running);
  assert.equal(cleanup.clean, true);
  assert.deepEqual(executor.calls.slice(-5).map((call) => call.argv.slice(0, 2)), [
    ['/usr/bin/machinectl', 'terminate'],
    ['/usr/bin/umount', '-l'],
    ['/usr/sbin/zfs', 'destroy'],
    ['/usr/sbin/zfs', 'list'],
    ['/usr/bin/mountpoint', '-q'],
  ]);
});

test('disposable machine rejects option injection in identities and relative roots', async () => {
  const manager = new DisposableMachineManager(new RecordingExecutor());
  await assert.rejects(() => manager.create({ id: '--all', baseSnapshot: 'pool/base@snap', dataset: 'pool/run', root: '/tmp/run' }), /id/);
  await assert.rejects(() => manager.create({ id: 'ok', baseSnapshot: 'pool/base@snap', dataset: 'pool/run', root: 'relative' }), /absolute/);
});
