import test from 'node:test';
import assert from 'node:assert/strict';
import { SystemdManager } from '../../dist/runtime/systemd/manager.js';

class RecordingExecutor {
  calls = [];
  async run(payload) {
    this.calls.push(payload);
    return { argv: payload.argv, target: payload.target, cwd: '/', startedAt: '', completedAt: '', durationMs: 0, exitCode: 0, signal: null, stdout: '', stderr: '', stdoutSha256: '', stderrSha256: '' };
  }
}

test('systemd manager builds exact host and machine commands without shell interpolation', async () => {
  const executor = new RecordingExecutor();
  const manager = new SystemdManager(executor);
  await manager.action('restart', { unit: 'example@alpha.service', target: { kind: 'machine', machine: 'arena-1' } });
  assert.deepEqual(executor.calls[0].argv, ['/usr/bin/systemctl', '--system', '--no-pager', 'restart', '--', 'example@alpha.service']);
  assert.deepEqual(executor.calls[0].target, { kind: 'machine', machine: 'arena-1' });
});

test('systemd manager validates unit and property inputs', async () => {
  const manager = new SystemdManager(new RecordingExecutor());
  await assert.rejects(() => manager.show({ unit: '--root=/tmp' }), /unit/);
  await assert.rejects(() => manager.show({ unit: 'ok.service', properties: ['Bad-Property'] }), /property/);
  await assert.rejects(() => manager.kill({ unit: 'ok.service', signal: 'TERM' }), /signal/);
});

test('systemd-run preserves exact argv and explicit properties', async () => {
  const executor = new RecordingExecutor();
  const manager = new SystemdManager(executor);
  await manager.run({ argv: ['/usr/bin/printf', '%s', 'a b;$(false)'], unit: 'babyx-probe.service', properties: { DynamicUser: 'yes', PrivateTmp: 'yes' } });
  const argv = executor.calls[0].argv;
  assert.deepEqual(argv.slice(-4), ['--', '/usr/bin/printf', '%s', 'a b;$(false)']);
  assert.ok(argv.includes('--property=DynamicUser=yes'));
  assert.ok(argv.includes('--property=PrivateTmp=yes'));
});

test('journal reads are bounded and machine-targetable', async () => {
  const executor = new RecordingExecutor();
  const manager = new SystemdManager(executor);
  await manager.logs({ unit: 'baby-x.service', lines: 42, since: '-5 min', target: { kind: 'machine', machine: 'build-1' } });
  assert.deepEqual(executor.calls[0].argv, ['/usr/bin/journalctl', '--no-pager', '--output=json-seq', '--unit', 'baby-x.service', '--lines', '42', '--since', '-5 min']);
  await assert.rejects(() => manager.logs({ unit: 'x.service', lines: 100001 }), /lines/);
});
