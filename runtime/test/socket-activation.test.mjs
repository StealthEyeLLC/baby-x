import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveRuntimeListenOptions } from '../../dist/runtime/server.js';

test('runtime binds its configured path outside systemd socket activation', () => {
  assert.deepEqual(resolveRuntimeListenOptions('/run/horsey/baby-x.sock', {}, 4100), { path: '/run/horsey/baby-x.sock' });
});

test('runtime adopts exactly the one descriptor provided by systemd', () => {
  assert.deepEqual(
    resolveRuntimeListenOptions('/run/horsey/baby-x.sock', { LISTEN_PID: '4100', LISTEN_FDS: '1' }, 4100),
    { fd: 3 },
  );
});

test('runtime rejects ambiguous or foreign socket activation state', () => {
  assert.throws(
    () => resolveRuntimeListenOptions('/run/horsey/baby-x.sock', { LISTEN_PID: '4100' }, 4100),
    /incomplete systemd socket activation environment/u,
  );
  assert.throws(
    () => resolveRuntimeListenOptions('/run/horsey/baby-x.sock', { LISTEN_PID: 'not-a-pid', LISTEN_FDS: '1' }, 4100),
    /invalid systemd socket activation environment/u,
  );
  assert.throws(
    () => resolveRuntimeListenOptions('/run/horsey/baby-x.sock', { LISTEN_PID: '4101', LISTEN_FDS: '1' }, 4100),
    /systemd socket activation pid mismatch/u,
  );
  assert.throws(
    () => resolveRuntimeListenOptions('/run/horsey/baby-x.sock', { LISTEN_PID: '4100', LISTEN_FDS: '2' }, 4100),
    /exactly one systemd socket is required/u,
  );
});
