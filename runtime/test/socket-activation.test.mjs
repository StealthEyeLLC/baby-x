import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveRuntimeListenOptions, startRuntimeServer } from '../../dist/runtime/server.js';

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

test('runtime rejects a wrong peer without crashing the socket worker', async () => {
  const temporary = mkdtempSync(join(tmpdir(), 'baby-x-wrong-peer-'));
  const socketPath = join(temporary, 'runtime.sock');
  const stateRoot = join(temporary, 'state');
  const publicKeyPath = join(temporary, 'gateway-public.pem');
  const { publicKey } = generateKeyPairSync('ed25519');
  writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }));

  const names = ['BABY_X_SOCKET_PATH', 'BABY_X_STATE_ROOT', 'BABY_X_GATEWAY_UID', 'BABY_X_GATEWAY_PUBLIC_KEY', 'LISTEN_PID', 'LISTEN_FDS', 'LISTEN_FDNAMES'];
  const prior = new Map(names.map((name) => [name, process.env[name]]));
  process.env.BABY_X_SOCKET_PATH = socketPath;
  process.env.BABY_X_STATE_ROOT = stateRoot;
  process.env.BABY_X_GATEWAY_UID = String((process.getuid?.() ?? 0) + 1);
  process.env.BABY_X_GATEWAY_PUBLIC_KEY = publicKeyPath;
  delete process.env.LISTEN_PID;
  delete process.env.LISTEN_FDS;
  delete process.env.LISTEN_FDNAMES;

  const server = startRuntimeServer();
  try {
    await once(server, 'listening');
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const client = connect(socketPath);
      await once(client, 'close');
      assert.equal(server.listening, true);
    }
  } finally {
    await new Promise((resolve) => server.close(resolve));
    for (const [name, value] of prior) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    rmSync(temporary, { recursive: true, force: true });
  }
});
