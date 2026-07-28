import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { RootProviderClient } from '../../dist/runtime/root-platform/microvm/provider-client.js';
import { resolveProviderListenOptions, startRootProviderServer } from '../../dist/runtime/root-platform/microvm/provider-server.js';

const fakeProvider = {
  describe() { return { providerId: 'fake-microvm-provider', supportState: 'SUPPORTED' }; },
};

async function close(server) {
  if (!server.listening) return;
  server.close();
  await once(server, 'close');
}

test('root provider socket activation environment is strict', () => {
  assert.deepEqual(resolveProviderListenOptions('/tmp/provider.sock', {}, 42), { path: '/tmp/provider.sock' });
  assert.deepEqual(resolveProviderListenOptions('/tmp/provider.sock', { LISTEN_PID: '42', LISTEN_FDS: '1' }, 42), { fd: 3 });
  assert.throws(() => resolveProviderListenOptions('/tmp/provider.sock', { LISTEN_PID: '42' }, 42), /invalid root provider socket activation environment/u);
  assert.throws(() => resolveProviderListenOptions('/tmp/provider.sock', { LISTEN_PID: '41', LISTEN_FDS: '1' }, 42), /invalid root provider socket activation environment/u);
  assert.throws(() => resolveProviderListenOptions('/tmp/provider.sock', { LISTEN_PID: '42', LISTEN_FDS: '2' }, 42), /invalid root provider socket activation environment/u);
});

test('root provider socket accepts the authorized peer and rejects a wrong uid', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-provider-socket-'));
  const authorizedPath = join(root, 'authorized.sock');
  const deniedPath = join(root, 'denied.sock');
  const authorized = startRootProviderServer(fakeProvider, { socketPath: authorizedPath, allowedUid: process.getuid(), listen: { path: authorizedPath } });
  const denied = startRootProviderServer(fakeProvider, { socketPath: deniedPath, allowedUid: process.getuid() + 1, listen: { path: deniedPath } });
  try {
    await Promise.all([once(authorized, 'listening'), once(denied, 'listening')]);
    const context = { subject: 'owner:socket-test', authorityClass: 'unrestricted-owner', idempotencyKey: 'socket-describe-0001' };
    const described = await new RootProviderClient(authorizedPath).call('describe', {}, context, 2_000);
    assert.equal(described.providerId, 'fake-microvm-provider');
    await assert.rejects(() => new RootProviderClient(deniedPath).call('describe', {}, context, 2_000), (error) => error.code === 'microvm_provider_unavailable');
  } finally {
    await Promise.all([close(authorized), close(denied)]);
    rmSync(root, { recursive: true, force: true });
  }
});
