import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createServer, connect } from 'node:net';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const require = createRequire(import.meta.url);

test('immutable release carries a working peer credential addon', async () => {
  const addon = require('../../dist/build/Release/peer_cred.node');
  assert.equal(typeof addon.getPeerCredentials, 'function');
  const temporary = mkdtempSync(join(tmpdir(), 'baby-x-peer-cred-'));
  const socketPath = join(temporary, 'peer.sock');
  const server = createServer();
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(socketPath, resolve);
    });
    const accepted = new Promise((resolve, reject) => {
      server.once('connection', (socket) => {
        try {
          const fd = socket._handle?.fd;
          assert.equal(typeof fd, 'number');
          const credential = addon.getPeerCredentials(fd);
          assert.equal(credential.uid, process.getuid());
          assert.equal(credential.gid, process.getgid());
          assert.equal(Number.isSafeInteger(credential.pid), true);
          socket.destroy();
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    });
    const client = connect(socketPath);
    await new Promise((resolve, reject) => {
      client.once('connect', resolve);
      client.once('error', reject);
    });
    await accepted;
    client.destroy();
  } finally {
    await new Promise((resolve) => server.close(() => resolve()));
    rmSync(temporary, { recursive: true, force: true });
  }
});

test('build report accounts for required native release artifacts', () => {
  const report = JSON.parse(readFileSync('dist/build-report.json', 'utf8'));
  assert.equal(report.peerCredentialAddon, 'built-and-copied');
  assert.equal(report.copiedNativeArtifacts >= 1, true);
});
