import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileManager, JobManager } from '../../dist/runtime/core.js';

async function waitFor(manager, id, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const record = manager.get(id);
    if (record.status !== 'running') return record;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error('job did not terminate');
}

test('files are binary safe, atomically replaceable, and digest readable', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-file-'));
  try {
    const files = new FileManager();
    const path = join(root, 'nested', 'value.bin');
    const initial = Buffer.from([0, 255, 1, 2]);
    files.replace({ path, data: initial.toString('base64'), encoding: 'base64' });
    const metadata = files.stat({ path });
    assert.equal(metadata.size, initial.length);
    const read = files.read({ path, encoding: 'base64' });
    assert.deepEqual(Buffer.from(read.data, 'base64'), initial);
    assert.throws(() => files.replace({ path, data: 'changed', expectedSha256: '0'.repeat(64) }), /compare-and-swap/u);
    files.remove({ path });
    assert.throws(() => files.stat({ path }));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('durable detached jobs stream exact stdout and support process-group cancellation', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-job-'));
  try {
    const manager = new JobManager(root);
    const completed = manager.start('test', { argv: ['/usr/bin/bash', '-lc', 'printf out; printf err >&2'] });
    const final = await waitFor(manager, completed.id);
    assert.equal(final.status, 'completed');
    assert.equal(Buffer.from(manager.read(completed.id, 'stdout').data, 'base64').toString(), 'out');
    assert.equal(Buffer.from(manager.read(completed.id, 'stderr').data, 'base64').toString(), 'err');
    const sleeping = manager.start('test', { argv: ['/usr/bin/bash', '-lc', 'sleep 30'] });
    manager.cancel(sleeping.id, 'SIGTERM');
    assert.equal(manager.get(sleeping.id).status, 'cancelled');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
