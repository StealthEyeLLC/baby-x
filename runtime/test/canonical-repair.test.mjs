import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime, FileManager, JobManager, sha256 } from '../../dist/runtime/core.js';

test('spec validation rejects malformed statements and accepts complete statements', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-spec-repair-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const invalid = await runtime.execute('babyx.spec.validate', { statement: { classification: 'hypothesis' } });
    assert.equal(invalid.valid, false);
    assert.ok(Array.isArray(invalid.errors));
    assert.ok(invalid.errors.length >= 4);
    const statement = {
      id: 'statement-1',
      classification: 'observed-invariant',
      subject: 'baby-x',
      predicate: 'gate-status',
      value: 'pass',
      provenance: [{ operation: 'test', timestamp: new Date().toISOString() }],
      confidence: 1,
    };
    const valid = await runtime.execute('babyx.spec.validate', { statement });
    assert.equal(valid.valid, true);
    assert.deepEqual(valid.errors, []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('job wait blocks until terminal state instead of aliasing get', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-wait-repair-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const job = runtime.jobs.start('test', { argv: ['/usr/bin/bash', '-lc', 'sleep 0.1; exit 0'] });
    const started = Date.now();
    const terminal = await runtime.execute('babyx.job.wait', { jobId: job.id, timeoutMs: 5_000 });
    assert.equal(terminal.status, 'completed');
    assert.ok(Date.now() - started >= 50);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('job reservation is durable before a failed spawn can escape', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-spawn-repair-'));
  try {
    const manager = new JobManager(root);
    assert.throws(() => manager.start('test', { argv: ['/definitely/not/a/real/executable'] }), /spawn returned no pid/u);
    const records = manager.list();
    assert.equal(records.length, 1);
    assert.equal(records[0].status, 'failed');
    assert.ok(records[0].completedAt);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('cancellation preserves terminal immutability', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-cancel-terminal-'));
  try {
    const manager = new JobManager(root);
    const job = manager.start('test', { argv: ['/usr/bin/true'] });
    const terminal = await manager.wait(job.id, 5_000);
    assert.equal(terminal.status, 'completed');
    const replay = manager.cancel(job.id, 'SIGTERM');
    assert.equal(replay.status, 'completed');
    assert.equal(replay.completedAt, terminal.completedAt);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('binary patch is compare-and-swap and atomic at exact offsets', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-patch-repair-'));
  try {
    const files = new FileManager();
    const path = join(root, 'value.bin');
    files.replace({ path, data: Buffer.from('abcdef').toString('base64'), encoding: 'base64' });
    const expectedSha256 = sha256(readFileSync(path));
    files.patch({ path, expectedSha256, patches: [{ offset: 2, data: Buffer.from('ZZ').toString('base64'), encoding: 'base64' }] });
    assert.equal(readFileSync(path, 'utf8'), 'abZZef');
    assert.throws(() => files.patch({ path, expectedSha256, patches: [{ offset: 0, data: 'x' }] }), /compare-and-swap mismatch/u);
    assert.throws(() => files.patch({ path, patches: [{ offset: 0, data: 'x' }] }), /expectedSha256/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('catalog and dispatcher agree on artifact verification and machine authority', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-catalog-repair-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const names = runtime.describe().operations.map((definition) => definition.operation);
    assert.equal(new Set(names).size, names.length);
    assert.ok(names.includes('babyx.artifact.verify'));
    for (const operation of ['babyx.machine.raw', 'babyx.machine.clone', 'babyx.machine.network.set', 'babyx.pty.create', 'babyx.artifact.begin']) assert.equal(names.includes(operation), false);
    await assert.rejects(() => runtime.execute('babyx.machine.raw', {}), /unknown operation/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
