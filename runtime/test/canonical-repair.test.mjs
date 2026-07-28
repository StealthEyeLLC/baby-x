import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime, FileManager, JobManager, sha256 } from '../../dist/runtime/core.js';
import { appendBoundedRuntimeFrameChunk } from '../../dist/runtime/server.js';
import { ArtifactManager } from '../../dist/runtime/artifacts/manager.js';
import { DurableRecordStore } from '../../dist/runtime/storage/record-store.js';

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


test('runtime frame accumulation rejects oversized chunks and declared frames before concatenation', () => {
  assert.throws(() => appendBoundedRuntimeFrameChunk(Buffer.alloc(0), Buffer.alloc(33), 24), /exceeds configured maximum/u);
  const header = Buffer.alloc(8);
  header.write('QRT1', 0);
  header.writeUInt32BE(25, 4);
  assert.throws(() => appendBoundedRuntimeFrameChunk(Buffer.alloc(0), header, 24), /exceeds configured maximum/u);
  const partial = appendBoundedRuntimeFrameChunk(Buffer.alloc(0), Buffer.from('QRT1'), 24);
  assert.equal(partial.length, 4);
});


test('public operation definitions expose finite honest execution contracts', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-contract-repair-'));
  try {
    const description = new BabyXRuntime({ stateRoot: root }).describe();
    assert.equal(description.operationCatalogVersion, '3.2.0');
    assert.match(description.operationCatalogSha256, /^[a-f0-9]{64}$/u);
    for (const definition of description.operations) {
      assert.equal(definition.input.type, 'object');
      assert.equal(definition.input.additionalProperties, false);
      assert.ok(definition.risk);
      assert.ok(definition.idempotency);
      assert.ok(definition.cancellation);
      assert.ok(definition.restartBehavior);
      assert.equal(typeof definition.postActionVerification, 'boolean');
      assert.ok(definition.errors.length >= 2);
      assert.ok(definition.postconditions.length >= 1);
      assert.equal(definition.limits.maxFrameBytes, 16_777_216);
      assert.equal(definition.authority.provider, 'baby-x-runtime');
    }
    const patch = description.operations.find((definition) => definition.operation === 'babyx.file.patch');
    assert.deepEqual(patch.input.required, ['path', 'expectedSha256', 'patches']);
    const wait = description.operations.find((definition) => definition.operation === 'babyx.job.wait');
    assert.deepEqual(wait.input.required, ['jobId']);
    assert.equal(wait.idempotency, 'read_only');
    const machineCreate = description.operations.find((definition) => definition.operation === 'babyx.machine.create');
    assert.equal(machineCreate.idempotency, 'caller_key');
    assert.equal(machineCreate.restartBehavior, 'durable_reconcile');
  } finally { rmSync(root, { recursive: true, force: true }); }
});


test('generic machine provider cannot bypass DisposableMachineService', () => {
  const source = readFileSync(new URL('../src/core.ts', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /if \(family === 'machine'\).*machinectl/su);
  assert.equal((source.match(/\/usr\/bin\/machinectl/gu) ?? []).length, 1);
});

test('generic object listings are deterministic and paginated', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-object-page-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    await runtime.execute('babyx.campaign.create', { id: 'campaign-c', name: 'c' });
    await runtime.execute('babyx.campaign.create', { id: 'campaign-a', name: 'a' });
    await runtime.execute('babyx.campaign.create', { id: 'campaign-b', name: 'b' });
    const page = await runtime.execute('babyx.campaign.list', { offset: 1, limit: 1 });
    assert.deepEqual(page.objects.map((value) => value.id), ['campaign-b']);
    assert.equal(page.total, 3);
    assert.equal(page.offset, 1);
    assert.equal(page.limit, 1);
    assert.equal(page.nextOffset, 2);
    await assert.rejects(() => runtime.execute('babyx.campaign.list', { limit: 1_001 }), /limit must be between 1 and 1000/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('artifact writes are durable and artifact reads are bounded and paginated', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-artifact-page-'));
  try {
    const manager = new ArtifactManager(root);
    const records = [manager.begin('c'), manager.begin('a'), manager.begin('b')];
    const sorted = [...records].sort((left, right) => String(left.id).localeCompare(String(right.id)));
    assert.deepEqual(manager.list(1, 1).map((value) => value.id), [sorted[1].id]);
    assert.equal(manager.count(), 3);
    assert.throws(() => manager.list(0, 1_001), /limit must be between 1 and 1000/u);
    assert.throws(() => manager.upload(String(records[0].id), -1, Buffer.from('x')), /non-negative safe integer/u);
    const bytes = Buffer.from('artifact-bytes');
    manager.upload(String(records[0].id), 0, bytes);
    const finalized = manager.finalize(String(records[0].id), bytes.length, sha256(bytes));
    assert.equal(finalized.state, 'finalized');
    assert.throws(() => manager.download(String(records[0].id), -1, 1), /non-negative safe integer/u);
    assert.throws(() => manager.download(String(records[0].id), 0, 65_537), /between 0 and 65536/u);
    const downloaded = manager.download(String(records[0].id), 0, 4);
    assert.equal(Buffer.from(downloaded.data, 'base64').toString('utf8'), 'arti');
    assert.equal(downloaded.eof, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});


test('durable record scans isolate a corrupt record without hiding healthy records', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-record-isolation-'));
  try {
    const store = new DurableRecordStore(root);
    assert.equal(store.create('good-a', { id: 'good-a', value: 1 }), true);
    assert.equal(store.create('bad', { id: 'bad', value: 2 }), true);
    assert.equal(store.create('good-b', { id: 'good-b', value: 3 }), true);
    writeFileSync(join(root, 'records', 'bad.json'), '{not-json', 'utf8');
    const page = store.scan(() => true, 0, 10);
    assert.deepEqual(page.records.map((record) => record.id), ['good-a', 'good-b']);
    assert.deepEqual(page.corruptRecordIds, ['bad']);
    assert.equal(page.total, 2);
    assert.throws(() => store.get('bad'), /corrupt/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('artifact metadata listing isolates one corrupt record and remains bounded', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-artifact-isolation-'));
  try {
    const manager = new ArtifactManager(root);
    const first = manager.begin('first');
    const corrupt = manager.begin('corrupt');
    const third = manager.begin('third');
    writeFileSync(join(root, 'record-store-v1', 'records', `${corrupt.id}.json`), '{broken', 'utf8');
    const page = manager.listPage(0, 10);
    assert.deepEqual(new Set(page.artifacts.map((record) => record.id)), new Set([first.id, third.id]));
    assert.deepEqual(page.corruptRecordIds, [corrupt.id]);
    assert.equal(page.total, 2);
    assert.throws(() => manager.listPage(0, 1_001), /limit must be between 1 and 1000/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});


test('canonical documents defer generated facts and duplicate facades are absent', () => {
  const operations = readFileSync('docs/OPERATIONS.md', 'utf8');
  const truth = readFileSync('docs/CANONICAL-TRUTH.md', 'utf8');
  const constitution = readFileSync('docs/BABY-X-CONSTITUTION.md', 'utf8');
  assert.match(operations, /runtime\/src\/operations\/definitions\.ts/u);
  assert.match(operations, /Legacy direct `machinectl` catalog entries/u);
  assert.match(truth, /Runtime source and strict validators/u);
  assert.match(truth, /HELD_BRANCH_ONLY/u);
  assert.match(constitution, /Disposable machine lifecycle belongs only to `DisposableMachineService`/u);
  for (const facade of [
    'runtime/src/battleground/manager.ts',
    'runtime/src/specification/observer.ts',
    'runtime/src/specification/scanner.ts',
    'runtime/src/specification/store.ts',
  ]) assert.equal(existsSync(facade), false);
});


test('failed record serialization removes its temporary file', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-record-temp-cleanup-'));
  try {
    const store = new DurableRecordStore(root);
    const cyclic = { id: 'cyclic' };
    cyclic.self = cyclic;
    assert.throws(() => store.put('cyclic', cyclic), /circular|cyclic|maximum call stack/iu);
    assert.deepEqual(readdirSync(join(root, 'records')), []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('artifact content paths cannot escape the artifact authority root', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-artifact-root-boundary-'));
  const outside = mkdtempSync(join(tmpdir(), 'baby-x-artifact-outside-'));
  try {
    const outsideFile = join(outside, 'outside');
    writeFileSync(outsideFile, 'outside', { mode: 0o600 });
    symlinkSync(outsideFile, join(root, 'linked-outside'));
    writeFileSync(join(root, 'index.json'), JSON.stringify({ artifacts: {
      direct: { id: 'direct', name: 'direct', state: 'finalized', path: outsideFile, size: 7, sha256: '0000000000000000000000000000000000000000000000000000000000000000' },
      linked: { id: 'linked', name: 'linked', state: 'finalized', path: join(root, 'linked-outside'), size: 7, sha256: '0000000000000000000000000000000000000000000000000000000000000000' },
    } }), { mode: 0o600 });
    const manager = new ArtifactManager(root);
    assert.throws(() => manager.download('direct'), /escapes artifact root/u);
    assert.throws(() => manager.abort('direct'), /escapes artifact root/u);
    assert.throws(() => manager.download('linked'), /escapes artifact root/u);
    assert.equal(readFileSync(outsideFile, 'utf8'), 'outside');
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});
