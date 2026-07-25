import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime, FileManager, JobManager, machineWrapped } from '../../dist/runtime/core.js';

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


test('managed machine execution wrapper enters the exact leader namespaces', () => {
  assert.deepEqual(machineWrapped(
    { kind: 'machine-process', machine: 'machine-1', processIdentity: { pid: 4242, pgid: 4242, processStartTime: '100', executablePath: '/usr/lib/systemd/systemd', bootId: 'boot-1' } },
    ['/usr/bin/printf', '%s', 'ok'],
    '/workspace',
    { MODE: 'test' },
  ), ['/usr/bin/nsenter', '--target', '4242', '--mount', '--uts', '--ipc', '--net', '--pid', '--cgroup', '--root=/proc/4242/root', '--wdns=/workspace', '--', '/usr/bin/env', 'MODE=test', '/usr/bin/printf', '%s', 'ok']);
});

test('durable job reconciliation terminalizes absent and reused process identities without fabricating exit zero', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-job-reconcile-'));
  try {
    mkdirSync(join(root, 'streams'), { recursive: true });
    const base = {
      id: 'job-stale', operation: 'babyx.machine.start', status: 'running', target: { kind: 'host' }, argv: ['/usr/bin/systemd-nspawn'], cwd: '/',
      createdAt: '2026-07-25T16:00:00.000Z', startedAt: '2026-07-25T16:00:00.000Z', pid: 4242, pgid: 4242,
      stdoutPath: join(root, 'streams', 'job-stale.stdout'), stderrPath: join(root, 'streams', 'job-stale.stderr'),
      processIdentity: { pid: 4242, pgid: 4242, processStartTime: '100', executablePath: '/usr/bin/systemd-nspawn', bootId: 'boot-1' },
    };
    writeFileSync(base.stdoutPath, ''); writeFileSync(base.stderrPath, '');
    writeFileSync(join(root, 'jobs.json'), JSON.stringify({ jobs: { [base.id]: base } }));
    const absent = new JobManager(root, { processIdentity: () => { throw new Error('absent'); }, now: () => '2026-07-25T17:00:00.000Z' });
    const lost = absent.reconcile(base.id);
    assert.equal(lost.status, 'lost');
    assert.equal(lost.exitCode, undefined);
    assert.equal(lost.reconciliation.classification, 'process-absent');
    assert.equal(absent.reconcile(base.id).completedAt, lost.completedAt);

    const conflictRecord = { ...base, id: 'job-reused', stdoutPath: join(root, 'streams', 'job-reused.stdout'), stderrPath: join(root, 'streams', 'job-reused.stderr') };
    writeFileSync(conflictRecord.stdoutPath, ''); writeFileSync(conflictRecord.stderrPath, '');
    writeFileSync(join(root, 'jobs.json'), JSON.stringify({ jobs: { [conflictRecord.id]: conflictRecord } }));
    const reused = new JobManager(root, { processIdentity: () => ({ pid: 4242, pgid: 4242, processStartTime: '999', executablePath: '/usr/bin/other', bootId: 'boot-1' }), now: () => '2026-07-25T17:01:00.000Z' });
    const conflicted = reused.reconcile(conflictRecord.id);
    assert.equal(conflicted.status, 'lost');
    assert.equal(conflicted.reconciliation.classification, 'identity-conflict');
    assert.equal(conflicted.exitCode, undefined);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('public job reconcile operation exposes truthful terminal recovery', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-runtime-job-reconcile-'));
  try {
    mkdirSync(join(root, 'jobs', 'streams'), { recursive: true });
    const id = 'job-public-stale';
    const stdoutPath = join(root, 'jobs', 'streams', id + '.stdout');
    const stderrPath = join(root, 'jobs', 'streams', id + '.stderr');
    writeFileSync(stdoutPath, ''); writeFileSync(stderrPath, '');
    writeFileSync(join(root, 'jobs', 'jobs.json'), JSON.stringify({ jobs: { [id]: { id, operation: 'babyx.machine.start', status: 'running', target: { kind: 'host' }, argv: ['/usr/bin/systemd-nspawn'], cwd: '/', createdAt: '2026-07-25T16:00:00.000Z', startedAt: '2026-07-25T16:00:00.000Z', pid: 999999999, pgid: 999999999, stdoutPath, stderrPath, processIdentity: { pid: 999999999, pgid: 999999999, processStartTime: '1', executablePath: '/usr/bin/systemd-nspawn', bootId: 'old-boot' } } } }));
    const runtime = new BabyXRuntime({ stateRoot: root });
    const result = await runtime.execute('babyx.job.reconcile', { jobId: id }, { subject: 'owner:test', authorityClass: 'unrestricted-owner' });
    assert.equal(result.status, 'lost');
    assert.equal(result.reconciliation.classification, 'process-absent');
    assert.ok(runtime.describe().operations.some((definition) => definition.operation === 'babyx.job.reconcile'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('machine-service startup reconciles dead recorded-running jobs', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-startup-job-reconcile-'));
  try {
    mkdirSync(join(root, 'jobs', 'streams'), { recursive: true });
    const id = 'job-startup-stale';
    const stdoutPath = join(root, 'jobs', 'streams', id + '.stdout');
    const stderrPath = join(root, 'jobs', 'streams', id + '.stderr');
    writeFileSync(stdoutPath, ''); writeFileSync(stderrPath, '');
    writeFileSync(join(root, 'jobs', 'jobs.json'), JSON.stringify({ jobs: { [id]: { id, operation: 'babyx.machine.start', status: 'running', target: { kind: 'host' }, argv: ['/usr/bin/systemd-nspawn'], cwd: '/', createdAt: '2026-07-25T16:00:00.000Z', startedAt: '2026-07-25T16:00:00.000Z', pid: 999999998, pgid: 999999998, stdoutPath, stderrPath, processIdentity: { pid: 999999998, pgid: 999999998, processStartTime: '1', executablePath: '/usr/bin/systemd-nspawn', bootId: 'old-boot' } } } }));
    const runtime = new BabyXRuntime({ stateRoot: root });
    await runtime.execute('babyx.machine.describe');
    const reconciled = await runtime.execute('babyx.job.get', { jobId: id });
    assert.equal(reconciled.status, 'lost');
    assert.equal(reconciled.reconciliation.classification, 'process-absent');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('durable job authority rejects a reused machine leader PID before namespace entry', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-job-target-identity-'));
  try {
    const manager = new JobManager(root, { processIdentity: () => ({ pid: 4242, pgid: 4242, processStartTime: '999', executablePath: '/usr/bin/foreign', bootId: 'boot-1' }) });
    assert.throws(() => manager.start('test', {
      argv: ['/usr/bin/true'],
      target: { kind: 'machine-process', machine: 'machine-1', processIdentity: { pid: 4242, pgid: 4242, processStartTime: '100', executablePath: '/usr/lib/systemd/systemd', bootId: 'boot-1' } },
    }), /identity changed before execution/u);
    assert.equal(manager.list().length, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
