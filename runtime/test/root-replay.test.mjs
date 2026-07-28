import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { release, tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime, canonicalize, sha256 } from '../../dist/runtime/core.js';
import { replayProviders } from '../../dist/runtime/root-platform/replay/providers.js';
import { RootReplayService } from '../../dist/runtime/root-platform/replay/service.js';

const d = (value) => sha256(String(value));
const expiry = () => new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
const context = (key) => ({ idempotencyKey: key, subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner' });
const source = { repository: 'StealthEyeLLC/baby-x', branch: 'build/root-replay', commit: 'a'.repeat(40), tree: 'b'.repeat(40) };
const intent = { purpose: 'replay exact immutable request', mutationDigest: d('mutation'), targetDigest: d('target'), rollbackDigest: d('rollback'), requiredAuthorities: ['root-replay-authority'], requiredVerifications: ['root-replay-verification'] };
const createPayload = { source, intent };

function provider(id) {
  const found = replayProviders().find((entry) => entry.definition.providerId === id);
  assert.ok(found, id);
  return found;
}

function compatibility(id) {
  const definition = provider(id).definition;
  return {
    architecture: 'x86_64',
    kernelRelease: release(),
    providerId: id,
    providerVersion: definition.implementationVersion,
    configurationDigest: definition.configurationDigest,
  };
}

function digestFile(path) {
  const content = readFileSync(path);
  return sha256(canonicalize([{ path: '.', kind: 'FILE', sizeBytes: content.length, digest: sha256(content) }]));
}

async function createTransaction(runtime, key, authorize = false) {
  let result = await runtime.execute('babyx.root.transaction.create', createPayload, context(`${key}-create`));
  if (authorize) {
    result = await runtime.execute('babyx.root.transaction.authorize', {
      transactionId: result.transaction.transactionId,
      expectedSequence: 1,
      decisionDigest: d(`${key}-decision`),
      expiresAt: expiry(),
    }, context(`${key}-authorize`));
  }
  return result.transaction;
}

function fakeEffects() {
  let restores = 0;
  return {
    get restores() { return restores; },
    async checkpoint(kind, request) {
      if (kind === 'CRIU_PROCESS') {
        mkdirSync(request.imagesDir, { recursive: true });
        writeFileSync(join(request.imagesDir, 'inventory.img'), 'fixture-criu-image');
      }
      if (kind === 'MICROVM_SNAPSHOT') return { snapshot: { snapshotId: `mvs_${'1'.repeat(32)}`, recordDigest: d('snapshot') } };
      return { kind, fixture: true };
    },
    async restore(kind) {
      restores += 1;
      return { kind, fixture: true, restored: true };
    },
  };
}

test('replay provider probes are truthful and compact', () => {
  const providers = replayProviders();
  assert.equal(providers.length, 5);
  assert.equal(new Set(providers.map((entry) => entry.definition.providerId)).size, 5);
  assert.equal(provider('request-replay').probe().supportState, 'SUPPORTED');
  assert.equal(provider('observation-replay').probe().supportState, 'SUPPORTED');
  if (!existsSync('/usr/sbin/criu')) assert.equal(provider('criu-checkpoint-restore').probe().supportState, 'UNAVAILABLE');
  if (!existsSync('/usr/bin/rr')) assert.equal(provider('rr-forensic-replay').probe().supportState, 'UNAVAILABLE');
});

test('request replay defaults to dry-run and observation replay is mutation-free', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-replay-request-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const transaction = await createTransaction(runtime, 'request-source');
    const requestReplay = await runtime.execute('babyx.root.replay.run', { kind: 'REQUEST_REPLAY', transactionId: transaction.transactionId }, context('request-dry-run'));
    assert.equal(requestReplay.replay.state, 'DRY_RUN_COMPLETE');
    assert.equal(requestReplay.replay.dryRun, true);
    assert.equal(requestReplay.replay.effectExecuted, false);
    assert.equal(requestReplay.replay.result.canonicalInput.operation, 'babyx.root.transaction.create');
    const observationReplay = await runtime.execute('babyx.root.replay.run', { kind: 'OBSERVATION_REPLAY', transactionId: transaction.transactionId }, context('observation-replay'));
    assert.equal(observationReplay.replay.state, 'COMPLETED');
    assert.equal(observationReplay.replay.effectExecuted, false);
    assert.equal(observationReplay.replay.result.mutationFree, true);
    assert.equal(observationReplay.replay.sourceRecordDigest, transaction.recordDigest);
    const loaded = await new BabyXRuntime({ stateRoot: root }).execute('babyx.root.replay.get', { replayId: requestReplay.replay.replayId });
    assert.equal(loaded.replay.recordDigest, requestReplay.replay.recordDigest);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('request replay never silently repeats a mutation', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-replay-deny-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const transaction = await createTransaction(runtime, 'deny-source');
    await assert.rejects(
      () => runtime.execute('babyx.root.replay.run', { kind: 'REQUEST_REPLAY', transactionId: transaction.transactionId, dryRun: false }, context('deny-effect')),
      /distinct authorized transaction/u,
    );
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('secret-bearing replay inputs are rejected before persistence', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-replay-secret-'));
  try {
    const service = new RootReplayService(root);
    await assert.rejects(
      () => service.runReplay({ kind: 'REQUEST_REPLAY', transactionId: `rtx_${'1'.repeat(32)}`, canonicalInput: { apiToken: 'must-not-persist' } }, context('secret-reject')),
      /secret-bearing fields/u,
    );
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('rr trace checkpoint is digest-bound, idempotent, restart-safe, and tamper-evident', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-replay-rr-'));
  try {
    const trace = join(root, 'trace.rr');
    writeFileSync(trace, 'rr-fixture-trace');
    const effects = fakeEffects();
    const options = { effectDelegate: effects, supportOverride: { 'rr-forensic-replay': true } };
    const service = new RootReplayService(root, options);
    const payload = { kind: 'RR_TRACE', traceReference: trace, traceDigest: digestFile(trace), traceSizeBytes: readFileSync(trace).length, compatibility: compatibility('rr-forensic-replay') };
    const first = await service.createCheckpoint(payload, context('rr-create'));
    assert.equal(first.checkpoint.state, 'READY');
    assert.equal(first.checkpoint.artifact.kind, 'FILE');
    const replay = await service.createCheckpoint(payload, context('rr-create'));
    assert.equal(replay.replayed, true);
    assert.equal(replay.checkpoint.checkpointId, first.checkpoint.checkpointId);
    const reloaded = new RootReplayService(root, options).getCheckpoint({ checkpointId: first.checkpoint.checkpointId }, context('rr-get'));
    assert.equal(reloaded.checkpoint.recordDigest, first.checkpoint.recordDigest);
    writeFileSync(trace, 'tampered-rr-trace');
    await assert.rejects(
      () => new RootReplayService(root, options).runReplay({ kind: 'RR_FORENSIC_REPLAY', checkpointId: first.checkpoint.checkpointId }, context('rr-dry-tamper')),
      /artifact digest no longer matches/u,
    );
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('checkpoint idempotency rejects conflicting requests', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-replay-conflict-'));
  try {
    const trace = join(root, 'trace.rr');
    writeFileSync(trace, 'rr-fixture-trace');
    const service = new RootReplayService(root, { effectDelegate: fakeEffects(), supportOverride: { 'rr-forensic-replay': true } });
    const base = { kind: 'RR_TRACE', traceReference: trace, traceDigest: digestFile(trace), traceSizeBytes: readFileSync(trace).length, compatibility: compatibility('rr-forensic-replay') };
    await service.createCheckpoint(base, context('rr-conflict'));
    await assert.rejects(() => service.createCheckpoint({ ...base, traceSizeBytes: 999 }, context('rr-conflict')), /different checkpoint request/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('CRIU checkpoint and restore fixtures require exact authorization and persist observations', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-replay-criu-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const transaction = await createTransaction(runtime, 'criu-effect', true);
    const effects = fakeEffects();
    const service = new RootReplayService(root, { effectDelegate: effects, supportOverride: { 'criu-checkpoint-restore': true } });
    const imagesDir = join(root, 'criu-images');
    const created = await service.createCheckpoint({
      kind: 'CRIU_PROCESS', transactionId: transaction.transactionId,
      process: { pid: process.pid, processStartTime: 'fixture-start', executablePath: process.execPath, pgid: null, bootId: 'fixture-boot' },
      imagesDir, compatibility: compatibility('criu-checkpoint-restore'),
    }, context('criu-create'));
    assert.equal(created.checkpoint.state, 'READY');
    await assert.rejects(
      () => service.restoreCheckpoint({ checkpointId: created.checkpoint.checkpointId, transactionId: transaction.transactionId, authorizationDigest: d('wrong') }, context('criu-restore-wrong')),
      /authorization digest does not match/u,
    );
    const restored = await service.restoreCheckpoint({ checkpointId: created.checkpoint.checkpointId, transactionId: transaction.transactionId, authorizationDigest: transaction.authorization.decisionDigest }, context('criu-restore'));
    assert.equal(restored.checkpoint.state, 'RESTORED');
    assert.equal(restored.checkpoint.restoreCount, 1);
    assert.equal(restored.checkpoint.lastRestore.effectExecuted, true);
    assert.equal(effects.restores, 1);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('effectful request replay only prepares delegation to a distinct exact authority transaction', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-replay-delegate-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const sourceTransaction = await createTransaction(runtime, 'delegate-source');
    const effectTransaction = await createTransaction(runtime, 'delegate-effect', true);
    const result = await runtime.execute('babyx.root.replay.run', {
      kind: 'REQUEST_REPLAY', transactionId: sourceTransaction.transactionId, dryRun: false,
      effectTransactionId: effectTransaction.transactionId, authorizationDigest: effectTransaction.authorization.decisionDigest,
    }, context('delegate-request'));
    assert.equal(result.replay.state, 'AUTHORIZED_PENDING');
    assert.equal(result.replay.effectAuthorized, true);
    assert.equal(result.replay.effectExecuted, false);
    assert.equal(result.replay.result.executionAuthority, 'babyx.root.transaction.*');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('restore failure is durable, explicit, and never reported as executed', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-replay-restore-failure-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const transaction = await createTransaction(runtime, 'restore-failure', true);
    const imagesDir = join(root, 'failed-criu-images');
    const creator = new RootReplayService(root, { effectDelegate: fakeEffects(), supportOverride: { 'criu-checkpoint-restore': true } });
    const created = await creator.createCheckpoint({
      kind: 'CRIU_PROCESS', transactionId: transaction.transactionId,
      process: { pid: process.pid, processStartTime: 'fixture-start', executablePath: process.execPath, pgid: null, bootId: 'fixture-boot' },
      imagesDir, compatibility: compatibility('criu-checkpoint-restore'),
    }, context('restore-failure-create'));
    const failingEffects = {
      async checkpoint() { throw new Error('not-used'); },
      async restore() { throw new Error('fixture restore failure'); },
    };
    const service = new RootReplayService(root, { effectDelegate: failingEffects, supportOverride: { 'criu-checkpoint-restore': true } });
    await assert.rejects(
      () => service.restoreCheckpoint({ checkpointId: created.checkpoint.checkpointId, transactionId: transaction.transactionId, authorizationDigest: transaction.authorization.decisionDigest }, context('restore-failure-run')),
      /fixture restore failure/u,
    );
    const failed = service.getCheckpoint({ checkpointId: created.checkpoint.checkpointId }, context('restore-failure-get')).checkpoint;
    assert.equal(failed.state, 'RESTORE_FAILED');
    assert.equal(failed.restoreCount, 1);
    assert.equal(failed.lastRestore.effectExecuted, false);
    assert.equal(failed.lastRestore.errorCode, 'root_replay_effect_failed');
    assert.match(failed.lastRestore.errorDigest, /^[a-f0-9]{64}$/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('checkpoint record tampering is detected before readback or replay', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-replay-record-tamper-'));
  try {
    const trace = join(root, 'trace.rr');
    writeFileSync(trace, 'rr-fixture-trace');
    const service = new RootReplayService(root, { effectDelegate: fakeEffects(), supportOverride: { 'rr-forensic-replay': true } });
    const created = await service.createCheckpoint({ kind: 'RR_TRACE', traceReference: trace, traceDigest: digestFile(trace), traceSizeBytes: readFileSync(trace).length, compatibility: compatibility('rr-forensic-replay') }, context('record-tamper-create'));
    const recordPath = join(root, 'root-platform', 'replay', 'checkpoints', 'records', `${created.checkpoint.checkpointId}.json`);
    const record = JSON.parse(readFileSync(recordPath, 'utf8'));
    record.ownerPrincipal = 'foreign-owner';
    writeFileSync(recordPath, JSON.stringify(record));
    assert.throws(() => service.getCheckpoint({ checkpointId: created.checkpoint.checkpointId }, context('record-tamper-get')), /digest verification/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('microVM snapshot replay fixtures delegate to the existing authority contract', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-replay-microvm-'));
  try {
    const service = new RootReplayService(root, { effectDelegate: fakeEffects(), supportOverride: { 'microvm-snapshot-replay': true } });
    const created = await service.createCheckpoint({
      kind: 'MICROVM_SNAPSHOT', vmId: `vm_${'1'.repeat(32)}`, expiresAt: expiry(), compatibility: compatibility('microvm-snapshot-replay'),
    }, context('microvm-fixture-create'));
    assert.equal(created.checkpoint.state, 'READY');
    assert.equal(created.checkpoint.artifact.kind, 'MICROVM_SNAPSHOT');
    const replay = await service.runReplay({ kind: 'MICROVM_SNAPSHOT_RESTORE', checkpointId: created.checkpoint.checkpointId }, context('microvm-fixture-dry-run'));
    assert.equal(replay.replay.state, 'DRY_RUN_COMPLETE');
    assert.equal(replay.replay.effectExecuted, false);
    assert.equal(replay.replay.result.providerId, 'microvm-snapshot-replay');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
