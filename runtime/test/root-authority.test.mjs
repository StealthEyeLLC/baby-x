import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime, sha256 } from '../../dist/runtime/core.js';

const d = (value) => sha256(String(value));
const expiry = () => new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
const context = (key) => ({ idempotencyKey: key, subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner' });
const createPayload = {
  source: { repository: 'StealthEyeLLC/baby-x', branch: 'build/root', commit: 'a'.repeat(40), tree: 'b'.repeat(40) },
  intent: { purpose: 'activate exact immutable release', mutationDigest: d('mutation'), targetDigest: d('target'), rollbackDigest: d('rollback'), requiredAuthorities: ['release-authority', 'runtime-health'], requiredVerifications: ['runtime-health'] },
};

async function committed(runtime) {
  let r = await runtime.execute('babyx.root.transaction.create', createPayload, context('create-committed'));
  const id = r.transaction.transactionId;
  r = await runtime.execute('babyx.root.transaction.authorize', { transactionId: id, expectedSequence: 1, decisionDigest: d('decision'), expiresAt: expiry() }, context('authorize-committed'));
  r = await runtime.execute('babyx.root.transaction.begin', { transactionId: id, expectedSequence: 2 }, context('begin-committed'));
  r = await runtime.execute('babyx.root.transaction.observe', { transactionId: id, expectedSequence: 3, phase: 'execution', status: 'succeeded', authority: 'release-authority', reference: 'release:exact', observationDigest: d('execution') }, context('observe-execution'));
  r = await runtime.execute('babyx.root.transaction.observe', { transactionId: id, expectedSequence: 4, phase: 'verification', status: 'succeeded', authority: 'runtime-health', reference: 'health:exact', observationDigest: d('verification') }, context('observe-verification'));
  return runtime.execute('babyx.root.transaction.commit', { transactionId: id, expectedSequence: 5, commitDigest: d('commit'), verificationDigest: d('verification') }, context('commit-exact'));
}

test('root authority completes exact verified commit and survives reload', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-'));
  try {
    const result = await committed(new BabyXRuntime({ stateRoot: root }));
    assert.equal(result.transaction.state, 'COMMITTED');
    assert.equal(result.transaction.sequence, 6);
    assert.equal(result.transaction.events.length, 6);
    assert.equal(result.transaction.events.at(-1).previousEventDigest, result.transaction.events.at(-2).eventDigest);
    const reloaded = new BabyXRuntime({ stateRoot: root });
    const verified = await reloaded.execute('babyx.root.transaction.verify', { transactionId: result.transaction.transactionId });
    assert.equal(verified.valid, true);
    const got = await reloaded.execute('babyx.root.transaction.get', { transactionId: result.transaction.transactionId });
    assert.equal(got.transaction.recordDigest, result.transaction.recordDigest);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('root create and transitions replay idempotently and reject conflicts', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-replay-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const first = await runtime.execute('babyx.root.transaction.create', createPayload, context('same-create-key'));
    const replay = await runtime.execute('babyx.root.transaction.create', createPayload, context('same-create-key'));
    assert.equal(replay.replayed, true);
    assert.equal(replay.transaction.transactionId, first.transaction.transactionId);
    await assert.rejects(() => runtime.execute('babyx.root.transaction.create', { ...createPayload, intent: { ...createPayload.intent, purpose: 'different' } }, context('same-create-key')), /different create request/u);
    const authorization = { transactionId: first.transaction.transactionId, expectedSequence: 1, decisionDigest: d('decision'), expiresAt: expiry() };
    await runtime.execute('babyx.root.transaction.authorize', authorization, context('same-auth-key'));
    const authReplay = await runtime.execute('babyx.root.transaction.authorize', authorization, context('same-auth-key'));
    assert.equal(authReplay.replayed, true);
    await assert.rejects(() => runtime.execute('babyx.root.transaction.begin', { transactionId: first.transaction.transactionId, expectedSequence: 1 }, context('wrong-sequence')), /expected sequence/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('commit is impossible before exact successful verification', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-gate-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    let r = await runtime.execute('babyx.root.transaction.create', createPayload, context('gate-create'));
    const id = r.transaction.transactionId;
    r = await runtime.execute('babyx.root.transaction.authorize', { transactionId: id, expectedSequence: 1, decisionDigest: d('decision'), expiresAt: expiry() }, context('gate-auth'));
    r = await runtime.execute('babyx.root.transaction.begin', { transactionId: id, expectedSequence: 2 }, context('gate-begin'));
    await assert.rejects(() => runtime.execute('babyx.root.transaction.commit', { transactionId: id, expectedSequence: 3, commitDigest: d('commit'), verificationDigest: d('verification') }, context('gate-commit')), /does not permit/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('rollback is requested then terminalized only by exact observed authority result', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-rollback-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    let r = await runtime.execute('babyx.root.transaction.create', createPayload, context('rollback-create'));
    const id = r.transaction.transactionId;
    r = await runtime.execute('babyx.root.transaction.rollback', { transactionId: id, expectedSequence: 1, rollbackDigest: d('rollback'), reasonDigest: d('failure') }, context('rollback-request'));
    assert.equal(r.transaction.state, 'ROLLBACK_REQUESTED');
    r = await runtime.execute('babyx.root.transaction.observe', { transactionId: id, expectedSequence: 2, phase: 'rollback', status: 'succeeded', authority: 'release-authority', reference: 'rollback:exact', observationDigest: d('rollback-proof') }, context('rollback-observe'));
    assert.equal(r.transaction.state, 'ROLLED_BACK');
    assert.equal(r.transaction.rollback.outcome, 'succeeded');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('tampering is detected and authority source has no executor path', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-tamper-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const created = await runtime.execute('babyx.root.transaction.create', createPayload, context('tamper-create'));
    const id = created.transaction.transactionId;
    const path = join(root, 'root-authority', 'transactions', 'records', `${id}.json`);
    const record = JSON.parse(readFileSync(path, 'utf8'));
    record.intent.purpose = 'tampered';
    writeFileSync(path, JSON.stringify(record));
    await assert.rejects(() => runtime.execute('babyx.root.transaction.authorize', { transactionId: id, expectedSequence: 1, decisionDigest: d('decision'), expiresAt: expiry() }, context('tamper-auth')), /integrity verification failed/u);
    const source = readFileSync('runtime/src/root-authority/service.ts', 'utf8');
    assert.doesNotMatch(source, /spawn|execFile|systemctl|machinectl|release\.activate|JobManager|DisposableMachineService|ArtifactManager/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('root catalog is finite, truthful, and dispatcher-backed', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-catalog-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const description = runtime.describe();
    const roots = description.operations.filter((entry) => entry.operation.startsWith('babyx.root.'));
    assert.equal(description.operationCatalogVersion, '5.0.0');
    assert.ok(roots.length >= 11);
    assert.equal(new Set(roots.map((entry) => entry.operation)).size, roots.length);
    for (const name of ['babyx.root.describe', 'babyx.root.transaction.create', 'babyx.root.transaction.get', 'babyx.root.transaction.list', 'babyx.root.transaction.authorize', 'babyx.root.transaction.begin', 'babyx.root.transaction.observe', 'babyx.root.transaction.commit', 'babyx.root.transaction.rollback', 'babyx.root.transaction.events', 'babyx.root.transaction.verify']) assert.ok(roots.some((entry) => entry.operation === name), name);
    assert.equal(roots.find((entry) => entry.operation === 'babyx.root.transaction.create').idempotency, 'caller_key');
    assert.equal(roots.find((entry) => entry.operation === 'babyx.root.transaction.get').mutation, false);
    const surface = await runtime.execute('babyx.root.describe', {});
    assert.equal(surface.authority, 'coordination-only');
    assert.equal(surface.executesCommands, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
