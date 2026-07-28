import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime, sha256 } from '../../dist/runtime/core.js';

const d = (value) => sha256(String(value));
const context = (key) => ({ idempotencyKey: key, subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner' });

test('Checkpoint G public surface is finite, dispatcher-backed, and honest on the live host', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-replay-integration-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const described = runtime.describe();
    assert.equal(described.operationCatalogVersion, '10.0.0');
    const expected = ['babyx.root.checkpoint.create','babyx.root.checkpoint.get','babyx.root.checkpoint.restore','babyx.root.replay.run','babyx.root.replay.get'];
    for (const operation of expected) assert.equal(described.operations.filter((entry) => entry.operation === operation).length, 1, operation);
    assert.equal(described.operations.length, 227);
    assert.equal(described.operations.filter((entry) => entry.operation.startsWith('babyx.root.')).length, 48);

    const providers = await runtime.execute('babyx.root.provider.list', { offset: 0, limit: 100 });
    const replayIds = providers.providers.map((entry) => entry.providerId);
    for (const id of ['request-replay','observation-replay','criu-checkpoint-restore','rr-forensic-replay','microvm-snapshot-replay']) assert.ok(replayIds.includes(id), id);
    const criu = await runtime.execute('babyx.root.provider.get', { providerId: 'criu-checkpoint-restore' });
    const rr = await runtime.execute('babyx.root.provider.get', { providerId: 'rr-forensic-replay' });
    assert.equal(criu.provider.supportState, 'UNAVAILABLE');
    assert.equal(rr.provider.supportState, 'UNAVAILABLE');

    const transaction = await runtime.execute('babyx.root.transaction.create', {
      source: { repository: 'StealthEyeLLC/baby-x', branch: 'build/root-replay', commit: 'a'.repeat(40), tree: 'b'.repeat(40) },
      intent: { purpose: 'integration replay', mutationDigest: d('mutation'), targetDigest: d('target'), rollbackDigest: d('rollback'), requiredAuthorities: ['root-replay-authority'], requiredVerifications: ['root-replay-verification'] },
    }, context('integration-root-create'));
    const replay = await runtime.execute('babyx.root.replay.run', { kind: 'REQUEST_REPLAY', transactionId: transaction.transaction.transactionId }, context('integration-request-replay'));
    assert.equal(replay.replay.state, 'DRY_RUN_COMPLETE');
    const loaded = await runtime.execute('babyx.root.replay.get', { replayId: replay.replay.replayId });
    assert.equal(loaded.integrity.valid, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
