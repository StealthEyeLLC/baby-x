import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime, canonicalize, decodeFrame, encodeFrame, operationDefinitions, sha256, verifyCanonical } from '../../dist/runtime/core.js';

test('QRT1 framing is deterministic and binary safe', () => {
  const value = { z: 1, a: { bytes: Buffer.from([0, 1, 255]).toString('base64') } };
  const frame = encodeFrame(value);
  assert.equal(frame.subarray(0, 4).toString(), 'QRT1');
  assert.deepEqual(decodeFrame(frame), value);
  assert.equal(frame.equals(encodeFrame(value)), true);
});

test('canonical Ed25519 verification detects alterations', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const value = { operation: 'babyx.health', payload: {} };
  const signature = sign(null, Buffer.from(canonicalize(value)), privateKey).toString('base64');
  assert.equal(verifyCanonical(publicKey, value, signature), true);
  assert.equal(verifyCanonical(publicKey, { ...value, operation: 'babyx.exec' }, signature), false);
});

test('describe exposes only implemented operations without duplicate authority paths', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-core-'));
  try {
    const description = new BabyXRuntime({ stateRoot: root }).describe();
    const operations = description.operations;
    assert.ok(Array.isArray(operations));
    assert.ok(operations.length >= 190);
    assert.equal(new Set(operations.map((item) => item.operation)).size, operations.length);
    for (const name of ['babyx.root.platform.describe', 'babyx.root.provider.list', 'babyx.root.provider.get', 'babyx.root.provider.reconcile']) assert.ok(operations.some((item) => item.operation === name), name);
    assert.ok(operations.some((item) => item.operation === 'babyx.artifact.verify'));
    assert.ok(operations.some((item) => item.operation === 'babyx.syscall.inject.fd'));
    assert.equal(operations.some((item) => item.operation === 'babyx.machine.raw'), false);
    assert.equal(operations.some((item) => item.operation === 'babyx.pty.create'), false);
    assert.equal(operations.some((item) => item.operation === 'babyx.artifact.begin'), false);
    for (const definition of operations) {
      assert.ok(['low', 'medium', 'high'].includes(definition.risk));
      assert.ok(['read_only', 'caller_key', 'conditional', 'non_idempotent'].includes(definition.idempotency));
      assert.equal(definition.receiptVersion, '1.0.0');
      assert.equal(definition.authority.class, 'unrestricted-owner');
      assert.equal(definition.input.type, 'object');
      assert.equal(definition.input.additionalProperties, false);
      assert.ok(Array.isArray(definition.errors));
      assert.ok(Array.isArray(definition.postconditions));
    }
    assert.equal(description.operationCatalogVersion, '10.0.0');
    const snapshot = description.operations.find((definition) => definition.operation === 'babyx.root.microvm.snapshot');
    const restore = description.operations.find((definition) => definition.operation === 'babyx.root.microvm.restore');
    const pool = description.operations.find((definition) => definition.operation === 'babyx.root.microvm.pool.reconcile');
    assert.deepEqual(snapshot.postconditions, ['microvm_snapshot_record_persisted', 'snapshot_artifact_digests_verified', 'credential_absence_verified', 'source_microvm_cleaned']);
    assert.deepEqual(restore.postconditions, ['microvm_record_persisted', 'snapshot_compatibility_verified', 'fresh_guest_identity_observed', 'provider_observation_reported']);
    assert.deepEqual(pool.postconditions, ['microvm_pool_record_persisted', 'pool_capacity_bounded', 'lease_state_reconciled', 'provider_observation_reported']);
    assert.match(description.operationCatalogSha256, /^[a-f0-9]{64}$/u);
    assert.equal(operationDefinitions().length, operations.length);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('compact proof remains independent from operational object persistence', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-proof-'));
  try {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const privatePath = join(root, 'proof.pem');
    writeFileSync(privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    const runtime = new BabyXRuntime({ stateRoot: root, proofPrivateKey: privatePath, proofKeyId: 'test-key' });
    const result = { ok: true, value: 7 };
    const proof = runtime.createProof('request-1', 'babyx.health', true, new Date().toISOString(), result);
    assert.equal('signature' in proof, true);
    if (!('signature' in proof)) throw new Error('proof not generated');
    const { signature, ...unsigned } = proof;
    assert.equal(verifyCanonical(publicKey, unsigned, signature), true);
    assert.equal(proof.resultSha256, sha256(canonicalize(result)));
    assert.ok(Buffer.byteLength(JSON.stringify(proof)) < 2048);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
