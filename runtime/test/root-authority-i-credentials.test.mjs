import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RootCredentialService } from '../../dist/runtime/root-fabric/credentials.js';
import { OPERATION_CATALOG_VERSION, OPERATION_DEFINITIONS } from '../../dist/runtime/operations/definitions.js';
import { ROOT_FABRIC_OPERATION_NAMES } from '../../dist/runtime/root-fabric/service.js';

const context = (key, subject = 'owner-a') => ({ subject, authorityClass: 'unrestricted-owner', idempotencyKey: key });
const transactionId = `rfx_${'b'.repeat(32)}`;
const bundleDigest = 'c'.repeat(64);
const grantDigest = 'd'.repeat(64);
const secretValue = 'jit-secret-material-should-never-enter-records';

function leasePayload(overrides = {}) {
  return {
    credentialReference: '/run/credentials/source-token', provider: 'HOST_ENVELOPE',
    skillBundleDigest: bundleDigest, grantDigest, transactionId, stepId: 'step-1',
    targetType: 'UNIT', targetId: 'babyx-effect-1.service', purpose: 'single transaction step',
    expiresAt: '2026-07-28T15:01:00.000Z', maximumTtlMs: 120_000,
    transactionDeadline: '2026-07-28T15:10:00.000Z', operationDeadline: '2026-07-28T15:05:00.000Z',
    revocationBehavior: 'CANCEL_AND_ROLLBACK', authorized: true, ...overrides,
  };
}
function deliveryPayload(leaseId, overrides = {}) {
  return { leaseId, transactionId, stepId: 'step-1', skillBundleDigest: bundleDigest, grantDigest, targetType: 'UNIT', targetId: 'babyx-effect-1.service', ...overrides };
}
function files(root) {
  const out = [];
  const walk = (path) => { for (const entry of readdirSync(path, { withFileTypes: true })) { const child = join(path, entry.name); if (entry.isDirectory()) walk(child); else out.push(child); } };
  walk(root); return out;
}

test('I: JIT credential leases are transaction-bound, private, redacted, revocable, and cleanable', () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-i-state-'));
  const deliveryRoot = mkdtempSync(join(tmpdir(), 'babyx-i-delivery-'));
  chmodSync(deliveryRoot, 0o700);
  let now = '2026-07-28T15:00:00.000Z';
  const secrets = { read(reference) { assert.equal(reference, '/run/credentials/source-token'); return Buffer.from(secretValue); } };
  try {
    const service = new RootCredentialService(root, secrets, { deliveryRoot, now: () => now });
    const issued = service.lease(leasePayload(), context('credential-lease-0001'));
    assert.equal(issued.replayed, false);
    assert.equal(issued.lease.state, 'LEASED');
    assert.match(issued.lease.leaseId, /^crl_[a-f0-9]{32}$/u);
    const leaseId = issued.lease.leaseId;
    assert.equal(service.lease(leasePayload(), context('credential-lease-0001')).replayed, true);
    assert.throws(() => service.lease(leasePayload({ purpose: 'conflict' }), context('credential-lease-0001')), (error) => error.code === 'idempotency_conflict');
    assert.throws(() => service.deliver(deliveryPayload(leaseId, { stepId: 'wrong-step' }), context('credential-deliver-wrong')), (error) => error.code === 'principal_mismatch');
    assert.throws(() => service.deliver(deliveryPayload(leaseId), context('credential-deliver-wrong-owner', 'owner-b')), (error) => error.code === 'principal_mismatch');
    const delivered = service.deliver(deliveryPayload(leaseId), context('credential-deliver-0001'));
    assert.equal(delivered.replayed, false);
    assert.equal(delivered.lease.state, 'DELIVERED');
    assert.equal(readFileSync(delivered.deliveryPath, 'utf8'), secretValue);
    assert.equal(statSync(delivered.deliveryPath).mode & 0o777, 0o400);
    assert.equal(statSync(deliveryRoot).mode & 0o077, 0);
    assert.equal(service.deliver(deliveryPayload(leaseId), context('credential-deliver-replay')).replayed, true);
    const publicView = JSON.stringify({ get: service.get({ leaseId }), list: service.list({ transactionId }) });
    assert.equal(publicView.includes(secretValue), false);
    assert.equal(service.verifyNoSecretMaterial(JSON.parse(publicView)), true);
    for (const path of files(root)) assert.equal(readFileSync(path, 'utf8').includes(secretValue), false, path);
    const revoked = service.revoke({ leaseId, reason: 'transaction terminal' }, context('credential-revoke-0001'));
    assert.equal(revoked.lease.state, 'CLEANED');
    assert.equal(revoked.lease.deliveryPath, null);
    assert.equal(existsSync(delivered.deliveryPath), false);
    assert.equal(service.clean({ leaseId, reason: 'idempotent cleanup' }, context('credential-clean-replay')).replayed, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(deliveryRoot, { recursive: true, force: true });
  }
});

test('I: expiry and startup recovery remove delivered material and enforce bounded TTL', () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-i-recovery-state-'));
  const deliveryRoot = mkdtempSync(join(tmpdir(), 'babyx-i-recovery-delivery-'));
  chmodSync(deliveryRoot, 0o700);
  let now = '2026-07-28T15:00:00.000Z';
  const secrets = { read() { return Buffer.from(secretValue); } };
  try {
    const service = new RootCredentialService(root, secrets, { deliveryRoot, now: () => now });
    assert.throws(() => service.lease(leasePayload({ expiresAt: '2026-07-28T15:03:00.000Z', maximumTtlMs: 60_000 }), context('credential-too-long')), (error) => error.code === 'credential_unavailable');
    const lease = service.lease(leasePayload({ expiresAt: '2026-07-28T15:00:01.000Z', maximumTtlMs: 60_000 }), context('credential-recovery-lease')).lease;
    const delivered = service.deliver(deliveryPayload(lease.leaseId), context('credential-recovery-deliver'));
    assert.equal(existsSync(delivered.deliveryPath), true);
    now = '2026-07-28T15:00:02.000Z';
    assert.equal(service.get({ leaseId: lease.leaseId }).lease.state, 'EXPIRED');
    const recovered = service.recover();
    assert.equal(recovered.ok, true);
    assert.equal(recovered.cleaned, 1);
    assert.equal(service.get({ leaseId: lease.leaseId }).lease.state, 'CLEANED');
    assert.equal(existsSync(delivered.deliveryPath), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(deliveryRoot, { recursive: true, force: true });
  }
});

test('I: catalog exposes exactly six schema-backed credential operations while preserving H', () => {
  assert.equal(OPERATION_CATALOG_VERSION, '3.4.0');
  assert.equal(OPERATION_DEFINITIONS.length, 230);
  const root = OPERATION_DEFINITIONS.filter((entry) => entry.operation.startsWith('babyx.root.'));
  assert.equal(root.length, 51);
  const expected = ['babyx.root.credential.lease', 'babyx.root.credential.deliver', 'babyx.root.credential.get', 'babyx.root.credential.list', 'babyx.root.credential.revoke', 'babyx.root.credential.clean'];
  for (const operation of expected) {
    assert.equal(ROOT_FABRIC_OPERATION_NAMES.filter((name) => name === operation).length, 1);
    const definition = OPERATION_DEFINITIONS.find((entry) => entry.operation === operation);
    assert.ok(definition);
    assert.equal(definition.input.additionalProperties, false);
  }
  for (const operation of ['babyx.root.observation.start', 'babyx.root.observation.get', 'babyx.root.observation.record', 'babyx.root.observation.finalize']) assert.ok(ROOT_FABRIC_OPERATION_NAMES.includes(operation));
  assert.equal(new Set(OPERATION_DEFINITIONS.map((entry) => entry.operation)).size, OPERATION_DEFINITIONS.length);
});
