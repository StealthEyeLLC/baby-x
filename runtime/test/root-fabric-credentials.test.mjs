import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RootCredentialService, redactSecrets } from '../../dist/runtime/root-fabric/credentials.js';

const context = (key) => ({ subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner', idempotencyKey: `test-${key}` });
const future = (ms) => new Date(Date.now() + ms).toISOString();

test('I credential leases are exact-bound, private, redacted, expiring, and restart-cleanable', () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-credentials-'));
  const deliveryRoot = join(root, 'delivery');
  const secretPath = join(root, 'source-secret');
  try {
    chmodSync(root, 0o700);
    writeFileSync(secretPath, 'credential-value-that-must-never-appear-in-records', { mode: 0o600 });
    const service = new RootCredentialService(root, undefined, { deliveryRoot });
    const payload = { credentialReference: secretPath, provider: 'HOST_ENVELOPE', skillBundleDigest: 'a'.repeat(64), grantDigest: 'b'.repeat(64), transactionId: 'rfx_credential', stepId: 'step-1', targetType: 'UNIT', targetId: 'babyx-root-test.service', purpose: 'test credential delivery', expiresAt: future(30_000), maximumTtlMs: 60_000, transactionDeadline: future(120_000), operationDeadline: future(60_000), revocationBehavior: 'FREEZE', authorized: true };
    const leased = service.lease(payload, context('credential-lease')).lease;
    assert.equal(leased.state, 'LEASED');
    assert.equal(JSON.stringify(leased).includes('credential-value-that-must-never-appear'), false);
    assert.throws(() => service.deliver({ leaseId: leased.leaseId, transactionId: 'wrong', stepId: payload.stepId, skillBundleDigest: payload.skillBundleDigest, grantDigest: payload.grantDigest, targetType: payload.targetType, targetId: payload.targetId }, context('credential-wrong')), /binding mismatch/u);
    const delivered = service.deliver({ leaseId: leased.leaseId, transactionId: payload.transactionId, stepId: payload.stepId, skillBundleDigest: payload.skillBundleDigest, grantDigest: payload.grantDigest, targetType: payload.targetType, targetId: payload.targetId }, context('credential-deliver'));
    assert.equal(readFileSync(delivered.deliveryPath, 'utf8'), 'credential-value-that-must-never-appear-in-records');
    assert.equal(statSync(delivered.deliveryPath).mode & 0o077, 0);
    const cleaned = service.clean({ leaseId: leased.leaseId, reason: 'test cleanup' }, context('credential-clean')).lease;
    assert.equal(cleaned.state, 'CLEANED');
    assert.equal(existsSync(delivered.deliveryPath), false);
    assert.deepEqual(redactSecrets({ token: 'abc', nested: { password: 'xyz' } }), { token: '[REDACTED]', nested: { password: '[REDACTED]' } });
    assert.equal(service.verifyNoSecretMaterial({ record: cleaned }), true);
    assert.throws(() => service.lease({ ...payload, expiresAt: future(180_000) }, context('credential-too-long')), /exceeds/u);
    const reloaded = new RootCredentialService(root, undefined, { deliveryRoot });
    assert.equal(reloaded.get({ leaseId: leased.leaseId }).lease.state, 'CLEANED');
    assert.equal(reloaded.recover().ok, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
