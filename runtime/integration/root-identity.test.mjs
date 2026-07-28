import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { BabyXRuntime } from '../../dist/runtime/core.js';
import { createSoftwareAttestationQuote } from '../../dist/runtime/root-platform/identity/providers.js';

const context = (key) => ({ subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner', idempotencyKey: key });
const digest = (character) => character.repeat(64);
const originalRootOperations = [
  'babyx.root.describe',
  'babyx.root.transaction.create',
  'babyx.root.transaction.get',
  'babyx.root.transaction.list',
  'babyx.root.transaction.authorize',
  'babyx.root.transaction.begin',
  'babyx.root.transaction.observe',
  'babyx.root.transaction.commit',
  'babyx.root.transaction.rollback',
  'babyx.root.transaction.events',
  'babyx.root.transaction.verify',
];

test('root identity public operations dispatch through the built catalog and remain durable across restart', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-identity-integration-'));
  try {
    const options = { stateRoot: root, sourceCommit: '1'.repeat(40), sourceTree: '2'.repeat(40) };
    const runtime = new BabyXRuntime(options);
    const described = runtime.describe();
    assert.equal(described.operationCatalogVersion, '10.0.0');
    for (const operation of originalRootOperations) assert.equal(described.operations.some((entry) => entry.operation === operation), true, operation);
    for (const operation of ['babyx.root.attestation.challenge','babyx.root.attestation.verify','babyx.root.attestation.get','babyx.root.identity.issue','babyx.root.identity.get','babyx.root.identity.revoke','babyx.root.secret.lease','babyx.root.secret.revoke']) {
      assert.equal(described.operations.some((entry) => entry.operation === operation), true, operation);
    }

    const providers = await runtime.execute('babyx.root.provider.list', {});
    const states = new Map(providers.providers.map((entry) => [entry.providerId, entry.supportState]));
    assert.equal(states.get('hardware-tpm'), 'UNAVAILABLE');
    assert.equal(states.get('software-tpm-fixture'), 'EXPERIMENTAL');
    assert.equal(states.get('measured-boot-evidence'), 'UNAVAILABLE');
    assert.equal(states.get('ima-measurement-evidence'), 'SUPPORTED');
    assert.equal(states.get('spire-workload-api'), 'UNAVAILABLE');
    assert.equal(states.get('sovereign-x509-svid'), 'EXPERIMENTAL');
    assert.equal(states.get('attestation-gated-secret-lease'), 'SUPPORTED');

    const challenge = await runtime.execute('babyx.root.attestation.challenge', { providerId: 'software-tpm-fixture', pcrSelection: [0, 7], ttlSeconds: 300 }, context('integration-challenge'));
    const pcrs = [
      { index: 0, algorithm: 'sha256', value: digest('a') },
      { index: 7, algorithm: 'sha256', value: digest('b') },
    ];
    const observedAt = new Date().toISOString();
    const quote = createSoftwareAttestationQuote({ nonce: challenge.challenge.nonce, pcrs, observedAt, eventLogDigest: digest('c'), imaDigest: digest('d') });
    const verified = await runtime.execute('babyx.root.attestation.verify', {
      challengeId: challenge.challenge.challengeId,
      quote,
      policy: { expectedPcrs: pcrs, maxAgeSeconds: 300, requireMeasuredBoot: true, requireIma: true },
    }, context('integration-verify'));
    assert.equal(verified.attestation.state, 'VERIFIED');

    const transactionId = 'rtx_integration1234';
    const identity = await runtime.execute('babyx.root.identity.issue', {
      attestationId: verified.attestation.attestationId,
      transactionId,
      skillBundleDigest: digest('a'),
      grantDigest: digest('b'),
      issuerProviderId: 'sovereign-x509-svid',
      selectors: [
        { type: 'transaction_id', value: transactionId },
        { type: 'skill_bundle_digest', value: digest('a') },
        { type: 'systemd_unit', value: 'baby-x.service' },
      ],
      ttlSeconds: 240,
    }, context('integration-identity'));
    assert.equal(identity.identity.state, 'ACTIVE');
    assert.equal(JSON.stringify(identity).includes('PRIVATE KEY'), false);

    const secretPath = join(root, 'integration-secret');
    writeFileSync(secretPath, 'integration-secret-material', { mode: 0o600 });
    const lease = await runtime.execute('babyx.root.secret.lease', {
      identityId: identity.identity.identityId,
      attestationId: verified.attestation.attestationId,
      transactionId,
      skillBundleDigest: digest('a'),
      grantDigest: digest('b'),
      providerId: 'local-secret-reference',
      secretReference: secretPath,
      target: { kind: 'SYSTEMD_UNIT', id: 'baby-x.service' },
      ttlSeconds: 120,
    }, context('integration-lease'));
    assert.equal(lease.lease.state, 'ACTIVE');
    assert.equal(lease.lease.secretValueReturned, false);
    assert.equal(JSON.stringify(lease).includes('integration-secret-material'), false);

    const restarted = new BabyXRuntime(options);
    const readback = await restarted.execute('babyx.root.identity.get', { identityId: identity.identity.identityId });
    assert.equal(readback.identity.recordDigest, identity.identity.recordDigest);
    const attestationReadback = await restarted.execute('babyx.root.attestation.get', { attestationId: verified.attestation.attestationId });
    assert.equal(attestationReadback.attestation.recordDigest, verified.attestation.recordDigest);

    const revokedLease = await restarted.execute('babyx.root.secret.revoke', { leaseId: lease.lease.leaseId, expectedSequence: 1, reasonDigest: digest('e') }, context('integration-lease-revoke'));
    assert.equal(revokedLease.lease.state, 'REVOKED');
    const revokedIdentity = await restarted.execute('babyx.root.identity.revoke', { identityId: identity.identity.identityId, expectedSequence: 1, reasonDigest: digest('f') }, context('integration-identity-revoke'));
    assert.equal(revokedIdentity.identity.state, 'REVOKED');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
