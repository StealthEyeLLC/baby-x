import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { RootIdentityService } from '../../dist/runtime/root-platform/identity/service.js';
import { createSoftwareAttestationQuote, identityProviders } from '../../dist/runtime/root-platform/identity/providers.js';

const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);
const DIGEST_C = 'c'.repeat(64);
const DIGEST_D = 'd'.repeat(64);
const TRANSACTION_ID = 'rtx_fixture1234';
const context = (key) => ({ subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner', idempotencyKey: key });
const pcrs = [
  { index: 0, algorithm: 'sha256', value: DIGEST_A },
  { index: 7, algorithm: 'sha256', value: DIGEST_B },
];

function verifiedFixture(service, now, prefix = 'fixture') {
  const challengeResult = service.attestationChallenge({ providerId: 'software-tpm-fixture', pcrSelection: [0, 7], ttlSeconds: 300 }, context(`${prefix}-challenge`));
  const quote = createSoftwareAttestationQuote({
    nonce: challengeResult.challenge.nonce,
    pcrs,
    observedAt: now,
    eventLogDigest: DIGEST_C,
    imaDigest: DIGEST_D,
  });
  const payload = {
    challengeId: challengeResult.challenge.challengeId,
    quote,
    policy: { expectedPcrs: pcrs, maxAgeSeconds: 300, requireMeasuredBoot: true, requireIma: true },
  };
  const verification = service.attestationVerify(payload, context(`${prefix}-verify`));
  return { challengeResult, payload, verification };
}

test('identity provider probes report exact live support without false hardware claims', () => {
  const observed = new Map(identityProviders().map((provider) => [provider.definition.providerId, provider.probe()]));
  assert.equal(observed.get('hardware-tpm').supportState, 'UNAVAILABLE');
  assert.equal(observed.get('software-tpm-fixture').supportState, 'EXPERIMENTAL');
  assert.equal(observed.get('measured-boot-evidence').supportState, 'UNAVAILABLE');
  assert.equal(observed.get('ima-measurement-evidence').supportState, 'SUPPORTED');
  assert.equal(observed.get('spire-workload-api').supportState, 'UNAVAILABLE');
  assert.equal(observed.get('sovereign-x509-svid').supportState, 'EXPERIMENTAL');
  assert.equal(observed.get('attestation-gated-secret-lease').supportState, 'SUPPORTED');
  assert.equal(observed.get('hardware-tpm').health.privateKeyExport, false);
  assert.equal(observed.get('ima-measurement-evidence').health.appraisalMutation, false);
  assert.equal(observed.get('attestation-gated-secret-lease').health.secretValuesReturned, false);
});

test('software TPM attestation, SPIFFE identity, secret lease, restart, and revocation form one durable chain', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-identity-'));
  let now = '2026-07-28T05:00:00.000Z';
  try {
    const service = new RootIdentityService({ stateRoot: root, now: () => now });
    const { payload, verification } = verifiedFixture(service, now, 'chain');
    assert.equal(verification.attestation.state, 'VERIFIED');
    assert.equal(verification.attestation.measuredBootVerified, true);
    assert.equal(verification.attestation.imaVerified, true);

    const repeated = service.attestationVerify(payload, context('chain-verify'));
    assert.equal(repeated.replayed, true);
    assert.equal(repeated.attestation.attestationId, verification.attestation.attestationId);

    const replayedQuote = createSoftwareAttestationQuote({ ...payload.quote, nonce: payload.quote.nonce, observedAt: '2026-07-28T05:00:01.000Z' });
    assert.throws(() => service.attestationVerify({ ...payload, quote: replayedQuote }, context('chain-verify-replay')), (error) => error.code === 'root_attestation_nonce_replay');

    const identityResult = service.identityIssue({
      attestationId: verification.attestation.attestationId,
      transactionId: TRANSACTION_ID,
      skillBundleDigest: DIGEST_A,
      grantDigest: DIGEST_B,
      issuerProviderId: 'sovereign-x509-svid',
      selectors: [
        { type: 'transaction_id', value: TRANSACTION_ID },
        { type: 'skill_bundle_digest', value: DIGEST_A },
        { type: 'systemd_unit', value: 'baby-x.service' },
        { type: 'uid', value: '0' },
        { type: 'executable_digest', value: DIGEST_C },
      ],
      ttlSeconds: 240,
    }, context('chain-identity'));
    assert.equal(identityResult.identity.state, 'ACTIVE');
    assert.match(identityResult.identity.spiffeId, /^spiffe:\/\/babyx\.stealtheye\.internal\/workload\/wid_[a-f0-9]{32}$/u);
    assert.match(identityResult.identity.certificatePem, /BEGIN CERTIFICATE/u);
    assert.equal(JSON.stringify(identityResult).includes('.key'), false);
    assert.equal(JSON.stringify(identityResult).includes('PRIVATE KEY'), false);

    const secretPath = join(root, 'fixture-secret');
    writeFileSync(secretPath, 'fixture-secret-value', { mode: 0o600 });
    const leaseResult = service.secretLease({
      identityId: identityResult.identity.identityId,
      attestationId: verification.attestation.attestationId,
      transactionId: TRANSACTION_ID,
      skillBundleDigest: DIGEST_A,
      grantDigest: DIGEST_B,
      providerId: 'local-secret-reference',
      secretReference: secretPath,
      target: { kind: 'SYSTEMD_UNIT', id: 'baby-x.service' },
      ttlSeconds: 120,
    }, context('chain-lease'));
    assert.equal(leaseResult.lease.state, 'ACTIVE');
    assert.equal(leaseResult.lease.secretValueReturned, false);
    assert.equal(JSON.stringify(leaseResult).includes('fixture-secret-value'), false);
    assert.equal(JSON.stringify(leaseResult).includes(secretPath), false);
    assert.equal(leaseResult.lease.secretReferenceDigest.length, 64);
    assert.equal(leaseResult.lease.secretMaterialDigest.length, 64);

    assert.throws(() => service.secretLease({
      identityId: identityResult.identity.identityId,
      attestationId: verification.attestation.attestationId,
      transactionId: TRANSACTION_ID,
      skillBundleDigest: DIGEST_A,
      grantDigest: DIGEST_B,
      providerId: 'local-secret-reference',
      secretReference: secretPath,
      target: { kind: 'SYSTEMD_UNIT', id: 'unbound.service' },
      ttlSeconds: 120,
    }, context('chain-lease-wrong-target')), (error) => error.code === 'root_secret_lease_denied');

    const restarted = new RootIdentityService({ stateRoot: root, now: () => now });
    assert.equal(restarted.identityGet({ identityId: identityResult.identity.identityId }, context('read-after-restart')).identity.state, 'ACTIVE');
    assert.throws(() => restarted.identityIssue({
      attestationId: verification.attestation.attestationId,
      transactionId: TRANSACTION_ID,
      skillBundleDigest: DIGEST_A,
      grantDigest: DIGEST_B,
      issuerProviderId: 'spire-workload-api',
      selectors: [
        { type: 'transaction_id', value: TRANSACTION_ID },
        { type: 'skill_bundle_digest', value: DIGEST_A },
        { type: 'systemd_unit', value: 'baby-x.service' },
      ],
      ttlSeconds: 120,
    }, context('chain-spire-unavailable')), (error) => error.code === 'root_identity_provider_unavailable');

    now = '2026-07-28T05:00:01.000Z';
    const rotated = restarted.identityIssue({
      attestationId: verification.attestation.attestationId,
      transactionId: TRANSACTION_ID,
      skillBundleDigest: DIGEST_A,
      grantDigest: DIGEST_B,
      issuerProviderId: 'sovereign-x509-svid',
      selectors: [
        { type: 'transaction_id', value: TRANSACTION_ID },
        { type: 'skill_bundle_digest', value: DIGEST_A },
        { type: 'systemd_unit', value: 'baby-x.service' },
      ],
      ttlSeconds: 120,
    }, context('chain-identity-rotation'));
    assert.notEqual(rotated.identity.identityId, identityResult.identity.identityId);
    assert.notEqual(rotated.identity.certificateDigest, identityResult.identity.certificateDigest);

    const revokedLease = restarted.secretRevoke({ leaseId: leaseResult.lease.leaseId, expectedSequence: 1, reasonDigest: DIGEST_D }, context('chain-lease-revoke'));
    assert.equal(revokedLease.lease.state, 'REVOKED');
    const revokedIdentity = restarted.identityRevoke({ identityId: identityResult.identity.identityId, expectedSequence: 1, reasonDigest: DIGEST_C }, context('chain-identity-revoke'));
    assert.equal(revokedIdentity.identity.state, 'REVOKED');
    const materials = join(root, 'root-platform', 'identity', 'materials');
    assert.equal(readdirSync(materials).some((name) => name.startsWith(identityResult.identity.identityId)), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('attestation rejects unavailable hardware, stale quotes, PCR mismatch, and invalid selector bindings', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-identity-denial-'));
  const now = '2026-07-28T05:00:00.000Z';
  try {
    const service = new RootIdentityService({ stateRoot: root, now: () => now });
    assert.throws(() => service.attestationChallenge({ providerId: 'hardware-tpm', pcrSelection: [0], ttlSeconds: 300 }, context('hardware-unavailable')), (error) => error.code === 'root_identity_provider_unavailable');

    const staleChallenge = service.attestationChallenge({ providerId: 'software-tpm-fixture', pcrSelection: [0, 7], ttlSeconds: 300 }, context('stale-challenge'));
    const staleQuote = createSoftwareAttestationQuote({ nonce: staleChallenge.challenge.nonce, pcrs, observedAt: '2026-07-28T04:00:00.000Z' });
    assert.throws(() => service.attestationVerify({ challengeId: staleChallenge.challenge.challengeId, quote: staleQuote, policy: { expectedPcrs: pcrs, maxAgeSeconds: 300, requireMeasuredBoot: false, requireIma: false } }, context('stale-verify')), (error) => error.code === 'root_attestation_stale');

    const mismatchChallenge = service.attestationChallenge({ providerId: 'software-tpm-fixture', pcrSelection: [0, 7], ttlSeconds: 300 }, context('pcr-challenge'));
    const mismatchQuote = createSoftwareAttestationQuote({ nonce: mismatchChallenge.challenge.nonce, pcrs, observedAt: now });
    const expected = [{ index: 0, algorithm: 'sha256', value: DIGEST_D }];
    assert.throws(() => service.attestationVerify({ challengeId: mismatchChallenge.challenge.challengeId, quote: mismatchQuote, policy: { expectedPcrs: expected, maxAgeSeconds: 300, requireMeasuredBoot: false, requireIma: false } }, context('pcr-verify')), (error) => error.code === 'root_attestation_pcr_mismatch');

    const { verification } = verifiedFixture(service, now, 'selector');
    assert.throws(() => service.identityIssue({
      attestationId: verification.attestation.attestationId,
      transactionId: TRANSACTION_ID,
      skillBundleDigest: DIGEST_A,
      grantDigest: DIGEST_B,
      issuerProviderId: 'sovereign-x509-svid',
      selectors: [{ type: 'transaction_id', value: TRANSACTION_ID }],
      ttlSeconds: 120,
    }, context('selector-mismatch')), (error) => error.code === 'root_identity_invalid_request');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('startup reconciliation expires the chain and removes private material', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-identity-expiry-'));
  let now = '2026-07-28T05:00:00.000Z';
  try {
    const first = new RootIdentityService({ stateRoot: root, now: () => now });
    const { verification } = verifiedFixture(first, now, 'expiry');
    const identityResult = first.identityIssue({
      attestationId: verification.attestation.attestationId,
      transactionId: TRANSACTION_ID,
      skillBundleDigest: DIGEST_A,
      grantDigest: DIGEST_B,
      issuerProviderId: 'sovereign-x509-svid',
      selectors: [
        { type: 'transaction_id', value: TRANSACTION_ID },
        { type: 'skill_bundle_digest', value: DIGEST_A },
        { type: 'systemd_unit', value: 'baby-x.service' },
      ],
      ttlSeconds: 60,
    }, context('expiry-identity'));
    const materialRoot = join(root, 'root-platform', 'identity', 'materials');
    assert.equal(readdirSync(materialRoot).some((name) => name.startsWith(identityResult.identity.identityId)), true);

    now = '2026-07-28T05:02:00.000Z';
    const restarted = new RootIdentityService({ stateRoot: root, now: () => now });
    assert.equal(restarted.identityGet({ identityId: identityResult.identity.identityId }, context('expiry-read')).identity.state, 'EXPIRED');
    assert.equal(readdirSync(materialRoot).some((name) => name.startsWith(identityResult.identity.identityId)), false);
    assert.equal(existsSync(materialRoot), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
