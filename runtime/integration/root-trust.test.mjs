import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { BabyXRuntime } from '../../dist/runtime/core.js';
import {
  context,
  createKeyedSigstoreBundle,
  createOciSkillFixture,
  createProvenance,
  createSigningKey,
  oneLeafTransparency,
  trustPolicy,
} from '../test/root-trust-fixtures.mjs';

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
const trustOperations = [
  'babyx.root.bundle.resolve',
  'babyx.root.bundle.verify',
  'babyx.root.bundle.cache',
  'babyx.root.provenance.verify',
  'babyx.root.transparency.verify',
  'babyx.root.transparency.status',
];

test('OCI trust, provenance, transparency, cache, and restart readback dispatch through the public catalog', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-trust-integration-'));
  try {
    const fixture = createOciSkillFixture(root);
    const options = { stateRoot: root, sourceCommit: '1'.repeat(40), sourceTree: '2'.repeat(40) };
    const runtime = new BabyXRuntime(options);
    const described = runtime.describe();
    assert.equal(described.operationCatalogVersion, '10.0.0');
    for (const operation of [...originalRootOperations, ...trustOperations]) {
      assert.equal(described.operations.some((entry) => entry.operation === operation), true, operation);
    }

    const providers = await runtime.execute('babyx.root.provider.list', {});
    const states = new Map(providers.providers.map((entry) => [entry.providerId, entry.supportState]));
    assert.equal(states.get('oci-skill-bundle'), 'SUPPORTED');
    assert.equal(states.get('sigstore-offline-verifier'), 'SUPPORTED');
    assert.equal(states.get('slsa-in-toto-verifier'), 'SUPPORTED');
    assert.equal(states.get('transparency-monitor'), 'DEGRADED');

    const resolved = await runtime.execute('babyx.root.bundle.resolve', {
      reference: fixture.exactReference,
      expectedManifestDigest: fixture.manifestDigest,
      discoveryOnly: false,
    }, context('integration-trust-resolve'));
    assert.equal(resolved.bundle.executionEligible, true);
    assert.equal(resolved.bundle.manifestDigest, fixture.manifestDigest);
    assert.equal(JSON.stringify(resolved).includes(fixture.layoutPath), false);

    const signingKey = createSigningKey();
    const logKey = createSigningKey();
    const observedAt = new Date().toISOString();
    const entryDigest = '8'.repeat(64);
    const transparency = oneLeafTransparency('integration-log', entryDigest, observedAt, logKey);
    const transparencyResult = await runtime.execute('babyx.root.transparency.verify', {
      logId: 'integration-log',
      entryDigest,
      checkpoint: transparency.checkpoint,
      checkpointPublicKeyPem: logKey.publicKeyPem,
      inclusionProof: transparency.inclusionProof,
      consistencyProof: null,
      maximumCheckpointAgeSeconds: 300,
    }, context('integration-transparency'));
    assert.equal(transparencyResult.transparency.state, 'VERIFIED');

    const signatureBundle = createKeyedSigstoreBundle(fixture.manifestDigest, signingKey, [{
      logId: 'integration-log',
      entryDigest,
      checkpointDigest: transparency.checkpointDigest,
      integratedTime: observedAt,
    }]);
    const signature = await runtime.execute('babyx.root.bundle.verify', {
      bundleId: resolved.bundle.bundleId,
      signatureBundle,
      trustPolicy: trustPolicy(signingKey.publicKeyPem, { requireTransparency: true }),
    }, context('integration-signature'));
    assert.equal(signature.bundle.signatureState, 'VERIFIED');

    const provenance = createProvenance(fixture.manifestHex, signingKey);
    const provenanceResult = await runtime.execute('babyx.root.provenance.verify', {
      bundleId: resolved.bundle.bundleId,
      envelope: provenance.envelope,
      verificationKeyPem: signingKey.publicKeyPem,
      expected: provenance.expected,
    }, context('integration-provenance'));
    assert.equal(provenanceResult.bundle.provenanceState, 'VERIFIED');

    const cached = await runtime.execute('babyx.root.bundle.cache', { bundleId: resolved.bundle.bundleId }, context('integration-cache'));
    assert.equal(cached.bundle.cacheState, 'CACHED');
    assert.equal(cached.bundle.contentVerified, true);

    const restarted = new BabyXRuntime(options);
    const readback = await restarted.execute('babyx.root.bundle.resolve', {
      reference: fixture.exactReference,
      expectedManifestDigest: fixture.manifestDigest,
      discoveryOnly: false,
    }, context('integration-restart-resolve'));
    assert.equal(readback.bundle.bundleId, resolved.bundle.bundleId);
    assert.equal(readback.bundle.signatureState, 'VERIFIED');
    assert.equal(readback.bundle.provenanceState, 'VERIFIED');
    assert.equal(readback.bundle.cacheState, 'CACHED');

    const transparencyReadback = await restarted.execute('babyx.root.transparency.status', { logId: 'integration-log' });
    assert.equal(transparencyReadback.transparency.checkpointDigest, transparency.checkpointDigest);
    assert.equal(transparencyReadback.transparency.criticalConflict, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
