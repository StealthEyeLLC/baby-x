import assert from 'node:assert/strict';
import { sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { RootTrustService } from '../../dist/runtime/root-platform/trust/service.js';
import { trustProviders } from '../../dist/runtime/root-platform/trust/providers.js';
import {
  context,
  createKeyedSigstoreBundle,
  createOciSkillFixture,
  createProvenance,
  createSigningKey,
  oneLeafTransparency,
  trustPolicy,
  twoLeafTransparency,
} from './root-trust-fixtures.mjs';

function errorCode(expected) {
  return (error) => error?.code === expected;
}

function transparencyPayload(logId, fixture, publicKeyPem, maximumCheckpointAgeSeconds = 3600) {
  return {
    logId,
    entryDigest: fixture.entryDigest,
    checkpoint: fixture.checkpoint,
    checkpointPublicKeyPem: publicKeyPem,
    inclusionProof: fixture.inclusionProof,
    consistencyProof: fixture.consistencyProof,
    maximumCheckpointAgeSeconds,
  };
}

test('trust provider probes report exact support states and no public-infrastructure claim', () => {
  const providers = new Map(trustProviders().map((provider) => [provider.definition.providerId, provider.probe()]));
  assert.equal(providers.get('oci-skill-bundle').supportState, 'SUPPORTED');
  assert.equal(providers.get('sigstore-offline-verifier').supportState, 'SUPPORTED');
  assert.equal(providers.get('slsa-in-toto-verifier').supportState, 'SUPPORTED');
  assert.equal(providers.get('transparency-monitor').supportState, 'DEGRADED');
  assert.equal(providers.get('oci-skill-bundle').health.digestPinnedExecution, true);
  assert.equal(providers.get('oci-skill-bundle').health.mutableTagsDiscoveryOnly, true);
  assert.equal(providers.get('sigstore-offline-verifier').health.publicKeylessInfrastructureRequired, false);
  assert.equal(providers.get('transparency-monitor').health.publicMonitorEnabled, false);
});

test('OCI Skill resolution rejects mutable execution, verifies all blobs, caches atomically, and reconciles tampering', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-trust-oci-'));
  const now = '2026-07-28T05:00:00.000Z';
  try {
    const fixture = createOciSkillFixture(root);
    const service = new RootTrustService({ stateRoot: root, now: () => now });
    assert.throws(() => service.bundleResolve({ reference: fixture.tagReference, expectedManifestDigest: null, discoveryOnly: false }, context('oci-tag-execution')), errorCode('root_trust_invalid_request'));

    const discovered = service.bundleResolve({ reference: fixture.tagReference, expectedManifestDigest: null, discoveryOnly: true }, context('oci-tag-discovery'));
    assert.equal(discovered.bundle.executionEligible, false);
    assert.equal(discovered.discoveredByMutableTag, true);
    assert.equal(JSON.stringify(discovered).includes(fixture.layoutPath), false);

    const key = createSigningKey();
    assert.throws(() => service.bundleVerify({
      bundleId: discovered.bundle.bundleId,
      signatureBundle: createKeyedSigstoreBundle(fixture.manifestDigest, key),
      trustPolicy: trustPolicy(key.publicKeyPem),
    }, context('oci-tag-verify')), errorCode('root_bundle_mutable_reference_rejected'));

    const exact = service.bundleResolve({ reference: fixture.exactReference, expectedManifestDigest: fixture.manifestDigest, discoveryOnly: false }, context('oci-exact-resolve'));
    assert.equal(exact.bundle.bundleId, discovered.bundle.bundleId);
    assert.equal(exact.bundle.executionEligible, true);
    assert.equal(exact.bundle.contentVerified, true);
    assert.equal(exact.bundle.manifestDigest, fixture.manifestDigest);

    const cached = service.bundleCache({ bundleId: exact.bundle.bundleId }, context('oci-cache'));
    assert.equal(cached.bundle.cacheState, 'CACHED');
    assert.equal(cached.bundle.contentVerified, true);
    assert.equal(JSON.stringify(cached).includes(join(root, 'root-platform', 'trust', 'cache')), false);

    const restarted = new RootTrustService({ stateRoot: root, now: () => now });
    const readback = restarted.bundleResolve({ reference: fixture.exactReference, expectedManifestDigest: fixture.manifestDigest, discoveryOnly: false }, context('oci-restart-resolve'));
    assert.equal(readback.bundle.bundleId, exact.bundle.bundleId);
    assert.equal(readback.bundle.cacheState, 'CACHED');

    const cachedLayer = join(root, 'root-platform', 'trust', 'cache', 'sha256', fixture.manifestHex, 'blobs', 'sha256', fixture.layerDescriptor.digest.slice('sha256:'.length));
    writeFileSync(cachedLayer, 'tampered-layer', { mode: 0o600 });
    const afterTamper = new RootTrustService({ stateRoot: root, now: () => now });
    const tampered = afterTamper.bundleResolve({ reference: fixture.exactReference, expectedManifestDigest: fixture.manifestDigest, discoveryOnly: false }, context('oci-tamper-readback'));
    assert.equal(tampered.bundle.cacheState, 'CACHE_FAILED');
    assert.equal(tampered.bundle.contentVerified, false);

    const invalid = createOciSkillFixture(root, { name: 'invalid-media', configMediaType: 'application/octet-stream' });
    assert.throws(() => service.bundleResolve({ reference: invalid.exactReference, expectedManifestDigest: invalid.manifestDigest, discoveryOnly: false }, context('oci-media-reject')), errorCode('root_bundle_media_type_rejected'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('keyed signature and DSSE in-toto SLSA verification enforce revocation and exact source, builder, dependencies, and products', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-trust-verify-'));
  const now = '2026-07-28T05:00:00.000Z';
  try {
    const fixture = createOciSkillFixture(root);
    const service = new RootTrustService({ stateRoot: root, now: () => now });
    const bundle = service.bundleResolve({ reference: fixture.exactReference, expectedManifestDigest: fixture.manifestDigest, discoveryOnly: false }, context('verify-resolve')).bundle;
    const key = createSigningKey();
    const signatureBundle = createKeyedSigstoreBundle(fixture.manifestDigest, key);

    const verified = service.bundleVerify({ bundleId: bundle.bundleId, signatureBundle, trustPolicy: trustPolicy(key.publicKeyPem) }, context('verify-signature'));
    assert.equal(verified.signatureVerification.state, 'VERIFIED');
    assert.equal(verified.bundle.signatureState, 'VERIFIED');
    assert.equal(verified.signatureVerification.signerDigest, key.signerDigest);

    assert.throws(() => service.bundleVerify({
      bundleId: bundle.bundleId,
      signatureBundle,
      trustPolicy: trustPolicy(key.publicKeyPem, { revokedSignerDigests: [key.signerDigest] }),
    }, context('verify-revoked')), errorCode('root_bundle_signer_revoked'));

    const damagedSignature = structuredClone(signatureBundle);
    damagedSignature.messageSignature.signature = Buffer.from('invalid-signature').toString('base64');
    assert.throws(() => service.bundleVerify({ bundleId: bundle.bundleId, signatureBundle: damagedSignature, trustPolicy: trustPolicy(key.publicKeyPem) }, context('verify-invalid-signature')), errorCode('root_bundle_signature_invalid'));

    const provenance = createProvenance(fixture.manifestHex, key);
    const provenanceResult = service.provenanceVerify({ bundleId: bundle.bundleId, envelope: provenance.envelope, verificationKeyPem: key.publicKeyPem, expected: provenance.expected }, context('verify-provenance'));
    assert.equal(provenanceResult.provenanceVerification.state, 'VERIFIED');
    assert.equal(provenanceResult.bundle.provenanceState, 'VERIFIED');

    const wrongBuilder = createProvenance(fixture.manifestHex, key, { builderId: 'https://evil.invalid/builder' });
    assert.throws(() => service.provenanceVerify({ bundleId: bundle.bundleId, envelope: wrongBuilder.envelope, verificationKeyPem: key.publicKeyPem, expected: wrongBuilder.expected }, context('verify-builder-mismatch')), errorCode('root_provenance_builder_mismatch'));

    const wrongSource = createProvenance(fixture.manifestHex, key, { sourceCommit: '3'.repeat(40) });
    assert.throws(() => service.provenanceVerify({ bundleId: bundle.bundleId, envelope: wrongSource.envelope, verificationKeyPem: key.publicKeyPem, expected: wrongSource.expected }, context('verify-source-mismatch')), errorCode('root_provenance_source_mismatch'));

    const wrongDependencies = createProvenance(fixture.manifestHex, key, { dependencies: [{ name: 'node-v24.18.0', digest: 'c'.repeat(64) }] });
    assert.throws(() => service.provenanceVerify({ bundleId: bundle.bundleId, envelope: wrongDependencies.envelope, verificationKeyPem: key.publicKeyPem, expected: wrongDependencies.expected }, context('verify-dependency-mismatch')), errorCode('root_provenance_dependency_mismatch'));

    const wrongProduct = createProvenance('d'.repeat(64), key);
    assert.throws(() => service.provenanceVerify({ bundleId: bundle.bundleId, envelope: wrongProduct.envelope, verificationKeyPem: key.publicKeyPem, expected: wrongProduct.expected }, context('verify-product-mismatch')), errorCode('root_provenance_product_mismatch'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('transparency verification persists signed inclusion, consistency, stale state, and terminal conflicts across restart', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-trust-transparency-'));
  let now = '2026-07-28T05:00:00.000Z';
  try {
    const key = createSigningKey();
    const service = new RootTrustService({ stateRoot: root, now: () => now });
    const firstEntry = '1'.repeat(64);
    const secondEntry = '2'.repeat(64);
    const first = oneLeafTransparency('babyx-log', firstEntry, now, key);
    const firstResult = service.transparencyVerify(transparencyPayload('babyx-log', first, key.publicKeyPem), context('transparency-first'));
    assert.equal(firstResult.transparency.state, 'VERIFIED');
    assert.equal(firstResult.transparency.treeSize, 1);

    now = '2026-07-28T05:00:01.000Z';
    const second = twoLeafTransparency('babyx-log', firstEntry, secondEntry, now, key);
    const secondResult = service.transparencyVerify(transparencyPayload('babyx-log', second, key.publicKeyPem), context('transparency-second'));
    assert.equal(secondResult.transparency.state, 'VERIFIED');
    assert.equal(secondResult.transparency.treeSize, 2);
    assert.deepEqual(secondResult.transparency.entryDigests, [firstEntry, secondEntry]);

    const restarted = new RootTrustService({ stateRoot: root, now: () => now });
    assert.equal(restarted.transparencyStatus({ logId: 'babyx-log' }, context('transparency-status')).transparency.rootHash, second.checkpoint.rootHash);

    const conflicting = twoLeafTransparency('babyx-log', firstEntry, '3'.repeat(64), now, key);
    assert.throws(() => restarted.transparencyVerify(transparencyPayload('babyx-log', conflicting, key.publicKeyPem), context('transparency-conflict')), errorCode('root_transparency_conflict'));
    const conflictState = restarted.transparencyStatus({ logId: 'babyx-log' }, context('transparency-conflict-status')).transparency;
    assert.equal(conflictState.state, 'CONFLICT');
    assert.equal(conflictState.criticalConflict, true);
    assert.equal(conflictState.conflictDigest.length, 64);
    assert.throws(() => restarted.transparencyVerify(transparencyPayload('babyx-log', second, key.publicKeyPem), context('transparency-conflict-terminal')), errorCode('root_transparency_conflict'));

    const stale = oneLeafTransparency('stale-log', '4'.repeat(64), '2026-07-28T03:00:00.000Z', key);
    assert.throws(() => restarted.transparencyVerify(transparencyPayload('stale-log', stale, key.publicKeyPem, 60), context('transparency-stale')), errorCode('root_transparency_checkpoint_stale'));
    assert.equal(restarted.transparencyStatus({ logId: 'stale-log' }, context('transparency-stale-status')).transparency.state, 'STALE');

    const invalidInclusion = oneLeafTransparency('invalid-inclusion-log', '5'.repeat(64), now, key);
    invalidInclusion.inclusionProof.hashes = ['6'.repeat(64)];
    assert.throws(() => restarted.transparencyVerify(transparencyPayload('invalid-inclusion-log', invalidInclusion, key.publicKeyPem), context('transparency-invalid-inclusion')), errorCode('root_transparency_inclusion_failure'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('signature policy can require an exact offline transparency monitor record', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-trust-offline-'));
  const now = '2026-07-28T05:00:00.000Z';
  try {
    const fixture = createOciSkillFixture(root);
    const service = new RootTrustService({ stateRoot: root, now: () => now });
    const bundle = service.bundleResolve({ reference: fixture.exactReference, expectedManifestDigest: fixture.manifestDigest, discoveryOnly: false }, context('offline-resolve')).bundle;
    const signingKey = createSigningKey();
    const logKey = createSigningKey();
    const entryDigest = '7'.repeat(64);
    const transparency = oneLeafTransparency('offline-log', entryDigest, now, logKey);
    service.transparencyVerify(transparencyPayload('offline-log', transparency, logKey.publicKeyPem), context('offline-transparency'));

    const tlogEntry = { logId: 'offline-log', entryDigest, checkpointDigest: transparency.checkpointDigest, integratedTime: now };
    const signatureBundle = createKeyedSigstoreBundle(fixture.manifestDigest, signingKey, [tlogEntry]);
    const verified = service.bundleVerify({ bundleId: bundle.bundleId, signatureBundle, trustPolicy: trustPolicy(signingKey.publicKeyPem, { requireTransparency: true }) }, context('offline-signature'));
    assert.equal(verified.signatureVerification.transparencyEntryDigests[0], entryDigest);

    const missing = createKeyedSigstoreBundle(fixture.manifestDigest, signingKey, [{ ...tlogEntry, logId: 'missing-log' }]);
    assert.throws(() => service.bundleVerify({ bundleId: bundle.bundleId, signatureBundle: missing, trustPolicy: trustPolicy(signingKey.publicKeyPem, { requireTransparency: true }) }, context('offline-missing')), errorCode('root_bundle_transparency_unverified'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('configured keyless certificate verification enforces local roots, issuer, and subject constraints', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-trust-keyless-'));
  const certRoot = join(root, 'certs');
  let now = new Date().toISOString();
  try {
    const fixture = createOciSkillFixture(root);
    const service = new RootTrustService({ stateRoot: root, now: () => now });
    const bundle = service.bundleResolve({ reference: fixture.exactReference, expectedManifestDigest: fixture.manifestDigest, discoveryOnly: false }, context('keyless-resolve')).bundle;
    const subjectUri = 'https://github.com/StealthEyeLLC/baby-x/.github/workflows/release.yml';
    const commands = [
      ['req','-x509','-newkey','ed25519','-nodes','-keyout',join(certRoot,'ca.key'),'-out',join(certRoot,'ca.crt'),'-subj','/CN=BabyX Test CA','-days','1'],
      ['req','-new','-newkey','ed25519','-nodes','-keyout',join(certRoot,'leaf.key'),'-out',join(certRoot,'leaf.csr'),'-subj','/CN=BabyX Keyless Fixture','-addext',`subjectAltName=URI:${subjectUri}`],
      ['x509','-req','-in',join(certRoot,'leaf.csr'),'-CA',join(certRoot,'ca.crt'),'-CAkey',join(certRoot,'ca.key'),'-CAcreateserial','-out',join(certRoot,'leaf.crt'),'-days','1','-copy_extensions','copy'],
    ];
    spawnSync('/usr/bin/mkdir', ['-p', certRoot], { encoding: 'utf8' });
    for (const args of commands) {
      const result = spawnSync('/usr/bin/openssl', args, { encoding: 'utf8', timeout: 10_000 });
      assert.equal(result.status, 0, result.stderr);
    }
    now = new Date(Date.now() + 1_000).toISOString();
    const leafKey = readFileSync(join(certRoot, 'leaf.key'));
    const leafCertificate = readFileSync(join(certRoot, 'leaf.crt'), 'utf8');
    const rootCertificate = readFileSync(join(certRoot, 'ca.crt'), 'utf8');
    const digestBytes = Buffer.from(fixture.manifestHex, 'hex');
    const signatureBundle = {
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.3',
      verificationMaterial: {
        kind: 'KEYLESS',
        publicKeyHint: null,
        certificatePem: leafCertificate,
        issuerCertificatePem: rootCertificate,
        tlogEntries: [],
      },
      messageSignature: {
        messageDigest: { algorithm: 'SHA2_256', digest: digestBytes.toString('base64') },
        signature: sign(null, digestBytes, leafKey).toString('base64'),
      },
    };
    const policy = {
      trustedPublicKeys: [],
      trustedRootCertificates: [rootCertificate],
      expectedIssuer: 'BabyX Test CA',
      expectedSubject: subjectUri,
      revokedSignerDigests: [],
      requireTransparency: false,
    };
    const verified = service.bundleVerify({ bundleId: bundle.bundleId, signatureBundle, trustPolicy: policy }, context('keyless-verify'));
    assert.equal(verified.signatureVerification.verificationKind, 'KEYLESS');
    assert.throws(() => service.bundleVerify({ bundleId: bundle.bundleId, signatureBundle, trustPolicy: { ...policy, expectedSubject: 'https://evil.invalid/workflow' } }, context('keyless-subject-mismatch')), errorCode('root_bundle_certificate_identity_mismatch'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
