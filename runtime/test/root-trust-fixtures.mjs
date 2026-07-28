import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize, sha256, signCanonical } from '../../dist/runtime/core.js';
import { dssePae, transparencyLeafHash, transparencyNodeHash } from '../../dist/runtime/root-platform/trust/crypto.js';
import { writeOciLayoutIndex } from '../../dist/runtime/root-platform/trust/oci.js';

export const SOURCE_REPOSITORY = 'https://github.com/StealthEyeLLC/baby-x';
export const SOURCE_COMMIT = '1'.repeat(40);
export const SOURCE_TREE = '2'.repeat(40);
export const BUILDER_ID = 'https://github.com/actions/runner';
export const WORKFLOW_ID = 'https://github.com/StealthEyeLLC/baby-x/.github/workflows/build.yml@refs/heads/main';
export const MATERIALS = [{ name: 'git+https://github.com/StealthEyeLLC/baby-x', digest: 'a'.repeat(64) }];
export const DEPENDENCIES = [{ name: 'node-v24.18.0', digest: 'b'.repeat(64) }];

function writeBlob(layoutPath, data) {
  const digest = sha256(data);
  const directory = join(layoutPath, 'blobs', 'sha256');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  writeFileSync(join(directory, digest), data, { mode: 0o600 });
  return { digest: `sha256:${digest}`, size: data.length };
}

export function createOciSkillFixture(root, options = {}) {
  const layoutPath = join(root, options.name ?? 'skill-layout');
  const config = Buffer.from(JSON.stringify({ schemaVersion: '1.0.0', skillId: 'fixture.skill', entrypoint: 'skill.json' }), 'utf8');
  const layer = Buffer.from('fixture-skill-layer\n', 'utf8');
  const configDescriptor = writeBlob(layoutPath, config);
  const layerDescriptor = writeBlob(layoutPath, layer);
  const manifest = {
    schemaVersion: 2,
    mediaType: options.manifestMediaType ?? 'application/vnd.oci.image.manifest.v1+json',
    config: {
      mediaType: options.configMediaType ?? 'application/vnd.stealtheye.babyx.skill.config.v1+json',
      ...configDescriptor,
    },
    layers: [{
      mediaType: options.layerMediaType ?? 'application/vnd.stealtheye.babyx.skill.layer.v1.tar+gzip',
      ...layerDescriptor,
    }],
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest), 'utf8');
  const manifestDescriptor = writeBlob(layoutPath, manifestBytes);
  writeOciLayoutIndex(layoutPath, {
    mediaType: manifest.mediaType,
    digest: manifestDescriptor.digest,
    size: manifestDescriptor.size,
  }, 'latest');
  return {
    layoutPath,
    manifest,
    manifestBytes,
    manifestDigest: manifestDescriptor.digest,
    manifestHex: manifestDescriptor.digest.slice('sha256:'.length),
    exactReference: `oci-layout:${layoutPath}@${manifestDescriptor.digest}`,
    tagReference: `oci-layout:${layoutPath}:latest`,
    configDescriptor,
    layerDescriptor,
  };
}

export function createSigningKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const signerDigest = sha256(publicKey.export({ type: 'spki', format: 'der' }));
  return { publicKey, privateKey, publicKeyPem, privateKeyPem, signerDigest };
}

export function createKeyedSigstoreBundle(manifestDigest, key, tlogEntries = []) {
  const digestBytes = Buffer.from(manifestDigest.slice('sha256:'.length), 'hex');
  return {
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.3',
    verificationMaterial: {
      kind: 'KEYED',
      publicKeyHint: key.signerDigest,
      certificatePem: null,
      issuerCertificatePem: null,
      tlogEntries,
    },
    messageSignature: {
      messageDigest: { algorithm: 'SHA2_256', digest: digestBytes.toString('base64') },
      signature: sign(null, digestBytes, key.privateKey).toString('base64'),
    },
  };
}

export function createProvenance(manifestHex, key, overrides = {}) {
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: overrides.subject ?? [{ name: 'skill-bundle', digest: { sha256: manifestHex } }],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: overrides.workflowId ?? WORKFLOW_ID,
        externalParameters: {
          source: {
            repository: overrides.sourceRepository ?? SOURCE_REPOSITORY,
            commit: overrides.sourceCommit ?? SOURCE_COMMIT,
            tree: overrides.sourceTree ?? SOURCE_TREE,
          },
        },
        resolvedDependencies: overrides.materials ?? MATERIALS.map((entry) => ({ uri: entry.name, digest: { sha256: entry.digest } })),
        internalParameters: {
          dependencies: overrides.dependencies ?? DEPENDENCIES,
        },
      },
      runDetails: { builder: { id: overrides.builderId ?? BUILDER_ID } },
    },
  };
  const payload = Buffer.from(JSON.stringify(statement), 'utf8');
  const envelope = {
    payloadType: 'application/vnd.in-toto+json',
    payload: payload.toString('base64'),
    signatures: [{
      keyid: key.signerDigest,
      sig: sign(null, dssePae('application/vnd.in-toto+json', payload), key.privateKey).toString('base64'),
    }],
  };
  const expected = {
    sourceRepository: SOURCE_REPOSITORY,
    sourceCommit: SOURCE_COMMIT,
    sourceTree: SOURCE_TREE,
    builderId: BUILDER_ID,
    workflowId: WORKFLOW_ID,
    materials: MATERIALS,
    dependencies: DEPENDENCIES,
    products: [{ name: 'skill-bundle', digest: manifestHex }],
  };
  return { statement, envelope, expected };
}

export function createCheckpoint(logId, treeSize, rootHash, issuedAt, key) {
  const unsigned = {
    logId,
    treeSize,
    rootHash,
    issuedAt,
    signerKeyId: key.signerDigest,
  };
  return { ...unsigned, signature: signCanonical(key.privateKeyPem, unsigned) };
}

export function oneLeafTransparency(logId, entryDigest, issuedAt, key) {
  const rootHash = transparencyLeafHash(entryDigest);
  const checkpoint = createCheckpoint(logId, 1, rootHash, issuedAt, key);
  return {
    entryDigest,
    checkpoint,
    checkpointDigest: sha256(canonicalize(checkpoint)),
    inclusionProof: { leafIndex: 0, treeSize: 1, hashes: [] },
    consistencyProof: null,
  };
}

export function twoLeafTransparency(logId, firstEntryDigest, secondEntryDigest, issuedAt, key) {
  const firstLeaf = transparencyLeafHash(firstEntryDigest);
  const secondLeaf = transparencyLeafHash(secondEntryDigest);
  const rootHash = transparencyNodeHash(firstLeaf, secondLeaf);
  const checkpoint = createCheckpoint(logId, 2, rootHash, issuedAt, key);
  return {
    entryDigest: secondEntryDigest,
    checkpoint,
    checkpointDigest: sha256(canonicalize(checkpoint)),
    inclusionProof: { leafIndex: 1, treeSize: 2, hashes: [firstLeaf] },
    consistencyProof: { firstSize: 1, secondSize: 2, hashes: [secondLeaf] },
  };
}

export function trustPolicy(publicKeyPem, overrides = {}) {
  return {
    trustedPublicKeys: [publicKeyPem],
    trustedRootCertificates: [],
    expectedIssuer: null,
    expectedSubject: null,
    revokedSignerDigests: [],
    requireTransparency: false,
    ...overrides,
  };
}

export function context(key) {
  return { subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner', idempotencyKey: key };
}
