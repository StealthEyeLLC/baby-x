import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  ArtifactManager,
  ImmutableReleaseContentService,
  ReleaseApplianceStore,
  ReleaseArchiveError,
  ReleaseContentError,
  buildOutputCacheKey,
  canonicalize,
  createDeterministicTar,
  dependencyCacheKey,
  normalizeBuildProfile,
  parseDeterministicTar,
  sha256,
  validateDeterministicEntries,
} from '../../dist/runtime/index.js';

const GIB = 1024 * 1024 * 1024;
const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);
const DIGEST_C = 'c'.repeat(64);
const GIT_A = 'a'.repeat(40);
const GIT_B = 'b'.repeat(40);
const FIXED_TIME = '2026-07-26T15:00:00.000Z';

function tempRoot(prefix = 'baby-x-release-content-') {
  return mkdtempSync(join(tmpdir(), prefix));
}

function healthyCapacity() {
  return {
    observedAt: FIXED_TIME,
    rootTotalBytes: 100 * GIB,
    rootAvailableBytes: 70 * GIB,
    rootAvailableInodes: 1_000_000,
    zfsPool: 'babycert',
    zfsAvailableBytes: 70 * GIB,
    memoryAvailableBytes: 16 * GIB,
    cpuPressure: { some: 0 },
    memoryPressure: { some: 0 },
    ioPressure: { some: 0 },
  };
}

function lowCapacity() {
  return {
    ...healthyCapacity(),
    rootAvailableBytes: 11 * GIB,
  };
}

function harness({ capacity = healthyCapacity, wrapArtifacts, productionRoots = [] } = {}) {
  const root = tempRoot();
  const isolatedBuildRoot = join(root, 'isolated-build');
  const releaseRoot = join(root, 'releases');
  const quarantineRoot = join(root, 'quarantine');
  const artifactRoot = join(root, 'artifacts');
  const storeRoot = join(root, 'store');
  for (const path of [isolatedBuildRoot, releaseRoot, quarantineRoot]) mkdirSync(path, { recursive: true });
  const baseArtifacts = new ArtifactManager(artifactRoot);
  const artifacts = wrapArtifacts === undefined ? baseArtifacts : wrapArtifacts(baseArtifacts);
  const store = new ReleaseApplianceStore(storeRoot);
  const service = new ImmutableReleaseContentService({
    isolatedBuildRoot,
    releaseRoot,
    quarantineRoot,
    artifacts,
    store,
    capacityProvider: capacity,
    productionRoots,
    now: () => FIXED_TIME,
  });
  return { root, isolatedBuildRoot, releaseRoot, quarantineRoot, artifactRoot, baseArtifacts, artifacts, store, service };
}

function runGit(repository, args, env = {}) {
  const result = spawnSync('/usr/bin/git', ['-C', repository, ...args], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  if (result.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${result.stderr}`);
  return result.stdout.trim();
}

function createGitRepository() {
  const repository = tempRoot('baby-x-source-repo-');
  runGit(repository, ['init', '-b', 'main']);
  runGit(repository, ['config', 'user.name', 'Release Test']);
  runGit(repository, ['config', 'user.email', 'release-test@example.invalid']);
  mkdirSync(join(repository, 'src'), { recursive: true });
  mkdirSync(join(repository, 'dist'), { recursive: true });
  writeFileSync(join(repository, 'package-lock.json'), '{"name":"fixture","lockfileVersion":3}\n');
  writeFileSync(join(repository, 'src', 'index.js'), 'console.log("one");\n');
  writeFileSync(join(repository, 'dist', 'tracked.js'), 'export const tracked = true;\n');
  runGit(repository, ['add', '.']);
  runGit(repository, ['commit', '-m', 'fixture one'], {
    GIT_AUTHOR_DATE: '2026-07-26T12:00:00Z',
    GIT_COMMITTER_DATE: '2026-07-26T12:00:00Z',
  });
  return repository;
}

function sourceIdentity(overrides = {}) {
  return {
    schemaVersion: '1.0.0',
    repository: 'StealthEyeLLC/fixture',
    repositoryId: 'repo-fixture-1',
    refContext: 'refs/heads/main',
    commit: GIT_A,
    tree: GIT_B,
    sourceArchiveArtifactId: 'source-artifact-fixture',
    sourceArchiveSha256: DIGEST_A,
    sourceManifestDigest: DIGEST_B,
    lockfilePath: 'package-lock.json',
    lockfileDigest: DIGEST_C,
    submodules: [],
    gitLfsObjects: [],
    resolvedAt: FIXED_TIME,
    resolverReceiptId: 'source-receipt-fixture',
    verifiedCommitState: 'VERIFIED',
    ...overrides,
  };
}

function buildProfile() {
  return {
    schemaVersion: '1.0.0',
    profileId: 'node-release-v1',
    platform: 'linux-amd64',
    packageManager: 'npm',
    installSteps: [{
      name: 'install',
      argv: ['npm', 'ci', '--ignore-scripts'],
      cwd: '.',
      environment: { NODE_ENV: 'production' },
      timeoutMs: 120_000,
      networkMode: 'RESTRICTED',
    }],
    buildSteps: [{
      name: 'build',
      argv: ['npm', 'run', 'build', '--', '--production'],
      cwd: '.',
      environment: { NODE_ENV: 'production' },
      timeoutMs: 120_000,
      networkMode: 'NONE',
    }],
    outputPaths: ['dist'],
    cachePaths: ['.npm-cache'],
    resourcePolicy: { memoryBytes: 512 * 1024 * 1024, cpuWeight: 100 },
  };
}

function packageRequest(outputDirectory, overrides = {}) {
  return {
    serviceId: 'fixture-service',
    outputDirectory,
    source: sourceIdentity(),
    buildId: 'build-fixture-1',
    buildProfile: buildProfile(),
    toolchainIdentity: { node: '24.18.0', npm: '11.6.2' },
    dependencyIdentity: { lockfileDigest: DIGEST_C, installMode: 'npm-ci' },
    serviceDefinitionDigest: DIGEST_A,
    executableTemplate: { argv: ['/usr/bin/node', 'app/server.js'] },
    runtimeRequirements: { node: '24.18.0', endpoint: 'unix-socket' },
    requiredConfigurationNames: ['NODE_ENV'],
    requiredCredentialNames: ['DATABASE_URL'],
    writablePaths: ['/var/lib/fixture-service'],
    readinessCompatibility: { protocol: 'http', path: '/healthz' },
    smokeCompatibility: { profile: 'fixture-smoke-v1' },
    minimumApplianceVersion: '1.0.0',
    producerIdentity: { authority: 'babyx.job', jobId: 'job-fixture-build' },
    provenanceReferences: [{ kind: 'build-receipt', id: 'receipt-build-fixture' }],
    sbomReferences: [],
    createdAt: FIXED_TIME,
    sourceEpoch: 1_785_074_400,
    ...overrides,
  };
}

function makeOutput(root, text = 'console.log("release");\n') {
  const output = join(root, `output-${sha256(text).slice(0, 12)}-${Math.random().toString(16).slice(2)}`);
  mkdirSync(output, { recursive: true });
  writeFileSync(join(output, 'server.js'), text, { mode: 0o755 });
  mkdirSync(join(output, 'assets'));
  writeFileSync(join(output, 'assets', 'version.txt'), 'v1\n');
  return output;
}

function errorCode(code) {
  return (error) => (error instanceof ReleaseContentError || error instanceof ReleaseArchiveError) && error.code === code;
}

function rewriteHeader(tar, mutate) {
  const output = Buffer.from(tar);
  mutate(output.subarray(0, 512));
  output.fill(0x20, 148, 156);
  let checksum = 0;
  for (const byte of output.subarray(0, 512)) checksum += byte;
  Buffer.from(`${checksum.toString(8).padStart(6, '0')}\0 `, 'ascii').copy(output, 148);
  return output;
}

test('exact mutable ref resolution binds immutable commit/tree and retains tracked build output', () => {
  const repository = createGitRepository();
  const h = harness();
  try {
    const firstCommit = runGit(repository, ['rev-parse', 'HEAD']);
    const firstTree = runGit(repository, ['rev-parse', 'HEAD^{tree}']);
    const first = h.service.resolveSource({
      repositoryPath: repository,
      repository: 'StealthEyeLLC/fixture',
      repositoryId: 'repo-fixture-1',
      ref: 'main',
      expectedCommit: firstCommit,
      expectedTree: firstTree,
      ownerPrincipal: 'owner-source-test',
      verifiedCommitState: 'VERIFIED',
      resolvedAt: FIXED_TIME,
    });
    assert.equal(first.sourceIdentity.commit, firstCommit);
    assert.equal(first.sourceIdentity.tree, firstTree);
    assert.equal(first.sourceIdentity.refContext, 'main');
    assert.equal('branch' in first.sourceIdentity, false);
    assert.ok(first.sourceManifest.entries.some((entry) => entry.path === 'source/dist/tracked.js'));
    assert.equal(h.baseArtifacts.verify(first.artifact.id).valid, true);

    writeFileSync(join(repository, 'src', 'index.js'), 'console.log("two");\n');
    runGit(repository, ['add', 'src/index.js']);
    runGit(repository, ['commit', '-m', 'fixture two'], {
      GIT_AUTHOR_DATE: '2026-07-26T12:01:00Z',
      GIT_COMMITTER_DATE: '2026-07-26T12:01:00Z',
    });
    const secondCommit = runGit(repository, ['rev-parse', 'HEAD']);
    assert.notEqual(secondCommit, firstCommit);
    const artifactCount = h.baseArtifacts.list().length;
    assert.throws(() => h.service.resolveSource({
      repositoryPath: repository,
      repository: 'StealthEyeLLC/fixture',
      repositoryId: 'repo-fixture-1',
      ref: 'main',
      expectedCommit: firstCommit,
      ownerPrincipal: 'owner-source-test',
      resolvedAt: FIXED_TIME,
    }), errorCode('release_source_mismatch'));
    assert.equal(h.baseArtifacts.list().length, artifactCount);

    const oldAgain = h.service.resolveSource({
      repositoryPath: repository,
      repository: 'StealthEyeLLC/fixture',
      repositoryId: 'repo-fixture-1',
      ref: firstCommit,
      expectedCommit: firstCommit,
      expectedTree: firstTree,
      ownerPrincipal: 'owner-source-test',
      verifiedCommitState: 'VERIFIED',
      resolvedAt: FIXED_TIME,
    });
    assert.equal(oldAgain.sourceIdentity.sourceArchiveArtifactId, first.sourceIdentity.sourceArchiveArtifactId);
    assert.equal(oldAgain.sourceIdentity.sourceArchiveSha256, first.sourceIdentity.sourceArchiveSha256);
  } finally {
    rmSync(repository, { recursive: true, force: true });
    rmSync(h.root, { recursive: true, force: true });
  }
});

test('source resolution rejects tracked secret material before artifact creation', () => {
  const repository = createGitRepository();
  const h = harness();
  try {
    writeFileSync(join(repository, '.env'), 'DATABASE_PASSWORD=not-allowed\n');
    runGit(repository, ['add', '.env']);
    runGit(repository, ['commit', '-m', 'add prohibited secret'], {
      GIT_AUTHOR_DATE: '2026-07-26T12:02:00Z',
      GIT_COMMITTER_DATE: '2026-07-26T12:02:00Z',
    });
    assert.throws(() => h.service.resolveSource({
      repositoryPath: repository,
      repository: 'StealthEyeLLC/fixture',
      ref: 'HEAD',
      ownerPrincipal: 'owner-source-secret-test',
      resolvedAt: FIXED_TIME,
    }), errorCode('release_secret_material_rejected'));
    assert.equal(h.baseArtifacts.list().length, 0);
  } finally {
    rmSync(repository, { recursive: true, force: true });
    rmSync(h.root, { recursive: true, force: true });
  }
});

test('normalized profiles preserve argv order and produce exact cache identities', () => {
  const profile = normalizeBuildProfile(buildProfile());
  assert.deepEqual(profile.installSteps[0].argv, ['npm', 'ci', '--ignore-scripts']);
  assert.deepEqual(profile.buildSteps[0].argv, ['npm', 'run', 'build', '--', '--production']);
  assert.match(profile.profileDigest, /^[a-f0-9]{64}$/u);
  const dependency = dependencyCacheKey(sourceIdentity(), profile, { node: '24.18.0' });
  const build = buildOutputCacheKey(sourceIdentity(), profile, { node: '24.18.0' }, DIGEST_A);
  assert.match(dependency, /^[a-f0-9]{64}$/u);
  assert.match(build, /^[a-f0-9]{64}$/u);
  assert.notEqual(dependency, build);
  assert.equal(dependency, dependencyCacheKey(sourceIdentity(), profile, { node: '24.18.0' }));
});

test('dependency cache reports miss, hit, and corruption as distinct outcomes', () => {
  const h = harness();
  try {
    const key = sha256('dependency-cache-key');
    assert.equal(h.service.lookupCache('dependency', key).result, 'MISS');
    const prepared = join(h.isolatedBuildRoot, 'dependency-cache.bin');
    writeFileSync(prepared, 'cache-bytes-v1');
    const stored = h.service.storeCache('dependency', key, prepared, 'owner-cache-test');
    assert.equal(stored.result, 'STORED');
    assert.equal(h.service.lookupCache('dependency', key).result, 'HIT');
    const record = h.baseArtifacts.get(stored.artifact.id);
    writeFileSync(record.path, 'corrupt-cache-bytes');
    const corrupt = h.service.lookupCache('dependency', key);
    assert.equal(corrupt.result, 'CORRUPT');
    assert.deepEqual(corrupt.artifactIds, [stored.artifact.id]);
  } finally {
    rmSync(h.root, { recursive: true, force: true });
  }
});

test('release artifact compression is deterministic across independent authorities', () => {
  const first = harness();
  const second = harness();
  try {
    const firstOutput = makeOutput(first.isolatedBuildRoot);
    const secondOutput = makeOutput(second.isolatedBuildRoot);
    const firstPackage = first.service.packageRelease(packageRequest(firstOutput));
    const secondPackage = second.service.packageRelease(packageRequest(secondOutput));
    assert.equal(firstPackage.artifact.sha256, secondPackage.artifact.sha256);
    assert.equal(firstPackage.deterministicDigest, secondPackage.deterministicDigest);
    assert.equal(firstPackage.manifest.artifactSha256, firstPackage.artifact.sha256);
    assert.equal(first.baseArtifacts.verify(firstPackage.artifact.id).valid, true);
    assert.equal(second.baseArtifacts.verify(secondPackage.artifact.id).valid, true);
  } finally {
    rmSync(first.root, { recursive: true, force: true });
    rmSync(second.root, { recursive: true, force: true });
  }
});

test('archive validation rejects traversal, escaping symlinks, special files, and setuid modes', () => {
  const bytes = Buffer.from('safe\n');
  const safeEntry = {
    path: 'app/safe.txt',
    type: 'file',
    mode: 0o644,
    size: bytes.length,
    sha256: sha256(bytes),
    data: bytes.toString('base64'),
    dataEncoding: 'base64',
  };
  assert.throws(() => validateDeterministicEntries([{ ...safeEntry, path: '../escape' }]), errorCode('release_archive_unsafe_path'));
  assert.throws(() => validateDeterministicEntries([{
    path: 'app/link',
    type: 'symlink',
    mode: 0o777,
    size: Buffer.byteLength('../../outside'),
    sha256: sha256(Buffer.from('../../outside')),
    linkTarget: '../../outside',
  }]), errorCode('release_archive_symlink_escape'));
  assert.throws(() => validateDeterministicEntries([{ ...safeEntry, mode: 0o4755 }]), errorCode('release_archive_unsafe_mode'));

  const tar = createDeterministicTar([safeEntry], 0);
  const traversalTar = rewriteHeader(tar, (header) => {
    header.fill(0, 0, 100);
    Buffer.from('../evil', 'utf8').copy(header, 0);
  });
  assert.throws(() => parseDeterministicTar(traversalTar), errorCode('release_archive_unsafe_path'));
  const specialTar = rewriteHeader(tar, (header) => { header[156] = '3'.charCodeAt(0); });
  assert.throws(() => parseDeterministicTar(specialTar), errorCode('release_archive_special_file'));
});

test('capacity admission rejects before artifact bytes or temporary package files are persisted', () => {
  const h = harness({ capacity: lowCapacity });
  try {
    const output = makeOutput(h.isolatedBuildRoot);
    const before = h.baseArtifacts.list().length;
    assert.throws(() => h.service.packageRelease(packageRequest(output)), errorCode('release_capacity_insufficient'));
    assert.equal(h.baseArtifacts.list().length, before);
    const temporaryFiles = readdirSync(h.isolatedBuildRoot).filter((name) => name.endsWith('.tmp'));
    assert.deepEqual(temporaryFiles, []);
    assert.equal(h.store.listRecordIdentities(100).some((identity) => identity.schemaId === 'CapacitySnapshotV1'), true);
  } finally {
    rmSync(h.root, { recursive: true, force: true });
  }
});

test('artifact response loss recovers by exact content key without duplicate artifact bytes', () => {
  let thrown = false;
  const h = harness({
    wrapArtifacts(base) {
      return {
        create(name, sourcePath, metadata) {
          const record = base.create(name, sourcePath, metadata);
          if (!thrown) {
            thrown = true;
            throw new Error('simulated response loss after artifact finalization');
          }
          return record;
        },
        get: (id) => base.get(id),
        list: () => base.list(),
        verify: (id) => base.verify(id),
      };
    },
  });
  try {
    const output = makeOutput(h.isolatedBuildRoot);
    const packaged = h.service.packageRelease(packageRequest(output));
    assert.equal(packaged.artifact.state, 'finalized');
    assert.equal(h.baseArtifacts.list().length, 1);
    assert.equal(h.baseArtifacts.verify(packaged.artifact.id).valid, true);
    const replay = h.service.packageRelease(packageRequest(output));
    assert.equal(replay.artifact.id, packaged.artifact.id);
    assert.equal(h.baseArtifacts.list().length, 1);
  } finally {
    rmSync(h.root, { recursive: true, force: true });
  }
});

test('materialization is content-addressed, immutable, idempotent, and conflicting bytes are quarantined', () => {
  const h = harness();
  try {
    const output = makeOutput(h.isolatedBuildRoot);
    const packaged = h.service.packageRelease(packageRequest(output));
    const materialized = h.service.materializeRelease({
      artifactId: packaged.artifact.id,
      artifactSha256: packaged.artifact.sha256,
      reservationOwner: 'owner-materialization-test',
    });
    assert.equal(materialized.reused, false);
    assert.equal(materialized.verification.valid, true);
    assert.equal(materialized.path, join(h.releaseRoot, packaged.artifact.sha256));
    assert.equal(statSync(join(materialized.path, 'app', 'server.js')).mode & 0o222, 0);
    const replay = h.service.materializeRelease({
      artifactId: packaged.artifact.id,
      artifactSha256: packaged.artifact.sha256,
      reservationOwner: 'owner-materialization-test',
    });
    assert.equal(replay.reused, true);

    const releaseRecord = h.service.createReleaseRecord({
      serviceId: 'fixture-service',
      artifactId: packaged.artifact.id,
      artifactSha256: packaged.artifact.sha256,
      artifactSizeBytes: packaged.artifact.size,
      manifestDigest: packaged.manifest.manifestDigest,
      sourceCommit: packaged.manifest.source.commit,
      sourceTree: packaged.manifest.source.tree,
      lockfileDigest: packaged.manifest.source.lockfileDigest,
      buildId: packaged.manifest.buildId,
      certificationId: 'certification-fixture-1',
      materializationPath: materialized.path,
      materializationMethod: 'EXTRACT',
      materializationVerifiedAt: FIXED_TIME,
      installedManifestDigest: materialized.verification.expectedDigest,
      immutablePermissionsVerified: true,
      credentialSetReferenceDigest: DIGEST_B,
      compatibleApplianceVersion: '1.0.0',
      retentionClass: 'RECENT',
      pinned: false,
      slotReferences: [],
      deploymentReferences: [],
      integrityState: 'VERIFIED',
      createdAt: FIXED_TIME,
      ownerPrincipal: 'owner-release-record-test',
      idempotencyKey: 'release-record-fixture-1',
      receiptReferences: ['receipt-materialization-fixture'],
    });
    assert.equal(releaseRecord.artifactSha256, packaged.artifact.sha256);
    assert.equal(h.store.getRecord('ReleaseRecordV1', releaseRecord.releaseId).integrityState, 'VERIFIED');

    const serverPath = join(materialized.path, 'app', 'server.js');
    chmodSync(serverPath, 0o644);
    writeFileSync(serverPath, 'corrupt\n');
    assert.throws(() => h.service.materializeRelease({
      artifactId: packaged.artifact.id,
      artifactSha256: packaged.artifact.sha256,
      reservationOwner: 'owner-materialization-test',
    }), errorCode('release_artifact_invalid'));
    assert.equal(existsSync(materialized.path), false);
    assert.equal(readdirSync(h.quarantineRoot).length, 1);
  } finally {
    rmSync(h.root, { recursive: true, force: true });
  }
});

test('build and cache inputs under production roots are rejected before artifact authority use', () => {
  const root = tempRoot();
  const productionRoot = join(root, 'production');
  mkdirSync(productionRoot, { recursive: true });
  const h = harness({ productionRoots: [productionRoot] });
  try {
    const productionOutput = makeOutput(productionRoot);
    assert.throws(() => h.service.packageRelease(packageRequest(productionOutput)), errorCode('release_production_build_path_forbidden'));
    const productionCache = join(productionRoot, 'cache.bin');
    writeFileSync(productionCache, 'cache');
    assert.throws(() => h.service.storeCache('build', sha256('production-cache'), productionCache, 'owner-production-path-test'), errorCode('release_production_build_path_forbidden'));
    assert.equal(h.baseArtifacts.list().length, 0);
  } finally {
    rmSync(h.root, { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
  }
});
