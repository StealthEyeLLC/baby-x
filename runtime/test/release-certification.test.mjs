import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  ArtifactManager,
  BabyXRuntime,
  ReleaseApplianceStore,
  ReleaseCertificationError,
  ReleaseCertificationService,
  canonicalize,
  normalizeReleaseCertificationProfile,
  sha256,
} from '../../dist/runtime/index.js';

const FIXED_TIME = '2026-07-26T15:00:00.000Z';
const GIT_A = 'a'.repeat(40);
const GIT_B = 'b'.repeat(40);
const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);
const DIGEST_C = 'c'.repeat(64);

function sourceIdentity() {
  return {
    schemaVersion: '1.0.0',
    repository: 'StealthEyeLLC/fixture',
    repositoryId: 'fixture-repository',
    refContext: 'refs/heads/main',
    commit: GIT_A,
    tree: GIT_B,
    sourceArchiveArtifactId: 'artifact-source-fixture',
    sourceArchiveSha256: DIGEST_A,
    sourceManifestDigest: DIGEST_B,
    lockfilePath: 'package-lock.json',
    lockfileDigest: DIGEST_C,
    submodules: [],
    gitLfsObjects: [],
    resolvedAt: FIXED_TIME,
    resolverReceiptId: 'source-receipt-fixture',
    verifiedCommitState: 'VERIFIED',
  };
}

function profile(overrides = {}) {
  const kinds = ['dependency', 'startup', 'readiness', 'smoke', 'security', 'resource', 'shutdown', 'acceptance'];
  return {
    schemaVersion: '1.0.0',
    id: 'release-certification-fixture',
    version: '1.0.0',
    steps: kinds.map((kind) => ({ id: `${kind}-check`, kind, argv: ['/usr/bin/true'], cwd: '/', timeoutMs: 10_000, required: true })),
    requiredCredentialNames: [],
    endpointContract: { type: 'unix-socket', path: '/run/fixture/service.sock' },
    ...overrides,
  };
}

function manifest(artifact, overrides = {}) {
  const unsigned = {
    schemaVersion: '1.0.0',
    artifactId: artifact.id,
    artifactSha256: artifact.sha256,
    sizeBytes: artifact.size,
    compression: { format: 'zstd', deterministic: true },
    source: sourceIdentity(),
    buildId: 'build-fixture-1',
    toolchainIdentity: { node: '24.18.0', npm: '11.6.2' },
    dependencyIdentity: { lockfileDigest: DIGEST_C, installMode: 'npm-ci' },
    serviceDefinitionDigest: DIGEST_A,
    layoutVersion: '1.0.0',
    executableTemplate: { argv: ['/usr/bin/node', 'app/server.js'] },
    runtimeRequirements: { node: '24.18.0' },
    requiredConfigurationNames: ['NODE_ENV'],
    requiredCredentialNames: [],
    files: [],
    writablePaths: ['/var/lib/fixture'],
    readinessCompatibility: { protocol: 'http', path: '/healthz' },
    smokeCompatibility: { profile: 'fixture-smoke-v1' },
    minimumApplianceVersion: '1.0.0',
    createdAt: FIXED_TIME,
    producerIdentity: { authority: 'babyx.job', jobId: 'job-build-fixture' },
    provenanceReferences: [],
    sbomReferences: [],
    ...overrides,
  };
  return { ...unsigned, manifestDigest: sha256(canonicalize(unsigned)) };
}

function request(artifact, overrides = {}) {
  const releaseManifest = overrides.manifest ?? manifest(artifact);
  return {
    schemaVersion: '1.0.0',
    artifactId: artifact.id,
    artifactSha256: artifact.sha256,
    manifest: releaseManifest,
    serviceDefinitionDigest: DIGEST_A,
    profile: profile(),
    baseSnapshot: { name: 'babycert/base/noble@golden-v1', guid: '9351137475418520293', creationTxg: 53 },
    machine: {
      machineName: 'release-certification-fixture',
      clone: { dataset: 'babycert/runs/release-certification-fixture', mountpoint: '/var/lib/baby-x/machines/release-certification-fixture', expectedRootPrefix: '/var/lib/baby-x/machines' },
      launch: { boot: true, networkMode: 'private', readOnlyRoot: false, binds: [], environment: [], properties: [] },
    },
    runtimeIdentity: { os: 'ubuntu-noble', architecture: 'amd64', node: '24.18.0' },
    dependencyIdentity: { lockfileDigest: DIGEST_C, installMode: 'npm-ci' },
    applianceCompatibilityVersion: '1.0.0',
    externalContractIdentities: { databaseSchema: 'fixture-v1', apiContract: 'fixture-v1' },
    securityPolicyVersion: 'security-v1',
    invalidationConditions: [],
    ...overrides,
    manifest: releaseManifest,
  };
}

class FakeJobs {
  records = new Map();
  reconcile(id) {
    const record = this.records.get(id);
    if (record === undefined) throw new Error(`unknown job ${id}`);
    return structuredClone(record);
  }
}

class FakeCertificationAuthority {
  calls = [];
  failPhase = null;
  cleanupFailure = false;
  activeJob = false;
  blockFirst = false;
  evidenceArtifactId;
  jobs;

  constructor(jobs, evidenceArtifactId) {
    this.jobs = jobs;
    this.evidenceArtifactId = evidenceArtifactId;
  }

  async run(payload, context) {
    this.calls.push({ payload: structuredClone(payload), context: structuredClone(context) });
    if (this.blockFirst && this.calls.length === 1) return new Promise(() => {});
    const childId = `child-certification-${this.calls.length}`;
    const jobId = `child-job-${this.calls.length}`;
    this.jobs.records.set(jobId, { id: jobId, status: this.activeJob ? 'running' : 'completed', exitCode: this.activeJob ? null : 0, signal: null, argv: ['/usr/bin/true'], createdAt: FIXED_TIME, startedAt: FIXED_TIME, ...(this.activeJob ? {} : { completedAt: FIXED_TIME }) });
    const steps = payload.profile.steps.map((step) => ({ id: step.id, phase: step.phase, required: step.required, state: this.failPhase === step.phase ? 'failed' : 'passed', jobId, exitCode: this.failPhase === step.phase ? 1 : 0, completedAt: FIXED_TIME }));
    const failed = steps.find((step) => step.state === 'failed');
    return {
      certification: {
        certificationId: childId,
        state: this.cleanupFailure ? 'RECOVERY_REQUIRED' : failed === undefined ? 'SUCCEEDED' : 'FAILED',
        machineId: 'mx-release-certification-fixture',
        jobIds: [jobId],
        profile: { id: payload.profile.id, version: payload.profile.version, steps },
        evidence: { status: 'complete', indexArtifactReference: this.evidenceArtifactId, indexDigest: DIGEST_A },
        cleanup: { required: true, stopStatus: 'succeeded', destroyStatus: this.cleanupFailure ? 'failed' : 'succeeded', absenceVerified: !this.cleanupFailure, sourcePreserved: true },
        proofReferences: [DIGEST_B],
        artifactReferences: [this.evidenceArtifactId],
        testResult: failed === undefined ? { status: 'passed' } : { status: 'failed', failedStepId: failed.id },
      },
    };
  }
}

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-release-certification-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const artifactSource = join(root, 'release.tar.zst');
  writeFileSync(artifactSource, Buffer.from('deterministic-release-artifact'));
  const evidenceSource = join(root, 'evidence.json');
  writeFileSync(evidenceSource, `${canonicalize({ evidence: 'fixture' })}\n`);
  const artifacts = new ArtifactManager(join(root, 'artifacts'));
  const artifact = artifacts.create('release-fixture', artifactSource, { kind: 'release-artifact' });
  const evidence = artifacts.create('release-certification-evidence', evidenceSource, { kind: 'certification-evidence' });
  const store = new ReleaseApplianceStore(join(root, 'release-store'));
  const jobs = new FakeJobs();
  const child = new FakeCertificationAuthority(jobs, evidence.id);
  const service = new ReleaseCertificationService({ stateRoot: root, store, artifacts, certification: child, jobs, now: () => FIXED_TIME });
  return { root, artifacts, artifact, evidence, store, jobs, child, service };
}

function context(key = 'release-certification-test-0001', subject = 'owner:test') {
  return { idempotencyKey: key, subject, authorityClass: 'owner' };
}

test('release certification profile normalization is deterministic and typed', () => {
  const first = normalizeReleaseCertificationProfile(profile());
  const second = normalizeReleaseCertificationProfile({ ...profile(), requiredCredentialNames: [] });
  assert.equal(first.profileDigest, second.profileDigest);
  assert.deepEqual(first.steps.map((step) => step.kind), ['dependency', 'startup', 'readiness', 'smoke', 'security', 'resource', 'shutdown', 'acceptance']);
  assert.throws(() => normalizeReleaseCertificationProfile(profile({ steps: [{ id: 'bad', kind: 'route', argv: ['/usr/bin/true'], cwd: '/', timeoutMs: 1, required: true }] })), (error) => error instanceof ReleaseCertificationError && error.code === 'release_invalid_request');
});

test('valid immutable artifact succeeds with exact disposable bindings, evidence, and cleanup', async (t) => {
  const f = fixture(t);
  const result = await f.service.certify(request(f.artifact), context());
  assert.equal(result.certification.state, 'SUCCEEDED');
  assert.equal(result.certification.artifactIntegrityResult.status, 'PASSED');
  assert.equal(result.certification.dependencyResult.status, 'PASSED');
  assert.equal(result.certification.startupResult.status, 'PASSED');
  assert.equal(result.certification.readinessResult.status, 'PASSED');
  assert.equal(result.certification.smokeResult.status, 'PASSED');
  assert.equal(result.certification.securityResult.status, 'PASSED');
  assert.equal(result.certification.cleanupResult.absenceVerified, true);
  assert.equal(result.certification.sourcePreservationResult.preserved, true);
  assert.equal(result.certification.activeJobIds.length, 0);
  assert.equal(f.artifacts.verify(result.certification.evidenceIndexId).valid, true);
  assert.equal(f.child.calls.length, 1);
  const childRequest = f.child.calls[0].payload;
  assert.equal(childRequest.source.commit, GIT_A);
  assert.equal(childRequest.source.tree, GIT_B);
  assert.equal(childRequest.source.snapshot, 'babycert/base/noble@golden-v1');
  assert.ok(childRequest.machine.launch.binds.some((bind) => bind.destination === '/run/baby-x/release-artifact.tar.zst' && bind.mode === 'ro'));
  assert.ok(childRequest.machine.launch.binds.some((bind) => bind.destination === '/run/baby-x/release-manifest.json' && bind.mode === 'ro'));
  assert.deepEqual(childRequest.profile.steps.slice(0, 3).map((step) => step.phase), ['artifact', 'manifest', 'runtime']);
  assert.match(f.child.calls[0].context.idempotencyKey, /^release-cert-[a-f0-9]{64}$/u);
  assert.equal(f.store.verify().valid, true);
});

test('bad manifest and dependency identity fail distinctly before child execution', async (t) => {
  const badManifestFixture = fixture(t);
  const bad = manifest(badManifestFixture.artifact);
  bad.manifestDigest = DIGEST_A;
  await assert.rejects(() => badManifestFixture.service.certify(request(badManifestFixture.artifact, { manifest: bad }), context('release-certification-bad-manifest')), (error) => error.code === 'release_artifact_invalid' && error.phase === 'manifest');
  assert.equal(badManifestFixture.child.calls.length, 0);

  const dependencyFixture = fixture(t);
  const dependencyResult = await dependencyFixture.service.certify(request(dependencyFixture.artifact, { dependencyIdentity: { lockfileDigest: DIGEST_B, installMode: 'npm-ci' } }), context('release-certification-bad-dependency'));
  assert.equal(dependencyResult.certification.state, 'FAILED');
  assert.equal(dependencyResult.certification.error.code, 'release_certification_stale');
  assert.equal(dependencyResult.certification.error.phase, 'dependency');
  assert.equal(dependencyFixture.child.calls.length, 0);
});

for (const phase of ['startup', 'readiness', 'smoke']) {
  test(`${phase} failure is recorded distinctly and cannot certify`, async (t) => {
    const f = fixture(t);
    f.child.failPhase = phase;
    const result = await f.service.certify(request(f.artifact), context(`release-certification-${phase}-failure`));
    assert.equal(result.certification.state, 'FAILED');
    assert.equal(result.certification[`${phase}Result`].status, 'FAILED');
    assert.equal(result.certification.error.phase, phase);
    assert.equal(result.certification.cleanupResult.absenceVerified, true);
  });
}

test('reuse occurs only for the exact complete certification identity', async (t) => {
  const f = fixture(t);
  const first = await f.service.certify(request(f.artifact), context('release-certification-reuse-first'));
  const replay = await f.service.certify(request(f.artifact), context('release-certification-reuse-second'));
  assert.equal(replay.reused, true);
  assert.equal(replay.certification.certificationId, first.certification.certificationId);
  assert.equal(f.child.calls.length, 1);

  const changed = await f.service.certify(request(f.artifact, { securityPolicyVersion: 'security-v2' }), context('release-certification-reuse-changed'));
  assert.equal(changed.reused, false);
  assert.notEqual(changed.certification.certificationId, first.certification.certificationId);
  assert.equal(f.child.calls.length, 2);
});

test('active durable jobs and cleanup failure both block false success', async (t) => {
  const active = fixture(t);
  active.child.activeJob = true;
  const activeResult = await active.service.certify(request(active.artifact), context('release-certification-active-job'));
  assert.equal(activeResult.certification.state, 'RECOVERY_REQUIRED');
  assert.deepEqual(activeResult.certification.activeJobIds, ['child-job-1']);
  assert.equal(activeResult.certification.error.code, 'release_recovery_required');

  const cleanup = fixture(t);
  cleanup.child.cleanupFailure = true;
  const cleanupResult = await cleanup.service.certify(request(cleanup.artifact), context('release-certification-cleanup-failure'));
  assert.equal(cleanupResult.certification.state, 'RECOVERY_REQUIRED');
  assert.equal(cleanupResult.certification.cleanupResult.destroyStatus, 'failed');
  assert.equal(cleanupResult.certification.error.code, 'release_recovery_required');
});

test('restart resumes the exact durable child identity without changing child idempotency', async (t) => {
  const f = fixture(t);
  f.child.blockFirst = true;
  void f.service.certify(request(f.artifact), context('release-certification-interrupted'));
  let record;
  for (let attempts = 0; attempts < 50; attempts += 1) {
    const identities = f.store.listRecordIdentities().filter((identity) => identity.schemaId === 'CertificationRecordV1');
    if (identities.length === 1) {
      record = f.store.getRecord('CertificationRecordV1', identities[0].recordId);
      if (record.state === 'STARTING') break;
    }
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.equal(record.state, 'STARTING');
  f.child.blockFirst = false;
  const restarted = new ReleaseCertificationService({ stateRoot: f.root, store: f.store, artifacts: f.artifacts, certification: f.child, jobs: f.jobs, now: () => FIXED_TIME });
  const resumed = await restarted.resume({ certificationId: record.certificationId, request: request(f.artifact) }, context('release-certification-resume'));
  assert.equal(resumed.certification.state, 'SUCCEEDED');
  assert.equal(f.child.calls.length, 2);
  assert.equal(f.child.calls[0].context.idempotencyKey, f.child.calls[1].context.idempotencyKey);
  assert.deepEqual(f.child.calls[0].payload.source, f.child.calls[1].payload.source);
});

test('owner-scoped reads and public operation registry expose one release certification surface', async (t) => {
  const f = fixture(t);
  const result = await f.service.certify(request(f.artifact), context('release-certification-owner-read'));
  assert.equal(f.service.get({ certificationId: result.certification.certificationId }, context('read-owner')).certification.certificationId, result.certification.certificationId);
  assert.throws(() => f.service.get({ certificationId: result.certification.certificationId }, context('read-other', 'owner:other')), (error) => error.code === 'release_record_not_found');
  assert.equal(f.service.list({}, context('list-other', 'owner:other')).total, 0);

  const runtimeRoot = mkdtempSync(join(tmpdir(), 'baby-x-release-certification-runtime-'));
  t.after(() => rmSync(runtimeRoot, { recursive: true, force: true }));
  const runtime = new BabyXRuntime({ stateRoot: runtimeRoot });
  const calls = [];
  runtime.releaseCertificationServiceInstance = {
    describe: () => ({ operation: 'babyx.release.certification.describe' }),
    certify: async (payload, operationContext) => { calls.push(['certify', payload, operationContext]); return { operation: 'babyx.release.certification.certify' }; },
    resume: async (payload, operationContext) => { calls.push(['resume', payload, operationContext]); return { operation: 'babyx.release.certification.resume' }; },
    get: (payload, operationContext) => { calls.push(['get', payload, operationContext]); return { operation: 'babyx.release.certification.get' }; },
    list: (payload, operationContext) => { calls.push(['list', payload, operationContext]); return { operation: 'babyx.release.certification.list' }; },
  };
  assert.equal((await runtime.execute('babyx.release.certification.describe')).operation, 'babyx.release.certification.describe');
  for (const name of ['certify', 'resume', 'get', 'list']) await runtime.execute(`babyx.release.certification.${name}`, {}, context(`runtime-${name}`));
  assert.deepEqual(calls.map(([name]) => name), ['certify', 'resume', 'get', 'list']);
  const operations = runtime.describe().operations.map((definition) => definition.operation);
  for (const name of ['describe', 'certify', 'resume', 'get', 'list']) assert.equal(operations.filter((operation) => operation === `babyx.release.certification.${name}`).length, 1);
});

test('release certification coordinator has no alternate process, machine, job, or artifact authority', () => {
  const source = readFileSync(new URL('../src/release/certification.ts', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /node:child_process|spawn\(|execFile\(|new JobManager|new ArtifactManager|new DisposableMachineService|\/usr\/sbin\/zfs|machinectl|systemd-nspawn/u);
  assert.match(source, /this\.options\.certification\.run/u);
  assert.match(source, /this\.options\.jobs\.reconcile/u);
  assert.match(source, /this\.options\.artifacts\.verify/u);
  assert.match(source, /this\.options\.store\.applyMutation/u);
});
