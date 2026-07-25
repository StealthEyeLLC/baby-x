import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { BabyXRuntime, canonicalize, sha256 } from '../../dist/runtime/core.js';
import { CandidateRaceService } from '../../dist/runtime/racing/service.js';

const context = { idempotencyKey: 'candidate-race-request-0001', subject: 'owner:test', authorityClass: 'unrestricted-owner' };

class FakeCertification {
  calls = [];
  executions = new Map();
  failures = new Map();
  cleanupFailures = new Set();
  validationFailures = new Set();
  evidenceFailures = new Set();
  async run(request, operationContext) {
    this.calls.push({ request: structuredClone(request), context: structuredClone(operationContext) });
    const candidateId = request.profile.id.split('-').at(-1);
    if (this.failures.has(candidateId)) throw Object.assign(new Error(this.failures.get(candidateId)), { code: 'provider_unavailable' });
    if (!this.executions.has(operationContext.idempotencyKey)) this.executions.set(operationContext.idempotencyKey, this.executions.size + 1);
    const ordinal = this.executions.get(operationContext.idempotencyKey);
    const validationFailed = this.validationFailures.has(candidateId);
    const cleanupFailed = this.cleanupFailures.has(candidateId);
    const evidenceFailed = this.evidenceFailures.has(candidateId);
    return {
      operation: 'babyx.certification.run',
      replayed: this.calls.filter((call) => call.context.idempotencyKey === operationContext.idempotencyKey).length > 1,
      certification: {
        certificationId: `cert-${candidateId}`,
        state: validationFailed ? 'FAILED' : cleanupFailed ? 'RECOVERY_REQUIRED' : evidenceFailed ? 'FAILED' : 'SUCCEEDED',
        source: structuredClone(request.source),
        machineId: `mx-${candidateId}`,
        jobIds: [`job-${candidateId}-strategy`, `job-${candidateId}-validation`],
        artifactReferences: [`artifact-${candidateId}`],
        proofReferences: [`proof-${candidateId}`],
        testResult: { status: validationFailed ? 'failed' : 'passed', ...(validationFailed ? { failedStepId: 'common-validation' } : {}) },
        evidence: { status: evidenceFailed ? 'failed' : 'complete', indexArtifactReference: evidenceFailed ? null : `artifact-cert-${candidateId}` },
        cleanup: { stopStatus: cleanupFailed ? 'failed' : 'succeeded', destroyStatus: cleanupFailed ? 'failed' : 'succeeded', absenceVerified: !cleanupFailed, sourcePreserved: true },
        ordinal,
      },
    };
  }
}

class FakeArtifacts {
  created = [];
  create(name, sourcePath, metadata) {
    const artifact = { id: `race-artifact-${this.created.length + 1}`, name, sourcePath, metadata: structuredClone(metadata), content: readFileSync(sourcePath, 'utf8') };
    this.created.push(artifact);
    return artifact;
  }
}

function raceStep(id, command = id, phase = 'build') {
  const normalized = [{ id, phase, argv: ['/usr/bin/printf', command], cwd: '/', timeoutMs: 10_000, required: true }];
  return { steps: normalized, digest: sha256(canonicalize(normalized)) };
}
function machine(candidateId) {
  return {
    machineName: `race-${candidateId}`,
    clone: { dataset: `pool/runs/race-${candidateId}`, mountpoint: `/var/lib/machines/race-${candidateId}`, expectedRootPrefix: '/var/lib/machines' },
    launch: { boot: true, networkMode: 'private', readOnlyRoot: false, binds: [], environment: [], properties: [] },
  };
}
function candidate(candidateId, assessment = {}, command = candidateId) {
  const strategy = raceStep(`strategy-${candidateId}`, command);
  return {
    candidateId,
    strategyDigest: strategy.digest,
    machine: machine(candidateId),
    strategySteps: strategy.steps,
    assessment: { regressionRisk: 20, maintainability: 80, changeSize: 100, resourceCost: 4096, ...assessment },
  };
}
function request(overrides = {}) {
  const description = 'Choose the safest correct implementation.';
  return {
    schemaVersion: '1.0.0',
    objective: { objectiveId: 'objective-1', description, objectiveDigest: sha256(description) },
    source: { commit: '1'.repeat(40), tree: '2'.repeat(40), snapshot: 'pool/source@race', expectedGuid: 'source-guid-race' },
    candidates: [candidate('alpha'), candidate('beta', { maintainability: 90 })],
    validation: { profileId: 'common-validation', version: '1', steps: [{ id: 'common-validation', phase: 'acceptance', argv: ['/usr/bin/printf', 'validate'], cwd: '/', timeoutMs: 10_000, required: true }] },
    preservation: { preserveWinnerEvidence: true, preserveFailureEvidence: true },
    costBounds: { maxMachines: 2, maxDurationMs: 120_000, maxDiskMb: 16_384 },
    ...overrides,
  };
}
function fixture(t, options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-race-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const certification = options.certification ?? new FakeCertification();
  const artifacts = options.artifacts === null ? undefined : options.artifacts ?? new FakeArtifacts();
  let id = 1;
  const service = new CandidateRaceService({ stateRoot: root, certification, artifacts, raceIdFactory: () => `race_test${String(id++).padStart(4, '0')}` });
  return { root, certification, artifacts, service };
}

test('two candidates use one exact source and common validation, then score deterministically', async (t) => {
  const f = fixture(t);
  const result = await f.service.run(request(), context);
  const race = result.race;
  assert.equal(race.state, 'COMPLETED');
  assert.equal(race.winnerCandidateId, 'beta');
  assert.equal(race.executionPolicy.mode, 'parallel-disposable');
  assert.equal(f.certification.calls.length, 2);
  for (const call of f.certification.calls) {
    assert.deepEqual(call.request.source, request().source);
    assert.equal(call.request.profile.steps.at(-1).id, 'common-validation');
    assert.equal(call.request.retention.preserveOnFailure, false);
  }
  assert.equal(new Set(f.certification.calls.map((call) => call.request.machine.clone.dataset)).size, 2);
  assert.equal(race.candidates.filter((item) => item.selected).length, 1);
  assert.ok(race.candidates.every((item) => item.cleanupVerified));
  assert.equal(race.cleanupFailures.length, 0);
  assert.ok(race.evidenceArtifactReference);
  assert.match(race.evidenceDigest, /^[a-f0-9]{64}$/u);
  assert.equal(f.artifacts.created.length, 1);
  assert.equal(existsSync(f.artifacts.created[0].sourcePath), false);
  assert.match(f.artifacts.created[0].content, /"mergePerformed":false/u);
  assert.match(f.artifacts.created[0].content, /"deploymentPerformed":false/u);
});

test('correctness and security outrank secondary score components', async (t) => {
  const f = fixture(t);
  f.certification.validationFailures.add('beta');
  const result = await f.service.run(request({ candidates: [candidate('alpha', { regressionRisk: 100, maintainability: 0, changeSize: 1_000_000, resourceCost: 10_000 }), candidate('beta', { regressionRisk: 0, maintainability: 100, changeSize: 0, resourceCost: 1 })] }), { ...context, idempotencyKey: 'race-correctness-first-0001' });
  assert.equal(result.race.winnerCandidateId, 'alpha');
  assert.equal(result.race.candidates.find((item) => item.candidateId === 'beta').rejectionReason, 'common-validation-failed');
});

test('candidate ID is the deterministic final tie-breaker', async (t) => {
  const f = fixture(t);
  const same = { regressionRisk: 10, maintainability: 50, changeSize: 100, resourceCost: 100 };
  const result = await f.service.run(request({ candidates: [candidate('zeta', same), candidate('alpha', same)] }), { ...context, idempotencyKey: 'race-tie-break-0001' });
  assert.equal(result.race.winnerCandidateId, 'alpha');
});

test('one provider failure cannot falsify another candidate', async (t) => {
  const f = fixture(t);
  f.certification.failures.set('alpha', 'provider unavailable for alpha');
  const result = await f.service.run(request(), { ...context, idempotencyKey: 'race-provider-isolation-0001' });
  assert.equal(result.race.state, 'COMPLETED');
  assert.equal(result.race.winnerCandidateId, 'beta');
  assert.equal(result.race.candidates.find((item) => item.candidateId === 'alpha').state, 'failed');
  assert.equal(result.race.candidates.find((item) => item.candidateId === 'beta').state, 'accepted');
  assert.equal(result.race.cleanupFailures.length, 1);
  assert.equal(result.race.lastError.code, 'candidate_race_cleanup_incomplete');
});

test('passing tests with unresolved cleanup are rejected and reported separately', async (t) => {
  const f = fixture(t);
  f.certification.cleanupFailures.add('beta');
  const result = await f.service.run(request(), { ...context, idempotencyKey: 'race-cleanup-rejection-0001' });
  assert.equal(result.race.winnerCandidateId, 'alpha');
  const beta = result.race.candidates.find((item) => item.candidateId === 'beta');
  assert.equal(beta.score.correctness, 100);
  assert.equal(beta.state, 'rejected');
  assert.equal(beta.rejectionReason, 'cleanup-unverified');
  assert.equal(result.race.cleanupFailures[0].candidateId, 'beta');
});

test('all rejected candidates produce no winner', async (t) => {
  const f = fixture(t);
  f.certification.validationFailures.add('alpha');
  f.certification.evidenceFailures.add('beta');
  const result = await f.service.run(request(), { ...context, idempotencyKey: 'race-no-winner-0001' });
  assert.equal(result.race.state, 'NO_WINNER');
  assert.equal(result.race.winnerCandidateId, null);
  assert.equal(result.race.candidates.some((item) => item.selected), false);
});

test('restart resumes durable certification identities without duplicate candidate execution', async (t) => {
  const f = fixture(t, { artifacts: null });
  const first = await f.service.run(request(), { ...context, idempotencyKey: 'race-restart-0001' });
  assert.equal(first.race.state, 'RECOVERY_REQUIRED');
  assert.equal(f.certification.executions.size, 2);
  const restartedArtifacts = new FakeArtifacts();
  const restarted = new CandidateRaceService({ stateRoot: f.root, certification: f.certification, artifacts: restartedArtifacts });
  const resumed = await restarted.resume({ raceId: first.race.raceId, reason: 'artifact authority restored' }, { ...context, idempotencyKey: 'race-resume-0001' });
  assert.equal(resumed.race.state, 'COMPLETED');
  assert.equal(f.certification.executions.size, 2);
  assert.equal(restartedArtifacts.created.length, 1);
});

test('validation rejects shared writable state, mismatched digests, and insufficient candidates', async (t) => {
  const f = fixture(t);
  const shared = candidate('beta'); shared.machine = machine('alpha');
  await assert.rejects(() => f.service.run(request({ candidates: [candidate('alpha'), shared] }), { ...context, idempotencyKey: 'race-shared-state-0001' }), (error) => error.code === 'candidate_race_shared_writable_state');
  const badStrategy = candidate('alpha'); badStrategy.strategyDigest = 'f'.repeat(64);
  await assert.rejects(() => f.service.run(request({ candidates: [badStrategy, candidate('beta')] }), { ...context, idempotencyKey: 'race-bad-strategy-0001' }), (error) => error.code === 'candidate_race_invalid_request');
  await assert.rejects(() => f.service.run(request({ candidates: [candidate('alpha')] }), { ...context, idempotencyKey: 'race-one-candidate-0001' }), (error) => error.code === 'candidate_race_invalid_request');
});

test('idempotency and owner visibility remain strict', async (t) => {
  const f = fixture(t);
  const first = await f.service.run(request(), context);
  const replay = await f.service.run(request(), context);
  assert.equal(replay.replayed, true);
  assert.equal(replay.race.raceId, first.race.raceId);
  await assert.rejects(() => f.service.run(request({ objective: { objectiveId: 'objective-2', description: 'Different objective.', objectiveDigest: sha256('Different objective.') } }), context), (error) => error.code === 'candidate_race_idempotency_conflict');
  assert.throws(() => f.service.get({ raceId: first.race.raceId }, { subject: 'owner:other', authorityClass: 'owner' }), (error) => error.code === 'candidate_race_not_found');
});

test('public runtime registry exposes and routes race operations', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-race-runtime-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const runtime = new BabyXRuntime({ stateRoot: root });
  const calls = [];
  runtime.candidateRaceServiceInstance = {
    describe: () => ({ operation: 'babyx.race.describe' }),
    run: async (payload, operationContext) => { calls.push(['run', payload, operationContext]); return { operation: 'babyx.race.run' }; },
    resume: async (payload, operationContext) => { calls.push(['resume', payload, operationContext]); return { operation: 'babyx.race.resume' }; },
    get: (payload, operationContext) => { calls.push(['get', payload, operationContext]); return { operation: 'babyx.race.get' }; },
    list: (payload, operationContext) => { calls.push(['list', payload, operationContext]); return { operation: 'babyx.race.list' }; },
  };
  assert.equal((await runtime.execute('babyx.race.describe')).operation, 'babyx.race.describe');
  for (const name of ['run', 'resume', 'get', 'list']) await runtime.execute(`babyx.race.${name}`, {}, context);
  assert.deepEqual(calls.map(([name]) => name), ['run', 'resume', 'get', 'list']);
  const names = new Set(runtime.describe().operations.map((definition) => definition.operation));
  for (const name of ['describe', 'run', 'resume', 'get', 'list']) assert.ok(names.has(`babyx.race.${name}`));
});

test('racing owns no provider, process, machine lifecycle, job, merge, or deployment authority', () => {
  const source = readFileSync(new URL('../src/racing/service.ts', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /child_process|spawn\(|execFile\(|\/usr\/sbin\/zfs|machinectl|systemd-nspawn|machine\.create|machine\.start|machine\.exec|machine\.stop|machine\.destroy|JobManager|git merge|git push|deploy\(/u);
  assert.match(source, /this\.options\.certification\.run/u);
  assert.match(source, /mergePerformed: false/u);
  assert.match(source, /deploymentPerformed: false/u);
});
