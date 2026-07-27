import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { BabyXRuntime } from '../../dist/runtime/core.js';
import { CertificationService } from '../../dist/runtime/certification/service.js';
import { normalizeMachineCreateRequest } from '../../dist/runtime/machines/identity.js';

const context = { idempotencyKey: 'certification-request-0001', subject: 'owner:test', authorityClass: 'unrestricted-owner' };

function machineView(machine) {
  return structuredClone({
    schemaVersion: '1.0.0',
    machineId: machine.machineId,
    machineName: machine.machineName,
    lifecycle: {
      persistedState: machine.state,
      desiredState: machine.state === 'DESTROYED' ? 'DESTROYED' : machine.state,
      observedState: machine.observedState,
      stateSequence: machine.sequence,
    },
    activeJobIds: [...machine.activeJobIds],
    protectedJobIds: [],
    artifactIds: [...machine.artifactIds],
    ...(machine.parentCertificationId === undefined ? {} : { parentCertificationId: machine.parentCertificationId }),
    cleanup: structuredClone(machine.cleanup),
  });
}

class FakeMachineAuthority {
  machine = {
    machineId: 'mx_certification01',
    machineName: 'certification-machine',
    sequence: 1,
    state: 'CLONED',
    observedState: 'CLONE_ONLY',
    activeJobIds: [],
    artifactIds: [],
    cleanup: { completed: false, datasetAbsentVerified: false, rootAbsentVerified: false, machineAbsentVerified: false, processAbsentVerified: false, retainedEvidence: [] },
  };
  calls = [];
  jobs = new Map();
  failCommands = new Set();
  createFailure = null;
  startFailure = false;
  createState = 'CLONED';
  stopFailure = false;
  destroyFailure = false;
  diagnosticFailure = false;
  diagnosticWithoutArtifact = false;
  statusAfterDestroy = 'ABSENT';
  nextJob = 1;

  create(payload, operationContext) {
    this.calls.push(['create', structuredClone(payload), structuredClone(operationContext)]);
    this.machine.state = this.createState;
    this.machine.parentCertificationId = payload.parentCertificationId;
    this.machine.observedState = this.createState === 'REQUESTED' ? 'ABSENT' : 'CLONE_ONLY';
    if (this.createFailure !== null) return Promise.reject(Object.assign(new Error(this.createFailure.message), { code: this.createFailure.code, details: { ...this.createFailure.details, machineId: this.machine.machineId, machineName: this.machine.machineName, stateSequence: this.machine.sequence } }));
    return Promise.resolve({ operation: 'babyx.machine.create', machine: machineView(this.machine), replayed: false });
  }
  get(payload, operationContext) {
    this.calls.push(['get', structuredClone(payload), structuredClone(operationContext)]);
    return { operation: 'babyx.machine.get', machine: machineView(this.machine) };
  }
  list() { return { operation: 'babyx.machine.list', machines: [machineView(this.machine)] }; }
  events() {
    return { operation: 'babyx.machine.events', events: [{ offset: 0, eventDigest: 'a'.repeat(64), operation: 'babyx.machine.create', stateSequence: 1 }] };
  }
  status(payload, operationContext) {
    this.calls.push(['status', structuredClone(payload), structuredClone(operationContext)]);
    const state = this.machine.state === 'DESTROYED' ? this.statusAfterDestroy : this.machine.observedState;
    return Promise.resolve({ operation: 'babyx.machine.status', machine: machineView(this.machine), observed: { state, observations: { source: 'present', clone: this.machine.state === 'DESTROYED' ? 'absent' : 'present', machine: state === 'RUNNING' ? 'running' : 'absent', process: state === 'RUNNING' ? 'present-exact' : 'absent', root: this.machine.state === 'DESTROYED' ? 'absent' : 'present' } } });
  }
  start(payload, operationContext) {
    this.calls.push(['start', structuredClone(payload), structuredClone(operationContext)]);
    if (this.startFailure) return Promise.reject(Object.assign(new Error('start failed before clone completion'), { code: 'machine_start_failed' }));
    this.machine.sequence += 1;
    this.machine.state = 'READY';
    this.machine.observedState = 'RUNNING';
    this.machine.activeJobIds = ['launch-job'];
    this.jobs.set('launch-job', { id: 'launch-job', operation: 'babyx.machine.start', status: 'running', exitCode: null, signal: null, argv: ['/usr/bin/systemd-nspawn'], createdAt: '2026-07-25T16:00:00.000Z', startedAt: '2026-07-25T16:00:00.000Z' });
    return Promise.resolve({ operation: 'babyx.machine.start', machine: machineView(this.machine), jobId: 'launch-job' });
  }
  exec(payload, operationContext) {
    this.calls.push(['exec', structuredClone(payload), structuredClone(operationContext)]);
    const command = payload.argv.at(-1);
    const id = `job-${this.nextJob++}`;
    const failed = this.failCommands.has(command);
    this.jobs.set(id, { id, status: 'completed', exitCode: failed ? 1 : 0, signal: null, argv: payload.argv, createdAt: '2026-07-25T16:00:00.000Z', startedAt: '2026-07-25T16:00:00.000Z', completedAt: '2026-07-25T16:00:01.000Z' });
    this.machine.sequence += 1;
    this.machine.state = 'EXECUTING';
    this.machine.activeJobIds = [...new Set([...this.machine.activeJobIds, id])];
    return Promise.resolve({ operation: 'babyx.machine.exec', machine: machineView(this.machine), jobId: id, resultDigest: 'b'.repeat(64) });
  }
  completeJob(id) {
    if (!this.machine.activeJobIds.includes(id)) return;
    this.machine.activeJobIds = this.machine.activeJobIds.filter((value) => value !== id);
    this.machine.sequence += 1;
    this.machine.state = 'READY';
  }
  stop(payload, operationContext) {
    this.calls.push(['stop', structuredClone(payload), structuredClone(operationContext)]);
    if (this.stopFailure) return Promise.reject(Object.assign(new Error('stop failed'), { code: 'machine_stop_failed' }));
    this.machine.sequence += 1;
    this.machine.state = 'STOPPED';
    this.machine.observedState = 'STOPPED';
    this.machine.activeJobIds = [];
    const launch = this.jobs.get('launch-job');
    if (launch?.status === 'running') this.jobs.set('launch-job', { ...launch, status: 'completed', exitCode: 0, completedAt: '2026-07-25T16:01:00.000Z' });
    return Promise.resolve({ operation: 'babyx.machine.stop', machine: machineView(this.machine) });
  }
  destroy(payload, operationContext) {
    this.calls.push(['destroy', structuredClone(payload), structuredClone(operationContext)]);
    if (this.destroyFailure) return Promise.reject(Object.assign(new Error('destroy failed'), { code: 'machine_destroy_failed' }));
    this.machine.sequence += 1;
    this.machine.state = 'DESTROYED';
    this.machine.observedState = 'ABSENT';
    this.machine.activeJobIds = [];
    this.machine.artifactIds = ['machine-cleanup-artifact'];
    this.machine.cleanup = { completed: true, datasetAbsentVerified: true, rootAbsentVerified: true, machineAbsentVerified: true, processAbsentVerified: true, retainedEvidence: ['machine-cleanup-artifact'] };
    return Promise.resolve({ operation: 'babyx.machine.destroy', machine: machineView(this.machine), artifactReferences: ['cleanup-proof-artifact'], tombstone: { finalEventDigest: 'd'.repeat(64) } });
  }
  reconcile(payload, operationContext) {
    this.calls.push(['reconcile', structuredClone(payload), structuredClone(operationContext)]);
    return Promise.resolve({ operation: 'babyx.machine.reconcile', processed: 1, results: [] });
  }
  expire(payload, operationContext) {
    this.calls.push(['expire', structuredClone(payload), structuredClone(operationContext)]);
    this.machine.sequence += 1;
    this.machine.state = 'EXPIRED';
    return { operation: 'babyx.machine.expire', machine: machineView(this.machine) };
  }
  diagnostics(payload, operationContext) {
    this.calls.push(['diagnostics', structuredClone(payload), structuredClone(operationContext)]);
    if (this.diagnosticFailure) return Promise.reject(Object.assign(new Error('diagnostic capture failed'), { code: 'machine_artifact_failed' }));
    this.machine.sequence += 1;
    return Promise.resolve({ operation: 'babyx.machine.diagnostics', machineId: this.machine.machineId, stateSequence: this.machine.sequence, artifactReference: this.diagnosticWithoutArtifact ? null : 'machine-diagnostic-artifact', evidenceDigest: 'e'.repeat(64) });
  }
}

class FakeJobs {
  constructor(machine) { this.machine = machine; }
  reconcile(id) {
    const job = this.machine.jobs.get(id);
    if (job === undefined) throw new Error(`unknown job ${id}`);
    return structuredClone(job);
  }
  get(id) {
    const job = this.machine.jobs.get(id);
    if (job === undefined) throw new Error(`unknown job ${id}`);
    if (job.status !== 'running') this.machine.completeJob(id);
    return structuredClone(job);
  }
}

class FakeArtifacts {
  created = [];
  fail = false;
  create(name, sourcePath, metadata) {
    if (this.fail) throw Object.assign(new Error('artifact create failed'), { code: 'artifact_create_failed' });
    const content = readFileSync(sourcePath, 'utf8');
    const artifact = { id: `artifact-${this.created.length + 1}`, name, sourcePath, metadata: structuredClone(metadata), content };
    this.created.push(artifact);
    return artifact;
  }
}

function request(overrides = {}) {
  const steps = ['dependency', 'build', 'lint', 'unit', 'integration', 'acceptance'].map((phase) => ({ id: phase, phase, argv: ['/usr/bin/printf', phase], cwd: '/', timeoutMs: 10_000, required: true }));
  return {
    schemaVersion: '1.0.0',
    source: { commit: '1'.repeat(40), tree: '2'.repeat(40), snapshot: 'pool/source@certification', expectedGuid: 'source-guid-1' },
    machine: {
      machineName: 'certification-machine',
      clone: { dataset: 'pool/runs/certification-machine', mountpoint: '/var/lib/machines/certification-machine', expectedRootPrefix: '/var/lib/machines' },
      launch: { boot: true, networkMode: 'private', readOnlyRoot: false, binds: [], environment: [], properties: [] },
    },
    profile: { id: 'baby-x-disposable-certification', version: '1', steps },
    retention: { preserveOnFailure: false },
    ...overrides,
  };
}

function fixture(t, options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-certification-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const machine = options.machine ?? new FakeMachineAuthority();
  const jobs = options.jobs ?? new FakeJobs(machine);
  const artifacts = options.artifacts === null ? undefined : options.artifacts ?? new FakeArtifacts();
  let id = 1;
  const service = new CertificationService({
    stateRoot: root,
    machine,
    jobs,
    artifacts,
    certificationIdFactory: () => `cert_test${String(id++).padStart(4, '0')}`,
    sleep: options.sleep ?? (async () => {}),
    jobPollIntervalMs: 1,
    machineSettleTimeoutMs: 5,
  });
  return { root, machine, jobs, artifacts, service };
}

function operationNames(machine) { return machine.calls.map(([name]) => name); }

for (const failedPhase of ['dependency', 'build', 'acceptance']) {
  test(`certification ${failedPhase} failure is distinct from successful cleanup`, async (t) => {
    const f = fixture(t);
    f.machine.failCommands.add(failedPhase);
    const result = await f.service.run(request(), { ...context, idempotencyKey: `cert-failure-${failedPhase}-0001` });
    const certification = result.certification;
    assert.equal(certification.state, 'FAILED');
    assert.equal(certification.success, false);
    assert.equal(certification.testResult.status, 'failed');
    assert.equal(certification.testResult.failedStepId, failedPhase);
    assert.equal(certification.cleanup.stopStatus, 'succeeded');
    assert.equal(certification.cleanup.destroyStatus, 'succeeded');
    assert.equal(certification.cleanup.absenceVerified, true);
    assert.ok(operationNames(f.machine).includes('stop'));
    assert.ok(operationNames(f.machine).includes('destroy'));
  });
}

test('full certification success binds source, machine, jobs, evidence, and verified cleanup', async (t) => {
  const f = fixture(t);
  const result = await f.service.run(request(), context);
  const certification = result.certification;
  assert.equal(certification.state, 'SUCCEEDED');
  assert.equal(certification.success, true);
  assert.equal(certification.testResult.status, 'passed');
  assert.equal(certification.evidence.status, 'complete');
  assert.equal(certification.cleanup.stopStatus, 'succeeded');
  assert.equal(certification.cleanup.destroyStatus, 'succeeded');
  assert.equal(certification.cleanup.absenceVerified, true);
  assert.equal(certification.cleanup.sourcePreserved, true);
  assert.equal(certification.source.commit, '1'.repeat(40));
  assert.equal(certification.source.tree, '2'.repeat(40));
  assert.equal(certification.source.snapshot, 'pool/source@certification');
  assert.equal(certification.executionPolicy.mode, 'disposable');
  assert.match(certification.executionPolicy.decisionDigest, /^[a-f0-9]{64}$/u);
  assert.equal(certification.machineId, 'mx_certification01');
  assert.equal(certification.jobIds.length, 7);
  assert.ok(certification.artifactReferences.includes('machine-diagnostic-artifact'));
  assert.ok(certification.artifactReferences.includes('machine-cleanup-artifact'));
  assert.ok(certification.artifactReferences.includes('cleanup-proof-artifact'));
  assert.ok(certification.evidence.indexArtifactReference);
  assert.ok(certification.proofReferences.includes('d'.repeat(64)));
  assert.equal(f.artifacts.created.length, 1);
  assert.equal(existsSync(f.artifacts.created[0].sourcePath), false);
  assert.match(f.artifacts.created[0].content, /mx_certification01/u);
  assert.match(f.artifacts.created[0].content, /pool\/source@certification/u);
  assert.match(f.artifacts.created[0].content, /job-6/u);
  const create = f.machine.calls.find(([name]) => name === 'create');
  assert.equal(create[1].parentCertificationId, certification.certificationId);
  assert.equal(create[1].source.snapshot, 'pool/source@certification');
  const normalizedCreate = normalizeMachineCreateRequest(create[1], 'owner:test', {
    sourceSnapshotRoots: ['pool/source'], cloneDatasetRoots: ['pool/runs'], machineRoot: '/var/lib/machines', allowedNetworkModes: ['private'],
  });
  assert.equal(normalizedCreate.parentCertificationId, certification.certificationId);
  assert.equal(normalizedCreate.clone.mountpoint, '/var/lib/machines/certification-machine');
  assert.equal(f.machine.calls.some(([name, payload]) => name === 'destroy' && String(payload).includes('pool/source@certification')), false);
});

test('preservation-on-failure retains the machine and can be expired through normal service cleanup', async (t) => {
  const f = fixture(t);
  f.machine.failCommands.add('acceptance');
  const preservedRequest = request({ retention: { preserveOnFailure: true, expiresAt: '2026-07-25T15:00:00.000Z' } });
  const first = await f.service.run(preservedRequest, { ...context, idempotencyKey: 'cert-preserve-failure-0001' });
  assert.equal(first.certification.state, 'PRESERVED');
  assert.equal(first.certification.cleanup.required, false);
  assert.equal(operationNames(f.machine).includes('stop'), false);
  assert.equal(operationNames(f.machine).includes('destroy'), false);
  const cleaned = await f.service.cleanup({ certificationId: first.certification.certificationId, reason: 'retention expired' }, { ...context, idempotencyKey: 'cert-preserve-cleanup-0001' });
  assert.equal(cleaned.certification.state, 'FAILED');
  assert.equal(cleaned.certification.cleanup.destroyStatus, 'succeeded');
  assert.ok(operationNames(f.machine).includes('expire'));
  assert.ok(operationNames(f.machine).includes('stop'));
  assert.ok(operationNames(f.machine).includes('destroy'));
});

test('durable running step resumes after service restart without duplicate execution', async (t) => {
  const blockedSleep = () => new Promise(() => {});
  const f = fixture(t, { sleep: blockedSleep });
  const originalGet = f.jobs.get.bind(f.jobs);
  let holdRunning = true;
  f.jobs.get = (id) => {
    const job = f.machine.jobs.get(id);
    if (holdRunning) return { ...job, status: 'running', exitCode: null, completedAt: null };
    return originalGet(id);
  };
  void f.service.run(request({ profile: { id: 'resume-profile', version: '1', steps: [{ id: 'build', phase: 'build', argv: ['/usr/bin/printf', 'build'], cwd: '/', required: true }] } }), { ...context, idempotencyKey: 'cert-interrupted-run-0001' });
  for (let attempts = 0; attempts < 20 && f.machine.calls.filter(([name]) => name === 'exec').length === 0; attempts += 1) await new Promise((resolve) => setImmediate(resolve));
  assert.equal(f.machine.calls.filter(([name]) => name === 'exec').length, 1);
  const recordsRoot = join(f.root, 'certification', 'record-store-v1', 'records');
  const recordName = readdirSync(recordsRoot).find((name) => name.endsWith('.json'));
  assert.ok(recordName);
  const certificationId = recordName.slice(0, -5);
  const persisted = JSON.parse(readFileSync(join(recordsRoot, recordName), 'utf8'));
  assert.equal(persisted.steps[0].state, 'running');
  holdRunning = false;
  const restarted = new CertificationService({ stateRoot: f.root, machine: f.machine, jobs: f.jobs, artifacts: f.artifacts, sleep: async () => {}, jobPollIntervalMs: 1, machineSettleTimeoutMs: 5 });
  const resumed = await restarted.resume({ certificationId, reason: 'process restarted' }, { ...context, idempotencyKey: 'cert-interrupted-resume-0001' });
  assert.equal(resumed.certification.state, 'SUCCEEDED');
  assert.equal(f.machine.calls.filter(([name]) => name === 'exec').length, 1);
});

test('diagnostic or artifact evidence failure blocks false certification success', async (t) => {
  const diagnostic = fixture(t);
  diagnostic.machine.diagnosticFailure = true;
  const diagnosticResult = await diagnostic.service.run(request(), { ...context, idempotencyKey: 'cert-evidence-failure-0001' });
  assert.equal(diagnosticResult.certification.testResult.status, 'passed');
  assert.equal(diagnosticResult.certification.evidence.status, 'failed');
  assert.equal(diagnosticResult.certification.state, 'FAILED');
  assert.equal(diagnosticResult.certification.success, false);

  const artifact = fixture(t);
  artifact.artifacts.fail = true;
  const artifactResult = await artifact.service.run(request(), { ...context, idempotencyKey: 'cert-artifact-failure-0001' });
  assert.equal(artifactResult.certification.testResult.status, 'passed');
  assert.equal(artifactResult.certification.evidence.status, 'failed');
  assert.equal(artifactResult.certification.state, 'FAILED');
});

for (const failure of ['stop', 'destroy']) {
  test(`${failure} failure produces recovery-required truth and never certification success`, async (t) => {
    const f = fixture(t);
    f.machine[`${failure}Failure`] = true;
    const result = await f.service.run(request(), { ...context, idempotencyKey: `cert-${failure}-failure-0001` });
    assert.equal(result.certification.testResult.status, 'passed');
    assert.equal(result.certification.state, 'RECOVERY_REQUIRED');
    assert.equal(result.certification.success, false);
    assert.equal(result.certification.cleanup.absenceVerified, false);
    assert.match(result.certification.lastError.code, /machine_|certification_/u);
  });
}

test('contradictory post-destroy observation blocks cleanup success', async (t) => {
  const f = fixture(t);
  f.machine.statusAfterDestroy = 'UNKNOWN';
  const result = await f.service.run(request(), { ...context, idempotencyKey: 'cert-absence-failure-0001' });
  assert.equal(result.certification.state, 'RECOVERY_REQUIRED');
  assert.equal(result.certification.success, false);
  assert.equal(result.certification.cleanup.absenceVerified, false);
  assert.equal(result.certification.lastError.code, 'certification_cleanup_failed');
});

test('idempotency and owner visibility remain strict', async (t) => {
  const f = fixture(t);
  const first = await f.service.run(request(), context);
  const replay = await f.service.run(request(), context);
  assert.equal(replay.replayed, true);
  assert.equal(replay.certification.certificationId, first.certification.certificationId);
  await assert.rejects(() => f.service.run(request({ source: { commit: '3'.repeat(40), tree: '2'.repeat(40), snapshot: 'pool/source@certification' } }), context), (error) => error.code === 'certification_idempotency_conflict');
  assert.throws(() => f.service.get({ certificationId: first.certification.certificationId }, { subject: 'owner:other', authorityClass: 'owner' }), (error) => error.code === 'certification_not_found');
});

test('public registry exposes and routes certification operations', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-certification-runtime-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const runtime = new BabyXRuntime({ stateRoot: root });
  const calls = [];
  runtime.certificationServiceInstance = {
    describe: () => ({ operation: 'babyx.certification.describe' }),
    run: async (payload, operationContext) => { calls.push(['run', payload, operationContext]); return { operation: 'babyx.certification.run' }; },
    resume: async (payload, operationContext) => { calls.push(['resume', payload, operationContext]); return { operation: 'babyx.certification.resume' }; },
    get: (payload, operationContext) => { calls.push(['get', payload, operationContext]); return { operation: 'babyx.certification.get' }; },
    list: (payload, operationContext) => { calls.push(['list', payload, operationContext]); return { operation: 'babyx.certification.list' }; },
    cleanup: async (payload, operationContext) => { calls.push(['cleanup', payload, operationContext]); return { operation: 'babyx.certification.cleanup' }; },
  };
  assert.equal((await runtime.execute('babyx.certification.describe')).operation, 'babyx.certification.describe');
  for (const name of ['run', 'resume', 'get', 'list', 'cleanup']) await runtime.execute(`babyx.certification.${name}`, {}, context);
  assert.deepEqual(calls.map(([name]) => name), ['run', 'resume', 'get', 'list', 'cleanup']);
  const names = new Set(runtime.describe().operations.map((definition) => definition.operation));
  for (const name of ['describe', 'run', 'resume', 'get', 'list', 'cleanup']) assert.ok(names.has(`babyx.certification.${name}`));
});

test('certification layer contains no direct provider or alternate execution authority', () => {
  const source = readFileSync(new URL('../src/certification/service.ts', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /node:child_process|spawn\(|execFile\(|\/usr\/sbin\/zfs|\/usr\/bin\/machinectl|systemd-nspawn|new JobManager|new ArtifactManager/u);
  assert.match(source, /this\.options\.machine\.create/u);
  assert.match(source, /this\.options\.machine\.start/u);
  assert.match(source, /this\.options\.machine\.exec/u);
  assert.match(source, /this\.options\.machine\.stop/u);
  assert.match(source, /this\.options\.machine\.destroy/u);
});

test('pre-clone failure skips stop and destroys through normal lifecycle with positive absence', async (t) => {
  const f = fixture(t);
  f.machine.createState = 'REQUESTED';
  f.machine.startFailure = true;
  const result = await f.service.run(request(), { ...context, idempotencyKey: 'cert-preclone-failure-0001' });
  assert.equal(result.certification.state, 'FAILED');
  assert.equal(result.certification.success, false);
  assert.equal(result.certification.cleanup.stopStatus, 'not-required');
  assert.equal(result.certification.cleanup.destroyStatus, 'succeeded');
  assert.equal(result.certification.cleanup.absenceVerified, true);
  assert.equal(operationNames(f.machine).includes('stop'), false);
  assert.equal(operationNames(f.machine).includes('destroy'), true);
});


test('source preflight failure retains exact reserved machine linkage and cleans without an invalid stop', async (t) => {
  const f = fixture(t);
  f.machine.createState = 'REQUESTED';
  f.machine.createFailure = { code: 'machine_source_mismatch', message: 'source snapshot GUID differs', details: { expectedGuid: 'stale-guid', actualGuid: 'live-guid' } };
  const result = await f.service.run(request(), { ...context, idempotencyKey: 'cert-source-mismatch-link-0001' });
  assert.equal(result.certification.state, 'FAILED');
  assert.equal(result.certification.machineId, f.machine.machine.machineId);
  assert.equal(result.certification.machineName, f.machine.machine.machineName);
  assert.equal(result.certification.cleanup.stopStatus, 'not-required');
  assert.equal(result.certification.cleanup.destroyStatus, 'succeeded');
  assert.equal(result.certification.cleanup.absenceVerified, true);
  assert.equal(operationNames(f.machine).includes('stop'), false);
  assert.equal(operationNames(f.machine).includes('destroy'), true);
});

test('cleanup waits through a transient launch-job teardown race and requires terminal durable state', async (t) => {
  const f = fixture(t);
  const stop = f.machine.stop.bind(f.machine);
  f.machine.stop = async (...args) => {
    const result = await stop(...args);
    const launch = f.machine.jobs.get('launch-job');
    f.machine.jobs.set('launch-job', { ...launch, status: 'running', exitCode: null, completedAt: undefined });
    return result;
  };
  const reconcile = f.jobs.reconcile.bind(f.jobs);
  let launchReconciliations = 0;
  f.jobs.reconcile = (id) => {
    if (id !== 'launch-job') return reconcile(id);
    launchReconciliations += 1;
    const launch = f.machine.jobs.get(id);
    if (launchReconciliations < 3) return { ...launch, status: 'running' };
    const terminal = { ...launch, status: 'lost', completedAt: '2026-07-25T16:01:01.000Z', reconciliation: { classification: 'process-absent', observedAt: '2026-07-25T16:01:01.000Z' } };
    f.machine.jobs.set(id, terminal);
    return terminal;
  };
  const result = await f.service.run(request(), { ...context, idempotencyKey: 'cert-transient-launch-cleanup-0001' });
  assert.equal(result.certification.state, 'SUCCEEDED');
  assert.equal(result.certification.success, true);
  assert.equal(result.certification.cleanup.absenceVerified, true);
  assert.ok(launchReconciliations >= 3);
  assert.equal(f.jobs.reconcile('launch-job').status, 'lost');
});

test('cleanup success is impossible while a related durable job remains running', async (t) => {
  const f = fixture(t);
  const reconcile = f.jobs.reconcile.bind(f.jobs);
  f.jobs.reconcile = (id) => id === 'launch-job' ? { ...f.machine.jobs.get(id), status: 'running' } : reconcile(id);
  const result = await f.service.run(request(), { ...context, idempotencyKey: 'cert-active-job-cleanup-0001' });
  assert.equal(result.certification.state, 'RECOVERY_REQUIRED');
  assert.equal(result.certification.success, false);
  assert.equal(result.certification.cleanup.absenceVerified, false);
  assert.equal(result.certification.lastError.code, 'certification_job_active');
});

test('successful certification leaves every related durable job terminal', async (t) => {
  const f = fixture(t);
  const result = await f.service.run(request(), { ...context, idempotencyKey: 'cert-terminal-jobs-0001' });
  assert.equal(result.certification.state, 'SUCCEEDED');
  assert.ok(result.certification.jobIds.length > 1);
  for (const jobId of result.certification.jobIds) assert.notEqual(f.jobs.reconcile(jobId).status, 'running');
});
