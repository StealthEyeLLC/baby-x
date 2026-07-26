import test from 'node:test';
import assert from 'node:assert/strict';
import {
  context,
  createVia,
  jobRecord,
  makeHarness,
} from '../test/_transaction-fixture.mjs';

function tx(result) { return result.transaction; }

async function execute(harness, created, key = 'execute-key-0001') {
  return harness.service.execute({ transactionId: tx(created).transactionId, expectedSequence: tx(created).lifecycle.stateSequence, reason: 'execute' }, context('owner-a', key));
}

async function validate(harness, executed, key = 'validate-key-0001') {
  return harness.service.validate({ transactionId: tx(executed).transactionId, expectedSequence: tx(executed).lifecycle.stateSequence, reason: 'validate' }, context('owner-a', key));
}

async function finalize(harness, validating, key = 'finalize-key-0001') {
  return harness.service.finalize({ transactionId: tx(validating).transactionId, expectedSequence: tx(validating).lifecycle.stateSequence, reason: 'finalize' }, context('owner-a', key));
}

test('complete delegated lifecycle reaches COMMITTED only after candidate, evidence, terminal jobs, and positive cleanup', async (t) => {
  const harness = makeHarness(t);
  const created = createVia(harness.service);
  const executed = await execute(harness, created);
  const validating = await validate(harness, executed);
  const committed = await finalize(harness, validating);
  const record = tx(committed);
  assert.equal(record.lifecycle.persistedState, 'COMMITTED');
  assert.equal(record.candidate.candidateTree, 'c'.repeat(40));
  assert.equal(record.candidate.validationPassed, true);
  assert.equal(record.execution.jobTerminalityStatus, 'all-terminal');
  assert.deepEqual(record.execution.activeJobIds, []);
  assert.equal(record.cleanup.completed, true);
  assert.equal(record.cleanup.machineAbsenceVerified, true);
  assert.equal(record.cleanup.processAbsenceVerified, true);
  assert.equal(record.cleanup.mountAbsenceVerified, true);
  assert.equal(record.cleanup.rootPathAbsenceVerified, true);
  assert.equal(record.cleanup.datasetAbsenceVerified, true);
  assert.match(record.evidence.finalEvidenceIndexDigest, /^[a-f0-9]{64}$/u);
  assert.equal(harness.machine.destroyCalls.length, 1);
  assert.deepEqual(harness.codeDriver.calls, { checkpoint: 1, execute: 1, validate: 1, finalize: 1, completeEvidence: 1 });
});

test('startup reconciliation after machine and mutation creation does not duplicate either authority action', async (t) => {
  const first = makeHarness(t);
  const created = createVia(first.service);
  const executed = await execute(first, created);
  assert.equal(tx(executed).lifecycle.persistedState, 'EXECUTING');
  const machineCount = first.machine.records.size;
  const jobCount = first.jobs.records.size;
  const driverCalls = structuredClone(first.codeDriver.calls);
  const restarted = makeHarness(t, {
    stateRoot: first.stateRoot,
    jobs: first.jobs,
    machine: first.machine,
    artifacts: first.artifacts,
    codeDriver: first.codeDriver,
    controllerId: 'controller-after-restart',
    hostBootId: 'boot-after-restart',
  });
  const report = await restarted.service.initialize();
  assert.equal(report.processed, 1);
  assert.equal(first.machine.records.size, machineCount);
  assert.equal(first.jobs.records.size, jobCount);
  assert.deepEqual(first.codeDriver.calls, driverCalls);
  assert.equal(restarted.service.store.get(tx(executed).transactionId).lifecycle.persistedState, 'EXECUTING');
});

test('response loss after durable execute intent persists RECOVERY_REQUIRED and startup does not resubmit blindly', async (t) => {
  const first = makeHarness(t);
  first.codeDriver.fail.execute = new Error('simulated response loss');
  const created = createVia(first.service);
  const uncertain = await execute(first, created);
  assert.equal(tx(uncertain).lifecycle.persistedState, 'RECOVERY_REQUIRED');
  assert.equal(first.codeDriver.calls.execute, 1);
  const restarted = makeHarness(t, {
    stateRoot: first.stateRoot,
    jobs: first.jobs,
    machine: first.machine,
    artifacts: first.artifacts,
    codeDriver: first.codeDriver,
    controllerId: 'controller-after-restart',
    hostBootId: 'boot-after-restart',
  });
  await restarted.service.initialize();
  assert.equal(first.codeDriver.calls.execute, 1);
  assert.notEqual(restarted.service.store.get(tx(uncertain).transactionId).lifecycle.persistedState, 'COMMITTED');
});

test('startup reconciliation never fabricates exit code zero for a lost child job', async (t) => {
  const first = makeHarness(t);
  const created = createVia(first.service);
  const executed = await execute(first, created);
  const jobId = tx(executed).execution.mutationJobIds[0];
  first.jobs.set(jobRecord(jobId, tx(executed).transactionId, 'owner-a', { status: 'lost', exitCode: null, signal: null }));
  const restarted = makeHarness(t, {
    stateRoot: first.stateRoot,
    jobs: first.jobs,
    machine: first.machine,
    artifacts: first.artifacts,
    codeDriver: first.codeDriver,
    controllerId: 'controller-after-restart',
    hostBootId: 'boot-after-restart',
  });
  await restarted.service.initialize();
  const durable = restarted.service.store.get(tx(executed).transactionId);
  assert.notEqual(durable.lifecycle.persistedState, 'COMMITTED');
  assert.equal(first.jobs.records.get(jobId).exitCode, null);
  assert.equal(first.jobs.records.get(jobId).status, 'lost');
});

test('duplicate validate and finalize requests replay without duplicate jobs or candidate artifacts', async (t) => {
  const harness = makeHarness(t);
  const created = createVia(harness.service);
  const executed = await execute(harness, created);
  const validationPayload = { transactionId: tx(executed).transactionId, expectedSequence: tx(executed).lifecycle.stateSequence, reason: 'validate' };
  const validating = await harness.service.validate(validationPayload, context('owner-a', 'validate-key-0001'));
  const validateReplay = await harness.service.validate(validationPayload, context('owner-a', 'validate-key-0001'));
  assert.equal(validateReplay.replayed, true);
  assert.equal(harness.codeDriver.calls.validate, 1);
  const finalizePayload = { transactionId: tx(validating).transactionId, expectedSequence: tx(validating).lifecycle.stateSequence, reason: 'finalize' };
  const committed = await harness.service.finalize(finalizePayload, context('owner-a', 'finalize-key-0001'));
  const artifactCount = harness.artifacts.records.size;
  const finalizeReplay = await harness.service.finalize(finalizePayload, context('owner-a', 'finalize-key-0001'));
  assert.equal(finalizeReplay.replayed, true);
  assert.equal(tx(finalizeReplay).lifecycle.persistedState, 'COMMITTED');
  assert.equal(harness.codeDriver.calls.finalize, 1);
  assert.equal(harness.artifacts.records.size, artifactCount);
  assert.equal(tx(committed).candidate.candidateId, tx(finalizeReplay).candidate.candidateId);
});

test('duplicate rollback request replays after canonical cleanup without duplicate machine destruction', async (t) => {
  const harness = makeHarness(t);
  const created = createVia(harness.service);
  const executed = await execute(harness, created);
  const payload = { transactionId: tx(executed).transactionId, expectedSequence: tx(executed).lifecycle.stateSequence, reason: 'rollback' };
  const rolledBack = await harness.service.rollback(payload, context('owner-a', 'rollback-key-0001'));
  assert.equal(tx(rolledBack).lifecycle.persistedState, 'ROLLED_BACK');
  const replay = await harness.service.rollback(payload, context('owner-a', 'rollback-key-0001'));
  assert.equal(replay.replayed, true);
  assert.equal(harness.machine.destroyCalls.length, 1);
});

test('cleanup obstruction persists RECOVERY_REQUIRED and reconciliation resumes canonical cleanup', async (t) => {
  const harness = makeHarness(t);
  const created = createVia(harness.service);
  const executed = await execute(harness, created);
  harness.machine.destroyFailure = new Error('simulated provider obstruction');
  const blocked = await harness.service.rollback({ transactionId: tx(executed).transactionId, expectedSequence: tx(executed).lifecycle.stateSequence }, context('owner-a', 'rollback-key-0001'));
  assert.equal(tx(blocked).lifecycle.persistedState, 'RECOVERY_REQUIRED');
  assert.equal(tx(blocked).lifecycle.desiredState, 'ROLLED_BACK');
  harness.machine.destroyFailure = null;
  const recovered = await harness.service.reconcile({ transactionId: tx(blocked).transactionId, expectedSequence: tx(blocked).lifecycle.stateSequence, reason: 'obstruction resolved' }, context('owner-a', 'reconcile-key-0001'));
  assert.equal(tx(recovered).lifecycle.persistedState, 'ROLLED_BACK');
  assert.equal(tx(recovered).cleanup.completed, true);
  assert.equal(harness.machine.destroyCalls.length, 2);
  const events = harness.service.store.events(tx(recovered).transactionId, 0, 100);
  assert.ok(events.some((event) => event.nextState === 'RECOVERY_REQUIRED'));
  assert.equal(events.at(-1).nextState, 'ROLLED_BACK');
});

test('incomplete candidate artifact truth prevents COMMITTED', async (t) => {
  const harness = makeHarness(t);
  const originalFinalize = harness.codeDriver.finalize.bind(harness.codeDriver);
  harness.codeDriver.finalize = async (record, operationContext) => {
    const result = await originalFinalize(record, operationContext);
    const manifest = harness.artifacts.records.get(result.candidateManifestArtifactId);
    harness.artifacts.set({ ...manifest, state: 'pending' });
    return result;
  };
  const created = createVia(harness.service);
  const executed = await execute(harness, created);
  const validating = await validate(harness, executed);
  await assert.rejects(() => finalize(harness, validating), /artifact is not finalized/u);
  const durable = harness.service.store.get(tx(validating).transactionId);
  assert.equal(durable.lifecycle.persistedState, 'PREPARING_CANDIDATE');
  assert.notEqual(durable.lifecycle.persistedState, 'COMMITTED');
});

test('status is a read-only derivation and reports unknown child truth without mutation', async (t) => {
  const harness = makeHarness(t);
  const created = createVia(harness.service);
  const record = tx(created);
  const before = harness.service.store.get(record.transactionId);
  const status = harness.service.status({ transactionId: record.transactionId }, context('owner-a', 'status-key-0001'));
  const after = harness.service.store.get(record.transactionId);
  assert.equal(status.truthful, true);
  assert.equal(after.lifecycle.stateSequence, before.lifecycle.stateSequence);
  assert.deepEqual(after, before);
});
