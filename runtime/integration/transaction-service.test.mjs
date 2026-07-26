import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { operationDefinitions } from '../../dist/runtime/core.js';
import {
  context,
  createRequest,
  createVia,
  jobRecord,
  makeHarness,
} from '../test/_transaction-fixture.mjs';

function transaction(result) { return result.transaction; }

async function executeCreated(harness, createResult, key = 'execute-key-0001') {
  const record = transaction(createResult);
  return harness.service.execute({ transactionId: record.transactionId, expectedSequence: record.lifecycle.stateSequence, reason: 'execute fixture mutation' }, context(record.ownerPrincipal, key));
}

test('service creation replays exactly and rejects conflicting idempotency-key reuse', (t) => {
  const harness = makeHarness(t);
  const first = createVia(harness.service);
  const replay = createVia(harness.service);
  assert.equal(transaction(replay).transactionId, transaction(first).transactionId);
  assert.equal(replay.replayed, true);
  assert.throws(() => createVia(harness.service, { request: createRequest({ tree: 'd'.repeat(40) }) }), /idempotency/u);
});

test('owner-scoped mutations reject the wrong principal and stale sequence', async (t) => {
  const harness = makeHarness(t);
  const created = createVia(harness.service);
  const record = transaction(created);
  await assert.rejects(() => harness.service.execute({ transactionId: record.transactionId, expectedSequence: 1 }, context('owner-b', 'execute-key-0001')), /wrong_principal|does not own/u);
  await assert.rejects(() => harness.service.execute({ transactionId: record.transactionId, expectedSequence: 2 }, context('owner-a', 'execute-key-0002')), /expected sequence does not match/u);
});

test('execute delegates checkpointing and mutation exactly once and replays without duplicate work', async (t) => {
  const harness = makeHarness(t);
  const created = createVia(harness.service);
  const first = await executeCreated(harness, created);
  assert.equal(transaction(first).lifecycle.persistedState, 'EXECUTING');
  assert.equal(harness.codeDriver.calls.checkpoint, 1);
  assert.equal(harness.codeDriver.calls.execute, 1);
  const replay = await harness.service.execute({ transactionId: transaction(created).transactionId, expectedSequence: 1, reason: 'execute fixture mutation' }, context('owner-a', 'execute-key-0001'));
  assert.equal(replay.replayed, true);
  assert.equal(harness.codeDriver.calls.checkpoint, 1);
  assert.equal(harness.codeDriver.calls.execute, 1);
});

test('conflicting mutation idempotency-key reuse is rejected', async (t) => {
  const harness = makeHarness(t);
  const created = createVia(harness.service);
  await executeCreated(harness, created);
  await assert.rejects(() => harness.service.execute({ transactionId: transaction(created).transactionId, expectedSequence: 1, reason: 'different request' }, context('owner-a', 'execute-key-0001')), /idempotency key was reused/u);
});

test('owner-scoped reads and bounded list/event operations hide other principals', (t) => {
  const harness = makeHarness(t, { maximumListLimit: 1, maximumEventLimit: 1 });
  const first = createVia(harness.service, { owner: 'owner-a', key: 'create-key-0001' });
  createVia(harness.service, { owner: 'owner-b', key: 'create-key-0002' });
  const listed = harness.service.list({ limit: 1 }, context('owner-a', 'read-key-0001'));
  assert.equal(listed.transactions.length, 1);
  assert.equal(listed.transactions[0].ownerPrincipal, 'owner-a');
  assert.throws(() => harness.service.list({ limit: 2 }, context('owner-a', 'read-key-0002')), /out of bounds/u);
  assert.throws(() => harness.service.get({ transactionId: transaction(first).transactionId }, context('owner-b', 'read-key-0003')), /not found/u);
  const events = harness.service.events({ transactionId: transaction(first).transactionId, limit: 1 }, context('owner-a', 'read-key-0004'));
  assert.equal(events.events.length, 1);
  assert.throws(() => harness.service.events({ transactionId: transaction(first).transactionId, limit: 2 }, context('owner-a', 'read-key-0005')), /out of bounds/u);
});

test('ambiguous child-job ownership persists AMBIGUOUS and never submits validation', async (t) => {
  const harness = makeHarness(t);
  const created = createVia(harness.service);
  const executed = await executeCreated(harness, created);
  const mutationJobId = transaction(executed).execution.mutationJobIds[0];
  harness.jobs.set(jobRecord(mutationJobId, transaction(executed).transactionId, 'different-owner'));
  const result = await harness.service.validate({ transactionId: transaction(executed).transactionId, expectedSequence: transaction(executed).lifecycle.stateSequence }, context('owner-a', 'validate-key-0001'));
  assert.equal(transaction(result).lifecycle.persistedState, 'AMBIGUOUS');
  assert.equal(harness.codeDriver.calls.validate, 0);
});

test('active related validation job blocks candidate finalization', async (t) => {
  const harness = makeHarness(t);
  const created = createVia(harness.service);
  const executed = await executeCreated(harness, created);
  const validating = await harness.service.validate({ transactionId: transaction(executed).transactionId, expectedSequence: transaction(executed).lifecycle.stateSequence }, context('owner-a', 'validate-key-0001'));
  const validationJobId = transaction(validating).execution.validationJobIds[0];
  harness.jobs.set(jobRecord(validationJobId, transaction(validating).transactionId, 'owner-a', { status: 'running', exitCode: null }));
  await assert.rejects(() => harness.service.finalize({ transactionId: transaction(validating).transactionId, expectedSequence: transaction(validating).lifecycle.stateSequence }, context('owner-a', 'finalize-key-0001')), /still active/u);
  assert.equal(harness.codeDriver.calls.finalize, 0);
});

test('validation failure delegates exact rollback and canonical machine destruction', async (t) => {
  const harness = makeHarness(t);
  const created = createVia(harness.service);
  const executed = await executeCreated(harness, created);
  const mutationJobId = transaction(executed).execution.mutationJobIds[0];
  harness.jobs.set(jobRecord(mutationJobId, transaction(executed).transactionId, 'owner-a', { status: 'failed', exitCode: 2 }));
  const rolledBack = await harness.service.validate({ transactionId: transaction(executed).transactionId, expectedSequence: transaction(executed).lifecycle.stateSequence }, context('owner-a', 'validate-key-0001'));
  assert.equal(transaction(rolledBack).lifecycle.persistedState, 'ROLLED_BACK');
  assert.equal(transaction(rolledBack).cleanup.completed, true);
  assert.equal(harness.machine.destroyCalls.length, 1);
  assert.equal(harness.codeDriver.calls.validate, 0);
});

test('conflicting machine ownership persists AMBIGUOUS and blocks destructive cleanup', async (t) => {
  const harness = makeHarness(t);
  const created = createVia(harness.service);
  const executed = await executeCreated(harness, created);
  const machineId = transaction(executed).execution.machineIds[0];
  const conflicting = harness.machine.records.get(machineId);
  harness.machine.set({ ...conflicting, ownerPrincipal: 'different-owner' });
  const result = await harness.service.rollback({ transactionId: transaction(executed).transactionId, expectedSequence: transaction(executed).lifecycle.stateSequence, reason: 'test rollback' }, context('owner-a', 'rollback-key-0001'));
  assert.equal(transaction(result).lifecycle.persistedState, 'AMBIGUOUS');
  assert.equal(harness.machine.destroyCalls.length, 0);
});

test('expiration delegates cleanup when needed and can close an unexecuted request without resources', async (t) => {
  const harness = makeHarness(t);
  const created = createVia(harness.service);
  const expired = await harness.service.expire({ transactionId: transaction(created).transactionId, expectedSequence: 1 }, context('owner-a', 'expire-key-0001'));
  assert.equal(transaction(expired).lifecycle.persistedState, 'EXPIRED');
  assert.equal(transaction(expired).cleanup.completed, true);
  assert.equal(harness.machine.destroyCalls.length, 0);
});

test('GC defaults to owner-scoped bounded dry-run with inclusion and exclusion reasons', (t) => {
  const harness = makeHarness(t, { maximumListLimit: 2 });
  createVia(harness.service, { owner: 'owner-a', key: 'create-key-0001' });
  createVia(harness.service, { owner: 'owner-b', key: 'create-key-0002' });
  const report = harness.service.gc({ limit: 2 }, context('owner-a', 'gc-key-0001'));
  return report.then((value) => {
    assert.equal(value.dryRun, true);
    assert.equal(value.ownerScoped, true);
    assert.equal(value.bounded, true);
    assert.equal(value.candidates.length, 1);
    assert.equal(value.candidates[0].ownerPrincipal, 'owner-a');
    assert.match(value.candidates[0].reason, /canonical expiration/u);
    assert.deepEqual(value.actions, []);
  });
});

test('single public registry exposes exactly twelve routed transaction operations', () => {
  const expected = [
    'babyx.transaction.create', 'babyx.transaction.events', 'babyx.transaction.execute', 'babyx.transaction.expire',
    'babyx.transaction.finalize', 'babyx.transaction.gc', 'babyx.transaction.get', 'babyx.transaction.list',
    'babyx.transaction.reconcile', 'babyx.transaction.rollback', 'babyx.transaction.status', 'babyx.transaction.validate',
  ];
  const definitions = operationDefinitions().filter((entry) => entry.operation.startsWith('babyx.transaction.'));
  assert.deepEqual(definitions.map((entry) => entry.operation).sort(), expected);
  assert.equal(new Set(definitions.map((entry) => entry.operation)).size, 12);
  for (const definition of definitions) assert.equal(definition.input.additionalProperties, false);
  const core = readFileSync('runtime/src/core.ts', 'utf8');
  assert.match(core, /transactionServiceInitializePromise/u);
  assert.match(core, /await this\.transactionService\(\)/u);
  const gateway = readFileSync('gateway/src/tool.js', 'utf8');
  assert.doesNotMatch(gateway, /transaction\.execute/u);
});

test('transaction coordinator source contains no direct provider, process, merge, deployment, or release authority', () => {
  const files = ['runtime/src/transactions/schemas.ts', 'runtime/src/transactions/store.ts', 'runtime/src/transactions/service.ts'];
  const source = files.map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.doesNotMatch(source, /from\s+['"]node:child_process['"]|\b(?:spawnSync|execFileSync|execSync|fork)\s*\(/u);
  assert.doesNotMatch(source, /\b(?:zfs|zpool|machinectl|systemd-nspawn)\b\s/u);
  assert.doesNotMatch(source, /\bgit\s+(?:merge|push|update-ref)|release activation|deploy\s*\(/iu);
  assert.match(source, /machineLifecycleAuthority: 'disposable-machine-service'/u);
  assert.match(source, /processAuthority: 'baby-x-durable-jobs'/u);
});


test('runtime wires the disposable driver to the sole durable job authority', () => {
  const core = readFileSync(`${process.cwd()}/runtime/src/core.ts`, 'utf8');
  assert.match(core, /new DisposableCodeTransactionDriver\(\{ machine, jobs: this\.jobs, artifacts \}\)/u);
  assert.doesNotMatch(core, /new DisposableCodeTransactionDriver\(\{[^}]*stateRoot/u);
});
