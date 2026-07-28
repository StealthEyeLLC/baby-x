import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalize, sha256 } from '../../dist/runtime/core.js';
import { OPERATION_CATALOG_VERSION, OPERATION_DEFINITIONS } from '../../dist/runtime/operations/definitions.js';
import { RootFabricError } from '../../dist/runtime/root-fabric/model.js';
import { RootFreezeService, RootRecoveryService } from '../../dist/runtime/root-fabric/recovery.js';
import { ROOT_FABRIC_OPERATION_NAMES } from '../../dist/runtime/root-fabric/service.js';
import { RootEffectTransactionService } from '../../dist/runtime/root-fabric/transactions.js';

const context = (key, subject = 'owner-a') => ({ subject, authorityClass: 'unrestricted-owner', idempotencyKey: key });
const NOW = '2026-07-28T16:00:00.000Z';
const transactionId = `rfx_${'e'.repeat(32)}`;
const jsonClone = (value) => JSON.parse(JSON.stringify(value));

function unitIdentity(id = transactionId, overrides = {}) {
  return {
    unitName: 'babyx-test.service',
    transactionId: id,
    requestDigest: 'a'.repeat(64),
    cgroupId: '/baby-x-root.slice/babyx-test.service',
    processId: 123,
    processStartTime: '55',
    systemdStartTimestamp: '42',
    bootId: 'boot-1',
    invocationId: 'inv-1',
    executablePath: '/usr/bin/test',
    ...overrides,
  };
}

function fakeTransaction(overrides = {}) {
  const lifecycle = { persistedState: 'EXECUTING', desiredState: 'EXECUTING', deadline: '2026-07-28T16:10:00.000Z', sequence: 7, terminal: false, ...(overrides.lifecycle ?? {}) };
  const lease = { fencingToken: 3, expiresAt: '2026-07-28T16:05:00.000Z', controllerId: 'controller-a', ...(overrides.lease ?? {}) };
  const id = overrides.transactionId ?? transactionId;
  const execution = {
    unitNames: ['babyx-test.service'], allMachineIds: ['machine-one'], allJobIds: ['job-one'],
    processIdentities: [unitIdentity(id)], terminal: false, ...(overrides.execution ?? {}),
  };
  return {
    transactionId: id,
    ownerPrincipal: { principalId: 'owner-a', principalDigest: 'owner-digest' },
    lifecycle,
    lease,
    skill: { skillId: overrides.skillId ?? 'skill-one' },
    execution,
    validation: { result: null, ...(overrides.validation ?? {}) },
    rollback: { result: null, ...(overrides.rollback ?? {}) },
    compensation: { result: null, ...(overrides.compensation ?? {}) },
    cleanup: { completed: false, terminalState: null, ...(overrides.cleanup ?? {}) },
  };
}

function fakeTransactions(records) {
  const byId = new Map(records.map((record) => [record.transactionId, jsonClone(record)]));
  const transitions = [];
  const replay = new Map();
  const read = (control) => {
    const record = byId.get(control.transactionId);
    if (!record) throw new RootFabricError('transaction_not_found', 'transaction not found');
    if (record.lifecycle.sequence !== control.expectedSequence) throw new RootFabricError('transaction_state_conflict', 'transaction sequence mismatch');
    if (record.lease.fencingToken !== control.fencingToken) throw new RootFabricError('fencing_token_stale', 'transaction fencing token mismatch');
    return record;
  };
  return {
    transitions,
    nonterminal(limit) { return [...byId.values()].filter((record) => !record.lifecycle.terminal).slice(0, limit).map((record) => jsonClone(record)); },
    record(id) { const record = byId.get(id); if (!record) throw new RootFabricError('transaction_not_found', 'transaction not found'); return jsonClone(record); },
    recoveryRecord(control) { return jsonClone(read(control)); },
    recoveryTransition(payload, runtimeContext) {
      const replayKey = runtimeContext.idempotencyKey;
      if (replay.has(replayKey)) return jsonClone(replay.get(replayKey));
      const current = read(payload);
      if (current.lifecycle.terminal) throw new RootFabricError('transaction_state_conflict', 'terminal transaction is immutable');
      const terminal = ['COMMITTED', 'ROLLED_BACK', 'COMPENSATED', 'FAILED', 'EXPIRED'].includes(payload.nextState);
      const next = jsonClone(current);
      next.lifecycle.persistedState = payload.nextState;
      next.lifecycle.desiredState = payload.nextState;
      next.lifecycle.sequence += 1;
      next.lifecycle.terminal = terminal;
      byId.set(next.transactionId, next);
      transitions.push({ transactionId: next.transactionId, priorState: current.lifecycle.persistedState, nextState: payload.nextState, expectedSequence: payload.expectedSequence, fencingToken: payload.fencingToken, classification: payload.classification });
      const result = { transaction: jsonClone(next), replayed: false };
      replay.set(replayKey, result);
      return jsonClone(result);
    },
  };
}

function fakeAuthority(options = {}) {
  const state = {
    unitActive: options.unitActive ?? true,
    unitMatches: options.unitMatches ?? true,
    processAbsent: options.processAbsent ?? true,
    cgroupEmpty: options.cgroupEmpty ?? true,
    machineActive: options.machineActive ?? true,
    jobActive: options.jobActive ?? true,
    unitKills: 0, machineKills: 0, jobKills: 0,
  };
  return {
    state,
    async inspectUnit(_unitName, expectedIdentity) {
      return { exists: true, matches: state.unitMatches, active: state.unitActive, terminal: !state.unitActive, identity: { ...expectedIdentity }, resultDigest: '1'.repeat(64) };
    },
    async inspectMachine(machineId, expectedIdentity) { return { exists: state.machineActive, matches: true, active: state.machineActive, terminal: !state.machineActive, identity: { machineId, ...expectedIdentity }, resultDigest: '2'.repeat(64) }; },
    async inspectJob(jobId) { return { exists: true, matches: true, active: state.jobActive, terminal: !state.jobActive, identity: { jobId }, resultDigest: '3'.repeat(64) }; },
    async killUnit(unitName, signal) { state.unitKills += 1; state.unitActive = false; return { unitName, signal, killed: true }; },
    async killMachine(machineId) { state.machineKills += 1; state.machineActive = false; return { machineId, destroyed: true }; },
    async killJob(jobId, signal) { state.jobKills += 1; state.jobActive = false; return { jobId, signal, cancelled: true }; },
    async verifyUnitAbsent(_unitName, expectedIdentity) {
      const identity = { ...expectedIdentity, processAbsent: state.processAbsent, cgroupEmpty: state.cgroupEmpty, unitCollected: false };
      return { exists: true, matches: state.unitMatches, active: state.unitActive, terminal: !state.unitActive && state.processAbsent && state.cgroupEmpty, identity, resultDigest: '4'.repeat(64) };
    },
    async verifyMachineAbsent() { return !state.machineActive; },
    async verifyJobTerminal() { return !state.jobActive; },
  };
}

function dependencies(root, transactions, authority) {
  return new RootRecoveryService({
    stateRoot: root,
    transactions,
    observations: { active() { return []; }, fail() { throw new Error('unexpected observation failure'); } },
    credentials: { recover() { return { ok: true, mutationsRecovered: 0, expired: 0, cleaned: 0, failures: [] }; } },
    freezes: new RootFreezeService(root, { now: () => NOW }),
    authority,
    now: () => NOW,
  });
}

function createRealTransaction(service, suffix = 'real') {
  const input = { path: `/tmp/babyx-${suffix}` };
  const step = {
    stepId: 'step-1', sequence: 1, operation: 'filesystem.file.create', operationVersion: '1.0.0', input, inputDigest: sha256(canonicalize(input)),
    resourceSelectors: { path: `/tmp/babyx-${suffix}` }, effectClass: 'REVERSIBLE', timeoutMs: 60_000, dependencies: [], preconditions: [], preparationRequirements: [], expectedObservations: [], validation: {}, rollbackOperation: 'filesystem.file.delete', compensationOperation: null,
    providerRequirements: ['HOST_ENVELOPE'], credentialReferences: [], restartBehavior: 'READBACK_BEFORE_RETRY',
  };
  const planWithoutDigest = { atomicityMode: 'ATOMIC_WITHIN_PROVIDER', steps: [step] };
  const plan = { ...planWithoutDigest, planDigest: sha256(canonicalize(planWithoutDigest)) };
  let transaction = service.create({
    source: { repository: 'StealthEyeLLC/baby-x', branch: 'test', commit: '1'.repeat(40), tree: '2'.repeat(40) },
    skill: { skillId: `skill-${suffix}`, skillVersion: '1.0.0', bundleDigest: '3'.repeat(64), manifestDigest: '4'.repeat(64), signerKeyId: 'signer-1', signerIdentity: 'signer-owner', signatureVerified: true, revocationStateDigest: '5'.repeat(64), capabilityGrantId: 'grant-a', capabilityGrantDigest: '6'.repeat(64) },
    deadline: '2026-07-28T16:20:00.000Z', atomicityMode: 'ATOMIC_WITHIN_PROVIDER', plan, policy: { requestedPolicy: 'root-policy-v1' }, requestedProvider: 'HOST_ENVELOPE', riskClass: 'controlled', environmentDigest: '7'.repeat(64),
  }, context(`create-${suffix}-0001`)).transaction;
  transaction = service.acquireLease({ transactionId: transaction.transactionId, expectedSequence: transaction.lifecycle.sequence, controllerId: `controller-${suffix}`, ttlMs: 300_000 }, context(`lease-${suffix}-0001`)).transaction;
  transaction = service.authorize({ transactionId: transaction.transactionId, expectedSequence: transaction.lifecycle.sequence, fencingToken: transaction.lease.fencingToken, decisionDigest: '8'.repeat(64), expiresAt: '2026-07-28T16:10:00.000Z', executionProvider: 'HOST_ENVELOPE', providerId: 'host-provider', providerVersion: '1.0.0', providerContractVersion: 'host@1', providerProfileDigest: '9'.repeat(64) }, context(`authorize-${suffix}-0001`)).transaction;
  transaction = service.prepare({ transactionId: transaction.transactionId, expectedSequence: transaction.lifecycle.sequence, fencingToken: transaction.lease.fencingToken, priorStateDigest: 'a'.repeat(64), artifactIds: [], snapshotReferences: [], rollbackReady: true, compensationReady: false }, context(`prepare-${suffix}-0001`)).transaction;
  transaction = service.begin({ transactionId: transaction.transactionId, expectedSequence: transaction.lifecycle.sequence, fencingToken: transaction.lease.fencingToken, activeJobIds: [], allJobIds: [], activeMachineIds: [], allMachineIds: [], unitNames: [], processIdentities: [], providerAttempts: [] }, context(`begin-${suffix}-0001`)).transaction;
  return transaction;
}

function commitRealTransaction(service, transaction, suffix = 'real') {
  transaction = service.validate({ transactionId: transaction.transactionId, expectedSequence: transaction.lifecycle.sequence, fencingToken: transaction.lease.fencingToken, specification: {}, validatorVersion: '1.0.0', expectedState: {}, observedState: {}, attempts: 1, result: 'SUCCEEDED', resultDigest: 'b'.repeat(64), failureReason: null, executionTerminal: true }, context(`validate-${suffix}-0001`)).transaction;
  return service.commit({ transactionId: transaction.transactionId, expectedSequence: transaction.lifecycle.sequence, fencingToken: transaction.lease.fencingToken, cleanupComplete: true, finalResultDigest: 'c'.repeat(64) }, context(`commit-${suffix}-0001`)).transaction;
}

test('J repair: historical freeze replay cannot overwrite a newer unfreeze and corruption fails closed', () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-j-freeze-'));
  try {
    const freezes = new RootFreezeService(root, { now: () => NOW });
    const freezePayload = { scope: 'TRANSACTION', selector: transactionId, active: true, reason: 'incident', expiresAt: null };
    const first = freezes.set(freezePayload, context('freeze-original-0001'));
    assert.equal(first.freeze.active, true);
    const unfrozen = freezes.set({ ...freezePayload, active: false, reason: 'incident resolved' }, context('freeze-unfreeze-0001'));
    assert.equal(unfrozen.freeze.active, false);
    const replay = freezes.set(freezePayload, context('freeze-original-0001'));
    assert.equal(replay.replayed, true);
    assert.equal(replay.historicalFreeze.active, true);
    assert.equal(replay.freeze.active, false);
    assert.equal(freezes.get({ scope: 'TRANSACTION', selector: transactionId }).freezes[0].active, false);

    const freezeDirectory = join(root, 'root-fabric', 'recovery', 'freezes', 'records');
    const recordPath = join(freezeDirectory, readdirSync(freezeDirectory).find((name) => !name.startsWith('.')));
    const tampered = JSON.parse(readFileSync(recordPath, 'utf8'));
    tampered.eventDigest = '0'.repeat(64);
    tampered.recordDigest = sha256(canonicalize(Object.fromEntries(Object.entries(tampered).filter(([key]) => key !== 'recordDigest'))));
    writeFileSync(recordPath, JSON.stringify(tampered), 'utf8');
    assert.throws(() => freezes.get({}), (error) => error.code === 'corrupt_record');
    writeFileSync(recordPath, '{', 'utf8');
    assert.throws(() => freezes.get({}), (error) => error.code === 'corrupt_record');
    assert.throws(() => freezes.isFrozen({ transactionId }), (error) => error.code === 'corrupt_record');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('J repair: recovery mutations require current sequence/fence and ordinary terminal transactions remain immutable', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-j-terminal-'));
  try {
    const transactions = new RootEffectTransactionService(root, { now: () => NOW });
    let transaction = createRealTransaction(transactions, 'terminal');
    assert.throws(() => transactions.recoveryRecord({ transactionId: transaction.transactionId, expectedSequence: transaction.lifecycle.sequence - 1, fencingToken: transaction.lease.fencingToken }, context('stale-sequence-0001')), (error) => error.code === 'transaction_state_conflict');
    assert.throws(() => transactions.recoveryRecord({ transactionId: transaction.transactionId, expectedSequence: transaction.lifecycle.sequence, fencingToken: transaction.lease.fencingToken + 1 }, context('stale-fence-0001')), (error) => error.code === 'fencing_token_stale');
    assert.throws(() => transactions.recoveryTransition({ transactionId: transaction.transactionId, expectedSequence: transaction.lifecycle.sequence, fencingToken: transaction.lease.fencingToken + 1, nextState: 'RECOVERY_REQUIRED', classification: 'forged', observations: {} }, context('stale-transition-0001')), (error) => error.code === 'fencing_token_stale');

    transaction = commitRealTransaction(transactions, transaction, 'terminal');
    assert.equal(transaction.lifecycle.persistedState, 'COMMITTED');
    const sequence = transaction.lifecycle.sequence;
    const eventCount = transaction.events.length;
    assert.throws(() => transactions.recoveryTransition({ transactionId: transaction.transactionId, expectedSequence: sequence, fencingToken: transaction.lease.fencingToken, nextState: 'RECOVERY_REQUIRED', classification: 'terminal-rewrite', observations: {} }, context('terminal-transition-0001')), (error) => error.code === 'transaction_state_conflict');
    assert.equal(transactions.record(transaction.transactionId).lifecycle.sequence, sequence);
    assert.equal(transactions.record(transaction.transactionId).events.length, eventCount);

    const recovery = dependencies(root, transactions, fakeAuthority({ unitActive: false, machineActive: false, jobActive: false }));
    const reconciled = await recovery.reconcile({ transactionId: transaction.transactionId, expectedSequence: sequence, fencingToken: transaction.lease.fencingToken }, context('terminal-reconcile-0001'));
    assert.equal(reconciled.results[0].nextState, 'COMMITTED');
    assert.equal(transactions.record(transaction.transactionId).lifecycle.sequence, sequence);
    assert.equal(transactions.record(transaction.transactionId).events.length, eventCount);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('J repair: emergency kill is durable, exact-replay safe, fenced, and dispatches each effect once', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-j-kill-'));
  try {
    const record = fakeTransaction();
    const transactions = fakeTransactions([record]);
    const authority = fakeAuthority();
    const recovery = dependencies(root, transactions, authority);
    const payload = { scope: 'TRANSACTION', selector: record.transactionId, reason: 'emergency', transactions: [{ transactionId: record.transactionId, expectedSequence: record.lifecycle.sequence, fencingToken: record.lease.fencingToken }] };
    const first = await recovery.kill(payload, context('kill-idempotency-0001'));
    assert.equal(first.replayed, false);
    assert.equal(first.complete, true);
    assert.equal(first.kill.state, 'COMPLETED');
    assert.equal(authority.state.unitKills, 1);
    assert.equal(authority.state.machineKills, 1);
    assert.equal(authority.state.jobKills, 1);
    assert.equal(transactions.transitions.length, 1);
    assert.equal(transactions.transitions[0].nextState, 'CANCEL_REQUESTED');
    const second = await recovery.kill(payload, context('kill-idempotency-0001'));
    assert.equal(second.replayed, true);
    assert.equal(second.kill.recordDigest, first.kill.recordDigest);
    assert.equal(authority.state.unitKills, 1);
    assert.equal(authority.state.machineKills, 1);
    assert.equal(authority.state.jobKills, 1);
    assert.equal(transactions.transitions.length, 1);
    await assert.rejects(recovery.kill({ ...payload, reason: 'different' }, context('kill-idempotency-0001')), (error) => error.code === 'idempotency_conflict');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('J repair: unit identity mismatch blocks kill and positive process/cgroup absence is mandatory without replaying effects', async () => {
  for (const scenario of [
    { name: 'identity-mismatch', authority: { unitMatches: false }, expectedKills: 0 },
    { name: 'process-remains', authority: { processAbsent: false }, expectedKills: 1 },
    { name: 'cgroup-remains', authority: { cgroupEmpty: false }, expectedKills: 1 },
  ]) {
    const root = mkdtempSync(join(tmpdir(), `babyx-j-${scenario.name}-`));
    try {
      const record = fakeTransaction({ execution: { allMachineIds: [], allJobIds: [] } });
      const transactions = fakeTransactions([record]);
      const authority = fakeAuthority(scenario.authority);
      const recovery = dependencies(root, transactions, authority);
      const payload = { scope: 'TRANSACTION', selector: record.transactionId, reason: scenario.name, transactions: [{ transactionId: record.transactionId, expectedSequence: record.lifecycle.sequence, fencingToken: record.lease.fencingToken }] };
      const first = await recovery.kill(payload, context(`kill-${scenario.name}-0001`));
      assert.equal(first.complete, false, scenario.name);
      assert.equal(first.kill.state, 'RECOVERY_REQUIRED', scenario.name);
      assert.equal(authority.state.unitKills, scenario.expectedKills, scenario.name);
      assert.equal(transactions.transitions.length, 1, scenario.name);
      assert.equal(transactions.transitions[0].nextState, 'RECOVERY_REQUIRED', scenario.name);
      const replay = await recovery.kill(payload, context(`kill-${scenario.name}-0001`));
      assert.equal(replay.replayed, true, scenario.name);
      assert.equal(authority.state.unitKills, scenario.expectedKills, scenario.name);
      assert.equal(transactions.transitions.length, 1, scenario.name);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('J repair: incomplete unit identity fails closed before dispatch', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-j-incomplete-'));
  try {
    const record = fakeTransaction({ execution: { allMachineIds: [], allJobIds: [], processIdentities: [{ unitName: 'babyx-test.service', processId: 123 }] } });
    const transactions = fakeTransactions([record]);
    const authority = fakeAuthority();
    const recovery = dependencies(root, transactions, authority);
    const payload = { scope: 'TRANSACTION', selector: record.transactionId, reason: 'incomplete identity', transactions: [{ transactionId: record.transactionId, expectedSequence: record.lifecycle.sequence, fencingToken: record.lease.fencingToken }] };
    const result = await recovery.kill(payload, context('kill-incomplete-identity-0001'));
    assert.equal(result.complete, false);
    assert.equal(authority.state.unitKills, 0);
    assert.match(result.unresolved.join('\n'), /incomplete_identity|complete unit recovery identity/u);
    assert.equal(transactions.transitions[0].nextState, 'RECOVERY_REQUIRED');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('J repair: completed cleanup preserves the declared truthful terminal result', async () => {
  for (const terminalState of ['ROLLED_BACK', 'COMPENSATED']) {
    const root = mkdtempSync(join(tmpdir(), `babyx-j-clean-${terminalState.toLowerCase()}-`));
    try {
      const record = fakeTransaction({ transactionId: `rfx_${terminalState === 'ROLLED_BACK' ? '1'.repeat(32) : '2'.repeat(32)}`, lifecycle: { persistedState: 'CLEANING', desiredState: 'CLEANING', sequence: 11 }, execution: { unitNames: [], allMachineIds: [], allJobIds: [], processIdentities: [] }, cleanup: { completed: true, terminalState } });
      const transactions = fakeTransactions([record]);
      const recovery = dependencies(root, transactions, fakeAuthority({ unitActive: false, machineActive: false, jobActive: false }));
      const result = await recovery.reconcile({ transactionId: record.transactionId, expectedSequence: record.lifecycle.sequence, fencingToken: record.lease.fencingToken }, context(`reconcile-clean-${terminalState.toLowerCase()}-0001`));
      assert.equal(result.results[0].classification, 'CLEANED');
      assert.equal(result.results[0].nextState, terminalState);
      assert.equal(transactions.transitions.length, 1);
      assert.equal(transactions.transitions[0].nextState, terminalState);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('J repair: catalog schemas and postconditions match the repaired implementation', () => {
  assert.equal(OPERATION_CATALOG_VERSION, '3.4.0');
  assert.equal(OPERATION_DEFINITIONS.length, 230);
  assert.equal(OPERATION_DEFINITIONS.filter((entry) => entry.operation.startsWith('babyx.root.')).length, 51);
  assert.equal(new Set(OPERATION_DEFINITIONS.map((entry) => entry.operation)).size, OPERATION_DEFINITIONS.length);
  for (const operation of ['babyx.root.freeze.get', 'babyx.root.freeze.set', 'babyx.root.kill', 'babyx.root.reconcile']) assert.equal(ROOT_FABRIC_OPERATION_NAMES.filter((name) => name === operation).length, 1);
  const kill = OPERATION_DEFINITIONS.find((entry) => entry.operation === 'babyx.root.kill');
  const reconcile = OPERATION_DEFINITIONS.find((entry) => entry.operation === 'babyx.root.reconcile');
  assert.deepEqual(kill.input.required, ['scope', 'selector', 'reason', 'transactions']);
  assert.deepEqual(reconcile.input.required, ['transactionId', 'expectedSequence', 'fencingToken']);
  assert.deepEqual(kill.postconditions, ['durable_kill_record_persisted', 'fenced_transaction_transition_reported', 'positive_absence_verification_reported']);
  assert.deepEqual(reconcile.postconditions, ['reconciliation_record_persisted', 'fenced_transaction_transition_reported']);
  const observationRecord = OPERATION_DEFINITIONS.find((entry) => entry.operation === 'babyx.root.observation.record');
  assert.deepEqual(observationRecord.postconditions, ['transaction_bound_observation_record_persisted', 'observation_event_chain_verified']);
  const credentialLease = OPERATION_DEFINITIONS.find((entry) => entry.operation === 'babyx.root.credential.lease');
  assert.deepEqual(credentialLease.postconditions, ['transaction_bound_credential_record_persisted', 'credential_event_chain_verified']);
});
