import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalize, sha256 } from '../../dist/runtime/core.js';
import { RootFreezeService, RootRecoveryService } from '../../dist/runtime/root-fabric/recovery.js';
import { OPERATION_CATALOG_VERSION, OPERATION_DEFINITIONS } from '../../dist/runtime/operations/definitions.js';
import { ROOT_FABRIC_OPERATION_NAMES } from '../../dist/runtime/root-fabric/service.js';

const context = (key, subject = 'owner-a') => ({ subject, authorityClass: 'unrestricted-owner', idempotencyKey: key });
const transactionId = `rfx_${'e'.repeat(32)}`;

function transaction(overrides = {}) {
  return {
    transactionId,
    lifecycle: { persistedState: 'EXECUTING', deadline: '2026-07-28T16:10:00.000Z', sequence: 4, ...overrides.lifecycle },
    skill: { skillId: 'skill-one' },
    execution: { unitNames: ['babyx-test.service'], allMachineIds: ['machine-one'], allJobIds: ['job-one'], processIdentities: [], terminal: false, ...overrides.execution },
    validation: { result: null, ...overrides.validation },
    rollback: { result: null, ...overrides.rollback },
    compensation: { result: null, ...overrides.compensation },
    cleanup: { completed: false, ...overrides.cleanup },
    ...Object.fromEntries(Object.entries(overrides).filter(([key]) => !['lifecycle', 'execution', 'validation', 'rollback', 'compensation', 'cleanup'].includes(key))),
  };
}

function transactionStore(records) {
  const byId = new Map(records.map((record) => [record.transactionId, structuredClone(record)]));
  const transitions = [];
  return {
    transitions,
    nonterminal(limit) { return [...byId.values()].slice(0, limit).map((record) => structuredClone(record)); },
    record(id) { const record = byId.get(id); if (!record) throw new Error('transaction not found'); return structuredClone(record); },
    reconcileTransition(id, nextState, reason, observations, actor) {
      const current = byId.get(id);
      if (!current) throw new Error('transaction not found');
      const next = { ...current, lifecycle: { ...current.lifecycle, persistedState: nextState, sequence: current.lifecycle.sequence + 1 } };
      byId.set(id, next);
      transitions.push({ id, nextState, reason, observations, actor });
      return structuredClone(next);
    },
  };
}

function recoveryDependencies(root, transactions, authority, now) {
  const failedObservations = [];
  let credentialRecoveries = 0;
  return {
    failedObservations,
    credentialRecoveries: () => credentialRecoveries,
    service: new RootRecoveryService({
      stateRoot: root,
      transactions,
      observations: {
        active() { return [{ sessionId: 'obs-expired', deadline: '2026-07-28T15:59:00.000Z' }]; },
        fail(sessionId, reason) { failedObservations.push({ sessionId, reason }); },
      },
      credentials: { recover() { credentialRecoveries += 1; return { ok: true, cleaned: 1 }; } },
      freezes: new RootFreezeService(root, { now }),
      authority,
      now,
    }),
  };
}

test('J: freezes are durable, digest-sealed, replay-safe, scope-aware, and expire closed', () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-j-freeze-'));
  let now = '2026-07-28T16:00:00.000Z';
  try {
    const freezes = new RootFreezeService(root, { now: () => now });
    const request = { scope: 'NEW_EXECUTION', selector: '*', active: true, reason: 'checkpoint J proof', expiresAt: '2026-07-28T16:00:01.000Z' };
    const first = freezes.set(request, context('freeze-0001'));
    assert.equal(first.replayed, false);
    assert.equal(first.freeze.active, true);
    assert.equal(first.freeze.recordDigest, sha256(canonicalize(Object.fromEntries(Object.entries(first.freeze).filter(([key]) => key !== 'recordDigest')))));
    assert.equal(freezes.set(request, context('freeze-0001')).replayed, true);
    assert.throws(() => freezes.set({ ...request, reason: 'conflict' }, context('freeze-0001')), (error) => error.code === 'idempotency_conflict');
    assert.equal(freezes.isFrozen({ newExecution: true }).frozen, true);
    assert.equal(new RootFreezeService(root, { now: () => now }).isFrozen({ newExecution: true }).frozen, true);
    now = '2026-07-28T16:00:02.000Z';
    const expired = freezes.get({ scope: 'NEW_EXECUTION', selector: '*' }).freezes[0];
    assert.equal(expired.active, false);
    assert.equal(expired.reason, 'freeze expired');
    assert.equal(expired.sequence, 2);
    assert.equal(expired.previousEventDigest, first.freeze.eventDigest);
    assert.equal(freezes.isFrozen({ newExecution: true }).frozen, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('J: emergency kill freezes first and requires terminal readback for units, machines, and jobs', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-j-kill-'));
  const calls = [];
  const records = transactionStore([transaction()]);
  const authority = {
    async inspectUnit() { throw new Error('not used by kill'); }, async inspectMachine() { throw new Error('not used by kill'); }, async inspectJob() { throw new Error('not used by kill'); },
    async killUnit(id, signal) { calls.push(['unit', id, signal]); return { killed: true }; },
    async killMachine(id) { calls.push(['machine', id]); return { destroyed: true }; },
    async killJob(id, signal) { calls.push(['job', id, signal]); return { cancelled: true }; },
    async verifyUnitAbsent() { return true; }, async verifyMachineAbsent() { return true; }, async verifyJobTerminal() { return true; },
  };
  try {
    const dependencies = recoveryDependencies(root, records, authority, () => '2026-07-28T16:00:00.000Z');
    const result = await dependencies.service.kill({ scope: 'TRANSACTION', selector: transactionId, reason: 'operator emergency stop' }, context('kill-0001'));
    assert.equal(result.complete, true);
    assert.equal(result.transactionCount, 1);
    assert.equal(result.actions.length, 3);
    assert.deepEqual(calls, [['unit', 'babyx-test.service', 'SIGKILL'], ['machine', 'machine-one'], ['job', 'job-one', 'SIGKILL']]);
    assert.equal(records.transitions.length, 1);
    assert.equal(records.transitions[0].nextState, 'CANCEL_REQUESTED');
    assert.equal(records.transitions[0].reason, 'emergency_kill');
    const freezes = new RootFreezeService(root, { now: () => '2026-07-28T16:00:00.000Z' });
    assert.equal(freezes.isFrozen({ transactionId }).frozen, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('J: incomplete kill and reconciliation fail closed into RECOVERY_REQUIRED while cleanup continues', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-j-reconcile-'));
  const activeId = `rfx_${'a'.repeat(32)}`;
  const expiredId = `rfx_${'b'.repeat(32)}`;
  const active = transaction({ transactionId: activeId, execution: { unitNames: ['active.service'], allMachineIds: [], allJobIds: [], processIdentities: [], terminal: false } });
  const expired = transaction({ transactionId: expiredId, lifecycle: { persistedState: 'READY', deadline: '2026-07-28T15:00:00.000Z', sequence: 2 }, execution: { unitNames: [], allMachineIds: [], allJobIds: [], processIdentities: [], terminal: false } });
  const records = transactionStore([active, expired]);
  const authority = {
    async inspectUnit() { return { exists: true, matches: true, active: true, terminal: false, identity: {}, resultDigest: 'a'.repeat(64) }; },
    async inspectMachine() { return { exists: false, matches: true, active: false, terminal: true, identity: {}, resultDigest: null }; },
    async inspectJob() { return { exists: false, matches: true, active: false, terminal: true, identity: {}, resultDigest: null }; },
    async killUnit() { return { killed: true }; }, async killMachine() { return { killed: true }; }, async killJob() { return { killed: true }; },
    async verifyUnitAbsent() { return true; }, async verifyMachineAbsent() { return true; }, async verifyJobTerminal() { return false; },
  };
  try {
    const dependencies = recoveryDependencies(root, records, authority, () => '2026-07-28T16:00:00.000Z');
    const reconciled = await dependencies.service.reconcile({ limit: 10 }, context('reconcile-0001'));
    assert.deepEqual(reconciled.results.map((entry) => entry.classification).sort(), ['EXPIRED', 'RESUMED']);
    assert.equal(records.transitions.some((entry) => entry.id === expiredId && entry.nextState === 'EXPIRED'), true);
    assert.equal(records.transitions.some((entry) => entry.id === activeId), false);
    assert.equal(dependencies.credentialRecoveries(), 1);
    assert.deepEqual(dependencies.failedObservations, [{ sessionId: 'obs-expired', reason: 'observation deadline elapsed during reconciliation' }]);
    assert.equal((await dependencies.service.reconcile({ limit: 10 }, context('reconcile-0001'))).replayed, true);

    const killRecords = transactionStore([transaction()]);
    const killDependencies = recoveryDependencies(join(root, 'incomplete'), killRecords, authority, () => '2026-07-28T16:00:00.000Z');
    const incomplete = await killDependencies.service.kill({ scope: 'TRANSACTION', selector: transactionId, reason: 'incomplete proof' }, context('kill-incomplete'));
    assert.equal(incomplete.complete, false);
    assert.equal(incomplete.unresolved.some((entry) => entry.includes(`${transactionId}:job:job-one`)), true);
    assert.equal(killRecords.transitions[0].nextState, 'RECOVERY_REQUIRED');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('J: catalog exposes exactly four schema-backed recovery controls and preserves H and I', () => {
  assert.equal(OPERATION_CATALOG_VERSION, '3.4.0');
  assert.equal(OPERATION_DEFINITIONS.length, 230);
  const root = OPERATION_DEFINITIONS.filter((entry) => entry.operation.startsWith('babyx.root.'));
  assert.equal(root.length, 51);
  const expected = ['babyx.root.freeze.get', 'babyx.root.freeze.set', 'babyx.root.kill', 'babyx.root.reconcile'];
  for (const operation of expected) {
    assert.equal(ROOT_FABRIC_OPERATION_NAMES.filter((name) => name === operation).length, 1);
    const definition = OPERATION_DEFINITIONS.find((entry) => entry.operation === operation);
    assert.ok(definition);
    assert.equal(definition.input.additionalProperties, false);
  }
  for (const operation of ['babyx.root.observation.start', 'babyx.root.credential.lease']) assert.ok(ROOT_FABRIC_OPERATION_NAMES.includes(operation));
  assert.equal(ROOT_FABRIC_OPERATION_NAMES.length, 40);
  assert.equal(new Set(OPERATION_DEFINITIONS.map((entry) => entry.operation)).size, OPERATION_DEFINITIONS.length);
});
