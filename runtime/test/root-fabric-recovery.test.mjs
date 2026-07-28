import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalize, sha256 } from '../../dist/runtime/core.js';
import { RootEffectTransactionService } from '../../dist/runtime/root-fabric/transactions.js';
import { RootObservationService } from '../../dist/runtime/root-fabric/observability.js';
import { RootCredentialService } from '../../dist/runtime/root-fabric/credentials.js';
import { RootFreezeService, RootRecoveryService } from '../../dist/runtime/root-fabric/recovery.js';

const d = (value) => sha256(String(value));
const context = (key) => ({ subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner', idempotencyKey: `test-${key}` });
const future = () => new Date(Date.now() + 3_600_000).toISOString();
function plan() {
  const input = { executable: '/usr/bin/true' };
  const step = { stepId: 'step-1', sequence: 1, operation: 'process.exec', operationVersion: '1.0.0', input, inputDigest: sha256(canonicalize(input)), resourceSelectors: { executable: '/usr/bin/true' }, effectClass: 'IRREVERSIBLE', timeoutMs: 30_000, dependencies: [], preconditions: [], preparationRequirements: [], expectedObservations: [], validation: {}, rollbackOperation: null, compensationOperation: null, providerRequirements: ['HOST_ENVELOPE'], credentialReferences: [], restartBehavior: 'NEVER_AUTOMATICALLY_RETRY' };
  return { atomicityMode: 'IRREVERSIBLE', steps: [step], planDigest: sha256(canonicalize({ atomicityMode: 'IRREVERSIBLE', steps: [step] })) };
}
function payload() { return { source: { repository: 'StealthEyeLLC/baby-x', branch: 'build/test', commit: 'a'.repeat(40), tree: 'b'.repeat(40) }, skill: { skillId: 'root.kill-test', skillVersion: '1', bundleDigest: d('bundle'), manifestDigest: d('manifest'), signerKeyId: 'key', signerIdentity: 'signer', signatureVerified: true, revocationStateDigest: d('revocation'), capabilityGrantId: 'grant', capabilityGrantDigest: d('grant') }, deadline: future(), atomicityMode: 'IRREVERSIBLE', plan: plan(), policy: {}, requestedProvider: 'HOST_ENVELOPE', riskClass: 'high', environmentDigest: d('env') }; }
function executing(service, prefix) {
  let result = service.create(payload(), context(`${prefix}-create`)); const id = result.transaction.transactionId;
  result = service.acquireLease({ transactionId: id, expectedSequence: 1, controllerId: 'controller', ttlMs: 60_000 }, context(`${prefix}-lease`)); const fence = result.transaction.lease.fencingToken;
  service.authorize({ transactionId: id, expectedSequence: 2, fencingToken: fence, decisionDigest: d('decision'), expiresAt: future(), executionProvider: 'HOST_ENVELOPE', providerId: 'systemd', providerVersion: '1', providerContractVersion: '1', providerProfileDigest: d('profile') }, context(`${prefix}-auth`));
  service.prepare({ transactionId: id, expectedSequence: 3, fencingToken: fence, priorStateDigest: d('prior'), artifactIds: [], snapshotReferences: [], rollbackReady: false, compensationReady: false }, context(`${prefix}-prepare`));
  result = service.begin({ transactionId: id, expectedSequence: 5, fencingToken: fence, activeJobIds: ['job-1'], allJobIds: ['job-1'], activeMachineIds: [], allMachineIds: [], unitNames: ['babyx-root-kill.service'], processIdentities: [{ unitName: 'babyx-root-kill.service', invocationId: 'invocation-1' }], providerAttempts: [] }, context(`${prefix}-begin`));
  return result.transaction;
}

test('J freeze persistence, lost-execution recovery, and complete kill are durable and bounded', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-recovery-'));
  const deliveryRoot = join(root, 'credentials-delivery');
  try {
    const transactions = new RootEffectTransactionService(root);
    const transaction = executing(transactions, 'recovery');
    const freezes = new RootFreezeService(root);
    freezes.set({ scope: 'TRANSACTION', selector: transaction.transactionId, active: true, reason: 'test freeze', expiresAt: null }, context('freeze'));
    assert.equal(freezes.isFrozen({ transactionId: transaction.transactionId }).frozen, true);
    assert.equal(new RootFreezeService(root).isFrozen({ transactionId: transaction.transactionId }).frozen, true);
    const killedUnits = [];
    const authority = {
      inspectUnit: async () => ({ exists: false, matches: true, active: false, terminal: true, identity: {}, resultDigest: null }),
      inspectMachine: async () => ({ exists: false, matches: true, active: false, terminal: true, identity: {}, resultDigest: null }),
      inspectJob: async () => ({ exists: false, matches: true, active: false, terminal: true, identity: {}, resultDigest: null }),
      killUnit: async (unitName, signal) => { killedUnits.push({ unitName, signal }); return { unitName, signal }; },
      killMachine: async (machineId) => ({ machineId }), verifyUnitAbsent: async () => true, verifyMachineAbsent: async () => true,
    };
    const observations = new RootObservationService(root);
    const credentials = new RootCredentialService(root, undefined, { deliveryRoot });
    const recovery = new RootRecoveryService({ stateRoot: root, transactions, observations, credentials, freezes, authority });
    const reconciled = await recovery.reconcile({ transactionId: transaction.transactionId }, context('reconcile'));
    assert.equal(reconciled.results[0].classification, 'RECOVERY_REQUIRED');
    assert.equal(transactions.record(transaction.transactionId).lifecycle.persistedState, 'RECOVERY_REQUIRED');

    const killTx = executing(transactions, 'kill');
    const killed = await recovery.kill({ scope: 'TRANSACTION', selector: killTx.transactionId, reason: 'test emergency kill' }, context('kill-transaction'));
    assert.equal(killed.complete, true);
    assert.equal(killedUnits.some((entry) => entry.unitName === 'babyx-root-kill.service' && entry.signal === 'SIGKILL'), true);
    assert.equal(transactions.record(killTx.transactionId).lifecycle.persistedState, 'CANCEL_REQUESTED');
    assert.equal(freezes.isFrozen({ transactionId: killTx.transactionId }).frozen, true);

    const killAllTx = executing(transactions, 'kill-all');
    const all = await recovery.kill({ scope: 'ALL', selector: '*', reason: 'global emergency stop' }, context('kill-all'));
    assert.equal(all.transactionCount >= 1, true);
    assert.equal(freezes.isFrozen({ newExecution: true }).frozen, true);
    assert.equal(['CANCEL_REQUESTED', 'RECOVERY_REQUIRED'].includes(transactions.record(killAllTx.transactionId).lifecycle.persistedState), true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
