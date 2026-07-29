import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalize, sha256 } from '../../dist/runtime/core.js';
import { OPERATION_CATALOG_VERSION, OPERATION_DEFINITIONS } from '../../dist/runtime/operations/definitions.js';
import { RootCredentialService } from '../../dist/runtime/root-fabric/credentials.js';
import { RootFabricError } from '../../dist/runtime/root-fabric/model.js';
import { ROOT_FABRIC_OPERATION_NAMES, RootFabricService } from '../../dist/runtime/root-fabric/service.js';

const context = (key, subject = 'owner-a') => ({ subject, authorityClass: 'unrestricted-owner', idempotencyKey: key });
const readContext = (subject = 'owner-a') => ({ subject, authorityClass: 'unrestricted-owner' });
const transactionId = `rfx_${'b'.repeat(32)}`;
const bundleDigest = 'c'.repeat(64);
const grantDigest = 'd'.repeat(64);
const policyDigest = 'e'.repeat(64);
const providerProfileDigest = 'f'.repeat(64);
const secretValue = 'jit-secret-material-should-never-enter-records';

function walkFiles(root) {
  const output = [];
  const walk = (path) => { for (const entry of readdirSync(path, { withFileTypes: true })) { const child = join(path, entry.name); if (entry.isDirectory()) walk(child); else output.push(child); } };
  walk(root);
  return output;
}

function makeBinding(input, overrides = {}) {
  return {
    transactionId,
    stepId: 'step-1',
    ownerPrincipalId: input.principalId,
    ownerPrincipalDigest: input.principalDigest,
    credentialReference: input.credentialReference,
    provider: 'HOST_ENVELOPE',
    providerId: 'host-provider',
    providerVersion: '1.0.0',
    providerProfileDigest,
    skillBundleDigest: bundleDigest,
    grantId: 'grant-a',
    grantDigest,
    policyDecisionDigest: policyDigest,
    policyVersion: 'policy-v1',
    transactionSequence: 7,
    fencingToken: 3,
    targetType: 'UNIT',
    targetId: 'babyx-effect-1.service',
    purpose: 'filesystem.file.create',
    transactionDeadline: '2026-07-28T15:10:00.000Z',
    operationDeadline: '2026-07-28T15:05:00.000Z',
    maximumTtlMs: 120_000,
    revocationBehavior: 'CANCEL_AND_ROLLBACK',
    authorizationDigest: 'a'.repeat(64),
    ...overrides,
  };
}

function authority(state) {
  return {
    resolve(input) {
      if (input.transactionId !== transactionId) throw new RootFabricError('transaction_not_found', 'transaction not found');
      if (input.stepId !== 'step-1') throw new RootFabricError('unsupported_operation', 'step not declared');
      if (input.credentialReference !== state.secretPath) throw new RootFabricError('grant_denied', 'credential reference not allowed');
      return makeBinding(input, state.overrides);
    },
    assertCurrent(lease, input) {
      const current = this.resolve({ transactionId: lease.transactionId, stepId: lease.stepId, credentialReference: lease.credentialReference, principalId: input.principalId, principalDigest: input.principalDigest, occurredAt: input.occurredAt });
      for (const key of ['provider', 'providerId', 'providerVersion', 'providerProfileDigest', 'skillBundleDigest', 'grantId', 'grantDigest', 'policyDecisionDigest', 'policyVersion', 'transactionSequence', 'fencingToken', 'targetType', 'targetId', 'purpose', 'authorizationDigest']) {
        if (lease[key] !== current[key]) throw new RootFabricError('fencing_token_stale', `credential ${key} binding changed`);
      }
    },
  };
}

function createPlan() {
  const input = { path: '/tmp/babyx-credential-target' };
  const step = {
    stepId: 'step-1', sequence: 1, operation: 'filesystem.file.create', operationVersion: '1.0.0', input, inputDigest: sha256(canonicalize(input)),
    resourceSelectors: { path: '/tmp/babyx-credential-target' }, effectClass: 'REVERSIBLE', timeoutMs: 120_000, dependencies: [], preconditions: [], preparationRequirements: [], expectedObservations: [], validation: {}, rollbackOperation: 'filesystem.file.delete', compensationOperation: null,
    providerRequirements: ['HOST_ENVELOPE'], credentialReferences: [], restartBehavior: 'READBACK_BEFORE_RETRY',
  };
  step.credentialReferences = [];
  return { step, plan: { atomicityMode: 'ATOMIC_WITHIN_PROVIDER', steps: [step] } };
}

function createExecutingTransaction(service, credentialReference, unitNames, suffix, policyExpiresAt = '2026-07-28T15:05:00.000Z') {
  const { step, plan: planWithoutDigest } = createPlan();
  step.credentialReferences = [credentialReference];
  const plan = { ...planWithoutDigest, planDigest: sha256(canonicalize(planWithoutDigest)) };
  const create = service.transactions.create({
    source: { repository: 'StealthEyeLLC/baby-x', branch: 'test', commit: '1'.repeat(40), tree: '2'.repeat(40) },
    skill: { skillId: `skill-${suffix}`, skillVersion: '1.0.0', bundleDigest, manifestDigest: '3'.repeat(64), signerKeyId: 'signer-1', signerIdentity: 'signer-owner', signatureVerified: true, revocationStateDigest: '4'.repeat(64), capabilityGrantId: 'grant-a', capabilityGrantDigest: grantDigest },
    deadline: '2026-07-28T15:10:00.000Z', atomicityMode: 'ATOMIC_WITHIN_PROVIDER', plan, policy: { requestedPolicy: 'root-policy-v1' }, requestedProvider: 'HOST_ENVELOPE', riskClass: 'controlled', environmentDigest: '5'.repeat(64),
  }, context(`create-${suffix}-0001`));
  let transaction = create.transaction;
  transaction = service.transactions.acquireLease({ transactionId: transaction.transactionId, expectedSequence: transaction.lifecycle.sequence, controllerId: `controller-${suffix}`, ttlMs: 300_000 }, context(`lease-${suffix}-0001`)).transaction;
  transaction = service.transactions.authorize({ transactionId: transaction.transactionId, expectedSequence: transaction.lifecycle.sequence, fencingToken: transaction.lease.fencingToken, decisionDigest: policyDigest, expiresAt: policyExpiresAt, executionProvider: 'HOST_ENVELOPE', providerId: 'host-provider', providerVersion: '1.0.0', providerContractVersion: 'host@1', providerProfileDigest }, context(`authorize-${suffix}-0001`)).transaction;
  transaction = service.transactions.prepare({ transactionId: transaction.transactionId, expectedSequence: transaction.lifecycle.sequence, fencingToken: transaction.lease.fencingToken, priorStateDigest: '6'.repeat(64), artifactIds: [], snapshotReferences: [], rollbackReady: true, compensationReady: false }, context(`prepare-${suffix}-0001`)).transaction;
  transaction = service.transactions.begin({ transactionId: transaction.transactionId, expectedSequence: transaction.lifecycle.sequence, fencingToken: transaction.lease.fencingToken, activeJobIds: ['job-1'], allJobIds: ['job-1'], activeMachineIds: [], allMachineIds: [], unitNames, processIdentities: [{ unitName: unitNames[0] ?? null, processId: 123, processStartTime: '55', bootId: 'boot-a', cgroupId: 'cg-a', invocationId: 'inv-a', executablePath: '/usr/bin/test' }], providerAttempts: [] }, context(`begin-${suffix}-0001`)).transaction;
  return transaction;
}

test('I repair: credential lifecycle is authority-derived, owner-isolated, private, and durably replay-safe', () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-i-state-'));
  const deliveryRoot = mkdtempSync(join(tmpdir(), 'babyx-i-delivery-'));
  const secretPath = join(root, 'source-token');
  chmodSync(deliveryRoot, 0o700);
  writeFileSync(secretPath, secretValue, { mode: 0o600 });
  let now = '2026-07-28T15:00:00.000Z';
  const state = { secretPath, overrides: {} };
  try {
    const service = new RootCredentialService(root, undefined, { deliveryRoot, now: () => now, authority: authority(state) });
    const payload = { credentialReference: secretPath, transactionId, stepId: 'step-1', requestedTtlMs: 60_000 };
    const issued = service.lease(payload, context('credential-lease-0001'));
    assert.equal(issued.replayed, false);
    assert.equal(issued.lease.state, 'LEASED');
    assert.equal(issued.lease.provider, 'HOST_ENVELOPE');
    assert.equal(issued.lease.targetId, 'babyx-effect-1.service');
    assert.equal(issued.lease.expiresAt, '2026-07-28T15:01:00.000Z');
    assert.equal(issued.lease.policyDecisionDigest, policyDigest);
    assert.equal(issued.lease.grantDigest, grantDigest);
    assert.equal(service.lease(payload, context('credential-lease-0001')).replayed, true);
    assert.throws(() => service.lease({ ...payload, requestedTtlMs: 30_000 }, context('credential-lease-0001')), (error) => error.code === 'idempotency_conflict');
    for (const forged of [
      { authorized: true }, { provider: 'HOST_ENVELOPE' }, { grantDigest }, { targetId: 'attacker.service' },
      { transactionDeadline: '2099-01-01T00:00:00.000Z' }, { operationDeadline: '2099-01-01T00:00:00.000Z' }, { expiresAt: '2099-01-01T00:00:00.000Z' },
    ]) assert.throws(() => service.lease({ ...payload, ...forged }, context(`forged-${Object.keys(forged)[0]}-0001`)), (error) => error.code === 'invalid_request');
    assert.throws(() => service.lease({ ...payload, transactionId: `rfx_${'f'.repeat(32)}` }, context('invented-binding-0001')), (error) => error.code === 'transaction_not_found');
    assert.throws(() => service.lease({ ...payload, stepId: 'invented-step' }, context('invented-step-0001')), (error) => error.code === 'unsupported_operation');

    const leaseId = issued.lease.leaseId;
    assert.throws(() => service.get({ leaseId }, readContext('owner-b')), (error) => error.code === 'principal_mismatch');
    assert.equal(service.list({}, readContext('owner-b')).total, 0);
    assert.equal(service.list({ transactionId }, readContext()).total, 1);

    state.overrides = { policyDecisionDigest: '9'.repeat(64) };
    assert.throws(() => service.deliver({ leaseId }, context('credential-deliver-stale-policy')), (error) => error.code === 'fencing_token_stale');
    state.overrides = { targetId: 'different.service' };
    assert.throws(() => service.deliver({ leaseId }, context('credential-deliver-stale-target')), (error) => error.code === 'fencing_token_stale');
    state.overrides = {};

    const delivered = service.deliver({ leaseId }, context('credential-deliver-0001'));
    assert.equal(delivered.replayed, false);
    assert.equal(delivered.lease.state, 'DELIVERED');
    assert.equal(readFileSync(delivered.deliveryPath, 'utf8'), secretValue);
    assert.equal(statSync(delivered.deliveryPath).mode & 0o777, 0o400);
    assert.equal(statSync(deliveryRoot).mode & 0o077, 0);
    const deliveryReplay = service.deliver({ leaseId }, context('credential-deliver-0001'));
    assert.equal(deliveryReplay.replayed, true);
    assert.equal(deliveryReplay.deliveryPath, delivered.deliveryPath);

    const publicView = JSON.stringify({ get: service.get({ leaseId }, readContext()), list: service.list({ transactionId }, readContext()) });
    assert.equal(publicView.includes(secretValue), false);
    assert.equal(service.verifyNoSecretMaterial(JSON.parse(publicView)), true);
    for (const path of walkFiles(join(root, 'root-fabric', 'credentials'))) assert.equal(readFileSync(path, 'utf8').includes(secretValue), false, path);

    const revoked = service.revoke({ leaseId, reason: 'transaction terminal' }, context('credential-revoke-0001'));
    assert.equal(revoked.replayed, false);
    assert.equal(revoked.lease.state, 'CLEANED');
    assert.equal(revoked.lease.deliveryPath, null);
    assert.equal(existsSync(delivered.deliveryPath), false);
    assert.equal(service.revoke({ leaseId, reason: 'transaction terminal' }, context('credential-revoke-0001')).replayed, true);
    const cleaned = service.clean({ leaseId, reason: 'idempotent cleanup' }, context('credential-clean-0001'));
    assert.equal(cleaned.replayed, false);
    assert.equal(cleaned.lease.state, 'CLEANED');
    assert.equal(service.clean({ leaseId, reason: 'idempotent cleanup' }, context('credential-clean-0001')).replayed, true);
    const recovered = service.recover();
    assert.equal(recovered.ok, true);
    assert.ok(recovered.mutationsRecovered >= 3);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(deliveryRoot, { recursive: true, force: true });
  }
});

test('I repair: expiry removes delivered material and startup recovery reaches CLEANED', () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-i-expiry-state-'));
  const deliveryRoot = mkdtempSync(join(tmpdir(), 'babyx-i-expiry-delivery-'));
  const secretPath = join(root, 'source-token');
  chmodSync(deliveryRoot, 0o700);
  writeFileSync(secretPath, secretValue, { mode: 0o600 });
  let now = '2026-07-28T15:00:00.000Z';
  const state = { secretPath, overrides: { maximumTtlMs: 1_000 } };
  try {
    const service = new RootCredentialService(root, undefined, { deliveryRoot, now: () => now, authority: authority(state) });
    const lease = service.lease({ credentialReference: secretPath, transactionId, stepId: 'step-1', requestedTtlMs: 1_000 }, context('credential-expiry-lease')).lease;
    const delivered = service.deliver({ leaseId: lease.leaseId }, context('credential-expiry-deliver'));
    assert.equal(existsSync(delivered.deliveryPath), true);
    now = '2026-07-28T15:00:02.000Z';
    assert.equal(service.get({ leaseId: lease.leaseId }, readContext()).lease.state, 'EXPIRED');
    assert.equal(existsSync(delivered.deliveryPath), false);
    const recovered = service.recover();
    assert.equal(recovered.ok, true);
    assert.equal(recovered.cleaned, 1);
    assert.equal(service.get({ leaseId: lease.leaseId }, readContext()).lease.state, 'CLEANED');
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(deliveryRoot, { recursive: true, force: true });
  }
});

test('I repair: RootFabricService derives grant, policy, provider, target, fence, and deadlines from the durable transaction', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-i-integration-state-'));
  const deliveryRoot = mkdtempSync(join(tmpdir(), 'babyx-i-integration-delivery-'));
  const secretPath = join(root, 'source-token');
  chmodSync(deliveryRoot, 0o700);
  writeFileSync(secretPath, secretValue, { mode: 0o600 });
  let now = '2026-07-28T15:00:00.000Z';
  try {
    const service = new RootFabricService({ stateRoot: root, sourceCommit: '1'.repeat(40), sourceTree: '2'.repeat(40), catalogVersion: '3.4.0', catalogDigest: () => '7'.repeat(64), credentialDeliveryRoot: deliveryRoot, now: () => now });
    const authorizeCalls = [];
    service.trust.authorize = (input) => {
      authorizeCalls.push(structuredClone(input));
      if (input.credentialReferences?.some((reference) => reference !== secretPath)) throw new RootFabricError('grant_denied', 'credential reference denied');
      return { grantId: 'grant-a', grantDigest, limits: { maximumCredentialTtlMs: 60_000, credentialRevocationBehavior: 'CANCEL_AND_ROLLBACK' }, policyVersion: 'policy-v1' };
    };
    const transaction = createExecutingTransaction(service, secretPath, ['babyx-effect-1.service'], 'good');
    const lease = await service.execute('babyx.root.credential.lease', { credentialReference: secretPath, transactionId: transaction.transactionId, stepId: 'step-1', requestedTtlMs: 30_000 }, context('integration-credential-lease'));
    assert.equal(lease.lease.provider, transaction.routing.executionProvider);
    assert.equal(lease.lease.providerId, transaction.routing.providerId);
    assert.equal(lease.lease.providerProfileDigest, transaction.routing.providerProfileDigest);
    assert.equal(lease.lease.skillBundleDigest, transaction.skill.bundleDigest);
    assert.equal(lease.lease.grantDigest, transaction.skill.capabilityGrantDigest);
    assert.equal(lease.lease.policyDecisionDigest, transaction.policy.decisionDigest);
    assert.equal(lease.lease.transactionSequence, transaction.lifecycle.sequence);
    assert.equal(lease.lease.fencingToken, transaction.lease.fencingToken);
    assert.equal(lease.lease.targetType, 'UNIT');
    assert.equal(lease.lease.targetId, 'babyx-effect-1.service');
    assert.equal(lease.lease.expiresAt, '2026-07-28T15:00:30.000Z');
    assert.equal(authorizeCalls.at(-1).credentialReferences[0], secretPath);

    await assert.rejects(service.execute('babyx.root.credential.lease', { credentialReference: secretPath, transactionId: `rfx_${'f'.repeat(32)}`, stepId: 'step-1' }, context('integration-invented-transaction')), (error) => error.code === 'transaction_not_found');
    await assert.rejects(service.execute('babyx.root.credential.lease', { credentialReference: secretPath, transactionId: transaction.transactionId, stepId: 'invented-step' }, context('integration-invented-step')), (error) => error.code === 'unsupported_operation');
    await assert.rejects(service.execute('babyx.root.credential.lease', { credentialReference: '/tmp/not-authorized', transactionId: transaction.transactionId, stepId: 'step-1' }, context('integration-wrong-reference')), (error) => error.code === 'grant_denied');
    for (const forged of [{ authorized: true }, { provider: 'HOST_ENVELOPE' }, { targetId: 'attacker.service' }, { transactionDeadline: '2099-01-01T00:00:00.000Z' }, { operationDeadline: '2099-01-01T00:00:00.000Z' }]) {
      await assert.rejects(service.execute('babyx.root.credential.lease', { credentialReference: secretPath, transactionId: transaction.transactionId, stepId: 'step-1', ...forged }, context(`integration-forged-${Object.keys(forged)[0]}`)), (error) => error.code === 'invalid_request');
    }
    const ambiguous = createExecutingTransaction(service, secretPath, ['unit-a.service', 'unit-b.service'], 'ambiguous');
    await assert.rejects(service.execute('babyx.root.credential.lease', { credentialReference: secretPath, transactionId: ambiguous.transactionId, stepId: 'step-1' }, context('integration-ambiguous-target')), (error) => error.code === 'credential_unavailable');
    const expiring = createExecutingTransaction(service, secretPath, ['unit-expiring.service'], 'expired-policy', '2026-07-28T15:00:30.000Z');
    now = '2026-07-28T15:01:00.000Z';
    await assert.rejects(service.execute('babyx.root.credential.lease', { credentialReference: secretPath, transactionId: expiring.transactionId, stepId: 'step-1' }, context('integration-expired-policy')), (error) => error.code === 'policy_denied');
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(deliveryRoot, { recursive: true, force: true });
  }
});

test('I repair: catalog exposes strict derived credential inputs without caller authorization or deadlines', () => {
  assert.equal(OPERATION_CATALOG_VERSION, '3.5.0');
  assert.equal(OPERATION_DEFINITIONS.length, 231);
  const root = OPERATION_DEFINITIONS.filter((entry) => entry.operation.startsWith('babyx.root.'));
  assert.equal(root.length, 51);
  const expected = ['babyx.root.credential.lease', 'babyx.root.credential.deliver', 'babyx.root.credential.get', 'babyx.root.credential.list', 'babyx.root.credential.revoke', 'babyx.root.credential.clean'];
  for (const operation of expected) {
    assert.equal(ROOT_FABRIC_OPERATION_NAMES.filter((name) => name === operation).length, 1);
    const definition = OPERATION_DEFINITIONS.find((entry) => entry.operation === operation);
    assert.ok(definition);
    assert.equal(definition.input.additionalProperties, false);
  }
  const lease = OPERATION_DEFINITIONS.find((entry) => entry.operation === 'babyx.root.credential.lease');
  assert.deepEqual(Object.keys(lease.input.properties).sort(), ['credentialReference', 'requestedTtlMs', 'stepId', 'transactionId']);
  for (const forbidden of ['authorized', 'provider', 'skillBundleDigest', 'grantDigest', 'targetType', 'targetId', 'expiresAt', 'transactionDeadline', 'operationDeadline']) assert.equal(forbidden in lease.input.properties, false);
  assert.equal(new Set(OPERATION_DEFINITIONS.map((entry) => entry.operation)).size, OPERATION_DEFINITIONS.length);
});
