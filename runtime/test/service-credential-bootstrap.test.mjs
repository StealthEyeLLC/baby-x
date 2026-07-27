import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
  ReleaseApplianceStore,
  ReleaseStoreError,
  ServiceCredentialBootstrapService,
  ServiceCredentialContractError,
  canonicalize,
  serviceCredentialCompatibilityDigest,
  sha256,
} from '../../dist/runtime/index.js';

const OWNER = 'stealtheye-owner';
const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);

function root() { return mkdtempSync(join(tmpdir(), 'baby-x-service-credential-bootstrap-')); }

function clock(start = Date.parse('2026-07-27T07:30:00.000Z')) {
  let value = start;
  return () => {
    const result = new Date(value).toISOString();
    value += 1_000;
    return result;
  };
}

function controller(suffix = 'a') {
  return { pid: 4242, processStartTime: `5188${suffix}`, executablePath: '/opt/baby-x/controller', bootId: `boot-${suffix}` };
}

function service(store, options = {}) {
  return new ServiceCredentialBootstrapService({ store, now: options.now ?? clock(), controllerIdentity: options.controllerIdentity ?? controller(), leaseTtlMs: 10_000 });
}

function request(overrides = {}) {
  return {
    ownerPrincipal: OWNER,
    idempotencyKey: 'k5-bootstrap-request-a',
    profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
    expectedCompatibilityIdentity: serviceCredentialCompatibilityDigest(),
    policyDecision: {
      decision: 'ALLOW', decisionDigest: DIGEST_A, policyIdentity: 'credential-bootstrap-policy-v1',
      environmentClass: 'production-controller', reasonCodes: ['CHECKPOINT_K5_AUTHORIZED'],
    },
    ...overrides,
  };
}

function readyFacts() {
  return {
    privateReferencesDurable: true, publicMaterialDurable: true, keyRelationshipVerified: true,
    serviceIdentityVerified: true, expectedUidVerified: true, ownershipVerified: true, modesVerified: true,
    temporaryMaterialAbsent: true, forbiddenAuthorityUntouched: true,
  };
}

function code(expected) {
  return (error) => (error instanceof ReleaseStoreError || error instanceof ServiceCredentialContractError) && error.code === expected;
}

function transition(coordinator, record, nextState, patch = {}, extras = {}) {
  return coordinator.transition({
    transactionId: record.transactionId,
    ownerPrincipal: OWNER,
    expectedSequence: record.sequence,
    nextState,
    operation: 'babyx.release.credential-bootstrap.reconcile',
    phase: `test-${String(nextState).toLowerCase()}`,
    patch,
    ...extras,
  });
}

test('durable bootstrap intent exists before any credential effect', () => {
  const directory = root();
  try {
    const coordinator = service(new ReleaseApplianceStore(directory));
    const record = coordinator.requestBootstrap(request());
    assert.equal(record.state, 'REQUESTED');
    assert.equal(record.sequence, 1);
    assert.equal(record.credentialReferenceIds.length, 0);
    assert.equal(record.cleanup.temporaryMaterialCreated, false);
    assert.equal(record.cleanup.productionPathsTouched, false);
    assert.equal(coordinator.events(record.transactionId).events.length, 1);
    assert.equal(coordinator.verifyStore().valid, true);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('idempotent replay returns the same generation and does not duplicate events', () => {
  const directory = root();
  try {
    const coordinator = service(new ReleaseApplianceStore(directory));
    const first = coordinator.requestBootstrap(request());
    const second = coordinator.requestBootstrap(request());
    assert.deepEqual(second, first);
    assert.equal(coordinator.events(first.transactionId).events.length, 1);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('conflicting reuse of an idempotency key fails closed', () => {
  const directory = root();
  try {
    const coordinator = service(new ReleaseApplianceStore(directory));
    coordinator.requestBootstrap(request());
    assert.throws(() => coordinator.requestBootstrap(request({ policyDecision: { ...request().policyDecision, decisionDigest: DIGEST_B } })), code('release_idempotency_conflict'));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('state transitions are append-only, digest-linked, and sequence exact', () => {
  const directory = root();
  try {
    const coordinator = service(new ReleaseApplianceStore(directory));
    let record = coordinator.requestBootstrap(request());
    record = transition(coordinator, record, 'PLANNING');
    record = transition(coordinator, record, 'GENERATING');
    assert.equal(record.sequence, 3);
    const events = coordinator.events(record.transactionId).events;
    assert.equal(events.length, 3);
    assert.equal(events[1].previousEventDigest, events[0].eventDigest);
    assert.equal(events[2].previousEventDigest, events[1].eventDigest);
    assert.throws(() => transition(coordinator, { ...record, sequence: 1 }, 'PERSISTING_REFERENCES'), code('release_stale_sequence'));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('wrong principal and immutable identity replacement are rejected', () => {
  const directory = root();
  try {
    const coordinator = service(new ReleaseApplianceStore(directory));
    const record = coordinator.requestBootstrap(request());
    assert.throws(() => coordinator.transition({ transactionId: record.transactionId, ownerPrincipal: 'wrong-owner', expectedSequence: 1, nextState: 'PLANNING', operation: 'babyx.release.credential-bootstrap.reconcile', phase: 'wrong-owner' }), code('release_credential_bootstrap_identity_mismatch'));
    assert.throws(() => transition(coordinator, record, 'PLANNING', { generationId: 'scg-replaced' }), code('release_credential_bootstrap_identity_mismatch'));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('READY cannot be reached without durable references and complete verification truth', () => {
  const directory = root();
  try {
    const coordinator = service(new ReleaseApplianceStore(directory));
    let record = coordinator.requestBootstrap(request());
    for (const state of ['PLANNING','GENERATING','PERSISTING_REFERENCES','BINDING_IDENTITY','MATERIALIZING_PUBLIC_STATE','VERIFYING']) record = transition(coordinator, record, state);
    assert.throws(() => transition(coordinator, record, 'READY', {}, { readyFacts: readyFacts() }), code('release_credential_bootstrap_not_ready'));
    record = coordinator.transition({
      transactionId: record.transactionId, ownerPrincipal: OWNER, expectedSequence: record.sequence,
      nextState: 'READY', operation: 'babyx.release.credential-bootstrap.reconcile', phase: 'verify-ready',
      patch: {
        credentialReferenceIds: ['credential-ref-gateway', 'credential-ref-proof'],
        publicMaterialReferences: [{ referenceId: 'public-proof', digest: DIGEST_A }],
      },
      readyFacts: readyFacts(),
    });
    assert.equal(record.state, 'READY');
    assert.deepEqual(record.verification, readyFacts());
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('unknown external state becomes RECOVERY_REQUIRED and repeated uncertainty becomes AMBIGUOUS', () => {
  const directory = root();
  try {
    const coordinator = service(new ReleaseApplianceStore(directory));
    let record = coordinator.requestBootstrap(request());
    record = coordinator.reconcile({ transactionId: record.transactionId, ownerPrincipal: OWNER, expectedSequence: record.sequence, observation: 'EXTERNAL_STATE_UNKNOWN', observationDigest: DIGEST_A });
    assert.equal(record.state, 'RECOVERY_REQUIRED');
    record = coordinator.reconcile({ transactionId: record.transactionId, ownerPrincipal: OWNER, expectedSequence: record.sequence, observation: 'EXTERNAL_EFFECT_OBSERVED', observationDigest: DIGEST_B });
    assert.equal(record.state, 'AMBIGUOUS');
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('no-effect recovery advances durable intent only to PLANNING', () => {
  const directory = root();
  try {
    const coordinator = service(new ReleaseApplianceStore(directory));
    const requested = coordinator.requestBootstrap(request());
    const recovered = coordinator.reconcile({ transactionId: requested.transactionId, ownerPrincipal: OWNER, expectedSequence: 1, observation: 'NO_EXTERNAL_EFFECT', observationDigest: DIGEST_A });
    assert.equal(recovered.state, 'PLANNING');
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('terminal records cannot be silently rewritten', () => {
  const directory = root();
  try {
    const coordinator = service(new ReleaseApplianceStore(directory));
    const requested = coordinator.requestBootstrap(request());
    const failed = transition(coordinator, requested, 'FAILED', { error: { code: 'release_credential_bootstrap_generation_failed', message: 'redacted', retryable: false, phase: 'test' } });
    assert.equal(failed.state, 'FAILED');
    assert.throws(() => transition(coordinator, failed, 'RECOVERY_REQUIRED'), code('release_credential_bootstrap_invalid_state'));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('response loss after record durability recovers exactly once', () => {
  const directory = root();
  try {
    let injected = false;
    const crashingStore = new ReleaseApplianceStore(directory, { faultInjector(stage) { if (stage === 'after_record_write' && !injected) { injected = true; throw new Error('simulated response loss after record'); } } });
    const crashing = service(crashingStore);
    assert.throws(() => crashing.requestBootstrap(request()), /simulated response loss/u);
    assert.equal(crashingStore.listPending().length, 1);
    const restartedStore = new ReleaseApplianceStore(directory);
    const restarted = service(restartedStore, { controllerIdentity: controller('b'), now: clock(Date.parse('2026-07-27T07:40:00.000Z')) });
    const report = restarted.startup();
    assert.equal(report.recoveredPending, 1);
    const replay = restarted.requestBootstrap(request());
    assert.equal(replay.state, 'REQUESTED');
    assert.equal(restarted.events(replay.transactionId).events.length, 1);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('response loss after event durability recovers without duplicate event', () => {
  const directory = root();
  try {
    let injected = false;
    const crashingStore = new ReleaseApplianceStore(directory, { faultInjector(stage) { if (stage === 'after_event_write' && !injected) { injected = true; throw new Error('simulated response loss after event'); } } });
    assert.throws(() => service(crashingStore).requestBootstrap(request()), /simulated response loss/u);
    const restarted = service(new ReleaseApplianceStore(directory), { controllerIdentity: controller('c'), now: clock(Date.parse('2026-07-27T07:50:00.000Z')) });
    assert.equal(restarted.startup().recoveredPending, 1);
    const replay = restarted.requestBootstrap(request());
    assert.equal(restarted.events(replay.transactionId).events.length, 1);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('live foreign SERVICE lease blocks overlapping bootstrap mutation', () => {
  const directory = root();
  try {
    const store = new ReleaseApplianceStore(directory);
    store.acquireLease({
      schemaVersion: '1.0.0', leaseId: 'foreign-lease', resourceType: 'SERVICE', resourceId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
      ownerPrincipal: 'foreign-owner', controllerIdentity: controller('foreign'), acquiredAt: '2026-07-27T07:29:00.000Z', expiresAt: '2026-07-27T08:00:00.000Z',
      sequence: 1, state: 'ACTIVE', observationDigest: DIGEST_A,
    }, { now: '2026-07-27T07:29:00.000Z', existingControllerAbsent: false });
    assert.throws(() => service(store).requestBootstrap(request()), code('release_controller_conflict'));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('released lease is replaced only after positive state readback', () => {
  const directory = root();
  try {
    const coordinator = service(new ReleaseApplianceStore(directory));
    let record = coordinator.requestBootstrap(request());
    record = transition(coordinator, record, 'PLANNING');
    assert.equal(record.state, 'PLANNING');
    const lease = coordinator.store.getLease('SERVICE', BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID);
    assert.equal(lease.state, 'RELEASED');
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('bounded transaction and event reads reject excessive limits', () => {
  const directory = root();
  try {
    const coordinator = service(new ReleaseApplianceStore(directory));
    const record = coordinator.requestBootstrap(request());
    assert.throws(() => coordinator.list({ limit: 201 }), code('release_credential_bootstrap_invalid_request'));
    assert.throws(() => coordinator.events(record.transactionId, 0, 1001), code('release_credential_bootstrap_invalid_request'));
    assert.equal(coordinator.list({ limit: 1 }).bounded, true);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('one corrupt bootstrap record is isolated from healthy transactions', () => {
  const directory = root();
  try {
    const store = new ReleaseApplianceStore(directory);
    const coordinator = service(store);
    const first = coordinator.requestBootstrap(request());
    const second = coordinator.requestBootstrap(request({ idempotencyKey: 'k5-bootstrap-request-b' }));
    writeFileSync(store.authoritativeRecordPath('ServiceCredentialBootstrapTransactionV1', first.transactionId), '{broken-json}\n', { mode: 0o600 });
    const listed = coordinator.list();
    assert.equal(listed.transactions.length, 1);
    assert.equal(listed.transactions[0].transactionId, second.transactionId);
    assert.equal(listed.isolated.length, 1);
    assert.equal(coordinator.startup().corrupt, 1);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('derived indexes repair without rewriting authoritative transaction bytes', () => {
  const directory = root();
  try {
    const store = new ReleaseApplianceStore(directory);
    const coordinator = service(store);
    const record = coordinator.requestBootstrap(request());
    const path = store.authoritativeRecordPath('ServiceCredentialBootstrapTransactionV1', record.transactionId);
    const before = sha256(readFileSync(path));
    const paths = store.derivedIndexPaths();
    writeFileSync(paths.indexesPath, '{"schemaVersion":"broken"}\n', { mode: 0o600 });
    writeFileSync(paths.idempotencyPath, '{broken}\n', { mode: 0o600 });
    const repaired = coordinator.verifyAndRepairIndexes();
    assert.equal(repaired.repairedIndexes, true);
    assert.equal(sha256(readFileSync(path)), before);
    assert.equal(coordinator.verifyStore().valid, true);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('active generation metadata is explicitly EMPTY before activation', () => {
  const directory = root();
  try {
    const active = service(new ReleaseApplianceStore(directory)).active();
    assert.deepEqual(active, { profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID, state: 'EMPTY', activeGenerationId: null, bounded: true });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('public describe and list surfaces contain no raw private material', () => {
  const directory = root();
  try {
    const coordinator = service(new ReleaseApplianceStore(directory));
    coordinator.requestBootstrap(request());
    assert.doesNotMatch(JSON.stringify(coordinator.describe()), /BEGIN PRIVATE KEY/u);
    assert.doesNotMatch(JSON.stringify(coordinator.list()), /BEGIN PRIVATE KEY/u);
    assert.throws(() => coordinator.describe({ unexpected: true }), code('release_credential_bootstrap_invalid_request'));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
