import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ReleaseApplianceStore,
  ReleaseStoreError,
  canonicalize,
  sha256,
} from '../../dist/runtime/index.js';

const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);
const DIGEST_C = 'c'.repeat(64);
const OWNER = 'owner-release-test';

function tempRoot() {
  return mkdtempSync(join(tmpdir(), 'baby-x-release-store-'));
}

function maintenanceRecord(id, sequence, state = 'REQUESTED', ownerPrincipal = OWNER) {
  const createdAt = '2026-07-26T14:00:00.000Z';
  return {
    schemaVersion: '1.0.0',
    maintenanceId: id,
    ownerPrincipal,
    idempotencyKey: `record-${id}`,
    creationRequestDigest: sha256(`create-${id}`),
    maintenanceKind: 'INVENTORY',
    state,
    sequence,
    activeJobIds: [],
    allJobIds: [],
    rebootRequired: false,
    livepatchState: { status: 'UNAVAILABLE' },
    preSnapshot: { digest: DIGEST_A },
    createdAt,
    updatedAt: createdAt,
  };
}

function mutation(record, expectedSequence, key, suffix = key, ownerPrincipal = OWNER) {
  return {
    schemaId: 'MaintenanceRecordV1',
    recordId: record.maintenanceId,
    ownerPrincipal,
    expectedSequence,
    idempotencyKey: key,
    requestDigest: sha256(canonicalize({ suffix, record })),
    operation: 'babyx.release.persist',
    phase: 'checkpoint-b',
    record,
    occurredAt: `2026-07-26T14:00:${String(expectedSequence).padStart(2, '0')}.000Z`,
  };
}

function lease({
  leaseId = 'lease-a',
  resourceType = 'DEPLOYMENT',
  resourceId = 'deployment-a',
  ownerPrincipal = OWNER,
  acquiredAt = '2026-07-26T14:00:00.000Z',
  expiresAt = '2026-07-26T15:00:00.000Z',
  sequence = 1,
  state = 'ACTIVE',
  observationDigest = DIGEST_A,
} = {}) {
  return {
    schemaVersion: '1.0.0',
    leaseId,
    resourceType,
    resourceId,
    ownerPrincipal,
    controllerIdentity: {
      pid: 101,
      processStartTime: '45700000',
      executablePath: '/opt/baby-x/controller',
      bootId: 'boot-a',
    },
    acquiredAt,
    expiresAt,
    sequence,
    state,
    observationDigest,
  };
}

function code(expected) {
  return (error) => error instanceof ReleaseStoreError && error.code === expected;
}

function fileSha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

test('write interruption after durable record replacement recovers exactly once on restart', () => {
  const root = tempRoot();
  try {
    let injected = false;
    const record = maintenanceRecord('maintenance-crash', 1);
    const input = mutation(record, 0, 'idem-crash');
    const crashing = new ReleaseApplianceStore(root, {
      faultInjector(stage) {
        if (stage === 'after_record_write' && !injected) {
          injected = true;
          throw new Error('simulated process loss after record fsync');
        }
      },
    });
    assert.throws(() => crashing.applyMutation(input), /simulated process loss/u);
    assert.equal(crashing.hasRecord('MaintenanceRecordV1', 'maintenance-crash'), true);
    assert.equal(crashing.events('MaintenanceRecordV1', 'maintenance-crash').length, 0);
    const pending = crashing.listPending();
    assert.equal(pending.length, 1);
    assert.equal(pending[0].state, 'PREPARED');

    const restarted = new ReleaseApplianceStore(root);
    const report = restarted.startupScan(100, 100);
    assert.equal(report.recoveredPending, 1);
    assert.equal(report.corrupt, 0);
    assert.equal(restarted.events('MaintenanceRecordV1', 'maintenance-crash').length, 1);
    assert.equal(restarted.listPending()[0].state, 'COMMITTED');
    assert.deepEqual(restarted.applyMutation(input), record);
    assert.equal(restarted.events('MaintenanceRecordV1', 'maintenance-crash').length, 1);
    assert.equal(restarted.verify().valid, true);

    const conflict = { ...input, requestDigest: DIGEST_B };
    assert.throws(() => restarted.applyMutation(conflict), code('release_idempotency_conflict'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('write interruption after event durability recovers pending state without duplicating event', () => {
  const root = tempRoot();
  try {
    let injected = false;
    const record = maintenanceRecord('maintenance-event-crash', 1);
    const input = mutation(record, 0, 'idem-event-crash');
    const crashing = new ReleaseApplianceStore(root, {
      faultInjector(stage) {
        if (stage === 'after_event_write' && !injected) {
          injected = true;
          throw new Error('simulated process loss after event fsync');
        }
      },
    });
    assert.throws(() => crashing.applyMutation(input), /simulated process loss/u);
    assert.equal(crashing.events('MaintenanceRecordV1', 'maintenance-event-crash').length, 1);
    assert.equal(crashing.listPending()[0].state, 'PREPARED');

    const restarted = new ReleaseApplianceStore(root);
    const report = restarted.startupScan(100, 100);
    assert.equal(report.recoveredPending, 1);
    assert.equal(restarted.events('MaintenanceRecordV1', 'maintenance-event-crash').length, 1);
    assert.equal(restarted.listPending()[0].state, 'COMMITTED');
    assert.deepEqual(restarted.applyMutation(input), record);
    assert.equal(restarted.verify().valid, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('stale sequence and wrong principal are rejected before mutation', () => {
  const root = tempRoot();
  try {
    const store = new ReleaseApplianceStore(root);
    store.applyMutation(mutation(maintenanceRecord('maintenance-sequence', 1), 0, 'idem-sequence-create'));
    assert.throws(
      () => store.applyMutation(mutation(maintenanceRecord('maintenance-sequence', 1), 0, 'idem-sequence-stale')),
      code('release_stale_sequence'),
    );
    assert.throws(
      () => store.applyMutation(mutation(maintenanceRecord('maintenance-sequence', 2, 'SIMULATING'), 1, 'idem-sequence-owner', 'owner', 'other-owner')),
      code('release_wrong_principal'),
    );
    assert.equal(store.events('MaintenanceRecordV1', 'maintenance-sequence').length, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('derived index corruption repairs without rewriting authoritative record bytes', () => {
  const root = tempRoot();
  try {
    const store = new ReleaseApplianceStore(root);
    store.applyMutation(mutation(maintenanceRecord('maintenance-index', 1), 0, 'idem-index'));
    const recordPath = store.authoritativeRecordPath('MaintenanceRecordV1', 'maintenance-index');
    const before = fileSha256(recordPath);
    const { indexesPath, idempotencyPath } = store.derivedIndexPaths();
    writeFileSync(indexesPath, '{"schemaVersion":"broken"}\n', { mode: 0o600 });
    writeFileSync(idempotencyPath, '{not-json}\n', { mode: 0o600 });
    const repaired = store.verifyAndRepairIndexes();
    assert.equal(repaired.repairedIndexes, true);
    assert.equal(repaired.indexesMatch, true);
    assert.equal(repaired.idempotencyMatch, true);
    assert.equal(fileSha256(recordPath), before);
    assert.equal(store.verify().valid, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('one corrupt record is isolated while neighboring records remain readable', () => {
  const root = tempRoot();
  try {
    const store = new ReleaseApplianceStore(root);
    store.applyMutation(mutation(maintenanceRecord('maintenance-corrupt', 1), 0, 'idem-corrupt'));
    store.applyMutation(mutation(maintenanceRecord('maintenance-healthy', 1), 0, 'idem-healthy'));
    const corruptPath = store.authoritativeRecordPath('MaintenanceRecordV1', 'maintenance-corrupt');
    writeFileSync(corruptPath, '{"schemaVersion":"1.0.0","maintenanceId":', { mode: 0o600 });
    const report = store.startupScan(100, 100);
    assert.equal(report.corrupt, 1);
    assert.equal(report.processedRecords, 1);
    assert.equal(store.getRecord('MaintenanceRecordV1', 'maintenance-healthy').maintenanceId, 'maintenance-healthy');
    assert.throws(() => store.getRecord('MaintenanceRecordV1', 'maintenance-corrupt'), code('release_record_corrupt'));
    const quarantine = join(root, 'quarantine', 'record');
    assert.equal(readdirSync(quarantine).filter((name) => name.endsWith('.json')).length, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('hash-chained event tampering fails closed', () => {
  const root = tempRoot();
  try {
    const store = new ReleaseApplianceStore(root);
    store.applyMutation(mutation(maintenanceRecord('maintenance-events', 1), 0, 'idem-events-1'));
    store.applyMutation(mutation(maintenanceRecord('maintenance-events', 2, 'SIMULATING'), 1, 'idem-events-2'));
    const eventPath = store.authoritativeEventPath('MaintenanceRecordV1', 'maintenance-events', 2);
    const event = JSON.parse(readFileSync(eventPath, 'utf8'));
    event.previousEventDigest = DIGEST_C;
    writeFileSync(eventPath, `${JSON.stringify(event)}\n`, { mode: 0o600 });
    assert.throws(() => store.events('MaintenanceRecordV1', 'maintenance-events'), code('release_event_corrupt'));
    const report = store.startupScan(100, 100);
    assert.equal(report.corrupt, 1);
    assert.equal(report.diagnostics[0].kind, 'event');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('live controller or route lease overlap is rejected', () => {
  const root = tempRoot();
  try {
    const store = new ReleaseApplianceStore(root);
    store.acquireLease(lease(), { now: '2026-07-26T14:10:00.000Z', existingControllerAbsent: false });
    assert.throws(
      () => store.acquireLease(lease({ leaseId: 'lease-b', ownerPrincipal: 'other-owner', observationDigest: DIGEST_B }), {
        now: '2026-07-26T14:10:00.000Z',
        existingControllerAbsent: true,
      }),
      code('release_controller_conflict'),
    );
    store.acquireLease(lease({
      leaseId: 'route-lease-a',
      resourceType: 'ROUTE',
      resourceId: 'route-a',
      observationDigest: DIGEST_B,
    }), { now: '2026-07-26T14:10:00.000Z', existingControllerAbsent: false });
    assert.throws(
      () => store.acquireLease(lease({
        leaseId: 'route-lease-b',
        resourceType: 'ROUTE',
        resourceId: 'route-a',
        ownerPrincipal: 'other-owner',
        observationDigest: DIGEST_C,
      }), { now: '2026-07-26T14:10:00.000Z', existingControllerAbsent: true }),
      code('release_controller_conflict'),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('expired lease takeover requires positive stale-controller absence', () => {
  const root = tempRoot();
  try {
    const store = new ReleaseApplianceStore(root);
    store.acquireLease(lease({ expiresAt: '2026-07-26T14:05:00.000Z' }), {
      now: '2026-07-26T14:00:00.000Z',
      existingControllerAbsent: false,
    });
    const replacement = lease({
      leaseId: 'lease-replacement',
      ownerPrincipal: 'replacement-owner',
      acquiredAt: '2026-07-26T14:10:00.000Z',
      expiresAt: '2026-07-26T15:10:00.000Z',
      observationDigest: DIGEST_B,
    });
    assert.throws(
      () => store.acquireLease(replacement, { now: '2026-07-26T14:10:00.000Z', existingControllerAbsent: false }),
      code('release_stale_controller_unproven'),
    );
    const acquired = store.acquireLease(replacement, {
      now: '2026-07-26T14:10:00.000Z',
      currentBootId: 'boot-b',
      existingControllerAbsent: true,
    });
    assert.equal(acquired.leaseId, 'lease-replacement');
    assert.equal(store.getLease('DEPLOYMENT', 'deployment-a').ownerPrincipal, 'replacement-owner');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('response-loss ambiguity blocks recovery until positive readback', () => {
  const root = tempRoot();
  try {
    let interrupted = false;
    const store = new ReleaseApplianceStore(root, {
      faultInjector(stage) {
        if (stage === 'after_pending_write' && !interrupted) {
          interrupted = true;
          throw new Error('simulated response loss before observed external result');
        }
      },
    });
    const input = mutation(maintenanceRecord('maintenance-readback', 1), 0, 'idem-readback');
    assert.throws(() => store.applyMutation(input), /simulated response loss/u);
    const mutationId = store.listPending()[0].mutationId;
    store.markPendingReadbackRequired(mutationId, DIGEST_A);
    assert.throws(() => store.recoverPending(mutationId), code('release_ambiguous_mutation'));
    const aborted = store.resolvePendingAfterReadback(mutationId, DIGEST_B, false);
    assert.equal(aborted.state, 'ABORTED');
    assert.equal(store.hasRecord('MaintenanceRecordV1', 'maintenance-readback'), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('startup reconciliation is explicitly bounded and defers overflow', () => {
  const root = tempRoot();
  try {
    const store = new ReleaseApplianceStore(root);
    for (let index = 1; index <= 3; index += 1) {
      const id = `maintenance-bounded-${index}`;
      store.applyMutation(mutation(maintenanceRecord(id, 1), 0, `idem-bounded-${index}`));
    }
    const report = store.startupScan(2, 100);
    assert.equal(report.processedRecords, 2);
    assert.equal(report.deferredRecords, 1);
    assert.equal(report.bounded, true);
    assert.equal(report.repairedIndexes, false);
    assert.equal(store.listRecordIdentities(2).length, 2);
    assert.throws(() => store.verify(2), code('release_invalid_request'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
