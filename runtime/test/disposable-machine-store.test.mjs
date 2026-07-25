import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MachineServiceError } from '../../dist/runtime/machines/errors.js';
import {
  MACHINE_SCHEMA_VERSION,
  assertDisposableMachineRecord,
  canonicalMachineEvidence,
  canonicalMachineRequestDigest,
  createMachineEvent,
} from '../../dist/runtime/machines/schemas.js';
import {
  assertMachineTransition,
  canTransitionMachineState,
} from '../../dist/runtime/machines/states.js';
import { DisposableMachineStore } from '../../dist/runtime/machines/store.js';

const NOW = '2026-07-25T10:00:00.000Z';
const LATER = '2026-07-25T10:01:00.000Z';
const MUCH_LATER = '2026-07-25T11:00:00.000Z';
const HOST_SHA = '1'.repeat(64);

function makeRecord(overrides = {}) {
  const machineId = overrides.machineId ?? 'mx_machine0001';
  const machineName = overrides.machineName ?? 'machine-1';
  const cloneDataset = overrides.cloneDataset ?? `pool/runs/${machineName}`;
  const mountpoint = overrides.mountpoint ?? `/var/lib/baby-x/machines/${machineName}`;
  const idempotencyKey = overrides.idempotencyKey ?? 'create-machine-1';
  const requestDigest = overrides.requestDigest ?? canonicalMachineRequestDigest({
    sourceSnapshot: 'pool/base@golden-v1',
    machineName,
    cloneDataset,
    mountpoint,
    launch: { boot: true, networkMode: 'none' },
  });
  return {
    schemaVersion: MACHINE_SCHEMA_VERSION,
    machineId,
    machineName,
    providerId: 'zfs-nspawn-disposable@1',
    ownerPrincipal: 'owner:test',
    creationIdempotencyKey: idempotencyKey,
    creationRequestDigest: requestDigest,
    source: {
      kind: 'zfs-snapshot',
      snapshot: 'pool/base@golden-v1',
      dataset: 'pool/base',
      snapshotGuid: '111222333',
      creationTxg: '444555',
      observedAt: NOW,
    },
    clone: {
      dataset: cloneDataset,
      mountpoint,
      expectedRootPrefix: '/var/lib/baby-x/machines',
      ownershipMarker: `baby-x:${machineId}`,
    },
    launch: {
      boot: true,
      networkMode: 'none',
      readOnlyRoot: false,
      binds: [],
      environment: [
        { name: 'VISIBLE', value: 'safe', redacted: false },
        { name: 'TOKEN', value: 'do-not-persist-in-evidence', redacted: true },
      ],
      properties: [],
      normalizedDigest: canonicalMachineRequestDigest({ boot: true, networkMode: 'none' }),
    },
    lifecycle: {
      desiredState: 'READY',
      persistedState: 'REQUESTED',
      observedState: 'NOT_OBSERVED',
      stateSequence: 1,
      terminal: false,
      createdAt: NOW,
      updatedAt: NOW,
    },
    host: {
      hostname: 'test-host',
      machineIdSha256: HOST_SHA,
      bootIdAtCreate: 'boot-1',
    },
    observations: {
      dataset: 'unknown',
      snapshot: 'unknown',
      mountpoint: 'unknown',
      machinectl: 'unknown',
      process: 'unknown',
      rootPath: 'unknown',
    },
    activeJobIds: [],
    protectedJobIds: [],
    artifactIds: [],
    proofReferences: [],
    cleanup: {
      requested: false,
      stopAttempted: false,
      stopVerified: false,
      datasetDestroyAttempted: false,
      datasetAbsentVerified: false,
      rootAbsentVerified: false,
      machineAbsentVerified: false,
      processAbsentVerified: false,
      completed: false,
      retainedEvidence: [],
    },
  };
}

function temporaryStore(t) {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-machine-store-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { root, store: new DisposableMachineStore(root) };
}

function creationEvent(record) {
  return {
    operation: 'babyx.machine.create',
    phase: 'request',
    kind: 'machine.requested',
    message: 'machine request persisted',
    requestDigest: record.creationRequestDigest,
    idempotencyKey: record.creationIdempotencyKey,
    occurredAt: NOW,
  };
}

function transitionEvent(operation, phase, kind, message, occurredAt = LATER) {
  return { operation, phase, kind, message, occurredAt };
}

function assertMachineError(code) {
  return (error) => error instanceof MachineServiceError && error.code === code;
}

test('canonical machine evidence is deterministic and redacts secret material', () => {
  const left = {
    z: 1,
    environment: [
      { name: 'TOKEN', value: 'secret-value', redacted: true },
      { name: 'SAFE', value: 'visible', redacted: false },
      { name: 'REFERENCE', secretReference: 'vault:item', redacted: true },
    ],
  };
  const right = { environment: left.environment, z: 1 };
  const evidence = canonicalMachineEvidence(left);
  assert.equal(evidence, canonicalMachineEvidence(right));
  assert.equal(canonicalMachineRequestDigest(left), canonicalMachineRequestDigest(right));
  assert.doesNotMatch(evidence, /secret-value/);
  assert.match(evidence, /\[REDACTED\]/);
  assert.match(evidence, /visible/);
});

test('canonical machine event digest is stable across equivalent drafts', () => {
  const draft = {
    schemaVersion: MACHINE_SCHEMA_VERSION,
    machineId: 'mx_machine0001',
    offset: 0,
    stateSequence: 1,
    nextState: 'REQUESTED',
    desiredState: 'READY',
    operation: 'babyx.machine.create',
    phase: 'request',
    kind: 'machine.requested',
    message: 'machine request persisted',
    requestDigest: 'a'.repeat(64),
    occurredAt: NOW,
  };
  const first = createMachineEvent(draft);
  const second = createMachineEvent({ message: draft.message, ...draft });
  assert.equal(first.eventDigest, second.eventDigest);
  assert.deepEqual(first, second);
});

test('record schema rejects unsafe identity, source, path, version, and fabricated destruction truth', () => {
  assert.doesNotThrow(() => assertDisposableMachineRecord(makeRecord()));

  const unsafeDataset = makeRecord();
  unsafeDataset.clone.dataset = '--destroy-all';
  assert.throws(() => assertDisposableMachineRecord(unsafeDataset), assertMachineError('machine_invalid_request'));

  const relativeRoot = makeRecord();
  relativeRoot.clone.mountpoint = 'relative/root';
  assert.throws(() => assertDisposableMachineRecord(relativeRoot), assertMachineError('machine_invalid_request'));

  const mismatchedSource = makeRecord();
  mismatchedSource.source.dataset = 'pool/other';
  assert.throws(() => assertDisposableMachineRecord(mismatchedSource), assertMachineError('machine_invalid_request'));

  const malformedSnapshot = makeRecord();
  malformedSnapshot.source.snapshot = 'pool/base@golden@extra';
  assert.throws(() => assertDisposableMachineRecord(malformedSnapshot), assertMachineError('machine_invalid_request'));

  const sourceAsClone = makeRecord();
  sourceAsClone.clone.dataset = sourceAsClone.source.dataset;
  assert.throws(() => assertDisposableMachineRecord(sourceAsClone), assertMachineError('machine_invalid_request'));

  const rootItself = makeRecord();
  rootItself.clone.mountpoint = rootItself.clone.expectedRootPrefix;
  assert.throws(() => assertDisposableMachineRecord(rootItself), assertMachineError('machine_invalid_request'));

  const unsupportedMajor = makeRecord();
  unsupportedMajor.schemaVersion = '2.0.0';
  assert.throws(() => assertDisposableMachineRecord(unsupportedMajor), assertMachineError('machine_invalid_request'));

  const fabricatedDestroyed = makeRecord();
  fabricatedDestroyed.lifecycle = {
    ...fabricatedDestroyed.lifecycle,
    desiredState: 'DESTROYED',
    persistedState: 'DESTROYED',
    observedState: 'ABSENT',
    terminal: true,
    destroyedAt: LATER,
  };
  assert.throws(() => assertDisposableMachineRecord(fabricatedDestroyed), assertMachineError('machine_invalid_request'));
});

test('state machine enforces normal transitions, exceptional truth, and optimistic sequence checks', () => {
  assert.equal(canTransitionMachineState(undefined, 'REQUESTED'), true);
  assert.equal(canTransitionMachineState('REQUESTED', 'CLONING'), true);
  assert.equal(canTransitionMachineState('REQUESTED', 'READY'), false);
  assert.equal(canTransitionMachineState('STARTING', 'AMBIGUOUS'), true);
  assert.equal(canTransitionMachineState('DESTROYED', 'UNKNOWN'), false);
  assert.equal(assertMachineTransition('REQUESTED', 'CLONING', 1, 1), 2);
  assert.throws(() => assertMachineTransition('REQUESTED', 'CLONING', 2, 1), assertMachineError('machine_sequence_conflict'));
  assert.throws(() => assertMachineTransition('REQUESTED', 'READY', 1, 1), assertMachineError('machine_state_conflict'));
});

test('durable store provides creation replay, conflict detection, restart verification, and bounded events', (t) => {
  const { root, store } = temporaryStore(t);
  const record = makeRecord();
  const created = store.create(record, creationEvent(record));
  assert.equal(created.machineId, record.machineId);
  assert.equal(store.getByName(record.machineName).machineId, record.machineId);

  const replay = store.create(makeRecord({ machineId: 'mx_machine9999' }), creationEvent(record));
  assert.equal(replay.machineId, record.machineId);
  assert.equal(store.list().length, 1);

  const conflictingRequest = makeRecord({ machineId: 'mx_machine0002', requestDigest: '2'.repeat(64) });
  assert.throws(() => store.create(conflictingRequest, creationEvent(conflictingRequest)), assertMachineError('machine_idempotency_conflict'));

  const duplicateName = makeRecord({ machineId: 'mx_machine0003', idempotencyKey: 'different-key', requestDigest: '3'.repeat(64) });
  assert.throws(() => store.create(duplicateName, creationEvent(duplicateName)), assertMachineError('machine_name_conflict'));

  const cloning = store.transition(record.machineId, 1, 'CLONING', 'READY', transitionEvent('babyx.machine.create', 'clone', 'machine.cloning', 'clone phase started'));
  assert.equal(cloning.lifecycle.stateSequence, 2);
  const cloned = store.transition(record.machineId, 2, 'CLONED', 'READY', transitionEvent('babyx.machine.create', 'clone-readback', 'machine.cloned', 'clone identity verified', MUCH_LATER));
  assert.equal(cloned.lifecycle.stateSequence, 3);
  assert.throws(() => store.transition(record.machineId, 2, 'STARTING', 'READY', transitionEvent('babyx.machine.start', 'start', 'machine.starting', 'stale mutation')), assertMachineError('machine_sequence_conflict'));

  const page = store.events(record.machineId, 1, 1);
  assert.equal(page.length, 1);
  assert.equal(page[0].offset, 1);
  assert.equal(store.events(record.machineId, 0, 100).length, 3);
  assert.throws(() => store.events(record.machineId, 0, 1_001), assertMachineError('machine_invalid_request'));

  const restarted = new DisposableMachineStore(root);
  assert.equal(restarted.get(record.machineId).lifecycle.persistedState, 'CLONED');
  assert.deepEqual(restarted.verify(), { valid: true, records: 1, events: 3, tombstones: 0, indexesMatch: true });
});

test('creation write failure does not poison reconstructable indexes or idempotency', (t) => {
  const { root, store } = temporaryStore(t);
  const record = makeRecord();
  const blockedEventPath = join(root, 'events', `${record.machineId}.jsonl`);
  mkdirSync(blockedEventPath);

  assert.throws(() => store.create(record, creationEvent(record)));
  assert.equal(store.list().length, 0);
  assert.throws(() => store.getByName(record.machineName), assertMachineError('machine_not_found'));
  assert.equal(existsSync(join(root, 'indexes.json')), false);
  assert.equal(existsSync(join(root, 'idempotency.json')), false);

  rmSync(blockedEventPath, { recursive: true });
  assert.equal(store.create(record, creationEvent(record)).machineId, record.machineId);
  assert.deepEqual(store.verify(), { valid: true, records: 1, events: 1, tombstones: 0, indexesMatch: true });
});

test('derived indexes can be detected as corrupt and rebuilt from authoritative records', (t) => {
  const { root, store } = temporaryStore(t);
  const record = makeRecord();
  store.create(record, creationEvent(record));
  writeFileSync(join(root, 'indexes.json'), '{"byDataset":{},"byName":{},"byRoot":{},"byState":{}}\n');

  assert.throws(() => store.verify(), assertMachineError('machine_index_corrupt'));
  store.rebuildIndexes(true);
  assert.equal(store.getByName(record.machineName).machineId, record.machineId);
  assert.deepEqual(store.verify(), { valid: true, records: 1, events: 1, tombstones: 0, indexesMatch: true });
});

test('store independently reserves dataset and root ownership', (t) => {
  const { store } = temporaryStore(t);
  const first = makeRecord();
  store.create(first, creationEvent(first));

  const datasetConflict = makeRecord({
    machineId: 'mx_machine0002',
    machineName: 'machine-2',
    idempotencyKey: 'create-machine-2',
    requestDigest: '4'.repeat(64),
    cloneDataset: first.clone.dataset,
    mountpoint: '/var/lib/baby-x/machines/machine-2',
  });
  assert.throws(() => store.create(datasetConflict, creationEvent(datasetConflict)), assertMachineError('machine_dataset_conflict'));

  const rootConflict = makeRecord({
    machineId: 'mx_machine0003',
    machineName: 'machine-3',
    idempotencyKey: 'create-machine-3',
    requestDigest: '5'.repeat(64),
    cloneDataset: 'pool/runs/machine-3',
    mountpoint: first.clone.mountpoint,
  });
  assert.throws(() => store.create(rootConflict, creationEvent(rootConflict)), assertMachineError('machine_root_conflict'));
});

test('controller leases reject live overlap, permit proven takeover, and release cleanly', (t) => {
  const { store } = temporaryStore(t);
  const first = {
    schemaVersion: MACHINE_SCHEMA_VERSION,
    leaseId: 'lease-1',
    machineId: 'mx_machine0001',
    operation: 'babyx.machine.start',
    ownerPrincipal: 'owner:test',
    requestDigest: '6'.repeat(64),
    acquiredAt: NOW,
    expiresAt: LATER,
    hostBootId: 'boot-1',
  };
  assert.equal(store.acquireLease(first, { currentBootId: 'boot-1', now: NOW }).leaseId, 'lease-1');
  assert.equal(store.acquireLease(first, { currentBootId: 'boot-1', now: NOW }).leaseId, 'lease-1');

  const overlapping = { ...first, leaseId: 'lease-2', requestDigest: '7'.repeat(64) };
  assert.throws(() => store.acquireLease(overlapping, { currentBootId: 'boot-1', existingOwnerAlive: true, now: NOW }), assertMachineError('machine_controller_conflict'));

  const takeover = {
    ...first,
    leaseId: 'lease-3',
    requestDigest: '8'.repeat(64),
    acquiredAt: MUCH_LATER,
    expiresAt: '2026-07-25T12:00:00.000Z',
    hostBootId: 'boot-2',
  };
  assert.equal(store.acquireLease(takeover, { currentBootId: 'boot-2', existingOwnerAlive: false, now: MUCH_LATER }).leaseId, 'lease-3');
  assert.throws(() => store.releaseLease(first.machineId, 'wrong-lease'), assertMachineError('machine_controller_conflict'));
  store.releaseLease(first.machineId, 'lease-3');
  assert.equal(store.getLease(first.machineId), undefined);
});

test('destruction releases live indexes only after verified cleanup and preserves a tombstone', (t) => {
  const { store } = temporaryStore(t);
  const record = makeRecord();
  store.create(record, creationEvent(record));
  store.transition(record.machineId, 1, 'CLONING', 'READY', transitionEvent('babyx.machine.create', 'clone', 'machine.cloning', 'clone phase started'));
  store.transition(record.machineId, 2, 'CLONED', 'READY', transitionEvent('babyx.machine.create', 'clone-readback', 'machine.cloned', 'clone verified'));
  store.transition(record.machineId, 3, 'DESTROYING', 'DESTROYED', transitionEvent('babyx.machine.destroy', 'destroy', 'machine.destroying', 'destroy phase started'));

  assert.throws(
    () => store.transition(record.machineId, 4, 'DESTROYED', 'DESTROYED', transitionEvent('babyx.machine.destroy', 'absence-readback', 'machine.destroyed', 'fabricated absence')),
    assertMachineError('machine_invalid_request'),
  );

  const cleanup = {
    requested: true,
    requestedAt: LATER,
    stopAttempted: true,
    stopVerified: true,
    datasetDestroyAttempted: true,
    datasetAbsentVerified: true,
    rootAbsentVerified: true,
    machineAbsentVerified: true,
    processAbsentVerified: true,
    completed: true,
    completedAt: MUCH_LATER,
    retainedEvidence: ['proof:absence:1'],
  };
  const destroyed = store.transition(
    record.machineId,
    4,
    'DESTROYED',
    'DESTROYED',
    transitionEvent('babyx.machine.destroy', 'absence-readback', 'machine.destroyed', 'all owned resources verified absent', MUCH_LATER),
    { cleanup, lifecycle: { ...store.get(record.machineId).lifecycle, observedState: 'ABSENT' } },
  );
  assert.equal(destroyed.lifecycle.terminal, true);
  assert.equal(destroyed.cleanup.completed, true);
  assert.throws(() => store.getByName(record.machineName), assertMachineError('machine_not_found'));

  const tombstone = store.createTombstone(record.machineId);
  assert.equal(tombstone.finalEventDigest, store.events(record.machineId, 0, 100).at(-1).eventDigest);
  assert.deepEqual(tombstone.cleanupEvidenceReferences, ['proof:absence:1']);
  assert.deepEqual(store.verify(), { valid: true, records: 1, events: 5, tombstones: 1, indexesMatch: true });

  const reuse = makeRecord({
    machineId: record.machineId,
    machineName: 'machine-reused',
    idempotencyKey: 'create-machine-reused',
    requestDigest: '9'.repeat(64),
    cloneDataset: 'pool/runs/machine-reused',
    mountpoint: '/var/lib/baby-x/machines/machine-reused',
  });
  assert.throws(() => store.create(reuse, creationEvent(reuse)), assertMachineError('machine_tombstone_conflict'));
});

test('event tampering and record corruption fail closed', (t) => {
  const { root, store } = temporaryStore(t);
  const record = makeRecord();
  store.create(record, creationEvent(record));

  const eventPath = join(root, 'events', `${record.machineId}.jsonl`);
  const event = JSON.parse(readFileSync(eventPath, 'utf8').trim());
  event.message = 'tampered';
  writeFileSync(eventPath, `${JSON.stringify(event)}\n`);
  assert.throws(() => store.events(record.machineId), assertMachineError('machine_event_corrupt'));

  const recordPath = join(root, 'records', `${record.machineId}.json`);
  writeFileSync(recordPath, '{not-json');
  assert.throws(() => store.get(record.machineId), assertMachineError('machine_record_corrupt'));
});
