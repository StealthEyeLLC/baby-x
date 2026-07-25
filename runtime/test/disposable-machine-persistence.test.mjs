import {
  test,
  assert,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
  join,
  MachineServiceError,
  MACHINE_SCHEMA_VERSION,
  assertDisposableMachineRecord,
  canonicalMachineEvidence,
  canonicalMachineRequestDigest,
  createMachineEvent,
  assertMachineTransition,
  canTransitionMachineState,
  DisposableMachineStore,
  NOW,
  LATER,
  MUCH_LATER,
  makeRecord,
  temporaryStore,
  creationEvent,
  transitionEvent,
  assertMachineError,
} from './_disposable-machine-store-fixture.mjs';

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
