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
