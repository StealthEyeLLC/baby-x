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
