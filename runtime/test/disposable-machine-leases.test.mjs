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
