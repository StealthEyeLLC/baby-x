import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DurableTransactionStore } from '../../dist/runtime/transactions/store.js';
import { createRequest, makeRecord, mutationDetails, tempRoot } from './_transaction-fixture.mjs';

function lease(record, overrides = {}) {
  return {
    schemaVersion: '1.0.0',
    leaseId: `tl_${'a'.repeat(32)}`,
    transactionId: record.transactionId,
    ownerPrincipal: record.ownerPrincipal,
    controllerId: 'controller-a',
    hostBootId: 'boot-a',
    operation: 'babyx.transaction.reconcile',
    acquiredAt: '2026-07-25T12:00:00.000Z',
    expiresAt: '2026-07-25T12:01:00.000Z',
    renewedAt: null,
    takeoverFromLeaseId: null,
    ...overrides,
  };
}

test('creation is idempotent and conflicting idempotency-key reuse is rejected', (t) => {
  const root = tempRoot(t, 'baby-x-transaction-store-');
  const store = new DurableTransactionStore(root);
  const first = store.create(makeRecord(), mutationDetails({ operation: 'babyx.transaction.create', phase: 'request' }));
  const replay = store.create(makeRecord({ transactionId: `tx_${'2'.repeat(32)}` }), mutationDetails({ operation: 'babyx.transaction.create', phase: 'request' }));
  assert.equal(replay.transactionId, first.transactionId);
  assert.throws(() => store.create(makeRecord({ transactionId: `tx_${'3'.repeat(32)}`, request: { ...makeRecord().source, repository: 'different' } }), mutationDetails()), /unsupported properties|idempotency/u);
  const conflicting = makeRecord({
    transactionId: `tx_${'3'.repeat(32)}`,
    request: createRequest({ repository: 'different/repository' }),
  });
  assert.throws(() => store.create(conflicting, mutationDetails()), /idempotency key was already used/u);
});

test('every mutation requires the exact durable sequence', (t) => {
  const root = tempRoot(t, 'baby-x-transaction-store-');
  const store = new DurableTransactionStore(root);
  const created = store.create(makeRecord(), mutationDetails());
  const updated = store.update(created.transactionId, created.lifecycle.stateSequence, mutationDetails({ occurredAt: '2026-07-25T12:00:02.000Z' }), { cleanup: { requested: true } });
  assert.equal(updated.lifecycle.stateSequence, 2);
  assert.throws(() => store.update(created.transactionId, 1, mutationDetails()), /stale_sequence|expected sequence/u);
});

test('append-only events maintain deterministic chain continuity and bounded listing', (t) => {
  const root = tempRoot(t, 'baby-x-transaction-store-');
  const store = new DurableTransactionStore(root);
  let record = store.create(makeRecord(), mutationDetails({ operation: 'babyx.transaction.create', phase: 'request' }));
  record = store.transition(record.transactionId, record.lifecycle.stateSequence, 'CHECKPOINTING', mutationDetails({ occurredAt: '2026-07-25T12:00:02.000Z' }));
  record = store.transition(record.transactionId, record.lifecycle.stateSequence, 'READY', mutationDetails({ occurredAt: '2026-07-25T12:00:03.000Z' }));
  const all = store.events(record.transactionId, 0, 10);
  assert.equal(all.length, 3);
  for (let index = 1; index < all.length; index += 1) {
    assert.equal(all[index].previousEventDigest, all[index - 1].eventDigest);
    assert.equal(all[index].priorSequence, all[index - 1].nextSequence);
  }
  assert.equal(store.events(record.transactionId, 1, 1).length, 1);
  assert.throws(() => store.events(record.transactionId, 0, 1001), /out of bounds/u);
});

test('derived-index corruption is detected and reconstructed from authoritative records only', (t) => {
  const root = tempRoot(t, 'baby-x-transaction-store-');
  const store = new DurableTransactionStore(root);
  const record = store.create(makeRecord(), mutationDetails());
  const recordPath = join(root, 'records', `${record.transactionId}.json`);
  const before = readFileSync(recordPath, 'utf8');
  writeFileSync(join(root, 'indexes', 'owner.json'), '{}\n', 'utf8');
  assert.equal(store.verifyIndexes().valid, false);
  const startup = store.initialize();
  assert.equal(startup.repairedIndexes, true);
  assert.equal(startup.indexes.valid, true);
  assert.equal(readFileSync(recordPath, 'utf8'), before);
});

test('authoritative-record corruption is isolated per record', (t) => {
  const root = tempRoot(t, 'baby-x-transaction-store-');
  const store = new DurableTransactionStore(root);
  const first = store.create(makeRecord(), mutationDetails());
  const second = store.create(makeRecord({ ownerPrincipal: 'owner-b', idempotencyKey: 'create-key-0002', transactionId: `tx_${'2'.repeat(32)}` }), mutationDetails({ idempotencyKey: 'create-key-0002' }));
  writeFileSync(join(root, 'records', `${first.transactionId}.json`), '{"corrupt":true}\n', 'utf8');
  const scan = store.scan(10);
  assert.deepEqual(scan.records.map((record) => record.transactionId), [second.transactionId]);
  assert.equal(scan.corrupt.length, 1);
  assert.throws(() => store.get(first.transactionId), /authoritative transaction record is corrupt/u);
});

test('failed durable write leaves recoverable intent and does not poison derived indexes', (t) => {
  const root = tempRoot(t, 'baby-x-transaction-store-');
  let failRecordOnce = true;
  const store = new DurableTransactionStore(root, {
    beforeWrite(kind) {
      if (kind === 'record' && failRecordOnce) {
        failRecordOnce = false;
        throw new Error('simulated record write failure');
      }
    },
  });
  const record = makeRecord();
  assert.throws(() => store.create(record, mutationDetails()), /simulated record write failure/u);
  assert.equal(readdirSync(join(root, 'pending')).length, 1);
  assert.throws(() => store.get(record.transactionId), /not found/u);
  const startup = store.initialize();
  assert.equal(startup.recoveredPending, 1);
  assert.equal(startup.indexes.valid, true);
  assert.equal(store.get(record.transactionId).transactionId, record.transactionId);
});

test('live lease overlap is rejected', (t) => {
  const root = tempRoot(t, 'baby-x-transaction-store-');
  const store = new DurableTransactionStore(root);
  const record = store.create(makeRecord(), mutationDetails());
  store.acquireLease(lease(record), { observedAt: '2026-07-25T12:00:10.000Z', currentControllerAbsent: true });
  assert.throws(() => store.acquireLease(lease(record, { leaseId: `tl_${'b'.repeat(32)}`, controllerId: 'controller-b' }), { observedAt: '2026-07-25T12:00:30.000Z', currentControllerAbsent: true }), /live transaction controller lease/u);
});

test('stale lease takeover requires positive controller absence proof', (t) => {
  const root = tempRoot(t, 'baby-x-transaction-store-');
  const store = new DurableTransactionStore(root);
  const record = store.create(makeRecord(), mutationDetails());
  const first = store.acquireLease(lease(record), { observedAt: '2026-07-25T12:00:10.000Z', currentControllerAbsent: true });
  const replacement = lease(record, { leaseId: `tl_${'b'.repeat(32)}`, controllerId: 'controller-b', hostBootId: 'boot-b', acquiredAt: '2026-07-25T12:02:00.000Z', expiresAt: '2026-07-25T12:03:00.000Z' });
  assert.throws(() => store.acquireLease(replacement, { observedAt: '2026-07-25T12:02:00.000Z', currentControllerAbsent: false }), /positive controller absence proof/u);
  const taken = store.acquireLease(replacement, { observedAt: '2026-07-25T12:02:00.000Z', currentControllerAbsent: true });
  assert.equal(taken.takeoverFromLeaseId, first.leaseId);
});

test('leases renew and release only under exact controller identity', (t) => {
  const root = tempRoot(t, 'baby-x-transaction-store-');
  const store = new DurableTransactionStore(root);
  const record = store.create(makeRecord(), mutationDetails());
  const acquired = store.acquireLease(lease(record), { observedAt: '2026-07-25T12:00:10.000Z', currentControllerAbsent: true });
  const renewed = store.renewLease(record.transactionId, acquired.leaseId, record.ownerPrincipal, 'controller-a', 'boot-a', '2026-07-25T12:00:30.000Z', '2026-07-25T12:02:00.000Z');
  assert.equal(renewed.renewedAt, '2026-07-25T12:00:30.000Z');
  assert.throws(() => store.releaseLease(record.transactionId, acquired.leaseId, record.ownerPrincipal, 'controller-b'), /lease release identity/u);
  assert.equal(store.releaseLease(record.transactionId, acquired.leaseId, record.ownerPrincipal, 'controller-a'), true);
  assert.equal(store.activeLease(record.transactionId), null);
});

test('startup index verification is bounded and preserves corrupt-record evidence', (t) => {
  const root = tempRoot(t, 'baby-x-transaction-store-');
  const store = new DurableTransactionStore(root);
  const record = store.create(makeRecord(), mutationDetails());
  writeFileSync(join(root, 'records', `${record.transactionId}.json`), 'not-json\n', 'utf8');
  const startup = store.initialize();
  assert.equal(startup.corruptRecords.length, 1);
  assert.equal(startup.indexes.valid, true);
  assert.equal(startup.indexes.recordCount, 0);
});
