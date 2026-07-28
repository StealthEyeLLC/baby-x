import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RootObservationService } from '../../dist/runtime/root-fabric/observability.js';
import { OPERATION_CATALOG_VERSION, OPERATION_DEFINITIONS } from '../../dist/runtime/operations/definitions.js';
import { ROOT_FABRIC_OPERATION_NAMES } from '../../dist/runtime/root-fabric/service.js';

const context = (key, subject = 'owner-a') => ({ subject, authorityClass: 'unrestricted-owner', idempotencyKey: key });
const transactionId = `rfx_${'a'.repeat(32)}`;
const binding = { transactionId, stepId: 'step-1', ownerPrincipalDigest: null, provider: 'HOST_ENVELOPE', transactionSequence: 7, fencingToken: 3, transactionDeadline: '2026-07-28T14:10:00.000Z', operationDeadline: '2026-07-28T14:01:00.000Z', executionBindingDigest: 'b'.repeat(64), unitNames: ['unit-1'], machineIds: ['machine-1'], processIdentities: [{ processId: 123, processStartTime: '55', bootId: 'boot-1', cgroupId: 'cg-1', unitName: 'unit-1' }] };
function authority(subject = 'owner-a') { return { resolve(input) { if (input.transactionId !== transactionId || input.stepId !== 'step-1') { const error = new Error('transaction or step unavailable'); error.code = 'transaction_not_found'; throw error; } return { ...binding, ownerPrincipalDigest: input.principalDigest }; }, assertEvent(_binding, event) { if (event.processId !== null && event.processId !== 123) { const error = new Error('process mismatch'); error.code = 'process_identity_conflict'; throw error; } } }; }
function startPayload(overrides = {}) {
  return { transactionId, stepId: 'step-1', requiredKinds: ['PROCESS', 'FILESYSTEM'], requiredSources: ['EBPF'], fallbackSources: ['BOUNDED_LOG'], maxEvents: 4, maxBytes: 65_536, maxDurationMs: 60_000, ...overrides };
}

test('H: durable observation sessions are idempotent, correlated, redacted, bounded, and artifact-backed', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-h-observe-'));
  let now = '2026-07-28T14:00:00.000Z';
  const spills = [];
  const artifacts = { async spill(name, value, metadata) { spills.push({ name, value, metadata }); return { artifactId: `artifact-${spills.length}` }; } };
  try {
    const service = new RootObservationService(root, artifacts, { now: () => now, authority: authority() });
    const first = service.start(startPayload(), context('observe-start-0001'));
    assert.equal(first.replayed, false);
    const sessionId = first.session.sessionId;
    assert.match(sessionId, /^obs_[a-f0-9]{32}$/u);
    assert.equal(service.start(startPayload(), context('observe-start-0001')).replayed, true);
    assert.throws(() => service.start(startPayload({ maxEvents: 5 }), context('observe-start-0001')), (error) => error.code === 'idempotency_conflict');
    const accepted = service.record({ sessionId, transactionId, stepId: 'step-1', kind: 'PROCESS', source: 'BOUNDED_LOG', occurredAt: now, cgroupId: 'cg-1', unitName: 'unit-1', machineId: 'machine-1', processId: 123, processStartTime: '55', bootId: 'boot-1', data: { command: 'safe', authorization: 'Bearer super-secret', nested: { password: 'hidden' } } }, context('observe-record-0001'));
    assert.equal(accepted.accepted, true);
    assert.equal(accepted.event.data.authorization, '[REDACTED]');
    assert.equal(accepted.event.data.nested.password, '[REDACTED]');
    assert.match(accepted.event.eventDigest, /^[a-f0-9]{64}$/u);
    assert.equal(accepted.event.previousEventDigest, null);
    assert.equal(service.record({ sessionId, transactionId, stepId: 'step-1', kind: 'PROCESS', source: 'BOUNDED_LOG', occurredAt: now, cgroupId: 'cg-1', unitName: 'unit-1', machineId: 'machine-1', processId: 123, processStartTime: '55', bootId: 'boot-1', data: { command: 'safe', authorization: 'Bearer super-secret', nested: { password: 'hidden' } } }, context('observe-record-0001')).replayed, true);
    assert.throws(() => service.record({ sessionId, transactionId, stepId: 'step-1', kind: 'FILESYSTEM', source: 'BOUNDED_LOG', data: { path: '/safe' } }, context('observe-record-0002', 'owner-b')), (error) => error.code === 'principal_mismatch');
    const second = service.record({ sessionId, transactionId, stepId: 'step-1', kind: 'FILESYSTEM', source: 'BOUNDED_LOG', data: { path: '/safe', token: 'must-not-leak' } }, context('observe-record-0003'));
    assert.equal(second.event.previousEventDigest, accepted.event.eventDigest);
    now = '2026-07-28T14:00:05.000Z';
    const finalized = await service.finalize({ sessionId, sourceStatus: { EBPF: 'UNAVAILABLE', BOUNDED_LOG: 'AVAILABLE' }, spill: true }, context('observe-finalize-0001'));
    assert.equal(finalized.replayed, false);
    assert.equal(finalized.session.state, 'FINALIZED');
    assert.equal(finalized.session.completeness, 'DEGRADED');
    assert.deepEqual(finalized.session.artifactIds, ['artifact-1']);
    assert.match(finalized.session.summaryDigest, /^[a-f0-9]{64}$/u);
    assert.equal(spills.length, 1);
    assert.equal(JSON.stringify(spills[0]).includes('super-secret'), false);
    assert.equal(JSON.stringify(spills[0]).includes('must-not-leak'), false);
    assert.equal((await service.finalize({ sessionId, sourceStatus: { EBPF: 'UNAVAILABLE', BOUNDED_LOG: 'AVAILABLE' }, spill: true }, context('observe-finalize-0001'))).replayed, true);
    const page = service.get({ sessionId, offset: 0, limit: 1 }, context('observe-get-0001'));
    assert.equal(page.session.events.length, 1);
    assert.equal(page.total, 2);
    assert.equal(page.nextOffset, 1);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('H: observation limits fail closed without losing durable overflow truth', () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-h-bounds-'));
  let now = '2026-07-28T14:00:00.000Z';
  try {
    const service = new RootObservationService(root, undefined, { now: () => now, authority: authority() });
    const started = service.start(startPayload({ requiredKinds: ['PROCESS'], requiredSources: ['PROC'], fallbackSources: [], maxEvents: 1, maxDurationMs: 1_000 }), context('observe-bound-start'));
    const sessionId = started.session.sessionId;
    assert.equal(service.record({ sessionId, transactionId, stepId: 'step-1', kind: 'PROCESS', source: 'PROC', data: { pid: 1 } }, context('observe-bound-record')).accepted, true);
    const droppedPayload = { sessionId, transactionId, stepId: 'step-1', kind: 'PROCESS', source: 'PROC', data: { pid: 2 } };
    assert.equal(service.record(droppedPayload, context('observe-bound-over')).dropped, true);
    const droppedReplay = service.record(droppedPayload, context('observe-bound-over'));
    assert.equal(droppedReplay.replayed, true);
    assert.equal(droppedReplay.accepted, false);
    assert.equal(droppedReplay.dropped, true);
    assert.equal(droppedReplay.reason, 'event_limit');
    const overflowed = service.get({ sessionId }, context('observe-get-bound')).session;
    assert.equal(overflowed.overflow, true);
    assert.equal(overflowed.droppedEvents, 1);
    now = '2026-07-28T14:00:02.000Z';
    assert.equal(service.record({ sessionId, transactionId, stepId: 'step-1', kind: 'PROCESS', source: 'PROC', data: { pid: 3 } }, context('observe-after-deadline')).dropped, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('H repair: invented transactions and steps fail, metadata secrets never persist, and event identity is authoritative', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-h-adversarial-'));
  try {
    const service = new RootObservationService(root, undefined, { now: () => '2026-07-28T14:00:00.000Z', authority: authority() });
    assert.throws(() => service.start(startPayload({ transactionId: `rfx_${'f'.repeat(32)}` }), context('invented-transaction')), (error) => error.code === 'transaction_not_found');
    assert.throws(() => service.start(startPayload({ stepId: 'invented-step' }), context('invented-step-key')), (error) => error.code === 'transaction_not_found');
    const started = service.start(startPayload({ requiredKinds: ['PROCESS'], requiredSources: ['PROC'] }), context('adversarial-start'));
    assert.throws(() => service.record({ sessionId: started.session.sessionId, transactionId, stepId: 'step-1', kind: 'PROCESS', source: 'PROC', processId: 999, data: {} }, context('wrong-process')), (error) => error.code === 'process_identity_conflict');
    service.record({ sessionId: started.session.sessionId, transactionId, stepId: 'step-1', kind: 'PROCESS', source: 'PROC', processId: 123, processStartTime: '55', bootId: 'boot-1', cgroupId: 'cg-1', data: {} }, context('right-process'));
    await assert.rejects(service.finalize({ sessionId: started.session.sessionId, sourceStatus: { PROC: 'Bearer secret-secret-secret-secret-secret' }, spill: false }, context('metadata-leak')), (error) => error.code === 'invalid_request');
    const finalized = await service.finalize({ sessionId: started.session.sessionId, sourceStatus: { PROC: 'AVAILABLE' }, spill: false }, context('metadata-safe'));
    assert.equal(JSON.stringify(finalized).includes('secret-secret'), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('H: catalog exposes one schema-backed observation surface while preserving A-G', () => {
  assert.equal(OPERATION_CATALOG_VERSION, '3.4.0');
  assert.equal(OPERATION_DEFINITIONS.length, 230);
  const root = OPERATION_DEFINITIONS.filter((entry) => entry.operation.startsWith('babyx.root.'));
  assert.equal(root.length, 51);
  const expected = ['babyx.root.observation.start', 'babyx.root.observation.get', 'babyx.root.observation.record', 'babyx.root.observation.finalize'];
  for (const operation of expected) {
    assert.equal(ROOT_FABRIC_OPERATION_NAMES.filter((name) => name === operation).length, 1);
    const definition = OPERATION_DEFINITIONS.find((entry) => entry.operation === operation);
    assert.ok(definition);
    assert.equal(definition.input.additionalProperties, false);
  }
  assert.equal(new Set(OPERATION_DEFINITIONS.map((entry) => entry.operation)).size, OPERATION_DEFINITIONS.length);
});
