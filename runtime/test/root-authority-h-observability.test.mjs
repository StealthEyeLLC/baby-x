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
function startPayload(overrides = {}) {
  return { transactionId, stepId: 'step-1', requiredKinds: ['PROCESS', 'FILESYSTEM'], requiredSources: ['EBPF'], fallbackSources: ['BOUNDED_LOG'], maxEvents: 4, maxBytes: 65_536, maxDurationMs: 60_000, ...overrides };
}

test('H: durable observation sessions are idempotent, correlated, redacted, bounded, and artifact-backed', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-h-observe-'));
  let now = '2026-07-28T14:00:00.000Z';
  const spills = [];
  const artifacts = { async spill(name, value, metadata) { spills.push({ name, value, metadata }); return { artifactId: `artifact-${spills.length}` }; } };
  try {
    const service = new RootObservationService(root, artifacts, { now: () => now });
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
    assert.throws(() => service.record({ sessionId, transactionId, stepId: 'step-1', kind: 'FILESYSTEM', source: 'BOUNDED_LOG', data: { path: '/safe' } }, context('observe-record-0002', 'owner-b')), (error) => error.code === 'principal_mismatch');
    service.record({ sessionId, transactionId, stepId: 'step-1', kind: 'FILESYSTEM', source: 'BOUNDED_LOG', data: { path: '/safe', token: 'must-not-leak' } }, context('observe-record-0003'));
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
    assert.equal((await service.finalize({ sessionId, sourceStatus: { EBPF: 'UNAVAILABLE', BOUNDED_LOG: 'AVAILABLE' }, spill: true }, context('observe-finalize-replay'))).replayed, true);
    const page = service.get({ sessionId, offset: 0, limit: 1 });
    assert.equal(page.session.events.length, 1);
    assert.equal(page.total, 2);
    assert.equal(page.nextOffset, 1);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('H: observation limits fail closed without losing durable overflow truth', () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-h-bounds-'));
  let now = '2026-07-28T14:00:00.000Z';
  try {
    const service = new RootObservationService(root, undefined, { now: () => now });
    const started = service.start(startPayload({ requiredKinds: ['PROCESS'], requiredSources: ['PROC'], fallbackSources: [], maxEvents: 1, maxDurationMs: 1_000 }), context('observe-bound-start'));
    const sessionId = started.session.sessionId;
    assert.equal(service.record({ sessionId, transactionId, stepId: 'step-1', kind: 'PROCESS', source: 'PROC', data: { pid: 1 } }, context('observe-bound-record')).accepted, true);
    assert.equal(service.record({ sessionId, transactionId, stepId: 'step-1', kind: 'PROCESS', source: 'PROC', data: { pid: 2 } }, context('observe-bound-over')).dropped, true);
    const overflowed = service.get({ sessionId }).session;
    assert.equal(overflowed.overflow, true);
    assert.equal(overflowed.droppedEvents, 1);
    now = '2026-07-28T14:00:02.000Z';
    assert.equal(service.record({ sessionId, transactionId, stepId: 'step-1', kind: 'PROCESS', source: 'PROC', data: { pid: 3 } }, context('observe-after-deadline')).dropped, true);
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
