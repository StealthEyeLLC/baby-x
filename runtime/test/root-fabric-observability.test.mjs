import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RootObservationService } from '../../dist/runtime/root-fabric/observability.js';

const context = (key) => ({ subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner', idempotencyKey: `test-${key}` });

test('H observations correlate, redact, bound, spill, and classify completeness', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-observe-'));
  try {
    const spilled = [];
    const service = new RootObservationService(root, { spill: async (name, value, metadata) => { spilled.push({ name, value, metadata }); return { artifactId: 'artifact-observation' }; } });
    const started = service.start({ transactionId: 'rfx_observation', stepId: 'step-1', requiredKinds: ['PROCESS', 'FILESYSTEM'], requiredSources: ['SYSTEMD'], fallbackSources: ['TARGET_READBACK'], maxEvents: 4, maxBytes: 65_536, maxDurationMs: 60_000 }, context('obs-start')).session;
    service.record({ sessionId: started.sessionId, transactionId: 'rfx_observation', stepId: 'step-1', kind: 'PROCESS', source: 'SYSTEMD', unitName: 'babyx-root-test.service', processId: 123, processStartTime: '456', bootId: 'boot-test', data: { action: 'exec', token: 'super-secret-token-value-12345678901234567890' } }, context('obs-record-1'));
    service.record({ sessionId: started.sessionId, transactionId: 'rfx_observation', stepId: 'step-1', kind: 'FILESYSTEM', source: 'TARGET_READBACK', data: { path: '/tmp/x', sha256: 'a'.repeat(64) } }, context('obs-record-2'));
    assert.throws(() => service.record({ sessionId: started.sessionId, transactionId: 'wrong', stepId: 'step-1', kind: 'PROCESS', source: 'SYSTEMD', data: {} }, context('obs-wrong')), /correlation/u);
    const finalized = await service.finalize({ sessionId: started.sessionId, sourceStatus: { SYSTEMD: 'AVAILABLE', TARGET_READBACK: 'AVAILABLE' }, spill: true }, context('obs-finalize'));
    assert.equal(finalized.session.completeness, 'COMPLETE');
    assert.equal(finalized.session.artifactIds[0], 'artifact-observation');
    assert.equal(spilled.length, 1);
    assert.equal(finalized.session.events[0].data.token, '[REDACTED]');

    const bounded = service.start({ transactionId: 'rfx_bounded', stepId: 'step-2', requiredKinds: ['PROCESS'], requiredSources: ['EBPF'], fallbackSources: ['PROC'], maxEvents: 1, maxBytes: 65_536, maxDurationMs: 60_000 }, context('obs-bounded')).session;
    service.record({ sessionId: bounded.sessionId, transactionId: 'rfx_bounded', stepId: 'step-2', kind: 'PROCESS', source: 'PROC', data: { action: 'readback' } }, context('obs-bounded-1'));
    const dropped = service.record({ sessionId: bounded.sessionId, transactionId: 'rfx_bounded', stepId: 'step-2', kind: 'PROCESS', source: 'PROC', data: { action: 'overflow' } }, context('obs-bounded-2'));
    assert.equal(dropped.dropped, true);
    const degraded = await service.finalize({ sessionId: bounded.sessionId, sourceStatus: { EBPF: 'UNAVAILABLE', PROC: 'AVAILABLE' }, spill: false }, context('obs-bounded-final'));
    assert.equal(degraded.session.completeness, 'PARTIAL');
    const reloaded = new RootObservationService(root);
    assert.equal(reloaded.get({ sessionId: started.sessionId }).session.summaryDigest, finalized.session.summaryDigest);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
