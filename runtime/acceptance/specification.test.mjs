import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime } from '../../dist/runtime/core.js';

test('retro-specification keeps observations distinct from owner declarations', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-spec-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const fact = await runtime.execute('babyx.spec.scan', { subject: 'sample', predicate: 'port', value: 8080, source: 'systemd-unit' });
    const observed = await runtime.execute('babyx.spec.observe', { subject: 'sample', predicate: 'response-type', value: 'json', source: 'trace' });
    const hypothesis = await runtime.execute('babyx.spec.generate', { subject: 'sample', predicate: 'nullable', value: false });
    assert.equal(fact.classification, 'static-fact');
    assert.equal(observed.classification, 'observed-invariant');
    assert.equal(hypothesis.classification, 'hypothesis');
    const falsified = await runtime.execute('babyx.spec.falsify', { id: hypothesis.id, counterexamples: ['contradictory-observation'] });
    assert.equal(falsified.classification, 'falsified-hypothesis');
    assert.notEqual(falsified.classification, 'declared-requirement');
    assert.ok(Array.isArray(falsified.provenance));
  } finally { rmSync(root, { recursive: true, force: true }); }
});
