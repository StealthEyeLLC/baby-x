import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime } from '../src/core.ts';

test('deterministic candidate-adversary-counterexample loop preserves replay assets', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-battle-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const candidate = await runtime.execute('babyx.candidate.submit', { sourceIdentity: { commit: 'bad' }, state: 'submitted' });
    const adversary = await runtime.execute('babyx.adversary.create', { type: 'process-kill', trigger: { signal: 'SIGKILL' } });
    const campaign = await runtime.execute('babyx.campaign.create', { candidateId: candidate.id, adversaryIds: [adversary.id], state: 'created' });
    await runtime.execute('babyx.campaign.start', { id: campaign.id });
    const counterexample = await runtime.execute('babyx.counterexample.create', { candidateId: candidate.id, trigger: adversary.trigger, expectedProperty: { survives: true }, observedResult: { survives: false }, replay: { result: 'reproduced' } });
    const refuted = await runtime.execute('babyx.candidate.verify', { id: candidate.id, result: { counterexampleId: counterexample.id } });
    assert.equal(refuted.state, 'bounded-pass');
    const replayed = await runtime.execute('babyx.counterexample.replay', { id: counterexample.id, result: 'reproduced' });
    assert.equal(replayed.lastAction, 'replay');
    assert.equal(runtime.counterexamples.list().length, 1);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
