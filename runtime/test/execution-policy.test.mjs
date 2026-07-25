import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { BabyXRuntime } from '../../dist/runtime/core.js';
import { decideExecutionPolicy } from '../../dist/runtime/policy/execution.js';

function input(overrides = {}) {
  return {
    schemaVersion: '1.0.0', objectiveType: 'development', mutationRisk: 'medium', dependencyUncertainty: 'limited', isolationRequirement: 'preferred', reversibility: 'reversible',
    requiredTools: ['/usr/bin/node'], requiredPackages: [], sourceSensitivity: 'internal', reproducibilityRequirement: 'preferred', networkRequirement: 'private',
    expectedDurationMs: 60_000, resourceProfile: { cpuUnits: 2, memoryMb: 2048, diskMb: 4096 }, explicitConstraint: 'auto', racingEligibility: false, candidateCount: 1,
    costBounds: { maxMachines: 4, maxDurationMs: 3_600_000, maxDiskMb: 65_536 }, ...overrides,
  };
}

test('policy decisions are deterministic and normalize unordered tool/package evidence', () => {
  const left = decideExecutionPolicy(input({ requiredTools: ['/usr/bin/zsh', '/usr/bin/node'], requiredPackages: ['git', 'make'] }));
  const right = decideExecutionPolicy(input({ requiredTools: ['/usr/bin/node', '/usr/bin/zsh', '/usr/bin/node'], requiredPackages: ['make', 'git'] }));
  assert.equal(left.mode, 'disposable');
  assert.equal(left.decisionDigest, right.decisionDigest);
  assert.deepEqual(left.normalizedInput.requiredTools, ['/usr/bin/node', '/usr/bin/zsh']);
  assert.deepEqual(left.normalizedInput.requiredPackages, ['git', 'make']);
});

test('production activation and host recovery remain host-authoritative', () => {
  for (const objectiveType of ['production-activation', 'host-recovery']) {
    const decision = decideExecutionPolicy(input({ objectiveType, mutationRisk: 'high', dependencyUncertainty: 'unknown', isolationRequirement: 'required', sourceSensitivity: 'production' }));
    assert.equal(decision.mode, 'host');
    assert.ok(decision.rationale.includes('host-authoritative-objective'));
  }
  assert.throws(() => decideExecutionPolicy(input({ objectiveType: 'production-activation', explicitConstraint: 'disposable' })), (error) => error.code === 'execution_policy_unsafe_override');
});

test('certification and unknown dependency installation default to disposable', () => {
  const certification = decideExecutionPolicy(input({ objectiveType: 'certification', mutationRisk: 'low', dependencyUncertainty: 'known', isolationRequirement: 'none' }));
  assert.equal(certification.mode, 'disposable');
  assert.equal(certification.cleanupPolicy.positiveAbsenceRequired, true);
  const packages = decideExecutionPolicy(input({ dependencyUncertainty: 'known', requiredPackages: ['unknown-toolchain'] }));
  assert.equal(packages.mode, 'disposable');
});

test('ordinary read-only inspection remains in a persistent workspace', () => {
  const decision = decideExecutionPolicy(input({ objectiveType: 'inspection', mutationRisk: 'low', dependencyUncertainty: 'known', isolationRequirement: 'none', reproducibilityRequirement: 'none', networkRequirement: 'none' }));
  assert.equal(decision.mode, 'workspace');
  assert.ok(decision.rationale.includes('ordinary-read-only-inspection'));
});

test('eligible racing selects parallel disposable only within aggregate cost bounds', () => {
  const parallel = decideExecutionPolicy(input({ objectiveType: 'candidate-race', mutationRisk: 'high', dependencyUncertainty: 'unknown', isolationRequirement: 'required', reproducibilityRequirement: 'required', racingEligibility: true, candidateCount: 3 }));
  assert.equal(parallel.mode, 'parallel-disposable');
  assert.equal(parallel.machineProfile.machineCount, 3);
  const bounded = decideExecutionPolicy(input({ objectiveType: 'candidate-race', racingEligibility: true, candidateCount: 3, costBounds: { maxMachines: 2, maxDurationMs: 3_600_000, maxDiskMb: 65_536 } }));
  assert.equal(bounded.mode, 'disposable');
  assert.ok(bounded.rationale.includes('parallel-race-exceeds-cost-bounds'));
});

test('safe explicit overrides work and unsafe host/workspace overrides fail closed', () => {
  assert.equal(decideExecutionPolicy(input({ objectiveType: 'inspection', mutationRisk: 'low', dependencyUncertainty: 'known', isolationRequirement: 'none', reproducibilityRequirement: 'none', explicitConstraint: 'host' })).mode, 'host');
  assert.throws(() => decideExecutionPolicy(input({ objectiveType: 'certification', explicitConstraint: 'host' })), (error) => error.code === 'execution_policy_unsafe_override');
  assert.throws(() => decideExecutionPolicy(input({ dependencyUncertainty: 'unknown', explicitConstraint: 'workspace' })), (error) => error.code === 'execution_policy_unsafe_override');
  assert.throws(() => decideExecutionPolicy(input({ explicitConstraint: 'parallel-disposable', racingEligibility: false })), (error) => error.code === 'execution_policy_unsafe_override');
});

test('hard duration, disk, and explicit parallel aggregate cost bounds are enforced', () => {
  assert.throws(() => decideExecutionPolicy(input({ expectedDurationMs: 3_600_001 })), (error) => error.code === 'execution_policy_cost_exceeded');
  assert.throws(() => decideExecutionPolicy(input({ resourceProfile: { cpuUnits: 2, memoryMb: 2048, diskMb: 65_537 } })), (error) => error.code === 'execution_policy_cost_exceeded');
  assert.throws(() => decideExecutionPolicy(input({ objectiveType: 'candidate-race', explicitConstraint: 'parallel-disposable', racingEligibility: true, candidateCount: 3, costBounds: { maxMachines: 2, maxDurationMs: 3_600_000, maxDiskMb: 65_536 } })), (error) => error.code === 'execution_policy_cost_exceeded');
});

test('validation rejects unsupported properties and overflowing values', () => {
  assert.throws(() => decideExecutionPolicy({ ...input(), surprise: true }), (error) => error.code === 'execution_policy_invalid_request');
  assert.throws(() => decideExecutionPolicy(input({ candidateCount: 101 })), (error) => error.code === 'execution_policy_invalid_request');
  assert.throws(() => decideExecutionPolicy(input({ requiredTools: [''] })), (error) => error.code === 'execution_policy_invalid_request');
});

test('public registry exposes and routes decision-only policy operations', async () => {
  const runtime = new BabyXRuntime({ stateRoot: '/tmp/baby-x-policy-runtime-test' });
  const described = await runtime.execute('babyx.execution.policy.describe');
  assert.equal(described.authority, 'decision-only');
  assert.equal(described.executesCommands, false);
  const decision = await runtime.execute('babyx.execution.policy.decide', input());
  assert.equal(decision.mode, 'workspace');
  const names = new Set(runtime.describe().operations.map((definition) => definition.operation));
  assert.ok(names.has('babyx.execution.policy.describe'));
  assert.ok(names.has('babyx.execution.policy.decide'));
});

test('policy source has no execution, lifecycle, persistence, or artifact authority', () => {
  const source = readFileSync(new URL('../src/policy/execution.ts', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /child_process|spawn\(|execFile\(|machine\.create|machine\.exec|JobManager|AtomicStore|ArtifactManager|writeFile/u);
  assert.match(source, /decideExecutionPolicy/u);
});
