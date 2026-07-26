import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assertChangedPathsAllowed,
  assertPatchTextSafe,
  codeMutationPlanDigest,
  deterministicCandidateId,
  normalizeCodeMutationPlan,
  parseRawGitDiff,
  validationExecutionDigest,
} from '../../dist/runtime/transactions/code-schemas.js';
import { codeTransactionPolicyDecision } from '../../dist/runtime/transactions/code-driver.js';

const transactionId = `tx_${'1'.repeat(32)}`;
const baseCommit = 'a'.repeat(40);
const baseTree = 'b'.repeat(40);

function plan(overrides = {}) {
  return {
    schemaVersion: '1.0.0',
    baseCommit,
    baseTree,
    mutationMode: 'DECLARED_EXECUTION_PLAN',
    patchArtifactId: null,
    executionPlanProfileId: 'declared-actions-v1',
    executionActions: [{ stepId: 'noop', kind: 'NO_OP', path: null, contentArtifactId: null, mode: null, symlinkTarget: null }],
    mutationInputArtifactIds: [],
    workingDirectory: '.',
    changedPathAllowlist: [],
    validationProfile: 'v2-c-default',
    validationSteps: [{ stepId: 'diff-check', phase: 'git-diff-check', argv: ['/usr/bin/git', 'diff', '--check'], cwd: '.', timeoutMs: 30_000, required: true }],
    assertions: [{ assertionId: 'network', kind: 'NETWORK_DISABLED', path: null, expected: null }],
    resourceBounds: {
      timeoutMs: 120_000,
      memoryMaxBytes: 268_435_456,
      cpuQuotaPercent: 100,
      tasksMax: 128,
      diskQuotaBytes: 1_073_741_824,
      outputLimitBytes: 1_048_576,
      artifactLimitBytes: 16_777_216,
    },
    expectedOutputFormat: 'git-tree-candidate-v1',
    idempotencyIdentity: 'driver-test-plan-v1',
    ...overrides,
  };
}

test('strict mutation plan normalizes exact identity and has deterministic digest', () => {
  const normalized = normalizeCodeMutationPlan(plan(), transactionId, baseCommit, baseTree);
  assert.equal(normalized.transactionId, transactionId);
  assert.equal(normalized.baseCommit, baseCommit);
  assert.equal(normalized.baseTree, baseTree);
  assert.match(codeMutationPlanDigest(normalized), /^[a-f0-9]{64}$/u);
  assert.equal(codeMutationPlanDigest(normalized), codeMutationPlanDigest(structuredClone(normalized)));
});

test('unknown mutation mode and unknown properties fail closed', () => {
  assert.throws(() => normalizeCodeMutationPlan(plan({ mutationMode: 'HOST_SHELL' }), transactionId, baseCommit, baseTree), /unknown mutation mode/u);
  assert.throws(() => normalizeCodeMutationPlan({ ...plan(), surprise: true }, transactionId, baseCommit, baseTree), /incompatible schema/u);
});

test('absolute paths, traversal, option injection, duplicates, and source mismatch are rejected', () => {
  for (const workingDirectory of ['/tmp/x', '../x', '-C']) {
    assert.throws(() => normalizeCodeMutationPlan(plan({ workingDirectory }), transactionId, baseCommit, baseTree), /transaction-relative path/u);
  }
  assert.throws(() => normalizeCodeMutationPlan(plan({ changedPathAllowlist: ['docs/a.md', 'docs/a.md'] }), transactionId, baseCommit, baseTree), /duplicates/u);
  assert.throws(() => normalizeCodeMutationPlan(plan(), transactionId, 'c'.repeat(40), baseTree), /source/u);
});

test('declared mutation paths and observed candidate paths are bound to the allowlist', () => {
  const action = { stepId: 'write', kind: 'WRITE_FILE', path: 'docs/a.md', contentArtifactId: 'artifact-a', mode: null, symlinkTarget: null };
  assert.throws(() => normalizeCodeMutationPlan(plan({ executionActions: [action], mutationInputArtifactIds: ['artifact-a'] }), transactionId, baseCommit, baseTree), /allowlist/u);
  assert.deepEqual(assertChangedPathsAllowed(['docs/b.md', 'docs/a.md', 'docs/a.md'], ['docs/a.md', 'docs/b.md']), ['docs/a.md', 'docs/b.md']);
  assert.throws(() => assertChangedPathsAllowed(['generated/unexpected.js'], ['docs/a.md']), /allowlist/u);
});

test('patch validation rejects traversal and option injection while accepting bounded repository paths', () => {
  assert.doesNotThrow(() => assertPatchTextSafe('diff --git a/docs/a.md b/docs/a.md\n--- a/docs/a.md\n+++ b/docs/a.md\n'));
  assert.throws(() => assertPatchTextSafe('diff --git a/../secret b/../secret\n--- a/../secret\n+++ b/../secret\n'), /transaction-relative path/u);
  assert.throws(() => assertPatchTextSafe('diff --git -p b/docs/a.md\n'), /transaction-relative path/u);
});

test('raw Git diff parsing preserves additions, deletions, modes, and symlink truth', () => {
  const zero = '0'.repeat(40);
  const one = '1'.repeat(40);
  const two = '2'.repeat(40);
  const raw = Buffer.from(`:000000 100644 ${zero} ${one} A\0docs/new.md\0:100644 000000 ${one} ${zero} D\0docs/old.md\0:100644 100755 ${one} ${two} M\0bin/run\0:100644 120000 ${one} ${two} T\0link\0`);
  const changes = parseRawGitDiff(raw);
  assert.deepEqual(changes.map(({ path, status }) => ({ path, status })), [
    { path: 'bin/run', status: 'modified' },
    { path: 'docs/new.md', status: 'added' },
    { path: 'docs/old.md', status: 'deleted' },
    { path: 'link', status: 'type-changed' },
  ]);
  assert.equal(changes.find((change) => change.path === 'bin/run').newMode, '100755');
  assert.equal(changes.find((change) => change.path === 'link').symlinkChanged, true);
});

test('candidate and validation identities are deterministic and content-sensitive', () => {
  const candidate = { schemaVersion: '1.0.0', transactionId, baseTree, candidateTree: baseTree };
  assert.equal(deterministicCandidateId(candidate), deterministicCandidateId(structuredClone(candidate)));
  assert.notEqual(deterministicCandidateId(candidate), deterministicCandidateId({ ...candidate, candidateTree: 'c'.repeat(40) }));
  const step = plan().validationSteps[0];
  assert.equal(validationExecutionDigest(step), validationExecutionDigest(structuredClone(step)));
  assert.notEqual(validationExecutionDigest(step), validationExecutionDigest({ ...step, timeoutMs: step.timeoutMs + 1 }));
});

test('execution policy binds disposable isolation, no network, and declared resource bounds', () => {
  const normalized = normalizeCodeMutationPlan(plan(), transactionId, baseCommit, baseTree);
  const decision = codeTransactionPolicyDecision(normalized);
  assert.equal(decision.mode, 'disposable');
  assert.equal(decision.machineProfile.networkMode, 'none');
  assert.equal(decision.normalizedInput.networkRequirement, 'none');
  assert.equal(decision.machineProfile.resources.memoryMb, 256);
  assert.equal(decision.machineProfile.resources.diskMb, 1024);
  assert.match(decision.decisionDigest, /^[a-f0-9]{64}$/u);
});
