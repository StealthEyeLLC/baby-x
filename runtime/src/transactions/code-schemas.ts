import { isAbsolute, normalize } from 'node:path';
import { canonicalize, sha256, type JsonObject } from '../core.ts';

export const CODE_MUTATION_PLAN_SCHEMA_VERSION = '1.0.0' as const;
export const CODE_CANDIDATE_SCHEMA_VERSION = '1.0.0' as const;
export const CODE_MUTATION_MODES = ['PATCH_ARTIFACT', 'DECLARED_EXECUTION_PLAN'] as const;
export type CodeMutationMode = typeof CODE_MUTATION_MODES[number];

export type CodeValidationPhase = 'build' | 'strict-lint' | 'targeted-tests' | 'full-tests' | 'shell-syntax' | 'git-diff-check' | 'assertion';
export type CodeActionKind = 'NO_OP' | 'WRITE_FILE' | 'DELETE_PATH' | 'SET_MODE' | 'CREATE_SYMLINK';
export type CodeAssertionKind = 'PATH_EXISTS' | 'FILE_CONTAINS' | 'NETWORK_DISABLED' | 'CREDENTIALS_ABSENT' | 'TREE_EQUALS_BASE';

export interface CodeResourceBoundsV1 extends JsonObject {
  timeoutMs: number;
  memoryMaxBytes: number;
  cpuQuotaPercent: number;
  tasksMax: number;
  diskQuotaBytes: number;
  outputLimitBytes: number;
  artifactLimitBytes: number;
}

export interface CodeExecutionActionV1 extends JsonObject {
  stepId: string;
  kind: CodeActionKind;
  path: string | null;
  contentArtifactId: string | null;
  mode: '0644' | '0755' | null;
  symlinkTarget: string | null;
}

export interface CodeValidationStepV1 extends JsonObject {
  stepId: string;
  phase: CodeValidationPhase;
  argv: string[];
  cwd: string;
  timeoutMs: number;
  required: boolean;
}

export interface CodeAssertionV1 extends JsonObject {
  assertionId: string;
  kind: CodeAssertionKind;
  path: string | null;
  expected: string | null;
}

export interface CodeMutationPlanV1 extends JsonObject {
  schemaVersion: typeof CODE_MUTATION_PLAN_SCHEMA_VERSION;
  transactionId: string;
  baseCommit: string;
  baseTree: string;
  mutationMode: CodeMutationMode;
  patchArtifactId: string | null;
  executionPlanProfileId: string | null;
  executionActions: CodeExecutionActionV1[];
  mutationInputArtifactIds: string[];
  workingDirectory: string;
  changedPathAllowlist: string[];
  validationProfile: string;
  validationSteps: CodeValidationStepV1[];
  assertions: CodeAssertionV1[];
  resourceBounds: CodeResourceBoundsV1;
  expectedOutputFormat: 'git-tree-candidate-v1';
  idempotencyIdentity: string;
}

export interface CodeValidationExecutionV1 extends JsonObject {
  stepId: string;
  phase: CodeValidationPhase;
  jobId: string;
  executionPlanDigest: string;
  argv: string[];
  startedAt: string;
  completedAt: string;
  status: 'passed' | 'failed' | 'lost' | 'ambiguous';
  exitCode: number | null;
  signal: string | null;
  artifactIds: string[];
  receiptReferences: string[];
}

export interface CodePathChangeV1 extends JsonObject {
  path: string;
  status: 'added' | 'deleted' | 'modified' | 'type-changed';
  oldMode: string;
  newMode: string;
  oldObject: string;
  newObject: string;
  symlinkChanged: boolean;
}

export class CodeTransactionError extends Error {
  constructor(readonly code: string, message: string, readonly details: Readonly<Record<string, unknown>> = {}) {
    super(message);
    this.name = 'CodeTransactionError';
  }
}

const GIT_ID = /^[a-f0-9]{40,64}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$/u;
const STEP_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u;
const ALLOWED_VALIDATION_EXECUTABLES = new Set([
  '/usr/bin/bash', '/usr/bin/find', '/usr/bin/git', '/usr/bin/node', '/usr/bin/npm', '/usr/bin/true',
]);

function fail(code: string, message: string, details: Readonly<Record<string, unknown>> = {}): never {
  throw new CodeTransactionError(code, message, details);
}

function object(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail('code_plan_invalid', `${field} must be an object`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, field: string, allowed: readonly string[], required = allowed): void {
  const allow = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !allow.has(key));
  const missing = required.filter((key) => !(key in value));
  if (unknown.length > 0 || missing.length > 0) fail('code_plan_invalid', `${field} has an incompatible schema`, { unknown, missing });
}

function text(value: unknown, field: string, maximum = 4096): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum || value.includes('\0')) fail('code_plan_invalid', `${field} must be a bounded non-empty NUL-free string`);
  return value;
}

function safeId(value: unknown, field: string): string {
  const result = text(value, field, 256);
  if (!SAFE_ID.test(result) || result.startsWith('-') || result.includes('..')) fail('code_plan_invalid', `${field} is unsafe`);
  return result;
}

function stepId(value: unknown, field: string): string {
  const result = text(value, field, 128);
  if (!STEP_ID.test(result)) fail('code_plan_invalid', `${field} is invalid`);
  return result;
}

function integer(value: unknown, field: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) fail('code_plan_invalid', `${field} must be a safe integer between ${minimum} and ${maximum}`);
  return Number(value);
}

function finite(value: unknown, field: string, minimum: number, maximum: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum || value > maximum) fail('code_plan_invalid', `${field} must be a finite number between ${minimum} and ${maximum}`);
  return value;
}

export function codeRelativePath(value: unknown, field: string, allowDot = false): string {
  const result = text(value, field, 4096);
  if (allowDot && result === '.') return result;
  if (isAbsolute(result) || normalize(result) !== result || result === '.' || result === '..' || result.startsWith('../') || result.startsWith('-') || result.includes('/../')) {
    fail('code_path_unsafe', `${field} must be a normalized transaction-relative path without traversal or option injection`, { path: result });
  }
  return result;
}

function stringArray(value: unknown, field: string, maximum: number): string[] {
  if (!Array.isArray(value) || value.length > maximum) fail('code_plan_invalid', `${field} must be a bounded array`);
  const result = value.map((entry, index) => text(entry, `${field}[${index}]`));
  if (new Set(result).size !== result.length) fail('code_plan_invalid', `${field} must not contain duplicates`);
  return result;
}

function normalizeBounds(value: unknown): CodeResourceBoundsV1 {
  const item = object(value, 'resourceBounds');
  exactKeys(item, 'resourceBounds', ['timeoutMs', 'memoryMaxBytes', 'cpuQuotaPercent', 'tasksMax', 'diskQuotaBytes', 'outputLimitBytes', 'artifactLimitBytes']);
  return {
    timeoutMs: integer(item.timeoutMs, 'resourceBounds.timeoutMs', 1, 86_400_000),
    memoryMaxBytes: integer(item.memoryMaxBytes, 'resourceBounds.memoryMaxBytes', 67_108_864, 68_719_476_736),
    cpuQuotaPercent: finite(item.cpuQuotaPercent, 'resourceBounds.cpuQuotaPercent', 1, 1_000),
    tasksMax: integer(item.tasksMax, 'resourceBounds.tasksMax', 1, 65_536),
    diskQuotaBytes: integer(item.diskQuotaBytes, 'resourceBounds.diskQuotaBytes', 1_048_576, 1_099_511_627_776),
    outputLimitBytes: integer(item.outputLimitBytes, 'resourceBounds.outputLimitBytes', 1_024, 1_073_741_824),
    artifactLimitBytes: integer(item.artifactLimitBytes, 'resourceBounds.artifactLimitBytes', 1_024, 17_179_869_184),
  };
}

function normalizeAction(value: unknown, index: number): CodeExecutionActionV1 {
  const field = `executionActions[${index}]`;
  const item = object(value, field);
  exactKeys(item, field, ['stepId', 'kind', 'path', 'contentArtifactId', 'mode', 'symlinkTarget']);
  const kind = text(item.kind, `${field}.kind`) as CodeActionKind;
  if (!['NO_OP', 'WRITE_FILE', 'DELETE_PATH', 'SET_MODE', 'CREATE_SYMLINK'].includes(kind)) fail('code_plan_invalid', `${field}.kind is unsupported`);
  const path = item.path === null ? null : codeRelativePath(item.path, `${field}.path`);
  const contentArtifactId = item.contentArtifactId === null ? null : safeId(item.contentArtifactId, `${field}.contentArtifactId`);
  const mode = item.mode === null ? null : text(item.mode, `${field}.mode`) as '0644' | '0755';
  const symlinkTarget = item.symlinkTarget === null ? null : codeRelativePath(item.symlinkTarget, `${field}.symlinkTarget`);
  if (mode !== null && !['0644', '0755'].includes(mode)) fail('code_plan_invalid', `${field}.mode is unsupported`);
  if (kind === 'NO_OP' && [path, contentArtifactId, mode, symlinkTarget].some((entry) => entry !== null)) fail('code_plan_invalid', 'NO_OP cannot contain mutation operands');
  if (kind === 'WRITE_FILE' && (path === null || contentArtifactId === null || mode !== null || symlinkTarget !== null)) fail('code_plan_invalid', 'WRITE_FILE requires only path and contentArtifactId');
  if (kind === 'DELETE_PATH' && (path === null || contentArtifactId !== null || mode !== null || symlinkTarget !== null)) fail('code_plan_invalid', 'DELETE_PATH requires only path');
  if (kind === 'SET_MODE' && (path === null || mode === null || contentArtifactId !== null || symlinkTarget !== null)) fail('code_plan_invalid', 'SET_MODE requires only path and mode');
  if (kind === 'CREATE_SYMLINK' && (path === null || symlinkTarget === null || contentArtifactId !== null || mode !== null)) fail('code_plan_invalid', 'CREATE_SYMLINK requires only path and symlinkTarget');
  return { stepId: stepId(item.stepId, `${field}.stepId`), kind, path, contentArtifactId, mode, symlinkTarget };
}

function normalizeValidationStep(value: unknown, index: number): CodeValidationStepV1 {
  const field = `validationSteps[${index}]`;
  const item = object(value, field);
  exactKeys(item, field, ['stepId', 'phase', 'argv', 'cwd', 'timeoutMs', 'required']);
  const phase = text(item.phase, `${field}.phase`) as CodeValidationPhase;
  if (!['build', 'strict-lint', 'targeted-tests', 'full-tests', 'shell-syntax', 'git-diff-check', 'assertion'].includes(phase)) fail('code_plan_invalid', `${field}.phase is unsupported`);
  const argv = stringArray(item.argv, `${field}.argv`, 128);
  if (argv.length === 0 || !ALLOWED_VALIDATION_EXECUTABLES.has(argv[0])) fail('code_plan_invalid', `${field}.argv executable is not an approved in-machine validation executable`, { executable: argv[0] ?? null });
  for (const [argumentIndex, argument] of argv.entries()) {
    if (argument.startsWith('/var/lib/') || argument.startsWith('/proc/1/') || argument.includes('/proc/1/root')) fail('code_host_path_rejected', `${field}.argv[${argumentIndex}] requests a raw host path`);
  }
  if (typeof item.required !== 'boolean') fail('code_plan_invalid', `${field}.required must be boolean`);
  return {
    stepId: stepId(item.stepId, `${field}.stepId`), phase, argv,
    cwd: codeRelativePath(item.cwd, `${field}.cwd`, true),
    timeoutMs: integer(item.timeoutMs, `${field}.timeoutMs`, 1, 86_400_000),
    required: item.required,
  };
}

function normalizeAssertion(value: unknown, index: number): CodeAssertionV1 {
  const field = `assertions[${index}]`;
  const item = object(value, field);
  exactKeys(item, field, ['assertionId', 'kind', 'path', 'expected']);
  const kind = text(item.kind, `${field}.kind`) as CodeAssertionKind;
  if (!['PATH_EXISTS', 'FILE_CONTAINS', 'NETWORK_DISABLED', 'CREDENTIALS_ABSENT', 'TREE_EQUALS_BASE'].includes(kind)) fail('code_plan_invalid', `${field}.kind is unsupported`);
  const path = item.path === null ? null : codeRelativePath(item.path, `${field}.path`);
  const expected = item.expected === null ? null : text(item.expected, `${field}.expected`, 16_384);
  if (kind === 'PATH_EXISTS' && (path === null || expected !== null)) fail('code_plan_invalid', 'PATH_EXISTS requires only path');
  if (kind === 'FILE_CONTAINS' && (path === null || expected === null)) fail('code_plan_invalid', 'FILE_CONTAINS requires path and expected');
  if (['NETWORK_DISABLED', 'CREDENTIALS_ABSENT', 'TREE_EQUALS_BASE'].includes(kind) && (path !== null || expected !== null)) fail('code_plan_invalid', `${kind} does not accept operands`);
  return { assertionId: stepId(item.assertionId, `${field}.assertionId`), kind, path, expected };
}

export function normalizeCodeMutationPlan(value: unknown, transactionId: string, baseCommit: string, baseTree: string): CodeMutationPlanV1 {
  const item = object(value, 'mutationPlan');
  exactKeys(item, 'mutationPlan', [
    'schemaVersion', 'baseCommit', 'baseTree', 'mutationMode', 'patchArtifactId', 'executionPlanProfileId',
    'executionActions', 'mutationInputArtifactIds', 'workingDirectory', 'changedPathAllowlist', 'validationProfile',
    'validationSteps', 'assertions', 'resourceBounds', 'expectedOutputFormat', 'idempotencyIdentity',
  ]);
  if (item.schemaVersion !== CODE_MUTATION_PLAN_SCHEMA_VERSION) fail('code_plan_invalid', 'mutation plan schema version is unsupported');
  const normalizedBaseCommit = text(item.baseCommit, 'mutationPlan.baseCommit', 64);
  const normalizedBaseTree = text(item.baseTree, 'mutationPlan.baseTree', 64);
  if (!GIT_ID.test(normalizedBaseCommit) || !GIT_ID.test(normalizedBaseTree) || normalizedBaseCommit !== baseCommit || normalizedBaseTree !== baseTree) fail('code_source_mismatch', 'mutation plan base identity must exactly equal the transaction source');
  const mutationMode = text(item.mutationMode, 'mutationPlan.mutationMode') as CodeMutationMode;
  if (!CODE_MUTATION_MODES.includes(mutationMode)) fail('code_mutation_mode_unsupported', 'unknown mutation mode fails closed', { mutationMode });
  const patchArtifactId = item.patchArtifactId === null ? null : safeId(item.patchArtifactId, 'mutationPlan.patchArtifactId');
  const executionPlanProfileId = item.executionPlanProfileId === null ? null : safeId(item.executionPlanProfileId, 'mutationPlan.executionPlanProfileId');
  if (!Array.isArray(item.executionActions) || item.executionActions.length > 256) fail('code_plan_invalid', 'executionActions must be a bounded array');
  const executionActions = item.executionActions.map(normalizeAction);
  const mutationInputArtifactIds = stringArray(item.mutationInputArtifactIds, 'mutationPlan.mutationInputArtifactIds', 256).map((entry, index) => safeId(entry, `mutationPlan.mutationInputArtifactIds[${index}]`)).sort();
  if (mutationMode === 'PATCH_ARTIFACT' && (patchArtifactId === null || executionPlanProfileId !== null || executionActions.length !== 0 || !mutationInputArtifactIds.includes(patchArtifactId))) fail('code_plan_invalid', 'PATCH_ARTIFACT requires exactly one bound patch artifact and no execution plan');
  if (mutationMode === 'DECLARED_EXECUTION_PLAN' && (patchArtifactId !== null || executionPlanProfileId === null)) fail('code_plan_invalid', 'DECLARED_EXECUTION_PLAN requires a profile and no patch artifact');
  if (new Set(executionActions.map((action) => action.stepId)).size !== executionActions.length) fail('code_plan_invalid', 'execution action step IDs must be unique');
  for (const action of executionActions) if (action.contentArtifactId !== null && !mutationInputArtifactIds.includes(action.contentArtifactId)) fail('code_plan_invalid', 'execution action content artifact is not bound in mutationInputArtifactIds', { stepId: action.stepId });
  if (!Array.isArray(item.validationSteps) || item.validationSteps.length === 0 || item.validationSteps.length > 64) fail('code_plan_invalid', 'validationSteps must contain between one and 64 steps');
  const validationSteps = item.validationSteps.map(normalizeValidationStep);
  if (new Set(validationSteps.map((step) => step.stepId)).size !== validationSteps.length) fail('code_plan_invalid', 'validation step IDs must be unique');
  if (!Array.isArray(item.assertions) || item.assertions.length > 64) fail('code_plan_invalid', 'assertions must be a bounded array');
  const assertions = item.assertions.map(normalizeAssertion);
  if (new Set(assertions.map((assertion) => assertion.assertionId)).size !== assertions.length) fail('code_plan_invalid', 'assertion IDs must be unique');
  const changedPathAllowlist = stringArray(item.changedPathAllowlist, 'mutationPlan.changedPathAllowlist', 10_000).map((entry, index) => codeRelativePath(entry, `mutationPlan.changedPathAllowlist[${index}]`)).sort();
  const actionPaths = executionActions.flatMap((action) => action.path === null ? [] : [action.path]);
  for (const path of actionPaths) if (!changedPathAllowlist.includes(path)) fail('code_allowlist_violation', 'declared action path is outside changed-path allowlist', { path });
  if (item.expectedOutputFormat !== 'git-tree-candidate-v1') fail('code_plan_invalid', 'expectedOutputFormat is unsupported');
  return {
    schemaVersion: CODE_MUTATION_PLAN_SCHEMA_VERSION, transactionId: text(transactionId, 'transactionId', 128),
    baseCommit: normalizedBaseCommit, baseTree: normalizedBaseTree, mutationMode, patchArtifactId, executionPlanProfileId,
    executionActions, mutationInputArtifactIds, workingDirectory: codeRelativePath(item.workingDirectory, 'mutationPlan.workingDirectory', true),
    changedPathAllowlist, validationProfile: safeId(item.validationProfile, 'mutationPlan.validationProfile'), validationSteps, assertions,
    resourceBounds: normalizeBounds(item.resourceBounds), expectedOutputFormat: 'git-tree-candidate-v1',
    idempotencyIdentity: safeId(item.idempotencyIdentity, 'mutationPlan.idempotencyIdentity'),
  };
}

export function assertCodeMutationPlan(value: unknown): CodeMutationPlanV1 {
  const item = object(value, 'mutation plan');
  return normalizeCodeMutationPlan(
    Object.fromEntries(Object.entries(item).filter(([key]) => key !== 'transactionId')),
    text(item.transactionId, 'mutationPlan.transactionId', 128),
    text(item.baseCommit, 'mutationPlan.baseCommit', 64),
    text(item.baseTree, 'mutationPlan.baseTree', 64),
  );
}

export function codeMutationPlanDigest(plan: CodeMutationPlanV1): string {
  return sha256(canonicalize(assertCodeMutationPlan(plan)));
}

export function assertChangedPathsAllowed(changedPaths: readonly string[], allowedPaths: readonly string[]): string[] {
  const normalized = [...new Set(changedPaths.map((path, index) => codeRelativePath(path, `changedPaths[${index}]`)))].sort();
  const allowed = new Set(allowedPaths);
  const unexpected = normalized.filter((path) => !allowed.has(path));
  if (unexpected.length > 0) fail('code_allowlist_violation', 'candidate contains mutation outside the declared changed-path allowlist', { unexpected });
  return normalized;
}

function patchPath(token: string): string | null {
  if (token === '/dev/null') return null;
  const stripped = token.startsWith('a/') || token.startsWith('b/') ? token.slice(2) : token;
  return codeRelativePath(stripped, 'patch path');
}

export function assertPatchTextSafe(value: string): void {
  if (Buffer.byteLength(value) > 67_108_864 || value.includes('\0')) fail('code_patch_invalid', 'patch is too large or contains NUL bytes');
  for (const line of value.split('\n')) {
    if (line.startsWith('--- ') || line.startsWith('+++ ')) patchPath(line.slice(4).split('\t', 1)[0]);
    if (line.startsWith('diff --git ')) {
      const tokens = line.slice(11).split(' ');
      if (tokens.length !== 2) fail('code_patch_invalid', 'diff header is malformed');
      patchPath(tokens[0]); patchPath(tokens[1]);
    }
  }
}

export function parseRawGitDiff(value: Buffer): CodePathChangeV1[] {
  const tokens = value.toString('utf8').split('\0').filter((entry) => entry.length > 0);
  const changes: CodePathChangeV1[] = [];
  for (let index = 0; index < tokens.length; index += 2) {
    const header = tokens[index];
    const path = tokens[index + 1];
    if (path === undefined || !header.startsWith(':')) fail('code_candidate_invalid', 'raw Git diff is malformed');
    const match = /^:([0-7]{6}) ([0-7]{6}) ([a-f0-9]+) ([a-f0-9]+) ([AMDT])$/u.exec(header);
    if (match === null) fail('code_candidate_invalid', 'raw Git diff contains an unsupported status or rename', { header });
    const status = ({ A: 'added', D: 'deleted', M: 'modified', T: 'type-changed' } as const)[match[5] as 'A' | 'D' | 'M' | 'T'];
    const oldMode = match[1]; const newMode = match[2];
    changes.push({
      path: codeRelativePath(path, 'raw diff path'), status, oldMode, newMode, oldObject: match[3], newObject: match[4],
      symlinkChanged: oldMode === '120000' || newMode === '120000',
    });
  }
  return changes.sort((left, right) => left.path.localeCompare(right.path));
}

export function validationExecutionDigest(step: CodeValidationStepV1): string {
  return sha256(canonicalize({ stepId: step.stepId, phase: step.phase, argv: step.argv, cwd: step.cwd, timeoutMs: step.timeoutMs, required: step.required }));
}

export function deterministicCandidateId(value: JsonObject): string {
  const digest = sha256(canonicalize(value));
  if (!DIGEST.test(digest)) fail('code_candidate_invalid', 'candidate digest is invalid');
  return `candidate_${digest.slice(0, 32)}`;
}
