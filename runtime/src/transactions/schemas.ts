import { randomUUID } from 'node:crypto';
import { isAbsolute, normalize } from 'node:path';
import { canonicalize, sha256, type JsonObject } from '../core.ts';
import { TRANSACTION_LEGACY_SCHEMA_VERSION, TRANSACTION_SCHEMA_VERSION } from '../compatibility/manifest.ts';
import {
  assertCodeMutationPlan,
  codeMutationPlanDigest,
  normalizeCodeMutationPlan,
  type CodeMutationPlanV1,
  type CodePathChangeV1,
  type CodeValidationExecutionV1,
} from './code-schemas.ts';
export { TRANSACTION_LEGACY_SCHEMA_VERSION, TRANSACTION_SCHEMA_VERSION };

export const TRANSACTION_EVENT_SCHEMA_VERSION = '1.0.0' as const;
export const TRANSACTION_LEASE_SCHEMA_VERSION = '1.0.0' as const;
export const TRANSACTION_INDEX_SCHEMA_VERSION = '1.0.0' as const;
export const TRANSACTION_KINDS = ['CODE_MUTATION'] as const;
export type TransactionKind = typeof TRANSACTION_KINDS[number];

export const TRANSACTION_STATES = [
  'REQUESTED', 'CHECKPOINTING', 'READY', 'EXECUTING', 'VALIDATING',
  'PREPARING_CANDIDATE', 'CANDIDATE_READY', 'CLEANING', 'COMMITTED',
  'ROLLBACK_REQUESTED', 'ROLLING_BACK', 'ROLLED_BACK', 'FAILED',
  'RECOVERY_REQUIRED', 'AMBIGUOUS', 'EXPIRED',
] as const;
export type TransactionState = typeof TRANSACTION_STATES[number];
export const TRANSACTION_TERMINAL_STATES = ['COMMITTED', 'ROLLED_BACK', 'FAILED', 'EXPIRED'] as const;

const TRANSITIONS: Readonly<Record<TransactionState, readonly TransactionState[]>> = {
  REQUESTED: ['CHECKPOINTING', 'ROLLBACK_REQUESTED', 'FAILED', 'EXPIRED'],
  CHECKPOINTING: ['READY', 'ROLLBACK_REQUESTED', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  READY: ['EXECUTING', 'ROLLBACK_REQUESTED', 'FAILED', 'RECOVERY_REQUIRED', 'EXPIRED'],
  EXECUTING: ['VALIDATING', 'ROLLBACK_REQUESTED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  VALIDATING: ['PREPARING_CANDIDATE', 'ROLLBACK_REQUESTED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  PREPARING_CANDIDATE: ['CANDIDATE_READY', 'ROLLBACK_REQUESTED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  CANDIDATE_READY: ['CLEANING', 'ROLLBACK_REQUESTED', 'RECOVERY_REQUIRED'],
  CLEANING: ['COMMITTED', 'ROLLING_BACK', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  COMMITTED: [],
  ROLLBACK_REQUESTED: ['ROLLING_BACK', 'ROLLED_BACK', 'EXPIRED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  ROLLING_BACK: ['ROLLED_BACK', 'EXPIRED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  ROLLED_BACK: [],
  FAILED: [],
  RECOVERY_REQUIRED: ['CLEANING', 'ROLLING_BACK', 'AMBIGUOUS'],
  AMBIGUOUS: ['RECOVERY_REQUIRED'],
  EXPIRED: [],
};

const DIGEST = /^[a-f0-9]{64}$/u;
const GIT_ID = /^[a-f0-9]{40,64}$/u;
const TRANSACTION_ID = /^tx_[a-z0-9][a-z0-9_-]{11,124}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$/u;
const ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const SECRET_ENVIRONMENT_NAME = /(^|_)(SECRET|TOKEN|PASSWORD|PASSPHRASE|PRIVATE_KEY|API_KEY|ACCESS_KEY|CREDENTIAL)(_|$)/iu;

export class TransactionError extends Error {
  constructor(readonly code: string, message: string, readonly details: Readonly<Record<string, unknown>> = {}) {
    super(message);
    this.name = 'TransactionError';
  }
}

function invalid(message: string, details: Readonly<Record<string, unknown>> = {}): never {
  throw new TransactionError('transaction_invalid_record', message, details);
}

function object(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid(`${field} must be an object`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, field: string, keys: readonly string[]): void {
  const expected = new Set(keys);
  const unknown = Object.keys(value).filter((key) => !expected.has(key));
  const missing = keys.filter((key) => !(key in value));
  if (unknown.length > 0 || missing.length > 0) invalid(`${field} has an incompatible schema`, { unknown, missing });
}

function text(value: unknown, field: string, maximum = 4096): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum || value.includes('\0')) invalid(`${field} must be a bounded non-empty NUL-free string`);
  return value;
}

function nullableText(value: unknown, field: string, maximum = 4096): string | null {
  return value === null ? null : text(value, field, maximum);
}

function bool(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') invalid(`${field} must be a boolean`);
  return value;
}

function integer(value: unknown, field: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum) invalid(`${field} must be a bounded safe integer`);
  return Number(value);
}

function timestamp(value: unknown, field: string): string {
  const result = text(value, field, 128);
  if (!Number.isFinite(Date.parse(result))) invalid(`${field} must be an ISO timestamp`);
  return result;
}

function nullableTimestamp(value: unknown, field: string): string | null {
  return value === null ? null : timestamp(value, field);
}

function digest(value: unknown, field: string): string {
  const result = text(value, field, 64);
  if (!DIGEST.test(result)) invalid(`${field} must be a lowercase SHA-256 digest`);
  return result;
}

function nullableDigest(value: unknown, field: string): string | null {
  return value === null ? null : digest(value, field);
}

function gitIdentity(value: unknown, field: string): string {
  const result = text(value, field, 64);
  if (!GIT_ID.test(result)) invalid(`${field} must be a lowercase Git object identity`);
  return result;
}

function nullableGitIdentity(value: unknown, field: string): string | null {
  return value === null ? null : gitIdentity(value, field);
}

function stringArray(value: unknown, field: string, maximum = 10_000): string[] {
  if (!Array.isArray(value) || value.length > maximum) invalid(`${field} must be a bounded array`);
  const result = value.map((entry, index) => text(entry, `${field}[${index}]`, 4096));
  if (new Set(result).size !== result.length) invalid(`${field} must not contain duplicates`);
  return result;
}

function optionalStringArray(value: unknown, field: string): string[] | null {
  return value === null ? null : stringArray(value, field);
}

function relativePath(value: unknown, field: string): string {
  const result = text(value, field, 4096);
  if (isAbsolute(result) || normalize(result) !== result || result === '.' || result === '..' || result.startsWith('../') || result.startsWith('-')) invalid(`${field} must be a normalized relative path without option injection`);
  return result;
}

function relativePathArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length > 100_000) invalid(`${field} must be a bounded array`);
  const result = value.map((entry, index) => relativePath(entry, `${field}[${index}]`));
  if (new Set(result).size !== result.length) invalid(`${field} must not contain duplicates`);
  return result;
}

function jsonObject(value: unknown, field: string): JsonObject {
  return structuredClone(object(value, field)) as JsonObject;
}

function safeId(value: unknown, field: string): string {
  const result = text(value, field, 256);
  if (!SAFE_ID.test(result) || result.startsWith('-') || result.includes('..')) invalid(`${field} is unsafe`);
  return result;
}

export interface TransactionSourceBindingV1 extends JsonObject {
  repository: string;
  branch: string | null;
  commit: string;
  tree: string;
  sourceArchiveArtifactId: string | null;
  immutableSourceReference: string;
  sourceManifestDigest: string;
  packageLockDigest: string | null;
  protectedSnapshot: string;
  expectedSnapshotGuid: string;
  observedSnapshotGuid: string | null;
  snapshotCreationTxg: string;
  sourceVerifiedAt: string | null;
}

export interface TransactionResourceIdentityV1 extends JsonObject {
  machineName: string;
  cloneDataset: string;
  mountpoint: string;
  expectedRootPrefix: string;
}

export interface TransactionPolicyBindingV1 extends JsonObject {
  policyDecisionDigest: string;
  selectedEnvironmentClass: 'disposable' | 'parallel-disposable';
  providerId: string;
  providerVersion: string;
  networkMode: 'none';
  resourceBoundIdentity: TransactionResourceIdentityV1;
}

export interface TransactionExecutionBindingV1 extends JsonObject {
  machineIds: string[];
  activeJobIds: string[];
  allRelatedJobIds: string[];
  mutationJobIds: string[];
  validationJobIds: string[];
  jobTerminalityStatus: 'not-observed' | 'active' | 'all-terminal' | 'ambiguous';
  mutationSubmitted: boolean;
  validationSubmitted: boolean;
}

export interface TransactionCandidateBindingV1 extends JsonObject {
  candidateId: string | null;
  baseCommit: string;
  baseTree: string;
  candidateTree: string | null;
  changedPaths: string[];
  addedFiles: string[];
  deletedFiles: string[];
  modifiedFiles: string[];
  fileModeChanges: string[];
  symlinkChanges: string[];
  pathChanges: CodePathChangeV1[];
  patchArtifactId: string | null;
  candidateArchiveArtifactId: string | null;
  candidateManifestArtifactId: string | null;
  validationDigest: string | null;
  mutationPlanDigest: string;
  validationPassed: boolean;
}

export interface TransactionEvidenceBindingV1 extends JsonObject {
  artifactIds: string[];
  receiptReferences: string[];
  eventTailDigest: string | null;
  finalEvidenceIndexArtifactId: string | null;
  finalEvidenceIndexDigest: string | null;
}

export interface TransactionCleanupBindingV1 extends JsonObject {
  required: boolean;
  requested: boolean;
  completed: boolean;
  machineAbsenceVerified: boolean;
  processAbsenceVerified: boolean;
  mountAbsenceVerified: boolean;
  rootPathAbsenceVerified: boolean;
  datasetAbsenceVerified: boolean;
  sourcePreserved: boolean;
  completedAt: string | null;
}

export interface TransactionErrorBindingV1 extends JsonObject {
  code: string;
  message: string;
  retryable: boolean;
  phase: string;
  details: JsonObject;
}

export interface TransactionEnvironmentBindingV1 extends JsonObject {
  normalizedValues: { name: string; value: string }[];
  normalizedDigest: string;
  credentialReferenceIds: string[];
  credentialPresence: boolean;
}

export interface TransactionCodeBindingV1 extends JsonObject {
  mutationPlan: CodeMutationPlanV1;
  mutationPlanDigest: string;
  materializationJobId: string | null;
  candidateJobIds: string[];
  validationExecutions: CodeValidationExecutionV1[];
}

export interface TransactionLifecycleV1 extends JsonObject {
  persistedState: TransactionState;
  desiredState: TransactionState;
  stateSequence: number;
  terminal: boolean;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
}

export interface DurableTransactionRecordV1 extends JsonObject {
  schemaVersion: typeof TRANSACTION_SCHEMA_VERSION | typeof TRANSACTION_LEGACY_SCHEMA_VERSION;
  transactionId: string;
  transactionKind: TransactionKind;
  ownerPrincipal: string;
  creationRequestDigest: string;
  idempotencyKey: string;
  lifecycle: TransactionLifecycleV1;
  source: TransactionSourceBindingV1;
  policy: TransactionPolicyBindingV1;
  execution: TransactionExecutionBindingV1;
  candidate: TransactionCandidateBindingV1;
  evidence: TransactionEvidenceBindingV1;
  cleanup: TransactionCleanupBindingV1;
  environment: TransactionEnvironmentBindingV1;
  code: TransactionCodeBindingV1 | null;
  error: TransactionErrorBindingV1 | null;
}

export interface TransactionEventV1 extends JsonObject {
  schemaVersion: typeof TRANSACTION_EVENT_SCHEMA_VERSION;
  eventId: string;
  transactionId: string;
  ownerPrincipal: string;
  operation: string;
  phase: string;
  priorState: TransactionState | null;
  nextState: TransactionState;
  priorSequence: number;
  nextSequence: number;
  requestDigest: string;
  idempotencyKey: string | null;
  occurredAt: string;
  previousEventDigest: string | null;
  eventDigest: string;
  machineId: string | null;
  jobIds: string[];
  candidateId: string | null;
  candidateTree: string | null;
  observationDigest: string | null;
}

export interface TransactionControllerLeaseV1 extends JsonObject {
  schemaVersion: typeof TRANSACTION_LEASE_SCHEMA_VERSION;
  leaseId: string;
  transactionId: string;
  ownerPrincipal: string;
  controllerId: string;
  hostBootId: string;
  operation: string;
  acquiredAt: string;
  expiresAt: string;
  renewedAt: string | null;
  takeoverFromLeaseId: string | null;
}

export interface TransactionCreateRequestV1 extends JsonObject {
  schemaVersion: typeof TRANSACTION_SCHEMA_VERSION;
  transactionKind: TransactionKind;
  repository: string;
  branch?: string;
  commit: string;
  tree: string;
  sourceArchiveArtifactId?: string;
  immutableSourceReference: string;
  sourceManifestDigest: string;
  packageLockDigest?: string;
  protectedSnapshot: string;
  expectedSnapshotGuid: string;
  snapshotCreationTxg: string;
  policyDecisionDigest: string;
  selectedEnvironmentClass: 'disposable' | 'parallel-disposable';
  providerId: string;
  providerVersion: string;
  networkMode: 'none';
  resourceBoundIdentity: TransactionResourceIdentityV1;
  normalizedEnvironment?: { name: string; value: string }[];
  credentialReferenceIds?: string[];
  credentialPresence?: boolean;
  mutationPlan: JsonObject;
}

function validateLifecycle(value: unknown): TransactionLifecycleV1 {
  const item = object(value, 'lifecycle');
  exactKeys(item, 'lifecycle', ['persistedState', 'desiredState', 'stateSequence', 'terminal', 'createdAt', 'updatedAt', 'completedAt']);
  const persistedState = text(item.persistedState, 'lifecycle.persistedState') as TransactionState;
  const desiredState = text(item.desiredState, 'lifecycle.desiredState') as TransactionState;
  if (!TRANSACTION_STATES.includes(persistedState) || !TRANSACTION_STATES.includes(desiredState)) invalid('lifecycle state is unsupported');
  const terminal = bool(item.terminal, 'lifecycle.terminal');
  const expectedTerminal = (TRANSACTION_TERMINAL_STATES as readonly string[]).includes(persistedState);
  if (terminal !== expectedTerminal) invalid('lifecycle terminal truth conflicts with persisted state');
  const completedAt = nullableTimestamp(item.completedAt, 'lifecycle.completedAt');
  if (terminal !== (completedAt !== null)) invalid('completedAt must exist exactly for terminal states');
  return {
    persistedState, desiredState, stateSequence: integer(item.stateSequence, 'lifecycle.stateSequence', 1), terminal,
    createdAt: timestamp(item.createdAt, 'lifecycle.createdAt'), updatedAt: timestamp(item.updatedAt, 'lifecycle.updatedAt'), completedAt,
  };
}

function validateSource(value: unknown): TransactionSourceBindingV1 {
  const item = object(value, 'source');
  exactKeys(item, 'source', ['repository', 'branch', 'commit', 'tree', 'sourceArchiveArtifactId', 'immutableSourceReference', 'sourceManifestDigest', 'packageLockDigest', 'protectedSnapshot', 'expectedSnapshotGuid', 'observedSnapshotGuid', 'snapshotCreationTxg', 'sourceVerifiedAt']);
  return {
    repository: text(item.repository, 'source.repository', 1024), branch: nullableText(item.branch, 'source.branch', 1024),
    commit: gitIdentity(item.commit, 'source.commit'), tree: gitIdentity(item.tree, 'source.tree'),
    sourceArchiveArtifactId: nullableText(item.sourceArchiveArtifactId, 'source.sourceArchiveArtifactId', 256),
    immutableSourceReference: text(item.immutableSourceReference, 'source.immutableSourceReference', 2048),
    sourceManifestDigest: digest(item.sourceManifestDigest, 'source.sourceManifestDigest'),
    packageLockDigest: nullableDigest(item.packageLockDigest, 'source.packageLockDigest'),
    protectedSnapshot: safeId(item.protectedSnapshot, 'source.protectedSnapshot'),
    expectedSnapshotGuid: text(item.expectedSnapshotGuid, 'source.expectedSnapshotGuid', 64),
    observedSnapshotGuid: nullableText(item.observedSnapshotGuid, 'source.observedSnapshotGuid', 64),
    snapshotCreationTxg: text(item.snapshotCreationTxg, 'source.snapshotCreationTxg', 64),
    sourceVerifiedAt: nullableTimestamp(item.sourceVerifiedAt, 'source.sourceVerifiedAt'),
  };
}

function validateResourceIdentity(value: unknown): TransactionResourceIdentityV1 {
  const item = object(value, 'policy.resourceBoundIdentity');
  exactKeys(item, 'policy.resourceBoundIdentity', ['machineName', 'cloneDataset', 'mountpoint', 'expectedRootPrefix']);
  const mountpoint = text(item.mountpoint, 'policy.resourceBoundIdentity.mountpoint', 4096);
  const expectedRootPrefix = text(item.expectedRootPrefix, 'policy.resourceBoundIdentity.expectedRootPrefix', 4096);
  if (!isAbsolute(mountpoint) || normalize(mountpoint) !== mountpoint || !isAbsolute(expectedRootPrefix) || normalize(expectedRootPrefix) !== expectedRootPrefix || mountpoint === '/' || expectedRootPrefix === '/') invalid('resource mount paths must be normalized absolute paths below root');
  return {
    machineName: safeId(item.machineName, 'policy.resourceBoundIdentity.machineName'),
    cloneDataset: safeId(item.cloneDataset, 'policy.resourceBoundIdentity.cloneDataset'),
    mountpoint, expectedRootPrefix,
  };
}

function validatePolicy(value: unknown): TransactionPolicyBindingV1 {
  const item = object(value, 'policy');
  exactKeys(item, 'policy', ['policyDecisionDigest', 'selectedEnvironmentClass', 'providerId', 'providerVersion', 'networkMode', 'resourceBoundIdentity']);
  const selectedEnvironmentClass = text(item.selectedEnvironmentClass, 'policy.selectedEnvironmentClass') as TransactionPolicyBindingV1['selectedEnvironmentClass'];
  if (!['disposable', 'parallel-disposable'].includes(selectedEnvironmentClass)) invalid('policy selected environment must be disposable');
  if (item.networkMode !== 'none') invalid('transaction network mode must be none');
  return {
    policyDecisionDigest: digest(item.policyDecisionDigest, 'policy.policyDecisionDigest'), selectedEnvironmentClass,
    providerId: safeId(item.providerId, 'policy.providerId'), providerVersion: text(item.providerVersion, 'policy.providerVersion', 128),
    networkMode: 'none', resourceBoundIdentity: validateResourceIdentity(item.resourceBoundIdentity),
  };
}

function validateExecution(value: unknown): TransactionExecutionBindingV1 {
  const item = object(value, 'execution');
  exactKeys(item, 'execution', ['machineIds', 'activeJobIds', 'allRelatedJobIds', 'mutationJobIds', 'validationJobIds', 'jobTerminalityStatus', 'mutationSubmitted', 'validationSubmitted']);
  const machineIds = stringArray(item.machineIds, 'execution.machineIds');
  const activeJobIds = stringArray(item.activeJobIds, 'execution.activeJobIds');
  const allRelatedJobIds = stringArray(item.allRelatedJobIds, 'execution.allRelatedJobIds');
  const mutationJobIds = stringArray(item.mutationJobIds, 'execution.mutationJobIds');
  const validationJobIds = stringArray(item.validationJobIds, 'execution.validationJobIds');
  for (const jobId of [...activeJobIds, ...mutationJobIds, ...validationJobIds]) if (!allRelatedJobIds.includes(jobId)) invalid('transaction job subsets must be bound in allRelatedJobIds');
  const jobTerminalityStatus = text(item.jobTerminalityStatus, 'execution.jobTerminalityStatus') as TransactionExecutionBindingV1['jobTerminalityStatus'];
  if (!['not-observed', 'active', 'all-terminal', 'ambiguous'].includes(jobTerminalityStatus)) invalid('job terminality status is unsupported');
  return { machineIds, activeJobIds, allRelatedJobIds, mutationJobIds, validationJobIds, jobTerminalityStatus, mutationSubmitted: bool(item.mutationSubmitted, 'execution.mutationSubmitted'), validationSubmitted: bool(item.validationSubmitted, 'execution.validationSubmitted') };
}

function validateLegacyCandidate(value: unknown, source: TransactionSourceBindingV1): TransactionCandidateBindingV1 {
  const item = object(value, 'candidate');
  exactKeys(item, 'candidate', ['candidateId', 'baseCommit', 'baseTree', 'candidateTree', 'changedPaths', 'patchArtifactId', 'candidateArchiveArtifactId', 'candidateManifestArtifactId', 'validationDigest', 'validationPassed']);
  const baseCommit = gitIdentity(item.baseCommit, 'candidate.baseCommit');
  const baseTree = gitIdentity(item.baseTree, 'candidate.baseTree');
  if (baseCommit !== source.commit || baseTree !== source.tree) invalid('candidate base identity must equal the immutable source identity');
  return {
    candidateId: nullableText(item.candidateId, 'candidate.candidateId', 256), baseCommit, baseTree,
    candidateTree: nullableGitIdentity(item.candidateTree, 'candidate.candidateTree'), changedPaths: relativePathArray(item.changedPaths, 'candidate.changedPaths'),
    addedFiles: [], deletedFiles: [], modifiedFiles: [], fileModeChanges: [], symlinkChanges: [], pathChanges: [],
    patchArtifactId: nullableText(item.patchArtifactId, 'candidate.patchArtifactId', 256),
    candidateArchiveArtifactId: nullableText(item.candidateArchiveArtifactId, 'candidate.candidateArchiveArtifactId', 256),
    candidateManifestArtifactId: nullableText(item.candidateManifestArtifactId, 'candidate.candidateManifestArtifactId', 256),
    validationDigest: nullableDigest(item.validationDigest, 'candidate.validationDigest'), mutationPlanDigest: '0'.repeat(64),
    validationPassed: bool(item.validationPassed, 'candidate.validationPassed'),
  };
}

function validateCandidate(value: unknown, source: TransactionSourceBindingV1): TransactionCandidateBindingV1 {
  const item = object(value, 'candidate');
  exactKeys(item, 'candidate', ['candidateId', 'baseCommit', 'baseTree', 'candidateTree', 'changedPaths', 'addedFiles', 'deletedFiles', 'modifiedFiles', 'fileModeChanges', 'symlinkChanges', 'pathChanges', 'patchArtifactId', 'candidateArchiveArtifactId', 'candidateManifestArtifactId', 'validationDigest', 'mutationPlanDigest', 'validationPassed']);
  const baseCommit = gitIdentity(item.baseCommit, 'candidate.baseCommit');
  const baseTree = gitIdentity(item.baseTree, 'candidate.baseTree');
  if (baseCommit !== source.commit || baseTree !== source.tree) invalid('candidate base identity must equal the immutable source identity');
  if (!Array.isArray(item.pathChanges) || item.pathChanges.length > 100_000) invalid('candidate.pathChanges must be a bounded array');
  const pathChanges = item.pathChanges.map((entry, index) => {
    const change = object(entry, `candidate.pathChanges[${index}]`);
    exactKeys(change, `candidate.pathChanges[${index}]`, ['path', 'status', 'oldMode', 'newMode', 'oldObject', 'newObject', 'symlinkChanged']);
    const status = text(change.status, `candidate.pathChanges[${index}].status`) as CodePathChangeV1['status'];
    if (!['added', 'deleted', 'modified', 'type-changed'].includes(status)) invalid('candidate path-change status is unsupported');
    return {
      path: relativePath(change.path, `candidate.pathChanges[${index}].path`), status,
      oldMode: text(change.oldMode, `candidate.pathChanges[${index}].oldMode`, 16), newMode: text(change.newMode, `candidate.pathChanges[${index}].newMode`, 16),
      oldObject: text(change.oldObject, `candidate.pathChanges[${index}].oldObject`, 64), newObject: text(change.newObject, `candidate.pathChanges[${index}].newObject`, 64),
      symlinkChanged: bool(change.symlinkChanged, `candidate.pathChanges[${index}].symlinkChanged`),
    };
  });
  const changedPaths = relativePathArray(item.changedPaths, 'candidate.changedPaths');
  if (canonicalize(changedPaths) !== canonicalize(pathChanges.map((entry) => entry.path))) invalid('candidate changed paths must exactly match pathChanges');
  return {
    candidateId: nullableText(item.candidateId, 'candidate.candidateId', 256), baseCommit, baseTree,
    candidateTree: nullableGitIdentity(item.candidateTree, 'candidate.candidateTree'), changedPaths,
    addedFiles: relativePathArray(item.addedFiles, 'candidate.addedFiles'), deletedFiles: relativePathArray(item.deletedFiles, 'candidate.deletedFiles'),
    modifiedFiles: relativePathArray(item.modifiedFiles, 'candidate.modifiedFiles'), fileModeChanges: relativePathArray(item.fileModeChanges, 'candidate.fileModeChanges'),
    symlinkChanges: relativePathArray(item.symlinkChanges, 'candidate.symlinkChanges'), pathChanges,
    patchArtifactId: nullableText(item.patchArtifactId, 'candidate.patchArtifactId', 256),
    candidateArchiveArtifactId: nullableText(item.candidateArchiveArtifactId, 'candidate.candidateArchiveArtifactId', 256),
    candidateManifestArtifactId: nullableText(item.candidateManifestArtifactId, 'candidate.candidateManifestArtifactId', 256),
    validationDigest: nullableDigest(item.validationDigest, 'candidate.validationDigest'), mutationPlanDigest: digest(item.mutationPlanDigest, 'candidate.mutationPlanDigest'),
    validationPassed: bool(item.validationPassed, 'candidate.validationPassed'),
  };
}

function validateEvidence(value: unknown): TransactionEvidenceBindingV1 {
  const item = object(value, 'evidence');
  exactKeys(item, 'evidence', ['artifactIds', 'receiptReferences', 'eventTailDigest', 'finalEvidenceIndexArtifactId', 'finalEvidenceIndexDigest']);
  return {
    artifactIds: stringArray(item.artifactIds, 'evidence.artifactIds'), receiptReferences: stringArray(item.receiptReferences, 'evidence.receiptReferences'),
    eventTailDigest: nullableDigest(item.eventTailDigest, 'evidence.eventTailDigest'), finalEvidenceIndexArtifactId: nullableText(item.finalEvidenceIndexArtifactId, 'evidence.finalEvidenceIndexArtifactId', 256),
    finalEvidenceIndexDigest: nullableDigest(item.finalEvidenceIndexDigest, 'evidence.finalEvidenceIndexDigest'),
  };
}

function validateCleanup(value: unknown): TransactionCleanupBindingV1 {
  const item = object(value, 'cleanup');
  exactKeys(item, 'cleanup', ['required', 'requested', 'completed', 'machineAbsenceVerified', 'processAbsenceVerified', 'mountAbsenceVerified', 'rootPathAbsenceVerified', 'datasetAbsenceVerified', 'sourcePreserved', 'completedAt']);
  const result = {
    required: bool(item.required, 'cleanup.required'), requested: bool(item.requested, 'cleanup.requested'), completed: bool(item.completed, 'cleanup.completed'),
    machineAbsenceVerified: bool(item.machineAbsenceVerified, 'cleanup.machineAbsenceVerified'), processAbsenceVerified: bool(item.processAbsenceVerified, 'cleanup.processAbsenceVerified'),
    mountAbsenceVerified: bool(item.mountAbsenceVerified, 'cleanup.mountAbsenceVerified'), rootPathAbsenceVerified: bool(item.rootPathAbsenceVerified, 'cleanup.rootPathAbsenceVerified'),
    datasetAbsenceVerified: bool(item.datasetAbsenceVerified, 'cleanup.datasetAbsenceVerified'), sourcePreserved: bool(item.sourcePreserved, 'cleanup.sourcePreserved'),
    completedAt: nullableTimestamp(item.completedAt, 'cleanup.completedAt'),
  };
  const allAbsence = result.machineAbsenceVerified && result.processAbsenceVerified && result.mountAbsenceVerified && result.rootPathAbsenceVerified && result.datasetAbsenceVerified;
  if (result.completed && (!result.requested || !allAbsence || !result.sourcePreserved || result.completedAt === null)) invalid('completed cleanup requires requested cleanup, full positive absence, source preservation, and completion time');
  if (!result.completed && result.completedAt !== null) invalid('incomplete cleanup cannot have completedAt');
  return result;
}

function validateEnvironment(value: unknown): TransactionEnvironmentBindingV1 {
  const item = object(value, 'environment');
  exactKeys(item, 'environment', ['normalizedValues', 'normalizedDigest', 'credentialReferenceIds', 'credentialPresence']);
  if (!Array.isArray(item.normalizedValues) || item.normalizedValues.length > 1_000) invalid('environment.normalizedValues must be bounded');
  const normalizedValues = item.normalizedValues.map((entry, index) => {
    const pair = object(entry, `environment.normalizedValues[${index}]`);
    exactKeys(pair, `environment.normalizedValues[${index}]`, ['name', 'value']);
    const name = text(pair.name, `environment.normalizedValues[${index}].name`, 128);
    if (!ENVIRONMENT_NAME.test(name) || SECRET_ENVIRONMENT_NAME.test(name)) invalid('raw secret-bearing environment names are prohibited', { name });
    return { name, value: text(pair.value, `environment.normalizedValues[${index}].value`, 4096) };
  }).sort((left, right) => left.name.localeCompare(right.name));
  if (new Set(normalizedValues.map((entry) => entry.name)).size !== normalizedValues.length) invalid('normalized environment names must be unique');
  const normalizedDigest = digest(item.normalizedDigest, 'environment.normalizedDigest');
  if (sha256(canonicalize(normalizedValues)) !== normalizedDigest) invalid('normalized environment digest does not match values');
  return { normalizedValues, normalizedDigest, credentialReferenceIds: stringArray(item.credentialReferenceIds, 'environment.credentialReferenceIds'), credentialPresence: bool(item.credentialPresence, 'environment.credentialPresence') };
}

function validateCode(value: unknown, transactionId: string, source: TransactionSourceBindingV1): TransactionCodeBindingV1 {
  const item = object(value, 'code');
  exactKeys(item, 'code', ['mutationPlan', 'mutationPlanDigest', 'materializationJobId', 'candidateJobIds', 'validationExecutions']);
  const mutationPlan = assertCodeMutationPlan(item.mutationPlan);
  if (mutationPlan.transactionId !== transactionId || mutationPlan.baseCommit !== source.commit || mutationPlan.baseTree !== source.tree) invalid('code mutation plan identity conflicts with transaction source');
  const mutationPlanDigest = digest(item.mutationPlanDigest, 'code.mutationPlanDigest');
  if (mutationPlanDigest !== codeMutationPlanDigest(mutationPlan)) invalid('code mutation plan digest is invalid');
  if (!Array.isArray(item.validationExecutions) || item.validationExecutions.length > 64) invalid('code.validationExecutions must be a bounded array');
  const validationExecutions = item.validationExecutions.map((entry, index) => {
    const execution = object(entry, `code.validationExecutions[${index}]`);
    exactKeys(execution, `code.validationExecutions[${index}]`, ['stepId', 'phase', 'jobId', 'executionPlanDigest', 'argv', 'startedAt', 'completedAt', 'status', 'exitCode', 'signal', 'artifactIds', 'receiptReferences']);
    const status = text(execution.status, `code.validationExecutions[${index}].status`) as CodeValidationExecutionV1['status'];
    if (!['passed', 'failed', 'lost', 'ambiguous'].includes(status)) invalid('code validation execution status is unsupported');
    const exitCode = execution.exitCode === null ? null : integer(execution.exitCode, `code.validationExecutions[${index}].exitCode`);
    return {
      stepId: text(execution.stepId, `code.validationExecutions[${index}].stepId`, 128),
      phase: text(execution.phase, `code.validationExecutions[${index}].phase`, 64) as CodeValidationExecutionV1['phase'],
      jobId: text(execution.jobId, `code.validationExecutions[${index}].jobId`, 256),
      executionPlanDigest: digest(execution.executionPlanDigest, `code.validationExecutions[${index}].executionPlanDigest`),
      argv: stringArray(execution.argv, `code.validationExecutions[${index}].argv`, 128),
      startedAt: timestamp(execution.startedAt, `code.validationExecutions[${index}].startedAt`),
      completedAt: timestamp(execution.completedAt, `code.validationExecutions[${index}].completedAt`), status, exitCode,
      signal: execution.signal === null ? null : text(execution.signal, `code.validationExecutions[${index}].signal`, 64),
      artifactIds: stringArray(execution.artifactIds, `code.validationExecutions[${index}].artifactIds`),
      receiptReferences: stringArray(execution.receiptReferences, `code.validationExecutions[${index}].receiptReferences`),
    };
  });
  return {
    mutationPlan, mutationPlanDigest,
    materializationJobId: item.materializationJobId === null ? null : text(item.materializationJobId, 'code.materializationJobId', 256),
    candidateJobIds: stringArray(item.candidateJobIds, 'code.candidateJobIds'),
    validationExecutions,
  };
}

function validateError(value: unknown): TransactionErrorBindingV1 | null {
  if (value === null) return null;
  const item = object(value, 'error');
  exactKeys(item, 'error', ['code', 'message', 'retryable', 'phase', 'details']);
  return { code: text(item.code, 'error.code', 256), message: text(item.message, 'error.message', 4096), retryable: bool(item.retryable, 'error.retryable'), phase: text(item.phase, 'error.phase', 256), details: jsonObject(item.details, 'error.details') };
}

export function assertTransactionId(value: unknown): string {
  const result = text(value, 'transactionId', 128);
  if (!TRANSACTION_ID.test(result)) invalid('transactionId is invalid');
  return result;
}

export function newTransactionId(): string {
  return `tx_${randomUUID().replaceAll('-', '')}`;
}

export function assertTransactionRecord(value: unknown): DurableTransactionRecordV1 {
  const item = object(value, 'transaction');
  const legacy = item.schemaVersion === TRANSACTION_LEGACY_SCHEMA_VERSION;
  const current = item.schemaVersion === TRANSACTION_SCHEMA_VERSION;
  if (!legacy && !current) invalid('transaction schema version is unsupported', { schemaVersion: item.schemaVersion });
  exactKeys(item, 'transaction', legacy
    ? ['schemaVersion', 'transactionId', 'transactionKind', 'ownerPrincipal', 'creationRequestDigest', 'idempotencyKey', 'lifecycle', 'source', 'policy', 'execution', 'candidate', 'evidence', 'cleanup', 'environment', 'error']
    : ['schemaVersion', 'transactionId', 'transactionKind', 'ownerPrincipal', 'creationRequestDigest', 'idempotencyKey', 'lifecycle', 'source', 'policy', 'execution', 'candidate', 'evidence', 'cleanup', 'environment', 'code', 'error']);
  const transactionKind = text(item.transactionKind, 'transactionKind') as TransactionKind;
  if (!TRANSACTION_KINDS.includes(transactionKind)) invalid('transaction kind is unsupported', { transactionKind });
  const source = validateSource(item.source);
  const record: DurableTransactionRecordV1 = {
    schemaVersion: legacy ? TRANSACTION_LEGACY_SCHEMA_VERSION : TRANSACTION_SCHEMA_VERSION, transactionId: assertTransactionId(item.transactionId), transactionKind,
    ownerPrincipal: text(item.ownerPrincipal, 'ownerPrincipal', 512), creationRequestDigest: digest(item.creationRequestDigest, 'creationRequestDigest'),
    idempotencyKey: text(item.idempotencyKey, 'idempotencyKey', 256), lifecycle: validateLifecycle(item.lifecycle), source,
    policy: validatePolicy(item.policy), execution: validateExecution(item.execution), candidate: legacy ? validateLegacyCandidate(item.candidate, source) : validateCandidate(item.candidate, source),
    evidence: validateEvidence(item.evidence), cleanup: validateCleanup(item.cleanup), environment: validateEnvironment(item.environment),
    code: legacy ? null : validateCode(item.code, assertTransactionId(item.transactionId), source), error: validateError(item.error),
  };
  assertTransactionStateInvariants(record);
  return record;
}

export function assertTransactionStateInvariants(record: DurableTransactionRecordV1): void {
  if (record.lifecycle.persistedState === 'COMMITTED') {
    if (!record.candidate.validationPassed || record.candidate.candidateTree === null || record.candidate.candidateManifestArtifactId === null || record.candidate.validationDigest === null) invalid('COMMITTED requires a durable validated candidate tree and manifest');
    if (record.schemaVersion === TRANSACTION_SCHEMA_VERSION && (record.candidate.patchArtifactId === null || record.candidate.candidateArchiveArtifactId === null)) invalid('V2-C COMMITTED requires complete candidate artifacts');
    if (record.execution.activeJobIds.length > 0 || record.execution.jobTerminalityStatus !== 'all-terminal') invalid('COMMITTED requires all related jobs terminal');
    if (!record.cleanup.completed) invalid('COMMITTED requires completed positive cleanup');
    if (record.evidence.finalEvidenceIndexArtifactId === null || record.evidence.finalEvidenceIndexDigest === null || record.evidence.eventTailDigest === null) invalid('COMMITTED requires complete evidence');
  }
  if (record.lifecycle.persistedState === 'ROLLED_BACK' && record.cleanup.required && !record.cleanup.completed) invalid('ROLLED_BACK cannot hide incomplete cleanup');
  if (record.lifecycle.persistedState === 'FAILED' && record.cleanup.required && !record.cleanup.completed) invalid('FAILED cannot hide unresolved cleanup');
  if (record.lifecycle.persistedState === 'EXPIRED' && record.cleanup.required && !record.cleanup.completed) invalid('EXPIRED cannot bypass cleanup');
}

export function assertTransactionTransition(prior: TransactionState, next: TransactionState): void {
  if (!(TRANSITIONS[prior] as readonly string[]).includes(next)) throw new TransactionError('transaction_illegal_transition', `illegal transaction transition ${prior} -> ${next}`, { prior, next });
  if (prior === 'EXECUTING' && next === 'COMMITTED') throw new TransactionError('transaction_illegal_transition', 'EXECUTING cannot transition directly to COMMITTED');
}

export function transactionRecordDigest(record: DurableTransactionRecordV1): string {
  if (record.schemaVersion === TRANSACTION_LEGACY_SCHEMA_VERSION) {
    const { code: _code, candidate, ...rest } = record;
    const legacyCandidate = {
      candidateId: candidate.candidateId, baseCommit: candidate.baseCommit, baseTree: candidate.baseTree,
      candidateTree: candidate.candidateTree, changedPaths: candidate.changedPaths, patchArtifactId: candidate.patchArtifactId,
      candidateArchiveArtifactId: candidate.candidateArchiveArtifactId, candidateManifestArtifactId: candidate.candidateManifestArtifactId,
      validationDigest: candidate.validationDigest, validationPassed: candidate.validationPassed,
    };
    const legacy = { ...rest, candidate: legacyCandidate };
    assertTransactionRecord(legacy);
    return sha256(canonicalize(legacy));
  }
  return sha256(canonicalize(assertTransactionRecord(record)));
}

export function normalizeTransactionCreateRequest(value: unknown, ownerPrincipal: string, idempotencyKey: string): TransactionCreateRequestV1 {
  const item = object(value, 'create request');
  const allowed = ['schemaVersion', 'transactionKind', 'repository', 'branch', 'commit', 'tree', 'sourceArchiveArtifactId', 'immutableSourceReference', 'sourceManifestDigest', 'packageLockDigest', 'protectedSnapshot', 'expectedSnapshotGuid', 'snapshotCreationTxg', 'policyDecisionDigest', 'selectedEnvironmentClass', 'providerId', 'providerVersion', 'networkMode', 'resourceBoundIdentity', 'normalizedEnvironment', 'credentialReferenceIds', 'credentialPresence', 'mutationPlan'];
  const unknown = Object.keys(item).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw new TransactionError('transaction_invalid_request', 'create request contains unsupported properties', { properties: unknown });
  if (item.schemaVersion !== TRANSACTION_SCHEMA_VERSION) throw new TransactionError('transaction_invalid_request', 'transaction schema version is unsupported');
  const transactionKind = text(item.transactionKind, 'transactionKind') as TransactionKind;
  if (!TRANSACTION_KINDS.includes(transactionKind)) throw new TransactionError('transaction_unknown_kind', 'unknown transaction kind', { transactionKind });
  const normalizedValuesInput = item.normalizedEnvironment ?? [];
  if (!Array.isArray(normalizedValuesInput)) throw new TransactionError('transaction_invalid_request', 'normalizedEnvironment must be an array');
  const normalizedValues = normalizedValuesInput.map((entry, index) => {
    const pair = object(entry, `normalizedEnvironment[${index}]`);
    exactKeys(pair, `normalizedEnvironment[${index}]`, ['name', 'value']);
    const name = text(pair.name, `normalizedEnvironment[${index}].name`, 128);
    if (!ENVIRONMENT_NAME.test(name) || SECRET_ENVIRONMENT_NAME.test(name)) throw new TransactionError('transaction_secret_rejected', 'raw secret-bearing environment values are prohibited', { name });
    return { name, value: text(pair.value, `normalizedEnvironment[${index}].value`, 4096) };
  }).sort((left, right) => left.name.localeCompare(right.name));
  if (new Set(normalizedValues.map((entry) => entry.name)).size !== normalizedValues.length) throw new TransactionError('transaction_invalid_request', 'normalized environment names must be unique');
  const normalizedCommit = gitIdentity(item.commit, 'commit');
  const normalizedTree = gitIdentity(item.tree, 'tree');
  const normalizedPlan = normalizeCodeMutationPlan(item.mutationPlan, 'tx_pending0000000000000000', normalizedCommit, normalizedTree);
  const mutationPlan = Object.fromEntries(Object.entries(normalizedPlan).filter(([key]) => key !== 'transactionId')) as JsonObject;
  const policy = validatePolicy({
    policyDecisionDigest: item.policyDecisionDigest, selectedEnvironmentClass: item.selectedEnvironmentClass,
    providerId: item.providerId, providerVersion: item.providerVersion, networkMode: item.networkMode, resourceBoundIdentity: item.resourceBoundIdentity,
  });
  return {
    schemaVersion: TRANSACTION_SCHEMA_VERSION, transactionKind, repository: text(item.repository, 'repository', 1024),
    ...(item.branch === undefined ? {} : { branch: text(item.branch, 'branch', 1024) }), commit: normalizedCommit, tree: normalizedTree,
    ...(item.sourceArchiveArtifactId === undefined ? {} : { sourceArchiveArtifactId: text(item.sourceArchiveArtifactId, 'sourceArchiveArtifactId', 256) }),
    immutableSourceReference: text(item.immutableSourceReference, 'immutableSourceReference', 2048), sourceManifestDigest: digest(item.sourceManifestDigest, 'sourceManifestDigest'),
    ...(item.packageLockDigest === undefined ? {} : { packageLockDigest: digest(item.packageLockDigest, 'packageLockDigest') }),
    protectedSnapshot: safeId(item.protectedSnapshot, 'protectedSnapshot'), expectedSnapshotGuid: text(item.expectedSnapshotGuid, 'expectedSnapshotGuid', 64),
    snapshotCreationTxg: text(item.snapshotCreationTxg, 'snapshotCreationTxg', 64), policyDecisionDigest: policy.policyDecisionDigest,
    selectedEnvironmentClass: policy.selectedEnvironmentClass, providerId: policy.providerId, providerVersion: policy.providerVersion, networkMode: 'none',
    resourceBoundIdentity: policy.resourceBoundIdentity, normalizedEnvironment: normalizedValues,
    credentialReferenceIds: item.credentialReferenceIds === undefined ? [] : stringArray(item.credentialReferenceIds, 'credentialReferenceIds'),
    credentialPresence: item.credentialPresence === undefined ? false : bool(item.credentialPresence, 'credentialPresence'),
    mutationPlan,
  };
}

export function transactionCreationDigest(request: TransactionCreateRequestV1, ownerPrincipal: string): string {
  return sha256(canonicalize({ ownerPrincipal, request }));
}

export function initialTransactionRecord(request: TransactionCreateRequestV1, ownerPrincipal: string, idempotencyKey: string, transactionId: string, occurredAt: string): DurableTransactionRecordV1 {
  const normalizedValues = request.normalizedEnvironment ?? [];
  const record: DurableTransactionRecordV1 = {
    schemaVersion: TRANSACTION_SCHEMA_VERSION, transactionId: assertTransactionId(transactionId), transactionKind: request.transactionKind,
    ownerPrincipal: text(ownerPrincipal, 'ownerPrincipal', 512), creationRequestDigest: transactionCreationDigest(request, ownerPrincipal), idempotencyKey: text(idempotencyKey, 'idempotencyKey', 256),
    lifecycle: { persistedState: 'REQUESTED', desiredState: 'COMMITTED', stateSequence: 1, terminal: false, createdAt: timestamp(occurredAt, 'occurredAt'), updatedAt: occurredAt, completedAt: null },
    source: {
      repository: request.repository, branch: request.branch ?? null, commit: request.commit, tree: request.tree,
      sourceArchiveArtifactId: request.sourceArchiveArtifactId ?? null, immutableSourceReference: request.immutableSourceReference,
      sourceManifestDigest: request.sourceManifestDigest, packageLockDigest: request.packageLockDigest ?? null,
      protectedSnapshot: request.protectedSnapshot, expectedSnapshotGuid: request.expectedSnapshotGuid, observedSnapshotGuid: null,
      snapshotCreationTxg: request.snapshotCreationTxg, sourceVerifiedAt: null,
    },
    policy: {
      policyDecisionDigest: request.policyDecisionDigest, selectedEnvironmentClass: request.selectedEnvironmentClass,
      providerId: request.providerId, providerVersion: request.providerVersion, networkMode: 'none', resourceBoundIdentity: structuredClone(request.resourceBoundIdentity),
    },
    execution: { machineIds: [], activeJobIds: [], allRelatedJobIds: [], mutationJobIds: [], validationJobIds: [], jobTerminalityStatus: 'not-observed', mutationSubmitted: false, validationSubmitted: false },
    candidate: { candidateId: null, baseCommit: request.commit, baseTree: request.tree, candidateTree: null, changedPaths: [], addedFiles: [], deletedFiles: [], modifiedFiles: [], fileModeChanges: [], symlinkChanges: [], pathChanges: [], patchArtifactId: null, candidateArchiveArtifactId: null, candidateManifestArtifactId: null, validationDigest: null, mutationPlanDigest: '0'.repeat(64), validationPassed: false },
    evidence: { artifactIds: [], receiptReferences: [], eventTailDigest: null, finalEvidenceIndexArtifactId: null, finalEvidenceIndexDigest: null },
    cleanup: { required: false, requested: false, completed: false, machineAbsenceVerified: false, processAbsenceVerified: false, mountAbsenceVerified: false, rootPathAbsenceVerified: false, datasetAbsenceVerified: false, sourcePreserved: false, completedAt: null },
    environment: { normalizedValues, normalizedDigest: sha256(canonicalize(normalizedValues)), credentialReferenceIds: request.credentialReferenceIds ?? [], credentialPresence: request.credentialPresence ?? false },
    code: (() => {
      const mutationPlan = normalizeCodeMutationPlan(request.mutationPlan, transactionId, request.commit, request.tree);
      const mutationPlanDigest = codeMutationPlanDigest(mutationPlan);
      return { mutationPlan, mutationPlanDigest, materializationJobId: null, candidateJobIds: [], validationExecutions: [] };
    })(),
    error: null,
  };
  record.candidate.mutationPlanDigest = record.code.mutationPlanDigest;
  return assertTransactionRecord(record);
}

export interface TransactionEventDraft {
  transactionId: string;
  ownerPrincipal: string;
  operation: string;
  phase: string;
  priorState: TransactionState | null;
  nextState: TransactionState;
  priorSequence: number;
  nextSequence: number;
  requestDigest: string;
  idempotencyKey?: string | null;
  occurredAt: string;
  previousEventDigest?: string | null;
  machineId?: string | null;
  jobIds?: string[];
  candidateId?: string | null;
  candidateTree?: string | null;
  observationDigest?: string | null;
}

export function createTransactionEvent(draft: TransactionEventDraft): TransactionEventV1 {
  const canonicalDraft = {
    schemaVersion: TRANSACTION_EVENT_SCHEMA_VERSION, transactionId: assertTransactionId(draft.transactionId), ownerPrincipal: text(draft.ownerPrincipal, 'ownerPrincipal', 512),
    operation: text(draft.operation, 'operation', 256), phase: text(draft.phase, 'phase', 256), priorState: draft.priorState,
    nextState: draft.nextState, priorSequence: integer(draft.priorSequence, 'priorSequence'), nextSequence: integer(draft.nextSequence, 'nextSequence', 1),
    requestDigest: digest(draft.requestDigest, 'requestDigest'), idempotencyKey: draft.idempotencyKey ?? null, occurredAt: timestamp(draft.occurredAt, 'occurredAt'),
    previousEventDigest: draft.previousEventDigest ?? null, machineId: draft.machineId ?? null, jobIds: draft.jobIds ?? [], candidateId: draft.candidateId ?? null,
    candidateTree: draft.candidateTree ?? null, observationDigest: draft.observationDigest ?? null,
  };
  if (canonicalDraft.priorState !== null && !TRANSACTION_STATES.includes(canonicalDraft.priorState)) invalid('event prior state is unsupported');
  if (!TRANSACTION_STATES.includes(canonicalDraft.nextState)) invalid('event next state is unsupported');
  if (canonicalDraft.nextSequence !== canonicalDraft.priorSequence + 1 && !(canonicalDraft.priorSequence === canonicalDraft.nextSequence && canonicalDraft.priorState === canonicalDraft.nextState)) invalid('event sequence is discontinuous');
  if (canonicalDraft.previousEventDigest !== null) digest(canonicalDraft.previousEventDigest, 'previousEventDigest');
  if (canonicalDraft.candidateTree !== null) gitIdentity(canonicalDraft.candidateTree, 'candidateTree');
  if (canonicalDraft.observationDigest !== null) digest(canonicalDraft.observationDigest, 'observationDigest');
  stringArray(canonicalDraft.jobIds, 'jobIds');
  const eventDigest = sha256(canonicalize(canonicalDraft));
  return { ...canonicalDraft, eventId: `te_${eventDigest.slice(0, 32)}`, eventDigest };
}

export function assertTransactionEvent(value: unknown): TransactionEventV1 {
  const item = object(value, 'transaction event');
  exactKeys(item, 'transaction event', ['schemaVersion', 'eventId', 'transactionId', 'ownerPrincipal', 'operation', 'phase', 'priorState', 'nextState', 'priorSequence', 'nextSequence', 'requestDigest', 'idempotencyKey', 'occurredAt', 'previousEventDigest', 'eventDigest', 'machineId', 'jobIds', 'candidateId', 'candidateTree', 'observationDigest']);
  const recreated = createTransactionEvent({
    transactionId: assertTransactionId(item.transactionId), ownerPrincipal: text(item.ownerPrincipal, 'ownerPrincipal', 512), operation: text(item.operation, 'operation', 256),
    phase: text(item.phase, 'phase', 256), priorState: item.priorState as TransactionState | null, nextState: item.nextState as TransactionState,
    priorSequence: integer(item.priorSequence, 'priorSequence'), nextSequence: integer(item.nextSequence, 'nextSequence', 1), requestDigest: digest(item.requestDigest, 'requestDigest'),
    idempotencyKey: item.idempotencyKey === null ? null : text(item.idempotencyKey, 'idempotencyKey', 256), occurredAt: timestamp(item.occurredAt, 'occurredAt'),
    previousEventDigest: item.previousEventDigest === null ? null : digest(item.previousEventDigest, 'previousEventDigest'),
    machineId: item.machineId === null ? null : text(item.machineId, 'machineId', 256), jobIds: stringArray(item.jobIds, 'jobIds'),
    candidateId: item.candidateId === null ? null : text(item.candidateId, 'candidateId', 256), candidateTree: nullableGitIdentity(item.candidateTree, 'candidateTree'),
    observationDigest: nullableDigest(item.observationDigest, 'observationDigest'),
  });
  if (item.eventId !== recreated.eventId || item.eventDigest !== recreated.eventDigest) invalid('transaction event digest is invalid');
  return recreated;
}

export function assertTransactionLease(value: unknown): TransactionControllerLeaseV1 {
  const item = object(value, 'transaction lease');
  exactKeys(item, 'transaction lease', ['schemaVersion', 'leaseId', 'transactionId', 'ownerPrincipal', 'controllerId', 'hostBootId', 'operation', 'acquiredAt', 'expiresAt', 'renewedAt', 'takeoverFromLeaseId']);
  if (item.schemaVersion !== TRANSACTION_LEASE_SCHEMA_VERSION) invalid('transaction lease schema version is unsupported');
  return {
    schemaVersion: TRANSACTION_LEASE_SCHEMA_VERSION, leaseId: safeId(item.leaseId, 'leaseId'), transactionId: assertTransactionId(item.transactionId),
    ownerPrincipal: text(item.ownerPrincipal, 'ownerPrincipal', 512), controllerId: safeId(item.controllerId, 'controllerId'), hostBootId: text(item.hostBootId, 'hostBootId', 256),
    operation: text(item.operation, 'operation', 256), acquiredAt: timestamp(item.acquiredAt, 'acquiredAt'), expiresAt: timestamp(item.expiresAt, 'expiresAt'),
    renewedAt: nullableTimestamp(item.renewedAt, 'renewedAt'), takeoverFromLeaseId: nullableText(item.takeoverFromLeaseId, 'takeoverFromLeaseId', 256),
  };
}

const REDACTED = '[REDACTED]';
const SENSITIVE_DETAIL_KEY = /(secret|token|password|passphrase|private|credential|authorization|cookie|key)/iu;

export function redactTransactionDetails(value: unknown, depth = 0): JsonObject {
  if (depth > 6) return { truncated: true };
  const input = value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : { value };
  const entries = Object.entries(input).slice(0, 100).map(([key, entry]) => {
    if (SENSITIVE_DETAIL_KEY.test(key)) return [key, REDACTED];
    if (typeof entry === 'string') return [key, entry.length > 1024 ? `${entry.slice(0, 1024)}…` : entry];
    if (entry !== null && typeof entry === 'object') {
      if (Array.isArray(entry)) return [key, entry.slice(0, 100).map((item) => typeof item === 'string' ? item.slice(0, 1024) : '[OBJECT]')];
      return [key, redactTransactionDetails(entry, depth + 1)];
    }
    return [key, entry];
  });
  return Object.fromEntries(entries) as JsonObject;
}
