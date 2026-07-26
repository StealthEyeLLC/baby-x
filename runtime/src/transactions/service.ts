import { hostname } from 'node:os';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize, sha256, type JobRecord, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { assertProviderCompatibility } from '../compatibility/manifest.ts';
import {
  TRANSACTION_SCHEMA_VERSION,
  TRANSACTION_STATES,
  TransactionError,
  assertTransactionId,
  initialTransactionRecord,
  newTransactionId,
  normalizeTransactionCreateRequest,
  redactTransactionDetails,
  type DurableTransactionRecordV1,
  type TransactionControllerLeaseV1,
  type TransactionErrorBindingV1,
  type TransactionState,
} from './schemas.ts';
import { DurableTransactionStore, type TransactionMutationDetails, type TransactionRecordPatch } from './store.ts';
import type { CodePathChangeV1, CodeValidationExecutionV1 } from './code-schemas.ts';

export interface TransactionOperationContext extends RuntimeExecutionContext {}

export interface TransactionMachineSurface {
  get(payload: JsonObject, context: RuntimeExecutionContext): JsonObject;
  status(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  stop(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  destroy(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  reconcile(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
}

export interface TransactionJobSurface {
  get(id: string): JobRecord;
  reconcile(id: string): JobRecord;
  cancel(id: string, signal?: string): JobRecord;
}

export interface TransactionArtifactSurface {
  get(id: string): JsonObject;
  verify?(id: string): JsonObject;
}

export interface TransactionCheckpointResult {
  observedSnapshotGuid: string;
  snapshotCreationTxg: string;
  sourceVerifiedAt: string;
  observationDigest: string;
  machineIds: string[];
}

export interface TransactionExecutionResult {
  machineIds: string[];
  allRelatedJobIds: string[];
  mutationJobIds: string[];
  activeJobIds: string[];
  materializationJobId: string;
}

export interface TransactionValidationResult {
  allRelatedJobIds: string[];
  validationJobIds: string[];
  activeJobIds: string[];
  validationExecutions: CodeValidationExecutionV1[];
}

export interface TransactionCandidateResult {
  candidateId: string;
  candidateTree: string;
  changedPaths: string[];
  pathChanges: CodePathChangeV1[];
  addedFiles: string[];
  deletedFiles: string[];
  modifiedFiles: string[];
  fileModeChanges: string[];
  symlinkChanges: string[];
  patchArtifactId: string;
  candidateArchiveArtifactId: string;
  candidateManifestArtifactId: string;
  validationDigest: string;
  validationPassed: true;
  artifactIds: string[];
  receiptReferences: string[];
  candidateJobIds: string[];
  validationExecutions: CodeValidationExecutionV1[];
}

export interface TransactionEvidenceResult {
  finalEvidenceIndexArtifactId: string;
  finalEvidenceIndexDigest: string;
  artifactIds: string[];
  receiptReferences: string[];
}

export interface TransactionCodeDriver {
  checkpoint(record: DurableTransactionRecordV1, context: TransactionOperationContext): Promise<TransactionCheckpointResult>;
  execute(record: DurableTransactionRecordV1, context: TransactionOperationContext): Promise<TransactionExecutionResult>;
  validate(record: DurableTransactionRecordV1, context: TransactionOperationContext): Promise<TransactionValidationResult>;
  finalize(record: DurableTransactionRecordV1, context: TransactionOperationContext): Promise<TransactionCandidateResult>;
  completeEvidence?(record: DurableTransactionRecordV1, context: TransactionOperationContext): Promise<TransactionEvidenceResult>;
}

export interface TransactionServiceOptions {
  stateRoot: string;
  machine: TransactionMachineSurface;
  jobs: TransactionJobSurface;
  artifacts: TransactionArtifactSurface;
  codeDriver?: TransactionCodeDriver;
  store?: DurableTransactionStore;
  now?: () => string;
  transactionIdFactory?: () => string;
  controllerId?: string;
  hostBootId?: string;
  leaseDurationMs?: number;
  startupReconcileLimit?: number;
  maximumListLimit?: number;
  maximumEventLimit?: number;
  controllerAbsent?: (lease: TransactionControllerLeaseV1) => boolean;
}

interface MutationRequest {
  transactionId: string;
  expectedSequence: number;
  reason?: string;
}

interface ReplayResult {
  record: DurableTransactionRecordV1;
  requestDigest: string;
  replayed: boolean;
}

interface JobObservation {
  records: JobRecord[];
  activeJobIds: string[];
  allTerminal: boolean;
  allSuccessful: boolean;
  ambiguous: boolean;
}

function serviceError(code: string, message: string, details: Readonly<Record<string, unknown>> = {}): TransactionError {
  return new TransactionError(code, message, details);
}

function requiredMutationContext(context: TransactionOperationContext): { idempotencyKey: string; subject: string } {
  if (typeof context.idempotencyKey !== 'string' || context.idempotencyKey.length < 8 || context.idempotencyKey.length > 256 || context.idempotencyKey.includes('\0')) throw serviceError('transaction_invalid_request', 'a bounded idempotencyKey is required for transaction mutation');
  if (typeof context.subject !== 'string' || context.subject.length === 0 || context.subject.length > 512 || context.subject.includes('\0')) throw serviceError('transaction_invalid_request', 'authenticated subject is required');
  return { idempotencyKey: context.idempotencyKey, subject: context.subject };
}

function requiredReadSubject(context: TransactionOperationContext): string {
  if (typeof context.subject !== 'string' || context.subject.length === 0 || context.subject.includes('\0')) throw serviceError('transaction_invalid_request', 'authenticated subject is required');
  return context.subject;
}

function authorizeRead(record: DurableTransactionRecordV1, context: TransactionOperationContext): void {
  if (context.authorityClass === 'unrestricted-owner') return;
  if (record.ownerPrincipal !== requiredReadSubject(context)) throw serviceError('transaction_not_found', 'transaction not found');
}

function authorizeMutation(record: DurableTransactionRecordV1, subject: string): void {
  if (record.ownerPrincipal !== subject) throw serviceError('transaction_wrong_principal', 'transaction mutation principal does not own the record');
}

function assertKeys(payload: JsonObject, allowed: readonly string[]): void {
  const unknown = Object.keys(payload).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw serviceError('transaction_invalid_request', 'request contains unsupported properties', { properties: unknown });
}

function expectedSequence(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1) throw serviceError('transaction_invalid_request', 'expectedSequence must be a positive safe integer');
  return Number(value);
}

function bounded(value: unknown, field: string, fallback: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || Number(value) < 0 || Number(value) > maximum) throw serviceError('transaction_invalid_request', `${field} is out of bounds`, { maximum });
  return Number(value);
}

function publicRecord(record: DurableTransactionRecordV1): JsonObject {
  return JSON.parse(canonicalize(record)) as JsonObject;
}

function summary(record: DurableTransactionRecordV1): JsonObject {
  return {
    transactionId: record.transactionId, transactionKind: record.transactionKind, ownerPrincipal: record.ownerPrincipal,
    persistedState: record.lifecycle.persistedState, desiredState: record.lifecycle.desiredState, stateSequence: record.lifecycle.stateSequence,
    terminal: record.lifecycle.terminal, repository: record.source.repository, commit: record.source.commit, tree: record.source.tree,
    candidateTree: record.candidate.candidateTree, machineIds: [...record.execution.machineIds], activeJobIds: [...record.execution.activeJobIds],
    createdAt: record.lifecycle.createdAt, updatedAt: record.lifecycle.updatedAt, completedAt: record.lifecycle.completedAt,
  };
}

function nestedObject(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw serviceError('transaction_child_truth_invalid', `${field} is not an object`);
  return value as Record<string, unknown>;
}

function machineRecord(result: JsonObject): Record<string, unknown> {
  return nestedObject(result.machine, 'machine response');
}

function machineLifecycle(record: Record<string, unknown>): { state: string; sequence: number; terminal: boolean } {
  const lifecycle = nestedObject(record.lifecycle, 'machine lifecycle');
  const state = String(lifecycle.persistedState ?? 'UNKNOWN');
  const sequence = Number(lifecycle.stateSequence);
  if (!Number.isSafeInteger(sequence) || sequence < 1) throw serviceError('transaction_child_truth_invalid', 'machine sequence is invalid');
  return { state, sequence, terminal: lifecycle.terminal === true };
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function stringList(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string' || entry.length === 0)) throw serviceError('transaction_phase_result_invalid', `${field} must be an array of strings`);
  return unique(value as string[]);
}

function errorBinding(code: string, message: string, retryable: boolean, phase: string, details: unknown = {}): TransactionErrorBindingV1 {
  return { code, message: message.slice(0, 4096), retryable, phase, details: redactTransactionDetails(details) };
}

function bootId(): string {
  return existsSync('/proc/sys/kernel/random/boot_id') ? readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim() : sha256(hostname());
}

export class TransactionService {
  readonly store: DurableTransactionStore;
  private readonly now: () => string;
  private readonly transactionIdFactory: () => string;
  private readonly controllerId: string;
  private readonly hostBootId: string;
  private readonly leaseDurationMs: number;
  private readonly startupReconcileLimit: number;
  private readonly maximumListLimit: number;
  private readonly maximumEventLimit: number;
  private readonly controllerAbsent: (lease: TransactionControllerLeaseV1) => boolean;

  constructor(private readonly options: TransactionServiceOptions) {
    this.store = options.store ?? new DurableTransactionStore(join(options.stateRoot, 'transactions'));
    this.now = options.now ?? (() => new Date().toISOString());
    this.transactionIdFactory = options.transactionIdFactory ?? newTransactionId;
    this.controllerId = options.controllerId ?? `transaction-controller-${hostname()}`;
    this.hostBootId = options.hostBootId ?? bootId();
    this.leaseDurationMs = options.leaseDurationMs ?? 30_000;
    this.startupReconcileLimit = options.startupReconcileLimit ?? 100;
    this.maximumListLimit = options.maximumListLimit ?? 1_000;
    this.maximumEventLimit = options.maximumEventLimit ?? 1_000;
    this.controllerAbsent = options.controllerAbsent ?? (() => false);
  }

  describe(): JsonObject {
    return {
      operation: 'babyx.transaction.describe', service: 'baby-x-transaction-service', schemaVersion: TRANSACTION_SCHEMA_VERSION,
      lifecycleAuthority: 'transaction-service', processAuthority: 'baby-x-durable-jobs', machineLifecycleAuthority: 'disposable-machine-service',
      artifactAuthority: 'baby-x-artifacts', certificationAuthority: 'baby-x-certification', executionPolicyAuthority: 'baby-x-execution-policy',
      executableKinds: ['CODE_MUTATION'], states: [...TRANSACTION_STATES],
      operations: ['babyx.transaction.create', 'babyx.transaction.get', 'babyx.transaction.list', 'babyx.transaction.events', 'babyx.transaction.status', 'babyx.transaction.execute', 'babyx.transaction.validate', 'babyx.transaction.finalize', 'babyx.transaction.rollback', 'babyx.transaction.reconcile', 'babyx.transaction.expire', 'babyx.transaction.gc'],
      limits: { startupReconcileLimit: this.startupReconcileLimit, maximumListLimit: this.maximumListLimit, maximumEventLimit: this.maximumEventLimit },
      boundaries: { merge: false, deployment: false, releaseActivation: false, directProcess: false, directProvider: false },
    };
  }

  async initialize(): Promise<JsonObject> {
    const verification = this.store.initialize();
    const eligible = this.store.scan(this.startupReconcileLimit).records.filter((record) => !record.lifecycle.terminal);
    const results: JsonObject[] = [];
    for (const record of eligible) {
      try {
        results.push(await this.reconcile(
          { transactionId: record.transactionId, expectedSequence: record.lifecycle.stateSequence, reason: 'bounded startup reconciliation' },
          { subject: record.ownerPrincipal, authorityClass: 'unrestricted-owner', idempotencyKey: `startup:${this.hostBootId}:${record.transactionId}:${record.lifecycle.stateSequence}` },
        ));
      } catch (error) {
        results.push({ transactionId: record.transactionId, deferred: true, error: { code: error instanceof TransactionError ? error.code : 'transaction_startup_reconcile_failed', message: error instanceof Error ? error.message : String(error) } });
      }
    }
    return { operation: 'babyx.transaction.reconcile', startup: true, verification, processed: results.length, bounded: true, results };
  }

  create(payload: JsonObject, context: TransactionOperationContext): JsonObject {
    const authenticated = requiredMutationContext(context);
    const request = normalizeTransactionCreateRequest(payload, authenticated.subject, authenticated.idempotencyKey);
    assertProviderCompatibility(request.providerId, request.providerVersion);
    const transactionId = this.transactionIdFactory();
    const occurredAt = this.now();
    const candidate = initialTransactionRecord(request, authenticated.subject, authenticated.idempotencyKey, transactionId, occurredAt);
    const record = this.store.create(candidate, {
      operation: 'babyx.transaction.create', phase: 'request', requestDigest: candidate.creationRequestDigest,
      idempotencyKey: authenticated.idempotencyKey, occurredAt,
    });
    return { operation: 'babyx.transaction.create', transaction: publicRecord(record), replayed: record.transactionId !== transactionId };
  }

  get(payload: JsonObject, context: TransactionOperationContext): JsonObject {
    assertKeys(payload, ['transactionId']);
    const record = this.store.get(assertTransactionId(payload.transactionId));
    authorizeRead(record, context);
    return { operation: 'babyx.transaction.get', transaction: publicRecord(record) };
  }

  list(payload: JsonObject = {}, context: TransactionOperationContext): JsonObject {
    assertKeys(payload, ['ownerPrincipal', 'state', 'terminal', 'offset', 'limit']);
    const requestedOwner = payload.ownerPrincipal === undefined ? undefined : String(payload.ownerPrincipal);
    const subject = context.authorityClass === 'unrestricted-owner' ? undefined : requiredReadSubject(context);
    if (subject !== undefined && requestedOwner !== undefined && requestedOwner !== subject) throw serviceError('transaction_not_found', 'owner scope is not accessible');
    const owner = subject ?? requestedOwner;
    const state = payload.state === undefined ? undefined : String(payload.state) as TransactionState;
    if (state !== undefined && !TRANSACTION_STATES.includes(state)) throw serviceError('transaction_invalid_request', 'state filter is unsupported');
    if (payload.terminal !== undefined && typeof payload.terminal !== 'boolean') throw serviceError('transaction_invalid_request', 'terminal must be a boolean');
    const offset = bounded(payload.offset, 'offset', 0, Number.MAX_SAFE_INTEGER);
    const limit = bounded(payload.limit, 'limit', Math.min(100, this.maximumListLimit), this.maximumListLimit);
    const filtered = this.store.list().filter((record) => (owner === undefined || record.ownerPrincipal === owner)
      && (state === undefined || record.lifecycle.persistedState === state)
      && (payload.terminal === undefined || record.lifecycle.terminal === payload.terminal));
    const selected = filtered.slice(offset, offset + limit).map(summary);
    return { operation: 'babyx.transaction.list', transactions: selected, offset, limit, total: filtered.length, nextOffset: offset + selected.length < filtered.length ? offset + selected.length : null };
  }

  events(payload: JsonObject, context: TransactionOperationContext): JsonObject {
    assertKeys(payload, ['transactionId', 'offset', 'limit']);
    const transactionId = assertTransactionId(payload.transactionId);
    const record = this.store.get(transactionId);
    authorizeRead(record, context);
    const offset = bounded(payload.offset, 'offset', 0, Number.MAX_SAFE_INTEGER);
    const limit = bounded(payload.limit, 'limit', Math.min(100, this.maximumEventLimit), this.maximumEventLimit);
    const events = this.store.events(transactionId, offset, limit);
    return { operation: 'babyx.transaction.events', transactionId, events: events.map((event) => JSON.parse(canonicalize(event)) as JsonObject), offset, limit, nextOffset: events.length === limit ? offset + events.length : null };
  }

  status(payload: JsonObject, context: TransactionOperationContext): JsonObject {
    assertKeys(payload, ['transactionId']);
    const record = this.store.get(assertTransactionId(payload.transactionId));
    authorizeRead(record, context);
    const jobs = record.execution.allRelatedJobIds.map((jobId) => {
      try {
        const job = this.options.jobs.get(jobId);
        return { jobId, status: job.status, exitCode: job.exitCode ?? null, signal: job.signal ?? null };
      } catch (error) { return { jobId, status: 'unknown', error: error instanceof Error ? error.message : String(error) }; }
    });
    const predicates = {
      exactSourceVerified: record.source.sourceVerifiedAt !== null && record.source.observedSnapshotGuid === record.source.expectedSnapshotGuid,
      candidateDurable: record.candidate.candidateTree !== null && record.candidate.candidateManifestArtifactId !== null,
      validationPassed: record.candidate.validationPassed,
      allJobsTerminal: record.execution.jobTerminalityStatus === 'all-terminal' && record.execution.activeJobIds.length === 0,
      cleanupComplete: record.cleanup.completed,
      evidenceComplete: record.evidence.finalEvidenceIndexArtifactId !== null && record.evidence.finalEvidenceIndexDigest !== null,
    };
    return { operation: 'babyx.transaction.status', transaction: summary(record), jobs, predicates, truthful: true, recommendedAction: record.lifecycle.persistedState === 'AMBIGUOUS' ? 'manual identity proof required' : record.lifecycle.persistedState === 'RECOVERY_REQUIRED' ? 'retry canonical reconciliation' : 'none' };
  }

  private mutationRequest(operation: string, payload: JsonObject, context: TransactionOperationContext, allowedExtra: readonly string[] = []): ReplayResult {
    assertKeys(payload, ['transactionId', 'expectedSequence', 'reason', ...allowedExtra]);
    const authenticated = requiredMutationContext(context);
    const transactionId = assertTransactionId(payload.transactionId);
    const record = this.store.get(transactionId);
    authorizeMutation(record, authenticated.subject);
    const requestDigest = sha256(canonicalize({ operation, payload }));
    const events = this.store.events(transactionId, 0, this.maximumEventLimit);
    const matching = events.filter((event) => event.idempotencyKey === authenticated.idempotencyKey);
    if (matching.some((event) => event.requestDigest !== requestDigest)) throw serviceError('transaction_idempotency_conflict', 'idempotency key was reused with a conflicting mutation request');
    if (matching.some((event) => event.operation === operation && event.requestDigest === requestDigest)) return { record, requestDigest, replayed: true };
    const expected = expectedSequence(payload.expectedSequence);
    if (record.lifecycle.stateSequence !== expected) throw serviceError('transaction_stale_sequence', 'expected sequence does not match durable transaction truth', { expectedSequence: expected, actualSequence: record.lifecycle.stateSequence });
    return { record, requestDigest, replayed: false };
  }

  private acquireLease(record: DurableTransactionRecordV1, operation: string): TransactionControllerLeaseV1 {
    const existing = this.store.activeLease(record.transactionId);
    if (existing !== null && existing.ownerPrincipal === record.ownerPrincipal && existing.controllerId === this.controllerId && existing.hostBootId === this.hostBootId) return existing;
    const acquiredAt = this.now();
    return this.store.acquireLease({
      schemaVersion: '1.0.0', leaseId: this.store.newLeaseId(), transactionId: record.transactionId, ownerPrincipal: record.ownerPrincipal,
      controllerId: this.controllerId, hostBootId: this.hostBootId, operation, acquiredAt,
      expiresAt: new Date(Date.parse(acquiredAt) + this.leaseDurationMs).toISOString(), renewedAt: null, takeoverFromLeaseId: null,
    }, { observedAt: acquiredAt, currentControllerAbsent: existing === null ? true : this.controllerAbsent(existing) });
  }

  private releaseLease(record: DurableTransactionRecordV1, lease: TransactionControllerLeaseV1): void {
    this.store.releaseLease(record.transactionId, lease.leaseId, record.ownerPrincipal, this.controllerId);
  }

  private details(operation: string, phase: string, requestDigest: string, context: TransactionOperationContext, extra: Partial<TransactionMutationDetails> = {}): TransactionMutationDetails {
    return { operation, phase, requestDigest, idempotencyKey: context.idempotencyKey ?? null, occurredAt: this.now(), ...extra };
  }

  async execute(payload: JsonObject, context: TransactionOperationContext): Promise<JsonObject> {
    const prelude = this.mutationRequest('babyx.transaction.execute', payload, context);
    if (prelude.replayed) return { operation: 'babyx.transaction.execute', transaction: publicRecord(prelude.record), replayed: true };
    if (this.options.codeDriver === undefined) throw serviceError('transaction_phase_unavailable', 'disposable code transaction driver is unavailable');
    const lease = this.acquireLease(prelude.record, 'babyx.transaction.execute');
    let current = prelude.record;
    try {
      if (current.lifecycle.persistedState === 'REQUESTED') {
        current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'CHECKPOINTING', this.details('babyx.transaction.execute', 'checkpoint-intent', prelude.requestDigest, context));
      }
      if (current.lifecycle.persistedState === 'CHECKPOINTING') {
        let checkpoint: TransactionCheckpointResult;
        try { checkpoint = await this.options.codeDriver.checkpoint(current, context); }
        catch (error) {
          const failed = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'FAILED', this.details('babyx.transaction.execute', 'checkpoint-failed', prelude.requestDigest, context), { error: errorBinding('transaction_checkpoint_failed', error instanceof Error ? error.message : String(error), false, 'checkpoint', error) });
          return { operation: 'babyx.transaction.execute', transaction: publicRecord(failed), replayed: false };
        }
        if (checkpoint.observedSnapshotGuid !== current.source.expectedSnapshotGuid || checkpoint.snapshotCreationTxg !== current.source.snapshotCreationTxg) {
          const failed = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'FAILED', this.details('babyx.transaction.execute', 'checkpoint-mismatch', prelude.requestDigest, context, { observationDigest: checkpoint.observationDigest }), { error: errorBinding('transaction_source_mismatch', 'source snapshot identity does not match the bound transaction baseline', false, 'checkpoint', checkpoint) });
          return { operation: 'babyx.transaction.execute', transaction: publicRecord(failed), replayed: false };
        }
        const checkpointMachineIds = stringList(checkpoint.machineIds, 'checkpoint.machineIds');
        current = this.store.update(current.transactionId, current.lifecycle.stateSequence, this.details('babyx.transaction.execute', 'checkpoint-readback', prelude.requestDigest, context, { observationDigest: checkpoint.observationDigest, machineId: checkpointMachineIds[0] ?? null }), {
          source: { observedSnapshotGuid: checkpoint.observedSnapshotGuid, sourceVerifiedAt: checkpoint.sourceVerifiedAt },
          execution: { machineIds: checkpointMachineIds },
          cleanup: { required: checkpointMachineIds.length > 0, sourcePreserved: true },
        });
        current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'READY', this.details('babyx.transaction.execute', 'checkpoint-complete', prelude.requestDigest, context));
      }
      if (current.lifecycle.persistedState !== 'READY') throw serviceError('transaction_state_conflict', 'execute requires REQUESTED, CHECKPOINTING, or READY state', { state: current.lifecycle.persistedState });
      let result: TransactionExecutionResult;
      try { result = await this.options.codeDriver.execute(current, context); }
      catch (error) {
        const uncertain = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'RECOVERY_REQUIRED', this.details('babyx.transaction.execute', 'execution-response-lost', prelude.requestDigest, context), { error: errorBinding('transaction_execution_uncertain', error instanceof Error ? error.message : String(error), true, 'execution', error) });
        return { operation: 'babyx.transaction.execute', transaction: publicRecord(uncertain), replayed: false };
      }
      const machineIds = stringList(result.machineIds, 'machineIds');
      const allRelatedJobIds = stringList(result.allRelatedJobIds, 'allRelatedJobIds');
      const mutationJobIds = stringList(result.mutationJobIds, 'mutationJobIds');
      const activeJobIds = stringList(result.activeJobIds, 'activeJobIds');
      for (const id of [...mutationJobIds, ...activeJobIds]) if (!allRelatedJobIds.includes(id)) throw serviceError('transaction_phase_result_invalid', 'execution job subsets are not bound to allRelatedJobIds');
      current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'EXECUTING', this.details('babyx.transaction.execute', 'mutation-submitted', prelude.requestDigest, context, { machineId: machineIds[0] ?? null, jobIds: mutationJobIds }), {
        execution: { machineIds, allRelatedJobIds, mutationJobIds, activeJobIds, mutationSubmitted: true, jobTerminalityStatus: activeJobIds.length > 0 ? 'active' : 'all-terminal' },
        code: { materializationJobId: result.materializationJobId },
        cleanup: { required: machineIds.length > 0, sourcePreserved: true },
      });
      return { operation: 'babyx.transaction.execute', transaction: publicRecord(current), replayed: false };
    } finally { this.releaseLease(prelude.record, lease); }
  }

  private observeJobs(record: DurableTransactionRecordV1, reconcile: boolean, selectedJobIds: readonly string[] = record.execution.allRelatedJobIds): JobObservation {
    const records: JobRecord[] = [];
    const activeJobIds: string[] = [];
    let allSuccessful = true;
    let ambiguous = false;
    for (const jobId of selectedJobIds) {
      let job: JobRecord;
      try { job = reconcile ? this.options.jobs.reconcile(jobId) : this.options.jobs.get(jobId); }
      catch { ambiguous = true; allSuccessful = false; continue; }
      const metadata = job.metadata ?? {};
      if (metadata.transactionId !== record.transactionId || metadata.ownerPrincipal !== record.ownerPrincipal) { ambiguous = true; allSuccessful = false; continue; }
      records.push(job);
      if (job.status === 'running') activeJobIds.push(jobId);
      if (job.status !== 'completed' || job.exitCode !== 0 || job.signal !== null && job.signal !== undefined) allSuccessful = false;
    }
    return { records, activeJobIds, allTerminal: !ambiguous && activeJobIds.length === 0 && records.length === selectedJobIds.length, allSuccessful: !ambiguous && allSuccessful, ambiguous };
  }

  async validate(payload: JsonObject, context: TransactionOperationContext): Promise<JsonObject> {
    const prelude = this.mutationRequest('babyx.transaction.validate', payload, context);
    if (prelude.replayed) return { operation: 'babyx.transaction.validate', transaction: publicRecord(prelude.record), replayed: true };
    if (this.options.codeDriver === undefined) throw serviceError('transaction_phase_unavailable', 'disposable code transaction driver is unavailable');
    if (prelude.record.lifecycle.persistedState !== 'EXECUTING') throw serviceError('transaction_state_conflict', 'validate requires EXECUTING state', { state: prelude.record.lifecycle.persistedState });
    const mutationTruth = this.observeJobs(prelude.record, true, prelude.record.execution.mutationJobIds);
    if (mutationTruth.ambiguous) {
      const ambiguous = this.store.transition(prelude.record.transactionId, prelude.record.lifecycle.stateSequence, 'AMBIGUOUS', this.details('babyx.transaction.validate', 'mutation-job-ambiguous', prelude.requestDigest, context), { execution: { activeJobIds: mutationTruth.activeJobIds, jobTerminalityStatus: 'ambiguous' }, error: errorBinding('transaction_job_ambiguous', 'mutation job ownership or truth is ambiguous', false, 'execution') });
      return { operation: 'babyx.transaction.validate', transaction: publicRecord(ambiguous), replayed: false };
    }
    if (!mutationTruth.allTerminal) throw serviceError('transaction_child_active', 'mutation jobs are still active', { activeJobIds: mutationTruth.activeJobIds });
    if (!mutationTruth.allSuccessful) {
      const rollback = this.store.transition(prelude.record.transactionId, prelude.record.lifecycle.stateSequence, 'ROLLBACK_REQUESTED', this.details('babyx.transaction.validate', 'mutation-failed', prelude.requestDigest, context), { lifecycle: { desiredState: 'ROLLED_BACK' }, execution: { activeJobIds: [], jobTerminalityStatus: 'all-terminal' }, error: errorBinding('transaction_mutation_failed', 'mutation job failed or was lost', false, 'execution', { jobs: mutationTruth.records.map((job) => ({ id: job.id, status: job.status, exitCode: job.exitCode ?? null, signal: job.signal ?? null })) }) });
      return this.cleanupWithLease(rollback, prelude.requestDigest, context, false, 'babyx.transaction.validate');
    }
    const lease = this.acquireLease(prelude.record, 'babyx.transaction.validate');
    try {
      let result: TransactionValidationResult;
      try { result = await this.options.codeDriver.validate(prelude.record, context); }
      catch (error) {
        const uncertain = this.store.transition(prelude.record.transactionId, prelude.record.lifecycle.stateSequence, 'RECOVERY_REQUIRED', this.details('babyx.transaction.validate', 'validation-response-lost', prelude.requestDigest, context), { error: errorBinding('transaction_validation_uncertain', error instanceof Error ? error.message : String(error), true, 'validation', error) });
        return { operation: 'babyx.transaction.validate', transaction: publicRecord(uncertain), replayed: false };
      }
      const newRelated = stringList(result.allRelatedJobIds, 'allRelatedJobIds');
      const validationJobIds = stringList(result.validationJobIds, 'validationJobIds');
      const activeJobIds = stringList(result.activeJobIds, 'activeJobIds');
      const allRelatedJobIds = unique([...prelude.record.execution.allRelatedJobIds, ...newRelated]);
      for (const id of [...validationJobIds, ...activeJobIds]) if (!allRelatedJobIds.includes(id)) throw serviceError('transaction_phase_result_invalid', 'validation job subsets are not bound to allRelatedJobIds');
      const validating = this.store.transition(prelude.record.transactionId, prelude.record.lifecycle.stateSequence, 'VALIDATING', this.details('babyx.transaction.validate', 'validation-submitted', prelude.requestDigest, context, { jobIds: validationJobIds }), {
        execution: { allRelatedJobIds, validationJobIds, activeJobIds, validationSubmitted: true, jobTerminalityStatus: activeJobIds.length > 0 ? 'active' : 'all-terminal' },
        code: { validationExecutions: result.validationExecutions },
      });
      return { operation: 'babyx.transaction.validate', transaction: publicRecord(validating), replayed: false };
    } finally { this.releaseLease(prelude.record, lease); }
  }

  async finalize(payload: JsonObject, context: TransactionOperationContext): Promise<JsonObject> {
    const prelude = this.mutationRequest('babyx.transaction.finalize', payload, context);
    if (prelude.replayed) return { operation: 'babyx.transaction.finalize', transaction: publicRecord(prelude.record), replayed: true };
    if (this.options.codeDriver === undefined) throw serviceError('transaction_phase_unavailable', 'disposable code transaction driver is unavailable');
    if (prelude.record.lifecycle.persistedState !== 'VALIDATING') throw serviceError('transaction_state_conflict', 'finalize requires VALIDATING state', { state: prelude.record.lifecycle.persistedState });
    const validationTruth = this.observeJobs(prelude.record, true, prelude.record.execution.validationJobIds);
    if (validationTruth.ambiguous) {
      const ambiguous = this.store.transition(prelude.record.transactionId, prelude.record.lifecycle.stateSequence, 'AMBIGUOUS', this.details('babyx.transaction.finalize', 'validation-ambiguous', prelude.requestDigest, context), { execution: { activeJobIds: validationTruth.activeJobIds, jobTerminalityStatus: 'ambiguous' }, error: errorBinding('transaction_validation_ambiguous', 'validation job ownership or result is ambiguous', false, 'validation') });
      return { operation: 'babyx.transaction.finalize', transaction: publicRecord(ambiguous), replayed: false };
    }
    if (!validationTruth.allTerminal) throw serviceError('transaction_child_active', 'validation jobs are still active', { activeJobIds: validationTruth.activeJobIds });
    if (!validationTruth.allSuccessful) {
      const rollback = this.store.transition(prelude.record.transactionId, prelude.record.lifecycle.stateSequence, 'ROLLBACK_REQUESTED', this.details('babyx.transaction.finalize', 'validation-failed', prelude.requestDigest, context), { lifecycle: { desiredState: 'ROLLED_BACK' }, execution: { activeJobIds: [], jobTerminalityStatus: 'all-terminal' }, error: errorBinding('transaction_validation_failed', 'required validation failed or was lost', false, 'validation', { jobs: validationTruth.records.map((job) => ({ id: job.id, status: job.status, exitCode: job.exitCode ?? null, signal: job.signal ?? null })) }) });
      return this.cleanupWithLease(rollback, prelude.requestDigest, context, false, 'babyx.transaction.finalize');
    }
    const lease = this.acquireLease(prelude.record, 'babyx.transaction.finalize');
    let current = prelude.record;
    try {
      current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'PREPARING_CANDIDATE', this.details('babyx.transaction.finalize', 'candidate-intent', prelude.requestDigest, context), { execution: { activeJobIds: [], jobTerminalityStatus: 'all-terminal' } });
      let candidate: TransactionCandidateResult;
      try { candidate = await this.options.codeDriver.finalize(current, context); }
      catch (error) {
        const rollback = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'ROLLBACK_REQUESTED', this.details('babyx.transaction.finalize', 'candidate-failed', prelude.requestDigest, context), { lifecycle: { desiredState: 'ROLLED_BACK' }, error: errorBinding('transaction_candidate_failed', error instanceof Error ? error.message : String(error), false, 'candidate', error) });
        return this.cleanupToTerminal(rollback, prelude.requestDigest, context, false);
      }
      const artifactIds = stringList(candidate.artifactIds, 'artifactIds');
      for (const requiredId of [candidate.patchArtifactId, candidate.candidateArchiveArtifactId, candidate.candidateManifestArtifactId]) {
        if (!artifactIds.includes(requiredId)) throw serviceError('transaction_candidate_invalid', 'required candidate artifact is not bound in artifactIds', { artifactId: requiredId });
      }
      for (const artifactId of artifactIds) {
        const artifact = this.options.artifacts.verify?.(artifactId) ?? this.options.artifacts.get(artifactId);
        if (artifact.state !== 'finalized' || typeof artifact.sha256 !== 'string') throw serviceError('transaction_artifact_incomplete', 'candidate artifact is not finalized and digest-verified', { artifactId });
      }
      current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'CANDIDATE_READY', this.details('babyx.transaction.finalize', 'candidate-durable', prelude.requestDigest, context, { candidateId: candidate.candidateId, candidateTree: candidate.candidateTree }), {
        candidate: {
          candidateId: candidate.candidateId, candidateTree: candidate.candidateTree, changedPaths: candidate.changedPaths, pathChanges: candidate.pathChanges,
          addedFiles: candidate.addedFiles, deletedFiles: candidate.deletedFiles, modifiedFiles: candidate.modifiedFiles,
          fileModeChanges: candidate.fileModeChanges, symlinkChanges: candidate.symlinkChanges,
          patchArtifactId: candidate.patchArtifactId, candidateArchiveArtifactId: candidate.candidateArchiveArtifactId,
          candidateManifestArtifactId: candidate.candidateManifestArtifactId, validationDigest: candidate.validationDigest, validationPassed: true,
        },
        execution: {
          allRelatedJobIds: unique([...current.execution.allRelatedJobIds, ...candidate.candidateJobIds]),
          activeJobIds: current.execution.activeJobIds.filter((id) => !candidate.candidateJobIds.includes(id)),
        },
        code: { candidateJobIds: candidate.candidateJobIds, validationExecutions: candidate.validationExecutions },
        evidence: { artifactIds: unique([...current.evidence.artifactIds, ...artifactIds]), receiptReferences: unique([...current.evidence.receiptReferences, ...candidate.receiptReferences]) },
      });
      current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'CLEANING', this.details('babyx.transaction.finalize', 'cleanup-intent', prelude.requestDigest, context), { cleanup: { requested: true } });
      const cleanedResult = await this.cleanupResources(current, prelude.requestDigest, context);
      current = cleanedResult.record;
      if (!cleanedResult.complete) return { operation: 'babyx.transaction.finalize', transaction: publicRecord(current), replayed: false };
      if (this.options.codeDriver.completeEvidence === undefined) {
        current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'RECOVERY_REQUIRED', this.details('babyx.transaction.finalize', 'evidence-incomplete', prelude.requestDigest, context), { error: errorBinding('transaction_evidence_incomplete', 'final evidence index has not been completed', true, 'evidence') });
        return { operation: 'babyx.transaction.finalize', transaction: publicRecord(current), replayed: false };
      }
      const evidence = await this.options.codeDriver.completeEvidence(current, context);
      const evidenceArtifacts = stringList(evidence.artifactIds, 'evidence.artifactIds');
      if (!evidenceArtifacts.includes(evidence.finalEvidenceIndexArtifactId)) throw serviceError('transaction_evidence_incomplete', 'final evidence index is not bound in artifactIds');
      for (const artifactId of evidenceArtifacts) {
        const artifact = this.options.artifacts.verify?.(artifactId) ?? this.options.artifacts.get(artifactId);
        if (artifact.state !== 'finalized' || typeof artifact.sha256 !== 'string') throw serviceError('transaction_artifact_incomplete', 'evidence artifact is not finalized and digest-verified', { artifactId });
      }
      current = this.store.update(current.transactionId, current.lifecycle.stateSequence, this.details('babyx.transaction.finalize', 'evidence-durable', prelude.requestDigest, context), { evidence: { artifactIds: unique([...current.evidence.artifactIds, ...evidenceArtifacts]), receiptReferences: unique([...current.evidence.receiptReferences, ...evidence.receiptReferences]), finalEvidenceIndexArtifactId: evidence.finalEvidenceIndexArtifactId, finalEvidenceIndexDigest: evidence.finalEvidenceIndexDigest } });
      current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'COMMITTED', this.details('babyx.transaction.finalize', 'transaction-committed', prelude.requestDigest, context, { candidateId: current.candidate.candidateId, candidateTree: current.candidate.candidateTree }));
      return { operation: 'babyx.transaction.finalize', transaction: publicRecord(current), replayed: false };
    } finally { this.releaseLease(prelude.record, lease); }
  }

  async rollback(payload: JsonObject, context: TransactionOperationContext): Promise<JsonObject> {
    const prelude = this.mutationRequest('babyx.transaction.rollback', payload, context);
    if (prelude.replayed) return { operation: 'babyx.transaction.rollback', transaction: publicRecord(prelude.record), replayed: true };
    if (prelude.record.lifecycle.persistedState === 'AMBIGUOUS') throw serviceError('transaction_identity_ambiguous', 'ambiguous ownership blocks destructive cleanup');
    let current = prelude.record;
    if (!['ROLLBACK_REQUESTED', 'ROLLING_BACK'].includes(current.lifecycle.persistedState)) {
      current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'ROLLBACK_REQUESTED', this.details('babyx.transaction.rollback', 'rollback-requested', prelude.requestDigest, context), { lifecycle: { desiredState: 'ROLLED_BACK' }, cleanup: { requested: true } });
    }
    return this.cleanupWithLease(current, prelude.requestDigest, context, false, 'babyx.transaction.rollback');
  }

  private async cleanupWithLease(record: DurableTransactionRecordV1, requestDigest: string, context: TransactionOperationContext, expired: boolean, operation: string): Promise<JsonObject> {
    const lease = this.acquireLease(record, operation);
    try { return await this.cleanupToTerminal(record, requestDigest, context, expired); }
    finally { this.releaseLease(record, lease); }
  }

  private async cleanupToTerminal(record: DurableTransactionRecordV1, requestDigest: string, context: TransactionOperationContext, expired: boolean): Promise<JsonObject> {
    let current = record;
    if (current.lifecycle.persistedState === 'ROLLBACK_REQUESTED') current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'ROLLING_BACK', this.details(expired ? 'babyx.transaction.expire' : 'babyx.transaction.rollback', 'rollback-cleanup', requestDigest, context), { cleanup: { requested: true } });
    const cleaned = await this.cleanupResources(current, requestDigest, context);
    current = cleaned.record;
    if (!cleaned.complete) return { operation: expired ? 'babyx.transaction.expire' : 'babyx.transaction.rollback', transaction: publicRecord(current), replayed: false };
    current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, expired ? 'EXPIRED' : 'ROLLED_BACK', this.details(expired ? 'babyx.transaction.expire' : 'babyx.transaction.rollback', expired ? 'expired' : 'rolled-back', requestDigest, context));
    return { operation: expired ? 'babyx.transaction.expire' : 'babyx.transaction.rollback', transaction: publicRecord(current), replayed: false };
  }

  private async cleanupResources(record: DurableTransactionRecordV1, requestDigest: string, context: TransactionOperationContext): Promise<{ record: DurableTransactionRecordV1; complete: boolean }> {
    if (record.lifecycle.persistedState === 'AMBIGUOUS') return { record, complete: false };
    let current = record;
    const jobs = this.observeJobs(current, true);
    if (jobs.ambiguous) {
      current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'AMBIGUOUS', this.details('babyx.transaction.reconcile', 'cleanup-job-ambiguous', requestDigest, context), { execution: { activeJobIds: jobs.activeJobIds, jobTerminalityStatus: 'ambiguous' }, error: errorBinding('transaction_job_ownership_ambiguous', 'related job ownership is ambiguous', false, 'cleanup') });
      return { record: current, complete: false };
    }
    for (const jobId of jobs.activeJobIds) {
      try { this.options.jobs.cancel(jobId, 'SIGTERM'); }
      catch (error) {
        current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'RECOVERY_REQUIRED', this.details('babyx.transaction.reconcile', 'cleanup-job-cancel-failed', requestDigest, context, { jobIds: [jobId] }), { execution: { activeJobIds: jobs.activeJobIds, jobTerminalityStatus: 'active' }, error: errorBinding('transaction_job_cleanup_failed', error instanceof Error ? error.message : String(error), true, 'cleanup', { jobId }) });
        return { record: current, complete: false };
      }
    }
    const terminalJobs = this.observeJobs(current, true);
    if (!terminalJobs.allTerminal) {
      current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'RECOVERY_REQUIRED', this.details('babyx.transaction.reconcile', 'cleanup-job-active', requestDigest, context, { jobIds: terminalJobs.activeJobIds }), { execution: { activeJobIds: terminalJobs.activeJobIds, jobTerminalityStatus: terminalJobs.ambiguous ? 'ambiguous' : 'active' }, error: errorBinding('transaction_jobs_not_terminal', 'related jobs remain active or unresolved', true, 'cleanup') });
      return { record: current, complete: false };
    }
    current = this.store.update(current.transactionId, current.lifecycle.stateSequence, this.details('babyx.transaction.reconcile', 'cleanup-jobs-terminal', requestDigest, context), { execution: { activeJobIds: [], jobTerminalityStatus: 'all-terminal' } });
    if (current.execution.machineIds.length === 0) {
      current = this.store.update(current.transactionId, current.lifecycle.stateSequence, this.details('babyx.transaction.reconcile', 'cleanup-no-machine-bound', requestDigest, context), { cleanup: { required: false, requested: true, completed: true, machineAbsenceVerified: true, processAbsenceVerified: true, mountAbsenceVerified: true, rootPathAbsenceVerified: true, datasetAbsenceVerified: true, sourcePreserved: true, completedAt: this.now() } });
      return { record: current, complete: true };
    }
    let fullAbsence = true;
    let sourcePreserved = true;
    for (const machineId of current.execution.machineIds) {
      let view: Record<string, unknown>;
      try { view = machineRecord(this.options.machine.get({ machineId }, { subject: current.ownerPrincipal, authorityClass: context.authorityClass })); }
      catch (error) {
        current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'AMBIGUOUS', this.details('babyx.transaction.reconcile', 'cleanup-machine-unresolved', requestDigest, context, { machineId }), { error: errorBinding('transaction_machine_ambiguous', error instanceof Error ? error.message : String(error), false, 'cleanup', { machineId }) });
        return { record: current, complete: false };
      }
      if (view.machineId !== machineId || view.ownerPrincipal !== current.ownerPrincipal) {
        current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'AMBIGUOUS', this.details('babyx.transaction.reconcile', 'cleanup-machine-ownership-conflict', requestDigest, context, { machineId }), { error: errorBinding('transaction_machine_ownership_ambiguous', 'bound machine ownership conflicts with transaction truth', false, 'cleanup', { machineId }) });
        return { record: current, complete: false };
      }
      let lifecycle = machineLifecycle(view);
      if (lifecycle.state !== 'DESTROYED') {
        try {
          const result = await this.options.machine.destroy({ machineId, expectedSequence: lifecycle.sequence, stopIfRunning: true, forceStop: false, reason: `transaction cleanup ${current.transactionId}` }, { subject: current.ownerPrincipal, authorityClass: context.authorityClass, idempotencyKey: `transaction-destroy:${current.transactionId}:${machineId}` });
          view = machineRecord(result);
          lifecycle = machineLifecycle(view);
        } catch (error) {
          current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'RECOVERY_REQUIRED', this.details('babyx.transaction.reconcile', 'cleanup-machine-failed', requestDigest, context, { machineId }), { error: errorBinding('transaction_machine_cleanup_failed', error instanceof Error ? error.message : String(error), true, 'cleanup', { machineId }) });
          return { record: current, complete: false };
        }
      }
      const cleanup = nestedObject(view.cleanup, 'machine cleanup');
      const observations = nestedObject(view.observations, 'machine observations');
      const source = nestedObject(view.source, 'machine source');
      const absent = lifecycle.state === 'DESTROYED' && cleanup.completed === true && cleanup.machineAbsentVerified === true && cleanup.processAbsentVerified === true && cleanup.rootAbsentVerified === true && cleanup.datasetAbsentVerified === true && observations.mountpoint === 'absent';
      fullAbsence = fullAbsence && absent;
      sourcePreserved = sourcePreserved && (source.snapshotGuid === current.source.expectedSnapshotGuid || source.expectedSnapshotGuid === current.source.expectedSnapshotGuid);
    }
    if (!fullAbsence || !sourcePreserved) {
      current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'RECOVERY_REQUIRED', this.details('babyx.transaction.reconcile', 'cleanup-readback-incomplete', requestDigest, context), { error: errorBinding('transaction_cleanup_incomplete', 'machine cleanup lacks complete positive absence or source preservation proof', true, 'cleanup') });
      return { record: current, complete: false };
    }
    current = this.store.update(current.transactionId, current.lifecycle.stateSequence, this.details('babyx.transaction.reconcile', 'cleanup-complete', requestDigest, context), { cleanup: { requested: true, completed: true, machineAbsenceVerified: true, processAbsenceVerified: true, mountAbsenceVerified: true, rootPathAbsenceVerified: true, datasetAbsenceVerified: true, sourcePreserved: true, completedAt: this.now() } });
    return { record: current, complete: true };
  }

  async reconcile(payload: JsonObject, context: TransactionOperationContext): Promise<JsonObject> {
    const prelude = this.mutationRequest('babyx.transaction.reconcile', payload, context);
    if (prelude.replayed) return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(prelude.record), replayed: true };
    if (prelude.record.lifecycle.terminal) return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(prelude.record), replayed: false, noOp: true };
    if (prelude.record.lifecycle.persistedState === 'AMBIGUOUS') return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(prelude.record), replayed: false, deferred: true };
    const lease = this.acquireLease(prelude.record, 'babyx.transaction.reconcile');
    let current = prelude.record;
    try {
      const jobs = this.observeJobs(current, true);
      if (jobs.ambiguous) {
        current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'AMBIGUOUS', this.details('babyx.transaction.reconcile', 'job-observation-ambiguous', prelude.requestDigest, context), { execution: { activeJobIds: jobs.activeJobIds, jobTerminalityStatus: 'ambiguous' }, error: errorBinding('transaction_job_ambiguous', 'job observations are insufficient or conflicting', false, 'reconcile') });
        return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(current), replayed: false };
      }
      current = this.store.update(current.transactionId, current.lifecycle.stateSequence, this.details('babyx.transaction.reconcile', 'child-truth-observed', prelude.requestDigest, context, { jobIds: jobs.records.map((job) => job.id) }), { execution: { activeJobIds: jobs.activeJobIds, jobTerminalityStatus: jobs.allTerminal ? 'all-terminal' : 'active' } });

      if (['ROLLBACK_REQUESTED', 'ROLLING_BACK'].includes(current.lifecycle.persistedState) || current.lifecycle.persistedState === 'RECOVERY_REQUIRED' && ['ROLLED_BACK', 'EXPIRED'].includes(current.lifecycle.desiredState)) {
        return this.cleanupToTerminal(current.lifecycle.persistedState === 'RECOVERY_REQUIRED'
          ? this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'ROLLING_BACK', this.details('babyx.transaction.reconcile', 'resume-rollback', prelude.requestDigest, context))
          : current, prelude.requestDigest, context, current.lifecycle.desiredState === 'EXPIRED');
      }

      if (current.lifecycle.persistedState === 'EXECUTING') {
        const mutationTruth = this.observeJobs(current, true, current.execution.mutationJobIds);
        if (mutationTruth.ambiguous) {
          current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'AMBIGUOUS', this.details('babyx.transaction.reconcile', 'mutation-job-ambiguous', prelude.requestDigest, context), { execution: { activeJobIds: mutationTruth.activeJobIds, jobTerminalityStatus: 'ambiguous' }, error: errorBinding('transaction_job_ambiguous', 'mutation job ownership or truth is ambiguous', false, 'execution') });
          return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(current), replayed: false };
        }
        if (!mutationTruth.allTerminal) return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(current), replayed: false, deferred: true };
        if (!mutationTruth.allSuccessful) {
          current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'ROLLBACK_REQUESTED', this.details('babyx.transaction.reconcile', 'mutation-failed', prelude.requestDigest, context), { lifecycle: { desiredState: 'ROLLED_BACK' }, execution: { activeJobIds: [], jobTerminalityStatus: 'all-terminal' }, error: errorBinding('transaction_mutation_failed', 'mutation job failed or was lost', false, 'execution', { jobs: mutationTruth.records.map((job) => ({ id: job.id, status: job.status, exitCode: job.exitCode ?? null, signal: job.signal ?? null })) }) });
          return this.cleanupToTerminal(current, prelude.requestDigest, context, false);
        }
        const driver = this.options.codeDriver;
        if (driver === undefined) {
          current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'RECOVERY_REQUIRED', this.details('babyx.transaction.reconcile', 'validation-driver-unavailable', prelude.requestDigest, context), { error: errorBinding('transaction_phase_unavailable', 'disposable code transaction driver is unavailable', true, 'validation') });
          return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(current), replayed: false };
        }
        let result: TransactionValidationResult;
        try { result = await driver.validate(current, context); }
        catch (error) {
          current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'RECOVERY_REQUIRED', this.details('babyx.transaction.reconcile', 'validation-response-lost', prelude.requestDigest, context), { error: errorBinding('transaction_validation_uncertain', error instanceof Error ? error.message : String(error), true, 'validation', error) });
          return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(current), replayed: false };
        }
        const newRelated = stringList(result.allRelatedJobIds, 'allRelatedJobIds');
        const validationJobIds = stringList(result.validationJobIds, 'validationJobIds');
        const activeJobIds = stringList(result.activeJobIds, 'activeJobIds');
        const allRelatedJobIds = unique([...current.execution.allRelatedJobIds, ...newRelated]);
        for (const id of [...validationJobIds, ...activeJobIds]) if (!allRelatedJobIds.includes(id)) throw serviceError('transaction_phase_result_invalid', 'validation job subsets are not bound to allRelatedJobIds');
        current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'VALIDATING', this.details('babyx.transaction.reconcile', 'validation-resumed', prelude.requestDigest, context, { jobIds: validationJobIds }), {
          execution: { allRelatedJobIds, validationJobIds, activeJobIds, validationSubmitted: true, jobTerminalityStatus: activeJobIds.length > 0 ? 'active' : 'all-terminal' },
          code: { validationExecutions: result.validationExecutions },
        });
        return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(current), replayed: false };
      }

      if (current.lifecycle.persistedState === 'VALIDATING') {
        const validationTruth = this.observeJobs(current, true, current.execution.validationJobIds);
        if (validationTruth.ambiguous) {
          current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'AMBIGUOUS', this.details('babyx.transaction.reconcile', 'validation-ambiguous', prelude.requestDigest, context), { execution: { activeJobIds: validationTruth.activeJobIds, jobTerminalityStatus: 'ambiguous' }, error: errorBinding('transaction_validation_ambiguous', 'validation job ownership or result is ambiguous', false, 'validation') });
          return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(current), replayed: false };
        }
        if (!validationTruth.allTerminal) return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(current), replayed: false, deferred: true };
        if (!validationTruth.allSuccessful) {
          current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'ROLLBACK_REQUESTED', this.details('babyx.transaction.reconcile', 'validation-failed', prelude.requestDigest, context), { lifecycle: { desiredState: 'ROLLED_BACK' }, execution: { activeJobIds: [], jobTerminalityStatus: 'all-terminal' }, error: errorBinding('transaction_validation_failed', 'required validation failed or was lost', false, 'validation', { jobs: validationTruth.records.map((job) => ({ id: job.id, status: job.status, exitCode: job.exitCode ?? null, signal: job.signal ?? null })) }) });
          return this.cleanupToTerminal(current, prelude.requestDigest, context, false);
        }
        current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'PREPARING_CANDIDATE', this.details('babyx.transaction.reconcile', 'resume-candidate-intent', prelude.requestDigest, context), { execution: { activeJobIds: [], jobTerminalityStatus: 'all-terminal' } });
      }

      if (current.lifecycle.persistedState === 'PREPARING_CANDIDATE') {
        const driver = this.options.codeDriver;
        if (driver === undefined) {
          current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'RECOVERY_REQUIRED', this.details('babyx.transaction.reconcile', 'candidate-driver-unavailable', prelude.requestDigest, context), { error: errorBinding('transaction_phase_unavailable', 'disposable code transaction driver is unavailable', true, 'candidate') });
          return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(current), replayed: false };
        }
        let candidate: TransactionCandidateResult;
        try { candidate = await driver.finalize(current, context); }
        catch (error) {
          current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'ROLLBACK_REQUESTED', this.details('babyx.transaction.reconcile', 'candidate-failed', prelude.requestDigest, context), { lifecycle: { desiredState: 'ROLLED_BACK' }, error: errorBinding('transaction_candidate_failed', error instanceof Error ? error.message : String(error), false, 'candidate', error) });
          return this.cleanupToTerminal(current, prelude.requestDigest, context, false);
        }
        const artifactIds = stringList(candidate.artifactIds, 'artifactIds');
        for (const requiredId of [candidate.patchArtifactId, candidate.candidateArchiveArtifactId, candidate.candidateManifestArtifactId]) {
          if (!artifactIds.includes(requiredId)) throw serviceError('transaction_candidate_invalid', 'required candidate artifact is not bound in artifactIds', { artifactId: requiredId });
        }
        for (const artifactId of artifactIds) {
          const artifact = this.options.artifacts.verify?.(artifactId) ?? this.options.artifacts.get(artifactId);
          if (artifact.state !== 'finalized' || typeof artifact.sha256 !== 'string') throw serviceError('transaction_artifact_incomplete', 'candidate artifact is not finalized and digest-verified', { artifactId });
        }
        current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'CANDIDATE_READY', this.details('babyx.transaction.reconcile', 'candidate-recovered', prelude.requestDigest, context, { candidateId: candidate.candidateId, candidateTree: candidate.candidateTree }), {
          candidate: {
            candidateId: candidate.candidateId, candidateTree: candidate.candidateTree, changedPaths: candidate.changedPaths, pathChanges: candidate.pathChanges,
            addedFiles: candidate.addedFiles, deletedFiles: candidate.deletedFiles, modifiedFiles: candidate.modifiedFiles,
            fileModeChanges: candidate.fileModeChanges, symlinkChanges: candidate.symlinkChanges,
            patchArtifactId: candidate.patchArtifactId, candidateArchiveArtifactId: candidate.candidateArchiveArtifactId,
            candidateManifestArtifactId: candidate.candidateManifestArtifactId, validationDigest: candidate.validationDigest, validationPassed: true,
          },
          execution: { allRelatedJobIds: unique([...current.execution.allRelatedJobIds, ...candidate.candidateJobIds]), activeJobIds: [], jobTerminalityStatus: 'all-terminal' },
          code: { candidateJobIds: candidate.candidateJobIds, validationExecutions: candidate.validationExecutions },
          evidence: { artifactIds: unique([...current.evidence.artifactIds, ...artifactIds]), receiptReferences: unique([...current.evidence.receiptReferences, ...candidate.receiptReferences]) },
        });
      }

      if (current.lifecycle.persistedState === 'CANDIDATE_READY') {
        current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'CLEANING', this.details('babyx.transaction.reconcile', 'resume-cleanup-intent', prelude.requestDigest, context), { cleanup: { requested: true } });
      }

      if (current.lifecycle.persistedState === 'RECOVERY_REQUIRED' && current.lifecycle.desiredState === 'COMMITTED') {
        if (!current.candidate.validationPassed || current.candidate.candidateTree === null) return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(current), replayed: false, deferred: true };
        current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'CLEANING', this.details('babyx.transaction.reconcile', 'resume-cleaning', prelude.requestDigest, context));
      }

      if (current.lifecycle.persistedState === 'CLEANING') {
        const cleaned = await this.cleanupResources(current, prelude.requestDigest, context);
        current = cleaned.record;
        if (!cleaned.complete) return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(current), replayed: false };
        if (current.evidence.finalEvidenceIndexArtifactId === null || current.evidence.finalEvidenceIndexDigest === null) {
          const driver = this.options.codeDriver;
          if (driver?.completeEvidence === undefined) {
            current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'RECOVERY_REQUIRED', this.details('babyx.transaction.reconcile', 'evidence-incomplete', prelude.requestDigest, context), { error: errorBinding('transaction_evidence_incomplete', 'final evidence index has not been completed', true, 'evidence') });
            return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(current), replayed: false };
          }
          let evidence: TransactionEvidenceResult;
          try { evidence = await driver.completeEvidence(current, context); }
          catch (error) {
            current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'RECOVERY_REQUIRED', this.details('babyx.transaction.reconcile', 'evidence-persistence-failed', prelude.requestDigest, context), { error: errorBinding('transaction_evidence_incomplete', error instanceof Error ? error.message : String(error), true, 'evidence', error) });
            return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(current), replayed: false };
          }
          const evidenceArtifacts = stringList(evidence.artifactIds, 'evidence.artifactIds');
          if (!evidenceArtifacts.includes(evidence.finalEvidenceIndexArtifactId)) throw serviceError('transaction_evidence_incomplete', 'final evidence index is not bound in artifactIds');
          for (const artifactId of evidenceArtifacts) {
            const artifact = this.options.artifacts.verify?.(artifactId) ?? this.options.artifacts.get(artifactId);
            if (artifact.state !== 'finalized' || typeof artifact.sha256 !== 'string') throw serviceError('transaction_artifact_incomplete', 'evidence artifact is not finalized and digest-verified', { artifactId });
          }
          current = this.store.update(current.transactionId, current.lifecycle.stateSequence, this.details('babyx.transaction.reconcile', 'evidence-durable', prelude.requestDigest, context), { evidence: { artifactIds: unique([...current.evidence.artifactIds, ...evidenceArtifacts]), receiptReferences: unique([...current.evidence.receiptReferences, ...evidence.receiptReferences]), finalEvidenceIndexArtifactId: evidence.finalEvidenceIndexArtifactId, finalEvidenceIndexDigest: evidence.finalEvidenceIndexDigest } });
        }
        current = this.store.transition(current.transactionId, current.lifecycle.stateSequence, 'COMMITTED', this.details('babyx.transaction.reconcile', 'transaction-committed', prelude.requestDigest, context, { candidateId: current.candidate.candidateId, candidateTree: current.candidate.candidateTree }));
      }
      return { operation: 'babyx.transaction.reconcile', transaction: publicRecord(current), replayed: false };
    } finally { this.releaseLease(prelude.record, lease); }
  }

  async expire(payload: JsonObject, context: TransactionOperationContext): Promise<JsonObject> {
    const prelude = this.mutationRequest('babyx.transaction.expire', payload, context);
    if (prelude.replayed) return { operation: 'babyx.transaction.expire', transaction: publicRecord(prelude.record), replayed: true };
    if (prelude.record.lifecycle.terminal) throw serviceError('transaction_terminal', 'terminal transaction cannot be expired');
    if (prelude.record.lifecycle.persistedState === 'AMBIGUOUS') throw serviceError('transaction_identity_ambiguous', 'ambiguous transaction cannot be expired destructively');
    if (!prelude.record.cleanup.required && prelude.record.execution.allRelatedJobIds.length === 0) {
      const expired = this.store.transition(prelude.record.transactionId, prelude.record.lifecycle.stateSequence, 'EXPIRED', this.details('babyx.transaction.expire', 'expired-without-resources', prelude.requestDigest, context), { lifecycle: { desiredState: 'EXPIRED' }, cleanup: { requested: true, completed: true, machineAbsenceVerified: true, processAbsenceVerified: true, mountAbsenceVerified: true, rootPathAbsenceVerified: true, datasetAbsenceVerified: true, sourcePreserved: true, completedAt: this.now() } });
      return { operation: 'babyx.transaction.expire', transaction: publicRecord(expired), replayed: false };
    }
    const rollback = this.store.transition(prelude.record.transactionId, prelude.record.lifecycle.stateSequence, 'ROLLBACK_REQUESTED', this.details('babyx.transaction.expire', 'expiration-cleanup-requested', prelude.requestDigest, context), { lifecycle: { desiredState: 'EXPIRED' }, cleanup: { requested: true } });
    return this.cleanupWithLease(rollback, prelude.requestDigest, context, true, 'babyx.transaction.expire');
  }

  async gc(payload: JsonObject = {}, context: TransactionOperationContext): Promise<JsonObject> {
    assertKeys(payload, ['dryRun', 'ownerPrincipal', 'state', 'offset', 'limit']);
    if (payload.dryRun !== undefined && typeof payload.dryRun !== 'boolean') throw serviceError('transaction_invalid_request', 'dryRun must be a boolean');
    const dryRun = payload.dryRun ?? true;
    const subject = context.authorityClass === 'unrestricted-owner' ? undefined : requiredReadSubject(context);
    const requestedOwner = payload.ownerPrincipal === undefined ? undefined : String(payload.ownerPrincipal);
    if (subject !== undefined && requestedOwner !== undefined && subject !== requestedOwner) throw serviceError('transaction_not_found', 'owner scope is not accessible');
    const owner = subject ?? requestedOwner;
    const state = payload.state === undefined ? undefined : String(payload.state) as TransactionState;
    if (state !== undefined && !TRANSACTION_STATES.includes(state)) throw serviceError('transaction_invalid_request', 'state filter is unsupported');
    const offset = bounded(payload.offset, 'offset', 0, Number.MAX_SAFE_INTEGER);
    const limit = bounded(payload.limit, 'limit', Math.min(100, this.maximumListLimit), this.maximumListLimit);
    const records = this.store.list().filter((record) => (owner === undefined || record.ownerPrincipal === owner) && (state === undefined || record.lifecycle.persistedState === state)).slice(offset, offset + limit);
    const candidates = records.map((record) => {
      const eligible = !record.lifecycle.terminal && record.lifecycle.persistedState !== 'AMBIGUOUS';
      return { transactionId: record.transactionId, ownerPrincipal: record.ownerPrincipal, state: record.lifecycle.persistedState, eligible, reason: eligible ? 'nonterminal owner-scoped transaction requires canonical expiration' : record.lifecycle.terminal ? 'terminal transaction retained as evidence' : 'ambiguous ownership blocks destructive action' };
    });
    const actions: JsonObject[] = [];
    if (!dryRun) {
      for (const candidate of candidates.filter((entry) => entry.eligible)) {
        const record = this.store.get(candidate.transactionId);
        actions.push(await this.expire({ transactionId: record.transactionId, expectedSequence: record.lifecycle.stateSequence, reason: 'bounded transaction GC' }, { subject: record.ownerPrincipal, authorityClass: context.authorityClass, idempotencyKey: `transaction-gc:${record.transactionId}:${record.lifecycle.stateSequence}` }));
      }
    }
    return { operation: 'babyx.transaction.gc', dryRun, ownerScoped: true, bounded: true, offset, limit, candidates, actions };
  }
}
