import { randomUUID } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, normalize } from 'node:path';
import {
  AtomicStore,
  canonicalize,
  sha256,
  type JobRecord,
  type JsonObject,
  type RuntimeExecutionContext,
} from '../core.ts';
import { canonicalMachineEvidence } from '../machines/schemas.ts';
import { decideExecutionPolicy, type ExecutionPolicyDecision } from '../policy/execution.ts';

export const CERTIFICATION_SCHEMA_VERSION = '1.0.0' as const;

export type CertificationState =
  | 'REQUESTED'
  | 'CREATING'
  | 'STARTING'
  | 'RUNNING'
  | 'CLEANING'
  | 'SUCCEEDED'
  | 'FAILED'
  | 'PRESERVED'
  | 'RECOVERY_REQUIRED';

export type CertificationStepPhase = 'dependency' | 'build' | 'lint' | 'unit' | 'integration' | 'acceptance';
export type CertificationStepState = 'pending' | 'running' | 'passed' | 'failed';

export interface CertificationStepRequest extends JsonObject {
  id: string;
  phase: CertificationStepPhase;
  argv: string[];
  cwd: string;
  timeoutMs?: number;
  required: boolean;
}

export interface CertificationRequest extends JsonObject {
  schemaVersion: typeof CERTIFICATION_SCHEMA_VERSION;
  source: {
    commit: string;
    tree: string;
    snapshot: string;
    expectedGuid?: string;
  };
  machine: JsonObject;
  profile: {
    id: string;
    version: string;
    steps: CertificationStepRequest[];
  };
  retention: {
    preserveOnFailure: boolean;
    expiresAt?: string;
  };
}

export interface CertificationStepRecord extends JsonObject {
  id: string;
  phase: CertificationStepPhase;
  required: boolean;
  state: CertificationStepState;
  jobId?: string;
  exitCode?: number | null;
  signal?: string | null;
  startedAt?: string;
  completedAt?: string;
  error?: JsonObject;
}

export interface CertificationRecord extends JsonObject {
  schemaVersion: typeof CERTIFICATION_SCHEMA_VERSION;
  certificationId: string;
  ownerPrincipal: string;
  requestDigest: string;
  requestIdempotencyKey: string;
  request: CertificationRequest;
  executionPolicy: ExecutionPolicyDecision;
  state: CertificationState;
  revision: number;
  createdAt: string;
  updatedAt: string;
  machineId?: string;
  machineName?: string;
  machineSequence?: number;
  jobIds: string[];
  artifactReferences: string[];
  proofReferences: string[];
  steps: CertificationStepRecord[];
  testResult: {
    status: 'pending' | 'passed' | 'failed';
    failedStepId?: string;
  };
  evidence: {
    status: 'pending' | 'complete' | 'failed';
    diagnosticArtifactReference?: string;
    indexArtifactReference?: string;
    indexDigest?: string;
    error?: JsonObject;
  };
  cleanup: {
    required: boolean;
    stopStatus: 'pending' | 'not-required' | 'succeeded' | 'failed';
    destroyStatus: 'pending' | 'not-required' | 'succeeded' | 'failed';
    absenceVerified: boolean;
    sourcePreserved: boolean;
    error?: JsonObject;
  };
  lastError?: JsonObject;
}

export interface CertificationMachineAuthority {
  create(payload: unknown, context: RuntimeExecutionContext): Promise<JsonObject>;
  get(payload: JsonObject, context: RuntimeExecutionContext): JsonObject;
  list(payload: JsonObject | undefined, context: RuntimeExecutionContext): JsonObject;
  events(payload: JsonObject, context: RuntimeExecutionContext): JsonObject;
  status(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  start(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  exec(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  stop(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  destroy(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  reconcile(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  expire(payload: JsonObject, context: RuntimeExecutionContext): JsonObject;
  diagnostics(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
}

export interface CertificationJobAuthority {
  get(id: string): JobRecord;
  reconcile(id: string): JobRecord;
}

export interface CertificationArtifactAuthority {
  create(name: string, sourcePath: string, metadata?: JsonObject): JsonObject;
}

export interface CertificationServiceOptions {
  stateRoot: string;
  machine: CertificationMachineAuthority;
  jobs: CertificationJobAuthority;
  artifacts?: CertificationArtifactAuthority;
  now?: () => string;
  sleep?: (milliseconds: number) => Promise<void>;
  certificationIdFactory?: () => string;
  jobPollIntervalMs?: number;
  machineSettleTimeoutMs?: number;
}

export class CertificationError extends Error {
  constructor(readonly code: string, message: string, readonly details: JsonObject = {}) {
    super(message);
    this.name = 'CertificationError';
  }
}

type CertificationStoreState = JsonObject & {
  records: Record<string, CertificationRecord>;
  byIdempotencyKey: Record<string, string>;
};

function object(value: unknown, field: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new CertificationError('certification_invalid_request', `${field} must be an object`);
  return value as JsonObject;
}

function text(value: unknown, field: string, maximum = 512): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum || value.includes('\0')) throw new CertificationError('certification_invalid_request', `${field} must be a bounded non-empty NUL-free string`);
  return value;
}

function optionalText(value: unknown, field: string, maximum = 512): string | undefined {
  return value === undefined ? undefined : text(value, field, maximum);
}

function timestamp(value: unknown, field: string): string | undefined {
  if (value === undefined) return undefined;
  const candidate = text(value, field, 64);
  if (!Number.isFinite(Date.parse(candidate))) throw new CertificationError('certification_invalid_request', `${field} must be an ISO timestamp`);
  return candidate;
}

function integer(value: unknown, field: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new CertificationError('certification_invalid_request', `${field} must be a safe integer between ${minimum} and ${maximum}`);
  return Number(value);
}

function allowedKeys(value: JsonObject, field: string, allowed: readonly string[]): void {
  const permitted = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !permitted.has(key));
  if (unknown.length > 0) throw new CertificationError('certification_invalid_request', `${field} contains unsupported properties`, { properties: unknown });
}

function mutationContext(context: RuntimeExecutionContext): { idempotencyKey: string; subject: string } {
  const idempotencyKey = text(context.idempotencyKey, 'idempotencyKey', 256);
  if (idempotencyKey.length < 8) throw new CertificationError('certification_invalid_request', 'idempotencyKey must contain at least eight characters');
  const subject = text(context.subject, 'subject', 256);
  return { idempotencyKey, subject };
}

function readSubject(context: RuntimeExecutionContext): string | undefined {
  if (context.authorityClass === 'unrestricted-owner') return undefined;
  return text(context.subject, 'subject', 256);
}

function certificationId(value: unknown): string {
  const candidate = text(value, 'certificationId', 128);
  if (!/^cert_[a-z0-9][a-z0-9_-]{7,120}$/u.test(candidate)) throw new CertificationError('certification_invalid_request', 'certificationId is invalid');
  return candidate;
}

function shaIdentity(value: unknown, field: string): string {
  const candidate = text(value, field, 64);
  if (!/^[a-f0-9]{40,64}$/u.test(candidate)) throw new CertificationError('certification_invalid_request', `${field} must be a lowercase source identity digest`);
  return candidate;
}

function normalizedCwd(value: unknown, field: string): string {
  const candidate = text(value, field, 1024);
  if (!isAbsolute(candidate) || normalize(candidate) !== candidate) throw new CertificationError('certification_invalid_request', `${field} must be a normalized absolute path`);
  return candidate;
}

function exactArgv(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 128) throw new CertificationError('certification_invalid_request', `${field} must be a non-empty bounded string array`);
  return value.map((entry, index) => text(entry, `${field}[${index}]`, 4096));
}

function normalizeMachineTemplate(value: unknown): JsonObject {
  const machine = structuredClone(object(value, 'machine'));
  allowedKeys(machine, 'machine', ['machineName', 'authorityReference', 'parentObjectiveId', 'parentCandidateId', 'clone', 'launch']);
  text(machine.machineName, 'machine.machineName', 64);
  optionalText(machine.authorityReference, 'machine.authorityReference', 256);
  optionalText(machine.parentObjectiveId, 'machine.parentObjectiveId', 256);
  optionalText(machine.parentCandidateId, 'machine.parentCandidateId', 256);
  const clone = object(machine.clone, 'machine.clone');
  allowedKeys(clone, 'machine.clone', ['dataset', 'mountpoint', 'expectedRootPrefix']);
  text(clone.dataset, 'machine.clone.dataset', 256);
  normalizedCwd(clone.mountpoint, 'machine.clone.mountpoint');
  normalizedCwd(clone.expectedRootPrefix, 'machine.clone.expectedRootPrefix');
  const launch = object(machine.launch, 'machine.launch');
  allowedKeys(launch, 'machine.launch', ['boot', 'command', 'networkMode', 'readOnlyRoot', 'binds', 'environment', 'properties', 'resourceProfile']);
  if (typeof launch.boot !== 'boolean') throw new CertificationError('certification_invalid_request', 'machine.launch.boot must be boolean');
  if (typeof launch.readOnlyRoot !== 'boolean') throw new CertificationError('certification_invalid_request', 'machine.launch.readOnlyRoot must be boolean');
  text(launch.networkMode, 'machine.launch.networkMode', 32);
  if (!Array.isArray(launch.binds) || !Array.isArray(launch.environment) || !Array.isArray(launch.properties)) throw new CertificationError('certification_invalid_request', 'machine launch binds, environment, and properties must be arrays');
  if (launch.command !== undefined) exactArgv(launch.command, 'machine.launch.command');
  safeMachineEnvironment(machine);
  return machine;
}

function safeMachineEnvironment(machine: JsonObject): void {
  const launch = object(machine.launch, 'machine.launch');
  if (launch.environment === undefined) return;
  if (!Array.isArray(launch.environment)) throw new CertificationError('certification_invalid_request', 'machine.launch.environment must be an array');
  for (const [index, entry] of launch.environment.entries()) {
    const environment = object(entry, `machine.launch.environment[${index}]`);
    if (environment.value !== undefined) throw new CertificationError('certification_secret_rejected', 'certification machine environment must use redacted secret references instead of persisted values', { index });
    if (typeof environment.secretReference !== 'string' || environment.redacted !== true) throw new CertificationError('certification_secret_rejected', 'certification machine environment entries require secretReference and redacted=true', { index });
  }
}

function normalizeRequest(value: unknown): CertificationRequest {
  const request = object(value, 'certification request');
  allowedKeys(request, 'certification request', ['schemaVersion', 'source', 'machine', 'profile', 'retention']);
  if (request.schemaVersion !== CERTIFICATION_SCHEMA_VERSION) throw new CertificationError('certification_invalid_request', `schemaVersion must be ${CERTIFICATION_SCHEMA_VERSION}`);
  const sourceValue = object(request.source, 'source');
  allowedKeys(sourceValue, 'source', ['commit', 'tree', 'snapshot', 'expectedGuid']);
  const source = {
    commit: shaIdentity(sourceValue.commit, 'source.commit'),
    tree: shaIdentity(sourceValue.tree, 'source.tree'),
    snapshot: text(sourceValue.snapshot, 'source.snapshot', 256),
    ...(sourceValue.expectedGuid === undefined ? {} : { expectedGuid: text(sourceValue.expectedGuid, 'source.expectedGuid', 256) }),
  };
  const machine = normalizeMachineTemplate(request.machine);
  const profileValue = object(request.profile, 'profile');
  allowedKeys(profileValue, 'profile', ['id', 'version', 'steps']);
  if (!Array.isArray(profileValue.steps) || profileValue.steps.length === 0 || profileValue.steps.length > 50) throw new CertificationError('certification_invalid_request', 'profile.steps must contain between one and fifty steps');
  const stepIds = new Set<string>();
  const steps = profileValue.steps.map((entry, index): CertificationStepRequest => {
    const step = object(entry, `profile.steps[${index}]`);
    allowedKeys(step, `profile.steps[${index}]`, ['id', 'phase', 'argv', 'cwd', 'timeoutMs', 'required']);
    const id = text(step.id, `profile.steps[${index}].id`, 96);
    if (!/^[a-z0-9][a-z0-9_.-]{0,95}$/u.test(id) || stepIds.has(id)) throw new CertificationError('certification_invalid_request', 'profile step IDs must be unique safe identifiers', { id });
    stepIds.add(id);
    const phase = text(step.phase, `profile.steps[${index}].phase`, 32) as CertificationStepPhase;
    if (!['dependency', 'build', 'lint', 'unit', 'integration', 'acceptance'].includes(phase)) throw new CertificationError('certification_invalid_request', 'profile step phase is invalid', { phase });
    if (step.required !== undefined && typeof step.required !== 'boolean') throw new CertificationError('certification_invalid_request', `profile.steps[${index}].required must be boolean`);
    return {
      id,
      phase,
      argv: exactArgv(step.argv, `profile.steps[${index}].argv`),
      cwd: normalizedCwd(step.cwd ?? '/', `profile.steps[${index}].cwd`),
      ...(step.timeoutMs === undefined ? {} : { timeoutMs: integer(step.timeoutMs, `profile.steps[${index}].timeoutMs`, 1, 86_400_000) }),
      required: step.required !== false,
    };
  });
  const retentionValue = request.retention === undefined ? {} : object(request.retention, 'retention');
  allowedKeys(retentionValue, 'retention', ['preserveOnFailure', 'expiresAt']);
  if (retentionValue.preserveOnFailure !== undefined && typeof retentionValue.preserveOnFailure !== 'boolean') throw new CertificationError('certification_invalid_request', 'retention.preserveOnFailure must be boolean');
  return {
    schemaVersion: CERTIFICATION_SCHEMA_VERSION,
    source,
    machine,
    profile: { id: text(profileValue.id, 'profile.id', 128), version: text(profileValue.version, 'profile.version', 64), steps },
    retention: {
      preserveOnFailure: retentionValue.preserveOnFailure === true,
      ...(retentionValue.expiresAt === undefined ? {} : { expiresAt: timestamp(retentionValue.expiresAt, 'retention.expiresAt') as string }),
    },
  };
}

function json(value: unknown, field: string): JsonObject {
  return object(value, field);
}

function machineFrom(result: JsonObject): JsonObject {
  return json(result.machine, 'machine result');
}

function machineIdFrom(machine: JsonObject): string {
  return text(machine.machineId, 'machine.machineId', 128);
}

function machineNameFrom(machine: JsonObject): string {
  return text(machine.machineName, 'machine.machineName', 128);
}

function lifecycle(machine: JsonObject): JsonObject {
  return json(machine.lifecycle, 'machine.lifecycle');
}

function sequenceFrom(machine: JsonObject): number {
  return integer(lifecycle(machine).stateSequence, 'machine.lifecycle.stateSequence', 1, Number.MAX_SAFE_INTEGER);
}

function stateFrom(machine: JsonObject): string {
  return text(lifecycle(machine).persistedState, 'machine.lifecycle.persistedState', 64);
}

function activeJobIdsFrom(machine: JsonObject): string[] {
  const value = machine.activeJobIds;
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === 'string');
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string') : [];
}

function errorEvidence(error: unknown, fallbackCode: string): JsonObject {
  if (error instanceof CertificationError) return { code: error.code, message: error.message, details: error.details };
  if (error instanceof Error) {
    const candidate = error as Error & { code?: unknown; details?: unknown };
    return {
      code: typeof candidate.code === 'string' ? candidate.code : fallbackCode,
      message: candidate.message,
      ...(candidate.details !== undefined ? { details: candidate.details } : {}),
    };
  }
  return { code: fallbackCode, message: 'unknown certification failure' };
}

function internalContext(context: RuntimeExecutionContext, certificationIdValue: string, phase: string): RuntimeExecutionContext {
  return { ...context, idempotencyKey: `${certificationIdValue}:${phase}` };
}

function publicRecord(record: CertificationRecord): JsonObject {
  return {
    schemaVersion: record.schemaVersion,
    certificationId: record.certificationId,
    ownerPrincipal: record.ownerPrincipal,
    requestDigest: record.requestDigest,
    executionPolicy: structuredClone(record.executionPolicy),
    state: record.state,
    revision: record.revision,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    source: structuredClone(record.request.source),
    profile: {
      id: record.request.profile.id,
      version: record.request.profile.version,
      digest: sha256(canonicalize(record.request.profile)),
      steps: record.steps.map((step) => ({ ...step })),
    },
    retention: structuredClone(record.request.retention),
    machineId: record.machineId ?? null,
    machineName: record.machineName ?? null,
    machineSequence: record.machineSequence ?? null,
    jobIds: [...record.jobIds],
    artifactReferences: [...record.artifactReferences],
    proofReferences: [...record.proofReferences],
    testResult: structuredClone(record.testResult),
    evidence: structuredClone(record.evidence),
    cleanup: structuredClone(record.cleanup),
    lastError: record.lastError === undefined ? null : structuredClone(record.lastError),
    success: record.state === 'SUCCEEDED',
  };
}

class CertificationStore {
  private readonly store: AtomicStore<CertificationStoreState>;

  constructor(root: string) {
    mkdirSync(root, { recursive: true, mode: 0o700 });
    this.store = new AtomicStore(join(root, 'certifications.json'), { records: {}, byIdempotencyKey: {} });
  }

  createOrReplay(idempotencyKey: string, requestDigest: string, factory: () => CertificationRecord): CertificationRecord {
    let result: CertificationRecord | undefined;
    this.store.update((current) => {
      const existingId = current.byIdempotencyKey[idempotencyKey];
      if (existingId !== undefined) {
        const existing = current.records[existingId];
        if (existing === undefined) throw new CertificationError('certification_store_corrupt', 'certification idempotency index points to a missing record');
        if (existing.requestDigest !== requestDigest) throw new CertificationError('certification_idempotency_conflict', 'idempotency key was already used with a different certification request digest');
        result = existing;
        return current;
      }
      const record = factory();
      if (current.records[record.certificationId] !== undefined) throw new CertificationError('certification_store_conflict', 'certification ID already exists');
      result = record;
      return {
        records: { ...current.records, [record.certificationId]: record },
        byIdempotencyKey: { ...current.byIdempotencyKey, [idempotencyKey]: record.certificationId },
      };
    });
    if (result === undefined) throw new CertificationError('certification_store_corrupt', 'certification create did not produce a record');
    return structuredClone(result);
  }

  get(id: string): CertificationRecord {
    const record = this.store.read().records[id];
    if (record === undefined) throw new CertificationError('certification_not_found', 'certification was not found');
    return structuredClone(record);
  }

  list(): CertificationRecord[] {
    return Object.values(this.store.read().records).map((record) => structuredClone(record));
  }

  update(id: string, updater: (record: CertificationRecord) => CertificationRecord): CertificationRecord {
    let result: CertificationRecord | undefined;
    this.store.update((current) => {
      const existing = current.records[id];
      if (existing === undefined) throw new CertificationError('certification_not_found', 'certification was not found');
      const next = updater(structuredClone(existing));
      result = { ...next, revision: existing.revision + 1, updatedAt: new Date().toISOString() };
      return { ...current, records: { ...current.records, [id]: result } };
    });
    if (result === undefined) throw new CertificationError('certification_store_corrupt', 'certification update did not produce a record');
    return structuredClone(result);
  }
}

export class CertificationService {
  private readonly store: CertificationStore;
  private readonly evidenceRoot: string;
  private readonly now: () => string;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly certificationIdFactory: () => string;
  private readonly jobPollIntervalMs: number;
  private readonly machineSettleTimeoutMs: number;

  constructor(private readonly options: CertificationServiceOptions) {
    this.store = new CertificationStore(join(options.stateRoot, 'certification'));
    this.evidenceRoot = join(options.stateRoot, 'certification', 'evidence');
    mkdirSync(this.evidenceRoot, { recursive: true, mode: 0o700 });
    this.now = options.now ?? (() => new Date().toISOString());
    this.sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    this.certificationIdFactory = options.certificationIdFactory ?? (() => `cert_${randomUUID().replaceAll('-', '')}`);
    this.jobPollIntervalMs = options.jobPollIntervalMs ?? 100;
    this.machineSettleTimeoutMs = options.machineSettleTimeoutMs ?? 60_000;
  }

  describe(): JsonObject {
    return {
      operation: 'babyx.certification.describe',
      schemaVersion: CERTIFICATION_SCHEMA_VERSION,
      authority: 'certification',
      lifecycleAuthority: 'disposable-machine-service',
      executionAuthority: 'baby-x-durable-jobs',
      artifactAuthority: 'baby-x-artifacts',
      operations: ['babyx.certification.describe', 'babyx.certification.run', 'babyx.certification.resume', 'babyx.certification.get', 'babyx.certification.list', 'babyx.certification.cleanup'],
      phases: ['dependency', 'build', 'lint', 'unit', 'integration', 'acceptance'],
      maximumSteps: 50,
      successRequires: ['tests-passed', 'evidence-complete', 'stop-succeeded', 'destroy-succeeded', 'positive-absence-verification', 'source-preserved'],
    };
  }

  async run(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = mutationContext(context);
    const request = normalizeRequest(payload);
    const requestDigest = sha256(canonicalMachineEvidence(request));
    const createdAt = this.now();
    const executionPolicy = decideExecutionPolicy({
      schemaVersion: '1.0.0', objectiveType: 'certification', mutationRisk: 'high', dependencyUncertainty: request.profile.steps.some((step) => step.phase === 'dependency') ? 'unknown' : 'known', isolationRequirement: 'required', reversibility: 'reversible',
      requiredTools: request.profile.steps.flatMap((step) => step.argv.slice(0, 1)), requiredPackages: request.profile.steps.filter((step) => step.phase === 'dependency').map((step) => step.id), sourceSensitivity: 'internal', reproducibilityRequirement: 'required',
      networkRequirement: (object(request.machine.launch, 'machine.launch').networkMode === 'none' ? 'none' : 'private'), expectedDurationMs: request.profile.steps.reduce((total, step) => total + (step.timeoutMs ?? 3_600_000), 0),
      resourceProfile: { cpuUnits: 1, memoryMb: 1024, diskMb: 4096 }, explicitConstraint: 'auto', racingEligibility: false, candidateCount: 1, costBounds: { maxMachines: 1, maxDurationMs: 604_800_000, maxDiskMb: 1_048_576 },
    });
    const record = this.store.createOrReplay(authenticated.idempotencyKey, requestDigest, () => ({
      schemaVersion: CERTIFICATION_SCHEMA_VERSION,
      certificationId: this.certificationIdFactory(),
      ownerPrincipal: authenticated.subject,
      requestDigest,
      requestIdempotencyKey: authenticated.idempotencyKey,
      request,
      executionPolicy,
      state: 'REQUESTED',
      revision: 1,
      createdAt,
      updatedAt: createdAt,
      jobIds: [],
      artifactReferences: [],
      proofReferences: [],
      steps: request.profile.steps.map((step) => ({ id: step.id, phase: step.phase, required: step.required, state: 'pending' })),
      testResult: { status: 'pending' },
      evidence: { status: 'pending' },
      cleanup: { required: !request.retention.preserveOnFailure, stopStatus: 'pending', destroyStatus: 'pending', absenceVerified: false, sourcePreserved: false },
    }));
    this.authorize(record, context);
    if (['SUCCEEDED', 'FAILED', 'PRESERVED'].includes(record.state)) return { operation: 'babyx.certification.run', certification: publicRecord(record), replayed: true };
    return this.drive(record.certificationId, context, 'babyx.certification.run');
  }

  async resume(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    allowedKeys(payload, 'certification resume request', ['certificationId', 'reason']);
    mutationContext(context);
    optionalText(payload.reason, 'reason', 1024);
    const id = certificationId(payload.certificationId);
    const record = this.store.get(id);
    this.authorize(record, context);
    if (['SUCCEEDED', 'FAILED', 'PRESERVED'].includes(record.state)) return { operation: 'babyx.certification.resume', certification: publicRecord(record), replayed: true };
    return this.drive(id, context, 'babyx.certification.resume');
  }

  get(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    allowedKeys(payload, 'certification get request', ['certificationId']);
    const record = this.store.get(certificationId(payload.certificationId));
    this.authorize(record, context);
    return { operation: 'babyx.certification.get', certification: publicRecord(record) };
  }

  list(payload: JsonObject = {}, context: RuntimeExecutionContext): JsonObject {
    allowedKeys(payload, 'certification list request', ['state', 'offset', 'limit']);
    const subject = readSubject(context);
    const state = optionalText(payload.state, 'state', 64);
    if (state !== undefined && !['REQUESTED', 'CREATING', 'STARTING', 'RUNNING', 'CLEANING', 'SUCCEEDED', 'FAILED', 'PRESERVED', 'RECOVERY_REQUIRED'].includes(state)) throw new CertificationError('certification_invalid_request', 'state filter is invalid');
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, Number.MAX_SAFE_INTEGER);
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, 200);
    const filtered = this.store.list()
      .filter((record) => subject === undefined || record.ownerPrincipal === subject)
      .filter((record) => state === undefined || record.state === state)
      .sort((left, right) => left.certificationId.localeCompare(right.certificationId));
    const records = filtered.slice(offset, offset + limit).map(publicRecord);
    return { operation: 'babyx.certification.list', certifications: records, offset, limit, total: filtered.length, nextOffset: offset + records.length < filtered.length ? offset + records.length : null };
  }

  async cleanup(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    allowedKeys(payload, 'certification cleanup request', ['certificationId', 'reason']);
    mutationContext(context);
    optionalText(payload.reason, 'reason', 1024);
    const id = certificationId(payload.certificationId);
    let record = this.store.get(id);
    this.authorize(record, context);
    if (record.machineId === undefined) record = this.recoverMachineLink(record, context);
    if (record.machineId === undefined) throw new CertificationError('certification_cleanup_unavailable', 'certification has no durable machine identity');
    const expiresAt = record.request.retention.expiresAt;
    if (expiresAt !== undefined && Date.parse(expiresAt) > Date.parse(this.now())) throw new CertificationError('certification_retention_active', 'certification retention has not expired', { expiresAt });
    record = this.store.update(id, (current) => ({ ...current, state: 'CLEANING', cleanup: { ...current.cleanup, required: true } }));
    try {
      const currentMachine = this.machineRecord(record.machineId, context);
      if (stateFrom(currentMachine) !== 'DESTROYED') {
        this.options.machine.expire({ machineId: record.machineId, expectedSequence: sequenceFrom(currentMachine), reason: 'certification retention expired' }, internalContext(context, id, 'expire'));
      }
      record = await this.cleanupMachine(this.store.get(id), context);
      const final = this.store.update(id, (current) => ({
        ...current,
        state: current.testResult.status === 'passed' && current.evidence.status === 'complete' ? 'SUCCEEDED' : 'FAILED',
        cleanup: { ...current.cleanup, required: true },
      }));
      return { operation: 'babyx.certification.cleanup', certification: publicRecord(final) };
    } catch (error) {
      const failed = this.store.update(id, (current) => ({ ...current, state: 'RECOVERY_REQUIRED', lastError: errorEvidence(error, 'certification_cleanup_failed'), cleanup: { ...current.cleanup, required: true, error: errorEvidence(error, 'certification_cleanup_failed') } }));
      return { operation: 'babyx.certification.cleanup', certification: publicRecord(failed) };
    }
  }

  private authorize(record: CertificationRecord, context: RuntimeExecutionContext): void {
    const subject = readSubject(context);
    if (subject !== undefined && subject !== record.ownerPrincipal) throw new CertificationError('certification_not_found', 'certification was not found');
  }

  private machineCreateRequest(record: CertificationRecord): JsonObject {
    const machine = structuredClone(record.request.machine);
    machine.schemaVersion = '1.0.0';
    machine.ownerPrincipal = record.ownerPrincipal;
    machine.parentCertificationId = record.certificationId;
    machine.source = {
      kind: 'zfs-snapshot',
      snapshot: record.request.source.snapshot,
      ...(record.request.source.expectedGuid === undefined ? {} : { expectedGuid: record.request.source.expectedGuid }),
    };
    if (record.request.retention.expiresAt !== undefined) machine.expiresAt = record.request.retention.expiresAt;
    machine.startImmediately = false;
    return machine;
  }

  private async drive(id: string, context: RuntimeExecutionContext, operation: string): Promise<JsonObject> {
    let record = this.store.get(id);
    try {
      if (record.machineId === undefined) {
        record = this.store.update(id, (current) => ({ ...current, state: 'CREATING' }));
        const created = await this.options.machine.create(this.machineCreateRequest(record), internalContext(context, id, 'machine-create'));
        const machine = machineFrom(created);
        record = this.store.update(id, (current) => ({
          ...current,
          state: 'STARTING',
          machineId: machineIdFrom(machine),
          machineName: machineNameFrom(machine),
          machineSequence: sequenceFrom(machine),
          jobIds: this.addReference(current.jobIds, created.jobId),
        }));
      }

      let machine = this.machineRecord(record.machineId as string, context);
      if (!['READY', 'EXECUTING'].includes(stateFrom(machine))) {
        if (!['CLONED', 'STARTING'].includes(stateFrom(machine))) {
          await this.options.machine.reconcile({ machineId: record.machineId, reason: 'certification resume before start' }, internalContext(context, id, 'reconcile-before-start'));
          machine = this.machineRecord(record.machineId as string, context);
        }
        if (!['READY', 'EXECUTING'].includes(stateFrom(machine))) {
          const started = await this.options.machine.start({ machineId: record.machineId, expectedSequence: sequenceFrom(machine), reason: 'certification requires a ready machine' }, internalContext(context, id, 'machine-start'));
          machine = machineFrom(started);
          record = this.store.update(id, (current) => ({ ...current, machineSequence: sequenceFrom(machine), jobIds: this.addReference(current.jobIds, started.jobId) }));
        }
      }
      record = this.store.update(id, (current) => ({ ...current, state: 'RUNNING', machineSequence: sequenceFrom(machine) }));

      for (const requestedStep of record.request.profile.steps) {
        record = this.store.get(id);
        let step = record.steps.find((entry) => entry.id === requestedStep.id);
        if (step === undefined) throw new CertificationError('certification_store_corrupt', 'certification step record is missing', { stepId: requestedStep.id });
        if (step.state === 'passed') continue;
        if (step.state === 'failed') break;
        let jobId = step.jobId;
        if (jobId === undefined) {
          machine = this.machineRecord(record.machineId as string, context);
          const execution = await this.options.machine.exec({
            machineId: record.machineId,
            expectedSequence: sequenceFrom(machine),
            argv: requestedStep.argv,
            cwd: requestedStep.cwd,
            ...(requestedStep.timeoutMs === undefined ? {} : { timeoutMs: requestedStep.timeoutMs }),
            artifactPolicy: { captureStreams: true },
            reason: `certification ${record.certificationId} step ${requestedStep.id}`,
          }, internalContext(context, id, `step-${requestedStep.id}`));
          jobId = text(execution.jobId, 'machine execution jobId', 128);
          record = this.store.update(id, (current) => ({
            ...current,
            machineSequence: sequenceFrom(machineFrom(execution)),
            jobIds: this.addReference(current.jobIds, jobId),
            steps: current.steps.map((entry) => entry.id === requestedStep.id ? { ...entry, state: 'running', jobId, startedAt: this.now() } : entry),
          }));
          step = record.steps.find((entry) => entry.id === requestedStep.id) as CertificationStepRecord;
        }
        const job = await this.waitForJob(jobId, requestedStep.timeoutMs ?? 3_600_000);
        machine = await this.waitForMachineJob(record.machineId as string, job.id, context);
        const passed = job.status === 'completed' && job.exitCode === 0;
        record = this.store.update(id, (current) => ({
          ...current,
          machineSequence: sequenceFrom(machine),
          steps: current.steps.map((entry) => entry.id === requestedStep.id ? {
            ...entry,
            state: passed ? 'passed' : 'failed',
            exitCode: job.exitCode ?? null,
            signal: job.signal ?? null,
            completedAt: this.now(),
            ...(passed ? {} : { error: { code: 'certification_step_failed', message: `certification step ${requestedStep.id} failed`, jobStatus: job.status } }),
          } : entry),
          testResult: passed ? current.testResult : { status: 'failed', failedStepId: requestedStep.id },
        }));
        if (!passed && requestedStep.required) break;
      }

      record = this.store.get(id);
      const requiredFailed = record.steps.find((step) => step.required && step.state === 'failed');
      const requiredIncomplete = record.steps.find((step) => step.required && step.state !== 'passed' && step.state !== 'failed');
      const testsPassed = requiredFailed === undefined && requiredIncomplete === undefined;
      record = this.store.update(id, (current) => ({ ...current, testResult: testsPassed ? { status: 'passed' } : { status: 'failed', ...(requiredFailed === undefined ? {} : { failedStepId: requiredFailed.id }) } }));

      record = await this.captureDiagnostics(record, context);
      if (!testsPassed && record.request.retention.preserveOnFailure) {
        record = await this.captureEvidenceIndex(this.store.update(id, (current) => ({ ...current, state: 'PRESERVED', cleanup: { ...current.cleanup, required: false, stopStatus: 'not-required', destroyStatus: 'not-required' } })), context);
        const preserved = this.store.update(id, (current) => ({ ...current, state: 'PRESERVED' }));
        return { operation, certification: publicRecord(preserved), replayed: false };
      }

      record = this.store.update(id, (current) => ({ ...current, state: 'CLEANING', cleanup: { ...current.cleanup, required: true } }));
      record = await this.cleanupMachine(record, context);
      record = await this.captureEvidenceIndex(record, context);
      const success = record.testResult.status === 'passed'
        && record.evidence.status === 'complete'
        && record.cleanup.stopStatus === 'succeeded'
        && record.cleanup.destroyStatus === 'succeeded'
        && record.cleanup.absenceVerified
        && record.cleanup.sourcePreserved;
      const final = this.store.update(id, (current) => ({ ...current, state: success ? 'SUCCEEDED' : 'FAILED' }));
      return { operation, certification: publicRecord(final), replayed: false };
    } catch (error) {
      record = this.store.update(id, (current) => ({ ...current, lastError: errorEvidence(error, 'certification_failed'), testResult: current.testResult.status === 'pending' ? { status: 'failed' } : current.testResult }));
      if (record.machineId === undefined) record = this.recoverMachineLink(record, context, error);
      if (record.machineId !== undefined && !record.request.retention.preserveOnFailure) {
        try {
          record = this.store.update(id, (current) => ({ ...current, state: 'CLEANING', cleanup: { ...current.cleanup, required: true } }));
          record = await this.cleanupMachine(record, context);
        } catch (cleanupError) {
          const failed = this.store.update(id, (current) => ({ ...current, state: 'RECOVERY_REQUIRED', cleanup: { ...current.cleanup, required: true, error: errorEvidence(cleanupError, 'certification_cleanup_failed') }, lastError: errorEvidence(cleanupError, 'certification_cleanup_failed') }));
          return { operation, certification: publicRecord(failed), replayed: false };
        }
      } else if (record.request.retention.preserveOnFailure) {
        const preserved = this.store.update(id, (current) => ({ ...current, state: 'PRESERVED', cleanup: { ...current.cleanup, required: false, stopStatus: 'not-required', destroyStatus: 'not-required' } }));
        return { operation, certification: publicRecord(preserved), replayed: false };
      }
      try { record = await this.captureEvidenceIndex(record, context); } catch {}
      const failed = this.store.update(id, (current) => ({ ...current, state: current.cleanup.absenceVerified ? 'FAILED' : 'RECOVERY_REQUIRED' }));
      return { operation, certification: publicRecord(failed), replayed: false };
    }
  }

  private recoverMachineLink(record: CertificationRecord, context: RuntimeExecutionContext, error?: unknown): CertificationRecord {
    let machineId: string | undefined;
    if (error instanceof Error && 'details' in error) {
      const details = (error as Error & { details?: unknown }).details;
      if (details !== null && typeof details === 'object' && !Array.isArray(details) && typeof (details as JsonObject).machineId === 'string') machineId = String((details as JsonObject).machineId);
    }
    if (machineId === undefined) {
      const listed = this.options.machine.list({ parentCertificationId: record.certificationId, offset: 0, limit: 2 }, context);
      const machines = Array.isArray(listed.machines) ? listed.machines : [];
      if (machines.length === 0) return record;
      if (machines.length !== 1 || typeof (machines[0] as JsonObject).machineId !== 'string') throw new CertificationError('certification_machine_link_ambiguous', 'certification parent identity resolves to multiple machines', { certificationId: record.certificationId, count: machines.length });
      machineId = String((machines[0] as JsonObject).machineId);
    }
    const machine = this.machineRecord(machineId, context);
    if (machine.parentCertificationId !== record.certificationId) throw new CertificationError('certification_machine_link_ambiguous', 'machine parent certification identity does not match', { certificationId: record.certificationId, machineId });
    return this.store.update(record.certificationId, (current) => ({ ...current, machineId, machineName: machineNameFrom(machine), machineSequence: sequenceFrom(machine) }));
  }

  private reconcileRelatedJobs(record: CertificationRecord): JobRecord[] {
    const jobs = record.jobIds.map((jobId) => this.options.jobs.reconcile(jobId));
    const running = jobs.filter((job) => job.status === 'running').map((job) => job.id);
    if (running.length > 0) throw new CertificationError('certification_job_active', 'related durable jobs remain active after machine teardown', { jobIds: running });
    return jobs;
  }

  private async captureDiagnostics(record: CertificationRecord, context: RuntimeExecutionContext): Promise<CertificationRecord> {
    if (record.machineId === undefined || record.evidence.diagnosticArtifactReference !== undefined) return record;
    try {
      const machine = this.machineRecord(record.machineId, context);
      const result = await this.options.machine.diagnostics({ machineId: record.machineId, expectedSequence: sequenceFrom(machine), maxEvents: 200, maxJobReferences: 200, reason: 'certification evidence capture before teardown' }, internalContext(context, record.certificationId, 'diagnostics'));
      const reference = optionalText(result.artifactReference, 'diagnostic artifact reference', 256);
      if (reference === undefined) throw new CertificationError('certification_evidence_failed', 'machine diagnostics did not produce an artifact reference');
      return this.store.update(record.certificationId, (current) => ({
        ...current,
        machineSequence: typeof result.stateSequence === 'number' ? result.stateSequence : current.machineSequence,
        artifactReferences: reference === undefined ? current.artifactReferences : this.addReference(current.artifactReferences, reference),
        evidence: { ...current.evidence, ...(reference === undefined ? {} : { diagnosticArtifactReference: reference }) },
      }));
    } catch (error) {
      return this.store.update(record.certificationId, (current) => ({ ...current, evidence: { ...current.evidence, status: 'failed', error: errorEvidence(error, 'certification_evidence_failed') } }));
    }
  }

  private async cleanupMachine(record: CertificationRecord, context: RuntimeExecutionContext): Promise<CertificationRecord> {
    if (record.machineId === undefined) return record;
    let machine = this.machineRecord(record.machineId, context);
    let machineState = stateFrom(machine);
    if (machineState === 'RECOVERY_REQUIRED') {
      await this.options.machine.reconcile({ machineId: record.machineId, reason: 'certification cleanup classification' }, internalContext(context, record.certificationId, 'cleanup-reconcile'));
      machine = this.machineRecord(record.machineId, context);
      machineState = stateFrom(machine);
    }
    if (['LOST', 'AMBIGUOUS', 'UNKNOWN'].includes(machineState)) throw new CertificationError('certification_cleanup_ambiguous', 'machine state blocks ordinary certification cleanup', { machineId: record.machineId, state: machineState });

    let stopStatus: CertificationRecord['cleanup']['stopStatus'] = record.cleanup.stopStatus;
    if (machineState === 'DESTROYED') stopStatus = 'succeeded';
    else if (['REQUESTED', 'CLONING', 'CLONED', 'STOPPED', 'DESTROYING'].includes(machineState)) stopStatus = 'not-required';
    else {
      const stopped = await this.options.machine.stop({ machineId: record.machineId, expectedSequence: sequenceFrom(machine), gracefulTimeoutMs: 30_000, forceAfterTimeout: false, reason: 'certification teardown' }, internalContext(context, record.certificationId, 'machine-stop'));
      machine = machineFrom(stopped);
      stopStatus = stateFrom(machine) === 'STOPPED' ? 'succeeded' : 'failed';
      record = this.store.update(record.certificationId, (current) => ({ ...current, machineSequence: sequenceFrom(machine), cleanup: { ...current.cleanup, stopStatus } }));
      if (stopStatus !== 'succeeded') throw new CertificationError('certification_stop_failed', 'certification machine did not reach STOPPED');
    }

    this.reconcileRelatedJobs(this.store.get(record.certificationId));
    if (stateFrom(machine) !== 'DESTROYED') {
      const destroyed = await this.options.machine.destroy({ machineId: record.machineId, expectedSequence: sequenceFrom(machine), stopIfRunning: true, forceStop: false, stopTimeoutMs: 30_000, reason: 'certification teardown and evidence retention' }, internalContext(context, record.certificationId, 'machine-destroy'));
      machine = machineFrom(destroyed);
      const machineLifecycle = lifecycle(machine);
      const cleanup = json(machine.cleanup, 'destroyed machine cleanup');
      const verified = machineLifecycle.persistedState === 'DESTROYED'
        && machineLifecycle.observedState === 'ABSENT'
        && cleanup.completed === true
        && cleanup.datasetAbsentVerified === true
        && cleanup.rootAbsentVerified === true
        && cleanup.machineAbsentVerified === true
        && cleanup.processAbsentVerified === true;
      if (!verified) throw new CertificationError('certification_destroy_failed', 'certification machine cleanup was not positively verified');
      const artifacts = [...stringArray(machine.artifactIds), ...stringArray(destroyed.artifactReferences)];
      record = this.store.update(record.certificationId, (current) => ({
        ...current,
        machineSequence: sequenceFrom(machine),
        artifactReferences: [...new Set([...current.artifactReferences, ...artifacts])].sort(),
        proofReferences: [...new Set([...current.proofReferences, text(json(destroyed.tombstone, 'destroy tombstone').finalEventDigest, 'tombstone.finalEventDigest', 128)])].sort(),
        cleanup: { ...current.cleanup, stopStatus, destroyStatus: 'succeeded', absenceVerified: false, sourcePreserved: true },
      }));
    } else {
      record = this.store.update(record.certificationId, (current) => ({ ...current, machineSequence: sequenceFrom(machine), cleanup: { ...current.cleanup, stopStatus, destroyStatus: 'succeeded', absenceVerified: false, sourcePreserved: true } }));
    }
    this.reconcileRelatedJobs(this.store.get(record.certificationId));
    const status = await this.options.machine.status({ machineId: record.machineId, includeJobs: true, includeRecentEvents: true }, context);
    const observed = json(status.observed, 'machine status observed');
    if (observed.state !== 'ABSENT') throw new CertificationError('certification_cleanup_failed', 'post-destroy machine status did not confirm ABSENT', { observedState: observed.state });
    return this.store.update(record.certificationId, (current) => ({ ...current, cleanup: { ...current.cleanup, absenceVerified: true } }));
  }

  private async captureEvidenceIndex(record: CertificationRecord, context: RuntimeExecutionContext): Promise<CertificationRecord> {
    if (record.evidence.indexArtifactReference !== undefined) return record;
    if (this.options.artifacts === undefined) {
      return this.store.update(record.certificationId, (current) => ({ ...current, evidence: { ...current.evidence, status: 'failed', error: { code: 'certification_evidence_failed', message: 'artifact authority is unavailable' } } }));
    }
    try {
      const machineEvents = record.machineId === undefined ? [] : json(this.options.machine.events({ machineId: record.machineId, offset: 0, limit: 200 }, context), 'machine events').events;
      const evidence = {
        schemaVersion: CERTIFICATION_SCHEMA_VERSION,
        certificationId: record.certificationId,
        ownerPrincipal: record.ownerPrincipal,
        source: record.request.source,
        profile: { id: record.request.profile.id, version: record.request.profile.version, digest: sha256(canonicalize(record.request.profile)) },
        executionPolicy: record.executionPolicy,
        state: record.state,
        testResult: record.testResult,
        evidence: { diagnosticArtifactReference: record.evidence.diagnosticArtifactReference ?? null },
        cleanup: record.cleanup,
        machineId: record.machineId ?? null,
        machineSequence: record.machineSequence ?? null,
        jobs: record.jobIds,
        steps: record.steps,
        artifactReferences: record.artifactReferences,
        proofReferences: record.proofReferences,
        machineEvents,
        capturedAt: this.now(),
      };
      const canonical = `${canonicalMachineEvidence(evidence)}\n`;
      if (Buffer.byteLength(canonical) > 1_048_576) throw new CertificationError('certification_evidence_failed', 'certification evidence index exceeds the one-megabyte bound');
      const digest = sha256(canonical);
      const path = join(this.evidenceRoot, `${record.certificationId}-${digest.slice(0, 16)}.json`);
      writeFileSync(path, canonical, { mode: 0o600, flag: 'wx' });
      let artifact: JsonObject;
      try {
        artifact = this.options.artifacts.create(`certification-${record.certificationId}-evidence-index`, path, { certificationId: record.certificationId, evidenceDigest: digest, sourceCommit: record.request.source.commit, sourceTree: record.request.source.tree });
      } finally {
        rmSync(path, { force: true });
      }
      const artifactId = text(artifact.id, 'certification evidence artifact ID', 256);
      return this.store.update(record.certificationId, (current) => ({
        ...current,
        artifactReferences: this.addReference(current.artifactReferences, artifactId),
        proofReferences: this.addReference(current.proofReferences, digest),
        evidence: { ...current.evidence, status: current.evidence.status === 'failed' ? 'failed' : 'complete', indexArtifactReference: artifactId, indexDigest: digest },
      }));
    } catch (error) {
      return this.store.update(record.certificationId, (current) => ({ ...current, evidence: { ...current.evidence, status: 'failed', error: errorEvidence(error, 'certification_evidence_failed') } }));
    }
  }

  private machineRecord(machineId: string, context: RuntimeExecutionContext): JsonObject {
    return machineFrom(this.options.machine.get({ machineId }, context));
  }

  private async waitForJob(jobId: string, timeoutMs: number): Promise<JobRecord> {
    const started = Date.now();
    for (;;) {
      const job = this.options.jobs.get(jobId);
      if (job.status !== 'running') return job;
      if (Date.now() - started >= timeoutMs + 60_000) throw new CertificationError('certification_job_wait_timeout', 'certification job did not reach a durable terminal state within the bounded wait', { jobId });
      await this.sleep(this.jobPollIntervalMs);
    }
  }

  private async waitForMachineJob(machineId: string, completedJobId: string, context: RuntimeExecutionContext): Promise<JsonObject> {
    const started = Date.now();
    for (;;) {
      const machine = this.machineRecord(machineId, context);
      const active = activeJobIdsFrom(machine);
      if (!active.includes(completedJobId)) return machine;
      if (Date.now() - started >= this.machineSettleTimeoutMs) {
        await this.options.machine.reconcile({ machineId, reason: 'certification waiting for durable job completion reconciliation' }, internalContext(context, machineId, `settle-${completedJobId}`));
        const reconciled = this.machineRecord(machineId, context);
        const remaining = activeJobIdsFrom(reconciled);
        if (!remaining.includes(completedJobId)) return reconciled;
        throw new CertificationError('certification_machine_settle_timeout', 'machine record did not settle after durable job completion', { machineId, completedJobId });
      }
      await this.sleep(this.jobPollIntervalMs);
    }
  }

  private addReference(values: string[], value: unknown): string[] {
    return typeof value === 'string' && value.length > 0 ? [...new Set([...values, value])].sort() : [...values];
  }
}
