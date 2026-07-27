import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import type { CertificationService } from '../certification/service.ts';
import { canonicalMachineEvidence } from '../machines/schemas.ts';
import { decideExecutionPolicy, type ExecutionPolicyDecision } from '../policy/execution.ts';
import { DurableClaimStore, DurableRecordStore } from '../storage/record-store.ts';

export const CANDIDATE_RACE_SCHEMA_VERSION = '1.0.0' as const;
export type CandidateRaceState = 'REQUESTED' | 'RUNNING' | 'SCORING' | 'COMPLETED' | 'NO_WINNER' | 'RECOVERY_REQUIRED';
export type CandidateState = 'pending' | 'running' | 'accepted' | 'rejected' | 'failed';

export interface CandidateScore extends JsonObject {
  correctness: number;
  securityPolicy: number;
  reproducibility: number;
  regressionRisk: number;
  maintainability: number;
  changeSize: number;
  resourceCost: number;
}

interface RaceStep extends JsonObject {
  id: string;
  phase: 'dependency' | 'build' | 'lint' | 'unit' | 'integration' | 'acceptance';
  argv: string[];
  cwd: string;
  timeoutMs?: number;
  required: boolean;
}

interface CandidateRequest extends JsonObject {
  candidateId: string;
  strategyDigest: string;
  machine: JsonObject;
  strategySteps: RaceStep[];
  assessment: {
    regressionRisk: number;
    maintainability: number;
    changeSize: number;
    resourceCost: number;
  };
}

interface RaceRequest extends JsonObject {
  schemaVersion: typeof CANDIDATE_RACE_SCHEMA_VERSION;
  objective: { objectiveId: string; description: string; objectiveDigest: string };
  source: { commit: string; tree: string; snapshot: string; expectedGuid?: string };
  candidates: CandidateRequest[];
  validation: { profileId: string; version: string; steps: RaceStep[] };
  preservation: { preserveWinnerEvidence: boolean; preserveFailureEvidence: boolean };
  costBounds: { maxMachines: number; maxDurationMs: number; maxDiskMb: number };
}

interface CandidateRecord extends JsonObject {
  candidateId: string;
  strategyDigest: string;
  sourceIdentity: JsonObject;
  machineTemplateDigest: string;
  validationProfileDigest: string;
  certificationId?: string;
  machineId?: string;
  childJobIds: string[];
  artifactReferences: string[];
  proofReferences: string[];
  state: CandidateState;
  score?: CandidateScore;
  rejectionReason?: string;
  selected: boolean;
  cleanupVerified: boolean;
  certification?: JsonObject;
}

interface RaceRecord extends JsonObject {
  schemaVersion: typeof CANDIDATE_RACE_SCHEMA_VERSION;
  raceId: string;
  ownerPrincipal: string;
  requestIdempotencyKey: string;
  requestDigest: string;
  request: RaceRequest;
  executionPolicy: ExecutionPolicyDecision;
  state: CandidateRaceState;
  revision: number;
  createdAt: string;
  updatedAt: string;
  candidates: CandidateRecord[];
  winnerCandidateId?: string;
  evidenceArtifactReference?: string;
  evidenceDigest?: string;
  cleanupFailures: JsonObject[];
  lastError?: JsonObject;
}

interface RaceStoreState extends JsonObject {
  records: Record<string, RaceRecord>;
  byIdempotencyKey: Record<string, string>;
}

interface RaceArtifactAuthority {
  create(name: string, sourcePath: string, metadata?: JsonObject): JsonObject;
}

export interface CandidateRaceServiceOptions {
  stateRoot: string;
  certification: CertificationService;
  artifacts?: RaceArtifactAuthority;
  now?: () => string;
  raceIdFactory?: () => string;
}

export class CandidateRaceError extends Error {
  constructor(readonly code: string, message: string, readonly details: JsonObject = {}) {
    super(message);
    this.name = 'CandidateRaceError';
  }
}

function object(value: unknown, field: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new CandidateRaceError('candidate_race_invalid_request', `${field} must be an object`);
  return value as JsonObject;
}
function allowed(value: JsonObject, field: string, keys: readonly string[]): void {
  const set = new Set(keys);
  const unknown = Object.keys(value).filter((key) => !set.has(key));
  if (unknown.length > 0) throw new CandidateRaceError('candidate_race_invalid_request', `${field} contains unsupported properties`, { properties: unknown });
}
function text(value: unknown, field: string, maximum = 512): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum || value.includes('\0')) throw new CandidateRaceError('candidate_race_invalid_request', `${field} must be a bounded non-empty NUL-free string`);
  return value;
}
function identifier(value: unknown, field: string): string {
  const candidate = text(value, field, 96);
  if (!/^[a-z0-9][a-z0-9_.-]{0,95}$/u.test(candidate)) throw new CandidateRaceError('candidate_race_invalid_request', `${field} must be a safe identifier`);
  return candidate;
}
function digest(value: unknown, field: string, lengths: readonly number[] = [40, 64]): string {
  const candidate = text(value, field, 64);
  if (!lengths.includes(candidate.length) || !/^[a-f0-9]+$/u.test(candidate)) throw new CandidateRaceError('candidate_race_invalid_request', `${field} must be a lowercase hexadecimal digest`);
  return candidate;
}
function integer(value: unknown, field: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new CandidateRaceError('candidate_race_invalid_request', `${field} must be a safe integer between ${minimum} and ${maximum}`);
  return Number(value);
}
function boolean(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') throw new CandidateRaceError('candidate_race_invalid_request', `${field} must be boolean`);
  return value;
}
function mutationContext(context: RuntimeExecutionContext): { idempotencyKey: string; subject: string } {
  const idempotencyKey = text(context.idempotencyKey, 'idempotencyKey', 256);
  if (idempotencyKey.length < 8) throw new CandidateRaceError('candidate_race_invalid_request', 'idempotencyKey must contain at least eight characters');
  return { idempotencyKey, subject: text(context.subject, 'subject', 256) };
}
function readSubject(context: RuntimeExecutionContext): string | undefined {
  return context.authorityClass === 'unrestricted-owner' ? undefined : text(context.subject, 'subject', 256);
}
function raceId(value: unknown): string {
  const candidate = text(value, 'raceId', 128);
  if (!/^race_[a-z0-9][a-z0-9_-]{7,120}$/u.test(candidate)) throw new CandidateRaceError('candidate_race_invalid_request', 'raceId is invalid');
  return candidate;
}
function argv(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 128) throw new CandidateRaceError('candidate_race_invalid_request', `${field} must be a non-empty bounded argv array`);
  return value.map((entry, index) => text(entry, `${field}[${index}]`, 4096));
}
function step(value: unknown, field: string): RaceStep {
  const item = object(value, field);
  allowed(item, field, ['id', 'phase', 'argv', 'cwd', 'timeoutMs', 'required']);
  const phase = text(item.phase, `${field}.phase`, 32) as RaceStep['phase'];
  if (!['dependency', 'build', 'lint', 'unit', 'integration', 'acceptance'].includes(phase)) throw new CandidateRaceError('candidate_race_invalid_request', `${field}.phase is invalid`);
  const cwd = text(item.cwd, `${field}.cwd`, 1024);
  if (!cwd.startsWith('/') || cwd.includes('/../') || cwd.endsWith('/..')) throw new CandidateRaceError('candidate_race_invalid_request', `${field}.cwd must be an absolute confined path`);
  return {
    id: identifier(item.id, `${field}.id`), phase, argv: argv(item.argv, `${field}.argv`), cwd,
    ...(item.timeoutMs === undefined ? {} : { timeoutMs: integer(item.timeoutMs, `${field}.timeoutMs`, 1, 86_400_000) }),
    required: item.required === undefined ? true : boolean(item.required, `${field}.required`),
  };
}
function machineIdentities(machine: JsonObject, field: string): { machineName: string; dataset: string; mountpoint: string } {
  const clone = object(machine.clone, `${field}.clone`);
  return {
    machineName: text(machine.machineName, `${field}.machineName`, 64),
    dataset: text(clone.dataset, `${field}.clone.dataset`, 256),
    mountpoint: text(clone.mountpoint, `${field}.clone.mountpoint`, 1024),
  };
}

function normalizeRequest(value: unknown): RaceRequest {
  const request = object(value, 'candidate race request');
  allowed(request, 'candidate race request', ['schemaVersion', 'objective', 'source', 'candidates', 'validation', 'preservation', 'costBounds']);
  if (request.schemaVersion !== CANDIDATE_RACE_SCHEMA_VERSION) throw new CandidateRaceError('candidate_race_invalid_request', `schemaVersion must be ${CANDIDATE_RACE_SCHEMA_VERSION}`);
  const objectiveValue = object(request.objective, 'objective');
  allowed(objectiveValue, 'objective', ['objectiveId', 'description', 'objectiveDigest']);
  const objective = { objectiveId: identifier(objectiveValue.objectiveId, 'objective.objectiveId'), description: text(objectiveValue.description, 'objective.description', 4096), objectiveDigest: digest(objectiveValue.objectiveDigest, 'objective.objectiveDigest', [64]) };
  if (sha256(objective.description) !== objective.objectiveDigest) throw new CandidateRaceError('candidate_race_invalid_request', 'objectiveDigest does not match the objective description');
  const sourceValue = object(request.source, 'source');
  allowed(sourceValue, 'source', ['commit', 'tree', 'snapshot', 'expectedGuid']);
  const source = { commit: digest(sourceValue.commit, 'source.commit'), tree: digest(sourceValue.tree, 'source.tree'), snapshot: text(sourceValue.snapshot, 'source.snapshot', 256), ...(sourceValue.expectedGuid === undefined ? {} : { expectedGuid: text(sourceValue.expectedGuid, 'source.expectedGuid', 256) }) };
  const validationValue = object(request.validation, 'validation');
  allowed(validationValue, 'validation', ['profileId', 'version', 'steps']);
  if (!Array.isArray(validationValue.steps) || validationValue.steps.length === 0 || validationValue.steps.length > 50) throw new CandidateRaceError('candidate_race_invalid_request', 'validation.steps must contain between one and fifty common steps');
  const validationSteps = validationValue.steps.map((entry, index) => step(entry, `validation.steps[${index}]`));
  const validationIds = new Set(validationSteps.map((entry) => entry.id));
  if (validationIds.size !== validationSteps.length) throw new CandidateRaceError('candidate_race_invalid_request', 'validation step IDs must be unique');
  const validation = { profileId: identifier(validationValue.profileId, 'validation.profileId'), version: text(validationValue.version, 'validation.version', 64), steps: validationSteps };
  if (!Array.isArray(request.candidates) || request.candidates.length < 2 || request.candidates.length > 20) throw new CandidateRaceError('candidate_race_invalid_request', 'candidates must contain between two and twenty candidates');
  const candidates = request.candidates.map((entry, index): CandidateRequest => {
    const candidate = object(entry, `candidates[${index}]`);
    allowed(candidate, `candidates[${index}]`, ['candidateId', 'strategyDigest', 'machine', 'strategySteps', 'assessment']);
    if (!Array.isArray(candidate.strategySteps) || candidate.strategySteps.length === 0 || candidate.strategySteps.length > 50) throw new CandidateRaceError('candidate_race_invalid_request', `candidates[${index}].strategySteps must contain between one and fifty steps`);
    const strategySteps = candidate.strategySteps.map((item, stepIndex) => step(item, `candidates[${index}].strategySteps[${stepIndex}]`));
    const strategyIds = new Set(strategySteps.map((item) => item.id));
    if (strategyIds.size !== strategySteps.length || strategySteps.some((item) => validationIds.has(item.id))) throw new CandidateRaceError('candidate_race_invalid_request', 'strategy and validation step IDs must be unique within a candidate');
    const assessmentValue = object(candidate.assessment, `candidates[${index}].assessment`);
    allowed(assessmentValue, `candidates[${index}].assessment`, ['regressionRisk', 'maintainability', 'changeSize', 'resourceCost']);
    const strategyDigest = digest(candidate.strategyDigest, `candidates[${index}].strategyDigest`, [64]);
    if (sha256(canonicalize(strategySteps)) !== strategyDigest) throw new CandidateRaceError('candidate_race_invalid_request', 'strategyDigest does not match normalized strategy steps', { candidateId: candidate.candidateId });
    return {
      candidateId: identifier(candidate.candidateId, `candidates[${index}].candidateId`),
      strategyDigest,
      machine: structuredClone(object(candidate.machine, `candidates[${index}].machine`)),
      strategySteps,
      assessment: {
        regressionRisk: integer(assessmentValue.regressionRisk, `candidates[${index}].assessment.regressionRisk`, 0, 100),
        maintainability: integer(assessmentValue.maintainability, `candidates[${index}].assessment.maintainability`, 0, 100),
        changeSize: integer(assessmentValue.changeSize, `candidates[${index}].assessment.changeSize`, 0, 1_000_000),
        resourceCost: integer(assessmentValue.resourceCost, `candidates[${index}].assessment.resourceCost`, 0, 1_000_000),
      },
    };
  });
  const candidateIds = new Set(candidates.map((candidate) => candidate.candidateId));
  if (candidateIds.size !== candidates.length) throw new CandidateRaceError('candidate_race_invalid_request', 'candidate IDs must be unique');
  const names = new Set<string>(); const datasets = new Set<string>(); const mountpoints = new Set<string>();
  for (const [index, candidate] of candidates.entries()) {
    const identity = machineIdentities(candidate.machine, `candidates[${index}].machine`);
    if (names.has(identity.machineName) || datasets.has(identity.dataset) || mountpoints.has(identity.mountpoint)) throw new CandidateRaceError('candidate_race_shared_writable_state', 'candidate machine names, clone datasets, and mountpoints must be unique');
    names.add(identity.machineName); datasets.add(identity.dataset); mountpoints.add(identity.mountpoint);
  }
  const preservationValue = object(request.preservation, 'preservation');
  allowed(preservationValue, 'preservation', ['preserveWinnerEvidence', 'preserveFailureEvidence']);
  const preservation = { preserveWinnerEvidence: boolean(preservationValue.preserveWinnerEvidence, 'preservation.preserveWinnerEvidence'), preserveFailureEvidence: boolean(preservationValue.preserveFailureEvidence, 'preservation.preserveFailureEvidence') };
  const costValue = object(request.costBounds, 'costBounds');
  allowed(costValue, 'costBounds', ['maxMachines', 'maxDurationMs', 'maxDiskMb']);
  const costBounds = { maxMachines: integer(costValue.maxMachines, 'costBounds.maxMachines', 1, 100), maxDurationMs: integer(costValue.maxDurationMs, 'costBounds.maxDurationMs', 1, 604_800_000), maxDiskMb: integer(costValue.maxDiskMb, 'costBounds.maxDiskMb', 1, 10_485_760) };
  return { schemaVersion: CANDIDATE_RACE_SCHEMA_VERSION, objective, source, candidates, validation, preservation, costBounds };
}

function errorEvidence(error: unknown, fallback: string): JsonObject {
  if (error instanceof CandidateRaceError) return { code: error.code, message: error.message, details: error.details };
  if (error instanceof Error) return { code: typeof (error as Error & { code?: unknown }).code === 'string' ? (error as Error & { code: string }).code : fallback, message: error.message };
  return { code: fallback, message: 'unknown candidate race failure' };
}
function publicRecord(record: RaceRecord): JsonObject {
  return {
    schemaVersion: record.schemaVersion, raceId: record.raceId, ownerPrincipal: record.ownerPrincipal,
    requestDigest: record.requestDigest, objective: structuredClone(record.request.objective), source: structuredClone(record.request.source),
    validationProfileDigest: sha256(canonicalize(record.request.validation)), executionPolicy: structuredClone(record.executionPolicy),
    state: record.state, revision: record.revision, createdAt: record.createdAt, updatedAt: record.updatedAt,
    winnerCandidateId: record.winnerCandidateId ?? null, evidenceArtifactReference: record.evidenceArtifactReference ?? null,
    evidenceDigest: record.evidenceDigest ?? null, cleanupFailures: structuredClone(record.cleanupFailures),
    candidates: record.candidates.map((candidate) => structuredClone(candidate)), lastError: record.lastError === undefined ? null : structuredClone(record.lastError),
  };
}

class RaceStore {
  private readonly records: DurableRecordStore<RaceRecord>;
  private readonly claims: DurableClaimStore<RaceRecord>;

  constructor(root: string) {
    mkdirSync(root, { recursive: true, mode: 0o700 });
    this.records = new DurableRecordStore(join(root, 'record-store-v1'));
    this.claims = new DurableClaimStore(join(root, 'idempotency-v1'));
    this.importLegacy(join(root, 'races.json'));
  }

  private importLegacy(path: string): void {
    if (!existsSync(path)) return;
    let legacy: RaceStoreState;
    try { legacy = JSON.parse(readFileSync(path, 'utf8')) as RaceStoreState; }
    catch (error) { throw new CandidateRaceError('candidate_race_store_corrupt', 'legacy race store is corrupt', { cause: error instanceof Error ? error.message : String(error) }); }
    for (const [id, record] of Object.entries(legacy.records ?? {})) if (!this.records.has(id)) this.records.create(id, record);
    for (const [key, id] of Object.entries(legacy.byIdempotencyKey ?? {})) {
      const record = legacy.records?.[id];
      if (record !== undefined) this.claims.claim(key, record.requestDigest, id, record);
    }
  }

  createOrReplay(key: string, requestDigest: string, factory: () => RaceRecord): RaceRecord {
    const existingClaim = this.claims.get(key);
    if (existingClaim !== undefined) {
      if (existingClaim.requestDigest !== requestDigest) throw new CandidateRaceError('candidate_race_idempotency_conflict', 'idempotency key was used with a different race request');
      if (!this.records.has(existingClaim.recordId)) this.records.create(existingClaim.recordId, existingClaim.record);
      const existing = this.records.get(existingClaim.recordId);
      if (existing.requestDigest !== requestDigest) throw new CandidateRaceError('candidate_race_store_corrupt', 'race claim points to a conflicting record');
      return structuredClone(existing);
    }
    const proposed = factory();
    if (this.records.has(proposed.raceId)) throw new CandidateRaceError('candidate_race_store_conflict', 'candidate race ID already exists');
    const claim = this.claims.claim(key, requestDigest, proposed.raceId, proposed);
    if (claim.requestDigest !== requestDigest) throw new CandidateRaceError('candidate_race_idempotency_conflict', 'idempotency key was used with a different race request');
    if (!this.records.has(claim.recordId)) this.records.create(claim.recordId, claim.record);
    return structuredClone(this.records.get(claim.recordId));
  }

  get(id: string): RaceRecord {
    try { return structuredClone(this.records.get(id)); }
    catch (error) {
      if (error instanceof Error && error.message === 'record not found') throw new CandidateRaceError('candidate_race_not_found', 'candidate race was not found');
      throw new CandidateRaceError('candidate_race_store_corrupt', error instanceof Error ? error.message : 'candidate race record is corrupt');
    }
  }

  list(predicate: (record: RaceRecord) => boolean, offset: number, limit: number) { return this.records.scan(predicate, offset, limit); }

  update(id: string, now: string, updater: (record: RaceRecord) => RaceRecord): RaceRecord {
    try { return this.records.update(id, (record) => ({ ...updater(record), revision: record.revision + 1, updatedAt: now })); }
    catch (error) {
      if (error instanceof Error && error.message === 'record not found') throw new CandidateRaceError('candidate_race_not_found', 'candidate race was not found');
      if (error instanceof CandidateRaceError) throw error;
      throw new CandidateRaceError('candidate_race_store_corrupt', error instanceof Error ? error.message : 'race update failed');
    }
  }
}

export function compareCandidateScores(left: CandidateRecord, right: CandidateRecord): number {
  const a = left.score; const b = right.score;
  if (a === undefined || b === undefined) throw new CandidateRaceError('candidate_race_score_missing', 'accepted candidates require scores');
  const comparisons: Array<[number, number, 'higher' | 'lower']> = [
    [a.correctness, b.correctness, 'higher'], [a.securityPolicy, b.securityPolicy, 'higher'], [a.reproducibility, b.reproducibility, 'higher'],
    [a.regressionRisk, b.regressionRisk, 'lower'], [a.maintainability, b.maintainability, 'higher'], [a.changeSize, b.changeSize, 'lower'], [a.resourceCost, b.resourceCost, 'lower'],
  ];
  for (const [leftValue, rightValue, direction] of comparisons) {
    if (leftValue === rightValue) continue;
    return direction === 'higher' ? rightValue - leftValue : leftValue - rightValue;
  }
  return left.candidateId.localeCompare(right.candidateId);
}

export class CandidateRaceService {
  private readonly store: RaceStore;
  private readonly evidenceRoot: string;
  private readonly now: () => string;
  private readonly raceIdFactory: () => string;
  constructor(private readonly options: CandidateRaceServiceOptions) {
    this.store = new RaceStore(join(options.stateRoot, 'candidate-racing'));
    this.evidenceRoot = join(options.stateRoot, 'candidate-racing', 'evidence');
    mkdirSync(this.evidenceRoot, { recursive: true, mode: 0o700 });
    this.now = options.now ?? (() => new Date().toISOString());
    this.raceIdFactory = options.raceIdFactory ?? (() => `race_${randomUUID().replaceAll('-', '')}`);
  }
  describe(): JsonObject {
    return {
      operation: 'babyx.race.describe', schemaVersion: CANDIDATE_RACE_SCHEMA_VERSION,
      operations: ['babyx.race.describe', 'babyx.race.run', 'babyx.race.resume', 'babyx.race.get', 'babyx.race.list'],
      lifecycleAuthority: 'certification-through-disposable-machine-service', scoring: 'lexicographic-correctness-security-reproducibility-risk-maintainability-size-resource-id',
      automaticMerge: false, automaticDeploy: false, minimumCandidates: 2, maximumCandidates: 20,
    };
  }
  async run(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = mutationContext(context);
    const request = normalizeRequest(payload);
    const requestDigest = sha256(canonicalMachineEvidence(request));
    const executionPolicy = decideExecutionPolicy({
      schemaVersion: '1.0.0', objectiveType: 'candidate-race', mutationRisk: 'high', dependencyUncertainty: 'unknown', isolationRequirement: 'required', reversibility: 'reversible',
      requiredTools: [...new Set(request.candidates.flatMap((candidate) => candidate.strategySteps.flatMap((item) => item.argv.slice(0, 1))).concat(request.validation.steps.flatMap((item) => item.argv.slice(0, 1))))],
      requiredPackages: request.candidates.flatMap((candidate) => candidate.strategySteps.filter((item) => item.phase === 'dependency').map((item) => item.id)),
      sourceSensitivity: 'internal', reproducibilityRequirement: 'required', networkRequirement: 'private',
      expectedDurationMs: Math.max(...request.candidates.map((candidate) => [...candidate.strategySteps, ...request.validation.steps].reduce((sum, item) => sum + (item.timeoutMs ?? 3_600_000), 0))),
      resourceProfile: { cpuUnits: 1, memoryMb: 1024, diskMb: Math.max(...request.candidates.map((candidate) => candidate.assessment.resourceCost || 1)) },
      explicitConstraint: 'auto', racingEligibility: true, candidateCount: request.candidates.length, costBounds: request.costBounds,
    });
    const createdAt = this.now();
    const record = this.store.createOrReplay(authenticated.idempotencyKey, requestDigest, () => ({
      schemaVersion: CANDIDATE_RACE_SCHEMA_VERSION, raceId: this.raceIdFactory(), ownerPrincipal: authenticated.subject,
      requestIdempotencyKey: authenticated.idempotencyKey, requestDigest, request, executionPolicy, state: 'REQUESTED', revision: 1, createdAt, updatedAt: createdAt,
      candidates: request.candidates.map((candidate) => ({
        candidateId: candidate.candidateId, strategyDigest: candidate.strategyDigest, sourceIdentity: structuredClone(request.source),
        machineTemplateDigest: sha256(canonicalMachineEvidence(candidate.machine)), validationProfileDigest: sha256(canonicalize(request.validation)),
        childJobIds: [], artifactReferences: [], proofReferences: [], state: 'pending', selected: false, cleanupVerified: false,
      })), cleanupFailures: [],
    }));
    this.authorize(record, context);
    if (['COMPLETED', 'NO_WINNER'].includes(record.state)) return { operation: 'babyx.race.run', race: publicRecord(record), replayed: true };
    return this.drive(record.raceId, context, 'babyx.race.run');
  }
  async resume(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    allowed(payload, 'race resume request', ['raceId', 'reason']); mutationContext(context);
    if (payload.reason !== undefined) text(payload.reason, 'reason', 1024);
    const id = raceId(payload.raceId); const record = this.store.get(id); this.authorize(record, context);
    if (['COMPLETED', 'NO_WINNER'].includes(record.state)) return { operation: 'babyx.race.resume', race: publicRecord(record), replayed: true };
    return this.drive(id, context, 'babyx.race.resume');
  }
  get(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    allowed(payload, 'race get request', ['raceId']); const record = this.store.get(raceId(payload.raceId)); this.authorize(record, context);
    return { operation: 'babyx.race.get', race: publicRecord(record) };
  }
  list(payload: JsonObject = {}, context: RuntimeExecutionContext): JsonObject {
    allowed(payload, 'race list request', ['state', 'offset', 'limit']); const subject = readSubject(context);
    const state = payload.state === undefined ? undefined : text(payload.state, 'state', 64);
    if (state !== undefined && !['REQUESTED', 'RUNNING', 'SCORING', 'COMPLETED', 'NO_WINNER', 'RECOVERY_REQUIRED'].includes(state)) throw new CandidateRaceError('candidate_race_invalid_request', 'state filter is invalid');
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, Number.MAX_SAFE_INTEGER);
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, 200);
    const page = this.store.list((record) => (subject === undefined || record.ownerPrincipal === subject) && (state === undefined || record.state === state), offset, limit);
    const selected = page.records.sort((a, b) => a.raceId.localeCompare(b.raceId)).map(publicRecord);
    return { operation: 'babyx.race.list', races: selected, offset, limit, total: page.total, nextOffset: page.nextOffset, corruptRecordIds: page.corruptRecordIds };
  }
  private authorize(record: RaceRecord, context: RuntimeExecutionContext): void {
    const subject = readSubject(context); if (subject !== undefined && subject !== record.ownerPrincipal) throw new CandidateRaceError('candidate_race_not_found', 'candidate race was not found');
  }
  private async drive(id: string, context: RuntimeExecutionContext, operation: string): Promise<JsonObject> {
    let record = this.store.update(id, this.now(), (current) => ({ ...current, state: 'RUNNING' }));
    const outcomes = await Promise.all(record.request.candidates.map(async (candidate) => this.executeCandidate(record, candidate, context)));
    for (const outcome of outcomes) {
      record = this.store.update(id, this.now(), (current) => ({ ...current, candidates: current.candidates.map((candidate) => candidate.candidateId === outcome.candidateId ? outcome : candidate) }));
    }
    record = this.store.update(id, this.now(), (current) => ({ ...current, state: 'SCORING' }));
    const eligible = record.candidates.filter((candidate) => candidate.state === 'accepted' && candidate.score !== undefined).sort(compareCandidateScores);
    const winner = eligible.at(0);
    const cleanupFailures = record.candidates.filter((candidate) => !candidate.cleanupVerified).map((candidate) => ({ candidateId: candidate.candidateId, certificationId: candidate.certificationId ?? null, reason: candidate.rejectionReason ?? 'cleanup-not-verified' }));
    record = this.store.update(id, this.now(), (current) => {
      const next: RaceRecord = {
        ...current,
        candidates: current.candidates.map((candidate) => ({ ...candidate, selected: candidate.candidateId === winner?.candidateId })),
        cleanupFailures,
        state: winner === undefined ? 'NO_WINNER' : 'COMPLETED',
      };
      if (winner === undefined) delete next.winnerCandidateId;
      else next.winnerCandidateId = winner.candidateId;
      return next;
    });
    record = await this.captureEvidence(record);
    if (record.cleanupFailures.length > 0) record = this.store.update(id, this.now(), (current) => ({ ...current, lastError: { code: 'candidate_race_cleanup_incomplete', message: 'one or more candidate cleanups were not verified', cleanupFailures: current.cleanupFailures } }));
    return { operation, race: publicRecord(record), replayed: false };
  }
  private async executeCandidate(record: RaceRecord, candidate: CandidateRequest, context: RuntimeExecutionContext): Promise<CandidateRecord> {
    const existing = record.candidates.find((item) => item.candidateId === candidate.candidateId);
    if (existing === undefined) throw new CandidateRaceError('candidate_race_store_corrupt', 'candidate record is missing');
    try {
      const certificationRequest = {
        schemaVersion: '1.0.0', source: record.request.source, machine: candidate.machine,
        profile: { id: `${record.request.validation.profileId}-${candidate.candidateId}`, version: record.request.validation.version, steps: [...candidate.strategySteps, ...record.request.validation.steps] },
        retention: { preserveOnFailure: false },
      };
      const result = await this.options.certification.run(certificationRequest, { ...context, idempotencyKey: `${record.raceId}:${candidate.candidateId}:certification` });
      const certification = object(result.certification, 'certification result');
      const certificationId = text(certification.certificationId, 'certification.certificationId', 128);
      const testResult = object(certification.testResult, 'certification.testResult');
      const evidence = object(certification.evidence, 'certification.evidence');
      const cleanup = object(certification.cleanup, 'certification.cleanup');
      const accepted = testResult.status === 'passed' && evidence.status === 'complete' && cleanup.destroyStatus === 'succeeded' && cleanup.absenceVerified === true && cleanup.sourcePreserved === true;
      const score: CandidateScore = {
        correctness: testResult.status === 'passed' ? 100 : 0,
        securityPolicy: evidence.status === 'complete' && cleanup.destroyStatus === 'succeeded' && cleanup.absenceVerified === true ? 100 : 0,
        reproducibility: certification.source !== undefined && canonicalize(certification.source) === canonicalize(record.request.source) ? 100 : 0,
        regressionRisk: candidate.assessment.regressionRisk, maintainability: candidate.assessment.maintainability,
        changeSize: candidate.assessment.changeSize, resourceCost: candidate.assessment.resourceCost,
      };
      return {
        ...existing, certificationId, machineId: typeof certification.machineId === 'string' ? certification.machineId : undefined,
        childJobIds: Array.isArray(certification.jobIds) ? certification.jobIds.filter((value): value is string => typeof value === 'string') : [],
        artifactReferences: Array.isArray(certification.artifactReferences) ? certification.artifactReferences.filter((value): value is string => typeof value === 'string') : [],
        proofReferences: Array.isArray(certification.proofReferences) ? certification.proofReferences.filter((value): value is string => typeof value === 'string') : [],
        state: accepted ? 'accepted' : 'rejected', score, selected: false,
        cleanupVerified: cleanup.destroyStatus === 'succeeded' && cleanup.absenceVerified === true && cleanup.sourcePreserved === true,
        ...(accepted ? {} : { rejectionReason: testResult.status !== 'passed' ? 'common-validation-failed' : evidence.status !== 'complete' ? 'evidence-incomplete' : 'cleanup-unverified' }),
        certification: structuredClone(certification),
      };
    } catch (error) {
      return { ...existing, state: 'failed', selected: false, cleanupVerified: false, rejectionReason: text(errorEvidence(error, 'candidate_execution_failed').code, 'candidate error code', 128), certification: { error: errorEvidence(error, 'candidate_execution_failed') } };
    }
  }
  private async captureEvidence(record: RaceRecord): Promise<RaceRecord> {
    if (record.evidenceArtifactReference !== undefined) return record;
    if (this.options.artifacts === undefined) return this.store.update(record.raceId, this.now(), (current) => ({ ...current, state: 'RECOVERY_REQUIRED', lastError: { code: 'candidate_race_evidence_failed', message: 'artifact authority is unavailable' } }));
    const evidence = {
      schemaVersion: CANDIDATE_RACE_SCHEMA_VERSION, raceId: record.raceId, objective: record.request.objective,
      source: record.request.source, executionPolicy: record.executionPolicy, validationProfileDigest: sha256(canonicalize(record.request.validation)),
      winnerCandidateId: record.winnerCandidateId ?? null, preservation: record.request.preservation,
      candidates: record.candidates.map((candidate) => ({ candidateId: candidate.candidateId, strategyDigest: candidate.strategyDigest, sourceIdentity: candidate.sourceIdentity, machineTemplateDigest: candidate.machineTemplateDigest, machineId: candidate.machineId ?? null, certificationId: candidate.certificationId ?? null, childJobIds: candidate.childJobIds, validationProfileDigest: candidate.validationProfileDigest, score: candidate.score ?? null, rejectionReason: candidate.rejectionReason ?? null, selected: candidate.selected, cleanupVerified: candidate.cleanupVerified, artifactReferences: candidate.artifactReferences, proofReferences: candidate.proofReferences })),
      cleanupFailures: record.cleanupFailures, mergePerformed: false, deploymentPerformed: false, capturedAt: this.now(),
    };
    const canonical = `${canonicalMachineEvidence(evidence)}\n`;
    if (Buffer.byteLength(canonical) > 1_048_576) return this.store.update(record.raceId, this.now(), (current) => ({ ...current, state: 'RECOVERY_REQUIRED', lastError: { code: 'candidate_race_evidence_failed', message: 'race evidence exceeds the one-megabyte bound' } }));
    const evidenceDigest = sha256(canonical); const path = join(this.evidenceRoot, `${record.raceId}-${evidenceDigest.slice(0, 16)}.json`);
    writeFileSync(path, canonical, { mode: 0o600, flag: 'wx' });
    try {
      const artifact = this.options.artifacts.create(`candidate-race-${record.raceId}-evidence`, path, { raceId: record.raceId, evidenceDigest, sourceCommit: record.request.source.commit, sourceTree: record.request.source.tree });
      const artifactId = text(artifact.id, 'race evidence artifact ID', 256);
      return this.store.update(record.raceId, this.now(), (current) => ({ ...current, evidenceArtifactReference: artifactId, evidenceDigest }));
    } finally { rmSync(path, { force: true }); }
  }
}
