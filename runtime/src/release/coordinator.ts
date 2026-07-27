import { randomUUID } from 'node:crypto';
import { closeSync, fsyncSync, mkdirSync, openSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import type { ArtifactManager } from '../artifacts/manager.ts';
import {
  canonicalize,
  sha256,
  type JobManager,
  type JobRecord,
  type JsonObject,
  type RuntimeExecutionContext,
} from '../core.ts';
import {
  assertDeploymentSuccess,
  assertReleaseTransition,
  assertTerminalDeploymentSafety,
  DEPLOYMENT_SUCCESS_REQUIREMENTS,
  type DeploymentSuccessEvidence,
} from './compatibility.ts';
import type { ImmutableReleaseContentService, NormalizedBuildProfile } from './content.ts';
import { normalizeBuildProfile, validateServiceDefinition } from './content.ts';
import type { ReleaseCertificationService } from './certification.ts';
import type { SlotRuntimeService } from './slot.ts';
import type { RouteAuthorityService } from './route.ts';
import { assertNoRawSecrets, boundedReleaseError, RELEASE_FAILURE_CODES, validateReleaseRecord } from './schemas.ts';
import { ReleaseApplianceStore, ReleaseStoreError } from './store.ts';

export const RELEASE_COORDINATOR_CONTRACT_VERSION = '1.0.0' as const;
export const RELEASE_OPERATION_LIMIT = 200 as const;
export const RELEASE_EVENT_LIMIT = 1_000 as const;
export const RELEASE_RECONCILE_LIMIT = 100 as const;

const IDENTIFIER = /^[a-z0-9][a-z0-9._:-]{0,127}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const GIT_SHA = /^[a-f0-9]{40}$/u;
const TERMINAL = new Set(['SUCCEEDED', 'ROLLED_BACK', 'FAILED', 'CANCELLED', 'EXPIRED']);
const PRE_CUTOVER = new Set([
  'REQUESTED', 'PREFLIGHTING', 'RESOLVING_SOURCE', 'REUSING_ARTIFACT', 'BUILDING', 'CERTIFYING',
  'READY_TO_STAGE', 'STAGING', 'STARTING_INACTIVE', 'READINESS_CHECKING', 'READY_TO_PROMOTE',
  'AWAITING_APPROVAL', 'CUTOVER_PREPARING',
]);
const PERSISTED_RELEASE_FAILURE_CODES = new Set<string>(RELEASE_FAILURE_CODES);
const MUTATION_STATES = new Set([
  'REQUESTED', 'PREFLIGHTING', 'RESOLVING_SOURCE', 'REUSING_ARTIFACT', 'BUILDING', 'CERTIFYING',
  'READY_TO_STAGE', 'STAGING', 'STARTING_INACTIVE', 'READINESS_CHECKING', 'READY_TO_PROMOTE',
  'AWAITING_APPROVAL', 'CUTOVER_PREPARING', 'CUTTING_OVER', 'OBSERVING', 'DRAINING_PREVIOUS',
  'FINALIZING', 'ROLLBACK_REQUESTED', 'ROLLING_BACK', 'CLEANUP_PENDING', 'CLEANING',
  'RECOVERY_REQUIRED', 'AMBIGUOUS',
]);

export class ReleaseCoordinatorError extends Error {
  constructor(readonly code: string, message: string, readonly details: JsonObject = {}, readonly phase?: string) {
    super(message);
    this.name = 'ReleaseCoordinatorError';
  }
}

export interface PreparedSource extends JsonObject {
  sourceIdentity: JsonObject;
  sourceManifest?: JsonObject;
  sourceEpoch: number;
  artifact?: JsonObject;
  receiptReferences: string[];
}

export interface PreparedArtifact extends JsonObject {
  artifact: JsonObject;
  manifest: JsonObject;
  buildId: string;
  jobIds: string[];
  reused: boolean;
  receiptReferences: string[];
}

export interface PreparedCertification extends JsonObject {
  certification: JsonObject;
  reused: boolean;
  jobIds: string[];
  receiptReferences: string[];
}

export interface PreparedRelease extends JsonObject {
  release: JsonObject;
  materialization: JsonObject;
  jobIds: string[];
  receiptReferences: string[];
}

export interface ReleasePreparationAuthority {
  readonly authority: 'release-preparation-composite';
  resolve(request: NormalizedDeploymentRequest, context: RuntimeExecutionContext): Promise<PreparedSource>;
  buildOrReuse(request: NormalizedDeploymentRequest, source: PreparedSource, context: RuntimeExecutionContext): Promise<PreparedArtifact>;
  certify(request: NormalizedDeploymentRequest, source: PreparedSource, artifact: PreparedArtifact, context: RuntimeExecutionContext): Promise<PreparedCertification>;
  materialize(request: NormalizedDeploymentRequest, source: PreparedSource, artifact: PreparedArtifact, certification: PreparedCertification, context: RuntimeExecutionContext): Promise<PreparedRelease>;
}

export interface ReleaseObservationAuthority {
  readonly authority: 'release-observation';
  observe(record: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext): Promise<JsonObject>;
}

export type DrainClassification =
  | 'DRAINING'
  | 'DRAINED'
  | 'TIMED_OUT'
  | 'UNSUPPORTED'
  | 'UNKNOWN'
  | 'IDENTITY_MISMATCH'
  | 'PROVIDER_FAILED'
  | 'FORCED_TERMINATION_REQUIRED';

export interface NormalizedDrainPolicy extends JsonObject {
  schemaVersion: '1.0.0';
  timeoutMs: number;
  intervalMs: number;
  maximumSamples: number;
  keepAlive: boolean;
  websocket: boolean;
  sse: boolean;
  worker: boolean;
  scheduler: boolean;
  keepAliveTimeoutMs: number;
  websocketMaximumLifetimeMs: number;
  sseMaximumLifetimeMs: number;
  workerGracePeriodMs: number;
  schedulerHandoffRequired: boolean;
  forceTerminationAfterDeadline: boolean;
  rollbackBehavior: 'RESTORE_AND_CANCEL_DRAIN' | 'PRESERVE_DRAINING';
}

export interface ReleaseDrainObservationProvider {
  readonly authority: 'release-drain-observation';
  observe(target: JsonObject, policy: NormalizedDrainPolicy, context: RuntimeExecutionContext): Promise<JsonObject>;
}

export interface ReleaseDrainAuthority {
  readonly authority: 'release-drain';
  drain(record: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext): Promise<JsonObject>;
}

export interface ReleaseProofAuthority {
  readonly authority: 'existing-babyx-proof';
  create(requestId: string, operation: string, ok: boolean, startedAt: string, result: unknown): JsonObject;
}

export interface ReleaseCoordinatorOptions {
  stateRoot: string;
  store: ReleaseApplianceStore;
  preparation: ReleasePreparationAuthority;
  slots: Pick<SlotRuntimeService, 'stage' | 'start' | 'stop' | 'cleanup' | 'activate' | 'markDraining' | 'getSlot' | 'getService' | 'listServices'> & {
    restoreActive?: (value: JsonObject, context: RuntimeExecutionContext) => JsonObject;
  };
  routes: Pick<RouteAuthorityService, 'acquireLease' | 'releaseLease' | 'prepare' | 'cutover' | 'restore' | 'reconcile' | 'expirePreview' | 'getRoute'> & {
    observeActive?: (value: JsonObject, context: RuntimeExecutionContext) => Promise<JsonObject>;
  };
  jobs: Pick<JobManager, 'get' | 'list' | 'reconcile'>;
  artifacts: ArtifactManager;
  observation: ReleaseObservationAuthority;
  drain: ReleaseDrainAuthority;
  proofs: ReleaseProofAuthority;
  governor?: { gc(payload: JsonObject, context: RuntimeExecutionContext): JsonObject };
  reporter?: { queueDeploymentProjection(record: JsonObject, context: RuntimeExecutionContext): JsonObject; reportingSatisfied(record: JsonObject): boolean };
  now?: () => string;
}

export interface NormalizedApprovalPolicy extends JsonObject {
  mode: 'NONE' | 'REQUIRED';
  expiresAfterMs: number;
  requiredPrincipal?: string;
}

export interface NormalizedObservationPolicy extends JsonObject {
  minimumDurationMs: number;
  minimumSamples: number;
  consecutiveFailureThreshold: number;
  recoverySamples: number;
  cooldownMs: number;
  errorRateThreshold: number;
  latencyThresholdMs: number;
  maximumProcessRestarts: number;
  missingTelemetry: 'ROLLBACK' | 'RECOVERY_REQUIRED';
  unknownTelemetry: 'ROLLBACK' | 'RECOVERY_REQUIRED';
  requiredSignals: string[];
}

export interface NormalizedDeploymentRequest extends JsonObject {
  schemaVersion: '1.0.0';
  serviceDefinition: JsonObject;
  serviceDefinitionDigest: string;
  serviceId: string;
  ownerPrincipal: string;
  source: JsonObject;
  build: JsonObject;
  certification: JsonObject;
  promotion: JsonObject;
  route: JsonObject;
  approvalPolicy: NormalizedApprovalPolicy;
  observationPolicy: NormalizedObservationPolicy;
  drainPolicy: NormalizedDrainPolicy;
  controller: JsonObject;
  triggerSource: 'MANUAL' | 'GITHUB' | 'SCHEDULED' | 'RECONCILIATION';
  triggerIdentity: JsonObject;
  credentialSetDigest: string;
  capacityAdmissionSnapshotId: string;
  scheduleAt?: string;
  expiresAt?: string;
  group?: JsonObject;
  migration?: JsonObject;
  requestDigest: string;
}

export interface ReleaseGroupMember extends JsonObject {
  serviceId: string;
  order: number;
  dependsOn: string[];
  request: JsonObject;
}

export interface ReleaseGroupContract extends JsonObject {
  groupId: string;
  members: ReleaseGroupMember[];
  promotionOrder: string[];
  rollbackOrder: string[];
  atomicity: 'ORDERED_NOT_EXTERNALLY_ATOMIC';
  digest: string;
}

export interface MigrationPhase extends JsonObject {
  id: string;
  kind: 'EXPAND' | 'MIGRATE' | 'CONTRACT';
  job: JsonObject;
  irreversible: boolean;
  compatibilityGate: JsonObject;
}

export interface MigrationContract extends JsonObject {
  phases: MigrationPhase[];
  irreversibleBoundary?: string;
  rollbackCompatibility: JsonObject;
  digest: string;
}

function object(value: unknown, field: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ReleaseCoordinatorError('release_invalid_request', `${field} must be an object`);
  return value as JsonObject;
}

function strictObject(value: unknown, field: string, allowed: readonly string[], required: readonly string[] = []): JsonObject {
  const result = object(value, field);
  const unknown = Object.keys(result).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw new ReleaseCoordinatorError('release_invalid_request', `${field} contains unsupported property ${unknown.sort()[0]}`);
  for (const key of required) if (result[key] === undefined) throw new ReleaseCoordinatorError('release_invalid_request', `${field}.${key} is required`);
  return result;
}

function text(value: unknown, field: string, maximum = 4096): string {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || Buffer.byteLength(value) > maximum) throw new ReleaseCoordinatorError('release_invalid_request', `${field} must be a bounded non-empty NUL-free string`);
  return value;
}

function identifier(value: unknown, field: string): string {
  const result = text(value, field, 128).toLowerCase();
  if (!IDENTIFIER.test(result)) throw new ReleaseCoordinatorError('release_invalid_request', `${field} must be a lowercase bounded identifier`);
  return result;
}

function digest(value: unknown, field: string): string {
  const result = text(value, field, 64);
  if (!DIGEST.test(result)) throw new ReleaseCoordinatorError('release_invalid_request', `${field} must be a lowercase SHA-256 digest`);
  return result;
}

function gitSha(value: unknown, field: string): string {
  const result = text(value, field, 40);
  if (!GIT_SHA.test(result)) throw new ReleaseCoordinatorError('release_invalid_request', `${field} must be a lowercase Git SHA`);
  return result;
}

function integer(value: unknown, field: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new ReleaseCoordinatorError('release_invalid_request', `${field} must be an integer between ${minimum} and ${maximum}`);
  return Number(value);
}

function finiteNumber(value: unknown, field: string, minimum: number, maximum: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum || value > maximum) throw new ReleaseCoordinatorError('release_invalid_request', `${field} must be a finite number between ${minimum} and ${maximum}`);
  return value;
}

function timestamp(value: unknown, field: string): string {
  const result = text(value, field, 64);
  if (!result.endsWith('Z') || !Number.isFinite(Date.parse(result)) || new Date(Date.parse(result)).toISOString() !== result) throw new ReleaseCoordinatorError('release_invalid_request', `${field} must be a canonical UTC timestamp`);
  return result;
}

function stringArray(value: unknown, field: string, maximum = 256): string[] {
  if (!Array.isArray(value) || value.length > maximum) throw new ReleaseCoordinatorError('release_invalid_request', `${field} must be a bounded string array`);
  return [...new Set(value.map((entry, index) => text(entry, `${field}[${index}]`, 256)))].sort();
}

function normalizedJson(value: unknown, field: string): JsonObject {
  const result = structuredClone(object(value, field));
  assertNoRawSecrets(result);
  return JSON.parse(canonicalize(result)) as JsonObject;
}

function requiredContext(context: RuntimeExecutionContext): { subject: string; idempotencyKey: string; authorityClass: string } {
  return {
    subject: identifier(context.subject, 'context.subject'),
    idempotencyKey: identifier(context.idempotencyKey, 'context.idempotencyKey'),
    authorityClass: typeof context.authorityClass === 'string' ? context.authorityClass : 'owner',
  };
}

function normalizeApprovalPolicy(value: unknown): NormalizedApprovalPolicy {
  const input = strictObject(value ?? {}, 'approvalPolicy', ['mode', 'expiresAfterMs', 'requiredPrincipal']);
  const mode = input.mode === undefined || input.mode === 'NONE' ? 'NONE' : input.mode === 'REQUIRED' ? 'REQUIRED' : (() => { throw new ReleaseCoordinatorError('release_invalid_request', 'approvalPolicy.mode is invalid'); })();
  const expiresAfterMs = input.expiresAfterMs === undefined ? 3_600_000 : integer(input.expiresAfterMs, 'approvalPolicy.expiresAfterMs', 1, 604_800_000);
  const requiredPrincipal = input.requiredPrincipal === undefined ? undefined : identifier(input.requiredPrincipal, 'approvalPolicy.requiredPrincipal');
  return { mode, expiresAfterMs, ...(requiredPrincipal === undefined ? {} : { requiredPrincipal }) };
}

export function normalizeDrainPolicy(value: unknown): NormalizedDrainPolicy {
  const input = strictObject(value ?? {}, 'drainPolicy', [
    'schemaVersion', 'timeoutMs', 'intervalMs', 'maximumSamples', 'keepAlive', 'websocket', 'sse', 'worker', 'scheduler',
    'keepAliveTimeoutMs', 'websocketMaximumLifetimeMs', 'sseMaximumLifetimeMs', 'workerGracePeriodMs',
    'schedulerHandoffRequired', 'forceTerminationAfterDeadline', 'rollbackBehavior',
  ]);
  if (input.schemaVersion !== undefined && input.schemaVersion !== '1.0.0') throw new ReleaseCoordinatorError('release_invalid_request', 'drainPolicy.schemaVersion is unsupported');
  const boolean = (entry: unknown, field: string, defaultValue: boolean): boolean => {
    if (entry === undefined) return defaultValue;
    if (typeof entry !== 'boolean') throw new ReleaseCoordinatorError('release_invalid_request', `${field} must be boolean`);
    return entry;
  };
  const rollbackBehavior = input.rollbackBehavior === undefined || input.rollbackBehavior === 'RESTORE_AND_CANCEL_DRAIN'
    ? 'RESTORE_AND_CANCEL_DRAIN'
    : input.rollbackBehavior === 'PRESERVE_DRAINING'
      ? 'PRESERVE_DRAINING'
      : (() => { throw new ReleaseCoordinatorError('release_invalid_request', 'drainPolicy.rollbackBehavior is invalid'); })();
  return {
    schemaVersion:'1.0.0',
    timeoutMs:input.timeoutMs === undefined ? 45_000 : integer(input.timeoutMs, 'drainPolicy.timeoutMs', 1, 3_600_000),
    intervalMs:input.intervalMs === undefined ? 250 : integer(input.intervalMs, 'drainPolicy.intervalMs', 1, 60_000),
    maximumSamples:input.maximumSamples === undefined ? 200 : integer(input.maximumSamples, 'drainPolicy.maximumSamples', 1, 1_000),
    keepAlive:boolean(input.keepAlive, 'drainPolicy.keepAlive', true),
    websocket:boolean(input.websocket, 'drainPolicy.websocket', true),
    sse:boolean(input.sse, 'drainPolicy.sse', true),
    worker:boolean(input.worker, 'drainPolicy.worker', false),
    scheduler:boolean(input.scheduler, 'drainPolicy.scheduler', false),
    keepAliveTimeoutMs:input.keepAliveTimeoutMs === undefined ? 5_000 : integer(input.keepAliveTimeoutMs, 'drainPolicy.keepAliveTimeoutMs', 0, 3_600_000),
    websocketMaximumLifetimeMs:input.websocketMaximumLifetimeMs === undefined ? 30_000 : integer(input.websocketMaximumLifetimeMs, 'drainPolicy.websocketMaximumLifetimeMs', 0, 86_400_000),
    sseMaximumLifetimeMs:input.sseMaximumLifetimeMs === undefined ? 30_000 : integer(input.sseMaximumLifetimeMs, 'drainPolicy.sseMaximumLifetimeMs', 0, 86_400_000),
    workerGracePeriodMs:input.workerGracePeriodMs === undefined ? 30_000 : integer(input.workerGracePeriodMs, 'drainPolicy.workerGracePeriodMs', 0, 86_400_000),
    schedulerHandoffRequired:boolean(input.schedulerHandoffRequired, 'drainPolicy.schedulerHandoffRequired', false),
    forceTerminationAfterDeadline:boolean(input.forceTerminationAfterDeadline, 'drainPolicy.forceTerminationAfterDeadline', false),
    rollbackBehavior,
  };
}


function normalizeDrainObservation(value: unknown, expectedSequence: number): JsonObject {
  const input = strictObject(value, 'drain observation', [
    'schemaVersion', 'observationSequence', 'observedAt', 'serviceId', 'slotId', 'releaseId', 'unitIdentity',
    'processIdentityDigest', 'routeGeneration', 'providerStatus', 'activeKeepAliveConnections', 'activeWebSockets',
    'activeSseStreams', 'activeLongRunningRequests', 'activeWorkerTasks', 'queuedWorkerTasks', 'activeSchedulerWork',
    'queuedSchedulerWork', 'applicationStatus', 'observationDigest',
  ], [
    'schemaVersion', 'observationSequence', 'observedAt', 'serviceId', 'slotId', 'releaseId', 'unitIdentity',
    'processIdentityDigest', 'routeGeneration', 'providerStatus', 'activeKeepAliveConnections', 'activeWebSockets',
    'activeSseStreams', 'activeLongRunningRequests', 'activeWorkerTasks', 'queuedWorkerTasks', 'activeSchedulerWork',
    'queuedSchedulerWork',
  ]);
  if (input.schemaVersion !== '1.0.0') throw new ReleaseCoordinatorError('release_invalid_request', 'drain observation schemaVersion is unsupported');
  const observationSequence = integer(input.observationSequence, 'drain observation.observationSequence', 1, Number.MAX_SAFE_INTEGER);
  if (observationSequence !== expectedSequence) throw new ReleaseCoordinatorError('release_stale_sequence', 'drain observation sequence does not match the durable observation sequence');
  const providerStatus = input.providerStatus === 'AVAILABLE' || input.providerStatus === 'UNAVAILABLE' || input.providerStatus === 'FAILED' || input.providerStatus === 'UNKNOWN'
    ? input.providerStatus
    : (() => { throw new ReleaseCoordinatorError('release_invalid_request', 'drain observation providerStatus is invalid'); })();
  const applicationStatus = input.applicationStatus === undefined
    ? undefined
    : input.applicationStatus === 'DRAINING' || input.applicationStatus === 'DRAINED' || input.applicationStatus === 'FAILED' || input.applicationStatus === 'UNKNOWN'
      ? input.applicationStatus
      : (() => { throw new ReleaseCoordinatorError('release_invalid_request', 'drain observation applicationStatus is invalid'); })();
  const normalized: JsonObject = {
    schemaVersion:'1.0.0',
    observationSequence,
    observedAt:timestamp(input.observedAt, 'drain observation.observedAt'),
    serviceId:identifier(input.serviceId, 'drain observation.serviceId'),
    slotId:identifier(input.slotId, 'drain observation.slotId'),
    releaseId:identifier(input.releaseId, 'drain observation.releaseId'),
    unitIdentity:text(input.unitIdentity, 'drain observation.unitIdentity', 256),
    processIdentityDigest:digest(input.processIdentityDigest, 'drain observation.processIdentityDigest'),
    routeGeneration:digest(input.routeGeneration, 'drain observation.routeGeneration'),
    providerStatus,
    activeKeepAliveConnections:integer(input.activeKeepAliveConnections, 'drain observation.activeKeepAliveConnections', 0, 1_000_000_000),
    activeWebSockets:integer(input.activeWebSockets, 'drain observation.activeWebSockets', 0, 1_000_000_000),
    activeSseStreams:integer(input.activeSseStreams, 'drain observation.activeSseStreams', 0, 1_000_000_000),
    activeLongRunningRequests:integer(input.activeLongRunningRequests, 'drain observation.activeLongRunningRequests', 0, 1_000_000_000),
    activeWorkerTasks:integer(input.activeWorkerTasks, 'drain observation.activeWorkerTasks', 0, 1_000_000_000),
    queuedWorkerTasks:integer(input.queuedWorkerTasks, 'drain observation.queuedWorkerTasks', 0, 1_000_000_000),
    activeSchedulerWork:integer(input.activeSchedulerWork, 'drain observation.activeSchedulerWork', 0, 1_000_000_000),
    queuedSchedulerWork:integer(input.queuedSchedulerWork, 'drain observation.queuedSchedulerWork', 0, 1_000_000_000),
    ...(applicationStatus === undefined ? {} : { applicationStatus }),
  };
  const observationDigest = sha256(canonicalize(normalized));
  if (input.observationDigest !== undefined && digest(input.observationDigest, 'drain observation.observationDigest') !== observationDigest) {
    throw new ReleaseCoordinatorError('release_identity_mismatch', 'drain observation digest does not match canonical observation bytes');
  }
  return { ...normalized, observationDigest };
}

function drainWorkState(observation: JsonObject, policy: NormalizedDrainPolicy): { known: boolean; remaining: number; details: JsonObject } {
  const details: JsonObject = {
    keepAliveConnections:policy.keepAlive ? integer(observation.activeKeepAliveConnections, 'drain observation.activeKeepAliveConnections', 0) : 0,
    webSockets:policy.websocket ? integer(observation.activeWebSockets, 'drain observation.activeWebSockets', 0) : 0,
    sseStreams:policy.sse ? integer(observation.activeSseStreams, 'drain observation.activeSseStreams', 0) : 0,
    longRunningRequests:integer(observation.activeLongRunningRequests, 'drain observation.activeLongRunningRequests', 0),
    activeWorkerTasks:policy.worker ? integer(observation.activeWorkerTasks, 'drain observation.activeWorkerTasks', 0) : 0,
    queuedWorkerTasks:policy.worker ? integer(observation.queuedWorkerTasks, 'drain observation.queuedWorkerTasks', 0) : 0,
    activeSchedulerWork:policy.scheduler || policy.schedulerHandoffRequired ? integer(observation.activeSchedulerWork, 'drain observation.activeSchedulerWork', 0) : 0,
    queuedSchedulerWork:policy.scheduler || policy.schedulerHandoffRequired ? integer(observation.queuedSchedulerWork, 'drain observation.queuedSchedulerWork', 0) : 0,
  };
  const remaining = Object.values(details).reduce((sum, value) => sum + Number(value), 0);
  return { known:observation.providerStatus === 'AVAILABLE', remaining, details };
}

function normalizeObservationPolicy(value: unknown): NormalizedObservationPolicy {
  const input = strictObject(value ?? {}, 'observationPolicy', [
    'minimumDurationMs', 'minimumSamples', 'consecutiveFailureThreshold', 'recoverySamples', 'cooldownMs',
    'errorRateThreshold', 'latencyThresholdMs', 'maximumProcessRestarts', 'missingTelemetry', 'unknownTelemetry', 'requiredSignals',
  ]);
  const missingTelemetry = input.missingTelemetry === undefined || input.missingTelemetry === 'ROLLBACK' ? 'ROLLBACK' : input.missingTelemetry === 'RECOVERY_REQUIRED' ? 'RECOVERY_REQUIRED' : (() => { throw new ReleaseCoordinatorError('release_invalid_request', 'observationPolicy.missingTelemetry is invalid'); })();
  const unknownTelemetry = input.unknownTelemetry === undefined || input.unknownTelemetry === 'ROLLBACK' ? 'ROLLBACK' : input.unknownTelemetry === 'RECOVERY_REQUIRED' ? 'RECOVERY_REQUIRED' : (() => { throw new ReleaseCoordinatorError('release_invalid_request', 'observationPolicy.unknownTelemetry is invalid'); })();
  return {
    minimumDurationMs: input.minimumDurationMs === undefined ? 30_000 : integer(input.minimumDurationMs, 'observationPolicy.minimumDurationMs', 0, 86_400_000),
    minimumSamples: input.minimumSamples === undefined ? 3 : integer(input.minimumSamples, 'observationPolicy.minimumSamples', 1, 100_000),
    consecutiveFailureThreshold: input.consecutiveFailureThreshold === undefined ? 2 : integer(input.consecutiveFailureThreshold, 'observationPolicy.consecutiveFailureThreshold', 1, 10_000),
    recoverySamples: input.recoverySamples === undefined ? 3 : integer(input.recoverySamples, 'observationPolicy.recoverySamples', 1, 10_000),
    cooldownMs: input.cooldownMs === undefined ? 60_000 : integer(input.cooldownMs, 'observationPolicy.cooldownMs', 0, 86_400_000),
    errorRateThreshold: input.errorRateThreshold === undefined ? 0.05 : finiteNumber(input.errorRateThreshold, 'observationPolicy.errorRateThreshold', 0, 1),
    latencyThresholdMs: input.latencyThresholdMs === undefined ? 2_000 : finiteNumber(input.latencyThresholdMs, 'observationPolicy.latencyThresholdMs', 1, 3_600_000),
    maximumProcessRestarts: input.maximumProcessRestarts === undefined ? 0 : integer(input.maximumProcessRestarts, 'observationPolicy.maximumProcessRestarts', 0, 10_000),
    missingTelemetry,
    unknownTelemetry,
    requiredSignals: input.requiredSignals === undefined ? ['readiness', 'publicProbe'] : stringArray(input.requiredSignals, 'observationPolicy.requiredSignals', 32),
  };
}

export function normalizeReleaseGroup(value: unknown): ReleaseGroupContract {
  const input = strictObject(value, 'group', ['groupId', 'members'], ['groupId', 'members']);
  const groupId = identifier(input.groupId, 'group.groupId');
  if (!Array.isArray(input.members) || input.members.length < 1 || input.members.length > 64) throw new ReleaseCoordinatorError('release_invalid_request', 'group.members must contain between one and 64 members');
  const members = input.members.map((entry, index) => {
    const member = strictObject(entry, `group.members[${index}]`, ['serviceId', 'order', 'dependsOn', 'request'], ['serviceId', 'order', 'dependsOn', 'request']);
    return {
      serviceId: identifier(member.serviceId, `group.members[${index}].serviceId`),
      order: integer(member.order, `group.members[${index}].order`, 0, 10_000),
      dependsOn: stringArray(member.dependsOn, `group.members[${index}].dependsOn`, 64).map((item) => identifier(item, 'dependency')),
      request: normalizedJson(member.request, `group.members[${index}].request`),
    } satisfies ReleaseGroupMember;
  });
  const ids = new Set(members.map((member) => member.serviceId));
  if (ids.size !== members.length) throw new ReleaseCoordinatorError('release_invalid_request', 'group service identities must be unique');
  for (const member of members) for (const dependency of member.dependsOn) if (!ids.has(dependency)) throw new ReleaseCoordinatorError('release_invalid_request', `group dependency ${dependency} is not a member`);
  const pending = new Map(members.map((member) => [member.serviceId, member]));
  const promotionOrder: string[] = [];
  while (pending.size > 0) {
    const ready = [...pending.values()].filter((member) => member.dependsOn.every((dependency) => promotionOrder.includes(dependency))).sort((left, right) => left.order - right.order || left.serviceId.localeCompare(right.serviceId));
    if (ready.length === 0) throw new ReleaseCoordinatorError('release_invalid_request', 'group dependencies contain a cycle');
    for (const member of ready) { promotionOrder.push(member.serviceId); pending.delete(member.serviceId); }
  }
  const normalized = { groupId, members: members.sort((left, right) => left.order - right.order || left.serviceId.localeCompare(right.serviceId)), promotionOrder, rollbackOrder: [...promotionOrder].reverse(), atomicity: 'ORDERED_NOT_EXTERNALLY_ATOMIC' as const };
  return { ...normalized, digest: sha256(canonicalize(normalized)) };
}

export function normalizeMigrationContract(value: unknown): MigrationContract {
  const input = strictObject(value, 'migration', ['phases', 'rollbackCompatibility'], ['phases', 'rollbackCompatibility']);
  if (!Array.isArray(input.phases) || input.phases.length > 32) throw new ReleaseCoordinatorError('release_invalid_request', 'migration.phases must be a bounded array');
  const phases = input.phases.map((entry, index) => {
    const phase = strictObject(entry, `migration.phases[${index}]`, ['id', 'kind', 'job', 'irreversible', 'compatibilityGate'], ['id', 'kind', 'job', 'irreversible', 'compatibilityGate']);
    const kind = phase.kind === 'EXPAND' || phase.kind === 'MIGRATE' || phase.kind === 'CONTRACT' ? phase.kind : (() => { throw new ReleaseCoordinatorError('release_invalid_request', 'migration phase kind is invalid'); })();
    if (typeof phase.irreversible !== 'boolean') throw new ReleaseCoordinatorError('release_invalid_request', 'migration phase irreversible must be boolean');
    return { id: identifier(phase.id, `migration.phases[${index}].id`), kind, job: normalizedJson(phase.job, `migration.phases[${index}].job`), irreversible: phase.irreversible, compatibilityGate: normalizedJson(phase.compatibilityGate, `migration.phases[${index}].compatibilityGate`) } satisfies MigrationPhase;
  });
  const order = phases.map((phase) => phase.kind).join(',');
  if (!/^((EXPAND)(,MIGRATE)?(,CONTRACT)?)?$|^(MIGRATE)(,CONTRACT)?$|^CONTRACT$/u.test(order)) throw new ReleaseCoordinatorError('release_invalid_request', 'migration phases must be ordered expand, migrate, contract');
  const irreversible = phases.find((phase) => phase.irreversible);
  const normalized = { phases, ...(irreversible === undefined ? {} : { irreversibleBoundary: irreversible.id }), rollbackCompatibility: normalizedJson(input.rollbackCompatibility, 'migration.rollbackCompatibility') };
  return { ...normalized, digest: sha256(canonicalize(normalized)) };
}

export function normalizeDeploymentRequest(value: unknown, ownerPrincipal: string): NormalizedDeploymentRequest {
  const candidate = object(value, 'deployment request');
  if (candidate.requestDigest !== undefined || candidate.ownerPrincipal !== undefined || candidate.serviceDefinitionDigest !== undefined) {
    const persisted = structuredClone(candidate) as unknown as NormalizedDeploymentRequest;
    if (persisted.schemaVersion !== '1.0.0' || persisted.ownerPrincipal !== ownerPrincipal) throw new ReleaseCoordinatorError('release_wrong_principal', 'persisted deployment request owner does not match authenticated principal');
    const requestDigest = digest(persisted.requestDigest, 'requestDigest');
    const base = { ...persisted } as JsonObject;
    delete base.requestDigest;
    if (sha256(canonicalize(base)) !== requestDigest) throw new ReleaseCoordinatorError('release_record_corrupt', 'persisted normalized deployment request digest does not match');
    assertNoRawSecrets(persisted);
    return persisted;
  }
  const input = strictObject(candidate, 'deployment request', [
    'schemaVersion', 'serviceDefinition', 'source', 'build', 'certification', 'promotion', 'route', 'approvalPolicy',
    'observationPolicy', 'drainPolicy', 'controller', 'triggerSource', 'triggerIdentity', 'credentialSetDigest',
    'capacityAdmissionSnapshotId', 'scheduleAt', 'expiresAt', 'group', 'migration',
  ], ['schemaVersion', 'serviceDefinition', 'source', 'build', 'certification', 'promotion', 'route', 'controller', 'credentialSetDigest', 'capacityAdmissionSnapshotId']);
  if (input.schemaVersion !== '1.0.0') throw new ReleaseCoordinatorError('release_invalid_request', 'deployment request schemaVersion must be 1.0.0');
  assertNoRawSecrets(input);
  const service = validateServiceDefinition(input.serviceDefinition);
  if (service.record.ownerPrincipal !== ownerPrincipal) throw new ReleaseCoordinatorError('release_wrong_principal', 'service owner does not match authenticated principal');
  const triggerSource = input.triggerSource === undefined || input.triggerSource === 'MANUAL' ? 'MANUAL' : ['GITHUB', 'SCHEDULED', 'RECONCILIATION'].includes(String(input.triggerSource)) ? input.triggerSource as NormalizedDeploymentRequest['triggerSource'] : (() => { throw new ReleaseCoordinatorError('release_invalid_request', 'triggerSource is invalid'); })();
  const base = {
    schemaVersion: '1.0.0' as const,
    serviceDefinition: service.record,
    serviceDefinitionDigest: service.digest,
    serviceId: identifier(service.record.serviceId, 'serviceDefinition.serviceId'),
    ownerPrincipal,
    source: normalizedJson(input.source, 'source'),
    build: normalizedJson(input.build, 'build'),
    certification: normalizedJson(input.certification, 'certification'),
    promotion: normalizedJson(input.promotion, 'promotion'),
    route: normalizedJson(input.route, 'route'),
    approvalPolicy: normalizeApprovalPolicy(input.approvalPolicy),
    observationPolicy: normalizeObservationPolicy(input.observationPolicy),
    drainPolicy: normalizeDrainPolicy(input.drainPolicy),
    controller: normalizedJson(input.controller, 'controller'),
    triggerSource,
    triggerIdentity: input.triggerIdentity === undefined ? { kind: triggerSource } : normalizedJson(input.triggerIdentity, 'triggerIdentity'),
    credentialSetDigest: digest(input.credentialSetDigest, 'credentialSetDigest'),
    capacityAdmissionSnapshotId: identifier(input.capacityAdmissionSnapshotId, 'capacityAdmissionSnapshotId'),
    ...(input.scheduleAt === undefined ? {} : { scheduleAt: timestamp(input.scheduleAt, 'scheduleAt') }),
    ...(input.expiresAt === undefined ? {} : { expiresAt: timestamp(input.expiresAt, 'expiresAt') }),
    ...(input.group === undefined ? {} : { group: normalizeReleaseGroup(input.group) }),
    ...(input.migration === undefined ? {} : { migration: normalizeMigrationContract(input.migration) }),
  };
  const routeMode = object(base.route, 'route').mode;
  if (routeMode === 'PREVIEW' && base.expiresAt === undefined) throw new ReleaseCoordinatorError('release_invalid_request', 'PREVIEW deployments require a canonical expiresAt timestamp');
  return { ...base, requestDigest: sha256(canonicalize(base)) };
}

export function bindReleaseApproval(record: JsonObject, request: NormalizedDeploymentRequest, value: unknown, now: string): JsonObject {
  const approval = strictObject(value, 'approval', ['deploymentId', 'ownerPrincipal', 'requestDigest', 'serviceId', 'sourceCommit', 'sourceTree', 'artifactDigest', 'releaseManifestDigest', 'certificationId', 'targetSlot', 'candidateRouteDigest', 'policyDigest', 'approvalMode', 'expiresAt', 'approvingPrincipal', 'sequence'], ['deploymentId', 'ownerPrincipal', 'requestDigest', 'serviceId', 'sourceCommit', 'sourceTree', 'artifactDigest', 'releaseManifestDigest', 'certificationId', 'targetSlot', 'candidateRouteDigest', 'policyDigest', 'approvalMode', 'expiresAt', 'approvingPrincipal', 'sequence']);
  const expected = {
    deploymentId: record.deploymentId,
    ownerPrincipal: record.ownerPrincipal,
    requestDigest: record.creationRequestDigest,
    serviceId: record.serviceId,
    sourceCommit: object(record.sourceIdentity, 'record.sourceIdentity').commit,
    sourceTree: object(record.sourceIdentity, 'record.sourceIdentity').tree,
    artifactDigest: object(record.artifact, 'record.artifact').sha256,
    releaseManifestDigest: object(record.artifactManifest, 'record.artifactManifest').manifestDigest,
    certificationId: object(record.certification, 'record.certification').certificationId,
    targetSlot: record.slotId,
    candidateRouteDigest: record.candidateRouteDigest,
    policyDigest: sha256(canonicalize({ approvalPolicy: request.approvalPolicy, observationPolicy: request.observationPolicy, drainPolicy: request.drainPolicy })),
    approvalMode: request.approvalPolicy.mode,
    sequence: record.sequence,
  };
  for (const [key, expectedValue] of Object.entries(expected)) if (approval[key] !== expectedValue) throw new ReleaseCoordinatorError('release_approval_mismatch', `approval ${key} does not bind the current deployment`);
  if (timestamp(approval.expiresAt, 'approval.expiresAt') <= now) throw new ReleaseCoordinatorError('release_approval_expired', 'approval has expired');
  const approvingPrincipal = identifier(approval.approvingPrincipal, 'approval.approvingPrincipal');
  if (request.approvalPolicy.requiredPrincipal !== undefined && approvingPrincipal !== request.approvalPolicy.requiredPrincipal) throw new ReleaseCoordinatorError('release_wrong_principal', 'approval principal is not authorized by policy');
  const normalized = { ...expected, expiresAt: approval.expiresAt, approvingPrincipal, approvedAt: now };
  return { ...normalized, approvalDigest: sha256(canonicalize(normalized)) };
}

export function evaluateReleaseObservation(policy: NormalizedObservationPolicy, samplesValue: unknown, stateValue: unknown = {}): JsonObject {
  if (!Array.isArray(samplesValue) || samplesValue.length > 10_000) throw new ReleaseCoordinatorError('release_invalid_request', 'observation samples must be a bounded array');
  const samples = samplesValue.map((entry, index) => {
    const sample = strictObject(entry, `samples[${index}]`, ['observedAt', 'signals', 'errorRate', 'latencyMs', 'processRestarts', 'manualRollback', 'unknown'], ['observedAt', 'signals']);
    const signals = object(sample.signals, `samples[${index}].signals`);
    const missingSignals = policy.requiredSignals.filter((signal) => signals[signal] === undefined);
    const failedSignals = policy.requiredSignals.filter((signal) => signals[signal] === false);
    const unknown = sample.unknown === true || policy.requiredSignals.some((signal) => signals[signal] === 'UNKNOWN');
    return {
      observedAt: timestamp(sample.observedAt, `samples[${index}].observedAt`), signals,
      missingSignals, failedSignals, unknown,
      errorRate: sample.errorRate === undefined ? null : finiteNumber(sample.errorRate, `samples[${index}].errorRate`, 0, 1),
      latencyMs: sample.latencyMs === undefined ? null : finiteNumber(sample.latencyMs, `samples[${index}].latencyMs`, 0, 3_600_000),
      processRestarts: sample.processRestarts === undefined ? null : integer(sample.processRestarts, `samples[${index}].processRestarts`, 0, 1_000_000),
      manualRollback: sample.manualRollback === true,
    };
  });
  const state = object(stateValue, 'observation state');
  const first = samples.at(0);
  const last = samples.at(-1);
  const durationMs = first === undefined || last === undefined ? 0 : Math.max(0, Date.parse(last.observedAt) - Date.parse(first.observedAt));
  const failures = samples.filter((sample) => sample.failedSignals.length > 0 || (sample.errorRate !== null && sample.errorRate > policy.errorRateThreshold) || (sample.latencyMs !== null && sample.latencyMs > policy.latencyThresholdMs) || (sample.processRestarts !== null && sample.processRestarts > policy.maximumProcessRestarts));
  const missing = samples.find((sample) => sample.missingSignals.length > 0);
  const unknown = samples.find((sample) => sample.unknown);
  let consecutiveFailures = 0;
  for (let index = samples.length - 1; index >= 0; index -= 1) {
    const sample = samples[index];
    if (sample === undefined || !failures.includes(sample)) break;
    consecutiveFailures += 1;
  }
  const priorLatched = state.rollbackLatched === true;
  const manual = samples.some((sample) => sample.manualRollback);
  const threshold = consecutiveFailures >= policy.consecutiveFailureThreshold;
  const rollbackLatched = priorLatched || manual || threshold || (missing !== undefined && policy.missingTelemetry === 'ROLLBACK') || (unknown !== undefined && policy.unknownTelemetry === 'ROLLBACK');
  const recoveryRequired = !rollbackLatched && ((missing !== undefined && policy.missingTelemetry === 'RECOVERY_REQUIRED') || (unknown !== undefined && policy.unknownTelemetry === 'RECOVERY_REQUIRED'));
  const complete = samples.length >= policy.minimumSamples && durationMs >= policy.minimumDurationMs;
  return {
    decision: rollbackLatched ? 'ROLLBACK' : recoveryRequired ? 'RECOVERY_REQUIRED' : complete && failures.length === 0 ? 'PASS' : 'CONTINUE',
    rollbackLatched,
    manualRollback: manual,
    thresholdBreach: threshold,
    missingTelemetry: missing !== undefined,
    unknownTelemetry: unknown !== undefined,
    sampleCount: samples.length,
    durationMs,
    consecutiveFailures,
    failureCount: failures.length,
    cooldownUntil: rollbackLatched && last !== undefined ? new Date(Date.parse(last.observedAt) + policy.cooldownMs).toISOString() : state.cooldownUntil ?? null,
    samples,
  };
}

export async function executeReleaseGroup(
  contract: ReleaseGroupContract,
  promote: (member: ReleaseGroupMember) => Promise<JsonObject>,
  rollback: (member: ReleaseGroupMember, result: JsonObject) => Promise<JsonObject>,
): Promise<JsonObject> {
  const byId = new Map(contract.members.map((member) => [member.serviceId, member]));
  const promoted: { member: ReleaseGroupMember; result: JsonObject }[] = [];
  for (const serviceId of contract.promotionOrder) {
    const member = byId.get(serviceId);
    if (member === undefined) throw new ReleaseCoordinatorError('release_group_invalid', 'group promotion order references an absent member');
    try {
      const result = await promote(member);
      if (result.state !== 'SUCCEEDED') throw new ReleaseCoordinatorError('release_group_member_failed', `group member ${serviceId} did not succeed`, { state: result.state });
      promoted.push({ member, result });
    } catch (error) {
      const rollbackResults: JsonObject[] = [];
      for (const completed of [...promoted].reverse()) rollbackResults.push(await rollback(completed.member, completed.result));
      return { status: 'PARTIAL_FAILURE', failedServiceId: serviceId, promoted: promoted.map((item) => item.member.serviceId), rollbackOrder: rollbackResults.map((item) => item.serviceId ?? null), error: boundedReleaseError(error, 'release_group_member_failed', false, 'group-promotion') };
    }
  }
  return { status: 'SUCCEEDED', promotionOrder: promoted.map((item) => item.member.serviceId), atomicity: contract.atomicity };
}

export async function executeMigrationContract(
  contract: MigrationContract,
  approval: JsonObject | undefined,
  execute: (phase: MigrationPhase) => Promise<JsonObject>,
): Promise<JsonObject> {
  const results: JsonObject[] = [];
  let irreversibleCrossed = false;
  for (const phase of contract.phases) {
    if (phase.irreversible && approval?.irreversibleMigrationApproved !== true) throw new ReleaseCoordinatorError('release_irreversible_migration_approval_required', `migration phase ${phase.id} requires explicit irreversible approval`);
    const result = await execute(phase);
    results.push({ phaseId: phase.id, kind: phase.kind, irreversible: phase.irreversible, result });
    if (result.status !== 'SUCCEEDED') return { status: 'FAILED', results, irreversibleCrossed, automaticRollbackAllowed: !irreversibleCrossed };
    if (phase.irreversible) irreversibleCrossed = true;
  }
  return { status: 'SUCCEEDED', results, irreversibleCrossed, automaticRollbackAllowed: !irreversibleCrossed };
}

function artifactMetadata(record: JsonObject): JsonObject {
  return record.metadata !== null && typeof record.metadata === 'object' && !Array.isArray(record.metadata) ? record.metadata as JsonObject : {};
}

async function waitForJob(jobs: Pick<JobManager, 'get' | 'reconcile'>, id: string, timeoutMs: number): Promise<JobRecord> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    const current = jobs.get(id);
    if (current.status !== 'running') return current;
    await new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 10));
  }
  return jobs.reconcile(id);
}

export class CompositeReleasePreparationAuthority implements ReleasePreparationAuthority {
  readonly authority = 'release-preparation-composite' as const;
  constructor(private readonly options: {
    content: ImmutableReleaseContentService;
    certification: ReleaseCertificationService;
    jobs: JobManager;
    artifacts: ArtifactManager;
    applianceVersion: string;
  }) {}

  async resolve(request: NormalizedDeploymentRequest): Promise<PreparedSource> {
    const source = request.source;
    const resolved = this.options.content.resolveSource({
      repositoryPath: text(source.repositoryPath, 'source.repositoryPath'),
      repository: text(source.repository, 'source.repository', 256),
      ...(source.repositoryId === undefined ? {} : { repositoryId: text(source.repositoryId, 'source.repositoryId', 256) }),
      ref: text(source.ref, 'source.ref', 256),
      ...(source.expectedCommit === undefined ? {} : { expectedCommit: gitSha(source.expectedCommit, 'source.expectedCommit') }),
      ...(source.expectedTree === undefined ? {} : { expectedTree: gitSha(source.expectedTree, 'source.expectedTree') }),
      ...(source.lockfilePath === undefined ? {} : { lockfilePath: text(source.lockfilePath, 'source.lockfilePath', 1024) }),
      ownerPrincipal: request.ownerPrincipal,
      verifiedCommitState: source.verifiedCommitState === 'VERIFIED' ? 'VERIFIED' : source.verifiedCommitState === 'NOT_REQUIRED' ? 'NOT_REQUIRED' : 'UNKNOWN',
    });
    return {
      sourceIdentity: object(resolved.sourceIdentity, 'resolved.sourceIdentity'),
      sourceManifest: object(resolved.sourceManifest, 'resolved.sourceManifest'),
      sourceEpoch: integer(resolved.sourceEpoch, 'resolved.sourceEpoch'),
      artifact: object(resolved.artifact, 'resolved.artifact'),
      receiptReferences: [text(object(resolved.resolverReceipt, 'resolverReceipt').receiptId, 'resolverReceipt.receiptId')],
    };
  }

  async buildOrReuse(request: NormalizedDeploymentRequest, source: PreparedSource, context: RuntimeExecutionContext): Promise<PreparedArtifact> {
    const build = request.build;
    const reusable = build.preparedArtifact;
    if (reusable !== undefined) {
      const prepared = strictObject(reusable, 'build.preparedArtifact', ['artifactId', 'artifactSha256', 'manifest', 'buildId', 'receiptReferences'], ['artifactId', 'artifactSha256', 'manifest', 'buildId']);
      const artifact = this.options.artifacts.get(text(prepared.artifactId, 'preparedArtifact.artifactId'));
      if (artifact.state !== 'finalized' || artifact.sha256 !== digest(prepared.artifactSha256, 'preparedArtifact.artifactSha256') || this.options.artifacts.verify(String(artifact.id)).valid !== true) throw new ReleaseCoordinatorError('release_artifact_invalid', 'prepared artifact failed exact integrity verification');
      const manifest = validateReleaseRecord('ReleaseArtifactManifestV1', prepared.manifest);
      if (manifest.artifactId !== artifact.id || manifest.artifactSha256 !== artifact.sha256 || object(manifest.source, 'manifest.source').commit !== source.sourceIdentity.commit || object(manifest.source, 'manifest.source').tree !== source.sourceIdentity.tree) throw new ReleaseCoordinatorError('release_artifact_invalid', 'prepared artifact manifest does not bind exact source and artifact identities');
      return { artifact, manifest, buildId: identifier(prepared.buildId, 'preparedArtifact.buildId'), jobIds: [], reused: true, receiptReferences: prepared.receiptReferences === undefined ? [] : stringArray(prepared.receiptReferences, 'preparedArtifact.receiptReferences') };
    }
    const profile = normalizeBuildProfile(build.profile) as NormalizedBuildProfile;
    const job = strictObject(build.job, 'build.job', ['argv', 'cwd', 'env', 'timeoutMs', 'outputDirectory'], ['argv', 'cwd', 'timeoutMs', 'outputDirectory']);
    if (!Array.isArray(job.argv) || job.argv.length === 0 || job.argv.some((item) => typeof item !== 'string' || item.includes('\0'))) throw new ReleaseCoordinatorError('release_invalid_request', 'build.job.argv must be a non-empty string array');
    const cwd = text(job.cwd, 'build.job.cwd');
    const env = job.env === undefined ? {} : normalizedJson(job.env, 'build.job.env');
    const timeoutMs = integer(job.timeoutMs, 'build.job.timeoutMs', 1, 86_400_000);
    const buildRequestDigest = sha256(canonicalize({
      operation: 'babyx.release.build', serviceId: request.serviceId, ownerPrincipal: request.ownerPrincipal,
      sourceCommit: source.sourceIdentity.commit, sourceTree: source.sourceIdentity.tree,
      buildProfileDigest: profile.profileDigest, argv: job.argv, cwd, env, timeoutMs,
      attemptIdentity: context.idempotencyKey,
    }));
    const matches = this.options.jobs.list().filter((candidate) => {
      const metadata = candidate.metadata;
      return metadata !== undefined && metadata.releaseBuildRequestDigest === buildRequestDigest;
    }).sort((left, right) => left.id.localeCompare(right.id));
    if (matches.length > 1) throw new ReleaseCoordinatorError('release_job_ambiguous', 'multiple durable build jobs match one exact build request', { buildRequestDigest, jobIds: matches.map((candidate) => candidate.id) });
    const started = matches[0] ?? this.options.jobs.start('babyx.release.build', {
      argv: job.argv, cwd, env, timeoutMs,
      metadata: {
        serviceId: request.serviceId, ownerPrincipal: request.ownerPrincipal,
        sourceCommit: source.sourceIdentity.commit, sourceTree: source.sourceIdentity.tree,
        buildProfileDigest: profile.profileDigest, releaseBuildRequestDigest: buildRequestDigest,
        attemptIdentity: context.idempotencyKey,
      },
    });
    const terminal = started.status === 'running'
      ? await waitForJob(this.options.jobs, started.id, timeoutMs + 5_000)
      : started;
    if (terminal.status !== 'completed' || terminal.exitCode !== 0) throw new ReleaseCoordinatorError('release_build_failed', 'durable build job did not complete successfully', { jobId: terminal.id, status: terminal.status, exitCode: terminal.exitCode });
    const packaged = this.options.content.packageRelease({
      serviceId: request.serviceId,
      outputDirectory: text(job.outputDirectory, 'build.job.outputDirectory'),
      source: source.sourceIdentity,
      buildId: identifier(build.buildId ?? `build-${sha256(canonicalize({ source: source.sourceIdentity, profile: profile.profileDigest })).slice(0, 40)}`, 'build.buildId'),
      buildProfile: profile,
      toolchainIdentity: normalizedJson(build.toolchainIdentity, 'build.toolchainIdentity'),
      dependencyIdentity: normalizedJson(build.dependencyIdentity, 'build.dependencyIdentity'),
      serviceDefinitionDigest: request.serviceDefinitionDigest,
      executableTemplate: normalizedJson(build.executableTemplate, 'build.executableTemplate'),
      runtimeRequirements: normalizedJson(build.runtimeRequirements, 'build.runtimeRequirements'),
      requiredConfigurationNames: build.requiredConfigurationNames === undefined ? [] : stringArray(build.requiredConfigurationNames, 'build.requiredConfigurationNames'),
      requiredCredentialNames: build.requiredCredentialNames === undefined ? [] : stringArray(build.requiredCredentialNames, 'build.requiredCredentialNames'),
      writablePaths: build.writablePaths === undefined ? [] : stringArray(build.writablePaths, 'build.writablePaths'),
      readinessCompatibility: normalizedJson(build.readinessCompatibility, 'build.readinessCompatibility'),
      smokeCompatibility: normalizedJson(build.smokeCompatibility, 'build.smokeCompatibility'),
      ...(build.migrationMetadata === undefined ? {} : { migrationMetadata: normalizedJson(build.migrationMetadata, 'build.migrationMetadata') }),
      minimumApplianceVersion: text(build.minimumApplianceVersion ?? this.options.applianceVersion, 'build.minimumApplianceVersion', 64),
      producerIdentity: normalizedJson(build.producerIdentity, 'build.producerIdentity'),
      provenanceReferences: Array.isArray(build.provenanceReferences) ? build.provenanceReferences.map((entry) => normalizedJson(entry, 'provenanceReference')) : [],
      sbomReferences: Array.isArray(build.sbomReferences) ? build.sbomReferences.map((entry) => normalizedJson(entry, 'sbomReference')) : [],
      createdAt: new Date().toISOString(),
      sourceEpoch: source.sourceEpoch,
    });
    return { artifact: object(packaged.artifact, 'packaged.artifact'), manifest: object(packaged.manifest, 'packaged.manifest'), buildId: String(object(packaged.manifest, 'packaged.manifest').buildId), jobIds: [terminal.id], reused: false, receiptReferences: [] };
  }

  async certify(request: NormalizedDeploymentRequest, source: PreparedSource, artifact: PreparedArtifact, context: RuntimeExecutionContext): Promise<PreparedCertification> {
    const body = request.certification;
    const result = await this.options.certification.certify({
      schemaVersion: '1.0.0', artifactId: artifact.artifact.id, artifactSha256: artifact.artifact.sha256, manifest: artifact.manifest,
      serviceDefinitionDigest: request.serviceDefinitionDigest,
      profile: body.profile,
      baseSnapshot: body.baseSnapshot,
      machine: body.machine,
      runtimeIdentity: body.runtimeIdentity,
      dependencyIdentity: artifact.manifest.dependencyIdentity,
      applianceCompatibilityVersion: body.applianceCompatibilityVersion ?? this.options.applianceVersion,
      externalContractIdentities: body.externalContractIdentities,
      securityPolicyVersion: body.securityPolicyVersion,
      invalidationConditions: body.invalidationConditions ?? [],
      ...(body.expiresAt === undefined ? {} : { expiresAt: body.expiresAt }),
    }, context);
    const certification = object(result.certification, 'certification result');
    if (certification.state !== 'SUCCEEDED') throw new ReleaseCoordinatorError('release_certification_failed', 'release certification did not succeed', { certificationId: certification.certificationId, state: certification.state });
    return { certification, reused: result.reused === true, jobIds: Array.isArray(certification.allJobIds) ? certification.allJobIds.map(String) : [], receiptReferences: Array.isArray(certification.receiptIds) ? certification.receiptIds.map(String) : [] };
  }

  async materialize(request: NormalizedDeploymentRequest, source: PreparedSource, artifact: PreparedArtifact, certification: PreparedCertification, context: RuntimeExecutionContext): Promise<PreparedRelease> {
    const materialization = this.options.content.materializeRelease({ artifactId: String(artifact.artifact.id), artifactSha256: String(artifact.artifact.sha256), reservationOwner: request.ownerPrincipal });
    const release = this.options.content.createReleaseRecord({
      serviceId: request.serviceId,
      artifactId: artifact.artifact.id,
      artifactSha256: artifact.artifact.sha256,
      artifactSizeBytes: artifact.artifact.size,
      manifestDigest: artifact.manifest.manifestDigest,
      sourceCommit: source.sourceIdentity.commit,
      sourceTree: source.sourceIdentity.tree,
      lockfileDigest: source.sourceIdentity.lockfileDigest,
      buildId: artifact.buildId,
      certificationId: certification.certification.certificationId,
      materializationPath: materialization.path,
      materializationMethod: materialization.reused === true ? 'CONTENT_ADDRESSED_REUSE' : 'ATOMIC_EXTRACT_PROMOTE',
      materializationVerifiedAt: new Date().toISOString(),
      installedManifestDigest: artifact.manifest.manifestDigest,
      immutablePermissionsVerified: object(materialization.verification, 'materialization.verification').valid === true,
      credentialSetReferenceDigest: request.credentialSetDigest,
      compatibleApplianceVersion: this.options.applianceVersion,
      retentionClass: 'RECENT', pinned: false, slotReferences: [], deploymentReferences: [], integrityState: 'VERIFIED',
      ownerPrincipal: request.ownerPrincipal,
      idempotencyKey: `release-${sha256(`${context.idempotencyKey}:${artifact.artifact.sha256}`).slice(0, 48)}`,
      receiptReferences: [...source.receiptReferences, ...artifact.receiptReferences, ...certification.receiptReferences],
    });
    return { release, materialization, jobIds: [...artifact.jobIds, ...certification.jobIds], receiptReferences: [...source.receiptReferences, ...artifact.receiptReferences, ...certification.receiptReferences] };
  }
}

function normalizeLease(request: NormalizedDeploymentRequest, deploymentId: string, now: string): JsonObject {
  const controller = request.controller;
  const acquiredAt = now;
  const durationMs = controller.leaseDurationMs === undefined ? 300_000 : integer(controller.leaseDurationMs, 'controller.leaseDurationMs', 1_000, 86_400_000);
  const controllerIdentity = normalizedJson(controller.identity, 'controller.identity');
  const observationDigest = digest(controller.observationDigest, 'controller.observationDigest');
  return {
    schemaVersion: '1.0.0',
    leaseId: identifier(controller.leaseId ?? `deployment-${sha256(deploymentId).slice(0, 48)}`, 'controller.leaseId'),
    resourceType: 'DEPLOYMENT', resourceId: deploymentId, ownerPrincipal: request.ownerPrincipal,
    controllerIdentity, acquiredAt, expiresAt: new Date(Date.parse(acquiredAt) + durationMs).toISOString(), sequence: 1, state: 'ACTIVE', observationDigest,
  };
}

function normalizeRouteLease(request: NormalizedDeploymentRequest, now: string, purpose: 'prepare' | 'cutover' | 'rollback' | 'reconcile' | 'expire' = 'cutover'): JsonObject {
  const route = request.route;
  const lease = strictObject(route.lease, 'route.lease', ['leaseId', 'controllerIdentity', 'durationMs', 'observationDigest', 'existingControllerAbsent'], ['leaseId', 'controllerIdentity', 'observationDigest']);
  const baseLeaseId = identifier(lease.leaseId, 'route.lease.leaseId');
  const leaseId = identifier(`${baseLeaseId.slice(0, 96)}-${purpose}`, 'route.lease.phaseLeaseId');
  return {
    leaseId,
    controllerIdentity: normalizedJson(lease.controllerIdentity, 'route.lease.controllerIdentity'),
    acquiredAt: now,
    expiresAt: new Date(Date.parse(now) + (lease.durationMs === undefined ? 300_000 : integer(lease.durationMs, 'route.lease.durationMs', 1_000, 86_400_000))).toISOString(),
    observationDigest: digest(lease.observationDigest, 'route.lease.observationDigest'),
    existingControllerAbsent: lease.existingControllerAbsent === true,
  };
}

function storeArtifact(manager: ArtifactManager, name: string, value: JsonObject): JsonObject {
  assertNoRawSecrets(value);
  const bytes = Buffer.from(`${canonicalize(value)}\n`, 'utf8');
  const record = manager.begin(name, { kind: 'RELEASE_EVIDENCE', digest: sha256(bytes) });
  manager.upload(String(record.id), 0, bytes);
  return manager.finalize(String(record.id), bytes.length, sha256(bytes));
}

function ownerRecord(store: ReleaseApplianceStore, deploymentId: string, context: RuntimeExecutionContext): JsonObject {
  let record: JsonObject;
  try { record = store.getRecord('DeploymentRecordV1', deploymentId); } catch (error) {
    if (error instanceof ReleaseStoreError && error.code === 'release_record_not_found') throw new ReleaseCoordinatorError('release_record_not_found', 'deployment was not found');
    throw error;
  }
  if (context.authorityClass !== 'unrestricted-owner' && record.ownerPrincipal !== context.subject) throw new ReleaseCoordinatorError('release_record_not_found', 'deployment was not found');
  return record;
}

function activeJobs(jobs: Pick<JobManager, 'get' | 'reconcile'>, ids: unknown): JobRecord[] {
  if (!Array.isArray(ids)) return [];
  return ids.map(String).map((id) => {
    const job = jobs.get(id);
    return job.status === 'running' ? jobs.reconcile(id) : job;
  }).filter((job) => job.status === 'running');
}

export function describeReleaseCoordinator(): JsonObject {
  return {
    contractVersion: RELEASE_COORDINATOR_CONTRACT_VERSION,
    authority: 'sole-release-activation-coordinator',
    composes: ['immutable-release-content', 'release-certification', 'slot-runtime', 'route-authority', 'durable-jobs', 'artifacts', 'proofs'],
    createsAlternateAuthority: false,
    publicOperations: ['plan', 'prepare', 'promote', 'approve', 'cancel', 'rollback', 'reconcile', 'resume', 'expire', 'gc', 'live', 'status', 'get', 'list', 'events', 'evidence', 'failures'],
    productionMutationEnabledByAdaptersOnly: true,
  };
}

export function releaseCoordinatorCapabilities(): JsonObject {
  return {
    operation: 'babyx.release.capabilities',
    coordinator: describeReleaseCoordinator(),
    deploymentStates: ['REQUESTED','PREFLIGHTING','RESOLVING_SOURCE','REUSING_ARTIFACT','BUILDING','CERTIFYING','READY_TO_STAGE','STAGING','STARTING_INACTIVE','READINESS_CHECKING','READY_TO_PROMOTE','AWAITING_APPROVAL','CUTOVER_PREPARING','CUTTING_OVER','OBSERVING','DRAINING_PREVIOUS','FINALIZING','SUCCEEDED','ROLLBACK_REQUESTED','ROLLING_BACK','ROLLED_BACK','CLEANUP_PENDING','CLEANING','FAILED','RECOVERY_REQUIRED','AMBIGUOUS','CANCELLED','EXPIRED'],
    modes: ['DIRECT', 'CANARY', 'SHADOW', 'PREVIEW'],
    groupContracts: true, migrationContracts: true, automaticRollback: true, startupReconciliation: true,
    successRequirements: [...DEPLOYMENT_SUCCESS_REQUIREMENTS],
  };
}

export function planReleaseDeployment(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
  const authenticated = requiredContext(context);
  const request = normalizeDeploymentRequest(payload.request, authenticated.subject);
  return {
    operation: 'babyx.release.plan', readOnly: true, requestDigest: request.requestDigest, serviceId: request.serviceId,
    phases: ['PREFLIGHTING','RESOLVING_SOURCE', request.build.preparedArtifact === undefined ? 'BUILDING' : 'REUSING_ARTIFACT','CERTIFYING','STAGING','STARTING_INACTIVE','READINESS_CHECKING', request.approvalPolicy.mode === 'REQUIRED' ? 'AWAITING_APPROVAL' : null,'CUTOVER_PREPARING','CUTTING_OVER','OBSERVING','DRAINING_PREVIOUS','FINALIZING'].filter(Boolean),
    externalEffects: ['durable-build-job','disposable-certification','immutable-materialization','private-slot-start','typed-caddy-load','public-probe','previous-slot-drain'].filter((effect) => !(effect === 'durable-build-job' && request.build.preparedArtifact !== undefined)),
    rollback: { priorRoutePreserved: true, priorSlotRetainedThroughObservation: true, automatic: true },
    group: request.group ?? null, migration: request.migration ?? null,
  };
}

export class ReleaseCoordinatorService {
  private readonly now: () => string;
  constructor(private readonly options: ReleaseCoordinatorOptions) { this.now = options.now ?? (() => new Date().toISOString()); }

  describe(): JsonObject { return describeReleaseCoordinator(); }

  capabilities(): JsonObject { return releaseCoordinatorCapabilities(); }

  plan(payload: JsonObject, context: RuntimeExecutionContext): JsonObject { return planReleaseDeployment(payload, context); }

  async initialize(limit = RELEASE_RECONCILE_LIMIT): Promise<JsonObject> {
    const all = this.options.store.listRecordIdentities(10_000).filter((identity) => identity.schemaId === 'DeploymentRecordV1');
    const identities = all.slice(0, limit);
    const results: JsonObject[] = [];
    for (const identity of identities) {
      let record = this.options.store.getRecord(identity.schemaId, identity.recordId);
      const priorState = String(record.state);
      if (!TERMINAL.has(priorState) && priorState !== 'AMBIGUOUS') {
        const context: RuntimeExecutionContext = {
          subject: String(record.ownerPrincipal), authorityClass: 'unrestricted-owner',
          idempotencyKey: `startup-${sha256(`${identity.recordId}:${record.sequence}`).slice(0, 48)}`,
        };
        try {
          const request = normalizeDeploymentRequest(record.normalizedRequest, String(record.ownerPrincipal));
          record = await this.reconcileOne(record, request, context);
        } catch (error) {
          try { record = this.classifyExternalFailure(record, String(record.ownerPrincipal), 'startup-reconcile', error); }
          catch { /* Preserve the authoritative record when even classification cannot be safely persisted. */ }
        }
      }
      results.push({ deploymentId: identity.recordId, priorState, state: record.state, sequence: record.sequence });
    }
    return {
      operation: 'babyx.release.reconcile', startup: true, scanned: identities.length,
      processed: results.length, deferred: Math.max(0, all.length - identities.length),
      deploymentIds: identities.map((identity) => identity.recordId), results,
    };
  }

  async prepare(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = requiredContext(context);
    const request = normalizeDeploymentRequest(payload.request, authenticated.subject);
    const deploymentId = payload.deploymentId === undefined ? `deploy-${sha256(canonicalize({ owner: authenticated.subject, idempotencyKey: authenticated.idempotencyKey, requestDigest: request.requestDigest })).slice(0, 40)}` : identifier(payload.deploymentId, 'deploymentId');
    let record: JsonObject;
    if (this.options.store.hasRecord('DeploymentRecordV1', deploymentId)) {
      record = ownerRecord(this.options.store, deploymentId, context);
      if (record.creationRequestDigest !== request.requestDigest || record.idempotencyKey !== authenticated.idempotencyKey) throw new ReleaseCoordinatorError('release_idempotency_conflict', 'deployment identity or idempotency key is bound to a different normalized request');
      if (['READY_TO_STAGE', 'SUCCEEDED', 'ROLLED_BACK', 'FAILED', 'CANCELLED', 'EXPIRED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'].includes(String(record.state))) return { operation: 'babyx.release.prepare', deployment: record, replayed: true };
    } else {
      record = this.createInitial(deploymentId, request, authenticated);
    }
    record = await this.advancePreparation(record, request, context);
    return { operation: 'babyx.release.prepare', deployment: record, replayed: false };
  }

  async promote(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = requiredContext(context);
    let record: JsonObject;
    let request: NormalizedDeploymentRequest;
    if (payload.request !== undefined) {
      request = normalizeDeploymentRequest(payload.request, authenticated.subject);
      const prepared = await this.prepare({ request, ...(payload.deploymentId === undefined ? {} : { deploymentId: payload.deploymentId }) }, context);
      record = object(prepared.deployment, 'prepared.deployment');
    } else {
      record = ownerRecord(this.options.store, identifier(payload.deploymentId, 'deploymentId'), context);
      request = normalizeDeploymentRequest(record.normalizedRequest, authenticated.subject);
    }
    if (TERMINAL.has(String(record.state))) return { operation: 'babyx.release.promote', deployment: record, replayed: true };
    record = await this.advancePromotion(record, request, context);
    return { operation: 'babyx.release.promote', deployment: record, replayed: false };
  }

  approve(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const authenticated = requiredContext(context);
    let record = ownerRecord(this.options.store, identifier(payload.deploymentId, 'deploymentId'), context);
    const expectedSequence = integer(payload.expectedSequence, 'expectedSequence');
    if (Number(record.sequence) !== expectedSequence) throw new ReleaseCoordinatorError('release_stale_sequence', 'expected sequence does not match deployment record');
    if (record.state !== 'AWAITING_APPROVAL') throw new ReleaseCoordinatorError('release_invalid_state', 'deployment is not awaiting approval');
    const request = normalizeDeploymentRequest(record.normalizedRequest, authenticated.subject);
    const approval = bindReleaseApproval(record, request, payload.approval, this.now());
    record = this.transition(record, 'AWAITING_APPROVAL', authenticated.subject, 'approval-bound', authenticated.idempotencyKey, { approvalEvidence: [...(Array.isArray(record.approvalEvidence) ? record.approvalEvidence : []), approval], approvalDigest: approval.approvalDigest });
    return { operation: 'babyx.release.approve', deployment: record };
  }

  async cancel(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = requiredContext(context);
    let record = ownerRecord(this.options.store, identifier(payload.deploymentId, 'deploymentId'), context);
    this.assertSequence(record, payload.expectedSequence);
    if (record.state === 'CANCELLED') return { operation: 'babyx.release.cancel', deployment: record, replayed: true };
    if (record.state === 'AMBIGUOUS') throw new ReleaseCoordinatorError('release_route_ambiguous', 'ambiguous deployment identity blocks cancellation and destructive cleanup');
    if (TERMINAL.has(String(record.state))) throw new ReleaseCoordinatorError('release_invalid_state', 'terminal deployment cannot be cancelled');
    if (['CUTOVER_PREPARING', 'CUTTING_OVER', 'OBSERVING', 'DRAINING_PREVIOUS', 'FINALIZING', 'ROLLBACK_REQUESTED', 'ROLLING_BACK'].includes(String(record.state))) throw new ReleaseCoordinatorError('release_unsafe_cancellation', 'cancellation is unsafe during or after cutover; request rollback instead');
    const reason = text(payload.reason ?? 'operator-request', 'reason', 1024);
    const request = normalizeDeploymentRequest(record.normalizedRequest, authenticated.subject);
    if (record.state === 'REQUESTED') {
      const evidence = { schemaVersion: '1.0.0', deploymentId: record.deploymentId, terminalState: 'CANCELLED', cancellation: { requestedAt: this.now(), reason }, cleanup: { required: false, completed: true, positiveAbsence: true }, createdAt: this.now() };
      const artifact = storeArtifact(this.options.artifacts, `${record.deploymentId}-cancelled-evidence.json`, evidence);
      const proof = this.options.proofs.create(String(record.deploymentId), 'babyx.release.cancel', true, String(record.createdAt), evidence);
      if (proof.error !== undefined) return { operation: 'babyx.release.cancel', deployment: this.recovery(record, authenticated.subject, 'cancel-proof-unavailable', new ReleaseCoordinatorError('release_evidence_incomplete', 'cancellation proof is unavailable')) };
      assertTerminalDeploymentSafety('CANCELLED', { cleanupComplete: true, activeRelatedJobs: 0, unresolvedAmbiguity: false, evidenceComplete: true, cancellationComplete: true });
      record = this.transition(record, 'CANCELLED', authenticated.subject, 'request-cancelled', authenticated.idempotencyKey, { desiredState: 'CANCELLED', cancellation: { requestedAt: this.now(), reason, completed: true }, cleanup: { required: false, completed: true, positiveAbsence: true }, evidenceIndexId: artifact.id, evidenceIndexDigest: artifact.sha256, finalProof: proof }, [{ artifactId: artifact.id, artifactSha256: artifact.sha256 }]);
      return { operation: 'babyx.release.cancel', deployment: record };
    }
    record = this.transition(record, 'CLEANUP_PENDING', authenticated.subject, 'cancel-requested', authenticated.idempotencyKey, { cancellation: { requestedAt: this.now(), reason }, terminalIntent: 'CANCELLED' });
    record = await this.cleanupCandidate(record, request, context, 'CANCELLED');
    return { operation: 'babyx.release.cancel', deployment: record };
  }

  async rollback(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = requiredContext(context);
    let record = ownerRecord(this.options.store, identifier(payload.deploymentId, 'deploymentId'), context);
    this.assertSequence(record, payload.expectedSequence);
    if (record.state === 'ROLLED_BACK') return { operation: 'babyx.release.rollback', deployment: record, replayed: true };
    if (TERMINAL.has(String(record.state))) throw new ReleaseCoordinatorError('release_invalid_state', 'terminal deployment cannot be rolled back');
    if (record.state !== 'ROLLBACK_REQUESTED' && record.state !== 'ROLLING_BACK') record = this.transition(record, 'ROLLBACK_REQUESTED', authenticated.subject, 'rollback-requested', authenticated.idempotencyKey, { rollbackStatus: { requestedAt: this.now(), reason: text(payload.reason ?? 'operator-request', 'reason', 1024), automatic: payload.automatic === true } });
    record = await this.executeRollback(record, normalizeDeploymentRequest(record.normalizedRequest, authenticated.subject), context);
    return { operation: 'babyx.release.rollback', deployment: record };
  }

  async reconcile(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = requiredContext(context);
    if (payload.deploymentId !== undefined) {
      let record = ownerRecord(this.options.store, identifier(payload.deploymentId, 'deploymentId'), context);
      if (payload.expectedSequence !== undefined) this.assertSequence(record, payload.expectedSequence);
      record = await this.reconcileOne(record, normalizeDeploymentRequest(record.normalizedRequest, authenticated.subject), context);
      return { operation: 'babyx.release.reconcile', deployments: [record], processed: 1 };
    }
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, RELEASE_RECONCILE_LIMIT);
    const candidates = this.listRecords(context).filter((record) => MUTATION_STATES.has(String(record.state)));
    const records = candidates.slice(0, limit);
    const results: JsonObject[] = [];
    for (const record of records) results.push(await this.reconcileOne(record, normalizeDeploymentRequest(record.normalizedRequest, authenticated.subject), context));
    return { operation: 'babyx.release.reconcile', deployments: results, processed: results.length, deferred: Math.max(0, candidates.length - results.length) };
  }

  async resume(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = requiredContext(context);
    let record = ownerRecord(this.options.store, identifier(payload.deploymentId, 'deploymentId'), context);
    this.assertSequence(record, payload.expectedSequence);
    if (record.state !== 'RECOVERY_REQUIRED') throw new ReleaseCoordinatorError('release_invalid_state', 'only RECOVERY_REQUIRED may resume');
    const resolution = strictObject(payload.resolution, 'resolution', ['obstructionResolved', 'observationDigest', 'resumeState'], ['obstructionResolved', 'observationDigest', 'resumeState']);
    if (resolution.obstructionResolved !== true) throw new ReleaseCoordinatorError('release_recovery_unresolved', 'resume requires positive obstruction-resolution evidence');
    digest(resolution.observationDigest, 'resolution.observationDigest');
    const resumeState = text(resolution.resumeState, 'resolution.resumeState', 64);
    record = this.transition(record, resumeState, authenticated.subject, 'recovery-resumed', authenticated.idempotencyKey, { recoveryResolution: { ...resolution, resolvedAt: this.now() }, error: undefined });
    record = await this.reconcileOne(record, normalizeDeploymentRequest(record.normalizedRequest, authenticated.subject), context);
    return { operation: 'babyx.release.resume', deployment: record };
  }

  async expire(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = requiredContext(context);
    let record = ownerRecord(this.options.store, identifier(payload.deploymentId, 'deploymentId'), context);
    this.assertSequence(record, payload.expectedSequence);
    const request = normalizeDeploymentRequest(record.normalizedRequest, authenticated.subject);
    if (request.expiresAt === undefined || Date.parse(request.expiresAt) > Date.parse(this.now())) throw new ReleaseCoordinatorError('release_not_expired', 'deployment has not expired');
    if (record.routeMode === 'PREVIEW' && record.routeId !== undefined) {
      const routeLease = normalizeRouteLease(request, this.now(), 'expire');
      this.options.routes.acquireLease(request.serviceId, routeLease, { ...context, idempotencyKey: `route-expire-lease-${sha256(String(record.deploymentId)).slice(0, 40)}` });
      const route = await this.options.routes.expirePreview({ serviceId: record.serviceId, lease: routeLease }, { ...context, idempotencyKey: `expire-route-${sha256(String(record.deploymentId)).slice(0, 40)}` });
      try { this.options.routes.releaseLease(request.serviceId, routeLease, { ...context, idempotencyKey: `route-expire-release-${sha256(String(record.deploymentId)).slice(0, 40)}` }); } catch {}
      if (route.state !== 'RESTORED_VERIFIED') return { operation: 'babyx.release.expire', deployment: this.recovery(record, authenticated.subject, 'preview-expiration-route', new ReleaseCoordinatorError('release_preview_cleanup_failed', 'preview route expiration was not verified')) };
      if (record.slotId !== undefined) {
        const candidate = this.options.slots.getSlot({ serviceId: request.serviceId, slotId: record.slotId }, context).slot as JsonObject;
        if (candidate.state === 'ACTIVE') this.options.slots.markDraining({ serviceId: request.serviceId, slotId: record.slotId, routeReadbackVerified: true }, { ...context, idempotencyKey: `preview-candidate-drain-${sha256(String(record.deploymentId)).slice(0, 40)}` });
      }
      if (record.priorKnownGoodSlotId !== undefined && this.options.slots.restoreActive !== undefined) {
        const prior = this.options.slots.getSlot({ serviceId: request.serviceId, slotId: record.priorKnownGoodSlotId }, context).slot as JsonObject;
        if (prior.state === 'DRAINING') this.options.slots.restoreActive({ serviceId: request.serviceId, slotId: record.priorKnownGoodSlotId, expectedSequence: prior.sequence, routeReadbackVerified: true, routeDigest: route.restorationReadbackDigest }, { ...context, idempotencyKey: `preview-prior-restore-${sha256(String(record.deploymentId)).slice(0, 40)}` });
      }
      record = this.transition(record, 'CLEANUP_PENDING', authenticated.subject, 'preview-expiration-route-restored', `preview-expire-cleanup-${sha256(String(record.deploymentId)).slice(0, 40)}`, { routeRecord: route, routeRestored: true, terminalIntent: 'EXPIRED', expiration: { requestedAt: this.now(), expiresAt: request.expiresAt } });
    } else {
      record = this.transition(record, 'CLEANUP_PENDING', authenticated.subject, 'expiration-requested', authenticated.idempotencyKey, { terminalIntent: 'EXPIRED', expiration: { requestedAt: this.now(), expiresAt: request.expiresAt } });
    }
    record = await this.cleanupCandidate(record, request, context, 'EXPIRED');
    return { operation: 'babyx.release.expire', deployment: record };
  }

  gc(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    requiredContext(context);
    if (this.options.governor !== undefined) return this.options.governor.gc(payload, context);
    if (payload.dryRun !== true) throw new ReleaseCoordinatorError('release_gc_dry_run_required', 'live GC requires the checkpoint H resource governor');
    const limit = payload.limit === undefined ? 100 : integer(payload.limit, 'limit', 1, RELEASE_OPERATION_LIMIT);
    const records = this.listRecords(context).filter((record) => TERMINAL.has(String(record.state))).slice(0, limit);
    return { operation: 'babyx.release.gc', dryRun: true, candidates: records.map((record) => ({ deploymentId: record.deploymentId, state: record.state, releaseId: record.releaseId, retainedBecause: record.state === 'SUCCEEDED' ? ['active-or-recent-release'] : ['evidence-retention'] })), destructiveActions: [] };
  }

  live(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const record = ownerRecord(this.options.store, identifier(payload.deploymentId, 'deploymentId'), context);
    return { operation: 'babyx.release.live', live: this.liveProjection(record) };
  }

  status(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const record = ownerRecord(this.options.store, identifier(payload.deploymentId, 'deploymentId'), context);
    return { operation: 'babyx.release.status', deploymentId: record.deploymentId, state: record.state, desiredState: record.desiredState, sequence: record.sequence, updatedAt: record.updatedAt, live: this.liveProjection(record), failure: record.error ?? null };
  }

  get(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    return { operation: 'babyx.release.get', deployment: ownerRecord(this.options.store, identifier(payload.deploymentId, 'deploymentId'), context) };
  }

  list(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, 100_000);
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, RELEASE_OPERATION_LIMIT);
    const state = payload.state === undefined ? undefined : text(payload.state, 'state', 64);
    const serviceId = payload.serviceId === undefined ? undefined : identifier(payload.serviceId, 'serviceId');
    const records = this.listRecords(context).filter((record) => state === undefined || record.state === state).filter((record) => serviceId === undefined || record.serviceId === serviceId);
    const selected = records.slice(offset, offset + limit);
    return { operation: 'babyx.release.list', deployments: selected, offset, limit, total: records.length, nextOffset: offset + selected.length < records.length ? offset + selected.length : null };
  }

  events(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const deploymentId = identifier(payload.deploymentId, 'deploymentId');
    ownerRecord(this.options.store, deploymentId, context);
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, 1_000_000);
    const limit = payload.limit === undefined ? 100 : integer(payload.limit, 'limit', 1, RELEASE_EVENT_LIMIT);
    const events = this.options.store.events('DeploymentRecordV1', deploymentId, offset, limit);
    return { operation: 'babyx.release.events', deploymentId, events, offset, limit, nextOffset: events.length === limit ? offset + events.length : null };
  }

  evidence(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const record = ownerRecord(this.options.store, identifier(payload.deploymentId, 'deploymentId'), context);
    return { operation: 'babyx.release.evidence', deploymentId: record.deploymentId, evidenceIndexId: record.evidenceIndexId ?? null, evidenceIndexDigest: record.evidenceIndexDigest ?? null, artifactReferences: record.artifactReferences ?? [], receiptReferences: record.receiptReferences ?? [], proof: record.finalProof ?? null, successEvidence: record.successEvidence ?? null };
  }

  failures(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const limit = payload.limit === undefined ? 100 : integer(payload.limit, 'limit', 1, RELEASE_OPERATION_LIMIT);
    const failures = this.listRecords(context).filter((record) => ['FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'ROLLED_BACK'].includes(String(record.state))).slice(0, limit).map((record) => ({ deploymentId: record.deploymentId, serviceId: record.serviceId, state: record.state, failureClass: record.failureClass ?? null, error: record.error ?? null, updatedAt: record.updatedAt }));
    return { operation: 'babyx.release.failures', failures, limit };
  }

  private createInitial(deploymentId: string, request: NormalizedDeploymentRequest, authenticated: { subject: string; idempotencyKey: string }): JsonObject {
    const createdAt = this.now();
    const record = validateReleaseRecord('DeploymentRecordV1', {
      schemaVersion: '1.0.0', deploymentId, deploymentKind: 'APPLICATION_RELEASE', ownerPrincipal: authenticated.subject,
      idempotencyKey: authenticated.idempotencyKey, creationRequestDigest: request.requestDigest, serviceId: request.serviceId,
      serviceDefinitionDigest: request.serviceDefinitionDigest, triggerSource: request.triggerSource, triggerIdentity: request.triggerIdentity,
      state: 'REQUESTED', desiredState: 'READY_TO_STAGE', sequence: 1, createdAt, updatedAt: createdAt,
      approvalPolicy: request.approvalPolicy, approvalEvidence: [], activeJobIds: [], allJobIds: [], machineIds: [],
      observationPolicy: request.observationPolicy, observationResults: [], cleanup: { required: true, completed: false },
      capacityAdmissionSnapshotId: request.capacityAdmissionSnapshotId, credentialSetDigest: request.credentialSetDigest,
      githubInboxIds: [], githubOutboxIds: [], artifactReferences: [], receiptReferences: [], normalizedRequest: request,
      routeMode: object(request.route, 'route').mode ?? 'DIRECT', groupContract: request.group ?? null, migrationContract: request.migration ?? null,
    });
    return this.options.store.applyMutation({ schemaId: 'DeploymentRecordV1', recordId: deploymentId, ownerPrincipal: authenticated.subject, expectedSequence: 0, idempotencyKey: authenticated.idempotencyKey, requestDigest: request.requestDigest, operation: 'babyx.release.prepare', phase: 'request', record, occurredAt: createdAt });
  }

  private async advancePreparation(recordValue: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext): Promise<JsonObject> {
    let record = recordValue;
    const owner = request.ownerPrincipal;
    try {
      if (record.state === 'REQUESTED') {
        const lease = normalizeLease(request, String(record.deploymentId), this.now());
        const acquired = this.options.store.acquireLease(validateReleaseRecord('ControllerLeaseV1', lease), { existingControllerAbsent: request.controller.existingControllerAbsent === true, now: this.now() });
        record = this.transition(record, 'PREFLIGHTING', owner, 'controller-lease-acquired', `preflight-${sha256(String(record.deploymentId)).slice(0, 40)}`, { controllerLeaseId: acquired.leaseId, controllerLeaseObservationDigest: acquired.observationDigest, desiredState: 'READY_TO_STAGE' });
      }
      if (record.state === 'PREFLIGHTING') record = this.transition(record, 'RESOLVING_SOURCE', owner, 'source-resolution-intent', `source-${sha256(String(record.deploymentId)).slice(0, 40)}`, { pendingEffect: { kind: 'SOURCE_RESOLUTION', intendedAt: this.now() } });
      if (record.state === 'RESOLVING_SOURCE') {
        const source = await this.options.preparation.resolve(request, { ...context, idempotencyKey: `resolve-${sha256(String(record.deploymentId)).slice(0, 40)}` });
        const nextState = request.build.preparedArtifact === undefined ? 'BUILDING' : 'REUSING_ARTIFACT';
        record = this.transition(record, nextState, owner, 'source-resolved', `source-result-${sha256(String(record.deploymentId)).slice(0, 40)}`, { sourceIdentity: source.sourceIdentity, sourceManifest: source.sourceManifest, sourceEpoch: source.sourceEpoch, sourceReceiptReferences: source.receiptReferences, pendingEffect: { kind: nextState === 'BUILDING' ? 'BUILD' : 'ARTIFACT_REUSE', intendedAt: this.now() } });
      }
      if (record.state === 'BUILDING' || record.state === 'REUSING_ARTIFACT') {
        const source: PreparedSource = { sourceIdentity: object(record.sourceIdentity, 'record.sourceIdentity'), sourceManifest: record.sourceManifest as JsonObject | undefined, sourceEpoch: integer(record.sourceEpoch, 'record.sourceEpoch'), receiptReferences: Array.isArray(record.sourceReceiptReferences) ? record.sourceReceiptReferences.map(String) : [] };
        const artifact = await this.options.preparation.buildOrReuse(request, source, { ...context, idempotencyKey: `artifact-${sha256(String(record.deploymentId)).slice(0, 40)}-${record.sequence}` });
        record = this.transition(record, 'CERTIFYING', owner, 'artifact-ready', `artifact-result-${sha256(String(record.deploymentId)).slice(0, 40)}`, { buildId: artifact.buildId, artifact: artifact.artifact, artifactManifest: artifact.manifest, artifactReused: artifact.reused, allJobIds: [...new Set([...(Array.isArray(record.allJobIds) ? record.allJobIds.map(String) : []), ...artifact.jobIds])], activeJobIds: artifact.jobIds.filter((id) => this.options.jobs.get(id).status === 'running'), artifactReceiptReferences: artifact.receiptReferences, pendingEffect: { kind: 'CERTIFICATION', intendedAt: this.now() } }, [{ artifactId: artifact.artifact.id, artifactSha256: artifact.artifact.sha256 }]);
      }
      if (record.state === 'CERTIFYING') {
        const source: PreparedSource = { sourceIdentity: object(record.sourceIdentity, 'record.sourceIdentity'), sourceManifest: record.sourceManifest as JsonObject | undefined, sourceEpoch: integer(record.sourceEpoch, 'record.sourceEpoch'), receiptReferences: Array.isArray(record.sourceReceiptReferences) ? record.sourceReceiptReferences.map(String) : [] };
        const artifact: PreparedArtifact = { artifact: object(record.artifact, 'record.artifact'), manifest: object(record.artifactManifest, 'record.artifactManifest'), buildId: text(record.buildId, 'record.buildId'), jobIds: [], reused: record.artifactReused === true, receiptReferences: Array.isArray(record.artifactReceiptReferences) ? record.artifactReceiptReferences.map(String) : [] };
        const certification = await this.options.preparation.certify(request, source, artifact, { ...context, idempotencyKey: `certify-${sha256(String(record.deploymentId)).slice(0, 40)}` });
        const materialized = await this.options.preparation.materialize(request, source, artifact, certification, { ...context, idempotencyKey: `materialize-${sha256(String(record.deploymentId)).slice(0, 40)}` });
        record = this.transition(record, 'READY_TO_STAGE', owner, 'release-prepared', `prepared-${sha256(String(record.deploymentId)).slice(0, 40)}`, { certificationId: certification.certification.certificationId, certification: certification.certification, releaseId: materialized.release.releaseId, releaseRecord: materialized.release, materialization: materialized.materialization, allJobIds: [...new Set([...(Array.isArray(record.allJobIds) ? record.allJobIds.map(String) : []), ...certification.jobIds, ...materialized.jobIds])], activeJobIds: [], receiptReferences: [...new Set([...(Array.isArray(record.receiptReferences) ? record.receiptReferences.map(String) : []), ...source.receiptReferences, ...artifact.receiptReferences, ...certification.receiptReferences, ...materialized.receiptReferences])], pendingEffect: undefined });
      }
      return record;
    } catch (error) {
      return this.classifyExternalFailure(record, owner, 'preparation', error);
    }
  }

  private async advancePromotion(recordValue: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext): Promise<JsonObject> {
    let record = recordValue;
    const owner = request.ownerPrincipal;
    try {
      if (['REQUESTED','PREFLIGHTING','RESOLVING_SOURCE','REUSING_ARTIFACT','BUILDING','CERTIFYING'].includes(String(record.state))) record = await this.advancePreparation(record, request, context);
      if (record.state === 'READY_TO_STAGE') {
        const selection = this.selectInactiveSlot(request.serviceId, String(record.releaseId), context);
        if (selection.noop === true && request.route.mode === 'DIRECT') return this.finalizeNoop(record, request, context, selection);
        record = this.transition(record, 'STAGING', owner, 'stage-intent', `stage-${sha256(String(record.deploymentId)).slice(0, 40)}-${record.sequence}`, { slotId: selection.inactiveSlot, priorKnownGoodSlotId: selection.activeSlot ?? undefined, priorKnownGoodReleaseId: selection.activeReleaseId ?? undefined, rollbackTarget: selection.activeSlot === undefined ? null : { slotId: selection.activeSlot, releaseId: selection.activeReleaseId }, pendingEffect: { kind: 'SLOT_STAGE', slotId: selection.inactiveSlot, intendedAt: this.now() } });
        const staged = this.options.slots.stage({ serviceDefinition: request.serviceDefinition, slotId: selection.inactiveSlot, release: record.releaseRecord, credentialSetDigest: request.credentialSetDigest, expectedProcessIdentity: object(request.promotion.expectedProcessIdentity, 'promotion.expectedProcessIdentity'), ...(request.promotion.endpointMode === undefined ? {} : { endpointMode: request.promotion.endpointMode }) }, { ...context, idempotencyKey: `slot-stage-${sha256(String(record.deploymentId)).slice(0, 40)}-${record.sequence}` });
        if (staged.state !== 'STAGED') throw new ReleaseCoordinatorError('release_slot_stage_failed', 'inactive slot did not reach STAGED', { state: staged.state });
        record = this.transition(record, 'STARTING_INACTIVE', owner, 'slot-staged', `slot-staged-${sha256(String(record.deploymentId)).slice(0, 40)}-${record.sequence}`, { slotRecord: staged, pendingEffect: { kind: 'SLOT_START', slotId: selection.inactiveSlot, intendedAt: this.now() } });
      }
      if (record.state === 'STARTING_INACTIVE') {
        const slot = object(record.slotRecord, 'record.slotRecord');
        const started = await this.options.slots.start({ serviceId: record.serviceId, slotId: record.slotId, expectedSequence: slot.sequence }, { ...context, idempotencyKey: `slot-start-${sha256(String(record.deploymentId)).slice(0, 40)}-${record.sequence}` });
        record = this.transition(record, 'READINESS_CHECKING', owner, 'slot-start-readback', `slot-started-${sha256(String(record.deploymentId)).slice(0, 40)}-${record.sequence}`, { slotRecord: started, pendingEffect: { kind: 'READINESS', intendedAt: this.now() } });
      }
      if (record.state === 'READINESS_CHECKING') {
        const slot = object(record.slotRecord, 'record.slotRecord');
        if (slot.state !== 'READY_PRIVATE') throw new ReleaseCoordinatorError(slot.state === 'AMBIGUOUS' ? 'release_process_ambiguous' : 'release_readiness_failed', 'candidate slot is not READY_PRIVATE', { slotState: slot.state });
        record = this.transition(record, 'READY_TO_PROMOTE', owner, 'readiness-verified', `ready-${sha256(String(record.deploymentId)).slice(0, 40)}-${record.sequence}`, { privateReadiness: { state: slot.state, processIdentity: slot.observedProcessIdentity, endpointIdentity: slot.endpointIdentity }, pendingEffect: undefined });
      }
      if (record.state === 'READY_TO_PROMOTE') {
        if (record.routeRecord === undefined) record = await this.prepareRouteCandidate(record, request, context);
        const scheduledFuture = request.scheduleAt !== undefined && Date.parse(request.scheduleAt) > Date.parse(this.now());
        if (request.approvalPolicy.mode === 'REQUIRED' || scheduledFuture) return this.transition(record, 'AWAITING_APPROVAL', owner, scheduledFuture ? 'scheduled-promotion-wait' : 'approval-required', `await-${sha256(String(record.deploymentId)).slice(0, 40)}`, { schedule: request.scheduleAt === undefined ? null : { promoteAt: request.scheduleAt, persistedAt: this.now() } });
        record = await this.cutover(record, request, context);
      }
      if (record.state === 'AWAITING_APPROVAL') {
        if (request.scheduleAt !== undefined && Date.parse(request.scheduleAt) > Date.parse(this.now())) return record;
        if (request.approvalPolicy.mode === 'REQUIRED' && (!Array.isArray(record.approvalEvidence) || record.approvalEvidence.length === 0)) return record;
        record = await this.cutover(record, request, context);
      }
      if (record.state === 'OBSERVING') record = await this.observe(record, request, context);
      if (record.state === 'DRAINING_PREVIOUS') record = await this.drainPrevious(record, request, context);
      if (record.state === 'FINALIZING') {
        if (request.route.mode === 'PREVIEW') {
          const expiration = record.expiration === undefined ? undefined : object(record.expiration, 'record.expiration');
          if (expiration?.status !== 'ACTIVE') {
            if (request.expiresAt === undefined) throw new ReleaseCoordinatorError('release_invalid_request', 'PREVIEW deployment is missing its required expiry');
            record = this.transition(record, 'FINALIZING', owner, 'preview-active-awaiting-expiry', `preview-active-${sha256(String(record.deploymentId)).slice(0, 40)}`, {
              desiredState: 'EXPIRED',
              expiration: {
                status: 'ACTIVE',
                activatedAt: this.now(),
                expiresAt: request.expiresAt,
                routeId: record.routeId,
                routeDigest: object(record.routeRecord, 'record.routeRecord').activeConfigReadbackDigest,
                candidateSlotId: record.slotId,
                priorProductionSlotId: record.priorKnownGoodSlotId ?? null,
                priorProductionReleaseId: record.priorKnownGoodReleaseId ?? null,
              },
            });
          }
        } else record = this.finalizeSuccess(record, request, context);
      }
      return record;
    } catch (error) {
      try { record = ownerRecord(this.options.store, String(record.deploymentId), context); } catch {}
      if (record.state === 'CUTTING_OVER' || record.state === 'OBSERVING' || record.state === 'DRAINING_PREVIOUS' || record.state === 'FINALIZING') {
        const requested = this.transition(record, 'ROLLBACK_REQUESTED', owner, 'promotion-failure-rollback', `auto-rollback-${sha256(String(record.deploymentId)).slice(0, 40)}`, { rollbackStatus: { requestedAt: this.now(), reason: error instanceof Error ? error.message : 'promotion failure', automatic: true } });
        return this.executeRollback(requested, request, context);
      }
      return this.classifyExternalFailure(record, owner, 'promotion', error);
    }
  }

  private async prepareRouteCandidate(recordValue: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext): Promise<JsonObject> {
    let record = recordValue;
    const slot = object(record.slotRecord, 'record.slotRecord');
    if (slot.state !== 'READY_PRIVATE' || slot.releaseId !== record.releaseId || object(slot.expectedProcessIdentity, 'slot.expectedProcessIdentity').artifactDigest !== object(record.artifact, 'record.artifact').sha256) throw new ReleaseCoordinatorError('release_candidate_identity_mismatch', 'candidate slot identity is not exactly bound to prepared release');
    const routeLease = normalizeRouteLease(request, this.now(), 'prepare');
    this.options.routes.acquireLease(request.serviceId, routeLease, { ...context, idempotencyKey: `route-prepare-lease-${sha256(String(record.deploymentId)).slice(0, 40)}` });
    try {
      const routeRequest = {
        serviceId: request.serviceId, desiredActiveSlot: record.slotId,
        endpoint: { type: slot.endpointType, value: object(slot.endpointIdentity, 'slot.endpointIdentity').endpoint },
        publicIdentity: request.route.publicIdentity,
        policy: request.route.policy,
        streamSettings: request.route.streamSettings,
        expectedReleaseIdentity: record.releaseId,
      };
      const preparedRoute = await this.options.routes.prepare({ request: routeRequest, lease: routeLease }, { ...context, idempotencyKey: `route-prepare-${sha256(String(record.deploymentId)).slice(0, 40)}` });
      if (preparedRoute.state !== 'VALIDATED') throw new ReleaseCoordinatorError(preparedRoute.state === 'AMBIGUOUS' ? 'release_route_ambiguous' : 'release_route_validation_failed', 'candidate route did not reach VALIDATED', { routeState: preparedRoute.state });
      record = this.transition(record, String(record.state), request.ownerPrincipal, 'route-candidate-validated', `route-candidate-${sha256(String(record.deploymentId)).slice(0, 40)}`, { routeId: preparedRoute.routeId, routeRecord: preparedRoute, candidateRouteDigest: preparedRoute.candidateConfigDigest, priorRouteDigest: preparedRoute.previousConfigDigest, routeLeaseId: routeLease.leaseId }, [{ artifactId: preparedRoute.previousConfigArtifactId, artifactSha256: preparedRoute.previousConfigDigest }, { artifactId: preparedRoute.candidateConfigArtifactId, artifactSha256: preparedRoute.candidateConfigDigest }]);
      return record;
    } finally {
      try { this.options.routes.releaseLease(request.serviceId, routeLease, { ...context, idempotencyKey: `route-prepare-release-${sha256(String(record.deploymentId)).slice(0, 40)}` }); } catch {}
    }
  }

  private async cutover(recordValue: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext): Promise<JsonObject> {
    let record = recordValue;
    const owner = request.ownerPrincipal;
    const slot = object(record.slotRecord, 'record.slotRecord');
    const preparedRoute = object(record.routeRecord, 'record.routeRecord');
    if (preparedRoute.state !== 'VALIDATED' || preparedRoute.candidateConfigDigest !== record.candidateRouteDigest) throw new ReleaseCoordinatorError('release_route_validation_failed', 'cutover requires the exact persisted VALIDATED route candidate');
    if (slot.state !== 'READY_PRIVATE' || slot.releaseId !== record.releaseId || object(slot.expectedProcessIdentity, 'slot.expectedProcessIdentity').artifactDigest !== object(record.artifact, 'record.artifact').sha256) throw new ReleaseCoordinatorError('release_candidate_identity_mismatch', 'candidate slot identity changed before cutover');
    const routeLease = normalizeRouteLease(request, this.now(), 'cutover');
    this.options.routes.acquireLease(request.serviceId, routeLease, { ...context, idempotencyKey: `route-cutover-lease-${sha256(String(record.deploymentId)).slice(0, 40)}` });
    const baseline = this.options.routes.observeActive === undefined ? { status: 'UNKNOWN' } : await this.options.routes.observeActive({ serviceId: request.serviceId, expected: 'PREVIOUS', expectedReleaseIdentity: record.priorKnownGoodReleaseId }, context);
    if (baseline.status !== 'PASS') throw new ReleaseCoordinatorError('release_route_ambiguous', 'current route no longer matches the captured prior configuration', { observationDigest: baseline.detailsDigest ?? null, status: baseline.status });
    record = this.transition(record, 'CUTOVER_PREPARING', owner, 'cutover-prepared', `cutover-prepare-${sha256(String(record.deploymentId)).slice(0, 40)}`, { routeLeaseId: routeLease.leaseId, priorRouteReadback: baseline, pendingEffect: { kind: 'CADDY_LOAD', candidateConfigDigest: preparedRoute.candidateConfigDigest, intendedAt: this.now() } });
    record = this.transition(record, 'CUTTING_OVER', owner, 'cutover-load-intent', `cutover-load-${sha256(String(record.deploymentId)).slice(0, 40)}`, {});
    let activeRoute: JsonObject;
    try {
      activeRoute = await this.options.routes.cutover({ serviceId: request.serviceId, lease: routeLease, expectedSequence: preparedRoute.sequence, publicProbeExpectedReleaseIdentity: record.releaseId }, { ...context, idempotencyKey: `route-cutover-${sha256(String(record.deploymentId)).slice(0, 40)}` });
    } catch (error) {
      activeRoute = await this.options.routes.reconcile({ serviceId: request.serviceId, lease: routeLease }, { ...context, idempotencyKey: `route-cutover-reconcile-${sha256(String(record.deploymentId)).slice(0, 40)}` });
      if (activeRoute.state !== 'ACTIVE_VERIFIED') throw new ReleaseCoordinatorError(activeRoute.state === 'AMBIGUOUS' ? 'release_route_ambiguous' : 'release_cutover_response_lost', 'cutover response was lost and exact active route could not be proven', { routeState: activeRoute.state, causeDigest: sha256(error instanceof Error ? error.message : String(error)) });
    }
    if (activeRoute.state !== 'ACTIVE_VERIFIED') throw new ReleaseCoordinatorError(activeRoute.state === 'AMBIGUOUS' ? 'release_route_ambiguous' : 'release_cutover_failed', 'route cutover was not exactly verified', { routeState: activeRoute.state });
    const slotState = this.convergePostCutoverSlots(record, request, activeRoute, context);
    try { this.options.routes.releaseLease(request.serviceId, routeLease, { ...context, idempotencyKey: `route-cutover-release-${sha256(String(record.deploymentId)).slice(0, 40)}` }); } catch {}
    return this.transition(record, 'OBSERVING', owner, 'cutover-verified', `observing-${sha256(String(record.deploymentId)).slice(0, 40)}`, { routeRecord: activeRoute, ...slotState, observationStartedAt: this.now(), pendingEffect: undefined });
  }

  private async observe(record: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext): Promise<JsonObject> {
    const observation = await this.options.observation.observe(record, request, context);
    const samples = [...(Array.isArray(record.observationResults) ? record.observationResults : []), ...(Array.isArray(observation.samples) ? observation.samples : [observation])].slice(-10_000);
    const evaluation = evaluateReleaseObservation(request.observationPolicy, samples, record.observationState ?? {});
    if (evaluation.decision === 'ROLLBACK') {
      const requested = this.transition(record, 'ROLLBACK_REQUESTED', request.ownerPrincipal, 'observation-rollback-triggered', `observation-rollback-${sha256(String(record.deploymentId)).slice(0, 40)}`, { observationResults: samples, observationState: evaluation, rollbackStatus: { requestedAt: this.now(), reason: evaluation.manualRollback === true ? 'manual-observation-rollback' : 'automatic-observation-threshold', automatic: evaluation.manualRollback !== true } });
      return this.executeRollback(requested, request, context);
    }
    if (evaluation.decision === 'RECOVERY_REQUIRED') return this.recovery(record, request.ownerPrincipal, 'observation-telemetry-unknown', new ReleaseCoordinatorError('release_telemetry_unknown', 'observation telemetry is missing or unknown'), { observationResults: samples, observationState: evaluation });
    if (evaluation.decision === 'CONTINUE') return this.transition(record, 'OBSERVING', request.ownerPrincipal, 'observation-continue', `observe-${sha256(`${record.deploymentId}:${record.sequence}`).slice(0, 48)}`, { observationResults: samples, observationState: evaluation });
    return this.transition(record, 'DRAINING_PREVIOUS', request.ownerPrincipal, 'observation-passed', `observe-pass-${sha256(String(record.deploymentId)).slice(0, 40)}`, { observationResults: samples, observationState: evaluation, observationCompletedAt: this.now() });
  }

  private async drainPrevious(recordValue: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext): Promise<JsonObject> {
    let record = recordValue;
    if (request.route.mode !== 'DIRECT') {
      return this.transition(record, 'FINALIZING', request.ownerPrincipal, 'non-direct-route-retained', `finalizing-${sha256(String(record.deploymentId)).slice(0, 40)}`, {
        drainStatus: { schemaVersion:'1.0.0', classification:'NOT_APPLICABLE', drained:false, routeMode:request.route.mode, priorProductionSlotRetained:true, observations:[], observationCount:0 },
        cleanup: { required:false, completed:true, priorSlotRetained:true, candidateActive:false, candidateRouted:true },
      });
    }
    if (record.priorKnownGoodSlotId === undefined) {
      return this.transition(record, 'FINALIZING', request.ownerPrincipal, 'no-prior-slot-to-drain', `finalizing-no-prior-${sha256(String(record.deploymentId)).slice(0, 32)}`, {
        drainStatus: { schemaVersion:'1.0.0', classification:'NOT_APPLICABLE', drained:false, reason:'NO_PRIOR_SLOT', observations:[], observationCount:0 },
        cleanup: { required:false, completed:true, priorSlotRetained:false, candidateActive:true },
      });
    }

    const existingDrain = record.drainStatus === undefined ? undefined : object(record.drainStatus, 'record.drainStatus');
    if (existingDrain?.target === undefined || existingDrain.startedAt === undefined || existingDrain.deadline === undefined || existingDrain.policyDigest === undefined) {
      const prior = this.options.slots.getSlot({ serviceId:request.serviceId, slotId:record.priorKnownGoodSlotId }, context).slot as JsonObject;
      const route = object(record.routeRecord, 'record.routeRecord');
      const observedProcessIdentity = object(prior.observedProcessIdentity, 'priorSlot.observedProcessIdentity');
      const startedAt = this.now();
      const target: JsonObject = {
        serviceId:request.serviceId,
        slotId:identifier(record.priorKnownGoodSlotId, 'record.priorKnownGoodSlotId'),
        releaseId:identifier(record.priorKnownGoodReleaseId ?? prior.releaseId, 'record.priorKnownGoodReleaseId'),
        unitIdentity:text(prior.systemdUnit, 'priorSlot.systemdUnit', 256),
        processIdentityDigest:sha256(canonicalize(observedProcessIdentity)),
        routeGeneration:sha256(canonicalize({
          routeId:route.routeId,
          sequence:route.sequence,
          activeConfigReadbackDigest:route.activeConfigReadbackDigest ?? null,
          observedActiveUpstream:route.observedActiveUpstream ?? null,
        })),
      };
      const intent: JsonObject = {
        schemaVersion:'1.0.0',
        classification:'DRAINING',
        drained:false,
        startedAt,
        deadline:new Date(Date.parse(startedAt) + request.drainPolicy.timeoutMs).toISOString(),
        nextObservationAt:startedAt,
        policyDigest:sha256(canonicalize(request.drainPolicy)),
        target,
        observations:[],
        observationCount:0,
        providerConfigured:true,
      };
      record = this.transition(record, 'DRAINING_PREVIOUS', request.ownerPrincipal, 'drain-intent-persisted', `drain-intent-${sha256(String(record.deploymentId)).slice(0, 40)}`, { drainStatus:intent });
    }

    const drain = await this.options.drain.drain(record, request, context);
    const classification = String(drain.classification ?? 'UNKNOWN');
    if (classification === 'DRAINING') {
      if (canonicalize(drain) === canonicalize(record.drainStatus)) return record;
      return this.transition(record, 'DRAINING_PREVIOUS', request.ownerPrincipal, 'drain-observation-persisted', `drain-observe-${sha256(`${record.deploymentId}:${drain.observationCount ?? 0}`).slice(0, 40)}`, { drainStatus:drain });
    }
    if (classification !== 'DRAINED' || drain.drained !== true || !Array.isArray(drain.observations) || drain.observations.length === 0) {
      const timeout = classification === 'TIMED_OUT' || classification === 'FORCED_TERMINATION_REQUIRED';
      return this.recovery(record, request.ownerPrincipal, 'drain-obstructed', new ReleaseCoordinatorError(timeout ? 'release_drain_timeout' : 'release_drain_failed', 'previous slot drain did not produce positively observed quiescence', { classification }), { drainStatus:drain }, timeout ? 'release_drain_timeout' : 'release_drain_failed');
    }
    const prior = this.options.slots.getSlot({ serviceId:request.serviceId, slotId:record.priorKnownGoodSlotId }, context).slot as JsonObject;
    if (prior.state === 'DRAINING') {
      const stopped = await this.options.slots.stop({ serviceId:request.serviceId, slotId:record.priorKnownGoodSlotId, expectedSequence:prior.sequence }, { ...context, idempotencyKey: `prior-stop-${sha256(String(record.deploymentId)).slice(0, 40)}` });
      if (stopped.state !== 'STOPPED') return this.recovery(record, request.ownerPrincipal, 'prior-stop-unverified', new ReleaseCoordinatorError('release_cleanup_failed', 'prior slot stop was not positively verified'), { drainStatus:drain });
    }
    return this.transition(record, 'FINALIZING', request.ownerPrincipal, 'drain-complete', `finalizing-${sha256(String(record.deploymentId)).slice(0, 40)}`, { drainStatus:drain, cleanup: { required:true, completed:true, priorSlotRetained:true, candidateActive:true } });
  }

  private finalizeSuccess(record: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext): JsonObject {
    const active = activeJobs(this.options.jobs, record.allJobIds);
    if (active.length > 0) return this.recovery(record, request.ownerPrincipal, 'active-related-jobs', new ReleaseCoordinatorError('release_active_jobs', 'active related jobs block terminal success', { jobIds: active.map((job) => job.id) }));
    const successEvidence = this.successEvidence(record, this.options.reporter?.reportingSatisfied(record) ?? true);
    try { assertDeploymentSuccess(successEvidence); } catch (error) { return this.recovery(record, request.ownerPrincipal, 'success-evidence-incomplete', error); }
    const evidence = {
      schemaVersion: '1.0.0', deploymentId: record.deploymentId, serviceId: record.serviceId, state: 'SUCCEEDED',
      sourceIdentity: record.sourceIdentity, artifact: record.artifact, artifactManifest: record.artifactManifest, certification: record.certification,
      releaseRecord: record.releaseRecord, slotRecord: record.slotRecord, routeRecord: record.routeRecord, observationState: record.observationState,
      drainStatus: record.drainStatus, cleanup: record.cleanup, successEvidence, eventTailDigest: this.eventTailDigest(record), createdAt: this.now(),
    };
    const artifact = storeArtifact(this.options.artifacts, `${record.deploymentId}-evidence.json`, evidence);
    const proof = this.options.proofs.create(String(record.deploymentId), 'babyx.release.promote', true, String(record.createdAt), evidence);
    if (proof.error !== undefined) return this.recovery(record, request.ownerPrincipal, 'proof-unavailable', new ReleaseCoordinatorError('release_evidence_incomplete', 'proof authority did not produce a proof'));
    const terminalCandidate = { ...record, evidenceIndexId: artifact.id, evidenceIndexDigest: artifact.sha256, finalProof: proof, successEvidence, eventTailDigest: this.eventTailDigest(record), artifactReferences: [...(Array.isArray(record.artifactReferences) ? record.artifactReferences : []), { artifactId: artifact.id, artifactSha256: artifact.sha256 }], receiptReferences: [...new Set([...(Array.isArray(record.receiptReferences) ? record.receiptReferences.map(String) : []), String(proof.requestId ?? record.deploymentId)])] };
    try { assertTerminalDeploymentSafety('SUCCEEDED', { cleanupComplete: true, activeRelatedJobs: 0, unresolvedAmbiguity: false, evidenceComplete: true }, successEvidence); } catch (error) { return this.recovery(record, request.ownerPrincipal, 'terminal-guard', error); }
    return this.transition(terminalCandidate, 'SUCCEEDED', request.ownerPrincipal, 'success-terminalized', `success-${sha256(String(record.deploymentId)).slice(0, 40)}`, { desiredState: 'SUCCEEDED', completedAt: this.now() }, [{ artifactId: artifact.id, artifactSha256: artifact.sha256 }], [String(proof.requestId ?? record.deploymentId)]);
  }

  private finalizeNoop(record: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext, selection: JsonObject): JsonObject {
    let next = this.transition(record, 'STAGING', request.ownerPrincipal, 'noop-detected', `noop-stage-${sha256(String(record.deploymentId)).slice(0, 40)}`, { slotId: selection.activeSlot, priorKnownGoodSlotId: selection.activeSlot, priorKnownGoodReleaseId: selection.activeReleaseId, noopPromotion: true });
    next = this.transition(next, 'STARTING_INACTIVE', request.ownerPrincipal, 'noop-stage-skipped', `noop-start-${sha256(String(record.deploymentId)).slice(0, 40)}`, {});
    next = this.transition(next, 'READINESS_CHECKING', request.ownerPrincipal, 'noop-start-skipped', `noop-readycheck-${sha256(String(record.deploymentId)).slice(0, 40)}`, {});
    next = this.transition(next, 'READY_TO_PROMOTE', request.ownerPrincipal, 'noop-live-identity-verified', `noop-ready-${sha256(String(record.deploymentId)).slice(0, 40)}`, { observedLiveReleaseId: record.releaseId });
    next = this.transition(next, 'CUTOVER_PREPARING', request.ownerPrincipal, 'noop-cutover-skipped', `noop-cutoverprep-${sha256(String(record.deploymentId)).slice(0, 40)}`, {});
    next = this.transition(next, 'CUTTING_OVER', request.ownerPrincipal, 'noop-route-unchanged', `noop-cutover-${sha256(String(record.deploymentId)).slice(0, 40)}`, {});
    next = this.transition(next, 'OBSERVING', request.ownerPrincipal, 'noop-observation', `noop-observe-${sha256(String(record.deploymentId)).slice(0, 40)}`, { observationResults: [{ observedAt: this.now(), signals: { readiness: true, publicProbe: true }, errorRate: 0, latencyMs: 0, processRestarts: 0 }] });
    next = this.transition(next, 'DRAINING_PREVIOUS', request.ownerPrincipal, 'noop-drain-skipped', `noop-drain-${sha256(String(record.deploymentId)).slice(0, 40)}`, { drainStatus: { status: 'NOT_APPLICABLE' } });
    next = this.transition(next, 'FINALIZING', request.ownerPrincipal, 'noop-finalizing', `noop-final-${sha256(String(record.deploymentId)).slice(0, 40)}`, { cleanup: { required: false, completed: true, noop: true }, routeRecord: selection.routeRecord, slotRecord: selection.activeSlotRecord, certification: record.certification });
    return this.finalizeSuccess(next, request, context);
  }

  private async executeRollback(recordValue: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext): Promise<JsonObject> {
    let record = recordValue;
    const beforeCutover = PRE_CUTOVER.has(String(record.state)) || (record.state === 'ROLLBACK_REQUESTED' && record.routeRecord === undefined);
    if (record.state !== 'ROLLING_BACK') record = this.transition(record, 'ROLLING_BACK', request.ownerPrincipal, 'rollback-intent', `rollback-${sha256(String(record.deploymentId)).slice(0, 40)}`, { pendingEffect: { kind: beforeCutover ? 'CANDIDATE_CLEANUP' : 'ROUTE_RESTORE', intendedAt: this.now() } });
    try {
      if (!beforeCutover && record.routeRecord !== undefined) {
        const routeLease = normalizeRouteLease(request, this.now(), 'rollback');
        this.options.routes.acquireLease(request.serviceId, routeLease, { ...context, idempotencyKey: `route-rollback-lease-${sha256(String(record.deploymentId)).slice(0, 40)}` });
        const route = await this.options.routes.restore({ serviceId: request.serviceId, lease: routeLease, expectedSequence: object(record.routeRecord, 'record.routeRecord').sequence, publicProbeExpectedReleaseIdentity: record.priorKnownGoodReleaseId }, { ...context, idempotencyKey: `route-restore-${sha256(String(record.deploymentId)).slice(0, 40)}` });
        if (route.state !== 'RESTORED_VERIFIED') throw new ReleaseCoordinatorError(route.state === 'AMBIGUOUS' ? 'release_route_ambiguous' : 'release_restore_failed', 'prior route restoration was not verified', { routeState: route.state });
        record = this.transition(record, 'OBSERVING', request.ownerPrincipal, 'rollback-route-restored', `rollback-observe-${sha256(String(record.deploymentId)).slice(0, 40)}`, { routeRecord: route, routeRestored: true, observedLiveReleaseId: record.priorKnownGoodReleaseId, rollbackObservation: { status: 'PASS', observedAt: this.now() } });
        if (record.slotId !== undefined) {
          const candidate = this.options.slots.getSlot({ serviceId: request.serviceId, slotId: record.slotId }, context).slot as JsonObject;
          if (candidate.state === 'ACTIVE') this.options.slots.markDraining({ serviceId: request.serviceId, slotId: record.slotId, routeReadbackVerified: true }, { ...context, idempotencyKey: `rollback-candidate-drain-${sha256(String(record.deploymentId)).slice(0, 40)}` });
        }
        if (record.priorKnownGoodSlotId !== undefined && this.options.slots.restoreActive !== undefined) {
          const prior = this.options.slots.getSlot({ serviceId: request.serviceId, slotId: record.priorKnownGoodSlotId }, context).slot as JsonObject;
          if (prior.state === 'DRAINING' || prior.state === 'STOPPED') this.options.slots.restoreActive({ serviceId: request.serviceId, slotId: record.priorKnownGoodSlotId, expectedSequence: prior.sequence, routeReadbackVerified: true, routeDigest: route.restorationReadbackDigest }, { ...context, idempotencyKey: `slot-restore-${sha256(String(record.deploymentId)).slice(0, 40)}` });
        }
        try { this.options.routes.releaseLease(request.serviceId, routeLease, { ...context, idempotencyKey: `route-rollback-release-${sha256(String(record.deploymentId)).slice(0, 40)}` }); } catch {}
        record = this.transition(record, 'CLEANUP_PENDING', request.ownerPrincipal, 'rollback-observation-passed', `rollback-cleanup-${sha256(String(record.deploymentId)).slice(0, 40)}`, { pendingEffect: { kind: 'FAILED_CANDIDATE_CLEANUP', intendedAt: this.now() } });
      } else if (record.state === 'ROLLING_BACK') {
        record = this.transition(record, 'CLEANUP_PENDING', request.ownerPrincipal, 'precutover-route-unchanged', `rollback-precutover-${sha256(String(record.deploymentId)).slice(0, 40)}`, { routeRestored: true, rollbackObservation: { status: 'NOT_APPLICABLE', routeUnchanged: true } });
      }
      return this.cleanupCandidate(record, request, context, 'ROLLED_BACK');
    } catch (error) {
      return this.classifyExternalFailure(record, request.ownerPrincipal, 'rollback', error);
    }
  }

  private async cleanupCandidate(recordValue: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext, terminalState: 'ROLLED_BACK' | 'CANCELLED' | 'EXPIRED' | 'FAILED'): Promise<JsonObject> {
    let record = recordValue;
    if (record.state !== 'CLEANING') record = this.transition(record, 'CLEANING', request.ownerPrincipal, 'cleanup-intent', `cleanup-${sha256(`${record.deploymentId}:${terminalState}`).slice(0, 48)}`, { terminalIntent: terminalState });
    if (record.slotId !== undefined) {
      let slot = this.options.slots.getSlot({ serviceId: request.serviceId, slotId: record.slotId }, context).slot as JsonObject;
      if (slot.state === 'ACTIVE') throw new ReleaseCoordinatorError('release_cleanup_active_slot', 'candidate cleanup is forbidden while the slot remains active');
      if (['READY_PRIVATE','RUNNING_NOT_READY','STARTING','DRAINING','FAILED'].includes(String(slot.state))) slot = await this.options.slots.stop({ serviceId: request.serviceId, slotId: record.slotId, expectedSequence: slot.sequence }, { ...context, idempotencyKey: `cleanup-stop-${sha256(String(record.deploymentId)).slice(0, 40)}` });
      if (['STOPPED','STAGED','FAILED'].includes(String(slot.state))) slot = await this.options.slots.cleanup({ serviceId: request.serviceId, slotId: record.slotId, expectedSequence: slot.sequence, protectedRollbackTarget: false }, { ...context, idempotencyKey: `cleanup-slot-${sha256(String(record.deploymentId)).slice(0, 40)}` });
      if (slot.state !== 'EMPTY_VERIFIED') return this.recovery(record, request.ownerPrincipal, 'cleanup-absence-unproven', new ReleaseCoordinatorError('release_cleanup_failed', 'candidate slot cleanup did not prove positive absence'), { cleanup: { required: true, completed: false, slotState: slot.state } });
      record = this.transition(record, 'CLEANING', request.ownerPrincipal, 'cleanup-slot-absent', `cleanup-absent-${sha256(String(record.deploymentId)).slice(0, 40)}`, { slotRecord: slot, cleanup: { required: true, completed: true, positiveAbsence: true, completedAt: this.now() } });
    } else record = this.transition(record, 'CLEANING', request.ownerPrincipal, 'cleanup-not-applicable', `cleanup-na-${sha256(String(record.deploymentId)).slice(0, 40)}`, { cleanup: { required: false, completed: true, positiveAbsence: true, completedAt: this.now() } });
    const active = activeJobs(this.options.jobs, record.allJobIds);
    if (active.length > 0) return this.recovery(record, request.ownerPrincipal, 'cleanup-active-jobs', new ReleaseCoordinatorError('release_active_jobs', 'active related jobs block terminal cleanup', { jobIds: active.map((job) => job.id) }));
    const evidence = { schemaVersion: '1.0.0', deploymentId: record.deploymentId, terminalState, routeRestored: record.routeRestored === true, cleanup: record.cleanup, failedCandidateEvidence: { sourceIdentity: record.sourceIdentity, artifact: record.artifact, certification: record.certification, slotRecord: record.slotRecord, routeRecord: record.routeRecord }, eventTailDigest: this.eventTailDigest(record), createdAt: this.now() };
    const artifact = storeArtifact(this.options.artifacts, `${record.deploymentId}-${terminalState.toLowerCase()}-evidence.json`, evidence);
    const proof = this.options.proofs.create(String(record.deploymentId), `babyx.release.${terminalState.toLowerCase()}`, terminalState !== 'FAILED', String(record.createdAt), evidence);
    if (proof.error !== undefined) return this.recovery(record, request.ownerPrincipal, 'cleanup-proof-unavailable', new ReleaseCoordinatorError('release_evidence_incomplete', 'terminal cleanup evidence proof is unavailable'));
    try { assertTerminalDeploymentSafety(terminalState, { cleanupComplete: true, activeRelatedJobs: 0, unresolvedAmbiguity: false, evidenceComplete: true, routeRestored: terminalState === 'ROLLED_BACK' ? record.routeRestored === true : undefined, cancellationComplete: terminalState === 'CANCELLED' ? true : undefined, expirationPolicyComplete: terminalState === 'EXPIRED' ? true : undefined }); } catch (error) { return this.recovery(record, request.ownerPrincipal, 'terminal-guard', error); }
    return this.transition(record, terminalState, request.ownerPrincipal, 'terminal-cleanup-verified', `terminal-${sha256(`${record.deploymentId}:${terminalState}`).slice(0, 48)}`, { desiredState: terminalState, completedAt: this.now(), evidenceIndexId: artifact.id, evidenceIndexDigest: artifact.sha256, finalProof: proof, eventTailDigest: this.eventTailDigest(record), artifactReferences: [...(Array.isArray(record.artifactReferences) ? record.artifactReferences : []), { artifactId: artifact.id, artifactSha256: artifact.sha256 }] }, [{ artifactId: artifact.id, artifactSha256: artifact.sha256 }], [String(proof.requestId ?? record.deploymentId)]);
  }

  private async reconcileOne(record: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext): Promise<JsonObject> {
    if (TERMINAL.has(String(record.state)) || record.state === 'AMBIGUOUS') return record;
    if (['REQUESTED','PREFLIGHTING','RESOLVING_SOURCE','REUSING_ARTIFACT','BUILDING','CERTIFYING'].includes(String(record.state))) return this.advancePreparation(record, request, context);
    if (['READY_TO_STAGE','STAGING','STARTING_INACTIVE','READINESS_CHECKING','READY_TO_PROMOTE','AWAITING_APPROVAL','OBSERVING','DRAINING_PREVIOUS','FINALIZING'].includes(String(record.state))) return this.advancePromotion(record, request, context);
    if (record.state === 'CUTOVER_PREPARING' || record.state === 'CUTTING_OVER') {
      try {
        const routeLease = normalizeRouteLease(request, this.now(), 'reconcile');
        this.options.routes.acquireLease(request.serviceId, routeLease, { ...context, idempotencyKey: `route-reconcile-lease-${sha256(String(record.deploymentId)).slice(0, 40)}` });
        const route = await this.options.routes.reconcile({ serviceId: request.serviceId, lease: routeLease }, { ...context, idempotencyKey: `route-reconcile-${sha256(String(record.deploymentId)).slice(0, 40)}` });
        try { this.options.routes.releaseLease(request.serviceId, routeLease, { ...context, idempotencyKey: `route-reconcile-release-${sha256(String(record.deploymentId)).slice(0, 40)}` }); } catch {}
        if (route.state === 'ACTIVE_VERIFIED') {
          const slotState = this.convergePostCutoverSlots(record, request, route, context);
          return this.transition(record, 'OBSERVING', request.ownerPrincipal, 'cutover-reconciled', `cutover-reconciled-${sha256(String(record.deploymentId)).slice(0, 40)}`, { routeRecord: route, ...slotState, observationStartedAt: record.observationStartedAt ?? this.now(), pendingEffect: undefined });
        }
        if (route.state === 'AMBIGUOUS') return this.ambiguous(record, request.ownerPrincipal, 'cutover-reconcile-ambiguous', new ReleaseCoordinatorError('release_route_ambiguous', 'route reconciliation is ambiguous'));
        return this.recovery(record, request.ownerPrincipal, 'cutover-reconcile-pending', new ReleaseCoordinatorError('release_recovery_required', 'route cutover requires continued recovery'));
      } catch (error) { return this.classifyExternalFailure(record, request.ownerPrincipal, 'cutover-reconcile', error); }
    }
    if (record.state === 'ROLLBACK_REQUESTED' || record.state === 'ROLLING_BACK') return this.executeRollback(record, request, context);
    if (record.state === 'CLEANUP_PENDING' || record.state === 'CLEANING') return this.cleanupCandidate(record, request, context, (record.terminalIntent as 'ROLLED_BACK' | 'CANCELLED' | 'EXPIRED' | 'FAILED') ?? 'FAILED');
    return record;
  }

  private convergePostCutoverSlots(record: JsonObject, request: NormalizedDeploymentRequest, activeRoute: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const candidate = this.options.slots.getSlot({ serviceId: request.serviceId, slotId: record.slotId }, context).slot as JsonObject;
    if (request.route.mode !== 'DIRECT') {
      if (!['READY_PRIVATE', 'ACTIVE'].includes(String(candidate.state))) throw new ReleaseCoordinatorError('release_process_ambiguous', 'non-direct routed candidate is not in a provable ready state', { slotState: candidate.state, routeMode: request.route.mode });
      if (candidate.state === 'ACTIVE' && record.priorKnownGoodSlotId !== undefined) throw new ReleaseCoordinatorError('release_process_ambiguous', 'non-direct route cannot claim the candidate as the sole active slot while a prior production slot exists', { slotState: candidate.state, routeMode: request.route.mode });
      return {
        slotRecord: candidate,
        observedLiveReleaseId: record.priorKnownGoodReleaseId ?? record.releaseId,
      };
    }
    if (record.priorKnownGoodSlotId !== undefined) {
      const previous = this.options.slots.getSlot({ serviceId: request.serviceId, slotId: record.priorKnownGoodSlotId }, context).slot as JsonObject;
      if (previous.state === 'ACTIVE') this.options.slots.markDraining({ serviceId: request.serviceId, slotId: record.priorKnownGoodSlotId, routeReadbackVerified: true }, { ...context, idempotencyKey: `slot-drain-${sha256(String(record.deploymentId)).slice(0, 40)}` });
    }
    const activeSlot = candidate.state === 'ACTIVE' ? candidate : this.options.slots.activate({ serviceId: request.serviceId, slotId: record.slotId, expectedSequence: candidate.sequence, routeReadbackVerified: true, routeDigest: activeRoute.activeConfigReadbackDigest }, { ...context, idempotencyKey: `slot-activate-${sha256(String(record.deploymentId)).slice(0, 40)}` });
    return { slotRecord: activeSlot, observedLiveReleaseId: record.releaseId };
  }

  private selectInactiveSlot(serviceId: string, desiredReleaseId: string, context: RuntimeExecutionContext): JsonObject {
    const slots: Record<string, JsonObject | undefined> = {};
    for (const slotId of ['blue', 'green']) {
      try { slots[slotId] = this.options.slots.getSlot({ serviceId, slotId }, context).slot as JsonObject; } catch { slots[slotId] = undefined; }
    }
    const activeEntry = Object.entries(slots).find(([, record]) => record?.state === 'ACTIVE');
    const activeSlot = activeEntry?.[0];
    const activeSlotRecord = activeEntry?.[1];
    const activeReleaseId = activeSlotRecord?.releaseId;
    let routeRecord: JsonObject | undefined;
    try { routeRecord = this.options.routes.getRoute({ serviceId }, context).route as JsonObject; } catch { routeRecord = undefined; }
    if (activeReleaseId !== undefined && desiredReleaseId !== undefined && activeReleaseId === desiredReleaseId && routeRecord?.state === 'ACTIVE_VERIFIED') return { noop: true, activeSlot, activeReleaseId, activeSlotRecord, routeRecord };
    const inactiveSlot = activeSlot === 'blue' ? 'green' : activeSlot === 'green' ? 'blue' : slots.blue === undefined || ['EMPTY','EMPTY_VERIFIED'].includes(String(slots.blue?.state)) ? 'blue' : 'green';
    const inactive = slots[inactiveSlot];
    if (inactive !== undefined && !['EMPTY','EMPTY_VERIFIED'].includes(String(inactive.state))) throw new ReleaseCoordinatorError('release_no_inactive_slot', 'inactive slot is not positively empty', { slotId: inactiveSlot, state: inactive.state });
    return { noop: false, inactiveSlot, activeSlot, activeReleaseId, activeSlotRecord, routeRecord };
  }

  private successEvidence(record: JsonObject, githubReportingDeliveredOrQueued = true): DeploymentSuccessEvidence {
    return {
      exactSourceResolved: object(record.sourceIdentity, 'record.sourceIdentity').commit !== undefined && object(record.sourceIdentity, 'record.sourceIdentity').tree !== undefined,
      artifactManifestVerified: object(record.artifactManifest, 'record.artifactManifest').manifestDigest !== undefined,
      certificationValid: object(record.certification, 'record.certification').state === 'SUCCEEDED',
      inactiveSlotStagedFromImmutableBytes: object(record.releaseRecord, 'record.releaseRecord').immutablePermissionsVerified === true,
      unitAndProcessIdentityVerified: object(record.slotRecord, 'record.slotRecord').observedProcessIdentity !== undefined,
      privateEndpointReady: object(record.slotRecord, 'record.slotRecord').state === 'ACTIVE' || object(record.slotRecord, 'record.slotRecord').state === 'READY_PRIVATE',
      candidateCaddyConfigValidated: record.noopPromotion === true || object(record.routeRecord, 'record.routeRecord').validationResult !== undefined,
      activeRouteReadbackMatches: record.noopPromotion === true || object(record.routeRecord, 'record.routeRecord').state === 'ACTIVE_VERIFIED',
      publicRouteSmokePassed: record.noopPromotion === true || object(object(record.routeRecord, 'record.routeRecord').publicProbeResult, 'publicProbeResult').status === 'PASS',
      observationPolicyPassed: record.noopPromotion === true || object(record.observationState, 'record.observationState').decision === 'PASS',
      allRelatedJobsTerminal: activeJobs(this.options.jobs, record.allJobIds).length === 0,
      previousSlotHandledTruthfully: record.drainStatus !== undefined || record.priorKnownGoodSlotId === undefined,
      evidenceIndexCompleteAndVerified: true,
      githubReportingDeliveredOrQueued,
      noUnresolvedAmbiguity: record.ambiguity === undefined,
    };
  }

  private liveProjection(record: JsonObject): JsonObject {
    const source = record.sourceIdentity === undefined ? {} : object(record.sourceIdentity, 'record.sourceIdentity');
    const artifact = record.artifact === undefined ? {} : object(record.artifact, 'record.artifact');
    const certification = record.certification === undefined ? {} : object(record.certification, 'record.certification');
    const slot = record.slotRecord === undefined ? {} : object(record.slotRecord, 'record.slotRecord');
    const route = record.routeRecord === undefined ? {} : object(record.routeRecord, 'record.routeRecord');
    return {
      service: record.serviceId,
      desiredRelease: record.releaseId ?? null,
      observedLiveRelease: record.observedLiveReleaseId ?? null,
      sourceCommit: source.commit ?? null,
      sourceTree: source.tree ?? null,
      artifactDigest: artifact.sha256 ?? null,
      certificationIdentity: certification.certificationId ?? null,
      activeSlot: slot.state === 'ACTIVE' ? slot.slotId : record.priorKnownGoodSlotId ?? null,
      unit: slot.systemdUnit ?? null,
      processIdentity: slot.observedProcessIdentity ?? null,
      endpoint: slot.endpointIdentity ?? null,
      routeConfigDigest: route.activeConfigReadbackDigest ?? route.restorationReadbackDigest ?? null,
      caddyUpstream: route.observedActiveUpstream ?? null,
      health: slot.readinessObservations ?? null,
      readiness: slot.state ?? null,
      observation: record.observationState ?? null,
      rollbackTarget: record.rollbackTarget ?? null,
      recovery: record.state === 'RECOVERY_REQUIRED' ? record.error ?? true : null,
      ambiguity: record.state === 'AMBIGUOUS' ? record.ambiguity ?? true : null,
      evidenceIdentity: record.evidenceIndexDigest ?? null,
    };
  }

  private listRecords(context: RuntimeExecutionContext): JsonObject[] {
    return this.options.store.listRecordIdentities(10_000).filter((identity) => identity.schemaId === 'DeploymentRecordV1').map((identity) => this.options.store.getRecord(identity.schemaId, identity.recordId)).filter((record) => context.authorityClass === 'unrestricted-owner' || record.ownerPrincipal === context.subject).sort((left, right) => String(left.deploymentId).localeCompare(String(right.deploymentId)));
  }

  private eventTailDigest(record: JsonObject): string {
    const events = this.options.store.events('DeploymentRecordV1', String(record.deploymentId), 0, RELEASE_EVENT_LIMIT);
    const tail = events.at(-1);
    return typeof tail?.eventDigest === 'string' ? tail.eventDigest : sha256(canonicalize(events));
  }

  private assertSequence(record: JsonObject, expected: unknown): void {
    if (Number(record.sequence) !== integer(expected, 'expectedSequence')) throw new ReleaseCoordinatorError('release_stale_sequence', 'expected sequence does not match deployment record');
  }

  private transition(record: JsonObject, state: string, ownerPrincipal: string, phase: string, idempotencyKey: string, patch: JsonObject, artifactReferences: JsonObject[] = [], receiptReferences: string[] = []): JsonObject {
    const prior = String(record.state);
    if (prior !== state) assertReleaseTransition('deployment', prior, state);
    const sequence = integer(record.sequence, 'record.sequence');
    const occurredAt = this.now();
    const draft: JsonObject = { ...record };
    for (const [key, value] of Object.entries(patch)) { if (value === undefined) delete draft[key]; else draft[key] = value; }
    const candidate = validateReleaseRecord('DeploymentRecordV1', { ...draft, state, sequence: sequence + 1, updatedAt: occurredAt, ...(TERMINAL.has(state) ? { completedAt: occurredAt } : {}) });
    const normalizedKey = IDENTIFIER.test(idempotencyKey) && idempotencyKey.length <= 128 ? idempotencyKey : `transition-${sha256(idempotencyKey).slice(0, 64)}`;
    const persisted = this.options.store.applyMutation({ schemaId: 'DeploymentRecordV1', recordId: String(record.deploymentId), ownerPrincipal, expectedSequence: sequence, idempotencyKey: normalizedKey, requestDigest: sha256(canonicalize({ deploymentId: record.deploymentId, prior, state, phase, patch })), operation: 'babyx.release.coordinate', phase: identifier(phase, 'phase'), record: candidate, occurredAt, childJobIds: Array.isArray(candidate.allJobIds) ? candidate.allJobIds as string[] : [], observationDigest: patch.observationState === undefined ? undefined : sha256(canonicalize(patch.observationState)), artifactReferences, receiptReferences });
    if (this.options.reporter !== undefined) {
      try { this.options.reporter.queueDeploymentProjection(persisted, { subject: ownerPrincipal, authorityClass: 'owner', idempotencyKey: `github-report-${sha256(`${record.deploymentId}:${sequence + 1}`).slice(0, 40)}` }); } catch {}
    }
    return persisted;
  }

  private structuredError(error: unknown, fallbackCode: string, retryable: boolean, phase: string, productionImpact: 'NONE' | 'CANDIDATE_ONLY' | 'ROLLED_BACK' | 'ACTIVE_DEGRADED' | 'UNKNOWN'): JsonObject {
    const originalCode = error !== null && typeof error === 'object' && 'code' in error ? String((error as { code?: unknown }).code ?? '') : '';
    const persistedCode = PERSISTED_RELEASE_FAILURE_CODES.has(originalCode) ? originalCode : fallbackCode;
    const bounded = boundedReleaseError(error, persistedCode, retryable, phase);
    const allowedCodes = new Set([
      'release_invalid_request','release_unknown_version','release_schema_invalid','release_record_corrupt','release_record_quarantined',
      'release_idempotency_conflict','release_stale_sequence','release_wrong_principal','release_illegal_transition','release_controller_conflict',
      'release_lease_ambiguous','release_source_mismatch','release_artifact_invalid','release_certification_failed','release_process_ambiguous',
      'release_endpoint_ambiguous','release_route_ambiguous','release_cleanup_failed','release_evidence_incomplete','release_child_job_failed',
      'release_active_jobs','release_capacity_rejected','release_credential_unavailable','release_github_delivery_pending','release_recovery_required',
    ]);
    const code = allowedCodes.has(bounded.code) ? bounded.code : fallbackCode;
    let message = bounded.message;
    try { assertNoRawSecrets({ message }); } catch { message = 'sensitive error details were redacted'; }
    return { code, message, retryable: bounded.retryable, phase: bounded.phase, productionImpact, detailsDigest: sha256(canonicalize({ originalCode: bounded.code, messageDigest: sha256(bounded.message), details: bounded.details ?? {} })) };
  }

  private classifyExternalFailure(record: JsonObject, owner: string, phase: string, error: unknown): JsonObject {
    const code = error instanceof Error && 'code' in error ? String((error as { code?: unknown }).code ?? '') : '';
    if (code.includes('ambiguous') || code.includes('identity_conflict')) return this.ambiguous(record, owner, phase, error);
    return this.recovery(record, owner, phase, error, {}, this.failureCodeFor(record, phase));
  }

  private failureCodeFor(record: JsonObject, phase: string): string {
    const state = String(record.state);
    if (phase === 'preparation') {
      if (state === 'PREFLIGHTING' || state === 'RESOLVING_SOURCE') return 'release_source_unresolved';
      if (state === 'REUSING_ARTIFACT') return 'release_artifact_invalid';
      if (state === 'BUILDING') return 'release_build_failed';
      if (state === 'CERTIFYING') return 'release_certification_failed';
    }
    if (state === 'READY_TO_STAGE' || state === 'STAGING') return 'release_stage_failed';
    if (state === 'STARTING_INACTIVE') return 'release_start_failed';
    if (state === 'READINESS_CHECKING') return 'release_readiness_failed';
    if (state === 'READY_TO_PROMOTE' || state === 'AWAITING_APPROVAL') return 'release_route_validation_failed';
    if (state === 'CUTOVER_PREPARING' || state === 'CUTTING_OVER') return 'release_cutover_failed';
    if (state === 'OBSERVING') return 'release_observation_failed';
    if (state === 'ROLLBACK_REQUESTED' || state === 'ROLLING_BACK') return 'release_rollback_failed';
    if (state === 'DRAINING_PREVIOUS') return 'release_drain_timeout';
    if (state === 'CLEANUP_PENDING' || state === 'CLEANING') return 'release_cleanup_failed';
    if (state === 'FINALIZING') return 'release_evidence_incomplete';
    return 'release_recovery_required';
  }

  private recovery(record: JsonObject, owner: string, phase: string, error: unknown, patch: JsonObject = {}, fallbackCode = 'release_recovery_required'): JsonObject {
    const structured = this.structuredError(error, fallbackCode, true, phase, ['CUTTING_OVER','OBSERVING','DRAINING_PREVIOUS','FINALIZING'].includes(String(record.state)) ? 'UNKNOWN' : 'CANDIDATE_ONLY');
    return this.transition(record, 'RECOVERY_REQUIRED', owner, phase, `recovery-${sha256(`${record.deploymentId}:${record.sequence}:${phase}`).slice(0, 48)}`, { ...patch, error: structured, recoveryFromState: record.state });
  }

  private ambiguous(record: JsonObject, owner: string, phase: string, error: unknown): JsonObject {
    const structured = this.structuredError(error, 'release_route_ambiguous', false, phase, 'UNKNOWN');
    return this.transition(record, 'AMBIGUOUS', owner, phase, `ambiguous-${sha256(`${record.deploymentId}:${record.sequence}:${phase}`).slice(0, 48)}`, { error: structured, ambiguity: { code: structured.code, detailsDigest: structured.detailsDigest, phase }, recoveryFromState: record.state });
  }
}

export class RouteSlotObservationAuthority implements ReleaseObservationAuthority {
  readonly authority = 'release-observation' as const;
  constructor(private readonly routes: ReleaseCoordinatorOptions['routes'], private readonly slots: ReleaseCoordinatorOptions['slots'], private readonly now: () => string = () => new Date().toISOString()) {}
  async observe(record: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext): Promise<JsonObject> {
    const slot = this.slots.getSlot({ serviceId: request.serviceId, slotId: record.slotId }, context).slot as JsonObject;
    let routeProbe: JsonObject = { status: 'UNKNOWN' };
    if (this.routes.observeActive !== undefined) routeProbe = await this.routes.observeActive({ serviceId: request.serviceId, expectedReleaseIdentity: record.releaseId }, context);
    return {
      observedAt: this.now(),
      signals: { readiness: slot.state === 'ACTIVE' || slot.state === 'READY_PRIVATE', publicProbe: routeProbe.status === 'PASS', watchdog: object(slot.observedProcessIdentity ?? {}, 'processIdentity').watchdogState !== 'UNKNOWN' },
      errorRate: routeProbe.errorRate ?? 0,
      latencyMs: routeProbe.latencyMs ?? 0,
      processRestarts: routeProbe.processRestarts ?? 0,
      unknown: routeProbe.status === 'UNKNOWN',
    };
  }
}

export interface BoundedDrainAuthorityOptions {
  provider?: ReleaseDrainObservationProvider;
  now?: () => string;
}

export class BoundedDrainAuthority implements ReleaseDrainAuthority {
  readonly authority = 'release-drain' as const;
  private readonly provider?: ReleaseDrainObservationProvider;
  private readonly now: () => string;
  constructor(options: BoundedDrainAuthorityOptions | (() => string) = {}) {
    const normalized = typeof options === 'function' ? { now:options } : options;
    this.provider = normalized.provider;
    this.now = normalized.now ?? (() => new Date().toISOString());
  }
  async drain(record: JsonObject, request: NormalizedDeploymentRequest, context: RuntimeExecutionContext): Promise<JsonObject> {
    const policy = request.drainPolicy;
    if (record.priorKnownGoodSlotId === undefined) return { schemaVersion:'1.0.0', classification:'NOT_APPLICABLE', drained:false, reason:'NO_PRIOR_SLOT', observations:[], observationCount:0 };
    const intent = object(record.drainStatus, 'record.drainStatus');
    const target = object(intent.target, 'record.drainStatus.target');
    const startedAt = timestamp(intent.startedAt, 'record.drainStatus.startedAt');
    const deadline = timestamp(intent.deadline, 'record.drainStatus.deadline');
    const policyDigest = digest(intent.policyDigest, 'record.drainStatus.policyDigest');
    if (policyDigest !== sha256(canonicalize(policy))) throw new ReleaseCoordinatorError('release_identity_mismatch', 'durable drain policy digest changed');
    const observations = Array.isArray(intent.observations) ? intent.observations.map((entry, index) => object(entry, `record.drainStatus.observations[${index}]`)).slice(-256) : [];
    const observationCount = intent.observationCount === undefined ? observations.length : integer(intent.observationCount, 'record.drainStatus.observationCount', observations.length, Number.MAX_SAFE_INTEGER);
    const currentTime = this.now();
    const currentTimeMs = Date.parse(currentTime);
    const deadlineMs = Date.parse(deadline);
    const terminalTimeout = (): JsonObject => ({
      ...intent,
      classification:policy.forceTerminationAfterDeadline ? 'FORCED_TERMINATION_REQUIRED' : 'TIMED_OUT',
      drained:false,
      completedAt:currentTime,
      observations,
      observationCount,
      providerConfigured:this.provider !== undefined,
    });
    if (currentTimeMs >= deadlineMs || observationCount >= policy.maximumSamples) return terminalTimeout();
    if (this.provider === undefined) return { ...intent, classification:'UNSUPPORTED', drained:false, completedAt:currentTime, observations, observationCount, providerConfigured:false };
    if (intent.nextObservationAt !== undefined && currentTimeMs < Date.parse(timestamp(intent.nextObservationAt, 'record.drainStatus.nextObservationAt'))) return { ...intent, observations, observationCount, providerConfigured:true };

    let observation: JsonObject;
    try { observation = normalizeDrainObservation(await this.provider.observe(target, policy, context), observationCount + 1); }
    catch (error) {
      return {
        ...intent,
        classification:'PROVIDER_FAILED',
        drained:false,
        completedAt:this.now(),
        observations,
        observationCount,
        providerConfigured:true,
        error:{
          code:'release_provider_failed',
          message:'drain observation provider failed',
          retryable:true,
          phase:'drain-observe',
          productionImpact:'UNKNOWN',
          detailsDigest:sha256(error instanceof Error ? error.message : String(error)),
        },
      };
    }
    const nextObservations = [...observations, observation].slice(-256);
    const nextCount = observationCount + 1;
    const base: JsonObject = {
      ...intent,
      observations:nextObservations,
      observationCount:nextCount,
      finalObservationDigest:observation.observationDigest,
      providerConfigured:true,
    };
    if (
      observation.serviceId !== target.serviceId || observation.slotId !== target.slotId || observation.releaseId !== target.releaseId
      || observation.unitIdentity !== target.unitIdentity || observation.processIdentityDigest !== target.processIdentityDigest
      || observation.routeGeneration !== target.routeGeneration
    ) return { ...base, classification:'IDENTITY_MISMATCH', drained:false, completedAt:this.now() };
    if (observation.providerStatus === 'UNAVAILABLE' || observation.providerStatus === 'FAILED') return { ...base, classification:'PROVIDER_FAILED', drained:false, completedAt:this.now() };
    if (observation.providerStatus === 'UNKNOWN') return { ...base, classification:'UNKNOWN', drained:false, completedAt:this.now() };
    const work = drainWorkState(observation, policy);
    if (observation.applicationStatus === 'FAILED') return { ...base, classification:'PROVIDER_FAILED', drained:false, completedAt:this.now(), remainingWork:work.details };
    if (observation.applicationStatus === 'UNKNOWN') return { ...base, classification:'UNKNOWN', drained:false, completedAt:this.now(), remainingWork:work.details };
    if (work.known && work.remaining === 0 && (observation.applicationStatus === undefined || observation.applicationStatus === 'DRAINED')) {
      return { ...base, classification:'DRAINED', drained:true, completedAt:this.now(), remainingWork:work.details };
    }
    const observedAtMs = Date.parse(this.now());
    if (observedAtMs >= deadlineMs || nextCount >= policy.maximumSamples) {
      return { ...base, classification:policy.forceTerminationAfterDeadline ? 'FORCED_TERMINATION_REQUIRED' : 'TIMED_OUT', drained:false, completedAt:this.now(), remainingWork:work.details };
    }
    return {
      ...base,
      classification:'DRAINING',
      drained:false,
      nextObservationAt:new Date(observedAtMs + policy.intervalMs).toISOString(),
      remainingWork:work.details,
    };
  }
}
