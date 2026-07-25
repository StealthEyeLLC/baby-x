import { isAbsolute, normalize } from 'node:path';
import { canonicalize, sha256, type ProcessIdentity } from '../core.ts';
import { MachineServiceError } from './errors.ts';

export const MACHINE_SCHEMA_VERSION = '1.0.0' as const;
export const MACHINE_PROVIDER_ID = 'zfs-nspawn-disposable@1' as const;

export const MACHINE_STATES = [
  'REQUESTED',
  'CLONING',
  'CLONED',
  'STARTING',
  'READY',
  'EXECUTING',
  'STOPPING',
  'STOPPED',
  'EXPIRED',
  'DESTROYING',
  'DESTROYED',
  'DEGRADED',
  'FAILED',
  'LOST',
  'RECOVERY_REQUIRED',
  'AMBIGUOUS',
  'UNKNOWN',
] as const;

export type MachineState = typeof MACHINE_STATES[number];
export type MachineDesiredState = 'CLONED' | 'READY' | 'STOPPED' | 'DESTROYED';
export type MachineObservedState = 'NOT_OBSERVED' | 'CLONE_ONLY' | 'RUNNING' | 'STOPPED_INTACT' | 'PARTIALLY_REMOVED' | 'ABSENT' | 'CONFLICT' | 'UNKNOWN';

export interface MachineBindV1 {
  source: string;
  destination: string;
  mode: 'ro' | 'rw';
  recursive: boolean;
  sourceIdentity?: { device?: number; inode?: number; sha256?: string };
}

export interface MachineEnvironmentV1 {
  name: string;
  value?: string;
  secretReference?: string;
  redacted: boolean;
}

export interface MachinePropertyV1 {
  name: string;
  value: string;
}

export interface MachineResourceProfileV1 {
  memoryMaxBytes?: number;
  memoryHighBytes?: number;
  cpuQuotaPercent?: number;
  tasksMax?: number;
  nofileSoft?: number;
  nofileHard?: number;
  runtimeDeadlineMs?: number;
  diskQuotaBytes?: number;
  outputLimitBytes?: number;
  artifactLimitBytes?: number;
}

export interface MachineObservationSetV1 {
  dataset: 'present-matching' | 'present-conflict' | 'absent' | 'unknown';
  snapshot: 'present-matching' | 'present-conflict' | 'absent' | 'unknown';
  mountpoint: 'present-matching' | 'present-conflict' | 'absent' | 'unknown';
  machinectl: 'running-matching' | 'stopped-matching' | 'present-conflict' | 'absent' | 'unknown';
  process: 'running-matching' | 'stopped' | 'stale-pid' | 'present-conflict' | 'absent' | 'unknown';
  rootPath: 'present-matching' | 'present-conflict' | 'absent' | 'unknown';
  observedAt?: string;
  observationDigest?: string;
}

export interface MachineCleanupV1 {
  requested: boolean;
  requestedAt?: string;
  stopAttempted: boolean;
  stopVerified: boolean;
  datasetDestroyAttempted: boolean;
  datasetAbsentVerified: boolean;
  rootAbsentVerified: boolean;
  machineAbsentVerified: boolean;
  processAbsentVerified: boolean;
  completed: boolean;
  completedAt?: string;
  retainedEvidence: string[];
}

export interface MachineFailureV1 {
  code: string;
  message: string;
  phase: string;
  retryable: boolean;
  destructiveRecoveryAllowed: boolean;
  commandExitCode?: number;
  signal?: string;
  observationDigest?: string;
  artifactReferences: string[];
  occurredAt: string;
}

export interface MachineRecoveryV1 {
  classification: string;
  recommendedAction: string;
  automaticActionAllowed: boolean;
  observedAt: string;
  evidenceReferences: string[];
}

export interface DisposableMachineRecordV1 {
  schemaVersion: typeof MACHINE_SCHEMA_VERSION;
  machineId: string;
  machineName: string;
  providerId: typeof MACHINE_PROVIDER_ID;
  ownerPrincipal: string;
  authorityReference?: string;
  parentObjectiveId?: string;
  parentCertificationId?: string;
  parentCandidateId?: string;
  creationIdempotencyKey: string;
  creationRequestDigest: string;
  source: {
    kind: 'zfs-snapshot';
    snapshot: string;
    dataset: string;
    snapshotGuid?: string;
    creationTxg?: string;
    observedAt: string;
  };
  clone: {
    dataset: string;
    datasetGuid?: string;
    mountpoint: string;
    expectedRootPrefix: string;
    ownershipMarker: string;
  };
  launch: {
    boot: boolean;
    command?: string[];
    networkMode: 'none' | 'private' | 'host' | 'custom';
    readOnlyRoot: boolean;
    binds: MachineBindV1[];
    environment: MachineEnvironmentV1[];
    properties: MachinePropertyV1[];
    resourceProfile?: MachineResourceProfileV1;
    normalizedDigest: string;
  };
  lifecycle: {
    desiredState: MachineDesiredState;
    persistedState: MachineState;
    observedState: MachineObservedState;
    stateSequence: number;
    terminal: boolean;
    createdAt: string;
    updatedAt: string;
    expiresAt?: string;
    destroyedAt?: string;
  };
  host: {
    hostname: string;
    machineIdSha256: string;
    bootIdAtCreate: string;
    lastObservedBootId?: string;
  };
  processIdentity?: ProcessIdentity & { processStartTime: string; executablePath: string; bootId: string; cgroupPath?: string; systemdUnit?: string };
  observations: MachineObservationSetV1;
  activeJobIds: string[];
  protectedJobIds: string[];
  artifactIds: string[];
  proofReferences: string[];
  lastError?: MachineFailureV1;
  recovery?: MachineRecoveryV1;
  cleanup: MachineCleanupV1;
}

export interface MachineEventV1 {
  schemaVersion: typeof MACHINE_SCHEMA_VERSION;
  machineId: string;
  offset: number;
  stateSequence: number;
  priorState?: MachineState;
  nextState: MachineState;
  desiredState: MachineDesiredState;
  operation: string;
  phase: string;
  kind: string;
  message: string;
  requestDigest?: string;
  idempotencyKey?: string;
  controllerLeaseId?: string;
  jobId?: string;
  artifactId?: string;
  proofReference?: string;
  observationDigest?: string;
  previousEventDigest?: string;
  occurredAt: string;
  eventDigest: string;
}

export type MachineEventDraft = Omit<MachineEventV1, 'eventDigest'>;

export interface MachineControllerLeaseV1 {
  schemaVersion: typeof MACHINE_SCHEMA_VERSION;
  leaseId: string;
  machineId: string;
  operation: string;
  ownerPrincipal: string;
  requestDigest: string;
  acquiredAt: string;
  expiresAt: string;
  hostBootId: string;
  controllerProcessIdentity?: ProcessIdentity;
}

export interface MachineTombstoneV1 {
  schemaVersion: typeof MACHINE_SCHEMA_VERSION;
  machineId: string;
  machineName: string;
  ownerPrincipal: string;
  sourceSnapshot: string;
  cloneDataset: string;
  creationRequestDigest: string;
  destroyedAt: string;
  finalEventDigest: string;
  cleanupEvidenceReferences: string[];
}

const MACHINE_ID = /^mx_[a-z0-9][a-z0-9_-]{7,124}$/u;
const MACHINE_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/u;
const ZFS_NAME = /^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const PROPERTY_NAME = /^[A-Za-z][A-Za-z0-9]*$/u;
const STATE_SET = new Set<string>(MACHINE_STATES);
const DESIRED_STATE_SET = new Set<string>(['CLONED', 'READY', 'STOPPED', 'DESTROYED']);
const OBSERVED_STATE_SET = new Set<string>(['NOT_OBSERVED', 'CLONE_ONLY', 'RUNNING', 'STOPPED_INTACT', 'PARTIALLY_REMOVED', 'ABSENT', 'CONFLICT', 'UNKNOWN']);

function invalid(message: string, details: Readonly<Record<string, unknown>> = {}): never {
  throw new MachineServiceError('machine_invalid_request', message, details);
}

function object(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid(`${field} must be an object`);
  return value as Record<string, unknown>;
}

function string(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) invalid(`${field} must be a non-empty NUL-free string`);
  return value;
}

function optionalString(value: unknown, field: string): string | undefined {
  return value === undefined ? undefined : string(value, field);
}

function bool(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') invalid(`${field} must be a boolean`);
  return value;
}

function integer(value: unknown, field: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum) invalid(`${field} must be a safe integer >= ${minimum}`);
  return Number(value);
}

function finitePositive(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) invalid(`${field} must be a finite positive number`);
  return value;
}

function isoTimestamp(value: unknown, field: string): string {
  const candidate = string(value, field);
  if (!Number.isFinite(Date.parse(candidate))) invalid(`${field} must be an ISO timestamp`);
  return candidate;
}

function shaDigest(value: unknown, field: string): string {
  const candidate = string(value, field);
  if (!SHA256.test(candidate)) invalid(`${field} must be a lowercase SHA-256 digest`);
  return candidate;
}

function stringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) invalid(`${field} must be an array`);
  return value.map((entry, index) => string(entry, `${field}[${index}]`));
}

function absolutePath(value: unknown, field: string, allowRoot = false): string {
  const candidate = string(value, field);
  if (!isAbsolute(candidate) || normalize(candidate) !== candidate || (!allowRoot && candidate === '/')) invalid(`${field} must be a normalized absolute path`);
  return candidate;
}

function zfsName(value: unknown, field: string): string {
  const candidate = string(value, field);
  if (!ZFS_NAME.test(candidate) || candidate.startsWith('-') || candidate.includes('..')) invalid(`${field} must be a safe ZFS identifier`);
  return candidate;
}

function machineState(value: unknown, field: string): MachineState {
  const candidate = string(value, field);
  if (!STATE_SET.has(candidate)) invalid(`${field} is not a supported machine state`);
  return candidate as MachineState;
}

function desiredState(value: unknown, field: string): MachineDesiredState {
  const candidate = string(value, field);
  if (!DESIRED_STATE_SET.has(candidate)) invalid(`${field} is not a supported desired state`);
  return candidate as MachineDesiredState;
}

function observedState(value: unknown, field: string): MachineObservedState {
  const candidate = string(value, field);
  if (!OBSERVED_STATE_SET.has(candidate)) invalid(`${field} is not a supported observed state`);
  return candidate as MachineObservedState;
}

function validateSchemaVersion(value: unknown, field: string): void {
  const candidate = string(value, field);
  const major = candidate.split('.')[0];
  if (major !== '1') invalid(`${field} has an unsupported major version`, { schemaVersion: candidate });
  if (candidate !== MACHINE_SCHEMA_VERSION) invalid(`${field} is not a supported schema version`, { schemaVersion: candidate });
}

function validateResourceProfile(value: unknown, field: string): void {
  const profile = object(value, field);
  for (const key of ['memoryMaxBytes', 'memoryHighBytes', 'tasksMax', 'nofileSoft', 'nofileHard', 'runtimeDeadlineMs', 'diskQuotaBytes', 'outputLimitBytes', 'artifactLimitBytes']) {
    if (profile[key] !== undefined) integer(profile[key], `${field}.${key}`, 1);
  }
  if (profile.cpuQuotaPercent !== undefined) finitePositive(profile.cpuQuotaPercent, `${field}.cpuQuotaPercent`);
}

function validateObservations(value: unknown, field: string): void {
  const observations = object(value, field);
  const values: Record<string, readonly string[]> = {
    dataset: ['present-matching', 'present-conflict', 'absent', 'unknown'],
    snapshot: ['present-matching', 'present-conflict', 'absent', 'unknown'],
    mountpoint: ['present-matching', 'present-conflict', 'absent', 'unknown'],
    machinectl: ['running-matching', 'stopped-matching', 'present-conflict', 'absent', 'unknown'],
    process: ['running-matching', 'stopped', 'stale-pid', 'present-conflict', 'absent', 'unknown'],
    rootPath: ['present-matching', 'present-conflict', 'absent', 'unknown'],
  };
  for (const [key, allowed] of Object.entries(values)) {
    const candidate = string(observations[key], `${field}.${key}`);
    if (!allowed.includes(candidate)) invalid(`${field}.${key} is invalid`);
  }
  if (observations.observedAt !== undefined) isoTimestamp(observations.observedAt, `${field}.observedAt`);
  if (observations.observationDigest !== undefined) shaDigest(observations.observationDigest, `${field}.observationDigest`);
}

function validateCleanup(value: unknown, field: string): void {
  const cleanup = object(value, field);
  for (const key of ['requested', 'stopAttempted', 'stopVerified', 'datasetDestroyAttempted', 'datasetAbsentVerified', 'rootAbsentVerified', 'machineAbsentVerified', 'processAbsentVerified', 'completed']) bool(cleanup[key], `${field}.${key}`);
  if (cleanup.requestedAt !== undefined) isoTimestamp(cleanup.requestedAt, `${field}.requestedAt`);
  if (cleanup.completedAt !== undefined) isoTimestamp(cleanup.completedAt, `${field}.completedAt`);
  stringArray(cleanup.retainedEvidence, `${field}.retainedEvidence`);
  if (cleanup.completed === true && !(cleanup.datasetAbsentVerified === true && cleanup.rootAbsentVerified === true && cleanup.machineAbsentVerified === true && cleanup.processAbsentVerified === true)) invalid(`${field}.completed requires all absence verification flags`);
}

function validateProcessIdentity(value: unknown, field: string): void {
  const identity = object(value, field);
  integer(identity.pid, `${field}.pid`, 1);
  string(identity.processStartTime, `${field}.processStartTime`);
  absolutePath(identity.executablePath, `${field}.executablePath`);
  string(identity.bootId, `${field}.bootId`);
  if (identity.pgid !== undefined) integer(identity.pgid, `${field}.pgid`, 1);
  optionalString(identity.cgroupPath, `${field}.cgroupPath`);
  optionalString(identity.systemdUnit, `${field}.systemdUnit`);
}

function validateFailure(value: unknown, field: string): void {
  const failure = object(value, field);
  string(failure.code, `${field}.code`);
  string(failure.message, `${field}.message`);
  string(failure.phase, `${field}.phase`);
  bool(failure.retryable, `${field}.retryable`);
  bool(failure.destructiveRecoveryAllowed, `${field}.destructiveRecoveryAllowed`);
  if (failure.commandExitCode !== undefined) integer(failure.commandExitCode, `${field}.commandExitCode`, 0);
  optionalString(failure.signal, `${field}.signal`);
  if (failure.observationDigest !== undefined) shaDigest(failure.observationDigest, `${field}.observationDigest`);
  stringArray(failure.artifactReferences, `${field}.artifactReferences`);
  isoTimestamp(failure.occurredAt, `${field}.occurredAt`);
}

function validateRecovery(value: unknown, field: string): void {
  const recovery = object(value, field);
  string(recovery.classification, `${field}.classification`);
  string(recovery.recommendedAction, `${field}.recommendedAction`);
  bool(recovery.automaticActionAllowed, `${field}.automaticActionAllowed`);
  isoTimestamp(recovery.observedAt, `${field}.observedAt`);
  stringArray(recovery.evidenceReferences, `${field}.evidenceReferences`);
}

export function assertDisposableMachineRecord(value: unknown): DisposableMachineRecordV1 {
  const record = object(value, 'machine record');
  validateSchemaVersion(record.schemaVersion, 'schemaVersion');
  const machineId = string(record.machineId, 'machineId');
  if (!MACHINE_ID.test(machineId)) invalid('machineId must be a service-generated mx_ identifier');
  const machineName = string(record.machineName, 'machineName');
  if (!MACHINE_NAME.test(machineName) || machineName.startsWith('-')) invalid('machineName is invalid');
  if (record.providerId !== MACHINE_PROVIDER_ID) invalid('providerId is unsupported');
  string(record.ownerPrincipal, 'ownerPrincipal');
  optionalString(record.authorityReference, 'authorityReference');
  optionalString(record.parentObjectiveId, 'parentObjectiveId');
  optionalString(record.parentCertificationId, 'parentCertificationId');
  optionalString(record.parentCandidateId, 'parentCandidateId');
  string(record.creationIdempotencyKey, 'creationIdempotencyKey');
  shaDigest(record.creationRequestDigest, 'creationRequestDigest');

  const source = object(record.source, 'source');
  if (source.kind !== 'zfs-snapshot') invalid('source.kind must be zfs-snapshot');
  const snapshot = zfsName(source.snapshot, 'source.snapshot');
  const snapshotSeparator = snapshot.indexOf('@');
  if (snapshotSeparator <= 0 || snapshotSeparator !== snapshot.lastIndexOf('@') || snapshotSeparator === snapshot.length - 1) invalid('source.snapshot must contain exactly one non-empty snapshot separator');
  const sourceDataset = zfsName(source.dataset, 'source.dataset');
  if (snapshot.slice(0, snapshot.indexOf('@')) !== sourceDataset) invalid('source.dataset must exactly match the dataset portion of source.snapshot');
  optionalString(source.snapshotGuid, 'source.snapshotGuid');
  optionalString(source.creationTxg, 'source.creationTxg');
  isoTimestamp(source.observedAt, 'source.observedAt');

  const clone = object(record.clone, 'clone');
  const cloneDataset = zfsName(clone.dataset, 'clone.dataset');
  if (cloneDataset.includes('@')) invalid('clone.dataset must identify a dataset, not a snapshot');
  if (cloneDataset === sourceDataset) invalid('clone.dataset must be distinct from source.dataset');
  optionalString(clone.datasetGuid, 'clone.datasetGuid');
  const mountpoint = absolutePath(clone.mountpoint, 'clone.mountpoint');
  const expectedRootPrefix = absolutePath(clone.expectedRootPrefix, 'clone.expectedRootPrefix');
  if (!mountpoint.startsWith(`${expectedRootPrefix}/`)) invalid('clone.mountpoint must be strictly confined beneath clone.expectedRootPrefix');
  string(clone.ownershipMarker, 'clone.ownershipMarker');

  const launch = object(record.launch, 'launch');
  bool(launch.boot, 'launch.boot');
  if (launch.command !== undefined) stringArray(launch.command, 'launch.command');
  const networkMode = string(launch.networkMode, 'launch.networkMode');
  if (!['none', 'private', 'host', 'custom'].includes(networkMode)) invalid('launch.networkMode is invalid');
  bool(launch.readOnlyRoot, 'launch.readOnlyRoot');
  if (!Array.isArray(launch.binds)) invalid('launch.binds must be an array');
  for (const [index, entry] of launch.binds.entries()) {
    const bind = object(entry, `launch.binds[${index}]`);
    absolutePath(bind.source, `launch.binds[${index}].source`);
    absolutePath(bind.destination, `launch.binds[${index}].destination`);
    if (!['ro', 'rw'].includes(string(bind.mode, `launch.binds[${index}].mode`))) invalid(`launch.binds[${index}].mode is invalid`);
    bool(bind.recursive, `launch.binds[${index}].recursive`);
    if (bind.sourceIdentity !== undefined) {
      const identity = object(bind.sourceIdentity, `launch.binds[${index}].sourceIdentity`);
      if (identity.device !== undefined) integer(identity.device, `launch.binds[${index}].sourceIdentity.device`);
      if (identity.inode !== undefined) integer(identity.inode, `launch.binds[${index}].sourceIdentity.inode`);
      if (identity.sha256 !== undefined) shaDigest(identity.sha256, `launch.binds[${index}].sourceIdentity.sha256`);
    }
  }
  if (!Array.isArray(launch.environment)) invalid('launch.environment must be an array');
  for (const [index, entry] of launch.environment.entries()) {
    const environment = object(entry, `launch.environment[${index}]`);
    const name = string(environment.name, `launch.environment[${index}].name`);
    if (!ENVIRONMENT_NAME.test(name)) invalid(`launch.environment[${index}].name is invalid`);
    const valueEntry = optionalString(environment.value, `launch.environment[${index}].value`);
    const secretReference = optionalString(environment.secretReference, `launch.environment[${index}].secretReference`);
    if ((valueEntry === undefined) === (secretReference === undefined)) invalid(`launch.environment[${index}] must contain exactly one of value or secretReference`);
    bool(environment.redacted, `launch.environment[${index}].redacted`);
    if (secretReference !== undefined && environment.redacted !== true) invalid(`launch.environment[${index}] secret references must be redacted`);
  }
  if (!Array.isArray(launch.properties)) invalid('launch.properties must be an array');
  for (const [index, entry] of launch.properties.entries()) {
    const property = object(entry, `launch.properties[${index}]`);
    const name = string(property.name, `launch.properties[${index}].name`);
    if (!PROPERTY_NAME.test(name)) invalid(`launch.properties[${index}].name is invalid`);
    string(property.value, `launch.properties[${index}].value`);
  }
  if (launch.resourceProfile !== undefined) validateResourceProfile(launch.resourceProfile, 'launch.resourceProfile');
  shaDigest(launch.normalizedDigest, 'launch.normalizedDigest');

  const lifecycle = object(record.lifecycle, 'lifecycle');
  desiredState(lifecycle.desiredState, 'lifecycle.desiredState');
  const persistedState = machineState(lifecycle.persistedState, 'lifecycle.persistedState');
  observedState(lifecycle.observedState, 'lifecycle.observedState');
  integer(lifecycle.stateSequence, 'lifecycle.stateSequence', 1);
  const terminal = bool(lifecycle.terminal, 'lifecycle.terminal');
  if (terminal !== (persistedState === 'DESTROYED')) invalid('lifecycle.terminal must be true only for DESTROYED');
  isoTimestamp(lifecycle.createdAt, 'lifecycle.createdAt');
  isoTimestamp(lifecycle.updatedAt, 'lifecycle.updatedAt');
  if (lifecycle.expiresAt !== undefined) isoTimestamp(lifecycle.expiresAt, 'lifecycle.expiresAt');
  if (lifecycle.destroyedAt !== undefined) isoTimestamp(lifecycle.destroyedAt, 'lifecycle.destroyedAt');
  if (persistedState === 'DESTROYED' && lifecycle.destroyedAt === undefined) invalid('DESTROYED records require lifecycle.destroyedAt');

  const host = object(record.host, 'host');
  string(host.hostname, 'host.hostname');
  shaDigest(host.machineIdSha256, 'host.machineIdSha256');
  string(host.bootIdAtCreate, 'host.bootIdAtCreate');
  optionalString(host.lastObservedBootId, 'host.lastObservedBootId');
  if (record.processIdentity !== undefined) validateProcessIdentity(record.processIdentity, 'processIdentity');
  validateObservations(record.observations, 'observations');
  stringArray(record.activeJobIds, 'activeJobIds');
  stringArray(record.protectedJobIds, 'protectedJobIds');
  stringArray(record.artifactIds, 'artifactIds');
  stringArray(record.proofReferences, 'proofReferences');
  if (record.lastError !== undefined) validateFailure(record.lastError, 'lastError');
  if (record.recovery !== undefined) validateRecovery(record.recovery, 'recovery');
  const cleanup = object(record.cleanup, 'cleanup');
  validateCleanup(cleanup, 'cleanup');
  if (persistedState === 'DESTROYED' && (cleanup.completed !== true || lifecycle.observedState !== 'ABSENT')) invalid('DESTROYED records require completed cleanup, positive absence verification, and observed ABSENT state');
  return record as unknown as DisposableMachineRecordV1;
}

function eventContent(event: MachineEventV1 | MachineEventDraft): Record<string, unknown> {
  const content = { ...event } as Record<string, unknown>;
  delete content.eventDigest;
  return content;
}

function validateEventShape(value: unknown, verifyDigest: boolean): MachineEventV1 {
  const event = object(value, 'machine event');
  validateSchemaVersion(event.schemaVersion, 'schemaVersion');
  const machineId = string(event.machineId, 'machineId');
  if (!MACHINE_ID.test(machineId)) invalid('event machineId is invalid');
  integer(event.offset, 'offset');
  integer(event.stateSequence, 'stateSequence', 1);
  if (event.priorState !== undefined) machineState(event.priorState, 'priorState');
  machineState(event.nextState, 'nextState');
  desiredState(event.desiredState, 'desiredState');
  string(event.operation, 'operation');
  string(event.phase, 'phase');
  string(event.kind, 'kind');
  string(event.message, 'message');
  for (const field of ['requestDigest', 'observationDigest', 'previousEventDigest']) if (event[field] !== undefined) shaDigest(event[field], field);
  for (const field of ['idempotencyKey', 'controllerLeaseId', 'jobId', 'artifactId', 'proofReference']) optionalString(event[field], field);
  isoTimestamp(event.occurredAt, 'occurredAt');
  const digest = shaDigest(event.eventDigest, 'eventDigest');
  if (verifyDigest && digest !== sha256(canonicalize(eventContent(event as unknown as MachineEventV1)))) throw new MachineServiceError('machine_event_corrupt', 'machine event digest mismatch', { machineId, offset: event.offset });
  return event as unknown as MachineEventV1;
}

export function createMachineEvent(draft: MachineEventDraft): MachineEventV1 {
  const provisional = { ...draft, eventDigest: '0'.repeat(64) };
  validateEventShape(provisional, false);
  const event = { ...draft, eventDigest: sha256(canonicalize(eventContent(draft))) };
  return validateEventShape(event, true);
}

export function assertMachineEvent(value: unknown): MachineEventV1 {
  return validateEventShape(value, true);
}

export function assertMachineControllerLease(value: unknown): MachineControllerLeaseV1 {
  const lease = object(value, 'controller lease');
  validateSchemaVersion(lease.schemaVersion, 'schemaVersion');
  string(lease.leaseId, 'leaseId');
  const machineId = string(lease.machineId, 'machineId');
  if (!MACHINE_ID.test(machineId)) invalid('lease machineId is invalid');
  string(lease.operation, 'operation');
  string(lease.ownerPrincipal, 'ownerPrincipal');
  shaDigest(lease.requestDigest, 'requestDigest');
  const acquiredAt = isoTimestamp(lease.acquiredAt, 'acquiredAt');
  const expiresAt = isoTimestamp(lease.expiresAt, 'expiresAt');
  if (Date.parse(expiresAt) <= Date.parse(acquiredAt)) invalid('lease expiresAt must be after acquiredAt');
  string(lease.hostBootId, 'hostBootId');
  if (lease.controllerProcessIdentity !== undefined) {
    const identity = object(lease.controllerProcessIdentity, 'controllerProcessIdentity');
    integer(identity.pid, 'controllerProcessIdentity.pid', 1);
    if (identity.processStartTime !== undefined) string(identity.processStartTime, 'controllerProcessIdentity.processStartTime');
    if (identity.executablePath !== undefined) absolutePath(identity.executablePath, 'controllerProcessIdentity.executablePath');
    if (identity.pgid !== undefined) integer(identity.pgid, 'controllerProcessIdentity.pgid', 1);
    if (identity.bootId !== undefined) string(identity.bootId, 'controllerProcessIdentity.bootId');
  }
  return lease as unknown as MachineControllerLeaseV1;
}

export function assertMachineTombstone(value: unknown): MachineTombstoneV1 {
  const tombstone = object(value, 'machine tombstone');
  validateSchemaVersion(tombstone.schemaVersion, 'schemaVersion');
  const machineId = string(tombstone.machineId, 'machineId');
  if (!MACHINE_ID.test(machineId)) invalid('tombstone machineId is invalid');
  const machineName = string(tombstone.machineName, 'machineName');
  if (!MACHINE_NAME.test(machineName)) invalid('tombstone machineName is invalid');
  string(tombstone.ownerPrincipal, 'ownerPrincipal');
  zfsName(tombstone.sourceSnapshot, 'sourceSnapshot');
  zfsName(tombstone.cloneDataset, 'cloneDataset');
  shaDigest(tombstone.creationRequestDigest, 'creationRequestDigest');
  isoTimestamp(tombstone.destroyedAt, 'destroyedAt');
  shaDigest(tombstone.finalEventDigest, 'finalEventDigest');
  stringArray(tombstone.cleanupEvidenceReferences, 'cleanupEvidenceReferences');
  return tombstone as unknown as MachineTombstoneV1;
}

function redactCanonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactCanonical);
  if (value === null || typeof value !== 'object') return value;
  const source = value as Record<string, unknown>;
  const result: Record<string, unknown> = {};
  const redactedEnvironment = source.redacted === true || typeof source.secretReference === 'string';
  for (const [key, entry] of Object.entries(source)) {
    if (entry === undefined) continue;
    if ((key === 'value' && redactedEnvironment) || /password|secretValue|credentialValue|accessToken|refreshToken/iu.test(key)) result[key] = '[REDACTED]';
    else result[key] = redactCanonical(entry);
  }
  return result;
}

export function canonicalMachineEvidence(value: unknown): string {
  return canonicalize(redactCanonical(value));
}

export function canonicalMachineRequestDigest(value: unknown): string {
  return sha256(canonicalMachineEvidence(value));
}
