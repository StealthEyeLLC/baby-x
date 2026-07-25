import { randomUUID } from 'node:crypto';
import { existsSync, lstatSync } from 'node:fs';
import { isAbsolute, join, normalize, relative, sep } from 'node:path';
import { MachineServiceError } from './errors.ts';
import {
  canonicalMachineRequestDigest,
  type MachineBindV1,
  type MachineEnvironmentV1,
  type MachinePropertyV1,
  type MachineResourceProfileV1,
} from './schemas.ts';

export interface MachineServiceConfig {
  sourceSnapshotRoots: readonly string[];
  cloneDatasetRoots: readonly string[];
  machineRoot: string;
  allowedNetworkModes: readonly ('none' | 'private' | 'host' | 'custom')[];
  defaultListLimit: number;
  maximumListLimit: number;
  maximumEventLimit: number;
  leaseDurationMs: number;
  readinessTimeoutMs: number;
  readinessPollIntervalMs: number;
  stopGracefulTimeoutMs: number;
  stopPollIntervalMs: number;
}

export interface MachineCreateRequestV1 {
  schemaVersion: '1.0.0';
  machineName: string;
  ownerPrincipal?: string;
  authorityReference?: string;
  parentObjectiveId?: string;
  parentCertificationId?: string;
  parentCandidateId?: string;
  source: { kind: 'zfs-snapshot'; snapshot: string; expectedGuid?: string };
  clone: { dataset: string; mountpoint: string; expectedRootPrefix: string };
  launch: {
    boot: boolean;
    command?: string[];
    networkMode: 'none' | 'private' | 'host' | 'custom';
    readOnlyRoot: boolean;
    binds: MachineBindV1[];
    environment: MachineEnvironmentV1[];
    properties: MachinePropertyV1[];
    resourceProfile?: MachineResourceProfileV1;
  };
  expiresAt?: string;
  startImmediately?: false;
}

export interface NormalizedMachineCreateRequestV1 extends MachineCreateRequestV1 {
  ownerPrincipal: string;
  source: MachineCreateRequestV1['source'] & { dataset: string };
}

const MACHINE_ID = /^mx_[a-z0-9][a-z0-9_-]{7,124}$/u;
const MACHINE_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/u;
const ZFS_NAME = /^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$/u;
const ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const PROPERTY_NAME = /^[A-Za-z][A-Za-z0-9]*$/u;

function invalid(message: string, details: Readonly<Record<string, unknown>> = {}): never {
  throw new MachineServiceError('machine_invalid_request', message, details);
}

function object(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid(`${field} must be an object`);
  return value as Record<string, unknown>;
}

function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) invalid(`${field} must be a non-empty NUL-free string`);
  return value;
}

function optionalText(value: unknown, field: string): string | undefined {
  return value === undefined ? undefined : text(value, field);
}

function flag(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') invalid(`${field} must be a boolean`);
  return value;
}

function positiveInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) invalid(`${field} must be a positive safe integer`);
  return Number(value);
}

function timestamp(value: unknown, field: string): string | undefined {
  if (value === undefined) return undefined;
  const candidate = text(value, field);
  if (!Number.isFinite(Date.parse(candidate))) invalid(`${field} must be an ISO timestamp`);
  return candidate;
}

function assertAllowedKeys(value: Record<string, unknown>, field: string, allowed: readonly string[]): void {
  const allowedSet = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !allowedSet.has(key));
  if (unknown.length > 0) invalid(`${field} contains unsupported properties`, { properties: unknown });
}

export function assertMachineId(value: unknown): string {
  const candidate = text(value, 'machineId');
  if (!MACHINE_ID.test(candidate)) invalid('machineId is invalid');
  return candidate;
}

export function assertMachineName(value: unknown): string {
  const candidate = text(value, 'machineName');
  if (!MACHINE_NAME.test(candidate) || candidate.startsWith('-')) invalid('machineName is invalid');
  return candidate;
}

export function assertZfsName(value: unknown, field: string): string {
  const candidate = text(value, field);
  if (!ZFS_NAME.test(candidate) || candidate.startsWith('-') || candidate.includes('..')) invalid(`${field} must be a safe ZFS identifier`);
  return candidate;
}

export function assertNormalizedAbsolutePath(value: unknown, field: string): string {
  const candidate = text(value, field);
  if (!isAbsolute(candidate) || normalize(candidate) !== candidate || candidate === '/') invalid(`${field} must be a normalized absolute path below root`);
  return candidate;
}

function strictlyBelow(candidate: string, root: string): boolean {
  const relation = relative(root, candidate);
  return relation.length > 0 && relation !== '..' && !relation.startsWith(`..${sep}`) && !isAbsolute(relation);
}

function datasetWithin(dataset: string, root: string): boolean {
  return dataset === root || dataset.startsWith(`${root}/`);
}

function datasetStrictlyWithin(dataset: string, root: string): boolean {
  return dataset.startsWith(`${root}/`);
}

function rejectExistingSymlinkComponents(path: string, root: string): void {
  const relation = relative(root, path);
  if (!relation || relation === '..' || relation.startsWith(`..${sep}`) || isAbsolute(relation)) return;
  let current = root;
  if (existsSync(current) && lstatSync(current).isSymbolicLink()) invalid('configured machine root must not be a symbolic link', { path: current });
  for (const component of relation.split(sep)) {
    current = join(current, component);
    if (!existsSync(current)) break;
    if (lstatSync(current).isSymbolicLink()) invalid('clone.mountpoint contains an existing symbolic-link component', { path: current });
  }
}

function normalizeStringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) invalid(`${field} must be an array`);
  return value.map((entry, index) => text(entry, `${field}[${index}]`));
}

function normalizeBinds(value: unknown): MachineBindV1[] {
  if (!Array.isArray(value)) invalid('launch.binds must be an array');
  return value.map((entry, index) => {
    const bind = object(entry, `launch.binds[${index}]`);
    assertAllowedKeys(bind, `launch.binds[${index}]`, ['source', 'destination', 'mode', 'recursive']);
    const mode = text(bind.mode, `launch.binds[${index}].mode`);
    if (mode !== 'ro' && mode !== 'rw') invalid(`launch.binds[${index}].mode must be ro or rw`);
    return {
      source: assertNormalizedAbsolutePath(bind.source, `launch.binds[${index}].source`),
      destination: assertNormalizedAbsolutePath(bind.destination, `launch.binds[${index}].destination`),
      mode,
      recursive: flag(bind.recursive, `launch.binds[${index}].recursive`),
    };
  });
}

function normalizeEnvironment(value: unknown): MachineEnvironmentV1[] {
  if (!Array.isArray(value)) invalid('launch.environment must be an array');
  return value.map((entry, index) => {
    const environment = object(entry, `launch.environment[${index}]`);
    assertAllowedKeys(environment, `launch.environment[${index}]`, ['name', 'value', 'secretReference', 'redacted']);
    const name = text(environment.name, `launch.environment[${index}].name`);
    if (!ENVIRONMENT_NAME.test(name)) invalid(`launch.environment[${index}].name is invalid`);
    const valueText = optionalText(environment.value, `launch.environment[${index}].value`);
    const secretReference = optionalText(environment.secretReference, `launch.environment[${index}].secretReference`);
    if ((valueText === undefined) === (secretReference === undefined)) invalid(`launch.environment[${index}] must contain exactly one of value or secretReference`);
    const redacted = flag(environment.redacted, `launch.environment[${index}].redacted`);
    if (secretReference !== undefined && !redacted) invalid(`launch.environment[${index}] secret references must be redacted`);
    if (valueText !== undefined && redacted) invalid(`launch.environment[${index}] redacted values must use secretReference`);
    return {
      name,
      ...(valueText === undefined ? {} : { value: valueText }),
      ...(secretReference === undefined ? {} : { secretReference }),
      redacted,
    };
  });
}

function normalizeProperties(value: unknown): MachinePropertyV1[] {
  if (!Array.isArray(value)) invalid('launch.properties must be an array');
  return value.map((entry, index) => {
    const property = object(entry, `launch.properties[${index}]`);
    assertAllowedKeys(property, `launch.properties[${index}]`, ['name', 'value']);
    const name = text(property.name, `launch.properties[${index}].name`);
    if (!PROPERTY_NAME.test(name)) invalid(`launch.properties[${index}].name is invalid`);
    return { name, value: text(property.value, `launch.properties[${index}].value`) };
  });
}

function normalizeResourceProfile(value: unknown): MachineResourceProfileV1 | undefined {
  if (value === undefined) return undefined;
  const profile = object(value, 'launch.resourceProfile');
  assertAllowedKeys(profile, 'launch.resourceProfile', [
    'memoryMaxBytes', 'memoryHighBytes', 'cpuQuotaPercent', 'tasksMax', 'nofileSoft', 'nofileHard',
    'runtimeDeadlineMs', 'diskQuotaBytes', 'outputLimitBytes', 'artifactLimitBytes',
  ]);
  const cpuQuotaPercent = profile.cpuQuotaPercent;
  if (cpuQuotaPercent !== undefined && (typeof cpuQuotaPercent !== 'number' || !Number.isFinite(cpuQuotaPercent) || cpuQuotaPercent <= 0)) invalid('launch.resourceProfile.cpuQuotaPercent must be finite and positive');
  return {
    ...(profile.memoryMaxBytes === undefined ? {} : { memoryMaxBytes: positiveInteger(profile.memoryMaxBytes, 'launch.resourceProfile.memoryMaxBytes') }),
    ...(profile.memoryHighBytes === undefined ? {} : { memoryHighBytes: positiveInteger(profile.memoryHighBytes, 'launch.resourceProfile.memoryHighBytes') }),
    ...(cpuQuotaPercent === undefined ? {} : { cpuQuotaPercent }),
    ...(profile.tasksMax === undefined ? {} : { tasksMax: positiveInteger(profile.tasksMax, 'launch.resourceProfile.tasksMax') }),
    ...(profile.nofileSoft === undefined ? {} : { nofileSoft: positiveInteger(profile.nofileSoft, 'launch.resourceProfile.nofileSoft') }),
    ...(profile.nofileHard === undefined ? {} : { nofileHard: positiveInteger(profile.nofileHard, 'launch.resourceProfile.nofileHard') }),
    ...(profile.runtimeDeadlineMs === undefined ? {} : { runtimeDeadlineMs: positiveInteger(profile.runtimeDeadlineMs, 'launch.resourceProfile.runtimeDeadlineMs') }),
    ...(profile.diskQuotaBytes === undefined ? {} : { diskQuotaBytes: positiveInteger(profile.diskQuotaBytes, 'launch.resourceProfile.diskQuotaBytes') }),
    ...(profile.outputLimitBytes === undefined ? {} : { outputLimitBytes: positiveInteger(profile.outputLimitBytes, 'launch.resourceProfile.outputLimitBytes') }),
    ...(profile.artifactLimitBytes === undefined ? {} : { artifactLimitBytes: positiveInteger(profile.artifactLimitBytes, 'launch.resourceProfile.artifactLimitBytes') }),
  };
}

function normalizeRoots(values: readonly string[], field: string): string[] {
  if (values.length === 0) invalid(`${field} must contain at least one configured root`);
  return values.map((value, index) => {
    const candidate = assertZfsName(value, `${field}[${index}]`).replace(/\/$/u, '');
    if (candidate.includes('@')) invalid(`${field}[${index}] must be a dataset root, not a snapshot`);
    return candidate;
  });
}

export function normalizeMachineServiceConfig(value: Partial<MachineServiceConfig> = {}): MachineServiceConfig {
  const sourceSnapshotRoots = normalizeRoots(value.sourceSnapshotRoots ?? ['babycert/base'], 'sourceSnapshotRoots');
  const cloneDatasetRoots = normalizeRoots(value.cloneDatasetRoots ?? ['babycert/runs'], 'cloneDatasetRoots');
  const machineRoot = assertNormalizedAbsolutePath(value.machineRoot ?? '/var/lib/baby-x/machines', 'machineRoot');
  const allowedNetworkModes = value.allowedNetworkModes ?? ['none', 'private'];
  if (allowedNetworkModes.length === 0 || allowedNetworkModes.some((mode) => !['none', 'private', 'host', 'custom'].includes(mode))) invalid('allowedNetworkModes is invalid');
  const defaultListLimit = positiveInteger(value.defaultListLimit ?? 50, 'defaultListLimit');
  const maximumListLimit = positiveInteger(value.maximumListLimit ?? 200, 'maximumListLimit');
  const maximumEventLimit = positiveInteger(value.maximumEventLimit ?? 200, 'maximumEventLimit');
  const leaseDurationMs = positiveInteger(value.leaseDurationMs ?? 300_000, 'leaseDurationMs');
  const readinessTimeoutMs = positiveInteger(value.readinessTimeoutMs ?? 30_000, 'readinessTimeoutMs');
  const readinessPollIntervalMs = positiveInteger(value.readinessPollIntervalMs ?? 250, 'readinessPollIntervalMs');
  const stopGracefulTimeoutMs = positiveInteger(value.stopGracefulTimeoutMs ?? 30_000, 'stopGracefulTimeoutMs');
  const stopPollIntervalMs = positiveInteger(value.stopPollIntervalMs ?? 250, 'stopPollIntervalMs');
  if (defaultListLimit > maximumListLimit) invalid('defaultListLimit must not exceed maximumListLimit');
  if (readinessPollIntervalMs > readinessTimeoutMs) invalid('readinessPollIntervalMs must not exceed readinessTimeoutMs');
  if (stopPollIntervalMs > stopGracefulTimeoutMs) invalid('stopPollIntervalMs must not exceed stopGracefulTimeoutMs');
  return { sourceSnapshotRoots, cloneDatasetRoots, machineRoot, allowedNetworkModes: [...allowedNetworkModes], defaultListLimit, maximumListLimit, maximumEventLimit, leaseDurationMs, readinessTimeoutMs, readinessPollIntervalMs, stopGracefulTimeoutMs, stopPollIntervalMs };
}

export function normalizeMachineCreateRequest(value: unknown, authenticatedPrincipal: string, configValue: Partial<MachineServiceConfig> = {}): NormalizedMachineCreateRequestV1 {
  const config = normalizeMachineServiceConfig(configValue);
  const request = object(value, 'machine create request');
  assertAllowedKeys(request, 'machine create request', [
    'schemaVersion', 'machineName', 'ownerPrincipal', 'authorityReference', 'parentObjectiveId', 'parentCertificationId',
    'parentCandidateId', 'source', 'clone', 'launch', 'expiresAt', 'startImmediately',
  ]);
  if (request.schemaVersion !== '1.0.0') invalid('schemaVersion must be 1.0.0');
  const machineName = assertMachineName(request.machineName);
  const requestedPrincipal = optionalText(request.ownerPrincipal, 'ownerPrincipal');
  if (requestedPrincipal !== undefined && requestedPrincipal !== authenticatedPrincipal) invalid('ownerPrincipal does not match the authenticated principal');

  const source = object(request.source, 'source');
  assertAllowedKeys(source, 'source', ['kind', 'snapshot', 'expectedGuid']);
  if (source.kind !== 'zfs-snapshot') invalid('source.kind must be zfs-snapshot');
  const snapshot = assertZfsName(source.snapshot, 'source.snapshot');
  const separator = snapshot.indexOf('@');
  if (separator <= 0 || separator !== snapshot.lastIndexOf('@') || separator === snapshot.length - 1) invalid('source.snapshot must contain exactly one non-empty @ separator');
  const sourceDataset = snapshot.slice(0, separator);
  if (!config.sourceSnapshotRoots.some((root) => datasetWithin(sourceDataset, root))) throw new MachineServiceError('machine_source_not_allowed', 'source snapshot is outside configured roots', { snapshot });
  const expectedGuid = optionalText(source.expectedGuid, 'source.expectedGuid');

  const clone = object(request.clone, 'clone');
  assertAllowedKeys(clone, 'clone', ['dataset', 'mountpoint', 'expectedRootPrefix']);
  const dataset = assertZfsName(clone.dataset, 'clone.dataset');
  if (dataset.includes('@')) invalid('clone.dataset must identify a dataset, not a snapshot');
  if (!config.cloneDatasetRoots.some((root) => datasetStrictlyWithin(dataset, root))) throw new MachineServiceError('machine_dataset_conflict', 'clone dataset must be a child of a configured clone root', { dataset });
  if (config.sourceSnapshotRoots.some((root) => datasetWithin(dataset, root)) || dataset === sourceDataset) throw new MachineServiceError('machine_dataset_conflict', 'clone dataset overlaps a protected source hierarchy', { dataset, sourceDataset });
  const mountpoint = assertNormalizedAbsolutePath(clone.mountpoint, 'clone.mountpoint');
  const expectedRootPrefix = assertNormalizedAbsolutePath(clone.expectedRootPrefix, 'clone.expectedRootPrefix');
  if (expectedRootPrefix !== config.machineRoot || !strictlyBelow(mountpoint, config.machineRoot)) throw new MachineServiceError('machine_root_conflict', 'clone mountpoint is outside the configured machine root', { mountpoint, machineRoot: config.machineRoot });
  rejectExistingSymlinkComponents(mountpoint, config.machineRoot);

  const launch = object(request.launch, 'launch');
  assertAllowedKeys(launch, 'launch', ['boot', 'command', 'networkMode', 'readOnlyRoot', 'binds', 'environment', 'properties', 'resourceProfile']);
  const networkMode = text(launch.networkMode, 'launch.networkMode');
  if (!['none', 'private', 'host', 'custom'].includes(networkMode) || !config.allowedNetworkModes.includes(networkMode as MachineCreateRequestV1['launch']['networkMode'])) invalid('launch.networkMode is not allowed by service policy', { networkMode });
  const command = launch.command === undefined ? undefined : normalizeStringArray(launch.command, 'launch.command');
  if (command !== undefined && command.length === 0) invalid('launch.command must not be empty');
  const resourceProfile = normalizeResourceProfile(launch.resourceProfile);
  if (request.startImmediately === true) invalid('startImmediately is unavailable until Checkpoint C');
  if (request.startImmediately !== undefined && request.startImmediately !== false) invalid('startImmediately must be false when present');
  const expiresAt = timestamp(request.expiresAt, 'expiresAt');

  const authorityReference = optionalText(request.authorityReference, 'authorityReference');
  const parentObjectiveId = optionalText(request.parentObjectiveId, 'parentObjectiveId');
  const parentCertificationId = optionalText(request.parentCertificationId, 'parentCertificationId');
  const parentCandidateId = optionalText(request.parentCandidateId, 'parentCandidateId');
  return {
    schemaVersion: '1.0.0',
    machineName,
    ownerPrincipal: authenticatedPrincipal,
    ...(authorityReference === undefined ? {} : { authorityReference }),
    ...(parentObjectiveId === undefined ? {} : { parentObjectiveId }),
    ...(parentCertificationId === undefined ? {} : { parentCertificationId }),
    ...(parentCandidateId === undefined ? {} : { parentCandidateId }),
    source: { kind: 'zfs-snapshot', snapshot, dataset: sourceDataset, ...(expectedGuid === undefined ? {} : { expectedGuid }) },
    clone: { dataset, mountpoint, expectedRootPrefix },
    launch: {
      boot: flag(launch.boot, 'launch.boot'),
      ...(command === undefined ? {} : { command }),
      networkMode: networkMode as MachineCreateRequestV1['launch']['networkMode'],
      readOnlyRoot: flag(launch.readOnlyRoot, 'launch.readOnlyRoot'),
      binds: normalizeBinds(launch.binds),
      environment: normalizeEnvironment(launch.environment),
      properties: normalizeProperties(launch.properties),
      ...(resourceProfile === undefined ? {} : { resourceProfile }),
    },
    ...(expiresAt === undefined ? {} : { expiresAt }),
    ...(request.startImmediately === undefined ? {} : { startImmediately: false }),
  };
}

export function machineCreationDigest(request: NormalizedMachineCreateRequestV1): string {
  return canonicalMachineRequestDigest(request);
}

export function machineLaunchDigest(request: NormalizedMachineCreateRequestV1): string {
  return canonicalMachineRequestDigest(request.launch);
}

export function newMachineId(): string {
  return `mx_${randomUUID().replaceAll('-', '')}`;
}

export function ownershipMarker(machineId: string, requestDigest: string): string {
  return canonicalMachineRequestDigest({ installation: 'baby-x', provider: 'zfs-nspawn-disposable@1', machineId, requestDigest });
}

export function ownershipProperties(machineId: string, requestDigest: string, ownerPrincipal: string): Readonly<Record<string, string>> {
  return {
    'com.stealtheye.babyx:machine-id': machineId,
    'com.stealtheye.babyx:provider': 'zfs-nspawn-disposable@1',
    'com.stealtheye.babyx:request-digest': requestDigest,
    'com.stealtheye.babyx:owner-principal': ownerPrincipal,
  };
}
