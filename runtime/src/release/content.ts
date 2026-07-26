import { randomUUID } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, posix, relative, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import type { ArtifactManager } from '../artifacts/manager.ts';
import { canonicalize, sha256, type JsonObject } from '../core.ts';
import { assertNoRawSecrets, validateReleaseRecord } from './schemas.ts';
import { ReleaseApplianceStore } from './store.ts';
import {
  DEFAULT_ARCHIVE_LIMITS,
  ReleaseArchiveError,
  atomicPromoteDirectory,
  compressZstd,
  createDeterministicTar,
  decompressZstd,
  extractValidatedEntries,
  makeImmutableTree,
  parseDeterministicTar,
  scanDirectory,
  validateDeterministicEntries,
  type ArchiveLimits,
  type DeterministicArchiveEntry,
} from './tar.ts';

const GIB = 1024 * 1024 * 1024;
const ROOT_HARD_FLOOR_BYTES = 12 * GIB;
const ROOT_WARNING_FLOOR_BYTES = 18 * GIB;
const ROOT_EMERGENCY_RESERVE_BYTES = 6 * GIB;
const ZFS_EMERGENCY_RESERVE_BYTES = 10 * GIB;
const MEMORY_EMERGENCY_RESERVE_BYTES = 2 * GIB;
const ROOT_WARNING_PERCENT = 15;
const MAX_GIT_OUTPUT_BYTES = 1024 * 1024 * 1024;

const SECRET_PATH = /(^|\/)(?:\.env(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)|[^/]+\.(?:pem|p12|pfx|key))$/iu;
const TRANSIENT_PATH = /(^|\/)(?:node_modules|\.git|coverage|\.cache|tmp|temp)(?:\/|$)/u;
const PRIVATE_MATERIAL = /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|BEGIN PGP PRIVATE KEY BLOCK|(?:ghp|github_pat)_[A-Za-z0-9_]{20,}/u;
const LFS_POINTER = /^version https:\/\/git-lfs\.github\.com\/spec\/v1\noid sha256:([a-f0-9]{64})\nsize ([0-9]+)\n?$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$/u;
const GIT_SHA = /^[a-f0-9]{40}$/u;

export class ReleaseContentError extends Error {
  readonly code: string;
  readonly details: JsonObject;
  constructor(code: string, message: string, details: JsonObject = {}) {
    super(message);
    this.name = 'ReleaseContentError';
    this.code = code;
    this.details = details;
  }
}

export interface ArtifactAuthority {
  create(name: string, sourcePath: string, metadata?: JsonObject): JsonObject;
  get(id: string): JsonObject;
  list(): JsonObject[];
  verify(id: string): JsonObject;
}

export interface CapacityObservation extends JsonObject {
  observedAt: string;
  rootTotalBytes: number;
  rootAvailableBytes: number;
  rootAvailableInodes: number;
  zfsPool: string;
  zfsAvailableBytes: number;
  memoryAvailableBytes: number;
  cpuPressure: JsonObject;
  memoryPressure: JsonObject;
  ioPressure: JsonObject;
}

export interface CapacityReservationRequest extends JsonObject {
  reservationId: string;
  purpose: 'SOURCE_ARCHIVE' | 'DEPENDENCY_CACHE' | 'BUILD_CACHE' | 'RELEASE_ARTIFACT' | 'MATERIALIZATION';
  rootBytes: number;
  zfsBytes: number;
  memoryBytes: number;
  ownerPrincipal: string;
  expiresAt?: string;
}

export interface ContentServiceOptions {
  isolatedBuildRoot: string;
  releaseRoot: string;
  quarantineRoot: string;
  artifacts: ArtifactAuthority | ArtifactManager;
  store: ReleaseApplianceStore;
  capacityProvider: () => CapacityObservation;
  productionRoots?: string[];
  gitPath?: string;
  zstdPath?: string;
  archiveLimits?: ArchiveLimits;
  now?: () => string;
}

export interface ResolveSourceRequest extends JsonObject {
  repositoryPath: string;
  repository: string;
  repositoryId?: string;
  ref: string;
  expectedCommit?: string;
  expectedTree?: string;
  lockfilePath?: string;
  ownerPrincipal: string;
  verifiedCommitState?: 'NOT_REQUIRED' | 'VERIFIED' | 'UNVERIFIED' | 'UNKNOWN';
  resolvedAt?: string;
}

export interface NormalizedBuildStep extends JsonObject {
  name: string;
  argv: string[];
  cwd: string;
  environment: Record<string, string>;
  timeoutMs: number;
  networkMode: 'NONE' | 'RESTRICTED' | 'INHERIT';
}

export interface NormalizedBuildProfile extends JsonObject {
  schemaVersion: '1.0.0';
  profileId: string;
  platform: string;
  packageManager: string;
  installSteps: NormalizedBuildStep[];
  buildSteps: NormalizedBuildStep[];
  outputPaths: string[];
  cachePaths: string[];
  resourcePolicy: JsonObject;
  profileDigest: string;
}

export interface PackageReleaseRequest extends JsonObject {
  serviceId: string;
  outputDirectory: string;
  source: JsonObject;
  buildId: string;
  buildProfile: JsonObject;
  toolchainIdentity: JsonObject;
  dependencyIdentity: JsonObject;
  serviceDefinitionDigest: string;
  executableTemplate: JsonObject;
  runtimeRequirements: JsonObject;
  requiredConfigurationNames: string[];
  requiredCredentialNames: string[];
  writablePaths: string[];
  readinessCompatibility: JsonObject;
  smokeCompatibility: JsonObject;
  migrationMetadata?: JsonObject;
  minimumApplianceVersion: string;
  producerIdentity: JsonObject;
  provenanceReferences?: JsonObject[];
  sbomReferences?: JsonObject[];
  createdAt: string;
  sourceEpoch: number;
}

export interface MaterializeReleaseRequest extends JsonObject {
  artifactId: string;
  artifactSha256: string;
  reservationOwner: string;
}

interface GitTreeRecord {
  mode: string;
  type: string;
  oid: string;
  path: string;
}

function ensureIdentifier(value: string, name: string): string {
  if (!IDENTIFIER.test(value)) throw new ReleaseContentError('release_invalid_request', `${name} must be a bounded identifier`, { [name]: value });
  return value;
}

function ensureDigest(value: string, name: string): string {
  if (!/^[a-f0-9]{64}$/u.test(value)) throw new ReleaseContentError('release_invalid_request', `${name} must be a lowercase SHA-256 digest`);
  return value;
}

function ensureGitSha(value: string, name: string): string {
  if (!GIT_SHA.test(value)) throw new ReleaseContentError('release_invalid_request', `${name} must be a lowercase 40-character Git SHA`);
  return value;
}

function finiteNonNegativeInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new ReleaseContentError('release_invalid_request', `${name} must be a non-negative safe integer`);
  return value;
}

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function strictObject(value: unknown, allowed: readonly string[], required: readonly string[], name: string): JsonObject {
  if (!isObject(value)) throw new ReleaseContentError('release_invalid_request', `${name} must be an object`);
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw new ReleaseContentError('release_invalid_request', `${name} contains unknown field ${unknown.sort()[0]}`);
  for (const key of required) if (value[key] === undefined) throw new ReleaseContentError('release_invalid_request', `${name}.${key} is required`);
  return value;
}

function sortedStringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || item.length === 0 || item.includes('\0'))) {
    throw new ReleaseContentError('release_invalid_request', `${name} must be an array of non-empty strings`);
  }
  return [...new Set(value as string[])].sort();
}

function orderedStringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || item.length === 0 || item.includes('\0'))) {
    throw new ReleaseContentError('release_invalid_request', `${name} must be an array of non-empty strings`);
  }
  return [...value] as string[];
}

function ensureWithin(root: string, candidate: string, name: string): string {
  const base = resolve(root);
  const target = resolve(candidate);
  if (target !== base && !target.startsWith(`${base}${sep}`)) throw new ReleaseContentError('release_path_outside_authority', `${name} is outside authorized root`, { root: base, path: target });
  return target;
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, 'r');
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function safeTemporaryFile(root: string, name: string, bytes: Buffer): string {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const path = join(root, `${name}.${randomUUID()}.tmp`);
  const descriptor = openSync(path, 'wx', 0o600);
  try {
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  fsyncDirectory(root);
  return path;
}

function git(gitPath: string, repositoryPath: string, args: string[], encoding: BufferEncoding | 'buffer' = 'utf8'): string | Buffer {
  const result = spawnSync(gitPath, ['-C', repositoryPath, ...args], {
    encoding: encoding === 'buffer' ? null : encoding,
    maxBuffer: MAX_GIT_OUTPUT_BYTES,
  });
  if (result.status !== 0) {
    const stderr = Buffer.isBuffer(result.stderr) ? result.stderr.toString('utf8') : String(result.stderr ?? '');
    throw new ReleaseContentError('release_source_unresolved', 'Git source resolution failed', { args, status: result.status ?? -1, stderr: stderr.slice(0, 2048) });
  }
  return encoding === 'buffer' ? Buffer.from(result.stdout as Buffer) : String(result.stdout).trim();
}

function parseGitTree(bytes: Buffer): GitTreeRecord[] {
  const records: GitTreeRecord[] = [];
  for (const item of bytes.toString('utf8').split('\0').filter(Boolean)) {
    const tab = item.indexOf('\t');
    const header = tab < 0 ? '' : item.slice(0, tab);
    const path = tab < 0 ? '' : item.slice(tab + 1);
    const [mode, type, oid] = header.split(' ');
    if (!/^[0-7]{6}$/u.test(mode ?? '') || !['blob', 'commit'].includes(type ?? '') || !GIT_SHA.test(oid ?? '') || path.length === 0) {
      throw new ReleaseContentError('release_source_mismatch', 'Git tree output is malformed', { item: item.slice(0, 512) });
    }
    records.push({ mode: mode as string, type: type as string, oid: oid as string, path });
  }
  return records.sort((left, right) => left.path.localeCompare(right.path));
}

function metadataEntries(entries: readonly DeterministicArchiveEntry[]): JsonObject[] {
  return entries.map(({ data, dataEncoding, ...entry }) => ({ ...entry })).sort((left, right) => String(left.path).localeCompare(String(right.path)));
}

function addParentDirectories(entries: Map<string, DeterministicArchiveEntry>, path: string): void {
  const parts = path.split('/');
  for (let index = 1; index < parts.length; index += 1) {
    const directory = parts.slice(0, index).join('/');
    if (!entries.has(directory)) entries.set(directory, { path: directory, type: 'directory', mode: 0o755, size: 0, sha256: sha256(Buffer.alloc(0)) });
  }
}

function secretPathOrContent(path: string, bytes: Buffer): void {
  if (SECRET_PATH.test(path)) throw new ReleaseContentError('release_secret_material_rejected', 'source or artifact contains a prohibited secret-bearing path', { path });
  if (PRIVATE_MATERIAL.test(bytes.toString('utf8'))) throw new ReleaseContentError('release_secret_material_rejected', 'source or artifact contains private credential material', { path });
}

function artifactMetadata(record: JsonObject): JsonObject {
  return isObject(record.metadata) ? record.metadata : {};
}

function artifactValid(artifacts: ArtifactAuthority, record: JsonObject): boolean {
  if (record.state !== 'finalized' || typeof record.id !== 'string') return false;
  try { return artifacts.verify(record.id).valid === true; } catch { return false; }
}

function immutableMetadata(entries: readonly DeterministicArchiveEntry[]): JsonObject[] {
  return metadataEntries(entries).map((entry) => ({
    path: entry.path,
    type: entry.type,
    size: entry.size,
    sha256: entry.sha256,
    ...(entry.linkTarget === undefined ? {} : { linkTarget: entry.linkTarget }),
  }));
}

export function normalizeBuildProfile(value: unknown): NormalizedBuildProfile {
  const profile = strictObject(
    value,
    ['schemaVersion', 'profileId', 'platform', 'packageManager', 'installSteps', 'buildSteps', 'outputPaths', 'cachePaths', 'resourcePolicy'],
    ['schemaVersion', 'profileId', 'platform', 'packageManager', 'installSteps', 'buildSteps', 'outputPaths', 'cachePaths', 'resourcePolicy'],
    'buildProfile',
  );
  if (profile.schemaVersion !== '1.0.0') throw new ReleaseContentError('release_invalid_request', 'unsupported build profile schema version');
  const normalizeSteps = (value: unknown, name: string): NormalizedBuildStep[] => {
    if (!Array.isArray(value) || value.length > 128) throw new ReleaseContentError('release_invalid_request', `${name} must be a bounded array`);
    return value.map((stepValue, index) => {
      const step = strictObject(stepValue, ['name', 'argv', 'cwd', 'environment', 'timeoutMs', 'networkMode'], ['name', 'argv', 'cwd', 'environment', 'timeoutMs', 'networkMode'], `${name}[${index}]`);
      const argv = orderedStringArray(step.argv, `${name}[${index}].argv`);
      if (argv.length === 0) throw new ReleaseContentError('release_invalid_request', `${name}[${index}].argv cannot be empty`);
      const cwd = String(step.cwd);
      if (cwd.startsWith('/') || cwd.includes('\0') || posix.normalize(cwd).startsWith('../')) throw new ReleaseContentError('release_invalid_request', `${name}[${index}].cwd must be relative`);
      if (!isObject(step.environment)) throw new ReleaseContentError('release_invalid_request', `${name}[${index}].environment must be an object`);
      const environment = Object.fromEntries(Object.entries(step.environment).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => {
        if (!/^[A-Z_][A-Z0-9_]*$/u.test(key) || typeof item !== 'string' || item.includes('\0')) throw new ReleaseContentError('release_invalid_request', `${name}[${index}].environment is invalid`);
        if (/TOKEN|PASSWORD|SECRET|PRIVATE_KEY/u.test(key)) throw new ReleaseContentError('release_secret_material_rejected', 'build profile cannot embed secret values', { key });
        return [key, item];
      }));
      const networkMode = String(step.networkMode);
      if (!['NONE', 'RESTRICTED', 'INHERIT'].includes(networkMode)) throw new ReleaseContentError('release_invalid_request', `${name}[${index}].networkMode is invalid`);
      return {
        name: ensureIdentifier(String(step.name), `${name}[${index}].name`),
        argv,
        cwd: cwd === '' ? '.' : posix.normalize(cwd),
        environment,
        timeoutMs: finiteNonNegativeInteger(Number(step.timeoutMs), `${name}[${index}].timeoutMs`),
        networkMode: networkMode as NormalizedBuildStep['networkMode'],
      };
    });
  };
  assertNoRawSecrets(profile.resourcePolicy);
  const normalizedWithoutDigest = {
    schemaVersion: '1.0.0' as const,
    profileId: ensureIdentifier(String(profile.profileId), 'profileId'),
    platform: ensureIdentifier(String(profile.platform), 'platform'),
    packageManager: ensureIdentifier(String(profile.packageManager), 'packageManager'),
    installSteps: normalizeSteps(profile.installSteps, 'installSteps'),
    buildSteps: normalizeSteps(profile.buildSteps, 'buildSteps'),
    outputPaths: sortedStringArray(profile.outputPaths, 'outputPaths').map((path) => posix.normalize(path)),
    cachePaths: sortedStringArray(profile.cachePaths, 'cachePaths').map((path) => posix.normalize(path)),
    resourcePolicy: structuredClone(profile.resourcePolicy),
  };
  const profileDigest = sha256(canonicalize(normalizedWithoutDigest));
  return { ...normalizedWithoutDigest, profileDigest };
}

export function dependencyCacheKey(source: JsonObject, profile: NormalizedBuildProfile, toolchainIdentity: JsonObject): string {
  return sha256(canonicalize({
    kind: 'dependency-cache-v1',
    repository: source.repository,
    tree: source.tree,
    lockfileDigest: source.lockfileDigest,
    profileDigest: profile.profileDigest,
    platform: profile.platform,
    packageManager: profile.packageManager,
    toolchainIdentity,
  }));
}

export function buildOutputCacheKey(source: JsonObject, profile: NormalizedBuildProfile, toolchainIdentity: JsonObject, serviceDefinitionDigest: string): string {
  return sha256(canonicalize({
    kind: 'build-output-cache-v1',
    repository: source.repository,
    commit: source.commit,
    tree: source.tree,
    sourceManifestDigest: source.sourceManifestDigest,
    profileDigest: profile.profileDigest,
    toolchainIdentity,
    serviceDefinitionDigest: ensureDigest(serviceDefinitionDigest, 'serviceDefinitionDigest'),
  }));
}

export function validateServiceDefinition(value: unknown): { record: JsonObject; digest: string } {
  const record = validateReleaseRecord('ServiceDefinitionV1', value);
  const declared = String(record.manifestDigest);
  const unsigned = { ...record };
  delete unsigned.manifestDigest;
  const digest = sha256(canonicalize(unsigned));
  if (declared !== digest) throw new ReleaseContentError('release_source_mismatch', 'service definition manifest digest does not match canonical bytes', { declared, digest });
  return { record, digest };
}

export function evaluateCapacity(observation: CapacityObservation, request: CapacityReservationRequest): JsonObject {
  for (const [name, value] of Object.entries({
    rootTotalBytes: observation.rootTotalBytes,
    rootAvailableBytes: observation.rootAvailableBytes,
    rootAvailableInodes: observation.rootAvailableInodes,
    zfsAvailableBytes: observation.zfsAvailableBytes,
    memoryAvailableBytes: observation.memoryAvailableBytes,
    rootBytes: request.rootBytes,
    zfsBytes: request.zfsBytes,
    memoryBytes: request.memoryBytes,
  })) finiteNonNegativeInteger(Number(value), name);
  const rootAfter = observation.rootAvailableBytes - request.rootBytes;
  const zfsAfter = observation.zfsAvailableBytes - request.zfsBytes;
  const memoryAfter = observation.memoryAvailableBytes - request.memoryBytes;
  const rootPercentAfter = observation.rootTotalBytes === 0 ? 0 : Math.floor((rootAfter * 100) / observation.rootTotalBytes);
  const reasons: string[] = [];
  if (rootAfter < ROOT_HARD_FLOOR_BYTES || rootAfter < ROOT_EMERGENCY_RESERVE_BYTES) reasons.push('root_capacity_below_hard_floor');
  if (zfsAfter < ZFS_EMERGENCY_RESERVE_BYTES) reasons.push('zfs_capacity_below_emergency_reserve');
  if (memoryAfter < MEMORY_EMERGENCY_RESERVE_BYTES) reasons.push('memory_capacity_below_emergency_reserve');
  if (observation.rootAvailableInodes < 10_000) reasons.push('root_inode_capacity_low');
  const warning = rootAfter < ROOT_WARNING_FLOOR_BYTES || rootPercentAfter < ROOT_WARNING_PERCENT;
  return {
    admission: reasons.length > 0 ? 'REJECT' : warning ? 'THROTTLE' : 'ALLOW',
    reasons,
    warning,
    rootAfter,
    rootPercentAfter,
    zfsAfter,
    memoryAfter,
  };
}

export class ImmutableReleaseContentService {
  private readonly isolatedBuildRoot: string;
  private readonly releaseRoot: string;
  private readonly quarantineRoot: string;
  private readonly productionRoots: string[];
  private readonly artifacts: ArtifactAuthority;
  private readonly store: ReleaseApplianceStore;
  private readonly capacityProvider: () => CapacityObservation;
  private readonly gitPath: string;
  private readonly zstdPath: string;
  private readonly archiveLimits: ArchiveLimits;
  private readonly now: () => string;

  constructor(options: ContentServiceOptions) {
    this.isolatedBuildRoot = resolve(options.isolatedBuildRoot);
    this.releaseRoot = resolve(options.releaseRoot);
    this.quarantineRoot = resolve(options.quarantineRoot);
    this.productionRoots = (options.productionRoots ?? []).map((path) => resolve(path));
    this.artifacts = options.artifacts as ArtifactAuthority;
    this.store = options.store;
    this.capacityProvider = options.capacityProvider;
    this.gitPath = options.gitPath ?? '/usr/bin/git';
    this.zstdPath = options.zstdPath ?? '/usr/bin/zstd';
    this.archiveLimits = options.archiveLimits ?? DEFAULT_ARCHIVE_LIMITS;
    this.now = options.now ?? (() => new Date().toISOString());
    for (const path of [this.isolatedBuildRoot, this.releaseRoot, this.quarantineRoot]) mkdirSync(path, { recursive: true, mode: 0o700 });
  }

  private assertNotProductionPath(path: string, name: string): string {
    const target = resolve(path);
    for (const root of this.productionRoots) {
      if (target === root || target.startsWith(`${root}${sep}`) || root.startsWith(`${target}${sep}`)) {
        throw new ReleaseContentError('release_production_build_path_forbidden', `${name} overlaps a production root`, { path: target, productionRoot: root });
      }
    }
    return ensureWithin(this.isolatedBuildRoot, target, name);
  }

  private reserve(requestValue: CapacityReservationRequest): JsonObject {
    const request: CapacityReservationRequest = {
      ...requestValue,
      reservationId: ensureIdentifier(requestValue.reservationId, 'reservationId'),
      ownerPrincipal: ensureIdentifier(requestValue.ownerPrincipal, 'ownerPrincipal'),
      rootBytes: finiteNonNegativeInteger(requestValue.rootBytes, 'rootBytes'),
      zfsBytes: finiteNonNegativeInteger(requestValue.zfsBytes, 'zfsBytes'),
      memoryBytes: finiteNonNegativeInteger(requestValue.memoryBytes, 'memoryBytes'),
    };
    const observation = this.capacityProvider();
    const decision = evaluateCapacity(observation, request);
    const observationDigest = sha256(canonicalize({ observation, request, decision }));
    const snapshotId = `capacity_${sha256(canonicalize({ reservationId: request.reservationId, observationDigest })).slice(0, 40)}`;
    const record = validateReleaseRecord('CapacitySnapshotV1', {
      schemaVersion: '1.0.0',
      snapshotId,
      observedAt: observation.observedAt,
      rootTotalBytes: observation.rootTotalBytes,
      rootAvailableBytes: observation.rootAvailableBytes,
      rootAvailableInodes: observation.rootAvailableInodes,
      zfsPool: observation.zfsPool,
      zfsAvailableBytes: observation.zfsAvailableBytes,
      memoryAvailableBytes: observation.memoryAvailableBytes,
      cpuPressure: observation.cpuPressure,
      memoryPressure: observation.memoryPressure,
      ioPressure: observation.ioPressure,
      reservations: [request],
      admission: decision.admission,
      observationDigest,
    });
    this.store.applyMutation({
      schemaId: 'CapacitySnapshotV1',
      recordId: snapshotId,
      ownerPrincipal: request.ownerPrincipal,
      expectedSequence: 0,
      idempotencyKey: `capacity-${request.reservationId}-${observationDigest.slice(0, 16)}`,
      requestDigest: sha256(canonicalize(record)),
      operation: 'babyx.release.capacity.reserve',
      phase: 'capacity-admission',
      record,
      occurredAt: observation.observedAt,
      observationDigest,
    });
    if (decision.admission === 'REJECT') throw new ReleaseContentError('release_capacity_insufficient', 'capacity admission rejected before persistent content write', { snapshotId, decision });
    return { snapshotId, observationDigest, decision, request };
  }

  private findContentArtifact(contentKey: string, expectedSha256?: string): JsonObject | undefined {
    const matches = this.artifacts.list().filter((record) => {
      const metadata = artifactMetadata(record);
      return record.state === 'finalized' && metadata.contentKey === contentKey;
    });
    if (matches.length === 0) return undefined;
    const valid = matches.filter((record) => artifactValid(this.artifacts, record));
    if (valid.length === 0) throw new ReleaseContentError('release_artifact_invalid', 'content-addressed artifact metadata exists but bytes are corrupt', { contentKey, artifactIds: matches.map((record) => record.id) });
    const matching = expectedSha256 === undefined ? valid : valid.filter((record) => record.sha256 === expectedSha256);
    if (matching.length === 0) throw new ReleaseContentError('release_artifact_invalid', 'content key resolves to unexpected digest', { contentKey, expectedSha256, observed: valid.map((record) => record.sha256) });
    matching.sort((left, right) => String(left.id).localeCompare(String(right.id)));
    return matching[0];
  }

  private ensureArtifact(name: string, bytes: Buffer, metadata: JsonObject, capacityPurpose: CapacityReservationRequest['purpose'], ownerPrincipal: string): JsonObject {
    const digest = sha256(bytes);
    const contentKey = ensureDigest(String(metadata.contentKey), 'contentKey');
    const existing = this.findContentArtifact(contentKey, digest);
    if (existing !== undefined) return existing;
    this.reserve({
      reservationId: `reserve_${contentKey.slice(0, 40)}`,
      purpose: capacityPurpose,
      rootBytes: bytes.length * 2 + 1024 * 1024,
      zfsBytes: bytes.length + 1024 * 1024,
      memoryBytes: Math.min(bytes.length * 2 + 64 * 1024 * 1024, 512 * 1024 * 1024),
      ownerPrincipal,
    });
    const temporary = safeTemporaryFile(this.isolatedBuildRoot, name.replace(/[^A-Za-z0-9._-]/gu, '_'), bytes);
    try {
      try {
        const created = this.artifacts.create(name, temporary, { ...metadata, contentKey, expectedSha256: digest });
        if (created.sha256 !== digest || !artifactValid(this.artifacts, created)) throw new ReleaseContentError('release_artifact_invalid', 'artifact authority did not preserve expected bytes', { id: created.id, digest });
        return created;
      } catch (error) {
        const recovered = this.findContentArtifact(contentKey, digest);
        if (recovered !== undefined) return recovered;
        throw error;
      }
    } finally {
      rmSync(temporary, { force: true });
    }
  }

  resolveSource(request: ResolveSourceRequest): JsonObject {
    const repositoryPath = resolve(request.repositoryPath);
    if (!existsSync(join(repositoryPath, '.git'))) throw new ReleaseContentError('release_source_unresolved', 'repository path is not a Git worktree', { repositoryPath });
    ensureIdentifier(request.ownerPrincipal, 'ownerPrincipal');
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(request.repository)) throw new ReleaseContentError('release_invalid_request', 'repository must be owner/name');
    if (request.ref.length === 0 || request.ref.includes('\0')) throw new ReleaseContentError('release_invalid_request', 'ref is invalid');
    const commit = ensureGitSha(String(git(this.gitPath, repositoryPath, ['rev-parse', '--verify', `${request.ref}^{commit}`])), 'commit');
    const tree = ensureGitSha(String(git(this.gitPath, repositoryPath, ['rev-parse', '--verify', `${commit}^{tree}`])), 'tree');
    if (request.expectedCommit !== undefined && commit !== ensureGitSha(request.expectedCommit, 'expectedCommit')) throw new ReleaseContentError('release_source_mismatch', 'resolved commit differs from expected commit', { expected: request.expectedCommit, observed: commit });
    if (request.expectedTree !== undefined && tree !== ensureGitSha(request.expectedTree, 'expectedTree')) throw new ReleaseContentError('release_source_mismatch', 'resolved tree differs from expected tree', { expected: request.expectedTree, observed: tree });
    const epoch = Number(String(git(this.gitPath, repositoryPath, ['show', '-s', '--format=%ct', commit])));
    finiteNonNegativeInteger(epoch, 'sourceEpoch');
    const treeRecords = parseGitTree(git(this.gitPath, repositoryPath, ['ls-tree', '-rz', '--full-tree', commit], 'buffer') as Buffer);
    const entries = new Map<string, DeterministicArchiveEntry>();
    const submodules: JsonObject[] = [];
    const gitLfsObjects: JsonObject[] = [];
    for (const item of treeRecords) {
      if (TRANSIENT_PATH.test(item.path)) continue;
      if (item.type === 'commit' || item.mode === '160000') {
        submodules.push({ path: item.path, commit: item.oid });
        continue;
      }
      const bytes = git(this.gitPath, repositoryPath, ['cat-file', 'blob', item.oid], 'buffer') as Buffer;
      secretPathOrContent(item.path, bytes);
      const archivePath = posix.join('source', item.path);
      addParentDirectories(entries, archivePath);
      if (item.mode === '120000') {
        const target = bytes.toString('utf8');
        const entry: DeterministicArchiveEntry = { path: archivePath, type: 'symlink', mode: 0o777, size: Buffer.byteLength(target), sha256: sha256(Buffer.from(target, 'utf8')), linkTarget: target };
        entries.set(archivePath, entry);
      } else {
        const mode = item.mode === '100755' ? 0o755 : 0o644;
        entries.set(archivePath, { path: archivePath, type: 'file', mode, size: bytes.length, sha256: sha256(bytes), data: bytes.toString('base64'), dataEncoding: 'base64' });
        const lfs = bytes.toString('utf8').match(LFS_POINTER);
        if (lfs !== null) gitLfsObjects.push({ path: item.path, sha256: lfs[1], size: Number(lfs[2]) });
      }
    }
    const normalizedEntries = validateDeterministicEntries([...entries.values()], this.archiveLimits);
    const lockfileCandidates = request.lockfilePath === undefined
      ? ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'Cargo.lock', 'poetry.lock', 'uv.lock']
      : [request.lockfilePath];
    const lockfile = lockfileCandidates.map((path) => normalizedEntries.find((entry) => entry.path === posix.join('source', path) && entry.type === 'file')).find((entry) => entry !== undefined);
    if (lockfile === undefined) throw new ReleaseContentError('release_source_mismatch', 'exact source tree lacks the required lockfile', { candidates: lockfileCandidates });
    const sourceManifest = {
      schemaVersion: '1.0.0',
      repository: request.repository,
      repositoryId: request.repositoryId ?? null,
      commit,
      tree,
      entries: metadataEntries(normalizedEntries),
      lockfilePath: String(lockfile.path).slice('source/'.length),
      lockfileDigest: lockfile.sha256,
      submodules: submodules.sort((left, right) => String(left.path).localeCompare(String(right.path))),
      gitLfsObjects: gitLfsObjects.sort((left, right) => String(left.path).localeCompare(String(right.path))),
    };
    const sourceManifestDigest = sha256(canonicalize(sourceManifest));
    const tar = createDeterministicTar(normalizedEntries, epoch, this.archiveLimits);
    const archive = compressZstd(tar, this.zstdPath);
    const contentKey = sha256(canonicalize({ kind: 'source-archive-v1', repository: request.repository, commit, tree, sourceManifestDigest }));
    const artifact = this.ensureArtifact(`source-${commit}.tar.zst`, archive, {
      kind: 'source-archive',
      contentKey,
      repository: request.repository,
      commit,
      tree,
      sourceManifestDigest,
      compression: { format: 'zstd', level: 19, threads: 1 },
    }, 'SOURCE_ARCHIVE', request.ownerPrincipal);
    const resolvedAt = request.resolvedAt ?? this.now();
    const resolverReceiptId = `source_receipt_${sha256(canonicalize({ repository: request.repository, commit, tree, artifactId: artifact.id, resolvedAt })).slice(0, 40)}`;
    const sourceIdentity = validateReleaseRecord('SourceIdentityV1', {
      schemaVersion: '1.0.0',
      repository: request.repository,
      ...(request.repositoryId === undefined ? {} : { repositoryId: request.repositoryId }),
      refContext: request.ref,
      commit,
      tree,
      sourceArchiveArtifactId: artifact.id,
      sourceArchiveSha256: artifact.sha256,
      sourceManifestDigest,
      lockfilePath: sourceManifest.lockfilePath,
      lockfileDigest: sourceManifest.lockfileDigest,
      submodules: sourceManifest.submodules,
      gitLfsObjects: sourceManifest.gitLfsObjects,
      resolvedAt,
      resolverReceiptId,
      verifiedCommitState: request.verifiedCommitState ?? 'UNKNOWN',
    });
    return {
      sourceIdentity,
      sourceManifest,
      sourceEpoch: epoch,
      artifact,
      resolverReceipt: {
        receiptId: resolverReceiptId,
        repository: request.repository,
        refContext: request.ref,
        commit,
        tree,
        sourceManifestDigest,
        sourceArchiveArtifactId: artifact.id,
        sourceArchiveSha256: artifact.sha256,
        resolvedAt,
      },
    };
  }

  lookupCache(namespace: 'dependency' | 'build', cacheKey: string): JsonObject {
    ensureDigest(cacheKey, 'cacheKey');
    const contentKey = sha256(canonicalize({ kind: `${namespace}-cache-v1`, cacheKey }));
    const matches = this.artifacts.list().filter((record) => {
      const metadata = artifactMetadata(record);
      return record.state === 'finalized' && metadata.kind === `${namespace}-cache` && metadata.cacheKey === cacheKey && metadata.contentKey === contentKey;
    });
    if (matches.length === 0) return { result: 'MISS', namespace, cacheKey, contentKey };
    const valid = matches.find((record) => artifactValid(this.artifacts, record));
    if (valid === undefined) return { result: 'CORRUPT', namespace, cacheKey, contentKey, artifactIds: matches.map((record) => record.id).sort() };
    return { result: 'HIT', namespace, cacheKey, contentKey, artifact: valid };
  }

  storeCache(namespace: 'dependency' | 'build', cacheKey: string, preparedPath: string, ownerPrincipal: string): JsonObject {
    ensureDigest(cacheKey, 'cacheKey');
    ensureIdentifier(ownerPrincipal, 'ownerPrincipal');
    const sourcePath = this.assertNotProductionPath(preparedPath, 'preparedPath');
    if (!lstatSync(sourcePath).isFile()) throw new ReleaseContentError('release_invalid_request', 'cache source must be a regular file', { sourcePath });
    const bytes = readFileSync(sourcePath);
    secretPathOrContent(posix.basename(sourcePath), bytes);
    const contentKey = sha256(canonicalize({ kind: `${namespace}-cache-v1`, cacheKey }));
    const artifact = this.ensureArtifact(`${namespace}-cache-${cacheKey}.bin`, bytes, { kind: `${namespace}-cache`, cacheKey, contentKey }, namespace === 'dependency' ? 'DEPENDENCY_CACHE' : 'BUILD_CACHE', ownerPrincipal);
    return { result: 'STORED', namespace, cacheKey, contentKey, artifact };
  }

  packageRelease(request: PackageReleaseRequest): JsonObject {
    const outputDirectory = this.assertNotProductionPath(request.outputDirectory, 'outputDirectory');
    if (!lstatSync(outputDirectory).isDirectory()) throw new ReleaseContentError('release_invalid_request', 'build output must be a directory');
    ensureIdentifier(request.serviceId, 'serviceId');
    ensureIdentifier(request.buildId, 'buildId');
    ensureDigest(request.serviceDefinitionDigest, 'serviceDefinitionDigest');
    const source = validateReleaseRecord('SourceIdentityV1', request.source);
    const profile = normalizeBuildProfile(request.buildProfile);
    assertNoRawSecrets(request.toolchainIdentity);
    assertNoRawSecrets(request.dependencyIdentity);
    const applicationEntries = scanDirectory(outputDirectory, 'app', this.archiveLimits);
    for (const entry of applicationEntries) {
      if (entry.type === 'file' && typeof entry.data === 'string') secretPathOrContent(entry.path, Buffer.from(entry.data, 'base64'));
      else if (SECRET_PATH.test(entry.path)) throw new ReleaseContentError('release_secret_material_rejected', 'release output contains prohibited path', { path: entry.path });
    }
    const payloadManifest = {
      schemaVersion: '1.0.0',
      serviceId: request.serviceId,
      sourceCommit: source.commit,
      sourceTree: source.tree,
      sourceManifestDigest: source.sourceManifestDigest,
      buildId: request.buildId,
      buildProfileDigest: profile.profileDigest,
      toolchainIdentity: request.toolchainIdentity,
      dependencyIdentity: request.dependencyIdentity,
      serviceDefinitionDigest: request.serviceDefinitionDigest,
      files: metadataEntries(applicationEntries),
      writablePaths: sortedStringArray(request.writablePaths, 'writablePaths'),
      minimumApplianceVersion: request.minimumApplianceVersion,
      createdAt: request.createdAt,
    };
    const payloadBytes = Buffer.from(`${canonicalize(payloadManifest)}\n`, 'utf8');
    const payloadEntry: DeterministicArchiveEntry = {
      path: 'meta/release-payload-manifest.json',
      type: 'file',
      mode: 0o444,
      size: payloadBytes.length,
      sha256: sha256(payloadBytes),
      data: payloadBytes.toString('base64'),
      dataEncoding: 'base64',
    };
    const entries = validateDeterministicEntries([...applicationEntries, {
      path: 'meta', type: 'directory', mode: 0o555, size: 0, sha256: sha256(Buffer.alloc(0)),
    }, payloadEntry], this.archiveLimits);
    const tar = createDeterministicTar(entries, request.sourceEpoch, this.archiveLimits);
    const archive = compressZstd(tar, this.zstdPath);
    const contentKey = sha256(canonicalize({ kind: 'release-artifact-v1', payloadManifest }));
    const artifact = this.ensureArtifact(`${request.serviceId}-${source.commit}.tar.zst`, archive, {
      kind: 'release-artifact',
      contentKey,
      serviceId: request.serviceId,
      sourceCommit: source.commit,
      sourceTree: source.tree,
      buildId: request.buildId,
      buildProfileDigest: profile.profileDigest,
      payloadManifestDigest: sha256(canonicalize(payloadManifest)),
      compression: { format: 'zstd', level: 19, threads: 1 },
    }, 'RELEASE_ARTIFACT', request.serviceId);
    const unsignedManifest: JsonObject = {
      schemaVersion: '1.0.0',
      artifactId: artifact.id,
      artifactSha256: artifact.sha256,
      sizeBytes: artifact.size,
      compression: { format: 'zstd', level: 19, threads: 1, deterministic: true },
      source,
      buildId: request.buildId,
      toolchainIdentity: request.toolchainIdentity,
      dependencyIdentity: request.dependencyIdentity,
      serviceDefinitionDigest: request.serviceDefinitionDigest,
      layoutVersion: '1.0.0',
      executableTemplate: request.executableTemplate,
      runtimeRequirements: request.runtimeRequirements,
      requiredConfigurationNames: sortedStringArray(request.requiredConfigurationNames, 'requiredConfigurationNames'),
      requiredCredentialNames: sortedStringArray(request.requiredCredentialNames, 'requiredCredentialNames'),
      files: metadataEntries(entries),
      writablePaths: sortedStringArray(request.writablePaths, 'writablePaths'),
      readinessCompatibility: request.readinessCompatibility,
      smokeCompatibility: request.smokeCompatibility,
      ...(request.migrationMetadata === undefined ? {} : { migrationMetadata: request.migrationMetadata }),
      minimumApplianceVersion: request.minimumApplianceVersion,
      createdAt: request.createdAt,
      producerIdentity: request.producerIdentity,
      provenanceReferences: request.provenanceReferences ?? [],
      sbomReferences: request.sbomReferences ?? [],
    };
    assertNoRawSecrets(unsignedManifest);
    const manifest = validateReleaseRecord('ReleaseArtifactManifestV1', { ...unsignedManifest, manifestDigest: sha256(canonicalize(unsignedManifest)) });
    return { artifact, manifest, payloadManifest, entries, deterministicDigest: artifact.sha256 };
  }

  private artifactBytes(artifactId: string, expectedSha256: string): { record: JsonObject; bytes: Buffer } {
    const record = this.artifacts.get(artifactId);
    if (record.state !== 'finalized' || record.sha256 !== expectedSha256 || this.artifacts.verify(artifactId).valid !== true) {
      throw new ReleaseContentError('release_artifact_invalid', 'artifact integrity verification failed', { artifactId, expectedSha256, observedSha256: record.sha256 });
    }
    const path = String(record.path);
    const bytes = readFileSync(path);
    if (sha256(bytes) !== expectedSha256) throw new ReleaseContentError('release_artifact_invalid', 'artifact bytes changed after authority verification', { artifactId });
    return { record, bytes };
  }

  private verifyExistingMaterialization(path: string, entries: readonly DeterministicArchiveEntry[]): JsonObject {
    const observed = scanDirectory(path, '', this.archiveLimits);
    const expectedMetadata = immutableMetadata(entries);
    const observedMetadata = immutableMetadata(observed);
    const expectedDigest = sha256(canonicalize(expectedMetadata));
    const observedDigest = sha256(canonicalize(observedMetadata));
    const writable = observed.filter((entry) => entry.type !== 'symlink' && (entry.mode & 0o222) !== 0).map((entry) => entry.path);
    return { valid: expectedDigest === observedDigest && writable.length === 0, expectedDigest, observedDigest, writable, entries: observed.length };
  }

  materializeRelease(request: MaterializeReleaseRequest): JsonObject {
    ensureIdentifier(request.artifactId, 'artifactId');
    ensureDigest(request.artifactSha256, 'artifactSha256');
    ensureIdentifier(request.reservationOwner, 'reservationOwner');
    const { bytes } = this.artifactBytes(request.artifactId, request.artifactSha256);
    const tar = decompressZstd(bytes, this.zstdPath, this.archiveLimits.maxExpandedBytes + 1024 * 1024);
    const entries = parseDeterministicTar(tar, this.archiveLimits);
    const expandedBytes = entries.reduce((sum, entry) => sum + (entry.type === 'file' ? entry.size : 0), 0);
    this.reserve({
      reservationId: `materialize_${request.artifactSha256.slice(0, 40)}`,
      purpose: 'MATERIALIZATION',
      rootBytes: expandedBytes + 64 * 1024 * 1024,
      zfsBytes: expandedBytes + 64 * 1024 * 1024,
      memoryBytes: Math.min(expandedBytes + 64 * 1024 * 1024, 512 * 1024 * 1024),
      ownerPrincipal: request.reservationOwner,
    });
    const finalPath = join(this.releaseRoot, request.artifactSha256);
    if (existsSync(finalPath)) {
      const verification = this.verifyExistingMaterialization(finalPath, entries);
      if (verification.valid === true) return { materialized: true, reused: true, path: finalPath, verification };
      mkdirSync(this.quarantineRoot, { recursive: true, mode: 0o700 });
      const quarantinePath = join(this.quarantineRoot, `${request.artifactSha256}.${Date.now()}.${randomUUID()}`);
      renameSync(finalPath, quarantinePath);
      fsyncDirectory(this.releaseRoot);
      fsyncDirectory(this.quarantineRoot);
      throw new ReleaseContentError('release_artifact_invalid', 'existing content-addressed release conflicted with expected manifest and was quarantined', { finalPath, quarantinePath, verification });
    }
    const staging = join(this.releaseRoot, `.staging-${request.artifactSha256}-${randomUUID()}`);
    extractValidatedEntries(entries, staging, this.archiveLimits);
    const beforeImmutable = this.verifyExistingMaterialization(staging, entries);
    if (beforeImmutable.expectedDigest !== beforeImmutable.observedDigest) {
      rmSync(staging, { recursive: true, force: true });
      throw new ReleaseContentError('release_artifact_invalid', 'materialized tree did not match artifact manifest', { verification: beforeImmutable });
    }
    makeImmutableTree(staging);
    const immutable = this.verifyExistingMaterialization(staging, entries);
    if (immutable.valid !== true) {
      rmSync(staging, { recursive: true, force: true });
      throw new ReleaseContentError('release_artifact_invalid', 'materialized tree is not immutable or digest-valid', { verification: immutable });
    }
    atomicPromoteDirectory(staging, finalPath);
    const finalVerification = this.verifyExistingMaterialization(finalPath, entries);
    if (finalVerification.valid !== true) throw new ReleaseContentError('release_artifact_invalid', 'final release verification failed after atomic promotion', { finalPath, finalVerification });
    return { materialized: true, reused: false, path: finalPath, verification: finalVerification };
  }

  createReleaseRecord(input: JsonObject): JsonObject {
    const serviceId = ensureIdentifier(String(input.serviceId), 'serviceId');
    const artifactId = ensureIdentifier(String(input.artifactId), 'artifactId');
    const artifactSha256 = ensureDigest(String(input.artifactSha256), 'artifactSha256');
    const releaseId = `release_${sha256(canonicalize({ serviceId, artifactSha256 })).slice(0, 40)}`;
    const record = validateReleaseRecord('ReleaseRecordV1', {
      schemaVersion: '1.0.0',
      releaseId,
      serviceId,
      artifactId,
      artifactSha256,
      artifactSizeBytes: finiteNonNegativeInteger(Number(input.artifactSizeBytes), 'artifactSizeBytes'),
      manifestDigest: ensureDigest(String(input.manifestDigest), 'manifestDigest'),
      sourceCommit: ensureGitSha(String(input.sourceCommit), 'sourceCommit'),
      sourceTree: ensureGitSha(String(input.sourceTree), 'sourceTree'),
      lockfileDigest: ensureDigest(String(input.lockfileDigest), 'lockfileDigest'),
      buildId: ensureIdentifier(String(input.buildId), 'buildId'),
      certificationId: ensureIdentifier(String(input.certificationId), 'certificationId'),
      materializationPath: ensureWithin(this.releaseRoot, String(input.materializationPath), 'materializationPath'),
      materializationMethod: String(input.materializationMethod),
      materializationVerifiedAt: String(input.materializationVerifiedAt),
      installedManifestDigest: ensureDigest(String(input.installedManifestDigest), 'installedManifestDigest'),
      immutablePermissionsVerified: input.immutablePermissionsVerified === true,
      credentialSetReferenceDigest: ensureDigest(String(input.credentialSetReferenceDigest), 'credentialSetReferenceDigest'),
      compatibleApplianceVersion: String(input.compatibleApplianceVersion),
      retentionClass: String(input.retentionClass ?? 'RECENT'),
      pinned: input.pinned === true,
      slotReferences: sortedStringArray(input.slotReferences ?? [], 'slotReferences'),
      deploymentReferences: sortedStringArray(input.deploymentReferences ?? [], 'deploymentReferences'),
      integrityState: String(input.integrityState ?? 'VERIFIED'),
      createdAt: String(input.createdAt ?? this.now()),
    });
    return this.store.applyMutation({
      schemaId: 'ReleaseRecordV1',
      recordId: releaseId,
      ownerPrincipal: ensureIdentifier(String(input.ownerPrincipal), 'ownerPrincipal'),
      expectedSequence: 0,
      idempotencyKey: ensureIdentifier(String(input.idempotencyKey), 'idempotencyKey'),
      requestDigest: sha256(canonicalize(record)),
      operation: 'babyx.release.record.create',
      phase: 'release-record',
      record,
      occurredAt: String(record.createdAt),
      artifactReferences: [{ artifactId, artifactSha256 }],
      receiptReferences: sortedStringArray(input.receiptReferences ?? [], 'receiptReferences'),
    });
  }
}
