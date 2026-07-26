import { spawnSync } from 'node:child_process';
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  readdirSync,
  readlinkSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, normalize, resolve, sep } from 'node:path';
import { randomUUID } from 'node:crypto';
import { canonicalize, sha256, type JobRecord, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { processIdentity, type ProcessIdentityRecord } from '../process/identity.ts';
import { SystemdManager } from '../systemd/manager.ts';
import { assertNoRawSecrets, boundedReleaseError, validateReleaseRecord } from './schemas.ts';
import { assertReleaseTransition } from './compatibility.ts';
import { validateServiceDefinition } from './content.ts';
import { ReleaseApplianceStore, ReleaseStoreError } from './store.ts';

export const SLOT_RUNTIME_CONTRACT_VERSION = '1.0.0' as const;
export const SLOT_IDS = ['blue', 'green'] as const;
export type SlotId = typeof SLOT_IDS[number];
export type SlotEndpointType = 'UNIX_SOCKET' | 'LOOPBACK_TCP';

const IDENTIFIER = /^[a-z0-9][a-z0-9.-]{0,63}$/u;
const USER = /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const UNIT = /^[A-Za-z0-9_.@:-]+\.service$/u;
const MAX_OBSERVATIONS = 256;

export class SlotRuntimeError extends Error {
  constructor(readonly code: string, message: string, readonly details: JsonObject = {}, readonly phase?: string) {
    super(message);
    this.name = 'SlotRuntimeError';
  }
}

export interface SlotProcessIdentity extends JsonObject {
  serviceId: string;
  slotId: SlotId;
  releaseId: string;
  artifactDigest: string;
  ownerPrincipal: string;
  unitName: string;
  unitGenerationDigest: string;
  mainPid: number;
  processStartTime: string;
  executablePath: string;
  bootId: string;
  cgroup: string;
  systemdUnit: string;
  endpointType: SlotEndpointType;
  endpoint: string;
  listenerOwner: JsonObject;
  readinessState: 'READY' | 'NOT_READY' | 'UNKNOWN';
  watchdogState: 'ACTIVE' | 'INACTIVE' | 'UNSUPPORTED' | 'UNKNOWN';
}

export interface SlotUnitBundle extends JsonObject {
  serviceId: string;
  slotId: SlotId;
  unitName: string;
  unitBytes: string;
  dropInBytes: string;
  unitDigest: string;
  dropInDigest: string;
  unitGenerationDigest: string;
  releaseRoot: string;
  runtimeRoot: string;
  stateRoot: string;
  cacheRoot: string;
  logRoot: string;
  endpointType: SlotEndpointType;
  endpoint: string;
  serviceUser: string;
  serviceGroup: string;
  executablePath: string;
  nativeReadiness: boolean;
  nativeWatchdog: boolean;
}

export interface SlotUnitObservation extends JsonObject {
  observedAt: string;
  unitExists: boolean;
  activeState: string;
  subState: string;
  unitName: string;
  unitDigest?: string;
  dropInDigest?: string;
  mainPid?: number;
  processStartTime?: string;
  executablePath?: string;
  bootId?: string;
  cgroup?: string;
  endpointExists: boolean;
  endpointOwner?: JsonObject;
  runtimePathExists: boolean;
  transientUnitExists: boolean;
  readinessState: 'READY' | 'NOT_READY' | 'UNKNOWN';
  watchdogState: 'ACTIVE' | 'INACTIVE' | 'UNSUPPORTED' | 'UNKNOWN';
}

export interface SlotValidationResult extends JsonObject {
  valid: boolean;
  validator: string;
  version: string;
  digest: string;
  diagnostics: string[];
}

export interface SlotSystemdAdapter {
  readonly authority: 'slot-systemd-adapter';
  validate(bundle: SlotUnitBundle): Promise<SlotValidationResult>;
  install(bundle: SlotUnitBundle): Promise<JsonObject>;
  start(bundle: SlotUnitBundle): Promise<JsonObject>;
  stop(bundle: SlotUnitBundle): Promise<JsonObject>;
  cleanup(bundle: SlotUnitBundle): Promise<JsonObject>;
  observe(bundle: SlotUnitBundle): Promise<SlotUnitObservation>;
  waitReady(bundle: SlotUnitBundle, policy: ReadinessPolicy): Promise<SlotUnitObservation[]>;
}

export interface ReadinessPolicy extends JsonObject {
  mode: 'NATIVE_NOTIFY' | 'POLL';
  timeoutMs: number;
  intervalMs: number;
  maximumSamples: number;
}

export interface SlotJobAuthority {
  get(id: string): JobRecord;
}

export interface SlotRuntimeServiceOptions {
  stateRoot: string;
  store: ReleaseApplianceStore;
  jobs: SlotJobAuthority;
  systemd: SlotSystemdAdapter;
  now?: () => string;
}

interface NormalizedService {
  record: JsonObject;
  digest: string;
  serviceId: string;
  ownerPrincipal: string;
  serviceUser: string;
  serviceGroup: string;
  argv: string[];
  executablePath: string;
  workingDirectory: string;
  endpointPreference: SlotEndpointType;
  allowLoopbackFallback: boolean;
  nativeReadiness: boolean;
  nativeWatchdog: boolean;
  readinessPolicy: ReadinessPolicy;
  resourceClass: 'PRODUCTION' | 'BACKGROUND';
  stateDirectories: string[];
  cacheDirectories: string[];
  logDirectories: string[];
  runtimeDirectories: string[];
}

function object(value: unknown, field: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new SlotRuntimeError('release_invalid_request', `${field} must be an object`);
  return value as JsonObject;
}

function text(value: unknown, field: string, maximum = 4096): string {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || Buffer.byteLength(value) > maximum) throw new SlotRuntimeError('release_invalid_request', `${field} must be a bounded non-empty NUL-free string`);
  return value;
}

function identifier(value: unknown, field: string): string {
  const result = text(value, field, 64);
  if (!IDENTIFIER.test(result) || result === '.' || result === '..') throw new SlotRuntimeError('release_invalid_request', `${field} must be a lowercase bounded identifier`);
  return result;
}

function user(value: unknown, field: string): string {
  const result = text(value, field, 64);
  if (!USER.test(result) || result.startsWith('-')) throw new SlotRuntimeError('release_invalid_request', `${field} must be a safe service identity`);
  return result;
}

function digest(value: unknown, field: string): string {
  const result = text(value, field, 64);
  if (!DIGEST.test(result)) throw new SlotRuntimeError('release_invalid_request', `${field} must be a lowercase SHA-256 digest`);
  return result;
}

function integer(value: unknown, field: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new SlotRuntimeError('release_invalid_request', `${field} must be an integer between ${minimum} and ${maximum}`);
  return Number(value);
}

function boolean(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') throw new SlotRuntimeError('release_invalid_request', `${field} must be boolean`);
  return value;
}

function safeAbsolute(value: unknown, field: string): string {
  const result = text(value, field);
  if (!result.startsWith('/') || normalize(result) !== result || result.includes('/../') || result.endsWith('/..')) throw new SlotRuntimeError('release_invalid_request', `${field} must be a normalized absolute path`);
  return result;
}

function safeRelative(value: unknown, field: string): string {
  const result = text(value, field);
  const normalized = normalize(result);
  if (result.startsWith('/') || normalized === '..' || normalized.startsWith(`..${sep}`)) throw new SlotRuntimeError('release_invalid_request', `${field} must be a relative path`);
  return normalized === '.' ? '' : normalized;
}

function stringArray(value: unknown, field: string, maximum = 128): string[] {
  if (!Array.isArray(value) || value.length > maximum) throw new SlotRuntimeError('release_invalid_request', `${field} must be a bounded string array`);
  return [...new Set(value.map((entry, index) => safeRelative(entry, `${field}[${index}]`)))].sort();
}

function slotId(value: unknown): SlotId {
  if (value !== 'blue' && value !== 'green') throw new SlotRuntimeError('release_invalid_request', 'slotId must be blue or green');
  return value;
}

function exactContext(context: RuntimeExecutionContext): { subject: string; idempotencyKey: string } {
  return { subject: identifier(context.subject, 'context.subject'), idempotencyKey: identifier(context.idempotencyKey, 'context.idempotencyKey') };
}

function ownerFromEvents(store: ReleaseApplianceStore, schemaId: string, recordId: string): string | undefined {
  const event = store.events(schemaId, recordId, 0, 1).at(0);
  return typeof event?.ownerPrincipal === 'string' ? event.ownerPrincipal : undefined;
}

function strictReadPayload(payload: JsonObject, allowed: readonly string[]): void {
  const unknown = Object.keys(payload).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw new SlotRuntimeError('release_invalid_request', `unsupported read property: ${unknown.sort()[0]}`);
}

function stablePort(serviceId: string, slot: SlotId, base = 20_000, span = 20_000): number {
  const value = Number.parseInt(sha256(`${serviceId}:${slot}`).slice(0, 8), 16);
  return base + (value % span);
}

function systemdQuote(value: string): string {
  if (value.includes('\0') || value.includes('\n') || value.includes('\r')) throw new SlotRuntimeError('release_invalid_request', 'systemd value contains prohibited control characters');
  return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('%', '%%')}"`;
}

function unitName(serviceId: string, slot: SlotId): string {
  const result = `babyx-release-${identifier(serviceId, 'serviceId')}-${slot}.service`;
  if (!UNIT.test(result)) throw new SlotRuntimeError('release_unit_invalid', 'generated unit name is invalid');
  return result;
}

function ensureUnder(root: string, candidate: string, field: string): string {
  const resolvedRoot = resolve(root);
  const resolved = resolve(candidate);
  if (resolved !== resolvedRoot && !resolved.startsWith(`${resolvedRoot}${sep}`)) throw new SlotRuntimeError('release_path_outside_authority', `${field} escapes its authority root`);
  return resolved;
}

function normalizeService(value: unknown): NormalizedService {
  const { record, digest: manifestDigest } = validateServiceDefinition(value);
  assertNoRawSecrets(record);
  const serviceId = identifier(record.serviceId, 'serviceId');
  const ownerPrincipal = identifier(record.ownerPrincipal, 'ownerPrincipal');
  const runtimeIdentity = object(record.runtimeIdentity, 'runtimeIdentity');
  const executableContract = object(record.executableContract, 'executableContract');
  const endpointPolicy = object(record.endpointPolicy, 'endpointPolicy');
  const readinessProbe = object(record.readinessProbe, 'readinessProbe');
  const resourceProfile = object(record.resourceProfile, 'resourceProfile');
  const argvValue = executableContract.argv;
  if (!Array.isArray(argvValue) || argvValue.length === 0 || argvValue.length > 128) throw new SlotRuntimeError('release_invalid_request', 'executableContract.argv must be a non-empty bounded array');
  const argv = argvValue.map((entry, index) => text(entry, `executableContract.argv[${index}]`));
  const executablePath = safeAbsolute(argv[0], 'executableContract.argv[0]');
  const endpointPreference = record.endpointPreference === 'UNIX_SOCKET' ? 'UNIX_SOCKET' : record.endpointPreference === 'LOOPBACK_TCP' ? 'LOOPBACK_TCP' : (() => { throw new SlotRuntimeError('release_invalid_request', 'endpointPreference is invalid'); })();
  const readinessMode = readinessProbe.mode === 'NATIVE_NOTIFY' ? 'NATIVE_NOTIFY' : readinessProbe.mode === 'POLL' ? 'POLL' : (() => { throw new SlotRuntimeError('release_invalid_request', 'readinessProbe.mode is invalid'); })();
  const serviceUser = user(runtimeIdentity.serviceUser, 'runtimeIdentity.serviceUser');
  const serviceGroup = user(runtimeIdentity.serviceGroup, 'runtimeIdentity.serviceGroup');
  const nativeReadiness = executableContract.nativeReadiness === undefined ? false : boolean(executableContract.nativeReadiness, 'executableContract.nativeReadiness');
  const nativeWatchdog = executableContract.nativeWatchdog === undefined ? false : boolean(executableContract.nativeWatchdog, 'executableContract.nativeWatchdog');
  if (readinessMode === 'NATIVE_NOTIFY' && !nativeReadiness) throw new SlotRuntimeError('release_invalid_request', 'native readiness cannot be requested when the executable does not support it');
  const resourceClass = resourceProfile.class === 'BACKGROUND' ? 'BACKGROUND' : resourceProfile.class === 'PRODUCTION' ? 'PRODUCTION' : (() => { throw new SlotRuntimeError('release_invalid_request', 'resourceProfile.class is invalid'); })();
  return {
    record,
    digest: manifestDigest,
    serviceId,
    ownerPrincipal,
    serviceUser,
    serviceGroup,
    argv,
    executablePath,
    workingDirectory: safeRelative(record.workingDirectory, 'workingDirectory'),
    endpointPreference,
    allowLoopbackFallback: endpointPolicy.allowLoopbackFallback === undefined ? false : boolean(endpointPolicy.allowLoopbackFallback, 'endpointPolicy.allowLoopbackFallback'),
    nativeReadiness,
    nativeWatchdog,
    readinessPolicy: {
      mode: readinessMode,
      timeoutMs: integer(readinessProbe.timeoutMs, 'readinessProbe.timeoutMs', 1, 300_000),
      intervalMs: integer(readinessProbe.intervalMs, 'readinessProbe.intervalMs', 1, 60_000),
      maximumSamples: integer(readinessProbe.maximumSamples, 'readinessProbe.maximumSamples', 1, MAX_OBSERVATIONS),
    },
    resourceClass,
    stateDirectories: stringArray(record.stateDirectories, 'stateDirectories'),
    cacheDirectories: stringArray(record.cacheDirectories, 'cacheDirectories'),
    logDirectories: stringArray(record.logDirectories, 'logDirectories'),
    runtimeDirectories: stringArray(record.runtimeDirectories, 'runtimeDirectories'),
  };
}

export function normalizeServiceDefinition(value: unknown): JsonObject {
  const service = normalizeService(value);
  return { ...service.record, manifestDigest: service.digest };
}

export function generateSlotUnit(serviceValue: unknown, slotValue: unknown, release: JsonObject, roots: JsonObject): SlotUnitBundle {
  const service = normalizeService(serviceValue);
  const slot = slotId(slotValue);
  const releaseId = identifier(release.releaseId, 'release.releaseId');
  const artifactDigest = digest(release.artifactSha256, 'release.artifactSha256');
  const releaseRootBase = safeAbsolute(roots.releaseRoot, 'roots.releaseRoot');
  const runtimeRootBase = safeAbsolute(roots.runtimeRoot, 'roots.runtimeRoot');
  const stateRootBase = safeAbsolute(roots.stateRoot, 'roots.stateRoot');
  const cacheRootBase = safeAbsolute(roots.cacheRoot, 'roots.cacheRoot');
  const logRootBase = safeAbsolute(roots.logRoot, 'roots.logRoot');
  const releaseRoot = ensureUnder(releaseRootBase, join(releaseRootBase, releaseId), 'releaseRoot');
  const runtimeRoot = ensureUnder(runtimeRootBase, join(runtimeRootBase, service.serviceId, slot), 'runtimeRoot');
  const stateRoot = ensureUnder(stateRootBase, join(stateRootBase, service.serviceId, slot), 'stateRoot');
  const cacheRoot = ensureUnder(cacheRootBase, join(cacheRootBase, service.serviceId, slot), 'cacheRoot');
  const logRoot = ensureUnder(logRootBase, join(logRootBase, service.serviceId, slot), 'logRoot');
  const name = unitName(service.serviceId, slot);
  const requestedEndpoint = roots.endpointMode;
  const endpointType: SlotEndpointType = requestedEndpoint === undefined
    ? service.endpointPreference
    : requestedEndpoint === 'UNIX_SOCKET' || requestedEndpoint === 'LOOPBACK_TCP'
      ? requestedEndpoint
      : (() => { throw new SlotRuntimeError('release_invalid_request', 'roots.endpointMode is invalid'); })();
  if (endpointType === 'LOOPBACK_TCP' && service.endpointPreference === 'UNIX_SOCKET' && !service.allowLoopbackFallback) throw new SlotRuntimeError('release_invalid_request', 'loopback fallback is not permitted by service policy');
  const endpoint = endpointType === 'UNIX_SOCKET'
    ? ensureUnder(runtimeRoot, join(runtimeRoot, 'application.sock'), 'endpoint')
    : `127.0.0.1:${stablePort(service.serviceId, slot)}`;
  const workingDirectory = service.workingDirectory.length === 0 ? releaseRoot : ensureUnder(releaseRoot, join(releaseRoot, service.workingDirectory), 'workingDirectory');
  const environment = [
    `BABYX_SERVICE_ID=${service.serviceId}`,
    `BABYX_SLOT_ID=${slot}`,
    `BABYX_RELEASE_ID=${releaseId}`,
    `BABYX_ARTIFACT_SHA256=${artifactDigest}`,
    `BABYX_ENDPOINT_TYPE=${endpointType}`,
    `BABYX_ENDPOINT=${endpoint}`,
  ].sort();
  const writable = [runtimeRoot, stateRoot, cacheRoot, logRoot].sort();
  const unitLines = [
    '[Unit]',
    `Description=Baby-X release ${service.serviceId} ${slot}`,
    'After=network.target',
    '',
    '[Service]',
    `Type=${service.nativeReadiness ? 'notify' : 'simple'}`,
    `User=${service.serviceUser}`,
    `Group=${service.serviceGroup}`,
    `WorkingDirectory=${systemdQuote(workingDirectory)}`,
    `ExecStart=${service.argv.map(systemdQuote).join(' ')}`,
    `Slice=${service.resourceClass === 'PRODUCTION' ? 'babyx-production.slice' : 'babyx-background.slice'}`,
    'NoNewPrivileges=yes',
    'PrivateTmp=yes',
    'ProtectSystem=strict',
    'ProtectHome=yes',
    `ReadOnlyPaths=${systemdQuote(releaseRoot)}`,
    `ReadWritePaths=${writable.map(systemdQuote).join(' ')}`,
    'Restart=on-failure',
    'RestartSec=2s',
    'KillMode=control-group',
    'TimeoutStopSec=45s',
    ...(service.nativeReadiness ? ['NotifyAccess=main'] : []),
    ...(service.nativeWatchdog ? ['WatchdogSec=30s'] : []),
    'StandardOutput=journal',
    'StandardError=journal',
    '',
    '[Install]',
    'WantedBy=multi-user.target',
    '',
  ];
  const dropInLines = [
    '[Service]',
    ...environment.map((entry) => `Environment=${systemdQuote(entry)}`),
    `RuntimeDirectoryMode=0750`,
    `StateDirectoryMode=0750`,
    `CacheDirectoryMode=0750`,
    `LogsDirectoryMode=0750`,
    '',
  ];
  const unitBytes = unitLines.join('\n');
  const dropInBytes = dropInLines.join('\n');
  const unitDigest = sha256(unitBytes);
  const dropInDigest = sha256(dropInBytes);
  return {
    serviceId: service.serviceId,
    slotId: slot,
    unitName: name,
    unitBytes,
    dropInBytes,
    unitDigest,
    dropInDigest,
    unitGenerationDigest: sha256(canonicalize({ contract: SLOT_RUNTIME_CONTRACT_VERSION, unitDigest, dropInDigest, releaseId, artifactDigest, endpointType, endpoint })),
    releaseRoot,
    runtimeRoot,
    stateRoot,
    cacheRoot,
    logRoot,
    endpointType,
    endpoint,
    serviceUser: service.serviceUser,
    serviceGroup: service.serviceGroup,
    executablePath: service.executablePath,
    nativeReadiness: service.nativeReadiness,
    nativeWatchdog: service.nativeWatchdog,
  };
}

function durableReplace(path: string, bytes: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const descriptor = openSync(temporary, 'wx', 0o600);
  try {
    writeFileSync(descriptor, bytes, { encoding: 'utf8' });
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  renameSync(temporary, path);
  const directory = openSync(dirname(path), 'r');
  try { fsyncSync(directory); } finally { closeSync(directory); }
}

function decodeCommandOutput(value: string): string {
  try { return Buffer.from(value, 'base64').toString('utf8'); } catch { return ''; }
}

function parseProperties(output: string): Record<string, string> {
  return Object.fromEntries(output.split(/\r?\n/u).filter(Boolean).map((line) => {
    const index = line.indexOf('=');
    return index < 0 ? [line, ''] : [line.slice(0, index), line.slice(index + 1)];
  }));
}

function processSocketInodes(pid: number): Set<string> {
  const result = new Set<string>();
  let names: string[] = [];
  try { names = readdirSync(`/proc/${pid}/fd`).slice(0, 4096); } catch { return result; }
  for (const name of names) {
    try {
      const target = readlinkSync(`/proc/${pid}/fd/${name}`);
      const match = /^socket:\[([0-9]+)\]$/u.exec(target);
      if (match !== null) result.add(match[1]);
    } catch { /* descriptor raced with observation */ }
  }
  return result;
}

function tcpListeners(port: number): string[] {
  const hexadecimalPort = port.toString(16).toUpperCase().padStart(4, '0');
  const result: string[] = [];
  for (const path of ['/proc/net/tcp', '/proc/net/tcp6']) {
    let lines: string[] = [];
    try { lines = readFileSync(path, 'utf8').split(/\r?\n/u).slice(1, 65537); } catch { continue; }
    for (const line of lines) {
      const fields = line.trim().split(/\s+/u);
      if (fields.length < 10 || fields[3] !== '0A') continue;
      const local = fields[1]?.split(':');
      if (local?.[1] !== hexadecimalPort) continue;
      const address = local[0];
      if (address !== '0100007F' && address !== '0000000000000000FFFF00000100007F') continue;
      result.push(fields[9]);
    }
  }
  return [...new Set(result)].sort();
}

function observeEndpoint(bundle: SlotUnitBundle, mainPid: number): { exists: boolean; owner?: JsonObject } {
  const ownedInodes = mainPid > 0 ? processSocketInodes(mainPid) : new Set<string>();
  if (bundle.endpointType === 'UNIX_SOCKET') {
    if (!existsSync(bundle.endpoint)) return { exists: false };
    let inode = '';
    let socket = false;
    try {
      const stat = lstatSync(bundle.endpoint);
      inode = String(stat.ino);
      socket = stat.isSocket();
    } catch { return { exists: false }; }
    if (!socket) return { exists: true, owner: { pid: 0, unitName: 'UNKNOWN', serviceId: 'UNKNOWN', slotId: 'UNKNOWN', inode, kind: 'FOREIGN_PATH' } };
    if (ownedInodes.has(inode)) return { exists: true, owner: { pid: mainPid, unitName: bundle.unitName, serviceId: bundle.serviceId, slotId: bundle.slotId, inode, kind: 'UNIX_SOCKET' } };
    return { exists: true, owner: { pid: 0, unitName: 'UNKNOWN', serviceId: 'UNKNOWN', slotId: 'UNKNOWN', inode, kind: 'FOREIGN_SOCKET' } };
  }
  const match = /^127\.0\.0\.1:([0-9]+)$/u.exec(bundle.endpoint);
  if (match === null) return { exists: true, owner: { pid: 0, unitName: 'UNKNOWN', serviceId: 'UNKNOWN', slotId: 'UNKNOWN', kind: 'INVALID_LOOPBACK_ENDPOINT' } };
  const inodes = tcpListeners(Number(match[1]));
  if (inodes.length === 0) return { exists: false };
  const owned = inodes.find((inode) => ownedInodes.has(inode));
  if (owned !== undefined) return { exists: true, owner: { pid: mainPid, unitName: bundle.unitName, serviceId: bundle.serviceId, slotId: bundle.slotId, inode: owned, kind: 'LOOPBACK_TCP' } };
  return { exists: true, owner: { pid: 0, unitName: 'UNKNOWN', serviceId: 'UNKNOWN', slotId: 'UNKNOWN', inodes, kind: 'FOREIGN_LOOPBACK_LISTENER' } };
}

export class HostSystemdSlotAdapter implements SlotSystemdAdapter {
  readonly authority = 'slot-systemd-adapter' as const;
  private readonly manager: SystemdManager;
  private readonly unitRoot: string;
  private readonly validationRoot: string;
  private readonly liveActions: boolean;
  private readonly now: () => string;

  constructor(options: { manager?: SystemdManager; unitRoot: string; validationRoot: string; liveActions?: boolean; now?: () => string }) {
    this.manager = options.manager ?? new SystemdManager();
    this.unitRoot = resolve(options.unitRoot);
    this.validationRoot = resolve(options.validationRoot);
    this.liveActions = options.liveActions === true;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  async validate(bundle: SlotUnitBundle): Promise<SlotValidationResult> {
    if (!UNIT.test(bundle.unitName) || sha256(bundle.unitBytes) !== bundle.unitDigest || sha256(bundle.dropInBytes) !== bundle.dropInDigest) throw new SlotRuntimeError('release_unit_invalid', 'unit bundle identity is invalid');
    mkdirSync(this.validationRoot, { recursive: true, mode: 0o700 });
    const root = join(this.validationRoot, bundle.unitGenerationDigest);
    const unitPath = join(root, bundle.unitName);
    const dropInPath = join(root, `${bundle.unitName}.d`, '10-babyx-release.conf');
    rmSync(root, { recursive: true, force: true });
    durableReplace(unitPath, bundle.unitBytes);
    durableReplace(dropInPath, bundle.dropInBytes);
    const result = spawnSync('/usr/bin/systemd-analyze', ['verify', unitPath], { encoding: 'utf8', timeout: 30_000, maxBuffer: 4 * 1024 * 1024 });
    const diagnostics = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.split(/\r?\n/u).filter(Boolean).slice(0, 128).map((line) => line.slice(0, 1024));
    rmSync(root, { recursive: true, force: true });
    return { valid: result.status === 0, validator: '/usr/bin/systemd-analyze verify', version: SLOT_RUNTIME_CONTRACT_VERSION, digest: sha256(canonicalize({ status: result.status, diagnostics })), diagnostics };
  }

  async install(bundle: SlotUnitBundle): Promise<JsonObject> {
    if (!this.liveActions) throw new SlotRuntimeError('release_provider_unavailable', 'live systemd mutation is disabled for this adapter');
    const unitPath = ensureUnder(this.unitRoot, join(this.unitRoot, bundle.unitName), 'unitPath');
    const dropInPath = ensureUnder(this.unitRoot, join(this.unitRoot, `${bundle.unitName}.d`, '10-babyx-release.conf'), 'dropInPath');
    for (const path of [bundle.runtimeRoot, bundle.stateRoot, bundle.cacheRoot, bundle.logRoot]) mkdirSync(path, { recursive: true, mode: 0o750 });
    durableReplace(unitPath, bundle.unitBytes);
    durableReplace(dropInPath, bundle.dropInBytes);
    const reload = await this.manager.daemonReload({ timeoutMs: 30_000 });
    if (reload.exitCode !== 0) throw new SlotRuntimeError('release_unit_invalid', 'systemd daemon reload failed', { stderrDigest: reload.stderrSha256 });
    return { installed: true, unitPath, dropInPath, unitDigest: bundle.unitDigest, dropInDigest: bundle.dropInDigest };
  }

  async start(bundle: SlotUnitBundle): Promise<JsonObject> {
    if (!this.liveActions) throw new SlotRuntimeError('release_provider_unavailable', 'live systemd mutation is disabled for this adapter');
    const result = await this.manager.action('start', { unit: bundle.unitName, timeoutMs: 60_000 });
    if (result.exitCode !== 0) throw new SlotRuntimeError('release_start_failed', 'systemd start failed', { stderrDigest: result.stderrSha256 });
    return { accepted: true, responseDigest: sha256(canonicalize(result)) };
  }

  async stop(bundle: SlotUnitBundle): Promise<JsonObject> {
    if (!this.liveActions) throw new SlotRuntimeError('release_provider_unavailable', 'live systemd mutation is disabled for this adapter');
    const result = await this.manager.action('stop', { unit: bundle.unitName, timeoutMs: 60_000 });
    if (result.exitCode !== 0) throw new SlotRuntimeError('release_cleanup_failed', 'systemd stop failed', { stderrDigest: result.stderrSha256 });
    return { accepted: true, responseDigest: sha256(canonicalize(result)) };
  }

  async cleanup(bundle: SlotUnitBundle): Promise<JsonObject> {
    if (!this.liveActions) throw new SlotRuntimeError('release_provider_unavailable', 'live systemd mutation is disabled for this adapter');
    const unitPath = ensureUnder(this.unitRoot, join(this.unitRoot, bundle.unitName), 'unitPath');
    const dropInRoot = ensureUnder(this.unitRoot, join(this.unitRoot, `${bundle.unitName}.d`), 'dropInRoot');
    rmSync(unitPath, { force: true });
    rmSync(dropInRoot, { recursive: true, force: true });
    for (const path of [bundle.runtimeRoot, bundle.stateRoot, bundle.cacheRoot, bundle.logRoot]) rmSync(path, { recursive: true, force: true });
    const reload = await this.manager.daemonReload({ timeoutMs: 30_000 });
    if (reload.exitCode !== 0) throw new SlotRuntimeError('release_cleanup_failed', 'systemd daemon reload failed during cleanup', { stderrDigest: reload.stderrSha256 });
    return { removed: true };
  }

  async observe(bundle: SlotUnitBundle): Promise<SlotUnitObservation> {
    const show = await this.manager.show({ unit: bundle.unitName, properties: ['LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlGroup', 'FragmentPath', 'DropInPaths'], timeoutMs: 30_000 });
    const properties = show.exitCode === 0 ? parseProperties(decodeCommandOutput(show.stdout)) : {};
    const unitExists = properties.LoadState !== undefined && properties.LoadState !== 'not-found';
    const mainPid = Number(properties.MainPID ?? 0);
    let identity: ProcessIdentityRecord | undefined;
    if (mainPid > 0) {
      try { identity = processIdentity(mainPid); } catch { identity = undefined; }
    }
    const endpointObservation = observeEndpoint(bundle, mainPid);
    const endpointExists = endpointObservation.exists;
    const endpointOwner = endpointObservation.owner;
    const fragment = properties.FragmentPath;
    const observedUnitDigest = typeof fragment === 'string' && fragment.startsWith('/') && existsSync(fragment) ? sha256(readFileSync(fragment)) : undefined;
    let observedDropInDigest: string | undefined;
    const dropIn = properties.DropInPaths?.split(' ').find((path) => path.endsWith('10-babyx-release.conf'));
    if (dropIn !== undefined && existsSync(dropIn)) observedDropInDigest = sha256(readFileSync(dropIn));
    return {
      observedAt: this.now(),
      unitExists,
      activeState: properties.ActiveState ?? 'unknown',
      subState: properties.SubState ?? 'unknown',
      unitName: bundle.unitName,
      ...(observedUnitDigest === undefined ? {} : { unitDigest: observedUnitDigest }),
      ...(observedDropInDigest === undefined ? {} : { dropInDigest: observedDropInDigest }),
      ...(mainPid > 0 ? { mainPid } : {}),
      ...(identity === undefined ? {} : { processStartTime: identity.processStartTime, executablePath: identity.executablePath, bootId: identity.bootId }),
      ...(properties.ControlGroup === undefined ? {} : { cgroup: properties.ControlGroup }),
      endpointExists,
      ...(endpointOwner === undefined ? {} : { endpointOwner }),
      runtimePathExists: existsSync(bundle.runtimeRoot),
      transientUnitExists: false,
      readinessState: properties.ActiveState === 'active' && properties.SubState === 'running' ? 'READY' : properties.ActiveState === 'active' ? 'NOT_READY' : 'UNKNOWN',
      watchdogState: bundle.nativeWatchdog ? (properties.ActiveState === 'active' ? 'ACTIVE' : 'UNKNOWN') : 'UNSUPPORTED',
    };
  }

  async waitReady(bundle: SlotUnitBundle, policy: ReadinessPolicy): Promise<SlotUnitObservation[]> {
    const started = Date.now();
    const observations: SlotUnitObservation[] = [];
    while (observations.length < policy.maximumSamples && Date.now() - started <= policy.timeoutMs) {
      const observation = await this.observe(bundle);
      observations.push(observation);
      if (observation.readinessState === 'READY') return observations;
      if (observation.activeState === 'failed' || observation.activeState === 'inactive') return observations;
      await new Promise<void>((resolvePromise) => setTimeout(resolvePromise, policy.intervalMs));
    }
    return observations;
  }
}

function bundleFromRecord(record: JsonObject): SlotUnitBundle {
  const bundle = object(record.unitBundle, 'slot.unitBundle');
  return bundle as SlotUnitBundle;
}

function replayByKey(store: ReleaseApplianceStore, schemaId: string, recordId: string, key: string, requestDigest: string): JsonObject | undefined {
  const event = store.events(schemaId, recordId, 0, 10_000).find((candidate) => candidate.idempotencyKey === key);
  if (event === undefined) return undefined;
  if (event.requestDigest !== requestDigest) throw new SlotRuntimeError('release_idempotency_conflict', 'idempotency key was reused with a different normalized request');
  return store.getRecord(schemaId, recordId);
}

function exactObservation(bundle: SlotUnitBundle, record: JsonObject, observation: SlotUnitObservation): SlotProcessIdentity {
  const expected = object(record.expectedProcessIdentity, 'slot.expectedProcessIdentity');
  const conflicts: string[] = [];
  if (!observation.unitExists || observation.unitName !== bundle.unitName) conflicts.push('unit');
  if (observation.unitDigest !== bundle.unitDigest || observation.dropInDigest !== bundle.dropInDigest) conflicts.push('unit-bytes');
  if (!Number.isSafeInteger(observation.mainPid) || Number(observation.mainPid) < 1) conflicts.push('main-pid');
  if (observation.processStartTime !== expected.processStartTime) conflicts.push('process-start-time');
  if (observation.executablePath !== bundle.executablePath) conflicts.push('executable');
  if (observation.bootId !== expected.bootId) conflicts.push('boot-id');
  if (observation.cgroup !== expected.cgroup) conflicts.push('cgroup');
  if (!observation.endpointExists) conflicts.push('endpoint-absent');
  const endpointOwner = observation.endpointOwner;
  if (endpointOwner === undefined) conflicts.push('endpoint-owner-missing');
  else {
    if (endpointOwner.pid !== observation.mainPid) conflicts.push('endpoint-owner-pid');
    if (endpointOwner.unitName !== bundle.unitName) conflicts.push('endpoint-owner-unit');
    if (endpointOwner.serviceId !== bundle.serviceId) conflicts.push('endpoint-owner-service');
    if (endpointOwner.slotId !== bundle.slotId) conflicts.push('endpoint-owner-slot');
  }
  if (conflicts.length > 0) throw new SlotRuntimeError('release_process_ambiguous', 'observed slot identity conflicts with the durable expected identity', { conflicts });
  return {
    serviceId: String(record.serviceId),
    slotId: record.slotId as SlotId,
    releaseId: String(record.releaseId),
    artifactDigest: String(expected.artifactDigest),
    ownerPrincipal: String(expected.ownerPrincipal),
    unitName: bundle.unitName,
    unitGenerationDigest: bundle.unitGenerationDigest,
    mainPid: Number(observation.mainPid),
    processStartTime: String(observation.processStartTime),
    executablePath: String(observation.executablePath),
    bootId: String(observation.bootId),
    cgroup: String(observation.cgroup),
    systemdUnit: bundle.unitName,
    endpointType: bundle.endpointType,
    endpoint: bundle.endpoint,
    listenerOwner: observation.endpointOwner ?? {},
    readinessState: observation.readinessState,
    watchdogState: observation.watchdogState,
  };
}

function positiveAbsence(observation: SlotUnitObservation): boolean {
  return !observation.unitExists
    && observation.mainPid === undefined
    && !observation.endpointExists
    && !observation.runtimePathExists
    && !observation.transientUnitExists;
}

export class SlotRuntimeService {
  private readonly now: () => string;
  private readonly roots: JsonObject;

  constructor(private readonly options: SlotRuntimeServiceOptions) {
    this.now = options.now ?? (() => new Date().toISOString());
    const root = resolve(options.stateRoot, 'release-appliance', 'slot-runtime');
    this.roots = {
      releaseRoot: join(root, 'releases'),
      runtimeRoot: join(root, 'runtime'),
      stateRoot: join(root, 'state'),
      cacheRoot: join(root, 'cache'),
      logRoot: join(root, 'log'),
    };
  }

  describe(): JsonObject {
    return {
      contractVersion: SLOT_RUNTIME_CONTRACT_VERSION,
      authority: 'slot-systemd-adapter',
      processAuthority: 'existing-babyx-job-manager',
      slotIds: [...SLOT_IDS],
      endpointModes: ['UNIX_SOCKET', 'LOOPBACK_TCP'],
      mutationPubliclyExposed: false,
      productionMutationEnabledByDefault: false,
    };
  }

  registerService(value: unknown, context: RuntimeExecutionContext): JsonObject {
    const authenticated = exactContext(context);
    const service = normalizeService(value);
    if (service.ownerPrincipal !== authenticated.subject) throw new SlotRuntimeError('release_wrong_principal', 'service owner does not match authenticated principal');
    if (this.options.store.hasRecord('ServiceDefinitionV1', service.serviceId)) {
      const existing = this.options.store.getRecord('ServiceDefinitionV1', service.serviceId);
      if (existing.ownerPrincipal !== authenticated.subject) throw new SlotRuntimeError('release_wrong_principal', 'service belongs to another principal');
      if (canonicalize(existing) !== canonicalize(service.record)) throw new SlotRuntimeError('release_idempotency_conflict', 'service identity is already bound to different immutable bytes');
      return existing;
    }
    return this.options.store.applyMutation({
      schemaId: 'ServiceDefinitionV1',
      recordId: service.serviceId,
      ownerPrincipal: authenticated.subject,
      expectedSequence: 0,
      idempotencyKey: authenticated.idempotencyKey,
      requestDigest: sha256(canonicalize(service.record)),
      operation: 'babyx.release.service.register',
      phase: 'service-definition',
      record: service.record,
      occurredAt: this.now(),
    });
  }

  stage(value: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const authenticated = exactContext(context);
    const service = normalizeService(value.serviceDefinition);
    if (service.ownerPrincipal !== authenticated.subject) throw new SlotRuntimeError('release_wrong_principal', 'service owner does not match authenticated principal');
    this.registerService(service.record, { ...context, idempotencyKey: `service-${sha256(authenticated.idempotencyKey).slice(0, 48)}` });
    const slot = slotId(value.slotId);
    const release = object(value.release, 'release');
    const releaseId = identifier(release.releaseId, 'release.releaseId');
    const artifactSha256 = digest(release.artifactSha256, 'release.artifactSha256');
    const credentialSetDigest = digest(value.credentialSetDigest, 'credentialSetDigest');
    for (const root of Object.values(this.roots)) mkdirSync(String(root), { recursive: true, mode: 0o700 });
    const endpointMode = value.endpointMode === undefined ? undefined : value.endpointMode === 'UNIX_SOCKET' || value.endpointMode === 'LOOPBACK_TCP' ? value.endpointMode : (() => { throw new SlotRuntimeError('release_invalid_request', 'endpointMode is invalid'); })();
    const bundle = generateSlotUnit(service.record, slot, release, { ...this.roots, ...(endpointMode === undefined ? {} : { endpointMode }) });
    const recordId = `${service.serviceId}:${slot}`;
    const expectedSequence = value.expectedSequence === undefined ? (this.options.store.hasRecord('SlotRecordV1', recordId) ? Number(this.options.store.getRecord('SlotRecordV1', recordId).sequence) : 0) : integer(value.expectedSequence, 'expectedSequence', 0, Number.MAX_SAFE_INTEGER);
    const requestDigest = sha256(canonicalize({ serviceDigest: service.digest, slot, releaseId, artifactSha256, credentialSetDigest, bundle }));
    const replay = replayByKey(this.options.store, 'SlotRecordV1', recordId, authenticated.idempotencyKey, requestDigest);
    if (replay !== undefined) return replay;
    const existing = this.options.store.hasRecord('SlotRecordV1', recordId) ? this.options.store.getRecord('SlotRecordV1', recordId) : undefined;
    if (existing !== undefined && !['EMPTY', 'EMPTY_VERIFIED'].includes(String(existing.state))) throw new SlotRuntimeError('release_invalid_state', 'slot must be positively empty before staging', { state: existing.state });
    if (existing !== undefined) assertReleaseTransition('slot', String(existing.state), 'STAGING');
    const expectedIdentity = object(value.expectedProcessIdentity, 'expectedProcessIdentity');
    const stagingRecord = validateReleaseRecord('SlotRecordV1', {
      schemaVersion: '1.0.0',
      serviceId: service.serviceId,
      slotId: slot,
      releaseId,
      desiredState: 'STAGED',
      state: 'STAGING',
      sequence: expectedSequence + 1,
      systemdUnit: bundle.unitName,
      unitDigest: bundle.unitDigest,
      dropInDigest: bundle.dropInDigest,
      serviceUser: bundle.serviceUser,
      serviceGroup: bundle.serviceGroup,
      runtimeDirectory: bundle.runtimeRoot,
      endpointType: bundle.endpointType,
      endpointIdentity: { type: bundle.endpointType, endpoint: bundle.endpoint },
      expectedProcessIdentity: { ...expectedIdentity, artifactDigest: artifactSha256, ownerPrincipal: authenticated.subject },
      activeJobIds: [],
      allJobIds: [],
      readinessObservations: [],
      livenessObservations: [],
      routeMembership: false,
      drainObservations: [],
      credentialSetDigest,
      unitBundle: bundle,
    });
    const stagedIntent = this.options.store.applyMutation({ schemaId: 'SlotRecordV1', recordId, ownerPrincipal: authenticated.subject, expectedSequence, idempotencyKey: authenticated.idempotencyKey, requestDigest, operation: 'babyx.release.slot.stage', phase: 'stage-intent', record: stagingRecord, occurredAt: this.now(), artifactReferences: [{ artifactId: release.artifactId, artifactSha256 }] });
    return this.transition(stagedIntent, authenticated.subject, 'STAGED', 'stage-verified', `${authenticated.idempotencyKey}-verified`, sha256(canonicalize({ requestDigest, bundle })), {});
  }

  async start(value: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = exactContext(context);
    const serviceId = identifier(value.serviceId, 'serviceId');
    const slot = slotId(value.slotId);
    const recordId = `${serviceId}:${slot}`;
    let record = this.ownerSlot(recordId, authenticated.subject);
    const expectedSequence = integer(value.expectedSequence, 'expectedSequence', 0, Number.MAX_SAFE_INTEGER);
    if (Number(record.sequence) !== expectedSequence) throw new SlotRuntimeError('release_stale_sequence', 'expected sequence does not match the slot record');
    const requestDigest = sha256(canonicalize({ serviceId, slot, releaseId: record.releaseId, unitDigest: record.unitDigest, dropInDigest: record.dropInDigest }));
    const replay = replayByKey(this.options.store, 'SlotRecordV1', recordId, authenticated.idempotencyKey, requestDigest);
    if (replay !== undefined && ['RUNNING_NOT_READY', 'READY_PRIVATE'].includes(String(replay.state))) return replay;
    if (!['STAGED', 'STARTING', 'RUNNING_NOT_READY'].includes(String(record.state))) throw new SlotRuntimeError('release_invalid_state', 'slot cannot be started from its current state', { state: record.state });
    const bundle = bundleFromRecord(record);
    const validation = await this.options.systemd.validate(bundle);
    if (!validation.valid) throw new SlotRuntimeError('release_unit_invalid', 'systemd unit validation failed before mutation', { validationDigest: validation.digest, diagnostics: validation.diagnostics.slice(0, 16) });
    if (record.state === 'STAGED') record = this.transition(record, authenticated.subject, 'STARTING', 'start-intent', authenticated.idempotencyKey, requestDigest, { validationResult: validation });
    let observation: SlotUnitObservation;
    const preexisting = await this.options.systemd.observe(bundle);
    if (preexisting.unitExists || preexisting.mainPid !== undefined || preexisting.endpointExists) {
      try {
        const identity = exactObservation(bundle, record, preexisting);
        record = this.transition(record, authenticated.subject, 'RUNNING_NOT_READY', 'start-adopt', `${authenticated.idempotencyKey}-adopt`, sha256(canonicalize({ requestDigest, preexisting })), { observedProcessIdentity: identity, startedAt: record.startedAt ?? this.now(), readinessObservations: [preexisting] });
        if (preexisting.readinessState === 'READY') return this.transition(record, authenticated.subject, 'READY_PRIVATE', 'start-adopt-ready', `${authenticated.idempotencyKey}-adopt-ready`, sha256(canonicalize({ requestDigest, preexisting, ready: true })), { observedProcessIdentity: identity, readyAt: this.now() });
      } catch (error) {
        return this.ambiguous(record, authenticated.subject, 'start-preexisting-conflict', error, requestDigest);
      }
    } else {
      try {
        await this.options.systemd.install(bundle);
        await this.options.systemd.start(bundle);
      } catch (error) {
        const readback = await this.options.systemd.observe(bundle);
        if (!readback.unitExists && readback.mainPid === undefined && !readback.endpointExists) return this.failed(record, authenticated.subject, 'start-failed', error, requestDigest);
        try { exactObservation(bundle, record, readback); } catch (identityError) { return this.ambiguous(record, authenticated.subject, 'start-response-loss', identityError, requestDigest); }
      }
      observation = await this.options.systemd.observe(bundle);
      let identity: SlotProcessIdentity;
      try { identity = exactObservation(bundle, record, observation); } catch (error) { return this.ambiguous(record, authenticated.subject, 'start-readback', error, requestDigest); }
      record = this.transition(record, authenticated.subject, 'RUNNING_NOT_READY', 'start-readback', `${authenticated.idempotencyKey}-readback`, sha256(canonicalize({ requestDigest, observation })), { observedProcessIdentity: identity, startedAt: this.now(), readinessObservations: [observation] });
    }
    const service = normalizeService(this.options.store.getRecord('ServiceDefinitionV1', serviceId));
    const observations = await this.options.systemd.waitReady(bundle, service.readinessPolicy);
    const bounded = observations.slice(-MAX_OBSERVATIONS);
    const final = bounded.at(-1);
    if (final === undefined || final.readinessState !== 'READY') return this.failed(record, authenticated.subject, final?.activeState === 'active' ? 'readiness-timeout' : 'readiness-failed', new SlotRuntimeError('release_readiness_failed', 'slot remained alive without exact readiness'), requestDigest, { readinessObservations: bounded });
    let identity: SlotProcessIdentity;
    try { identity = exactObservation(bundle, record, final); } catch (error) { return this.ambiguous(record, authenticated.subject, 'readiness-readback', error, requestDigest); }
    return this.transition(record, authenticated.subject, 'READY_PRIVATE', 'readiness-verified', `${authenticated.idempotencyKey}-ready`, sha256(canonicalize({ requestDigest, final })), { observedProcessIdentity: identity, readinessObservations: bounded, readyAt: this.now() });
  }

  async stop(value: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = exactContext(context);
    const serviceId = identifier(value.serviceId, 'serviceId');
    const slot = slotId(value.slotId);
    const recordId = `${serviceId}:${slot}`;
    let record = this.ownerSlot(recordId, authenticated.subject);
    if (record.state === 'ACTIVE') throw new SlotRuntimeError('release_invalid_state', 'active slot cannot be stopped without route coordination');
    const expectedSequence = integer(value.expectedSequence, 'expectedSequence', 0, Number.MAX_SAFE_INTEGER);
    if (Number(record.sequence) !== expectedSequence) throw new SlotRuntimeError('release_stale_sequence', 'expected sequence does not match the slot record');
    const requestDigest = sha256(canonicalize({ serviceId, slot, releaseId: record.releaseId, action: 'stop' }));
    const replay = replayByKey(this.options.store, 'SlotRecordV1', recordId, authenticated.idempotencyKey, requestDigest);
    if (replay !== undefined && replay.state === 'STOPPED') return replay;
    if (!['STARTING', 'RUNNING_NOT_READY', 'READY_PRIVATE', 'DRAINING', 'FAILED', 'STOPPING'].includes(String(record.state))) throw new SlotRuntimeError('release_invalid_state', 'slot cannot be stopped from its current state', { state: record.state });
    if (record.state !== 'STOPPING') record = this.transition(record, authenticated.subject, 'STOPPING', 'stop-intent', authenticated.idempotencyKey, requestDigest, {});
    const bundle = bundleFromRecord(record);
    try { await this.options.systemd.stop(bundle); } catch (error) {
      const observation = await this.options.systemd.observe(bundle);
      if (!observation.unitExists && observation.mainPid === undefined && !observation.endpointExists) return this.transition(record, authenticated.subject, 'STOPPED', 'stop-response-loss-absent', `${authenticated.idempotencyKey}-absent`, sha256(canonicalize({ requestDigest, observation })), { stoppedAt: this.now() });
      try { exactObservation(bundle, record, observation); } catch (identityError) { return this.ambiguous(record, authenticated.subject, 'stop-response-loss', identityError, requestDigest); }
      return this.recovery(record, authenticated.subject, 'stop-obstructed', error, requestDigest);
    }
    const observation = await this.options.systemd.observe(bundle);
    if (observation.mainPid !== undefined || observation.endpointExists || observation.activeState === 'active') return this.recovery(record, authenticated.subject, 'stop-absence-unproven', new SlotRuntimeError('release_cleanup_failed', 'stop did not prove process and listener absence'), requestDigest);
    return this.transition(record, authenticated.subject, 'STOPPED', 'stop-verified', `${authenticated.idempotencyKey}-verified`, sha256(canonicalize({ requestDigest, observation })), { stoppedAt: this.now(), livenessObservations: [...(Array.isArray(record.livenessObservations) ? record.livenessObservations : []), observation].slice(-MAX_OBSERVATIONS) });
  }

  async cleanup(value: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = exactContext(context);
    const serviceId = identifier(value.serviceId, 'serviceId');
    const slot = slotId(value.slotId);
    const recordId = `${serviceId}:${slot}`;
    let record = this.ownerSlot(recordId, authenticated.subject);
    const expectedSequence = integer(value.expectedSequence, 'expectedSequence', 0, Number.MAX_SAFE_INTEGER);
    if (Number(record.sequence) !== expectedSequence) throw new SlotRuntimeError('release_stale_sequence', 'expected sequence does not match the slot record');
    if (record.state === 'ACTIVE' || record.routeMembership === true) throw new SlotRuntimeError('release_invalid_state', 'active slot cannot be cleaned');
    if (value.protectedRollbackTarget === true) throw new SlotRuntimeError('release_invalid_state', 'protected rollback target cannot be cleaned');
    for (const jobId of Array.isArray(record.activeJobIds) ? record.activeJobIds : []) {
      const job = this.options.jobs.get(String(jobId));
      if (job.status === 'running') throw new SlotRuntimeError('release_active_jobs', 'active related jobs block cleanup');
    }
    const requestDigest = sha256(canonicalize({ serviceId, slot, releaseId: record.releaseId, action: 'cleanup' }));
    const replay = replayByKey(this.options.store, 'SlotRecordV1', recordId, authenticated.idempotencyKey, requestDigest);
    if (replay !== undefined && replay.state === 'EMPTY_VERIFIED') return replay;
    if (!['STAGED', 'STOPPED', 'FAILED', 'CLEANING'].includes(String(record.state))) throw new SlotRuntimeError('release_invalid_state', 'slot cannot be cleaned from its current state', { state: record.state });
    if (record.state !== 'CLEANING') record = this.transition(record, authenticated.subject, 'CLEANING', 'cleanup-intent', authenticated.idempotencyKey, requestDigest, {});
    const bundle = bundleFromRecord(record);
    try { await this.options.systemd.cleanup(bundle); } catch (error) { return this.recovery(record, authenticated.subject, 'cleanup-effect-failed', error, requestDigest); }
    const observation = await this.options.systemd.observe(bundle);
    if (!positiveAbsence(observation)) return this.recovery(record, authenticated.subject, 'cleanup-absence-unproven', new SlotRuntimeError('release_cleanup_failed', 'cleanup did not prove unit, process, endpoint, runtime path, and transient-unit absence'), requestDigest, { ambiguity: { observationDigest: sha256(canonicalize(observation)) } });
    return this.transition(record, authenticated.subject, 'EMPTY_VERIFIED', 'cleanup-verified', `${authenticated.idempotencyKey}-verified`, sha256(canonicalize({ requestDigest, observation })), { desiredState: 'EMPTY_VERIFIED', releaseId: undefined, observedProcessIdentity: undefined, endpointIdentity: undefined, routeMembership: false, cleanupCompletedAt: this.now(), ambiguity: undefined, error: undefined });
  }

  activate(value: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const authenticated = exactContext(context);
    const serviceId = identifier(value.serviceId, 'serviceId');
    const slot = slotId(value.slotId);
    const recordId = `${serviceId}:${slot}`;
    const record = this.ownerSlot(recordId, authenticated.subject);
    const expectedSequence = integer(value.expectedSequence, 'expectedSequence', 0, Number.MAX_SAFE_INTEGER);
    if (Number(record.sequence) !== expectedSequence) throw new SlotRuntimeError('release_stale_sequence', 'expected sequence does not match the slot record');
    if (record.state !== 'READY_PRIVATE') throw new SlotRuntimeError('release_invalid_state', 'only READY_PRIVATE may become ACTIVE');
    const other = slot === 'blue' ? 'green' : 'blue';
    const otherId = `${serviceId}:${other}`;
    if (this.options.store.hasRecord('SlotRecordV1', otherId)) {
      const otherRecord = this.ownerSlot(otherId, authenticated.subject);
      if (otherRecord.state === 'ACTIVE') throw new SlotRuntimeError('release_invalid_state', 'previous active slot must be marked DRAINING after route readback before activating the replacement');
    }
    if (value.routeReadbackVerified !== true) throw new SlotRuntimeError('release_route_ambiguous', 'slot activation requires exact route readback');
    const requestDigest = sha256(canonicalize({ serviceId, slot, routeDigest: digest(value.routeDigest, 'routeDigest') }));
    return this.transition(record, authenticated.subject, 'ACTIVE', 'route-readback-activation', authenticated.idempotencyKey, requestDigest, { desiredState: 'ACTIVE', routeMembership: true, exposedAt: this.now() });
  }

  markDraining(value: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const authenticated = exactContext(context);
    const serviceId = identifier(value.serviceId, 'serviceId');
    const slot = slotId(value.slotId);
    const record = this.ownerSlot(`${serviceId}:${slot}`, authenticated.subject);
    if (record.state !== 'ACTIVE') throw new SlotRuntimeError('release_invalid_state', 'only ACTIVE slot may begin draining');
    if (value.routeReadbackVerified !== true) throw new SlotRuntimeError('release_route_ambiguous', 'drain requires exact replacement-route readback');
    return this.transition(record, authenticated.subject, 'DRAINING', 'drain-start', authenticated.idempotencyKey, sha256(canonicalize({ serviceId, slot, action: 'drain' })), { desiredState: 'DRAINING', routeMembership: false, drainStartedAt: this.now() });
  }

  getService(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    strictReadPayload(payload, ['serviceId']);
    const serviceId = identifier(payload.serviceId, 'serviceId');
    const record = this.options.store.getRecord('ServiceDefinitionV1', serviceId);
    if (context.authorityClass !== 'unrestricted-owner' && record.ownerPrincipal !== context.subject) throw new SlotRuntimeError('release_record_not_found', 'service was not found');
    return { operation: 'babyx.release.service.get', service: record };
  }

  listServices(payload: JsonObject = {}, context: RuntimeExecutionContext): JsonObject {
    strictReadPayload(payload, ['offset', 'limit']);
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, 10_000);
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, 200);
    const records = this.options.store.listRecordIdentities(10_000)
      .filter((identity) => identity.schemaId === 'ServiceDefinitionV1')
      .map((identity) => this.options.store.getRecord(identity.schemaId, identity.recordId))
      .filter((record) => context.authorityClass === 'unrestricted-owner' || record.ownerPrincipal === context.subject)
      .sort((left, right) => String(left.serviceId).localeCompare(String(right.serviceId)));
    const selected = records.slice(offset, offset + limit);
    return { operation: 'babyx.release.service.list', services: selected, offset, limit, total: records.length, nextOffset: offset + selected.length < records.length ? offset + selected.length : null };
  }

  getSlot(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    strictReadPayload(payload, ['serviceId', 'slotId']);
    const serviceId = identifier(payload.serviceId, 'serviceId');
    const slot = slotId(payload.slotId);
    const record = this.ownerSlot(`${serviceId}:${slot}`, context.authorityClass === 'unrestricted-owner' ? undefined : context.subject);
    return { operation: 'babyx.release.slot.get', slot: record };
  }

  private ownerSlot(recordId: string, subject?: string): JsonObject {
    let record: JsonObject;
    try { record = this.options.store.getRecord('SlotRecordV1', recordId); } catch (error) {
      if (error instanceof ReleaseStoreError && error.code === 'release_record_not_found') throw new SlotRuntimeError('release_record_not_found', 'slot was not found');
      throw error;
    }
    const owner = ownerFromEvents(this.options.store, 'SlotRecordV1', recordId);
    if (subject !== undefined && owner !== subject) throw new SlotRuntimeError('release_record_not_found', 'slot was not found');
    return record;
  }

  private transition(record: JsonObject, ownerPrincipal: string, state: string, phase: string, idempotencyKey: string, requestDigest: string, patch: JsonObject): JsonObject {
    const prior = String(record.state);
    if (prior !== state) assertReleaseTransition('slot', prior, state);
    const sequence = integer(record.sequence, 'slot.sequence', 0, Number.MAX_SAFE_INTEGER);
    const occurredAt = this.now();
    const draft: JsonObject = { ...record };
    for (const [key, value] of Object.entries(patch)) {
      if (value === undefined) delete draft[key];
      else draft[key] = value;
    }
    const candidate = validateReleaseRecord('SlotRecordV1', { ...draft, state, sequence: sequence + 1 });
    return this.options.store.applyMutation({ schemaId: 'SlotRecordV1', recordId: `${record.serviceId}:${record.slotId}`, ownerPrincipal, expectedSequence: sequence, idempotencyKey, requestDigest, operation: 'babyx.release.slot.coordinate', phase, record: candidate, occurredAt, childJobIds: Array.isArray(candidate.allJobIds) ? candidate.allJobIds as string[] : [], observationDigest: patch.observedProcessIdentity === undefined ? undefined : sha256(canonicalize(patch.observedProcessIdentity)) });
  }

  private structuredError(error: unknown, fallbackCode: string, retryable: boolean, phase: string): JsonObject {
    const bounded = boundedReleaseError(error, fallbackCode, retryable, phase);
    return {
      code: bounded.code,
      message: bounded.message,
      retryable: bounded.retryable,
      phase: bounded.phase,
      productionImpact: 'NONE',
      detailsDigest: sha256(canonicalize(bounded.details ?? {})),
    };
  }

  private failed(record: JsonObject, ownerPrincipal: string, phase: string, error: unknown, requestDigest: string, patch: JsonObject = {}): JsonObject {
    const structured = this.structuredError(error, 'release_start_failed', true, phase);
    return this.transition(record, ownerPrincipal, 'FAILED', phase, `${record.serviceId}-${record.slotId}-${record.sequence}-${phase}`, sha256(canonicalize({ requestDigest, phase, error: structured })), { ...patch, desiredState: 'FAILED', error: structured });
  }

  private recovery(record: JsonObject, ownerPrincipal: string, phase: string, error: unknown, requestDigest: string, patch: JsonObject = {}): JsonObject {
    const structured = this.structuredError(error, 'release_recovery_required', true, phase);
    return this.transition(record, ownerPrincipal, 'RECOVERY_REQUIRED', phase, `${record.serviceId}-${record.slotId}-${record.sequence}-${phase}`, sha256(canonicalize({ requestDigest, phase, error: structured })), { ...patch, desiredState: 'RECOVERY_REQUIRED', error: structured });
  }

  private ambiguous(record: JsonObject, ownerPrincipal: string, phase: string, error: unknown, requestDigest: string): JsonObject {
    const structured = this.structuredError(error, 'release_process_ambiguous', false, phase);
    return this.transition(record, ownerPrincipal, 'AMBIGUOUS', phase, `${record.serviceId}-${record.slotId}-${record.sequence}-${phase}`, sha256(canonicalize({ requestDigest, phase, structured })), { desiredState: 'AMBIGUOUS', ambiguity: { code: structured.code, detailsDigest: structured.detailsDigest }, error: structured });
  }
}
