import {
  chmodSync, chownSync, closeSync, constants, existsSync, fchmodSync, fchownSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, readlinkSync, realpathSync, renameSync, rmSync, statSync, symlinkSync,
  unlinkSync, writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { randomUUID } from 'node:crypto';
import { canonicalize, sha256, type CommandResult, type JsonObject } from '../core.ts';
import { SystemdManager } from '../systemd/manager.ts';
import { RootFabricError, integer, object, strictObject, text, type AdapterRestartBehavior, type RootEffectClass, type RootExecutionProvider } from './model.ts';
import type { BrokerEffectAdapter, BrokerEffectResult, RootBrokerRequest } from './broker.ts';

export interface RootEffectDefinition extends JsonObject {
  operation: string;
  version: '1.0.0';
  effectClass: RootEffectClass;
  atomicityModes: string[];
  providers: RootExecutionProvider[];
  requiredCapabilities: string[];
  restartBehavior: AdapterRestartBehavior;
  cancellable: boolean;
  timeoutMs: number;
  rollbackOperation: string | null;
  compensationOperation: string | null;
}

export interface EffectStorageAuthority {
  prepareSnapshot(input: JsonObject): Promise<JsonObject>;
  verifySnapshot(input: JsonObject): Promise<JsonObject>;
  rollbackSnapshot(input: JsonObject): Promise<JsonObject>;
  releaseSnapshot(input: JsonObject): Promise<JsonObject>;
  mountCreate(input: JsonObject): Promise<JsonObject>;
  mountRemove(input: JsonObject): Promise<JsonObject>;
  mountStatus(input: JsonObject): Promise<JsonObject>;
}

export interface EffectNetworkAuthority {
  portCheck(input: JsonObject): Promise<JsonObject>;
  listenerVerify(input: JsonObject): Promise<JsonObject>;
  applyOwnedRule(input: JsonObject): Promise<JsonObject>;
  removeOwnedRule(input: JsonObject): Promise<JsonObject>;
}

export interface ArtifactAuthority {
  capture(name: string, bytes: Buffer, metadata: JsonObject): Promise<{ artifactId: string; sha256: string; size: number }>;
  read(artifactId: string): Promise<Buffer>;
}

export interface HostEnvelopeProfile extends JsonObject {
  unit: string;
  argv: string[];
  workingDirectory: string;
  user: string;
  group: string;
  timeoutMs: number;
  cpuQuota: string;
  memoryMax: string;
  ioWeight: string;
  tasksMax: number;
  readOnlyPaths: string[];
  readWritePaths: string[];
  inaccessiblePaths: string[];
  restrictAddressFamilies: string[];
  systemCallFilter: string[];
  capabilityBoundingSet: string[];
  credentialPaths: string[];
}

const VERSION = '1.0.0' as const;
const UNIT = /^[A-Za-z0-9_.@:-]+$/u;
const SIGNAL = /^SIG[A-Z0-9]+$/u;

const DEFINITIONS: RootEffectDefinition[] = [
  ['filesystem.file.create', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READBACK_BEFORE_RETRY', true, 'filesystem.file.remove', null],
  ['filesystem.file.replace', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READBACK_BEFORE_RETRY', true, 'filesystem.file.replace', null],
  ['filesystem.file.remove', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READBACK_BEFORE_RETRY', true, 'filesystem.file.create', null],
  ['filesystem.directory.create', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'IDEMPOTENT_RETRY', true, 'filesystem.directory.remove', null],
  ['filesystem.directory.remove', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READBACK_BEFORE_RETRY', true, 'filesystem.directory.create', null],
  ['filesystem.metadata.update', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READBACK_BEFORE_RETRY', true, 'filesystem.metadata.update', null],
  ['filesystem.symlink.replace', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READBACK_BEFORE_RETRY', true, 'filesystem.symlink.replace', null],
  ['filesystem.release-pointer.switch', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE'], 'READBACK_BEFORE_RETRY', true, 'filesystem.release-pointer.switch', null],
  ['process.exec', 'IRREVERSIBLE', ['IRREVERSIBLE'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'NEVER_AUTOMATICALLY_RETRY', true, null, null],
  ['process.signal', 'IRREVERSIBLE', ['IRREVERSIBLE'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READBACK_BEFORE_RETRY', true, null, null],
  ['process.freeze', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'IDEMPOTENT_RETRY', true, 'process.thaw', null],
  ['process.thaw', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'IDEMPOTENT_RETRY', true, 'process.freeze', null],
  ['process.terminate', 'IRREVERSIBLE', ['IRREVERSIBLE'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READBACK_BEFORE_RETRY', true, null, null],
  ['service.status', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE'], 'READ_ONLY_RETRY', false, null, null],
  ['service.start', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE'], 'READBACK_BEFORE_RETRY', true, 'service.stop', null],
  ['service.stop', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE'], 'READBACK_BEFORE_RETRY', true, 'service.start', null],
  ['service.restart', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE'], 'READBACK_BEFORE_RETRY', true, 'service.restart', null],
  ['service.reload', 'COMPENSATABLE', ['SAGA'], ['HOST_ENVELOPE'], 'READBACK_BEFORE_RETRY', true, null, 'service.restart'],
  ['service.enable', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE'], 'READBACK_BEFORE_RETRY', true, 'service.disable', null],
  ['service.disable', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE'], 'READBACK_BEFORE_RETRY', true, 'service.enable', null],
  ['mount.status', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READ_ONLY_RETRY', false, null, null],
  ['mount.create', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READBACK_BEFORE_RETRY', true, 'mount.remove', null],
  ['mount.remove', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READBACK_BEFORE_RETRY', true, 'mount.create', null],
  ['snapshot.prepare', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READBACK_BEFORE_RETRY', true, 'snapshot.release', null],
  ['snapshot.verify', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READ_ONLY_RETRY', false, null, null],
  ['snapshot.rollback', 'IRREVERSIBLE', ['IRREVERSIBLE'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'NEVER_AUTOMATICALLY_RETRY', true, null, null],
  ['snapshot.release', 'IRREVERSIBLE', ['IRREVERSIBLE'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READBACK_BEFORE_RETRY', true, null, null],
  ['network.port.check', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READ_ONLY_RETRY', false, null, null],
  ['network.listener.verify', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'], 'READ_ONLY_RETRY', false, null, null],
  ['network.policy.apply-owned-rule', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE'], 'READBACK_BEFORE_RETRY', true, 'network.policy.remove-owned-rule', null],
  ['network.policy.remove-owned-rule', 'REVERSIBLE', ['ATOMIC_WITHIN_PROVIDER', 'SAGA'], ['HOST_ENVELOPE'], 'READBACK_BEFORE_RETRY', true, 'network.policy.apply-owned-rule', null],
].map(([operation, effectClass, atomicityModes, providers, restartBehavior, cancellable, rollbackOperation, compensationOperation]) => ({
  operation: operation as string, version: VERSION, effectClass: effectClass as RootEffectClass, atomicityModes: atomicityModes as string[],
  providers: providers as RootExecutionProvider[], requiredCapabilities: [], restartBehavior: restartBehavior as AdapterRestartBehavior,
  cancellable: cancellable as boolean, timeoutMs: operation === 'process.exec' ? 3_600_000 : 300_000,
  rollbackOperation: rollbackOperation as string | null, compensationOperation: compensationOperation as string | null,
}));

function unit(value: unknown): string {
  const result = text(value, 'unit', 256);
  if (!UNIT.test(result) || result.startsWith('-')) throw new RootFabricError('invalid_request', 'unit is invalid');
  return result;
}

function absoluteExecutable(value: unknown): string {
  const executable = text(value, 'executable', 4_096);
  if (!isAbsolute(executable)) throw new RootFabricError('invalid_request', 'executable must be absolute');
  const info = lstatSync(executable);
  if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o111) === 0) throw new RootFabricError('precondition_failed', 'executable must be a non-symlink executable regular file');
  return executable;
}

function commandResult(value: CommandResult): JsonObject {
  return value as unknown as JsonObject;
}

function ensureConfined(rootValue: unknown, pathValue: unknown, allowMissingLeaf = true): { root: string; path: string; parent: string; name: string } {
  const rootInput = text(rootValue, 'root', 4_096);
  const relativePath = text(pathValue, 'path', 4_096);
  if (!isAbsolute(rootInput)) throw new RootFabricError('path_escape', 'confinement root must be absolute');
  if (isAbsolute(relativePath) || relativePath.includes('\0') || relativePath.split(/[\\/]/u).includes('..')) throw new RootFabricError('path_escape', 'path must be confined and relative');
  const root = realpathSync(rootInput);
  const path = resolve(root, relativePath);
  const rel = relative(root, path);
  if (rel === '' || rel.startsWith(`..${sep}`) || rel === '..' || isAbsolute(rel)) throw new RootFabricError('path_escape', 'path escapes confinement root or targets the root itself');
  let cursor = root;
  const components = rel.split(sep);
  for (let index = 0; index < components.length - 1; index += 1) {
    cursor = join(cursor, components[index]!);
    const info = lstatSync(cursor);
    if (info.isSymbolicLink()) throw new RootFabricError('symlink_escape', 'path contains a symlink component');
    if (!info.isDirectory()) throw new RootFabricError('precondition_failed', 'path parent is not a directory');
  }
  if (existsSync(path)) {
    const info = lstatSync(path);
    if (info.isSymbolicLink()) throw new RootFabricError('symlink_escape', 'target is a symlink');
  } else if (!allowMissingLeaf) throw new RootFabricError('precondition_failed', 'target does not exist');
  return { root, path, parent: dirname(path), name: components.at(-1)! };
}

function fileState(path: string): JsonObject {
  if (!existsSync(path)) return { exists: false };
  const info = lstatSync(path);
  const base: JsonObject = { exists: true, mode: info.mode & 0o7777, uid: info.uid, gid: info.gid, size: info.size, type: info.isFile() ? 'file' : info.isDirectory() ? 'directory' : info.isSymbolicLink() ? 'symlink' : 'unsupported' };
  if (info.isFile()) return { ...base, sha256: sha256(readFileSync(path)) };
  if (info.isSymbolicLink()) return { ...base, symlinkTarget: readlinkSync(path) };
  return base;
}

async function capturePrior(artifactAuthority: ArtifactAuthority | undefined, transactionId: string, step: string, path: string): Promise<JsonObject> {
  const state = fileState(path);
  if (state.exists !== true || state.type !== 'file') return state;
  if (artifactAuthority === undefined) throw new RootFabricError('preparation_failed', 'file rollback requires the canonical artifact authority');
  const artifact = await artifactAuthority.capture(`root-prior-${transactionId}-${step}`, readFileSync(path), { transactionId, path, state });
  return { ...state, artifactId: artifact.artifactId, artifactSha256: artifact.sha256 };
}

function writeAtomic(path: string, data: Buffer, mode: number, uid: number | undefined, gid: number | undefined): void {
  const temporary = join(dirname(path), `.${randomUUID()}.babyx.tmp`);
  const fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    writeFileSync(fd, data);
    fchmodSync(fd, mode);
    if (uid !== undefined || gid !== undefined) fchownSync(fd, uid ?? -1, gid ?? -1);
    fsyncSync(fd);
  } finally { closeSync(fd); }
  try {
    renameSync(temporary, path);
    const parent = openSync(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY);
    try { fsyncSync(parent); } finally { closeSync(parent); }
  } catch (error) { try { unlinkSync(temporary); } catch {} throw error; }
}

export class HostEnvelopeProvider {
  constructor(private readonly systemd: SystemdManager = new SystemdManager()) {}

  profile(inputValue: unknown, request: RootBrokerRequest): HostEnvelopeProfile {
    const input = strictObject(inputValue, 'host envelope input', ['executable', 'argv', 'workingDirectory', 'user', 'group', 'timeoutMs', 'cpuQuota', 'memoryMax', 'ioWeight', 'tasksMax', 'readOnlyPaths', 'readWritePaths', 'inaccessiblePaths', 'restrictAddressFamilies', 'systemCallFilter', 'capabilityBoundingSet', 'credentialPaths']);
    const executable = absoluteExecutable(input.executable);
    if (!Array.isArray(input.argv) || input.argv.length > 256 || input.argv.some((entry) => typeof entry !== 'string' || entry.includes('\0'))) throw new RootFabricError('invalid_request', 'argv must be a bounded NUL-free string array');
    const suffix = sha256(`${request.transactionId}:${request.transactionSequence}:${request.inputDigest}`).slice(0, 16);
    const unitName = `babyx-root-${suffix}.service`;
    const pathList = (value: unknown, field: string) => {
      if (!Array.isArray(value) || value.length > 128) throw new RootFabricError('invalid_request', `${field} must be a bounded path array`);
      return value.map((entry, index) => { const path = text(entry, `${field}[${index}]`, 4_096); if (!isAbsolute(path)) throw new RootFabricError('invalid_request', `${field} paths must be absolute`); return path; });
    };
    return {
      unit: unitName, argv: [executable, ...(input.argv as string[])], workingDirectory: text(input.workingDirectory, 'workingDirectory', 4_096),
      user: identifierLike(input.user, 'user'), group: identifierLike(input.group, 'group'), timeoutMs: integer(input.timeoutMs, 'timeoutMs', 1, 3_600_000),
      cpuQuota: text(input.cpuQuota, 'cpuQuota', 32), memoryMax: text(input.memoryMax, 'memoryMax', 32), ioWeight: text(input.ioWeight, 'ioWeight', 32), tasksMax: integer(input.tasksMax, 'tasksMax', 1, 65_536),
      readOnlyPaths: pathList(input.readOnlyPaths ?? [], 'readOnlyPaths'), readWritePaths: pathList(input.readWritePaths ?? [], 'readWritePaths'), inaccessiblePaths: pathList(input.inaccessiblePaths ?? [], 'inaccessiblePaths'),
      restrictAddressFamilies: stringList(input.restrictAddressFamilies ?? [], 'restrictAddressFamilies', 32), systemCallFilter: stringList(input.systemCallFilter ?? [], 'systemCallFilter', 512), capabilityBoundingSet: stringList(input.capabilityBoundingSet ?? [], 'capabilityBoundingSet', 128), credentialPaths: pathList(input.credentialPaths ?? [], 'credentialPaths'),
    };
  }

  async execute(input: JsonObject, request: RootBrokerRequest): Promise<BrokerEffectResult> {
    const profile = this.profile(input, request);
    const properties: Record<string, string> = {
      Type: 'exec', WorkingDirectory: profile.workingDirectory, User: profile.user, Group: profile.group,
      RuntimeMaxSec: String(Math.ceil(profile.timeoutMs / 1_000)), KillMode: 'control-group', CollectMode: 'inactive-or-failed',
      Slice: 'baby-x-root.slice', CPUQuota: profile.cpuQuota, MemoryMax: profile.memoryMax, IOWeight: profile.ioWeight, TasksMax: String(profile.tasksMax),
      NoNewPrivileges: 'yes', PrivateTmp: 'yes', ProtectSystem: 'strict', ProtectHome: 'yes', RestrictNamespaces: 'yes', LockPersonality: 'yes', MemoryDenyWriteExecute: 'yes',
    };
    if (profile.readOnlyPaths.length > 0) properties.ReadOnlyPaths = profile.readOnlyPaths.join(' ');
    if (profile.readWritePaths.length > 0) properties.ReadWritePaths = profile.readWritePaths.join(' ');
    if (profile.inaccessiblePaths.length > 0) properties.InaccessiblePaths = profile.inaccessiblePaths.join(' ');
    if (profile.restrictAddressFamilies.length > 0) properties.RestrictAddressFamilies = profile.restrictAddressFamilies.join(' ');
    if (profile.systemCallFilter.length > 0) properties.SystemCallFilter = profile.systemCallFilter.join(' ');
    if (profile.capabilityBoundingSet.length > 0) properties.CapabilityBoundingSet = profile.capabilityBoundingSet.join(' ');
    const propertyEntries = profile.credentialPaths.map((path, index) => `LoadCredential=credential-${index}:${path}`);
    const result = await this.systemd.run({ argv: profile.argv, unit: profile.unit.replace(/\.service$/u, ''), properties, propertyEntries, timeoutMs: profile.timeoutMs });
    return { classification: result.exitCode === 0 ? 'SUCCEEDED' : 'FAILED', executionIdentity: { unit: profile.unit, provider: 'systemd-transient', profileDigest: sha256(canonicalize(profile)) }, result: commandResult(result), cleanupState: { unitCollected: true, cgroupEmpty: true } };
  }

  async signal(unitName: string, signalName: string): Promise<JsonObject> {
    if (!UNIT.test(unitName)) throw new RootFabricError('invalid_request', 'unit name is invalid');
    if (!SIGNAL.test(signalName)) throw new RootFabricError('invalid_request', 'signal name is invalid');
    return commandResult(await this.systemd.kill({ unit: unitName, signal: signalName, who: 'all' }));
  }

  async freeze(unitName: string, frozen: boolean): Promise<JsonObject> {
    if (!UNIT.test(unitName)) throw new RootFabricError('invalid_request', 'unit name is invalid');
    const action = frozen ? 'freeze' : 'thaw';
    const result = await this.systemd.raw('systemctl', ['--system', '--no-pager', action, '--', unitName]);
    return commandResult(result);
  }
}

function identifierLike(value: unknown, field: string): string {
  const result = text(value, field, 256);
  if (!/^[A-Za-z0-9_.@:-]+$/u.test(result) || result.startsWith('-')) throw new RootFabricError('invalid_request', `${field} is invalid`);
  return result;
}

function stringList(value: unknown, field: string, maximum: number): string[] {
  if (!Array.isArray(value) || value.length > maximum || value.some((entry) => typeof entry !== 'string' || entry.length === 0 || entry.includes('\0'))) throw new RootFabricError('invalid_request', `${field} must be a bounded NUL-free string array`);
  return [...new Set(value as string[])];
}

export class RootEffectRegistry {
  private readonly definitions = new Map(DEFINITIONS.map((definition) => [`${definition.operation}@${definition.version}`, definition]));
  constructor(private readonly options: {
    systemd?: SystemdManager;
    storage: EffectStorageAuthority;
    network: EffectNetworkAuthority;
    artifacts?: ArtifactAuthority;
  }) {}

  list(): RootEffectDefinition[] { return [...this.definitions.values()].sort((left, right) => left.operation.localeCompare(right.operation)); }
  get(operation: string, version = VERSION): RootEffectDefinition {
    const definition = this.definitions.get(`${operation}@${version}`);
    if (definition === undefined) throw new RootFabricError('unsupported_operation', `typed effect ${operation}@${version} is unsupported`);
    return definition;
  }

  adapter(operation: string, version = VERSION): BrokerEffectAdapter {
    const definition = this.get(operation, version);
    return { operation, version, execute: async (input, request) => this.execute(definition, input, request) };
  }

  adapters(): BrokerEffectAdapter[] { return this.list().map((definition) => this.adapter(definition.operation, definition.version)); }

  private async execute(definition: RootEffectDefinition, input: JsonObject, request: RootBrokerRequest): Promise<BrokerEffectResult> {
    if (!definition.providers.includes(request.selectedProvider)) throw new RootFabricError('unsupported_provider', `${definition.operation} does not support ${request.selectedProvider}`);
    if (request.selectedProvider === 'DISPOSABLE_MACHINE') return { classification: 'SUCCEEDED', result: { delegated: true, authority: 'Disposable Machine Service', operation: definition.operation, inputDigest: request.inputDigest }, executionIdentity: { provider: 'DISPOSABLE_MACHINE', transactionId: request.transactionId }, cleanupState: { delegated: true } };
    if (definition.operation.startsWith('filesystem.')) return this.filesystem(definition.operation, input, request);
    if (definition.operation === 'process.exec') return new HostEnvelopeProvider(this.options.systemd).execute(input, request);
    if (definition.operation === 'process.signal') return { classification: 'SUCCEEDED', result: await new HostEnvelopeProvider(this.options.systemd).signal(unit(input.unit), text(input.signal, 'signal', 32)) };
    if (definition.operation === 'process.freeze' || definition.operation === 'process.thaw') return { classification: 'SUCCEEDED', result: await new HostEnvelopeProvider(this.options.systemd).freeze(unit(input.unit), definition.operation.endsWith('freeze')) };
    if (definition.operation === 'process.terminate') return { classification: 'SUCCEEDED', result: await new HostEnvelopeProvider(this.options.systemd).signal(unit(input.unit), 'SIGKILL') };
    if (definition.operation.startsWith('service.')) return this.service(definition.operation, input);
    if (definition.operation === 'mount.status') return { classification: 'SUCCEEDED', result: await this.options.storage.mountStatus(input) };
    if (definition.operation === 'mount.create') return { classification: 'SUCCEEDED', result: await this.options.storage.mountCreate(input) };
    if (definition.operation === 'mount.remove') return { classification: 'SUCCEEDED', result: await this.options.storage.mountRemove(input) };
    if (definition.operation === 'snapshot.prepare') return { classification: 'SUCCEEDED', result: await this.options.storage.prepareSnapshot(input) };
    if (definition.operation === 'snapshot.verify') return { classification: 'SUCCEEDED', result: await this.options.storage.verifySnapshot(input) };
    if (definition.operation === 'snapshot.rollback') return { classification: 'SUCCEEDED', result: await this.options.storage.rollbackSnapshot(input) };
    if (definition.operation === 'snapshot.release') return { classification: 'SUCCEEDED', result: await this.options.storage.releaseSnapshot(input) };
    if (definition.operation === 'network.port.check') return { classification: 'SUCCEEDED', result: await this.options.network.portCheck(input) };
    if (definition.operation === 'network.listener.verify') return { classification: 'SUCCEEDED', result: await this.options.network.listenerVerify(input) };
    if (definition.operation === 'network.policy.apply-owned-rule') return { classification: 'SUCCEEDED', result: await this.options.network.applyOwnedRule(input) };
    if (definition.operation === 'network.policy.remove-owned-rule') return { classification: 'SUCCEEDED', result: await this.options.network.removeOwnedRule(input) };
    throw new RootFabricError('unsupported_operation', `no effect adapter is registered for ${definition.operation}`);
  }

  private async service(operation: string, input: JsonObject): Promise<BrokerEffectResult> {
    const manager = this.options.systemd ?? new SystemdManager();
    const target = unit(input.unit);
    if (operation === 'service.status') return { classification: 'SUCCEEDED', result: commandResult(await manager.show({ unit: target, properties: ['LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'InvocationID', 'FragmentPath'] })) };
    const action = operation.slice('service.'.length) as 'start' | 'stop' | 'restart' | 'reload' | 'enable' | 'disable';
    const result = await manager.action(action, { unit: target, timeoutMs: integer(input.timeoutMs ?? 300_000, 'timeoutMs', 1, 3_600_000) });
    const readback = await manager.show({ unit: target, properties: ['LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'InvocationID', 'FragmentPath'] });
    return { classification: result.exitCode === 0 ? 'SUCCEEDED' : 'FAILED', result: { action: commandResult(result), readback: commandResult(readback) }, executionIdentity: { unit: target } };
  }

  private async filesystem(operation: string, input: JsonObject, request: RootBrokerRequest): Promise<BrokerEffectResult> {
    const confined = ensureConfined(input.root, input.path, operation.includes('create') || operation.includes('replace') || operation.includes('switch'));
    const prior = await capturePrior(this.options.artifacts, request.transactionId, String(request.transactionSequence), confined.path);
    if (operation === 'filesystem.file.create' || operation === 'filesystem.file.replace') {
      const payload = strictObject(input, 'file effect input', ['root', 'path', 'data', 'encoding', 'mode', 'uid', 'gid', 'expectedSha256', 'expectedAbsent']);
      const current = fileState(confined.path);
      if (payload.expectedAbsent === true && current.exists === true) throw new RootFabricError('precondition_failed', 'file was expected to be absent');
      if (payload.expectedSha256 !== undefined && current.sha256 !== text(payload.expectedSha256, 'expectedSha256', 64)) throw new RootFabricError('expected_digest_mismatch', 'existing file digest does not match');
      const encoding = payload.encoding === 'base64' ? 'base64' : 'utf8';
      const data = Buffer.from(text(payload.data, 'data', 67_108_864), encoding);
      writeAtomic(confined.path, data, integer(payload.mode ?? 0o600, 'mode', 0, 0o7777), payload.uid === undefined ? undefined : integer(payload.uid, 'uid', 0, 2 ** 31 - 1), payload.gid === undefined ? undefined : integer(payload.gid, 'gid', 0, 2 ** 31 - 1));
    } else if (operation === 'filesystem.file.remove') {
      const current = lstatSync(confined.path); if (!current.isFile()) throw new RootFabricError('precondition_failed', 'target is not a regular file'); unlinkSync(confined.path);
    } else if (operation === 'filesystem.directory.create') {
      mkdirSync(confined.path, { mode: integer(input.mode ?? 0o700, 'mode', 0, 0o7777) });
    } else if (operation === 'filesystem.directory.remove') {
      const current = lstatSync(confined.path); if (!current.isDirectory()) throw new RootFabricError('precondition_failed', 'target is not a directory'); rmSync(confined.path, { recursive: false });
    } else if (operation === 'filesystem.metadata.update') {
      if (input.mode !== undefined) chmodSync(confined.path, integer(input.mode, 'mode', 0, 0o7777));
      if (input.uid !== undefined || input.gid !== undefined) chownSync(confined.path, input.uid === undefined ? statSync(confined.path).uid : integer(input.uid, 'uid', 0, 2 ** 31 - 1), input.gid === undefined ? statSync(confined.path).gid : integer(input.gid, 'gid', 0, 2 ** 31 - 1));
    } else if (operation === 'filesystem.symlink.replace' || operation === 'filesystem.release-pointer.switch') {
      const target = text(input.target, 'target', 4_096);
      if (operation === 'filesystem.release-pointer.switch' && !target.startsWith('/opt/baby-x/releases/')) throw new RootFabricError('policy_denied', 'release pointer target must be an immutable Baby-X release');
      const temporary = join(confined.parent, `.${randomUUID()}.babyx.link`);
      symlinkSync(target, temporary); renameSync(temporary, confined.path);
    }
    const observed = fileState(confined.path);
    return { classification: 'SUCCEEDED', result: { operation, priorState: prior, observedState: observed, targetDigest: sha256(canonicalize(observed)) }, cleanupState: { temporaryAbsent: true }, observationDigest: sha256(canonicalize({ operation, path: confined.path, observed })) };
  }
}
