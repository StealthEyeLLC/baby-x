import { lstatSync, readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { canonicalize, sha256, type CommandResult, type JsonObject } from '../core.ts';
import { SystemdManager } from '../systemd/manager.ts';
import { processIdentity as readProcessIdentity } from '../process/identity.ts';
import { RootFabricError, integer, strictObject, text } from './model.ts';
import type { BrokerEffectResult, RootBrokerRequest } from './broker.ts';

export interface HostEnvelopeProfile extends JsonObject {
  unit: string;
  argv: string[];
  workingDirectory: string;
  user: string;
  group: string;
  environment: string[];
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

const UNIT = /^[A-Za-z0-9_.@:-]+$/u;
const SIGNAL = /^SIG[A-Z0-9]+$/u;
const IDENTITY_PROPERTIES = ['Id', 'InvocationID', 'MainPID', 'ExecMainStartTimestampMonotonic', 'ControlGroup', 'ActiveState', 'SubState', 'Result', 'Environment'] as const;

function identifierLike(value: unknown, field: string): string {
  const result = text(value, field, 256);
  if (!/^[A-Za-z0-9_.@:-]+$/u.test(result) || result.startsWith('-')) throw new RootFabricError('invalid_request', `${field} is invalid`);
  return result;
}
function stringList(value: unknown, field: string, maximum: number): string[] {
  if (!Array.isArray(value) || value.length > maximum || value.some((entry) => typeof entry !== 'string' || entry.length === 0 || entry.includes('\0'))) throw new RootFabricError('invalid_request', `${field} must be a bounded NUL-free string array`);
  return [...new Set(value as string[])];
}
function pathList(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length > 128) throw new RootFabricError('invalid_request', `${field} must be a bounded path array`);
  return value.map((entry, index) => { const path = text(entry, `${field}[${index}]`, 4_096); if (!isAbsolute(path)) throw new RootFabricError('invalid_request', `${field} paths must be absolute`); return path; });
}
function absoluteExecutable(value: unknown): string {
  const executable = text(value, 'executable', 4_096);
  if (!isAbsolute(executable)) throw new RootFabricError('invalid_request', 'executable must be absolute');
  const info = lstatSync(executable);
  if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o111) === 0) throw new RootFabricError('precondition_failed', 'executable must be a non-symlink executable regular file');
  return executable;
}
function commandResult(value: CommandResult): JsonObject { return value as unknown as JsonObject; }
function parseShow(stdout: string): JsonObject {
  const result: JsonObject = {};
  for (const line of stdout.split(/\r?\n/u)) {
    const at = line.indexOf('=');
    if (at > 0) result[line.slice(0, at)] = line.slice(at + 1);
  }
  return result;
}
function bootId(): string {
  const value = readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
  if (!/^[a-f0-9-]{36}$/u.test(value)) throw new RootFabricError('identity_mismatch', 'host boot identity is malformed');
  return value;
}

export class HostEnvelopeProvider {
  constructor(private readonly systemd: SystemdManager = new SystemdManager()) {}

  profile(inputValue: unknown, request: RootBrokerRequest): HostEnvelopeProfile {
    const input = strictObject(inputValue, 'host envelope input', ['executable', 'argv', 'workingDirectory', 'user', 'group', 'environment', 'timeoutMs', 'cpuQuota', 'memoryMax', 'ioWeight', 'tasksMax', 'readOnlyPaths', 'readWritePaths', 'inaccessiblePaths', 'restrictAddressFamilies', 'systemCallFilter', 'capabilityBoundingSet', 'credentialPaths']);
    const executable = absoluteExecutable(input.executable);
    if (!Array.isArray(input.argv) || input.argv.length > 256 || input.argv.some((entry) => typeof entry !== 'string' || entry.includes('\0'))) throw new RootFabricError('invalid_request', 'argv must be a bounded NUL-free string array');
    const environment = stringList(input.environment ?? [], 'environment', 256);
    for (const entry of environment) {
      if (!/^[A-Z_][A-Z0-9_]*=[^\0]*$/u.test(entry)) throw new RootFabricError('invalid_request', 'environment must be an explicit NAME=value allowlist');
      if (entry.startsWith('BABYX_ROOT_TRANSACTION_ID=') || entry.startsWith('BABYX_ROOT_REQUEST_DIGEST=')) throw new RootFabricError('invalid_request', 'reserved root authority environment markers may not be caller supplied');
    }
    const suffix = sha256(`${request.transactionId}:${request.transactionSequence}:${request.inputDigest}`).slice(0, 16);
    return {
      unit: `babyx-root-${suffix}.service`, argv: [executable, ...(input.argv as string[])], workingDirectory: text(input.workingDirectory, 'workingDirectory', 4_096),
      user: identifierLike(input.user, 'user'), group: identifierLike(input.group, 'group'), environment,
      timeoutMs: integer(input.timeoutMs, 'timeoutMs', 1, 3_600_000), cpuQuota: text(input.cpuQuota, 'cpuQuota', 32), memoryMax: text(input.memoryMax, 'memoryMax', 32), ioWeight: text(input.ioWeight, 'ioWeight', 32), tasksMax: integer(input.tasksMax, 'tasksMax', 1, 65_536),
      readOnlyPaths: pathList(input.readOnlyPaths ?? [], 'readOnlyPaths'), readWritePaths: pathList(input.readWritePaths ?? [], 'readWritePaths'), inaccessiblePaths: pathList(input.inaccessiblePaths ?? [], 'inaccessiblePaths'),
      restrictAddressFamilies: stringList(input.restrictAddressFamilies ?? [], 'restrictAddressFamilies', 32), systemCallFilter: stringList(input.systemCallFilter ?? [], 'systemCallFilter', 512), capabilityBoundingSet: stringList(input.capabilityBoundingSet ?? [], 'capabilityBoundingSet', 128), credentialPaths: pathList(input.credentialPaths ?? [], 'credentialPaths'),
    };
  }

  async execute(input: JsonObject, request: RootBrokerRequest): Promise<BrokerEffectResult> {
    const profile = this.profile(input, request);
    const properties: Record<string, string> = {
      Type: 'exec', WorkingDirectory: profile.workingDirectory, User: profile.user, Group: profile.group,
      RuntimeMaxSec: String(Math.ceil(profile.timeoutMs / 1_000)), KillMode: 'control-group', CollectMode: 'inactive-or-failed', Slice: 'baby-x-root.slice',
      CPUQuota: profile.cpuQuota, MemoryMax: profile.memoryMax, IOWeight: profile.ioWeight, TasksMax: String(profile.tasksMax),
      NoNewPrivileges: 'yes', PrivateTmp: 'yes', ProtectSystem: 'strict', ProtectHome: 'yes', RestrictNamespaces: 'yes', LockPersonality: 'yes', MemoryDenyWriteExecute: 'yes',
      ProtectKernelTunables: 'yes', ProtectKernelModules: 'yes', ProtectControlGroups: 'yes', RestrictSUIDSGID: 'yes', RemoveIPC: 'yes', PrivateDevices: 'yes',
      Environment: [...profile.environment, `BABYX_ROOT_TRANSACTION_ID=${request.transactionId}`, `BABYX_ROOT_REQUEST_DIGEST=${sha256(canonicalize(request))}`].join(' '),
    };
    if (profile.readOnlyPaths.length > 0) properties.ReadOnlyPaths = profile.readOnlyPaths.join(' ');
    if (profile.readWritePaths.length > 0) properties.ReadWritePaths = profile.readWritePaths.join(' ');
    if (profile.inaccessiblePaths.length > 0) properties.InaccessiblePaths = profile.inaccessiblePaths.join(' ');
    if (profile.restrictAddressFamilies.length > 0) properties.RestrictAddressFamilies = profile.restrictAddressFamilies.join(' ');
    if (profile.systemCallFilter.length > 0) properties.SystemCallFilter = profile.systemCallFilter.join(' ');
    if (profile.capabilityBoundingSet.length > 0) properties.CapabilityBoundingSet = profile.capabilityBoundingSet.join(' ');
    const propertyEntries = profile.credentialPaths.map((path, index) => `LoadCredential=credential-${index}:${path}`);
    const launched = await this.systemd.run({ argv: profile.argv, unit: profile.unit.replace(/\.service$/u, ''), properties, propertyEntries, timeoutMs: profile.timeoutMs });
    const readback = await this.readback(profile.unit);
    const mainPid = Number(readback.MainPID ?? '0');
    let processReadback: { processStartTime: string; executablePath: string; bootId: string } | null = null;
    if (Number.isSafeInteger(mainPid) && mainPid > 0) {
      try { processReadback = readProcessIdentity(mainPid); } catch { processReadback = null; }
    }
    return {
      classification: launched.exitCode === 0 ? 'SUCCEEDED' : 'FAILED',
      executionIdentity: { unit: profile.unit, unitName: profile.unit, transactionId: request.transactionId, requestDigest: sha256(canonicalize(request)), invocationId: readback.InvocationID ?? '', mainPid: readback.MainPID ?? '0', processId: mainPid, processStartTime: processReadback?.processStartTime ?? readback.ExecMainStartTimestampMonotonic ?? '0', systemdStartTimestamp: readback.ExecMainStartTimestampMonotonic ?? '0', bootId: processReadback?.bootId ?? bootId(), cgroup: readback.ControlGroup ?? '', cgroupId: readback.ControlGroup ?? '', executablePath: processReadback?.executablePath ?? profile.argv[0]!, provider: 'systemd-transient', profileDigest: sha256(canonicalize(profile)) },
      result: commandResult(launched), cleanupState: { readback, unitCollected: readback.ActiveState === 'inactive' || readback.ActiveState === 'failed', cgroupEmpty: readback.MainPID === '0' },
    };
  }

  async readback(unitName: string): Promise<JsonObject> {
    if (!UNIT.test(unitName)) throw new RootFabricError('invalid_request', 'unit name is invalid');
    const result = await this.systemd.show({ unit: unitName, properties: IDENTITY_PROPERTIES });
    if (result.exitCode !== 0) return { Id: unitName, ActiveState: 'absent', MainPID: '0', readback: commandResult(result) };
    return { ...parseShow(result.stdout), readback: commandResult(result) };
  }

  async cancel(unitName: string, signalName = 'SIGTERM'): Promise<JsonObject> {
    if (!UNIT.test(unitName) || !SIGNAL.test(signalName)) throw new RootFabricError('invalid_request', 'unit or signal is invalid');
    const signalled = await this.systemd.kill({ unit: unitName, signal: signalName, who: 'all' });
    const killed = await this.systemd.kill({ unit: unitName, signal: 'SIGKILL', who: 'all' });
    const readback = await this.readback(unitName);
    return { signalled: commandResult(signalled), killed: commandResult(killed), readback, complete: readback.MainPID === '0' || readback.ActiveState === 'absent' };
  }

  async signal(unitName: string, signalName: string): Promise<JsonObject> {
    if (!UNIT.test(unitName) || !SIGNAL.test(signalName)) throw new RootFabricError('invalid_request', 'unit or signal is invalid');
    return commandResult(await this.systemd.kill({ unit: unitName, signal: signalName, who: 'all' }));
  }
  async freeze(unitName: string, frozen: boolean): Promise<JsonObject> {
    if (!UNIT.test(unitName)) throw new RootFabricError('invalid_request', 'unit name is invalid');
    const result = await this.systemd.raw('systemctl', ['--system', '--no-pager', frozen ? 'freeze' : 'thaw', '--', unitName]);
    return { action: frozen ? 'freeze' : 'thaw', result: commandResult(result), readback: await this.readback(unitName) };
  }
}
