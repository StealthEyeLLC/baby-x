import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import { MediationError } from './errors.ts';
import { runtimeArchitecture, syscallNumber, type MediationArchitecture } from './syscall-tables.ts';

export const MEDIATION_PROFILE_SCHEMA_VERSION = '1.0.0' as const;
export const MEDIATION_PROVIDER_CONTRACT_VERSION = '1.0.0' as const;
export const MEDIATION_LAYERS = ['SECCOMP_FILTER', 'SECCOMP_NOTIFY', 'LANDLOCK', 'BPF_LSM'] as const;
export type MediationLayer = typeof MEDIATION_LAYERS[number];
export type ProfileStatus = 'ACTIVE' | 'REVOKED';

export interface DefaultAction extends JsonObject { kind: 'allow' | 'errno' | 'kill'; errno: number | null }
export interface DeniedSyscall extends JsonObject { syscall: string; syscallNumber: number; action: 'errno' | 'kill'; errno: number | null }
export interface NotifiedSyscall extends JsonObject { syscall: string; syscallNumber: number; decision: 'allow' | 'deny' | 'emulate'; errno: number | null; value: number | null }
export interface ArgumentConstraint extends JsonObject { syscall: string; syscallNumber: number; index: number; value: number }
export interface PathConstraint extends JsonObject { path: string; access: 'read' | 'write' }
export interface SocketConstraint extends JsonObject { protocol: 'tcp'; action: 'bind' | 'connect'; port: number }
export interface BpfRules extends JsonObject { mode: 'observe' | 'enforce'; hooks: string[] }

export interface MediationProfileSpec extends JsonObject {
  schemaVersion: typeof MEDIATION_PROFILE_SCHEMA_VERSION;
  version: string;
  skillBundleDigest: string;
  grantDigest: string;
  providerScope: MediationLayer[];
  architecture: MediationArchitecture;
  defaultAction: DefaultAction;
  allowedSyscalls: string[];
  deniedSyscalls: DeniedSyscall[];
  notifiedSyscalls: NotifiedSyscall[];
  argumentConstraints: ArgumentConstraint[];
  pathConstraints: PathConstraint[];
  socketConstraints: SocketConstraint[];
  landlockRules: JsonObject;
  bpfRules: BpfRules;
  expiresAt: string;
  profileDigest: string;
}

const DIGEST = /^[a-f0-9]{64}$/u;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/u;
const LAYERS = new Set<string>(MEDIATION_LAYERS);
const INPUT_KEYS = new Set([
  'version', 'skillBundleDigest', 'grantDigest', 'providerScope', 'architecture', 'defaultAction',
  'allowedSyscalls', 'deniedSyscalls', 'notifiedSyscalls', 'argumentConstraints', 'pathConstraints',
  'socketConstraints', 'bpfRules', 'expiresAt',
]);

function object(value: unknown, field: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new MediationError('mediation_invalid_request', `${field} must be an object`);
  return value as JsonObject;
}

function strict(value: unknown, field: string, keys: readonly string[]): JsonObject {
  const result = object(value, field);
  const allowed = new Set(keys);
  const unknown = Object.keys(result).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw new MediationError('mediation_invalid_request', `${field} contains unsupported properties`, { properties: unknown });
  return result;
}

function text(value: unknown, field: string, maximum = 256): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || value.includes('\0')) throw new MediationError('mediation_invalid_request', `${field} must be a bounded non-empty NUL-free string`);
  return value;
}

function digest(value: unknown, field: string): string {
  const normalized = text(value, field, 64);
  if (!DIGEST.test(normalized)) throw new MediationError('mediation_invalid_request', `${field} must be a lowercase SHA-256 digest`);
  return normalized;
}

function integer(value: unknown, field: string, minimum: number, maximum: number): number {
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < minimum || normalized > maximum) throw new MediationError('mediation_invalid_request', `${field} must be an integer between ${minimum} and ${maximum}`);
  return normalized;
}

function list(value: unknown, field: string, maximum = 128): unknown[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > maximum) throw new MediationError('mediation_invalid_request', `${field} must be a bounded array`);
  return value;
}

function enumValue<T extends string>(value: unknown, field: string, allowed: readonly T[]): T {
  if (typeof value !== 'string' || !allowed.includes(value as T)) throw new MediationError('mediation_invalid_request', `${field} is invalid`);
  return value as T;
}

function syscallList(value: unknown, field: string, architecture: MediationArchitecture): string[] {
  const normalized = list(value, field).map((entry, index) => {
    const name = text(entry, `${field}[${index}]`, 64);
    syscallNumber(architecture, name);
    return name;
  });
  if (new Set(normalized).size !== normalized.length) throw new MediationError('mediation_invalid_request', `${field} must not contain duplicates`);
  return [...normalized].sort();
}

function defaultAction(value: unknown): DefaultAction {
  if (value === undefined) return { kind: 'allow', errno: null };
  const input = strict(value, 'defaultAction', ['kind', 'errno']);
  const kind = enumValue(input.kind, 'defaultAction.kind', ['allow', 'errno', 'kill'] as const);
  const errorNumber = kind === 'errno' ? integer(input.errno, 'defaultAction.errno', 1, 4095) : null;
  if (kind !== 'errno' && input.errno !== undefined && input.errno !== null) throw new MediationError('mediation_invalid_request', 'defaultAction.errno is only valid for errno');
  return { kind, errno: errorNumber };
}

function denied(value: unknown, architecture: MediationArchitecture): DeniedSyscall[] {
  const normalized = list(value, 'deniedSyscalls').map((entry, index) => {
    const input = strict(entry, `deniedSyscalls[${index}]`, ['syscall', 'action', 'errno']);
    const syscall = text(input.syscall, `deniedSyscalls[${index}].syscall`, 64);
    const action = enumValue(input.action, `deniedSyscalls[${index}].action`, ['errno', 'kill'] as const);
    const errorNumber = action === 'errno' ? integer(input.errno, `deniedSyscalls[${index}].errno`, 1, 4095) : null;
    if (action === 'kill' && input.errno !== undefined && input.errno !== null) throw new MediationError('mediation_invalid_request', 'kill rules cannot include errno');
    return { syscall, syscallNumber: syscallNumber(architecture, syscall), action, errno: errorNumber };
  });
  const names = normalized.map((entry) => entry.syscall);
  if (new Set(names).size !== names.length) throw new MediationError('mediation_invalid_request', 'deniedSyscalls must not contain duplicates');
  return normalized.sort((left, right) => left.syscall.localeCompare(right.syscall));
}

function notified(value: unknown, architecture: MediationArchitecture): NotifiedSyscall[] {
  const normalized = list(value, 'notifiedSyscalls').map((entry, index) => {
    const input = strict(entry, `notifiedSyscalls[${index}]`, ['syscall', 'decision', 'errno', 'value']);
    const syscall = text(input.syscall, `notifiedSyscalls[${index}].syscall`, 64);
    const decision = enumValue(input.decision, `notifiedSyscalls[${index}].decision`, ['allow', 'deny', 'emulate'] as const);
    const errorNumber = decision === 'deny' ? (input.errno === undefined ? 1 : integer(input.errno, `notifiedSyscalls[${index}].errno`, 1, 4095)) : null;
    const emulatedValue = decision === 'emulate' ? integer(input.value, `notifiedSyscalls[${index}].value`, 0, Number.MAX_SAFE_INTEGER) : null;
    if (decision !== 'deny' && input.errno !== undefined && input.errno !== null) throw new MediationError('mediation_invalid_request', 'notify errno is only valid for deny');
    if (decision !== 'emulate' && input.value !== undefined && input.value !== null) throw new MediationError('mediation_invalid_request', 'notify value is only valid for emulate');
    return { syscall, syscallNumber: syscallNumber(architecture, syscall), decision, errno: errorNumber, value: emulatedValue };
  });
  const names = normalized.map((entry) => entry.syscall);
  if (new Set(names).size !== names.length) throw new MediationError('mediation_invalid_request', 'notifiedSyscalls must not contain duplicates');
  return normalized.sort((left, right) => left.syscall.localeCompare(right.syscall));
}

function argumentsFor(value: unknown, architecture: MediationArchitecture): ArgumentConstraint[] {
  const normalized = list(value, 'argumentConstraints').map((entry, index) => {
    const input = strict(entry, `argumentConstraints[${index}]`, ['syscall', 'index', 'value']);
    const syscall = text(input.syscall, `argumentConstraints[${index}].syscall`, 64);
    return { syscall, syscallNumber: syscallNumber(architecture, syscall), index: integer(input.index, `argumentConstraints[${index}].index`, 0, 5), value: integer(input.value, `argumentConstraints[${index}].value`, 0, Number.MAX_SAFE_INTEGER) };
  });
  const keys = normalized.map((entry) => `${entry.syscall}:${entry.index}`);
  if (new Set(keys).size !== keys.length) throw new MediationError('mediation_invalid_request', 'argumentConstraints must not contain duplicate syscall indexes');
  return normalized.sort((left, right) => left.syscall.localeCompare(right.syscall) || left.index - right.index);
}

function paths(value: unknown): PathConstraint[] {
  const normalized = list(value, 'pathConstraints', 64).map((entry, index) => {
    const input = strict(entry, `pathConstraints[${index}]`, ['path', 'access']);
    const path = text(input.path, `pathConstraints[${index}].path`, 4096);
    if (!path.startsWith('/') || path.includes('/../') || path.endsWith('/..')) throw new MediationError('mediation_invalid_request', 'path constraints require absolute normalized paths');
    return { path, access: enumValue(input.access, `pathConstraints[${index}].access`, ['read', 'write'] as const) };
  });
  const keys = normalized.map((entry) => `${entry.access}:${entry.path}`);
  if (new Set(keys).size !== keys.length) throw new MediationError('mediation_invalid_request', 'pathConstraints must not contain duplicates');
  return normalized.sort((left, right) => left.path.localeCompare(right.path) || left.access.localeCompare(right.access));
}

function sockets(value: unknown): SocketConstraint[] {
  const normalized = list(value, 'socketConstraints', 64).map((entry, index) => {
    const input = strict(entry, `socketConstraints[${index}]`, ['protocol', 'action', 'port']);
    return { protocol: enumValue(input.protocol, `socketConstraints[${index}].protocol`, ['tcp'] as const), action: enumValue(input.action, `socketConstraints[${index}].action`, ['bind', 'connect'] as const), port: integer(input.port, `socketConstraints[${index}].port`, 0, 65535) };
  });
  const keys = normalized.map((entry) => `${entry.protocol}:${entry.action}:${entry.port}`);
  if (new Set(keys).size !== keys.length) throw new MediationError('mediation_invalid_request', 'socketConstraints must not contain duplicates');
  return normalized.sort((left, right) => left.action.localeCompare(right.action) || left.port - right.port);
}

function bpf(value: unknown): BpfRules {
  if (value === undefined) return { mode: 'observe', hooks: [] };
  const input = strict(value, 'bpfRules', ['mode', 'hooks']);
  const mode = enumValue(input.mode, 'bpfRules.mode', ['observe', 'enforce'] as const);
  const hooks = list(input.hooks, 'bpfRules.hooks', 32).map((entry, index) => text(entry, `bpfRules.hooks[${index}]`, 128));
  if (new Set(hooks).size !== hooks.length) throw new MediationError('mediation_invalid_request', 'bpfRules.hooks must not contain duplicates');
  return { mode, hooks: [...hooks].sort() };
}

export function normalizeMediationProfile(value: unknown, now = new Date()): MediationProfileSpec {
  const input = object(value, 'mediation profile');
  const unknown = Object.keys(input).filter((key) => !INPUT_KEYS.has(key));
  if (unknown.length > 0) throw new MediationError('mediation_invalid_request', 'mediation profile contains unsupported properties', { properties: unknown });
  const architecture = enumValue(input.architecture ?? runtimeArchitecture(), 'architecture', ['x86_64', 'aarch64'] as const);
  if (architecture !== runtimeArchitecture()) throw new MediationError('mediation_invalid_request', 'profile architecture is incompatible with this runtime', { requested: architecture, runtime: runtimeArchitecture() });
  const providerScope = list(input.providerScope, 'providerScope', 4).map((entry, index) => {
    const layer = text(entry, `providerScope[${index}]`, 32);
    if (!LAYERS.has(layer)) throw new MediationError('mediation_invalid_request', `unknown mediation layer: ${layer}`);
    return layer as MediationLayer;
  });
  if (providerScope.length < 1 || new Set(providerScope).size !== providerScope.length) throw new MediationError('mediation_invalid_request', 'providerScope must contain one or more unique layers');
  const normalizedDefaultAction = defaultAction(input.defaultAction);
  const allowedSyscalls = syscallList(input.allowedSyscalls, 'allowedSyscalls', architecture);
  const deniedSyscalls = denied(input.deniedSyscalls, architecture);
  const notifiedSyscalls = notified(input.notifiedSyscalls, architecture);
  if ((allowedSyscalls.length > 0 || deniedSyscalls.length > 0 || normalizedDefaultAction.kind !== 'allow') && !providerScope.includes('SECCOMP_FILTER')) throw new MediationError('mediation_invalid_request', 'filter rules require SECCOMP_FILTER scope');
  if (notifiedSyscalls.length > 0 && !providerScope.includes('SECCOMP_NOTIFY')) throw new MediationError('mediation_invalid_request', 'notification rules require SECCOMP_NOTIFY scope');
  const classified = [...allowedSyscalls, ...deniedSyscalls.map((entry) => entry.syscall), ...notifiedSyscalls.map((entry) => entry.syscall)];
  if (new Set(classified).size !== classified.length) throw new MediationError('mediation_invalid_request', 'a syscall cannot be allowed, denied, and notified simultaneously');
  const argumentConstraints = argumentsFor(input.argumentConstraints, architecture);
  const notifiedNames = new Set(notifiedSyscalls.map((entry) => entry.syscall));
  if (argumentConstraints.some((entry) => !notifiedNames.has(entry.syscall))) throw new MediationError('mediation_invalid_request', 'argument constraints require a notified syscall');
  const pathConstraints = paths(input.pathConstraints);
  const socketConstraints = sockets(input.socketConstraints);
  if (pathConstraints.length > 0 || socketConstraints.length > 0) {
    if (!providerScope.includes('LANDLOCK')) throw new MediationError('mediation_invalid_request', 'path and socket constraints require LANDLOCK scope');
  }
  const bpfRules = bpf(input.bpfRules);
  if ((bpfRules.hooks.length > 0 || bpfRules.mode === 'enforce') && !providerScope.includes('BPF_LSM')) throw new MediationError('mediation_invalid_request', 'BPF rules require BPF_LSM scope');
  const expiresAt = text(input.expiresAt, 'expiresAt', 64);
  const expiry = Date.parse(expiresAt);
  if (!Number.isFinite(expiry) || expiry <= now.getTime()) throw new MediationError('mediation_invalid_request', 'expiresAt must be a future ISO-8601 timestamp');
  const version = text(input.version, 'version', 64);
  if (!VERSION.test(version)) throw new MediationError('mediation_invalid_request', 'version is invalid');
  const unsigned = {
    schemaVersion: MEDIATION_PROFILE_SCHEMA_VERSION,
    version,
    skillBundleDigest: digest(input.skillBundleDigest, 'skillBundleDigest'),
    grantDigest: digest(input.grantDigest, 'grantDigest'),
    providerScope: [...providerScope].sort(),
    architecture,
    defaultAction: normalizedDefaultAction,
    allowedSyscalls,
    deniedSyscalls,
    notifiedSyscalls,
    argumentConstraints,
    pathConstraints,
    socketConstraints,
    landlockRules: { paths: pathConstraints, tcpPorts: socketConstraints },
    bpfRules,
    expiresAt: new Date(expiry).toISOString(),
  };
  return { ...unsigned, profileDigest: sha256(canonicalize(unsigned)) } as MediationProfileSpec;
}

export function strictMediationPayload(value: unknown, field: string, allowed: readonly string[]): JsonObject {
  return strict(value, field, allowed);
}
