import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../../core.ts';
import { RootReplayError } from './errors.ts';
import { CHECKPOINT_KINDS, REPLAY_KINDS, type CheckpointKind, type ReplayCompatibility, type ReplayKind, type ReplayProcessIdentity } from './records.ts';

const DIGEST = /^[a-f0-9]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const TRANSACTION_ID = /^rtx_[A-Za-z0-9_-]{8,128}$/u;
const CHECKPOINT_ID = /^rcp_[a-f0-9]{32}$/u;
const REPLAY_ID = /^rrp_[a-f0-9]{32}$/u;
const SECRET_KEY = /(?:password|passwd|secret|token|credential|private[_-]?key|api[_-]?key|bearer|cookie)/iu;
const CHECKPOINT_SET = new Set<string>(CHECKPOINT_KINDS);
const REPLAY_SET = new Set<string>(REPLAY_KINDS);

function fail(code: string, message: string, details: JsonObject = {}): never { throw new RootReplayError(code, message, details); }
function object(value: unknown, field: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail('root_replay_invalid_request', `${field} must be an object`);
  return value as JsonObject;
}
function allowed(value: JsonObject, field: string, keys: readonly string[]): void {
  const permit = new Set(keys);
  const unknown = Object.keys(value).filter((key) => !permit.has(key));
  if (unknown.length > 0) fail('root_replay_invalid_request', `${field} contains unsupported properties`, { properties: unknown });
}
function text(value: unknown, field: string, maximum = 4096): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || value.includes('\0')) fail('root_replay_invalid_request', `${field} must be a bounded non-empty NUL-free string`);
  return value;
}
function digest(value: unknown, field: string): string {
  const normalized = text(value, field, 64);
  if (!DIGEST.test(normalized)) fail('root_replay_invalid_request', `${field} must be a lowercase SHA-256 digest`);
  return normalized;
}
function identifier(value: unknown, field: string): string {
  const normalized = text(value, field, 256);
  if (!IDENTIFIER.test(normalized)) fail('root_replay_invalid_request', `${field} is invalid`);
  return normalized;
}
function optionalTransaction(value: unknown, field = 'transactionId'): string | null {
  if (value === undefined || value === null) return null;
  const normalized = text(value, field, 160);
  if (!TRANSACTION_ID.test(normalized)) fail('root_replay_invalid_request', `${field} is invalid`);
  return normalized;
}
function timestamp(value: unknown, field: string): string {
  const normalized = text(value, field, 64);
  const parsed = Date.parse(normalized);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== normalized) fail('root_replay_invalid_request', `${field} must be an exact ISO-8601 UTC timestamp`);
  return normalized;
}
function absolutePath(value: unknown, field: string): string {
  const normalized = text(value, field, 4096);
  if (!normalized.startsWith('/')) fail('root_replay_invalid_request', `${field} must be absolute`);
  return normalized;
}
function safeInteger(value: unknown, field: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) fail('root_replay_invalid_request', `${field} must be a safe integer between ${minimum} and ${maximum}`);
  return Number(value);
}
function nullablePgid(value: unknown): number | null {
  if (value === undefined || value === null) return null;
  return safeInteger(value, 'process.pgid', 1, Number.MAX_SAFE_INTEGER);
}

export function ownerPrincipal(context: RuntimeExecutionContext): string {
  if (context.authorityClass !== undefined && context.authorityClass !== 'unrestricted-owner') fail('root_replay_authority_denied', 'unrestricted-owner authority is required');
  return identifier(context.subject ?? 'stealtheye-owner', 'owner principal');
}

export function idempotencyDigest(context: RuntimeExecutionContext): string {
  const value = context.idempotencyKey;
  if (typeof value !== 'string' || value.length < 8 || value.length > 256 || value.includes('\0')) fail('root_replay_idempotency_required', 'a bounded idempotency key is required');
  return sha256(value);
}

export function requestDigest(operation: string, principal: string, payload: JsonObject): string {
  return sha256(canonicalize({ operation, principal, payload }));
}

export function rejectSecretMaterial(value: unknown, path = 'canonicalInput'): void {
  if (value === null || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    if (value.length > 4096) fail('root_replay_invalid_request', `${path} is too large`);
    value.forEach((entry, index) => rejectSecretMaterial(entry, `${path}[${index}]`));
    return;
  }
  const candidate = value as JsonObject;
  for (const [key, entry] of Object.entries(candidate)) {
    if (SECRET_KEY.test(key)) fail('root_replay_secret_material_rejected', 'replay input may contain references or digests but not secret-bearing fields', { path: `${path}.${key}` });
    rejectSecretMaterial(entry, `${path}.${key}`);
  }
  if (Buffer.byteLength(canonicalize(value)) > 1024 * 1024) fail('root_replay_invalid_request', `${path} exceeds the maximum canonical size`);
}

function processIdentity(value: unknown): ReplayProcessIdentity {
  const payload = object(value, 'process');
  allowed(payload, 'process', ['pid', 'processStartTime', 'executablePath', 'pgid', 'bootId']);
  return {
    pid: safeInteger(payload.pid, 'process.pid', 1, Number.MAX_SAFE_INTEGER),
    processStartTime: text(payload.processStartTime, 'process.processStartTime', 128),
    executablePath: absolutePath(payload.executablePath, 'process.executablePath'),
    pgid: nullablePgid(payload.pgid),
    bootId: identifier(payload.bootId, 'process.bootId'),
  };
}

function compatibility(value: unknown): ReplayCompatibility {
  const payload = object(value, 'compatibility');
  allowed(payload, 'compatibility', ['architecture', 'kernelRelease', 'providerId', 'providerVersion', 'configurationDigest']);
  if (payload.architecture !== 'x86_64' && payload.architecture !== 'aarch64') fail('root_replay_invalid_request', 'compatibility.architecture is unsupported');
  return {
    architecture: payload.architecture,
    kernelRelease: text(payload.kernelRelease, 'compatibility.kernelRelease', 256),
    providerId: identifier(payload.providerId, 'compatibility.providerId'),
    providerVersion: text(payload.providerVersion, 'compatibility.providerVersion', 256),
    configurationDigest: digest(payload.configurationDigest, 'compatibility.configurationDigest'),
  };
}

export interface NormalizedCheckpointCreate extends JsonObject {
  kind: CheckpointKind;
  transactionId: string | null;
  process: ReplayProcessIdentity | null;
  imagesDir: string | null;
  traceReference: string | null;
  traceDigest: string | null;
  traceSizeBytes: number | null;
  vmId: string | null;
  expiresAt: string | null;
  compatibility: ReplayCompatibility;
}

export function normalizeCheckpointCreate(value: unknown): NormalizedCheckpointCreate {
  const payload = object(value, 'checkpoint create payload');
  allowed(payload, 'checkpoint create payload', ['kind', 'transactionId', 'process', 'imagesDir', 'traceReference', 'traceDigest', 'traceSizeBytes', 'vmId', 'expiresAt', 'compatibility']);
  if (typeof payload.kind !== 'string' || !CHECKPOINT_SET.has(payload.kind)) fail('root_replay_invalid_request', 'checkpoint kind is unsupported');
  const kind = payload.kind as CheckpointKind;
  const normalized: NormalizedCheckpointCreate = {
    kind,
    transactionId: optionalTransaction(payload.transactionId),
    process: payload.process === undefined ? null : processIdentity(payload.process),
    imagesDir: payload.imagesDir === undefined ? null : absolutePath(payload.imagesDir, 'imagesDir'),
    traceReference: payload.traceReference === undefined ? null : absolutePath(payload.traceReference, 'traceReference'),
    traceDigest: payload.traceDigest === undefined ? null : digest(payload.traceDigest, 'traceDigest'),
    traceSizeBytes: payload.traceSizeBytes === undefined ? null : safeInteger(payload.traceSizeBytes, 'traceSizeBytes', 0, Number.MAX_SAFE_INTEGER),
    vmId: payload.vmId === undefined ? null : identifier(payload.vmId, 'vmId'),
    expiresAt: payload.expiresAt === undefined ? null : timestamp(payload.expiresAt, 'expiresAt'),
    compatibility: compatibility(payload.compatibility),
  };
  if (kind === 'CRIU_PROCESS' && (normalized.process === null || normalized.imagesDir === null)) fail('root_replay_invalid_request', 'CRIU_PROCESS requires process and imagesDir');
  if (kind === 'RR_TRACE' && (normalized.traceReference === null || normalized.traceDigest === null)) fail('root_replay_invalid_request', 'RR_TRACE requires traceReference and traceDigest');
  if (kind === 'MICROVM_SNAPSHOT' && (normalized.vmId === null || normalized.expiresAt === null)) fail('root_replay_invalid_request', 'MICROVM_SNAPSHOT requires vmId and expiresAt');
  return normalized;
}

export function normalizeCheckpointGet(value: unknown): { checkpointId: string } {
  const payload = object(value, 'checkpoint get payload');
  allowed(payload, 'checkpoint get payload', ['checkpointId']);
  const checkpointId = text(payload.checkpointId, 'checkpointId', 64);
  if (!CHECKPOINT_ID.test(checkpointId)) fail('root_replay_invalid_request', 'checkpointId is invalid');
  return { checkpointId };
}

export interface NormalizedCheckpointRestore extends JsonObject {
  checkpointId: string;
  authorizationDigest: string;
  transactionId: string | null;
  target: JsonObject;
}

export function normalizeCheckpointRestore(value: unknown): NormalizedCheckpointRestore {
  const payload = object(value, 'checkpoint restore payload');
  allowed(payload, 'checkpoint restore payload', ['checkpointId', 'authorizationDigest', 'transactionId', 'target']);
  const checkpointId = text(payload.checkpointId, 'checkpointId', 64);
  if (!CHECKPOINT_ID.test(checkpointId)) fail('root_replay_invalid_request', 'checkpointId is invalid');
  const target = payload.target === undefined ? {} : object(payload.target, 'target');
  rejectSecretMaterial(target, 'target');
  return { checkpointId, authorizationDigest: digest(payload.authorizationDigest, 'authorizationDigest'), transactionId: optionalTransaction(payload.transactionId), target: structuredClone(target) };
}

export interface NormalizedReplayRun extends JsonObject {
  kind: ReplayKind;
  transactionId: string | null;
  checkpointId: string | null;
  canonicalInput: JsonObject | null;
  dryRun: boolean;
  authorizationDigest: string | null;
  effectTransactionId: string | null;
  target: JsonObject;
}

export function normalizeReplayRun(value: unknown): NormalizedReplayRun {
  const payload = object(value, 'replay run payload');
  allowed(payload, 'replay run payload', ['kind', 'transactionId', 'checkpointId', 'canonicalInput', 'dryRun', 'authorizationDigest', 'effectTransactionId', 'target']);
  if (typeof payload.kind !== 'string' || !REPLAY_SET.has(payload.kind)) fail('root_replay_invalid_request', 'replay kind is unsupported');
  const checkpointId = payload.checkpointId === undefined || payload.checkpointId === null ? null : text(payload.checkpointId, 'checkpointId', 64);
  if (checkpointId !== null && !CHECKPOINT_ID.test(checkpointId)) fail('root_replay_invalid_request', 'checkpointId is invalid');
  const canonicalInput = payload.canonicalInput === undefined || payload.canonicalInput === null ? null : object(payload.canonicalInput, 'canonicalInput');
  if (canonicalInput !== null) rejectSecretMaterial(canonicalInput);
  const target = payload.target === undefined ? {} : object(payload.target, 'target');
  rejectSecretMaterial(target, 'target');
  const dryRun = payload.dryRun === undefined ? true : payload.dryRun;
  if (typeof dryRun !== 'boolean') fail('root_replay_invalid_request', 'dryRun must be a boolean');
  return {
    kind: payload.kind as ReplayKind,
    transactionId: optionalTransaction(payload.transactionId),
    checkpointId,
    canonicalInput: canonicalInput === null ? null : structuredClone(canonicalInput),
    dryRun,
    authorizationDigest: payload.authorizationDigest === undefined || payload.authorizationDigest === null ? null : digest(payload.authorizationDigest, 'authorizationDigest'),
    effectTransactionId: optionalTransaction(payload.effectTransactionId, 'effectTransactionId'),
    target: structuredClone(target),
  };
}

export function normalizeReplayGet(value: unknown): { replayId: string } {
  const payload = object(value, 'replay get payload');
  allowed(payload, 'replay get payload', ['replayId']);
  const replayId = text(payload.replayId, 'replayId', 64);
  if (!REPLAY_ID.test(replayId)) fail('root_replay_invalid_request', 'replayId is invalid');
  return { replayId };
}
