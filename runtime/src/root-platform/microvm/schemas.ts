import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import { MicrovmError } from './errors.ts';

export const MICROVM_SCHEMA_VERSION = '1.0.0' as const;
export const MICROVM_LIFECYCLES = ['REQUESTED','PREPARING','STARTING','BOOTING','READY','RUNNING','STOPPING','STOPPED','FAILED','LOST','CLEANING','CLEANED','AMBIGUOUS','RECOVERY_REQUIRED'] as const;
export type MicrovmLifecycle = typeof MICROVM_LIFECYCLES[number];

const DIGEST = /^[a-f0-9]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const TRANSACTION = /^rtx_[A-Za-z0-9_-]{8,128}$/u;
const VM_ID = /^mvm_[a-f0-9]{32}$/u;
const TASK_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/u;

export interface MicrovmCreateRequest extends JsonObject {
  transactionId: string;
  skillBundleDigest: string;
  grantDigest: string;
  policyDigest: string;
  firecrackerVersion: 'v1.15.1';
  kernelDigest: string;
  rootImageDigest: string;
  vcpuCount: number;
  memoryMiB: number;
  networkMode: 'NONE';
}

function strictObject(value: unknown, name: string, allowed: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new MicrovmError('microvm_invalid_request', `${name} must be an object`);
  const input = value as Record<string, unknown>;
  const extras = Object.keys(input).filter((key) => !allowed.includes(key));
  if (extras.length > 0) throw new MicrovmError('microvm_invalid_request', `${name} has unsupported properties`, { properties: extras.sort() });
  return input;
}
function text(input: Record<string, unknown>, key: string, pattern: RegExp): string {
  const value = input[key];
  if (typeof value !== 'string' || !pattern.test(value)) throw new MicrovmError('microvm_invalid_request', `${key} is invalid`);
  return value;
}
function integer(input: Record<string, unknown>, key: string, minimum: number, maximum: number, fallback: number): number {
  const value = input[key] === undefined ? fallback : Number(input[key]);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new MicrovmError('microvm_invalid_request', `${key} must be between ${minimum} and ${maximum}`);
  return value;
}

export function normalizeCreateRequest(value: unknown): MicrovmCreateRequest {
  const input = strictObject(value, 'microVM create payload', ['transactionId','skillBundleDigest','grantDigest','policyDigest','firecrackerVersion','kernelDigest','rootImageDigest','vcpuCount','memoryMiB','networkMode']);
  const firecrackerVersion = input.firecrackerVersion ?? 'v1.15.1';
  const networkMode = input.networkMode ?? 'NONE';
  if (firecrackerVersion !== 'v1.15.1') throw new MicrovmError('microvm_invalid_request', 'firecrackerVersion must match the pinned provider');
  if (networkMode !== 'NONE') throw new MicrovmError('microvm_invalid_request', 'networking is disabled unless a later explicit policy provider is installed');
  return {
    transactionId: text(input, 'transactionId', TRANSACTION),
    skillBundleDigest: text(input, 'skillBundleDigest', DIGEST),
    grantDigest: text(input, 'grantDigest', DIGEST),
    policyDigest: text(input, 'policyDigest', DIGEST),
    firecrackerVersion,
    kernelDigest: text(input, 'kernelDigest', DIGEST),
    rootImageDigest: text(input, 'rootImageDigest', DIGEST),
    vcpuCount: integer(input, 'vcpuCount', 1, 8, 1),
    memoryMiB: integer(input, 'memoryMiB', 128, 4096, 256),
    networkMode,
  };
}

export function normalizeVmSelector(value: unknown): { vmId: string } {
  const input = strictObject(value, 'microVM selector', ['vmId']);
  return { vmId: text(input, 'vmId', VM_ID) };
}

export function normalizeListRequest(value: unknown): { ownerPrincipal?: string; lifecycle?: MicrovmLifecycle; offset: number; limit: number } {
  const input = strictObject(value, 'microVM list payload', ['ownerPrincipal','lifecycle','offset','limit']);
  const ownerPrincipal = input.ownerPrincipal;
  if (ownerPrincipal !== undefined && (typeof ownerPrincipal !== 'string' || !IDENTIFIER.test(ownerPrincipal))) throw new MicrovmError('microvm_invalid_request', 'ownerPrincipal is invalid');
  const lifecycle = input.lifecycle;
  if (lifecycle !== undefined && !MICROVM_LIFECYCLES.includes(lifecycle as MicrovmLifecycle)) throw new MicrovmError('microvm_invalid_request', 'lifecycle is invalid');
  return { ownerPrincipal: ownerPrincipal as string | undefined, lifecycle: lifecycle as MicrovmLifecycle | undefined, offset: integer(input,'offset',0,10_000_000,0), limit: integer(input,'limit',1,1000,100) };
}

export type MicrovmExecAction =
  | { action: 'ECHO'; taskId: string; input: string }
  | { action: 'SLEEP'; taskId: string; durationMs: number }
  | { action: 'STATUS'; taskId: string }
  | { action: 'CANCEL'; taskId: string };

export function normalizeExecRequest(value: unknown): { vmId: string; request: MicrovmExecAction } {
  const input = strictObject(value, 'microVM exec payload', ['vmId','action','taskId','input','durationMs']);
  const vmId = text(input,'vmId',VM_ID);
  const action = input.action;
  if (action !== 'ECHO' && action !== 'SLEEP' && action !== 'STATUS' && action !== 'CANCEL') throw new MicrovmError('microvm_invalid_request', 'action is invalid');
  const taskId = text(input,'taskId',TASK_ID);
  if (action === 'ECHO') {
    if (typeof input.input !== 'string' || Buffer.byteLength(input.input,'utf8') > 1024) throw new MicrovmError('microvm_invalid_request', 'input must be a UTF-8 string no larger than 1024 bytes');
    return { vmId, request: { action, taskId, input: input.input } };
  }
  if (action === 'SLEEP') return { vmId, request: { action, taskId, durationMs: integer(input,'durationMs',0,60_000,0) } };
  return { vmId, request: { action, taskId } };
}

export function createRequestDigest(ownerPrincipal: string, request: MicrovmCreateRequest): string {
  return sha256(canonicalize({ operation: 'babyx.root.microvm.create', ownerPrincipal, request }));
}


const SNAPSHOT_ID = /^mvs_[a-f0-9]{32}$/u;
const POOL_ID = /^mvp_[a-f0-9]{32}$/u;

export function normalizeSnapshotRequest(value: unknown, now = new Date()): { vmId: string; expiresAt: string } {
  const input = strictObject(value, 'microVM snapshot payload', ['vmId', 'expiresAt']);
  const vmId = text(input, 'vmId', VM_ID);
  const expiresAt = input.expiresAt === undefined ? new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString() : String(input.expiresAt);
  const parsed = Date.parse(expiresAt);
  if (!Number.isFinite(parsed) || parsed <= now.getTime() || parsed > now.getTime() + 30 * 24 * 60 * 60 * 1000) throw new MicrovmError('microvm_invalid_request', 'expiresAt must be a future ISO-8601 time within 30 days');
  return { vmId, expiresAt: new Date(parsed).toISOString() };
}

export interface MicrovmRestoreRequest extends JsonObject {
  snapshotId: string;
  transactionId: string;
  skillBundleDigest: string;
  grantDigest: string;
  policyDigest: string;
  networkMode: 'NONE';
}

export function normalizeRestoreRequest(value: unknown): MicrovmRestoreRequest {
  const input = strictObject(value, 'microVM restore payload', ['snapshotId', 'transactionId', 'skillBundleDigest', 'grantDigest', 'policyDigest', 'networkMode']);
  const networkMode = input.networkMode ?? 'NONE';
  if (networkMode !== 'NONE') throw new MicrovmError('microvm_invalid_request', 'snapshot restore networking is disabled');
  return { snapshotId: text(input, 'snapshotId', SNAPSHOT_ID), transactionId: text(input, 'transactionId', TRANSACTION), skillBundleDigest: text(input, 'skillBundleDigest', DIGEST), grantDigest: text(input, 'grantDigest', DIGEST), policyDigest: text(input, 'policyDigest', DIGEST), networkMode };
}

export type MicrovmPoolAction =
  | { action: 'RECONCILE'; poolId?: string; snapshotId: string; desiredWarmCount: number; expiresAt: string }
  | { action: 'ACQUIRE'; poolId: string; transactionId: string; skillBundleDigest: string; grantDigest: string; policyDigest: string }
  | { action: 'RELEASE'; poolId: string; vmId: string };

export function normalizePoolRequest(value: unknown, now = new Date()): MicrovmPoolAction {
  const input = strictObject(value, 'microVM pool payload', ['action', 'poolId', 'snapshotId', 'desiredWarmCount', 'maximumWarmCount', 'expiresAt', 'transactionId', 'skillBundleDigest', 'grantDigest', 'policyDigest', 'vmId']);
  const action = input.action;
  if (action === 'RECONCILE') {
    const maximumWarmCount = input.maximumWarmCount === undefined ? 1 : Number(input.maximumWarmCount);
    if (maximumWarmCount !== 1) throw new MicrovmError('microvm_invalid_request', 'Firecracker v1.15.1 snapshot pools support maximumWarmCount 1 because guest CID cannot be rewritten');
    const desiredWarmCount = integer(input, 'desiredWarmCount', 0, 1, 1);
    const expiresAt = input.expiresAt === undefined ? new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString() : String(input.expiresAt);
    const parsed = Date.parse(expiresAt);
    if (!Number.isFinite(parsed) || parsed <= now.getTime() || parsed > now.getTime() + 30 * 24 * 60 * 60 * 1000) throw new MicrovmError('microvm_invalid_request', 'expiresAt must be a future ISO-8601 time within 30 days');
    return { action, poolId: input.poolId === undefined ? undefined : text(input, 'poolId', POOL_ID), snapshotId: text(input, 'snapshotId', SNAPSHOT_ID), desiredWarmCount, expiresAt: new Date(parsed).toISOString() };
  }
  if (action === 'ACQUIRE') return { action, poolId: text(input, 'poolId', POOL_ID), transactionId: text(input, 'transactionId', TRANSACTION), skillBundleDigest: text(input, 'skillBundleDigest', DIGEST), grantDigest: text(input, 'grantDigest', DIGEST), policyDigest: text(input, 'policyDigest', DIGEST) };
  if (action === 'RELEASE') return { action, poolId: text(input, 'poolId', POOL_ID), vmId: text(input, 'vmId', VM_ID) };
  throw new MicrovmError('microvm_invalid_request', 'pool action is invalid');
}
