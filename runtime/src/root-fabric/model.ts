import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';

export const ROOT_FABRIC_SCHEMA_VERSION = '1.0.0' as const;
export const ROOT_FABRIC_VERSION = '1.0.0' as const;
export const ROOT_FABRIC_PROVIDER_VERSION = 'transactional-root-fabric@1' as const;
export const ROOT_BROKER_PROTOCOL_VERSION = '1.0.0' as const;

export const ROOT_EFFECT_STATES = [
  'REQUESTED', 'AUTHORIZING', 'PREPARING', 'READY', 'EXECUTING', 'VALIDATING', 'COMMITTING', 'COMMITTED',
  'CANCEL_REQUESTED', 'ROLLBACK_REQUESTED', 'ROLLING_BACK', 'ROLLED_BACK', 'COMPENSATING', 'COMPENSATED',
  'CLEANING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'EXPIRED',
] as const;
export type RootEffectState = typeof ROOT_EFFECT_STATES[number];
export type RootAtomicityMode = 'ATOMIC_WITHIN_PROVIDER' | 'SAGA' | 'IRREVERSIBLE';
export type RootEffectClass = 'REVERSIBLE' | 'COMPENSATABLE' | 'IRREVERSIBLE';
export type RootExecutionProvider = 'HOST_ENVELOPE' | 'DISPOSABLE_MACHINE';
export type ObservationCompleteness = 'COMPLETE' | 'PARTIAL' | 'DEGRADED' | 'UNAVAILABLE';
export type AdapterRestartBehavior = 'READ_ONLY_RETRY' | 'IDEMPOTENT_RETRY' | 'READBACK_BEFORE_RETRY' | 'ROLLBACK_BEFORE_RETRY' | 'NEVER_AUTOMATICALLY_RETRY';

export type RootFabricErrorCode =
  | 'invalid_request' | 'unsupported_schema' | 'unsupported_operation' | 'unsupported_provider'
  | 'compatibility_failed' | 'authentication_failed' | 'principal_mismatch' | 'bundle_not_found'
  | 'bundle_digest_mismatch' | 'bundle_signature_invalid' | 'bundle_expired' | 'bundle_revoked'
  | 'signer_revoked' | 'grant_not_found' | 'grant_expired' | 'grant_revoked' | 'grant_denied'
  | 'policy_denied' | 'idempotency_conflict' | 'transaction_not_found' | 'transaction_state_conflict'
  | 'lease_conflict' | 'fencing_token_stale' | 'resource_conflict' | 'path_escape' | 'symlink_escape'
  | 'expected_digest_mismatch' | 'precondition_failed' | 'preparation_failed' | 'snapshot_failed'
  | 'credential_unavailable' | 'credential_delivery_failed' | 'broker_unavailable' | 'broker_protocol_mismatch'
  | 'broker_replay_detected' | 'unit_launch_failed' | 'unit_identity_conflict' | 'process_identity_conflict'
  | 'machine_unavailable' | 'machine_identity_conflict' | 'observation_unavailable' | 'observation_incomplete'
  | 'execution_failed' | 'validation_failed' | 'rollback_failed' | 'compensation_failed' | 'cleanup_failed'
  | 'protected_source_mismatch' | 'frozen' | 'deadline_exceeded' | 'ambiguous' | 'recovery_required'
  | 'corrupt_record' | 'internal_error';

export class RootFabricError extends Error {
  constructor(readonly code: RootFabricErrorCode, message: string, readonly details: JsonObject = {}) {
    super(message);
    this.name = 'RootFabricError';
  }
}

export interface RootPrincipalRecord extends JsonObject {
  principalType: string;
  principalId: string;
  authorityClass: string;
  authenticatedSubject: string;
  gatewayIdentity: string;
  requestIdentity: string;
  principalDigest: string;
  authenticatedAt: string;
}

export interface RootSkillBinding extends JsonObject {
  skillId: string;
  skillVersion: string;
  bundleDigest: string;
  manifestDigest: string;
  signerKeyId: string;
  signerIdentity: string;
  signatureVerified: boolean;
  revocationStateDigest: string;
  capabilityGrantId: string;
  capabilityGrantDigest: string;
}

export interface RootPlanStep extends JsonObject {
  stepId: string;
  sequence: number;
  operation: string;
  operationVersion: string;
  input: JsonObject;
  inputDigest: string;
  resourceSelectors: JsonObject;
  effectClass: RootEffectClass;
  timeoutMs: number;
  dependencies: string[];
  preconditions: JsonObject[];
  preparationRequirements: JsonObject[];
  expectedObservations: JsonObject[];
  validation: JsonObject;
  rollbackOperation: string | null;
  compensationOperation: string | null;
  providerRequirements: RootExecutionProvider[];
  credentialReferences: string[];
  restartBehavior: AdapterRestartBehavior;
}

export interface RootFabricEvent extends JsonObject {
  schemaVersion: typeof ROOT_FABRIC_SCHEMA_VERSION;
  eventId: string;
  transactionId: string;
  sequence: number;
  stateGeneration: number;
  ownerPrincipalDigest: string;
  skillBundleDigest: string;
  operation: string;
  phase: string;
  priorState: RootEffectState | null;
  nextState: RootEffectState;
  requestDigest: string;
  idempotencyKeyDigest: string;
  occurredAt: string;
  fencingToken: number;
  provider: RootExecutionProvider | null;
  references: JsonObject;
  observationDigest: string | null;
  previousEventDigest: string | null;
  eventDigest: string;
}

export interface RootEffectTransaction extends JsonObject {
  schemaVersion: typeof ROOT_FABRIC_SCHEMA_VERSION;
  providerVersion: typeof ROOT_FABRIC_PROVIDER_VERSION;
  transactionId: string;
  transactionKind: 'ROOT_EFFECT';
  ownerPrincipal: RootPrincipalRecord;
  skill: RootSkillBinding;
  request: JsonObject;
  lifecycle: JsonObject & { persistedState: RootEffectState; desiredState: RootEffectState; sequence: number; terminal: boolean; createdAt: string; updatedAt: string; deadline: string };
  lease: JsonObject & { controllerId: string | null; leaseOwner: string | null; fencingToken: number; acquiredAt: string | null; renewedAt: string | null; expiresAt: string | null; predecessorLease: string | null; takeoverReason: string | null };
  policy: JsonObject;
  routing: JsonObject & { projectPath: 'DIRECT_BUILD'; executionProvider: RootExecutionProvider | null; providerId: string | null; providerVersion: string | null; providerContractVersion: string | null; providerProfileDigest: string | null };
  plan: JsonObject & { atomicityMode: RootAtomicityMode; planDigest: string; steps: RootPlanStep[] };
  preparation: JsonObject;
  execution: JsonObject;
  observations: JsonObject;
  validation: JsonObject;
  rollback: JsonObject;
  compensation: JsonObject;
  credentials: JsonObject;
  cleanup: JsonObject;
  evidence: JsonObject;
  error: JsonObject | null;
  events: RootFabricEvent[];
  eventHeadDigest: string;
  recordDigest: string;
}

export const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
export const DIGEST = /^[a-f0-9]{64}$/u;
export const GIT_ID = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;

export function object(value: unknown, field: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new RootFabricError('invalid_request', `${field} must be an object`);
  return value as JsonObject;
}

export function strictObject(value: unknown, field: string, keys: readonly string[]): JsonObject {
  const candidate = object(value, field);
  const allowed = new Set(keys);
  const unknown = Object.keys(candidate).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw new RootFabricError('invalid_request', `${field} contains unsupported properties`, { properties: unknown });
  return candidate;
}

export function text(value: unknown, field: string, maximum = 1_024): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || value.includes('\0')) throw new RootFabricError('invalid_request', `${field} must be a bounded non-empty NUL-free string`);
  return value;
}

export function identifier(value: unknown, field: string): string {
  const normalized = text(value, field, 256);
  if (!IDENTIFIER.test(normalized)) throw new RootFabricError('invalid_request', `${field} is invalid`);
  return normalized;
}

export function digest(value: unknown, field: string): string {
  const normalized = text(value, field, 64);
  if (!DIGEST.test(normalized)) throw new RootFabricError('invalid_request', `${field} must be a lowercase SHA-256 digest`);
  return normalized;
}

export function gitIdentity(value: unknown, field: string): string {
  const normalized = text(value, field, 64);
  if (!GIT_ID.test(normalized)) throw new RootFabricError('invalid_request', `${field} must be a lowercase Git object identity`);
  return normalized;
}

export function integer(value: unknown, field: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new RootFabricError('invalid_request', `${field} must be an integer between ${minimum} and ${maximum}`);
  return Number(value);
}

export function timestamp(value: unknown, field: string): string {
  const normalized = text(value, field, 64);
  const parsed = Date.parse(normalized);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== normalized) throw new RootFabricError('invalid_request', `${field} must be an exact ISO-8601 UTC timestamp`);
  return normalized;
}

export function stringArray(value: unknown, field: string, maximum = 64, allowEmpty = true): string[] {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0) || value.length > maximum) throw new RootFabricError('invalid_request', `${field} must be a bounded string array`);
  const normalized = value.map((entry, index) => text(entry, `${field}[${index}]`, 1_024));
  if (new Set(normalized).size !== normalized.length) throw new RootFabricError('invalid_request', `${field} must not contain duplicates`);
  return normalized;
}

export function contextPrincipal(context: RuntimeExecutionContext, occurredAt: string): RootPrincipalRecord {
  const authenticatedSubject = identifier(context.subject ?? 'stealtheye-owner', 'authenticated subject');
  const authorityClass = identifier(context.authorityClass ?? 'unrestricted-owner', 'authority class');
  const identity = {
    principalType: 'authenticated-subject', principalId: authenticatedSubject, authorityClass,
    authenticatedSubject, gatewayIdentity: 'baby-x-gateway', requestIdentity: authenticatedSubject,
  };
  return { ...identity, authenticatedAt: occurredAt, principalDigest: sha256(canonicalize(identity)) };
}

export function idempotency(context: RuntimeExecutionContext): { key: string; digest: string } {
  const key = context.idempotencyKey;
  if (typeof key !== 'string' || key.length < 8 || key.length > 256 || key.includes('\0')) throw new RootFabricError('invalid_request', 'a bounded idempotency key is required');
  return { key, digest: sha256(key) };
}

export function recordWithoutDigest(record: RootEffectTransaction): JsonObject {
  const { recordDigest: _recordDigest, ...unsigned } = record;
  return unsigned;
}

export function eventWithoutDigest(event: RootFabricEvent): JsonObject {
  const { eventDigest: _eventDigest, ...unsigned } = event;
  return unsigned;
}

export function sealTransaction(record: Omit<RootEffectTransaction, 'recordDigest'>): RootEffectTransaction {
  return { ...record, recordDigest: sha256(canonicalize(record)) } as RootEffectTransaction;
}

export function verifyTransaction(record: RootEffectTransaction): { valid: boolean; errors: string[]; computedRecordDigest: string } {
  const errors: string[] = [];
  const computedRecordDigest = sha256(canonicalize(recordWithoutDigest(record)));
  if (record.schemaVersion !== ROOT_FABRIC_SCHEMA_VERSION) errors.push('schema version mismatch');
  if (record.providerVersion !== ROOT_FABRIC_PROVIDER_VERSION) errors.push('provider version mismatch');
  if (record.transactionKind !== 'ROOT_EFFECT') errors.push('transaction kind mismatch');
  if (!IDENTIFIER.test(record.transactionId)) errors.push('transaction ID invalid');
  if (!ROOT_EFFECT_STATES.includes(record.lifecycle.persistedState)) errors.push('state invalid');
  if (record.recordDigest !== computedRecordDigest) errors.push('record digest mismatch');
  let previous: string | null = null;
  let previousState: RootEffectState | null = null;
  for (let index = 0; index < record.events.length; index += 1) {
    const event = record.events[index]!;
    if (event.sequence !== index + 1) errors.push(`event ${index + 1} sequence mismatch`);
    if (event.previousEventDigest !== previous) errors.push(`event ${index + 1} previous digest mismatch`);
    if (event.priorState !== previousState) errors.push(`event ${index + 1} prior state mismatch`);
    if (event.eventDigest !== sha256(canonicalize(eventWithoutDigest(event)))) errors.push(`event ${index + 1} digest mismatch`);
    previous = event.eventDigest;
    previousState = event.nextState;
  }
  if (record.lifecycle.sequence !== record.events.length) errors.push('lifecycle sequence mismatch');
  if (record.eventHeadDigest !== previous) errors.push('event head mismatch');
  if (record.lifecycle.persistedState !== previousState) errors.push('state does not match event ledger');
  return { valid: errors.length === 0, errors, computedRecordDigest };
}

export function assertTransaction(record: RootEffectTransaction): void {
  const result = verifyTransaction(record);
  if (!result.valid) throw new RootFabricError('corrupt_record', 'root effect transaction integrity failed', { transactionId: record.transactionId, errors: result.errors });
}
