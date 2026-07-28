import { canonicalize, sha256, type JsonObject } from '../../core.ts';

export const ROOT_REPLAY_SCHEMA_VERSION = '1.0.0' as const;
export const ROOT_REPLAY_PROVIDER_VERSION = 'durable-checkpoint-replay@1' as const;

export const CHECKPOINT_KINDS = ['CRIU_PROCESS', 'RR_TRACE', 'MICROVM_SNAPSHOT'] as const;
export type CheckpointKind = typeof CHECKPOINT_KINDS[number];
export const REPLAY_KINDS = ['REQUEST_REPLAY', 'OBSERVATION_REPLAY', 'CRIU_CHECKPOINT_RESTORE', 'RR_FORENSIC_REPLAY', 'MICROVM_SNAPSHOT_RESTORE'] as const;
export type ReplayKind = typeof REPLAY_KINDS[number];
export type CheckpointState = 'CREATING' | 'READY' | 'RESTORING' | 'RESTORED' | 'RESTORE_FAILED' | 'FAILED';
export type ReplayState = 'RUNNING' | 'DRY_RUN_COMPLETE' | 'COMPLETED' | 'AUTHORIZED_PENDING' | 'FAILED';

export interface ReplayCompatibility extends JsonObject {
  architecture: 'x86_64' | 'aarch64';
  kernelRelease: string;
  providerId: string;
  providerVersion: string;
  configurationDigest: string;
}

export interface ReplayProcessIdentity extends JsonObject {
  pid: number;
  processStartTime: string;
  executablePath: string;
  pgid: number | null;
  bootId: string;
}

export interface CheckpointArtifact extends JsonObject {
  kind: 'DIRECTORY' | 'FILE' | 'MICROVM_SNAPSHOT';
  reference: string;
  referenceDigest: string;
  contentDigest: string;
  sizeBytes: number | null;
}

export interface CheckpointRestoreObservation extends JsonObject {
  operationDigest: string;
  authorizationDigest: string;
  providerObservationDigest: string;
  effectExecuted: boolean;
  completedAt: string;
  errorCode: string | null;
  errorDigest: string | null;
}

export interface CheckpointRecord extends JsonObject {
  schemaVersion: typeof ROOT_REPLAY_SCHEMA_VERSION;
  providerVersion: typeof ROOT_REPLAY_PROVIDER_VERSION;
  checkpointId: string;
  checkpointKind: CheckpointKind;
  ownerPrincipal: string;
  transactionId: string | null;
  creationRequestDigest: string;
  creationIdempotencyKeyDigest: string;
  providerId: string;
  state: CheckpointState;
  sequence: number;
  processIdentity: ReplayProcessIdentity | null;
  compatibility: ReplayCompatibility;
  artifact: CheckpointArtifact | null;
  restoreCount: number;
  lastRestore: CheckpointRestoreObservation | null;
  createdAt: string;
  updatedAt: string;
  recordDigest: string;
}

export interface ReplayRecord extends JsonObject {
  schemaVersion: typeof ROOT_REPLAY_SCHEMA_VERSION;
  providerVersion: typeof ROOT_REPLAY_PROVIDER_VERSION;
  replayId: string;
  replayKind: ReplayKind;
  ownerPrincipal: string;
  transactionId: string | null;
  checkpointId: string | null;
  creationRequestDigest: string;
  creationIdempotencyKeyDigest: string;
  state: ReplayState;
  dryRun: boolean;
  effectAuthorized: boolean;
  effectExecuted: boolean;
  sourceRecordDigest: string | null;
  canonicalInputDigest: string | null;
  observationDigest: string | null;
  resultDigest: string;
  result: JsonObject;
  createdAt: string;
  updatedAt: string;
  recordDigest: string;
}

type ReplaySidecarRecord = CheckpointRecord | ReplayRecord;

function unsigned(record: ReplaySidecarRecord): JsonObject {
  const { recordDigest: _recordDigest, ...value } = record;
  return value;
}

export function sealCheckpointRecord(record: Omit<CheckpointRecord, 'recordDigest'>): CheckpointRecord {
  return { ...record, recordDigest: sha256(canonicalize(record as unknown as JsonObject)) };
}

export function sealReplayRecord(record: Omit<ReplayRecord, 'recordDigest'>): ReplayRecord {
  return { ...record, recordDigest: sha256(canonicalize(record as unknown as JsonObject)) };
}

export function verifyCheckpointRecord(record: CheckpointRecord): boolean {
  return record.schemaVersion === ROOT_REPLAY_SCHEMA_VERSION
    && record.providerVersion === ROOT_REPLAY_PROVIDER_VERSION
    && record.recordDigest === sha256(canonicalize(unsigned(record)));
}

export function verifyReplayRecord(record: ReplayRecord): boolean {
  return record.schemaVersion === ROOT_REPLAY_SCHEMA_VERSION
    && record.providerVersion === ROOT_REPLAY_PROVIDER_VERSION
    && record.recordDigest === sha256(canonicalize(unsigned(record)));
}
