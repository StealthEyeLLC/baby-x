import { randomUUID } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs';
import { arch, release } from 'node:os';
import { join, relative } from 'node:path';
import { CriuManager } from '../../checkpoint/criu.ts';
import { canonicalize, Executor, sha256, type JsonObject, type RuntimeExecutionContext } from '../../core.ts';
import {
  TransactionalRootAuthorityService,
  verifyRootTransactionRecord,
  type RootTransactionRecord,
} from '../../root-authority/service.ts';
import { RootMicrovmService } from '../microvm/service.ts';
import type { RootPlatformProvider } from '../provider-registry.ts';
import { RootReplayError } from './errors.ts';
import { replayProviders } from './providers.ts';
import {
  ROOT_REPLAY_PROVIDER_VERSION,
  ROOT_REPLAY_SCHEMA_VERSION,
  sealCheckpointRecord,
  sealReplayRecord,
  type CheckpointArtifact,
  type CheckpointKind,
  type CheckpointRecord,
  type ReplayRecord,
} from './records.ts';
import {
  idempotencyDigest,
  normalizeCheckpointCreate,
  normalizeCheckpointGet,
  normalizeCheckpointRestore,
  normalizeReplayGet,
  normalizeReplayRun,
  ownerPrincipal,
  requestDigest,
  type NormalizedCheckpointCreate,
  type NormalizedCheckpointRestore,
  type NormalizedReplayRun,
} from './schemas.ts';
import { RootReplayStore } from './store.ts';

interface PathDigest { digest: string; sizeBytes: number; kind: 'FILE' | 'DIRECTORY' }
export interface EffectDelegate {
  checkpoint(kind: CheckpointKind, request: NormalizedCheckpointCreate, context: RuntimeExecutionContext): Promise<JsonObject>;
  restore(kind: CheckpointKind, checkpoint: CheckpointRecord, target: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
}
export interface ReplayServiceOptions {
  now?: () => string;
  providers?: RootPlatformProvider[];
  supportOverride?: Partial<Record<string, boolean>>;
  effectDelegate?: EffectDelegate;
  transactionReader?: (transactionId: string) => RootTransactionRecord;
  hostArchitecture?: string;
  hostKernelRelease?: string;
  microvmService?: RootMicrovmService;
}

function pathDigest(root: string): PathDigest {
  if (!existsSync(root)) throw new RootReplayError('root_replay_trace_integrity_failure', 'checkpoint artifact does not exist', { referenceDigest: sha256(root) });
  const entries: JsonObject[] = [];
  let sizeBytes = 0;
  const visit = (path: string): void => {
    const stat = lstatSync(path);
    const name = relative(root, path) || '.';
    if (stat.isSymbolicLink()) throw new RootReplayError('root_replay_trace_integrity_failure', 'checkpoint artifacts may not contain symbolic links', { pathDigest: sha256(name) });
    if (stat.isFile()) {
      const content = readFileSync(path);
      sizeBytes += content.length;
      entries.push({ path: name, kind: 'FILE', sizeBytes: content.length, digest: sha256(content) });
      return;
    }
    if (!stat.isDirectory()) throw new RootReplayError('root_replay_trace_integrity_failure', 'checkpoint artifact contains an unsupported filesystem entry', { pathDigest: sha256(name) });
    entries.push({ path: name, kind: 'DIRECTORY' });
    for (const child of readdirSync(path).sort()) visit(join(path, child));
  };
  visit(root);
  return { digest: sha256(canonicalize(entries)), sizeBytes, kind: lstatSync(root).isDirectory() ? 'DIRECTORY' : 'FILE' };
}

function errorCode(error: unknown): string {
  if (error instanceof RootReplayError) return error.code;
  if (error !== null && typeof error === 'object' && typeof (error as { code?: unknown }).code === 'string') return String((error as { code: string }).code);
  return 'root_replay_effect_failed';
}
function errorDigest(error: unknown): string {
  return sha256(error instanceof Error ? `${error.name}:${error.message}` : String(error));
}
function id(prefix: 'rcp' | 'rrp'): string { return `${prefix}_${randomUUID().replaceAll('-', '')}`; }
function derivedContext(context: RuntimeExecutionContext, key: string): RuntimeExecutionContext { return { ...context, idempotencyKey: key }; }

class NativeEffectDelegate implements EffectDelegate {
  private readonly criu = new CriuManager();
  private readonly executor = new Executor();
  constructor(private readonly microvm: RootMicrovmService) {}

  async checkpoint(kind: CheckpointKind, request: NormalizedCheckpointCreate, context: RuntimeExecutionContext): Promise<JsonObject> {
    if (kind === 'CRIU_PROCESS') {
      if (!existsSync('/usr/sbin/criu')) throw new RootReplayError('root_replay_provider_unavailable', 'CRIU is not installed on this host');
      const result = await this.criu.dump({ pid: request.process!.pid, imagesDir: request.imagesDir!, leaveRunning: true });
      if (result.exitCode !== 0) throw new RootReplayError('root_replay_checkpoint_failed', 'CRIU checkpoint creation failed', { exitCode: result.exitCode, stderrDigest: result.stderrSha256 });
      return { argv: result.argv, exitCode: result.exitCode, stdoutDigest: result.stdoutSha256, stderrDigest: result.stderrSha256 };
    }
    if (kind === 'RR_TRACE') return { boundExistingTrace: true };
    const result = await this.microvm.snapshot({ vmId: request.vmId, expiresAt: request.expiresAt }, context);
    return result;
  }

  async restore(kind: CheckpointKind, checkpoint: CheckpointRecord, target: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    if (checkpoint.artifact === null) throw new RootReplayError('root_replay_integrity_failure', 'checkpoint artifact is missing');
    if (kind === 'CRIU_PROCESS') {
      if (!existsSync('/usr/sbin/criu')) throw new RootReplayError('root_replay_provider_unavailable', 'CRIU is not installed on this host');
      const result = await this.criu.restore({ imagesDir: checkpoint.artifact.reference, restoreDetached: true });
      if (result.exitCode !== 0) throw new RootReplayError('root_replay_restore_failed', 'CRIU restore failed', { exitCode: result.exitCode, stderrDigest: result.stderrSha256 });
      return { argv: result.argv, exitCode: result.exitCode, stdoutDigest: result.stdoutSha256, stderrDigest: result.stderrSha256 };
    }
    if (kind === 'RR_TRACE') {
      if (!existsSync('/usr/bin/rr')) throw new RootReplayError('root_replay_provider_unavailable', 'rr is not installed on this host');
      const result = await this.executor.run({ argv: ['/usr/bin/rr', 'replay', '-a', checkpoint.artifact.reference], timeoutMs: 0 });
      if (result.exitCode !== 0) throw new RootReplayError('root_replay_restore_failed', 'rr forensic replay failed', { exitCode: result.exitCode, stderrDigest: result.stderrSha256 });
      return { argv: result.argv, exitCode: result.exitCode, stdoutDigest: result.stdoutSha256, stderrDigest: result.stderrSha256 };
    }
    return this.microvm.restore({ snapshotId: checkpoint.artifact.reference, ...target }, context);
  }
}

export class RootReplayService {
  private readonly store: RootReplayStore;
  private readonly providers: Map<string, RootPlatformProvider>;
  private readonly supportOverride: Partial<Record<string, boolean>>;
  private readonly effects: EffectDelegate;
  private readonly transactionReader: (transactionId: string) => RootTransactionRecord;
  private readonly now: () => string;
  private readonly hostArchitecture: string;
  private readonly hostKernelRelease: string;

  constructor(stateRoot: string, options: ReplayServiceOptions = {}) {
    this.store = new RootReplayStore(stateRoot);
    const providers = options.providers ?? replayProviders();
    this.providers = new Map(providers.map((provider) => [provider.definition.providerId, provider]));
    this.supportOverride = options.supportOverride ?? {};
    this.effects = options.effectDelegate ?? new NativeEffectDelegate(options.microvmService ?? new RootMicrovmService());
    const authority = new TransactionalRootAuthorityService(stateRoot);
    this.transactionReader = options.transactionReader ?? ((transactionId) => authority.get({ transactionId }).transaction as RootTransactionRecord);
    this.now = options.now ?? (() => new Date().toISOString());
    const observedArchitecture = arch();
    this.hostArchitecture = options.hostArchitecture ?? (observedArchitecture === 'x64' ? 'x86_64' : observedArchitecture);
    this.hostKernelRelease = options.hostKernelRelease ?? release();
  }

  private providerId(kind: CheckpointKind): string {
    if (kind === 'CRIU_PROCESS') return 'criu-checkpoint-restore';
    if (kind === 'RR_TRACE') return 'rr-forensic-replay';
    return 'microvm-snapshot-replay';
  }

  private provider(providerId: string): RootPlatformProvider {
    const provider = this.providers.get(providerId);
    if (provider === undefined) throw new RootReplayError('root_replay_provider_unavailable', 'replay provider is not registered', { providerId });
    const supported = this.supportOverride[providerId] ?? provider.probe().supportState === 'SUPPORTED';
    if (!supported) throw new RootReplayError('root_replay_provider_unavailable', 'replay provider prerequisites are unavailable', { providerId });
    return provider;
  }

  private verifyCompatibility(record: Pick<CheckpointRecord, 'providerId' | 'compatibility'>): RootPlatformProvider {
    const provider = this.provider(record.providerId);
    const expected = provider.definition;
    const compatibility = record.compatibility;
    if (compatibility.architecture !== this.hostArchitecture
      || compatibility.kernelRelease !== this.hostKernelRelease
      || compatibility.providerId !== expected.providerId
      || compatibility.providerVersion !== expected.implementationVersion
      || compatibility.configurationDigest !== expected.configurationDigest) {
      throw new RootReplayError('root_replay_compatibility_mismatch', 'checkpoint compatibility does not match the selected live provider', {
        providerId: expected.providerId,
        architecture: this.hostArchitecture,
        kernelRelease: this.hostKernelRelease,
      });
    }
    return provider;
  }

  private transaction(transactionId: string, owner: string): RootTransactionRecord {
    const record = this.transactionReader(transactionId);
    const integrity = verifyRootTransactionRecord(record);
    if (!integrity.valid) throw new RootReplayError('root_replay_source_integrity_failure', 'root transaction record failed integrity verification', { transactionId, errors: integrity.errors });
    if (record.ownerPrincipal !== owner) throw new RootReplayError('root_replay_authority_denied', 'root transaction belongs to a different principal', { transactionId });
    return record;
  }

  private authorize(transactionId: string | null, authorizationDigest: string, owner: string): RootTransactionRecord {
    if (transactionId === null) throw new RootReplayError('root_replay_authorization_required', 'an authorized root transaction is required for an effectful replay');
    const record = this.transaction(transactionId, owner);
    if (record.authorization === null || record.authorization.decisionDigest !== authorizationDigest) throw new RootReplayError('root_replay_authorization_required', 'authorization digest does not match the root transaction');
    if (Date.parse(record.authorization.expiresAt) <= Date.parse(this.now())) throw new RootReplayError('root_replay_authorization_required', 'root transaction authorization has expired');
    if (!['AUTHORIZED', 'EXECUTING', 'VERIFYING', 'COMMIT_READY', 'COMMITTED'].includes(record.state)) throw new RootReplayError('root_replay_authorization_required', 'root transaction is not in an authorized state', { state: record.state });
    return record;
  }

  private artifactFromMicrovm(result: JsonObject): CheckpointArtifact {
    const snapshot = result.snapshot;
    if (snapshot === null || typeof snapshot !== 'object' || Array.isArray(snapshot)) throw new RootReplayError('root_replay_checkpoint_failed', 'microVM snapshot authority returned no snapshot record');
    const record = snapshot as JsonObject;
    if (typeof record.snapshotId !== 'string') throw new RootReplayError('root_replay_checkpoint_failed', 'microVM snapshot record has no identifier');
    const contentDigest = typeof record.recordDigest === 'string' && /^[a-f0-9]{64}$/u.test(record.recordDigest) ? record.recordDigest : sha256(canonicalize(record));
    return { kind: 'MICROVM_SNAPSHOT', reference: record.snapshotId, referenceDigest: sha256(record.snapshotId), contentDigest, sizeBytes: null };
  }

  private verifyArtifact(checkpoint: CheckpointRecord): void {
    if (checkpoint.artifact === null) throw new RootReplayError('root_replay_integrity_failure', 'checkpoint artifact is missing');
    if (checkpoint.checkpointKind === 'MICROVM_SNAPSHOT') return;
    const observed = pathDigest(checkpoint.artifact.reference);
    if (observed.digest !== checkpoint.artifact.contentDigest || observed.sizeBytes !== checkpoint.artifact.sizeBytes) throw new RootReplayError('root_replay_trace_integrity_failure', 'checkpoint artifact digest no longer matches the durable record', { checkpointId: checkpoint.checkpointId });
  }

  async createCheckpoint(payload: unknown, context: RuntimeExecutionContext): Promise<JsonObject> {
    const request = normalizeCheckpointCreate(payload);
    const owner = ownerPrincipal(context);
    const key = context.idempotencyKey!;
    const keyDigest = idempotencyDigest(context);
    const digest = requestDigest('babyx.root.checkpoint.create', owner, request);
    const prior = this.store.checkpointClaim(key);
    if (prior !== undefined) {
      if (prior.requestDigest !== digest) throw new RootReplayError('root_replay_idempotency_conflict', 'idempotency key is bound to a different checkpoint request');
      const current = this.store.getCheckpoint(prior.recordId);
      if (current.state === 'READY') return { checkpoint: current, replayed: true };
    }
    const providerId = this.providerId(request.kind);
    const provider = this.verifyCompatibility({ providerId, compatibility: request.compatibility });
    if (request.compatibility.providerId !== providerId
      || request.compatibility.providerVersion !== provider.definition.implementationVersion
      || request.compatibility.configurationDigest !== provider.definition.configurationDigest) {
      throw new RootReplayError('root_replay_compatibility_mismatch', 'declared checkpoint compatibility does not match the selected provider');
    }
    const checkpointId = prior?.recordId ?? id('rcp');
    const now = this.now();
    const initial = sealCheckpointRecord({
      schemaVersion: ROOT_REPLAY_SCHEMA_VERSION, providerVersion: ROOT_REPLAY_PROVIDER_VERSION, checkpointId,
      checkpointKind: request.kind, ownerPrincipal: owner, transactionId: request.transactionId,
      creationRequestDigest: digest, creationIdempotencyKeyDigest: keyDigest, providerId, state: 'CREATING', sequence: 1,
      processIdentity: request.process, compatibility: request.compatibility, artifact: null, restoreCount: 0, lastRestore: null,
      createdAt: now, updatedAt: now,
    });
    const claimed = prior === undefined ? this.store.claimCheckpoint(key, digest, initial) : this.store.getCheckpoint(checkpointId);
    try {
      const result = await this.effects.checkpoint(request.kind, request, derivedContext(context, `root-checkpoint-create-${checkpointId}`));
      let artifact: CheckpointArtifact;
      if (request.kind === 'MICROVM_SNAPSHOT') artifact = this.artifactFromMicrovm(result);
      else {
        const reference = request.kind === 'CRIU_PROCESS' ? request.imagesDir! : request.traceReference!;
        const observed = pathDigest(reference);
        if (request.kind === 'RR_TRACE' && observed.digest !== request.traceDigest) throw new RootReplayError('root_replay_trace_integrity_failure', 'rr trace digest does not match the declared digest');
        if (request.kind === 'RR_TRACE' && request.traceSizeBytes !== null && observed.sizeBytes !== request.traceSizeBytes) throw new RootReplayError('root_replay_trace_integrity_failure', 'rr trace size does not match the declared size');
        artifact = { kind: request.kind === 'CRIU_PROCESS' ? 'DIRECTORY' : observed.kind, reference, referenceDigest: sha256(reference), contentDigest: observed.digest, sizeBytes: observed.sizeBytes };
      }
      const ready = this.store.putCheckpoint({ ...claimed, state: 'READY', sequence: claimed.sequence + 1, artifact, updatedAt: this.now(), recordDigest: claimed.recordDigest });
      return { checkpoint: ready, replayed: false, providerObservationDigest: sha256(canonicalize(result)) };
    } catch (error) {
      this.store.putCheckpoint({ ...claimed, state: 'FAILED', sequence: claimed.sequence + 1, updatedAt: this.now(), recordDigest: claimed.recordDigest });
      throw error;
    }
  }

  getCheckpoint(payload: unknown, context: RuntimeExecutionContext): JsonObject {
    const { checkpointId } = normalizeCheckpointGet(payload);
    const record = this.store.getCheckpoint(checkpointId);
    if (record.ownerPrincipal !== ownerPrincipal(context)) throw new RootReplayError('root_replay_authority_denied', 'checkpoint belongs to a different principal');
    return { checkpoint: record, integrity: { valid: true, recordDigest: record.recordDigest } };
  }

  private async restoreNormalized(request: NormalizedCheckpointRestore, context: RuntimeExecutionContext): Promise<JsonObject> {
    const owner = ownerPrincipal(context);
    const key = context.idempotencyKey!;
    idempotencyDigest(context);
    const digest = requestDigest('babyx.root.checkpoint.restore', owner, request);
    const priorClaim = this.store.restoreClaim(key);
    if (priorClaim !== undefined) {
      if (priorClaim.requestDigest !== digest) throw new RootReplayError('root_replay_idempotency_conflict', 'idempotency key is bound to a different restore request');
      const current = this.store.getCheckpoint(priorClaim.recordId);
      if (current.state === 'RESTORED') return { checkpoint: current, replayed: true };
    }
    const checkpoint = this.store.getCheckpoint(request.checkpointId);
    if (checkpoint.ownerPrincipal !== owner) throw new RootReplayError('root_replay_authority_denied', 'checkpoint belongs to a different principal');
    if (!['READY', 'RESTORED', 'RESTORE_FAILED', 'RESTORING'].includes(checkpoint.state)) throw new RootReplayError('root_replay_state_conflict', 'checkpoint is not restorable', { state: checkpoint.state });
    if (checkpoint.transactionId !== null && checkpoint.transactionId !== request.transactionId) throw new RootReplayError('root_replay_authority_denied', 'restore transaction does not match the checkpoint binding');
    this.authorize(request.transactionId, request.authorizationDigest, owner);
    this.verifyCompatibility(checkpoint);
    this.verifyArtifact(checkpoint);
    const restoring = checkpoint.state === 'RESTORING' ? checkpoint : this.store.putCheckpoint({ ...checkpoint, state: 'RESTORING', sequence: checkpoint.sequence + 1, updatedAt: this.now(), recordDigest: checkpoint.recordDigest });
    this.store.claimRestore(key, digest, restoring);
    try {
      const result = await this.effects.restore(checkpoint.checkpointKind, checkpoint, request.target, derivedContext(context, `root-checkpoint-restore-${checkpoint.checkpointId}-${checkpoint.restoreCount + 1}`));
      const completedAt = this.now();
      const observation = { operationDigest: digest, authorizationDigest: request.authorizationDigest, providerObservationDigest: sha256(canonicalize(result)), effectExecuted: true, completedAt, errorCode: null, errorDigest: null };
      const restored = this.store.putCheckpoint({ ...restoring, state: 'RESTORED', sequence: restoring.sequence + 1, restoreCount: restoring.restoreCount + 1, lastRestore: observation, updatedAt: completedAt, recordDigest: restoring.recordDigest });
      return { checkpoint: restored, replayed: false, providerResult: result };
    } catch (error) {
      const completedAt = this.now();
      const observation = { operationDigest: digest, authorizationDigest: request.authorizationDigest, providerObservationDigest: sha256('failed'), effectExecuted: false, completedAt, errorCode: errorCode(error), errorDigest: errorDigest(error) };
      this.store.putCheckpoint({ ...restoring, state: 'RESTORE_FAILED', sequence: restoring.sequence + 1, restoreCount: restoring.restoreCount + 1, lastRestore: observation, updatedAt: completedAt, recordDigest: restoring.recordDigest });
      throw error;
    }
  }

  restoreCheckpoint(payload: unknown, context: RuntimeExecutionContext): Promise<JsonObject> { return this.restoreNormalized(normalizeCheckpointRestore(payload), context); }

  private requestReplay(request: NormalizedReplayRun, owner: string): { state: ReplayRecord['state']; result: JsonObject; sourceRecordDigest: string; canonicalInputDigest: string; effectAuthorized: boolean } {
    if (request.transactionId === null) throw new RootReplayError('root_replay_invalid_request', 'REQUEST_REPLAY requires transactionId');
    const source = this.transaction(request.transactionId, owner);
    const canonicalInput = { operation: 'babyx.root.transaction.create', source: source.source, intent: source.intent };
    const canonicalInputDigest = sha256(canonicalize(canonicalInput));
    if (request.canonicalInput !== null && sha256(canonicalize(request.canonicalInput)) !== canonicalInputDigest) throw new RootReplayError('root_replay_source_integrity_failure', 'supplied canonical input does not match the durable transaction source and intent');
    if (request.dryRun) return { state: 'DRY_RUN_COMPLETE', result: { dryRun: true, effectExecuted: false, canonicalInput, sourceState: source.state, safeToDelegate: true }, sourceRecordDigest: source.recordDigest, canonicalInputDigest, effectAuthorized: false };
    if (request.authorizationDigest === null || request.effectTransactionId === null) throw new RootReplayError('root_replay_authorization_required', 'effectful request replay requires a distinct authorized transaction and authorization digest');
    if (request.effectTransactionId === request.transactionId) throw new RootReplayError('root_replay_authorization_required', 'request replay may not reuse the source transaction as new effect authority');
    const effect = this.authorize(request.effectTransactionId, request.authorizationDigest, owner);
    if (canonicalize(effect.source) !== canonicalize(source.source) || canonicalize(effect.intent) !== canonicalize(source.intent)) throw new RootReplayError('root_replay_authorization_required', 'authorized effect transaction does not exactly match the replayed source and intent');
    return { state: 'AUTHORIZED_PENDING', result: { dryRun: false, effectExecuted: false, delegatedTransactionId: effect.transactionId, authorizationDigest: request.authorizationDigest, executionAuthority: 'babyx.root.transaction.*' }, sourceRecordDigest: source.recordDigest, canonicalInputDigest, effectAuthorized: true };
  }

  private observationReplay(request: NormalizedReplayRun, owner: string): { result: JsonObject; sourceRecordDigest: string; observationDigest: string } {
    if (request.transactionId === null) throw new RootReplayError('root_replay_invalid_request', 'OBSERVATION_REPLAY requires transactionId');
    const source = this.transaction(request.transactionId, owner);
    const observation = { transactionId: source.transactionId, state: source.state, sequence: source.sequence, eventCount: source.eventCount, eventHeadDigest: source.eventHeadDigest, observations: source.observations, recordDigest: source.recordDigest };
    const observationDigest = sha256(canonicalize(observation));
    return { result: { verified: true, mutationFree: true, observationDigest, eventCount: source.eventCount, observationCount: source.observations.length, state: source.state }, sourceRecordDigest: source.recordDigest, observationDigest };
  }

  async runReplay(payload: unknown, context: RuntimeExecutionContext): Promise<JsonObject> {
    const request = normalizeReplayRun(payload);
    const owner = ownerPrincipal(context);
    const key = context.idempotencyKey!;
    const keyDigest = idempotencyDigest(context);
    const digest = requestDigest('babyx.root.replay.run', owner, request);
    const prior = this.store.replayClaim(key);
    if (prior !== undefined) {
      if (prior.requestDigest !== digest) throw new RootReplayError('root_replay_idempotency_conflict', 'idempotency key is bound to a different replay request');
      const current = this.store.getReplay(prior.recordId);
      if (current.state !== 'RUNNING') return { replay: current, replayed: true };
    }
    const replayId = prior?.recordId ?? id('rrp');
    const now = this.now();
    const initial = sealReplayRecord({
      schemaVersion: ROOT_REPLAY_SCHEMA_VERSION, providerVersion: ROOT_REPLAY_PROVIDER_VERSION, replayId, replayKind: request.kind,
      ownerPrincipal: owner, transactionId: request.transactionId, checkpointId: request.checkpointId,
      creationRequestDigest: digest, creationIdempotencyKeyDigest: keyDigest, state: 'RUNNING', dryRun: request.dryRun,
      effectAuthorized: false, effectExecuted: false, sourceRecordDigest: null, canonicalInputDigest: null, observationDigest: null,
      resultDigest: sha256(canonicalize({})), result: {}, createdAt: now, updatedAt: now,
    });
    const running = prior === undefined ? this.store.claimReplay(key, digest, initial) : this.store.getReplay(replayId);
    try {
      let state: ReplayRecord['state'] = 'COMPLETED';
      let result: JsonObject;
      let sourceRecordDigest: string | null = null;
      let canonicalInputDigest: string | null = null;
      let observationDigest: string | null = null;
      let effectAuthorized = false;
      let effectExecuted = false;
      if (request.kind === 'REQUEST_REPLAY') {
        const replay = this.requestReplay(request, owner);
        state = replay.state; result = replay.result; sourceRecordDigest = replay.sourceRecordDigest; canonicalInputDigest = replay.canonicalInputDigest; effectAuthorized = replay.effectAuthorized;
      } else if (request.kind === 'OBSERVATION_REPLAY') {
        const replay = this.observationReplay(request, owner);
        result = replay.result; sourceRecordDigest = replay.sourceRecordDigest; observationDigest = replay.observationDigest;
      } else {
        if (request.checkpointId === null) throw new RootReplayError('root_replay_invalid_request', `${request.kind} requires checkpointId`);
        const checkpoint = this.store.getCheckpoint(request.checkpointId);
        const expectedKind = request.kind === 'CRIU_CHECKPOINT_RESTORE' ? 'CRIU_PROCESS' : request.kind === 'RR_FORENSIC_REPLAY' ? 'RR_TRACE' : 'MICROVM_SNAPSHOT';
        if (checkpoint.checkpointKind !== expectedKind) throw new RootReplayError('root_replay_invalid_request', 'replay kind does not match checkpoint kind');
        if (request.dryRun) {
          this.verifyCompatibility(checkpoint); this.verifyArtifact(checkpoint);
          state = 'DRY_RUN_COMPLETE'; result = { dryRun: true, effectExecuted: false, checkpointId: checkpoint.checkpointId, checkpointDigest: checkpoint.recordDigest, providerId: checkpoint.providerId };
        } else {
          if (request.authorizationDigest === null) throw new RootReplayError('root_replay_authorization_required', 'effectful checkpoint replay requires authorizationDigest');
          const restored = await this.restoreNormalized({ checkpointId: checkpoint.checkpointId, authorizationDigest: request.authorizationDigest, transactionId: request.transactionId, target: request.target }, derivedContext(context, `root-replay-restore-${replayId}`));
          result = { dryRun: false, effectExecuted: true, restore: restored }; effectAuthorized = true; effectExecuted = true;
        }
      }
      const complete = this.store.putReplay({ ...running, state, effectAuthorized, effectExecuted, sourceRecordDigest, canonicalInputDigest, observationDigest, result, resultDigest: sha256(canonicalize(result)), updatedAt: this.now(), recordDigest: running.recordDigest });
      return { replay: complete, replayed: false };
    } catch (error) {
      const result = { errorCode: errorCode(error), errorDigest: errorDigest(error) };
      this.store.putReplay({ ...running, state: 'FAILED', result, resultDigest: sha256(canonicalize(result)), updatedAt: this.now(), recordDigest: running.recordDigest });
      throw error;
    }
  }

  getReplay(payload: unknown, context: RuntimeExecutionContext): JsonObject {
    const { replayId } = normalizeReplayGet(payload);
    const record = this.store.getReplay(replayId);
    if (record.ownerPrincipal !== ownerPrincipal(context)) throw new RootReplayError('root_replay_authority_denied', 'replay belongs to a different principal');
    return { replay: record, integrity: { valid: true, recordDigest: record.recordDigest } };
  }
}
