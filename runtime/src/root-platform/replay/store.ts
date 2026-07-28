import { join } from 'node:path';
import { DurableClaimStore, DurableRecordStore } from '../../storage/record-store.ts';
import { RootReplayError } from './errors.ts';
import {
  sealCheckpointRecord,
  sealReplayRecord,
  verifyCheckpointRecord,
  verifyReplayRecord,
  type CheckpointRecord,
  type ReplayRecord,
} from './records.ts';

function validCheckpoint(record: CheckpointRecord): CheckpointRecord {
  if (!verifyCheckpointRecord(record)) throw new RootReplayError('root_replay_integrity_failure', 'checkpoint record failed digest verification', { checkpointId: record.checkpointId });
  return structuredClone(record);
}

function validReplay(record: ReplayRecord): ReplayRecord {
  if (!verifyReplayRecord(record)) throw new RootReplayError('root_replay_integrity_failure', 'replay record failed digest verification', { replayId: record.replayId });
  return structuredClone(record);
}

export class RootReplayStore {
  private readonly checkpoints: DurableRecordStore<CheckpointRecord>;
  private readonly replays: DurableRecordStore<ReplayRecord>;
  private readonly checkpointClaims: DurableClaimStore<CheckpointRecord>;
  private readonly restoreClaims: DurableClaimStore<CheckpointRecord>;
  private readonly replayClaims: DurableClaimStore<ReplayRecord>;

  constructor(root: string) {
    const base = join(root, 'root-platform', 'replay');
    this.checkpoints = new DurableRecordStore(join(base, 'checkpoints'));
    this.replays = new DurableRecordStore(join(base, 'replays'));
    this.checkpointClaims = new DurableClaimStore(join(base, 'claims', 'checkpoints'));
    this.restoreClaims = new DurableClaimStore(join(base, 'claims', 'restores'));
    this.replayClaims = new DurableClaimStore(join(base, 'claims', 'replays'));
  }

  checkpointClaim(key: string): { requestDigest: string; recordId: string; record: CheckpointRecord } | undefined { return this.checkpointClaims.get(key); }
  restoreClaim(key: string): { requestDigest: string; recordId: string; record: CheckpointRecord } | undefined { return this.restoreClaims.get(key); }
  replayClaim(key: string): { requestDigest: string; recordId: string; record: ReplayRecord } | undefined { return this.replayClaims.get(key); }

  claimCheckpoint(key: string, requestDigest: string, record: CheckpointRecord): CheckpointRecord {
    const claim = this.checkpointClaims.claim(key, requestDigest, record.checkpointId, record);
    if (claim.requestDigest !== requestDigest) throw new RootReplayError('root_replay_idempotency_conflict', 'idempotency key is bound to a different checkpoint request');
    if (!this.checkpoints.has(claim.recordId)) this.checkpoints.create(claim.recordId, claim.record);
    return validCheckpoint(this.checkpoints.get(claim.recordId));
  }

  claimRestore(key: string, requestDigest: string, record: CheckpointRecord): CheckpointRecord {
    const claim = this.restoreClaims.claim(key, requestDigest, record.checkpointId, record);
    if (claim.requestDigest !== requestDigest) throw new RootReplayError('root_replay_idempotency_conflict', 'idempotency key is bound to a different restore request');
    return validCheckpoint(this.checkpoints.get(claim.recordId));
  }

  claimReplay(key: string, requestDigest: string, record: ReplayRecord): ReplayRecord {
    const claim = this.replayClaims.claim(key, requestDigest, record.replayId, record);
    if (claim.requestDigest !== requestDigest) throw new RootReplayError('root_replay_idempotency_conflict', 'idempotency key is bound to a different replay request');
    if (!this.replays.has(claim.recordId)) this.replays.create(claim.recordId, claim.record);
    return validReplay(this.replays.get(claim.recordId));
  }

  getCheckpoint(id: string): CheckpointRecord {
    try { return validCheckpoint(this.checkpoints.get(id)); }
    catch (error) {
      if (error instanceof RootReplayError) throw error;
      throw new RootReplayError('root_checkpoint_not_found', 'checkpoint record was not found', { checkpointId: id });
    }
  }

  getReplay(id: string): ReplayRecord {
    try { return validReplay(this.replays.get(id)); }
    catch (error) {
      if (error instanceof RootReplayError) throw error;
      throw new RootReplayError('root_replay_not_found', 'replay record was not found', { replayId: id });
    }
  }

  putCheckpoint(record: CheckpointRecord): CheckpointRecord {
    const { recordDigest: _recordDigest, ...unsigned } = record;
    const sealed = sealCheckpointRecord(unsigned as Omit<CheckpointRecord, 'recordDigest'>);
    this.checkpoints.put(sealed.checkpointId, sealed);
    return validCheckpoint(sealed);
  }

  putReplay(record: ReplayRecord): ReplayRecord {
    const { recordDigest: _recordDigest, ...unsigned } = record;
    const sealed = sealReplayRecord(unsigned as Omit<ReplayRecord, 'recordDigest'>);
    this.replays.put(sealed.replayId, sealed);
    return validReplay(sealed);
  }
}
