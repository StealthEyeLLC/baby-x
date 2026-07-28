import { sha256, type JsonObject, type RuntimeExecutionContext } from '../../core.ts';
import { BpfLsmController } from './bpf-lsm.ts';
import { MediationError } from './errors.ts';
import { NativeMediationRunner } from './native.ts';
import { MediationProfileStore } from './records.ts';
import { strictMediationPayload } from './schemas.ts';

function profileId(value: unknown): string {
  if (typeof value !== 'string' || !/^mpf_[a-f0-9]{32}$/u.test(value)) throw new MediationError('mediation_invalid_request', 'profileId is invalid');
  return value;
}

function owner(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(value)) throw new MediationError('mediation_invalid_request', 'ownerPrincipal is invalid');
  return value;
}

export class RootMediationService {
  private readonly store: MediationProfileStore;
  private readonly native: NativeMediationRunner;
  private readonly bpf: BpfLsmController;
  private readonly now: () => string;

  constructor(options: { stateRoot: string; now?: () => string; native?: NativeMediationRunner; bpf?: BpfLsmController }) {
    this.now = options.now ?? (() => new Date().toISOString());
    this.store = new MediationProfileStore(options.stateRoot, { now: this.now });
    this.native = options.native ?? new NativeMediationRunner();
    this.bpf = options.bpf ?? new BpfLsmController();
  }

  create(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictMediationPayload(payloadValue, 'mediation profile create payload', ['profile']);
    return this.store.create(payload.profile, context);
  }

  get(payloadValue: unknown): JsonObject {
    const payload = strictMediationPayload(payloadValue, 'mediation profile get payload', ['profileId']);
    return { profile: this.store.effective(this.store.latest(profileId(payload.profileId))) };
  }

  list(payloadValue: unknown): JsonObject {
    const payload = strictMediationPayload(payloadValue, 'mediation profile list payload', ['ownerPrincipal', 'status', 'offset', 'limit']);
    const status = payload.status;
    if (status !== undefined && status !== 'ACTIVE' && status !== 'REVOKED' && status !== 'EXPIRED') throw new MediationError('mediation_invalid_request', 'status is invalid');
    return this.store.list({ ownerPrincipal: owner(payload.ownerPrincipal), status, offset: payload.offset, limit: payload.limit });
  }

  revoke(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictMediationPayload(payloadValue, 'mediation profile revoke payload', ['profileId', 'expectedSequence', 'reasonDigest']);
    return this.store.revoke(profileId(payload.profileId), payload.expectedSequence, payload.reasonDigest, context);
  }

  events(payloadValue: unknown): JsonObject {
    const payload = strictMediationPayload(payloadValue, 'mediation events payload', ['profileId', 'offset', 'limit']);
    return this.store.listEvents(profileId(payload.profileId), payload.offset, payload.limit);
  }

  execute(profileIdValue: string, transactionId: string, command: string[], timeoutMs = 60_000): JsonObject {
    const record = this.store.latest(profileId(profileIdValue));
    if (record.status === 'REVOKED') throw new MediationError('mediation_profile_revoked', 'mediation profile is revoked', { profileId: record.profileId });
    if (Date.parse(record.profile.expiresAt) <= Date.parse(this.now())) throw new MediationError('mediation_profile_expired', 'mediation profile is expired', { profileId: record.profileId });
    if (record.profile.providerScope.includes('BPF_LSM')) {
      const probe = this.bpf.probe();
      if (probe.supportState !== 'EXPERIMENTAL') throw new MediationError('mediation_bpf_unavailable', 'BPF LSM rules cannot be applied on this host', { probe });
      if (record.profile.bpfRules.mode === 'enforce') throw new MediationError('mediation_bpf_unavailable', 'BPF LSM enforcement remains disabled until an enforcement-specific gate passes', { probe });
    }
    const result = this.native.execute(record.profile, transactionId, command, timeoutMs);
    const events = this.store.appendDecisionEvents(record, transactionId, result);
    return { profileId: record.profileId, profileDigest: record.profile.profileDigest, transactionId, result: { ok: result.ok, status: result.status, eventCount: result.events, droppedEventCount: result.droppedEvents, stdoutDigest: result.stdoutDigest, stderrDigest: result.stderrDigest, binaryDigest: result.binaryDigest }, eventDigest: events.at(-1)?.eventDigest ?? sha256(''), decisionEventsPersisted: events.length };
  }

  reconcile(): JsonObject { return this.store.reconcile(); }
}
