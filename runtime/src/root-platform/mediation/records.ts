import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../../storage/record-store.ts';
import { MediationError } from './errors.ts';
import type { NativeDecisionEvent, NativeExecutionResult } from './native.ts';
import { MEDIATION_PROFILE_SCHEMA_VERSION, normalizeMediationProfile, type MediationProfileSpec, type ProfileStatus } from './schemas.ts';

export const MEDIATION_RECORD_SCHEMA_VERSION = '1.0.0' as const;
export const MEDIATION_EVENT_SCHEMA_VERSION = '1.0.0' as const;

export interface MediationProfileRecord extends JsonObject {
  schemaVersion: typeof MEDIATION_RECORD_SCHEMA_VERSION;
  profileId: string;
  ownerPrincipal: string;
  sequence: number;
  status: ProfileStatus;
  profile: MediationProfileSpec;
  requestDigest: string;
  idempotencyKeyDigest: string;
  priorRecordDigest: string | null;
  createdAt: string;
  updatedAt: string;
  revokedAt: string | null;
  revocationReasonDigest: string | null;
  recordDigest: string;
}

export interface MediationEventRecord extends JsonObject {
  schemaVersion: typeof MEDIATION_EVENT_SCHEMA_VERSION;
  eventId: string;
  profileId: string;
  sequence: number;
  operation: 'CREATED' | 'REVOKED' | 'DECISION' | 'RECONCILED';
  ownerPrincipal: string;
  transactionId: string | null;
  details: JsonObject;
  occurredAt: string;
  priorEventDigest: string | null;
  eventDigest: string;
}

function withoutRecordDigest(record: MediationProfileRecord): JsonObject {
  const { recordDigest: _recordDigest, ...unsigned } = record;
  return unsigned;
}

function withoutEventDigest(record: MediationEventRecord): JsonObject {
  const { eventDigest: _eventDigest, ...unsigned } = record;
  return unsigned;
}

export function verifyMediationProfileRecord(record: MediationProfileRecord): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (record.schemaVersion !== MEDIATION_RECORD_SCHEMA_VERSION) errors.push('schema version mismatch');
  if (record.profile.schemaVersion !== MEDIATION_PROFILE_SCHEMA_VERSION) errors.push('profile schema version mismatch');
  if (!/^mpf_[a-f0-9]{32}$/u.test(record.profileId)) errors.push('profile identifier mismatch');
  if (!Number.isSafeInteger(record.sequence) || record.sequence < 1) errors.push('sequence is invalid');
  if (record.recordDigest !== sha256(canonicalize(withoutRecordDigest(record)))) errors.push('record digest mismatch');
  return { valid: errors.length === 0, errors };
}

export function verifyMediationEventRecord(record: MediationEventRecord): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (record.schemaVersion !== MEDIATION_EVENT_SCHEMA_VERSION) errors.push('schema version mismatch');
  if (!/^mpe_[a-f0-9]{32}$/u.test(record.eventId)) errors.push('event identifier mismatch');
  if (!Number.isSafeInteger(record.sequence) || record.sequence < 1) errors.push('sequence is invalid');
  if (record.eventDigest !== sha256(canonicalize(withoutEventDigest(record)))) errors.push('event digest mismatch');
  return { valid: errors.length === 0, errors };
}

function principal(context: RuntimeExecutionContext): string {
  const value = context.subject ?? 'stealtheye-owner';
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(value)) throw new MediationError('mediation_invalid_request', 'owner principal is invalid');
  return value;
}

function idempotency(context: RuntimeExecutionContext): { key: string; digest: string } {
  const key = context.idempotencyKey;
  if (typeof key !== 'string' || key.length < 8 || key.length > 256 || key.includes('\0')) throw new MediationError('mediation_idempotency_required', 'a bounded idempotency key is required');
  return { key, digest: sha256(key) };
}

function profileIdentifier(value: unknown): string {
  if (typeof value !== 'string' || !/^mpf_[a-f0-9]{32}$/u.test(value)) throw new MediationError('mediation_invalid_request', 'profileId is invalid');
  return value;
}

function page(offsetValue: unknown, limitValue: unknown): { offset: number; limit: number } {
  const offset = offsetValue === undefined ? 0 : Number(offsetValue);
  const limit = limitValue === undefined ? 100 : Number(limitValue);
  if (!Number.isSafeInteger(offset) || offset < 0) throw new MediationError('mediation_invalid_request', 'offset must be a non-negative safe integer');
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) throw new MediationError('mediation_invalid_request', 'limit must be between 1 and 1000');
  return { offset, limit };
}

export class MediationProfileStore {
  private readonly profiles: DurableRecordStore<MediationProfileRecord>;
  private readonly events: DurableRecordStore<MediationEventRecord>;
  private readonly claims: DurableClaimStore<MediationProfileRecord>;
  private readonly now: () => string;

  constructor(stateRoot: string, options: { now?: () => string } = {}) {
    const root = join(stateRoot, 'root-platform', 'mediation');
    this.profiles = new DurableRecordStore<MediationProfileRecord>(join(root, 'profiles'));
    this.events = new DurableRecordStore<MediationEventRecord>(join(root, 'events'));
    this.claims = new DurableClaimStore<MediationProfileRecord>(join(root, 'idempotency'));
    this.now = options.now ?? (() => new Date().toISOString());
  }

  latest(profileIdValue: unknown): MediationProfileRecord {
    const profileId = profileIdentifier(profileIdValue);
    const records = this.profiles.scan((record) => record.profileId === profileId, 0, 10_000).records.sort((left, right) => right.sequence - left.sequence);
    const record = records[0];
    if (record === undefined) throw new MediationError('mediation_profile_not_found', `mediation profile not found: ${profileId}`, { profileId });
    const verification = verifyMediationProfileRecord(record);
    if (!verification.valid) throw new MediationError('mediation_integrity_failure', 'mediation profile integrity failed', { profileId, errors: verification.errors });
    return structuredClone(record);
  }

  effective(record: MediationProfileRecord): JsonObject {
    const expired = record.status === 'ACTIVE' && Date.parse(record.profile.expiresAt) <= Date.parse(this.now());
    return { ...structuredClone(record), effectiveStatus: expired ? 'EXPIRED' : record.status };
  }

  create(profileValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const ownerPrincipal = principal(context);
    const idem = idempotency(context);
    const now = this.now();
    const profile = normalizeMediationProfile(profileValue, new Date(now));
    const requestDigest = sha256(canonicalize({ operation: 'babyx.root.mediation.profile.create', ownerPrincipal, profile }));
    const base = {
      schemaVersion: MEDIATION_RECORD_SCHEMA_VERSION,
      profileId: `mpf_${randomUUID().replaceAll('-', '')}`,
      ownerPrincipal,
      sequence: 1,
      status: 'ACTIVE' as const,
      profile,
      requestDigest,
      idempotencyKeyDigest: idem.digest,
      priorRecordDigest: null,
      createdAt: now,
      updatedAt: now,
      revokedAt: null,
      revocationReasonDigest: null,
    };
    const candidate = { ...base, recordDigest: sha256(canonicalize(base)) } as MediationProfileRecord;
    const claim = this.claims.claim(`${ownerPrincipal}:${idem.key}`, requestDigest, `${candidate.profileId}:1`, candidate);
    if (claim.requestDigest !== requestDigest) throw new MediationError('mediation_idempotency_conflict', 'idempotency key already belongs to a different mediation request');
    const record = claim.record;
    const verification = verifyMediationProfileRecord(record);
    if (!verification.valid) throw new MediationError('mediation_integrity_failure', 'claimed mediation profile is invalid', { errors: verification.errors });
    const created = !this.profiles.has(claim.recordId);
    if (created && !this.profiles.create(claim.recordId, record)) throw new MediationError('mediation_integrity_failure', 'mediation profile could not be persisted');
    if (created) this.appendEvent(record, 'CREATED', null, { profileDigest: record.profile.profileDigest, providerScope: record.profile.providerScope });
    return { profile: this.effective(record), replayed: !created };
  }

  revoke(profileIdValue: unknown, expectedSequenceValue: unknown, reasonDigestValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const profileId = profileIdentifier(profileIdValue);
    const ownerPrincipal = principal(context);
    const idem = idempotency(context);
    const expectedSequence = Number(expectedSequenceValue);
    if (!Number.isSafeInteger(expectedSequence) || expectedSequence < 1) throw new MediationError('mediation_invalid_request', 'expectedSequence must be a positive safe integer');
    if (typeof reasonDigestValue !== 'string' || !/^[a-f0-9]{64}$/u.test(reasonDigestValue)) throw new MediationError('mediation_invalid_request', 'reasonDigest must be a lowercase SHA-256 digest');
    const requestDigest = sha256(canonicalize({ operation: 'babyx.root.mediation.profile.revoke', ownerPrincipal, profileId, expectedSequence, reasonDigest: reasonDigestValue }));
    const claimKey = `${ownerPrincipal}:${idem.key}`;
    const existingClaim = this.claims.get(claimKey);
    if (existingClaim !== undefined) {
      if (existingClaim.requestDigest !== requestDigest) throw new MediationError('mediation_idempotency_conflict', 'idempotency key already belongs to a different mediation request');
      const verification = verifyMediationProfileRecord(existingClaim.record);
      if (!verification.valid) throw new MediationError('mediation_integrity_failure', 'claimed revoked mediation profile is invalid', { errors: verification.errors });
      return { profile: this.effective(existingClaim.record), replayed: true };
    }
    const prior = this.latest(profileId);
    if (prior.ownerPrincipal !== ownerPrincipal) throw new MediationError('mediation_profile_not_found', 'mediation profile was not found for this owner');
    if (prior.sequence !== expectedSequence) throw new MediationError('mediation_sequence_conflict', 'mediation profile sequence conflict', { expectedSequence, observedSequence: prior.sequence });
    const now = this.now();
    const base = {
      ...prior,
      sequence: prior.sequence + 1,
      status: 'REVOKED' as const,
      requestDigest,
      idempotencyKeyDigest: idem.digest,
      priorRecordDigest: prior.recordDigest,
      updatedAt: now,
      revokedAt: now,
      revocationReasonDigest: reasonDigestValue,
    };
    const { recordDigest: _priorDigest, ...unsigned } = base;
    const candidate = { ...unsigned, recordDigest: sha256(canonicalize(unsigned)) } as MediationProfileRecord;
    const claim = this.claims.claim(claimKey, requestDigest, `${profileId}:${candidate.sequence}`, candidate);
    if (claim.requestDigest !== requestDigest) throw new MediationError('mediation_idempotency_conflict', 'idempotency key already belongs to a different mediation request');
    const record = claim.record;
    const created = !this.profiles.has(claim.recordId);
    if (created && !this.profiles.create(claim.recordId, record)) throw new MediationError('mediation_integrity_failure', 'revoked mediation profile could not be persisted');
    if (created) this.appendEvent(record, 'REVOKED', null, { reasonDigest: reasonDigestValue, priorRecordDigest: prior.recordDigest });
    return { profile: this.effective(record), replayed: !created };
  }

  list(filters: { ownerPrincipal?: string; status?: 'ACTIVE' | 'REVOKED' | 'EXPIRED'; offset?: unknown; limit?: unknown }): JsonObject {
    const pagination = page(filters.offset, filters.limit);
    const latest = new Map<string, MediationProfileRecord>();
    for (const record of this.profiles.scan(() => true, 0, 10_000).records) {
      const prior = latest.get(record.profileId);
      if (prior === undefined || record.sequence > prior.sequence) latest.set(record.profileId, record);
    }
    const all = [...latest.values()]
      .filter((record) => filters.ownerPrincipal === undefined || record.ownerPrincipal === filters.ownerPrincipal)
      .map((record) => this.effective(record))
      .filter((record) => filters.status === undefined || record.effectiveStatus === filters.status)
      .sort((left, right) => String(left.profileId).localeCompare(String(right.profileId)));
    const profiles = all.slice(pagination.offset, pagination.offset + pagination.limit);
    return { profiles, offset: pagination.offset, limit: pagination.limit, total: all.length, nextOffset: pagination.offset + profiles.length < all.length ? pagination.offset + profiles.length : null };
  }

  appendDecisionEvents(profile: MediationProfileRecord, transactionId: string, execution: NativeExecutionResult): MediationEventRecord[] {
    const events = execution.decisionEvents.slice(0, 1_000).map((decision) => this.appendEvent(profile, 'DECISION', transactionId, this.decisionDetails(decision, execution)));
    if (execution.decisionEvents.length === 0) events.push(this.appendEvent(profile, 'DECISION', transactionId, { decision: 'none', status: execution.status, ok: execution.ok, eventCount: execution.events, droppedEventCount: execution.droppedEvents, stdoutDigest: execution.stdoutDigest, stderrDigest: execution.stderrDigest, binaryDigest: execution.binaryDigest }));
    return events;
  }

  listEvents(profileIdValue: unknown, offsetValue: unknown, limitValue: unknown): JsonObject {
    const profileId = profileIdentifier(profileIdValue);
    this.latest(profileId);
    const pagination = page(offsetValue, limitValue);
    const scan = this.events.scan((event) => event.profileId === profileId, pagination.offset, pagination.limit);
    for (const event of scan.records) {
      const verification = verifyMediationEventRecord(event);
      if (!verification.valid) throw new MediationError('mediation_integrity_failure', 'mediation event integrity failed', { eventId: event.eventId, errors: verification.errors });
    }
    return { events: scan.records, offset: pagination.offset, limit: pagination.limit, total: scan.total, nextOffset: scan.nextOffset, corruptRecordIds: scan.corruptRecordIds };
  }

  reconcile(): JsonObject {
    const profileScan = this.profiles.scan(() => true, 0, 10_000);
    const eventScan = this.events.scan(() => true, 0, 10_000);
    let validProfiles = 0;
    let validEvents = 0;
    for (const record of profileScan.records) if (verifyMediationProfileRecord(record).valid) validProfiles += 1;
    for (const event of eventScan.records) if (verifyMediationEventRecord(event).valid) validEvents += 1;
    return { ok: profileScan.corruptRecordIds.length === 0 && eventScan.corruptRecordIds.length === 0 && validProfiles === profileScan.records.length && validEvents === eventScan.records.length, profileRecords: profileScan.records.length, validProfiles, eventRecords: eventScan.records.length, validEvents, corruptProfileRecordIds: profileScan.corruptRecordIds, corruptEventRecordIds: eventScan.corruptRecordIds };
  }

  private decisionDetails(decision: NativeDecisionEvent, execution: NativeExecutionResult): JsonObject {
    return { ...structuredClone(decision), status: execution.status, executionOk: execution.ok, eventCount: execution.events, droppedEventCount: execution.droppedEvents, stdoutDigest: execution.stdoutDigest, stderrDigest: execution.stderrDigest, binaryDigest: execution.binaryDigest };
  }

  private appendEvent(profile: MediationProfileRecord, operation: MediationEventRecord['operation'], transactionId: string | null, details: JsonObject): MediationEventRecord {
    const prior = this.events.scan((event) => event.profileId === profile.profileId, 0, 10_000).records.sort((left, right) => right.sequence - left.sequence)[0];
    const base = {
      schemaVersion: MEDIATION_EVENT_SCHEMA_VERSION,
      eventId: `mpe_${randomUUID().replaceAll('-', '')}`,
      profileId: profile.profileId,
      sequence: (prior?.sequence ?? 0) + 1,
      operation,
      ownerPrincipal: profile.ownerPrincipal,
      transactionId,
      details: structuredClone(details),
      occurredAt: this.now(),
      priorEventDigest: prior?.eventDigest ?? null,
    };
    const event = { ...base, eventDigest: sha256(canonicalize(base)) } as MediationEventRecord;
    if (!this.events.create(`${event.profileId}:${String(event.sequence).padStart(12, '0')}:${event.eventId}`, event)) throw new MediationError('mediation_integrity_failure', 'mediation event could not be persisted');
    return event;
  }
}
