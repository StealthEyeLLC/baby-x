import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, statfsSync } from 'node:fs';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import type { ArtifactManager } from '../artifacts/manager.ts';
import { evaluateCapacity, type CapacityObservation, type CapacityReservationAuthority, type CapacityReservationRequest } from './content.ts';
import { validateReleaseRecord } from './schemas.ts';
import { ReleaseApplianceStore, ReleaseStoreError } from './store.ts';

const GIB = 1024 * 1024 * 1024;
const LEDGER_SCHEMA = 'CapacityReservationLedgerV1';
const LEDGER_ID = 'release-capacity';
const LEDGER_OWNER = 'baby-x-resource-governor';
const MAX_RESERVATIONS = 10_000;
const MAX_RECENT_RESERVATIONS = 256;
const MAX_GC_CANDIDATES = 1_000;
const DEFAULT_RESERVATION_MS = 15 * 60 * 1_000;

export const RELEASE_CAPACITY_DEFAULTS = Object.freeze({
  rootWarningBytes: 20 * GIB,
  rootWarningPercent: 20,
  rootBackgroundThrottleBytes: 15 * GIB,
  rootStagingRejectBytes: 12 * GIB,
  rootEmergencyBytes: 8 * GIB,
  zfsWarningBytes: 3 * GIB,
  zfsWarningPercent: 25,
  zfsCloneRejectBytes: 2 * GIB,
  memoryHeavyweightReserveBytes: 2 * GIB,
  rootMinimumInodes: 10_000,
  defaultHeavyweightConcurrency: 1,
  maximumBackgroundConcurrency: 4,
  journalMaximumLines: 10_000,
  streamReadMaximumBytes: 1024 * 1024,
  evidenceMaximumReferences: 10_000,
  gcMaximumCandidates: MAX_GC_CANDIDATES,
});

export type ReleaseWorkClass = 'PRODUCTION_CONTROL' | 'HEAVYWEIGHT' | 'BACKGROUND';
export type PressureLevel = 'GREEN' | 'YELLOW' | 'RED' | 'UNKNOWN';

export interface PriorityEnforcementAuthority {
  readonly authority: 'existing-systemd-resource-authority';
  apply(request: { target: string; workClass: ReleaseWorkClass; properties: Readonly<Record<string, string>> }, context: RuntimeExecutionContext): Promise<JsonObject> | JsonObject;
}

export type RetentionFaultStage =
  | 'before_intent'
  | 'after_intent'
  | 'before_remove'
  | 'after_remove'
  | 'before_absence_verification'
  | 'during_absence_verification'
  | 'after_absence_verification'
  | 'before_terminal_persist';

export interface ReleaseResourceGovernorOptions {
  store: ReleaseApplianceStore;
  artifacts: ArtifactManager;
  capacityProvider: () => CapacityObservation;
  priorityAuthority?: PriorityEnforcementAuthority;
  retentionFaultInjector?: (stage: RetentionFaultStage, context: JsonObject) => void;
  now?: () => string;
}

export class ReleaseGovernorError extends Error {
  readonly code: string;
  readonly details: JsonObject;
  constructor(code: string, message: string, details: JsonObject = {}) { super(message); this.name = 'ReleaseGovernorError'; this.code = code; this.details = details; }
}

function isObject(value: unknown): value is JsonObject { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function object(value: unknown, name: string): JsonObject { if (!isObject(value)) throw new ReleaseGovernorError('release_invalid_request', `${name} must be an object`); return value; }
function integer(value: unknown, name: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new ReleaseGovernorError('release_invalid_request', `${name} must be an integer between ${minimum} and ${maximum}`);
  return Number(value);
}
function text(value: unknown, name: string, maximum = 256): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || value.includes('\0')) throw new ReleaseGovernorError('release_invalid_request', `${name} must be a bounded string`);
  return value;
}
function identifier(value: unknown, name: string): string {
  const result = text(value, name);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$/u.test(result)) throw new ReleaseGovernorError('release_invalid_request', `${name} must be an identifier`);
  return result;
}
function timestamp(value: unknown, name: string): string {
  const result = text(value, name);
  if (!result.endsWith('Z') || Number.isNaN(Date.parse(result))) throw new ReleaseGovernorError('release_invalid_request', `${name} must be an absolute UTC timestamp`);
  return result;
}
function strictObject(value: unknown, name: string, allowed: readonly string[], required: readonly string[] = []): JsonObject {
  const result = object(value, name);
  for (const key of Object.keys(result)) if (!allowed.includes(key)) throw new ReleaseGovernorError('release_invalid_request', `${name} contains unsupported property ${key}`);
  for (const key of required) if (result[key] === undefined) throw new ReleaseGovernorError('release_invalid_request', `${name}.${key} is required`);
  return result;
}
function sortedUnique(values: Iterable<string>): string[] { return [...new Set(values)].sort(); }
function totalReservations(reservations: readonly JsonObject[]): JsonObject {
  return {
    rootBytes: reservations.reduce((sum, item) => sum + Number(item.rootBytes ?? 0), 0),
    zfsBytes: reservations.reduce((sum, item) => sum + Number(item.zfsBytes ?? 0), 0),
    memoryBytes: reservations.reduce((sum, item) => sum + Number(item.memoryBytes ?? 0), 0),
  };
}
function reservationDigest(value: JsonObject): string {
  const copy = { ...value }; delete copy.createdAt; delete copy.expiresAt; delete copy.snapshotId; delete copy.admission; delete copy.state; delete copy.releasedAt; delete copy.releaseReason; delete copy.requestDigest;
  return sha256(canonicalize(copy));
}
function normalizeReservation(value: CapacityReservationRequest, now: string): JsonObject {
  const input = strictObject(value, 'capacity reservation', ['reservationId','purpose','workClass','rootBytes','zfsBytes','memoryBytes','ownerPrincipal','expiresAt'], ['reservationId','purpose','rootBytes','zfsBytes','memoryBytes','ownerPrincipal']);
  const purpose = text(input.purpose, 'purpose') as CapacityReservationRequest['purpose'];
  const purposes = new Set(['SOURCE_ARCHIVE','DEPENDENCY_CACHE','BUILD_CACHE','RELEASE_ARTIFACT','MATERIALIZATION','CERTIFICATION','DISPOSABLE_CLONE','BACKGROUND_MAINTENANCE']);
  if (!purposes.has(purpose)) throw new ReleaseGovernorError('release_invalid_request', 'capacity reservation purpose is unsupported');
  const defaultClass: ReleaseWorkClass = purpose === 'DEPENDENCY_CACHE' || purpose === 'BUILD_CACHE' || purpose === 'BACKGROUND_MAINTENANCE' ? 'BACKGROUND' : 'HEAVYWEIGHT';
  const workClass = String(input.workClass ?? defaultClass) as ReleaseWorkClass;
  if (!['PRODUCTION_CONTROL','HEAVYWEIGHT','BACKGROUND'].includes(workClass)) throw new ReleaseGovernorError('release_invalid_request', 'capacity workClass is unsupported');
  const normalized: JsonObject = {
    schemaVersion: '1.0.0', reservationId: identifier(input.reservationId, 'reservationId'), ownerPrincipal: identifier(input.ownerPrincipal, 'ownerPrincipal'),
    purpose, workClass, rootBytes: integer(input.rootBytes, 'rootBytes'), zfsBytes: integer(input.zfsBytes, 'zfsBytes'), memoryBytes: integer(input.memoryBytes, 'memoryBytes'),
    createdAt: now, expiresAt: input.expiresAt === undefined ? new Date(Date.parse(now) + DEFAULT_RESERVATION_MS).toISOString() : timestamp(input.expiresAt, 'expiresAt'),
  };
  return { ...normalized, requestDigest: reservationDigest(normalized) };
}
function validateReservation(value: unknown): JsonObject { return validateReleaseRecord('CapacityReservationV1', value); }
function activeAt(reservation: JsonObject, now: string): boolean { return reservation.state === 'ACTIVE' && Date.parse(String(reservation.expiresAt)) > Date.parse(now); }
function normalizeObservation(value: CapacityObservation): CapacityObservation {
  const input = object(value, 'capacity observation');
  const normalized: CapacityObservation = {
    observedAt: timestamp(input.observedAt, 'observedAt'), rootTotalBytes: integer(input.rootTotalBytes, 'rootTotalBytes'), rootAvailableBytes: integer(input.rootAvailableBytes, 'rootAvailableBytes'),
    rootAvailableInodes: integer(input.rootAvailableInodes, 'rootAvailableInodes'), zfsPool: text(input.zfsPool, 'zfsPool'), zfsAvailableBytes: integer(input.zfsAvailableBytes, 'zfsAvailableBytes'),
    memoryAvailableBytes: integer(input.memoryAvailableBytes, 'memoryAvailableBytes'), cpuPressure: object(input.cpuPressure, 'cpuPressure'), memoryPressure: object(input.memoryPressure, 'memoryPressure'), ioPressure: object(input.ioPressure, 'ioPressure'),
  };
  if (input.zfsTotalBytes !== undefined) normalized.zfsTotalBytes = integer(input.zfsTotalBytes, 'zfsTotalBytes');
  return normalized;
}
function parsePsiFile(path: string): JsonObject {
  try {
    const rows: JsonObject = {};
    for (const line of readFileSync(path, 'utf8').trim().split(/\n/u)) {
      const [kind, ...parts] = line.trim().split(/\s+/u);
      if (!kind) continue;
      const metrics: JsonObject = {};
      for (const part of parts) { const [key, raw] = part.split('='); if (key && raw !== undefined) metrics[key] = Number(raw); }
      rows[kind] = metrics;
    }
    return { status: 'AVAILABLE', ...rows };
  } catch { return { status: 'UNKNOWN' }; }
}
function metric(value: JsonObject, kind: string, key: string): number | undefined {
  const section = value[kind];
  if (!isObject(section) || typeof section[key] !== 'number' || !Number.isFinite(section[key])) return undefined;
  return Number(section[key]);
}
export function pressureLevel(value: JsonObject): PressureLevel {
  const declared = typeof value.level === 'string' ? value.level : typeof value.status === 'string' ? value.status : undefined;
  if (declared === 'GREEN' || declared === 'YELLOW' || declared === 'RED' || declared === 'UNKNOWN') return declared;
  const some = metric(value, 'some', 'avg10');
  const full = metric(value, 'full', 'avg10') ?? 0;
  if (some === undefined) return 'UNKNOWN';
  if (full >= 1 || some >= 20) return 'RED';
  if (full >= 0.1 || some >= 5) return 'YELLOW';
  return 'GREEN';
}
export function releasePriorityProfile(workClass: ReleaseWorkClass): Readonly<Record<string, string>> {
  if (workClass === 'PRODUCTION_CONTROL') return Object.freeze({ CPUWeight: '10000', IOWeight: '10000', Nice: '-10', OOMScoreAdjust: '-900' });
  if (workClass === 'HEAVYWEIGHT') return Object.freeze({ CPUWeight: '200', IOWeight: '200', Nice: '5', OOMScoreAdjust: '200' });
  return Object.freeze({ CPUWeight: '100', IOWeight: '100', Nice: '10', OOMScoreAdjust: '500' });
}
export function evaluateGovernor(observation: CapacityObservation, admission: string, serviceHealth: 'GREEN' | 'YELLOW' | 'RED' | 'UNKNOWN' = 'GREEN'): JsonObject {
  const levels = { cpu: pressureLevel(observation.cpuPressure), memory: pressureLevel(observation.memoryPressure), io: pressureLevel(observation.ioPressure) };
  const values = Object.values(levels);
  const worst: PressureLevel = values.includes('RED') ? 'RED' : values.includes('YELLOW') ? 'YELLOW' : values.includes('UNKNOWN') ? 'UNKNOWN' : 'GREEN';
  const productionControlConcurrency = 1;
  const heavyweightConcurrency = admission === 'REJECT' || worst === 'RED' || serviceHealth === 'RED' || observation.memoryAvailableBytes < RELEASE_CAPACITY_DEFAULTS.memoryHeavyweightReserveBytes ? 0 : 1;
  const backgroundConcurrency = admission === 'ALLOW' && worst === 'GREEN' && serviceHealth === 'GREEN' ? 4 : admission === 'REJECT' || worst === 'RED' || serviceHealth === 'RED' || worst === 'UNKNOWN' || serviceHealth === 'UNKNOWN' ? 0 : 1;
  return { pressure: levels, worstPressure: worst, serviceHealth, productionControlConcurrency, heavyweightConcurrency, backgroundConcurrency, productionControlResponsive: true, priorities: { productionControl: releasePriorityProfile('PRODUCTION_CONTROL'), heavyweight: releasePriorityProfile('HEAVYWEIGHT'), background: releasePriorityProfile('BACKGROUND') } };
}

export function observeHostCapacity(options: { rootPath: string; zfsDataset?: string; zfsPath?: string; now?: () => string }): CapacityObservation {
  const root = statfsSync(options.rootPath);
  const blockSize = Number(root.bsize);
  let zfsAvailableBytes = 0;
  let zfsTotalBytes = 0;
  let zfsPool = options.zfsDataset ?? 'babycert';
  const zfsPath = options.zfsPath ?? (existsSync('/usr/sbin/zfs') ? '/usr/sbin/zfs' : '/usr/bin/zfs');
  if (existsSync(zfsPath)) {
    const result = spawnSync(zfsPath, ['list', '-Hp', '-o', 'available,used', zfsPool], { encoding: 'utf8', timeout: 5_000 });
    if (result.status === 0) {
      const [available, used] = result.stdout.trim().split(/\s+/u).map(Number);
      if (Number.isSafeInteger(available) && Number.isSafeInteger(used) && available >= 0 && used >= 0) { zfsAvailableBytes = available; zfsTotalBytes = available + used; }
    } else zfsPool = `${zfsPool}:unavailable`;
  } else zfsPool = `${zfsPool}:unavailable`;
  return {
    observedAt: (options.now ?? (() => new Date().toISOString()))(), rootTotalBytes: Number(root.blocks) * blockSize, rootAvailableBytes: Number(root.bavail) * blockSize,
    rootAvailableInodes: Number(root.ffree), zfsPool, zfsTotalBytes, zfsAvailableBytes, memoryAvailableBytes: Number(process.memoryUsage().rss) >= 0 ? Number(readFileSync('/proc/meminfo','utf8').match(/^MemAvailable:\s+([0-9]+)/mu)?.[1] ?? 0) * 1024 : 0,
    cpuPressure: parsePsiFile('/proc/pressure/cpu'), memoryPressure: parsePsiFile('/proc/pressure/memory'), ioPressure: parsePsiFile('/proc/pressure/io'),
  };
}

function effectiveObservation(observation: CapacityObservation, totals: JsonObject): CapacityObservation {
  return { ...observation, rootAvailableBytes: Math.max(0, observation.rootAvailableBytes - Number(totals.rootBytes ?? 0)), zfsAvailableBytes: Math.max(0, observation.zfsAvailableBytes - Number(totals.zfsBytes ?? 0)), memoryAvailableBytes: Math.max(0, observation.memoryAvailableBytes - Number(totals.memoryBytes ?? 0)) };
}
function syntheticLedger(now: string): JsonObject { return { schemaVersion:'1.0.0', ledgerId:LEDGER_ID, ownerPrincipal:LEDGER_OWNER, state:'ACTIVE', sequence:0, reservations:[], reservedRootBytes:0, reservedZfsBytes:0, reservedMemoryBytes:0, reconstructedAt:now, reconstructionDigest:sha256(canonicalize([])), updatedAt:now }; }
function reservationState(reservations: readonly JsonObject[], now: string): { all: JsonObject[]; active: JsonObject[]; totals: JsonObject; changed: boolean } {
  let changed = false;
  const all = reservations.map((entry) => {
    const item = validateReservation(entry);
    if (item.state === 'ACTIVE' && Date.parse(String(item.expiresAt)) <= Date.parse(now)) { changed = true; return validateReservation({ ...item, state:'EXPIRED', releasedAt:now, releaseReason:'lease-expired' }); }
    return item;
  });
  const active = all.filter((entry) => activeAt(entry, now));
  return { all, active, totals: totalReservations(active), changed };
}
function ledgerDigest(reservations: readonly JsonObject[], totals: JsonObject): string { return sha256(canonicalize({ reservations, totals })); }

function collectArtifactIds(value: unknown, path = '$', output = new Map<string,string[]>()): Map<string,string[]> {
  if (Array.isArray(value)) { value.forEach((entry,index) => collectArtifactIds(entry, `${path}[${index}]`, output)); return output; }
  if (!isObject(value)) return output;
  for (const [key, entry] of Object.entries(value)) {
    const next = `${path}.${key}`;
    if (typeof entry === 'string' && /(?:artifactId|evidenceIndexId)$/u.test(key)) output.set(entry, [...(output.get(entry) ?? []), next]);
    else collectArtifactIds(entry, next, output);
  }
  return output;
}
function recordProtectsArtifacts(schemaId: string, record: JsonObject): boolean {
  if (schemaId === 'EvidenceIndexV1') return true;
  if (schemaId === 'ReleaseRecordV1') return record.pinned === true || ['ACTIVE','ROLLBACK','PINNED','QUARANTINE'].includes(String(record.retentionClass)) || record.integrityState !== 'VERIFIED' || (Array.isArray(record.slotReferences) && record.slotReferences.length > 0) || (Array.isArray(record.deploymentReferences) && record.deploymentReferences.length > 0);
  if (schemaId === 'DeploymentRecordV1') return !['ROLLED_BACK','FAILED','CANCELLED','EXPIRED'].includes(String(record.state)) || ['AMBIGUOUS','RECOVERY_REQUIRED'].includes(String(record.state));
  if (schemaId === 'RouteRecordV1') return !['ABSENT_VERIFIED'].includes(String(record.state));
  if (schemaId === 'CertificationRecordV1') return !['FAILED'].includes(String(record.state)) || record.evidenceIndexId !== undefined;
  return !['CapacitySnapshotV1','CapacityReservationLedgerV1','RetentionDecisionV1','RetentionEvictionV1'].includes(schemaId);
}

export function projectReleaseCapacity(observationValue: CapacityObservation, payloadValue: JsonObject = {}, activeReservationsValue: readonly JsonObject[] = [], nowValue?: string): JsonObject {
  const payload=strictObject(payloadValue,'capacity request',['projection','serviceHealth']);
  const observation=normalizeObservation(observationValue);
  const now=nowValue ?? observation.observedAt;
  const activeReservations=activeReservationsValue.map(validateReservation).filter((entry)=>activeAt(entry,now));
  const totals=totalReservations(activeReservations);
  const effective=effectiveObservation(observation,totals);
  let projection:JsonObject|undefined;
  if(payload.projection!==undefined){ const request=normalizeReservation(object(payload.projection,'projection') as CapacityReservationRequest,now); const decision=evaluateCapacity(effective,request as CapacityReservationRequest); projection={request,decision}; }
  const baseDecision=evaluateCapacity(effective,{reservationId:'projection-zero',purpose:'BACKGROUND_MAINTENANCE',workClass:'BACKGROUND',rootBytes:0,zfsBytes:0,memoryBytes:0,ownerPrincipal:LEDGER_OWNER} as CapacityReservationRequest);
  const serviceHealth=payload.serviceHealth===undefined?'GREEN':String(payload.serviceHealth) as 'GREEN'|'YELLOW'|'RED'|'UNKNOWN';
  if(!['GREEN','YELLOW','RED','UNKNOWN'].includes(serviceHealth))throw new ReleaseGovernorError('release_invalid_request','serviceHealth is invalid');
  return {operation:'babyx.release.capacity',readOnly:true,observedAt:observation.observedAt,observation,activeReservations,activeReservationTotals:totals,admission:baseDecision,governor:evaluateGovernor(effective,String(baseDecision.admission),serviceHealth),floors:RELEASE_CAPACITY_DEFAULTS,bounds:{journalMaximumLines:RELEASE_CAPACITY_DEFAULTS.journalMaximumLines,streamReadMaximumBytes:RELEASE_CAPACITY_DEFAULTS.streamReadMaximumBytes,evidenceMaximumReferences:RELEASE_CAPACITY_DEFAULTS.evidenceMaximumReferences},...(projection===undefined?{}:{projection})};
}

export class ReleaseResourceGovernor implements CapacityReservationAuthority {
  readonly authority = 'release-resource-governor' as const;
  private readonly now: () => string;
  constructor(private readonly options: ReleaseResourceGovernorOptions) { this.now = options.now ?? (() => new Date().toISOString()); }
  private ledger(): JsonObject { return this.options.store.hasRecord(LEDGER_SCHEMA, LEDGER_ID) ? this.options.store.getRecord(LEDGER_SCHEMA, LEDGER_ID) : syntheticLedger(this.now()); }
  private normalizedLedger(current: JsonObject, now: string): { ledger: JsonObject; state: ReturnType<typeof reservationState> } {
    const entries = Array.isArray(current.reservations) ? current.reservations : [];
    const state = reservationState(entries as JsonObject[], now);
    const recent = state.all.filter((entry) => entry.state !== 'ACTIVE').slice(-MAX_RECENT_RESERVATIONS);
    const reservations = [...state.active, ...recent].slice(-MAX_RESERVATIONS);
    const digest = ledgerDigest(reservations, state.totals);
    return { state, ledger: validateReleaseRecord(LEDGER_SCHEMA, { ...current, sequence:Number(current.sequence), reservations, reservedRootBytes:state.totals.rootBytes, reservedZfsBytes:state.totals.zfsBytes, reservedMemoryBytes:state.totals.memoryBytes, reconstructedAt:now, reconstructionDigest:digest, updatedAt:now }) };
  }
  private writeLedger(current: JsonObject, reservations: JsonObject[], operation: string, idempotencyKey: string, now: string): JsonObject {
    const state = reservationState(reservations, now);
    const retained = [...state.active, ...state.all.filter((entry) => entry.state !== 'ACTIVE').slice(-MAX_RECENT_RESERVATIONS)].slice(-MAX_RESERVATIONS);
    const totals = totalReservations(state.active);
    const candidate = validateReleaseRecord(LEDGER_SCHEMA, { schemaVersion:'1.0.0', ledgerId:LEDGER_ID, ownerPrincipal:LEDGER_OWNER, state:'ACTIVE', sequence:Number(current.sequence)+1, reservations:retained, reservedRootBytes:totals.rootBytes, reservedZfsBytes:totals.zfsBytes, reservedMemoryBytes:totals.memoryBytes, reconstructedAt:now, reconstructionDigest:ledgerDigest(retained,totals), updatedAt:now });
    return this.options.store.applyMutation({ schemaId:LEDGER_SCHEMA, recordId:LEDGER_ID, ownerPrincipal:LEDGER_OWNER, expectedSequence:Number(current.sequence), idempotencyKey, requestDigest:sha256(canonicalize(candidate)), operation, phase:'capacity-ledger', record:candidate, occurredAt:now, observationDigest:String(candidate.reconstructionDigest) });
  }
  reconstruct(): JsonObject {
    const now = this.now(); const current = this.ledger(); const normalized = this.normalizedLedger(current, now);
    const same = current.sequence !== 0 && current.reconstructionDigest === normalized.ledger.reconstructionDigest && current.reservedRootBytes === normalized.ledger.reservedRootBytes && current.reservedZfsBytes === normalized.ledger.reservedZfsBytes && current.reservedMemoryBytes === normalized.ledger.reservedMemoryBytes;
    if (same) return { operation:'babyx.release.capacity.reconstruct', repaired:false, ledger:current };
    return { operation:'babyx.release.capacity.reconstruct', repaired:true, ledger:this.writeLedger(current, normalized.ledger.reservations as JsonObject[], 'babyx.release.capacity.reconstruct', `capacity-reconstruct-${Number(current.sequence)+1}-${String(normalized.ledger.reconstructionDigest).slice(0,16)}`, now) };
  }
  reserve(requestValue: CapacityReservationRequest): JsonObject {
    const now = this.now(); const request = normalizeReservation(requestValue, now);
    for (let attempt=0; attempt<4; attempt+=1) {
      const current = this.ledger(); const normalized = this.normalizedLedger(current, now); const reservations = normalized.ledger.reservations as JsonObject[];
      const existing = reservations.find((entry) => entry.reservationId === request.reservationId);
      if (existing !== undefined && existing.requestDigest !== request.requestDigest) throw new ReleaseGovernorError('release_idempotency_conflict', 'reservation identity is bound to a different request', { reservationId:request.reservationId });
      if (existing !== undefined && activeAt(existing, now)) return { operation:'babyx.release.capacity.reserve', replayed:true, reservation:existing, ledger:normalized.ledger };
      const active = reservations.filter((entry) => activeAt(entry, now) && entry.reservationId !== request.reservationId);
      const totals = totalReservations(active);
      const observation = normalizeObservation(this.options.capacityProvider());
      const effective = effectiveObservation(observation, totals);
      const decision = evaluateCapacity(effective, request as CapacityReservationRequest);
      const governorDecision = evaluateGovernor(effective, String(decision.admission));
      const observationDigest = sha256(canonicalize({ observation, activeReservationTotals:totals, request, decision, governorDecision }));
      const snapshotId = `capacity_${sha256(canonicalize({ reservationId:request.reservationId, requestDigest:request.requestDigest, observationDigest })).slice(0,40)}`;
      const snapshot = validateReleaseRecord('CapacitySnapshotV1', { schemaVersion:'1.0.0', snapshotId, observedAt:observation.observedAt, rootTotalBytes:observation.rootTotalBytes, rootAvailableBytes:observation.rootAvailableBytes, rootAvailableInodes:observation.rootAvailableInodes, zfsPool:observation.zfsPool, ...(observation.zfsTotalBytes===undefined?{}:{zfsTotalBytes:observation.zfsTotalBytes}), zfsAvailableBytes:observation.zfsAvailableBytes, memoryAvailableBytes:observation.memoryAvailableBytes, cpuPressure:observation.cpuPressure, memoryPressure:observation.memoryPressure, ioPressure:observation.ioPressure, reservations:[...active,request], activeReservationTotals:totals, admission:decision.admission, governorDecision, observationDigest });
      if (!this.options.store.hasRecord('CapacitySnapshotV1', snapshotId)) this.options.store.applyMutation({ schemaId:'CapacitySnapshotV1', recordId:snapshotId, ownerPrincipal:String(request.ownerPrincipal), expectedSequence:0, idempotencyKey:`capacity-snapshot-${snapshotId}`, requestDigest:sha256(canonicalize(snapshot)), operation:'babyx.release.capacity.snapshot', phase:'capacity-observation', record:snapshot, occurredAt:observation.observedAt, observationDigest });
      if (decision.admission === 'REJECT') throw new ReleaseGovernorError('release_capacity_insufficient', 'capacity admission rejected before persistent content write', { snapshotId, decision, governorDecision });
      const reservation = validateReservation({ ...request, snapshotId, admission:decision.admission, state:'ACTIVE' });
      const next = [...reservations.filter((entry) => entry.reservationId !== request.reservationId), reservation];
      try {
        const ledger = this.writeLedger(current, next, 'babyx.release.capacity.reserve', `capacity-reserve-${request.reservationId}-${Number(current.sequence)+1}-${String(request.requestDigest).slice(0,16)}`, now);
        return { operation:'babyx.release.capacity.reserve', replayed:false, reservation, snapshot, decision, governorDecision, ledger };
      } catch (error) {
        if (!(error instanceof ReleaseStoreError) || error.code !== 'release_stale_sequence' || attempt === 3) throw error;
      }
    }
    throw new ReleaseGovernorError('release_recovery_required', 'capacity reservation could not converge after bounded retries');
  }
  release(reservationIdValue: string, ownerPrincipalValue: string, reason = 'completed'): JsonObject {
    const reservationId = identifier(reservationIdValue,'reservationId'); const ownerPrincipal = identifier(ownerPrincipalValue,'ownerPrincipal'); const now=this.now();
    for (let attempt=0; attempt<4; attempt+=1) {
      const current=this.ledger(); const reservations=(this.normalizedLedger(current,now).ledger.reservations as JsonObject[]); const index=reservations.findIndex((entry)=>entry.reservationId===reservationId);
      if (index<0) return { operation:'babyx.release.capacity.release', released:false, alreadyAbsent:true, reservationId };
      const existing=reservations[index]; if (existing.ownerPrincipal!==ownerPrincipal) throw new ReleaseGovernorError('release_wrong_principal','reservation owner does not match');
      if (existing.state!=='ACTIVE') return { operation:'babyx.release.capacity.release', released:false, replayed:true, reservation:existing };
      const released=validateReservation({ ...existing, state:'RELEASED', releasedAt:now, releaseReason:text(reason,'reason',256) }); const next=[...reservations]; next[index]=released;
      try { return { operation:'babyx.release.capacity.release', released:true, reservation:released, ledger:this.writeLedger(current,next,'babyx.release.capacity.release',`capacity-release-${reservationId}-${Number(current.sequence)+1}`,now) }; }
      catch(error){ if(!(error instanceof ReleaseStoreError)||error.code!=='release_stale_sequence'||attempt===3) throw error; }
    }
    throw new ReleaseGovernorError('release_recovery_required','capacity release could not converge after bounded retries');
  }
  capacity(payloadValue: JsonObject = {}): JsonObject {
    const now=this.now(); const current=this.ledger(); const normalized=this.normalizedLedger(current,now);
    return projectReleaseCapacity(this.options.capacityProvider(), payloadValue, normalized.state.active, now);
  }
  async enforcePriority(payloadValue: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const payload=strictObject(payloadValue,'priority request',['target','workClass'],['target','workClass']); const target=identifier(payload.target,'target'); const workClass=String(payload.workClass) as ReleaseWorkClass; if(!['PRODUCTION_CONTROL','HEAVYWEIGHT','BACKGROUND'].includes(workClass)) throw new ReleaseGovernorError('release_invalid_request','workClass is invalid'); const properties=releasePriorityProfile(workClass);
    if(this.options.priorityAuthority===undefined) return { operation:'babyx.release.capacity.priority', target, workClass, properties, applied:false, reason:'provider-not-configured' };
    const result=await this.options.priorityAuthority.apply({target,workClass,properties},context); return { operation:'babyx.release.capacity.priority',target,workClass,properties,applied:true,result };
  }
  private references(): { protected:Map<string,string[]>; uncertain:boolean; digest:string } {
    const protectedRefs=new Map<string,string[]>(); let uncertain=false; const identities=this.options.store.listRecordIdentities(10_000);
    for(const identity of identities){ try{ const record=this.options.store.getRecord(identity.schemaId,identity.recordId); if(!recordProtectsArtifacts(identity.schemaId,record)) continue; for(const [artifactId,paths] of collectArtifactIds(record)) protectedRefs.set(artifactId,[...(protectedRefs.get(artifactId)??[]),...paths.map((path)=>`${identity.schemaId}:${identity.recordId}:${path}`)]); }catch{ uncertain=true; } }
    const normalized=[...protectedRefs.entries()].map(([id,refs])=>[id,sortedUnique(refs)]).sort(([a],[b])=>a.localeCompare(b)); return {protected:protectedRefs,uncertain,digest:sha256(canonicalize({normalized,uncertain}))};
  }
  planGc(payloadValue: JsonObject = {}): JsonObject {
    const payload=strictObject(payloadValue,'gc request',['limit','maxBytes'],[]); const limit=payload.limit===undefined?100:integer(payload.limit,'limit',1,MAX_GC_CANDIDATES); const maxBytes=payload.maxBytes===undefined?Number.MAX_SAFE_INTEGER:integer(payload.maxBytes,'maxBytes',0); const now=this.now(); const refs=this.references(); const artifacts=this.options.artifacts.list().filter((entry)=>entry.state==='finalized').sort((a,b)=>String((a.metadata as JsonObject|undefined)?.lastAccessedAt??a.finalizedAt??a.createdAt).localeCompare(String((b.metadata as JsonObject|undefined)?.lastAccessedAt??b.finalizedAt??b.createdAt))||String(a.id).localeCompare(String(b.id)));
    const decisions:JsonObject[]=[]; let selectedBytes=0;
    for(const artifact of artifacts){ if(decisions.length>=limit) break; const id=String(artifact.id); const metadata=isObject(artifact.metadata)?artifact.metadata:{}; const protectedReferences=sortedUnique(refs.protected.get(id)??[]); const retentionClass=String(metadata.retentionClass??(String(metadata.kind??'').endsWith('-cache')?'CACHE':'RECENT')); const reasons:string[]=[]; let decision:'RETAIN'|'EVICT'|'QUARANTINE'|'DEFER'='RETAIN'; let valid=true; try{valid=this.options.artifacts.verify(id).valid===true;}catch{valid=false;}
      if(!valid){decision='QUARANTINE';reasons.push('artifact-integrity-not-verified');}
      else if(refs.uncertain){decision='DEFER';reasons.push('authoritative-reference-scan-uncertain');}
      else if(metadata.pinned===true||retentionClass==='PINNED'){reasons.push('pinned');}
      else if(['ACTIVE','ROLLBACK','QUARANTINE'].includes(retentionClass)){reasons.push(`retention-class-${retentionClass.toLowerCase()}`);}
      else if(protectedReferences.length>0){reasons.push('protected-authoritative-reference');}
      else if(retentionClass!=='CACHE'){reasons.push(`retention-class-${retentionClass.toLowerCase()}`);}
      else if(selectedBytes+Number(artifact.size??0)>maxBytes){decision='DEFER';reasons.push('gc-byte-bound');}
      else{decision='EVICT';reasons.push('unreferenced-cache-lru');selectedBytes+=Number(artifact.size??0);}
      decisions.push({objectType:'ARTIFACT',objectId:id,artifactSha256:artifact.sha256,sizeBytes:Number(artifact.size??0),retentionClass,lastAccessedAt:metadata.lastAccessedAt??artifact.finalizedAt??artifact.createdAt,decision,reasons,referenceCount:protectedReferences.length,protectedReferences});
    }
    const planIdentity={schemaVersion:'1.0.0',referenceDigest:refs.digest,limit,maxBytes,selectedBytes,decisions};
    const planDigest=sha256(canonicalize(planIdentity));
    return {operation:'babyx.release.gc',dryRun:true,decidedAt:now,...planIdentity,planDigest,destructiveActions:[]};
  }
  private retentionFault(stage: RetentionFaultStage, context: JsonObject): void {
    this.options.retentionFaultInjector?.(stage, structuredClone(context));
  }
  private mutationKey(...parts: string[]): string {
    return `retention-${sha256(parts.join(':')).slice(0, 48)}`;
  }
  private artifactPresence(artifactId: string, expectedDigest: string): JsonObject {
    try {
      const record = this.options.artifacts.get(artifactId);
      const metadata = isObject(record.metadata) ? record.metadata : {};
      if (record.sha256 !== expectedDigest) {
        return { status:'IDENTITY_MISMATCH', present:true, observedDigest:record.sha256, retentionClass:metadata.retentionClass, pinned:metadata.pinned === true };
      }
      const verification = this.options.artifacts.verify(artifactId);
      return {
        status:verification.valid === true ? 'PRESENT_VERIFIED' : 'PRESENT_CORRUPT',
        present:true,
        observedDigest:verification.sha256,
        retentionClass:metadata.retentionClass,
        pinned:metadata.pinned === true,
      };
    } catch (error) {
      if (error instanceof Error && /artifact not found/u.test(error.message)) return { status:'ABSENT_VERIFIED', present:false };
      return { status:'UNKNOWN', present:null, errorDigest:sha256(error instanceof Error ? error.message : String(error)) };
    }
  }
  private writeEviction(current: JsonObject, state: string, phase: string, extras: JsonObject = {}): JsonObject {
    const occurredAt = this.now();
    const merged: JsonObject = { ...current, ...extras };
    if (['REMOVING','VERIFYING_ABSENCE','REMOVED'].includes(state)) delete merged.error;
    const candidate = validateReleaseRecord('RetentionEvictionV1', {
      ...merged,
      state,
      sequence:Number(current.sequence) + 1,
      updatedAt:occurredAt,
    });
    return this.options.store.applyMutation({
      schemaId:'RetentionEvictionV1',
      recordId:String(candidate.decisionId),
      ownerPrincipal:String(candidate.ownerPrincipal),
      expectedSequence:Number(current.sequence),
      idempotencyKey:this.mutationKey(String(candidate.decisionId), String(candidate.sequence), state),
      requestDigest:sha256(canonicalize(candidate)),
      operation:'babyx.release.gc',
      phase,
      record:candidate,
      occurredAt,
      artifactReferences:[],
      observationDigest:typeof candidate.observationDigest === 'string' ? candidate.observationDigest : undefined,
    });
  }
  private createEviction(item: JsonObject, plan: JsonObject, owner: string, idempotencyKey: string): JsonObject {
    const decisionId = `retention-${sha256(`${String(plan.planDigest)}:${String(item.objectId)}`).slice(0, 40)}`;
    if (this.options.store.hasRecord('RetentionEvictionV1', decisionId)) {
      const existing = this.options.store.getRecord('RetentionEvictionV1', decisionId);
      if (existing.ownerPrincipal !== owner) throw new ReleaseGovernorError('release_wrong_principal', 'retention eviction owner does not match');
      if (
        existing.idempotencyKey !== idempotencyKey
        || existing.planDigest !== plan.planDigest
        || existing.artifactId !== item.objectId
        || existing.expectedArtifactDigest !== item.artifactSha256
      ) throw new ReleaseGovernorError('release_idempotency_conflict', 'retention eviction identity conflicts with the durable request');
      return existing;
    }
    const requestedAt = this.now();
    const identity: JsonObject = {
      decisionId,
      ownerPrincipal:owner,
      artifactId:item.objectId,
      objectId:item.objectId,
      expectedArtifactDigest:item.artifactSha256,
      retentionClass:item.retentionClass,
      planDigest:plan.planDigest,
      referenceScanDigest:plan.referenceDigest,
      protectedReferenceResult:Number(item.referenceCount) === 0 ? 'UNPROTECTED' : 'PROTECTED',
      protectedReferences:item.protectedReferences,
      idempotencyKey,
      requestedAction:'REMOVE',
      requestedAt,
    };
    const requestDigest = sha256(canonicalize(identity));
    const record = validateReleaseRecord('RetentionEvictionV1', {
      schemaVersion:'1.0.0',
      ...identity,
      requestDigest,
      sequence:1,
      state:'REQUESTED',
      updatedAt:requestedAt,
    });
    this.retentionFault('before_intent', { decisionId, artifactId:item.objectId });
    const durable = this.options.store.applyMutation({
      schemaId:'RetentionEvictionV1',
      recordId:decisionId,
      ownerPrincipal:owner,
      expectedSequence:0,
      idempotencyKey:this.mutationKey(decisionId, 'requested'),
      requestDigest,
      operation:'babyx.release.gc',
      phase:'retention-intent',
      record,
      occurredAt:requestedAt,
      artifactReferences:[],
    });
    this.retentionFault('after_intent', { decisionId, artifactId:item.objectId, sequence:durable.sequence });
    return durable;
  }
  private blockedEviction(record: JsonObject, refs: ReturnType<ReleaseResourceGovernor['references']>, reason: string): JsonObject {
    const protectedReferences = sortedUnique(refs.protected.get(String(record.artifactId)) ?? []);
    return this.writeEviction(record, 'BLOCKED', 'retention-reference-check', {
      removalReferenceScanDigest:refs.digest,
      protectedReferenceResult:refs.uncertain ? 'UNCERTAIN' : 'PROTECTED',
      protectedReferences,
      observationDigest:sha256(canonicalize({ reason, referenceScanDigest:refs.digest, protectedReferences })),
      error:{
        code:'release_recovery_required',
        message:reason,
        retryable:false,
        phase:'retention-reference-check',
        productionImpact:'NONE',
        detailsDigest:sha256(reason),
      },
    });
  }
  private ensureFinalRetentionDecision(eviction: JsonObject): JsonObject {
    const decisionId = String(eviction.decisionId);
    if (this.options.store.hasRecord('RetentionDecisionV1', decisionId)) {
      const existing = this.options.store.getRecord('RetentionDecisionV1', decisionId);
      if (
        existing.ownerPrincipal !== eviction.ownerPrincipal
        || existing.objectId !== eviction.artifactId
        || existing.planDigest !== eviction.planDigest
        || existing.executionState !== 'EXECUTED'
      ) throw new ReleaseGovernorError('release_idempotency_conflict', 'terminal retention decision conflicts with durable eviction truth');
      return existing;
    }
    const base: JsonObject = {
      schemaVersion:'1.0.0',
      decisionId,
      ownerPrincipal:eviction.ownerPrincipal,
      objectType:'ARTIFACT',
      objectId:eviction.artifactId,
      decision:'EVICT',
      reasons:['unreferenced-cache-lru'],
      referenceCount:0,
      protectedReferences:[],
      decidedAt:eviction.requestedAt,
      planDigest:eviction.planDigest,
      executionState:'EXECUTED',
      sequence:1,
      executedAt:eviction.removedAt,
      bytesFreed:Number(eviction.bytesFreed ?? 0),
    };
    const decision = validateReleaseRecord('RetentionDecisionV1', { ...base, decisionDigest:sha256(canonicalize(base)) });
    return this.options.store.applyMutation({
      schemaId:'RetentionDecisionV1',
      recordId:decisionId,
      ownerPrincipal:String(eviction.ownerPrincipal),
      expectedSequence:0,
      idempotencyKey:this.mutationKey(decisionId, 'terminal-decision'),
      requestDigest:sha256(canonicalize(decision)),
      operation:'babyx.release.gc',
      phase:'retention-terminal-evidence',
      record:decision,
      occurredAt:String(eviction.removedAt),
      artifactReferences:[],
      observationDigest:String(eviction.observationDigest),
    });
  }
  private executeEviction(recordValue: JsonObject): JsonObject {
    let record = validateReleaseRecord('RetentionEvictionV1', recordValue);
    if (record.state === 'REMOVED') {
      this.ensureFinalRetentionDecision(record);
      return record;
    }
    if (record.state === 'BLOCKED' || record.state === 'FAILED') return record;

    let observation = this.artifactPresence(String(record.artifactId), String(record.expectedArtifactDigest));
    if (observation.status === 'IDENTITY_MISMATCH' || observation.status === 'PRESENT_CORRUPT') {
      return this.writeEviction(record, 'FAILED', 'retention-identity-check', {
        observationDigest:sha256(canonicalize(observation)),
        error:{
          code:'release_artifact_invalid',
          message:'artifact identity or integrity does not match eviction intent',
          retryable:false,
          phase:'retention-identity-check',
          productionImpact:'NONE',
          detailsDigest:sha256(canonicalize(observation)),
        },
      });
    }
    if (observation.status === 'UNKNOWN') {
      return this.writeEviction(record, 'AMBIGUOUS', 'retention-readback', {
        observationDigest:sha256(canonicalize(observation)),
        error:{
          code:'release_recovery_required',
          message:'artifact presence could not be proven',
          retryable:true,
          phase:'retention-readback',
          productionImpact:'UNKNOWN',
          detailsDigest:sha256(canonicalize(observation)),
        },
      });
    }

    if (observation.present === true) {
      if (observation.pinned === true || observation.retentionClass !== 'CACHE') {
        return this.writeEviction(record, 'BLOCKED', 'retention-class-recheck', {
          observationDigest:sha256(canonicalize(observation)),
          protectedReferenceResult:'PROTECTED',
          error:{
            code:'release_recovery_required',
            message:'artifact retention metadata became protected before removal',
            retryable:false,
            phase:'retention-class-recheck',
            productionImpact:'NONE',
            detailsDigest:sha256(canonicalize(observation)),
          },
        });
      }
      const refs = this.references();
      const protectedReferences = sortedUnique(refs.protected.get(String(record.artifactId)) ?? []);
      if (refs.uncertain || protectedReferences.length > 0) {
        return this.blockedEviction(record, refs, refs.uncertain ? 'authoritative reference scan is uncertain' : 'artifact became protected before removal');
      }
      record = this.writeEviction(record, 'REMOVING', 'retention-removing', {
        removalReferenceScanDigest:refs.digest,
        protectedReferenceResult:'UNPROTECTED',
        protectedReferences,
        removingAt:this.now(),
      });
      this.retentionFault('before_remove', { decisionId:record.decisionId, artifactId:record.artifactId, sequence:record.sequence });
      let removal: JsonObject | undefined;
      try {
        removal = this.options.artifacts.remove(String(record.artifactId), String(record.expectedArtifactDigest));
      } catch (error) {
        observation = this.artifactPresence(String(record.artifactId), String(record.expectedArtifactDigest));
        if (observation.present === true) {
          return this.writeEviction(record, 'RECOVERY_REQUIRED', 'retention-remove-failed', {
            observationDigest:sha256(canonicalize(observation)),
            error:{
              code:'release_recovery_required',
              message:'artifact removal did not complete',
              retryable:true,
              phase:'retention-remove',
              productionImpact:'NONE',
              detailsDigest:sha256(error instanceof Error ? error.message : String(error)),
            },
          });
        }
        if (observation.present === null) {
          return this.writeEviction(record, 'AMBIGUOUS', 'retention-remove-response-loss', {
            observationDigest:sha256(canonicalize(observation)),
            error:{
              code:'release_response_lost',
              message:'artifact removal response was lost and absence is unproven',
              retryable:true,
              phase:'retention-remove',
              productionImpact:'UNKNOWN',
              detailsDigest:sha256(error instanceof Error ? error.message : String(error)),
            },
          });
        }
      }
      this.retentionFault('after_remove', { decisionId:record.decisionId, artifactId:record.artifactId, sequence:record.sequence });
      record = this.writeEviction(record, 'VERIFYING_ABSENCE', 'retention-absence-requested', {
        bytesFreed:Number(removal?.bytesFreed ?? record.bytesFreed ?? 0),
      });
    } else if (record.state !== 'VERIFYING_ABSENCE') {
      record = this.writeEviction(record, 'VERIFYING_ABSENCE', 'retention-recovery-readback');
    }

    this.retentionFault('before_absence_verification', { decisionId:record.decisionId, artifactId:record.artifactId, sequence:record.sequence });
    observation = this.artifactPresence(String(record.artifactId), String(record.expectedArtifactDigest));
    this.retentionFault('during_absence_verification', { decisionId:record.decisionId, artifactId:record.artifactId, observation });
    if (observation.status !== 'ABSENT_VERIFIED') {
      const nextState = observation.present === true ? 'RECOVERY_REQUIRED' : 'AMBIGUOUS';
      return this.writeEviction(record, nextState, 'retention-absence-unproven', {
        observationDigest:sha256(canonicalize(observation)),
        error:{
          code:'release_recovery_required',
          message:'positive artifact absence was not proven',
          retryable:true,
          phase:'retention-absence',
          productionImpact:'UNKNOWN',
          detailsDigest:sha256(canonicalize(observation)),
        },
      });
    }
    const observationDigest = sha256(canonicalize(observation));
    this.retentionFault('after_absence_verification', { decisionId:record.decisionId, artifactId:record.artifactId, observationDigest });
    this.retentionFault('before_terminal_persist', { decisionId:record.decisionId, artifactId:record.artifactId, sequence:record.sequence });
    const removedAt = this.now();
    record = this.writeEviction(record, 'REMOVED', 'retention-removed', {
      absenceVerifiedAt:removedAt,
      removedAt,
      observationDigest,
    });
    this.ensureFinalRetentionDecision(record);
    return record;
  }
  private evictionRecords(planDigest?: string): JsonObject[] {
    return this.options.store.listRecordIdentities(10_000)
      .filter((entry) => entry.schemaId === 'RetentionEvictionV1')
      .map((entry) => this.options.store.getRecord(entry.schemaId, entry.recordId))
      .filter((record) => planDigest === undefined || record.planDigest === planDigest)
      .sort((left, right) => String(left.artifactId).localeCompare(String(right.artifactId)));
  }
  private validateEvictionReplay(records: readonly JsonObject[], owner: string, idempotencyKey: string): void {
    for (const record of records) {
      if (record.ownerPrincipal !== owner) throw new ReleaseGovernorError('release_wrong_principal', 'retention eviction belongs to a different principal');
      if (record.idempotencyKey !== idempotencyKey) throw new ReleaseGovernorError('release_idempotency_conflict', 'retention eviction idempotency key conflicts with durable intent');
    }
  }
  recoverRetentionEvictions(context: RuntimeExecutionContext, planDigest?: string): JsonObject {
    const owner = identifier(context.subject, 'context.subject');
    const idempotencyKey = identifier(context.idempotencyKey, 'context.idempotencyKey');
    const records = this.evictionRecords(planDigest);
    const selected = planDigest === undefined ? records.filter((record) => record.ownerPrincipal === owner) : records;
    if (planDigest !== undefined) this.validateEvictionReplay(selected, owner, idempotencyKey);
    const recovered = selected.map((record) => this.executeEviction(record));
    return { operation:'babyx.release.gc.recover', ownerPrincipal:owner, planDigest, recovered };
  }
  gc(payloadValue: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'gc request', ['dryRun','limit','maxBytes','planDigest'], ['dryRun']);
    if (payload.dryRun === true) return this.planGc({ ...(payload.limit === undefined ? {} : { limit:payload.limit }), ...(payload.maxBytes === undefined ? {} : { maxBytes:payload.maxBytes }) });
    if (payload.dryRun !== false) throw new ReleaseGovernorError('release_invalid_request', 'dryRun must be boolean');
    const owner = identifier(context.subject, 'context.subject');
    const idempotencyKey = identifier(context.idempotencyKey, 'context.idempotencyKey');
    if (typeof payload.planDigest !== 'string') throw new ReleaseGovernorError('release_stale_sequence', 'live GC requires the exact current dry-run plan digest');

    let records = this.evictionRecords(payload.planDigest);
    this.validateEvictionReplay(records, owner, idempotencyKey);
    const currentPlan = this.planGc({ ...(payload.limit === undefined ? {} : { limit:payload.limit }), ...(payload.maxBytes === undefined ? {} : { maxBytes:payload.maxBytes }) });
    if (currentPlan.planDigest === payload.planDigest) {
      const evictionItems = (currentPlan.decisions as JsonObject[]).filter((item) => item.decision === 'EVICT');
      for (const item of evictionItems) this.createEviction(item, currentPlan, owner, idempotencyKey);
      records = this.evictionRecords(payload.planDigest);
      this.validateEvictionReplay(records, owner, idempotencyKey);
    } else if (records.length === 0) {
      throw new ReleaseGovernorError('release_stale_sequence', 'live GC requires the exact current dry-run plan digest');
    }

    const executed = records.map((record) => {
      const decision = this.executeEviction(record);
      return { decision, removal:{ bytesFreed:Number(decision.bytesFreed ?? 0), state:decision.state } };
    });
    return {
      ...(currentPlan.planDigest === payload.planDigest ? currentPlan : { operation:'babyx.release.gc', planDigest:payload.planDigest, recovered:true }),
      dryRun:false,
      destructiveActions:executed,
      bytesFreed:executed.reduce((sum, item) => sum + Number(object(item.removal, 'removal').bytesFreed ?? 0), 0),
    };
  }

}
