import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../storage/record-store.ts';
import { RootFabricError, contextPrincipal, digest, idempotency, identifier, integer, object, strictObject, text, type RootEffectState, type RootEffectTransaction } from './model.ts';
import { RootEffectTransactionService } from './transactions.ts';
import { RootObservationService } from './observability.ts';
import { RootCredentialService } from './credentials.ts';

export const ROOT_RECOVERY_SCHEMA_VERSION = '1.1.0' as const;
export const FREEZE_SCOPES = ['GLOBAL', 'PRINCIPAL', 'SKILL', 'BUNDLE', 'GRANT', 'TRANSACTION', 'PROVIDER', 'CREDENTIAL_ISSUANCE', 'NEW_EXECUTION'] as const;
export type FreezeScope = typeof FREEZE_SCOPES[number];
export type ReconciliationClassification = 'RECOVERED' | 'RESUMED' | 'ROLLED_BACK' | 'COMPENSATED' | 'CLEANED' | 'EXPIRED' | 'FAILED' | 'RECOVERY_REQUIRED' | 'AMBIGUOUS';

export interface FreezeRecord extends JsonObject {
  schemaVersion: typeof ROOT_RECOVERY_SCHEMA_VERSION;
  freezeId: string;
  scope: FreezeScope;
  selector: string;
  active: boolean;
  reason: string;
  authorityPrincipalDigest: string;
  createdAt: string;
  updatedAt: string;
  expiresAt: string | null;
  sequence: number;
  previousEventDigest: string | null;
  eventDigest: string;
  recordDigest: string;
}

export interface ReconciliationRecord extends JsonObject {
  schemaVersion: typeof ROOT_RECOVERY_SCHEMA_VERSION;
  reconciliationId: string;
  transactionId: string;
  priorState: RootEffectState;
  nextState: RootEffectState;
  classification: ReconciliationClassification;
  observations: JsonObject;
  actions: JsonObject[];
  occurredAt: string;
  recordDigest: string;
}

export interface ExecutionReadback extends JsonObject {
  exists: boolean;
  matches: boolean;
  active: boolean;
  terminal: boolean;
  identity: JsonObject;
  resultDigest: string | null;
}

export interface RecoveryAuthority {
  inspectUnit(unitName: string, expectedIdentity: JsonObject): Promise<ExecutionReadback>;
  inspectMachine(machineId: string, expectedIdentity: JsonObject): Promise<ExecutionReadback>;
  inspectJob(jobId: string): Promise<ExecutionReadback>;
  killUnit(unitName: string, signal: string): Promise<JsonObject>;
  killMachine(machineId: string): Promise<JsonObject>;
  killJob(jobId: string, signal: string): Promise<JsonObject>;
  verifyUnitAbsent(unitName: string, expectedIdentity: JsonObject): Promise<ExecutionReadback>;
  verifyMachineAbsent(machineId: string): Promise<boolean>;
  verifyJobTerminal(jobId: string): Promise<boolean>;
}

type KillActionState = 'PENDING' | 'DISPATCHED' | 'VERIFIED' | 'FAILED';
type KillRecordState = 'RUNNING' | 'COMPLETED' | 'RECOVERY_REQUIRED';

interface KillAction extends JsonObject {
  actionId: string;
  transactionId: string;
  resourceType: 'UNIT' | 'MACHINE' | 'JOB';
  resourceId: string;
  expectedIdentity: JsonObject;
  state: KillActionState;
  attempts: number;
  dispatchedAt: string | null;
  verifiedAt: string | null;
  result: JsonObject | null;
  verification: JsonObject | null;
  error: string | null;
}

interface KillTarget extends JsonObject {
  transactionId: string;
  expectedSequence: number;
  fencingToken: number;
  transitionState: RootEffectState | null;
  transitionSequence: number | null;
}

interface KillRecord extends JsonObject {
  schemaVersion: typeof ROOT_RECOVERY_SCHEMA_VERSION;
  killId: string;
  principalDigest: string;
  scope: 'TRANSACTION' | 'SKILL' | 'ALL';
  selector: string;
  reason: string;
  requestDigest: string;
  state: KillRecordState;
  freezeDigest: string;
  targets: KillTarget[];
  actions: KillAction[];
  unresolved: string[];
  createdAt: string;
  updatedAt: string;
  recordDigest: string;
}

function unsigned<T extends JsonObject>(record: T): JsonObject {
  const { recordDigest: _recordDigest, ...rest } = record;
  return rest;
}
function seal<T extends JsonObject>(record: Omit<T, 'recordDigest'>): T {
  return { ...record, recordDigest: sha256(canonicalize(record)) } as T;
}
function verify(record: JsonObject): boolean {
  return typeof record.recordDigest === 'string' && record.recordDigest === sha256(canonicalize(unsigned(record)));
}
function freezeEventUnsigned(record: FreezeRecord): JsonObject {
  return {
    freezeId: record.freezeId,
    scope: record.scope,
    selector: record.selector,
    active: record.active,
    reason: record.reason,
    authorityPrincipalDigest: record.authorityPrincipalDigest,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    expiresAt: record.expiresAt,
    sequence: record.sequence,
    previousEventDigest: record.previousEventDigest,
  };
}
function verifyFreeze(record: FreezeRecord): boolean {
  return record.schemaVersion === ROOT_RECOVERY_SCHEMA_VERSION
    && verify(record)
    && record.eventDigest === sha256(canonicalize(freezeEventUnsigned(record)));
}
function scope(value: unknown): FreezeScope {
  const normalized = text(value, 'scope', 32) as FreezeScope;
  if (!FREEZE_SCOPES.includes(normalized)) throw new RootFabricError('invalid_request', 'freeze scope is invalid');
  return normalized;
}
function freezeKey(scopeValue: FreezeScope, selector: string): string {
  return `freeze_${sha256(canonicalize({ scope: scopeValue, selector })).slice(0, 40)}`;
}
function requestDigest(operation: string, principalDigest: string, payload: JsonObject): string {
  return sha256(canonicalize({ operation, principalDigest, payload }));
}
function control(value: unknown, field: string): { transactionId: string; expectedSequence: number; fencingToken: number } {
  const candidate = strictObject(value, field, ['transactionId', 'expectedSequence', 'fencingToken']);
  return {
    transactionId: identifier(candidate.transactionId, `${field}.transactionId`),
    expectedSequence: integer(candidate.expectedSequence, `${field}.expectedSequence`, 1, 10_000_000),
    fencingToken: integer(candidate.fencingToken, `${field}.fencingToken`, 1, Number.MAX_SAFE_INTEGER),
  };
}
function controls(value: unknown): { transactionId: string; expectedSequence: number; fencingToken: number }[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 4_096) throw new RootFabricError('invalid_request', 'transactions must be a non-empty bounded recovery control array');
  const normalized = value.map((entry, index) => control(entry, `transactions[${index}]`)).sort((left, right) => left.transactionId.localeCompare(right.transactionId));
  if (new Set(normalized.map((entry) => entry.transactionId)).size !== normalized.length) throw new RootFabricError('invalid_request', 'transactions must not contain duplicate transaction IDs');
  return normalized;
}
function completeUnitIdentity(transaction: RootEffectTransaction, unitName: string): JsonObject | null {
  const identities = Array.isArray(transaction.execution.processIdentities) ? transaction.execution.processIdentities as JsonObject[] : [];
  const raw = identities.find((identity) => identity.unitName === unitName || identity.unit === unitName);
  if (raw === undefined) return null;
  const processIdValue = raw.processId ?? raw.pid ?? raw.mainPid;
  const cgroupValue = raw.cgroupId ?? raw.cgroup ?? raw.controlGroup;
  const required = {
    unitName,
    transactionId: raw.transactionId,
    requestDigest: raw.requestDigest,
    cgroupId: cgroupValue,
    processId: processIdValue,
    processStartTime: raw.processStartTime,
    systemdStartTimestamp: raw.systemdStartTimestamp,
    bootId: raw.bootId,
    invocationId: raw.invocationId,
    executablePath: raw.executablePath,
  };
  try {
    return {
      unitName: identifier(required.unitName, 'unitName'),
      transactionId: identifier(required.transactionId, 'transactionId'),
      requestDigest: digest(required.requestDigest, 'requestDigest'),
      cgroupId: text(required.cgroupId, 'cgroupId', 1_024),
      processId: integer(Number(required.processId), 'processId', 1, 2 ** 31 - 1),
      processStartTime: text(required.processStartTime, 'processStartTime', 128),
      systemdStartTimestamp: text(required.systemdStartTimestamp, 'systemdStartTimestamp', 128),
      bootId: identifier(required.bootId, 'bootId'),
      invocationId: identifier(required.invocationId, 'invocationId'),
      executablePath: text(required.executablePath, 'executablePath', 4_096),
    };
  } catch { return null; }
}

export class RootFreezeService {
  private readonly records: DurableRecordStore<FreezeRecord>;
  private readonly claims: DurableClaimStore<FreezeRecord>;
  private readonly now: () => string;
  constructor(stateRoot: string, options: { now?: () => string } = {}) {
    const root = join(stateRoot, 'root-fabric', 'recovery');
    this.records = new DurableRecordStore(join(root, 'freezes'));
    this.claims = new DurableClaimStore(join(root, 'freeze-claims'));
    this.now = options.now ?? (() => new Date().toISOString());
  }

  get(payloadValue: unknown): JsonObject {
    const payload = strictObject(payloadValue ?? {}, 'freeze get payload', ['scope', 'selector', 'offset', 'limit']);
    const requestedScope = payload.scope === undefined ? undefined : scope(payload.scope);
    const requestedSelector = payload.selector === undefined ? undefined : text(payload.selector, 'selector', 512);
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, 10_000_000);
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, 200);
    const scan = this.records.scan((record) => (requestedScope === undefined || record.scope === requestedScope) && (requestedSelector === undefined || record.selector === requestedSelector), offset, limit);
    if (scan.corruptRecordIds.length > 0 || scan.records.some((record) => !verifyFreeze(record))) throw new RootFabricError('corrupt_record', 'freeze authority contains a corrupt record', { corruptRecordIds: scan.corruptRecordIds });
    const now = Date.parse(this.now());
    const freezes = scan.records.map((record) => record.active && record.expiresAt !== null && Date.parse(record.expiresAt) <= now ? this.expire(record) : record);
    return { freezes, offset, limit, total: scan.total, nextOffset: scan.nextOffset, corruptRecordIds: [] };
  }

  set(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'freeze set payload', ['scope', 'selector', 'active', 'reason', 'expiresAt']);
    const occurredAt = this.now();
    const principal = contextPrincipal(context, occurredAt);
    const idem = idempotency(context);
    const normalizedScope = scope(payload.scope);
    const selector = text(payload.selector, 'selector', 512);
    if (normalizedScope === 'GLOBAL' && selector !== '*') throw new RootFabricError('invalid_request', 'GLOBAL freeze selector must be *');
    const active = payload.active === true;
    const expiresAt = payload.expiresAt === null || payload.expiresAt === undefined ? null : text(payload.expiresAt, 'expiresAt', 64);
    if (expiresAt !== null && (!Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= Date.parse(occurredAt))) throw new RootFabricError('invalid_request', 'freeze expiry must be in the future');
    const normalized = { scope: normalizedScope, selector, active, reason: text(payload.reason, 'reason', 1_024), expiresAt };
    const request = requestDigest('babyx.root.freeze.set', principal.principalDigest, normalized);
    const claimKey = `${principal.principalDigest}:${idem.key}`;
    const existingClaim = this.claims.get(claimKey);
    const key = freezeKey(normalizedScope, selector);
    if (existingClaim !== undefined) {
      if (existingClaim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another freeze change');
      if (this.records.has(key)) {
        const current = this.records.get(key);
        if (!verifyFreeze(current)) throw new RootFabricError('corrupt_record', 'freeze record integrity failed');
        return { freeze: current, historicalFreeze: existingClaim.record, replayed: true };
      }
      if (!verifyFreeze(existingClaim.record)) throw new RootFabricError('corrupt_record', 'freeze claim integrity failed');
      this.records.create(key, existingClaim.record);
      return { freeze: this.records.get(key), historicalFreeze: existingClaim.record, replayed: true };
    }
    const current = this.records.has(key) ? this.records.get(key) : null;
    if (current !== null && !verifyFreeze(current)) throw new RootFabricError('corrupt_record', 'freeze record integrity failed');
    const sequence = (current?.sequence ?? 0) + 1;
    const eventBase = { freezeId: current?.freezeId ?? `frz_${randomUUID().replaceAll('-', '')}`, scope: normalizedScope, selector, active, reason: normalized.reason, authorityPrincipalDigest: principal.principalDigest, createdAt: current?.createdAt ?? occurredAt, updatedAt: occurredAt, expiresAt, sequence, previousEventDigest: current?.eventDigest ?? null };
    const record = seal<FreezeRecord>({ schemaVersion: ROOT_RECOVERY_SCHEMA_VERSION, ...eventBase, eventDigest: sha256(canonicalize(eventBase)) });
    const claim = this.claims.claim(claimKey, request, key, record);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another freeze change');
    const live = this.records.has(key) ? this.records.get(key) : current;
    if (live !== null && live !== undefined && live.recordDigest !== current?.recordDigest) throw new RootFabricError('transaction_state_conflict', 'freeze changed before commit');
    this.records.put(key, claim.record);
    return { freeze: this.records.get(key), replayed: false };
  }

  isFrozen(input: { principalId?: string; skillId?: string; bundleDigest?: string; grantId?: string; transactionId?: string; provider?: string; credentialIssuance?: boolean; newExecution?: boolean }): { frozen: boolean; matches: FreezeRecord[] } {
    const now = Date.parse(this.now());
    const scan = this.records.scan((record) => {
      if (!record.active || (record.expiresAt !== null && Date.parse(record.expiresAt) <= now)) return false;
      if (record.scope === 'GLOBAL') return true;
      if (record.scope === 'PRINCIPAL') return input.principalId === record.selector;
      if (record.scope === 'SKILL') return input.skillId === record.selector;
      if (record.scope === 'BUNDLE') return input.bundleDigest === record.selector;
      if (record.scope === 'GRANT') return input.grantId === record.selector;
      if (record.scope === 'TRANSACTION') return input.transactionId === record.selector;
      if (record.scope === 'PROVIDER') return input.provider === record.selector;
      if (record.scope === 'CREDENTIAL_ISSUANCE') return input.credentialIssuance === true;
      if (record.scope === 'NEW_EXECUTION') return input.newExecution === true;
      return false;
    }, 0, 10_000);
    if (scan.corruptRecordIds.length > 0 || scan.records.some((record) => !verifyFreeze(record))) throw new RootFabricError('corrupt_record', 'freeze authority contains a corrupt record', { corruptRecordIds: scan.corruptRecordIds });
    return { frozen: scan.records.length > 0, matches: scan.records };
  }

  private expire(record: FreezeRecord): FreezeRecord {
    if (!record.active) return record;
    const occurredAt = this.now();
    const eventBase = { freezeId: record.freezeId, scope: record.scope, selector: record.selector, active: false, reason: 'freeze expired', authorityPrincipalDigest: record.authorityPrincipalDigest, createdAt: record.createdAt, updatedAt: occurredAt, expiresAt: record.expiresAt, sequence: record.sequence + 1, previousEventDigest: record.eventDigest };
    const next = seal<FreezeRecord>({ schemaVersion: ROOT_RECOVERY_SCHEMA_VERSION, ...eventBase, eventDigest: sha256(canonicalize(eventBase)) });
    this.records.put(freezeKey(record.scope, record.selector), next);
    return next;
  }
}

export class RootRecoveryService {
  private readonly records: DurableRecordStore<ReconciliationRecord>;
  private readonly claims: DurableClaimStore<ReconciliationRecord>;
  private readonly killRecords: DurableRecordStore<KillRecord>;
  private readonly killClaims: DurableClaimStore<KillRecord>;
  private readonly now: () => string;

  constructor(private readonly options: {
    stateRoot: string;
    transactions: RootEffectTransactionService;
    observations: RootObservationService;
    credentials: RootCredentialService;
    freezes: RootFreezeService;
    authority: RecoveryAuthority;
    now?: () => string;
  }) {
    const root = join(options.stateRoot, 'root-fabric', 'recovery');
    this.records = new DurableRecordStore(join(root, 'reconciliations'));
    this.claims = new DurableClaimStore(join(root, 'reconciliation-claims'));
    this.killRecords = new DurableRecordStore(join(root, 'kills'));
    this.killClaims = new DurableClaimStore(join(root, 'kill-claims'));
    this.now = options.now ?? (() => new Date().toISOString());
  }

  async reconcile(payloadValue: unknown, context: RuntimeExecutionContext): Promise<JsonObject> {
    const payload = strictObject(payloadValue, 'reconcile payload', ['transactionId', 'expectedSequence', 'fencingToken']);
    const principal = contextPrincipal(context, this.now());
    const idem = idempotency(context);
    const normalizedControl = control(payload, 'reconcile');
    const normalized = { ...normalizedControl };
    const request = requestDigest('babyx.root.reconcile', principal.principalDigest, normalized);
    const claimKey = `${principal.principalDigest}:${idem.key}`;
    const existing = this.claims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another reconciliation request');
      const record = this.records.has(existing.recordId) ? this.records.get(existing.recordId) : existing.record;
      if (!verify(record)) throw new RootFabricError('corrupt_record', 'reconciliation record integrity failed');
      if (!this.records.has(existing.recordId)) this.records.create(existing.recordId, record);
      return { reconciliation: record, results: record.observations.transactionResults ?? [], replayed: true };
    }
    const recoveredKills: string[] = [];
    for (const kill of this.killRecords.scan((record) => record.principalDigest === principal.principalDigest && record.state === 'RUNNING', 0, 1_000).records) {
      if (!verify(kill)) throw new RootFabricError('corrupt_record', 'kill record integrity failed');
      const recovered = await this.executeKill(kill, context);
      recoveredKills.push(recovered.killId);
    }
    const transaction = this.options.transactions.recoveryRecord(normalizedControl, context);
    const result = await this.reconcileTransaction(transaction, normalizedControl, context);
    const credentialRecovery = this.options.credentials.recover();
    const activeObservations = this.options.observations.active(4_096);
    for (const observation of activeObservations) if (Date.parse(observation.deadline) <= Date.parse(this.now())) this.options.observations.fail(observation.sessionId, 'observation deadline elapsed during reconciliation');
    const summary = { transactionId: transaction.transactionId, transactionResults: [result], credentialRecovery, recoveredKillIds: recoveredKills, expiredObservationCount: activeObservations.filter((observation) => Date.parse(observation.deadline) <= Date.parse(this.now())).length };
    const reconciliationId = `rec_${randomUUID().replaceAll('-', '')}`;
    const aggregate = seal<ReconciliationRecord>({ schemaVersion: ROOT_RECOVERY_SCHEMA_VERSION, reconciliationId, transactionId: transaction.transactionId, priorState: result.priorState as RootEffectState, nextState: result.nextState as RootEffectState, classification: result.classification as ReconciliationClassification, observations: summary, actions: [], occurredAt: this.now() });
    const claim = this.claims.claim(claimKey, request, reconciliationId, aggregate);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another reconciliation request');
    if (!this.records.has(claim.recordId)) this.records.create(claim.recordId, claim.record);
    return { reconciliation: this.records.get(claim.recordId), results: [result], replayed: false };
  }

  async kill(payloadValue: unknown, context: RuntimeExecutionContext): Promise<JsonObject> {
    const payload = strictObject(payloadValue, 'kill payload', ['scope', 'selector', 'reason', 'transactions']);
    const principal = contextPrincipal(context, this.now());
    const idem = idempotency(context);
    const requestedScope = text(payload.scope, 'scope', 32);
    if (!['TRANSACTION', 'SKILL', 'ALL'].includes(requestedScope)) throw new RootFabricError('invalid_request', 'kill scope must be TRANSACTION, SKILL, or ALL');
    const selector = text(payload.selector, 'selector', 512);
    const reason = text(payload.reason, 'reason', 1_024);
    const normalizedControls = controls(payload.transactions);
    const normalized = { scope: requestedScope, selector, reason, transactions: normalizedControls };
    const request = requestDigest('babyx.root.kill', principal.principalDigest, normalized);
    const claimKey = `${principal.principalDigest}:${idem.key}`;
    const existing = this.killClaims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another emergency kill');
      const current = this.killRecords.has(existing.recordId) ? this.killRecords.get(existing.recordId) : existing.record;
      if (!verify(current)) throw new RootFabricError('corrupt_record', 'kill record integrity failed');
      if (!this.killRecords.has(existing.recordId)) this.killRecords.create(existing.recordId, current);
      if (current.state === 'RUNNING') await this.ensureKillFreeze(current, context);
      const finished = current.state === 'RUNNING' ? await this.executeKill(current, context) : current;
      return this.killResponse(finished, true);
    }
    const freezeScope: FreezeScope = requestedScope === 'ALL' ? 'GLOBAL' : requestedScope === 'SKILL' ? 'SKILL' : 'TRANSACTION';
    const freezeSelector = requestedScope === 'ALL' ? '*' : selector;
    const freeze = this.options.freezes.set({ scope: freezeScope, selector: freezeSelector, active: true, reason, expiresAt: null }, { ...context, idempotencyKey: `kill-freeze-${idem.digest.slice(0, 32)}` }).freeze as FreezeRecord;
    const candidates = this.options.transactions.nonterminal(4_096).filter((transaction) => requestedScope === 'ALL' || (requestedScope === 'TRANSACTION' ? transaction.transactionId === selector : transaction.skill.skillId === selector));
    const expectedIds = candidates.map((transaction) => transaction.transactionId).sort();
    const suppliedIds = normalizedControls.map((entry) => entry.transactionId);
    if (canonicalize(expectedIds) !== canonicalize(suppliedIds)) throw new RootFabricError('transaction_state_conflict', 'kill transaction controls do not exactly match the authoritative scope', { expectedIds, suppliedIds });
    if (requestedScope === 'TRANSACTION' && expectedIds.length !== 1) throw new RootFabricError('transaction_not_found', 'kill transaction selector does not identify one active transaction');
    const transactions = normalizedControls.map((entry) => this.options.transactions.recoveryRecord(entry, context));
    const actions: KillAction[] = [];
    const unresolved: string[] = [];
    for (const transaction of transactions) {
      for (const unitName of transaction.execution.unitNames as string[]) {
        const expectedIdentity = completeUnitIdentity(transaction, unitName);
        const actionId = `act_${sha256(canonicalize({ transactionId: transaction.transactionId, resourceType: 'UNIT', resourceId: unitName })).slice(0, 32)}`;
        if (expectedIdentity === null) unresolved.push(`${transaction.transactionId}:unit:${unitName}:incomplete_identity`);
        actions.push({ actionId, transactionId: transaction.transactionId, resourceType: 'UNIT', resourceId: unitName, expectedIdentity: expectedIdentity ?? { unitName, incompleteIdentity: true }, state: expectedIdentity === null ? 'FAILED' : 'PENDING', attempts: 0, dispatchedAt: null, verifiedAt: null, result: null, verification: null, error: expectedIdentity === null ? 'complete unit recovery identity is required' : null });
      }
      for (const machineId of transaction.execution.allMachineIds as string[]) actions.push({ actionId: `act_${sha256(canonicalize({ transactionId: transaction.transactionId, resourceType: 'MACHINE', resourceId: machineId })).slice(0, 32)}`, transactionId: transaction.transactionId, resourceType: 'MACHINE', resourceId: machineId, expectedIdentity: { machineId, transactionId: transaction.transactionId }, state: 'PENDING', attempts: 0, dispatchedAt: null, verifiedAt: null, result: null, verification: null, error: null });
      for (const jobId of transaction.execution.allJobIds as string[]) actions.push({ actionId: `act_${sha256(canonicalize({ transactionId: transaction.transactionId, resourceType: 'JOB', resourceId: jobId })).slice(0, 32)}`, transactionId: transaction.transactionId, resourceType: 'JOB', resourceId: jobId, expectedIdentity: { jobId }, state: 'PENDING', attempts: 0, dispatchedAt: null, verifiedAt: null, result: null, verification: null, error: null });
    }
    const killId = `kil_${randomUUID().replaceAll('-', '')}`;
    const createdAt = this.now();
    const record = seal<KillRecord>({ schemaVersion: ROOT_RECOVERY_SCHEMA_VERSION, killId, principalDigest: principal.principalDigest, scope: requestedScope as KillRecord['scope'], selector, reason, requestDigest: request, state: 'RUNNING', freezeDigest: freeze.recordDigest, targets: normalizedControls.map((entry) => ({ ...entry, transitionState: null, transitionSequence: null })), actions, unresolved, createdAt, updatedAt: createdAt });
    const claim = this.killClaims.claim(claimKey, request, killId, record);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another emergency kill');
    if (!this.killRecords.has(claim.recordId)) this.killRecords.create(claim.recordId, claim.record);
    const finished = await this.executeKill(this.killRecords.get(claim.recordId), context);
    return this.killResponse(finished, false);
  }

  private async ensureKillFreeze(record: KillRecord, context: RuntimeExecutionContext): Promise<void> {
    const freezeScope: FreezeScope = record.scope === 'ALL' ? 'GLOBAL' : record.scope === 'SKILL' ? 'SKILL' : 'TRANSACTION';
    const selector = record.scope === 'ALL' ? '*' : record.selector;
    if (!this.options.freezes.isFrozen(record.scope === 'ALL' ? { newExecution: true } : record.scope === 'SKILL' ? { skillId: selector } : { transactionId: selector }).frozen) {
      this.options.freezes.set({ scope: freezeScope, selector, active: true, reason: record.reason, expiresAt: null }, { ...context, idempotencyKey: `kill-refreeze-${record.killId.slice(-32)}` });
    }
  }

  private async executeKill(initial: KillRecord, context: RuntimeExecutionContext): Promise<KillRecord> {
    let record = this.readKill(initial.killId);
    if (record.state === 'COMPLETED') return record;
    for (const initialAction of record.actions) {
      record = this.readKill(record.killId);
      const action = record.actions.find((entry) => entry.actionId === initialAction.actionId)!;
      if (action.state === 'VERIFIED') continue;
      if (action.error === 'complete unit recovery identity is required') continue;
      if (action.state === 'DISPATCHED' || action.state === 'FAILED') {
        const verification = await this.verifyAction(action);
        if (verification.ok) { record = this.updateAction(record, action.actionId, { state: 'VERIFIED', verifiedAt: this.now(), verification: verification.details, error: null }); continue; }
      }
      try {
        const inspection = await this.inspectAction(action);
        if (inspection.terminal) {
          const verification = await this.verifyAction(action);
          if (verification.ok) { record = this.updateAction(record, action.actionId, { state: 'VERIFIED', verifiedAt: this.now(), verification: verification.details, error: null }); continue; }
        }
        if (inspection.exists && !inspection.matches) throw new RootFabricError('process_identity_conflict', `${action.resourceType.toLowerCase()} identity does not match the transaction`);
        record = this.updateAction(record, action.actionId, { state: 'DISPATCHED', attempts: action.attempts + 1, dispatchedAt: this.now(), error: null });
        const liveAction = record.actions.find((entry) => entry.actionId === action.actionId)!;
        const result = await this.dispatchAction(liveAction);
        record = this.updateAction(record, action.actionId, { result });
        const verification = await this.verifyAction(liveAction);
        record = this.updateAction(record, action.actionId, verification.ok ? { state: 'VERIFIED', verifiedAt: this.now(), verification: verification.details, error: null } : { state: 'FAILED', verification: verification.details, error: 'positive terminal absence verification failed' });
      } catch (error) {
        record = this.updateAction(record, action.actionId, { state: 'FAILED', error: error instanceof Error ? error.message : 'unknown kill failure' });
      }
    }
    record = this.readKill(record.killId);
    const unresolved = record.actions.filter((action) => action.state !== 'VERIFIED').map((action) => `${action.transactionId}:${action.resourceType.toLowerCase()}:${action.resourceId}:${action.error ?? action.state.toLowerCase()}`);
    if (canonicalize(unresolved) !== canonicalize(record.unresolved)) record = this.updateKill(record, { unresolved });
    for (const initialTarget of record.targets) {
      record = this.readKill(record.killId);
      const target = record.targets.find((entry) => entry.transactionId === initialTarget.transactionId)!;
      if (target.transitionState !== null) continue;
      const targetUnresolved = record.unresolved.filter((entry) => entry.startsWith(`${target.transactionId}:`));
      const nextState: RootEffectState = targetUnresolved.length === 0 ? 'CANCEL_REQUESTED' : 'RECOVERY_REQUIRED';
      const transition = this.options.transactions.recoveryTransition({ transactionId: target.transactionId, expectedSequence: target.expectedSequence, fencingToken: target.fencingToken, nextState, classification: targetUnresolved.length === 0 ? 'emergency_kill' : 'emergency_kill_incomplete', observations: { scope: record.scope, selector: record.selector, killId: record.killId, unresolved: targetUnresolved, actions: record.actions.filter((action) => action.transactionId === target.transactionId) } }, { ...context, idempotencyKey: `kill-transition-${sha256(`${record.killId}:${target.transactionId}`).slice(0, 32)}` }) as { transaction: RootEffectTransaction };
      record = this.updateTarget(record, target.transactionId, { transitionState: transition.transaction.lifecycle.persistedState, transitionSequence: transition.transaction.lifecycle.sequence });
    }
    record = this.readKill(record.killId);
    return this.updateKill(record, { state: record.unresolved.length === 0 ? 'COMPLETED' : 'RECOVERY_REQUIRED' });
  }

  private async inspectAction(action: KillAction): Promise<ExecutionReadback> {
    if (action.resourceType === 'UNIT') return this.options.authority.inspectUnit(action.resourceId, action.expectedIdentity);
    if (action.resourceType === 'MACHINE') return this.options.authority.inspectMachine(action.resourceId, action.expectedIdentity);
    return this.options.authority.inspectJob(action.resourceId);
  }
  private async dispatchAction(action: KillAction): Promise<JsonObject> {
    if (action.resourceType === 'UNIT') return this.options.authority.killUnit(action.resourceId, 'SIGKILL');
    if (action.resourceType === 'MACHINE') return this.options.authority.killMachine(action.resourceId);
    return this.options.authority.killJob(action.resourceId, 'SIGKILL');
  }
  private async verifyAction(action: KillAction): Promise<{ ok: boolean; details: JsonObject }> {
    if (action.resourceType === 'UNIT') {
      const readback = await this.options.authority.verifyUnitAbsent(action.resourceId, action.expectedIdentity);
      const identity = readback.identity;
      const ok = readback.matches && !readback.active && readback.terminal && identity.processAbsent === true && identity.cgroupEmpty === true;
      return { ok, details: readback };
    }
    if (action.resourceType === 'MACHINE') { const ok = await this.options.authority.verifyMachineAbsent(action.resourceId); return { ok, details: { absent: ok } }; }
    const ok = await this.options.authority.verifyJobTerminal(action.resourceId); return { ok, details: { terminal: ok } };
  }

  private updateAction(record: KillRecord, actionId: string, patch: JsonObject): KillRecord {
    return this.updateKill(record, { actions: record.actions.map((action) => action.actionId === actionId ? { ...action, ...patch } : action) });
  }
  private updateTarget(record: KillRecord, transactionId: string, patch: JsonObject): KillRecord {
    return this.updateKill(record, { targets: record.targets.map((target) => target.transactionId === transactionId ? { ...target, ...patch } : target) });
  }
  private updateKill(record: KillRecord, patch: JsonObject): KillRecord {
    const live = this.readKill(record.killId);
    if (live.recordDigest !== record.recordDigest) throw new RootFabricError('transaction_state_conflict', 'kill record changed before durable update');
    const next = seal<KillRecord>({ ...unsigned(record), ...patch, updatedAt: this.now() } as Omit<KillRecord, 'recordDigest'>);
    this.killRecords.put(record.killId, next);
    return this.readKill(record.killId);
  }
  private readKill(killId: string): KillRecord {
    const record = this.killRecords.get(killId);
    if (!verify(record)) throw new RootFabricError('corrupt_record', 'kill record integrity failed');
    return record;
  }
  private killResponse(record: KillRecord, replayed: boolean): JsonObject {
    return { kill: record, scope: record.scope, selector: record.selector, frozen: true, transactionCount: record.targets.length, actions: record.actions, unresolved: record.unresolved, complete: record.state === 'COMPLETED', replayed };
  }

  private async reconcileTransaction(transaction: RootEffectTransaction, recoveryControl: { transactionId: string; expectedSequence: number; fencingToken: number }, context: RuntimeExecutionContext): Promise<JsonObject> {
    const observations: JsonObject = { units: [], machines: [], jobs: [] };
    const actions: JsonObject[] = [];
    let mismatch = false; let active = false; let missing = false; let terminal = true;
    for (const unitName of transaction.execution.unitNames as string[]) {
      const expected = completeUnitIdentity(transaction, unitName);
      if (expected === null) {
        mismatch = true; terminal = false;
        (observations.units as JsonObject[]).push({ unitName, error: 'complete unit recovery identity is required' });
        continue;
      }
      const readback = await this.options.authority.inspectUnit(unitName, expected);
      (observations.units as JsonObject[]).push({ unitName, expectedIdentityDigest: sha256(canonicalize(expected)), readback });
      mismatch ||= readback.exists && !readback.matches; active ||= readback.active; missing ||= !readback.exists; terminal &&= readback.terminal;
    }
    for (const machineId of transaction.execution.allMachineIds as string[]) {
      const readback = await this.options.authority.inspectMachine(machineId, { machineId, transactionId: transaction.transactionId });
      (observations.machines as JsonObject[]).push({ machineId, readback });
      mismatch ||= readback.exists && !readback.matches; active ||= readback.active; missing ||= !readback.exists; terminal &&= readback.terminal;
    }
    for (const jobId of transaction.execution.allJobIds as string[]) {
      const readback = await this.options.authority.inspectJob(jobId);
      (observations.jobs as JsonObject[]).push({ jobId, readback });
      active ||= readback.active; missing ||= !readback.exists; terminal &&= readback.terminal;
    }
    let classification: ReconciliationClassification = 'RECOVERED';
    let nextState = transaction.lifecycle.persistedState;
    if (transaction.lifecycle.terminal) {
      if (transaction.lifecycle.persistedState === 'ROLLED_BACK') classification = 'ROLLED_BACK';
      else if (transaction.lifecycle.persistedState === 'COMPENSATED') classification = 'COMPENSATED';
      else if (transaction.lifecycle.persistedState === 'FAILED') classification = 'FAILED';
      else if (transaction.lifecycle.persistedState === 'EXPIRED') classification = 'EXPIRED';
    } else if (mismatch) { classification = 'AMBIGUOUS'; nextState = 'AMBIGUOUS'; }
    else if (Date.parse(transaction.lifecycle.deadline) <= Date.parse(this.now()) && ['REQUESTED', 'AUTHORIZING', 'PREPARING', 'READY'].includes(transaction.lifecycle.persistedState)) { classification = 'EXPIRED'; nextState = 'EXPIRED'; }
    else if (transaction.lifecycle.persistedState === 'EXECUTING') {
      if (active) classification = 'RESUMED';
      else if (terminal && !missing && transaction.execution.allJobIds.length > 0) { classification = 'RECOVERED'; nextState = 'VALIDATING'; }
      else { classification = 'RECOVERY_REQUIRED'; nextState = 'RECOVERY_REQUIRED'; }
    } else if (transaction.lifecycle.persistedState === 'VALIDATING' || transaction.lifecycle.persistedState === 'COMMITTING') {
      if (transaction.validation.result === 'SUCCEEDED' && transaction.execution.terminal === true && transaction.lifecycle.persistedState === 'VALIDATING') { classification = 'RECOVERED'; nextState = 'COMMITTING'; }
      else if (transaction.validation.result === 'FAILED') { classification = 'FAILED'; nextState = 'FAILED'; }
      else { classification = 'RECOVERY_REQUIRED'; nextState = 'RECOVERY_REQUIRED'; }
    } else if (transaction.lifecycle.persistedState === 'ROLLBACK_REQUESTED' || transaction.lifecycle.persistedState === 'ROLLING_BACK') {
      classification = transaction.rollback.result === 'SUCCEEDED' ? 'ROLLED_BACK' : 'RECOVERY_REQUIRED'; nextState = transaction.rollback.result === 'SUCCEEDED' ? 'ROLLED_BACK' : 'RECOVERY_REQUIRED';
    } else if (transaction.lifecycle.persistedState === 'COMPENSATING') {
      classification = transaction.compensation.result === 'SUCCEEDED' ? 'COMPENSATED' : 'RECOVERY_REQUIRED'; nextState = transaction.compensation.result === 'SUCCEEDED' ? 'COMPENSATED' : 'RECOVERY_REQUIRED';
    } else if (transaction.lifecycle.persistedState === 'CLEANING') {
      if (transaction.cleanup.completed === true && ['FAILED', 'ROLLED_BACK', 'COMPENSATED'].includes(String(transaction.cleanup.terminalState))) { classification = 'CLEANED'; nextState = transaction.cleanup.terminalState as RootEffectState; }
      else { classification = 'RECOVERY_REQUIRED'; nextState = 'RECOVERY_REQUIRED'; }
    }
    let updated = transaction;
    if (nextState !== transaction.lifecycle.persistedState) {
      const transition = this.options.transactions.recoveryTransition({ ...recoveryControl, nextState, classification: classification.toLowerCase(), observations }, { ...context, idempotencyKey: `reconcile-transition-${sha256(`${context.idempotencyKey ?? ''}:${transaction.transactionId}:${transaction.lifecycle.sequence}:${nextState}`).slice(0, 32)}` }) as { transaction: RootEffectTransaction };
      updated = transition.transaction;
    }
    const record = seal<ReconciliationRecord>({ schemaVersion: ROOT_RECOVERY_SCHEMA_VERSION, reconciliationId: `rec_${randomUUID().replaceAll('-', '')}`, transactionId: transaction.transactionId, priorState: transaction.lifecycle.persistedState, nextState: updated.lifecycle.persistedState, classification, observations, actions, occurredAt: this.now() });
    this.records.put(record.reconciliationId, record);
    return record;
  }
}
