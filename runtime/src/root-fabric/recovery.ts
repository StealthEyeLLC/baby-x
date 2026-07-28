import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../storage/record-store.ts';
import { RootFabricError, contextPrincipal, idempotency, identifier, integer, strictObject, text, type RootEffectState, type RootEffectTransaction } from './model.ts';
import { RootEffectTransactionService } from './transactions.ts';
import { RootObservationService } from './observability.ts';
import { RootCredentialService } from './credentials.ts';

export const ROOT_RECOVERY_SCHEMA_VERSION = '1.0.0' as const;
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
  verifyUnitAbsent(unitName: string): Promise<boolean>;
  verifyMachineAbsent(machineId: string): Promise<boolean>;
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
    const now = Date.parse(this.now());
    const freezes = scan.records.filter(verify).map((record) => record.active && record.expiresAt !== null && Date.parse(record.expiresAt) <= now ? this.expire(record) : record);
    return { freezes, offset, limit, total: scan.total, nextOffset: scan.nextOffset, corruptRecordIds: scan.corruptRecordIds };
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
    if (existingClaim !== undefined) {
      if (existingClaim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another freeze change');
      this.records.put(existingClaim.recordId, existingClaim.record);
      return { freeze: this.records.get(existingClaim.recordId), replayed: true };
    }
    const key = freezeKey(normalizedScope, selector);
    const current = this.records.has(key) ? this.records.get(key) : null;
    if (current !== null && !verify(current)) throw new RootFabricError('corrupt_record', 'freeze record integrity failed');
    const sequence = (current?.sequence ?? 0) + 1;
    const eventBase = { freezeId: current?.freezeId ?? `frz_${randomUUID().replaceAll('-', '')}`, scope: normalizedScope, selector, active, reason: normalized.reason, authorityPrincipalDigest: principal.principalDigest, createdAt: current?.createdAt ?? occurredAt, updatedAt: occurredAt, expiresAt, sequence, previousEventDigest: current?.eventDigest ?? null };
    const record = seal<FreezeRecord>({ ...eventBase, eventDigest: sha256(canonicalize(eventBase)) });
    const claim = this.claims.claim(claimKey, request, key, record);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another freeze change');
    this.records.put(key, claim.record);
    return { freeze: this.records.get(key), replayed: false };
  }

  isFrozen(input: { principalId?: string; skillId?: string; bundleDigest?: string; grantId?: string; transactionId?: string; provider?: string; credentialIssuance?: boolean; newExecution?: boolean }): { frozen: boolean; matches: FreezeRecord[] } {
    const now = Date.parse(this.now());
    const matches = this.records.scan((record) => {
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
    }, 0, 10_000).records.filter(verify);
    return { frozen: matches.length > 0, matches };
  }

  private expire(record: FreezeRecord): FreezeRecord {
    if (!record.active) return record;
    const occurredAt = this.now();
    const eventBase = { ...unsigned(record), active: false, reason: 'freeze expired', updatedAt: occurredAt, sequence: record.sequence + 1, previousEventDigest: record.eventDigest };
    const next = seal<FreezeRecord>({ ...eventBase, eventDigest: sha256(canonicalize(eventBase)) } as Omit<FreezeRecord, 'recordDigest'>);
    this.records.put(freezeKey(record.scope, record.selector), next);
    return next;
  }
}

export class RootRecoveryService {
  private readonly records: DurableRecordStore<ReconciliationRecord>;
  private readonly claims: DurableClaimStore<ReconciliationRecord>;
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
    this.now = options.now ?? (() => new Date().toISOString());
  }

  async reconcile(payloadValue: unknown, context: RuntimeExecutionContext): Promise<JsonObject> {
    const payload = strictObject(payloadValue ?? {}, 'reconcile payload', ['transactionId', 'limit']);
    const principal = contextPrincipal(context, this.now());
    const idem = idempotency(context);
    const transactionId = payload.transactionId === undefined ? undefined : identifier(payload.transactionId, 'transactionId');
    const limit = payload.limit === undefined ? 4_096 : integer(payload.limit, 'limit', 1, 4_096);
    const normalized = { transactionId: transactionId ?? null, limit };
    const request = requestDigest('babyx.root.reconcile', principal.principalDigest, normalized);
    const claimKey = `${principal.principalDigest}:${idem.key}`;
    const existing = this.claims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another reconciliation request');
      return { reconciliation: existing.record, replayed: true };
    }
    const candidates = transactionId === undefined ? this.options.transactions.nonterminal(limit) : [this.options.transactions.record(transactionId)];
    const results: JsonObject[] = [];
    for (const transaction of candidates) results.push(await this.reconcileTransaction(transaction));
    const credentialRecovery = this.options.credentials.recover();
    const activeObservations = this.options.observations.active(limit);
    for (const observation of activeObservations) if (Date.parse(observation.deadline) <= Date.parse(this.now())) this.options.observations.fail(observation.sessionId, 'observation deadline elapsed during reconciliation');
    const summary = { transactionId: transactionId ?? null, transactionResults: results, credentialRecovery, expiredObservationCount: activeObservations.filter((observation) => Date.parse(observation.deadline) <= Date.parse(this.now())).length };
    const reconciliationId = `rec_${randomUUID().replaceAll('-', '')}`;
    const aggregate = seal<ReconciliationRecord>({ schemaVersion: ROOT_RECOVERY_SCHEMA_VERSION, reconciliationId, transactionId: transactionId ?? '*', priorState: 'REQUESTED', nextState: results.some((result) => result.classification === 'AMBIGUOUS') ? 'AMBIGUOUS' : results.some((result) => result.classification === 'RECOVERY_REQUIRED') ? 'RECOVERY_REQUIRED' : 'READY', classification: results.some((result) => result.classification === 'AMBIGUOUS') ? 'AMBIGUOUS' : results.some((result) => result.classification === 'RECOVERY_REQUIRED') ? 'RECOVERY_REQUIRED' : 'RECOVERED', observations: summary, actions: [], occurredAt: this.now() });
    const claim = this.claims.claim(claimKey, request, reconciliationId, aggregate);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another reconciliation request');
    if (!this.records.has(claim.recordId)) this.records.create(claim.recordId, claim.record);
    return { reconciliation: this.records.get(claim.recordId), results, replayed: false };
  }

  async kill(payloadValue: unknown, context: RuntimeExecutionContext): Promise<JsonObject> {
    const payload = strictObject(payloadValue, 'kill payload', ['scope', 'selector', 'reason']);
    const principal = contextPrincipal(context, this.now());
    idempotency(context);
    const requestedScope = text(payload.scope, 'scope', 32);
    if (!['TRANSACTION', 'SKILL', 'ALL'].includes(requestedScope)) throw new RootFabricError('invalid_request', 'kill scope must be TRANSACTION, SKILL, or ALL');
    const selector = text(payload.selector, 'selector', 512);
    const freezeScope: FreezeScope = requestedScope === 'ALL' ? 'GLOBAL' : requestedScope === 'SKILL' ? 'SKILL' : 'TRANSACTION';
    this.options.freezes.set({ scope: freezeScope, selector: requestedScope === 'ALL' ? '*' : selector, active: true, reason: text(payload.reason, 'reason', 1_024), expiresAt: null }, { ...context, idempotencyKey: `${context.idempotencyKey ?? 'kill'}-freeze` });
    const transactions = this.options.transactions.nonterminal(4_096).filter((transaction) => requestedScope === 'ALL' || (requestedScope === 'TRANSACTION' ? transaction.transactionId === selector : transaction.skill.skillId === selector));
    const actions: JsonObject[] = [];
    const unresolved: string[] = [];
    for (const transaction of transactions) {
      for (const unitName of transaction.execution.unitNames as string[]) {
        try { actions.push({ type: 'unit-kill', unitName, result: await this.options.authority.killUnit(unitName, 'SIGKILL') }); if (!await this.options.authority.verifyUnitAbsent(unitName)) unresolved.push(`unit:${unitName}`); }
        catch (error) { unresolved.push(`unit:${unitName}:${error instanceof Error ? error.message : 'unknown error'}`); }
      }
      for (const machineId of transaction.execution.allMachineIds as string[]) {
        try { actions.push({ type: 'machine-kill', machineId, result: await this.options.authority.killMachine(machineId) }); if (!await this.options.authority.verifyMachineAbsent(machineId)) unresolved.push(`machine:${machineId}`); }
        catch (error) { unresolved.push(`machine:${machineId}:${error instanceof Error ? error.message : 'unknown error'}`); }
      }
      this.options.transactions.reconcileTransition(transaction.transactionId, unresolved.length === 0 ? 'CANCEL_REQUESTED' : 'RECOVERY_REQUIRED', unresolved.length === 0 ? 'emergency_kill' : 'emergency_kill_incomplete', { scope: requestedScope, selector, unresolved, actions }, `kill:${principal.principalId}`);
    }
    return { scope: requestedScope, selector, frozen: true, transactionCount: transactions.length, actions, unresolved, complete: unresolved.length === 0 };
  }

  private async reconcileTransaction(transaction: RootEffectTransaction): Promise<JsonObject> {
    const observations: JsonObject = { units: [], machines: [], jobs: [] };
    const actions: JsonObject[] = [];
    let mismatch = false; let active = false; let missing = false; let terminal = true;
    for (const unitName of transaction.execution.unitNames as string[]) {
      const expected = (transaction.execution.processIdentities as JsonObject[]).find((identity) => identity.unitName === unitName) ?? { unitName };
      const readback = await this.options.authority.inspectUnit(unitName, expected);
      (observations.units as JsonObject[]).push({ unitName, readback });
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
    if (mismatch) { classification = 'AMBIGUOUS'; nextState = 'AMBIGUOUS'; }
    else if (Date.parse(transaction.lifecycle.deadline) <= Date.parse(this.now()) && ['REQUESTED', 'AUTHORIZING', 'PREPARING', 'READY'].includes(transaction.lifecycle.persistedState)) { classification = 'EXPIRED'; nextState = 'EXPIRED'; }
    else if (transaction.lifecycle.persistedState === 'EXECUTING') {
      if (active) classification = 'RESUMED';
      else if (terminal && !missing && transaction.execution.allJobIds.length > 0) { classification = 'RECOVERED'; nextState = 'VALIDATING'; }
      else { classification = 'RECOVERY_REQUIRED'; nextState = 'RECOVERY_REQUIRED'; }
    } else if (transaction.lifecycle.persistedState === 'VALIDATING' || transaction.lifecycle.persistedState === 'COMMITTING') {
      if (transaction.validation.result === 'SUCCEEDED' && transaction.execution.terminal === true) { classification = 'RECOVERED'; nextState = 'COMMITTING'; }
      else if (transaction.validation.result === 'FAILED') { classification = 'FAILED'; nextState = 'FAILED'; }
      else { classification = 'RECOVERY_REQUIRED'; nextState = 'RECOVERY_REQUIRED'; }
    } else if (transaction.lifecycle.persistedState === 'ROLLBACK_REQUESTED' || transaction.lifecycle.persistedState === 'ROLLING_BACK') {
      classification = transaction.rollback.result === 'SUCCEEDED' ? 'ROLLED_BACK' : 'RECOVERY_REQUIRED'; nextState = transaction.rollback.result === 'SUCCEEDED' ? 'ROLLED_BACK' : 'RECOVERY_REQUIRED';
    } else if (transaction.lifecycle.persistedState === 'COMPENSATING') {
      classification = transaction.compensation.result === 'SUCCEEDED' ? 'COMPENSATED' : 'RECOVERY_REQUIRED'; nextState = transaction.compensation.result === 'SUCCEEDED' ? 'COMPENSATED' : 'RECOVERY_REQUIRED';
    } else if (transaction.lifecycle.persistedState === 'CLEANING') {
      classification = transaction.cleanup.completed === true ? 'CLEANED' : 'RECOVERY_REQUIRED'; nextState = transaction.cleanup.completed === true ? 'FAILED' : 'RECOVERY_REQUIRED';
    }
    const updated = nextState === transaction.lifecycle.persistedState && classification === 'RESUMED' ? transaction : this.options.transactions.reconcileTransition(transaction.transactionId, nextState, classification.toLowerCase(), observations, 'root-reconciler');
    const record = seal<ReconciliationRecord>({ schemaVersion: ROOT_RECOVERY_SCHEMA_VERSION, reconciliationId: `rec_${randomUUID().replaceAll('-', '')}`, transactionId: transaction.transactionId, priorState: transaction.lifecycle.persistedState, nextState: updated.lifecycle.persistedState, classification, observations, actions, occurredAt: this.now() });
    this.records.put(record.reconciliationId, record);
    return record;
  }
}
