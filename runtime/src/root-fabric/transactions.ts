import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../storage/record-store.ts';
import {
  ROOT_FABRIC_PROVIDER_VERSION, ROOT_FABRIC_SCHEMA_VERSION, ROOT_EFFECT_STATES,
  RootFabricError, assertTransaction, contextPrincipal, digest, gitIdentity, idempotency, identifier, integer,
  object, sealTransaction, strictObject, stringArray, text, timestamp, verifyTransaction,
  type RootAtomicityMode, type RootEffectClass, type RootEffectState, type RootEffectTransaction,
  type RootExecutionProvider, type RootFabricEvent, type RootPlanStep, type RootSkillBinding,
} from './model.ts';

const TERMINAL = new Set<RootEffectState>(['COMMITTED', 'ROLLED_BACK', 'COMPENSATED', 'FAILED', 'AMBIGUOUS', 'EXPIRED']);
const EFFECT_CLASSES = new Set<RootEffectClass>(['REVERSIBLE', 'COMPENSATABLE', 'IRREVERSIBLE']);
const ATOMICITY = new Set<RootAtomicityMode>(['ATOMIC_WITHIN_PROVIDER', 'SAGA', 'IRREVERSIBLE']);
const PROVIDERS = new Set<RootExecutionProvider>(['HOST_ENVELOPE', 'DISPOSABLE_MACHINE']);
const RESTART = new Set(['READ_ONLY_RETRY', 'IDEMPOTENT_RETRY', 'READBACK_BEFORE_RETRY', 'ROLLBACK_BEFORE_RETRY', 'NEVER_AUTOMATICALLY_RETRY']);

const RECOVERY_TRANSITIONS: Readonly<Record<RootEffectState, readonly RootEffectState[]>> = Object.freeze({
  REQUESTED: ['EXPIRED', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCEL_REQUESTED'],
  AUTHORIZING: ['EXPIRED', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCEL_REQUESTED'],
  PREPARING: ['EXPIRED', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCEL_REQUESTED'],
  READY: ['EXPIRED', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCEL_REQUESTED'],
  EXECUTING: ['VALIDATING', 'CANCEL_REQUESTED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  VALIDATING: ['COMMITTING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  COMMITTING: ['RECOVERY_REQUIRED', 'AMBIGUOUS'],
  COMMITTED: [],
  CANCEL_REQUESTED: ['ROLLBACK_REQUESTED', 'CLEANING', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  ROLLBACK_REQUESTED: ['ROLLING_BACK', 'ROLLED_BACK', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  ROLLING_BACK: ['ROLLED_BACK', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  ROLLED_BACK: [],
  COMPENSATING: ['COMPENSATED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  COMPENSATED: [],
  CLEANING: ['FAILED', 'ROLLED_BACK', 'COMPENSATED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  FAILED: [],
  RECOVERY_REQUIRED: ['ROLLBACK_REQUESTED', 'CLEANING', 'FAILED', 'AMBIGUOUS'],
  AMBIGUOUS: ['RECOVERY_REQUIRED', 'ROLLBACK_REQUESTED', 'CLEANING', 'FAILED'],
  EXPIRED: [],
});

function requestDigest(operation: string, principalDigest: string, payload: JsonObject): string {
  return sha256(canonicalize({ operation, principalDigest, payload }));
}

function normalizeSkill(value: unknown): RootSkillBinding {
  const skill = strictObject(value, 'skill', ['skillId', 'skillVersion', 'bundleDigest', 'manifestDigest', 'signerKeyId', 'signerIdentity', 'signatureVerified', 'revocationStateDigest', 'capabilityGrantId', 'capabilityGrantDigest']);
  if (skill.signatureVerified !== true) throw new RootFabricError('bundle_signature_invalid', 'Skill bundle must be verified before transaction creation');
  return {
    skillId: identifier(skill.skillId, 'skill.skillId'),
    skillVersion: text(skill.skillVersion, 'skill.skillVersion', 128),
    bundleDigest: digest(skill.bundleDigest, 'skill.bundleDigest'),
    manifestDigest: digest(skill.manifestDigest, 'skill.manifestDigest'),
    signerKeyId: identifier(skill.signerKeyId, 'skill.signerKeyId'),
    signerIdentity: identifier(skill.signerIdentity, 'skill.signerIdentity'),
    signatureVerified: true,
    revocationStateDigest: digest(skill.revocationStateDigest, 'skill.revocationStateDigest'),
    capabilityGrantId: identifier(skill.capabilityGrantId, 'skill.capabilityGrantId'),
    capabilityGrantDigest: digest(skill.capabilityGrantDigest, 'skill.capabilityGrantDigest'),
  };
}

function normalizeStep(value: unknown, index: number): RootPlanStep {
  const step = strictObject(value, `plan.steps[${index}]`, ['stepId', 'sequence', 'operation', 'operationVersion', 'input', 'inputDigest', 'resourceSelectors', 'effectClass', 'timeoutMs', 'dependencies', 'preconditions', 'preparationRequirements', 'expectedObservations', 'validation', 'rollbackOperation', 'compensationOperation', 'providerRequirements', 'credentialReferences', 'restartBehavior']);
  const effectClass = text(step.effectClass, `plan.steps[${index}].effectClass`, 32) as RootEffectClass;
  if (!EFFECT_CLASSES.has(effectClass)) throw new RootFabricError('invalid_request', `plan.steps[${index}].effectClass is invalid`);
  const restartBehavior = text(step.restartBehavior, `plan.steps[${index}].restartBehavior`, 64);
  if (!RESTART.has(restartBehavior)) throw new RootFabricError('invalid_request', `plan.steps[${index}].restartBehavior is invalid`);
  if (!Array.isArray(step.providerRequirements) || step.providerRequirements.length < 1 || step.providerRequirements.length > 2) throw new RootFabricError('invalid_request', `plan.steps[${index}].providerRequirements must be non-empty and bounded`);
  const providerRequirements = step.providerRequirements.map((provider, providerIndex) => {
    const normalized = text(provider, `plan.steps[${index}].providerRequirements[${providerIndex}]`, 32) as RootExecutionProvider;
    if (!PROVIDERS.has(normalized)) throw new RootFabricError('unsupported_provider', `unsupported execution provider ${normalized}`);
    return normalized;
  });
  if (new Set(providerRequirements).size !== providerRequirements.length) throw new RootFabricError('invalid_request', `plan.steps[${index}].providerRequirements contains duplicates`);
  const input = object(step.input, `plan.steps[${index}].input`);
  const inputDigest = digest(step.inputDigest, `plan.steps[${index}].inputDigest`);
  if (inputDigest !== sha256(canonicalize(input))) throw new RootFabricError('expected_digest_mismatch', `plan.steps[${index}].inputDigest does not match input`);
  const sequence = integer(step.sequence, `plan.steps[${index}].sequence`, 1, 32);
  if (sequence !== index + 1) throw new RootFabricError('invalid_request', 'plan step sequence must be contiguous and ordered');
  for (const field of ['preconditions', 'preparationRequirements', 'expectedObservations'] as const) {
    if (!Array.isArray(step[field]) || step[field].length > 64 || step[field].some((entry) => entry === null || typeof entry !== 'object' || Array.isArray(entry))) throw new RootFabricError('invalid_request', `plan.steps[${index}].${field} must be a bounded object array`);
  }
  return {
    stepId: identifier(step.stepId, `plan.steps[${index}].stepId`), sequence,
    operation: identifier(step.operation, `plan.steps[${index}].operation`),
    operationVersion: text(step.operationVersion, `plan.steps[${index}].operationVersion`, 64),
    input, inputDigest,
    resourceSelectors: object(step.resourceSelectors, `plan.steps[${index}].resourceSelectors`), effectClass,
    timeoutMs: integer(step.timeoutMs, `plan.steps[${index}].timeoutMs`, 1, 3_600_000),
    dependencies: stringArray(step.dependencies, `plan.steps[${index}].dependencies`, 32),
    preconditions: step.preconditions as JsonObject[], preparationRequirements: step.preparationRequirements as JsonObject[],
    expectedObservations: step.expectedObservations as JsonObject[], validation: object(step.validation, `plan.steps[${index}].validation`),
    rollbackOperation: step.rollbackOperation === null ? null : identifier(step.rollbackOperation, `plan.steps[${index}].rollbackOperation`),
    compensationOperation: step.compensationOperation === null ? null : identifier(step.compensationOperation, `plan.steps[${index}].compensationOperation`),
    providerRequirements, credentialReferences: stringArray(step.credentialReferences, `plan.steps[${index}].credentialReferences`, 64),
    restartBehavior: restartBehavior as RootPlanStep['restartBehavior'],
  };
}

function normalizePlan(value: unknown): RootEffectTransaction['plan'] {
  const plan = strictObject(value, 'plan', ['atomicityMode', 'planDigest', 'steps']);
  const atomicityMode = text(plan.atomicityMode, 'plan.atomicityMode', 32) as RootAtomicityMode;
  if (!ATOMICITY.has(atomicityMode)) throw new RootFabricError('invalid_request', 'plan.atomicityMode is invalid');
  if (!Array.isArray(plan.steps) || plan.steps.length < 1 || plan.steps.length > 32) throw new RootFabricError('invalid_request', 'plan.steps must contain between 1 and 32 entries');
  const steps = plan.steps.map(normalizeStep);
  const ids = steps.map((step) => step.stepId);
  if (new Set(ids).size !== ids.length) throw new RootFabricError('invalid_request', 'plan step IDs must be unique');
  for (const step of steps) if (step.dependencies.some((dependency) => !ids.includes(dependency) || steps.findIndex((candidate) => candidate.stepId === dependency) >= step.sequence - 1)) throw new RootFabricError('invalid_request', `step ${step.stepId} has an unknown or forward dependency`);
  if (atomicityMode === 'IRREVERSIBLE' && steps.some((step) => step.effectClass !== 'IRREVERSIBLE')) throw new RootFabricError('invalid_request', 'IRREVERSIBLE atomicity requires every step to be irreversible');
  if (atomicityMode !== 'IRREVERSIBLE' && steps.some((step) => step.effectClass === 'IRREVERSIBLE')) throw new RootFabricError('policy_denied', 'irreversible steps require IRREVERSIBLE atomicity mode');
  const computed = sha256(canonicalize({ atomicityMode, steps }));
  if (digest(plan.planDigest, 'plan.planDigest') !== computed) throw new RootFabricError('expected_digest_mismatch', 'plan.planDigest does not match the canonical plan');
  return { atomicityMode, planDigest: computed, steps };
}

function appendEvent(current: RootEffectTransaction | null, operation: string, phase: string, nextState: RootEffectState, request: string, idempotencyDigest: string, occurredAt: string, patch: JsonObject, references: JsonObject = {}, observationDigest: string | null = null): RootEffectTransaction {
  const sequence = (current?.lifecycle.sequence ?? 0) + 1;
  const transactionId = current?.transactionId ?? identifier(patch.transactionId, 'transactionId');
  const ownerPrincipal = current?.ownerPrincipal ?? object(patch.ownerPrincipal, 'ownerPrincipal') as RootEffectTransaction['ownerPrincipal'];
  const skill = current?.skill ?? object(patch.skill, 'skill') as RootSkillBinding;
  const eventBase = {
    schemaVersion: ROOT_FABRIC_SCHEMA_VERSION, eventId: `rte_${sha256(`${transactionId}:${sequence}:${request}`).slice(0, 32)}`,
    transactionId, sequence, stateGeneration: sequence, ownerPrincipalDigest: ownerPrincipal.principalDigest,
    skillBundleDigest: skill.bundleDigest, operation, phase, priorState: current?.lifecycle.persistedState ?? null, nextState,
    requestDigest: request, idempotencyKeyDigest: idempotencyDigest, occurredAt,
    fencingToken: current?.lease.fencingToken ?? 0, provider: current?.routing.executionProvider ?? null,
    references, observationDigest, previousEventDigest: current?.eventHeadDigest ?? null,
  };
  const event: RootFabricEvent = { ...eventBase, eventDigest: sha256(canonicalize(eventBase)) };
  const base = current === null ? patch : { ...current, ...patch };
  const lifecycle = {
    ...(current?.lifecycle ?? object(patch.lifecycle, 'lifecycle')),
    persistedState: nextState, desiredState: nextState, sequence, terminal: TERMINAL.has(nextState), updatedAt: occurredAt,
  } as RootEffectTransaction['lifecycle'];
  const { recordDigest: _oldDigest, ...unsigned } = base as RootEffectTransaction;
  return sealTransaction({ ...unsigned, lifecycle, events: [...(current?.events ?? []), event], eventHeadDigest: event.eventDigest } as Omit<RootEffectTransaction, 'recordDigest'>);
}

export class RootEffectTransactionService {
  private readonly records: DurableRecordStore<RootEffectTransaction>;
  private readonly claims: DurableClaimStore<RootEffectTransaction>;
  private readonly now: () => string;

  constructor(readonly stateRoot: string, options: { now?: () => string } = {}) {
    const root = join(stateRoot, 'root-fabric', 'transactions');
    this.records = new DurableRecordStore(join(root, 'authoritative'));
    this.claims = new DurableClaimStore(join(root, 'idempotency'));
    this.now = options.now ?? (() => new Date().toISOString());
  }

  create(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'root effect create payload', ['source', 'skill', 'deadline', 'atomicityMode', 'plan', 'policy', 'requestedProvider', 'riskClass', 'environmentDigest']);
    const occurredAt = this.now();
    const ownerPrincipal = contextPrincipal(context, occurredAt);
    const idem = idempotency(context);
    const source = strictObject(payload.source, 'source', ['repository', 'branch', 'commit', 'tree']);
    const normalizedSource = { repository: text(source.repository, 'source.repository', 2_048), branch: text(source.branch, 'source.branch', 256), commit: gitIdentity(source.commit, 'source.commit'), tree: gitIdentity(source.tree, 'source.tree') };
    const skill = normalizeSkill(payload.skill);
    const deadline = timestamp(payload.deadline, 'deadline');
    if (Date.parse(deadline) <= Date.parse(occurredAt)) throw new RootFabricError('deadline_exceeded', 'transaction deadline must be in the future');
    const plan = normalizePlan(payload.plan);
    if (payload.atomicityMode !== plan.atomicityMode) throw new RootFabricError('invalid_request', 'atomicityMode must match plan.atomicityMode');
    const requestedProvider = payload.requestedProvider === null || payload.requestedProvider === undefined ? null : text(payload.requestedProvider, 'requestedProvider', 32) as RootExecutionProvider;
    if (requestedProvider !== null && !PROVIDERS.has(requestedProvider)) throw new RootFabricError('unsupported_provider', 'requestedProvider is unsupported');
    const policy = object(payload.policy, 'policy');
    const environmentDigest = digest(payload.environmentDigest, 'environmentDigest');
    const normalized = { source: normalizedSource, skill, deadline, atomicityMode: plan.atomicityMode, plan, policy, requestedProvider, riskClass: identifier(payload.riskClass, 'riskClass'), environmentDigest };
    const request = requestDigest('babyx.root.effect.create', ownerPrincipal.principalDigest, normalized);
    const claimKey = `create:${ownerPrincipal.principalDigest}:${idem.digest}`;
    const existing = this.claims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another root effect request');
      if (!this.records.has(existing.recordId)) this.records.create(existing.recordId, existing.record);
      const replay = this.records.get(existing.recordId); assertTransaction(replay); return { transaction: replay, replayed: true };
    }
    const transactionId = `rfx_${randomUUID().replaceAll('-', '')}`;
    const candidate = appendEvent(null, 'babyx.root.effect.create', 'request', 'REQUESTED', request, idem.digest, occurredAt, {
      schemaVersion: ROOT_FABRIC_SCHEMA_VERSION, providerVersion: ROOT_FABRIC_PROVIDER_VERSION, transactionId, transactionKind: 'ROOT_EFFECT', ownerPrincipal, skill,
      request: { source: normalizedSource, creationRequestDigest: request, idempotencyKeyDigest: idem.digest, submittedAt: occurredAt, deadline, atomicityMode: plan.atomicityMode, canonicalPlanDigest: plan.planDigest, environmentDigest, requestedProvider, riskClass: normalized.riskClass },
      lifecycle: { persistedState: 'REQUESTED', desiredState: 'REQUESTED', sequence: 0, terminal: false, createdAt: occurredAt, updatedAt: occurredAt, deadline },
      lease: { controllerId: null, leaseOwner: null, fencingToken: 0, acquiredAt: null, renewedAt: null, expiresAt: null, predecessorLease: null, takeoverReason: null },
      policy, routing: { projectPath: 'DIRECT_BUILD', executionProvider: null, providerId: null, providerVersion: null, providerContractVersion: null, providerProfileDigest: null }, plan,
      preparation: { complete: false, priorStateDigest: null, artifactIds: [], snapshotReferences: [], rollbackReady: false, compensationReady: false, startedAt: null, completedAt: null, error: null },
      execution: { activeJobIds: [], allJobIds: [], activeMachineIds: [], allMachineIds: [], unitNames: [], processIdentities: [], providerAttempts: [], terminal: false },
      observations: { completeness: 'UNAVAILABLE', sessionIds: [], summaryDigest: null, droppedEvents: 0 },
      validation: { specification: {}, validatorVersion: null, expectedState: null, observedState: null, attempts: 0, result: null, resultDigest: null, validatedAt: null, failureReason: null },
      rollback: { requested: false, reason: null, steps: [], jobs: [], result: null, restoredStateDigest: null, unresolvedEffects: [], completedAt: null },
      compensation: { requested: false, reason: null, steps: [], jobs: [], result: null, residualDifferences: [], completedAt: null },
      credentials: { leaseIds: [], allTerminal: true, cleaned: true }, cleanup: { required: true, requested: false, completed: false, unitRemoved: false, cgroupEmpty: false, processAbsent: false, machineAbsent: false, mountAbsent: false, temporaryPathAbsent: false, credentialPathAbsent: false, observerStopped: false, sourcePreserved: true, completedAt: null, result: null },
      evidence: { artifactIds: [], receiptIds: [], proofIds: [], eventTailDigest: null, catalogDigest: null, compatibilityDigest: null, finalResultDigest: null }, error: null,
      events: [], eventHeadDigest: '',
    });
    const claim = this.claims.claim(claimKey, request, transactionId, candidate);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another root effect request');
    if (!this.records.has(claim.recordId) && !this.records.create(claim.recordId, claim.record)) throw new RootFabricError('internal_error', 'transaction record could not be created');
    const record = this.records.get(claim.recordId); assertTransaction(record); return { transaction: record, replayed: claim.recordId !== transactionId };
  }

  get(payloadValue: unknown): JsonObject {
    const payload = strictObject(payloadValue, 'root effect get payload', ['transactionId']);
    const record = this.read(identifier(payload.transactionId, 'transactionId'));
    return { transaction: record, integrity: verifyTransaction(record) };
  }

  list(payloadValue: unknown): JsonObject {
    const payload = strictObject(payloadValue ?? {}, 'root effect list payload', ['state', 'ownerPrincipal', 'offset', 'limit']);
    const state = payload.state === undefined ? undefined : text(payload.state, 'state', 32) as RootEffectState;
    if (state !== undefined && !ROOT_EFFECT_STATES.includes(state)) throw new RootFabricError('invalid_request', 'state is invalid');
    const ownerPrincipal = payload.ownerPrincipal === undefined ? undefined : identifier(payload.ownerPrincipal, 'ownerPrincipal');
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, 10_000_000);
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, 200);
    const scan = this.records.scan((record) => (state === undefined || record.lifecycle.persistedState === state) && (ownerPrincipal === undefined || record.ownerPrincipal.principalId === ownerPrincipal), offset, limit);
    const invalidRecordIds: string[] = [];
    const transactions = scan.records.flatMap((record) => { const integrity = verifyTransaction(record); if (!integrity.valid) { invalidRecordIds.push(record.transactionId); return []; } return [{ transactionId: record.transactionId, ownerPrincipal: record.ownerPrincipal.principalId, state: record.lifecycle.persistedState, sequence: record.lifecycle.sequence, updatedAt: record.lifecycle.updatedAt, planDigest: record.plan.planDigest, recordDigest: record.recordDigest }]; });
    return { transactions, offset, limit, total: scan.total, nextOffset: scan.nextOffset, corruptRecordIds: scan.corruptRecordIds, invalidRecordIds };
  }

  events(payloadValue: unknown): JsonObject {
    const payload = strictObject(payloadValue, 'root effect events payload', ['transactionId', 'offset', 'limit']);
    const record = this.read(identifier(payload.transactionId, 'transactionId'));
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, 10_000_000);
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, 200);
    const events = record.events.slice(offset, offset + limit);
    return { events, offset, limit, total: record.events.length, nextOffset: offset + events.length < record.events.length ? offset + events.length : null, integrity: verifyTransaction(record) };
  }

  acquireLease(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'lease acquire payload', ['transactionId', 'expectedSequence', 'controllerId', 'ttlMs', 'takeoverReason']);
    return this.mutate('babyx.root.effect.lease.acquire', payload, context, (record, occurredAt, request, idemDigest) => {
      if (record.lifecycle.terminal) throw new RootFabricError('transaction_state_conflict', 'terminal transaction cannot acquire a lease');
      const expectedSequence = integer(payload.expectedSequence, 'expectedSequence', 1, 10_000_000);
      if (record.lifecycle.sequence !== expectedSequence) throw new RootFabricError('transaction_state_conflict', 'expected sequence mismatch');
      const controllerId = identifier(payload.controllerId, 'controllerId');
      const ttlMs = integer(payload.ttlMs, 'ttlMs', 1_000, 300_000);
      const expired = record.lease.expiresAt === null || Date.parse(record.lease.expiresAt) <= Date.parse(occurredAt);
      if (!expired && record.lease.controllerId !== controllerId) throw new RootFabricError('lease_conflict', 'transaction lease is held by another controller');
      const nextLease = { controllerId, leaseOwner: record.ownerPrincipal.principalId, fencingToken: record.lease.controllerId === controllerId && !expired ? record.lease.fencingToken : record.lease.fencingToken + 1, acquiredAt: expired ? occurredAt : record.lease.acquiredAt, renewedAt: occurredAt, expiresAt: new Date(Date.parse(occurredAt) + ttlMs).toISOString(), predecessorLease: expired ? record.lease.controllerId : record.lease.predecessorLease, takeoverReason: expired && record.lease.controllerId !== null ? text(payload.takeoverReason ?? 'expired lease takeover', 'takeoverReason', 512) : null };
      return appendEvent(record, 'babyx.root.effect.lease.acquire', 'lease', record.lifecycle.persistedState, request, idemDigest, occurredAt, { lease: nextLease }, { controllerId, fencingToken: nextLease.fencingToken });
    });
  }

  authorize(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    return this.transition('babyx.root.effect.authorize', payloadValue, context, ['REQUESTED'], 'AUTHORIZING', 'authorization', (record, payload, occurredAt) => ({
      policy: { ...record.policy, decisionDigest: digest(payload.decisionDigest, 'decisionDigest'), authorizedAt: occurredAt, expiresAt: timestamp(payload.expiresAt, 'expiresAt') },
      routing: { projectPath: 'DIRECT_BUILD', executionProvider: text(payload.executionProvider, 'executionProvider', 32) as RootExecutionProvider, providerId: identifier(payload.providerId, 'providerId'), providerVersion: text(payload.providerVersion, 'providerVersion', 64), providerContractVersion: text(payload.providerContractVersion, 'providerContractVersion', 64), providerProfileDigest: digest(payload.providerProfileDigest, 'providerProfileDigest') },
    }), ['transactionId', 'expectedSequence', 'fencingToken', 'decisionDigest', 'expiresAt', 'executionProvider', 'providerId', 'providerVersion', 'providerContractVersion', 'providerProfileDigest']);
  }

  prepare(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    return this.transition('babyx.root.effect.prepare', payloadValue, context, ['AUTHORIZING', 'PREPARING'], 'PREPARING', 'preparation', (record, payload, occurredAt) => {
      const rollbackReady = payload.rollbackReady === true;
      const compensationReady = payload.compensationReady === true;
      if (record.plan.atomicityMode === 'ATOMIC_WITHIN_PROVIDER' && !rollbackReady) throw new RootFabricError('preparation_failed', 'atomic transaction requires rollback preparation');
      if (record.plan.atomicityMode === 'SAGA' && !rollbackReady && !compensationReady) throw new RootFabricError('preparation_failed', 'SAGA requires rollback or compensation preparation');
      return { preparation: { complete: true, priorStateDigest: digest(payload.priorStateDigest, 'priorStateDigest'), artifactIds: stringArray(payload.artifactIds ?? [], 'artifactIds', 256), snapshotReferences: stringArray(payload.snapshotReferences ?? [], 'snapshotReferences', 64), rollbackReady, compensationReady, startedAt: record.preparation.startedAt ?? occurredAt, completedAt: occurredAt, error: null } };
    }, ['transactionId', 'expectedSequence', 'fencingToken', 'priorStateDigest', 'artifactIds', 'snapshotReferences', 'rollbackReady', 'compensationReady'], 'READY');
  }

  begin(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    return this.transition('babyx.root.effect.begin', payloadValue, context, ['READY'], 'EXECUTING', 'execution', (record, payload) => ({
      execution: { ...record.execution, activeJobIds: stringArray(payload.activeJobIds ?? [], 'activeJobIds', 256), allJobIds: stringArray(payload.allJobIds ?? payload.activeJobIds ?? [], 'allJobIds', 1024), activeMachineIds: stringArray(payload.activeMachineIds ?? [], 'activeMachineIds', 64), allMachineIds: stringArray(payload.allMachineIds ?? payload.activeMachineIds ?? [], 'allMachineIds', 256), unitNames: stringArray(payload.unitNames ?? [], 'unitNames', 128), processIdentities: Array.isArray(payload.processIdentities) ? payload.processIdentities : [], providerAttempts: Array.isArray(payload.providerAttempts) ? payload.providerAttempts : [], terminal: false },
    }), ['transactionId', 'expectedSequence', 'fencingToken', 'activeJobIds', 'allJobIds', 'activeMachineIds', 'allMachineIds', 'unitNames', 'processIdentities', 'providerAttempts']);
  }

  validate(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'babyx.root.effect.validate payload', ['transactionId', 'expectedSequence', 'fencingToken', 'specification', 'validatorVersion', 'expectedState', 'observedState', 'attempts', 'result', 'resultDigest', 'failureReason', 'executionTerminal']);
    return this.mutate('babyx.root.effect.validate', payload, context, (record, occurredAt, request, idemDigest) => {
      if (!['EXECUTING', 'VALIDATING'].includes(record.lifecycle.persistedState)) throw new RootFabricError('transaction_state_conflict', `state ${record.lifecycle.persistedState} does not permit validation`);
      this.assertLease(record, payload, occurredAt);
      const result = text(payload.result, 'result', 32);
      if (!['SUCCEEDED', 'FAILED', 'AMBIGUOUS'].includes(result)) throw new RootFabricError('invalid_request', 'validation result is invalid');
      const patch = { execution: { ...record.execution, activeJobIds: [], activeMachineIds: [], terminal: payload.executionTerminal === true }, validation: { specification: object(payload.specification, 'specification'), validatorVersion: text(payload.validatorVersion, 'validatorVersion', 64), expectedState: payload.expectedState ?? null, observedState: payload.observedState ?? null, attempts: integer(payload.attempts, 'attempts', 1, 1_000), result, resultDigest: digest(payload.resultDigest, 'resultDigest'), validatedAt: occurredAt, failureReason: payload.failureReason === null || payload.failureReason === undefined ? null : text(payload.failureReason, 'failureReason', 2_048) } };
      const validating = record.lifecycle.persistedState === 'VALIDATING' ? record : appendEvent(record, 'babyx.root.effect.validate', 'validation', 'VALIDATING', request, idemDigest, occurredAt, patch);
      const terminalState: RootEffectState = result === 'SUCCEEDED' ? 'COMMITTING' : result === 'FAILED' ? 'FAILED' : 'AMBIGUOUS';
      return appendEvent(validating, 'babyx.root.effect.validate', 'validation-complete', terminalState, request, idemDigest, occurredAt, record.lifecycle.persistedState === 'VALIDATING' ? patch : {});
    });
  }

  commit(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    return this.transition('babyx.root.effect.commit', payloadValue, context, ['COMMITTING'], 'COMMITTED', 'commit', (record, payload, occurredAt) => {
      if (record.validation.result !== 'SUCCEEDED') throw new RootFabricError('validation_failed', 'commit requires successful validation');
      if (record.execution.terminal !== true || (record.execution.activeJobIds as unknown[]).length > 0 || (record.execution.activeMachineIds as unknown[]).length > 0) throw new RootFabricError('transaction_state_conflict', 'commit requires all related execution terminal');
      if (record.credentials.allTerminal !== true || record.credentials.cleaned !== true) throw new RootFabricError('credential_delivery_failed', 'commit requires terminal cleaned credentials');
      if (payload.cleanupComplete !== true) throw new RootFabricError('cleanup_failed', 'commit requires cleanup proof');
      const finalResultDigest = digest(payload.finalResultDigest, 'finalResultDigest');
      return { cleanup: { ...record.cleanup, completed: true, result: 'SUCCEEDED', completedAt: occurredAt }, evidence: { ...record.evidence, eventTailDigest: record.eventHeadDigest, finalResultDigest } };
    }, ['transactionId', 'expectedSequence', 'fencingToken', 'cleanupComplete', 'finalResultDigest']);
  }

  cancel(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    return this.transition('babyx.root.effect.cancel', payloadValue, context, ['REQUESTED', 'AUTHORIZING', 'PREPARING', 'READY', 'EXECUTING', 'VALIDATING'], 'CANCEL_REQUESTED', 'cancel', (_record, payload) => ({ error: { code: 'cancel_requested', message: text(payload.reason, 'reason', 1_024), retryable: false, phase: 'cancel', redactedDetails: {} } }), ['transactionId', 'expectedSequence', 'fencingToken', 'reason']);
  }

  rollback(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'rollback payload', ['transactionId', 'expectedSequence', 'fencingToken', 'phase', 'reason', 'restoredStateDigest', 'result', 'unresolvedEffects']);
    const phase = text(payload.phase, 'phase', 32);
    if (phase === 'request') return this.transition('babyx.root.effect.rollback', payload, context, ['REQUESTED', 'AUTHORIZING', 'PREPARING', 'READY', 'EXECUTING', 'VALIDATING', 'COMMITTING', 'COMMITTED', 'FAILED', 'AMBIGUOUS', 'CANCEL_REQUESTED'], 'ROLLBACK_REQUESTED', 'rollback-request', (record) => ({ rollback: { ...record.rollback, requested: true, reason: text(payload.reason, 'reason', 1_024), requestedAt: this.now() } }), Object.keys(payload));
    if (phase === 'begin') return this.transition('babyx.root.effect.rollback', payload, context, ['ROLLBACK_REQUESTED'], 'ROLLING_BACK', 'rollback', (record) => ({ rollback: { ...record.rollback, result: 'RUNNING' } }), Object.keys(payload));
    if (phase === 'complete') return this.transition('babyx.root.effect.rollback', payload, context, ['ROLLING_BACK'], payload.result === 'SUCCEEDED' ? 'ROLLED_BACK' : 'RECOVERY_REQUIRED', 'rollback', (record, inner, occurredAt) => ({ rollback: { ...record.rollback, result: text(inner.result, 'result', 32), restoredStateDigest: inner.restoredStateDigest === null ? null : digest(inner.restoredStateDigest, 'restoredStateDigest'), unresolvedEffects: stringArray(inner.unresolvedEffects ?? [], 'unresolvedEffects', 256), completedAt: occurredAt } }), Object.keys(payload));
    throw new RootFabricError('invalid_request', 'rollback phase must be request, begin, or complete');
  }

  compensate(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'compensate payload', ['transactionId', 'expectedSequence', 'fencingToken', 'phase', 'reason', 'result', 'residualDifferences']);
    const phase = text(payload.phase, 'phase', 32);
    if (phase === 'begin') return this.transition('babyx.root.effect.compensate', payload, context, ['FAILED', 'AMBIGUOUS', 'CANCEL_REQUESTED'], 'COMPENSATING', 'compensation', (record) => ({ compensation: { ...record.compensation, requested: true, reason: text(payload.reason, 'reason', 1_024), result: 'RUNNING' } }), Object.keys(payload));
    if (phase === 'complete') return this.transition('babyx.root.effect.compensate', payload, context, ['COMPENSATING'], payload.result === 'SUCCEEDED' ? 'COMPENSATED' : 'RECOVERY_REQUIRED', 'compensation', (record, inner, occurredAt) => ({ compensation: { ...record.compensation, result: text(inner.result, 'result', 32), residualDifferences: stringArray(inner.residualDifferences ?? [], 'residualDifferences', 256), completedAt: occurredAt } }), Object.keys(payload));
    throw new RootFabricError('invalid_request', 'compensate phase must be begin or complete');
  }

  clean(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'babyx.root.effect.clean payload', ['transactionId', 'expectedSequence', 'fencingToken', 'completed', 'terminalState', 'unitRemoved', 'cgroupEmpty', 'processAbsent', 'machineAbsent', 'mountAbsent', 'temporaryPathAbsent', 'credentialPathAbsent', 'observerStopped', 'sourcePreserved']);
    return this.mutate('babyx.root.effect.clean', payload, context, (record, occurredAt, request, idemDigest) => {
      if (!['CANCEL_REQUESTED', 'ROLLED_BACK', 'COMPENSATED', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CLEANING'].includes(record.lifecycle.persistedState)) throw new RootFabricError('transaction_state_conflict', `state ${record.lifecycle.persistedState} does not permit cleanup`);
      this.assertLease(record, payload, occurredAt);
      const completed = payload.completed === true;
      const cleanup = { ...record.cleanup, requested: true, completed, unitRemoved: payload.unitRemoved === true, cgroupEmpty: payload.cgroupEmpty === true, processAbsent: payload.processAbsent === true, machineAbsent: payload.machineAbsent === true, mountAbsent: payload.mountAbsent === true, temporaryPathAbsent: payload.temporaryPathAbsent === true, credentialPathAbsent: payload.credentialPathAbsent === true, observerStopped: payload.observerStopped === true, sourcePreserved: payload.sourcePreserved === true, completedAt: completed ? occurredAt : null, result: completed ? 'SUCCEEDED' : 'RUNNING' };
      const cleaning = record.lifecycle.persistedState === 'CLEANING' ? record : appendEvent(record, 'babyx.root.effect.clean', 'cleanup', 'CLEANING', request, idemDigest, occurredAt, { cleanup });
      if (!completed) return record.lifecycle.persistedState === 'CLEANING' ? appendEvent(cleaning, 'babyx.root.effect.clean', 'cleanup-progress', 'CLEANING', request, idemDigest, occurredAt, { cleanup }) : cleaning;
      const terminalState = text(payload.terminalState, 'terminalState', 32) as RootEffectState;
      if (!['FAILED', 'ROLLED_BACK', 'COMPENSATED'].includes(terminalState)) throw new RootFabricError('invalid_request', 'cleanup terminalState must be FAILED, ROLLED_BACK, or COMPENSATED');
      return appendEvent(cleaning, 'babyx.root.effect.clean', 'cleanup-complete', terminalState, request, idemDigest, occurredAt, record.lifecycle.persistedState === 'CLEANING' ? { cleanup } : {});
    });
  }

  repair(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'babyx.root.effect.repair payload', ['transactionId', 'expectedSequence', 'fencingToken', 'nextState', 'reason']);
    const nextState = text(payload.nextState, 'nextState', 32) as RootEffectState;
    if (!['ROLLBACK_REQUESTED', 'CLEANING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'].includes(nextState)) throw new RootFabricError('invalid_request', 'administrative repair may not directly create a successful terminal state');
    return this.transition('babyx.root.effect.repair', payload, context, ['RECOVERY_REQUIRED', 'AMBIGUOUS', 'CLEANING'], nextState, 'repair', (record, inner, occurredAt) => ({ error: { code: 'administrative_repair', message: text(inner.reason, 'reason', 1_024), retryable: false, phase: 'repair', redactedDetails: { priorState: record.lifecycle.persistedState, repairedAt: occurredAt } } }), Object.keys(payload));
  }

  recoveryRecord(payloadValue: unknown, context: RuntimeExecutionContext): RootEffectTransaction {
    const payload = strictObject(payloadValue, 'root recovery control payload', ['transactionId', 'expectedSequence', 'fencingToken']);
    const transactionId = identifier(payload.transactionId, 'transactionId');
    const current = this.read(transactionId);
    const principal = contextPrincipal(context, this.now());
    if (principal.principalDigest !== current.ownerPrincipal.principalDigest) throw new RootFabricError('principal_mismatch', 'root recovery transaction principal mismatch');
    this.assertLease(current, payload, this.now());
    return current;
  }

  recoveryTransition(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'root recovery transition payload', ['transactionId', 'expectedSequence', 'fencingToken', 'nextState', 'classification', 'observations']);
    const nextState = text(payload.nextState, 'nextState', 32) as RootEffectState;
    if (!ROOT_EFFECT_STATES.includes(nextState)) throw new RootFabricError('invalid_request', 'recovery next state is invalid');
    const classification = text(payload.classification, 'classification', 64);
    const observations = object(payload.observations, 'observations');
    return this.mutate('babyx.root.reconcile.transition', payload, context, (record, occurredAt, request, idemDigest) => {
      if (record.lifecycle.terminal || TERMINAL.has(record.lifecycle.persistedState)) throw new RootFabricError('transaction_state_conflict', 'ordinary terminal transactions are immutable during recovery');
      if (nextState === record.lifecycle.persistedState) throw new RootFabricError('transaction_state_conflict', 'recovery may not append a no-op lifecycle transition');
      const allowed = RECOVERY_TRANSITIONS[record.lifecycle.persistedState];
      if (!allowed.includes(nextState)) throw new RootFabricError('transaction_state_conflict', `recovery transition ${record.lifecycle.persistedState} -> ${nextState} is not allowed`, { allowed });
      this.assertLease(record, payload, occurredAt);
      const adverse = ['FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'EXPIRED'].includes(nextState);
      const error = adverse ? { code: classification, message: classification, retryable: nextState === 'RECOVERY_REQUIRED', phase: 'reconciliation', redactedDetails: observations } : record.error;
      return appendEvent(record, 'babyx.root.reconcile.transition', 'reconciliation', nextState, request, idemDigest, occurredAt, { error }, { classification }, sha256(canonicalize(observations)));
    });
  }

  nonterminal(limit = 4096): RootEffectTransaction[] { return this.records.scan((record) => !record.lifecycle.terminal, 0, limit).records.filter((record) => { try { assertTransaction(record); return true; } catch { return false; } }); }
  record(transactionId: string): RootEffectTransaction { return this.read(identifier(transactionId, 'transactionId')); }

  private read(transactionId: string): RootEffectTransaction {
    try { const record = this.records.get(transactionId); assertTransaction(record); return record; }
    catch (error) { if (error instanceof RootFabricError) throw error; if (error instanceof Error && error.message === 'record not found') throw new RootFabricError('transaction_not_found', 'root effect transaction not found', { transactionId }); throw new RootFabricError('corrupt_record', 'root effect transaction could not be read', { transactionId }); }
  }

  private transition(operation: string, payloadValue: unknown, context: RuntimeExecutionContext, allowedStates: readonly RootEffectState[], nextState: RootEffectState, phase: string, patcher: (record: RootEffectTransaction, payload: JsonObject, occurredAt: string) => JsonObject, keys: readonly string[], finalState = nextState): JsonObject {
    const payload = strictObject(payloadValue, `${operation} payload`, keys);
    return this.mutate(operation, payload, context, (record, occurredAt, request, idemDigest) => {
      if (!allowedStates.includes(record.lifecycle.persistedState)) throw new RootFabricError('transaction_state_conflict', `state ${record.lifecycle.persistedState} does not permit ${operation}`, { allowedStates });
      this.assertLease(record, payload, occurredAt);
      const patch = patcher(record, payload, occurredAt);
      const intermediate = appendEvent(record, operation, phase, nextState, request, idemDigest, occurredAt, patch);
      if (finalState === nextState) return intermediate;
      return appendEvent(intermediate, operation, `${phase}-complete`, finalState, request, idemDigest, occurredAt, {}, {}, null);
    });
  }

  private assertLease(record: RootEffectTransaction, payload: JsonObject, occurredAt: string): void {
    const expectedSequence = integer(payload.expectedSequence, 'expectedSequence', 1, 10_000_000);
    if (record.lifecycle.sequence !== expectedSequence) throw new RootFabricError('transaction_state_conflict', 'expected sequence mismatch', { expected: expectedSequence, actual: record.lifecycle.sequence });
    const fencingToken = integer(payload.fencingToken, 'fencingToken', 1, Number.MAX_SAFE_INTEGER);
    if (record.lease.fencingToken !== fencingToken) throw new RootFabricError('fencing_token_stale', 'fencing token is stale', { expected: record.lease.fencingToken, actual: fencingToken });
    if (record.lease.expiresAt === null || Date.parse(record.lease.expiresAt) <= Date.parse(occurredAt)) throw new RootFabricError('lease_conflict', 'controller lease is absent or expired');
  }

  private mutate(operation: string, payload: JsonObject, context: RuntimeExecutionContext, mutator: (record: RootEffectTransaction, occurredAt: string, request: string, idemDigest: string) => RootEffectTransaction): JsonObject {
    const transactionId = identifier(payload.transactionId, 'transactionId');
    const current = this.read(transactionId);
    const principal = contextPrincipal(context, this.now());
    if (principal.principalDigest !== current.ownerPrincipal.principalDigest) throw new RootFabricError('principal_mismatch', 'root effect transaction principal mismatch');
    const idem = idempotency(context);
    const request = requestDigest(operation, principal.principalDigest, payload);
    const claimKey = `${transactionId}:${operation}:${idem.digest}`;
    const existing = this.claims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== request || existing.recordId !== transactionId) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another request');
      const live = this.read(transactionId);
      if (live.lifecycle.sequence < existing.record.lifecycle.sequence) this.records.put(transactionId, existing.record);
      return { transaction: this.read(transactionId), replayed: true };
    }
    const candidate = mutator(current, this.now(), request, idem.digest); assertTransaction(candidate);
    const claim = this.claims.claim(claimKey, request, transactionId, candidate);
    if (claim.requestDigest !== request || claim.recordId !== transactionId) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another request');
    const live = this.read(transactionId);
    if (live.lifecycle.sequence !== current.lifecycle.sequence) throw new RootFabricError('transaction_state_conflict', 'transaction changed before commit');
    this.records.put(transactionId, claim.record);
    return { transaction: this.read(transactionId), replayed: false };
  }
}
