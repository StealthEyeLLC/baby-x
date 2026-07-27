import { canonicalize, sha256, type JsonObject } from '../core.ts';
import { ReleaseApplianceStore, ReleaseStoreError, type ReleaseStartupReport } from './store.ts';
import {
  BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
  SERVICE_CREDENTIAL_BOOTSTRAP_SCHEMA_VERSION,
  ServiceCredentialContractError,
  assertServiceCredentialReadyFacts,
  assertServiceCredentialTransition,
  createServiceCredentialBootstrapPlan,
  describeServiceCredentialProfile,
  serviceCredentialCompatibilityDigest,
  serviceCredentialProfileDigest,
  type ServiceCredentialBootstrapPlanInput,
} from './service-credentials.ts';

const TRANSACTION_SCHEMA = 'ServiceCredentialBootstrapTransactionV1';
const PROFILE_STATE_SCHEMA = 'ServiceCredentialProfileStateV1';
const MAX_TRANSACTION_LIST = 200;
const MAX_EVENT_LIST = 1_000;

export interface ServiceCredentialBootstrapServiceOptions {
  store: ReleaseApplianceStore;
  now?: () => string;
  controllerIdentity: JsonObject;
  leaseTtlMs?: number;
}

export interface ServiceCredentialTransitionInput {
  transactionId: string;
  ownerPrincipal: string;
  expectedSequence: number;
  nextState: string;
  operation: string;
  phase: string;
  patch?: JsonObject;
  readyFacts?: JsonObject;
  observationDigest?: string;
  childJobIds?: string[];
  artifactReferences?: JsonObject[];
  receiptReferences?: string[];
}

export interface ServiceCredentialReconcileInput {
  transactionId: string;
  ownerPrincipal: string;
  expectedSequence: number;
  observation: 'NO_EXTERNAL_EFFECT' | 'EXTERNAL_EFFECT_ABSENT' | 'EXTERNAL_STATE_UNKNOWN' | 'EXTERNAL_EFFECT_OBSERVED';
  observationDigest: string;
}

function safeIdentifier(value: unknown, name: string): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$/u.test(value)) {
    throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', `${name} must be a bounded identifier`);
  }
  return value;
}

function safeDigest(value: unknown, name: string): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/u.test(value)) {
    throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', `${name} must be a lowercase sha256 digest`);
  }
  return value;
}

function safeSequence(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', `${name} must be a non-negative safe integer`);
  }
  return Number(value);
}

function object(value: unknown, name: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', `${name} must be an object`);
  }
  return structuredClone(value as JsonObject);
}

function terminal(state: unknown): boolean {
  return state === 'FAILED' || state === 'REVOKED';
}

function immutableTransactionFacts(record: JsonObject): JsonObject {
  return {
    transactionId: record.transactionId,
    ownerPrincipal: record.ownerPrincipal,
    idempotencyKey: record.idempotencyKey,
    creationRequestDigest: record.creationRequestDigest,
    profileId: record.profileId,
    profileDigest: record.profileDigest,
    compatibilityDigest: record.compatibilityDigest,
    planDigest: record.planDigest,
    generationId: record.generationId,
  };
}

export class ServiceCredentialBootstrapService {
  readonly store: ReleaseApplianceStore;
  private readonly now: () => string;
  private readonly controllerIdentity: JsonObject;
  private readonly leaseTtlMs: number;

  constructor(options: ServiceCredentialBootstrapServiceOptions) {
    this.store = options.store;
    this.now = options.now ?? (() => new Date().toISOString());
    this.controllerIdentity = object(options.controllerIdentity, 'controllerIdentity');
    this.leaseTtlMs = options.leaseTtlMs ?? 30_000;
    if (!Number.isSafeInteger(this.leaseTtlMs) || this.leaseTtlMs < 1_000 || this.leaseTtlMs > 300_000) {
      throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', 'leaseTtlMs must be between 1000 and 300000');
    }
  }

  describe(payload: JsonObject = {}): JsonObject {
    if (Object.keys(payload).length !== 0) throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', 'describe rejects unknown fields');
    return {
      ...describeServiceCredentialProfile(),
      transactionSchema: TRANSACTION_SCHEMA,
      profileStateSchema: PROFILE_STATE_SCHEMA,
      limits: { transactions: MAX_TRANSACTION_LIST, events: MAX_EVENT_LIST },
      durableAuthority: 'ReleaseApplianceStore',
      leaseResourceType: 'SERVICE',
      productionMaterializationEnabled: false,
    };
  }

  profiles(payload: JsonObject = {}): JsonObject {
    if (Object.keys(payload).length !== 0) throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', 'profiles rejects unknown fields');
    return {
      profiles: [{
        profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
        profileDigest: serviceCredentialProfileDigest(),
        compatibilityDigest: serviceCredentialCompatibilityDigest(),
      }],
      total: 1,
      bounded: true,
    };
  }

  plan(input: ServiceCredentialBootstrapPlanInput): JsonObject {
    return structuredClone(createServiceCredentialBootstrapPlan(input));
  }

  private leaseIdentity(profileId: string, ownerPrincipal: string, occurredAt: string): JsonObject {
    const observationDigest = sha256(canonicalize({
      profileId,
      ownerPrincipal,
      controllerIdentity: this.controllerIdentity,
      occurredAt,
    }));
    return {
      schemaVersion: '1.0.0',
      leaseId: `scl-${sha256(canonicalize({ profileId, ownerPrincipal, controllerIdentity: this.controllerIdentity })).slice(0, 40)}`,
      resourceType: 'SERVICE',
      resourceId: profileId,
      ownerPrincipal,
      controllerIdentity: structuredClone(this.controllerIdentity),
      acquiredAt: occurredAt,
      expiresAt: new Date(Date.parse(occurredAt) + this.leaseTtlMs).toISOString(),
      sequence: 1,
      state: 'ACTIVE',
      observationDigest,
    };
  }

  private withProfileLease<T>(profileId: string, ownerPrincipal: string, action: () => T): T {
    const occurredAt = this.now();
    const lease = this.leaseIdentity(profileId, ownerPrincipal, occurredAt);
    const existing = this.store.getLease('SERVICE', profileId);
    const existingControllerAbsent = existing !== undefined
      && (existing.state !== 'ACTIVE' || Date.parse(String(existing.expiresAt)) <= Date.parse(occurredAt));
    this.store.acquireLease(lease, { now: occurredAt, existingControllerAbsent });
    try {
      return action();
    } finally {
      const releaseDigest = sha256(canonicalize({ leaseId: lease.leaseId, ownerPrincipal, releasedAt: this.now() }));
      this.store.releaseLease('SERVICE', profileId, String(lease.leaseId), ownerPrincipal, releaseDigest, this.now());
    }
  }

  requestBootstrap(input: ServiceCredentialBootstrapPlanInput): JsonObject {
    const plan = createServiceCredentialBootstrapPlan(input);
    const ownerPrincipal = safeIdentifier(plan.ownerPrincipal, 'ownerPrincipal');
    const profileId = safeIdentifier(plan.profileId, 'profileId');
    const transactionId = safeIdentifier(plan.transactionId, 'transactionId');
    const occurredAt = this.now();
    return this.withProfileLease(profileId, ownerPrincipal, () => {
      const record: JsonObject = {
        schemaVersion: SERVICE_CREDENTIAL_BOOTSTRAP_SCHEMA_VERSION,
        transactionId,
        ownerPrincipal,
        idempotencyKey: safeIdentifier(plan.idempotencyKey, 'idempotencyKey'),
        creationRequestDigest: safeDigest(plan.requestDigest, 'requestDigest'),
        profileId,
        profileDigest: safeDigest(plan.profileDigest, 'profileDigest'),
        compatibilityDigest: safeDigest(plan.compatibilityDigest, 'compatibilityDigest'),
        planDigest: safeDigest(plan.planDigest, 'planDigest'),
        policyDecision: object(plan.policyDecision, 'policyDecision'),
        declaredEffects: structuredClone(plan.declaredEffects as JsonObject[]),
        state: 'REQUESTED',
        sequence: 1,
        generationId: safeIdentifier(plan.generationId, 'generationId'),
        allGenerationIds: [safeIdentifier(plan.generationId, 'generationId')],
        activeJobIds: [],
        allJobIds: [],
        credentialReferenceIds: [],
        publicMaterialReferences: [],
        cleanup: {
          temporaryMaterialCreated: false,
          temporaryMaterialAbsent: true,
          positiveAbsenceVerified: true,
          productionPathsTouched: false,
        },
        evidenceReferences: [],
        ...(plan.rotationPredecessorGenerationId === undefined ? {} : { rotationPredecessorGenerationId: plan.rotationPredecessorGenerationId }),
        createdAt: occurredAt,
        updatedAt: occurredAt,
      };
      return this.store.applyMutation({
        schemaId: TRANSACTION_SCHEMA,
        recordId: transactionId,
        ownerPrincipal,
        expectedSequence: 0,
        idempotencyKey: safeIdentifier(plan.idempotencyKey, 'idempotencyKey'),
        requestDigest: safeDigest(plan.requestDigest, 'requestDigest'),
        operation: 'babyx.release.credential-bootstrap.ensure',
        phase: 'request',
        record,
        occurredAt,
      });
    });
  }

  get(transactionId: string): JsonObject {
    return this.store.getRecord(TRANSACTION_SCHEMA, safeIdentifier(transactionId, 'transactionId'));
  }

  list(input: { offset?: number; limit?: number; state?: string; profileId?: string } = {}): JsonObject {
    const offset = safeSequence(input.offset ?? 0, 'offset');
    const limit = safeSequence(input.limit ?? 50, 'limit');
    if (limit < 1 || limit > MAX_TRANSACTION_LIST) throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', `limit must be between 1 and ${MAX_TRANSACTION_LIST}`);
    const identities = this.store.listRecordIdentities(10_000).filter((entry) => entry.schemaId === TRANSACTION_SCHEMA);
    const records: JsonObject[] = [];
    const isolated: JsonObject[] = [];
    for (const identity of identities) {
      try {
        const record = this.store.getRecord(identity.schemaId, identity.recordId);
        if (input.state !== undefined && record.state !== input.state) continue;
        if (input.profileId !== undefined && record.profileId !== input.profileId) continue;
        records.push(record);
      } catch (error) {
        isolated.push({ recordId: identity.recordId, errorCode: error instanceof ReleaseStoreError ? error.code : 'release_record_corrupt' });
      }
    }
    records.sort((left, right) => String(left.transactionId).localeCompare(String(right.transactionId), 'en'));
    return {
      transactions: records.slice(offset, offset + limit),
      offset,
      limit,
      total: records.length,
      isolated: isolated.slice(0, 50),
      bounded: true,
    };
  }

  events(transactionId: string, offset = 0, limit = 100): JsonObject {
    safeSequence(offset, 'offset');
    safeSequence(limit, 'limit');
    if (limit < 1 || limit > MAX_EVENT_LIST) throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', `event limit must be between 1 and ${MAX_EVENT_LIST}`);
    const id = safeIdentifier(transactionId, 'transactionId');
    const events = this.store.events(TRANSACTION_SCHEMA, id, offset, limit);
    return { transactionId: id, offset, limit, events, returned: events.length, bounded: true };
  }

  transition(inputValue: ServiceCredentialTransitionInput): JsonObject {
    const input = structuredClone(inputValue);
    const transactionId = safeIdentifier(input.transactionId, 'transactionId');
    const ownerPrincipal = safeIdentifier(input.ownerPrincipal, 'ownerPrincipal');
    const expectedSequence = safeSequence(input.expectedSequence, 'expectedSequence');
    const nextState = safeIdentifier(input.nextState, 'nextState');
    const operation = safeIdentifier(input.operation, 'operation');
    const phase = safeIdentifier(input.phase, 'phase');
    const current = this.get(transactionId);
    if (current.ownerPrincipal !== ownerPrincipal) throw new ServiceCredentialContractError('release_credential_bootstrap_identity_mismatch', 'owner principal does not match transaction');
    if (terminal(current.state)) throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_state', `terminal transaction ${transactionId} cannot be rewritten`);
    if (Number(current.sequence) !== expectedSequence) throw new ReleaseStoreError('release_stale_sequence', 'expected sequence does not match durable transaction', { expectedSequence, actualSequence: current.sequence });
    assertServiceCredentialTransition(String(current.state), nextState);
    const patch = input.patch === undefined ? {} : object(input.patch, 'patch');
    for (const key of Object.keys(immutableTransactionFacts(current))) {
      if (patch[key] !== undefined && canonicalize(patch[key]) !== canonicalize(current[key])) {
        throw new ServiceCredentialContractError('release_credential_bootstrap_identity_mismatch', `immutable transaction field ${key} cannot change`);
      }
    }
    const occurredAt = this.now();
    const candidate: JsonObject = {
      ...current,
      ...patch,
      state: nextState,
      sequence: expectedSequence + 1,
      updatedAt: occurredAt,
      ...(nextState === 'READY' ? { verification: structuredClone(input.readyFacts as JsonObject) } : {}),
      ...((nextState === 'FAILED' || nextState === 'REVOKED') ? { completedAt: occurredAt } : {}),
    };
    if (nextState === 'READY') {
      if (input.readyFacts === undefined) throw new ServiceCredentialContractError('release_credential_bootstrap_not_ready', 'READY requires verification facts');
      assertServiceCredentialReadyFacts(input.readyFacts);
      if (!Array.isArray(candidate.credentialReferenceIds) || candidate.credentialReferenceIds.length < 2) throw new ServiceCredentialContractError('release_credential_bootstrap_not_ready', 'READY requires both durable private credential references');
      if (!Array.isArray(candidate.publicMaterialReferences) || candidate.publicMaterialReferences.length < 1) throw new ServiceCredentialContractError('release_credential_bootstrap_not_ready', 'READY requires durable public material');
    }
    const requestDigest = sha256(canonicalize({
      immutable: immutableTransactionFacts(current),
      expectedSequence,
      nextState,
      operation,
      phase,
      patch,
      readyFacts: input.readyFacts ?? null,
      observationDigest: input.observationDigest ?? null,
    }));
    const internalIdempotencyKey = `sct-${sha256(canonicalize({ transactionId, expectedSequence, nextState, requestDigest })).slice(0, 48)}`;
    return this.withProfileLease(String(current.profileId), ownerPrincipal, () => this.store.applyMutation({
      schemaId: TRANSACTION_SCHEMA,
      recordId: transactionId,
      ownerPrincipal,
      expectedSequence,
      idempotencyKey: internalIdempotencyKey,
      requestDigest,
      operation,
      phase,
      record: candidate,
      occurredAt,
      observationDigest: input.observationDigest,
      childJobIds: input.childJobIds,
      artifactReferences: input.artifactReferences,
      receiptReferences: input.receiptReferences,
    }));
  }

  reconcile(inputValue: ServiceCredentialReconcileInput): JsonObject {
    const input = structuredClone(inputValue);
    safeDigest(input.observationDigest, 'observationDigest');
    const current = this.get(input.transactionId);
    if (current.ownerPrincipal !== input.ownerPrincipal) throw new ServiceCredentialContractError('release_credential_bootstrap_identity_mismatch', 'owner principal does not match transaction');
    if (Number(current.sequence) !== input.expectedSequence) throw new ReleaseStoreError('release_stale_sequence', 'expected sequence does not match durable transaction');
    if (terminal(current.state) || current.state === 'READY') return current;
    if (current.state === 'AMBIGUOUS') {
      return this.transition({
        transactionId: input.transactionId,
        ownerPrincipal: input.ownerPrincipal,
        expectedSequence: input.expectedSequence,
        nextState: 'RECOVERY_REQUIRED',
        operation: 'babyx.release.credential-bootstrap.reconcile',
        phase: 'ambiguity-readback',
        observationDigest: input.observationDigest,
        patch: { cleanup: { ...(current.cleanup as JsonObject), lastObservation: input.observation, observationDigest: input.observationDigest } },
      });
    }
    if (input.observation === 'EXTERNAL_STATE_UNKNOWN' || input.observation === 'EXTERNAL_EFFECT_OBSERVED') {
      const nextState = current.state === 'RECOVERY_REQUIRED' ? 'AMBIGUOUS' : 'RECOVERY_REQUIRED';
      return this.transition({
        transactionId: input.transactionId,
        ownerPrincipal: input.ownerPrincipal,
        expectedSequence: input.expectedSequence,
        nextState,
        operation: 'babyx.release.credential-bootstrap.reconcile',
        phase: 'external-readback',
        observationDigest: input.observationDigest,
        patch: { cleanup: { ...(current.cleanup as JsonObject), lastObservation: input.observation, observationDigest: input.observationDigest } },
      });
    }
    if (current.state === 'REQUESTED') {
      return this.transition({
        transactionId: input.transactionId,
        ownerPrincipal: input.ownerPrincipal,
        expectedSequence: input.expectedSequence,
        nextState: 'PLANNING',
        operation: 'babyx.release.credential-bootstrap.reconcile',
        phase: 'intent-recovery',
        observationDigest: input.observationDigest,
      });
    }
    return current;
  }

  active(profileId = BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID): JsonObject {
    const id = safeIdentifier(profileId, 'profileId');
    if (!this.store.hasRecord(PROFILE_STATE_SCHEMA, id)) {
      return { profileId: id, state: 'EMPTY', activeGenerationId: null, bounded: true };
    }
    return this.store.getRecord(PROFILE_STATE_SCHEMA, id);
  }

  startup(recordLimit = 1_000, pendingLimit = 1_000): ReleaseStartupReport {
    return this.store.startupScan(recordLimit, pendingLimit);
  }

  verifyStore(): JsonObject {
    return this.store.verify();
  }

  verifyAndRepairIndexes(): JsonObject {
    return this.store.verifyAndRepairIndexes();
  }
}
