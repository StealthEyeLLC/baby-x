import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { RootNetworkEffectAuthority, RootStorageEffectAuthority } from './authorities.ts';
import { createRootCompatibilityManifest } from './compatibility.ts';
import { RootEffectRegistry } from './effects.ts';
import { ROOT_FABRIC_PROVIDER_VERSION, ROOT_FABRIC_SCHEMA_VERSION, RootFabricError, contextPrincipal, object, strictObject, text, type RootEffectClass, type RootExecutionProvider } from './model.ts';
import { RootTrustService } from './trust.ts';
import { RootEffectTransactionService } from './transactions.ts';
import { RootObservationService } from './observability.ts';
import { RootCredentialService, type CredentialAuthorizationBinding, type RootCredentialLease } from './credentials.ts';
import { RootFreezeService, RootRecoveryService, type RecoveryAuthority } from './recovery.ts';

export const ROOT_FABRIC_OPERATION_NAMES = Object.freeze([
  'babyx.root.compatibility.get', 'babyx.root.effect.registry',
  'babyx.root.effect.create', 'babyx.root.effect.get', 'babyx.root.effect.list', 'babyx.root.effect.events',
  'babyx.root.effect.lease.acquire', 'babyx.root.effect.authorize', 'babyx.root.effect.prepare', 'babyx.root.effect.begin',
  'babyx.root.effect.validate', 'babyx.root.effect.commit', 'babyx.root.effect.cancel', 'babyx.root.effect.rollback',
  'babyx.root.effect.compensate', 'babyx.root.effect.clean', 'babyx.root.effect.repair',
  'babyx.root.bundle.verify', 'babyx.root.bundle.install', 'babyx.root.bundle.get', 'babyx.root.bundle.list', 'babyx.root.bundle.revoke',
  'babyx.root.grant.install', 'babyx.root.grant.get', 'babyx.root.grant.list', 'babyx.root.grant.revoke',
  'babyx.root.observation.start', 'babyx.root.observation.get', 'babyx.root.observation.record', 'babyx.root.observation.finalize',
  'babyx.root.credential.lease', 'babyx.root.credential.deliver', 'babyx.root.credential.get', 'babyx.root.credential.list', 'babyx.root.credential.revoke', 'babyx.root.credential.clean',
  'babyx.root.freeze.get', 'babyx.root.freeze.set', 'babyx.root.kill', 'babyx.root.reconcile',
] as const);
function envList(name: string): string[] { return (process.env[name] ?? '').split(',').map((value) => value.trim()).filter(Boolean); }
function keyFrom(directory: string, keyId: string): string | Buffer | undefined { if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(keyId)) return undefined; const path = join(directory, `${keyId}.pub`); return existsSync(path) ? readFileSync(path) : undefined; }

export class RootFabricService {
  readonly transactions: RootEffectTransactionService;
  readonly trust: RootTrustService;
  readonly effects: RootEffectRegistry;
  readonly observations: RootObservationService;
  readonly credentials: RootCredentialService;
  readonly freezes: RootFreezeService;
  readonly recovery: RootRecoveryService;
  constructor(private readonly options: { stateRoot: string; sourceCommit: string; sourceTree: string; catalogVersion: string; catalogDigest: () => string; publicKey?: (keyId: string) => string | Buffer | undefined; trustDirectory?: string; artifacts?: { spill(name: string, value: JsonObject, metadata: JsonObject): Promise<{ artifactId: string }> }; credentialDeliveryRoot?: string; recoveryAuthority?: RecoveryAuthority; now?: () => string }) {
    this.transactions = new RootEffectTransactionService(options.stateRoot, { now: options.now });
    this.trust = new RootTrustService(options.stateRoot, options.publicKey ?? ((keyId) => keyFrom(options.trustDirectory ?? '/etc/baby-x/root-trust', keyId)), { now: options.now });
    const observationAuthority = {
      resolve: (input: { transactionId: string; stepId: string; principalId: string; principalDigest: string; occurredAt: string }) => {
        const transaction = this.transactions.record(input.transactionId);
        if (transaction.ownerPrincipal.principalDigest !== input.principalDigest || transaction.ownerPrincipal.principalId !== input.principalId) throw new RootFabricError('principal_mismatch', 'observation transaction owner mismatch');
        if (!['EXECUTING', 'VALIDATING'].includes(transaction.lifecycle.persistedState) || transaction.lifecycle.terminal) throw new RootFabricError('transaction_state_conflict', 'transaction lifecycle does not permit observation');
        const step = transaction.plan.steps.find((candidate) => candidate.stepId === input.stepId);
        if (!step) throw new RootFabricError('unsupported_operation', 'observation step is not declared by the transaction');
        const provider = transaction.routing.executionProvider;
        if (provider === null || !step.providerRequirements.includes(provider)) throw new RootFabricError('unsupported_provider', 'observation step is not bound to the selected provider');
        if (typeof transaction.policy.decisionDigest !== 'string' || typeof transaction.policy.expiresAt !== 'string' || Date.parse(transaction.policy.expiresAt) <= Date.parse(input.occurredAt)) throw new RootFabricError('policy_denied', 'transaction policy authorization is absent or expired');
        const unitNames = Array.isArray(transaction.execution.unitNames) ? transaction.execution.unitNames as string[] : [];
        const machineIds = Array.isArray(transaction.execution.allMachineIds) ? transaction.execution.allMachineIds as string[] : [];
        const processIdentities = Array.isArray(transaction.execution.processIdentities) ? transaction.execution.processIdentities as JsonObject[] : [];
        if (unitNames.length === 0 && machineIds.length === 0 && processIdentities.length === 0) throw new RootFabricError('observation_unavailable', 'transaction has no authoritative execution identity');
        const operationDeadline = new Date(Math.min(Date.parse(transaction.lifecycle.deadline), Date.parse(transaction.policy.expiresAt), Date.parse(input.occurredAt) + step.timeoutMs)).toISOString();
        const executionBindingDigest = sha256(canonicalize({ transactionId: transaction.transactionId, sequence: transaction.lifecycle.sequence, fencingToken: transaction.lease.fencingToken, provider, stepId: step.stepId, unitNames, machineIds, processIdentities }));
        return { transactionId: transaction.transactionId, stepId: step.stepId, ownerPrincipalDigest: transaction.ownerPrincipal.principalDigest, provider, transactionSequence: transaction.lifecycle.sequence, fencingToken: transaction.lease.fencingToken, transactionDeadline: transaction.lifecycle.deadline, operationDeadline, executionBindingDigest, unitNames, machineIds, processIdentities };
      },
      assertEvent: (binding: JsonObject, eventIdentity: JsonObject) => {
        const units = binding.unitNames as string[]; const machines = binding.machineIds as string[]; const identities = binding.processIdentities as JsonObject[];
        if (eventIdentity.unitName !== null && !units.includes(String(eventIdentity.unitName))) throw new RootFabricError('unit_identity_conflict', 'observation unit is not bound to the transaction');
        if (eventIdentity.machineId !== null && !machines.includes(String(eventIdentity.machineId))) throw new RootFabricError('machine_identity_conflict', 'observation machine is not bound to the transaction');
        if (eventIdentity.processId !== null) {
          const match = identities.some((identity) => Number(identity.processId ?? identity.pid) === Number(eventIdentity.processId) && (eventIdentity.processStartTime === null || identity.processStartTime === eventIdentity.processStartTime) && (eventIdentity.bootId === null || identity.bootId === eventIdentity.bootId) && (eventIdentity.cgroupId === null || identity.cgroupId === eventIdentity.cgroupId || identity.controlGroup === eventIdentity.cgroupId));
          if (!match) throw new RootFabricError('process_identity_conflict', 'observation process identity is not bound to the transaction');
        }
      },
    };
    this.observations = new RootObservationService(options.stateRoot, options.artifacts, { now: options.now, authority: observationAuthority });
    const resolveCredentialBinding = (input: { transactionId: string; stepId: string; credentialReference: string; principalId: string; principalDigest: string; occurredAt: string }): CredentialAuthorizationBinding => {
      const transaction = this.transactions.record(input.transactionId);
      if (transaction.ownerPrincipal.principalId !== input.principalId || transaction.ownerPrincipal.principalDigest !== input.principalDigest) throw new RootFabricError('principal_mismatch', 'credential transaction owner mismatch');
      if (transaction.lifecycle.persistedState !== 'EXECUTING' || transaction.lifecycle.terminal) throw new RootFabricError('transaction_state_conflict', 'transaction lifecycle does not permit credential issuance');
      if (transaction.lease.controllerId === null || transaction.lease.fencingToken < 1 || transaction.lease.expiresAt === null || Date.parse(transaction.lease.expiresAt) <= Date.parse(input.occurredAt)) throw new RootFabricError('fencing_token_stale', 'credential issuance requires a current controller lease and fencing token');
      const step = transaction.plan.steps.find((candidate) => candidate.stepId === input.stepId);
      if (!step) throw new RootFabricError('unsupported_operation', 'credential step is not declared by the transaction');
      if (!step.credentialReferences.includes(input.credentialReference)) throw new RootFabricError('grant_denied', 'credential reference is not declared by the transaction step');
      const provider = transaction.routing.executionProvider;
      if (provider === null || !step.providerRequirements.includes(provider)) throw new RootFabricError('unsupported_provider', 'credential step is not bound to the selected provider');
      if (transaction.routing.providerId === null || transaction.routing.providerVersion === null || transaction.routing.providerProfileDigest === null) throw new RootFabricError('credential_unavailable', 'credential provider identity is incomplete');
      if (typeof transaction.policy.decisionDigest !== 'string' || typeof transaction.policy.expiresAt !== 'string' || Date.parse(transaction.policy.expiresAt) <= Date.parse(input.occurredAt)) throw new RootFabricError('policy_denied', 'transaction policy authorization is absent or expired');
      const grant = this.trust.authorize({ grantId: transaction.skill.capabilityGrantId, bundleDigest: transaction.skill.bundleDigest, ownerPrincipal: transaction.ownerPrincipal.principalId, operation: step.operation, provider, effectClass: step.effectClass, resources: step.resourceSelectors, credentialReferences: [input.credentialReference] });
      if (grant.grantDigest !== transaction.skill.capabilityGrantDigest) throw new RootFabricError('grant_denied', 'transaction grant digest does not match the authoritative grant');
      let targetType: 'UNIT' | 'MACHINE'; let targetId: string;
      if (provider === 'HOST_ENVELOPE') {
        const units = Array.isArray(transaction.execution.unitNames) ? [...new Set(transaction.execution.unitNames as string[])] : [];
        if (units.length !== 1) throw new RootFabricError('credential_unavailable', 'host credential issuance requires exactly one authoritative unit target');
        targetType = 'UNIT'; targetId = units[0]!;
      } else {
        const machines = Array.isArray(transaction.execution.activeMachineIds) ? [...new Set(transaction.execution.activeMachineIds as string[])] : [];
        if (machines.length !== 1) throw new RootFabricError('credential_unavailable', 'machine credential issuance requires exactly one authoritative active machine target');
        targetType = 'MACHINE'; targetId = machines[0]!;
      }
      this.assertNotFrozen({ principalId: transaction.ownerPrincipal.principalId, skillId: transaction.skill.skillId, bundleDigest: transaction.skill.bundleDigest, grantId: transaction.skill.capabilityGrantId, transactionId: transaction.transactionId, provider, credentialIssuance: true, newExecution: true });
      const limitValue = grant.limits.maximumCredentialTtlMs ?? grant.limits.credentialTtlMs;
      const maximumTtlMs = Number.isSafeInteger(limitValue) && Number(limitValue) >= 1_000 && Number(limitValue) <= 3_600_000 ? Number(limitValue) : Math.min(Math.max(step.timeoutMs, 1_000), 300_000);
      const configuredRevocation = grant.limits.credentialRevocationBehavior;
      const revocationBehavior = configuredRevocation === 'FREEZE' || configuredRevocation === 'ALLOW_TO_FINISH' || configuredRevocation === 'CANCEL_AND_ROLLBACK' ? configuredRevocation : 'CANCEL_AND_ROLLBACK';
      const operationDeadline = new Date(Math.min(Date.parse(transaction.lifecycle.deadline), Date.parse(transaction.policy.expiresAt), Date.parse(input.occurredAt) + step.timeoutMs)).toISOString();
      const authorizationDigest = sha256(canonicalize({ transactionId: transaction.transactionId, transactionSequence: transaction.lifecycle.sequence, fencingToken: transaction.lease.fencingToken, ownerPrincipalDigest: transaction.ownerPrincipal.principalDigest, stepId: step.stepId, operation: step.operation, credentialReference: input.credentialReference, provider, providerId: transaction.routing.providerId, providerVersion: transaction.routing.providerVersion, providerProfileDigest: transaction.routing.providerProfileDigest, targetType, targetId, bundleDigest: transaction.skill.bundleDigest, grantDigest: grant.grantDigest, policyDecisionDigest: transaction.policy.decisionDigest, policyVersion: grant.policyVersion, maximumTtlMs, revocationBehavior }));
      return { transactionId: transaction.transactionId, stepId: step.stepId, ownerPrincipalId: transaction.ownerPrincipal.principalId, ownerPrincipalDigest: transaction.ownerPrincipal.principalDigest, credentialReference: input.credentialReference, provider, providerId: transaction.routing.providerId, providerVersion: transaction.routing.providerVersion, providerProfileDigest: transaction.routing.providerProfileDigest, skillBundleDigest: transaction.skill.bundleDigest, grantId: grant.grantId, grantDigest: grant.grantDigest, policyDecisionDigest: transaction.policy.decisionDigest, policyVersion: grant.policyVersion, transactionSequence: transaction.lifecycle.sequence, fencingToken: transaction.lease.fencingToken, targetType, targetId, purpose: step.operation, transactionDeadline: transaction.lifecycle.deadline, operationDeadline, maximumTtlMs, revocationBehavior, authorizationDigest };
    };
    const credentialAuthority = {
      resolve: resolveCredentialBinding,
      assertCurrent: (lease: RootCredentialLease, input: { principalId: string; principalDigest: string; occurredAt: string }) => {
        const current = resolveCredentialBinding({ transactionId: lease.transactionId, stepId: lease.stepId, credentialReference: lease.credentialReference, principalId: input.principalId, principalDigest: input.principalDigest, occurredAt: input.occurredAt });
        const exact = lease.ownerPrincipalId === current.ownerPrincipalId && lease.principalDigest === current.ownerPrincipalDigest && lease.provider === current.provider && lease.providerId === current.providerId && lease.providerVersion === current.providerVersion && lease.providerProfileDigest === current.providerProfileDigest && lease.skillBundleDigest === current.skillBundleDigest && lease.grantId === current.grantId && lease.grantDigest === current.grantDigest && lease.policyDecisionDigest === current.policyDecisionDigest && lease.policyVersion === current.policyVersion && lease.transactionSequence === current.transactionSequence && lease.fencingToken === current.fencingToken && lease.targetType === current.targetType && lease.targetId === current.targetId && lease.purpose === current.purpose && lease.transactionDeadline === current.transactionDeadline && lease.maximumTtlMs === current.maximumTtlMs && lease.revocationBehavior === current.revocationBehavior && lease.authorizationDigest === current.authorizationDigest;
        if (!exact) throw new RootFabricError('fencing_token_stale', 'credential lease no longer matches the authoritative transaction, grant, policy, provider, or target');
        if (Date.parse(lease.operationDeadline) <= Date.parse(input.occurredAt) || Date.parse(lease.operationDeadline) > Date.parse(current.transactionDeadline)) throw new RootFabricError('deadline_exceeded', 'credential operation deadline is no longer valid');
      },
    };
    this.credentials = new RootCredentialService(options.stateRoot, undefined, { deliveryRoot: options.credentialDeliveryRoot ?? join(options.stateRoot, 'root-fabric', 'credential-delivery'), now: options.now, authority: credentialAuthority });
    this.freezes = new RootFreezeService(options.stateRoot, { now: options.now });
    const unavailable: RecoveryAuthority = {
      async inspectUnit() { return { exists: false, matches: false, active: false, terminal: false, identity: {}, resultDigest: null }; },
      async inspectMachine() { return { exists: false, matches: false, active: false, terminal: false, identity: {}, resultDigest: null }; },
      async inspectJob() { return { exists: false, matches: false, active: false, terminal: false, identity: {}, resultDigest: null }; },
      async killUnit() { throw new RootFabricError('resource_unavailable', 'unit recovery authority is unavailable'); },
      async killMachine() { throw new RootFabricError('resource_unavailable', 'machine recovery authority is unavailable'); },
      async killJob() { throw new RootFabricError('resource_unavailable', 'job recovery authority is unavailable'); },
      async verifyUnitAbsent() { return false; },
      async verifyMachineAbsent() { return false; },
      async verifyJobTerminal() { return false; },
    };
    this.recovery = new RootRecoveryService({ stateRoot: options.stateRoot, transactions: this.transactions, observations: this.observations, credentials: this.credentials, freezes: this.freezes, authority: options.recoveryAuthority ?? unavailable, now: options.now });
    this.effects = new RootEffectRegistry({ storage: new RootStorageEffectAuthority({ datasetRoots: envList('BABYX_ROOT_DATASET_ROOTS'), mountRoots: envList('BABYX_ROOT_MOUNT_ROOTS') }), network: new RootNetworkEffectAuthority({ table: process.env.BABYX_ROOT_NFT_TABLE ?? 'babyx_root' }) });
  }
  compatibility(): JsonObject { const value = createRootCompatibilityManifest({ sourceCommit: this.options.sourceCommit, sourceTree: this.options.sourceTree, catalogVersion: this.options.catalogVersion, catalogDigest: this.options.catalogDigest(), providerContractVersions: { rootFabric: ROOT_FABRIC_PROVIDER_VERSION, transaction: ROOT_FABRIC_SCHEMA_VERSION, broker: '1.0.0', observation: '1.1.0', credential: '1.1.0', recovery: '1.0.0' } }); return value as unknown as JsonObject; }
  async execute(operation: string, payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    if (!ROOT_FABRIC_OPERATION_NAMES.includes(operation as typeof ROOT_FABRIC_OPERATION_NAMES[number])) throw new RootFabricError('unsupported_operation', `unsupported A-J root fabric operation ${operation}`);
    if (operation === 'babyx.root.compatibility.get') return this.compatibility();
    if (operation === 'babyx.root.effect.registry') return { effects: this.effects.list() };
    if (operation === 'babyx.root.effect.create') { this.assertCreateAllowed(payload, context); return this.transactions.create(payload, context); }
    if (operation === 'babyx.root.effect.get') return this.transactions.get(payload);
    if (operation === 'babyx.root.effect.list') return this.transactions.list(payload);
    if (operation === 'babyx.root.effect.events') return this.transactions.events(payload);
    if (operation === 'babyx.root.effect.lease.acquire') return this.transactions.acquireLease(payload, context);
    if (operation === 'babyx.root.effect.authorize') { this.assertAuthorization(payload); return this.transactions.authorize(payload, context); }
    if (operation === 'babyx.root.effect.prepare') return this.transactions.prepare(payload, context);
    if (operation === 'babyx.root.effect.begin') { this.assertBeginAllowed(payload); return this.transactions.begin(payload, context); }
    if (operation === 'babyx.root.effect.validate') return this.transactions.validate(payload, context);
    if (operation === 'babyx.root.effect.commit') return this.transactions.commit(payload, context);
    if (operation === 'babyx.root.effect.cancel') return this.transactions.cancel(payload, context);
    if (operation === 'babyx.root.effect.rollback') return this.transactions.rollback(payload, context);
    if (operation === 'babyx.root.effect.compensate') return this.transactions.compensate(payload, context);
    if (operation === 'babyx.root.effect.clean') return this.transactions.clean(payload, context);
    if (operation === 'babyx.root.effect.repair') return this.transactions.repair(payload, context);
    if (operation === 'babyx.root.bundle.verify') return this.trust.bundleVerify(payload);
    if (operation === 'babyx.root.bundle.install') return this.trust.bundleInstall(payload, context);
    if (operation === 'babyx.root.bundle.get') return this.trust.bundleGet(payload);
    if (operation === 'babyx.root.bundle.list') return this.trust.bundleList(payload);
    if (operation === 'babyx.root.bundle.revoke') return this.trust.bundleRevoke(payload, context);
    if (operation === 'babyx.root.grant.install') return this.trust.grantInstall(payload, context);
    if (operation === 'babyx.root.grant.get') return this.trust.grantGet(payload);
    if (operation === 'babyx.root.grant.list') return this.trust.grantList(payload);
    if (operation === 'babyx.root.grant.revoke') return this.trust.grantRevoke(payload, context);
    if (operation === 'babyx.root.observation.start') return this.observations.start(payload, context);
    if (operation === 'babyx.root.observation.get') return this.observations.get(payload, context);
    if (operation === 'babyx.root.observation.record') return this.observations.record(payload, context);
    if (operation === 'babyx.root.observation.finalize') return this.observations.finalize(payload, context);
    if (operation === 'babyx.root.credential.lease') return this.credentials.lease(payload, context);
    if (operation === 'babyx.root.credential.deliver') return this.credentials.deliver(payload, context);
    if (operation === 'babyx.root.credential.get') return this.credentials.get(payload, context);
    if (operation === 'babyx.root.credential.list') return this.credentials.list(payload, context);
    if (operation === 'babyx.root.credential.revoke') return this.credentials.revoke(payload, context);
    if (operation === 'babyx.root.credential.clean') return this.credentials.clean(payload, context);
    if (operation === 'babyx.root.freeze.get') return this.freezes.get(payload);
    if (operation === 'babyx.root.freeze.set') return this.freezes.set(payload, context);
    if (operation === 'babyx.root.kill') return this.recovery.kill(payload, context);
    return this.recovery.reconcile(payload, context);
  }
  verifyBrokerBinding(requestValue: JsonObject): void {
    const request = strictObject(requestValue, 'broker binding', ['protocolVersion', 'requestId', 'transactionId', 'transactionSequence', 'fencingToken', 'ownerPrincipalDigest', 'skillBundleDigest', 'grantDigest', 'policyDecisionDigest', 'operation', 'operationVersion', 'operationInput', 'inputDigest', 'deadline', 'nonce', 'selectedProvider', 'credentialReferences']);
    const transaction = this.transactions.record(text(request.transactionId, 'transactionId', 256));
    if (transaction.lifecycle.persistedState !== 'EXECUTING' || transaction.lifecycle.sequence !== request.transactionSequence || transaction.lease.fencingToken !== request.fencingToken) throw new RootFabricError('fencing_token_stale', 'broker transaction sequence or fencing token mismatch');
    if (transaction.ownerPrincipal.principalDigest !== request.ownerPrincipalDigest || transaction.skill.bundleDigest !== request.skillBundleDigest || transaction.skill.capabilityGrantDigest !== request.grantDigest || transaction.policy.decisionDigest !== request.policyDecisionDigest || transaction.routing.executionProvider !== request.selectedProvider) throw new RootFabricError('principal_mismatch', 'broker request is not bound to the authorized transaction');
    this.assertNotFrozen({ principalId: transaction.ownerPrincipal.principalId, skillId: transaction.skill.skillId, bundleDigest: transaction.skill.bundleDigest, grantId: transaction.skill.capabilityGrantId, transactionId: transaction.transactionId, provider: String(request.selectedProvider), newExecution: true });
    const step = transaction.plan.steps.find((candidate) => candidate.operation === request.operation && candidate.operationVersion === request.operationVersion && candidate.inputDigest === request.inputDigest);
    if (!step) throw new RootFabricError('unsupported_operation', 'broker request does not match a declared transaction step');
    this.trust.authorize({ grantId: transaction.skill.capabilityGrantId, bundleDigest: transaction.skill.bundleDigest, ownerPrincipal: transaction.ownerPrincipal.principalId, operation: step.operation, provider: request.selectedProvider as RootExecutionProvider, effectClass: step.effectClass, resources: step.resourceSelectors, credentialReferences: request.credentialReferences as string[] });
  }
  private assertCreateAllowed(payloadValue: JsonObject, context: RuntimeExecutionContext): void {
    const payload = object(payloadValue, 'root effect create payload'); const skill = object(payload.skill, 'skill'); const plan = object(payload.plan, 'plan');
    if (!Array.isArray(plan.steps)) throw new RootFabricError('invalid_request', 'plan.steps must be an array');
    const principal = contextPrincipal(context, new Date().toISOString());
    this.assertNotFrozen({ principalId: principal.principalId, skillId: String(skill.skillId), bundleDigest: String(skill.bundleDigest), grantId: String(skill.capabilityGrantId), newExecution: true });
    for (const raw of plan.steps) { const step = object(raw, 'plan step'); const providers = Array.isArray(step.providerRequirements) ? step.providerRequirements as RootExecutionProvider[] : []; for (const provider of providers) this.trust.authorize({ grantId: String(skill.capabilityGrantId), bundleDigest: String(skill.bundleDigest), ownerPrincipal: principal.principalId, operation: String(step.operation), provider, effectClass: step.effectClass as RootEffectClass, resources: object(step.resourceSelectors, 'resourceSelectors'), credentialReferences: Array.isArray(step.credentialReferences) ? step.credentialReferences as string[] : [] }); }
  }
  private assertAuthorization(payloadValue: JsonObject): void {
    const payload = object(payloadValue, 'authorize payload'); const transaction = this.transactions.record(text(payload.transactionId, 'transactionId', 256)); const provider = text(payload.executionProvider, 'executionProvider', 32) as RootExecutionProvider;
    this.assertNotFrozen({ principalId: transaction.ownerPrincipal.principalId, skillId: transaction.skill.skillId, bundleDigest: transaction.skill.bundleDigest, grantId: transaction.skill.capabilityGrantId, transactionId: transaction.transactionId, provider, newExecution: true });
    for (const step of transaction.plan.steps) if (step.providerRequirements.includes(provider)) this.trust.authorize({ grantId: transaction.skill.capabilityGrantId, bundleDigest: transaction.skill.bundleDigest, ownerPrincipal: transaction.ownerPrincipal.principalId, operation: step.operation, provider, effectClass: step.effectClass, resources: step.resourceSelectors, credentialReferences: step.credentialReferences });
  }
  private assertBeginAllowed(payloadValue: JsonObject): void { const payload = object(payloadValue, 'begin payload'); const transaction = this.transactions.record(text(payload.transactionId, 'transactionId', 256)); if (transaction.routing.executionProvider === null) throw new RootFabricError('state_conflict', 'execution provider must be authorized before begin'); this.assertNotFrozen({ principalId: transaction.ownerPrincipal.principalId, skillId: transaction.skill.skillId, bundleDigest: transaction.skill.bundleDigest, grantId: transaction.skill.capabilityGrantId, transactionId: transaction.transactionId, provider: transaction.routing.executionProvider, newExecution: true }); }
  private assertNotFrozen(input: { principalId?: string; skillId?: string; bundleDigest?: string; grantId?: string; transactionId?: string; provider?: string; credentialIssuance?: boolean; newExecution?: boolean }): void { const result = this.freezes.isFrozen(input); if (result.frozen) throw new RootFabricError('state_conflict', 'root execution is frozen', { freezeIds: result.matches.map((record) => record.freezeId), scopes: result.matches.map((record) => record.scope) }); }
}
