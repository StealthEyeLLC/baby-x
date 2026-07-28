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

export const ROOT_FABRIC_OPERATION_NAMES = Object.freeze([
  'babyx.root.compatibility.get', 'babyx.root.effect.registry',
  'babyx.root.effect.create', 'babyx.root.effect.get', 'babyx.root.effect.list', 'babyx.root.effect.events',
  'babyx.root.effect.lease.acquire', 'babyx.root.effect.authorize', 'babyx.root.effect.prepare', 'babyx.root.effect.begin',
  'babyx.root.effect.validate', 'babyx.root.effect.commit', 'babyx.root.effect.cancel', 'babyx.root.effect.rollback',
  'babyx.root.effect.compensate', 'babyx.root.effect.clean', 'babyx.root.effect.repair',
  'babyx.root.bundle.verify', 'babyx.root.bundle.install', 'babyx.root.bundle.get', 'babyx.root.bundle.list', 'babyx.root.bundle.revoke',
  'babyx.root.grant.install', 'babyx.root.grant.get', 'babyx.root.grant.list', 'babyx.root.grant.revoke',
  'babyx.root.observation.start', 'babyx.root.observation.get', 'babyx.root.observation.record', 'babyx.root.observation.finalize',
] as const);
function envList(name: string): string[] { return (process.env[name] ?? '').split(',').map((value) => value.trim()).filter(Boolean); }
function keyFrom(directory: string, keyId: string): string | Buffer | undefined { if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(keyId)) return undefined; const path = join(directory, `${keyId}.pub`); return existsSync(path) ? readFileSync(path) : undefined; }

export class RootFabricService {
  readonly transactions: RootEffectTransactionService;
  readonly trust: RootTrustService;
  readonly effects: RootEffectRegistry;
  readonly observations: RootObservationService;
  constructor(private readonly options: { stateRoot: string; sourceCommit: string; sourceTree: string; catalogVersion: string; catalogDigest: () => string; publicKey?: (keyId: string) => string | Buffer | undefined; trustDirectory?: string; artifacts?: { spill(name: string, value: JsonObject, metadata: JsonObject): Promise<{ artifactId: string }> }; now?: () => string }) {
    this.transactions = new RootEffectTransactionService(options.stateRoot, { now: options.now });
    this.trust = new RootTrustService(options.stateRoot, options.publicKey ?? ((keyId) => keyFrom(options.trustDirectory ?? '/etc/baby-x/root-trust', keyId)), { now: options.now });
    this.observations = new RootObservationService(options.stateRoot, options.artifacts, { now: options.now });
    this.effects = new RootEffectRegistry({ storage: new RootStorageEffectAuthority({ datasetRoots: envList('BABYX_ROOT_DATASET_ROOTS'), mountRoots: envList('BABYX_ROOT_MOUNT_ROOTS') }), network: new RootNetworkEffectAuthority({ table: process.env.BABYX_ROOT_NFT_TABLE ?? 'babyx_root' }) });
  }
  compatibility(): JsonObject { const value = createRootCompatibilityManifest({ sourceCommit: this.options.sourceCommit, sourceTree: this.options.sourceTree, catalogVersion: this.options.catalogVersion, catalogDigest: this.options.catalogDigest(), providerContractVersions: { rootFabric: ROOT_FABRIC_PROVIDER_VERSION, transaction: ROOT_FABRIC_SCHEMA_VERSION, broker: '1.0.0', observation: '1.0.0' } }); return value as unknown as JsonObject; }
  async execute(operation: string, payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    if (!ROOT_FABRIC_OPERATION_NAMES.includes(operation as typeof ROOT_FABRIC_OPERATION_NAMES[number])) throw new RootFabricError('unsupported_operation', `unsupported A-H root fabric operation ${operation}`);
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
    if (operation === 'babyx.root.observation.get') return this.observations.get(payload);
    if (operation === 'babyx.root.observation.record') return this.observations.record(payload, context);
    return this.observations.finalize(payload, context);
  }
  verifyBrokerBinding(requestValue: JsonObject): void {
    const request = strictObject(requestValue, 'broker binding', ['protocolVersion', 'requestId', 'transactionId', 'transactionSequence', 'fencingToken', 'ownerPrincipalDigest', 'skillBundleDigest', 'grantDigest', 'policyDecisionDigest', 'operation', 'operationVersion', 'operationInput', 'inputDigest', 'deadline', 'nonce', 'selectedProvider', 'credentialReferences']);
    const transaction = this.transactions.record(text(request.transactionId, 'transactionId', 256));
    if (transaction.lifecycle.persistedState !== 'EXECUTING' || transaction.lifecycle.sequence !== request.transactionSequence || transaction.lease.fencingToken !== request.fencingToken) throw new RootFabricError('fencing_token_stale', 'broker transaction sequence or fencing token mismatch');
    if (transaction.ownerPrincipal.principalDigest !== request.ownerPrincipalDigest || transaction.skill.bundleDigest !== request.skillBundleDigest || transaction.skill.capabilityGrantDigest !== request.grantDigest || transaction.policy.decisionDigest !== request.policyDecisionDigest || transaction.routing.executionProvider !== request.selectedProvider) throw new RootFabricError('principal_mismatch', 'broker request is not bound to the authorized transaction');
    const step = transaction.plan.steps.find((candidate) => candidate.operation === request.operation && candidate.operationVersion === request.operationVersion && candidate.inputDigest === request.inputDigest);
    if (!step) throw new RootFabricError('unsupported_operation', 'broker request does not match a declared transaction step');
    this.trust.authorize({ grantId: transaction.skill.capabilityGrantId, bundleDigest: transaction.skill.bundleDigest, ownerPrincipal: transaction.ownerPrincipal.principalId, operation: step.operation, provider: request.selectedProvider as RootExecutionProvider, effectClass: step.effectClass, resources: step.resourceSelectors, credentialReferences: request.credentialReferences as string[] });
  }
  private assertCreateAllowed(payloadValue: JsonObject, context: RuntimeExecutionContext): void {
    const payload = object(payloadValue, 'root effect create payload'); const skill = object(payload.skill, 'skill'); const plan = object(payload.plan, 'plan');
    if (!Array.isArray(plan.steps)) throw new RootFabricError('invalid_request', 'plan.steps must be an array');
    const principal = contextPrincipal(context, new Date().toISOString());
    for (const raw of plan.steps) { const step = object(raw, 'plan step'); const providers = Array.isArray(step.providerRequirements) ? step.providerRequirements as RootExecutionProvider[] : []; for (const provider of providers) this.trust.authorize({ grantId: String(skill.capabilityGrantId), bundleDigest: String(skill.bundleDigest), ownerPrincipal: principal.principalId, operation: String(step.operation), provider, effectClass: step.effectClass as RootEffectClass, resources: object(step.resourceSelectors, 'resourceSelectors'), credentialReferences: Array.isArray(step.credentialReferences) ? step.credentialReferences as string[] : [] }); }
  }
  private assertAuthorization(payloadValue: JsonObject): void {
    const payload = object(payloadValue, 'authorize payload'); const transaction = this.transactions.record(text(payload.transactionId, 'transactionId', 256)); const provider = text(payload.executionProvider, 'executionProvider', 32) as RootExecutionProvider;
    for (const step of transaction.plan.steps) if (step.providerRequirements.includes(provider)) this.trust.authorize({ grantId: transaction.skill.capabilityGrantId, bundleDigest: transaction.skill.bundleDigest, ownerPrincipal: transaction.ownerPrincipal.principalId, operation: step.operation, provider, effectClass: step.effectClass, resources: step.resourceSelectors, credentialReferences: step.credentialReferences });
  }
  private assertBeginAllowed(payloadValue: JsonObject): void { const payload = object(payloadValue, 'begin payload'); const transaction = this.transactions.record(text(payload.transactionId, 'transactionId', 256)); if (transaction.routing.executionProvider === null) throw new RootFabricError('state_conflict', 'execution provider must be authorized before begin'); }
}
