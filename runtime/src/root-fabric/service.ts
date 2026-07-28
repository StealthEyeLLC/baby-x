import { existsSync, readFileSync } from 'node:fs';
import { arch, platform, release } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { RootEffectTransactionService } from './transactions.ts';
import { RootTrustService } from './trust.ts';
import { RootObservationService } from './observability.ts';
import { RootCredentialService } from './credentials.ts';
import { RootFreezeService, RootRecoveryService, type RecoveryAuthority } from './recovery.ts';
import { RootEffectRegistry, type ArtifactAuthority } from './effects.ts';
import { RootNetworkEffectAuthority, RootStorageEffectAuthority } from './authorities.ts';
import { ROOT_BROKER_PROTOCOL_VERSION, ROOT_FABRIC_PROVIDER_VERSION, ROOT_FABRIC_SCHEMA_VERSION, ROOT_FABRIC_VERSION, RootFabricError, contextPrincipal, object, strictObject, text, type RootEffectClass, type RootExecutionProvider } from './model.ts';

export const ROOT_FABRIC_OPERATION_NAMES = [
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
] as const;

interface RuntimeArtifactAuthority extends ArtifactAuthority {
  spill(name: string, value: JsonObject, metadata: JsonObject): Promise<{ artifactId: string }>;
}

function executable(name: string): string | null {
  const result = spawnSync('/usr/bin/env', ['bash', '-lc', `command -v -- ${name}`], { encoding: 'utf8', timeout: 5_000 });
  return result.status === 0 && result.stdout.trim().length > 0 ? result.stdout.trim() : null;
}

function probe(command: string, argv: string[] = ['--version']): JsonObject {
  const path = executable(command);
  if (path === null) return { supported: false, path: null, version: null };
  const result = spawnSync(path, argv, { encoding: 'utf8', timeout: 5_000 });
  return { supported: result.status === 0, path, version: (result.stdout || result.stderr).trim().split('\n')[0] ?? null, exitCode: result.status };
}

function envList(name: string): string[] {
  return (process.env[name] ?? '').split(',').map((value) => value.trim()).filter(Boolean);
}

function publicKeyFromDirectory(directory: string, keyId: string): string | Buffer | undefined {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(keyId)) return undefined;
  const path = join(directory, `${keyId}.pub`);
  return existsSync(path) ? readFileSync(path) : undefined;
}

export class RootFabricService {
  readonly transactions: RootEffectTransactionService;
  readonly trust: RootTrustService;
  readonly observations: RootObservationService;
  readonly credentials: RootCredentialService;
  readonly freezes: RootFreezeService;
  readonly recovery: RootRecoveryService;
  readonly effects: RootEffectRegistry;

  constructor(private readonly options: {
    stateRoot: string;
    sourceCommit: string;
    sourceTree: string;
    catalogVersion: string;
    catalogDigest: () => string;
    artifacts: RuntimeArtifactAuthority;
    recoveryAuthority: RecoveryAuthority;
    publicKey?: (keyId: string) => string | Buffer | undefined;
    trustDirectory?: string;
    now?: () => string;
  }) {
    const publicKey = options.publicKey ?? ((keyId: string) => publicKeyFromDirectory(options.trustDirectory ?? '/etc/baby-x/root-trust', keyId));
    this.transactions = new RootEffectTransactionService(options.stateRoot, { now: options.now });
    this.trust = new RootTrustService(options.stateRoot, publicKey, { now: options.now });
    this.observations = new RootObservationService(options.stateRoot, options.artifacts, { now: options.now });
    this.credentials = new RootCredentialService(options.stateRoot, undefined, { deliveryRoot: process.env.BABYX_ROOT_CREDENTIAL_ROOT ?? '/run/baby-x/root-credentials', now: options.now });
    this.freezes = new RootFreezeService(options.stateRoot, { now: options.now });
    this.effects = new RootEffectRegistry({
      storage: new RootStorageEffectAuthority({ datasetRoots: envList('BABYX_ROOT_DATASET_ROOTS'), mountRoots: envList('BABYX_ROOT_MOUNT_ROOTS') }),
      network: new RootNetworkEffectAuthority({ table: process.env.BABYX_ROOT_NFT_TABLE ?? 'babyx_root' }),
      artifacts: options.artifacts,
    });
    this.recovery = new RootRecoveryService({ stateRoot: options.stateRoot, transactions: this.transactions, observations: this.observations, credentials: this.credentials, freezes: this.freezes, authority: options.recoveryAuthority, now: options.now });
  }

  compatibility(): JsonObject {
    const manifest = {
      schemaVersion: ROOT_FABRIC_SCHEMA_VERSION, rootFabricVersion: ROOT_FABRIC_VERSION, providerVersion: ROOT_FABRIC_PROVIDER_VERSION,
      sourceCommit: this.options.sourceCommit, sourceTree: this.options.sourceTree, os: platform(), architecture: arch(), kernel: release(),
      bootId: existsSync('/proc/sys/kernel/random/boot_id') ? readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim() : null,
      systemd: probe('systemctl'), node: process.version, npm: probe('npm'), cgroupMode: existsSync('/sys/fs/cgroup/cgroup.controllers') ? 'v2' : 'legacy-or-unavailable',
      controllers: existsSync('/sys/fs/cgroup/cgroup.controllers') ? readFileSync('/sys/fs/cgroup/cgroup.controllers', 'utf8').trim().split(/\s+/u) : [],
      transientUnits: existsSync('/run/systemd/system'), pidfd: { native: false, fallback: 'process-start-time-and-boot-id' },
      openat2: { native: false, fallback: 'descriptor-component-walk-and-O_NOFOLLOW' }, renameat2: { native: false, fallback: 'same-filesystem-atomic-rename' },
      seccomp: existsSync('/proc/sys/kernel/seccomp'), seccompNotification: existsSync('/proc/sys/kernel/seccomp'), landlock: existsSync('/sys/kernel/security/landlock'),
      activeLsms: existsSync('/sys/kernel/security/lsm') ? readFileSync('/sys/kernel/security/lsm', 'utf8').trim().split(',') : [],
      ebpf: existsSync('/sys/fs/bpf'), btf: existsSync('/sys/kernel/btf/vmlinux'), bpfLsm: existsSync('/sys/kernel/security/lsm') && readFileSync('/sys/kernel/security/lsm', 'utf8').includes('bpf'),
      bpftrace: probe('bpftrace'), packetCapture: probe('tcpdump'), kvm: existsSync('/dev/kvm'), tpm: existsSync('/dev/tpmrm0') || existsSync('/dev/tpm0'),
      criu: probe('criu'), zfs: probe('zfs'), nspawn: probe('systemd-nspawn'),
      protectedSnapshot: { name: 'babycert/base/noble@golden-v1', guid: '9351137475418520293', creationTxg: '53' },
      brokerProtocol: ROOT_BROKER_PROTOCOL_VERSION, transactionSchema: ROOT_FABRIC_SCHEMA_VERSION, eventSchema: ROOT_FABRIC_SCHEMA_VERSION,
      grantSchema: '1.0.0', bundleSchema: '1.0.0', observationSchema: '1.0.0', credentialSchema: '1.0.0', recoverySchema: '1.0.0',
      catalogVersion: this.options.catalogVersion, catalogDigest: this.options.catalogDigest(),
      limits: { retainedTransactions: 4_096, activeTransactions: 16, activePerPrincipal: 4, planSteps: 32, brokerRequestBytes: 1_048_576, brokerResponseBytes: 65_536, observationSummaryBytes: 65_536, publicPageSize: 200, maximumRuntimeMs: 3_600_000, defaultRuntimeMs: 300_000, outputPerStreamBytes: 67_108_864 },
      authority: { transaction: 'RootEffectTransactionService', jobs: 'existing durable JobManager', machines: 'existing DisposableMachineService', artifacts: 'existing ArtifactManager', policy: 'existing execution-policy authority', deployment: 'existing release authority' },
      operationCount: ROOT_FABRIC_OPERATION_NAMES.length, operations: ROOT_FABRIC_OPERATION_NAMES,
    };
    return { manifest, digest: sha256(canonicalize(manifest)) };
  }

  async execute(operation: string, payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    if (!ROOT_FABRIC_OPERATION_NAMES.includes(operation as typeof ROOT_FABRIC_OPERATION_NAMES[number])) throw new RootFabricError('unsupported_operation', `unsupported root fabric operation ${operation}`);
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
    if (operation === 'babyx.root.observation.finalize') return this.observations.finalize(payload, context);
    if (operation === 'babyx.root.credential.lease') { this.assertCredentialAllowed(payload); return this.credentials.lease(payload, context); }
    if (operation === 'babyx.root.credential.deliver') return this.credentials.deliver(payload, context);
    if (operation === 'babyx.root.credential.get') return this.credentials.get(payload);
    if (operation === 'babyx.root.credential.list') return this.credentials.list(payload);
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
    const step = transaction.plan.steps.find((candidate) => candidate.operation === request.operation && candidate.operationVersion === request.operationVersion && candidate.inputDigest === request.inputDigest);
    if (step === undefined) throw new RootFabricError('unsupported_operation', 'broker request does not match a declared transaction step');
    const frozen = this.freezes.isFrozen({ principalId: transaction.ownerPrincipal.principalId, skillId: transaction.skill.skillId, bundleDigest: transaction.skill.bundleDigest, grantId: transaction.skill.capabilityGrantId, transactionId: transaction.transactionId, provider: String(request.selectedProvider), newExecution: true });
    if (frozen.frozen) throw new RootFabricError('frozen', 'root broker execution is frozen', { freezeIds: frozen.matches.map((record) => record.freezeId) });
    this.trust.authorize({ grantId: transaction.skill.capabilityGrantId, bundleDigest: transaction.skill.bundleDigest, ownerPrincipal: transaction.ownerPrincipal.principalId, operation: step.operation, provider: request.selectedProvider as RootExecutionProvider, effectClass: step.effectClass, resources: step.resourceSelectors, credentialReferences: request.credentialReferences as string[] });
  }

  private assertCreateAllowed(payloadValue: JsonObject, context: RuntimeExecutionContext): void {
    const payload = object(payloadValue, 'root effect create payload');
    const skill = object(payload.skill, 'skill');
    const plan = object(payload.plan, 'plan');
    if (!Array.isArray(plan.steps)) throw new RootFabricError('invalid_request', 'plan.steps must be an array');
    const principal = contextPrincipal(context, new Date().toISOString());
    const requestedProvider = payload.requestedProvider === null || payload.requestedProvider === undefined ? null : text(payload.requestedProvider, 'requestedProvider', 32) as RootExecutionProvider;
    const frozen = this.freezes.isFrozen({ principalId: principal.principalId, skillId: String(skill.skillId), bundleDigest: String(skill.bundleDigest), grantId: String(skill.capabilityGrantId), provider: requestedProvider ?? undefined, newExecution: true });
    if (frozen.frozen) throw new RootFabricError('frozen', 'new root effect creation is frozen', { freezeIds: frozen.matches.map((record) => record.freezeId) });
    for (const rawStep of plan.steps) {
      const step = object(rawStep, 'plan step');
      const providers = Array.isArray(step.providerRequirements) ? step.providerRequirements as RootExecutionProvider[] : [];
      for (const provider of providers) this.trust.authorize({ grantId: String(skill.capabilityGrantId), bundleDigest: String(skill.bundleDigest), ownerPrincipal: principal.principalId, operation: String(step.operation), provider, effectClass: step.effectClass as RootEffectClass, resources: object(step.resourceSelectors, 'resourceSelectors'), credentialReferences: Array.isArray(step.credentialReferences) ? step.credentialReferences as string[] : [] });
    }
  }

  private assertAuthorization(payloadValue: JsonObject): void {
    const payload = object(payloadValue, 'authorize payload');
    const transaction = this.transactions.record(text(payload.transactionId, 'transactionId', 256));
    const provider = text(payload.executionProvider, 'executionProvider', 32) as RootExecutionProvider;
    const frozen = this.freezes.isFrozen({ principalId: transaction.ownerPrincipal.principalId, skillId: transaction.skill.skillId, bundleDigest: transaction.skill.bundleDigest, grantId: transaction.skill.capabilityGrantId, transactionId: transaction.transactionId, provider });
    if (frozen.frozen) throw new RootFabricError('frozen', 'root effect authorization is frozen', { freezeIds: frozen.matches.map((record) => record.freezeId) });
    for (const step of transaction.plan.steps) if (step.providerRequirements.includes(provider)) this.trust.authorize({ grantId: transaction.skill.capabilityGrantId, bundleDigest: transaction.skill.bundleDigest, ownerPrincipal: transaction.ownerPrincipal.principalId, operation: step.operation, provider, effectClass: step.effectClass, resources: step.resourceSelectors, credentialReferences: step.credentialReferences });
  }

  private assertBeginAllowed(payloadValue: JsonObject): void {
    const payload = object(payloadValue, 'begin payload');
    const transaction = this.transactions.record(text(payload.transactionId, 'transactionId', 256));
    const frozen = this.freezes.isFrozen({ principalId: transaction.ownerPrincipal.principalId, skillId: transaction.skill.skillId, bundleDigest: transaction.skill.bundleDigest, grantId: transaction.skill.capabilityGrantId, transactionId: transaction.transactionId, provider: transaction.routing.executionProvider ?? undefined, newExecution: true });
    if (frozen.frozen) throw new RootFabricError('frozen', 'root effect execution is frozen', { freezeIds: frozen.matches.map((record) => record.freezeId) });
  }

  private assertCredentialAllowed(payloadValue: JsonObject): void {
    const payload = object(payloadValue, 'credential lease payload');
    const frozen = this.freezes.isFrozen({ transactionId: String(payload.transactionId), bundleDigest: String(payload.skillBundleDigest), grantId: undefined, provider: String(payload.provider), credentialIssuance: true });
    if (frozen.frozen) throw new RootFabricError('frozen', 'credential issuance is frozen', { freezeIds: frozen.matches.map((record) => record.freezeId) });
  }
}
