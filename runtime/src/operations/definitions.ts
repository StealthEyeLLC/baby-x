export type OperationRisk = 'low' | 'medium' | 'high';
export type OperationIdempotency = 'read_only' | 'caller_key' | 'conditional' | 'non_idempotent';

export interface OperationDefinition {
  operation: string;
  family: string;
  version: string;
  description: string;
  mutation: boolean;
  risk: OperationRisk;
  idempotency: OperationIdempotency;
  errors: readonly string[];
  cancellation: string;
  restartBehavior: string;
  postActionVerification: boolean;
  postconditions: readonly string[];
  receiptVersion: '1.0.0';
  limits: Record<string, number>;
  authority: { class: 'unrestricted-owner'; provider: 'baby-x-runtime' };
  input: Record<string, unknown>;
  output?: Record<string, unknown>;
}

const operations = `
babyx.describe
babyx.health
babyx.core.compatibility
babyx.transaction.create
babyx.transaction.get
babyx.transaction.list
babyx.transaction.events
babyx.transaction.status
babyx.transaction.execute
babyx.transaction.validate
babyx.transaction.finalize
babyx.transaction.rollback
babyx.transaction.reconcile
babyx.transaction.expire
babyx.transaction.gc
babyx.root.describe
babyx.root.transaction.create
babyx.root.transaction.get
babyx.root.transaction.list
babyx.root.transaction.authorize
babyx.root.transaction.begin
babyx.root.transaction.observe
babyx.root.transaction.commit
babyx.root.transaction.rollback
babyx.root.transaction.events
babyx.root.transaction.verify
babyx.root.compatibility.get
babyx.root.effect.registry
babyx.root.effect.create
babyx.root.effect.get
babyx.root.effect.list
babyx.root.effect.events
babyx.root.effect.lease.acquire
babyx.root.effect.authorize
babyx.root.effect.prepare
babyx.root.effect.begin
babyx.root.effect.validate
babyx.root.effect.commit
babyx.root.effect.cancel
babyx.root.effect.rollback
babyx.root.effect.compensate
babyx.root.effect.clean
babyx.root.effect.repair
babyx.root.bundle.verify
babyx.root.bundle.install
babyx.root.bundle.get
babyx.root.bundle.list
babyx.root.bundle.revoke
babyx.root.grant.install
babyx.root.grant.get
babyx.root.grant.list
babyx.root.grant.revoke
babyx.root.observation.start
babyx.root.observation.get
babyx.root.observation.record
babyx.root.observation.finalize
babyx.root.credential.lease
babyx.root.credential.deliver
babyx.root.credential.get
babyx.root.credential.list
babyx.root.credential.revoke
babyx.root.credential.clean
babyx.root.freeze.get
babyx.root.freeze.set
babyx.root.kill
babyx.root.reconcile
babyx.exec
babyx.shell
babyx.job.get
babyx.job.list
babyx.job.wait
babyx.job.reconcile
babyx.job.cancel
babyx.job.stream.read
babyx.file.stat
babyx.file.read
babyx.file.write
babyx.file.replace
babyx.file.patch
babyx.file.copy
babyx.file.move
babyx.file.remove
babyx.file.list
babyx.artifact.create
babyx.artifact.list
babyx.artifact.get
babyx.artifact.verify
babyx.systemd.describe
babyx.systemd.list
babyx.systemd.show
babyx.systemd.start
babyx.systemd.stop
babyx.systemd.restart
babyx.systemd.reload
babyx.systemd.enable
babyx.systemd.disable
babyx.systemd.mask
babyx.systemd.unmask
babyx.systemd.daemon-reload
babyx.systemd.reset-failed
babyx.systemd.kill
babyx.systemd.logs
babyx.systemd.run
babyx.systemd.raw
babyx.machine.describe
babyx.machine.list
babyx.machine.get
babyx.machine.create
babyx.machine.events
babyx.machine.start
babyx.machine.exec
babyx.machine.shell
babyx.machine.status
babyx.machine.reconcile
babyx.machine.expire
babyx.machine.gc
babyx.machine.diagnostics
babyx.machine.stop
babyx.machine.destroy
babyx.certification.describe
babyx.certification.run
babyx.certification.resume
babyx.certification.get
babyx.certification.list
babyx.certification.cleanup
babyx.execution.policy.describe
babyx.execution.policy.decide
babyx.race.describe
babyx.race.run
babyx.race.resume
babyx.race.get
babyx.race.list
babyx.trace.describe
babyx.trace.probes.list
babyx.trace.validate
babyx.trace.start
babyx.trace.get
babyx.trace.read
babyx.trace.stop
babyx.trace.snapshot
babyx.trace.recipe.list
babyx.trace.recipe.run
babyx.trace.raw
babyx.debug.describe
babyx.debug.attach
babyx.debug.get
babyx.debug.command
babyx.debug.batch
babyx.debug.threads
babyx.debug.backtrace
babyx.debug.registers
babyx.debug.memory.read
babyx.debug.memory.write
babyx.debug.breakpoint.set
babyx.debug.breakpoint.remove
babyx.debug.watchpoint.set
babyx.debug.core.create
babyx.debug.detach
babyx.debug.kill
babyx.debug.raw
babyx.checkpoint.describe
babyx.checkpoint.check
babyx.checkpoint.compatibility
babyx.checkpoint.create
babyx.checkpoint.pre-dump
babyx.checkpoint.list
babyx.checkpoint.get
babyx.checkpoint.inspect
babyx.checkpoint.restore
babyx.checkpoint.clone
babyx.checkpoint.export
babyx.checkpoint.import
babyx.checkpoint.remove
babyx.checkpoint.raw
babyx.packet.describe
babyx.packet.interfaces
babyx.packet.capture.start
babyx.packet.capture.get
babyx.packet.capture.stop
babyx.packet.capture.freeze
babyx.packet.capture.list
babyx.packet.decode
babyx.packet.follow
babyx.packet.statistics
babyx.packet.remove
babyx.packet.raw
babyx.syscall.describe
babyx.syscall.profile.create
babyx.syscall.profile.get
babyx.syscall.profile.list
babyx.syscall.profile.remove
babyx.syscall.supervisor.start
babyx.syscall.supervisor.get
babyx.syscall.events.read
babyx.syscall.respond
babyx.syscall.inject.error
babyx.syscall.inject.delay
babyx.syscall.inject.fd
babyx.syscall.delegate
babyx.syscall.continue
babyx.syscall.stop
babyx.syscall.raw
babyx.spec.describe
babyx.spec.scan
babyx.spec.observe
babyx.spec.generate
babyx.spec.get
babyx.spec.list
babyx.spec.diff
babyx.spec.validate
babyx.spec.promote
babyx.spec.reject
babyx.spec.falsify
babyx.spec.export
babyx.spec.remove
babyx.spec.raw
babyx.battleground.describe
babyx.campaign.create
babyx.campaign.get
babyx.campaign.list
babyx.campaign.start
babyx.campaign.step
babyx.campaign.pause
babyx.campaign.resume
babyx.campaign.cancel
babyx.campaign.remove
babyx.candidate.submit
babyx.candidate.get
babyx.candidate.list
babyx.candidate.build
babyx.candidate.verify
babyx.adversary.create
babyx.adversary.get
babyx.adversary.list
babyx.adversary.run
babyx.adversary.remove
babyx.adversary.raw
babyx.counterexample.create
babyx.counterexample.get
babyx.counterexample.list
babyx.counterexample.export
babyx.counterexample.replay
babyx.counterexample.remove
`.trim().split(/\s+/u);

const readSuffixes = new Set(['describe', 'health', 'get', 'list', 'read', 'events', 'status', 'inspect', 'logs', 'interfaces', 'statistics', 'compatibility', 'check', 'diff', 'validate', 'verify', 'registry', 'export', 'wait']);
const durableFamilies = new Set(['machine', 'certification', 'race', 'root', 'transaction']);
const highRiskFamilies = new Set(['systemd', 'machine', 'debug', 'checkpoint', 'syscall']);
const conditionalFileSuffixes = new Set(['write', 'replace', 'patch', 'copy', 'move', 'remove']);

const stringValue = { type: 'string', minLength: 1, maxLength: 65_536 } as const;
const identifier = { type: 'string', minLength: 1, maxLength: 256, pattern: '^[A-Za-z0-9][A-Za-z0-9._:-]*$' } as const;
const nonNegativeInteger = { type: 'integer', minimum: 0, maximum: 67_108_864 } as const;
const positiveInteger = { type: 'integer', minimum: 1, maximum: 67_108_864 } as const;
const stringArray = { type: 'array', maxItems: 4_096, items: { type: 'string', maxLength: 65_536 } } as const;
const jsonObject = { type: 'object', additionalProperties: true } as const;

const commonProperties: Record<string, unknown> = {
  id: identifier,
  jobId: identifier,
  name: stringValue,
  path: stringValue,
  sourcePath: stringValue,
  source: stringValue,
  destination: stringValue,
  data: { type: 'string', maxLength: 22_369_624 },
  encoding: { enum: ['base64', 'utf8'] },
  offset: nonNegativeInteger,
  limit: nonNegativeInteger,
  maxEntries: { type: 'integer', minimum: 1, maximum: 10_000 },
  maxDepth: { type: 'integer', minimum: 0, maximum: 64 },
  recursive: { type: 'boolean' },
  overwrite: { type: 'boolean' },
  create: { type: 'boolean' },
  expectedSha256: { type: 'string', pattern: '^[a-f0-9]{64}$' },
  patches: { type: 'array', minItems: 1, maxItems: 1_024, items: jsonObject },
  argv: stringArray,
  cwd: stringValue,
  env: jsonObject,
  target: jsonObject,
  timeoutMs: { type: 'integer', minimum: 1, maximum: 86_400_000 },
  shell: stringValue,
  script: stringValue,
  command: stringValue,
  signal: { type: 'string', minLength: 1, maxLength: 32 },
  stream: { enum: ['stdout', 'stderr'] },
  status: stringValue,
  tool: stringValue,
  unit: stringValue,
  machine: stringValue,
  properties: stringArray,
  metadata: jsonObject,
  subject: stringValue,
  predicate: stringValue,
  value: {},
  statement: jsonObject,
  left: {},
  right: {},
  counterexamples: { type: 'array', maxItems: 10_000, items: { type: 'string', maxLength: 256 } },
  result: {},
  profile: stringValue,
  ownerPrincipal: stringValue,
  idempotencyKey: identifier,
  requestDigest: { type: 'string', pattern: '^[a-f0-9]{64}$' },
};

function objectSchema(properties: Record<string, unknown>, required: readonly string[] = [], extras: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: 'object',
    additionalProperties: false,
    properties,
    ...(required.length === 0 ? {} : { required }),
    ...extras,
  };
}

function rootSchema(operation: string): Record<string, unknown> {
  const digest = { type: 'string', pattern: '^[a-f0-9]{64}$' } as const;
  const gitIdentity = { type: 'string', pattern: '^(?:[a-f0-9]{40}|[a-f0-9]{64})$' } as const;
  const transactionId = { type: 'string', pattern: '^rtx_[a-f0-9]{32}$' } as const;
  const expectedSequence = { type: 'integer', minimum: 1, maximum: 10_000_000 } as const;
  const page = { offset: { type: 'integer', minimum: 0, maximum: 10_000_000 }, limit: { type: 'integer', minimum: 1, maximum: 1_000 } } as const;
  if (operation === 'babyx.root.describe') return objectSchema({});
  if (operation === 'babyx.root.transaction.create') return objectSchema({
    source: objectSchema({ repository: stringValue, branch: stringValue, commit: gitIdentity, tree: gitIdentity }, ['repository', 'branch', 'commit', 'tree']),
    intent: objectSchema({ purpose: stringValue, mutationDigest: digest, targetDigest: digest, rollbackDigest: digest, requiredAuthorities: stringArray, requiredVerifications: stringArray }, ['purpose', 'mutationDigest', 'targetDigest', 'rollbackDigest', 'requiredAuthorities', 'requiredVerifications']),
  }, ['source', 'intent']);
  if (operation === 'babyx.root.transaction.get' || operation === 'babyx.root.transaction.verify') return objectSchema({ transactionId }, ['transactionId']);
  if (operation === 'babyx.root.transaction.list') return objectSchema({ state: stringValue, ownerPrincipal: identifier, ...page });
  if (operation === 'babyx.root.transaction.events') return objectSchema({ transactionId, ...page }, ['transactionId']);
  if (operation === 'babyx.root.transaction.authorize') return objectSchema({ transactionId, expectedSequence, decisionDigest: digest, expiresAt: stringValue }, ['transactionId', 'expectedSequence', 'decisionDigest', 'expiresAt']);
  if (operation === 'babyx.root.transaction.begin') return objectSchema({ transactionId, expectedSequence }, ['transactionId', 'expectedSequence']);
  if (operation === 'babyx.root.transaction.observe') return objectSchema({ transactionId, expectedSequence, phase: { enum: ['execution', 'verification', 'rollback'] }, status: { enum: ['succeeded', 'failed', 'ambiguous'] }, authority: identifier, reference: stringValue, observationDigest: digest }, ['transactionId', 'expectedSequence', 'phase', 'status', 'authority', 'reference', 'observationDigest']);
  if (operation === 'babyx.root.transaction.commit') return objectSchema({ transactionId, expectedSequence, commitDigest: digest, verificationDigest: digest }, ['transactionId', 'expectedSequence', 'commitDigest', 'verificationDigest']);
  if (operation === 'babyx.root.transaction.rollback') return objectSchema({ transactionId, expectedSequence, rollbackDigest: digest, reasonDigest: digest }, ['transactionId', 'expectedSequence', 'rollbackDigest', 'reasonDigest']);

  const effectTransactionId = { type: 'string', pattern: '^rfx_[a-f0-9]{32}$' } as const;
  const leaseId = { type: 'string', pattern: '^crl_[a-f0-9]{32}$' } as const;
  const sessionId = { type: 'string', pattern: '^obs_[a-f0-9]{32}$' } as const;
  const fencingToken = { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER } as const;
  const recoveryControl = objectSchema({ transactionId: effectTransactionId, expectedSequence, fencingToken }, ['transactionId', 'expectedSequence', 'fencingToken']);
  const effectPage = { offset: { type: 'integer', minimum: 0, maximum: 10_000_000 }, limit: { type: 'integer', minimum: 1, maximum: 200 } } as const;
  const strictJsonObject = { type: 'object', additionalProperties: true } as const;
  const boundedSmallStrings = { type: 'array', maxItems: 256, items: { type: 'string', maxLength: 4_096 } } as const;
  if (operation === 'babyx.root.compatibility.get' || operation === 'babyx.root.effect.registry') return objectSchema({});
  if (operation === 'babyx.root.effect.create') return objectSchema({ source: strictJsonObject, skill: strictJsonObject, deadline: stringValue, atomicityMode: { enum: ['ATOMIC_WITHIN_PROVIDER', 'SAGA', 'IRREVERSIBLE'] }, plan: strictJsonObject, policy: strictJsonObject, requestedProvider: { enum: ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE', null] }, riskClass: identifier, environmentDigest: digest }, ['source', 'skill', 'deadline', 'atomicityMode', 'plan', 'policy', 'riskClass', 'environmentDigest']);
  if (operation === 'babyx.root.effect.get') return objectSchema({ transactionId: effectTransactionId }, ['transactionId']);
  if (operation === 'babyx.root.effect.list') return objectSchema({ state: stringValue, ownerPrincipal: identifier, ...effectPage });
  if (operation === 'babyx.root.effect.events') return objectSchema({ transactionId: effectTransactionId, ...effectPage }, ['transactionId']);
  if (operation === 'babyx.root.effect.lease.acquire') return objectSchema({ transactionId: effectTransactionId, expectedSequence, controllerId: identifier, ttlMs: { type: 'integer', minimum: 1_000, maximum: 300_000 }, takeoverReason: stringValue }, ['transactionId', 'expectedSequence', 'controllerId', 'ttlMs']);
  if (operation === 'babyx.root.effect.authorize') return objectSchema({ transactionId: effectTransactionId, expectedSequence, fencingToken, decisionDigest: digest, expiresAt: stringValue, executionProvider: { enum: ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'] }, providerId: identifier, providerVersion: stringValue, providerContractVersion: stringValue, providerProfileDigest: digest }, ['transactionId', 'expectedSequence', 'fencingToken', 'decisionDigest', 'expiresAt', 'executionProvider', 'providerId', 'providerVersion', 'providerContractVersion', 'providerProfileDigest']);
  if (operation === 'babyx.root.effect.prepare') return objectSchema({ transactionId: effectTransactionId, expectedSequence, fencingToken, priorStateDigest: digest, artifactIds: boundedSmallStrings, snapshotReferences: boundedSmallStrings, rollbackReady: { type: 'boolean' }, compensationReady: { type: 'boolean' } }, ['transactionId', 'expectedSequence', 'fencingToken', 'priorStateDigest', 'rollbackReady', 'compensationReady']);
  if (operation === 'babyx.root.effect.begin') return objectSchema({ transactionId: effectTransactionId, expectedSequence, fencingToken, activeJobIds: boundedSmallStrings, allJobIds: boundedSmallStrings, activeMachineIds: boundedSmallStrings, allMachineIds: boundedSmallStrings, unitNames: boundedSmallStrings, processIdentities: { type: 'array', maxItems: 256, items: strictJsonObject }, providerAttempts: { type: 'array', maxItems: 256, items: strictJsonObject } }, ['transactionId', 'expectedSequence', 'fencingToken']);
  if (operation === 'babyx.root.effect.validate') return objectSchema({ transactionId: effectTransactionId, expectedSequence, fencingToken, specification: strictJsonObject, validatorVersion: stringValue, expectedState: {}, observedState: {}, attempts: { type: 'integer', minimum: 1, maximum: 1_000 }, result: { enum: ['SUCCEEDED', 'FAILED', 'AMBIGUOUS'] }, resultDigest: digest, failureReason: { anyOf: [{ type: 'null' }, stringValue] }, executionTerminal: { type: 'boolean' } }, ['transactionId', 'expectedSequence', 'fencingToken', 'specification', 'validatorVersion', 'attempts', 'result', 'resultDigest', 'executionTerminal']);
  if (operation === 'babyx.root.effect.commit') return objectSchema({ transactionId: effectTransactionId, expectedSequence, fencingToken, cleanupComplete: { type: 'boolean' }, finalResultDigest: digest }, ['transactionId', 'expectedSequence', 'fencingToken', 'cleanupComplete', 'finalResultDigest']);
  if (operation === 'babyx.root.effect.cancel') return objectSchema({ transactionId: effectTransactionId, expectedSequence, fencingToken, reason: stringValue }, ['transactionId', 'expectedSequence', 'fencingToken', 'reason']);
  if (operation === 'babyx.root.effect.rollback') return objectSchema({ transactionId: effectTransactionId, expectedSequence, fencingToken, phase: { enum: ['request', 'begin', 'complete'] }, reason: stringValue, restoredStateDigest: { anyOf: [{ type: 'null' }, digest] }, result: stringValue, unresolvedEffects: boundedSmallStrings }, ['transactionId', 'expectedSequence', 'fencingToken', 'phase']);
  if (operation === 'babyx.root.effect.compensate') return objectSchema({ transactionId: effectTransactionId, expectedSequence, fencingToken, phase: { enum: ['begin', 'complete'] }, reason: stringValue, result: stringValue, residualDifferences: boundedSmallStrings }, ['transactionId', 'expectedSequence', 'fencingToken', 'phase']);
  if (operation === 'babyx.root.effect.clean') return objectSchema({ transactionId: effectTransactionId, expectedSequence, fencingToken, completed: { type: 'boolean' }, terminalState: { enum: ['FAILED', 'ROLLED_BACK', 'COMPENSATED'] }, unitRemoved: { type: 'boolean' }, cgroupEmpty: { type: 'boolean' }, processAbsent: { type: 'boolean' }, machineAbsent: { type: 'boolean' }, mountAbsent: { type: 'boolean' }, temporaryPathAbsent: { type: 'boolean' }, credentialPathAbsent: { type: 'boolean' }, observerStopped: { type: 'boolean' }, sourcePreserved: { type: 'boolean' } }, ['transactionId', 'expectedSequence', 'fencingToken', 'completed']);
  if (operation === 'babyx.root.effect.repair') return objectSchema({ transactionId: effectTransactionId, expectedSequence, fencingToken, nextState: { enum: ['ROLLBACK_REQUESTED', 'CLEANING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'] }, reason: stringValue }, ['transactionId', 'expectedSequence', 'fencingToken', 'nextState', 'reason']);
  if (operation === 'babyx.root.bundle.verify' || operation === 'babyx.root.bundle.install') return objectSchema({ manifest: strictJsonObject, signature: stringValue }, ['manifest', 'signature']);
  if (operation === 'babyx.root.bundle.get') return objectSchema({ bundleDigest: digest }, ['bundleDigest']);
  if (operation === 'babyx.root.bundle.list') return objectSchema({ state: stringValue, ...effectPage });
  if (operation === 'babyx.root.bundle.revoke') return objectSchema({ bundleDigest: digest, reason: stringValue }, ['bundleDigest', 'reason']);
  if (operation === 'babyx.root.grant.install') return objectSchema({ grant: strictJsonObject }, ['grant']);
  if (operation === 'babyx.root.grant.get') return objectSchema({ grantId: identifier }, ['grantId']);
  if (operation === 'babyx.root.grant.list') return objectSchema({ state: stringValue, ownerPrincipal: identifier, ...effectPage });
  if (operation === 'babyx.root.observation.start') return objectSchema({ transactionId: effectTransactionId, stepId: identifier, requiredKinds: boundedSmallStrings, requiredSources: boundedSmallStrings, fallbackSources: boundedSmallStrings, maxEvents: { type: 'integer', minimum: 1, maximum: 100_000 }, maxBytes: { type: 'integer', minimum: 1_024, maximum: 67_108_864 }, maxDurationMs: { type: 'integer', minimum: 1_000, maximum: 3_600_000 } }, ['transactionId', 'stepId', 'requiredKinds', 'requiredSources']);
  if (operation === 'babyx.root.observation.get') return objectSchema({ sessionId, ...effectPage }, ['sessionId']);
  if (operation === 'babyx.root.observation.record') return objectSchema({ sessionId, transactionId: effectTransactionId, stepId: identifier, kind: identifier, source: identifier, occurredAt: stringValue, cgroupId: { anyOf: [{ type: 'null' }, stringValue] }, unitName: { anyOf: [{ type: 'null' }, identifier] }, machineId: { anyOf: [{ type: 'null' }, identifier] }, processId: { anyOf: [{ type: 'null' }, positiveInteger] }, processStartTime: { anyOf: [{ type: 'null' }, stringValue] }, bootId: { anyOf: [{ type: 'null' }, identifier] }, data: strictJsonObject }, ['sessionId', 'transactionId', 'stepId', 'kind', 'source', 'data']);
  if (operation === 'babyx.root.observation.finalize') return objectSchema({ sessionId, sourceStatus: strictJsonObject, spill: { type: 'boolean' } }, ['sessionId', 'sourceStatus']);
  if (operation === 'babyx.root.credential.lease') return objectSchema({ credentialReference: stringValue, transactionId: effectTransactionId, stepId: identifier, requestedTtlMs: { type: 'integer', minimum: 1_000, maximum: 3_600_000 } }, ['credentialReference', 'transactionId', 'stepId']);
  if (operation === 'babyx.root.credential.deliver') return objectSchema({ leaseId }, ['leaseId']);
  if (operation === 'babyx.root.credential.get') return objectSchema({ leaseId }, ['leaseId']);
  if (operation === 'babyx.root.credential.list') return objectSchema({ state: stringValue, transactionId: effectTransactionId, ...effectPage });
  if (operation === 'babyx.root.credential.revoke' || operation === 'babyx.root.credential.clean') return objectSchema({ leaseId, reason: stringValue }, ['leaseId', 'reason']);
  if (operation === 'babyx.root.freeze.get') return objectSchema({ scope: stringValue, selector: stringValue, ...effectPage });
  if (operation === 'babyx.root.freeze.set') return objectSchema({ scope: { enum: ['GLOBAL', 'PRINCIPAL', 'SKILL', 'BUNDLE', 'GRANT', 'TRANSACTION', 'PROVIDER', 'CREDENTIAL_ISSUANCE', 'NEW_EXECUTION'] }, selector: stringValue, active: { type: 'boolean' }, reason: stringValue, expiresAt: { anyOf: [{ type: 'null' }, stringValue] } }, ['scope', 'selector', 'active', 'reason']);
  if (operation === 'babyx.root.kill') return objectSchema({ scope: { enum: ['TRANSACTION', 'SKILL', 'ALL'] }, selector: stringValue, reason: stringValue, transactions: { type: 'array', minItems: 1, maxItems: 4_096, items: recoveryControl } }, ['scope', 'selector', 'reason', 'transactions']);
  if (operation === 'babyx.root.reconcile') return recoveryControl;
  if (operation === 'babyx.root.grant.revoke') return objectSchema({ grantId: identifier, reason: stringValue }, ['grantId', 'reason']);
  throw new Error(`missing root operation schema: ${operation}`);
}

function schemaFor(operation: string): Record<string, unknown> {
  if (operation.startsWith('babyx.transaction.')) {
    const schema = transactionInputSchemas[operation];
    if (schema === undefined) throw new Error(`missing transaction operation schema: ${operation}`);
    return schema;
  }
  if (operation === 'babyx.core.compatibility') return objectSchema({});
  if (operation.startsWith('babyx.root.')) return rootSchema(operation);
  if (operation === 'babyx.describe' || operation === 'babyx.health' || operation.endsWith('.describe')) return objectSchema({});
  if (operation === 'babyx.exec') return objectSchema({ argv: stringArray, cwd: stringValue, env: jsonObject, target: jsonObject, timeoutMs: positiveInteger }, ['argv']);
  if (operation === 'babyx.shell') return objectSchema({ shell: stringValue, command: stringValue, script: stringValue, cwd: stringValue, env: jsonObject, target: jsonObject, timeoutMs: positiveInteger }, [], { anyOf: [{ required: ['command'] }, { required: ['script'] }] });
  if (operation === 'babyx.job.list') return objectSchema({ status: stringValue, limit: { type: 'integer', minimum: 1, maximum: 10_000 } });
  if (operation === 'babyx.job.get' || operation === 'babyx.job.reconcile') return objectSchema({ jobId: identifier }, ['jobId']);
  if (operation === 'babyx.job.wait') return objectSchema({ jobId: identifier, timeoutMs: { type: 'integer', minimum: 0, maximum: 300_000 } }, ['jobId']);
  if (operation === 'babyx.job.cancel') return objectSchema({ jobId: identifier, signal: commonProperties.signal }, ['jobId']);
  if (operation === 'babyx.job.stream.read') return objectSchema({ jobId: identifier, stream: commonProperties.stream, offset: nonNegativeInteger, limit: { type: 'integer', minimum: 0, maximum: 65_536 } }, ['jobId', 'stream']);
  if (operation === 'babyx.file.stat') return objectSchema({ path: stringValue }, ['path']);
  if (operation === 'babyx.file.read') return objectSchema({ path: stringValue, offset: nonNegativeInteger, limit: { type: 'integer', minimum: 0, maximum: 65_536 }, encoding: commonProperties.encoding }, ['path']);
  if (operation === 'babyx.file.write') return objectSchema({ path: stringValue, data: commonProperties.data, encoding: commonProperties.encoding, offset: nonNegativeInteger, create: commonProperties.create }, ['path', 'data']);
  if (operation === 'babyx.file.replace') return objectSchema({ path: stringValue, data: commonProperties.data, encoding: commonProperties.encoding, expectedSha256: commonProperties.expectedSha256 }, ['path', 'data']);
  if (operation === 'babyx.file.patch') return objectSchema({ path: stringValue, expectedSha256: commonProperties.expectedSha256, patches: commonProperties.patches }, ['path', 'expectedSha256', 'patches']);
  if (operation === 'babyx.file.copy') return objectSchema({ source: stringValue, destination: stringValue, overwrite: commonProperties.overwrite }, ['source', 'destination']);
  if (operation === 'babyx.file.move') return objectSchema({ source: stringValue, destination: stringValue }, ['source', 'destination']);
  if (operation === 'babyx.file.remove') return objectSchema({ path: stringValue, recursive: commonProperties.recursive }, ['path']);
  if (operation === 'babyx.file.list') return objectSchema({ path: stringValue, maxEntries: commonProperties.maxEntries, maxDepth: commonProperties.maxDepth, recursive: commonProperties.recursive }, ['path']);
  if (operation === 'babyx.artifact.create') return objectSchema({ name: stringValue, sourcePath: stringValue, metadata: jsonObject }, ['name', 'sourcePath']);
  if (operation === 'babyx.artifact.get' || operation === 'babyx.artifact.verify') return objectSchema({ id: identifier }, ['id']);
  if (operation === 'babyx.artifact.list') return objectSchema({ offset: nonNegativeInteger, limit: { type: 'integer', minimum: 1, maximum: 1_000 } });
  if (['babyx.spec.list', 'babyx.campaign.list', 'babyx.candidate.list', 'babyx.adversary.list', 'babyx.counterexample.list'].includes(operation)) return objectSchema({ offset: nonNegativeInteger, limit: { type: 'integer', minimum: 1, maximum: 1_000 } });
  if (operation === 'babyx.spec.validate') return objectSchema({ statement: jsonObject }, ['statement']);
  if (operation === 'babyx.spec.diff') return objectSchema({ left: {}, right: {} }, ['left', 'right']);
  if (operation.endsWith('.raw')) return objectSchema({ tool: stringValue, argv: stringArray, cwd: stringValue, env: jsonObject, target: jsonObject, timeoutMs: positiveInteger }, ['tool']);
  const suffix = operation.split('.').at(-1) ?? '';
  const required = ['get', 'remove', 'reject', 'promote', 'falsify'].includes(suffix) ? ['id'] : [];
  return objectSchema(commonProperties, required);
}

const transactionIdProperty = { type: 'string', pattern: '^tx_[a-z0-9][a-z0-9_-]{11,124}$' };
const expectedSequenceProperty = { type: 'integer', minimum: 1 };
const transactionMutationInput = {
  type: 'object', additionalProperties: false,
  properties: { transactionId: transactionIdProperty, expectedSequence: expectedSequenceProperty, reason: { type: 'string', maxLength: 4096 } },
  required: ['transactionId', 'expectedSequence'],
};
const transactionInputSchemas: Record<string, Record<string, unknown>> = {
  'babyx.transaction.create': {
    type: 'object', additionalProperties: false,
    properties: {
      schemaVersion: { const: '1.0.0' },
      transactionKind: { enum: ['CODE_MUTATION'] },
      repository: { type: 'string', minLength: 1, maxLength: 1024 },
      branch: { type: 'string', minLength: 1, maxLength: 1024 },
      commit: { type: 'string', pattern: '^[a-f0-9]{40,64}$' },
      tree: { type: 'string', pattern: '^[a-f0-9]{40,64}$' },
      sourceArchiveArtifactId: { type: 'string', minLength: 1, maxLength: 256 },
      immutableSourceReference: { type: 'string', minLength: 1, maxLength: 2048 },
      sourceManifestDigest: { type: 'string', pattern: '^[a-f0-9]{64}$' },
      packageLockDigest: { type: 'string', pattern: '^[a-f0-9]{64}$' },
      protectedSnapshot: { type: 'string', minLength: 1, maxLength: 256 },
      expectedSnapshotGuid: { type: 'string', minLength: 1, maxLength: 64 },
      snapshotCreationTxg: { type: 'string', minLength: 1, maxLength: 64 },
      policyDecisionDigest: { type: 'string', pattern: '^[a-f0-9]{64}$' },
      selectedEnvironmentClass: { enum: ['disposable', 'parallel-disposable'] },
      providerId: { type: 'string', minLength: 1, maxLength: 256 },
      providerVersion: { type: 'string', minLength: 1, maxLength: 128 },
      networkMode: { const: 'none' },
      resourceBoundIdentity: {
        type: 'object', additionalProperties: false,
        properties: {
          machineName: { type: 'string', minLength: 1, maxLength: 256 },
          cloneDataset: { type: 'string', minLength: 1, maxLength: 256 },
          mountpoint: { type: 'string', minLength: 2, maxLength: 4096 },
          expectedRootPrefix: { type: 'string', minLength: 2, maxLength: 4096 },
        },
        required: ['machineName', 'cloneDataset', 'mountpoint', 'expectedRootPrefix'],
      },
      normalizedEnvironment: {
        type: 'array', maxItems: 1000,
        items: { type: 'object', additionalProperties: false, properties: { name: { type: 'string', minLength: 1, maxLength: 128 }, value: { type: 'string', maxLength: 4096 } }, required: ['name', 'value'] },
      },
      credentialReferenceIds: { type: 'array', maxItems: 1000, uniqueItems: true, items: { type: 'string', minLength: 1, maxLength: 4096 } },
      credentialPresence: { type: 'boolean' },
    },
    required: ['schemaVersion', 'transactionKind', 'repository', 'commit', 'tree', 'immutableSourceReference', 'sourceManifestDigest', 'protectedSnapshot', 'expectedSnapshotGuid', 'snapshotCreationTxg', 'policyDecisionDigest', 'selectedEnvironmentClass', 'providerId', 'providerVersion', 'networkMode', 'resourceBoundIdentity'],
  },
  'babyx.transaction.get': { type: 'object', additionalProperties: false, properties: { transactionId: transactionIdProperty }, required: ['transactionId'] },
  'babyx.transaction.list': { type: 'object', additionalProperties: false, properties: { ownerPrincipal: { type: 'string', minLength: 1, maxLength: 512 }, state: { type: 'string' }, terminal: { type: 'boolean' }, offset: { type: 'integer', minimum: 0 }, limit: { type: 'integer', minimum: 0, maximum: 1000 } } },
  'babyx.transaction.events': { type: 'object', additionalProperties: false, properties: { transactionId: transactionIdProperty, offset: { type: 'integer', minimum: 0 }, limit: { type: 'integer', minimum: 0, maximum: 1000 } }, required: ['transactionId'] },
  'babyx.transaction.status': { type: 'object', additionalProperties: false, properties: { transactionId: transactionIdProperty }, required: ['transactionId'] },
  'babyx.transaction.execute': transactionMutationInput,
  'babyx.transaction.validate': transactionMutationInput,
  'babyx.transaction.finalize': transactionMutationInput,
  'babyx.transaction.rollback': transactionMutationInput,
  'babyx.transaction.reconcile': transactionMutationInput,
  'babyx.transaction.expire': transactionMutationInput,
  'babyx.transaction.gc': { type: 'object', additionalProperties: false, properties: { dryRun: { type: 'boolean' }, ownerPrincipal: { type: 'string', minLength: 1, maxLength: 512 }, state: { type: 'string' }, offset: { type: 'integer', minimum: 0 }, limit: { type: 'integer', minimum: 0, maximum: 1000 } } },
};

function familyOf(operation: string): string {
  return operation.split('.')[1] ?? 'core';
}

function isMutation(operation: string): boolean {
  if (operation.startsWith('babyx.transaction.')) {
    const suffix = operation.split('.').at(-1) ?? operation;
    return !['get', 'list', 'events', 'status'].includes(suffix);
  }
  if (operation === 'babyx.execution.policy.decide' || operation === 'babyx.spec.export' || operation === 'babyx.counterexample.export') return false;
  const suffix = operation.split('.').at(-1) ?? operation;
  return !readSuffixes.has(suffix);
}

function riskFor(operation: string, mutation: boolean): OperationRisk {
  if (!mutation) return 'low';
  const family = familyOf(operation);
  if (operation.endsWith('.raw') || highRiskFamilies.has(family) || operation === 'babyx.file.remove' || operation === 'babyx.file.move') return 'high';
  return 'medium';
}

function idempotencyFor(operation: string, mutation: boolean): OperationIdempotency {
  if (!mutation) return 'read_only';
  const family = familyOf(operation);
  const suffix = operation.split('.').at(-1) ?? '';
  if (durableFamilies.has(family)) return 'caller_key';
  if (family === 'file' && conditionalFileSuffixes.has(suffix)) return 'conditional';
  return 'non_idempotent';
}

function errorsFor(operation: string): readonly string[] {
  const errors = ['invalid_request', 'operation_failed'];
  const family = familyOf(operation);
  if (durableFamilies.has(family)) errors.push('idempotency_conflict', 'state_conflict', 'resource_unavailable', 'ambiguous');
  if (family === 'file') errors.push('compare_and_swap_mismatch', 'resource_unavailable');
  if (operation.endsWith('.raw')) errors.push('tool_unavailable');
  return errors;
}

function restartFor(operation: string, mutation: boolean): string {
  if (!mutation) return 'read_only';
  if (durableFamilies.has(familyOf(operation))) return 'durable_reconcile';
  return 'retry_requires_external_observation';
}

function cancellationFor(operation: string, mutation: boolean): string {
  if (!mutation) return 'not_applicable';
  if (durableFamilies.has(familyOf(operation))) return 'durable_reconcile';
  return 'not_supported_after_dispatch';
}

function postconditionsFor(operation: string, mutation: boolean): readonly string[] {
  if (!mutation) return ['result_is_bounded'];
  const family = familyOf(operation);
  if (family === 'machine') return ['authoritative_machine_record_persisted', 'observed_state_reported'];
  if (family === 'certification' || family === 'race') return ['durable_record_persisted', 'evidence_references_reported'];
  if (family === 'root') {
    if (operation.startsWith('babyx.root.effect.')) return ['authoritative_transaction_record_persisted', 'digest_chained_event_appended'];
    if (operation === 'babyx.root.observation.start' || operation === 'babyx.root.observation.record' || operation === 'babyx.root.observation.finalize') return ['transaction_bound_observation_record_persisted', 'observation_event_chain_verified'];
    if (operation.startsWith('babyx.root.credential.')) return ['transaction_bound_credential_record_persisted', 'credential_event_chain_verified'];
    if (operation === 'babyx.root.freeze.set') return ['freeze_record_persisted', 'freeze_event_head_verified'];
    if (operation === 'babyx.root.kill') return ['durable_kill_record_persisted', 'fenced_transaction_transition_reported', 'positive_absence_verification_reported'];
    if (operation === 'babyx.root.reconcile') return ['reconciliation_record_persisted', 'fenced_transaction_transition_reported'];
    if (operation.startsWith('babyx.root.bundle.') || operation.startsWith('babyx.root.grant.')) return ['trust_record_persisted'];
    return ['durable_root_record_persisted'];
  }
  if (family === 'file') return ['resulting_file_metadata_reported'];
  if (family === 'artifact') return ['artifact_digest_and_metadata_reported'];
  return ['command_result_reported'];
}

export const OPERATION_CATALOG_VERSION = '3.6.0';

export const OPERATION_DEFINITIONS: readonly OperationDefinition[] = operations.map((operation) => {
  const mutation = isMutation(operation);
  const family = familyOf(operation);
  return {
    operation,
    family,
    version: '1.0.0',
    description: `Baby-X owner-authorized ${operation.slice('babyx.'.length)} operation.`,
    mutation,
    risk: riskFor(operation, mutation),
    idempotency: idempotencyFor(operation, mutation),
    errors: errorsFor(operation),
    cancellation: cancellationFor(operation, mutation),
    restartBehavior: restartFor(operation, mutation),
    postActionVerification: durableFamilies.has(family) || family === 'file' || family === 'artifact',
    postconditions: postconditionsFor(operation, mutation),
    receiptVersion: '1.0.0',
    limits: { maxFrameBytes: 16_777_216, maxInlineResultBytes: 65_536 },
    authority: { class: 'unrestricted-owner', provider: 'baby-x-runtime' },
    input: schemaFor(operation),
    output: { type: 'object', additionalProperties: true },
  };
});

export const OPERATION_NAMES = new Set(OPERATION_DEFINITIONS.map((definition) => definition.operation));
export const OPERATION_BY_NAME = new Map(OPERATION_DEFINITIONS.map((definition) => [definition.operation, definition] as const));
