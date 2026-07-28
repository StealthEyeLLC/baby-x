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
babyx.root.describe
babyx.root.platform.describe
babyx.root.provider.list
babyx.root.provider.get
babyx.root.provider.reconcile
babyx.root.mediation.profile.create
babyx.root.mediation.profile.get
babyx.root.mediation.profile.list
babyx.root.mediation.profile.revoke
babyx.root.mediation.events
babyx.root.microvm.create
babyx.root.microvm.get
babyx.root.microvm.list
babyx.root.microvm.exec
babyx.root.microvm.stop
babyx.root.microvm.remove
babyx.root.microvm.snapshot
babyx.root.microvm.restore
babyx.root.microvm.pool.reconcile
babyx.root.attestation.challenge
babyx.root.attestation.verify
babyx.root.attestation.get
babyx.root.identity.issue
babyx.root.identity.get
babyx.root.identity.revoke
babyx.root.secret.lease
babyx.root.secret.revoke
babyx.root.bundle.resolve
babyx.root.bundle.verify
babyx.root.bundle.cache
babyx.root.provenance.verify
babyx.root.transparency.verify
babyx.root.transparency.status
babyx.root.checkpoint.create
babyx.root.checkpoint.get
babyx.root.checkpoint.restore
babyx.root.replay.run
babyx.root.replay.get
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

const readSuffixes = new Set(['describe', 'health', 'get', 'list', 'read', 'events', 'status', 'inspect', 'logs', 'interfaces', 'statistics', 'compatibility', 'check', 'diff', 'validate', 'export', 'wait']);
const durableFamilies = new Set(['machine', 'certification', 'race', 'root']);
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
  if (operation === 'babyx.root.describe' || operation === 'babyx.root.platform.describe') return objectSchema({});
  const providerId = { type: 'string', pattern: '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$' } as const;
  if (operation === 'babyx.root.provider.list') return objectSchema({ family: providerId, supportState: { enum: ['SUPPORTED', 'DEGRADED', 'UNAVAILABLE', 'EXPERIMENTAL', 'DISABLED', 'REVOKED', 'FAILED'] }, ...page });
  if (operation === 'babyx.root.provider.get' || operation === 'babyx.root.provider.reconcile') return objectSchema({ providerId }, ['providerId']);
  const mediationProfileId = { type: 'string', pattern: '^mpf_[a-f0-9]{32}$' } as const;
  const mediationSyscall = { type: 'string', pattern: '^[a-z0-9_]{1,64}$' } as const;
  const mediationProfile = objectSchema({
    version: { type: 'string', pattern: '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$' },
    skillBundleDigest: digest,
    grantDigest: digest,
    providerScope: { type: 'array', minItems: 1, maxItems: 4, uniqueItems: true, items: { enum: ['SECCOMP_FILTER', 'SECCOMP_NOTIFY', 'LANDLOCK', 'BPF_LSM'] } },
    architecture: { enum: ['x86_64', 'aarch64'] },
    defaultAction: objectSchema({ kind: { enum: ['allow', 'errno', 'kill'] }, errno: { type: ['integer', 'null'], minimum: 1, maximum: 4095 } }, ['kind']),
    allowedSyscalls: { type: 'array', maxItems: 128, uniqueItems: true, items: mediationSyscall },
    deniedSyscalls: { type: 'array', maxItems: 128, items: objectSchema({ syscall: mediationSyscall, action: { enum: ['errno', 'kill'] }, errno: { type: ['integer', 'null'], minimum: 1, maximum: 4095 } }, ['syscall', 'action']) },
    notifiedSyscalls: { type: 'array', maxItems: 128, items: objectSchema({ syscall: mediationSyscall, decision: { enum: ['allow', 'deny', 'emulate'] }, errno: { type: ['integer', 'null'], minimum: 1, maximum: 4095 }, value: { type: ['integer', 'null'], minimum: 0, maximum: Number.MAX_SAFE_INTEGER } }, ['syscall', 'decision']) },
    argumentConstraints: { type: 'array', maxItems: 128, items: objectSchema({ syscall: mediationSyscall, index: { type: 'integer', minimum: 0, maximum: 5 }, value: { type: 'integer', minimum: 0, maximum: Number.MAX_SAFE_INTEGER } }, ['syscall', 'index', 'value']) },
    pathConstraints: { type: 'array', maxItems: 64, items: objectSchema({ path: stringValue, access: { enum: ['read', 'write'] } }, ['path', 'access']) },
    socketConstraints: { type: 'array', maxItems: 64, items: objectSchema({ protocol: { enum: ['tcp'] }, action: { enum: ['bind', 'connect'] }, port: { type: 'integer', minimum: 0, maximum: 65535 } }, ['protocol', 'action', 'port']) },
    bpfRules: objectSchema({ mode: { enum: ['observe', 'enforce'] }, hooks: { type: 'array', maxItems: 32, uniqueItems: true, items: stringValue } }, ['mode', 'hooks']),
    expiresAt: stringValue,
  }, ['version', 'skillBundleDigest', 'grantDigest', 'providerScope', 'architecture', 'expiresAt']);
  if (operation === 'babyx.root.mediation.profile.create') return objectSchema({ profile: mediationProfile }, ['profile']);
  if (operation === 'babyx.root.mediation.profile.get') return objectSchema({ profileId: mediationProfileId }, ['profileId']);
  if (operation === 'babyx.root.mediation.profile.list') return objectSchema({ ownerPrincipal: identifier, status: { enum: ['ACTIVE', 'REVOKED', 'EXPIRED'] }, ...page });
  if (operation === 'babyx.root.mediation.profile.revoke') return objectSchema({ profileId: mediationProfileId, expectedSequence, reasonDigest: digest }, ['profileId', 'expectedSequence', 'reasonDigest']);
  if (operation === 'babyx.root.mediation.events') return objectSchema({ profileId: mediationProfileId, ...page }, ['profileId']);
  const microvmId = { type: 'string', pattern: '^mvm_[a-f0-9]{32}$' } as const;
  const microvmTransactionId = { type: 'string', pattern: '^rtx_[A-Za-z0-9_-]{8,128}$' } as const;
  const microvmLifecycle = { enum: ['REQUESTED','PREPARING','STARTING','BOOTING','READY','RUNNING','STOPPING','STOPPED','FAILED','LOST','CLEANING','CLEANED','AMBIGUOUS','RECOVERY_REQUIRED'] } as const;
  if (operation === 'babyx.root.microvm.create') return objectSchema({ transactionId: microvmTransactionId, skillBundleDigest: digest, grantDigest: digest, policyDigest: digest, firecrackerVersion: { const: 'v1.15.1' }, kernelDigest: digest, rootImageDigest: digest, vcpuCount: { type: 'integer', minimum: 1, maximum: 8 }, memoryMiB: { type: 'integer', minimum: 128, maximum: 4096 }, networkMode: { const: 'NONE' } }, ['transactionId','skillBundleDigest','grantDigest','policyDigest','kernelDigest','rootImageDigest']);
  if (operation === 'babyx.root.microvm.get' || operation === 'babyx.root.microvm.stop' || operation === 'babyx.root.microvm.remove') return objectSchema({ vmId: microvmId }, ['vmId']);
  if (operation === 'babyx.root.microvm.list') return objectSchema({ ownerPrincipal: identifier, lifecycle: microvmLifecycle, ...page });
  if (operation === 'babyx.root.microvm.exec') return objectSchema({ vmId: microvmId, action: { enum: ['ECHO','SLEEP','STATUS','CANCEL'] }, taskId: { type: 'string', pattern: '^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$' }, input: { type: 'string', maxLength: 1024 }, durationMs: { type: 'integer', minimum: 0, maximum: 60000 } }, ['vmId','action','taskId']);
  const snapshotId = { type: 'string', pattern: '^mvs_[a-f0-9]{32}$' } as const;
  const poolId = { type: 'string', pattern: '^mvp_[a-f0-9]{32}$' } as const;
  if (operation === 'babyx.root.microvm.snapshot') return objectSchema({ vmId: microvmId, expiresAt: stringValue }, ['vmId']);
  if (operation === 'babyx.root.microvm.restore') return objectSchema({ snapshotId, transactionId: microvmTransactionId, skillBundleDigest: digest, grantDigest: digest, policyDigest: digest, networkMode: { const: 'NONE' } }, ['snapshotId','transactionId','skillBundleDigest','grantDigest','policyDigest']);
  if (operation === 'babyx.root.microvm.pool.reconcile') return objectSchema({ action: { enum: ['RECONCILE','ACQUIRE','RELEASE'] }, poolId, snapshotId, desiredWarmCount: { type: 'integer', minimum: 0, maximum: 1 }, maximumWarmCount: { const: 1 }, expiresAt: stringValue, transactionId: microvmTransactionId, skillBundleDigest: digest, grantDigest: digest, policyDigest: digest, vmId: microvmId }, ['action']);
  const attestationChallengeId = { type: 'string', pattern: '^atc_[a-f0-9]{32}$' } as const;
  const attestationId = { type: 'string', pattern: '^atv_[a-f0-9]{32}$' } as const;
  const workloadIdentityId = { type: 'string', pattern: '^wid_[a-f0-9]{32}$' } as const;
  const secretLeaseId = { type: 'string', pattern: '^sls_[a-f0-9]{32}$' } as const;
  const nullableDigest = { type: ['string', 'null'], pattern: '^[a-f0-9]{64}$' } as const;
  const pcr = objectSchema({ index: { type: 'integer', minimum: 0, maximum: 23 }, algorithm: { const: 'sha256' }, value: digest }, ['index', 'algorithm', 'value']);
  const pcrs = { type: 'array', maxItems: 24, items: pcr } as const;
  const selector = objectSchema({ type: { enum: ['systemd_unit','uid','gid','executable_path','executable_digest','cgroup','vm_id','transaction_id','skill_bundle_digest'] }, value: { type: 'string', minLength: 1, maxLength: 1024 } }, ['type','value']);
  if (operation === 'babyx.root.attestation.challenge') return objectSchema({ providerId: { enum: ['hardware-tpm','software-tpm-fixture'] }, pcrSelection: { type: 'array', minItems: 1, maxItems: 24, uniqueItems: true, items: { type: 'integer', minimum: 0, maximum: 23 } }, ttlSeconds: { type: 'integer', minimum: 30, maximum: 900 } });
  if (operation === 'babyx.root.attestation.verify') return objectSchema({
    challengeId: attestationChallengeId,
    quote: objectSchema({ providerId: { enum: ['hardware-tpm','software-tpm-fixture'] }, nonce: digest, pcrs: { ...pcrs, minItems: 1 }, eventLogDigest: nullableDigest, imaDigest: nullableDigest, bootId: identifier, observedAt: stringValue, attestationKeyId: identifier, signature: digest }, ['providerId','nonce','pcrs','eventLogDigest','imaDigest','bootId','observedAt','attestationKeyId','signature']),
    policy: objectSchema({ expectedPcrs: pcrs, maxAgeSeconds: { type: 'integer', minimum: 1, maximum: 900 }, requireMeasuredBoot: { type: 'boolean' }, requireIma: { type: 'boolean' } }, ['expectedPcrs','maxAgeSeconds','requireMeasuredBoot','requireIma']),
  }, ['challengeId','quote','policy']);
  if (operation === 'babyx.root.attestation.get') return objectSchema({ challengeId: attestationChallengeId, attestationId }, [], { anyOf: [{ required: ['challengeId'] }, { required: ['attestationId'] }] });
  if (operation === 'babyx.root.identity.issue') return objectSchema({ attestationId, transactionId: microvmTransactionId, skillBundleDigest: digest, grantDigest: digest, issuerProviderId: { enum: ['spire-workload-api','sovereign-x509-svid'] }, selectors: { type: 'array', minItems: 1, maxItems: 16, items: selector }, ttlSeconds: { type: 'integer', minimum: 60, maximum: 3600 } }, ['attestationId','transactionId','skillBundleDigest','grantDigest','issuerProviderId','selectors']);
  if (operation === 'babyx.root.identity.get') return objectSchema({ identityId: workloadIdentityId }, ['identityId']);
  if (operation === 'babyx.root.identity.revoke') return objectSchema({ identityId: workloadIdentityId, expectedSequence, reasonDigest: digest }, ['identityId','expectedSequence','reasonDigest']);
  if (operation === 'babyx.root.secret.lease') return objectSchema({ identityId: workloadIdentityId, attestationId, transactionId: microvmTransactionId, skillBundleDigest: digest, grantDigest: digest, providerId: { const: 'local-secret-reference' }, secretReference: { type: 'string', minLength: 1, maxLength: 4096 }, target: objectSchema({ kind: { enum: ['SYSTEMD_UNIT','MICROVM','HOST_ENVELOPE','DISPOSABLE_MACHINE'] }, id: identifier }, ['kind','id']), ttlSeconds: { type: 'integer', minimum: 30, maximum: 3600 } }, ['identityId','attestationId','transactionId','skillBundleDigest','grantDigest','providerId','secretReference','target']);
  if (operation === 'babyx.root.secret.revoke') return objectSchema({ leaseId: secretLeaseId, expectedSequence, reasonDigest: digest }, ['leaseId','expectedSequence','reasonDigest']);
  const bundleId = { type: 'string', pattern: '^bnd_[a-f0-9]{32}$' } as const;
  const ociDigest = { type: 'string', pattern: '^sha256:[a-f0-9]{64}$' } as const;
  const nullableOciDigest = { type: ['string','null'], pattern: '^sha256:[a-f0-9]{64}$' } as const;
  const publicPem = { type: 'string', minLength: 1, maxLength: 65_536 } as const;
  const nullablePem = { type: ['string','null'], maxLength: 65_536 } as const;
  const base64Value = { type: 'string', minLength: 1, maxLength: 8 * 1024 * 1024, pattern: '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$' } as const;
  const digestDescriptor = objectSchema({ name: { type: 'string', minLength: 1, maxLength: 1_024 }, digest }, ['name','digest']);
  const digestDescriptors = { type: 'array', maxItems: 256, items: digestDescriptor } as const;
  if (operation === 'babyx.root.bundle.resolve') return objectSchema({ reference: { type: 'string', minLength: 1, maxLength: 4_096 }, expectedManifestDigest: nullableOciDigest, discoveryOnly: { type: 'boolean' } }, ['reference']);
  if (operation === 'babyx.root.bundle.cache') return objectSchema({ bundleId }, ['bundleId']);
  if (operation === 'babyx.root.bundle.verify') return objectSchema({
    bundleId,
    signatureBundle: objectSchema({
      mediaType: { const: 'application/vnd.dev.sigstore.bundle+json;version=0.3' },
      verificationMaterial: objectSchema({
        kind: { enum: ['KEYED','KEYLESS'] },
        publicKeyHint: nullableDigest,
        certificatePem: nullablePem,
        issuerCertificatePem: nullablePem,
        tlogEntries: { type: 'array', maxItems: 16, items: objectSchema({ logId: identifier, entryDigest: digest, checkpointDigest: digest, integratedTime: stringValue }, ['logId','entryDigest','checkpointDigest','integratedTime']) },
      }, ['kind','publicKeyHint','certificatePem','issuerCertificatePem','tlogEntries']),
      messageSignature: objectSchema({ messageDigest: objectSchema({ algorithm: { const: 'SHA2_256' }, digest: base64Value }, ['algorithm','digest']), signature: base64Value }, ['messageDigest','signature']),
    }, ['mediaType','verificationMaterial','messageSignature']),
    trustPolicy: objectSchema({
      trustedPublicKeys: { type: 'array', maxItems: 32, uniqueItems: true, items: publicPem },
      trustedRootCertificates: { type: 'array', maxItems: 32, uniqueItems: true, items: publicPem },
      expectedIssuer: { type: ['string','null'], maxLength: 1_024 },
      expectedSubject: { type: ['string','null'], maxLength: 1_024 },
      revokedSignerDigests: { type: 'array', maxItems: 256, uniqueItems: true, items: digest },
      requireTransparency: { type: 'boolean' },
    }, ['trustedPublicKeys','trustedRootCertificates','expectedIssuer','expectedSubject','revokedSignerDigests','requireTransparency']),
  }, ['bundleId','signatureBundle','trustPolicy']);
  if (operation === 'babyx.root.provenance.verify') return objectSchema({
    bundleId,
    envelope: objectSchema({ payloadType: { const: 'application/vnd.in-toto+json' }, payload: base64Value, signatures: { type: 'array', minItems: 1, maxItems: 16, items: objectSchema({ keyid: digest, sig: base64Value }, ['keyid','sig']) } }, ['payloadType','payload','signatures']),
    verificationKeyPem: publicPem,
    expected: objectSchema({ sourceRepository: { type: 'string', minLength: 1, maxLength: 2_048 }, sourceCommit: { type: 'string', pattern: '^[a-f0-9]{40}$' }, sourceTree: { type: 'string', pattern: '^[a-f0-9]{40}$' }, builderId: { type: 'string', minLength: 1, maxLength: 2_048 }, workflowId: { type: 'string', minLength: 1, maxLength: 2_048 }, materials: digestDescriptors, dependencies: digestDescriptors, products: digestDescriptors }, ['sourceRepository','sourceCommit','sourceTree','builderId','workflowId','materials','dependencies','products']),
  }, ['bundleId','envelope','verificationKeyPem','expected']);
  if (operation === 'babyx.root.transparency.verify') return objectSchema({
    logId: identifier,
    entryDigest: digest,
    checkpoint: objectSchema({ logId: identifier, treeSize: { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER }, rootHash: digest, issuedAt: stringValue, signerKeyId: digest, signature: base64Value }, ['logId','treeSize','rootHash','issuedAt','signerKeyId','signature']),
    checkpointPublicKeyPem: publicPem,
    inclusionProof: objectSchema({ leafIndex: { type: 'integer', minimum: 0, maximum: Number.MAX_SAFE_INTEGER }, treeSize: { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER }, hashes: { type: 'array', maxItems: 256, items: digest } }, ['leafIndex','treeSize','hashes']),
    consistencyProof: { anyOf: [{ type: 'null' }, objectSchema({ firstSize: { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER }, secondSize: { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER }, hashes: { type: 'array', maxItems: 256, items: digest } }, ['firstSize','secondSize','hashes'])] },
    maximumCheckpointAgeSeconds: { type: 'integer', minimum: 1, maximum: 31_536_000 },
  }, ['logId','entryDigest','checkpoint','checkpointPublicKeyPem','inclusionProof','consistencyProof']);
  if (operation === 'babyx.root.transparency.status') return objectSchema({ logId: identifier }, ['logId']);
  const rootCheckpointId = { type: 'string', pattern: '^rcp_[a-f0-9]{32}$' } as const;
  const rootReplayId = { type: 'string', pattern: '^rrp_[a-f0-9]{32}$' } as const;
  const replayTransactionId = { type: ['string','null'], pattern: '^rtx_[A-Za-z0-9_-]{8,128}$' } as const;
  const replayCompatibility = objectSchema({ architecture: { enum: ['x86_64','aarch64'] }, kernelRelease: stringValue, providerId, providerVersion: stringValue, configurationDigest: digest }, ['architecture','kernelRelease','providerId','providerVersion','configurationDigest']);
  const replayProcess = objectSchema({ pid: { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER }, processStartTime: stringValue, executablePath: stringValue, pgid: { type: ['integer','null'], minimum: 1, maximum: Number.MAX_SAFE_INTEGER }, bootId: identifier }, ['pid','processStartTime','executablePath','bootId']);
  if (operation === 'babyx.root.checkpoint.create') return objectSchema({
    kind: { enum: ['CRIU_PROCESS','RR_TRACE','MICROVM_SNAPSHOT'] }, transactionId: replayTransactionId, process: replayProcess,
    imagesDir: stringValue, traceReference: stringValue, traceDigest: digest, traceSizeBytes: { type: ['integer','null'], minimum: 0, maximum: Number.MAX_SAFE_INTEGER },
    vmId: microvmId, expiresAt: stringValue, compatibility: replayCompatibility,
  }, ['kind','compatibility']);
  if (operation === 'babyx.root.checkpoint.get') return objectSchema({ checkpointId: rootCheckpointId }, ['checkpointId']);
  if (operation === 'babyx.root.checkpoint.restore') return objectSchema({ checkpointId: rootCheckpointId, authorizationDigest: digest, transactionId: replayTransactionId, target: jsonObject }, ['checkpointId','authorizationDigest']);
  if (operation === 'babyx.root.replay.run') return objectSchema({
    kind: { enum: ['REQUEST_REPLAY','OBSERVATION_REPLAY','CRIU_CHECKPOINT_RESTORE','RR_FORENSIC_REPLAY','MICROVM_SNAPSHOT_RESTORE'] },
    transactionId: replayTransactionId, checkpointId: { anyOf: [{ type: 'null' }, rootCheckpointId] }, canonicalInput: { anyOf: [{ type: 'null' }, jsonObject] },
    dryRun: { type: 'boolean' }, authorizationDigest: { anyOf: [{ type: 'null' }, digest] }, effectTransactionId: replayTransactionId, target: jsonObject,
  }, ['kind']);
  if (operation === 'babyx.root.replay.get') return objectSchema({ replayId: rootReplayId }, ['replayId']);
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
  throw new Error(`missing root operation schema: ${operation}`);
}

function schemaFor(operation: string): Record<string, unknown> {
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

function familyOf(operation: string): string {
  return operation.split('.')[1] ?? 'core';
}

function isMutation(operation: string): boolean {
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
  if (operation === 'babyx.root.provider.reconcile') return ['provider_reconciliation_record_persisted', 'provider_state_observed'];
  if (operation === 'babyx.root.mediation.profile.create' || operation === 'babyx.root.mediation.profile.revoke') return ['mediation_profile_record_persisted', 'digest_chained_event_appended'];
  if (operation === 'babyx.root.microvm.create' || operation === 'babyx.root.microvm.exec' || operation === 'babyx.root.microvm.stop' || operation === 'babyx.root.microvm.remove') return ['microvm_record_persisted', 'provider_observation_reported'];
  if (operation === 'babyx.root.microvm.snapshot') return ['microvm_snapshot_record_persisted', 'snapshot_artifact_digests_verified', 'credential_absence_verified', 'source_microvm_cleaned'];
  if (operation === 'babyx.root.microvm.restore') return ['microvm_record_persisted', 'snapshot_compatibility_verified', 'fresh_guest_identity_observed', 'provider_observation_reported'];
  if (operation === 'babyx.root.microvm.pool.reconcile') return ['microvm_pool_record_persisted', 'pool_capacity_bounded', 'lease_state_reconciled', 'provider_observation_reported'];
  if (operation === 'babyx.root.attestation.challenge') return ['attestation_challenge_persisted', 'nonce_bound', 'provider_support_observed'];
  if (operation === 'babyx.root.attestation.verify') return ['attestation_verification_persisted', 'nonce_consumed', 'freshness_and_measurements_verified'];
  if (operation === 'babyx.root.identity.issue' || operation === 'babyx.root.identity.revoke') return ['workload_identity_record_persisted', 'selector_binding_verified', 'private_key_not_returned'];
  if (operation === 'babyx.root.secret.lease' || operation === 'babyx.root.secret.revoke') return ['secret_lease_record_persisted', 'attestation_and_identity_verified', 'secret_value_not_returned'];
  if (operation === 'babyx.root.bundle.resolve') return ['oci_bundle_record_persisted', 'manifest_digest_bound', 'mutable_tags_discovery_only'];
  if (operation === 'babyx.root.bundle.verify') return ['signature_verification_record_persisted', 'signer_and_manifest_digest_verified', 'revocation_policy_applied'];
  if (operation === 'babyx.root.bundle.cache') return ['content_addressed_cache_verified', 'all_oci_blob_digests_verified', 'atomic_cache_state_persisted'];
  if (operation === 'babyx.root.provenance.verify') return ['provenance_verification_record_persisted', 'dsse_signature_verified', 'source_builder_materials_and_products_verified'];
  if (operation === 'babyx.root.transparency.verify') return ['transparency_monitor_record_persisted', 'signed_checkpoint_and_inclusion_verified', 'consistency_or_conflict_state_persisted'];
  if (operation === 'babyx.root.checkpoint.create') return ['digest_sealed_checkpoint_record_persisted', 'provider_compatibility_bound', 'artifact_integrity_recorded'];
  if (operation === 'babyx.root.checkpoint.restore') return ['explicit_authorization_verified', 'provider_compatibility_revalidated', 'restore_observation_persisted'];
  if (operation === 'babyx.root.replay.run') return ['digest_sealed_replay_record_persisted', 'dry_run_default_enforced', 'no_alternate_effect_authority_created'];
  if (family === 'root') return ['authoritative_transaction_record_persisted', 'digest_chained_event_appended'];
  if (family === 'file') return ['resulting_file_metadata_reported'];
  if (family === 'artifact') return ['artifact_digest_and_metadata_reported'];
  return ['command_result_reported'];
}

export const OPERATION_CATALOG_VERSION = '10.0.0';

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
