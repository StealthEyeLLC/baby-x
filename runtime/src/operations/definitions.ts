export interface OperationDefinition {
  operation: string;
  family: string;
  version: string;
  description: string;
  mutation: boolean;
  input: Record<string, unknown>;
  output?: Record<string, unknown>;
}

const operations = `
babyx.describe
babyx.health
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
babyx.pty.create
babyx.pty.input
babyx.pty.resize
babyx.pty.read
babyx.pty.close
babyx.artifact.create
babyx.artifact.begin
babyx.artifact.upload
babyx.artifact.finalize
babyx.artifact.abort
babyx.artifact.download
babyx.artifact.list
babyx.artifact.get
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
babyx.machine.base.list
babyx.machine.base.create
babyx.machine.base.update
babyx.machine.list
babyx.machine.get
babyx.machine.create
babyx.machine.events
babyx.machine.clone
babyx.machine.snapshot
babyx.machine.restore
babyx.machine.import
babyx.machine.export
babyx.machine.rename
babyx.machine.start
babyx.machine.boot
babyx.machine.exec
babyx.machine.shell
babyx.machine.status
babyx.machine.reconcile
babyx.machine.expire
babyx.machine.gc
babyx.machine.diagnostics
babyx.machine.inspect
babyx.machine.logs
babyx.machine.copy.to
babyx.machine.copy.from
babyx.machine.bind
babyx.machine.network.get
babyx.machine.network.set
babyx.machine.freeze
babyx.machine.thaw
babyx.machine.stop
babyx.machine.destroy
babyx.machine.terminate
babyx.machine.poweroff
babyx.machine.reboot
babyx.machine.remove
babyx.machine.raw
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
babyx.release.describe
babyx.release.capabilities
babyx.release.capacity
babyx.release.credentials.describe
babyx.release.credentials.rotate
babyx.release.github.status
babyx.release.github.reconcile
babyx.release.github.webhook.ingest
babyx.release.plan
babyx.release.prepare
babyx.release.promote
babyx.release.approve
babyx.release.cancel
babyx.release.rollback
babyx.release.reconcile
babyx.release.resume
babyx.release.expire
babyx.release.gc
babyx.release.live
babyx.release.status
babyx.release.get
babyx.release.list
babyx.release.events
babyx.release.evidence
babyx.release.failures
babyx.release.service.get
babyx.release.service.list
babyx.release.slot.get
babyx.release.route.get
babyx.release.certification.describe
babyx.release.certification.certify
babyx.release.certification.resume
babyx.release.certification.get
babyx.release.certification.list
babyx.maintenance.describe
babyx.maintenance.plan
babyx.maintenance.apply
babyx.maintenance.status
babyx.maintenance.reconcile
babyx.maintenance.reboot
`.trim().split(/\s+/u);

const readSuffixes = new Set(['capacity', 'describe', 'health', 'get', 'list', 'read', 'events', 'status', 'inspect', 'logs', 'interfaces', 'statistics', 'compatibility', 'capabilities', 'check', 'diff', 'validate', 'plan', 'live', 'evidence', 'failures']);
const forcedMutations = new Set(['babyx.maintenance.plan']);
const exactInputs: Readonly<Record<string, JsonObject>> = Object.freeze({
  'babyx.release.describe': { type: 'object', additionalProperties: false },
  'babyx.release.capabilities': { type: 'object', additionalProperties: false },
  'babyx.release.capacity': {
    type: 'object', additionalProperties: false, properties: {
      serviceHealth: { enum: ['GREEN', 'YELLOW', 'RED', 'UNKNOWN'] },
      projection: { type: 'object', additionalProperties: false, required: ['reservationId', 'purpose', 'rootBytes', 'zfsBytes', 'memoryBytes', 'ownerPrincipal'], properties: {
        reservationId: { type: 'string' }, purpose: { enum: ['SOURCE_ARCHIVE', 'DEPENDENCY_CACHE', 'BUILD_CACHE', 'RELEASE_ARTIFACT', 'MATERIALIZATION', 'CERTIFICATION', 'DISPOSABLE_CLONE', 'BACKGROUND_MAINTENANCE'] },
        workClass: { enum: ['PRODUCTION_CONTROL', 'HEAVYWEIGHT', 'BACKGROUND'] }, rootBytes: { type: 'integer', minimum: 0 }, zfsBytes: { type: 'integer', minimum: 0 }, memoryBytes: { type: 'integer', minimum: 0 }, ownerPrincipal: { type: 'string' }, expiresAt: { type: 'string' },
      } },
    },
  },
  'babyx.release.credentials.describe': {
    type: 'object', additionalProperties: false, properties: { serviceId: { type: 'string' } },
  },
  'babyx.release.credentials.rotate': {
    type: 'object', additionalProperties: false, required: ['credentialSet', 'expectedProcessIdentity'], properties: {
      credentialSet: { type: 'object', additionalProperties: false, required: ['credentialSetId', 'serviceId', 'version', 'provider', 'entries'], properties: {
        credentialSetId: { type: 'string' }, serviceId: { type: 'string' }, version: { type: 'integer', minimum: 1 },
        provider: { enum: ['SYSTEMD_CREDENTIAL', 'SYSTEMD_ENCRYPTED_CREDENTIAL', 'LEGACY_FILE_ADAPTER'] },
        entries: { type: 'array', minItems: 1, maxItems: 256, items: { type: 'object', additionalProperties: false, required: ['name', 'mode', 'sourceRef', 'objectDigest', 'version'], properties: {
          name: { type: 'string' }, mode: { enum: ['PLAIN', 'ENCRYPTED'] }, sourceRef: { type: 'string' }, objectDigest: { type: 'string', pattern: '^[a-f0-9]{64}$' }, version: { type: 'integer', minimum: 1 }, environmentName: { type: 'string' },
        } } },
        previousCredentialSetId: { type: 'string' }, overlapUntil: { type: 'string' },
      } },
      expectedProcessIdentity: { type: 'object', additionalProperties: true }, endpointMode: { enum: ['UNIX_SOCKET', 'LOOPBACK_TCP'] },
    },
  },
  'babyx.release.github.status': {
    type: 'object', additionalProperties: false, properties: { repository: { type: 'string' }, limit: { type: 'integer', minimum: 1, maximum: 200 } },
  },
  'babyx.release.github.reconcile': {
    type: 'object', additionalProperties: false, properties: { limit: { type: 'integer', minimum: 1, maximum: 100 }, poll: { type: 'boolean' } },
  },
  'babyx.release.github.webhook.ingest': {
    type: 'object', additionalProperties: false, required: ['method','path','headers','rawBodyBase64'], properties: {
      method: { enum: ['POST'] }, path: { type: 'string', maxLength: 256 },
      headers: { type: 'object', additionalProperties: { type: 'string', maxLength: 4096 }, maxProperties: 64 },
      rawBodyBase64: { type: 'string', maxLength: 1398120 },
    },
  },
  'babyx.release.plan': {
    type: 'object', additionalProperties: false, required: ['request'], properties: { request: { type: 'object', additionalProperties: true } },
  },
  'babyx.release.prepare': {
    type: 'object', additionalProperties: false, required: ['request'], properties: { request: { type: 'object', additionalProperties: true }, deploymentId: { type: 'string', pattern: '^[a-z0-9][a-z0-9._:-]{0,127}$' } },
  },
  'babyx.release.promote': {
    type: 'object', additionalProperties: false, properties: { request: { type: 'object', additionalProperties: true }, deploymentId: { type: 'string', pattern: '^[a-z0-9][a-z0-9._:-]{0,127}$' } },
  },
  'babyx.release.approve': {
    type: 'object', additionalProperties: false, required: ['deploymentId', 'expectedSequence', 'approval'], properties: { deploymentId: { type: 'string' }, expectedSequence: { type: 'integer', minimum: 0 }, approval: { type: 'object', additionalProperties: true } },
  },
  'babyx.release.cancel': {
    type: 'object', additionalProperties: false, required: ['deploymentId', 'expectedSequence'], properties: { deploymentId: { type: 'string' }, expectedSequence: { type: 'integer', minimum: 0 }, reason: { type: 'string', maxLength: 1024 } },
  },
  'babyx.release.rollback': {
    type: 'object', additionalProperties: false, required: ['deploymentId', 'expectedSequence'], properties: { deploymentId: { type: 'string' }, expectedSequence: { type: 'integer', minimum: 0 }, reason: { type: 'string', maxLength: 1024 }, automatic: { type: 'boolean' } },
  },
  'babyx.release.reconcile': {
    type: 'object', additionalProperties: false, properties: { deploymentId: { type: 'string' }, expectedSequence: { type: 'integer', minimum: 0 }, limit: { type: 'integer', minimum: 1, maximum: 100 } },
  },
  'babyx.release.resume': {
    type: 'object', additionalProperties: false, required: ['deploymentId', 'expectedSequence', 'resolution'], properties: { deploymentId: { type: 'string' }, expectedSequence: { type: 'integer', minimum: 0 }, resolution: { type: 'object', additionalProperties: true } },
  },
  'babyx.release.expire': {
    type: 'object', additionalProperties: false, required: ['deploymentId', 'expectedSequence'], properties: { deploymentId: { type: 'string' }, expectedSequence: { type: 'integer', minimum: 0 } },
  },
  'babyx.release.gc': {
    type: 'object', additionalProperties: false, required: ['dryRun'], properties: { dryRun: { type: 'boolean' }, limit: { type: 'integer', minimum: 1, maximum: 1000 }, maxBytes: { type: 'integer', minimum: 0 }, planDigest: { type: 'string', pattern: '^[a-f0-9]{64}$' } },
  },
  'babyx.release.live': { type: 'object', additionalProperties: false, required: ['deploymentId'], properties: { deploymentId: { type: 'string' } } },
  'babyx.release.status': { type: 'object', additionalProperties: false, required: ['deploymentId'], properties: { deploymentId: { type: 'string' } } },
  'babyx.release.get': { type: 'object', additionalProperties: false, required: ['deploymentId'], properties: { deploymentId: { type: 'string' } } },
  'babyx.release.list': { type: 'object', additionalProperties: false, properties: { offset: { type: 'integer', minimum: 0 }, limit: { type: 'integer', minimum: 1, maximum: 200 }, state: { type: 'string' }, serviceId: { type: 'string' } } },
  'babyx.release.events': { type: 'object', additionalProperties: false, required: ['deploymentId'], properties: { deploymentId: { type: 'string' }, offset: { type: 'integer', minimum: 0 }, limit: { type: 'integer', minimum: 1, maximum: 1000 } } },
  'babyx.release.evidence': { type: 'object', additionalProperties: false, required: ['deploymentId'], properties: { deploymentId: { type: 'string' } } },
  'babyx.release.failures': { type: 'object', additionalProperties: false, properties: { limit: { type: 'integer', minimum: 1, maximum: 200 } } },
  'babyx.release.service.get': {
    type: 'object', additionalProperties: false, required: ['serviceId'],
    properties: { serviceId: { type: 'string', pattern: '^[a-z0-9][a-z0-9.-]{0,63}$' } },
  },
  'babyx.release.service.list': {
    type: 'object', additionalProperties: false,
    properties: { offset: { type: 'integer', minimum: 0, maximum: 10000 }, limit: { type: 'integer', minimum: 1, maximum: 200 } },
  },
  'babyx.release.slot.get': {
    type: 'object', additionalProperties: false, required: ['serviceId', 'slotId'],
    properties: { serviceId: { type: 'string', pattern: '^[a-z0-9][a-z0-9.-]{0,63}$' }, slotId: { type: 'string', enum: ['blue', 'green'] } },
  },
  'babyx.release.route.get': {
    type: 'object', additionalProperties: false, required: ['serviceId'],
    properties: { serviceId: { type: 'string', pattern: '^[a-z0-9][a-z0-9.-]{0,63}$' } },
  },
  'babyx.maintenance.describe': { type: 'object', additionalProperties: false },
  'babyx.maintenance.plan': {
    type: 'object', additionalProperties: false, required: ['maintenanceKind'], properties: {
      maintenanceKind: { enum: ['PACKAGE_UPDATE', 'SERVICE_RUNTIME_UPDATE', 'SOFT_REBOOT', 'FULL_REBOOT', 'KEXEC', 'LIVEPATCH', 'FILESYSTEM', 'OTHER_APPROVED'] },
      targetPackages: { type: 'array', maxItems: 256, items: { type: 'string', minLength: 1, maxLength: 256 } },
      scheduledFor: { type: 'string', maxLength: 64 }, reason: { type: 'string', maxLength: 1024 }, automaticAllowed: { type: 'boolean' },
      metadata: { type: 'object', additionalProperties: true },
    },
  },
  'babyx.maintenance.apply': {
    type: 'object', additionalProperties: false, required: ['maintenanceId', 'expectedSequence'], properties: {
      maintenanceId: { type: 'string', pattern: '^[a-z0-9][a-z0-9._:-]{0,127}$' }, expectedSequence: { type: 'integer', minimum: 0 },
      approvalEvidence: { type: 'array', maxItems: 32, items: { type: 'object', additionalProperties: true } },
    },
  },
  'babyx.maintenance.status': {
    type: 'object', additionalProperties: false, properties: {
      maintenanceId: { type: 'string', pattern: '^[a-z0-9][a-z0-9._:-]{0,127}$' }, state: { type: 'string', maxLength: 64 }, limit: { type: 'integer', minimum: 1, maximum: 200 },
    },
  },
  'babyx.maintenance.reconcile': {
    type: 'object', additionalProperties: false, properties: {
      maintenanceId: { type: 'string', pattern: '^[a-z0-9][a-z0-9._:-]{0,127}$' }, limit: { type: 'integer', minimum: 1, maximum: 100 },
    },
  },
  'babyx.maintenance.reboot': {
    type: 'object', additionalProperties: false, required: ['mode'], properties: {
      maintenanceId: { type: 'string', pattern: '^[a-z0-9][a-z0-9._:-]{0,127}$' }, expectedSequence: { type: 'integer', minimum: 0 },
      mode: { enum: ['SOFT', 'FULL', 'KEXEC'] }, approvalEvidence: { type: 'array', maxItems: 32, items: { type: 'object', additionalProperties: true } },
      scheduledFor: { type: 'string', maxLength: 64 }, reason: { type: 'string', maxLength: 1024 },
    },
  },
});

function familyOf(operation: string): string {
  const segments = operation.split('.');
  return segments[1] ?? 'core';
}

export const OPERATION_DEFINITIONS: readonly OperationDefinition[] = operations.map((operation) => {
  const suffix = operation.split('.').at(-1) ?? operation;
  return {
    operation,
    family: familyOf(operation),
    version: '1.0.0',
    description: `Baby-X unrestricted ${operation.slice('babyx.'.length)} operation.`,
    mutation: forcedMutations.has(operation) || !readSuffixes.has(suffix),
    input: exactInputs[operation] ?? { type: 'object', additionalProperties: true },
    output: { type: 'object', additionalProperties: true },
  };
});

export const OPERATION_NAMES = new Set(OPERATION_DEFINITIONS.map((definition) => definition.operation));
