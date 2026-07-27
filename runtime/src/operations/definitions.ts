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

const readSuffixes = new Set(['describe', 'health', 'get', 'list', 'read', 'events', 'status', 'inspect', 'logs', 'interfaces', 'statistics', 'compatibility', 'check', 'diff', 'validate']);

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
    mutation: !readSuffixes.has(suffix),
    input: { type: 'object', additionalProperties: true },
    output: { type: 'object', additionalProperties: true },
  };
});

export const OPERATION_NAMES = new Set(OPERATION_DEFINITIONS.map((definition) => definition.operation));
