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
const durableFamilies = new Set(['machine', 'certification', 'race']);
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

function schemaFor(operation: string): Record<string, unknown> {
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
  if (family === 'file') return ['resulting_file_metadata_reported'];
  if (family === 'artifact') return ['artifact_digest_and_metadata_reported'];
  return ['command_result_reported'];
}

export const OPERATION_CATALOG_VERSION = '2.0.0';

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
