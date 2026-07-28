import type { JsonObject, CommandResult } from '../core.ts';
import { SystemdManager } from '../systemd/manager.ts';
import type { BrokerEffectAdapter, BrokerEffectResult, RootBrokerRequest } from './broker.ts';
import { RootFilesystemEffects, FILESYSTEM_EFFECT_OPERATIONS, type FilesystemArtifactAuthority } from './filesystem-effects.ts';
import { HostEnvelopeProvider } from './host-envelope.ts';
import { RootFabricError, integer, text, type RootAtomicityMode, type RootEffectClass, type RootExecutionProvider } from './model.ts';

export interface EffectStorageAuthority {
  mountStatus(input: JsonObject): Promise<JsonObject>;
  mountCreate(input: JsonObject): Promise<JsonObject>;
  mountRemove(input: JsonObject): Promise<JsonObject>;
  prepareSnapshot(input: JsonObject): Promise<JsonObject>;
  verifySnapshot(input: JsonObject): Promise<JsonObject>;
  rollbackSnapshot(input: JsonObject): Promise<JsonObject>;
  releaseSnapshot(input: JsonObject): Promise<JsonObject>;
}
export interface EffectNetworkAuthority {
  portCheck(input: JsonObject): Promise<JsonObject>;
  listenerVerify(input: JsonObject): Promise<JsonObject>;
  applyOwnedRule(input: JsonObject): Promise<JsonObject>;
  removeOwnedRule(input: JsonObject): Promise<JsonObject>;
}
export interface ArtifactAuthority extends FilesystemArtifactAuthority {}
export interface RootEffectDefinition extends JsonObject {
  schemaVersion: '1.0.0'; operation: string; version: '1.0.0'; effectClass: RootEffectClass;
  atomicityModes: RootAtomicityMode[]; providers: RootExecutionProvider[]; requiredCapabilities: string[];
  restartBehavior: string; cancellable: boolean; timeoutMs: number; rollbackOperation: string | null; compensationOperation: string | null;
}
const VERSION = '1.0.0' as const;
const HOST: RootExecutionProvider[] = ['HOST_ENVELOPE'];
const HOST_OR_MACHINE: RootExecutionProvider[] = ['HOST_ENVELOPE', 'DISPOSABLE_MACHINE'];
function def(operation: string, effectClass: RootEffectClass, providers: RootExecutionProvider[], rollbackOperation: string | null = null): RootEffectDefinition {
  return { schemaVersion: VERSION, operation, version: VERSION, effectClass, atomicityModes: ['ATOMIC_WITHIN_PROVIDER', 'BEST_EFFORT_WITH_COMPENSATION'], providers, requiredCapabilities: [operation], restartBehavior: 'READBACK_BEFORE_RETRY', cancellable: operation === 'process.exec', timeoutMs: 300_000, rollbackOperation, compensationOperation: rollbackOperation };
}
const definitions: RootEffectDefinition[] = [
  ...FILESYSTEM_EFFECT_OPERATIONS.map((operation) => def(operation, 'REVERSIBLE', HOST_OR_MACHINE, operation.includes('create') ? operation.replace('create', 'remove') : null)),
  def('process.exec', 'COMPENSATABLE', HOST_OR_MACHINE, 'process.terminate'), def('process.signal', 'REVERSIBLE', HOST), def('process.freeze', 'REVERSIBLE', HOST, 'process.thaw'), def('process.thaw', 'REVERSIBLE', HOST, 'process.freeze'), def('process.terminate', 'COMPENSATABLE', HOST),
  def('service.status', 'READ_ONLY', HOST), def('service.start', 'REVERSIBLE', HOST, 'service.stop'), def('service.stop', 'REVERSIBLE', HOST, 'service.start'), def('service.restart', 'REVERSIBLE', HOST), def('service.reload', 'REVERSIBLE', HOST), def('service.enable', 'REVERSIBLE', HOST, 'service.disable'), def('service.disable', 'REVERSIBLE', HOST, 'service.enable'),
  def('mount.status', 'READ_ONLY', HOST), def('mount.create', 'REVERSIBLE', HOST, 'mount.remove'), def('mount.remove', 'REVERSIBLE', HOST, 'mount.create'),
  def('snapshot.prepare', 'REVERSIBLE', HOST, 'snapshot.release'), def('snapshot.verify', 'READ_ONLY', HOST), def('snapshot.rollback', 'REVERSIBLE', HOST), def('snapshot.release', 'COMPENSATABLE', HOST),
  def('network.port.check', 'READ_ONLY', HOST), def('network.listener.verify', 'READ_ONLY', HOST), def('network.policy.apply-owned-rule', 'REVERSIBLE', HOST, 'network.policy.remove-owned-rule'), def('network.policy.remove-owned-rule', 'REVERSIBLE', HOST, 'network.policy.apply-owned-rule'),
];
function command(result: CommandResult): JsonObject { return result as unknown as JsonObject; }
function unit(value: unknown): string { const name = text(value, 'unit', 256); if (!/^[A-Za-z0-9_.@:-]+$/u.test(name) || name.startsWith('-')) throw new RootFabricError('invalid_request', 'unit is invalid'); return name; }

export class RootEffectRegistry {
  private readonly byKey = new Map<string, RootEffectDefinition>();
  private readonly filesystem: RootFilesystemEffects;
  constructor(private readonly options: { storage: EffectStorageAuthority; network: EffectNetworkAuthority; systemd?: SystemdManager; artifacts?: ArtifactAuthority }) {
    this.filesystem = new RootFilesystemEffects({ artifacts: options.artifacts });
    for (const definition of definitions) {
      const key = `${definition.operation}@${definition.version}`;
      if (this.byKey.has(key)) throw new RootFabricError('resource_conflict', `duplicate typed effect ${key}`);
      this.byKey.set(key, definition);
    }
  }
  list(): RootEffectDefinition[] { return [...this.byKey.values()].sort((a, b) => a.operation.localeCompare(b.operation)); }
  get(operation: string, version = VERSION): RootEffectDefinition { const found = this.byKey.get(`${operation}@${version}`); if (!found) throw new RootFabricError('unsupported_operation', `typed effect ${operation}@${version} is unsupported`); return found; }
  adapter(operation: string, version = VERSION): BrokerEffectAdapter { const definition = this.get(operation, version); return { operation, version, execute: (input, request) => this.execute(definition, input, request) }; }
  adapters(): BrokerEffectAdapter[] { return this.list().map((definition) => this.adapter(definition.operation, definition.version)); }

  private async execute(definition: RootEffectDefinition, input: JsonObject, request: RootBrokerRequest): Promise<BrokerEffectResult> {
    if (!definition.providers.includes(request.selectedProvider)) throw new RootFabricError('unsupported_provider', `${definition.operation} does not support ${request.selectedProvider}`);
    if (request.selectedProvider === 'DISPOSABLE_MACHINE') return { classification: 'SUCCEEDED', result: { delegated: true, authority: 'Disposable Machine Service', operation: definition.operation, inputDigest: request.inputDigest }, executionIdentity: { provider: 'DISPOSABLE_MACHINE', transactionId: request.transactionId }, cleanupState: { delegated: true } };
    if (definition.operation.startsWith('filesystem.')) return this.filesystem.execute(definition.operation as typeof FILESYSTEM_EFFECT_OPERATIONS[number], input, request);
    const envelope = new HostEnvelopeProvider(this.options.systemd);
    if (definition.operation === 'process.exec') return envelope.execute(input, request);
    if (definition.operation === 'process.signal') return { classification: 'SUCCEEDED', result: await envelope.signal(unit(input.unit), text(input.signal, 'signal', 32)) };
    if (definition.operation === 'process.freeze' || definition.operation === 'process.thaw') return { classification: 'SUCCEEDED', result: await envelope.freeze(unit(input.unit), definition.operation.endsWith('freeze')) };
    if (definition.operation === 'process.terminate') return { classification: 'SUCCEEDED', result: await envelope.cancel(unit(input.unit), 'SIGTERM') };
    if (definition.operation.startsWith('service.')) return this.service(definition.operation, input);
    if (definition.operation === 'mount.status') return { classification: 'SUCCEEDED', result: await this.options.storage.mountStatus(input) };
    if (definition.operation === 'mount.create') return { classification: 'SUCCEEDED', result: await this.options.storage.mountCreate(input) };
    if (definition.operation === 'mount.remove') return { classification: 'SUCCEEDED', result: await this.options.storage.mountRemove(input) };
    if (definition.operation === 'snapshot.prepare') return { classification: 'SUCCEEDED', result: await this.options.storage.prepareSnapshot(input) };
    if (definition.operation === 'snapshot.verify') return { classification: 'SUCCEEDED', result: await this.options.storage.verifySnapshot(input) };
    if (definition.operation === 'snapshot.rollback') return { classification: 'SUCCEEDED', result: await this.options.storage.rollbackSnapshot(input) };
    if (definition.operation === 'snapshot.release') return { classification: 'SUCCEEDED', result: await this.options.storage.releaseSnapshot(input) };
    if (definition.operation === 'network.port.check') return { classification: 'SUCCEEDED', result: await this.options.network.portCheck(input) };
    if (definition.operation === 'network.listener.verify') return { classification: 'SUCCEEDED', result: await this.options.network.listenerVerify(input) };
    if (definition.operation === 'network.policy.apply-owned-rule') return { classification: 'SUCCEEDED', result: await this.options.network.applyOwnedRule(input) };
    if (definition.operation === 'network.policy.remove-owned-rule') return { classification: 'SUCCEEDED', result: await this.options.network.removeOwnedRule(input) };
    throw new RootFabricError('unsupported_operation', `no finite adapter exists for ${definition.operation}`);
  }

  private async service(operation: string, input: JsonObject): Promise<BrokerEffectResult> {
    const manager = this.options.systemd ?? new SystemdManager();
    const target = unit(input.unit);
    const properties = ['LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'InvocationID', 'FragmentPath'] as const;
    const before = command(await manager.show({ unit: target, properties }));
    if (operation === 'service.status') return { classification: 'SUCCEEDED', result: { priorState: before, readback: before }, executionIdentity: { unit: target } };
    const action = operation.slice('service.'.length) as 'start' | 'stop' | 'restart' | 'reload' | 'enable' | 'disable';
    const result = await manager.action(action, { unit: target, timeoutMs: integer(input.timeoutMs ?? 300_000, 'timeoutMs', 1, 3_600_000) });
    const readback = command(await manager.show({ unit: target, properties }));
    return { classification: result.exitCode === 0 ? 'SUCCEEDED' : 'FAILED', result: { priorState: before, action: command(result), readback }, executionIdentity: { unit: target } };
  }

  async restoreService(input: JsonObject): Promise<JsonObject> {
    const manager = this.options.systemd ?? new SystemdManager();
    const target = unit(input.unit);
    const active = input.priorActive === true;
    const enabled = input.priorEnabled === true;
    const activeResult = await manager.action(active ? 'start' : 'stop', { unit: target, timeoutMs: 300_000 });
    const enabledResult = await manager.action(enabled ? 'enable' : 'disable', { unit: target, timeoutMs: 300_000 });
    const readback = await manager.show({ unit: target, properties: ['ActiveState', 'UnitFileState', 'InvocationID'] });
    return { restored: activeResult.exitCode === 0 && enabledResult.exitCode === 0, active: command(activeResult), enabled: command(enabledResult), readback: command(readback) };
  }
}
