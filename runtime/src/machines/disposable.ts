import { Executor, type CommandResult, type JsonObject } from '../core.ts';
import { MachineManager, type MachineLaunchOptions } from './manager.ts';
import type { MachineDefinition } from './definitions.ts';

const TOKEN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const ZFS_NAME = /^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$/;
const ABSOLUTE_PATH = /^\//;

function token(value: string, field: string): string {
  if (!TOKEN.test(value)) throw new Error(`${field} contains invalid characters`);
  return value;
}

function zfsName(value: string, field: string): string {
  if (!ZFS_NAME.test(value) || value.startsWith('-')) throw new Error(`${field} is not a safe ZFS name`);
  return value;
}

function absolutePath(value: string, field: string): string {
  if (!ABSOLUTE_PATH.test(value) || value.includes('\0')) throw new Error(`${field} must be an absolute NUL-free path`);
  return value;
}

export interface DisposableMachineRequest {
  id: string;
  baseSnapshot: string;
  dataset: string;
  root: string;
  machineClass?: MachineDefinition['class'];
  launch?: Omit<MachineLaunchOptions, 'definition'>;
  ownershipProperties?: Readonly<Record<string, string>>;
}

export interface DisposableMachineInstance {
  id: string;
  dataset: string;
  root: string;
  baseSnapshot: string;
  state: 'created' | 'running';
  launchResult?: CommandResult;
}

export class DisposableMachineManager {
  private readonly machines: MachineManager;

  constructor(private readonly executor: Pick<Executor, 'run'> = new Executor()) {
    this.machines = new MachineManager(executor);
  }

  describe(): JsonObject {
    return {
      provider: 'zfs-nspawn-disposable',
      version: '1',
      actions: ['create', 'launch', 'inspect', 'exec', 'destroy'],
      exactArgv: true,
      durableLifecycleOwner: 'caller-job',
      persistenceOwner: 'caller-job',
      cleanupVerification: true,
    };
  }

  async create(request: DisposableMachineRequest): Promise<DisposableMachineInstance> {
    const id = token(request.id, 'id');
    const baseSnapshot = zfsName(request.baseSnapshot, 'baseSnapshot');
    const dataset = zfsName(request.dataset, 'dataset');
    const root = absolutePath(request.root, 'root');
    const argv = ['/usr/sbin/zfs', 'clone', '-o', `mountpoint=${root}`];
    for (const [name, value] of Object.entries(request.ownershipProperties ?? {}).sort(([left], [right]) => left.localeCompare(right))) {
      if (!/^com\.stealtheye\.babyx:[a-z-]+$/u.test(name) || !value || value.includes('\0')) throw new Error('ownership properties must be safe Baby-X ZFS properties');
      argv.push('-o', `${name}=${value}`);
    }
    argv.push(baseSnapshot, dataset);
    const clone = await this.executor.run({ argv });
    if (clone.exitCode !== 0) throw new Error(`zfs clone failed: ${clone.stderr}`);
    return { id, dataset, root, baseSnapshot, state: 'created' };
  }

  async launch(instance: DisposableMachineInstance, options: Omit<MachineLaunchOptions, 'definition'> = {}): Promise<DisposableMachineInstance> {
    const definition: MachineDefinition = {
      name: token(instance.id, 'id'),
      class: 'disposable-experiment',
      root: absolutePath(instance.root, 'root'),
      imageKind: 'directory',
      properties: {},
    };
    const launchResult = await this.machines.launch({ definition, ...options });
    if (launchResult.exitCode !== 0) throw new Error(`nspawn launch failed: ${launchResult.stderr}`);
    return { ...instance, state: 'running', launchResult };
  }

  inspect(id: string): Promise<JsonObject> {
    return this.machines.adopt(token(id, 'id'));
  }

  exec(id: string, argv: readonly string[], timeoutMs = 0): Promise<CommandResult> {
    return this.machines.shell(token(id, 'id'), argv, timeoutMs);
  }

  async destroy(instance: DisposableMachineInstance): Promise<JsonObject> {
    const id = token(instance.id, 'id');
    const dataset = zfsName(instance.dataset, 'dataset');
    const root = absolutePath(instance.root, 'root');
    if (dataset.includes('@')) throw new Error('clone dataset must not be a snapshot');
    const terminate = await this.executor.run({ argv: ['/usr/bin/machinectl', 'terminate', id] });
    const unmount = await this.executor.run({ argv: ['/usr/bin/umount', '-l', root] });
    const destroy = await this.executor.run({ argv: ['/usr/sbin/zfs', 'destroy', dataset] });
    const datasetReadback = await this.executor.run({ argv: ['/usr/sbin/zfs', 'list', '-H', '-o', 'name', dataset] });
    const mountReadback = await this.executor.run({ argv: ['/usr/bin/mountpoint', '-q', root] });
    return {
      id,
      dataset,
      root,
      clean: destroy.exitCode === 0 && datasetReadback.exitCode !== 0 && mountReadback.exitCode !== 0,
      terminateExitCode: terminate.exitCode,
      unmountExitCode: unmount.exitCode,
      destroyExitCode: destroy.exitCode,
      datasetAbsentVerified: datasetReadback.exitCode !== 0,
      rootUnmountedVerified: mountReadback.exitCode !== 0,
    };
  }

  async mountpoint(rootValue: string): Promise<CommandResult> {
    const root = absolutePath(rootValue, 'root');
    return this.executor.run({ argv: ['/usr/bin/mountpoint', '-q', root] });
  }

  async unmount(rootValue: string): Promise<CommandResult> {
    const root = absolutePath(rootValue, 'root');
    return this.executor.run({ argv: ['/usr/bin/umount', root] });
  }

  async listDescendants(datasetValue: string): Promise<CommandResult> {
    const dataset = zfsName(datasetValue, 'dataset');
    return this.executor.run({ argv: ['/usr/sbin/zfs', 'list', '-H', '-o', 'name', '-r', '-t', 'all', dataset] });
  }

  async destroyClone(datasetValue: string): Promise<CommandResult> {
    const dataset = zfsName(datasetValue, 'dataset');
    if (dataset.includes('@')) throw new Error('clone dataset must not be a snapshot');
    return this.executor.run({ argv: ['/usr/sbin/zfs', 'destroy', dataset] });
  }

}
