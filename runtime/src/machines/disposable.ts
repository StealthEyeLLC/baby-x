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
    const clone = await this.executor.run({ argv: ['/usr/sbin/zfs', 'clone', '-o', `mountpoint=${root}`, baseSnapshot, dataset] });
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
    const terminate = await this.machines.lifecycle('terminate', id);
    const unmount = await this.executor.run({ argv: ['/usr/bin/umount', '-l', root] });
    const destroy = await this.executor.run({ argv: ['/usr/sbin/zfs', 'destroy', '-r', dataset] });
    const datasetCheck = await this.executor.run({ argv: ['/usr/sbin/zfs', 'list', '-H', '-o', 'name', dataset] });
    const mountCheck = await this.executor.run({ argv: ['/usr/bin/mountpoint', '-q', root] });
    const clean = datasetCheck.exitCode !== 0 && mountCheck.exitCode !== 0;
    if (!clean) throw new Error('disposable machine cleanup verification failed');
    return {
      id,
      dataset,
      root,
      clean,
      terminateExitCode: terminate.exitCode,
      unmountExitCode: unmount.exitCode,
      destroyExitCode: destroy.exitCode,
    };
  }
}
