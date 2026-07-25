import { Executor, type CommandResult, type JsonObject } from '../core.ts';
import type { MachineDefinition } from './definitions.ts';

const MACHINE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const ABSOLUTE_PATH = /^\//;

function machineName(name: string): string {
  if (!MACHINE_PATTERN.test(name)) throw new Error('machine name must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}');
  return name;
}

function absolutePath(path: string, field: string): string {
  if (!ABSOLUTE_PATH.test(path) || path.includes('\0')) throw new Error(`${field} must be an absolute NUL-free path`);
  return path;
}

function exactArgv(argv: readonly string[]): string[] {
  if (argv.length === 0 || argv.some((value) => value.includes('\0'))) throw new Error('argv must be a non-empty NUL-free string array');
  return [...argv];
}

export interface MachineLaunchOptions {
  definition: MachineDefinition;
  boot?: boolean;
  ephemeral?: boolean;
  privateNetwork?: boolean;
  networkVeth?: boolean;
  readOnly?: boolean;
  binds?: readonly { source: string; destination?: string; readOnly?: boolean }[];
  environment?: Readonly<Record<string, string>>;
  properties?: readonly string[];
  extraArgs?: readonly string[];
  timeoutMs?: number;
}

export class MachineManager {
  constructor(private readonly executor: Pick<Executor, 'run'> = new Executor()) {}

  describe(): JsonObject {
    return {
      provider: 'systemd-nspawn',
      version: '1',
      tools: ['/usr/bin/systemd-nspawn', '/usr/bin/machinectl', '/usr/bin/systemd-run', '/usr/bin/journalctl'],
      machineClasses: ['persistent-workspace', 'clean-build', 'disposable-experiment', 'adversarial-arena', 'failure-replay', 'production-rehearsal', 'custom'],
      exactArgv: true,
      adoption: true,
      lifecycle: ['launch', 'list', 'show', 'status', 'shell', 'copy-in', 'copy-out', 'terminate', 'poweroff', 'reboot', 'enable', 'disable', 'remove'],
    };
  }

  async list(): Promise<CommandResult> {
    return this.executor.run({ argv: ['/usr/bin/machinectl', '--no-pager', '--no-legend', 'list'] });
  }

  async show(name: string, properties: readonly string[] = []): Promise<CommandResult> {
    const argv = ['/usr/bin/machinectl', '--no-pager', 'show', machineName(name)];
    for (const property of properties) {
      if (!/^[A-Za-z][A-Za-z0-9]+$/.test(property)) throw new Error(`invalid machine property: ${property}`);
      argv.push('--property', property);
    }
    return this.executor.run({ argv });
  }

  async status(name: string): Promise<CommandResult> {
    return this.executor.run({ argv: ['/usr/bin/machinectl', '--no-pager', 'status', machineName(name)] });
  }

  launchArgv(options: MachineLaunchOptions): string[] {
    const definition = options.definition;
    const argv = ['/usr/bin/systemd-nspawn', '--quiet', `--machine=${machineName(definition.name)}`];
    const root = absolutePath(definition.root, 'definition.root');
    argv.push(definition.imageKind === 'raw' ? `--image=${root}` : `--directory=${root}`);
    if (options.boot ?? true) argv.push('--boot');
    if (options.ephemeral) argv.push('--ephemeral');
    if (options.privateNetwork) argv.push('--private-network');
    if (options.networkVeth) argv.push('--network-veth');
    if (options.readOnly) argv.push('--read-only');
    for (const bind of options.binds ?? []) {
      const source = absolutePath(bind.source, 'bind.source');
      const destination = bind.destination ? absolutePath(bind.destination, 'bind.destination') : source;
      argv.push(`${bind.readOnly ? '--bind-ro' : '--bind'}=${source}:${destination}`);
    }
    for (const [name, value] of Object.entries(options.environment ?? {})) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || value.includes('\0')) throw new Error(`invalid environment entry: ${name}`);
      argv.push(`--setenv=${name}=${value}`);
    }
    for (const property of options.properties ?? []) {
      if (!property || property.includes('\0')) throw new Error('properties must be non-empty NUL-free strings');
      argv.push(`--property=${property}`);
    }
    argv.push(...exactArgv(options.extraArgs ?? ['--']));
    return argv;
  }

  async launch(options: MachineLaunchOptions): Promise<CommandResult> {
    return this.executor.run({ argv: this.launchArgv(options), timeoutMs: options.timeoutMs ?? 0 });
  }

  async shell(name: string, argv: readonly string[], timeoutMs = 0): Promise<CommandResult> {
    return this.executor.run({ target: { kind: 'machine', machine: machineName(name) }, argv: exactArgv(argv), timeoutMs });
  }

  async copyIn(name: string, source: string, destination: string): Promise<CommandResult> {
    return this.executor.run({ argv: ['/usr/bin/machinectl', 'copy-to', machineName(name), absolutePath(source, 'source'), absolutePath(destination, 'destination')] });
  }

  async copyOut(name: string, source: string, destination: string): Promise<CommandResult> {
    return this.executor.run({ argv: ['/usr/bin/machinectl', 'copy-from', machineName(name), absolutePath(source, 'source'), absolutePath(destination, 'destination')] });
  }

  async lifecycle(action: 'terminate' | 'poweroff' | 'reboot' | 'enable' | 'disable' | 'remove', name: string): Promise<CommandResult> {
    return this.executor.run({ argv: ['/usr/bin/machinectl', action, machineName(name)] });
  }

  async adopt(name: string): Promise<JsonObject> {
    const result = await this.show(name, ['Name', 'Class', 'Service', 'RootDirectory', 'State', 'Leader', 'Timestamp']);
    const properties: Record<string, string> = {};
    for (const line of result.stdout.split('\n')) {
      const index = line.indexOf('=');
      if (index > 0) properties[line.slice(0, index)] = line.slice(index + 1);
    }
    return {
      name: machineName(name),
      found: result.exitCode === 0,
      properties,
      result,
    };
  }

  async raw(tool: 'systemd-nspawn' | 'machinectl', argv: readonly string[], timeoutMs = 0): Promise<CommandResult> {
    const executable = tool === 'systemd-nspawn' ? '/usr/bin/systemd-nspawn' : '/usr/bin/machinectl';
    return this.executor.run({ argv: [executable, ...exactArgv(argv)], timeoutMs });
  }
}
