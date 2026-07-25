import { Executor, type CommandResult, type ExecutionTarget, type JsonObject } from '../core.ts';

export interface GdbRunOptions {
  executable?: string;
  coreFile?: string;
  pid?: number;
  commands?: readonly string[];
  batch?: boolean;
  quiet?: boolean;
  target?: ExecutionTarget;
  timeoutMs?: number;
  extraArgs?: readonly string[];
}

function text(value: string, field: string): string {
  if (!value || value.includes('\0')) throw new Error(`${field} must be non-empty and NUL-free`);
  return value;
}
function absolutePath(value: string, field: string): string {
  text(value, field);
  if (!value.startsWith('/')) throw new Error(`${field} must be absolute`);
  return value;
}
function pidValue(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error('pid must be a positive integer');
  return value;
}

export class GdbManager {
  constructor(private readonly executor: Pick<Executor, 'run'> = new Executor()) {}

  describe(): JsonObject {
    return { provider: 'gdb', version: '1', executable: '/usr/bin/gdb', modes: ['launch', 'attach', 'core'], exactArgv: true, machineTargets: true };
  }

  async run(options: GdbRunOptions): Promise<CommandResult> {
    const selectors = Number(Boolean(options.executable)) + Number(options.pid !== undefined) + Number(Boolean(options.coreFile));
    if (selectors === 0) throw new Error('provide executable, pid, or coreFile');
    if (options.coreFile && !options.executable) throw new Error('coreFile requires executable');
    const argv = ['/usr/bin/gdb'];
    if (options.quiet ?? true) argv.push('--quiet');
    if (options.batch ?? true) argv.push('--batch');
    for (const command of options.commands ?? []) argv.push('--ex', text(command, 'command'));
    for (const arg of options.extraArgs ?? []) argv.push(text(arg, 'extraArgs'));
    if (options.pid !== undefined) argv.push('--pid', String(pidValue(options.pid)));
    if (options.executable) argv.push('--se', absolutePath(options.executable, 'executable'));
    if (options.coreFile) argv.push('--core', absolutePath(options.coreFile, 'coreFile'));
    return this.executor.run({ argv, target: options.target ?? { kind: 'host' }, timeoutMs: options.timeoutMs ?? 0 });
  }

  async backtrace(options: Omit<GdbRunOptions, 'commands'>): Promise<CommandResult> {
    return this.run({ ...options, commands: ['set pagination off', 'thread apply all bt full'] });
  }

  async registers(options: Omit<GdbRunOptions, 'commands'>): Promise<CommandResult> {
    return this.run({ ...options, commands: ['set pagination off', 'info registers'] });
  }

  async mappings(options: Omit<GdbRunOptions, 'commands'>): Promise<CommandResult> {
    return this.run({ ...options, commands: ['set pagination off', 'info proc mappings'] });
  }
}
