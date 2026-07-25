import { Executor, type CommandResult, type ExecutionTarget, type JsonObject } from '../core.ts';

export interface CriuCommonOptions {
  imagesDir: string;
  workDir?: string;
  logFile?: string;
  target?: ExecutionTarget;
  timeoutMs?: number;
  shellJob?: boolean;
  tcpEstablished?: boolean;
  fileLocks?: boolean;
  extUnixSk?: boolean;
  leaveRunning?: boolean;
  extraArgs?: readonly string[];
}

export interface CriuDumpOptions extends CriuCommonOptions { pid: number; }
export interface CriuRestoreOptions extends CriuCommonOptions { restoreDetached?: boolean; pidfile?: string; }

function text(value: string, field: string): string {
  if (!value || value.includes('\0')) throw new Error(`${field} must be non-empty and NUL-free`);
  return value;
}
function absolutePath(value: string, field: string): string {
  text(value, field);
  if (!value.startsWith('/')) throw new Error(`${field} must be absolute`);
  return value;
}
function positiveInt(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${field} must be a positive integer`);
  return value;
}

export class CriuManager {
  constructor(private readonly executor: Pick<Executor, 'run'> = new Executor()) {}

  describe(): JsonObject {
    return { provider: 'criu', version: '1', executable: '/usr/sbin/criu', operations: ['check', 'dump', 'pre-dump', 'restore'], exactArgv: true, machineTargets: true };
  }

  private common(options: CriuCommonOptions): string[] {
    const argv = ['--images-dir', absolutePath(options.imagesDir, 'imagesDir')];
    if (options.workDir) argv.push('--work-dir', absolutePath(options.workDir, 'workDir'));
    if (options.logFile) argv.push('--log-file', text(options.logFile, 'logFile'));
    if (options.shellJob) argv.push('--shell-job');
    if (options.tcpEstablished) argv.push('--tcp-established');
    if (options.fileLocks) argv.push('--file-locks');
    if (options.extUnixSk) argv.push('--ext-unix-sk');
    if (options.leaveRunning) argv.push('--leave-running');
    for (const arg of options.extraArgs ?? []) argv.push(text(arg, 'extraArgs'));
    return argv;
  }

  async check(target: ExecutionTarget = { kind: 'host' }, timeoutMs = 0): Promise<CommandResult> {
    return this.executor.run({ argv: ['/usr/sbin/criu', 'check', '--all'], target, timeoutMs });
  }

  async dump(options: CriuDumpOptions): Promise<CommandResult> {
    return this.executor.run({ argv: ['/usr/sbin/criu', 'dump', '--tree', String(positiveInt(options.pid, 'pid')), ...this.common(options)], target: options.target ?? { kind: 'host' }, timeoutMs: options.timeoutMs ?? 0 });
  }

  async preDump(options: CriuDumpOptions): Promise<CommandResult> {
    return this.executor.run({ argv: ['/usr/sbin/criu', 'pre-dump', '--tree', String(positiveInt(options.pid, 'pid')), ...this.common(options)], target: options.target ?? { kind: 'host' }, timeoutMs: options.timeoutMs ?? 0 });
  }

  async restore(options: CriuRestoreOptions): Promise<CommandResult> {
    const argv = ['/usr/sbin/criu', 'restore', ...this.common(options)];
    if (options.restoreDetached) argv.push('--restore-detached');
    if (options.pidfile) argv.push('--pidfile', absolutePath(options.pidfile, 'pidfile'));
    return this.executor.run({ argv, target: options.target ?? { kind: 'host' }, timeoutMs: options.timeoutMs ?? 0 });
  }
}
