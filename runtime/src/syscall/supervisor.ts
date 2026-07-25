import { join } from 'node:path';
import { Executor, type CommandResult, type ExecutionTarget, type JsonObject } from '../core.ts';

export const SECCOMP_SUPERVISOR_ACTIONS = ['continue', 'errno', 'value', 'delay', 'delegate', 'inject-fd', 'record'] as const;
export type SeccompSupervisorAction = typeof SECCOMP_SUPERVISOR_ACTIONS[number];

export interface SeccompSupervisorOptions {
  executable?: string;
  target?: ExecutionTarget;
  timeoutMs?: number;
}

function validateExecutable(value: string): string {
  if (!value || value.includes('\0')) throw new Error('executable must be non-empty and NUL-free');
  if (!value.startsWith('/')) throw new Error('executable must be absolute');
  return value;
}

export class SeccompSupervisorManager {
  constructor(
    private readonly executor: Pick<Executor, 'run'> = new Executor(),
    private readonly defaultExecutable = join(process.cwd(), 'runtime', 'native', 'seccomp-supervisor', 'target', 'release', 'baby-x-seccomp-supervisor'),
  ) {}

  describe(): JsonObject {
    return {
      provider: 'seccomp-user-notification',
      version: '1',
      executable: this.defaultExecutable,
      supportedActions: ['describe', 'probe'],
      plannedResponseActions: [...SECCOMP_SUPERVISOR_ACTIONS],
      realUserNotification: true,
      exactArgv: true,
      limitations: ['native helper currently implements describe and probe only'],
    };
  }

  async nativeDescribe(options: SeccompSupervisorOptions = {}): Promise<CommandResult> {
    return this.invoke('describe', options);
  }

  async probe(options: SeccompSupervisorOptions = {}): Promise<CommandResult> {
    return this.invoke('probe', options);
  }

  async invoke(action: 'describe' | 'probe', options: SeccompSupervisorOptions = {}): Promise<CommandResult> {
    if (action !== 'describe' && action !== 'probe') throw new Error(`unsupported native seccomp supervisor action: ${action}`);
    const executable = validateExecutable(options.executable ?? this.defaultExecutable);
    return this.executor.run({
      argv: [executable, action],
      target: options.target ?? { kind: 'host' },
      timeoutMs: options.timeoutMs ?? 30_000,
    });
  }

  assertResponseAction(action: string): asserts action is SeccompSupervisorAction {
    if (!(SECCOMP_SUPERVISOR_ACTIONS as readonly string[]).includes(action)) {
      throw new Error(`unsupported seccomp response action: ${action}`);
    }
  }
}
