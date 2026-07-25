import { Executor, type CommandResult, type ExecutionTarget, type JsonObject } from '../core.ts';

export const BPFTRACE_RECIPES = ['cpu-profile', 'scheduler-latency', 'blocked-tasks', 'syscall-count', 'syscall-latency', 'disk-latency', 'page-faults', 'process-exec', 'file-open', 'tcp-connect', 'tcp-reset', 'tcp-retransmit', 'socket-lifetime', 'memory-allocation'] as const;
export type BpftraceRecipe = typeof BPFTRACE_RECIPES[number];

export interface BpftraceRunOptions {
  program?: string;
  file?: string;
  target?: ExecutionTarget;
  timeoutMs?: number;
  output?: 'text' | 'json';
  unsafe?: boolean;
  include?: readonly string[];
  definitions?: Readonly<Record<string, string | number>>;
  extraArgs?: readonly string[];
}

const RECIPE_PROGRAMS: Readonly<Record<BpftraceRecipe, string>> = {
  'cpu-profile': 'profile:hz:99 { @[comm] = count(); }',
  'scheduler-latency': 'tracepoint:sched:sched_wakeup { @w[args->pid] = nsecs; } tracepoint:sched:sched_switch /@w[args->next_pid]/ { @us = hist((nsecs-@w[args->next_pid])/1000); delete(@w[args->next_pid]); }',
  'blocked-tasks': 'tracepoint:sched:sched_switch /args->prev_state != 0/ { @[args->prev_comm] = count(); }',
  'syscall-count': 'tracepoint:raw_syscalls:sys_enter { @[comm, args->id] = count(); }',
  'syscall-latency': 'tracepoint:raw_syscalls:sys_enter { @s[tid] = nsecs; } tracepoint:raw_syscalls:sys_exit /@s[tid]/ { @us = hist((nsecs-@s[tid])/1000); delete(@s[tid]); }',
  'disk-latency': 'tracepoint:block:block_rq_issue { @s[args->dev, args->sector] = nsecs; } tracepoint:block:block_rq_complete /@s[args->dev, args->sector]/ { @us = hist((nsecs-@s[args->dev, args->sector])/1000); delete(@s[args->dev, args->sector]); }',
  'page-faults': 'software:page-faults:1 { @[comm] = count(); }',
  'process-exec': 'tracepoint:sched:sched_process_exec { printf("%d %s\n", pid, str(args->filename)); }',
  'file-open': 'tracepoint:syscalls:sys_enter_openat { printf("%d %s %s\n", pid, comm, str(args->filename)); }',
  'tcp-connect': 'kprobe:tcp_v4_connect { printf("%d %s\n", pid, comm); }',
  'tcp-reset': 'tracepoint:tcp:tcp_receive_reset { @[comm] = count(); }',
  'tcp-retransmit': 'tracepoint:tcp:tcp_retransmit_skb { @[comm] = count(); }',
  'socket-lifetime': 'kprobe:tcp_set_state { @[comm, arg1] = count(); }',
  'memory-allocation': 'uprobe:/lib/x86_64-linux-gnu/libc.so.6:malloc { @[comm] = count(); }',
};

function validateText(value: string, field: string): string {
  if (!value || value.includes('\0')) throw new Error(`${field} must be non-empty and NUL-free`);
  return value;
}

function validatePath(value: string, field: string): string {
  validateText(value, field);
  if (!value.startsWith('/')) throw new Error(`${field} must be absolute`);
  return value;
}

export class BpftraceManager {
  constructor(private readonly executor: Pick<Executor, 'run'> = new Executor()) {}

  describe(): JsonObject {
    return { provider: 'bpftrace', version: '1', executable: '/usr/bin/bpftrace', recipes: [...BPFTRACE_RECIPES], output: ['text', 'json'], exactArgv: true };
  }

  recipe(name: BpftraceRecipe): string {
    if (!BPFTRACE_RECIPES.includes(name)) throw new Error(`unknown bpftrace recipe: ${name}`);
    return RECIPE_PROGRAMS[name];
  }

  async run(options: BpftraceRunOptions): Promise<CommandResult> {
    if (Boolean(options.program) === Boolean(options.file)) throw new Error('provide exactly one of program or file');
    const argv = ['/usr/bin/bpftrace'];
    if (options.output === 'json') argv.push('--output', 'json');
    if (options.unsafe) argv.push('--unsafe');
    for (const include of options.include ?? []) argv.push('--include', validatePath(include, 'include'));
    for (const [name, value] of Object.entries(options.definitions ?? {})) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(`invalid definition name: ${name}`);
      const rendered = String(value);
      if (rendered.includes('\0')) throw new Error(`invalid definition value: ${name}`);
      argv.push('--define', `${name}=${rendered}`);
    }
    for (const arg of options.extraArgs ?? []) argv.push(validateText(arg, 'extraArgs'));
    if (options.file) argv.push(validatePath(options.file, 'file'));
    else argv.push('-e', validateText(options.program!, 'program'));
    return this.executor.run({ argv, target: options.target ?? { kind: 'host' }, timeoutMs: options.timeoutMs ?? 0 });
  }

  async runRecipe(name: BpftraceRecipe, options: Omit<BpftraceRunOptions, 'program' | 'file'> = {}): Promise<CommandResult> {
    return this.run({ ...options, program: this.recipe(name) });
  }

  async listProbes(pattern?: string, target: ExecutionTarget = { kind: 'host' }): Promise<CommandResult> {
    const argv = ['/usr/bin/bpftrace', '--list'];
    if (pattern) argv.push(validateText(pattern, 'pattern'));
    return this.executor.run({ argv, target });
  }

  async info(target: ExecutionTarget = { kind: 'host' }): Promise<CommandResult> {
    return this.executor.run({ argv: ['/usr/bin/bpftrace', '--info'], target });
  }
}
