import { Executor, type CommandResult, type ExecutionTarget, type JsonObject } from '../core.ts';

export type SystemdScope = 'system' | 'user';

export interface SystemdRequestOptions {
  target?: ExecutionTarget;
  scope?: SystemdScope;
  timeoutMs?: number;
}

export interface SystemdUnitQuery extends SystemdRequestOptions {
  unit: string;
}

const UNIT_PATTERN = /^[A-Za-z0-9_.@:-]+$/;
const PROPERTY_PATTERN = /^[A-Za-z][A-Za-z0-9]+$/;

function assertUnit(unit: string): string {
  if (!UNIT_PATTERN.test(unit)) throw new Error('unit must be a non-empty systemd unit name without whitespace or option prefixes');
  if (unit.startsWith('-')) throw new Error('unit must not begin with an option prefix');
  return unit;
}

function assertProperties(properties: readonly string[]): string[] {
  return properties.map((property) => {
    if (!PROPERTY_PATTERN.test(property)) throw new Error(`invalid systemd property: ${property}`);
    return property;
  });
}

function targetPayload(options: SystemdRequestOptions): JsonObject {
  return {
    target: options.target ?? { kind: 'host' },
    timeoutMs: options.timeoutMs ?? 0,
  };
}

function systemctlPrefix(scope: SystemdScope = 'system'): string[] {
  return scope === 'user' ? ['/usr/bin/systemctl', '--user', '--no-pager'] : ['/usr/bin/systemctl', '--system', '--no-pager'];
}

export class SystemdManager {
  constructor(private readonly executor: Pick<Executor, 'run'> = new Executor()) {}

  describe(): JsonObject {
    return {
      provider: 'systemd',
      version: '1',
      scopes: ['system', 'user'],
      tools: ['/usr/bin/systemctl', '/usr/bin/systemd-run', '/usr/bin/journalctl'],
      unrestricted: true,
      hostAndMachineTargets: true,
    };
  }

  async list(options: SystemdRequestOptions & { type?: string; state?: string; pattern?: string } = {}): Promise<CommandResult> {
    const argv = [...systemctlPrefix(options.scope), 'list-units', '--all', '--plain', '--no-legend'];
    if (options.type) argv.push(`--type=${options.type}`);
    if (options.state) argv.push(`--state=${options.state}`);
    if (options.pattern) argv.push(options.pattern);
    return this.executor.run({ ...targetPayload(options), argv });
  }

  async show(query: SystemdUnitQuery & { properties?: readonly string[] }): Promise<CommandResult> {
    const argv = [...systemctlPrefix(query.scope), 'show', '--all', assertUnit(query.unit)];
    for (const property of assertProperties(query.properties ?? [])) argv.push('--property', property);
    return this.executor.run({ ...targetPayload(query), argv });
  }

  async action(action: 'start' | 'stop' | 'restart' | 'reload' | 'enable' | 'disable' | 'mask' | 'unmask' | 'reset-failed', query: SystemdUnitQuery): Promise<CommandResult> {
    return this.executor.run({ ...targetPayload(query), argv: [...systemctlPrefix(query.scope), action, '--', assertUnit(query.unit)] });
  }

  async daemonReload(options: SystemdRequestOptions = {}): Promise<CommandResult> {
    return this.executor.run({ ...targetPayload(options), argv: [...systemctlPrefix(options.scope), 'daemon-reload'] });
  }

  async kill(query: SystemdUnitQuery & { signal?: string; who?: 'main' | 'control' | 'all' }): Promise<CommandResult> {
    const signal = query.signal ?? 'SIGTERM';
    if (!/^SIG[A-Z0-9]+$/.test(signal)) throw new Error('signal must be a POSIX SIG* name');
    const who = query.who ?? 'all';
    return this.executor.run({
      ...targetPayload(query),
      argv: [...systemctlPrefix(query.scope), 'kill', `--signal=${signal}`, `--kill-whom=${who}`, '--', assertUnit(query.unit)],
    });
  }

  async logs(query: SystemdUnitQuery & { lines?: number; since?: string; until?: string; follow?: boolean }): Promise<CommandResult> {
    const lines = query.lines ?? 200;
    if (!Number.isSafeInteger(lines) || lines < 0 || lines > 100_000) throw new Error('lines must be an integer between 0 and 100000');
    const argv = ['/usr/bin/journalctl', '--no-pager', '--output=json-seq', '--unit', assertUnit(query.unit), '--lines', String(lines)];
    if (query.scope === 'user') argv.push('--user');
    if (query.since) argv.push('--since', query.since);
    if (query.until) argv.push('--until', query.until);
    if (query.follow) argv.push('--follow');
    return this.executor.run({ ...targetPayload(query), argv });
  }

  async run(options: SystemdRequestOptions & { argv: readonly string[]; unit?: string; properties?: Readonly<Record<string, string>> }): Promise<CommandResult> {
    if (options.argv.length === 0 || options.argv.some((value) => value.includes('\0'))) throw new Error('argv must be a non-empty NUL-free string array');
    const argv = ['/usr/bin/systemd-run', '--wait', '--pipe', '--collect', '--quiet'];
    if (options.scope === 'user') argv.push('--user');
    if (options.unit) argv.push(`--unit=${assertUnit(options.unit)}`);
    for (const [name, value] of Object.entries(options.properties ?? {})) {
      if (!PROPERTY_PATTERN.test(name) || value.includes('\0')) throw new Error(`invalid systemd-run property: ${name}`);
      argv.push(`--property=${name}=${value}`);
    }
    argv.push('--', ...options.argv);
    return this.executor.run({ ...targetPayload(options), argv });
  }

  async raw(tool: 'systemctl' | 'systemd-run' | 'journalctl', argv: readonly string[], options: SystemdRequestOptions = {}): Promise<CommandResult> {
    if (argv.some((value) => value.includes('\0'))) throw new Error('raw argv must be NUL-free');
    const executable = tool === 'systemctl' ? '/usr/bin/systemctl' : tool === 'systemd-run' ? '/usr/bin/systemd-run' : '/usr/bin/journalctl';
    return this.executor.run({ ...targetPayload(options), argv: [executable, ...argv] });
  }
}
