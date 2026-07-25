import { Executor, type CommandResult, type ExecutionTarget, type JsonObject } from '../core.ts';

export const PACKET_TOOLS = ['tcpdump', 'dumpcap', 'tshark'] as const;
export type PacketTool = typeof PACKET_TOOLS[number];

export interface CaptureOptions {
  tool?: PacketTool;
  interface?: string;
  outputPath: string;
  filter?: string;
  snaplen?: number;
  packetCount?: number;
  durationSeconds?: number;
  rotateSeconds?: number;
  rotateFiles?: number;
  promiscuous?: boolean;
  immediate?: boolean;
  target?: ExecutionTarget;
  timeoutMs?: number;
  extraArgs?: readonly string[];
}

function text(value: string, field: string): string {
  if (!value || value.includes('\0')) throw new Error(`${field} must be non-empty and NUL-free`);
  return value;
}
function absolutePath(value: string): string {
  text(value, 'outputPath');
  if (!value.startsWith('/')) throw new Error('outputPath must be absolute');
  return value;
}
function bounded(value: number | undefined, field: string, min: number, max: number): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`${field} must be an integer between ${min} and ${max}`);
  return value;
}

export class PacketCaptureManager {
  constructor(private readonly executor: Pick<Executor, 'run'> = new Executor()) {}

  describe(): JsonObject {
    return { provider: 'packet-capture', version: '1', tools: [...PACKET_TOOLS], exactArgv: true, outputs: ['pcap', 'pcapng'], boundedRotation: true };
  }

  async interfaces(tool: PacketTool = 'tcpdump', target: ExecutionTarget = { kind: 'host' }): Promise<CommandResult> {
    const argv = tool === 'tcpdump' ? ['/usr/bin/tcpdump', '--list-interfaces'] : [`/usr/bin/${tool}`, '--list-interfaces'];
    return this.executor.run({ argv, target });
  }

  async capture(options: CaptureOptions): Promise<CommandResult> {
    const tool = options.tool ?? 'tcpdump';
    if (!PACKET_TOOLS.includes(tool)) throw new Error(`unsupported packet tool: ${tool}`);
    const iface = text(options.interface ?? 'any', 'interface');
    if (iface.startsWith('-')) throw new Error('interface must not begin with an option prefix');
    const output = absolutePath(options.outputPath);
    const snaplen = bounded(options.snaplen, 'snaplen', 0, 262144);
    const count = bounded(options.packetCount, 'packetCount', 1, 1_000_000_000);
    const duration = bounded(options.durationSeconds, 'durationSeconds', 1, 31_536_000);
    const rotateSeconds = bounded(options.rotateSeconds, 'rotateSeconds', 1, 31_536_000);
    const rotateFiles = bounded(options.rotateFiles, 'rotateFiles', 1, 1_000_000);
    const argv: string[] = [`/usr/bin/${tool}`];

    if (tool === 'tcpdump') {
      argv.push('--interface', iface, '--write', output, '--numeric');
      if (snaplen !== undefined) argv.push('--snapshot-length', String(snaplen));
      if (count !== undefined) argv.push('--count', String(count));
      if (rotateSeconds !== undefined) argv.push('--rotate-seconds', String(rotateSeconds));
      if (rotateFiles !== undefined) argv.push('--rotate-file-count', String(rotateFiles));
      if (options.promiscuous === false) argv.push('--no-promiscuous-mode');
      if (options.immediate) argv.push('--immediate-mode');
      if (duration !== undefined) argv.unshift('/usr/bin/timeout', '--signal=INT', '--kill-after=5s', String(duration));
      for (const arg of options.extraArgs ?? []) argv.push(text(arg, 'extraArgs'));
      if (options.filter) argv.push(text(options.filter, 'filter'));
    } else {
      argv.push('--interface', iface, '--write', output);
      if (snaplen !== undefined) argv.push('--snapshot-length', String(snaplen));
      if (count !== undefined) argv.push('--count', String(count));
      if (duration !== undefined) argv.push('--autostop', `duration:${duration}`);
      if (rotateSeconds !== undefined) argv.push('--ring-buffer', `duration:${rotateSeconds}`);
      if (rotateFiles !== undefined) argv.push('--ring-buffer', `files:${rotateFiles}`);
      if (options.promiscuous === false) argv.push('--no-promiscuous-mode');
      for (const arg of options.extraArgs ?? []) argv.push(text(arg, 'extraArgs'));
      if (options.filter) argv.push('--capture-filter', text(options.filter, 'filter'));
    }
    return this.executor.run({ argv, target: options.target ?? { kind: 'host' }, timeoutMs: options.timeoutMs ?? 0 });
  }

  async decode(path: string, displayFilter?: string, target: ExecutionTarget = { kind: 'host' }): Promise<CommandResult> {
    const argv = ['/usr/bin/tshark', '--read-file', absolutePath(path), '--output', 'json'];
    if (displayFilter) argv.push('--display-filter', text(displayFilter, 'displayFilter'));
    return this.executor.run({ argv, target });
  }

  async statistics(path: string, statistic: string, target: ExecutionTarget = { kind: 'host' }): Promise<CommandResult> {
    return this.executor.run({ argv: ['/usr/bin/tshark', '--read-file', absolutePath(path), '--statistics', text(statistic, 'statistic')], target });
  }
}
