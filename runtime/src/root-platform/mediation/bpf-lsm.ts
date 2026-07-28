import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256, type JsonObject } from '../../core.ts';
import { MediationError } from './errors.ts';

export type BpfCommandRunner = (argv: string[]) => { status: number | null; stdout: string; stderr: string };

function defaultRunner(argv: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync('/usr/sbin/bpftool', argv, { encoding: 'utf8', timeout: 10_000, maxBuffer: 1_048_576 });
  return { status: result.status, stdout: String(result.stdout ?? '').slice(0, 65_536), stderr: String(result.stderr ?? result.error?.message ?? '').slice(0, 65_536) };
}

function candidates(name: string): string[] {
  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  return [
    join(moduleDirectory, '..', '..', 'native', 'bpf-lsm', name),
    join(process.cwd(), 'runtime', 'native', 'bpf-lsm', name === 'observe-exec.bpf.o' ? `build/${name}` : name),
    join(process.cwd(), 'dist', 'runtime', 'native', 'bpf-lsm', name),
  ];
}

function firstExisting(name: string): string | null { return candidates(name).find((path) => existsSync(path)) ?? null; }

export interface BpfLsmControllerOptions {
  run?: BpfCommandRunner;
  sourcePath?: string | null;
  objectPath?: string | null;
  activeLsms?: string[];
  bpftoolAvailable?: boolean;
  btfAvailable?: boolean;
}

export class BpfLsmController {
  readonly sourcePath: string | null;
  readonly objectPath: string | null;
  readonly sourceDigest: string | null;
  readonly objectDigest: string | null;

  private readonly run: BpfCommandRunner;
  private readonly activeLsmsOverride: string[] | undefined;
  private readonly bpftoolAvailableOverride: boolean | undefined;
  private readonly btfAvailableOverride: boolean | undefined;

  constructor(options: BpfLsmControllerOptions = {}) {
    this.run = options.run ?? defaultRunner;
    this.sourcePath = options.sourcePath === undefined ? firstExisting('observe-exec.bpf.c') : options.sourcePath;
    this.objectPath = options.objectPath === undefined ? firstExisting('observe-exec.bpf.o') : options.objectPath;
    this.sourceDigest = this.sourcePath === null ? null : sha256(readFileSync(this.sourcePath));
    this.objectDigest = this.objectPath === null ? null : sha256(readFileSync(this.objectPath));
    this.activeLsmsOverride = options.activeLsms;
    this.bpftoolAvailableOverride = options.bpftoolAvailable;
    this.btfAvailableOverride = options.btfAvailable;
  }

  probe(): JsonObject {
    const activeLsms = this.activeLsmsOverride ?? (existsSync('/sys/kernel/security/lsm') ? readFileSync('/sys/kernel/security/lsm', 'utf8').trim().split(',').filter(Boolean) : []);
    const bpftoolAvailable = this.bpftoolAvailableOverride ?? existsSync('/usr/sbin/bpftool');
    const btfAvailable = this.btfAvailableOverride ?? existsSync('/sys/kernel/btf/vmlinux');
    const bpfLsmActive = activeLsms.includes('bpf');
    const state = !bpfLsmActive ? 'UNAVAILABLE' : !bpftoolAvailable || !btfAvailable || this.objectPath === null ? 'DEGRADED' : 'EXPERIMENTAL';
    const reason = !bpfLsmActive ? 'bpf_lsm_not_active' : !bpftoolAvailable ? 'bpftool_unavailable' : !btfAvailable ? 'btf_unavailable' : this.objectPath === null ? 'bpf_object_unavailable' : 'observation_mode_only';
    return { supportState: state, health: { ok: state === 'EXPERIMENTAL', reason, activeLsms, bpftoolAvailable, btfAvailable, sourceDigest: this.sourceDigest, objectDigest: this.objectDigest, eventCount: 0, droppedEventCount: 0 } };
  }

  load(pinRoot: string): JsonObject {
    const probe = this.probe();
    if ((probe.supportState as string) === 'UNAVAILABLE') throw new MediationError('mediation_bpf_unavailable', 'BPF LSM is not active on this host', { probe });
    if (this.objectPath === null) throw new MediationError('mediation_bpf_unavailable', 'the deterministic BPF LSM object is unavailable', { probe });
    const result = this.run(['prog', 'loadall', this.objectPath, pinRoot, 'autoattach']);
    if (result.status !== 0) throw new MediationError('mediation_native_failed', 'BPF LSM load failed', { status: result.status, stderr: result.stderr.slice(0, 4_096) });
    return this.health(pinRoot);
  }

  health(pinRoot: string): JsonObject {
    const result = this.run(['prog', 'show', 'pinned', pinRoot, '-j']);
    return { ok: result.status === 0, pinRoot, objectDigest: this.objectDigest, stdoutDigest: sha256(result.stdout), stderr: result.status === 0 ? null : result.stderr.slice(0, 4_096), eventCount: 0, droppedEventCount: 0 };
  }

  detach(pinRoot: string): JsonObject {
    rmSync(pinRoot, { recursive: true, force: true });
    return { ok: !existsSync(pinRoot), pinRoot, detached: true };
  }

  reconcile(pinRoot: string, desired: 'ATTACHED' | 'DETACHED'): JsonObject {
    if (desired === 'DETACHED') return this.detach(pinRoot);
    const current = this.health(pinRoot);
    return current.ok === true ? current : this.load(pinRoot);
  }
}
