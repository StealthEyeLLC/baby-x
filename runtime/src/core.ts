import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { constants as fsConstants, createReadStream, createWriteStream, existsSync, mkdirSync, openSync, closeSync, fsyncSync, readFileSync, readSync, renameSync, rmSync, statSync, writeFileSync, writeSync, readdirSync, copyFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { processIdentity as readProcessIdentity } from './process/identity.ts';
import { OPERATION_CATALOG_VERSION, OPERATION_DEFINITIONS, OPERATION_NAMES, type OperationDefinition } from './operations/definitions.ts';

export type JsonObject = Record<string, unknown>;

export interface ProcessIdentity {
  pid: number;
  processStartTime?: string;
  executablePath?: string;
  pgid?: number;
  bootId?: string;
}

export type CompleteProcessIdentity = ProcessIdentity & { processStartTime: string; executablePath: string; bootId: string };
export type ExecutionTarget = { kind: 'host' } | { kind: 'machine'; machine: string } | { kind: 'machine-process'; machine: string; processIdentity: CompleteProcessIdentity };

export interface CommandResult {
  argv: string[];
  target: ExecutionTarget;
  cwd: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  stdoutSha256: string;
  stderrSha256: string;
}

export interface BabyXProof {
  version: '1';
  requestId: string;
  operation: string;
  ok: boolean;
  startedAt: string;
  completedAt: string;
  hostname: string;
  machineIdSha256: string;
  resultSha256: string;
  keyId: string;
  signature: string;
}

export interface SpecificationStatement {
  id: string;
  classification: 'declared-requirement' | 'static-fact' | 'observed-invariant' | 'hypothesis' | 'falsified-hypothesis';
  subject: string;
  predicate: string;
  value: unknown;
  provenance: JsonObject[];
  confidence?: number;
  firstObservedAt?: string;
  lastObservedAt?: string;
  falsifiedBy?: string[];
}

export interface InterventionLease {
  targetIdentity: ProcessIdentity;
  ownerKind: 'gdb' | 'criu' | 'ptrace' | 'other';
  ownerId: string;
  acquiredAt: string;
  state: 'active' | 'releasing' | 'stale';
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const QRT_MAGIC = Buffer.from('QRT1');
const MAX_INLINE = 65_536;

export function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const object = value as JsonObject;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(object[key])}`).join(',')}}`;
}

export function encodeFrame(value: unknown): Buffer {
  const body = Buffer.from(canonicalize(value));
  const frame = Buffer.allocUnsafe(8 + body.length);
  QRT_MAGIC.copy(frame, 0);
  frame.writeUInt32BE(body.length, 4);
  body.copy(frame, 8);
  return frame;
}

export function decodeFrame(frame: Buffer, maximum = 16 * 1024 * 1024): unknown {
  if (frame.length < 8 || !frame.subarray(0, 4).equals(QRT_MAGIC)) throw new Error('invalid QRT1 frame');
  const length = frame.readUInt32BE(4);
  if (length > maximum || frame.length !== length + 8) throw new Error('invalid QRT1 frame length');
  return JSON.parse(frame.subarray(8).toString('utf8')) as unknown;
}

export function signCanonical(privateKey: string | Buffer, value: unknown): string {
  return cryptoSign(null, Buffer.from(canonicalize(value)), privateKey).toString('base64');
}

export function verifyCanonical(publicKey: string | Buffer, value: unknown, signature: string): boolean {
  return cryptoVerify(null, Buffer.from(canonicalize(value)), publicKey, Buffer.from(signature, 'base64'));
}

export class AtomicStore<T extends JsonObject> {
  constructor(readonly path: string, readonly initial: T) { mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); }
  read(): T {
    if (!existsSync(this.path)) return structuredClone(this.initial);
    return JSON.parse(readFileSync(this.path, 'utf8')) as T;
  }
  write(value: T): void {
    const temporary = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    const file = openSync(temporary, 'wx', 0o600);
    try {
      writeFileSync(file, `${canonicalize(value)}\n`);
      fsyncSync(file);
    } finally { closeSync(file); }
    renameSync(temporary, this.path);
    const directory = openSync(dirname(this.path), 'r');
    try { fsyncSync(directory); } finally { closeSync(directory); }
  }
  update(mutator: (current: T) => T): T { const next = mutator(this.read()); this.write(next); return next; }
}

function requiredString(payload: JsonObject, key: string): string {
  const value = payload[key];
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) throw new Error(`${key} must be a non-empty NUL-free string`);
  return value;
}

function completeExecutionIdentity(value: unknown): CompleteProcessIdentity {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('machine process target requires processIdentity');
  const identity = value as JsonObject;
  const pid = Number(identity.pid);
  const pgid = identity.pgid === undefined ? undefined : Number(identity.pgid);
  const processStartTime = requiredString(identity, 'processStartTime');
  const executablePath = requiredString(identity, 'executablePath');
  const bootId = requiredString(identity, 'bootId');
  if (!Number.isSafeInteger(pid) || pid < 1 || (pgid !== undefined && (!Number.isSafeInteger(pgid) || pgid < 1))) throw new Error('machine process target identity has invalid pid or pgid');
  return { pid, ...(pgid === undefined ? {} : { pgid }), processStartTime, executablePath, bootId };
}

function sameCompleteIdentity(expected: CompleteProcessIdentity, actual: ProcessIdentity): boolean {
  return expected.pid === actual.pid
    && expected.processStartTime === actual.processStartTime
    && expected.executablePath === actual.executablePath
    && expected.bootId === actual.bootId
    && (expected.pgid === undefined || expected.pgid === actual.pgid);
}

function sameJobIdentity(expected: CompleteProcessIdentity, actual: ProcessIdentity): boolean {
  return expected.pid === actual.pid
    && expected.processStartTime === actual.processStartTime
    && expected.bootId === actual.bootId
    && (expected.pgid === undefined || expected.pgid === actual.pgid);
}

function isCompleteProcessIdentity(identity: ProcessIdentity | undefined): identity is CompleteProcessIdentity {
  return identity !== undefined
    && typeof identity.processStartTime === 'string'
    && identity.processStartTime.length > 0
    && typeof identity.executablePath === 'string'
    && identity.executablePath.length > 0
    && typeof identity.bootId === 'string'
    && identity.bootId.length > 0;
}

function isTerminalJob(record: JobRecord): boolean {
  return ['completed', 'failed', 'cancelled', 'lost'].includes(record.status);
}

function assertMachineProcessTarget(target: ExecutionTarget, resolver: (pid: number) => ProcessIdentity): void {
  if (target.kind !== 'machine-process') return;
  let actual: ProcessIdentity;
  try { actual = resolver(target.processIdentity.pid); }
  catch { throw new Error('machine target process is absent before execution'); }
  if (!sameCompleteIdentity(target.processIdentity, actual)) throw new Error('machine target process identity changed before execution');
}

function optionalTarget(payload: JsonObject): ExecutionTarget {
  const candidate = payload.target;
  if (candidate === undefined) return { kind: 'host' };
  if (candidate === null || typeof candidate !== 'object') throw new Error('target must be an object');
  const target = candidate as JsonObject;
  if (target.kind === 'host') return { kind: 'host' };
  if (target.kind === 'machine') return { kind: 'machine', machine: requiredString(target, 'machine') };
  if (target.kind === 'machine-process') return { kind: 'machine-process', machine: requiredString(target, 'machine'), processIdentity: completeExecutionIdentity(target.processIdentity) };
  throw new Error('target kind must be host, machine, or machine-process');
}

function assertStrings(values: unknown, key: string): string[] {
  if (!Array.isArray(values) || values.length === 0 || values.some((value) => typeof value !== 'string' || value.includes('\0'))) throw new Error(`${key} must be a non-empty NUL-free string array`);
  return values as string[];
}

export function machineWrapped(target: ExecutionTarget, argv: string[], cwd: string, environment: JsonObject): string[] {
  if (target.kind === 'host') return argv;
  if (target.kind === 'machine') {
    const wrapped = ['/usr/bin/machinectl', '--quiet', '--uid=root'];
    for (const [key, value] of Object.entries(environment)) wrapped.push(`--setenv=${key}=${String(value)}`);
    wrapped.push('shell', target.machine, '/usr/bin/env', `--chdir=${cwd}`, '--', ...argv);
    return wrapped;
  }
  const pid = String(target.processIdentity.pid);
  // nsenter's default PID-namespace fork supervisor mirrors a stopped child by
  // stopping itself. Detached durable jobs cannot receive that wrapper's exit
  // event until an external SIGCONT, so use no-fork and create the actual
  // workload as an explicit shell child after setns(CLONE_NEWPID).
  const wrapped = ['/usr/bin/nsenter', '--target', pid, '--no-fork', '--mount', '--uts', '--ipc', '--net', '--pid', '--cgroup', `--root=/proc/${pid}/root`, `--wdns=${cwd}`, '--', '/usr/bin/env'];
  for (const [key, value] of Object.entries(environment)) wrapped.push(`${key}=${String(value)}`);
  wrapped.push('/bin/sh', '-c', '"$@"; status=$?; exit "$status"', 'baby-x-machine-exec', ...argv);
  return wrapped;
}

function bounded(value: Buffer): string { return value.subarray(0, MAX_INLINE).toString('base64'); }

export class Executor {
  async run(payload: JsonObject): Promise<CommandResult> {
    const target = optionalTarget(payload);
    const argv = assertStrings(payload.argv, 'argv');
    const cwd = typeof payload.cwd === 'string' ? payload.cwd : '/';
    const environment = payload.env && typeof payload.env === 'object' ? payload.env as JsonObject : {};
    assertMachineProcessTarget(target, readProcessIdentity);
    const effective = machineWrapped(target, argv, cwd, environment);
    const started = Date.now();
    const startedAt = new Date(started).toISOString();
    const executable = effective[0];
    if (executable === undefined) throw new Error('empty executable');
    const result = spawnSync(executable, effective.slice(1), {
      cwd: target.kind === 'host' ? cwd : '/',
      env: { ...process.env, ...Object.fromEntries(Object.entries(environment).map(([key, value]) => [key, String(value)])) },
      encoding: null,
      timeout: typeof payload.timeoutMs === 'number' ? payload.timeoutMs : 0,
      maxBuffer: 64 * 1024 * 1024,
      killSignal: 'SIGTERM',
    });
    const completed = Date.now();
    const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.alloc(0);
    const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.error?.message ?? '');
    return {
      argv,
      target,
      cwd,
      startedAt,
      completedAt: new Date(completed).toISOString(),
      durationMs: completed - started,
      exitCode: result.status,
      signal: result.signal,
      stdout: bounded(stdout),
      stderr: bounded(stderr),
      stdoutSha256: sha256(stdout),
      stderrSha256: sha256(stderr),
    };
  }
}

export interface JobRecord extends JsonObject {
  id: string;
  operation: string;
  status: 'starting' | 'running' | 'completed' | 'failed' | 'cancelled' | 'lost';
  target: ExecutionTarget;
  argv: string[];
  cwd: string;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  pid?: number;
  pgid?: number;
  exitCode?: number | null;
  signal?: string | null;
  stdoutPath: string;
  stderrPath: string;
  metadata?: JsonObject;
  processIdentity?: ProcessIdentity;
  timeoutMs?: number;
  reconciliation?: {
    classification: 'running-exact' | 'process-absent' | 'identity-conflict' | 'identity-incomplete';
    observedAt: string;
    actualIdentity?: ProcessIdentity;
  };
}

export interface JobManagerOptions {
  processIdentity?: (pid: number) => ProcessIdentity;
  now?: () => string;
}

export type JobChangeListener = (record: JobRecord) => void | Promise<void>;

export class JobManager {
  private readonly listeners = new Set<JobChangeListener>();
  private readonly store: AtomicStore<{ jobs: Record<string, JobRecord> }>;
  private readonly processIdentity: (pid: number) => ProcessIdentity;
  private readonly now: () => string;
  constructor(private readonly root: string, options: JobManagerOptions = {}) {
    mkdirSync(join(root, 'streams'), { recursive: true, mode: 0o700 });
    this.store = new AtomicStore(join(root, 'jobs.json'), { jobs: {} });
    this.processIdentity = options.processIdentity ?? readProcessIdentity;
    this.now = options.now ?? (() => new Date().toISOString());
  }
  list(limit = 1_000, status?: JobRecord['status']): JobRecord[] { if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) throw new Error('job list limit must be between 1 and 10000'); return Object.values(this.store.read().jobs).filter((record) => status === undefined || record.status === status).sort((left, right) => left.id.localeCompare(right.id)).slice(0, limit); }
  get(id: string): JobRecord { const record = this.store.read().jobs[id]; if (!record) throw new Error('job not found'); return record; }
  onChange(listener: JobChangeListener): () => void { this.listeners.add(listener); return () => this.listeners.delete(listener); }
  private notify(record: JobRecord): void {
    for (const listener of this.listeners) queueMicrotask(() => { void Promise.resolve(listener(structuredClone(record))).catch(() => undefined); });
  }
  start(operation: string, payload: JsonObject): JobRecord {
    const id = randomUUID();
    const target = optionalTarget(payload);
    const argv = assertStrings(payload.argv, 'argv');
    const cwd = typeof payload.cwd === 'string' ? payload.cwd : '/';
    const env = payload.env && typeof payload.env === 'object' ? payload.env as JsonObject : {};
    const metadata = payload.metadata && typeof payload.metadata === 'object' && !Array.isArray(payload.metadata) ? structuredClone(payload.metadata as JsonObject) : undefined;
    const timeoutMs = payload.timeoutMs === undefined ? undefined : Number(payload.timeoutMs);
    assertMachineProcessTarget(target, this.processIdentity);
    if (timeoutMs !== undefined && (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0)) throw new Error('timeoutMs must be a positive safe integer');
    const effective = machineWrapped(target, argv, cwd, env);
    const executable = effective[0];
    if (!executable) throw new Error('empty executable');
    const stdoutPath = join(this.root, 'streams', `${id}.stdout`);
    const stderrPath = join(this.root, 'streams', `${id}.stderr`);
    const createdAt = this.now();
    const reserved: JobRecord = {
      id, operation, status: 'starting', target, argv, cwd, createdAt, stdoutPath, stderrPath,
      ...(metadata === undefined ? {} : { metadata }),
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
    };
    this.store.update((current) => ({ jobs: { ...current.jobs, [id]: reserved } }));
    this.notify(reserved);
    const stdoutFd = openSync(stdoutPath, 'a', 0o600);
    const stderrFd = openSync(stderrPath, 'a', 0o600);
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(executable, effective.slice(1), { cwd: target.kind === 'host' ? cwd : '/', env: { ...process.env, ...Object.fromEntries(Object.entries(env).map(([key, value]) => [key, String(value)])) }, detached: true, stdio: ['ignore', stdoutFd, stderrFd] });
    } catch (error) {
      closeSync(stdoutFd); closeSync(stderrFd);
      const failed: JobRecord = { ...reserved, status: 'failed', completedAt: this.now(), metadata: { ...(reserved.metadata ?? {}), spawnError: error instanceof Error ? error.message : String(error) } };
      this.store.update((current) => ({ jobs: { ...current.jobs, [id]: failed } }));
      this.notify(failed);
      throw error;
    }
    closeSync(stdoutFd); closeSync(stderrFd);
    if (child.pid === undefined) {
      child.once('error', () => undefined);
      const failed: JobRecord = { ...reserved, status: 'failed', completedAt: this.now(), metadata: { ...(reserved.metadata ?? {}), spawnError: 'spawn returned no pid' } };
      this.store.update((current) => ({ jobs: { ...current.jobs, [id]: failed } }));
      this.notify(failed);
      throw new Error('spawn returned no pid');
    }
    let identity: ProcessIdentity;
    try { identity = this.processIdentity(child.pid); } catch { identity = { pid: child.pid, pgid: child.pid }; }
    const running: JobRecord = { ...reserved, status: 'running', startedAt: this.now(), pid: child.pid, pgid: child.pid, processIdentity: identity };
    this.store.update((current) => ({ jobs: { ...current.jobs, [id]: running } }));
    this.notify(running);
    let timeout: NodeJS.Timeout | undefined;
    if (timeoutMs !== undefined) {
      timeout = setTimeout(() => {
        try {
          const current = this.get(id);
          if (current.status !== 'running' || current.pid === undefined || current.pgid === undefined || !isCompleteProcessIdentity(current.processIdentity)) return;
          let actual: ProcessIdentity;
          try { actual = this.processIdentity(current.pid); } catch { this.reconcile(id); return; }
          if (!sameJobIdentity(current.processIdentity, actual)) { this.reconcile(id); return; }
          this.store.update((state) => {
            const existing = state.jobs[id];
            if (!existing || isTerminalJob(existing)) return state;
            return { jobs: { ...state.jobs, [id]: { ...existing, metadata: { ...(existing.metadata ?? {}), timeoutTriggeredAt: this.now() } } } };
          });
          process.kill(-current.pgid, 'SIGTERM');
        } catch {}
      }, timeoutMs);
      timeout.unref();
    }
    child.once('error', (error) => {
      if (timeout !== undefined) clearTimeout(timeout);
      let failed: JobRecord | undefined;
      this.store.update((current) => {
        const existing = current.jobs[id];
        if (!existing || isTerminalJob(existing)) return current;
        failed = { ...existing, status: 'failed', completedAt: this.now(), metadata: { ...(existing.metadata ?? {}), spawnError: error.message } };
        return { jobs: { ...current.jobs, [id]: failed } };
      });
      if (failed !== undefined) this.notify(failed);
    });
    child.once('exit', (code, signal) => {
      if (timeout !== undefined) clearTimeout(timeout);
      let completed: JobRecord | undefined;
      this.store.update((current) => {
        const existing = current.jobs[id];
        if (!existing || isTerminalJob(existing)) return current;
        completed = { ...existing, status: signal ? 'failed' : code === 0 ? 'completed' : 'failed', exitCode: code, signal, completedAt: this.now() };
        return { jobs: { ...current.jobs, [id]: completed } };
      });
      if (completed !== undefined) this.notify(completed);
    });
    child.unref();
    return running;
  }
  async wait(id: string, timeoutMs = 30_000): Promise<JobRecord> {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 300_000) throw new Error('job wait timeoutMs must be between 0 and 300000');
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const record = this.get(id);
      if (isTerminalJob(record) || Date.now() >= deadline) return record;
      await new Promise<void>((resolve) => setTimeout(resolve, Math.min(25, Math.max(1, deadline - Date.now()))));
    }
  }
  reconcile(id: string): JobRecord {
    const record = this.get(id);
    if (record.status !== 'starting' && record.status !== 'running') return record;
    const observedAt = this.now();
    const expected = record.processIdentity;
    let classification: NonNullable<JobRecord['reconciliation']>['classification'];
    let actual: ProcessIdentity | undefined;
    if (record.pid === undefined || expected === undefined || expected.processStartTime === undefined || expected.executablePath === undefined || expected.bootId === undefined) classification = 'identity-incomplete';
    else {
      try { actual = this.processIdentity(record.pid); } catch { classification = 'process-absent'; }
      if (actual !== undefined) {
        classification = isCompleteProcessIdentity(expected) && sameJobIdentity(expected, actual)
          ? 'running-exact' : 'identity-conflict';
      }
    }
    if (classification === 'running-exact') return { ...record, reconciliation: { classification, observedAt, ...(actual === undefined ? {} : { actualIdentity: actual }) } };
    const next: JobRecord = { ...record, status: 'lost', completedAt: observedAt, reconciliation: { classification, observedAt, ...(actual === undefined ? {} : { actualIdentity: actual }) } };
    this.store.update((current) => ({ jobs: { ...current.jobs, [id]: next } }));
    this.notify(next);
    return next;
  }
  reconcileRunning(limit = 1_000): JobRecord[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) throw new Error('job reconcile limit must be between 1 and 10000');
    return this.list(10_000).filter((record) => record.status === 'starting' || record.status === 'running').sort((left, right) => left.id.localeCompare(right.id)).slice(0, limit).map((record) => this.reconcile(record.id));
  }
  cancel(id: string, signal = 'SIGTERM'): JobRecord {
    const record = this.get(id);
    if (isTerminalJob(record)) return record;
    if (record.status === 'starting') {
      const next: JobRecord = { ...record, status: 'cancelled', signal, completedAt: this.now() };
      this.store.update((current) => ({ jobs: { ...current.jobs, [id]: next } }));
      this.notify(next);
      return next;
    }
    if (record.pid === undefined || record.pgid === undefined || !isCompleteProcessIdentity(record.processIdentity)) return this.reconcile(id);
    let actual: ProcessIdentity;
    try { actual = this.processIdentity(record.pid); } catch { return this.reconcile(id); }
    if (!sameJobIdentity(record.processIdentity, actual)) return this.reconcile(id);
    try { process.kill(-record.pgid, signal as NodeJS.Signals); } catch (error) {
      if (error instanceof Error && 'code' in error && (error as NodeJS.ErrnoException).code === 'ESRCH') return this.reconcile(id);
      throw error;
    }
    let next: JobRecord = record;
    this.store.update((current) => {
      const existing = current.jobs[id];
      if (!existing || isTerminalJob(existing)) { if (existing) next = existing; return current; }
      next = { ...existing, status: 'cancelled', signal, completedAt: this.now() };
      return { jobs: { ...current.jobs, [id]: next } };
    });
    if (next.status === 'cancelled') this.notify(next);
    return next;
  }
  read(id: string, stream: 'stdout' | 'stderr', offset = 0, limit = 65_536): JsonObject {
    if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('stream offset must be a non-negative safe integer');
    if (!Number.isSafeInteger(limit) || limit < 0 || limit > MAX_INLINE) throw new Error(`stream limit must be between 0 and ${MAX_INLINE}`);
    const record = this.get(id);
    const path = stream === 'stdout' ? record.stdoutPath : record.stderrPath;
    const size = statSync(path).size;
    const count = Math.max(0, Math.min(limit, size - offset));
    const buffer = Buffer.alloc(count);
    const fd = openSync(path, 'r');
    try { if (count > 0) readSync(fd, buffer, 0, count, offset); } finally { closeSync(fd); }
    return { data: buffer.toString('base64'), offset: offset + count, eof: offset + count >= size, encoding: 'base64' };
  }
}

export class FileManager {
  stat(payload: JsonObject): JsonObject { const path = requiredString(payload, 'path'); const stat = statSync(path); return { path, size: stat.size, mode: stat.mode, uid: stat.uid, gid: stat.gid, isFile: stat.isFile(), isDirectory: stat.isDirectory(), sha256: stat.isFile() ? sha256(readFileSync(path)) : undefined }; }
  read(payload: JsonObject): JsonObject {
    const path = requiredString(payload, 'path');
    const offset = payload.offset === undefined ? 0 : Number(payload.offset);
    const limit = payload.limit === undefined ? MAX_INLINE : Number(payload.limit);
    if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('file offset must be a non-negative safe integer');
    if (!Number.isSafeInteger(limit) || limit < 0 || limit > MAX_INLINE) throw new Error(`file limit must be between 0 and ${MAX_INLINE}`);
    const size = statSync(path).size; const count = Math.max(0, Math.min(limit, size - offset)); const buffer = Buffer.alloc(count); const fd = openSync(path, 'r');
    try { if (count > 0) readSync(fd, buffer, 0, count, offset); } finally { closeSync(fd); }
    return { data: payload.encoding === 'utf8' ? buffer.toString('utf8') : buffer.toString('base64'), encoding: payload.encoding === 'utf8' ? 'utf8' : 'base64', offset: offset + count, eof: offset + count >= size, sha256: sha256(readFileSync(path)) };
  }
  write(payload: JsonObject): JsonObject { const path = requiredString(payload, 'path'); const data = requiredString(payload, 'data'); const buffer = Buffer.from(data, payload.encoding === 'base64' ? 'base64' : 'utf8'); if (buffer.length > MAX_INLINE) throw new Error(`file write is limited to ${MAX_INLINE} bytes`); mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); const offset = payload.offset === undefined ? null : Number(payload.offset); if (offset !== null && (!Number.isSafeInteger(offset) || offset < 0)) throw new Error('file offset must be a non-negative safe integer'); const fd = openSync(path, payload.create === false ? 'r+' : 'a+', 0o600); try { writeSync(fd, buffer, 0, buffer.length, offset); fsyncSync(fd); } finally { closeSync(fd); } return this.stat({ path }); }
  replace(payload: JsonObject): JsonObject {
    const path = requiredString(payload, 'path');
    if (typeof payload.expectedSha256 === 'string' && (!existsSync(path) || sha256(readFileSync(path)) !== payload.expectedSha256)) throw new Error('compare-and-swap mismatch');
    const data = Buffer.from(requiredString(payload, 'data'), payload.encoding === 'base64' ? 'base64' : 'utf8');
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); const temporary = `${path}.${randomUUID()}.tmp`; const fd = openSync(temporary, 'wx', 0o600);
    try { writeFileSync(fd, data); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(temporary, path); const directory = openSync(dirname(path), 'r'); try { fsyncSync(directory); } finally { closeSync(directory); }
    return this.stat({ path });
  }
  patch(payload: JsonObject): JsonObject {
    const path = requiredString(payload, 'path');
    const expectedSha256 = requiredString(payload, 'expectedSha256');
    const current = readFileSync(path);
    if (sha256(current) !== expectedSha256) throw new Error('compare-and-swap mismatch');
    if (!Array.isArray(payload.patches) || payload.patches.length < 1 || payload.patches.length > 1_024) throw new Error('patches must contain between 1 and 1024 entries');
    const patches = payload.patches.map((value, index) => {
      if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`patch ${index} must be an object`);
      const patch = value as JsonObject; const offset = Number(patch.offset); const data = patch.data;
      if (!Number.isSafeInteger(offset) || offset < 0) throw new Error(`patch ${index} offset must be a non-negative safe integer`);
      if (typeof data !== 'string') throw new Error(`patch ${index} data must be a string`);
      const bytes = Buffer.from(data, patch.encoding === 'base64' ? 'base64' : 'utf8');
      return { offset, bytes };
    }).sort((left, right) => left.offset - right.offset);
    for (let index = 1; index < patches.length; index += 1) if (patches[index]!.offset < patches[index - 1]!.offset + patches[index - 1]!.bytes.length) throw new Error('patch ranges must not overlap');
    const size = Math.max(current.length, ...patches.map((patch) => patch.offset + patch.bytes.length));
    if (size > 64 * 1024 * 1024) throw new Error('patched file exceeds 64 MiB');
    const next = Buffer.alloc(size); current.copy(next); for (const patch of patches) patch.bytes.copy(next, patch.offset);
    return this.replace({ path, data: next.toString('base64'), encoding: 'base64', expectedSha256 });
  }
  copy(payload: JsonObject): JsonObject { const source = requiredString(payload, 'source'); const destination = requiredString(payload, 'destination'); mkdirSync(dirname(destination), { recursive: true, mode: 0o700 }); copyFileSync(source, destination, payload.overwrite === false ? fsConstants.COPYFILE_EXCL : 0); return this.stat({ path: destination }); }
  move(payload: JsonObject): JsonObject { const destination = requiredString(payload, 'destination'); mkdirSync(dirname(destination), { recursive: true, mode: 0o700 }); renameSync(requiredString(payload, 'source'), destination); return { moved: true }; }
  remove(payload: JsonObject): JsonObject { rmSync(requiredString(payload, 'path'), { recursive: payload.recursive === true, force: true }); return { removed: true }; }
  list(payload: JsonObject): JsonObject { const path = requiredString(payload, 'path'); const maxEntries = payload.maxEntries === undefined ? 1_000 : Number(payload.maxEntries); if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 10_000) throw new Error('maxEntries must be between 1 and 10000'); return { path, entries: readdirSync(path, { withFileTypes: true }).slice(0, maxEntries).map((entry) => ({ name: entry.name, directory: entry.isDirectory(), symbolicLink: entry.isSymbolicLink() })) }; }
}

const SPECIFICATION_CLASSIFICATIONS = new Set<SpecificationStatement['classification']>(['declared-requirement', 'static-fact', 'observed-invariant', 'hypothesis', 'falsified-hypothesis']);

function validateSpecificationStatement(value: unknown): string[] {
  const errors: string[] = [];
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return ['statement must be an object'];
  const statement = value as JsonObject;
  for (const key of ['id', 'subject', 'predicate']) if (typeof statement[key] !== 'string' || String(statement[key]).length === 0) errors.push(`${key} must be a non-empty string`);
  if (typeof statement.classification !== 'string' || !SPECIFICATION_CLASSIFICATIONS.has(statement.classification as SpecificationStatement['classification'])) errors.push('classification is invalid');
  if (!('value' in statement)) errors.push('value is required');
  if (!Array.isArray(statement.provenance) || statement.provenance.length === 0 || statement.provenance.some((item) => item === null || typeof item !== 'object' || Array.isArray(item))) errors.push('provenance must be a non-empty array of objects');
  if (statement.confidence !== undefined && (typeof statement.confidence !== 'number' || !Number.isFinite(statement.confidence) || statement.confidence < 0 || statement.confidence > 1)) errors.push('confidence must be between 0 and 1');
  if (statement.classification === 'falsified-hypothesis' && (!Array.isArray(statement.falsifiedBy) || statement.falsifiedBy.some((item) => typeof item !== 'string'))) errors.push('falsifiedBy must be a string array for falsified hypotheses');
  return errors;
}

function pageArguments(payload: JsonObject, maximum = 1_000): { offset: number; limit: number } {
  const offset = payload.offset === undefined ? 0 : Number(payload.offset);
  const limit = payload.limit === undefined ? 100 : Number(payload.limit);
  if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('offset must be a non-negative safe integer');
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > maximum) throw new Error(`limit must be between 1 and ${maximum}`);
  return { offset, limit };
}

export class ObjectStore {
  private readonly store: AtomicStore<{ objects: Record<string, JsonObject> }>;
  constructor(path: string) { this.store = new AtomicStore(path, { objects: {} }); }
  create(value: JsonObject): JsonObject { const id = typeof value.id === 'string' ? value.id : randomUUID(); const object = { ...value, id, createdAt: value.createdAt ?? new Date().toISOString(), updatedAt: new Date().toISOString() }; this.store.update((current) => ({ objects: { ...current.objects, [id]: object } })); return object; }
  get(id: string): JsonObject { const object = this.store.read().objects[id]; if (!object) throw new Error('object not found'); return object; }
  count(): number { return Object.keys(this.store.read().objects).length; }
  list(offset = 0, limit = 100): JsonObject[] {
    if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('offset must be a non-negative safe integer');
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) throw new Error('limit must be between 1 and 10000');
    return Object.values(this.store.read().objects)
      .sort((left, right) => String(left.id).localeCompare(String(right.id)))
      .slice(offset, offset + limit);
  }
  remove(id: string): JsonObject { this.store.update((current) => { const objects = { ...current.objects }; delete objects[id]; return { objects }; }); return { removed: true, id }; }
  update(id: string, patch: JsonObject): JsonObject { return this.create({ ...this.get(id), ...patch, id }); }
}

function executable(name: string): string | null {
  const result = spawnSync('/usr/bin/env', ['bash', '-lc', `command -v -- ${JSON.stringify(name)}`], { encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : null;
}

function machineIdHash(): string { try { return sha256(readFileSync('/etc/machine-id')); } catch { return sha256(hostname()); } }

function toolAvailability(): JsonObject {
  const names = ['systemd-nspawn', 'machinectl', 'bpftrace', 'gdb', 'criu', 'tcpdump', 'dumpcap', 'tshark', 'tmux'];
  return Object.fromEntries(names.map((name) => [name, executable(name)]));
}

export interface RuntimeOptions { stateRoot?: string; sourceCommit?: string; sourceTree?: string; proofPrivateKey?: string; proofKeyId?: string; machineServiceConfig?: JsonObject; }

export interface RuntimeExecutionContext { idempotencyKey?: string; subject?: string; authorityClass?: string; }

interface MachineServiceSurface {
  describe(): JsonObject;
  create(payload: unknown, context: RuntimeExecutionContext): Promise<JsonObject>;
  get(payload: JsonObject, context: RuntimeExecutionContext): JsonObject;
  list(payload: JsonObject | undefined, context: RuntimeExecutionContext): JsonObject;
  events(payload: JsonObject, context: RuntimeExecutionContext): JsonObject;
  status(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  start(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  exec(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  shell(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  stop(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  destroy(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  initialize(): Promise<JsonObject>;
  reconcile(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  expire(payload: JsonObject, context: RuntimeExecutionContext): JsonObject;
  gc(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  diagnostics(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
}

export class BabyXRuntime {
  readonly stateRoot: string;
  readonly executor = new Executor();
  readonly files = new FileManager();
  readonly jobs: JobManager;
  readonly specs: ObjectStore;
  readonly campaigns: ObjectStore;
  readonly candidates: ObjectStore;
  readonly adversaries: ObjectStore;
  readonly counterexamples: ObjectStore;
  readonly leases: ObjectStore;
  private machineServiceInstance?: MachineServiceSurface;
  private machineServiceInitializePromise?: Promise<JsonObject>;
  private artifactManagerInstance?: import('./artifacts/manager.ts').ArtifactManager;
  private certificationServiceInstance?: import('./certification/service.ts').CertificationService;
  private candidateRaceServiceInstance?: import('./racing/service.ts').CandidateRaceService;
  private transactionServiceInstance?: import('./transactions/service.ts').TransactionService;
  private transactionServiceInitializePromise?: Promise<JsonObject>;
  private rootAuthorityServiceInstance?: import('./root-authority/service.ts').TransactionalRootAuthorityService;
  private rootFabricServiceInstance?: import('./root-fabric/service.ts').RootFabricService;
  constructor(readonly options: RuntimeOptions = {}) {
    this.stateRoot = options.stateRoot ?? process.env.BABY_X_STATE_ROOT ?? '/var/lib/baby-x';
    mkdirSync(this.stateRoot, { recursive: true, mode: 0o700 });
    this.jobs = new JobManager(join(this.stateRoot, 'jobs'));
    this.specs = new ObjectStore(join(this.stateRoot, 'specifications', 'objects.json'));
    this.campaigns = new ObjectStore(join(this.stateRoot, 'battleground', 'campaigns.json'));
    this.candidates = new ObjectStore(join(this.stateRoot, 'battleground', 'candidates.json'));
    this.adversaries = new ObjectStore(join(this.stateRoot, 'battleground', 'adversaries.json'));
    this.counterexamples = new ObjectStore(join(this.stateRoot, 'counterexamples', 'objects.json'));
    this.leases = new ObjectStore(join(this.stateRoot, 'debug', 'leases.json'));
  }
  describe(): JsonObject {
    const tools = toolAvailability();
    return {
      product: 'baby-x', protocol: 'QRT1/1.0.0', sourceVersion: '0.1.0', sourceCommit: this.options.sourceCommit ?? process.env.BABY_X_SOURCE_COMMIT ?? null, sourceTree: this.options.sourceTree ?? process.env.BABY_X_SOURCE_TREE ?? null,
      hostname: hostname(), machineIdSha256: machineIdHash(), authorityClass: 'unrestricted-owner', configuredLimits: { maxFrameSize: 16 * 1024 * 1024, maxInlineResultBytes: MAX_INLINE }, operationCatalogVersion: OPERATION_CATALOG_VERSION, operationCatalogSha256: sha256(canonicalize(OPERATION_DEFINITIONS)), operations: OPERATION_DEFINITIONS,
      hostSystemdAvailable: existsSync('/run/systemd/system'), nspawnAvailable: Boolean(tools['systemd-nspawn']), machineStorageCapabilities: { root: '/var/lib/machines', reflinkProbe: executable('cp') !== null },
      bpftraceAvailable: Boolean(tools.bpftrace), gdbAvailable: Boolean(tools.gdb), ptraceConfiguration: existsSync('/proc/sys/kernel/yama/ptrace_scope') ? readFileSync('/proc/sys/kernel/yama/ptrace_scope', 'utf8').trim() : null,
      criuAvailable: Boolean(tools.criu), criuBasicCheck: tools.criu ? spawnSync(String(tools.criu), ['check'], { encoding: 'utf8' }).status === 0 : false,
      packetTools: { tcpdump: tools.tcpdump, dumpcap: tools.dumpcap, tshark: tools.tshark }, seccompUserNotification: { nativeHelper: existsSync(join(process.cwd(), 'runtime', 'native', 'seccomp-supervisor', 'target', 'release', 'baby-x-seccomp-supervisor')), kernel: existsSync('/proc/sys/kernel/seccomp') },
      nativeHelperIdentities: { peerCredentialSourceSha256: existsSync(join(process.cwd(), 'runtime', 'native', 'peer-cred', 'peer_cred.cc')) ? sha256(readFileSync(join(process.cwd(), 'runtime', 'native', 'peer-cred', 'peer_cred.cc'))) : null },
    };
  }
  health(): JsonObject { return { ok: true, product: 'baby-x', hostname: hostname(), uid: process.getuid?.() ?? null, stateRoot: this.stateRoot, machineIdSha256: machineIdHash(), timestamp: new Date().toISOString() }; }
  private async artifactManager(): Promise<import('./artifacts/manager.ts').ArtifactManager> {
    if (this.artifactManagerInstance === undefined) {
      const { ArtifactManager } = await import('./artifacts/manager.ts');
      this.artifactManagerInstance = new ArtifactManager(join(this.stateRoot, 'artifacts'));
    }
    return this.artifactManagerInstance;
  }
  private async machineService(): Promise<MachineServiceSurface> {
    if (this.machineServiceInstance === undefined) {
      const { DisposableMachineService } = await import('./machines/service.ts');
      this.machineServiceInstance = new DisposableMachineService({
        stateRoot: this.stateRoot,
        executor: this.executor,
        jobs: this.jobs,
        artifacts: await this.artifactManager(),
        config: this.options.machineServiceConfig ?? {},
      });
      this.jobs.reconcileRunning();
      await new Promise<void>((resolve) => queueMicrotask(resolve));
      this.machineServiceInitializePromise = this.machineServiceInstance.initialize().catch((error: unknown) => ({
        operation: 'babyx.machine.reconcile', startup: true, processed: 0, deferred: true,
        error: { code: error instanceof Error && 'code' in error ? String((error as { code?: unknown }).code ?? 'machine_startup_reconcile_failed') : 'machine_startup_reconcile_failed', message: error instanceof Error ? error.message : 'startup reconciliation failed' },
      }));
    }
    await this.machineServiceInitializePromise;
    return this.machineServiceInstance;
  }
  private async certificationService(): Promise<import('./certification/service.ts').CertificationService> {
    if (this.certificationServiceInstance === undefined) {
      const { CertificationService } = await import('./certification/service.ts');
      this.certificationServiceInstance = new CertificationService({
        stateRoot: this.stateRoot,
        machine: await this.machineService(),
        jobs: this.jobs,
        artifacts: await this.artifactManager(),
      });
    }
    return this.certificationServiceInstance;
  }
  private async candidateRaceService(): Promise<import('./racing/service.ts').CandidateRaceService> {
    if (this.candidateRaceServiceInstance === undefined) {
      const { CandidateRaceService } = await import('./racing/service.ts');
      this.candidateRaceServiceInstance = new CandidateRaceService({ stateRoot: this.stateRoot, certification: await this.certificationService(), artifacts: await this.artifactManager() });
    }
    return this.candidateRaceServiceInstance;
  }
  private async transactionService(): Promise<import('./transactions/service.ts').TransactionService> {
    if (this.transactionServiceInstance === undefined) {
      const { TransactionService } = await import('./transactions/service.ts');
      const { DisposableCodeTransactionDriver } = await import('./transactions/code-driver.ts');
      const machine = await this.machineService();
      const artifacts = await this.artifactManager();
      this.transactionServiceInstance = new TransactionService({
        stateRoot: this.stateRoot,
        machine,
        jobs: this.jobs,
        artifacts,
        codeDriver: new DisposableCodeTransactionDriver({ machine, jobs: this.jobs, artifacts }),
      });
      this.transactionServiceInitializePromise = this.transactionServiceInstance.initialize().catch((error: unknown) => ({
        operation: 'babyx.transaction.reconcile', startup: true, processed: 0, deferred: true,
        error: {
          code: error instanceof Error && 'code' in error ? String((error as { code?: unknown }).code ?? 'transaction_startup_reconcile_failed') : 'transaction_startup_reconcile_failed',
          message: error instanceof Error ? error.message : 'transaction startup reconciliation failed',
        },
      }));
    }
    await this.transactionServiceInitializePromise;
    return this.transactionServiceInstance;
  }
  private async rootAuthorityService(): Promise<import('./root-authority/service.ts').TransactionalRootAuthorityService> {
    if (this.rootAuthorityServiceInstance === undefined) {
      const { TransactionalRootAuthorityService } = await import('./root-authority/service.ts');
      this.rootAuthorityServiceInstance = new TransactionalRootAuthorityService(this.stateRoot);
    }
    return this.rootAuthorityServiceInstance;
  }

  private async rootFabricService(): Promise<import('./root-fabric/service.ts').RootFabricService> {
    if (this.rootFabricServiceInstance === undefined) {
      const { RootFabricService } = await import('./root-fabric/service.ts');
      const artifacts = await this.artifactManager();
      const observationArtifacts = {
        spill: async (name: string, value: JsonObject, metadata: JsonObject) => {
          const bytes = Buffer.from(canonicalize(value), 'utf8');
          const record = artifacts.begin(name, metadata);
          const artifactId = String(record.id);
          for (let offset = 0; offset < bytes.length; offset += 65_536) {
            artifacts.upload(artifactId, offset, bytes.subarray(offset, Math.min(offset + 65_536, bytes.length)));
          }
          artifacts.finalize(artifactId, bytes.length, sha256(bytes));
          return { artifactId };
        },
      };
      const machines = await this.machineService();
      const recoveryContext = (key: string): RuntimeExecutionContext => ({ subject: 'baby-x-root-recovery', authorityClass: 'unrestricted-owner', idempotencyKey: key });
      const terminalJobStates = new Set<JobRecord['status']>(['completed', 'failed', 'cancelled', 'lost']);
      const systemdEnvironmentValue = (environment: string, name: string): string | null => {
        const match = new RegExp(`(?:^|\s)${name}=([^\s\"]+)`, 'u').exec(environment);
        return match?.[1] ?? null;
      };
      const inspectUnit = async (unitName: string, expectedIdentity: JsonObject): Promise<JsonObject> => {
        const result = await this.executor.run({ argv: ['/usr/bin/systemctl', 'show', unitName, '--no-pager', '--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,InvocationID,ExecMainStartTimestampMonotonic,Environment'], cwd: '/' });
        const output = Buffer.from(result.stdout, 'base64').toString('utf8');
        const properties = Object.fromEntries(output.split('\n').filter((line) => line.includes('=')).map((line) => { const index = line.indexOf('='); return [line.slice(0, index), line.slice(index + 1)]; }));
        const exists = result.exitCode === 0 && properties.LoadState !== 'not-found';
        const active = exists && ['active', 'activating', 'deactivating', 'reloading'].includes(properties.ActiveState ?? '');
        const actualPid = Number(properties.MainPID ?? 0);
        let processReadback: ProcessIdentity | null = null;
        if (Number.isSafeInteger(actualPid) && actualPid > 0) {
          try { processReadback = readProcessIdentity(actualPid); } catch { processReadback = null; }
        }
        const environment = properties.Environment ?? '';
        const transactionId = systemdEnvironmentValue(environment, 'BABYX_ROOT_TRANSACTION_ID');
        const requestDigest = systemdEnvironmentValue(environment, 'BABYX_ROOT_REQUEST_DIGEST');
        const identity = {
          unitName,
          loadState: properties.LoadState ?? null,
          activeState: properties.ActiveState ?? null,
          subState: properties.SubState ?? null,
          transactionId,
          requestDigest,
          cgroupId: properties.ControlGroup ?? null,
          processId: Number.isSafeInteger(actualPid) ? actualPid : 0,
          processStartTime: processReadback?.processStartTime ?? null,
          systemdStartTimestamp: properties.ExecMainStartTimestampMonotonic ?? null,
          bootId: processReadback?.bootId ?? null,
          invocationId: properties.InvocationID ?? null,
          executablePath: processReadback?.executablePath ?? null,
        };
        const staticMatches = exists
          && expectedIdentity.unitName === unitName
          && expectedIdentity.transactionId === transactionId
          && expectedIdentity.requestDigest === requestDigest
          && expectedIdentity.cgroupId === identity.cgroupId
          && expectedIdentity.systemdStartTimestamp === identity.systemdStartTimestamp
          && expectedIdentity.invocationId === identity.invocationId;
        const processMatches = !active || (processReadback !== null
          && Number(expectedIdentity.processId) === actualPid
          && expectedIdentity.processStartTime === processReadback.processStartTime
          && expectedIdentity.bootId === processReadback.bootId
          && expectedIdentity.executablePath === processReadback.executablePath);
        const matches = staticMatches && processMatches;
        return { exists, matches, active, terminal: !active, identity, resultDigest: sha256(canonicalize({ identity, exitCode: result.exitCode, signal: result.signal })) };
      };
      const recoveryAuthority = {
        inspectUnit,
        inspectMachine: async (machineId: string, expectedIdentity: JsonObject): Promise<JsonObject> => {
          try {
            const result = await machines.status({ machineId, includeJobs: false, includeRecentEvents: false }, recoveryContext(`root-recovery-machine-status-${machineId}`));
            const machine = result.machine as JsonObject;
            const lifecycle = machine.lifecycle as JsonObject;
            const persistedState = String(lifecycle.persistedState ?? 'UNKNOWN');
            const observedState = String(lifecycle.observedState ?? 'UNKNOWN');
            const identity = { machineId: String(machine.machineId ?? machineId), transactionId: machine.transactionId ?? null, persistedState, observedState, stateSequence: lifecycle.stateSequence ?? null };
            const matches = identity.machineId === machineId && observedState !== 'CONFLICT' && (expectedIdentity.transactionId === undefined || machine.transactionId === expectedIdentity.transactionId);
            return { exists: true, matches, active: ['STARTING', 'READY', 'EXECUTING', 'STOPPING', 'DESTROYING'].includes(persistedState), terminal: persistedState === 'DESTROYED' && observedState === 'ABSENT', identity, resultDigest: sha256(canonicalize(identity)) };
          } catch (error) {
            if (error instanceof Error && /not found/iu.test(error.message)) return { exists: false, matches: true, active: false, terminal: true, identity: { machineId }, resultDigest: null };
            throw error;
          }
        },
        inspectJob: async (jobId: string): Promise<JsonObject> => {
          try {
            const record = this.jobs.reconcile(jobId);
            const classification = record.reconciliation?.classification ?? null;
            const identity = { jobId, pid: record.pid ?? null, pgid: record.pgid ?? null, processIdentity: record.processIdentity ?? null, status: record.status, classification };
            return { exists: true, matches: classification !== 'identity-conflict', active: ['starting', 'running'].includes(record.status), terminal: terminalJobStates.has(record.status), identity, resultDigest: sha256(canonicalize(identity)) };
          } catch (error) {
            if (error instanceof Error && /not found/iu.test(error.message)) return { exists: false, matches: true, active: false, terminal: true, identity: { jobId }, resultDigest: null };
            throw error;
          }
        },
        killUnit: async (unitName: string, signal: string): Promise<JsonObject> => {
          const result = await this.executor.run({ argv: ['/usr/bin/systemctl', 'kill', `--signal=${signal}`, '--kill-whom=all', unitName], cwd: '/' });
          if (result.exitCode !== 0) throw new Error(`systemd kill failed for ${unitName}`);
          return result as unknown as JsonObject;
        },
        killMachine: async (machineId: string): Promise<JsonObject> => {
          const current = await machines.get({ machineId }, recoveryContext(`root-recovery-machine-get-${machineId}`));
          const machine = current.machine as JsonObject;
          const lifecycle = machine.lifecycle as JsonObject;
          const expectedSequence = Number(lifecycle.stateSequence);
          if (!Number.isSafeInteger(expectedSequence) || expectedSequence < 1) throw new Error(`machine ${machineId} has no valid state sequence`);
          return machines.destroy({ machineId, expectedSequence, stopIfRunning: true, forceStop: true, stopTimeoutMs: 5_000, reason: 'root emergency kill' }, recoveryContext(`root-recovery-machine-destroy-${machineId}-${expectedSequence}`));
        },
        killJob: async (jobId: string, signal: string): Promise<JsonObject> => this.jobs.cancel(jobId, signal) as unknown as JsonObject,
        verifyUnitAbsent: async (unitName: string, expectedIdentity: JsonObject): Promise<JsonObject> => {
          const readback = await inspectUnit(unitName, expectedIdentity);
          const expectedPid = Number(expectedIdentity.processId);
          let processAbsent = true;
          if (Number.isSafeInteger(expectedPid) && expectedPid > 0) {
            try {
              const observed = readProcessIdentity(expectedPid);
              processAbsent = observed.processStartTime !== expectedIdentity.processStartTime || observed.bootId !== expectedIdentity.bootId || observed.executablePath !== expectedIdentity.executablePath;
            } catch { processAbsent = true; }
          }
          const cgroupId = String(expectedIdentity.cgroupId ?? '');
          const cgroupPath = cgroupId.startsWith('/') ? `/sys/fs/cgroup${cgroupId}` : join('/sys/fs/cgroup', cgroupId);
          let cgroupEmpty = true;
          if (cgroupId.length > 0 && existsSync(cgroupPath)) {
            try { cgroupEmpty = readFileSync(join(cgroupPath, 'cgroup.procs'), 'utf8').trim().length === 0; }
            catch { cgroupEmpty = false; }
          }
          const unitCollected = readback.exists === false || (readback.identity as JsonObject).loadState === 'not-found';
          const identitySafe = readback.exists === false || readback.matches === true;
          const active = readback.active === true;
          const terminal = !active && processAbsent && cgroupEmpty;
          const identity = { ...(readback.identity as JsonObject), processAbsent, cgroupEmpty, unitCollected };
          return { exists: readback.exists, matches: identitySafe, active, terminal, identity, resultDigest: sha256(canonicalize({ identity, sourceResultDigest: readback.resultDigest })) };
        },
        verifyMachineAbsent: async (machineId: string): Promise<boolean> => {
          const readback = await recoveryAuthority.inspectMachine(machineId, { machineId });
          return readback.exists === false || readback.terminal === true;
        },
        verifyJobTerminal: async (jobId: string): Promise<boolean> => {
          const readback = await recoveryAuthority.inspectJob(jobId);
          return readback.exists === false || readback.terminal === true;
        },
      };
      this.rootFabricServiceInstance = new RootFabricService({
        stateRoot: this.stateRoot,
        sourceCommit: this.options.sourceCommit ?? process.env.BABY_X_SOURCE_COMMIT ?? 'unknown',
        sourceTree: this.options.sourceTree ?? process.env.BABY_X_SOURCE_TREE ?? 'unknown',
        catalogVersion: OPERATION_CATALOG_VERSION,
        catalogDigest: () => sha256(canonicalize(OPERATION_DEFINITIONS)),
        artifacts: observationArtifacts,
        credentialDeliveryRoot: process.env.BABYX_ROOT_CREDENTIAL_ROOT ?? '/run/baby-x/root-credentials',
        recoveryAuthority,
      });
    }
    return this.rootFabricServiceInstance;
  }
  async execute(operation: string, payload: JsonObject = {}, context: RuntimeExecutionContext = {}): Promise<JsonObject> {
    if (!OPERATION_NAMES.has(operation)) throw new Error(`unknown operation: ${operation}`);
    if (operation === 'babyx.describe') return this.describe();
    if (operation === 'babyx.core.compatibility') {
      if (Object.keys(payload).length > 0) throw new Error('babyx.core.compatibility does not accept input');
      const compatibility = await import('./compatibility/manifest.ts');
      return compatibility.describeCoreCompatibility({ currentSourceCommit: this.options.sourceCommit ?? process.env.BABY_X_SOURCE_COMMIT ?? null, currentSourceTree: this.options.sourceTree ?? process.env.BABY_X_SOURCE_TREE ?? null });
    }
    if (operation === 'babyx.health') return this.health();
    if (operation.startsWith('babyx.transaction.')) {
      const service = await this.transactionService();
      if (operation === 'babyx.transaction.create') return service.create(payload, context);
      if (operation === 'babyx.transaction.get') return service.get(payload, context);
      if (operation === 'babyx.transaction.list') return service.list(payload, context);
      if (operation === 'babyx.transaction.events') return service.events(payload, context);
      if (operation === 'babyx.transaction.status') return service.status(payload, context);
      if (operation === 'babyx.transaction.execute') return service.execute(payload, context);
      if (operation === 'babyx.transaction.validate') return service.validate(payload, context);
      if (operation === 'babyx.transaction.finalize') return service.finalize(payload, context);
      if (operation === 'babyx.transaction.rollback') return service.rollback(payload, context);
      if (operation === 'babyx.transaction.reconcile') return service.reconcile(payload, context);
      if (operation === 'babyx.transaction.expire') return service.expire(payload, context);
      if (operation === 'babyx.transaction.gc') return service.gc(payload, context);
      throw new Error('unsupported transaction operation');
    }
    if (operation.startsWith('babyx.root.')) {
      const service = await this.rootAuthorityService();
      if (operation === 'babyx.root.describe') return service.describe();
      if (operation === 'babyx.root.transaction.create') return service.create(payload, context);
      if (operation === 'babyx.root.transaction.get') return service.get(payload);
      if (operation === 'babyx.root.transaction.list') return service.list(payload);
      if (operation === 'babyx.root.transaction.authorize') return service.authorize(payload, context);
      if (operation === 'babyx.root.transaction.begin') return service.begin(payload, context);
      if (operation === 'babyx.root.transaction.observe') return service.observe(payload, context);
      if (operation === 'babyx.root.transaction.commit') return service.commit(payload, context);
      if (operation === 'babyx.root.transaction.rollback') return service.rollback(payload, context);
      if (operation === 'babyx.root.transaction.events') return service.events(payload);
      if (operation === 'babyx.root.transaction.verify') return service.verify(payload);
      return (await this.rootFabricService()).execute(operation, payload, context);
    }
    if (operation === 'babyx.exec') return this.executor.run(payload) as unknown as JsonObject;
    if (operation === 'babyx.shell') return this.executor.run({ ...payload, argv: [typeof payload.shell === 'string' ? payload.shell : '/usr/bin/bash', '-lc', typeof payload.script === 'string' ? payload.script : requiredString(payload, 'command')] }) as unknown as JsonObject;
    if (operation === 'babyx.job.list') return { jobs: this.jobs.list(payload.limit === undefined ? 1_000 : Number(payload.limit), typeof payload.status === 'string' ? payload.status as JobRecord['status'] : undefined) };
    if (operation === 'babyx.job.get') return this.jobs.get(requiredString(payload, 'jobId'));
    if (operation === 'babyx.job.wait') return this.jobs.wait(requiredString(payload, 'jobId'), payload.timeoutMs === undefined ? 30_000 : Number(payload.timeoutMs));
    if (operation === 'babyx.job.reconcile') return this.jobs.reconcile(requiredString(payload, 'jobId'));
    if (operation === 'babyx.job.cancel') return this.jobs.cancel(requiredString(payload, 'jobId'), typeof payload.signal === 'string' ? payload.signal : 'SIGTERM');
    if (operation === 'babyx.job.stream.read') return this.jobs.read(requiredString(payload, 'jobId'), payload.stream === 'stderr' ? 'stderr' : 'stdout', typeof payload.offset === 'number' ? payload.offset : 0, typeof payload.limit === 'number' ? payload.limit : 65_536);
    if (['babyx.machine.describe', 'babyx.machine.create', 'babyx.machine.get', 'babyx.machine.list', 'babyx.machine.events', 'babyx.machine.status', 'babyx.machine.start', 'babyx.machine.exec', 'babyx.machine.shell', 'babyx.machine.stop', 'babyx.machine.destroy', 'babyx.machine.reconcile', 'babyx.machine.expire', 'babyx.machine.gc', 'babyx.machine.diagnostics'].includes(operation)) {
      const service = await this.machineService();
      if (operation === 'babyx.machine.describe') return service.describe();
      if (operation === 'babyx.machine.create') return service.create(payload, context);
      if (operation === 'babyx.machine.get') return service.get(payload, context);
      if (operation === 'babyx.machine.list') return service.list(payload, context);
      if (operation === 'babyx.machine.events') return service.events(payload, context);
      if (operation === 'babyx.machine.status') return service.status(payload, context);
      if (operation === 'babyx.machine.start') return service.start(payload, context);
      if (operation === 'babyx.machine.exec') return service.exec(payload, context);
      if (operation === 'babyx.machine.shell') return service.shell(payload, context);
      if (operation === 'babyx.machine.stop') return service.stop(payload, context);
      if (operation === 'babyx.machine.destroy') return service.destroy(payload, context);
      if (operation === 'babyx.machine.reconcile') return service.reconcile(payload, context);
      if (operation === 'babyx.machine.expire') return service.expire(payload, context);
      if (operation === 'babyx.machine.gc') return service.gc(payload, context);
      return service.diagnostics(payload, context);
    }
    if (['babyx.race.describe', 'babyx.race.run', 'babyx.race.resume', 'babyx.race.get', 'babyx.race.list'].includes(operation)) {
      const service = await this.candidateRaceService();
      if (operation === 'babyx.race.describe') return service.describe();
      if (operation === 'babyx.race.run') return service.run(payload, context);
      if (operation === 'babyx.race.resume') return service.resume(payload, context);
      if (operation === 'babyx.race.get') return service.get(payload, context);
      return service.list(payload, context);
    }
    if (['babyx.execution.policy.describe', 'babyx.execution.policy.decide'].includes(operation)) {
      const policy = await import('./policy/execution.ts');
      return operation === 'babyx.execution.policy.describe' ? policy.describeExecutionPolicy() : policy.decideExecutionPolicy(payload);
    }
    if (['babyx.certification.describe', 'babyx.certification.run', 'babyx.certification.resume', 'babyx.certification.get', 'babyx.certification.list', 'babyx.certification.cleanup'].includes(operation)) {
      const service = await this.certificationService();
      if (operation === 'babyx.certification.describe') return service.describe();
      if (operation === 'babyx.certification.run') return service.run(payload, context);
      if (operation === 'babyx.certification.resume') return service.resume(payload, context);
      if (operation === 'babyx.certification.get') return service.get(payload, context);
      if (operation === 'babyx.certification.list') return service.list(payload, context);
      return service.cleanup(payload, context);
    }
    if (operation === 'babyx.artifact.create') return (await this.artifactManager()).create(requiredString(payload, 'name'), requiredString(payload, 'sourcePath'), payload.metadata && typeof payload.metadata === 'object' && !Array.isArray(payload.metadata) ? payload.metadata as JsonObject : {});
    if (operation === 'babyx.artifact.get') return (await this.artifactManager()).get(requiredString(payload, 'id'));
    if (operation === 'babyx.artifact.list') {
      const manager = await this.artifactManager();
      const { offset, limit } = pageArguments(payload);
      return manager.listPage(offset, limit);
    }
    if (operation === 'babyx.artifact.verify') return (await this.artifactManager()).verify(requiredString(payload, 'id'));
    if (operation.startsWith('babyx.file.')) return this.fileOperation(operation, payload);
    if (operation.startsWith('babyx.spec.')) return this.specOperation(operation, payload);
    if (operation.startsWith('babyx.campaign.')) return this.objectOperation(operation, payload, this.campaigns);
    if (operation.startsWith('babyx.candidate.')) return this.objectOperation(operation, payload, this.candidates);
    if (operation.startsWith('babyx.adversary.')) return this.objectOperation(operation, payload, this.adversaries);
    if (operation.startsWith('babyx.counterexample.')) return this.objectOperation(operation, payload, this.counterexamples);
    if (operation.endsWith('.describe')) return { operation, available: this.providerAvailable(operation), tools: toolAvailability() };
    if (operation.endsWith('.raw')) return this.rawOperation(operation, payload);
    return this.structuredProviderOperation(operation, payload);
  }
  private fileOperation(operation: string, payload: JsonObject): JsonObject {
    const suffix = operation.slice('babyx.file.'.length);
    if (suffix === 'stat') return this.files.stat(payload); if (suffix === 'read') return this.files.read(payload); if (suffix === 'write') return this.files.write(payload); if (suffix === 'replace') return this.files.replace(payload); if (suffix === 'copy') return this.files.copy(payload); if (suffix === 'move') return this.files.move(payload); if (suffix === 'remove') return this.files.remove(payload); if (suffix === 'list') return this.files.list(payload);
    if (suffix === 'patch') return this.files.patch(payload);
    throw new Error('unsupported file operation');
  }
  private specOperation(operation: string, payload: JsonObject): JsonObject {
    const suffix = operation.slice('babyx.spec.'.length);
    if (suffix === 'describe') return { classifications: ['declared-requirement', 'static-fact', 'observed-invariant', 'hypothesis', 'falsified-hypothesis'], analyzers: ['repository-identity', 'operation-schema', 'test-name', 'systemd-dependency', 'nspawn-definition', 'observed-shape', 'state-transition', 'resource-ownership', 'process-port-topology'] };
    if (suffix === 'list') { const { offset, limit } = pageArguments(payload); const statements = this.specs.list(offset, limit); const total = this.specs.count(); return { statements, offset, limit, total, nextOffset: offset + statements.length < total ? offset + statements.length : null }; } if (suffix === 'get') return this.specs.get(requiredString(payload, 'id')); if (suffix === 'remove' || suffix === 'reject') return this.specs.remove(requiredString(payload, 'id'));
    if (suffix === 'promote') return this.specs.update(requiredString(payload, 'id'), { classification: 'declared-requirement', promotedAt: new Date().toISOString() });
    if (suffix === 'falsify') return this.specs.update(requiredString(payload, 'id'), { classification: 'falsified-hypothesis', falsifiedBy: payload.counterexamples ?? [], lastObservedAt: new Date().toISOString() });
    if (suffix === 'scan' || suffix === 'observe' || suffix === 'generate') { const statement: SpecificationStatement = { id: randomUUID(), classification: suffix === 'scan' ? 'static-fact' : suffix === 'observe' ? 'observed-invariant' : 'hypothesis', subject: typeof payload.subject === 'string' ? payload.subject : 'baby-x', predicate: typeof payload.predicate === 'string' ? payload.predicate : suffix, value: payload.value ?? payload, provenance: [{ operation, timestamp: new Date().toISOString(), source: payload.source ?? null }], firstObservedAt: new Date().toISOString(), lastObservedAt: new Date().toISOString() }; return this.specs.create(statement as unknown as JsonObject); }
    if (suffix === 'diff') return { left: payload.left, right: payload.right, equal: canonicalize(payload.left) === canonicalize(payload.right) }; if (suffix === 'validate') { const statement = payload.statement ?? null; const errors = validateSpecificationStatement(statement); return { valid: errors.length === 0, errors, statement }; } if (suffix === 'export') { const total = this.specs.count(); if (total > 10_000) throw new Error('specification export exceeds 10000 statements'); const statements = this.specs.list(0, 10_000); return { statements, total, sha256: sha256(canonicalize(statements)) }; } if (suffix === 'raw') return this.rawOperation(operation, payload);
    throw new Error('unsupported specification operation');
  }
  private objectOperation(operation: string, payload: JsonObject, store: ObjectStore): JsonObject {
    const suffix = operation.split('.').at(-1) ?? '';
    if (suffix === 'list') { const { offset, limit } = pageArguments(payload); const objects = store.list(offset, limit); const total = store.count(); return { objects, offset, limit, total, nextOffset: offset + objects.length < total ? offset + objects.length : null }; } if (suffix === 'get') return store.get(requiredString(payload, 'id')); if (suffix === 'remove') return store.remove(requiredString(payload, 'id'));
    if (['create', 'submit'].includes(suffix)) return store.create(payload);
    if (['start', 'step', 'pause', 'resume', 'cancel', 'build', 'verify', 'run', 'replay', 'export'].includes(suffix)) { const id = requiredString(payload, 'id'); const state = suffix === 'start' || suffix === 'resume' ? 'running' : suffix === 'pause' ? 'paused' : suffix === 'cancel' ? 'cancelled' : suffix === 'verify' ? 'bounded-pass' : suffix; return store.update(id, { state, lastAction: suffix, updatedAt: new Date().toISOString(), result: payload.result ?? null }); }
    return store.create({ ...payload, operation });
  }
  private providerAvailable(operation: string): boolean {
    const family = operation.split('.')[1]; const tool = family === 'trace' ? 'bpftrace' : family === 'debug' ? 'gdb' : family === 'checkpoint' ? 'criu' : family === 'packet' ? 'tcpdump' : family === 'machine' ? 'systemd-nspawn' : family === 'systemd' ? 'systemctl' : family === 'pty' ? 'tmux' : family === 'syscall' ? join(process.cwd(), 'runtime', 'native', 'seccomp-supervisor', 'target', 'release', 'baby-x-seccomp-supervisor') : null; return tool ? Boolean(executable(tool) ?? existsSync(tool)) : true;
  }
  private async rawOperation(operation: string, payload: JsonObject): Promise<JsonObject> {
    const tool = requiredString(payload, 'tool'); const argv = Array.isArray(payload.argv) ? payload.argv : []; return this.executor.run({ ...payload, argv: [tool, ...assertStrings(argv.length > 0 ? argv : ['--help'], 'argv')] }) as unknown as JsonObject;
  }
  private async structuredProviderOperation(operation: string, payload: JsonObject): Promise<JsonObject> {
    const family = operation.split('.')[1] ?? '';
    const suffix = operation.split('.').slice(2).join('.');
    if (family === 'systemd') { const unit = typeof payload.unit === 'string' ? payload.unit : undefined; const mapping: Record<string, string[]> = { list: ['list-units', '--all', '--no-pager'], show: ['show', String(unit)], start: ['start', String(unit)], stop: ['stop', String(unit)], restart: ['restart', String(unit)], reload: ['reload', String(unit)], enable: ['enable', String(unit)], disable: ['disable', String(unit)], mask: ['mask', String(unit)], unmask: ['unmask', String(unit)], 'daemon-reload': ['daemon-reload'], 'reset-failed': ['reset-failed', ...(unit ? [unit] : [])], kill: ['kill', String(unit)] }; if (suffix === 'logs') return this.executor.run({ ...payload, argv: ['/usr/bin/journalctl', '--no-pager', '-u', String(unit), ...(Array.isArray(payload.argv) ? payload.argv : [])] }) as unknown as JsonObject; if (suffix === 'run') return this.executor.run({ ...payload, argv: ['/usr/bin/systemd-run', '--wait', '--pipe', '--collect', ...(Array.isArray(payload.properties) ? (payload.properties as string[]).flatMap((property) => [`--property=${property}`]) : []), '--', ...assertStrings(payload.argv, 'argv')] }) as unknown as JsonObject; return this.executor.run({ ...payload, argv: ['/usr/bin/systemctl', ...(mapping[suffix] ?? [suffix, ...(unit ? [unit] : [])])] }) as unknown as JsonObject; }
    if (family === 'machine') throw new Error('machine operations must be routed through DisposableMachineService');
    const tools: Record<string, string> = { trace: '/usr/bin/bpftrace', debug: '/usr/bin/gdb', checkpoint: '/usr/sbin/criu', packet: suffix.startsWith('decode') || suffix.startsWith('follow') || suffix.startsWith('statistics') ? '/usr/bin/tshark' : '/usr/bin/tcpdump', syscall: join(process.cwd(), 'runtime', 'native', 'seccomp-supervisor', 'target', 'release', 'baby-x-seccomp-supervisor') };
    const tool = tools[family]; if (!tool || (!existsSync(tool) && executable(tool) === null)) return { operation, status: 'unavailable', requiredTool: tool ?? family };
    const argv = Array.isArray(payload.argv) ? payload.argv as string[] : ['--help']; return this.executor.run({ ...payload, argv: [tool, ...argv] }) as unknown as JsonObject;
  }
  createProof(requestId: string, operation: string, ok: boolean, startedAt: string, result: unknown): BabyXProof | { error: string } {
    const completedAt = new Date().toISOString(); const unsigned = { version: '1' as const, requestId, operation, ok, startedAt, completedAt, hostname: hostname(), machineIdSha256: machineIdHash(), resultSha256: sha256(canonicalize(result)), keyId: this.options.proofKeyId ?? process.env.BABY_X_PROOF_KEY_ID ?? 'baby-x-proof-v1' };
    const keyPath = this.options.proofPrivateKey ?? process.env.BABY_X_PROOF_PRIVATE_KEY; if (!keyPath) return { error: 'proof private key unavailable' };
    try { return { ...unsigned, signature: signCanonical(readFileSync(keyPath), unsigned) }; } catch (error) { return { error: error instanceof Error ? error.message : String(error) }; }
  }
}

export function operationDefinitions(): readonly OperationDefinition[] { return OPERATION_DEFINITIONS; }
