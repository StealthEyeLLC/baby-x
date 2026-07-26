import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { constants as fsConstants, createReadStream, createWriteStream, existsSync, mkdirSync, openSync, closeSync, readFileSync, readSync, renameSync, rmSync, statSync, writeFileSync, writeSync, readdirSync, copyFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { processIdentity as readProcessIdentity } from './process/identity.ts';
import { OPERATION_DEFINITIONS, OPERATION_NAMES, type OperationDefinition } from './operations/definitions.ts';

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
    writeFileSync(temporary, `${canonicalize(value)}\n`, { mode: 0o600 });
    renameSync(temporary, this.path);
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
  const wrapped = ['/usr/bin/nsenter', '--target', pid, '--mount', '--uts', '--ipc', '--net', '--pid', '--cgroup', `--root=/proc/${pid}/root`, `--wdns=${cwd}`, '--', '/usr/bin/env'];
  for (const [key, value] of Object.entries(environment)) wrapped.push(`${key}=${String(value)}`);
  wrapped.push(...argv);
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
  status: 'running' | 'completed' | 'failed' | 'cancelled' | 'lost';
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
  list(): JobRecord[] { return Object.values(this.store.read().jobs); }
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
    const stdoutFd = openSync(stdoutPath, 'a', 0o600);
    const stderrFd = openSync(stderrPath, 'a', 0o600);
    const child = spawn(executable, effective.slice(1), { cwd: target.kind === 'host' ? cwd : '/', env: { ...process.env, ...Object.fromEntries(Object.entries(env).map(([key, value]) => [key, String(value)])) }, detached: true, stdio: ['ignore', stdoutFd, stderrFd] });
    child.unref(); closeSync(stdoutFd); closeSync(stderrFd);
    let identity: ProcessIdentity | undefined;
    if (child.pid !== undefined) {
      try { identity = readProcessIdentity(child.pid); } catch { identity = { pid: child.pid, pgid: child.pid }; }
    }
    const record: JobRecord = {
      id, operation, status: 'running', target, argv, cwd, createdAt: new Date().toISOString(), startedAt: new Date().toISOString(),
      pid: child.pid, pgid: child.pid, stdoutPath, stderrPath,
      ...(metadata === undefined ? {} : { metadata }),
      ...(identity === undefined ? {} : { processIdentity: identity }),
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
    };
    this.store.update((current) => ({ jobs: { ...current.jobs, [id]: record } }));
    this.notify(record);
    let timeout: NodeJS.Timeout | undefined;
    if (timeoutMs !== undefined) {
      timeout = setTimeout(() => { try { if (child.pid !== undefined) process.kill(-child.pid, 'SIGTERM'); } catch {} }, timeoutMs);
      timeout.unref();
    }
    child.on('exit', (code, signal) => {
      if (timeout !== undefined) clearTimeout(timeout);
      let completed: JobRecord | undefined;
      this.store.update((current) => {
        const existing = current.jobs[id];
        if (!existing) return current;
        completed = { ...existing, status: signal ? 'failed' : code === 0 ? 'completed' : 'failed', exitCode: code, signal, completedAt: new Date().toISOString() };
        return { jobs: { ...current.jobs, [id]: completed } };
      });
      if (completed !== undefined) this.notify(completed);
    });
    return record;
  }
  reconcile(id: string): JobRecord {
    const record = this.get(id);
    if (record.status !== 'running') return record;
    const observedAt = this.now();
    const expected = record.processIdentity;
    let classification: NonNullable<JobRecord['reconciliation']>['classification'];
    let actual: ProcessIdentity | undefined;
    if (record.pid === undefined || expected === undefined || expected.processStartTime === undefined || expected.executablePath === undefined || expected.bootId === undefined) classification = 'identity-incomplete';
    else {
      try { actual = this.processIdentity(record.pid); } catch { classification = 'process-absent'; }
      if (actual !== undefined) {
        classification = actual.pid === expected.pid
          && actual.processStartTime === expected.processStartTime
          && actual.executablePath === expected.executablePath
          && actual.bootId === expected.bootId
          && (expected.pgid === undefined || actual.pgid === expected.pgid)
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
    return this.list().filter((record) => record.status === 'running').sort((left, right) => left.id.localeCompare(right.id)).slice(0, limit).map((record) => this.reconcile(record.id));
  }
  cancel(id: string, signal = 'SIGTERM'): JobRecord {
    const record = this.get(id);
    if (record.pgid) process.kill(-record.pgid, signal as NodeJS.Signals);
    const next = { ...record, status: 'cancelled' as const, signal, completedAt: new Date().toISOString() };
    this.store.update((current) => ({ jobs: { ...current.jobs, [id]: next } }));
    this.notify(next);
    return next;
  }
  read(id: string, stream: 'stdout' | 'stderr', offset = 0, limit = 65_536): JsonObject {
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
  read(payload: JsonObject): JsonObject { const path = requiredString(payload, 'path'); const offset = typeof payload.offset === 'number' ? payload.offset : 0; const limit = typeof payload.limit === 'number' ? payload.limit : 65_536; const size = statSync(path).size; const count = Math.max(0, Math.min(limit, size - offset)); const buffer = Buffer.alloc(count); const fd = openSync(path, 'r'); try { if (count > 0) readSync(fd, buffer, 0, count, offset); } finally { closeSync(fd); } return { data: payload.encoding === 'utf8' ? buffer.toString('utf8') : buffer.toString('base64'), encoding: payload.encoding === 'utf8' ? 'utf8' : 'base64', offset: offset + count, eof: offset + count >= size, sha256: sha256(readFileSync(path)) }; }
  write(payload: JsonObject): JsonObject { const path = requiredString(payload, 'path'); const data = requiredString(payload, 'data'); const buffer = Buffer.from(data, payload.encoding === 'base64' ? 'base64' : 'utf8'); mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); const fd = openSync(path, payload.create === false ? 'r+' : 'a+', 0o600); try { writeSync(fd, buffer, 0, buffer.length, typeof payload.offset === 'number' ? payload.offset : null); } finally { closeSync(fd); } return this.stat({ path }); }
  replace(payload: JsonObject): JsonObject { const path = requiredString(payload, 'path'); if (typeof payload.expectedSha256 === 'string' && existsSync(path) && sha256(readFileSync(path)) !== payload.expectedSha256) throw new Error('compare-and-swap mismatch'); const data = Buffer.from(requiredString(payload, 'data'), payload.encoding === 'base64' ? 'base64' : 'utf8'); mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); const temporary = `${path}.${randomUUID()}.tmp`; writeFileSync(temporary, data, { mode: 0o600 }); renameSync(temporary, path); return this.stat({ path }); }
  copy(payload: JsonObject): JsonObject { const source = requiredString(payload, 'source'); const destination = requiredString(payload, 'destination'); mkdirSync(dirname(destination), { recursive: true, mode: 0o700 }); copyFileSync(source, destination, payload.overwrite === false ? fsConstants.COPYFILE_EXCL : 0); return this.stat({ path: destination }); }
  move(payload: JsonObject): JsonObject { renameSync(requiredString(payload, 'source'), requiredString(payload, 'destination')); return { moved: true }; }
  remove(payload: JsonObject): JsonObject { rmSync(requiredString(payload, 'path'), { recursive: payload.recursive === true, force: true }); return { removed: true }; }
  list(payload: JsonObject): JsonObject { const path = requiredString(payload, 'path'); return { path, entries: readdirSync(path, { withFileTypes: true }).slice(0, typeof payload.maxEntries === 'number' ? payload.maxEntries : 10_000).map((entry) => ({ name: entry.name, directory: entry.isDirectory(), symbolicLink: entry.isSymbolicLink() })) }; }
}

export class ObjectStore {
  private readonly store: AtomicStore<{ objects: Record<string, JsonObject> }>;
  constructor(path: string) { this.store = new AtomicStore(path, { objects: {} }); }
  create(value: JsonObject): JsonObject { const id = typeof value.id === 'string' ? value.id : randomUUID(); const object = { ...value, id, createdAt: value.createdAt ?? new Date().toISOString(), updatedAt: new Date().toISOString() }; this.store.update((current) => ({ objects: { ...current.objects, [id]: object } })); return object; }
  get(id: string): JsonObject { const object = this.store.read().objects[id]; if (!object) throw new Error('object not found'); return object; }
  list(): JsonObject[] { return Object.values(this.store.read().objects); }
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
      hostname: hostname(), machineIdSha256: machineIdHash(), authorityClass: 'unrestricted-owner', configuredLimits: { maxFrameSize: 16 * 1024 * 1024, maxInlineResultBytes: MAX_INLINE }, operations: OPERATION_DEFINITIONS,
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
      this.transactionServiceInstance = new TransactionService({
        stateRoot: this.stateRoot,
        machine: await this.machineService(),
        jobs: this.jobs,
        artifacts: await this.artifactManager(),
      });
      this.transactionServiceInitializePromise = this.transactionServiceInstance.initialize().catch((error: unknown) => ({
        operation: 'babyx.transaction.reconcile', startup: true, processed: 0, deferred: true,
        error: { code: error instanceof Error && 'code' in error ? String((error as { code?: unknown }).code ?? 'transaction_startup_reconcile_failed') : 'transaction_startup_reconcile_failed', message: error instanceof Error ? error.message : 'transaction startup reconciliation failed' },
      }));
    }
    await this.transactionServiceInitializePromise;
    return this.transactionServiceInstance;
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
    if (operation === 'babyx.exec') return this.executor.run(payload) as unknown as JsonObject;
    if (operation === 'babyx.shell') return this.executor.run({ ...payload, argv: [typeof payload.shell === 'string' ? payload.shell : '/usr/bin/bash', '-lc', typeof payload.script === 'string' ? payload.script : requiredString(payload, 'command')] }) as unknown as JsonObject;
    if (operation === 'babyx.job.list') return { jobs: this.jobs.list() };
    if (operation === 'babyx.job.get' || operation === 'babyx.job.wait') return this.jobs.get(requiredString(payload, 'jobId'));
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
    if (operation === 'babyx.artifact.list') return { artifacts: (await this.artifactManager()).list() };
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
    if (suffix === 'patch') { const patches = Array.isArray(payload.patches) ? payload.patches : []; for (const patch of patches) this.files.write({ path: payload.path, ...(patch as JsonObject) }); return this.files.stat({ path: payload.path }); }
    throw new Error('unsupported file operation');
  }
  private specOperation(operation: string, payload: JsonObject): JsonObject {
    const suffix = operation.slice('babyx.spec.'.length);
    if (suffix === 'describe') return { classifications: ['declared-requirement', 'static-fact', 'observed-invariant', 'hypothesis', 'falsified-hypothesis'], analyzers: ['repository-identity', 'operation-schema', 'test-name', 'systemd-dependency', 'nspawn-definition', 'observed-shape', 'state-transition', 'resource-ownership', 'process-port-topology'] };
    if (suffix === 'list') return { statements: this.specs.list() }; if (suffix === 'get') return this.specs.get(requiredString(payload, 'id')); if (suffix === 'remove' || suffix === 'reject') return this.specs.remove(requiredString(payload, 'id'));
    if (suffix === 'promote') return this.specs.update(requiredString(payload, 'id'), { classification: 'declared-requirement', promotedAt: new Date().toISOString() });
    if (suffix === 'falsify') return this.specs.update(requiredString(payload, 'id'), { classification: 'falsified-hypothesis', falsifiedBy: payload.counterexamples ?? [], lastObservedAt: new Date().toISOString() });
    if (suffix === 'scan' || suffix === 'observe' || suffix === 'generate') { const statement: SpecificationStatement = { id: randomUUID(), classification: suffix === 'scan' ? 'static-fact' : suffix === 'observe' ? 'observed-invariant' : 'hypothesis', subject: typeof payload.subject === 'string' ? payload.subject : 'baby-x', predicate: typeof payload.predicate === 'string' ? payload.predicate : suffix, value: payload.value ?? payload, provenance: [{ operation, timestamp: new Date().toISOString(), source: payload.source ?? null }], firstObservedAt: new Date().toISOString(), lastObservedAt: new Date().toISOString() }; return this.specs.create(statement as unknown as JsonObject); }
    if (suffix === 'diff') return { left: payload.left, right: payload.right, equal: canonicalize(payload.left) === canonicalize(payload.right) }; if (suffix === 'validate') return { valid: true, statement: payload.statement ?? null }; if (suffix === 'export') return { statements: this.specs.list(), sha256: sha256(canonicalize(this.specs.list())) }; if (suffix === 'raw') return this.rawOperation(operation, payload);
    throw new Error('unsupported specification operation');
  }
  private objectOperation(operation: string, payload: JsonObject, store: ObjectStore): JsonObject {
    const suffix = operation.split('.').at(-1) ?? '';
    if (suffix === 'list') return { objects: store.list() }; if (suffix === 'get') return store.get(requiredString(payload, 'id')); if (suffix === 'remove') return store.remove(requiredString(payload, 'id'));
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
    if (family === 'machine') { const machine = typeof payload.machine === 'string' ? payload.machine : undefined; if (suffix === 'exec' || suffix === 'shell') return this.executor.run({ ...payload, target: { kind: 'machine', machine }, argv: suffix === 'shell' ? ['/usr/bin/bash', '-lc', requiredString(payload, 'command')] : assertStrings(payload.argv, 'argv') }) as unknown as JsonObject; const args = Array.isArray(payload.argv) ? payload.argv as string[] : [suffix.replaceAll('.', '-'), ...(machine ? [machine] : [])]; return this.executor.run({ ...payload, argv: ['/usr/bin/machinectl', ...args] }) as unknown as JsonObject; }
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
