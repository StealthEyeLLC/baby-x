import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256, type JsonObject } from '../../core.ts';
import { MediationError } from './errors.ts';
import type { MediationProfileSpec } from './schemas.ts';

export type NativeMediationComponent = 'filter' | 'notify' | 'landlock';

export interface NativeProbe extends JsonObject {
  ok: boolean;
  component: NativeMediationComponent;
  binaryPath: string;
  binaryDigest: string;
  details: JsonObject;
  error: string | null;
}

export interface NativeDecisionEvent extends JsonObject {
  transactionId: string;
  pid: number;
  syscall: number;
  decision: string;
  valid: boolean;
  identity: boolean;
  arguments: boolean;
  staleAfterResponse: boolean;
}

export interface NativeExecutionResult extends JsonObject {
  ok: boolean;
  transactionId: string;
  status: number;
  events: number;
  droppedEvents: number;
  decisionEvents: NativeDecisionEvent[];
  stdout: string;
  stderr: string;
  stdoutDigest: string;
  stderrDigest: string;
  binaryPath: string;
  binaryDigest: string;
}

function executableCandidates(): string[] {
  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  return [
    process.env.BABY_X_MEDIATION_SUPERVISOR,
    join(moduleDirectory, '..', '..', 'native', 'mediation-supervisor', 'baby-x-mediation-supervisor'),
    join(process.cwd(), 'runtime', 'native', 'mediation-supervisor', 'build', 'baby-x-mediation-supervisor'),
    join(process.cwd(), 'dist', 'runtime', 'native', 'mediation-supervisor', 'baby-x-mediation-supervisor'),
  ].filter((value): value is string => typeof value === 'string' && value.length > 0);
}

function parsedObject(text: string, field: string): JsonObject {
  let value: unknown;
  try { value = JSON.parse(text); }
  catch { throw new MediationError('mediation_native_failed', `${field} was not valid JSON`); }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new MediationError('mediation_native_failed', `${field} must be a JSON object`);
  return value as JsonObject;
}

function bounded(value: string | Buffer | null | undefined): string {
  return typeof value === 'string' ? value.slice(0, 65_536) : Buffer.isBuffer(value) ? value.subarray(0, 65_536).toString('utf8') : '';
}

function safeCommand(value: unknown): string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 256) throw new MediationError('mediation_invalid_request', 'command must be a bounded non-empty string array');
  return value.map((entry, index) => {
    if (typeof entry !== 'string' || entry.length < 1 || entry.length > 65_536 || entry.includes('\0')) throw new MediationError('mediation_invalid_request', `command[${index}] must be a bounded non-empty NUL-free string`);
    return entry;
  });
}

function safeTransactionId(value: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(value)) throw new MediationError('mediation_invalid_request', 'transactionId is invalid');
  return value;
}

export class NativeMediationRunner {
  readonly binaryPath: string;
  readonly binaryDigest: string;

  constructor(path?: string) {
    const resolved = path ?? executableCandidates().find((candidate) => existsSync(candidate));
    if (resolved === undefined) throw new MediationError('mediation_native_unavailable', 'the Baby-X mediation supervisor is unavailable');
    this.binaryPath = resolved;
    this.binaryDigest = sha256(readFileSync(resolved));
  }

  probe(component: NativeMediationComponent): NativeProbe {
    const result = spawnSync(this.binaryPath, ['probe', component], { encoding: 'utf8', timeout: 10_000, maxBuffer: 1_048_576 });
    const stdout = bounded(result.stdout).trim();
    const stderr = bounded(result.stderr).trim();
    if (result.error !== undefined || result.status !== 0 || stdout.length === 0) {
      return { ok: false, component, binaryPath: this.binaryPath, binaryDigest: this.binaryDigest, details: {}, error: result.error?.message ?? (stderr || `probe exited ${String(result.status)}`) };
    }
    const lines = stdout.split('\n').filter((line) => line.trim().startsWith('{'));
    const details = parsedObject(lines.at(-1) ?? '', `${component} probe`);
    return { ok: details.ok === true, component, binaryPath: this.binaryPath, binaryDigest: this.binaryDigest, details, error: details.ok === true ? null : stderr || 'probe returned false' };
  }

  execute(profile: MediationProfileSpec, transactionIdValue: string, commandValue: unknown, timeoutMs = 60_000): NativeExecutionResult {
    const transactionId = safeTransactionId(transactionIdValue);
    const command = safeCommand(commandValue);
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) throw new MediationError('mediation_invalid_request', 'timeoutMs must be between 1 and 300000');
    const argv = ['run', '--transaction', transactionId, '--deadline-ms', String(Math.min(timeoutMs, 60_000))];
    if (profile.defaultAction.kind === 'allow' || profile.defaultAction.kind === 'kill') argv.push('--default', profile.defaultAction.kind);
    else argv.push('--default', `errno:${String(profile.defaultAction.errno)}`);
    for (const syscall of profile.allowedSyscalls) argv.push('--allow', syscall);
    for (const rule of profile.deniedSyscalls) {
      if (rule.action === 'kill') argv.push('--kill', rule.syscall);
      else argv.push('--errno', `${rule.syscall}:${String(rule.errno)}`);
    }
    for (const rule of profile.notifiedSyscalls) {
      const suffix = rule.decision === 'allow' ? 'allow' : rule.decision === 'deny' ? `deny:${String(rule.errno)}` : `emulate:${String(rule.value)}`;
      argv.push('--notify', `${rule.syscall}:${suffix}`);
    }
    for (const constraint of profile.argumentConstraints) argv.push('--arg-eq', `${constraint.syscall}:${constraint.index}:${constraint.value}`);
    for (const constraint of profile.pathConstraints) argv.push(constraint.access === 'write' ? '--landlock-write' : '--landlock-read', constraint.path);
    for (const constraint of profile.socketConstraints) argv.push(constraint.action === 'bind' ? '--landlock-bind-port' : '--landlock-connect-port', String(constraint.port));
    argv.push('--', ...command);
    const result = spawnSync(this.binaryPath, argv, { encoding: 'utf8', timeout: timeoutMs + 5_000, maxBuffer: 2_097_152 });
    const stdout = bounded(result.stdout);
    const stderr = bounded(result.stderr);
    if (result.error !== undefined) throw new MediationError('mediation_native_failed', 'native mediation execution failed', { reason: result.error.message });
    const decisionEvents: NativeDecisionEvent[] = [];
    let summary: JsonObject | undefined;
    for (const line of stdout.split('\n')) {
      if (line.startsWith('BABYX_EVENT ')) {
        const event = parsedObject(line.slice('BABYX_EVENT '.length), 'native mediation event');
        if (decisionEvents.length < 1_000) decisionEvents.push(event as NativeDecisionEvent);
      } else if (line.startsWith('BABYX_RESULT ')) summary = parsedObject(line.slice('BABYX_RESULT '.length), 'native mediation result');
    }
    if (summary === undefined) throw new MediationError('mediation_native_failed', 'native mediation result was absent', { exitStatus: result.status, stderr: stderr.slice(0, 4_096) });
    const status = Number(summary.status);
    const events = Number(summary.events);
    const droppedEvents = Number(summary.droppedEvents);
    if (!Number.isSafeInteger(status) || !Number.isSafeInteger(events) || !Number.isSafeInteger(droppedEvents)) throw new MediationError('mediation_native_failed', 'native mediation result was malformed');
    return {
      ok: summary.ok === true,
      transactionId,
      status,
      events,
      droppedEvents,
      decisionEvents,
      stdout,
      stderr,
      stdoutDigest: sha256(stdout),
      stderrDigest: sha256(stderr),
      binaryPath: this.binaryPath,
      binaryDigest: this.binaryDigest,
    };
  }
}
