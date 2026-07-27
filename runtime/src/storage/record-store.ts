import { createHash, randomUUID } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, linkSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { canonicalize, type JsonObject } from '../core.ts';

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;

function checkedId(value: string): string {
  if (!SAFE_ID.test(value)) throw new Error('record ID is invalid');
  return value;
}

function fsyncDirectory(path: string): void {
  const fd = openSync(path, 'r');
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function writeTemporary(path: string, value: JsonObject): string {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const fd = openSync(temporary, 'wx', 0o600);
  try {
    writeFileSync(fd, `${canonicalize(value)}\n`);
    fsyncSync(fd);
  } finally { closeSync(fd); }
  return temporary;
}

function replaceDurably(path: string, value: JsonObject): void {
  const temporary = writeTemporary(path, value);
  try {
    renameSync(temporary, path);
    fsyncDirectory(dirname(path));
  } finally { rmSync(temporary, { force: true }); }
}

function createDurably(path: string, value: JsonObject): boolean {
  const temporary = writeTemporary(path, value);
  try {
    try { linkSync(temporary, path); }
    catch (error) {
      if (error instanceof Error && 'code' in error && (error as NodeJS.ErrnoException).code === 'EEXIST') return false;
      throw error;
    }
    fsyncDirectory(dirname(path));
    return true;
  } finally { unlinkSync(temporary); }
}

export interface RecordScan<T> {
  records: T[];
  offset: number;
  limit: number;
  total: number;
  nextOffset: number | null;
  corruptRecordIds: string[];
}

export class DurableRecordStore<T extends JsonObject> {
  private readonly recordsRoot: string;

  constructor(readonly root: string) {
    this.recordsRoot = join(root, 'records');
    mkdirSync(this.recordsRoot, { recursive: true, mode: 0o700 });
  }

  private path(id: string): string { return join(this.recordsRoot, `${checkedId(id)}.json`); }

  has(id: string): boolean { return existsSync(this.path(id)); }

  create(id: string, record: T): boolean { return createDurably(this.path(id), record); }

  put(id: string, record: T): void { replaceDurably(this.path(id), record); }

  get(id: string): T {
    const path = this.path(id);
    if (!existsSync(path)) throw new Error('record not found');
    try { return JSON.parse(readFileSync(path, 'utf8')) as T; }
    catch (error) { throw new Error(`record ${id} is corrupt`, { cause: error }); }
  }

  update(id: string, updater: (record: T) => T): T {
    const next = updater(structuredClone(this.get(id)));
    this.put(id, next);
    return structuredClone(next);
  }

  remove(id: string): void {
    rmSync(this.path(id), { force: true });
    fsyncDirectory(this.recordsRoot);
  }

  scan(predicate: (record: T) => boolean = () => true, offset = 0, limit = 1_000): RecordScan<T> {
    if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('record offset must be a non-negative safe integer');
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) throw new Error('record limit must be between 1 and 10000');
    const files = readdirSync(this.recordsRoot).filter((name) => name.endsWith('.json')).sort();
    const records: T[] = [];
    const corruptRecordIds: string[] = [];
    let total = 0;
    for (const name of files) {
      const id = name.slice(0, -5);
      let record: T;
      try { record = this.get(id); }
      catch { corruptRecordIds.push(id); continue; }
      if (!predicate(record)) continue;
      if (total >= offset && records.length < limit) records.push(structuredClone(record));
      total += 1;
    }
    return { records, offset, limit, total, nextOffset: offset + records.length < total ? offset + records.length : null, corruptRecordIds };
  }
}

interface DurableClaim<T extends JsonObject> extends JsonObject {
  key: string;
  requestDigest: string;
  recordId: string;
  record: T;
}

export class DurableClaimStore<T extends JsonObject> {
  constructor(private readonly root: string) { mkdirSync(root, { recursive: true, mode: 0o700 }); }

  private path(key: string): string { return join(this.root, `${createHash('sha256').update(key).digest('hex')}.json`); }

  get(key: string): DurableClaim<T> | undefined {
    const path = this.path(key);
    if (!existsSync(path)) return undefined;
    let claim: DurableClaim<T>;
    try { claim = JSON.parse(readFileSync(path, 'utf8')) as DurableClaim<T>; }
    catch (error) { throw new Error('idempotency claim is corrupt', { cause: error }); }
    if (claim.key !== key || typeof claim.requestDigest !== 'string' || typeof claim.recordId !== 'string' || claim.record === null || typeof claim.record !== 'object' || Array.isArray(claim.record)) throw new Error('idempotency claim is invalid');
    return claim;
  }

  claim(key: string, requestDigest: string, recordId: string, record: T): DurableClaim<T> {
    const candidate: DurableClaim<T> = { key, requestDigest, recordId: checkedId(recordId), record: structuredClone(record) };
    if (createDurably(this.path(key), candidate)) return candidate;
    const existing = this.get(key);
    if (existing === undefined) throw new Error('idempotency claim disappeared');
    return existing;
  }
}
