import { createHash, randomUUID } from 'node:crypto';
import { copyFileSync, existsSync, fsyncSync, mkdirSync, openSync, closeSync, readFileSync, readSync, renameSync, rmSync, statSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { type JsonObject } from '../core.ts';
import { DurableRecordStore } from '../storage/record-store.ts';

const MAX_CHUNK = 65_536;
const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;

function hashFile(path: string): { size: number; sha256: string } {
  const size = statSync(path).size;
  const hash = createHash('sha256');
  const buffer = Buffer.alloc(MAX_CHUNK);
  const fd = openSync(path, 'r');
  try {
    let offset = 0;
    while (offset < size) {
      const count = readSync(fd, buffer, 0, Math.min(buffer.length, size - offset), offset);
      if (count === 0) break;
      hash.update(buffer.subarray(0, count));
      offset += count;
    }
  } finally { closeSync(fd); }
  return { size, sha256: hash.digest('hex') };
}

export class ArtifactManager {
  private readonly records: DurableRecordStore<JsonObject>;

  constructor(private readonly root: string) {
    mkdirSync(root, { recursive: true, mode: 0o700 });
    this.records = new DurableRecordStore(join(root, 'record-store-v1'));
    this.importLegacy(join(root, 'index.json'));
  }

  private importLegacy(path: string): void {
    if (!existsSync(path)) return;
    let legacy: { artifacts?: Record<string, JsonObject> };
    try { legacy = JSON.parse(readFileSync(path, 'utf8')) as { artifacts?: Record<string, JsonObject> }; }
    catch (error) { throw new Error('legacy artifact index is corrupt', { cause: error }); }
    for (const [id, record] of Object.entries(legacy.artifacts ?? {})) if (!this.records.has(id)) this.records.create(id, record);
  }

  begin(name: string, metadata: JsonObject = {}): JsonObject {
    const id = randomUUID();
    const record = { id, name, metadata, state: 'uploading', path: join(this.root, `${id}.partial`), createdAt: new Date().toISOString() };
    if (!this.records.create(id, record)) throw new Error('artifact ID conflict');
    return structuredClone(record);
  }

  upload(id: string, offset: number, data: Buffer): JsonObject {
    if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('artifact offset must be a non-negative safe integer');
    if (data.length > MAX_CHUNK) throw new Error(`artifact upload chunk exceeds ${MAX_CHUNK} bytes`);
    const record = this.get(id);
    if (record.state !== 'uploading') throw new Error('artifact is immutable');
    if (offset + data.length > MAX_ARTIFACT_BYTES) throw new Error('artifact exceeds maximum size');
    const fd = openSync(String(record.path), 'a+', 0o600);
    try { writeSync(fd, data, 0, data.length, offset); fsyncSync(fd); } finally { closeSync(fd); }
    return { id, offset: offset + data.length };
  }

  finalize(id: string, expectedSize: number, expectedSha256: string): JsonObject {
    if (!Number.isSafeInteger(expectedSize) || expectedSize < 0 || expectedSize > MAX_ARTIFACT_BYTES) throw new Error('artifact expected size is invalid');
    if (!/^[a-f0-9]{64}$/u.test(expectedSha256)) throw new Error('artifact expected SHA-256 is invalid');
    const record = this.get(id);
    if (record.state !== 'uploading') return this.verify(id);
    const observed = hashFile(String(record.path));
    if (observed.size !== expectedSize || observed.sha256 !== expectedSha256) throw new Error('artifact integrity mismatch');
    const finalPath = join(this.root, observed.sha256);
    if (!existsSync(finalPath)) renameSync(String(record.path), finalPath); else rmSync(String(record.path), { force: true });
    const artifactDirectory = openSync(this.root, 'r');
    try { fsyncSync(artifactDirectory); } finally { closeSync(artifactDirectory); }
    const finalized = { ...record, state: 'finalized', path: finalPath, size: observed.size, sha256: observed.sha256, finalizedAt: new Date().toISOString() };
    this.records.put(id, finalized);
    return structuredClone(finalized);
  }

  create(name: string, sourcePath: string, metadata: JsonObject = {}): JsonObject {
    const source = hashFile(sourcePath);
    if (source.size > MAX_ARTIFACT_BYTES) throw new Error('artifact source exceeds maximum size');
    const record = this.begin(name, metadata);
    copyFileSync(sourcePath, String(record.path));
    const fd = openSync(String(record.path), 'r');
    try { fsyncSync(fd); } finally { closeSync(fd); }
    return this.finalize(String(record.id), source.size, source.sha256);
  }

  get(id: string): JsonObject {
    try { return structuredClone(this.records.get(id)); }
    catch (error) {
      if (error instanceof Error && error.message === 'record not found') throw new Error('artifact not found');
      throw error;
    }
  }

  list(offset = 0, limit = 1_000): JsonObject[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) throw new Error('artifact list limit must be between 1 and 1000');
    return this.records.scan(() => true, offset, limit).records;
  }

  count(): number {
    return this.records.scan(() => true, 0, 1).total;
  }

  listPage(offset = 0, limit = 1_000): JsonObject {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) throw new Error('artifact list limit must be between 1 and 1000');
    const page = this.records.scan(() => true, offset, limit);
    return { artifacts: page.records, offset, limit, total: page.total, nextOffset: page.nextOffset, corruptRecordIds: page.corruptRecordIds };
  }

  abort(id: string): void {
    const record = this.get(id);
    rmSync(String(record.path), { force: true });
    this.records.remove(id);
  }

  download(id: string, offset = 0, limit = MAX_CHUNK): JsonObject {
    if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('artifact offset must be a non-negative safe integer');
    if (!Number.isSafeInteger(limit) || limit < 0 || limit > MAX_CHUNK) throw new Error(`artifact download limit must be between 0 and ${MAX_CHUNK}`);
    const record = this.get(id);
    if (record.state !== 'finalized') throw new Error('artifact is not finalized');
    const path = String(record.path);
    const size = statSync(path).size;
    const count = Math.max(0, Math.min(limit, size - offset));
    const buffer = Buffer.alloc(count);
    const fd = openSync(path, 'r');
    try { if (count) readSync(fd, buffer, 0, count, offset); } finally { closeSync(fd); }
    return { data: buffer.toString('base64'), encoding: 'base64', offset: offset + count, eof: offset + count >= size };
  }

  verify(id: string): JsonObject {
    const record = this.get(id);
    if (record.state !== 'finalized' || typeof record.path !== 'string' || typeof record.size !== 'number' || typeof record.sha256 !== 'string') return { id, valid: false, reason: 'artifact is not finalized' };
    if (!existsSync(record.path)) return { id, valid: false, reason: 'artifact content is absent' };
    const observed = hashFile(record.path);
    return { id, valid: observed.size === record.size && observed.sha256 === record.sha256, expectedSize: record.size, observedSize: observed.size, expectedSha256: record.sha256, observedSha256: observed.sha256 };
  }
}
