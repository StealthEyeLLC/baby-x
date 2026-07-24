import { createHash, randomUUID } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, openSync, closeSync, readFileSync, readSync, renameSync, rmSync, statSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { AtomicStore, type JsonObject } from '../core.ts';

export class ArtifactManager {
  private readonly store: AtomicStore<{ artifacts: Record<string, JsonObject> }>;
  constructor(private readonly root: string) { mkdirSync(root, { recursive: true, mode: 0o700 }); this.store = new AtomicStore(join(root, 'index.json'), { artifacts: {} }); }
  begin(name: string, metadata: JsonObject = {}): JsonObject { const id = randomUUID(); const record = { id, name, metadata, state: 'uploading', path: join(this.root, `${id}.partial`), createdAt: new Date().toISOString() }; this.store.update((current) => ({ artifacts: { ...current.artifacts, [id]: record } })); return record; }
  upload(id: string, offset: number, data: Buffer): JsonObject { const record = this.get(id); if (record.state !== 'uploading') throw new Error('artifact is immutable'); const fd = openSync(String(record.path), 'a+', 0o600); try { writeSync(fd, data, 0, data.length, offset); } finally { closeSync(fd); } return { id, offset: offset + data.length }; }
  finalize(id: string, expectedSize: number, expectedSha256: string): JsonObject { const record = this.get(id); const bytes = readFileSync(String(record.path)); const digest = createHash('sha256').update(bytes).digest('hex'); if (bytes.length !== expectedSize || digest !== expectedSha256) throw new Error('artifact integrity mismatch'); const finalPath = join(this.root, digest); if (!existsSync(finalPath)) renameSync(String(record.path), finalPath); else rmSync(String(record.path), { force: true }); const finalized = { ...record, state: 'finalized', path: finalPath, size: bytes.length, sha256: digest, finalizedAt: new Date().toISOString() }; this.store.update((current) => ({ artifacts: { ...current.artifacts, [id]: finalized } })); return finalized; }
  create(name: string, sourcePath: string, metadata: JsonObject = {}): JsonObject { const record = this.begin(name, metadata); const bytes = readFileSync(sourcePath); this.upload(String(record.id), 0, bytes); return this.finalize(String(record.id), bytes.length, createHash('sha256').update(bytes).digest('hex')); }
  get(id: string): JsonObject { const value = this.store.read().artifacts[id]; if (!value) throw new Error('artifact not found'); return value; }
  list(): JsonObject[] { return Object.values(this.store.read().artifacts); }
  abort(id: string): void { const record = this.get(id); rmSync(String(record.path), { force: true }); this.store.update((current) => { const artifacts = { ...current.artifacts }; delete artifacts[id]; return { artifacts }; }); }
  download(id: string, offset = 0, limit = 65_536): JsonObject { const record = this.get(id); const path = String(record.path); const size = statSync(path).size; const count = Math.max(0, Math.min(limit, size - offset)); const buffer = Buffer.alloc(count); const fd = openSync(path, 'r'); try { if (count) readSync(fd, buffer, 0, count, offset); } finally { closeSync(fd); } return { data: buffer.toString('base64'), encoding: 'base64', offset: offset + count, eof: offset + count >= size }; }
}
