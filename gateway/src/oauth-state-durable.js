import { randomUUID, createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
export class OAuthStateStore {
  constructor(path) { this.path = path; mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); }
  read() { return existsSync(this.path) ? JSON.parse(readFileSync(this.path, 'utf8')) : { clients: {}, codes: {}, refresh: {}, revoked: {} }; }
  write(state) { const temporary = `${this.path}.${process.pid}.${randomUUID()}.tmp`; writeFileSync(temporary, `${JSON.stringify(state)}\n`, { mode: 0o600 }); renameSync(temporary, this.path); }
  digest(value) { return createHash('sha256').update(value).digest('hex'); }
  update(mutator) { const next = mutator(this.read()); this.write(next); return next; }
}
