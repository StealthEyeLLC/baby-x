import { readFileSync } from 'node:fs';

export class SecretProvider {
  read(reference: string): Buffer { if (!reference.startsWith('/')) throw new Error('secret reference must be an absolute path'); return readFileSync(reference); }
  redact(value: unknown): unknown { return typeof value === 'string' ? '[REDACTED]' : value; }
}
