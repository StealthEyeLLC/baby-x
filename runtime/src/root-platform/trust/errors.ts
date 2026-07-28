import type { JsonObject } from '../../core.ts';

export class RootTrustError extends Error {
  constructor(readonly code: string, message: string, readonly details: JsonObject = {}) {
    super(message);
    this.name = 'RootTrustError';
  }
}
