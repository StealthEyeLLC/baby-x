import type { JsonObject } from '../core.ts';

export type RootPlatformErrorCode =
  | 'root_platform_invalid_request'
  | 'root_platform_duplicate_provider'
  | 'root_platform_provider_not_found'
  | 'root_platform_provider_failed'
  | 'root_platform_idempotency_required'
  | 'root_platform_idempotency_conflict'
  | 'root_platform_integrity_failure';

export class RootPlatformError extends Error {
  constructor(readonly code: RootPlatformErrorCode, message: string, readonly details: JsonObject = {}) {
    super(message);
    this.name = 'RootPlatformError';
  }
}
