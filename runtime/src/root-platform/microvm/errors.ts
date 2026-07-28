import type { JsonObject } from '../../core.ts';

export type MicrovmErrorCode =
  | 'microvm_invalid_request'
  | 'microvm_not_found'
  | 'microvm_idempotency_conflict'
  | 'microvm_state_conflict'
  | 'microvm_asset_unavailable'
  | 'microvm_asset_integrity_failure'
  | 'microvm_provider_unavailable'
  | 'microvm_guest_authentication_failed'
  | 'microvm_guest_protocol_failed'
  | 'microvm_process_identity_conflict'
  | 'microvm_cleanup_failed'
  | 'microvm_ambiguous';

export class MicrovmError extends Error {
  readonly code: MicrovmErrorCode;
  readonly details: JsonObject;
  constructor(code: MicrovmErrorCode, message: string, details: JsonObject = {}) {
    super(message);
    this.name = 'MicrovmError';
    this.code = code;
    this.details = details;
  }
}
