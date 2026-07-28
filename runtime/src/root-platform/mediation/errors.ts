import type { JsonObject } from '../../core.ts';

export type MediationErrorCode =
  | 'mediation_invalid_request'
  | 'mediation_profile_not_found'
  | 'mediation_profile_revoked'
  | 'mediation_profile_expired'
  | 'mediation_sequence_conflict'
  | 'mediation_idempotency_required'
  | 'mediation_idempotency_conflict'
  | 'mediation_native_unavailable'
  | 'mediation_native_failed'
  | 'mediation_integrity_failure'
  | 'mediation_bpf_unavailable';

export class MediationError extends Error {
  constructor(readonly code: MediationErrorCode, message: string, readonly details: JsonObject = {}) {
    super(message);
    this.name = 'MediationError';
  }
}
