export type MachineErrorCode =
  | 'machine_invalid_request'
  | 'machine_not_found'
  | 'machine_name_conflict'
  | 'machine_idempotency_conflict'
  | 'machine_sequence_conflict'
  | 'machine_state_conflict'
  | 'machine_controller_conflict'
  | 'machine_source_not_allowed'
  | 'machine_source_not_found'
  | 'machine_source_mismatch'
  | 'machine_provider_unavailable'
  | 'machine_clone_failed'
  | 'machine_readback_mismatch'
  | 'machine_identity_ambiguous'
  | 'machine_dataset_conflict'
  | 'machine_root_conflict'
  | 'machine_record_corrupt'
  | 'machine_event_corrupt'
  | 'machine_index_corrupt'
  | 'machine_tombstone_conflict';

export class MachineServiceError extends Error {
  readonly code: MachineErrorCode;
  readonly details: Readonly<Record<string, unknown>>;

  constructor(code: MachineErrorCode, message: string, details: Readonly<Record<string, unknown>> = {}) {
    super(message);
    this.name = 'MachineServiceError';
    this.code = code;
    this.details = details;
  }
}
