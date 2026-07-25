import { MachineServiceError } from './errors.ts';
import { MACHINE_STATES, type MachineState } from './schemas.ts';

const NORMAL_TRANSITIONS: Readonly<Record<MachineState, readonly MachineState[]>> = {
  REQUESTED: ['CLONING'],
  CLONING: ['CLONED'],
  CLONED: ['STARTING', 'EXPIRED', 'DESTROYING'],
  STARTING: ['READY', 'STOPPING', 'EXPIRED'],
  READY: ['EXECUTING', 'STOPPING', 'EXPIRED'],
  EXECUTING: ['READY', 'STOPPING', 'EXPIRED'],
  STOPPING: ['STOPPED', 'EXPIRED'],
  STOPPED: ['STARTING', 'EXPIRED', 'DESTROYING'],
  EXPIRED: ['STOPPING', 'DESTROYING'],
  DESTROYING: ['DESTROYED'],
  DESTROYED: [],
  DEGRADED: ['STOPPING', 'EXPIRED', 'DESTROYING'],
  FAILED: ['STOPPING', 'EXPIRED', 'DESTROYING'],
  LOST: [],
  RECOVERY_REQUIRED: ['CLONED', 'READY', 'STOPPED', 'EXPIRED', 'DESTROYING'],
  AMBIGUOUS: [],
  UNKNOWN: [],
};

export const EXCEPTIONAL_MACHINE_STATES = ['DEGRADED', 'FAILED', 'LOST', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'UNKNOWN'] as const;
const EXCEPTIONAL_SET = new Set<MachineState>(EXCEPTIONAL_MACHINE_STATES);

export function isMachineState(value: unknown): value is MachineState {
  return typeof value === 'string' && (MACHINE_STATES as readonly string[]).includes(value);
}

export function isTerminalMachineState(state: MachineState): boolean {
  return state === 'DESTROYED';
}

export function isRecoverableMachineState(state: MachineState): boolean {
  return ['DEGRADED', 'FAILED', 'LOST', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'UNKNOWN'].includes(state);
}

export function allowedMachineTransitions(state: MachineState): readonly MachineState[] {
  if (state === 'DESTROYED') return [];
  return [...NORMAL_TRANSITIONS[state], ...EXCEPTIONAL_MACHINE_STATES.filter((candidate) => candidate !== state)];
}

export function canTransitionMachineState(prior: MachineState | undefined, next: MachineState): boolean {
  if (prior === undefined) return next === 'REQUESTED';
  if (prior === 'DESTROYED' || prior === next) return false;
  if (NORMAL_TRANSITIONS[prior].includes(next)) return true;
  return EXCEPTIONAL_SET.has(next);
}

export function assertExpectedMachineSequence(actual: number, expected: number): void {
  if (!Number.isSafeInteger(actual) || !Number.isSafeInteger(expected) || actual !== expected) {
    throw new MachineServiceError('machine_sequence_conflict', 'machine state sequence does not match expected sequence', { actual, expected });
  }
}

export function assertMachineTransition(prior: MachineState | undefined, next: MachineState, actualSequence: number, expectedSequence: number): number {
  assertExpectedMachineSequence(actualSequence, expectedSequence);
  if (!canTransitionMachineState(prior, next)) throw new MachineServiceError('machine_state_conflict', `machine state transition ${prior ?? 'none'} -> ${next} is not allowed`, { prior, next });
  return actualSequence + 1;
}
