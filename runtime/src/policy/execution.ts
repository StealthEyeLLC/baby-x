import { canonicalize, sha256, type JsonObject } from '../core.ts';

export const EXECUTION_POLICY_VERSION = '1.0.0' as const;
export type ExecutionMode = 'host' | 'workspace' | 'disposable' | 'parallel-disposable';

type ObjectiveType = 'inspection' | 'development' | 'certification' | 'production-activation' | 'host-recovery' | 'benchmark' | 'candidate-race' | 'custom';
type Risk = 'low' | 'medium' | 'high' | 'unknown';
type DependencyUncertainty = 'known' | 'limited' | 'unknown';
type Isolation = 'none' | 'preferred' | 'required';
type Reversibility = 'reversible' | 'partial' | 'irreversible';
type SourceSensitivity = 'public' | 'internal' | 'sensitive' | 'production';
type Reproducibility = 'none' | 'preferred' | 'required';
type NetworkRequirement = 'none' | 'private' | 'outbound' | 'public';

export interface ExecutionPolicyInput extends JsonObject {
  schemaVersion: typeof EXECUTION_POLICY_VERSION;
  objectiveType: ObjectiveType;
  mutationRisk: Risk;
  dependencyUncertainty: DependencyUncertainty;
  isolationRequirement: Isolation;
  reversibility: Reversibility;
  requiredTools: string[];
  requiredPackages: string[];
  sourceSensitivity: SourceSensitivity;
  reproducibilityRequirement: Reproducibility;
  networkRequirement: NetworkRequirement;
  expectedDurationMs: number;
  resourceProfile: { cpuUnits: number; memoryMb: number; diskMb: number };
  explicitConstraint: 'auto' | ExecutionMode;
  racingEligibility: boolean;
  candidateCount: number;
  costBounds: { maxMachines: number; maxDurationMs: number; maxDiskMb: number };
}

export interface ExecutionPolicyDecision extends JsonObject {
  schemaVersion: typeof EXECUTION_POLICY_VERSION;
  mode: ExecutionMode;
  rationale: string[];
  machineProfile?: JsonObject;
  validationProfile: JsonObject;
  cleanupPolicy: JsonObject;
  normalizedInput: ExecutionPolicyInput;
  decisionDigest: string;
}

export class ExecutionPolicyError extends Error {
  constructor(readonly code: string, message: string, readonly details: JsonObject = {}) {
    super(message);
    this.name = 'ExecutionPolicyError';
  }
}

function object(value: unknown, field: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ExecutionPolicyError('execution_policy_invalid_request', `${field} must be an object`);
  return value as JsonObject;
}
function allowed(value: JsonObject, field: string, keys: readonly string[]): void {
  const set = new Set(keys);
  const unknown = Object.keys(value).filter((key) => !set.has(key));
  if (unknown.length > 0) throw new ExecutionPolicyError('execution_policy_invalid_request', `${field} contains unsupported properties`, { properties: unknown });
}
function enumeration<T extends string>(value: unknown, field: string, values: readonly T[]): T {
  if (typeof value !== 'string' || !values.includes(value as T)) throw new ExecutionPolicyError('execution_policy_invalid_request', `${field} is invalid`);
  return value as T;
}
function integer(value: unknown, field: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new ExecutionPolicyError('execution_policy_invalid_request', `${field} must be a safe integer between ${minimum} and ${maximum}`);
  return Number(value);
}
function strings(value: unknown, field: string, maximum = 100): string[] {
  if (!Array.isArray(value) || value.length > maximum) throw new ExecutionPolicyError('execution_policy_invalid_request', `${field} must be a bounded string array`);
  const normalized = value.map((entry, index) => {
    if (typeof entry !== 'string' || entry.length === 0 || entry.length > 256 || entry.includes('\0')) throw new ExecutionPolicyError('execution_policy_invalid_request', `${field}[${index}] is invalid`);
    return entry;
  });
  return [...new Set(normalized)].sort();
}

export function normalizeExecutionPolicyInput(value: unknown): ExecutionPolicyInput {
  const input = object(value, 'execution policy input');
  allowed(input, 'execution policy input', [
    'schemaVersion', 'objectiveType', 'mutationRisk', 'dependencyUncertainty', 'isolationRequirement', 'reversibility',
    'requiredTools', 'requiredPackages', 'sourceSensitivity', 'reproducibilityRequirement', 'networkRequirement',
    'expectedDurationMs', 'resourceProfile', 'explicitConstraint', 'racingEligibility', 'candidateCount', 'costBounds',
  ]);
  if (input.schemaVersion !== EXECUTION_POLICY_VERSION) throw new ExecutionPolicyError('execution_policy_invalid_request', `schemaVersion must be ${EXECUTION_POLICY_VERSION}`);
  const resource = object(input.resourceProfile, 'resourceProfile');
  allowed(resource, 'resourceProfile', ['cpuUnits', 'memoryMb', 'diskMb']);
  const cost = object(input.costBounds, 'costBounds');
  allowed(cost, 'costBounds', ['maxMachines', 'maxDurationMs', 'maxDiskMb']);
  if (typeof input.racingEligibility !== 'boolean') throw new ExecutionPolicyError('execution_policy_invalid_request', 'racingEligibility must be boolean');
  return {
    schemaVersion: EXECUTION_POLICY_VERSION,
    objectiveType: enumeration(input.objectiveType, 'objectiveType', ['inspection', 'development', 'certification', 'production-activation', 'host-recovery', 'benchmark', 'candidate-race', 'custom']),
    mutationRisk: enumeration(input.mutationRisk, 'mutationRisk', ['low', 'medium', 'high', 'unknown']),
    dependencyUncertainty: enumeration(input.dependencyUncertainty, 'dependencyUncertainty', ['known', 'limited', 'unknown']),
    isolationRequirement: enumeration(input.isolationRequirement, 'isolationRequirement', ['none', 'preferred', 'required']),
    reversibility: enumeration(input.reversibility, 'reversibility', ['reversible', 'partial', 'irreversible']),
    requiredTools: strings(input.requiredTools, 'requiredTools'),
    requiredPackages: strings(input.requiredPackages, 'requiredPackages'),
    sourceSensitivity: enumeration(input.sourceSensitivity, 'sourceSensitivity', ['public', 'internal', 'sensitive', 'production']),
    reproducibilityRequirement: enumeration(input.reproducibilityRequirement, 'reproducibilityRequirement', ['none', 'preferred', 'required']),
    networkRequirement: enumeration(input.networkRequirement, 'networkRequirement', ['none', 'private', 'outbound', 'public']),
    expectedDurationMs: integer(input.expectedDurationMs, 'expectedDurationMs', 1, 604_800_000),
    resourceProfile: {
      cpuUnits: integer(resource.cpuUnits, 'resourceProfile.cpuUnits', 1, 1024),
      memoryMb: integer(resource.memoryMb, 'resourceProfile.memoryMb', 64, 1_048_576),
      diskMb: integer(resource.diskMb, 'resourceProfile.diskMb', 1, 10_485_760),
    },
    explicitConstraint: enumeration(input.explicitConstraint, 'explicitConstraint', ['auto', 'host', 'workspace', 'disposable', 'parallel-disposable']),
    racingEligibility: input.racingEligibility,
    candidateCount: integer(input.candidateCount, 'candidateCount', 1, 100),
    costBounds: {
      maxMachines: integer(cost.maxMachines, 'costBounds.maxMachines', 1, 100),
      maxDurationMs: integer(cost.maxDurationMs, 'costBounds.maxDurationMs', 1, 604_800_000),
      maxDiskMb: integer(cost.maxDiskMb, 'costBounds.maxDiskMb', 1, 10_485_760),
    },
  };
}

function hostUnsafe(input: ExecutionPolicyInput): string[] {
  const reasons: string[] = [];
  if (input.objectiveType === 'certification' || input.objectiveType === 'candidate-race') reasons.push('objective-requires-isolation');
  if (input.mutationRisk === 'high' || input.mutationRisk === 'unknown') reasons.push('mutation-risk');
  if (input.dependencyUncertainty === 'unknown' || input.requiredPackages.length > 0) reasons.push('dependency-installation');
  if (input.isolationRequirement === 'required') reasons.push('isolation-required');
  if (input.sourceSensitivity === 'sensitive') reasons.push('sensitive-source');
  return reasons;
}

function workspaceUnsafe(input: ExecutionPolicyInput): string[] {
  const reasons = hostUnsafe(input);
  if (input.reproducibilityRequirement === 'required') reasons.push('reproducibility-required');
  return [...new Set(reasons)].sort();
}

function profiles(input: ExecutionPolicyInput, mode: ExecutionMode): Pick<ExecutionPolicyDecision, 'machineProfile' | 'validationProfile' | 'cleanupPolicy'> {
  const validationProfile: JsonObject = {
    reproducibility: input.reproducibilityRequirement,
    sourceIdentityRequired: input.reproducibilityRequirement !== 'none' || ['certification', 'candidate-race'].includes(input.objectiveType),
    commonValidationRequired: input.objectiveType === 'candidate-race',
  };
  if (mode === 'host' || mode === 'workspace') {
    return {
      validationProfile,
      cleanupPolicy: { mode: 'retain-authoritative-environment', evidenceRequired: true },
    };
  }
  return {
    machineProfile: {
      provider: 'zfs-nspawn-disposable@1',
      networkMode: input.networkRequirement === 'none' ? 'none' : input.networkRequirement === 'public' ? 'private' : input.networkRequirement,
      resources: input.resourceProfile,
      machineCount: mode === 'parallel-disposable' ? input.candidateCount : 1,
    },
    validationProfile,
    cleanupPolicy: {
      mode: 'destroy-after-evidence',
      preserveOnFailure: ['certification', 'candidate-race'].includes(input.objectiveType),
      positiveAbsenceRequired: true,
    },
  };
}

export function decideExecutionPolicy(value: unknown): ExecutionPolicyDecision {
  const input = normalizeExecutionPolicyInput(value);
  if (input.costBounds.maxDurationMs < input.expectedDurationMs) throw new ExecutionPolicyError('execution_policy_cost_exceeded', 'expected duration exceeds the absolute policy cost bound');
  if (input.costBounds.maxDiskMb < input.resourceProfile.diskMb) throw new ExecutionPolicyError('execution_policy_cost_exceeded', 'required disk exceeds the absolute policy cost bound');
  const rationale: string[] = [];
  let mode: ExecutionMode;

  if (input.objectiveType === 'production-activation' || input.objectiveType === 'host-recovery') {
    if (!['auto', 'host'].includes(input.explicitConstraint)) throw new ExecutionPolicyError('execution_policy_unsafe_override', 'production activation and host recovery must remain host-authoritative');
    mode = 'host';
    rationale.push('host-authoritative-objective');
  } else if (input.explicitConstraint !== 'auto') {
    mode = input.explicitConstraint;
    if (mode === 'host') {
      const unsafe = hostUnsafe(input);
      if (unsafe.length > 0) throw new ExecutionPolicyError('execution_policy_unsafe_override', 'explicit host override is unsafe for this objective', { reasons: unsafe });
    }
    if (mode === 'workspace') {
      const unsafe = workspaceUnsafe(input);
      if (unsafe.length > 0) throw new ExecutionPolicyError('execution_policy_unsafe_override', 'explicit workspace override is unsafe for this objective', { reasons: unsafe });
    }
    if (mode === 'parallel-disposable' && (!input.racingEligibility || input.candidateCount < 2)) throw new ExecutionPolicyError('execution_policy_unsafe_override', 'parallel-disposable requires eligible candidate racing with at least two candidates');
    if (mode === 'parallel-disposable' && (input.costBounds.maxMachines < input.candidateCount || input.costBounds.maxDiskMb < input.resourceProfile.diskMb * input.candidateCount)) throw new ExecutionPolicyError('execution_policy_cost_exceeded', 'parallel-disposable exceeds machine or aggregate disk cost bounds');
    rationale.push('explicit-safe-constraint');
  } else if (input.objectiveType === 'certification') {
    mode = 'disposable';
    rationale.push('certification-defaults-disposable');
  } else if (input.objectiveType === 'candidate-race' && input.racingEligibility && input.candidateCount >= 2) {
    const parallelFits = input.costBounds.maxMachines >= input.candidateCount
      && input.costBounds.maxDurationMs >= input.expectedDurationMs
      && input.costBounds.maxDiskMb >= input.resourceProfile.diskMb * input.candidateCount;
    mode = parallelFits ? 'parallel-disposable' : 'disposable';
    rationale.push(parallelFits ? 'eligible-race-within-cost-bounds' : 'parallel-race-exceeds-cost-bounds');
  } else if (input.mutationRisk === 'high' || input.mutationRisk === 'unknown') {
    mode = 'disposable'; rationale.push('risky-or-unknown-mutation');
  } else if (input.dependencyUncertainty === 'unknown' || input.requiredPackages.length > 0) {
    mode = 'disposable'; rationale.push('unknown-or-installing-dependencies');
  } else if (input.isolationRequirement === 'required' || input.reproducibilityRequirement === 'required' || input.sourceSensitivity === 'sensitive') {
    mode = 'disposable'; rationale.push('isolation-reproducibility-or-source-sensitivity');
  } else if (input.objectiveType === 'inspection' && input.mutationRisk === 'low' && input.dependencyUncertainty === 'known') {
    mode = 'workspace'; rationale.push('ordinary-read-only-inspection');
  } else {
    mode = 'workspace'; rationale.push('bounded-reversible-workspace-default');
  }

  const profile = profiles(input, mode);
  const draft = { schemaVersion: EXECUTION_POLICY_VERSION, mode, rationale, ...profile, normalizedInput: input };
  return { ...draft, decisionDigest: sha256(canonicalize(draft)) };
}

export function describeExecutionPolicy(): JsonObject {
  return {
    operation: 'babyx.execution.policy.describe',
    schemaVersion: EXECUTION_POLICY_VERSION,
    modes: ['host', 'workspace', 'disposable', 'parallel-disposable'],
    authority: 'decision-only',
    executesCommands: false,
    mandatoryRules: ['host-authoritative-production', 'disposable-certification', 'disposable-unknown-dependencies', 'deterministic-evidence-digest'],
  };
}
