import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { canonicalize, sha256, type JsonObject } from '../core.ts';
import {
  BUILD_STATES,
  CERTIFICATION_STATES,
  DEPLOYMENT_STATES,
  RELEASE_RECORD_SCHEMAS,
  RELEASE_SCHEMA_VERSION,
  ROUTE_STATES,
  SLOT_STATES,
  ReleaseSchemaError,
  releaseSchemaDigest,
} from './schemas.ts';
import {
  BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
  SERVICE_CREDENTIAL_BOOTSTRAP_STATES,
  SERVICE_CREDENTIAL_COMPATIBILITY_IDENTITY,
  serviceCredentialCompatibilityDigest,
  serviceCredentialProfileDigest,
} from './service-credentials.ts';

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

export const RELEASE_APPLIANCE_VERSION = '1.0.0' as const;
export const RELEASE_COMPATIBILITY_SCHEMA_VERSION = '1.0.0' as const;

export const FROZEN_GOD_MODE_BASELINE = deepFreeze({
  repository: 'StealthEyeLLC/baby-x',
  branch: 'build/baby-x-god-mode-v1',
  commit: 'b8dcc150ddc175b2ad00099df405b8a3bf0e843a',
  tree: '2045a746e0c6d928cf3354fd0ef9544918fbf514',
});

export const RELEASE_DOCUMENTATION_CHECKPOINT = deepFreeze({
  branch: 'build/baby-x-self-reconciling-release-appliance-v1',
  commit: 'e52950447fc319f9e0833bc01d3d3d047565879a',
  tree: 'e49a6b91afe7eaff4016fb7c5c737817966f0f01',
  directParentCommit: FROZEN_GOD_MODE_BASELINE.commit,
});

export const PROTECTED_CERTIFICATION_SNAPSHOT = deepFreeze({
  name: 'babycert/base/noble@golden-v1',
  guid: '9351137475418520293',
  creationTxg: 53,
});

export type StateMachineName = 'deployment' | 'slot' | 'route' | 'build' | 'certification';

type TransitionTable = Readonly<Record<string, readonly string[]>>;

function table(entries: Record<string, string[]>): TransitionTable {
  return Object.freeze(Object.fromEntries(Object.entries(entries).map(([state, next]) => [state, Object.freeze([...new Set(next)].sort())])));
}

const deploymentTransitions: TransitionTable = table({
  REQUESTED: ['PREFLIGHTING', 'CANCELLED', 'EXPIRED'],
  PREFLIGHTING: ['RESOLVING_SOURCE', 'CLEANUP_PENDING', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCELLED'],
  RESOLVING_SOURCE: ['REUSING_ARTIFACT', 'BUILDING', 'CLEANUP_PENDING', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCELLED'],
  REUSING_ARTIFACT: ['CERTIFYING', 'CLEANUP_PENDING', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCELLED'],
  BUILDING: ['CERTIFYING', 'CLEANUP_PENDING', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCELLED'],
  CERTIFYING: ['READY_TO_STAGE', 'CLEANUP_PENDING', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCELLED'],
  READY_TO_STAGE: ['STAGING', 'ROLLBACK_REQUESTED', 'CLEANUP_PENDING', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCELLED'],
  STAGING: ['STARTING_INACTIVE', 'ROLLBACK_REQUESTED', 'CLEANUP_PENDING', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCELLED'],
  STARTING_INACTIVE: ['READINESS_CHECKING', 'ROLLBACK_REQUESTED', 'CLEANUP_PENDING', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCELLED'],
  READINESS_CHECKING: ['READY_TO_PROMOTE', 'ROLLBACK_REQUESTED', 'CLEANUP_PENDING', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCELLED'],
  READY_TO_PROMOTE: ['AWAITING_APPROVAL', 'CUTOVER_PREPARING', 'ROLLBACK_REQUESTED', 'CLEANUP_PENDING', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCELLED'],
  AWAITING_APPROVAL: ['CUTOVER_PREPARING', 'ROLLBACK_REQUESTED', 'CLEANUP_PENDING', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCELLED', 'EXPIRED'],
  CUTOVER_PREPARING: ['CUTTING_OVER', 'ROLLBACK_REQUESTED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  CUTTING_OVER: ['OBSERVING', 'ROLLBACK_REQUESTED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  OBSERVING: ['DRAINING_PREVIOUS', 'CLEANUP_PENDING', 'ROLLBACK_REQUESTED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  DRAINING_PREVIOUS: ['FINALIZING', 'ROLLBACK_REQUESTED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  FINALIZING: ['SUCCEEDED', 'ROLLBACK_REQUESTED', 'CLEANUP_PENDING', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  ROLLBACK_REQUESTED: ['ROLLING_BACK', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  ROLLING_BACK: ['OBSERVING', 'CLEANUP_PENDING', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  CLEANUP_PENDING: ['CLEANING', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  CLEANING: ['ROLLED_BACK', 'FAILED', 'CANCELLED', 'EXPIRED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  RECOVERY_REQUIRED: ['PREFLIGHTING', 'RESOLVING_SOURCE', 'REUSING_ARTIFACT', 'BUILDING', 'CERTIFYING', 'READY_TO_STAGE', 'STAGING', 'STARTING_INACTIVE', 'READINESS_CHECKING', 'READY_TO_PROMOTE', 'AWAITING_APPROVAL', 'CUTOVER_PREPARING', 'CUTTING_OVER', 'OBSERVING', 'DRAINING_PREVIOUS', 'FINALIZING', 'ROLLBACK_REQUESTED', 'ROLLING_BACK', 'CLEANUP_PENDING', 'CLEANING', 'AMBIGUOUS'],
  AMBIGUOUS: ['RECOVERY_REQUIRED'],
  SUCCEEDED: [], ROLLED_BACK: [], FAILED: [], CANCELLED: [], EXPIRED: [],
});

const slotTransitions: TransitionTable = table({
  EMPTY: ['STAGING'],
  STAGING: ['STAGED', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  STAGED: ['STARTING', 'CLEANING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  STARTING: ['RUNNING_NOT_READY', 'STOPPING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  RUNNING_NOT_READY: ['READY_PRIVATE', 'STOPPING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  READY_PRIVATE: ['ACTIVE', 'STOPPING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  ACTIVE: ['DRAINING', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  DRAINING: ['STOPPING', 'ACTIVE', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  STOPPING: ['STOPPED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  STOPPED: ['CLEANING', 'STARTING', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  CLEANING: ['EMPTY_VERIFIED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  EMPTY_VERIFIED: ['STAGING'],
  FAILED: ['STOPPING', 'CLEANING', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  RECOVERY_REQUIRED: ['STAGING', 'STAGED', 'STARTING', 'RUNNING_NOT_READY', 'READY_PRIVATE', 'ACTIVE', 'DRAINING', 'STOPPING', 'STOPPED', 'CLEANING', 'EMPTY_VERIFIED', 'FAILED', 'AMBIGUOUS'],
  AMBIGUOUS: ['RECOVERY_REQUIRED'],
});

const routeTransitions: TransitionTable = table({
  OBSERVED: ['PREPARING', 'RESTORE_REQUESTED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  PREPARING: ['VALIDATED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  VALIDATED: ['LOADING', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  LOADING: ['VERIFYING', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  VERIFYING: ['ACTIVE_VERIFIED', 'RESTORE_REQUESTED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  ACTIVE_VERIFIED: ['PREPARING', 'RESTORE_REQUESTED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  RESTORE_REQUESTED: ['RESTORING', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  RESTORING: ['RESTORED_VERIFIED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  RESTORED_VERIFIED: ['PREPARING', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  RECOVERY_REQUIRED: ['OBSERVED', 'PREPARING', 'VALIDATED', 'LOADING', 'VERIFYING', 'ACTIVE_VERIFIED', 'RESTORE_REQUESTED', 'RESTORING', 'RESTORED_VERIFIED', 'AMBIGUOUS'],
  AMBIGUOUS: ['RECOVERY_REQUIRED'],
});

const buildTransitions: TransitionTable = table({
  REQUESTED: ['MATERIALIZING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  MATERIALIZING: ['RESTORING_CACHE', 'INSTALLING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  RESTORING_CACHE: ['INSTALLING', 'BUILDING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  INSTALLING: ['BUILDING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  BUILDING: ['PACKAGING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  PACKAGING: ['VERIFYING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  VERIFYING: ['CLEANING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  CLEANING: ['SUCCEEDED', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  RECOVERY_REQUIRED: ['MATERIALIZING', 'RESTORING_CACHE', 'INSTALLING', 'BUILDING', 'PACKAGING', 'VERIFYING', 'CLEANING', 'AMBIGUOUS'],
  AMBIGUOUS: ['RECOVERY_REQUIRED'], SUCCEEDED: [], FAILED: [],
});

const certificationTransitions: TransitionTable = table({
  REQUESTED: ['MATERIALIZING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  MATERIALIZING: ['STARTING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  STARTING: ['VALIDATING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  VALIDATING: ['ACCEPTANCE', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  ACCEPTANCE: ['EVIDENCE', 'FAILED', 'PRESERVED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  EVIDENCE: ['CLEANING', 'FAILED', 'PRESERVED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  CLEANING: ['SUCCEEDED', 'FAILED', 'PRESERVED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  PRESERVED: ['CLEANING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'],
  RECOVERY_REQUIRED: ['MATERIALIZING', 'STARTING', 'VALIDATING', 'ACCEPTANCE', 'EVIDENCE', 'CLEANING', 'PRESERVED', 'AMBIGUOUS'],
  AMBIGUOUS: ['RECOVERY_REQUIRED'], SUCCEEDED: [], FAILED: [],
});

export const RELEASE_STATE_TRANSITIONS: Readonly<Record<StateMachineName, TransitionTable>> = Object.freeze({
  deployment: deploymentTransitions,
  slot: slotTransitions,
  route: routeTransitions,
  build: buildTransitions,
  certification: certificationTransitions,
});

export const TERMINAL_STATES = Object.freeze({
  deployment: Object.freeze(['SUCCEEDED', 'ROLLED_BACK', 'FAILED', 'CANCELLED', 'EXPIRED']),
  slot: Object.freeze(['EMPTY_VERIFIED']),
  route: Object.freeze(['ACTIVE_VERIFIED', 'RESTORED_VERIFIED']),
  build: Object.freeze(['SUCCEEDED', 'FAILED']),
  certification: Object.freeze(['SUCCEEDED', 'FAILED', 'PRESERVED']),
});

export const DEPLOYMENT_SUCCESS_REQUIREMENTS = Object.freeze([
  'exactSourceResolved', 'artifactManifestVerified', 'certificationValid', 'inactiveSlotStagedFromImmutableBytes',
  'unitAndProcessIdentityVerified', 'privateEndpointReady', 'candidateCaddyConfigValidated', 'activeRouteReadbackMatches',
  'publicRouteSmokePassed', 'observationPolicyPassed', 'allRelatedJobsTerminal', 'previousSlotHandledTruthfully',
  'evidenceIndexCompleteAndVerified', 'githubReportingDeliveredOrQueued', 'noUnresolvedAmbiguity',
] as const);

export type DeploymentSuccessRequirement = typeof DEPLOYMENT_SUCCESS_REQUIREMENTS[number];
export type DeploymentSuccessEvidence = Record<DeploymentSuccessRequirement, boolean>;

export interface TerminalSafetyFacts extends JsonObject {
  cleanupComplete: boolean;
  activeRelatedJobs: number;
  unresolvedAmbiguity: boolean;
  evidenceComplete: boolean;
  routeRestored?: boolean;
  cancellationComplete?: boolean;
  expirationPolicyComplete?: boolean;
}

export function assertReleaseTransition(machine: StateMachineName, priorState: string, nextState: string): void {
  const allowed = RELEASE_STATE_TRANSITIONS[machine][priorState];
  if (allowed === undefined) throw new ReleaseSchemaError('release_invalid_state', `unknown ${machine} state ${priorState}`);
  if (!allowed.includes(nextState)) throw new ReleaseSchemaError('release_illegal_transition', `illegal ${machine} transition ${priorState} -> ${nextState}`);
}

export function isTerminalReleaseState(machine: StateMachineName, state: string): boolean {
  return (TERMINAL_STATES[machine] as readonly string[]).includes(state);
}

export function assertDeploymentSuccess(evidence: DeploymentSuccessEvidence): void {
  const missing = DEPLOYMENT_SUCCESS_REQUIREMENTS.filter((requirement) => evidence[requirement] !== true);
  if (missing.length > 0) throw new ReleaseSchemaError('release_success_predicate_failed', `deployment success predicate failed: ${missing.join(', ')}`);
}

export function assertTerminalDeploymentSafety(state: string, facts: TerminalSafetyFacts, successEvidence?: DeploymentSuccessEvidence): void {
  if (!(TERMINAL_STATES.deployment as readonly string[]).includes(state)) throw new ReleaseSchemaError('release_nonterminal_state', `${state} is not a deployment terminal state`);
  if (facts.activeRelatedJobs !== 0) throw new ReleaseSchemaError('release_active_jobs', 'terminal deployment cannot hide active related jobs');
  if (facts.unresolvedAmbiguity) throw new ReleaseSchemaError('release_ambiguous_resources', 'terminal deployment cannot hide unresolved ambiguity');
  if (!facts.evidenceComplete) throw new ReleaseSchemaError('release_evidence_incomplete', 'terminal deployment requires complete evidence');
  if (state === 'SUCCEEDED') {
    if (successEvidence === undefined) throw new ReleaseSchemaError('release_success_predicate_failed', 'SUCCEEDED requires success evidence');
    assertDeploymentSuccess(successEvidence);
  }
  if (state === 'ROLLED_BACK' && (facts.routeRestored !== true || facts.cleanupComplete !== true)) throw new ReleaseSchemaError('release_rollback_incomplete', 'ROLLED_BACK requires verified route restoration and cleanup truth');
  if (state === 'FAILED' && facts.cleanupComplete !== true) throw new ReleaseSchemaError('release_cleanup_failed', 'FAILED requires cleanup truth');
  if (state === 'CANCELLED' && (facts.cancellationComplete !== true || facts.cleanupComplete !== true)) throw new ReleaseSchemaError('release_cleanup_failed', 'CANCELLED requires completed cancellation and cleanup');
  if (state === 'EXPIRED' && facts.expirationPolicyComplete !== true) throw new ReleaseSchemaError('release_cleanup_failed', 'EXPIRED requires completed expiration cleanup or retention policy');
}

const schemaSupport = deepFreeze(Object.fromEntries(Object.keys(RELEASE_RECORD_SCHEMAS).sort().map((schemaId) => [schemaId, {
  current: RELEASE_SCHEMA_VERSION,
  readable: [RELEASE_SCHEMA_VERSION],
  writable: [RELEASE_SCHEMA_VERSION],
  unknownFields: 'REJECT',
  unknownNewerMajor: 'FAIL_CLOSED',
  migration: 'EXPLICIT_ONLY',
}])));

export const RELEASE_COMPATIBILITY_MANIFEST: Readonly<JsonObject> = deepFreeze({
  schemaVersion: RELEASE_COMPATIBILITY_SCHEMA_VERSION,
  applianceVersion: RELEASE_APPLIANCE_VERSION,
  product: 'baby-x-self-reconciling-release-appliance',
  repository: 'StealthEyeLLC/baby-x',
  implementationBranch: RELEASE_DOCUMENTATION_CHECKPOINT.branch,
  frozenBaseline: FROZEN_GOD_MODE_BASELINE,
  documentationCheckpoint: RELEASE_DOCUMENTATION_CHECKPOINT,
  protectedCertificationSnapshot: PROTECTED_CERTIFICATION_SNAPSHOT,
  branchPolicy: {
    v2TransactionalToolFabricDependency: false,
    historyRewriteAllowed: false,
    forcePushAllowed: false,
    productionMutationBeforeCheckpointL: false,
  },
  schemaSupport,
  providerContracts: {
    durableJobAuthority: { namespace: 'babyx.job', version: '1.0.0', reuseRequired: true },
    disposableMachineAuthority: { namespace: 'babyx.machine', version: '1.0.0', reuseRequired: true },
    artifactAuthority: { namespace: 'babyx.artifact', version: '1.0.0', reuseRequired: true },
    proofAuthority: { namespace: 'babyx.proof', version: '1.0.0', reuseRequired: true },
    systemdAdapter: { provider: 'systemd', minimumVersion: '255', authority: 'release-transaction-only' },
    routeAdapter: { provider: 'caddy', minimumVersion: '2.6.2', authority: 'release-transaction-only' },
    sourceResolver: { provider: 'github', mutableRefIsIdentity: false, exactCommitAndTreeRequired: true },
    credentialAuthority: { preferred: 'systemd-credentials', rawValuesInRecords: false, soleAuthority: true, serviceCredentialIssuanceExtension: '1.0.0' },
    maintenanceAuthority: { separateFromReleaseAuthority: true, schema: 'MaintenanceRecordV1' },
  },
  serviceCredentialBootstrap: {
    profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
    profileDigest: serviceCredentialProfileDigest(),
    compatibilityIdentity: SERVICE_CREDENTIAL_COMPATIBILITY_IDENTITY,
    compatibilityDigest: serviceCredentialCompatibilityDigest(),
    states: SERVICE_CREDENTIAL_BOOTSTRAP_STATES,
    productionMaterializationEnabled: false,
    checkpoint: 'K.5',
  },
  operations: [
    { operation: 'babyx.release.describe', mutation: false, inputSchema: { type: 'object', additionalProperties: false } },
    { operation: 'babyx.release.capabilities', mutation: false, inputSchema: { type: 'object', additionalProperties: false } },
  ],
  invariants: {
    exactProcessIdentityRequired: true,
    idempotencyRequiredForMutation: true,
    expectedSequenceRequiredForMutation: true,
    pendingIntentBeforeExternalEffect: true,
    responseLossRequiresReadback: true,
    ambiguityBlocksDestructiveCleanup: true,
    positiveAbsenceRequiredForCleanup: true,
    signedEvidenceRequired: true,
    rawSecretsProhibited: true,
    oneReleaseAuthority: true,
    oneRouteAuthorityPerService: true,
  },
});

export function releaseCompatibilityDigest(): string { return sha256(canonicalize(RELEASE_COMPATIBILITY_MANIFEST)); }

function commandPath(name: string): string | null {
  const result = spawnSync('/usr/bin/env', ['bash', '-lc', `command -v -- ${JSON.stringify(name)}`], { encoding: 'utf8' });
  return result.status === 0 && result.stdout.trim().length > 0 ? result.stdout.trim() : null;
}

function commandVersion(path: string | null, argv: string[]): string | null {
  if (path === null) return null;
  const result = spawnSync(path, argv, { encoding: 'utf8', timeout: 5_000 });
  if (result.status !== 0) return null;
  return `${result.stdout}${result.stderr}`.trim().split('\n')[0] ?? null;
}

function assertEmptyReadPayload(payload: JsonObject): void {
  const keys = Object.keys(payload);
  if (keys.length > 0) throw new ReleaseSchemaError('release_invalid_request', `read-only release operation rejects unknown field ${keys.sort()[0]}`);
}

export function describeReleaseAppliance(payload: JsonObject = {}): JsonObject {
  assertEmptyReadPayload(payload);
  return {
    product: 'baby-x-self-reconciling-release-appliance',
    version: RELEASE_APPLIANCE_VERSION,
    readOnly: true,
    compatibilityManifest: structuredClone(RELEASE_COMPATIBILITY_MANIFEST),
    compatibilityDigest: releaseCompatibilityDigest(),
    recordSchemas: structuredClone(RELEASE_RECORD_SCHEMAS),
    recordSchemaDigest: releaseSchemaDigest(),
    stateMachines: {
      states: { deployment: DEPLOYMENT_STATES, slot: SLOT_STATES, route: ROUTE_STATES, build: BUILD_STATES, certification: CERTIFICATION_STATES, serviceCredentialBootstrap: SERVICE_CREDENTIAL_BOOTSTRAP_STATES },
      transitions: structuredClone(RELEASE_STATE_TRANSITIONS),
      terminalStates: structuredClone(TERMINAL_STATES),
      deploymentSuccessRequirements: DEPLOYMENT_SUCCESS_REQUIREMENTS,
    },
    authorityBoundary: {
      releaseAuthority: 'declared-checkpoint-a',
      durableJobAuthority: 'existing-babyx-job',
      machineAuthority: 'existing-babyx-machine',
      artifactAuthority: 'existing-babyx-artifact',
      proofAuthority: 'existing-babyx-proof',
      hostMaintenanceAuthority: 'separate',
      productionMutationEnabled: false,
    },
  };
}

export function releaseApplianceCapabilities(payload: JsonObject = {}): JsonObject {
  assertEmptyReadPayload(payload);
  const systemctl = commandPath('systemctl');
  const nspawn = commandPath('systemd-nspawn');
  const machinectl = commandPath('machinectl');
  const zfs = commandPath('zfs');
  const caddy = commandPath('caddy');
  const git = commandPath('git');
  const zstd = commandPath('zstd');
  const seccompHelper = 'runtime/native/seccomp-supervisor/target/release/baby-x-seccomp-supervisor';
  return {
    product: 'baby-x-self-reconciling-release-appliance',
    version: RELEASE_APPLIANCE_VERSION,
    readOnly: true,
    productionMutationEnabled: false,
    compatibilityDigest: releaseCompatibilityDigest(),
    recordSchemaDigest: releaseSchemaDigest(),
    host: {
      systemd: { available: systemctl !== null, path: systemctl, version: commandVersion(systemctl, ['--version']) },
      nspawn: { available: nspawn !== null, path: nspawn },
      machinectl: { available: machinectl !== null, path: machinectl },
      zfs: { available: zfs !== null, path: zfs, version: commandVersion(zfs, ['version']) },
      caddy: { available: caddy !== null, path: caddy, version: commandVersion(caddy, ['version']) },
      git: { available: git !== null, path: git, version: commandVersion(git, ['--version']) },
      zstd: { available: zstd !== null, path: zstd, version: commandVersion(zstd, ['--version']) },
      seccompSupervisor: { available: existsSync(seccompHelper), path: seccompHelper, optionalAtCheckpointA: true },
    },
    authorities: {
      durableJobs: { namespace: 'babyx.job', status: 'REUSE_REQUIRED' },
      disposableMachines: { namespace: 'babyx.machine', status: 'REUSE_REQUIRED' },
      artifacts: { namespace: 'babyx.artifact', status: 'REUSE_REQUIRED' },
      proofs: { namespace: 'babyx.proof', status: 'REUSE_REQUIRED' },
      release: { namespace: 'babyx.release', status: 'DECLARED_NOT_MUTATING' },
      maintenance: { namespace: 'babyx.maintenance', status: 'SEPARATE_DECLARED_NOT_MUTATING' },
    },
    protectedSnapshot: PROTECTED_CERTIFICATION_SNAPSHOT,
    providerBackup: { status: 'CONFIGURED_EXPECTATION_UNVERIFIED', apiConfigured: false },
  };
}
