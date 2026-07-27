import { canonicalize, sha256, type JsonObject } from '../core.ts';
import { SERVICE_CREDENTIAL_BOOTSTRAP_STATES } from './service-credentials.ts';

export const RELEASE_SCHEMA_VERSION = '1.0.0' as const;
export const MAX_RELEASE_STRING_BYTES = 65_536;
export const MAX_RELEASE_ARRAY_ITEMS = 10_000;
export const MAX_RELEASE_OBJECT_KEYS = 1_000;
export const MAX_RELEASE_NESTING = 24;

export type ReleaseFieldKind = 'string' | 'integer' | 'number' | 'boolean' | 'object' | 'array' | 'json';

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

export interface ReleaseFieldSchema extends JsonObject {
  kind: ReleaseFieldKind;
  required?: boolean;
  enum?: readonly string[];
  format?: 'digest' | 'git-sha' | 'timestamp' | 'identifier';
  items?: ReleaseFieldSchema;
  properties?: Record<string, ReleaseFieldSchema>;
  additionalProperties?: boolean;
  reference?: string;
  maxItems?: number;
  maxLength?: number;
}

export interface ReleaseRecordSchema extends JsonObject {
  schemaId: string;
  schemaVersion: typeof RELEASE_SCHEMA_VERSION;
  type: 'object';
  additionalProperties: false;
  required: readonly string[];
  properties: Record<string, ReleaseFieldSchema>;
}

const stringField = (required = false, format?: ReleaseFieldSchema['format']): ReleaseFieldSchema => ({ kind: 'string', required, ...(format === undefined ? {} : { format }) });
const integerField = (required = false): ReleaseFieldSchema => ({ kind: 'integer', required });
const numberField = (required = false): ReleaseFieldSchema => ({ kind: 'number', required });
const booleanField = (required = false): ReleaseFieldSchema => ({ kind: 'boolean', required });
const jsonField = (required = false): ReleaseFieldSchema => ({ kind: 'json', required });
const stringArray = (required = false, maxItems = MAX_RELEASE_ARRAY_ITEMS): ReleaseFieldSchema => ({ kind: 'array', required, items: stringField(true), maxItems });
const objectArray = (required = false, maxItems = MAX_RELEASE_ARRAY_ITEMS): ReleaseFieldSchema => ({ kind: 'array', required, items: jsonField(true), maxItems });
const enumField = (values: readonly string[], required = false): ReleaseFieldSchema => ({ kind: 'string', required, enum: values });
const referenceField = (reference: string, required = false): ReleaseFieldSchema => ({ kind: 'object', required, reference, additionalProperties: false });

function schema(schemaId: string, properties: Record<string, ReleaseFieldSchema>): ReleaseRecordSchema {
  const complete = { schemaVersion: enumField([RELEASE_SCHEMA_VERSION], true), ...properties };
  return {
    schemaId,
    schemaVersion: RELEASE_SCHEMA_VERSION,
    type: 'object',
    additionalProperties: false,
    required: Object.entries(complete).filter(([, value]) => value.required === true).map(([key]) => key).sort(),
    properties: complete,
  };
}

export const DEPLOYMENT_STATES = [
  'REQUESTED', 'PREFLIGHTING', 'RESOLVING_SOURCE', 'REUSING_ARTIFACT', 'BUILDING', 'CERTIFYING',
  'READY_TO_STAGE', 'STAGING', 'STARTING_INACTIVE', 'READINESS_CHECKING', 'READY_TO_PROMOTE',
  'AWAITING_APPROVAL', 'CUTOVER_PREPARING', 'CUTTING_OVER', 'OBSERVING', 'DRAINING_PREVIOUS',
  'FINALIZING', 'SUCCEEDED', 'ROLLBACK_REQUESTED', 'ROLLING_BACK', 'ROLLED_BACK', 'CLEANUP_PENDING',
  'CLEANING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CANCELLED', 'EXPIRED',
] as const;

export const SLOT_STATES = [
  'EMPTY', 'STAGING', 'STAGED', 'STARTING', 'RUNNING_NOT_READY', 'READY_PRIVATE', 'ACTIVE', 'DRAINING',
  'STOPPING', 'STOPPED', 'CLEANING', 'EMPTY_VERIFIED', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS',
] as const;

export const ROUTE_STATES = [
  'OBSERVED', 'PREPARING', 'VALIDATED', 'LOADING', 'VERIFYING', 'ACTIVE_VERIFIED', 'RESTORE_REQUESTED',
  'RESTORING', 'RESTORED_VERIFIED', 'RECOVERY_REQUIRED', 'AMBIGUOUS',
] as const;

export const BUILD_STATES = [
  'REQUESTED', 'MATERIALIZING', 'RESTORING_CACHE', 'INSTALLING', 'BUILDING', 'PACKAGING', 'VERIFYING',
  'SUCCEEDED', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS', 'CLEANING',
] as const;

export const CERTIFICATION_STATES = [
  'REQUESTED', 'MATERIALIZING', 'STARTING', 'VALIDATING', 'ACCEPTANCE', 'EVIDENCE', 'CLEANING',
  'SUCCEEDED', 'FAILED', 'PRESERVED', 'RECOVERY_REQUIRED', 'AMBIGUOUS',
] as const;

export const RELEASE_FAILURE_CODES = [
  'release_invalid_request', 'release_wrong_principal', 'release_stale_sequence', 'release_idempotency_conflict',
  'release_capacity_insufficient', 'release_source_unresolved', 'release_source_mismatch', 'release_cache_corrupt',
  'release_build_failed', 'release_artifact_invalid', 'release_certification_failed', 'release_certification_stale',
  'release_stage_failed', 'release_unit_invalid', 'release_start_failed', 'release_process_ambiguous',
  'release_readiness_failed', 'release_route_validation_failed', 'release_cutover_failed', 'release_route_ambiguous',
  'release_observation_failed', 'release_rollback_failed', 'release_drain_timeout', 'release_cleanup_failed',
  'release_evidence_incomplete', 'release_credential_unavailable', 'release_github_reporting_deferred',
  'release_provider_unavailable', 'release_provider_incompatible', 'release_recovery_required',
  'release_caddy_config_invalid', 'release_caddy_load_failed', 'release_caddy_load_unobserved', 'release_caddy_read_failed',
  'release_caddy_timeout', 'release_caddy_validation_failed', 'release_config_too_large', 'release_controller_conflict',
  'release_preview_auth_required', 'release_preview_cleanup_failed', 'release_preview_not_expired', 'release_private_probe_failed',
  'release_public_admin_forbidden', 'release_public_probe_failed', 'release_record_not_found', 'release_response_lost',
  'release_restore_unobserved', 'release_shadow_credential_forbidden', 'release_shadow_side_effect_forbidden',
  'release_webhook_signature_invalid', 'release_github_delivery_conflict', 'release_github_token_invalid', 'release_github_unavailable',
  'release_credential_reference_invalid', 'release_credential_rotation_failed', 'release_approval_mismatch', 'release_approval_expired',
  'release_maintenance_approval_required', 'release_maintenance_provider_unavailable', 'release_maintenance_simulation_failed',
  'release_maintenance_verification_failed', 'release_maintenance_apply_failed', 'release_maintenance_certification_failed',
  'release_maintenance_reboot_forbidden', 'release_maintenance_recovery_required',
  'release_credential_bootstrap_invalid_request', 'release_credential_bootstrap_policy_denied',
  'release_credential_bootstrap_profile_unsupported', 'release_credential_bootstrap_incompatible',
  'release_credential_bootstrap_invalid_state', 'release_credential_bootstrap_illegal_transition',
  'release_credential_bootstrap_not_ready', 'release_credential_bootstrap_generation_failed',
  'release_credential_bootstrap_identity_mismatch', 'release_credential_bootstrap_materialization_failed',
  'release_credential_bootstrap_verification_failed', 'release_credential_bootstrap_cleanup_failed',
  'release_credential_bootstrap_revoked', 'release_credential_bootstrap_ambiguous',
] as const;

const structuredError = (): ReleaseFieldSchema => ({
  kind: 'object',
  additionalProperties: false,
  properties: {
    code: enumField(RELEASE_FAILURE_CODES, true),
    message: stringField(true),
    retryable: booleanField(true),
    phase: stringField(false, 'identifier'),
    productionImpact: enumField(['NONE', 'CANDIDATE_ONLY', 'ROLLED_BACK', 'ACTIVE_DEGRADED', 'UNKNOWN']),
    detailsDigest: stringField(false, 'digest'),
  },
});

export const RELEASE_RECORD_SCHEMAS: Readonly<Record<string, ReleaseRecordSchema>> = deepFreeze({
  ServiceDefinitionV1: schema('ServiceDefinitionV1', {
    serviceId: stringField(true, 'identifier'), displayName: stringField(true), ownerPrincipal: stringField(true, 'identifier'),
    organization: stringField(true, 'identifier'), repository: stringField(true), allowedRepositoryIds: stringArray(),
    serviceKind: enumField(['WEB', 'API', 'WORKER', 'SCHEDULER', 'INTERNAL'], true), deploymentGroup: stringField(), orderedDependencies: stringArray(),
    runtimeIdentity: jsonField(true), executableContract: jsonField(true), workingDirectory: stringField(true), environment: jsonField(), credentialReferenceNames: stringArray(),
    userPolicy: jsonField(), slotModel: enumField(['BLUE_GREEN'], true), endpointPreference: enumField(['UNIX_SOCKET', 'LOOPBACK_TCP'], true), endpointPolicy: jsonField(true),
    readinessProbe: jsonField(true), livenessProbe: jsonField(), observationProbes: objectArray(), smokeTestProfile: jsonField(true), drainProtocol: jsonField(true),
    terminationPolicy: jsonField(true), restartPolicy: jsonField(true), watchdogPolicy: jsonField(), resourceProfile: jsonField(true), filesystemWritePolicy: jsonField(true),
    stateDirectories: stringArray(), cacheDirectories: stringArray(), logDirectories: stringArray(), runtimeDirectories: stringArray(), caddyRouteTemplateId: stringField(true, 'identifier'),
    publicHostnames: stringArray(), pathMatchers: stringArray(), migrationContract: jsonField(), rollbackContract: jsonField(true), retentionPolicy: jsonField(true),
    approvalPolicy: jsonField(true), automationPolicy: jsonField(true), manifestDigest: stringField(true, 'digest'), provenance: jsonField(true),
  }),
  SourceIdentityV1: schema('SourceIdentityV1', {
    repository: stringField(true), repositoryId: stringField(), refContext: stringField(), commit: stringField(true, 'git-sha'), tree: stringField(true, 'git-sha'),
    sourceArchiveArtifactId: stringField(true, 'identifier'), sourceArchiveSha256: stringField(true, 'digest'), sourceManifestDigest: stringField(true, 'digest'),
    lockfilePath: stringField(true), lockfileDigest: stringField(true, 'digest'), submodules: objectArray(), gitLfsObjects: objectArray(), resolvedAt: stringField(true, 'timestamp'),
    resolverReceiptId: stringField(true, 'identifier'), verifiedCommitState: enumField(['NOT_REQUIRED', 'VERIFIED', 'UNVERIFIED', 'UNKNOWN']),
  }),
  BuildRecordV1: schema('BuildRecordV1', {
    buildId: stringField(true, 'identifier'), ownerPrincipal: stringField(true, 'identifier'), idempotencyKey: stringField(true, 'identifier'), creationRequestDigest: stringField(true, 'digest'),
    source: referenceField('SourceIdentityV1', true), buildProfile: jsonField(true), buildProfileDigest: stringField(true, 'digest'), toolchainIdentity: jsonField(true),
    baseSnapshotIdentity: jsonField(true), dependencyCacheKey: stringField(true, 'digest'), dependencyCacheResult: enumField(['HIT', 'MISS', 'BYPASS', 'CORRUPT'], true),
    buildCacheKey: stringField(true, 'digest'), buildCacheResult: enumField(['HIT', 'MISS', 'BYPASS', 'CORRUPT'], true), machineId: stringField(true, 'identifier'),
    activeJobIds: stringArray(true), allJobIds: stringArray(true), steps: objectArray(true), outputArtifacts: objectArray(true), provenanceArtifacts: objectArray(),
    resourceSummary: jsonField(true), state: enumField(BUILD_STATES, true), error: structuredError(), cleanup: jsonField(true), evidenceIndexId: stringField(true, 'identifier'),
    sequence: integerField(true), createdAt: stringField(true, 'timestamp'), updatedAt: stringField(true, 'timestamp'), completedAt: stringField(false, 'timestamp'),
  }),
  ReleaseArtifactManifestV1: schema('ReleaseArtifactManifestV1', {
    artifactId: stringField(true, 'identifier'), artifactSha256: stringField(true, 'digest'), sizeBytes: integerField(true), compression: jsonField(true),
    source: referenceField('SourceIdentityV1', true), buildId: stringField(true, 'identifier'), toolchainIdentity: jsonField(true), dependencyIdentity: jsonField(true),
    serviceDefinitionDigest: stringField(true, 'digest'), layoutVersion: stringField(true), executableTemplate: jsonField(true), runtimeRequirements: jsonField(true),
    requiredConfigurationNames: stringArray(true), requiredCredentialNames: stringArray(true), files: objectArray(true), writablePaths: stringArray(true),
    readinessCompatibility: jsonField(true), smokeCompatibility: jsonField(true), migrationMetadata: jsonField(), minimumApplianceVersion: stringField(true),
    createdAt: stringField(true, 'timestamp'), producerIdentity: jsonField(true), provenanceReferences: objectArray(), sbomReferences: objectArray(), manifestDigest: stringField(true, 'digest'),
  }),
  CertificationRecordV1: schema('CertificationRecordV1', {
    certificationId: stringField(true, 'identifier'), artifactId: stringField(true, 'identifier'), artifactSha256: stringField(true, 'digest'), manifestDigest: stringField(true, 'digest'),
    serviceDefinitionDigest: stringField(true, 'digest'), profile: jsonField(true), profileDigest: stringField(true, 'digest'), baseSnapshotName: stringField(true),
    baseSnapshotGuid: stringField(true), baseSnapshotCreationTxg: integerField(true), machineId: stringField(true, 'identifier'), activeJobIds: stringArray(true), allJobIds: stringArray(true),
    dependencyResult: jsonField(true), startupResult: jsonField(true), readinessResult: jsonField(true), smokeResult: jsonField(true), integrationResult: jsonField(true),
    securityResult: jsonField(true), acceptanceResult: jsonField(true), artifactIntegrityResult: jsonField(true), cleanupResult: jsonField(true), sourcePreservationResult: jsonField(true),
    evidenceIndexId: stringField(true, 'identifier'), receiptIds: stringArray(true), invalidationConditions: objectArray(), expiresAt: stringField(false, 'timestamp'),
    state: enumField(CERTIFICATION_STATES, true), error: structuredError(), sequence: integerField(true), createdAt: stringField(true, 'timestamp'), updatedAt: stringField(true, 'timestamp'), completedAt: stringField(false, 'timestamp'),
  }),
  ReleaseRecordV1: schema('ReleaseRecordV1', {
    releaseId: stringField(true, 'identifier'), serviceId: stringField(true, 'identifier'), artifactId: stringField(true, 'identifier'), artifactSha256: stringField(true, 'digest'),
    artifactSizeBytes: integerField(true), manifestDigest: stringField(true, 'digest'), sourceCommit: stringField(true, 'git-sha'), sourceTree: stringField(true, 'git-sha'),
    lockfileDigest: stringField(true, 'digest'), buildId: stringField(true, 'identifier'), certificationId: stringField(true, 'identifier'), materializationPath: stringField(true),
    materializationMethod: enumField(['EXTRACT', 'REFLINK', 'COPY', 'REUSE'], true), materializationVerifiedAt: stringField(true, 'timestamp'), installedManifestDigest: stringField(true, 'digest'),
    immutablePermissionsVerified: booleanField(true), credentialSetReferenceDigest: stringField(true, 'digest'), compatibleApplianceVersion: stringField(true),
    retentionClass: enumField(['ACTIVE', 'ROLLBACK', 'PINNED', 'RECENT', 'CACHE', 'QUARANTINE'], true), pinned: booleanField(true), slotReferences: stringArray(true),
    deploymentReferences: stringArray(true), integrityState: enumField(['VERIFIED', 'CORRUPT', 'QUARANTINED', 'UNKNOWN'], true), createdAt: stringField(true, 'timestamp'),
  }),
  SlotRecordV1: schema('SlotRecordV1', {
    serviceId: stringField(true, 'identifier'), slotId: enumField(['blue', 'green'], true), releaseId: stringField(), desiredState: enumField(SLOT_STATES, true),
    state: enumField(SLOT_STATES, true), sequence: integerField(true), systemdUnit: stringField(true), unitDigest: stringField(true, 'digest'), dropInDigest: stringField(true, 'digest'),
    serviceUser: stringField(true), serviceGroup: stringField(true), runtimeDirectory: stringField(true), endpointType: enumField(['UNIX_SOCKET', 'LOOPBACK_TCP'], true),
    endpointIdentity: jsonField(), expectedProcessIdentity: jsonField(), observedProcessIdentity: jsonField(), unitBundle: jsonField(true), validationResult: jsonField(), activeJobIds: stringArray(true), allJobIds: stringArray(true),
    readinessObservations: objectArray(), livenessObservations: objectArray(), routeMembership: booleanField(true), drainObservations: objectArray(), credentialSetDigest: stringField(true, 'digest'),
    startedAt: stringField(false, 'timestamp'), readyAt: stringField(false, 'timestamp'), exposedAt: stringField(false, 'timestamp'), drainStartedAt: stringField(false, 'timestamp'),
    stoppedAt: stringField(false, 'timestamp'), cleanupCompletedAt: stringField(false, 'timestamp'), ambiguity: jsonField(), error: structuredError(),
  }),
  RouteRecordV1: schema('RouteRecordV1', {
    routeId: stringField(true, 'identifier'), serviceId: stringField(true, 'identifier'), ownerPrincipal: stringField(true, 'identifier'), publicIdentity: jsonField(true),
    desiredActiveSlot: enumField(['blue', 'green'], true), templateId: stringField(true, 'identifier'), routeMode: enumField(['DIRECT', 'CANARY', 'SHADOW', 'PREVIEW'], true),
    expectedUpstreams: stringArray(true), previousObservedUpstreams: stringArray(), streamSettings: jsonField(true), routePolicy: jsonField(true),
    routeLeaseId: stringField(true, 'identifier'), routeLeaseObservationDigest: stringField(true, 'digest'), operationRequestDigest: stringField(true, 'digest'), operationIdempotencyKey: stringField(true, 'identifier'),
    priorActiveSlot: enumField(['blue', 'green']), previousConfigArtifactId: stringField(), previousConfigDigest: stringField(false, 'digest'), previousObservedUpstreamsDigest: stringField(false, 'digest'),
    candidateConfigArtifactId: stringField(), candidateConfigDigest: stringField(false, 'digest'), configGenerationDigest: stringField(false, 'digest'),
    currentConfigCapture: jsonField(), validationJobId: stringField(), validationResult: jsonField(), installedCaddyVersion: stringField(), installedCaddyCapabilities: jsonField(),
    loadRequestDigest: stringField(false, 'digest'), loadResponseDigest: stringField(false, 'digest'), loadIntent: jsonField(), apiResponse: jsonField(),
    activeConfigReadbackDigest: stringField(false, 'digest'), activeConfigReadback: jsonField(), expectedActiveUpstream: jsonField(), observedActiveUpstream: jsonField(),
    privateProbeResult: jsonField(), publicProbeResult: jsonField(), rollbackConfigArtifactId: stringField(), rollbackDigest: stringField(false, 'digest'),
    restoreRequestDigest: stringField(false, 'digest'), restoreLoadIntent: jsonField(), restorationResponseDigest: stringField(false, 'digest'), restorationReadbackDigest: stringField(false, 'digest'), restorationPublicProbe: jsonField(),
    previewExpiresAt: stringField(false, 'timestamp'), previewCleanup: jsonField(), cleanupCompletedAt: stringField(false, 'timestamp'), routeAbsent: booleanField(),
    cutoverAt: stringField(false, 'timestamp'), rollbackAt: stringField(false, 'timestamp'), state: enumField(ROUTE_STATES, true), sequence: integerField(true), ambiguity: jsonField(), error: structuredError(),
  }),
  DeploymentRecordV1: schema('DeploymentRecordV1', {
    deploymentId: stringField(true, 'identifier'), deploymentKind: enumField(['APPLICATION_RELEASE'], true), ownerPrincipal: stringField(true, 'identifier'),
    idempotencyKey: stringField(true, 'identifier'), creationRequestDigest: stringField(true, 'digest'), serviceId: stringField(true, 'identifier'), serviceDefinitionDigest: stringField(true, 'digest'),
    triggerSource: enumField(['MANUAL', 'GITHUB', 'SCHEDULED', 'RECONCILIATION'], true), triggerIdentity: jsonField(true), normalizedRequest: jsonField(true),
    controllerLeaseId: stringField(), controllerLeaseObservationDigest: stringField(false, 'digest'), pendingEffect: jsonField(), recoveryFromState: enumField(DEPLOYMENT_STATES), recoveryResolution: jsonField(),
    sourceIdentity: referenceField('SourceIdentityV1'), sourceManifest: jsonField(), sourceEpoch: integerField(), sourceReceiptReferences: stringArray(),
    buildId: stringField(), artifactId: stringField(), artifact: jsonField(), artifactManifest: jsonField(), artifactReused: booleanField(), artifactReceiptReferences: stringArray(),
    certificationId: stringField(), certification: jsonField(), releaseId: stringField(), releaseRecord: jsonField(), materialization: jsonField(),
    slotId: enumField(['blue', 'green']), slotRecord: jsonField(), privateReadiness: jsonField(), routeId: stringField(), routeRecord: jsonField(), routeMode: enumField(['DIRECT', 'CANARY', 'SHADOW', 'PREVIEW']),
    candidateRouteDigest: stringField(false, 'digest'), priorRouteDigest: stringField(false, 'digest'), routeLeaseId: stringField(), priorRouteReadback: jsonField(), observedLiveReleaseId: stringField(),
    state: enumField(DEPLOYMENT_STATES, true), desiredState: enumField(DEPLOYMENT_STATES, true), sequence: integerField(true), createdAt: stringField(true, 'timestamp'),
    updatedAt: stringField(true, 'timestamp'), completedAt: stringField(false, 'timestamp'), approvalPolicy: jsonField(true), approvalEvidence: objectArray(), approvalDigest: stringField(false, 'digest'), schedule: jsonField(),
    activeJobIds: stringArray(true), allJobIds: stringArray(true), machineIds: stringArray(true), observationPolicy: jsonField(true), observationResults: objectArray(), observationState: jsonField(),
    observationStartedAt: stringField(false, 'timestamp'), observationCompletedAt: stringField(false, 'timestamp'),
    priorKnownGoodReleaseId: stringField(), priorKnownGoodSlotId: enumField(['blue', 'green']), rollbackTarget: jsonField(), rollbackStatus: jsonField(), rollbackObservation: jsonField(), routeRestored: booleanField(),
    drainStatus: jsonField(), cleanup: jsonField(true), terminalIntent: enumField(['ROLLED_BACK', 'FAILED', 'CANCELLED', 'EXPIRED']), cancellation: jsonField(), expiration: jsonField(),
    capacityAdmissionSnapshotId: stringField(true, 'identifier'), credentialSetDigest: stringField(true, 'digest'), githubInboxIds: stringArray(), githubOutboxIds: stringArray(),
    groupContract: jsonField(), groupResult: jsonField(), migrationContract: jsonField(), migrationResult: jsonField(), noopPromotion: booleanField(),
    eventTailDigest: stringField(false, 'digest'), artifactReferences: objectArray(), receiptReferences: stringArray(), evidenceIndexId: stringField(), evidenceIndexDigest: stringField(false, 'digest'),
    finalProof: jsonField(), successEvidence: jsonField(), failureClass: stringField(), ambiguity: jsonField(), error: structuredError(),
  }),
  ObservationRecordV1: schema('ObservationRecordV1', {
    observationId: stringField(true, 'identifier'), deploymentId: stringField(true, 'identifier'), sampleSequence: integerField(true), observedAt: stringField(true, 'timestamp'),
    routeIdentity: jsonField(true), slotIdentity: jsonField(true), probeStatus: enumField(['PASS', 'FAIL', 'TIMEOUT', 'UNKNOWN'], true), latencyMs: numberField(true),
    processState: stringField(true), restartCount: integerField(true), httpStatusDistribution: jsonField(true), applicationMetrics: jsonField(), memory: jsonField(true), cpu: jsonField(true),
    io: jsonField(true), listeners: objectArray(true), errorCount: integerField(true), timeoutCount: integerField(true), sampleDigest: stringField(true, 'digest'),
    thresholdEvaluation: jsonField(true), recommendation: enumField(['CONTINUE', 'PROMOTE', 'ROLLBACK', 'DEFER', 'RECOVERY_REQUIRED'], true),
  }),
  EvidenceIndexV1: schema('EvidenceIndexV1', {
    evidenceIndexId: stringField(true, 'identifier'), parentType: stringField(true, 'identifier'), parentId: stringField(true, 'identifier'), finalState: stringField(true),
    recordDigests: jsonField(true), orderedEventDigests: stringArray(true), jobSummaries: objectArray(true), machineSummaries: objectArray(true), artifactSummaries: objectArray(true),
    identityBindings: jsonField(true), healthSummaries: objectArray(), cutoverConfigDigests: stringArray(), rollbackConfigDigests: stringArray(), credentialSetDigest: stringField(true, 'digest'),
    capacitySnapshotIds: stringArray(), githubReferences: objectArray(), cleanupProof: jsonField(true), signerIdentity: jsonField(true), signedReceiptIds: stringArray(true),
    evidenceIndexDigest: stringField(true, 'digest'), createdAt: stringField(true, 'timestamp'),
  }),
  ServiceCredentialDefinitionV1: schema('ServiceCredentialDefinitionV1', {
    definitionId: stringField(true, 'identifier'), profileId: stringField(true, 'identifier'), name: stringField(true, 'identifier'), purpose: stringField(true, 'identifier'),
    confidentiality: enumField(['PRIVATE', 'PUBLIC'], true), algorithm: enumField(['ED25519'], true), privateEncoding: enumField(['PKCS8_PEM'], true), publicEncoding: enumField(['SPKI_PEM'], true),
    permittedConsumers: stringArray(true, 32), materializationContract: jsonField(true), rotationContract: jsonField(true), definitionDigest: stringField(true, 'digest'),
  }),
  ServiceCredentialBootstrapPlanV1: schema('ServiceCredentialBootstrapPlanV1', {
    planId: stringField(true, 'identifier'), transactionId: stringField(true, 'identifier'), generationId: stringField(true, 'identifier'), ownerPrincipal: stringField(true, 'identifier'),
    idempotencyKey: stringField(true, 'identifier'), profileId: stringField(true, 'identifier'), profileDigest: stringField(true, 'digest'), compatibilityDigest: stringField(true, 'digest'),
    requestDigest: stringField(true, 'digest'), policyDecision: jsonField(true), declaredEffects: objectArray(true, 32), materialization: jsonField(true), verificationRequirements: stringArray(true, 64),
    rotationPredecessorGenerationId: stringField(false, 'identifier'), planDigest: stringField(true, 'digest'), createdAt: stringField(true, 'timestamp'),
  }),
  ServiceCredentialBootstrapTransactionV1: schema('ServiceCredentialBootstrapTransactionV1', {
    transactionId: stringField(true, 'identifier'), ownerPrincipal: stringField(true, 'identifier'), idempotencyKey: stringField(true, 'identifier'), creationRequestDigest: stringField(true, 'digest'),
    profileId: stringField(true, 'identifier'), profileDigest: stringField(true, 'digest'), compatibilityDigest: stringField(true, 'digest'), planDigest: stringField(true, 'digest'),
    policyDecision: jsonField(true), declaredEffects: objectArray(true, 32), state: enumField(SERVICE_CREDENTIAL_BOOTSTRAP_STATES, true), sequence: integerField(true),
    generationId: stringField(true, 'identifier'), allGenerationIds: stringArray(true, 256), activeJobIds: stringArray(true, 256), allJobIds: stringArray(true, 10_000),
    credentialReferenceIds: stringArray(true, 32), publicMaterialReferences: objectArray(true, 32), serviceIdentityBinding: jsonField(), verification: jsonField(), cleanup: jsonField(true),
    rotationPredecessorGenerationId: stringField(false, 'identifier'), rollbackTargetGenerationId: stringField(false, 'identifier'), evidenceReferences: objectArray(), error: structuredError(),
    createdAt: stringField(true, 'timestamp'), updatedAt: stringField(true, 'timestamp'), completedAt: stringField(false, 'timestamp'),
  }),
  ServiceCredentialGenerationV1: schema('ServiceCredentialGenerationV1', {
    generationId: stringField(true, 'identifier'), ownerPrincipal: stringField(true, 'identifier'), profileId: stringField(true, 'identifier'), profileDigest: stringField(true, 'digest'), ordinal: integerField(true),
    state: enumField(['ISSUING', 'READY', 'ACTIVE', 'RETIRED', 'REVOKED', 'FAILED', 'AMBIGUOUS'], true), predecessorGenerationId: stringField(false, 'identifier'), successorGenerationId: stringField(false, 'identifier'),
    privateReferences: objectArray(true, 16), publicMaterials: objectArray(true, 16), publicFingerprints: objectArray(true, 16), serviceIdentityBinding: jsonField(true),
    compatibilityDigest: stringField(true, 'digest'), verificationDigest: stringField(false, 'digest'), revocationReasonDigest: stringField(false, 'digest'), sequence: integerField(true),
    createdAt: stringField(true, 'timestamp'), updatedAt: stringField(true, 'timestamp'), activatedAt: stringField(false, 'timestamp'), retiredAt: stringField(false, 'timestamp'), revokedAt: stringField(false, 'timestamp'),
  }),
  ServiceCredentialProfileStateV1: schema('ServiceCredentialProfileStateV1', {
    profileStateId: stringField(true, 'identifier'), ownerPrincipal: stringField(true, 'identifier'), profileId: stringField(true, 'identifier'), profileDigest: stringField(true, 'digest'),
    state: enumField(['EMPTY', 'ACTIVE', 'ROTATING', 'ROLLBACK_READY', 'AMBIGUOUS', 'REVOKED'], true), activeGenerationId: stringField(false, 'identifier'), previousGenerationId: stringField(false, 'identifier'),
    generationIds: stringArray(true, 256), compatibilityDigest: stringField(true, 'digest'), sequence: integerField(true), createdAt: stringField(true, 'timestamp'), updatedAt: stringField(true, 'timestamp'),
  }),
  ServiceCredentialVerificationV1: schema('ServiceCredentialVerificationV1', {
    verificationId: stringField(true, 'identifier'), generationId: stringField(true, 'identifier'), profileId: stringField(true, 'identifier'), publicFingerprints: objectArray(true, 16),
    keyRelationships: objectArray(true, 16), serviceIdentity: jsonField(true), ownershipChecks: objectArray(true, 32), modeChecks: objectArray(true, 32), temporaryMaterialCleanup: jsonField(true),
    forbiddenAuthorityChecks: objectArray(true, 16), compatibilityDigest: stringField(true, 'digest'), observationDigest: stringField(true, 'digest'), verifiedAt: stringField(true, 'timestamp'),
  }),
  CredentialSetReferenceV1: schema('CredentialSetReferenceV1', {
    credentialSetId: stringField(true, 'identifier'), ownerPrincipal: stringField(true, 'identifier'), serviceId: stringField(true, 'identifier'), version: integerField(true),
    names: stringArray(true), provider: enumField(['SYSTEMD_CREDENTIAL', 'SYSTEMD_ENCRYPTED_CREDENTIAL', 'LEGACY_FILE_ADAPTER'], true), entries: objectArray(true),
    referenceDigest: stringField(true, 'digest'), bindingDigest: stringField(true, 'digest'), state: enumField(['ACTIVE', 'ROTATING', 'RETIRED', 'REVOKED'], true), sequence: integerField(true),
    previousCredentialSetId: stringField(), compatibilityLauncher: jsonField(), overlapUntil: stringField(false, 'timestamp'), createdAt: stringField(true, 'timestamp'),
    updatedAt: stringField(true, 'timestamp'), rotatedAt: stringField(false, 'timestamp'), retiredAt: stringField(false, 'timestamp'), validation: jsonField(), error: structuredError(),
  }),
  CapacitySnapshotV1: schema('CapacitySnapshotV1', {
    snapshotId: stringField(true, 'identifier'), observedAt: stringField(true, 'timestamp'), rootTotalBytes: integerField(true), rootAvailableBytes: integerField(true),
    rootAvailableInodes: integerField(true), zfsPool: stringField(true), zfsTotalBytes: integerField(), zfsAvailableBytes: integerField(true), memoryAvailableBytes: integerField(true),
    cpuPressure: jsonField(true), memoryPressure: jsonField(true), ioPressure: jsonField(true), reservations: objectArray(true), activeReservationTotals: jsonField(),
    admission: enumField(['ALLOW', 'THROTTLE', 'REJECT', 'EMERGENCY_ONLY'], true), governorDecision: jsonField(), observationDigest: stringField(true, 'digest'),
  }),
  CapacityReservationV1: schema('CapacityReservationV1', {
    reservationId: stringField(true, 'identifier'), ownerPrincipal: stringField(true, 'identifier'),
    purpose: enumField(['SOURCE_ARCHIVE', 'DEPENDENCY_CACHE', 'BUILD_CACHE', 'RELEASE_ARTIFACT', 'MATERIALIZATION', 'CERTIFICATION', 'DISPOSABLE_CLONE', 'BACKGROUND_MAINTENANCE'], true),
    workClass: enumField(['PRODUCTION_CONTROL', 'HEAVYWEIGHT', 'BACKGROUND'], true), rootBytes: integerField(true), zfsBytes: integerField(true), memoryBytes: integerField(true),
    requestDigest: stringField(true, 'digest'), snapshotId: stringField(true, 'identifier'), admission: enumField(['ALLOW', 'THROTTLE', 'EMERGENCY_ONLY'], true),
    state: enumField(['ACTIVE', 'RELEASED', 'EXPIRED'], true), createdAt: stringField(true, 'timestamp'), expiresAt: stringField(true, 'timestamp'),
    releasedAt: stringField(false, 'timestamp'), releaseReason: stringField(),
  }),
  CapacityReservationLedgerV1: schema('CapacityReservationLedgerV1', {
    ledgerId: stringField(true, 'identifier'), ownerPrincipal: stringField(true, 'identifier'), state: enumField(['ACTIVE'], true), sequence: integerField(true),
    reservations: objectArray(true), reservedRootBytes: integerField(true), reservedZfsBytes: integerField(true), reservedMemoryBytes: integerField(true),
    reconstructedAt: stringField(true, 'timestamp'), reconstructionDigest: stringField(true, 'digest'), updatedAt: stringField(true, 'timestamp'),
  }),
  GitHubInboxRecordV1: schema('GitHubInboxRecordV1', {
    inboxId: stringField(true, 'identifier'), ownerPrincipal: stringField(true, 'identifier'), deliveryId: stringField(true, 'identifier'), source: enumField(['WEBHOOK', 'POLL'], true),
    repositoryId: stringField(true, 'identifier'), repository: stringField(true), installationId: stringField(true, 'identifier'), eventName: stringField(true), action: stringField(),
    bodySha256: stringField(true, 'digest'), signatureVerified: booleanField(true), receivedAt: stringField(true, 'timestamp'), normalizedEvent: jsonField(true),
    normalizedRequestDigest: stringField(true, 'digest'), convergenceKey: stringField(true, 'digest'), processingState: enumField(['RECEIVED', 'PROCESSING', 'PROCESSED', 'EXCLUDED', 'CONFLICT', 'RECOVERY_REQUIRED'], true),
    disposition: enumField(['ACCEPTED', 'DUPLICATE', 'REJECTED', 'DEFERRED'], true), sequence: integerField(true), processedAt: stringField(false, 'timestamp'),
    deploymentId: stringField(), exclusionReason: stringField(), error: structuredError(),
  }),
  GitHubOutboxRecordV1: schema('GitHubOutboxRecordV1', {
    outboxId: stringField(true, 'identifier'), ownerPrincipal: stringField(true, 'identifier'), repositoryId: stringField(true, 'identifier'), repository: stringField(true),
    installationId: stringField(true, 'identifier'), deploymentId: stringField(true, 'identifier'), reportKind: enumField(['DEPLOYMENT', 'CHECK', 'COMMENT'], true), targetOperation: stringField(true, 'identifier'),
    payloadDigest: stringField(true, 'digest'), payload: jsonField(true), state: enumField(['QUEUED', 'SENDING', 'DELIVERED', 'FAILED', 'DEFERRED', 'UNKNOWN', 'RECOVERY_REQUIRED'], true), attemptCount: integerField(true), sequence: integerField(true),
    createdAt: stringField(true, 'timestamp'), updatedAt: stringField(true, 'timestamp'), nextAttemptAt: stringField(false, 'timestamp'), deliveredAt: stringField(false, 'timestamp'),
    remoteIdentity: jsonField(), lastStatus: jsonField(), error: structuredError(),
  }),
  ControllerLeaseV1: schema('ControllerLeaseV1', {
    leaseId: stringField(true, 'identifier'), resourceType: enumField(['DEPLOYMENT', 'ROUTE', 'SERVICE', 'MAINTENANCE'], true), resourceId: stringField(true, 'identifier'),
    ownerPrincipal: stringField(true, 'identifier'), controllerIdentity: jsonField(true), acquiredAt: stringField(true, 'timestamp'), expiresAt: stringField(true, 'timestamp'),
    sequence: integerField(true), state: enumField(['ACTIVE', 'RELEASING', 'RELEASED', 'STALE', 'AMBIGUOUS'], true), observationDigest: stringField(true, 'digest'),
  }),
  EventRecordV1: schema('EventRecordV1', {
    eventId: stringField(true, 'identifier'), parentType: stringField(true, 'identifier'), parentId: stringField(true, 'identifier'), ownerPrincipal: stringField(true, 'identifier'),
    operation: stringField(true, 'identifier'), phase: stringField(true, 'identifier'), priorState: stringField(true), nextState: stringField(true), priorSequence: integerField(true),
    nextSequence: integerField(true), requestDigest: stringField(true, 'digest'), idempotencyKey: stringField(), occurredAt: stringField(true, 'timestamp'), previousEventDigest: stringField(false, 'digest'),
    eventDigest: stringField(true, 'digest'), childJobIds: stringArray(true), machineId: stringField(), releaseId: stringField(), slotId: stringField(), routeId: stringField(),
    observationDigest: stringField(false, 'digest'), artifactReferences: objectArray(), receiptReferences: stringArray(), error: structuredError(),
  }),
  PendingMutationV1: schema('PendingMutationV1', {
    mutationId: stringField(true, 'identifier'), parentType: stringField(true, 'identifier'), parentId: stringField(true, 'identifier'), ownerPrincipal: stringField(true, 'identifier'),
    operation: stringField(true, 'identifier'), expectedSequence: integerField(true), nextSequence: integerField(true), idempotencyKey: stringField(true, 'identifier'), requestDigest: stringField(true, 'digest'),
    desiredState: stringField(true), externalAction: jsonField(true), state: enumField(['PREPARED', 'SIDE_EFFECT_STARTED', 'READBACK_REQUIRED', 'COMMITTING', 'COMMITTED', 'ABORTED', 'AMBIGUOUS'], true),
    preparedAt: stringField(true, 'timestamp'), updatedAt: stringField(true, 'timestamp'), observationDigest: stringField(false, 'digest'), error: structuredError(),
  }),
  RetentionDecisionV1: schema('RetentionDecisionV1', {
    decisionId: stringField(true, 'identifier'), ownerPrincipal: stringField(), objectType: stringField(true, 'identifier'), objectId: stringField(true, 'identifier'), decision: enumField(['RETAIN', 'EVICT', 'QUARANTINE', 'DEFER'], true),
    reasons: stringArray(true), referenceCount: integerField(true), protectedReferences: stringArray(true), decidedAt: stringField(true, 'timestamp'), decisionDigest: stringField(true, 'digest'),
    planDigest: stringField(false, 'digest'), executionState: enumField(['PLANNED', 'EXECUTED', 'FAILED']), sequence: integerField(), executedAt: stringField(false, 'timestamp'), bytesFreed: integerField(), error: structuredError(),
  }),
  RetentionEvictionV1: schema('RetentionEvictionV1', {
    decisionId: stringField(true, 'identifier'), ownerPrincipal: stringField(true, 'identifier'), artifactId: stringField(true, 'identifier'), objectId: stringField(true, 'identifier'),
    expectedArtifactDigest: stringField(true, 'digest'), retentionClass: enumField(['CACHE'], true), planDigest: stringField(true, 'digest'),
    referenceScanDigest: stringField(true, 'digest'), removalReferenceScanDigest: stringField(false, 'digest'),
    protectedReferenceResult: enumField(['UNPROTECTED', 'PROTECTED', 'UNCERTAIN'], true), protectedReferences: stringArray(true, 1_000),
    idempotencyKey: stringField(true, 'identifier'), requestDigest: stringField(true, 'digest'), sequence: integerField(true),
    requestedAction: enumField(['REMOVE'], true), requestedAt: stringField(true, 'timestamp'), updatedAt: stringField(true, 'timestamp'),
    state: enumField(['REQUESTED', 'REMOVING', 'VERIFYING_ABSENCE', 'REMOVED', 'BLOCKED', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'], true),
    removingAt: stringField(false, 'timestamp'), absenceVerifiedAt: stringField(false, 'timestamp'), removedAt: stringField(false, 'timestamp'),
    bytesFreed: integerField(), observationDigest: stringField(false, 'digest'), error: structuredError(),
  }),
  MigrationRunV1: schema('MigrationRunV1', {
    migrationRunId: stringField(true, 'identifier'), deploymentId: stringField(true, 'identifier'), migrationContractDigest: stringField(true, 'digest'), phase: enumField(['EXPAND', 'MIGRATE', 'CONTRACT'], true),
    reversibility: enumField(['REVERSIBLE', 'FORWARD_ONLY', 'IRREVERSIBLE'], true), approvalEvidence: objectArray(), activeJobIds: stringArray(true), allJobIds: stringArray(true),
    state: enumField(['REQUESTED', 'RUNNING', 'VERIFYING', 'SUCCEEDED', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'], true), evidenceIndexId: stringField(), error: structuredError(),
  }),
  MaintenanceRecordV1: schema('MaintenanceRecordV1', {
    maintenanceId: stringField(true, 'identifier'),
    ownerPrincipal: stringField(true, 'identifier'),
    idempotencyKey: stringField(true, 'identifier'),
    creationRequestDigest: stringField(true, 'digest'),
    failureDomain: enumField(['HOST_MAINTENANCE']),
    maintenanceKind: enumField(['INVENTORY', 'PACKAGE_UPDATE', 'SERVICE_RUNTIME_UPDATE', 'SOFT_REBOOT', 'FULL_REBOOT', 'KEXEC', 'LIVEPATCH', 'FILESYSTEM', 'OTHER_APPROVED', 'RECOVERY'], true),
    targetPackages: stringArray(),
    requestedReason: jsonField(),
    metadata: jsonField(),
    packagePlan: jsonField(),
    approvalEvidence: objectArray(),
    approvalRequired: booleanField(),
    riskClass: enumField(['LOW', 'MEDIUM', 'HIGH', 'UNKNOWN']),
    disposableVerificationRequired: booleanField(),
    disposableVerification: jsonField(),
    state: enumField(['REQUESTED', 'SIMULATING', 'SCHEDULED', 'AWAITING_APPROVAL', 'VERIFYING_DISPOSABLE', 'APPLYING', 'REBOOT_REQUIRED', 'VERIFYING_HOST', 'SUCCEEDED', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'], true),
    sequence: integerField(true),
    activeJobIds: stringArray(true),
    allJobIds: stringArray(true),
    rebootRequired: booleanField(true),
    kernelAffected: booleanField(),
    livepatchState: jsonField(true),
    preSnapshot: jsonField(true),
    providerBackupCapability: jsonField(),
    zfsSnapshotReferences: stringArray(),
    activeServices: stringArray(),
    rollbackReleases: stringArray(),
    drainPlan: jsonField(),
    rollbackPlan: jsonField(),
    rebootPlan: jsonField(),
    applicationResult: jsonField(),
    postSnapshot: jsonField(),
    postUpdateCertification: jsonField(),
    evidenceIndexId: jsonField(),
    scheduledFor: jsonField(),
    automaticAllowed: booleanField(),
    error: structuredError(),
    createdAt: stringField(true, 'timestamp'),
    updatedAt: stringField(true, 'timestamp'),
    completedAt: jsonField(),
  }),
});

export class ReleaseSchemaError extends Error {
  readonly code: string;
  readonly path: string;
  constructor(code: string, message: string, path = '$') { super(message); this.name = 'ReleaseSchemaError'; this.code = code; this.path = path; }
}

function isObject(value: unknown): value is JsonObject { return value !== null && typeof value === 'object' && !Array.isArray(value); }

function assertBoundedJson(value: unknown, path: string, depth: number): void {
  if (depth > MAX_RELEASE_NESTING) throw new ReleaseSchemaError('release_schema_bounds', `${path} exceeds maximum nesting`, path);
  if (typeof value === 'string') {
    if (value.includes('\0') || Buffer.byteLength(value) > MAX_RELEASE_STRING_BYTES) throw new ReleaseSchemaError('release_schema_bounds', `${path} contains an invalid or oversized string`, path);
    return;
  }
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new ReleaseSchemaError('release_schema_type', `${path} must contain finite numbers`, path);
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_RELEASE_ARRAY_ITEMS) throw new ReleaseSchemaError('release_schema_bounds', `${path} has too many items`, path);
    value.forEach((item, index) => assertBoundedJson(item, `${path}[${index}]`, depth + 1));
    return;
  }
  if (!isObject(value)) throw new ReleaseSchemaError('release_schema_type', `${path} contains an unsupported value`, path);
  const keys = Object.keys(value);
  if (keys.length > MAX_RELEASE_OBJECT_KEYS) throw new ReleaseSchemaError('release_schema_bounds', `${path} has too many keys`, path);
  for (const key of keys) {
    if (key.includes('\0') || Buffer.byteLength(key) > 256) throw new ReleaseSchemaError('release_schema_bounds', `${path} has an invalid key`, path);
    assertBoundedJson(value[key], `${path}.${key}`, depth + 1);
  }
}

function assertStringFormat(value: string, format: ReleaseFieldSchema['format'], path: string): void {
  if (format === 'digest' && !/^[a-f0-9]{64}$/u.test(value)) throw new ReleaseSchemaError('release_schema_format', `${path} must be a lowercase SHA-256 digest`, path);
  if (format === 'git-sha' && !/^[a-f0-9]{40}$/u.test(value)) throw new ReleaseSchemaError('release_schema_format', `${path} must be a lowercase 40-character Git SHA`, path);
  if (format === 'timestamp' && (Number.isNaN(Date.parse(value)) || !value.endsWith('Z'))) throw new ReleaseSchemaError('release_schema_format', `${path} must be an absolute UTC timestamp`, path);
  if (format === 'identifier' && (!/^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$/u.test(value))) throw new ReleaseSchemaError('release_schema_format', `${path} must be a bounded identifier`, path);
}

function validateField(rule: ReleaseFieldSchema, value: unknown, path: string): void {
  if (rule.kind === 'json') { assertBoundedJson(value, path, 0); return; }
  if (rule.kind === 'string') {
    if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || Buffer.byteLength(value) > (rule.maxLength ?? MAX_RELEASE_STRING_BYTES)) throw new ReleaseSchemaError('release_schema_type', `${path} must be a non-empty bounded string`, path);
    if (rule.enum !== undefined && !rule.enum.includes(value)) throw new ReleaseSchemaError('release_schema_enum', `${path} has an unsupported value`, path);
    assertStringFormat(value, rule.format, path);
    return;
  }
  if (rule.kind === 'integer') {
    if (!Number.isSafeInteger(value) || Number(value) < 0) throw new ReleaseSchemaError('release_schema_type', `${path} must be a non-negative safe integer`, path);
    return;
  }
  if (rule.kind === 'number') {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new ReleaseSchemaError('release_schema_type', `${path} must be a non-negative finite number`, path);
    return;
  }
  if (rule.kind === 'boolean') {
    if (typeof value !== 'boolean') throw new ReleaseSchemaError('release_schema_type', `${path} must be boolean`, path);
    return;
  }
  if (rule.kind === 'array') {
    if (!Array.isArray(value)) throw new ReleaseSchemaError('release_schema_type', `${path} must be an array`, path);
    if (value.length > (rule.maxItems ?? MAX_RELEASE_ARRAY_ITEMS)) throw new ReleaseSchemaError('release_schema_bounds', `${path} has too many items`, path);
    if (rule.items !== undefined) value.forEach((item, index) => validateField(rule.items as ReleaseFieldSchema, item, `${path}[${index}]`));
    return;
  }
  if (!isObject(value)) throw new ReleaseSchemaError('release_schema_type', `${path} must be an object`, path);
  if (rule.reference !== undefined) { validateReleaseRecord(rule.reference, value); return; }
  const properties = rule.properties ?? {};
  const unknown = Object.keys(value).filter((key) => !(key in properties));
  if (rule.additionalProperties !== true && unknown.length > 0) throw new ReleaseSchemaError('release_schema_unknown_field', `${path} contains unknown field ${unknown.sort()[0]}`, `${path}.${unknown.sort()[0]}`);
  for (const [key, childRule] of Object.entries(properties)) {
    if (childRule.required === true && value[key] === undefined) throw new ReleaseSchemaError('release_schema_required', `${path}.${key} is required`, `${path}.${key}`);
    if (value[key] !== undefined) validateField(childRule, value[key], `${path}.${key}`);
  }
}

const sensitiveKey = /^(?:password|passphrase|token|accessToken|refreshToken|privateKey|secret|secretValue|credentialValue|envFile|authorization)$/iu;
const secretMaterial = /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|(?:ghp|github_pat)_[A-Za-z0-9_]{20,}|AWS_SECRET_ACCESS_KEY\s*=|BEGIN PGP PRIVATE KEY BLOCK/u;

function findRawSecret(value: unknown, path: string, depth: number): string | null {
  if (depth > MAX_RELEASE_NESTING) return path;
  if (typeof value === 'string') return secretMaterial.test(value) ? path : null;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) { const found = findRawSecret(value[index], `${path}[${index}]`, depth + 1); if (found !== null) return found; }
    return null;
  }
  if (!isObject(value)) return null;
  for (const [key, item] of Object.entries(value)) {
    if (sensitiveKey.test(key)) return `${path}.${key}`;
    const found = findRawSecret(item, `${path}.${key}`, depth + 1);
    if (found !== null) return found;
  }
  return null;
}

export function assertNoRawSecrets(value: unknown): void {
  const path = findRawSecret(value, '$', 0);
  if (path !== null) throw new ReleaseSchemaError('release_secret_material_rejected', `raw secret material is prohibited at ${path}`, path);
}

export function validateReleaseRecord(schemaId: string, value: unknown): JsonObject {
  const recordSchema = RELEASE_RECORD_SCHEMAS[schemaId];
  if (recordSchema === undefined) throw new ReleaseSchemaError('release_schema_unknown', `unknown release schema ${schemaId}`);
  if (!isObject(value)) throw new ReleaseSchemaError('release_schema_type', `${schemaId} must be an object`);
  const version = value.schemaVersion;
  if (typeof version !== 'string') throw new ReleaseSchemaError('release_schema_required', '$.schemaVersion is required', '$.schemaVersion');
  const major = Number.parseInt(version.split('.')[0] ?? '', 10);
  if (Number.isFinite(major) && major > 1) throw new ReleaseSchemaError('release_schema_newer_unsupported', `newer ${schemaId} schema version ${version} is unsupported`, '$.schemaVersion');
  if (version !== RELEASE_SCHEMA_VERSION) throw new ReleaseSchemaError('release_schema_version_unsupported', `${schemaId} schema version ${version} is unsupported`, '$.schemaVersion');
  const unknown = Object.keys(value).filter((key) => !(key in recordSchema.properties));
  if (unknown.length > 0) throw new ReleaseSchemaError('release_schema_unknown_field', `${schemaId} contains unknown field ${unknown.sort()[0]}`, `$.${unknown.sort()[0]}`);
  for (const required of recordSchema.required) if (value[required] === undefined) throw new ReleaseSchemaError('release_schema_required', `$.${required} is required`, `$.${required}`);
  for (const [key, item] of Object.entries(value)) validateField(recordSchema.properties[key] as ReleaseFieldSchema, item, `$.${key}`);
  assertNoRawSecrets(value);
  return structuredClone(value);
}

export function releaseSchemaDigest(): string { return sha256(canonicalize(RELEASE_RECORD_SCHEMAS)); }

export function redactReleaseValue(value: unknown, depth = 0): unknown {
  if (depth > MAX_RELEASE_NESTING) return '[TRUNCATED]';
  if (typeof value === 'string') {
    if (secretMaterial.test(value)) return '[REDACTED]';
    return Buffer.byteLength(value) <= 4_096 ? value : `${value.slice(0, 4_096)}...[TRUNCATED]`;
  }
  if (Array.isArray(value)) return value.slice(0, 256).map((item) => redactReleaseValue(item, depth + 1));
  if (!isObject(value)) return value;
  const redacted: JsonObject = {};
  for (const [key, item] of Object.entries(value).slice(0, 256)) redacted[key] = sensitiveKey.test(key) ? '[REDACTED]' : redactReleaseValue(item, depth + 1);
  return redacted;
}

export interface BoundedReleaseError extends JsonObject {
  code: string;
  message: string;
  retryable: boolean;
  phase?: string;
  details?: unknown;
}

export function boundedReleaseError(error: unknown, code = 'release_invalid_request', retryable = false, phase?: string): BoundedReleaseError {
  const source = error instanceof Error ? error.message : String(error);
  const message = Buffer.byteLength(source) <= 1_024 ? source : `${source.slice(0, 1_024)}...[TRUNCATED]`;
  const details = error !== null && typeof error === 'object' && 'details' in error ? redactReleaseValue((error as { details?: unknown }).details) : undefined;
  return { code, message, retryable, ...(phase === undefined ? {} : { phase }), ...(details === undefined ? {} : { details }) };
}
