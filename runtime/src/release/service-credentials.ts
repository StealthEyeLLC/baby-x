import { canonicalize, sha256, type JsonObject } from '../core.ts';

export const SERVICE_CREDENTIAL_CONTRACT_VERSION = '1.0.0' as const;
export const SERVICE_CREDENTIAL_PROFILE_SCHEMA_VERSION = '1.0.0' as const;
export const SERVICE_CREDENTIAL_BOOTSTRAP_SCHEMA_VERSION = '1.0.0' as const;
export const BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID = 'baby-x.production-controller.v1' as const;
export const BABY_X_PRODUCTION_GATEWAY_ACCOUNT = 'fix-mcp' as const;
export const BABY_X_PRODUCTION_GATEWAY_UID = 997 as const;
export const SERVICE_CREDENTIAL_ALGORITHM = 'ED25519' as const;
export const SERVICE_CREDENTIAL_PRIVATE_ENCODING = 'PKCS8_PEM' as const;
export const SERVICE_CREDENTIAL_PUBLIC_ENCODING = 'SPKI_PEM' as const;

export const SERVICE_CREDENTIAL_BOOTSTRAP_STATES = [
  'REQUESTED',
  'PLANNING',
  'GENERATING',
  'PERSISTING_REFERENCES',
  'BINDING_IDENTITY',
  'MATERIALIZING_PUBLIC_STATE',
  'VERIFYING',
  'READY',
  'ROTATION_REQUESTED',
  'ROTATING',
  'ROLLBACK_REQUESTED',
  'ROLLING_BACK',
  'CLEANING',
  'FAILED',
  'RECOVERY_REQUIRED',
  'AMBIGUOUS',
  'REVOKED',
] as const;

export type ServiceCredentialBootstrapState = typeof SERVICE_CREDENTIAL_BOOTSTRAP_STATES[number];

const transitionEntries: Readonly<Record<ServiceCredentialBootstrapState, readonly ServiceCredentialBootstrapState[]>> = Object.freeze({
  REQUESTED: Object.freeze(['PLANNING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS']),
  PLANNING: Object.freeze(['GENERATING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS']),
  GENERATING: Object.freeze(['PERSISTING_REFERENCES', 'CLEANING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS']),
  PERSISTING_REFERENCES: Object.freeze(['BINDING_IDENTITY', 'CLEANING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS']),
  BINDING_IDENTITY: Object.freeze(['MATERIALIZING_PUBLIC_STATE', 'CLEANING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS']),
  MATERIALIZING_PUBLIC_STATE: Object.freeze(['VERIFYING', 'CLEANING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS']),
  VERIFYING: Object.freeze(['READY', 'CLEANING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS']),
  READY: Object.freeze(['ROTATION_REQUESTED', 'ROLLBACK_REQUESTED', 'REVOKED', 'RECOVERY_REQUIRED', 'AMBIGUOUS']),
  ROTATION_REQUESTED: Object.freeze(['ROTATING', 'RECOVERY_REQUIRED', 'AMBIGUOUS']),
  ROTATING: Object.freeze(['VERIFYING', 'CLEANING', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS']),
  ROLLBACK_REQUESTED: Object.freeze(['ROLLING_BACK', 'RECOVERY_REQUIRED', 'AMBIGUOUS']),
  ROLLING_BACK: Object.freeze(['READY', 'RECOVERY_REQUIRED', 'AMBIGUOUS']),
  CLEANING: Object.freeze(['FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS']),
  FAILED: Object.freeze([]),
  RECOVERY_REQUIRED: Object.freeze([
    'PLANNING', 'GENERATING', 'PERSISTING_REFERENCES', 'BINDING_IDENTITY', 'MATERIALIZING_PUBLIC_STATE',
    'VERIFYING', 'ROTATING', 'ROLLING_BACK', 'CLEANING', 'AMBIGUOUS',
  ]),
  AMBIGUOUS: Object.freeze(['RECOVERY_REQUIRED']),
  REVOKED: Object.freeze([]),
});

export const SERVICE_CREDENTIAL_STATE_TRANSITIONS = transitionEntries;
export const SERVICE_CREDENTIAL_TERMINAL_STATES = Object.freeze(['FAILED', 'REVOKED'] as const);

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

function exactKeys(value: JsonObject, allowed: readonly string[], required: readonly string[], name: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', `${name} contains unsupported property ${key}`);
  }
  for (const key of required) {
    if (value[key] === undefined) throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', `${name}.${key} is required`);
  }
}

function identifier(value: unknown, name: string): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$/u.test(value)) {
    throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', `${name} must be an identifier`);
  }
  return value;
}

function digest(value: unknown, name: string): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/u.test(value)) {
    throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', `${name} must be a lowercase sha256 digest`);
  }
  return value;
}

function policyDecision(value: unknown): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', 'policyDecision must be an object');
  }
  const decision = structuredClone(value as JsonObject);
  exactKeys(decision, ['decision', 'decisionDigest', 'policyIdentity', 'environmentClass', 'reasonCodes'], ['decision', 'decisionDigest', 'policyIdentity', 'environmentClass'], 'policyDecision');
  if (decision.decision !== 'ALLOW') throw new ServiceCredentialContractError('release_credential_bootstrap_policy_denied', 'credential bootstrap requires an explicit ALLOW decision');
  digest(decision.decisionDigest, 'policyDecision.decisionDigest');
  identifier(decision.policyIdentity, 'policyDecision.policyIdentity');
  identifier(decision.environmentClass, 'policyDecision.environmentClass');
  if (decision.reasonCodes !== undefined && (!Array.isArray(decision.reasonCodes) || decision.reasonCodes.some((entry) => typeof entry !== 'string'))) {
    throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_request', 'policyDecision.reasonCodes must be a string array');
  }
  return decision;
}

export class ServiceCredentialContractError extends Error {
  constructor(readonly code: string, message: string, readonly details: JsonObject = {}) {
    super(message);
    this.name = 'ServiceCredentialContractError';
  }
}

const gatewayPrivateDefinition = {
  definitionId: 'baby-x.gateway-authority.private.v1',
  name: 'gateway-authority-private',
  purpose: 'GATEWAY_REQUEST_AUTHORITY',
  confidentiality: 'PRIVATE',
  algorithm: SERVICE_CREDENTIAL_ALGORITHM,
  privateEncoding: SERVICE_CREDENTIAL_PRIVATE_ENCODING,
  publicEncoding: SERVICE_CREDENTIAL_PUBLIC_ENCODING,
  permittedConsumers: ['baby-x-gateway.service'],
  rotation: { independentlyGenerated: true, overlappingValidityRequired: true, rollbackGenerationRetained: true },
  materialization: {
    mechanism: 'SYSTEMD_LOAD_CREDENTIAL',
    unit: 'baby-x-gateway.service',
    credentialName: 'baby-x-gateway-authority-private',
    runtimePath: '%d/baby-x-gateway-authority-private',
    environmentName: 'BABY_X_GATEWAY_PRIVATE_KEY',
    persistentPath: null,
    ownerName: BABY_X_PRODUCTION_GATEWAY_ACCOUNT,
    ownerUid: BABY_X_PRODUCTION_GATEWAY_UID,
    groupName: 'horsey',
    mode: '0400',
  },
};

const proofPrivateDefinition = {
  definitionId: 'baby-x.proof.private.v1',
  name: 'proof-private',
  purpose: 'BABY_X_PROOF_SIGNING',
  confidentiality: 'PRIVATE',
  algorithm: SERVICE_CREDENTIAL_ALGORITHM,
  privateEncoding: SERVICE_CREDENTIAL_PRIVATE_ENCODING,
  publicEncoding: SERVICE_CREDENTIAL_PUBLIC_ENCODING,
  permittedConsumers: ['baby-x.service'],
  rotation: { independentlyGenerated: true, overlappingValidityRequired: true, rollbackGenerationRetained: true },
  materialization: {
    mechanism: 'SYSTEMD_LOAD_CREDENTIAL',
    unit: 'baby-x.service',
    credentialName: 'baby-x-proof-private',
    runtimePath: '%d/baby-x-proof-private',
    environmentName: 'BABY_X_PROOF_PRIVATE_KEY',
    persistentPath: null,
    ownerName: 'root',
    ownerUid: 0,
    groupName: 'root',
    mode: '0400',
  },
};

const proofPublicDefinition = {
  definitionId: 'baby-x.proof.public.v1',
  name: 'proof-public',
  purpose: 'BABY_X_PROOF_VERIFICATION',
  confidentiality: 'PUBLIC',
  algorithm: SERVICE_CREDENTIAL_ALGORITHM,
  privateEncoding: SERVICE_CREDENTIAL_PRIVATE_ENCODING,
  publicEncoding: SERVICE_CREDENTIAL_PUBLIC_ENCODING,
  permittedConsumers: ['baby-x-gateway.service'],
  rotation: { derivedFrom: 'proof-private', overlappingValidityRequired: true, rollbackGenerationRetained: true },
  materialization: {
    mechanism: 'ATOMIC_PUBLIC_FILE',
    unit: 'baby-x-gateway.service',
    credentialName: null,
    runtimePath: '/etc/baby-x/proof-public.pem',
    environmentName: 'BABY_X_PROOF_PUBLIC_KEY',
    persistentPath: '/etc/baby-x/proof-public.pem',
    ownerName: 'root',
    ownerUid: 0,
    groupName: 'horsey',
    mode: '0640',
  },
};

export const BABY_X_PRODUCTION_CONTROLLER_PROFILE: Readonly<JsonObject> = deepFreeze({
  schemaVersion: SERVICE_CREDENTIAL_PROFILE_SCHEMA_VERSION,
  contractVersion: SERVICE_CREDENTIAL_CONTRACT_VERSION,
  profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
  profileVersion: 1,
  serviceId: 'baby-x',
  displayName: 'Baby-X production controller identity set',
  algorithmPolicy: {
    algorithm: SERVICE_CREDENTIAL_ALGORITHM,
    privateEncoding: SERVICE_CREDENTIAL_PRIVATE_ENCODING,
    publicEncoding: SERVICE_CREDENTIAL_PUBLIC_ENCODING,
    substitutionAllowed: false,
    deterministicPrivateKeysAllowed: false,
    secureRandomRequired: true,
  },
  serviceIdentity: {
    accountName: BABY_X_PRODUCTION_GATEWAY_ACCOUNT,
    expectedUid: BABY_X_PRODUCTION_GATEWAY_UID,
    expectedGroupName: 'horsey',
    lookupAuthority: 'LOCAL_ACCOUNT_DATABASE',
    lookupCommand: '/usr/bin/getent',
    launcherUnit: 'baby-x-gateway.service',
    launcherExecutable: '/opt/node-v24.18.0-linux-x64/bin/node',
    controllerUnit: 'baby-x.service',
    controllerExecutable: '/opt/baby-x/current/runtime/src/cli/main.ts',
    staleBindingDetectionRequired: true,
  },
  credentialDefinitions: [gatewayPrivateDefinition, proofPrivateDefinition, proofPublicDefinition],
  environmentBindings: {
    BABY_X_GATEWAY_UID: String(BABY_X_PRODUCTION_GATEWAY_UID),
    BABY_X_GATEWAY_PRIVATE_KEY: '%d/baby-x-gateway-authority-private',
    BABY_X_PROOF_PRIVATE_KEY: '%d/baby-x-proof-private',
    BABY_X_PROOF_PUBLIC_KEY: '/etc/baby-x/proof-public.pem',
  },
  approvedPersistentPaths: ['/etc/baby-x/proof-public.pem'],
  forbiddenAuthorityPaths: ['/etc/stealtheye-quirt/authority.key'],
  privateMaterialInEnvironmentAllowed: false,
  privateMaterialInJsonAllowed: false,
  productionMaterializationAuthorizedAtCheckpointK5: false,
  compatibleController: {
    releaseApplianceVersion: '1.0.0',
    runtimeSchemaVersion: '1.0.0',
    gatewayProtocolVersion: '1.0.0',
  },
});

export function serviceCredentialProfileDigest(): string {
  return sha256(canonicalize(BABY_X_PRODUCTION_CONTROLLER_PROFILE));
}

export const SERVICE_CREDENTIAL_COMPATIBILITY_IDENTITY: Readonly<JsonObject> = deepFreeze({
  contractVersion: SERVICE_CREDENTIAL_CONTRACT_VERSION,
  profileSchemaVersion: SERVICE_CREDENTIAL_PROFILE_SCHEMA_VERSION,
  bootstrapSchemaVersion: SERVICE_CREDENTIAL_BOOTSTRAP_SCHEMA_VERSION,
  profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
  profileDigest: serviceCredentialProfileDigest(),
  algorithms: [SERVICE_CREDENTIAL_ALGORITHM],
  privateEncodings: [SERVICE_CREDENTIAL_PRIVATE_ENCODING],
  publicEncodings: [SERVICE_CREDENTIAL_PUBLIC_ENCODING],
  credentialAuthority: 'systemd-credential-reference-authority',
  rawPrivateMaterialReturned: false,
});

export function serviceCredentialCompatibilityDigest(): string {
  return sha256(canonicalize(SERVICE_CREDENTIAL_COMPATIBILITY_IDENTITY));
}

export function describeServiceCredentialProfile(): JsonObject {
  return {
    readOnly: true,
    profile: structuredClone(BABY_X_PRODUCTION_CONTROLLER_PROFILE),
    profileDigest: serviceCredentialProfileDigest(),
    compatibilityIdentity: structuredClone(SERVICE_CREDENTIAL_COMPATIBILITY_IDENTITY),
    compatibilityDigest: serviceCredentialCompatibilityDigest(),
  };
}

export interface ServiceCredentialBootstrapPlanInput {
  ownerPrincipal: string;
  idempotencyKey: string;
  profileId: string;
  expectedCompatibilityIdentity: string;
  policyDecision: JsonObject;
  rotationPredecessorGenerationId?: string;
}

export function createServiceCredentialBootstrapPlan(inputValue: ServiceCredentialBootstrapPlanInput): JsonObject {
  const input = structuredClone(inputValue);
  const ownerPrincipal = identifier(input.ownerPrincipal, 'ownerPrincipal');
  const idempotencyKey = identifier(input.idempotencyKey, 'idempotencyKey');
  const profileId = identifier(input.profileId, 'profileId');
  if (profileId !== BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID) {
    throw new ServiceCredentialContractError('release_credential_bootstrap_profile_unsupported', `unsupported service credential profile ${profileId}`);
  }
  const expectedCompatibilityIdentity = digest(input.expectedCompatibilityIdentity, 'expectedCompatibilityIdentity');
  const actualCompatibilityIdentity = serviceCredentialCompatibilityDigest();
  if (expectedCompatibilityIdentity !== actualCompatibilityIdentity) {
    throw new ServiceCredentialContractError('release_credential_bootstrap_incompatible', 'service credential compatibility identity mismatch', {
      expectedCompatibilityIdentity,
      actualCompatibilityIdentity,
    });
  }
  const normalizedPolicyDecision = policyDecision(input.policyDecision);
  const rotationPredecessorGenerationId = input.rotationPredecessorGenerationId === undefined
    ? undefined
    : identifier(input.rotationPredecessorGenerationId, 'rotationPredecessorGenerationId');
  const requestIdentity = {
    ownerPrincipal,
    idempotencyKey,
    profileId,
    expectedCompatibilityIdentity,
    policyDecisionDigest: normalizedPolicyDecision.decisionDigest,
    rotationPredecessorGenerationId: rotationPredecessorGenerationId ?? null,
  };
  const requestDigest = sha256(canonicalize(requestIdentity));
  const transactionId = `scbt-${requestDigest.slice(0, 32)}`;
  const generationId = `scg-${sha256(canonicalize({ requestDigest, generation: 1 })).slice(0, 32)}`;
  const planBase: JsonObject = {
    schemaVersion: SERVICE_CREDENTIAL_BOOTSTRAP_SCHEMA_VERSION,
    planVersion: 1,
    transactionId,
    generationId,
    ownerPrincipal,
    idempotencyKey,
    profileId,
    profileDigest: serviceCredentialProfileDigest(),
    compatibilityDigest: actualCompatibilityIdentity,
    requestDigest,
    policyDecision: normalizedPolicyDecision,
    declaredEffects: [
      { authority: 'existing-credential-authority', effect: 'ISSUE_PRIVATE_REFERENCE', names: ['gateway-authority-private', 'proof-private'] },
      { authority: 'existing-credential-authority', effect: 'PERSIST_PUBLIC_MATERIAL_REFERENCE', names: ['proof-public'] },
      { authority: 'local-account-database', effect: 'VERIFY_ONLY', accountName: BABY_X_PRODUCTION_GATEWAY_ACCOUNT, expectedUid: BABY_X_PRODUCTION_GATEWAY_UID },
      { authority: 'release-appliance', effect: 'PERSIST_DURABLE_BOOTSTRAP_RECORDS' },
    ],
    materialization: {
      productionEffectsAuthorized: false,
      privateMechanism: 'SYSTEMD_LOAD_CREDENTIAL',
      publicMechanism: 'ATOMIC_PUBLIC_FILE',
      approvedProductionRoot: '/etc/baby-x',
      createProductionRoot: false,
    },
    verificationRequirements: [
      'privateReferencesDurable',
      'publicMaterialDurable',
      'privatePublicRelationshipVerified',
      'serviceIdentityVerified',
      'expectedUidVerified',
      'ownershipVerified',
      'modesVerified',
      'temporaryMaterialAbsent',
      'forbiddenAuthorityUntouched',
    ],
    ...(rotationPredecessorGenerationId === undefined ? {} : { rotationPredecessorGenerationId }),
  };
  return deepFreeze({ ...planBase, planDigest: sha256(canonicalize(planBase)) });
}

export function assertServiceCredentialTransition(priorState: string, nextState: string): void {
  if (!(SERVICE_CREDENTIAL_BOOTSTRAP_STATES as readonly string[]).includes(priorState)) {
    throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_state', `unknown service credential state ${priorState}`);
  }
  if (!(SERVICE_CREDENTIAL_BOOTSTRAP_STATES as readonly string[]).includes(nextState)) {
    throw new ServiceCredentialContractError('release_credential_bootstrap_invalid_state', `unknown service credential state ${nextState}`);
  }
  const allowed = SERVICE_CREDENTIAL_STATE_TRANSITIONS[priorState as ServiceCredentialBootstrapState];
  if (!allowed.includes(nextState as ServiceCredentialBootstrapState)) {
    throw new ServiceCredentialContractError('release_credential_bootstrap_illegal_transition', `illegal service credential transition ${priorState} -> ${nextState}`);
  }
}

export function assertServiceCredentialReadyFacts(value: JsonObject): void {
  exactKeys(value, [
    'privateReferencesDurable', 'publicMaterialDurable', 'keyRelationshipVerified', 'serviceIdentityVerified',
    'expectedUidVerified', 'ownershipVerified', 'modesVerified', 'temporaryMaterialAbsent', 'forbiddenAuthorityUntouched',
  ], [
    'privateReferencesDurable', 'publicMaterialDurable', 'keyRelationshipVerified', 'serviceIdentityVerified',
    'expectedUidVerified', 'ownershipVerified', 'modesVerified', 'temporaryMaterialAbsent', 'forbiddenAuthorityUntouched',
  ], 'readyFacts');
  const missing = Object.entries(value).filter(([, fact]) => fact !== true).map(([name]) => name).sort();
  if (missing.length > 0) {
    throw new ServiceCredentialContractError('release_credential_bootstrap_not_ready', `READY requirements failed: ${missing.join(', ')}`);
  }
}
