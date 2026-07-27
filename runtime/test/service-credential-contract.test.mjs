import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BABY_X_PRODUCTION_CONTROLLER_PROFILE,
  BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
  BABY_X_PRODUCTION_GATEWAY_ACCOUNT,
  BABY_X_PRODUCTION_GATEWAY_UID,
  OPERATION_DEFINITIONS,
  RELEASE_COMPATIBILITY_MANIFEST,
  RELEASE_RECORD_SCHEMAS,
  SERVICE_CREDENTIAL_BOOTSTRAP_STATES,
  SERVICE_CREDENTIAL_COMPATIBILITY_IDENTITY,
  ServiceCredentialContractError,
  assertServiceCredentialReadyFacts,
  assertServiceCredentialTransition,
  canonicalize,
  createServiceCredentialBootstrapPlan,
  describeServiceCredentialProfile,
  serviceCredentialCompatibilityDigest,
  serviceCredentialProfileDigest,
  sha256,
  validateReleaseRecord,
} from '../../dist/runtime/index.js';

const DIGEST = 'a'.repeat(64);
const allowedPolicy = {
  decision: 'ALLOW',
  decisionDigest: DIGEST,
  policyIdentity: 'owner-service-credential-policy-v1',
  environmentClass: 'production-controller',
  reasonCodes: ['CHECKPOINT_K5_AUTHORIZED'],
};

function plan(overrides = {}) {
  return createServiceCredentialBootstrapPlan({
    ownerPrincipal: 'stealtheye-owner',
    idempotencyKey: 'k5-contract-test',
    profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
    expectedCompatibilityIdentity: serviceCredentialCompatibilityDigest(),
    policyDecision: allowedPolicy,
    ...overrides,
  });
}

test('service credential profile is deterministic and immutable', () => {
  assert.equal(serviceCredentialProfileDigest(), sha256(canonicalize(BABY_X_PRODUCTION_CONTROLLER_PROFILE)));
  assert.equal(Object.isFrozen(BABY_X_PRODUCTION_CONTROLLER_PROFILE), true);
  assert.equal(Object.isFrozen(BABY_X_PRODUCTION_CONTROLLER_PROFILE.serviceIdentity), true);
});

test('Baby-X profile binds the exact fix-mcp production identity', () => {
  assert.equal(BABY_X_PRODUCTION_GATEWAY_ACCOUNT, 'fix-mcp');
  assert.equal(BABY_X_PRODUCTION_GATEWAY_UID, 997);
  assert.equal(BABY_X_PRODUCTION_CONTROLLER_PROFILE.serviceIdentity.accountName, 'fix-mcp');
  assert.equal(BABY_X_PRODUCTION_CONTROLLER_PROFILE.serviceIdentity.expectedUid, 997);
});

test('Baby-X profile uses Ed25519 PKCS8 private and SPKI public encodings', () => {
  assert.deepEqual(BABY_X_PRODUCTION_CONTROLLER_PROFILE.algorithmPolicy, {
    algorithm: 'ED25519', privateEncoding: 'PKCS8_PEM', publicEncoding: 'SPKI_PEM',
    substitutionAllowed: false, deterministicPrivateKeysAllowed: false, secureRandomRequired: true,
  });
});

test('private credentials use systemd runtime credential paths, not environment bytes', () => {
  const definitions = BABY_X_PRODUCTION_CONTROLLER_PROFILE.credentialDefinitions;
  const privateDefinitions = definitions.filter((entry) => entry.confidentiality === 'PRIVATE');
  assert.equal(privateDefinitions.length, 2);
  for (const entry of privateDefinitions) {
    assert.equal(entry.materialization.mechanism, 'SYSTEMD_LOAD_CREDENTIAL');
    assert.match(entry.materialization.runtimePath, /^%d\//u);
    assert.equal(entry.materialization.persistentPath, null);
  }
  assert.equal(BABY_X_PRODUCTION_CONTROLLER_PROFILE.privateMaterialInEnvironmentAllowed, false);
  assert.equal(BABY_X_PRODUCTION_CONTROLLER_PROFILE.privateMaterialInJsonAllowed, false);
});

test('proof public material contract matches certified K gateway path', () => {
  const definition = BABY_X_PRODUCTION_CONTROLLER_PROFILE.credentialDefinitions.find((entry) => entry.name === 'proof-public');
  assert.equal(definition.materialization.persistentPath, '/etc/baby-x/proof-public.pem');
  assert.equal(definition.materialization.mode, '0640');
  assert.equal(definition.materialization.groupName, 'horsey');
});

test('unrelated Quirt authority is explicitly forbidden', () => {
  assert.deepEqual(BABY_X_PRODUCTION_CONTROLLER_PROFILE.forbiddenAuthorityPaths, ['/etc/stealtheye-quirt/authority.key']);
});

test('K.5 profile cannot authorize production materialization', () => {
  assert.equal(BABY_X_PRODUCTION_CONTROLLER_PROFILE.productionMaterializationAuthorizedAtCheckpointK5, false);
  assert.equal(plan().materialization.productionEffectsAuthorized, false);
  assert.equal(plan().materialization.createProductionRoot, false);
});

test('bootstrap plan is deterministic for the same authorized request', () => {
  const first = plan();
  const second = plan();
  assert.deepEqual(first, second);
  assert.equal(first.planDigest, sha256(canonicalize(Object.fromEntries(Object.entries(first).filter(([key]) => key !== 'planDigest')))));
});

test('bootstrap plan changes when idempotency identity changes', () => {
  assert.notEqual(plan().requestDigest, plan({ idempotencyKey: 'k5-contract-test-two' }).requestDigest);
  assert.notEqual(plan().generationId, plan({ idempotencyKey: 'k5-contract-test-two' }).generationId);
});

test('unsupported service credential profile fails closed', () => {
  assert.throws(() => plan({ profileId: 'crib.service.v1' }), (error) => error instanceof ServiceCredentialContractError && error.code === 'release_credential_bootstrap_profile_unsupported');
});

test('compatibility substitution fails closed', () => {
  assert.throws(() => plan({ expectedCompatibilityIdentity: 'b'.repeat(64) }), (error) => error instanceof ServiceCredentialContractError && error.code === 'release_credential_bootstrap_incompatible');
});

test('policy decision must explicitly allow bootstrap', () => {
  assert.throws(() => plan({ policyDecision: { ...allowedPolicy, decision: 'DENY' } }), (error) => error instanceof ServiceCredentialContractError && error.code === 'release_credential_bootstrap_policy_denied');
});

test('service credential lifecycle permits recovery but rejects direct REQUESTED to READY', () => {
  assert.doesNotThrow(() => assertServiceCredentialTransition('REQUESTED', 'PLANNING'));
  assert.doesNotThrow(() => assertServiceCredentialTransition('AMBIGUOUS', 'RECOVERY_REQUIRED'));
  assert.throws(() => assertServiceCredentialTransition('REQUESTED', 'READY'), /illegal service credential transition/u);
});

test('READY predicate requires every verification fact', () => {
  const facts = {
    privateReferencesDurable: true, publicMaterialDurable: true, keyRelationshipVerified: true,
    serviceIdentityVerified: true, expectedUidVerified: true, ownershipVerified: true, modesVerified: true,
    temporaryMaterialAbsent: true, forbiddenAuthorityUntouched: true,
  };
  assert.doesNotThrow(() => assertServiceCredentialReadyFacts(facts));
  assert.throws(() => assertServiceCredentialReadyFacts({ ...facts, expectedUidVerified: false }), /expectedUidVerified/u);
});

test('strict K.5 record schemas are registered and reject unknown fields', () => {
  for (const schemaId of ['ServiceCredentialDefinitionV1', 'ServiceCredentialBootstrapPlanV1', 'ServiceCredentialBootstrapTransactionV1', 'ServiceCredentialGenerationV1', 'ServiceCredentialProfileStateV1', 'ServiceCredentialVerificationV1']) {
    assert.ok(RELEASE_RECORD_SCHEMAS[schemaId], schemaId);
    assert.equal(RELEASE_RECORD_SCHEMAS[schemaId].additionalProperties, false);
  }
  assert.throws(() => validateReleaseRecord('ServiceCredentialProfileStateV1', { schemaVersion: '1.0.0', unexpected: true }), /unknown field/u);
});

test('compatibility manifest includes exact K.5 identity and fail-closed authority boundary', () => {
  assert.equal(RELEASE_COMPATIBILITY_MANIFEST.serviceCredentialBootstrap.profileId, BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID);
  assert.equal(RELEASE_COMPATIBILITY_MANIFEST.serviceCredentialBootstrap.compatibilityDigest, serviceCredentialCompatibilityDigest());
  assert.equal(RELEASE_COMPATIBILITY_MANIFEST.serviceCredentialBootstrap.productionMaterializationEnabled, false);
  assert.equal(RELEASE_COMPATIBILITY_MANIFEST.providerContracts.credentialAuthority.soleAuthority, true);
  assert.equal(SERVICE_CREDENTIAL_COMPATIBILITY_IDENTITY.rawPrivateMaterialReturned, false);
});

test('operation catalog exposes one bounded K.5 surface with correct mutation classification', () => {
  const definitions = OPERATION_DEFINITIONS.filter((entry) => entry.operation.startsWith('babyx.release.credential-bootstrap.'));
  assert.equal(definitions.length, 15);
  assert.equal(new Set(definitions.map((entry) => entry.operation)).size, 15);
  const readOnly = new Set(['describe', 'profiles', 'plan', 'get', 'list', 'events', 'verify', 'active', 'compatibility']);
  for (const definition of definitions) {
    const suffix = definition.operation.split('.').at(-1);
    assert.equal(definition.mutation, !readOnly.has(suffix), definition.operation);
    assert.equal(definition.input.additionalProperties, false, definition.operation);
  }
});

test('profile description contains only public contract metadata', () => {
  const described = describeServiceCredentialProfile();
  assert.equal(described.readOnly, true);
  assert.equal(described.compatibilityDigest, serviceCredentialCompatibilityDigest());
  assert.doesNotMatch(JSON.stringify(described), /BEGIN PRIVATE KEY/u);
});

test('state inventory contains every required K.5 lifecycle phase exactly once', () => {
  const required = ['REQUESTED','PLANNING','GENERATING','PERSISTING_REFERENCES','BINDING_IDENTITY','MATERIALIZING_PUBLIC_STATE','VERIFYING','READY','ROTATION_REQUESTED','ROTATING','ROLLBACK_REQUESTED','ROLLING_BACK','CLEANING','FAILED','RECOVERY_REQUIRED','AMBIGUOUS','REVOKED'];
  assert.deepEqual([...SERVICE_CREDENTIAL_BOOTSTRAP_STATES], required);
  assert.equal(new Set(SERVICE_CREDENTIAL_BOOTSTRAP_STATES).size, required.length);
});
