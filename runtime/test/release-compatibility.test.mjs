import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import {
  BabyXRuntime,
  DEPLOYMENT_SUCCESS_REQUIREMENTS,
  FROZEN_GOD_MODE_BASELINE,
  PROTECTED_CERTIFICATION_SNAPSHOT,
  RELEASE_COMPATIBILITY_MANIFEST,
  RELEASE_DOCUMENTATION_CHECKPOINT,
  RELEASE_RECORD_SCHEMAS,
  ReleaseSchemaError,
  assertDeploymentSuccess,
  assertNoRawSecrets,
  assertReleaseTransition,
  assertTerminalDeploymentSafety,
  boundedReleaseError,
  canonicalize,
  describeReleaseAppliance,
  operationDefinitions,
  redactReleaseValue,
  releaseApplianceCapabilities,
  releaseCompatibilityDigest,
  releaseSchemaDigest,
  sha256,
  validateReleaseRecord,
} from '../../dist/runtime/index.js';

const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);
const GIT_A = 'a'.repeat(40);
const GIT_B = 'b'.repeat(40);

function sourceIdentity(overrides = {}) {
  return {
    schemaVersion: '1.0.0',
    repository: 'StealthEyeLLC/baby-x',
    commit: GIT_A,
    tree: GIT_B,
    sourceArchiveArtifactId: 'artifact-source-1',
    sourceArchiveSha256: DIGEST_A,
    sourceManifestDigest: DIGEST_B,
    lockfilePath: 'package-lock.json',
    lockfileDigest: DIGEST_A,
    resolvedAt: '2026-07-26T14:00:00.000Z',
    resolverReceiptId: 'receipt-source-1',
    ...overrides,
  };
}

function successEvidence() {
  return Object.fromEntries(DEPLOYMENT_SUCCESS_REQUIREMENTS.map((requirement) => [requirement, true]));
}

function filesystemSnapshot(root) {
  const entries = [];
  function walk(path) {
    if (!existsSync(path)) return;
    for (const name of readdirSync(path).sort()) {
      const absolute = join(path, name);
      const info = statSync(absolute);
      const key = relative(root, absolute);
      if (info.isDirectory()) {
        entries.push({ key, type: 'directory', mode: info.mode & 0o777 });
        walk(absolute);
      } else {
        entries.push({
          key,
          type: 'file',
          mode: info.mode & 0o777,
          size: info.size,
          sha256: createHash('sha256').update(readFileSync(absolute)).digest('hex'),
        });
      }
    }
  }
  walk(root);
  return entries;
}

function errorCode(expected) {
  return (error) => error instanceof ReleaseSchemaError && error.code === expected;
}

test('release compatibility and schema digests are deterministic and canonical', () => {
  assert.equal(releaseCompatibilityDigest(), releaseCompatibilityDigest());
  assert.equal(releaseSchemaDigest(), releaseSchemaDigest());
  assert.equal(releaseCompatibilityDigest(), sha256(canonicalize(RELEASE_COMPATIBILITY_MANIFEST)));
  assert.equal(releaseSchemaDigest(), sha256(canonicalize(RELEASE_RECORD_SCHEMAS)));
  assert.equal(canonicalize({ z: 1, a: 2 }), canonicalize({ a: 2, z: 1 }));
  assert.match(releaseCompatibilityDigest(), /^[a-f0-9]{64}$/u);
  assert.match(releaseSchemaDigest(), /^[a-f0-9]{64}$/u);
});

test('release record inventory is complete, recursively frozen, and versioned', () => {
  const requiredSchemas = [
    'BuildRecordV1', 'CapacitySnapshotV1', 'CertificationRecordV1', 'ControllerLeaseV1',
    'CredentialSetReferenceV1', 'DeploymentRecordV1', 'EventRecordV1', 'EvidenceIndexV1',
    'GitHubInboxRecordV1', 'GitHubOutboxRecordV1', 'MaintenanceRecordV1', 'MigrationRunV1',
    'ObservationRecordV1', 'PendingMutationV1', 'ReleaseArtifactManifestV1', 'ReleaseRecordV1',
    'RetentionDecisionV1', 'RouteRecordV1', 'ServiceDefinitionV1', 'SlotRecordV1', 'SourceIdentityV1',
  ];
  assert.deepEqual(Object.keys(RELEASE_RECORD_SCHEMAS).sort(), requiredSchemas);
  assert.equal(Object.isFrozen(RELEASE_RECORD_SCHEMAS), true);
  assert.equal(Object.isFrozen(RELEASE_RECORD_SCHEMAS.SourceIdentityV1.properties), true);
  assert.equal(RELEASE_RECORD_SCHEMAS.SourceIdentityV1.schemaVersion, '1.0.0');
});

test('strict schemas accept exact v1 records and reject unknown fields', () => {
  assert.deepEqual(validateReleaseRecord('SourceIdentityV1', sourceIdentity()), sourceIdentity());
  assert.throws(
    () => validateReleaseRecord('SourceIdentityV1', sourceIdentity({ surprise: true })),
    errorCode('release_schema_unknown_field'),
  );
  assert.throws(
    () => validateReleaseRecord('SourceIdentityV1', sourceIdentity({ commit: 'not-a-git-sha' })),
    errorCode('release_schema_format'),
  );
});

test('unknown newer major durable schemas fail closed', () => {
  assert.throws(
    () => validateReleaseRecord('SourceIdentityV1', sourceIdentity({ schemaVersion: '2.0.0' })),
    errorCode('release_schema_newer_unsupported'),
  );
  assert.throws(
    () => validateReleaseRecord('SourceIdentityV1', sourceIdentity({ schemaVersion: '1.1.0' })),
    errorCode('release_schema_version_unsupported'),
  );
});

test('state machines allow declared paths and reject unsafe jumps', () => {
  assert.doesNotThrow(() => assertReleaseTransition('deployment', 'REQUESTED', 'PREFLIGHTING'));
  assert.doesNotThrow(() => assertReleaseTransition('deployment', 'AMBIGUOUS', 'RECOVERY_REQUIRED'));
  assert.doesNotThrow(() => assertReleaseTransition('slot', 'READY_PRIVATE', 'ACTIVE'));
  assert.doesNotThrow(() => assertReleaseTransition('route', 'VALIDATED', 'LOADING'));
  assert.throws(() => assertReleaseTransition('deployment', 'REQUESTED', 'SUCCEEDED'), errorCode('release_illegal_transition'));
  assert.throws(() => assertReleaseTransition('deployment', 'AMBIGUOUS', 'SUCCEEDED'), errorCode('release_illegal_transition'));
  assert.throws(() => assertReleaseTransition('slot', 'ACTIVE', 'CLEANING'), errorCode('release_illegal_transition'));
});

test('terminal state and success guards require complete truthful evidence', () => {
  const evidence = successEvidence();
  assert.doesNotThrow(() => assertDeploymentSuccess(evidence));
  assert.doesNotThrow(() => assertTerminalDeploymentSafety('SUCCEEDED', {
    cleanupComplete: true,
    activeRelatedJobs: 0,
    unresolvedAmbiguity: false,
    evidenceComplete: true,
  }, evidence));
  const incomplete = { ...evidence, publicRouteSmokePassed: false };
  assert.throws(() => assertDeploymentSuccess(incomplete), errorCode('release_success_predicate_failed'));
  assert.throws(() => assertTerminalDeploymentSafety('SUCCEEDED', {
    cleanupComplete: true,
    activeRelatedJobs: 1,
    unresolvedAmbiguity: false,
    evidenceComplete: true,
  }, evidence), errorCode('release_active_jobs'));
  assert.throws(() => assertTerminalDeploymentSafety('ROLLED_BACK', {
    cleanupComplete: true,
    activeRelatedJobs: 0,
    unresolvedAmbiguity: false,
    evidenceComplete: true,
    routeRestored: false,
  }), errorCode('release_rollback_incomplete'));
  assert.throws(() => assertTerminalDeploymentSafety('FAILED', {
    cleanupComplete: false,
    activeRelatedJobs: 0,
    unresolvedAmbiguity: false,
    evidenceComplete: true,
  }), errorCode('release_cleanup_failed'));
});

test('raw secret material is rejected and diagnostic details are bounded and redacted', () => {
  assert.throws(() => assertNoRawSecrets({ nested: { password: 'do-not-store' } }), errorCode('release_secret_material_rejected'));
  assert.throws(() => assertNoRawSecrets({ value: '-----BEGIN PRIVATE KEY-----' }), errorCode('release_secret_material_rejected'));
  assert.deepEqual(redactReleaseValue({ password: 'secret', nested: { token: 'credential', safe: 'ok' } }), {
    password: '[REDACTED]',
    nested: { token: '[REDACTED]', safe: 'ok' },
  });
  const failure = new Error('x'.repeat(2_000));
  failure.details = { password: 'secret', nested: { authorization: 'Bearer hidden', safe: 'visible' } };
  const bounded = boundedReleaseError(failure, 'release_invalid_request', false, 'preflight');
  assert.ok(Buffer.byteLength(bounded.message) < 1_100);
  assert.equal(bounded.details.password, '[REDACTED]');
  assert.equal(bounded.details.nested.authorization, '[REDACTED]');
  assert.equal(bounded.details.nested.safe, 'visible');
});

test('frozen baseline identities and branch isolation are immutable and exact', () => {
  assert.deepEqual(FROZEN_GOD_MODE_BASELINE, {
    repository: 'StealthEyeLLC/baby-x',
    branch: 'build/baby-x-god-mode-v1',
    commit: 'b8dcc150ddc175b2ad00099df405b8a3bf0e843a',
    tree: '2045a746e0c6d928cf3354fd0ef9544918fbf514',
  });
  assert.equal(RELEASE_DOCUMENTATION_CHECKPOINT.commit, 'e52950447fc319f9e0833bc01d3d3d047565879a');
  assert.equal(RELEASE_DOCUMENTATION_CHECKPOINT.tree, 'e49a6b91afe7eaff4016fb7c5c737817966f0f01');
  assert.equal(RELEASE_DOCUMENTATION_CHECKPOINT.directParentCommit, FROZEN_GOD_MODE_BASELINE.commit);
  assert.deepEqual(PROTECTED_CERTIFICATION_SNAPSHOT, {
    name: 'babycert/base/noble@golden-v1',
    guid: '9351137475418520293',
    creationTxg: 53,
  });
  assert.equal(RELEASE_COMPATIBILITY_MANIFEST.branchPolicy.v2TransactionalToolFabricDependency, false);
  assert.equal(RELEASE_COMPATIBILITY_MANIFEST.branchPolicy.productionMutationBeforeCheckpointL, false);
  assert.equal(Object.isFrozen(RELEASE_COMPATIBILITY_MANIFEST.branchPolicy), true);
  assert.throws(() => { RELEASE_COMPATIBILITY_MANIFEST.branchPolicy.forcePushAllowed = true; }, TypeError);
});

test('release describe and capabilities are exposed once, strict, read-only, and authority-safe', async () => {
  const definitions = operationDefinitions();
  for (const operation of ['babyx.release.describe', 'babyx.release.capabilities']) {
    const matching = definitions.filter((definition) => definition.operation === operation);
    assert.equal(matching.length, 1);
    assert.equal(matching[0].mutation, false);
    assert.equal(matching[0].family, 'release');
    assert.equal(matching[0].input.additionalProperties, false);
  }
  const description = describeReleaseAppliance({});
  assert.equal(description.readOnly, true);
  assert.equal(description.authorityBoundary.productionMutationEnabled, false);
  assert.equal(description.authorityBoundary.durableJobAuthority, 'existing-babyx-job');
  assert.equal(description.authorityBoundary.machineAuthority, 'existing-babyx-machine');
  const capabilities = releaseApplianceCapabilities({});
  assert.equal(capabilities.readOnly, true);
  assert.equal(capabilities.productionMutationEnabled, false);
  assert.equal(capabilities.authorities.durableJobs.status, 'REUSE_REQUIRED');
  assert.equal(capabilities.providerBackup.status, 'CONFIGURED_EXPECTATION_UNVERIFIED');
  assert.throws(() => describeReleaseAppliance({ unknown: true }), errorCode('release_invalid_request'));

  const root = mkdtempSync(join(tmpdir(), 'baby-x-release-readonly-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const before = filesystemSnapshot(root);
    const runtimeDescription = await runtime.execute('babyx.release.describe', {});
    const runtimeCapabilities = await runtime.execute('babyx.release.capabilities', {});
    const after = filesystemSnapshot(root);
    assert.equal(runtimeDescription.compatibilityDigest, releaseCompatibilityDigest());
    assert.equal(runtimeCapabilities.recordSchemaDigest, releaseSchemaDigest());
    assert.deepEqual(after, before);
    await assert.rejects(runtime.execute('babyx.release.describe', { mutate: true }), errorCode('release_invalid_request'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
