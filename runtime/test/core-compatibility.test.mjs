import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  BABY_X_CORE_COMPATIBILITY_VERSION,
  FROZEN_CORE_COMPATIBILITY_MANIFEST,
  assertCompatibilityManifest,
  assertProviderCompatibility,
  assertReadableSchema,
  compatibilityManifestCanonical,
  compatibilityManifestDigest,
  coreCompatibilityManifest,
  describeCoreCompatibility,
} from '../../dist/runtime/compatibility/manifest.js';
import { BabyXRuntime, operationDefinitions, sha256 } from '../../dist/runtime/core.js';
import { MACHINE_PROVIDER_ID, MACHINE_SCHEMA_VERSION } from '../../dist/runtime/machines/schemas.js';
import { CERTIFICATION_SCHEMA_VERSION } from '../../dist/runtime/certification/service.js';
import { EXECUTION_POLICY_VERSION } from '../../dist/runtime/policy/execution.js';
import { CANDIDATE_RACE_SCHEMA_VERSION } from '../../dist/runtime/racing/service.js';

test('compatibility manifest serialization is deterministic', () => {
  assert.equal(compatibilityManifestCanonical(), compatibilityManifestCanonical());
  assert.deepEqual(coreCompatibilityManifest(), coreCompatibilityManifest());
});

test('compatibility manifest canonical digest is deterministic and independently recomputable', () => {
  assert.equal(compatibilityManifestDigest(), sha256(compatibilityManifestCanonical()));
  assert.match(compatibilityManifestDigest(), /^[a-f0-9]{64}$/u);
});

test('compatibility manifest binds the exact frozen rollback and protected snapshot identities', () => {
  const manifest = coreCompatibilityManifest();
  assert.deepEqual(manifest.frozenRollback, {
    branch: 'build/baby-x-transactional-root-authority-k-deployment-v1',
    evidenceCommit: '5d993569a22c05acdbdba615376ec8cb9028f6e6',
    evidenceTree: 'b0b9acacb010b68ad7c37d11dd4e3434941def3a',
  });
  assert.deepEqual(manifest.certifiedImplementation, {
    commit: '6e268c39f689b3c2c36ebcd2c3d40d4136e4e313',
    tree: '3ef05a48141b9ac8ba0efe058ea9dd6bac687911',
  });
  assert.deepEqual(manifest.kProductionBaselineCompatibility, {
    branch: 'build/baby-x-transactional-root-authority-k-deployment-v1',
    commit: '5d993569a22c05acdbdba615376ec8cb9028f6e6',
    tree: 'b0b9acacb010b68ad7c37d11dd4e3434941def3a',
    parent: '09ed66a470d8430fc5a1db118ce24cb4913b5cc6',
    readable: true,
    authoritativeRecordRewrite: false,
  });
  assert.deepEqual(manifest.protectedSourceSnapshot, {
    name: 'babycert/base/noble@golden-v1',
    expectedGuid: '9351137475418520293',
    expectedCreationTxg: '53',
  });
});

test('strict manifest validation rejects unknown fields and altered values', () => {
  assert.deepEqual(assertCompatibilityManifest(coreCompatibilityManifest()), FROZEN_CORE_COMPATIBILITY_MANIFEST);
  assert.throws(() => assertCompatibilityManifest({ ...coreCompatibilityManifest(), unknown: true }), /exact supported canonical manifest/u);
  assert.throws(() => assertCompatibilityManifest({ ...coreCompatibilityManifest(), operationCatalogVersion: '999.0.0' }), /exact supported canonical manifest/u);
});

test('unknown newer durable schemas fail closed', () => {
  assert.throws(() => assertReadableSchema('machineRecord', '2.0.0'), /not readable/u);
  assert.throws(() => assertReadableSchema('futureAuthority', '1.0.0'), /not readable/u);
});

test('God Mode v1 durable schema versions remain readable without authoritative rewrite', () => {
  for (const [domain, versions] of Object.entries(coreCompatibilityManifest().godModeV1DurableRecordCompatibility.readableSchemaVersions)) {
    for (const version of versions) assert.doesNotThrow(() => assertReadableSchema(domain, version));
  }
  assert.equal(coreCompatibilityManifest().godModeV1DurableRecordCompatibility.silentAuthoritativeRewrite, false);
});

test('manifest versions match existing certified authority contracts', () => {
  const manifest = coreCompatibilityManifest();
  assert.equal(manifest.babyXCoreCompatibilityVersion, BABY_X_CORE_COMPATIBILITY_VERSION);
  assert.equal(manifest.machineRecordSchemaVersion, MACHINE_SCHEMA_VERSION);
  assert.equal(manifest.certificationSchemaVersion, CERTIFICATION_SCHEMA_VERSION);
  assert.equal(manifest.executionPolicyVersion, EXECUTION_POLICY_VERSION);
  assert.equal(manifest.candidateRacingVersion, CANDIDATE_RACE_SCHEMA_VERSION);
});

test('incompatible provider contracts are rejected', () => {
  assert.doesNotThrow(() => assertProviderCompatibility(MACHINE_PROVIDER_ID, '1.0.0'));
  assert.throws(() => assertProviderCompatibility(MACHINE_PROVIDER_ID, '2.0.0'), /not compatible/u);
  assert.throws(() => assertProviderCompatibility('foreign-provider@1', '1.0.0'), /not compatible/u);
});

test('runtime-supplied development identity cannot alter frozen rollback identity', () => {
  const report = describeCoreCompatibility({ currentSourceCommit: 'runtime-value', currentSourceTree: 'runtime-tree' });
  assert.equal(report.currentDevelopmentCompatibilityIdentity.sourceCommit, 'runtime-value');
  assert.deepEqual(report.frozenBaselineIdentity, coreCompatibilityManifest().frozenRollback);
});

test('public compatibility operation is read-only, strict, and routed by the single runtime catalog', async (t) => {
  const stateRoot = mkdtempSync(join(tmpdir(), 'baby-x-v2a-runtime-'));
  t.after(() => rmSync(stateRoot, { recursive: true, force: true }));
  const runtime = new BabyXRuntime({ stateRoot });
  const definitions = operationDefinitions().filter((entry) => entry.operation === 'babyx.core.compatibility');
  assert.equal(definitions.length, 1);
  assert.equal(definitions[0].mutation, false);
  assert.equal(definitions[0].input.additionalProperties, false);
  const result = await runtime.execute('babyx.core.compatibility', {});
  assert.equal(result.operation, 'babyx.core.compatibility');
  assert.equal(result.readOnly, true);
  await assert.rejects(() => runtime.execute('babyx.core.compatibility', { override: true }), /does not accept input/u);
});

test('compatibility source contains no execution, lifecycle, artifact, cleanup, merge, or deployment authority', () => {
  const source = readFileSync('runtime/src/compatibility/manifest.ts', 'utf8');
  const imports = [...source.matchAll(/from\s+['"]([^'"]+)['"]/gu)].map((match) => match[1]);
  assert.deepEqual(imports, ['node:crypto']);
  assert.doesNotMatch(source, /child_process|\b(?:JobManager|MachineService|ArtifactManager)\b|\b(?:spawn|exec|destroy|cleanup|merge|deploy)\s*\(/u);
});

test('gateway remains a single dynamic catalog and exposes no duplicate compatibility lane', () => {
  const gateway = readFileSync('gateway/src/tool.js', 'utf8');
  const catalog = readFileSync('gateway/src/catalog.js', 'utf8');
  assert.match(gateway, /single unrestricted Baby-X interface/u);
  assert.match(catalog, /babyx\.describe/u);
  assert.doesNotMatch(gateway, /core\.compatibility/u);
});
