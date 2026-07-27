import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync,
} from 'node:fs';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';
import {
  BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
  BabyXRuntime,
  ReleaseApplianceStore,
  ServiceCredentialActivationError,
  ServiceCredentialActivationService,
  ServiceCredentialAuthority,
  ServiceCredentialBootstrapService,
  ServiceCredentialFilesystemAuthority,
  canonicalize,
  serviceCredentialCompatibilityDigest,
  sha256,
} from '../../dist/runtime/index.js';

const OWNER = 'stealtheye-owner';
const POLICY = {
  decision: 'ALLOW', decisionDigest: 'a'.repeat(64), policyIdentity: 'credential-bootstrap-policy-v1',
  environmentClass: 'production-controller', reasonCodes: ['CHECKPOINT_K5_AUTHORIZED'],
};

function root() { return mkdtempSync(join(tmpdir(), 'baby-x-service-credential-activation-')); }
function clock(start = Date.parse('2026-07-27T09:00:00.000Z')) { let value = start; return () => { const out = new Date(value).toISOString(); value += 1000; return out; }; }
function controller(suffix = 'a') { return { pid: 6000, processStartTime: `8000${suffix}`, executablePath: '/opt/baby-x/controller', bootId: `boot-${suffix}` }; }
function observation() { return { accountName: 'fix-mcp', observedUid: 997, observedGid: 986, reverseUidAccountName: 'fix-mcp', lookupSource: 'DURABLE_JOB_AUTHORITY_GETENT', verifiedAt: '2026-07-27T09:00:00.000Z' }; }
const lookup = { authority: 'durable-job-authority', async lookup() { return observation(); } };

function environment(options = {}) {
  const base = root();
  const state = join(base, 'state'); const privateRoot = join(base, 'private'); const publicRoot = join(base, 'public'); const stagingRoot = join(base, 'staging');
  const now = options.now ?? clock();
  const store = options.store ?? new ReleaseApplianceStore(state, options.storeOptions);
  const bootstrap = new ServiceCredentialBootstrapService({ store, now, controllerIdentity: controller(options.controllerSuffix ?? 'a'), leaseTtlMs: 10_000 });
  const uid = process.getuid?.() ?? 0; const gid = process.getgid?.() ?? 0;
  const issuer = new ServiceCredentialFilesystemAuthority({ store, bootstrap, privateRoot, publicRoot, privateOwnerUid: uid, privateOwnerGid: gid, publicOwnerUid: uid, publicOwnerGid: gid, now, faultInjector: options.issuerFault });
  const authority = new ServiceCredentialAuthority({ store, bootstrap, issuer, accountLookup: lookup, privateRoots: [privateRoot], publicRoots: [publicRoot], privateOwnerUid: uid, privateOwnerGid: gid, publicOwnerUid: uid, publicOwnerGid: gid, stagingRoot, now });
  return { base, state, privateRoot, publicRoot, stagingRoot, now, store, bootstrap, issuer, authority, uid, gid };
}

function context(key) { return { subject: OWNER, ownerPrincipal: OWNER, idempotencyKey: key }; }
function planPayload(env, key, predecessor) {
  const ctx = context(key);
  const base = { profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID, expectedCompatibilityIdentity: serviceCredentialCompatibilityDigest(), policyDecision: POLICY, ...(predecessor ? { rotationPredecessorGenerationId: predecessor } : {}) };
  const plan = env.authority.plan(base, ctx);
  return { payload: { ...base, declaredEffects: plan.declaredEffects }, context: ctx, plan };
}
async function ensure(env, key = 'ensure-a') { const { payload, context: ctx } = planPayload(env, key); return env.authority.ensure(payload, ctx); }
async function rotate(env, key, predecessor) { const { payload, context: ctx } = planPayload(env, key, predecessor); return env.authority.rotate(payload, ctx); }
function code(expected) { return (error) => error instanceof ServiceCredentialActivationError && error.code === expected; }
function generationIds(env) { return env.store.listRecordIdentities(1000).filter((entry) => entry.schemaId === 'ServiceCredentialGenerationV1').map((entry) => entry.recordId).sort(); }
function findFile(rootValue, name) {
  for (const entry of readdirSync(rootValue, { recursive: true, withFileTypes: true })) if (entry.name === name) return join(entry.parentPath, entry.name);
  return undefined;
}

test('first ensure issues, verifies, and atomically activates one generation', async () => {
  const env = environment();
  try {
    const result = await ensure(env);
    assert.equal(result.active.activeGenerationId, result.transaction.generationId);
    assert.equal(env.authority.active().activeGeneration.state, 'ACTIVE');
    assert.equal(generationIds(env).length, 1);
    const verification = env.authority.verify({ generationId: result.transaction.generationId });
    assert.equal(verification.publicOnly, true);
    assert.equal(verification.serviceIdentity.observedUid, 997);
    assert.equal(verification.temporaryMaterialCleanup.temporaryMaterialAbsent, true);
    assert.doesNotMatch(JSON.stringify(result), /BEGIN PRIVATE KEY/u);
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});

test('high-level ensure requires exact declared effects and is idempotent', async () => {
  const env = environment();
  try {
    const first = await ensure(env, 'ensure-idempotent');
    const second = await ensure(env, 'ensure-idempotent');
    assert.equal(second.active.activeGenerationId, first.active.activeGenerationId);
    assert.equal(generationIds(env).length, 1);
    const prepared = planPayload(env, 'ensure-conflict');
    await assert.rejects(() => env.authority.ensure({ ...prepared.payload, declaredEffects: [] }, prepared.context), code('release_credential_bootstrap_invalid_request'));
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});

test('successful rotation independently issues a new generation and retires predecessor only after verification', async () => {
  const env = environment();
  try {
    const first = await ensure(env, 'ensure-rotate');
    const oldId = first.active.activeGenerationId;
    const rotated = await rotate(env, 'rotate-success', oldId);
    const newId = rotated.active.activeGenerationId;
    assert.notEqual(newId, oldId);
    assert.equal(rotated.priorRemainedActiveUntilVerification, true);
    assert.equal(env.store.getRecord('ServiceCredentialGenerationV1', oldId).state, 'RETIRED');
    assert.equal(env.store.getRecord('ServiceCredentialGenerationV1', newId).state, 'ACTIVE');
    assert.equal(env.store.getRecord('ServiceCredentialGenerationV1', newId).predecessorGenerationId, oldId);
    assert.equal(env.store.getRecord('ServiceCredentialGenerationV1', oldId).successorGenerationId, newId);
    assert.equal(generationIds(env).length, 2);
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});

test('rotation failure before verification leaves prior generation authoritative and active', async () => {
  let armed = false;
  const env = environment({ issuerFault(stage) { if (armed && stage === 'after_proof_private_write') throw new Error('rotation-failure-before-verification'); } });
  try {
    const first = await ensure(env, 'ensure-before-failed-rotation');
    const oldId = first.active.activeGenerationId;
    armed = true;
    await assert.rejects(() => rotate(env, 'rotate-failure', oldId), /rotation-failure-before-verification/u);
    assert.equal(env.authority.active().activeGenerationId, oldId);
    assert.equal(env.store.getRecord('ServiceCredentialGenerationV1', oldId).state, 'ACTIVE');
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});

test('rollback switches to prior verified generation without regeneration', async () => {
  const env = environment();
  try {
    const first = await ensure(env, 'ensure-rollback'); const oldId = first.active.activeGenerationId;
    const rotated = await rotate(env, 'rotate-before-rollback', oldId); const newId = rotated.active.activeGenerationId;
    const before = generationIds(env);
    const activeBeforeRollback = env.authority.active();
    const rolled = env.authority.rollback({ profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID, targetGenerationId: oldId, expectedSequence: activeBeforeRollback.sequence, reason: 'verified rollback' }, context('rollback-a'));
    assert.equal(rolled.active.activeGenerationId, oldId);
    assert.equal(rolled.rolledBackFromGenerationId, newId);
    assert.equal(rolled.regenerated, false);
    assert.deepEqual(generationIds(env), before);
    assert.equal(env.store.getRecord('ServiceCredentialGenerationV1', newId).state, 'RETIRED');
    assert.equal(env.store.getRecord('ServiceCredentialGenerationV1', oldId).state, 'ACTIVE');
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});

test('revocation is explicit, evidence-preserving, idempotent, and forbidden for active generation', async () => {
  const env = environment();
  try {
    const first = await ensure(env, 'ensure-revoke'); const oldId = first.active.activeGenerationId;
    const activeGeneration = env.store.getRecord('ServiceCredentialGenerationV1', oldId);
    await assert.rejects(async () => env.authority.revoke({ generationId: oldId, expectedSequence: activeGeneration.sequence, reason: 'active cannot be revoked' }, context('revoke-active')), code('release_credential_bootstrap_invalid_state'));
    const rotated = await rotate(env, 'rotate-before-revoke', oldId);
    const oldBeforeRevocation = env.store.getRecord('ServiceCredentialGenerationV1', oldId);
    const revoked = env.authority.revoke({ generationId: oldId, expectedSequence: oldBeforeRevocation.sequence, reason: 'superseded after verified rotation' }, context('revoke-old'));
    assert.equal(revoked.state, 'REVOKED'); assert.equal(revoked.evidencePreserved, true); assert.equal(revoked.privateMaterialDestroyed, false);
    const replay = env.authority.revoke({ generationId: oldId, expectedSequence: oldBeforeRevocation.sequence, reason: 'superseded after verified rotation' }, context('revoke-old'));
    assert.equal(replay.replayed, true);
    assert.equal(env.authority.active().activeGenerationId, rotated.active.activeGenerationId);
    assert.throws(() => env.authority.verify({ generationId: oldId }), code('release_credential_bootstrap_revoked'));
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});

test('lost activation response after profile switch recovers by readback and finalizes predecessor retirement', async () => {
  const env = environment();
  try {
    const first = await ensure(env, 'ensure-response-loss'); const oldId = first.active.activeGenerationId;
    const prepared = planPayload(env, 'prepare-second', oldId);
    const transaction = env.bootstrap.requestBootstrap({ ownerPrincipal: OWNER, idempotencyKey: prepared.context.idempotencyKey, profileId: prepared.payload.profileId, expectedCompatibilityIdentity: prepared.payload.expectedCompatibilityIdentity, policyDecision: POLICY, rotationPredecessorGenerationId: oldId });
    const issued = await env.issuer.issueWithAuthoritativeAccountLookup({ transactionId: transaction.transactionId, ownerPrincipal: OWNER, expectedSequence: transaction.sequence, idempotencyKey: transaction.idempotencyKey, ordinal: 2 }, lookup);
    const newId = issued.transaction.generationId;
    let writes = 0;
    const faultyStore = new ReleaseApplianceStore(env.state, { faultInjector(stage) { if (stage === 'after_record_write') { writes += 1; if (writes === 2) throw new Error('lost-after-profile-switch'); } } });
    const faultyBootstrap = new ServiceCredentialBootstrapService({ store: faultyStore, now: env.now, controllerIdentity: controller('fault'), leaseTtlMs: 10_000 });
    const faultyActivation = new ServiceCredentialActivationService({ store: faultyStore, bootstrap: faultyBootstrap, issuer: env.issuer, privateRoots: [env.privateRoot], publicRoots: [env.publicRoot], privateOwnerUid: env.uid, privateOwnerGid: env.gid, publicOwnerUid: env.uid, publicOwnerGid: env.gid, now: env.now });
    assert.throws(() => faultyActivation.activateGeneration(newId, OWNER), /lost-after-profile-switch/u);
    const recoveredStore = new ReleaseApplianceStore(env.state); recoveredStore.startupScan();
    const recoveredBootstrap = new ServiceCredentialBootstrapService({ store: recoveredStore, now: env.now, controllerIdentity: controller('recovered'), leaseTtlMs: 10_000 });
    const recovered = new ServiceCredentialActivationService({ store: recoveredStore, bootstrap: recoveredBootstrap, issuer: env.issuer, privateRoots: [env.privateRoot], publicRoots: [env.publicRoot], privateOwnerUid: env.uid, privateOwnerGid: env.gid, publicOwnerUid: env.uid, publicOwnerGid: env.gid, now: env.now });
    const replay = recovered.activateGeneration(newId, OWNER);
    assert.equal(replay.replayed, true);
    assert.equal(recovered.active().activeGenerationId, newId);
    assert.equal(recoveredStore.getRecord('ServiceCredentialGenerationV1', oldId).state, 'RETIRED');
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});

test('materialization dry-run has zero filesystem effects and exact plan readback', async () => {
  const env = environment();
  try {
    const first = await ensure(env, 'ensure-plan'); const generationId = first.active.activeGenerationId;
    const target = join(env.base, 'not-created-by-plan');
    const plan = env.authority.materializationPlan(generationId, target);
    assert.equal(existsSync(target), false);
    const dry = env.authority.activation.materialize(plan, true);
    assert.equal(dry.filesystemEffects, false); assert.equal(existsSync(target), false);
    assert.equal(plan.files.length, 4);
    assert.equal(plan.planDigest, sha256(canonicalize(Object.fromEntries(Object.entries(plan).filter(([key]) => key !== 'planDigest')))));
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});

test('materialization writes exact public metadata and systemd path bindings without private bytes', async () => {
  const env = environment();
  try {
    const first = await ensure(env, 'ensure-materialize'); const generationId = first.active.activeGenerationId;
    const target = join(env.base, 'install-root'); const plan = env.authority.materializationPlan(generationId, target);
    const applied = env.authority.activation.materialize(plan, false);
    assert.equal(applied.applied, true); assert.equal(applied.readbackVerified, true); assert.equal(applied.temporaryMaterialAbsent, true);
    const metadataPath = join(target, 'etc/baby-x/credential-generation.json');
    const proofPublicPath = join(target, 'etc/baby-x/proof-public.pem');
    const controllerDropIn = readFileSync(join(target, 'etc/systemd/system/baby-x.service.d/20-service-credentials.conf'), 'utf8');
    const gatewayDropIn = readFileSync(join(target, 'etc/systemd/system/baby-x-gateway.service.d/20-service-credentials.conf'), 'utf8');
    assert.equal(lstatSync(metadataPath).mode & 0o777, 0o640); assert.equal(lstatSync(proofPublicPath).mode & 0o777, 0o640);
    assert.match(controllerDropIn, /LoadCredential=baby-x-proof-private:/u); assert.match(controllerDropIn, /BABY_X_PROOF_PRIVATE_KEY=%d\/baby-x-proof-private/u);
    assert.match(gatewayDropIn, /LoadCredential=baby-x-gateway-authority-private:/u); assert.match(gatewayDropIn, /BABY_X_GATEWAY_PRIVATE_KEY=%d\/baby-x-gateway-authority-private/u);
    assert.match(gatewayDropIn, /BABY_X_GATEWAY_UID=997/u);
    const installedText = [readFileSync(metadataPath, 'utf8'), controllerDropIn, gatewayDropIn].join('\n');
    assert.doesNotMatch(installedText, /-----BEGIN PRIVATE KEY-----/u);
    assert.equal(JSON.parse(readFileSync(metadataPath, 'utf8')).rawPrivateMaterialIncluded, false);
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});

test('credential paths survive simulated launcher restart boundaries and remain cryptographically usable', async () => {
  const env = environment();
  try {
    const first = await ensure(env, 'ensure-restart'); const generationId = first.active.activeGenerationId;
    const plan = env.authority.materializationPlan(generationId, join(env.base, 'restart-root'));
    const controllerDropIn = Buffer.from(plan.files.find((entry) => entry.relativePath.includes('baby-x.service.d')).bytesBase64, 'base64').toString('utf8');
    const gatewayDropIn = Buffer.from(plan.files.find((entry) => entry.relativePath.includes('baby-x-gateway.service.d')).bytesBase64, 'base64').toString('utf8');
    const proofSource = controllerDropIn.match(/LoadCredential=baby-x-proof-private:(.+)/u)[1].trim();
    const gatewaySource = gatewayDropIn.match(/LoadCredential=baby-x-gateway-authority-private:(.+)/u)[1].trim();
    const proofPublic = createPublicKey(readFileSync(env.store.getRecord('ServiceCredentialGenerationV1', generationId).publicMaterials[0].path));
    for (const restart of [1, 2]) {
      const credentials = join(env.base, `run-credentials-${restart}`); mkdirSync(credentials, { mode: 0o700 });
      const proofRuntime = join(credentials, 'baby-x-proof-private'); const gatewayRuntime = join(credentials, 'baby-x-gateway-authority-private');
      copyFileSync(proofSource, proofRuntime); copyFileSync(gatewaySource, gatewayRuntime); chmodSync(proofRuntime, 0o400); chmodSync(gatewayRuntime, 0o400);
      const message = randomBytes(32); const signature = sign(null, message, createPrivateKey(readFileSync(proofRuntime)));
      assert.equal(verify(null, message, proofPublic, signature), true); signature.fill(0); message.fill(0);
      assert.equal(createPrivateKey(readFileSync(gatewayRuntime)).asymmetricKeyType, 'ed25519');
    }
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});

test('wrong UID, wrong mode, and public/private mismatch fail verification and activation', async () => {
  for (const scenario of ['uid', 'mode', 'mismatch']) {
    const env = environment();
    try {
      const first = await ensure(env, `ensure-${scenario}`); const generationId = first.active.activeGenerationId;
      const generation = env.store.getRecord('ServiceCredentialGenerationV1', generationId);
      if (scenario === 'uid') {
        env.store.applyMutation({ schemaId: 'ServiceCredentialGenerationV1', recordId: generationId, ownerPrincipal: OWNER, expectedSequence: generation.sequence, idempotencyKey: `mutate-${scenario}`, requestDigest: sha256(scenario), operation: 'test', phase: 'tamper', record: { ...generation, serviceIdentityBinding: { ...generation.serviceIdentityBinding, observedUid: 998 }, sequence: generation.sequence + 1, updatedAt: env.now() }, occurredAt: env.now() });
      } else if (scenario === 'mode') {
        const reference = env.store.getRecord('CredentialSetReferenceV1', generation.privateReferences[0].credentialSetId); chmodSync(reference.entries[0].sourceRef, 0o644);
      } else {
        const other = await ensure(env, `other-${scenario}`); const otherGeneration = env.store.getRecord('ServiceCredentialGenerationV1', other.active.activeGenerationId); writeFileSync(generation.publicMaterials[0].path, readFileSync(otherGeneration.publicMaterials[0].path)); chmodSync(generation.publicMaterials[0].path, 0o640);
      }
      assert.throws(() => env.authority.verify({ generationId }), (error) => error instanceof ServiceCredentialActivationError);
    } finally { rmSync(env.base, { recursive: true, force: true }); }
  }
});

test('installer rejects inactive, revoked, incompatible, and production-root generations', async () => {
  const env = environment();
  try {
    const first = await ensure(env, 'ensure-installer-reject'); const oldId = first.active.activeGenerationId;
    const rotated = await rotate(env, 'rotate-installer-reject', oldId); const activeId = rotated.active.activeGenerationId;
    assert.throws(() => env.authority.materializationPlan(oldId, join(env.base, 'inactive')), code('release_credential_bootstrap_invalid_state'));
    const oldForRevocation = env.store.getRecord('ServiceCredentialGenerationV1', oldId);
    env.authority.revoke({ generationId: oldId, expectedSequence: oldForRevocation.sequence, reason: 'superseded' }, context('revoke-for-installer'));
    assert.throws(() => env.authority.verify({ generationId: oldId }), code('release_credential_bootstrap_revoked'));
    const plan = env.authority.materializationPlan(activeId, '/etc/baby-x');
    assert.throws(() => env.authority.activation.materialize(plan, true), code('release_credential_bootstrap_materialization_failed'));
    assert.equal(existsSync('/etc/baby-x'), false);
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});

test('temporary cleanup removes only safe temp objects and positively verifies absence', async () => {
  const env = environment();
  try {
    await ensure(env, 'ensure-clean');
    const temp = findFile(env.privateRoot, 'gateway-authority-private.pem');
    const stale = join(dirname(temp), '.stale.tmp-recovery'); writeFileSync(stale, 'stale', { mode: 0o400 });
    const result = env.authority.clean();
    assert.equal(result.removedCount, 1); assert.equal(result.temporaryMaterialAbsent, true); assert.equal(existsSync(stale), false);
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});

test('public authority surfaces remain bounded and contain no private key material', async () => {
  const env = environment();
  try {
    const first = await ensure(env, 'ensure-public-surfaces');
    const values = [env.authority.describe(), env.authority.profiles(), env.authority.compatibility(), env.authority.active(), env.authority.verify({ generationId: first.active.activeGenerationId })];
    for (const value of values) assert.doesNotMatch(JSON.stringify(value), /-----BEGIN PRIVATE KEY-----/u);
    assert.equal(env.authority.describe().activation.atomicSourceOfTruth, 'ServiceCredentialProfileStateV1');
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});


test('unified Baby-X runtime operation surface executes rotation, rollback, revocation, reconciliation, and cleanup', async () => {
  const env = environment();
  try {
    const runtime = new BabyXRuntime({ stateRoot: join(env.base, 'runtime'), serviceCredentialAuthority: env.authority });
    const basePayload = { profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID, expectedCompatibilityIdentity: serviceCredentialCompatibilityDigest(), policyDecision: POLICY };
    const ensureContext = { subject: OWNER, idempotencyKey: 'runtime-unified-ensure' };
    const ensurePlan = await runtime.execute('babyx.release.credential-bootstrap.plan', basePayload, ensureContext);
    const ensured = await runtime.execute('babyx.release.credential-bootstrap.ensure', { ...basePayload, declaredEffects: ensurePlan.declaredEffects }, ensureContext);
    const firstId = ensured.active.activeGenerationId;
    const activeFirst = await runtime.execute('babyx.release.credential-bootstrap.active', { profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID });
    assert.equal(activeFirst.activeGenerationId, firstId);
    const verified = await runtime.execute('babyx.release.credential-bootstrap.verify', { generationId: firstId });
    assert.equal(verified.publicOnly, true);

    const rotateContext = { subject: OWNER, idempotencyKey: 'runtime-unified-rotate' };
    const rotationBase = { ...basePayload, rotationPredecessorGenerationId: firstId };
    const rotatePlan = await runtime.execute('babyx.release.credential-bootstrap.plan', rotationBase, rotateContext);
    const rotated = await runtime.execute('babyx.release.credential-bootstrap.rotate', { ...rotationBase, declaredEffects: rotatePlan.declaredEffects }, rotateContext);
    const secondId = rotated.active.activeGenerationId;
    assert.notEqual(secondId, firstId);

    const reconciled = await runtime.execute('babyx.release.credential-bootstrap.reconcile', {
      transactionId: rotated.transaction.transactionId,
      expectedSequence: rotated.transaction.sequence,
    }, { subject: OWNER, idempotencyKey: 'runtime-unified-reconcile' });
    assert.equal(reconciled.transactionId, rotated.transaction.transactionId);

    const activeBeforeRollback = env.authority.active();
    const rolled = await runtime.execute('babyx.release.credential-bootstrap.rollback', {
      profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
      targetGenerationId: firstId,
      expectedSequence: activeBeforeRollback.sequence,
      reason: 'runtime operation rollback test',
    }, { subject: OWNER, idempotencyKey: 'runtime-unified-rollback' });
    assert.equal(rolled.active.activeGenerationId, firstId);
    assert.equal(rolled.regenerated, false);

    const second = env.store.getRecord('ServiceCredentialGenerationV1', secondId);
    const revoked = await runtime.execute('babyx.release.credential-bootstrap.revoke', {
      generationId: secondId,
      expectedSequence: second.sequence,
      reason: 'retired generation no longer needed',
    }, { subject: OWNER, idempotencyKey: 'runtime-unified-revoke' });
    assert.equal(revoked.state, 'REVOKED');
    assert.equal(revoked.evidencePreserved, true);

    const transaction = env.authority.get({ transactionId: ensured.transaction.transactionId });
    const cleaned = await runtime.execute('babyx.release.credential-bootstrap.clean', {
      transactionId: transaction.transactionId,
      expectedSequence: transaction.sequence,
    }, { subject: OWNER, idempotencyKey: 'runtime-unified-clean' });
    assert.equal(cleaned.temporaryMaterialAbsent, true);
    assert.doesNotMatch(JSON.stringify({ ensured, rotated, reconciled, rolled, revoked, cleaned }), /-----BEGIN PRIVATE KEY-----/u);
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});


test('repository installer consumes only an exact verified staged credential generation under isolated roots', async () => {
  const env = environment();
  try {
    const first = await ensure(env, 'ensure-isolated-installer');
    const generationId = first.active.activeGenerationId;
    const bindingRoot = join(env.base, 'credential-bindings');
    const materialized = env.authority.activation.materialize(env.authority.materializationPlan(generationId, bindingRoot), false);
    assert.equal(materialized.readbackVerified, true);
    const installRoot = join(env.base, 'opt-baby-x');
    const systemdRoot = join(env.base, 'systemd');
    const configRoot = join(env.base, 'config');
    const tmpfilesRoot = join(env.base, 'tmpfiles');
    const libexecRoot = join(env.base, 'libexec');
    const result = spawnSync('bash', ['scripts/install-local.sh'], {
      cwd: process.cwd(), encoding: 'utf8',
      env: {
        ...process.env,
        BABY_X_RELEASE_ID: 'k5d-isolated-release',
        BABY_X_INSTALL_ROOT: installRoot,
        BABY_X_INSTALL_UNITS: '1',
        BABY_X_CREDENTIAL_GENERATION_ID: generationId,
        BABY_X_CREDENTIAL_BINDING_ROOT: bindingRoot,
        BABY_X_SYSTEMD_ROOT: systemdRoot,
        BABY_X_CONFIG_ROOT: configRoot,
        BABY_X_TMPFILES_ROOT: tmpfilesRoot,
        BABY_X_LIBEXEC_ROOT: libexecRoot,
        BABY_X_INSTALL_OWNER: String(process.getuid()),
        BABY_X_INSTALL_GROUP: String(process.getgid()),
        BABY_X_SKIP_SYSTEMD: '1',
      },
    });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    const metadata = JSON.parse(readFileSync(join(configRoot, 'credential-generation.json'), 'utf8'));
    assert.equal(metadata.generationId, generationId);
    assert.equal(metadata.rawPrivateMaterialIncluded, false);
    assert.equal(lstatSync(join(configRoot, 'credential-generation.json')).mode & 0o777, 0o640);
    assert.equal(lstatSync(join(configRoot, 'proof-public.pem')).mode & 0o777, 0o640);
    const controllerBinding = readFileSync(join(systemdRoot, 'baby-x.service.d/20-service-credentials.conf'), 'utf8');
    const gatewayBinding = readFileSync(join(systemdRoot, 'baby-x-gateway.service.d/20-service-credentials.conf'), 'utf8');
    assert.match(controllerBinding, /LoadCredential=baby-x-proof-private:/u);
    assert.match(gatewayBinding, /LoadCredential=baby-x-gateway-authority-private:/u);
    assert.doesNotMatch(`${JSON.stringify(metadata)}\n${controllerBinding}\n${gatewayBinding}`, /-----BEGIN PRIVATE KEY-----/u);
    assert.equal(existsSync('/etc/baby-x'), false);
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});

test('repository installer rejects missing or mismatched credential-generation identity before release installation', async () => {
  const base = root();
  try {
    const installRoot = join(base, 'install');
    const missing = spawnSync('bash', ['scripts/install-local.sh'], { cwd: process.cwd(), encoding: 'utf8', env: { ...process.env, BABY_X_RELEASE_ID: 'missing-generation', BABY_X_INSTALL_ROOT: installRoot, BABY_X_INSTALL_UNITS: '1' } });
    assert.notEqual(missing.status, 0);
    assert.equal(existsSync(join(installRoot, 'releases', 'missing-generation')), false);

    const env = environment();
    try {
      const first = await ensure(env, 'ensure-mismatch-installer');
      const generationId = first.active.activeGenerationId;
      const bindingRoot = join(env.base, 'bindings');
      env.authority.activation.materialize(env.authority.materializationPlan(generationId, bindingRoot), false);
      const mismatchRoot = join(base, 'mismatch-install');
      const mismatch = spawnSync('bash', ['scripts/install-local.sh'], {
        cwd: process.cwd(), encoding: 'utf8',
        env: { ...process.env, BABY_X_RELEASE_ID: 'mismatch-generation', BABY_X_INSTALL_ROOT: mismatchRoot, BABY_X_INSTALL_UNITS: '1', BABY_X_CREDENTIAL_GENERATION_ID: 'scg-wrong-generation', BABY_X_CREDENTIAL_BINDING_ROOT: bindingRoot, BABY_X_SKIP_SYSTEMD: '1' },
      });
      assert.notEqual(mismatch.status, 0);
      assert.equal(existsSync(join(mismatchRoot, 'releases', 'mismatch-generation')), false);
    } finally { rmSync(env.base, { recursive: true, force: true }); }
  } finally { rmSync(base, { recursive: true, force: true }); }
});

test('base systemd assets fail closed on missing credential metadata and contain no optional environment-file bypass', () => {
  const controller = readFileSync('ops/systemd/baby-x.service', 'utf8');
  const gateway = readFileSync('ops/systemd/baby-x-gateway.service', 'utf8');
  assert.match(controller, /ConditionPathExists=\/etc\/baby-x\/credential-generation\.json/u);
  assert.match(controller, /ExecStartPre=\/usr\/bin\/test -r \/etc\/baby-x\/credential-generation\.json/u);
  assert.match(gateway, /ConditionPathExists=\/etc\/baby-x\/proof-public\.pem/u);
  assert.match(gateway, /User=fix-mcp/u);
  assert.doesNotMatch(controller, /EnvironmentFile=/u);
  assert.doesNotMatch(gateway, /EnvironmentFile=/u);
  assert.doesNotMatch(`${controller}\n${gateway}`, /BEGIN PRIVATE KEY/u);
});


test('stale rollback and revocation sequences fail before lifecycle mutation', async () => {
  const env = environment();
  try {
    const first = await ensure(env, 'ensure-sequence-guard');
    const oldId = first.active.activeGenerationId;
    const rotated = await rotate(env, 'rotate-sequence-guard', oldId);
    const newId = rotated.active.activeGenerationId;
    const profileBefore = env.authority.active();
    assert.throws(() => env.authority.rollback({
      profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
      targetGenerationId: oldId,
      expectedSequence: Number(profileBefore.sequence) - 1,
      reason: 'stale rollback must fail',
    }, context('rollback-stale-sequence')), code('release_credential_bootstrap_sequence_conflict'));
    assert.equal(env.authority.active().activeGenerationId, newId);

    const oldBefore = env.store.getRecord('ServiceCredentialGenerationV1', oldId);
    assert.throws(() => env.authority.revoke({
      generationId: oldId,
      expectedSequence: Number(oldBefore.sequence) - 1,
      reason: 'stale revocation must fail',
    }, context('revoke-stale-sequence')), code('release_credential_bootstrap_sequence_conflict'));
    assert.equal(env.store.getRecord('ServiceCredentialGenerationV1', oldId).state, oldBefore.state);
  } finally { rmSync(env.base, { recursive: true, force: true }); }
});
