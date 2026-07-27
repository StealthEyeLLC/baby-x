import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
  BabyXRuntime,
  ReleaseApplianceStore,
  ServiceCredentialBootstrapService,
  ServiceCredentialFilesystemAuthority,
  ServiceCredentialIssuanceError,
  parseGetentPasswd,
  serviceCredentialCompatibilityDigest,
  sha256,
  validateServiceIdentityObservation,
} from '../../dist/runtime/index.js';

const OWNER = 'stealtheye-owner';
const POLICY_DIGEST = 'a'.repeat(64);

function scratch() { return mkdtempSync(join(tmpdir(), 'baby-x-k5-issuer-')); }
function clock(start = Date.parse('2026-07-27T08:00:00.000Z')) {
  let value = start;
  return () => { const result = new Date(value).toISOString(); value += 1_000; return result; };
}
function controller() { return { pid: 7001, processStartTime: '52000001', executablePath: '/opt/baby-x/controller', bootId: 'boot-k5c' }; }
function identity(overrides = {}) {
  return {
    accountName: 'fix-mcp', observedUid: 997, observedGid: 986, reverseUidAccountName: 'fix-mcp',
    lookupSource: 'durable-job:getent', verifiedAt: '2026-07-27T08:00:00.000Z', ...overrides,
  };
}
function request(overrides = {}) {
  return {
    ownerPrincipal: OWNER,
    idempotencyKey: 'k5c-bootstrap-a',
    profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
    expectedCompatibilityIdentity: serviceCredentialCompatibilityDigest(),
    policyDecision: { decision: 'ALLOW', decisionDigest: POLICY_DIGEST, policyIdentity: 'k5-service-credential-policy', environmentClass: 'production-controller', reasonCodes: ['CHECKPOINT_K5_AUTHORIZED'] },
    ...overrides,
  };
}
function fixture(options = {}) {
  const root = scratch();
  const now = options.now ?? clock();
  const store = new ReleaseApplianceStore(join(root, 'state'));
  const bootstrap = new ServiceCredentialBootstrapService({ store, now, controllerIdentity: controller(), leaseTtlMs: 10_000 });
  const transaction = bootstrap.requestBootstrap(request(options.request));
  const authority = new ServiceCredentialFilesystemAuthority({
    store, bootstrap,
    privateRoot: join(root, 'credential-authority'),
    publicRoot: join(root, 'public-material'),
    privateOwnerUid: process.getuid(), privateOwnerGid: process.getgid(),
    publicOwnerUid: process.getuid(), publicOwnerGid: process.getgid(),
    now,
    faultInjector: options.faultInjector,
  });
  return { root, store, bootstrap, transaction, authority, close() { rmSync(root, { recursive: true, force: true }); } };
}
function issue(fx, overrides = {}) {
  return fx.authority.issue({
    transactionId: fx.transaction.transactionId,
    ownerPrincipal: OWNER,
    expectedSequence: fx.transaction.sequence,
    idempotencyKey: fx.transaction.idempotencyKey,
    identityObservation: identity(),
    ...overrides,
  });
}
function code(expected) {
  return (error) => error instanceof ServiceCredentialIssuanceError && error.code === expected;
}
function generationDirectory(fx) { return join(fx.root, 'credential-authority', 'generations', fx.transaction.generationId); }
function publicDirectory(fx) { return join(fx.root, 'public-material', 'generations', fx.transaction.generationId); }


test('successful first issuance reaches READY with opaque references and public fingerprints only', () => {
  const fx = fixture();
  try {
    const result = issue(fx);
    assert.equal(result.transaction.state, 'READY');
    assert.equal(result.generation.state, 'READY');
    assert.equal(result.rawPrivateMaterialReturned, false);
    assert.equal(result.generation.publicFingerprints.length, 2);
    assert.doesNotMatch(JSON.stringify(result), /BEGIN PRIVATE KEY/u);
    assert.equal(lstatSync(join(generationDirectory(fx), 'gateway-authority-private.pem')).mode & 0o777, 0o400);
    assert.equal(lstatSync(join(generationDirectory(fx), 'proof-private.pem')).mode & 0o777, 0o400);
    assert.equal(lstatSync(join(publicDirectory(fx), 'proof-public.pem')).mode & 0o777, 0o640);
    assert.equal(readdirSync(generationDirectory(fx)).some((name) => name.includes('.tmp-')), false);
  } finally { fx.close(); }
});

test('proof private and public material form a valid Ed25519 signing relationship', () => {
  const fx = fixture();
  try {
    issue(fx);
    const privateKey = createPrivateKey(readFileSync(join(generationDirectory(fx), 'proof-private.pem')));
    const publicKey = createPublicKey(readFileSync(join(publicDirectory(fx), 'proof-public.pem')));
    assert.equal(privateKey.asymmetricKeyType, 'ed25519');
    assert.equal(publicKey.asymmetricKeyType, 'ed25519');
    const message = Buffer.from('checkpoint-k5-proof-relationship');
    const signature = sign(null, message, privateKey);
    assert.equal(verify(null, message, publicKey, signature), true);
  } finally { fx.close(); }
});

test('idempotent replay returns the same durable generation without new key material', () => {
  const fx = fixture();
  try {
    const first = issue(fx);
    const gatewayPath = join(generationDirectory(fx), 'gateway-authority-private.pem');
    const proofPath = join(generationDirectory(fx), 'proof-private.pem');
    const before = [sha256(readFileSync(gatewayPath)), sha256(readFileSync(proofPath))];
    const replay = issue(fx);
    assert.equal(replay.replayed, true);
    assert.equal(replay.generation.generationId, first.generation.generationId);
    assert.deepEqual([sha256(readFileSync(gatewayPath)), sha256(readFileSync(proofPath))], before);
  } finally { fx.close(); }
});

test('conflicting idempotency identity fails closed', () => {
  const fx = fixture();
  try {
    assert.throws(() => issue(fx, { idempotencyKey: 'different-idempotency-key' }), code('release_idempotency_conflict'));
    assert.equal(existsSync(generationDirectory(fx)), false);
  } finally { fx.close(); }
});

test('wrong owner principal fails before credential effects', () => {
  const fx = fixture();
  try {
    assert.throws(() => issue(fx, { ownerPrincipal: 'wrong-owner' }), code('release_credential_bootstrap_identity_mismatch'));
    assert.equal(existsSync(generationDirectory(fx)), false);
  } finally { fx.close(); }
});

test('lost response after gateway private write recovers the same key and completes once', () => {
  let crash = true;
  const fx = fixture({ faultInjector(stage) { if (stage === 'after_gateway_private_write' && crash) { crash = false; throw new Error('lost after gateway private write'); } } });
  try {
    assert.throws(() => issue(fx), /lost after gateway private write/u);
    const gatewayPath = join(generationDirectory(fx), 'gateway-authority-private.pem');
    const digest = sha256(readFileSync(gatewayPath));
    const recovered = issue(fx);
    assert.equal(recovered.transaction.state, 'READY');
    assert.equal(sha256(readFileSync(gatewayPath)), digest);
  } finally { fx.close(); }
});

test('lost response after public material write recovers without duplicate generation', () => {
  let crash = true;
  const fx = fixture({ faultInjector(stage) { if (stage === 'after_public_write' && crash) { crash = false; throw new Error('lost after public write'); } } });
  try {
    assert.throws(() => issue(fx), /lost after public write/u);
    const publicPath = join(publicDirectory(fx), 'proof-public.pem');
    const digest = sha256(readFileSync(publicPath));
    const recovered = issue(fx);
    assert.equal(recovered.transaction.state, 'READY');
    assert.equal(sha256(readFileSync(publicPath)), digest);
  } finally { fx.close(); }
});

test('lost response after private reference persistence adopts the durable reference', () => {
  let crash = true;
  const fx = fixture({ faultInjector(stage) { if (stage === 'after_reference_persist' && crash) { crash = false; throw new Error('lost after reference persistence'); } } });
  try {
    assert.throws(() => issue(fx), /lost after reference persistence/u);
    const referencesBefore = fx.store.listRecordIdentities().filter((entry) => entry.schemaId === 'CredentialSetReferenceV1');
    assert.equal(referencesBefore.length, 1);
    const recovered = issue(fx);
    assert.equal(recovered.transaction.state, 'READY');
    assert.equal(fx.store.listRecordIdentities().filter((entry) => entry.schemaId === 'CredentialSetReferenceV1').length, 1);
  } finally { fx.close(); }
});

test('lost response after generation persistence is recovered by durable readback', () => {
  let crash = true;
  const fx = fixture({ faultInjector(stage) { if (stage === 'after_generation_persist' && crash) { crash = false; throw new Error('lost after generation persistence'); } } });
  try {
    assert.throws(() => issue(fx), /lost after generation persistence/u);
    assert.equal(fx.store.hasRecord('ServiceCredentialGenerationV1', fx.transaction.generationId), true);
    const recovered = issue(fx);
    assert.equal(recovered.transaction.state, 'READY');
    assert.equal(recovered.generation.generationId, fx.transaction.generationId);
  } finally { fx.close(); }
});

test('strict service identity accepts only fix-mcp UID 997 and unique reverse lookup', () => {
  const validated = validateServiceIdentityObservation(identity());
  assert.equal(validated.accountName, 'fix-mcp');
  assert.equal(validated.observedUid, 997);
  assert.equal(validated.reverseUidAccountName, 'fix-mcp');
  assert.match(validated.bindingDigest, /^[a-f0-9]{64}$/u);
  assert.throws(() => validateServiceIdentityObservation(identity({ accountName: 'root' })), code('release_credential_bootstrap_identity_mismatch'));
  assert.throws(() => validateServiceIdentityObservation(identity({ observedUid: 998 })), code('release_credential_bootstrap_identity_mismatch'));
  assert.throws(() => validateServiceIdentityObservation(identity({ reverseUidAccountName: 'replacement-account' })), code('release_credential_bootstrap_identity_mismatch'));
});

test('authoritative passwd parsing rejects malformed, wrong-principal, and invalid UID observations', () => {
  assert.deepEqual(parseGetentPasswd('fix-mcp:x:997:986::/var/lib/fix-mcp:/usr/sbin/nologin\n', 'fix-mcp'), {
    accountName: 'fix-mcp', uid: 997, gid: 986, home: '/var/lib/fix-mcp', shell: '/usr/sbin/nologin',
  });
  assert.throws(() => parseGetentPasswd('', 'fix-mcp'), code('release_credential_bootstrap_identity_mismatch'));
  assert.throws(() => parseGetentPasswd('root:x:0:0:root:/root:/bin/bash', 'fix-mcp'), code('release_credential_bootstrap_identity_mismatch'));
  assert.throws(() => parseGetentPasswd('fix-mcp:x:not-a-uid:986::/var/lib/fix-mcp:/usr/sbin/nologin', 'fix-mcp'), code('release_credential_bootstrap_identity_mismatch'));
});

test('malformed preexisting private PEM fails closed and is not overwritten', () => {
  const fx = fixture();
  try {
    mkdirSync(generationDirectory(fx), { recursive: true, mode: 0o700 });
    const path = join(generationDirectory(fx), 'gateway-authority-private.pem');
    writeFileSync(path, 'not-a-private-key\n', { mode: 0o400 });
    chmodSync(path, 0o400);
    assert.throws(() => issue(fx), code('release_credential_bootstrap_verification_failed'));
    assert.equal(readFileSync(path, 'utf8'), 'not-a-private-key\n');
  } finally { fx.close(); }
});

test('preexisting private credential with permissive mode fails closed', () => {
  const fx = fixture();
  try {
    mkdirSync(generationDirectory(fx), { recursive: true, mode: 0o700 });
    const pair = generateKeyPairSync('ed25519');
    const path = join(generationDirectory(fx), 'gateway-authority-private.pem');
    writeFileSync(path, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o644 });
    chmodSync(path, 0o644);
    assert.throws(() => issue(fx), code('release_credential_bootstrap_materialization_failed'));
  } finally { fx.close(); }
});

test('unsafe symlink parent is rejected before private material is written', () => {
  const fx = fixture();
  try {
    const outside = join(fx.root, 'outside');
    mkdirSync(outside, { mode: 0o700 });
    mkdirSync(join(fx.root, 'credential-authority'), { recursive: true, mode: 0o700 });
    symlinkSync(outside, join(fx.root, 'credential-authority', 'generations'));
    assert.throws(() => issue(fx), code('release_credential_bootstrap_materialization_failed'));
    assert.deepEqual(readdirSync(outside), []);
  } finally { fx.close(); }
});

test('hard-linked preexisting credential object is rejected', () => {
  const fx = fixture();
  try {
    mkdirSync(generationDirectory(fx), { recursive: true, mode: 0o700 });
    const pair = generateKeyPairSync('ed25519');
    const path = join(generationDirectory(fx), 'gateway-authority-private.pem');
    writeFileSync(path, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o400 });
    chmodSync(path, 0o400);
    linkSync(path, join(fx.root, 'attacker-hardlink'));
    assert.equal(lstatSync(path).nlink, 2);
    assert.throws(() => issue(fx), code('release_credential_bootstrap_materialization_failed'));
  } finally { fx.close(); }
});

test('conflicting preexisting public material is never overwritten', () => {
  const fx = fixture();
  try {
    mkdirSync(publicDirectory(fx), { recursive: true, mode: 0o700 });
    const other = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
    const path = join(publicDirectory(fx), 'proof-public.pem');
    writeFileSync(path, other, { mode: 0o640 });
    chmodSync(path, 0o640);
    const before = sha256(readFileSync(path));
    assert.throws(() => issue(fx), code('release_credential_bootstrap_materialization_failed'));
    assert.equal(sha256(readFileSync(path)), before);
  } finally { fx.close(); }
});

test('stale temporary credential files are removed and positively absent after issuance', () => {
  const fx = fixture();
  try {
    mkdirSync(generationDirectory(fx), { recursive: true, mode: 0o700 });
    const stale = join(generationDirectory(fx), '.gateway-authority-private.pem.tmp-stale');
    writeFileSync(stale, 'stale', { mode: 0o400 });
    const result = issue(fx);
    assert.equal(result.transaction.state, 'READY');
    assert.equal(existsSync(stale), false);
    assert.equal(readdirSync(generationDirectory(fx)).some((name) => name.includes('.tmp-')), false);
  } finally { fx.close(); }
});

test('production credential roots remain forbidden at K.5 before any path creation', () => {
  const root = scratch();
  try {
    const store = new ReleaseApplianceStore(join(root, 'state'));
    const bootstrap = new ServiceCredentialBootstrapService({ store, now: clock(), controllerIdentity: controller() });
    assert.throws(() => new ServiceCredentialFilesystemAuthority({ store, bootstrap, privateRoot: '/etc/baby-x/private', publicRoot: join(root, 'public') }), code('release_credential_bootstrap_materialization_failed'));
    assert.equal(existsSync('/etc/baby-x'), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('unrelated Quirt authority root is rejected before filesystem access', () => {
  const root = scratch();
  try {
    const store = new ReleaseApplianceStore(join(root, 'state'));
    const bootstrap = new ServiceCredentialBootstrapService({ store, now: clock(), controllerIdentity: controller() });
    assert.throws(() => new ServiceCredentialFilesystemAuthority({ store, bootstrap, privateRoot: '/etc/stealtheye-quirt', publicRoot: join(root, 'public') }), code('release_credential_bootstrap_materialization_failed'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('public transaction, generation, event, and authority results redact private material', () => {
  const fx = fixture();
  try {
    const result = issue(fx);
    const generation = fx.store.getRecord('ServiceCredentialGenerationV1', result.generation.generationId);
    const events = fx.bootstrap.events(fx.transaction.transactionId);
    const exposed = JSON.stringify({ result, generation, events, describe: fx.authority.describe() });
    assert.doesNotMatch(exposed, /BEGIN PRIVATE KEY/u);
    assert.doesNotMatch(exposed, /MC4CAQAwBQYDK2Vw/u);
    assert.equal(exposed.includes('/etc/stealtheye-quirt/authority.key'), true);
    assert.equal(exposed.includes('rawPrivateMaterialReturned":false'), true);
  } finally { fx.close(); }
});


test('unconfigured runtime credential-bootstrap discovery is pure and mutations fail closed', async () => {
  const root = scratch();
  try {
    const runtime = new BabyXRuntime({ stateRoot: join(root, 'runtime') });
    const before = JSON.stringify(readdirSync(join(root, 'runtime'), { recursive: true }).sort());
    const described = await runtime.execute('babyx.release.credential-bootstrap.describe', {});
    const profiles = await runtime.execute('babyx.release.credential-bootstrap.profiles', {});
    const compatibility = await runtime.execute('babyx.release.credential-bootstrap.compatibility', {});
    const listed = await runtime.execute('babyx.release.credential-bootstrap.list', {});
    assert.equal(described.configured, false);
    assert.equal(described.issuer.configured, false);
    assert.equal(profiles.total, 1);
    assert.equal(compatibility.readOnly, true);
    assert.equal(listed.total, 0);
    assert.equal(JSON.stringify(readdirSync(join(root, 'runtime'), { recursive: true }).sort()), before);
    await assert.rejects(runtime.execute('babyx.release.credential-bootstrap.ensure', {
      profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
      expectedCompatibilityIdentity: serviceCredentialCompatibilityDigest(),
      policyDecision: request().policyDecision,
      declaredEffects: [{}],
    }, { subject: OWNER, idempotencyKey: 'unconfigured-ensure' }), (error) => error?.code === 'release_provider_unavailable');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('public Baby-X operation surface plans, ensures, reads, and verifies one generation', async () => {
  const fx = fixture();
  try {
    const lookup = { authority: 'durable-job-authority', async lookup() { return identity({ lookupSource: 'DURABLE_JOB_AUTHORITY_GETENT' }); } };
    const runtime = new BabyXRuntime({
      stateRoot: join(fx.root, 'runtime'),
      serviceCredentialBootstrapService: fx.bootstrap,
      serviceCredentialFilesystemAuthority: fx.authority,
      serviceCredentialAccountLookup: lookup,
    });
    const context = { subject: OWNER, idempotencyKey: 'runtime-k5c-ensure' };
    const planPayload = {
      profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
      expectedCompatibilityIdentity: serviceCredentialCompatibilityDigest(),
      policyDecision: request().policyDecision,
    };
    const plan = await runtime.execute('babyx.release.credential-bootstrap.plan', planPayload, context);
    const ensured = await runtime.execute('babyx.release.credential-bootstrap.ensure', { ...planPayload, declaredEffects: plan.declaredEffects }, context);
    assert.equal(ensured.transaction.state, 'READY');
    assert.equal(ensured.rawPrivateMaterialReturned, false);
    const fetched = await runtime.execute('babyx.release.credential-bootstrap.get', { transactionId: ensured.transaction.transactionId });
    assert.equal(fetched.state, 'READY');
    const events = await runtime.execute('babyx.release.credential-bootstrap.events', { transactionId: ensured.transaction.transactionId, limit: 100 });
    assert.ok(events.events.length >= 8);
    const verification = await runtime.execute('babyx.release.credential-bootstrap.verify', { generationId: ensured.generation.generationId });
    assert.equal(verification.rawPrivateMaterialReturned, false);
    assert.equal(verification.keyRelationships.every((entry) => entry.verified === true), true);
    assert.equal(verification.temporaryMaterialCleanup.positiveAbsenceVerified, true);
    assert.doesNotMatch(JSON.stringify({ ensured, fetched, events, verification }), /BEGIN PRIVATE KEY/u);
  } finally { fx.close(); }
});

test('public ensure rejects declared effects that differ from the immutable plan before durable intent', async () => {
  const fx = fixture();
  try {
    const runtime = new BabyXRuntime({
      stateRoot: join(fx.root, 'runtime'),
      serviceCredentialBootstrapService: fx.bootstrap,
      serviceCredentialFilesystemAuthority: fx.authority,
      serviceCredentialAccountLookup: { authority: 'durable-job-authority', async lookup() { return identity(); } },
    });
    const before = fx.store.listRecordIdentities().length;
    await assert.rejects(runtime.execute('babyx.release.credential-bootstrap.ensure', {
      profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
      expectedCompatibilityIdentity: serviceCredentialCompatibilityDigest(),
      policyDecision: request().policyDecision,
      declaredEffects: [{ authority: 'unapproved-parallel-vault', effect: 'MINT_RAW_SECRET' }],
    }, { subject: OWNER, idempotencyKey: 'runtime-effects-conflict' }), (error) => error?.code === 'release_credential_bootstrap_invalid_request');
    assert.equal(fx.store.listRecordIdentities().length, before);
  } finally { fx.close(); }
});

test('generation verification detects public material corruption without exposing private bytes', () => {
  const fx = fixture();
  try {
    const result = issue(fx);
    const verified = fx.authority.verifyGeneration(result.generation.generationId);
    assert.equal(verified.rawPrivateMaterialReturned, false);
    const publicPath = join(publicDirectory(fx), 'proof-public.pem');
    chmodSync(publicPath, 0o640);
    writeFileSync(publicPath, 'corrupt-public-material\n', { mode: 0o640 });
    assert.throws(() => fx.authority.verifyGeneration(result.generation.generationId), code('release_credential_bootstrap_verification_failed'));
  } finally { fx.close(); }
});
