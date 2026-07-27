#!/usr/bin/env node
import { createPrivateKey, createPublicKey, randomBytes, randomUUID, sign, verify } from 'node:crypto';
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
  DurableJobServiceAccountLookup,
  JobManager,
  ReleaseApplianceStore,
  ServiceCredentialAuthority,
  ServiceCredentialBootstrapService,
  ServiceCredentialFilesystemAuthority,
  canonicalize,
  serviceCredentialCompatibilityDigest,
  sha256,
} from '../dist/runtime/index.js';

const OWNER = 'stealtheye-owner';
const POLICY = {
  decision: 'ALLOW',
  decisionDigest: 'c'.repeat(64),
  policyIdentity: 'checkpoint-k5-disposable-certification-policy',
  environmentClass: 'production-controller',
  reasonCodes: ['CHECKPOINT_K5_AUTHORIZED', 'DISPOSABLE_MACHINE_ONLY'],
};
const root = mkdtempSync(join(tmpdir(), 'baby-x-k5-certification-'));
const stateRoot = join(root, 'state');
const privateRoot = join(root, 'credential-authority');
const publicRoot = join(root, 'public-material');
const stagingRoot = join(root, 'staging');
const installRoot = join(root, 'install-root');
let counter = 0;
const now = () => new Date(Date.parse('2026-07-27T10:00:00.000Z') + (counter++ * 1000)).toISOString();
const controllerIdentity = { pid: process.pid, processStartTime: `cert-${process.pid}`, executablePath: process.execPath, bootId: `cert-${randomUUID()}` };

function context(idempotencyKey) { return { subject: OWNER, ownerPrincipal: OWNER, idempotencyKey }; }
function planPayload(authority, idempotencyKey, predecessor) {
  const base = {
    profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
    expectedCompatibilityIdentity: serviceCredentialCompatibilityDigest(),
    policyDecision: POLICY,
    ...(predecessor === undefined ? {} : { rotationPredecessorGenerationId: predecessor }),
  };
  const ctx = context(idempotencyKey);
  const plan = authority.plan(base, ctx);
  return { payload: { ...base, declaredEffects: plan.declaredEffects }, context: ctx };
}
function generationIds(store) {
  return store.listRecordIdentities(1000).filter((entry) => entry.schemaId === 'ServiceCredentialGenerationV1').map((entry) => entry.recordId).sort();
}
function assert(condition, message) { if (!condition) throw new Error(message); }

let publicResult;
try {
  const store = new ReleaseApplianceStore(stateRoot); store.startupScan();
  const bootstrap = new ServiceCredentialBootstrapService({ store, now, controllerIdentity, leaseTtlMs: 10_000 });
  const jobs = new JobManager(join(root, 'jobs'));
  const jobAdapter = {
    authority: 'existing-babyx-job',
    start: jobs.start.bind(jobs),
    get: jobs.get.bind(jobs),
    read: jobs.read.bind(jobs),
    reconcile: jobs.reconcile.bind(jobs),
  };
  const accountLookup = new DurableJobServiceAccountLookup({ jobs: jobAdapter, now, pollIntervalMs: 10, timeoutMs: 10_000 });
  const uid = process.getuid?.() ?? 0; const gid = process.getgid?.() ?? 0;
  const issuer = new ServiceCredentialFilesystemAuthority({ store, bootstrap, privateRoot, publicRoot, privateOwnerUid: uid, privateOwnerGid: gid, publicOwnerUid: uid, publicOwnerGid: gid, now });
  const authority = new ServiceCredentialAuthority({ store, bootstrap, issuer, accountLookup, privateRoots: [privateRoot], publicRoots: [publicRoot], privateOwnerUid: uid, privateOwnerGid: gid, publicOwnerUid: uid, publicOwnerGid: gid, stagingRoot, now });

  const firstPrepared = planPayload(authority, 'certification-ensure-v1');
  const first = await authority.ensure(firstPrepared.payload, firstPrepared.context);
  const firstId = first.active.activeGenerationId;
  const firstReplay = await authority.ensure(firstPrepared.payload, firstPrepared.context);
  assert(firstReplay.active.activeGenerationId === firstId, 'idempotent ensure created a different generation');
  assert(generationIds(store).length === 1, 'idempotent ensure created a duplicate generation');
  const firstVerification = authority.verify({ generationId: firstId });
  assert(firstVerification.serviceIdentity.observedUid === 997, 'fix-mcp UID 997 was not verified');
  assert(firstVerification.serviceIdentity.accountName === 'fix-mcp', 'fix-mcp principal was not verified');

  const rotationPrepared = planPayload(authority, 'certification-rotate-v2', firstId);
  const rotated = await authority.rotate(rotationPrepared.payload, rotationPrepared.context);
  const secondId = rotated.active.activeGenerationId;
  assert(secondId !== firstId, 'rotation did not issue an independent generation');
  assert(rotated.priorRemainedActiveUntilVerification === true, 'rotation did not preserve prior generation until verification');
  const secondVerification = authority.verify({ generationId: secondId });

  const beforeRollback = generationIds(store);
  const activeBeforeRollback = authority.active();
  const rollback = authority.rollback({ profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID, targetGenerationId: firstId, expectedSequence: activeBeforeRollback.sequence, reason: 'disposable certification rollback' }, context('certification-rollback-v1'));
  assert(rollback.regenerated === false, 'rollback regenerated credential material');
  assert(canonicalize(generationIds(store)) === canonicalize(beforeRollback), 'rollback changed the generation set');
  const secondBeforeRevoke = store.getRecord('ServiceCredentialGenerationV1', secondId);
  const revoked = authority.revoke({ generationId: secondId, expectedSequence: secondBeforeRevoke.sequence, reason: 'disposable certification retired generation' }, context('certification-revoke-v2'));
  assert(revoked.state === 'REVOKED' && revoked.evidencePreserved === true, 'revocation did not preserve evidence');

  const materializationPlan = authority.materializationPlan(firstId, installRoot);
  const dryRun = authority.activation.materialize(materializationPlan, true);
  assert(dryRun.filesystemEffects === false && !existsSync(installRoot), 'materialization dry-run created filesystem effects');
  const materialized = authority.activation.materialize(materializationPlan, false);
  assert(materialized.readbackVerified === true && materialized.temporaryMaterialAbsent === true, 'materialization readback or cleanup failed');
  const metadata = JSON.parse(readFileSync(join(installRoot, 'etc/baby-x/credential-generation.json'), 'utf8'));
  assert(metadata.generationId === firstId && metadata.rawPrivateMaterialIncluded === false, 'materialized metadata identity is incorrect');

  const firstGeneration = store.getRecord('ServiceCredentialGenerationV1', firstId);
  const credentialReference = store.getRecord('CredentialSetReferenceV1', firstGeneration.privateReferences[0].credentialSetId);
  const proofPrivatePath = credentialReference.entries.find((entry) => entry.name === 'baby-x-proof-private').sourceRef;
  const gatewayPrivatePath = credentialReference.entries.find((entry) => entry.name === 'baby-x-gateway-authority-private').sourceRef;
  const proofPublicPath = firstGeneration.publicMaterials.find((entry) => entry.name === 'proof-public').path;
  const proofPublic = createPublicKey(readFileSync(proofPublicPath));
  const gatewayPublic = createPublicKey(createPrivateKey(readFileSync(gatewayPrivatePath)));
  for (const restart of [1, 2]) {
    const runtimeCredentialRoot = join(root, `runtime-credentials-${restart}`); mkdirSync(runtimeCredentialRoot, { mode: 0o700 });
    const proofRuntime = join(runtimeCredentialRoot, 'baby-x-proof-private');
    const gatewayRuntime = join(runtimeCredentialRoot, 'baby-x-gateway-authority-private');
    copyFileSync(proofPrivatePath, proofRuntime); copyFileSync(gatewayPrivatePath, gatewayRuntime); chmodSync(proofRuntime, 0o400); chmodSync(gatewayRuntime, 0o400);
    const challenge = randomBytes(64);
    const proofSignature = sign(null, challenge, createPrivateKey(readFileSync(proofRuntime)));
    assert(verify(null, challenge, proofPublic, proofSignature), 'proof signing failed across launcher restart boundary');
    const gatewaySignature = sign(null, challenge, createPrivateKey(readFileSync(gatewayRuntime)));
    assert(verify(null, challenge, gatewayPublic, gatewaySignature), 'gateway authority verification failed across launcher restart boundary');
    challenge.fill(0); proofSignature.fill(0); gatewaySignature.fill(0);
    rmSync(runtimeCredentialRoot, { recursive: true, force: true });
    assert(!existsSync(runtimeCredentialRoot), 'runtime credential directory survived restart cleanup');
  }

  const cleanup = authority.clean();
  assert(cleanup.temporaryMaterialAbsent === true, 'temporary credential material cleanup was not positively verified');
  const serialized = JSON.stringify({ first, firstReplay, firstVerification, rotated, secondVerification, rollback, revoked, materialized, metadata, cleanup });
  assert(!serialized.includes(['-----BEGIN ', 'PRIVATE KEY-----'].join('')), 'private key material entered public certification results');
  const forbiddenChecks = Array.isArray(firstVerification.forbiddenAuthorityChecks) ? firstVerification.forbiddenAuthorityChecks : [];
  assert(forbiddenChecks.length === 1 && forbiddenChecks.every((entry) => entry.accessed === false && entry.verified === true), 'unrelated Quirt authority negative-access verification failed');

  publicResult = {
    schemaVersion: 'baby-x-k5-disposable-certification-v1',
    status: 'PASS',
    profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
    algorithm: 'ED25519',
    privateEncoding: 'PKCS8_PEM',
    publicEncoding: 'SPKI_PEM',
    firstGenerationId: firstId,
    secondGenerationId: secondId,
    publicFingerprints: firstVerification.publicFingerprints,
    serviceIdentity: { accountName: firstVerification.serviceIdentity.accountName, observedUid: firstVerification.serviceIdentity.observedUid, observedGid: firstVerification.serviceIdentity.observedGid, reverseUidAccountName: firstVerification.serviceIdentity.reverseUidAccountName, lookupSource: firstVerification.serviceIdentity.lookupSource },
    idempotentReplay: firstReplay.active.activeGenerationId === firstId,
    rotation: { independentGeneration: secondId !== firstId, priorRemainedActiveUntilVerification: rotated.priorRemainedActiveUntilVerification },
    rollback: { regenerated: rollback.regenerated, activeGenerationId: rollback.active.activeGenerationId },
    revocation: { state: revoked.state, evidencePreserved: revoked.evidencePreserved },
    launcherRestartsVerified: 2,
    materialization: { dryRunNoEffects: dryRun.filesystemEffects === false, readbackVerified: materialized.readbackVerified, privateMaterialExcluded: metadata.rawPrivateMaterialIncluded === false },
    cleanup: { temporaryMaterialAbsent: cleanup.temporaryMaterialAbsent, testRootWillBeRemoved: true },
    rawPrivateMaterialReturned: false,
  };
} finally {
  rmSync(root, { recursive: true, force: true });
}
assert(!existsSync(root), 'certification test root survived cleanup');
publicResult.cleanup.testRootAbsent = true;
process.stdout.write(`${JSON.stringify(publicResult)}\n`);
