import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalize, sha256, signCanonical, verifyCanonical } from '../../dist/runtime/core.js';
import { OPERATION_CATALOG_VERSION, OPERATION_DEFINITIONS } from '../../dist/runtime/operations/definitions.js';
import { RootBrokerService } from '../../dist/runtime/root-fabric/broker.js';
import { createRootCompatibilityManifest, readLegacyRootRecord, requireCompatibleMajor, validateStrictVersionedRecord } from '../../dist/runtime/root-fabric/compatibility.js';
import { RootEffectRegistry } from '../../dist/runtime/root-fabric/effects.js';
import { RootFilesystemEffects, filesystemState } from '../../dist/runtime/root-fabric/filesystem-effects.js';
import { HostEnvelopeProvider } from '../../dist/runtime/root-fabric/host-envelope.js';
import { verifyTransaction } from '../../dist/runtime/root-fabric/model.js';
import { ROOT_FABRIC_OPERATION_NAMES } from '../../dist/runtime/root-fabric/service.js';
import { RootTrustService } from '../../dist/runtime/root-fabric/trust.js';
import { RootEffectTransactionService } from '../../dist/runtime/root-fabric/transactions.js';
import { RootNetworkEffectAuthority, RootStorageEffectAuthority } from '../../dist/runtime/root-fabric/authorities.js';

const zero = '0'.repeat(64);
const one = '1'.repeat(64);
const two = '2'.repeat(64);
const three = '3'.repeat(64);
const sourceCommit = 'f03550add0a76277bf7ac7ca051006eea48a4ead';
const sourceTree = 'a0bfd76beb54b58bc9546dba166e66cd9584ca39';
const commandResult = (stdout = '', exitCode = 0) => ({ argv: [], cwd: '/', exitCode, signal: null, stdout, stderr: '', stdoutBytes: Buffer.byteLength(stdout), stderrBytes: 0, stdoutSha256: zero, stderrSha256: zero, startedAt: 'x', completedAt: 'y', durationMs: 1 });
const context = (idempotencyKey) => ({ subject: 'owner-a', authorityClass: 'unrestricted-owner', idempotencyKey });

function transactionPayload() {
  const input = { path: 'safe' };
  const step = { stepId: 'step-1', sequence: 1, operation: 'filesystem.file.create', operationVersion: '1.0.0', input, inputDigest: sha256(canonicalize(input)), resourceSelectors: { paths: ['safe'] }, effectClass: 'REVERSIBLE', timeoutMs: 30_000, dependencies: [], preconditions: [], preparationRequirements: [], expectedObservations: [], validation: { kind: 'digest' }, rollbackOperation: 'filesystem.file.remove', compensationOperation: null, providerRequirements: ['HOST_ENVELOPE'], credentialReferences: [], restartBehavior: 'READBACK_BEFORE_RETRY' };
  const plan = { atomicityMode: 'ATOMIC_WITHIN_PROVIDER', steps: [step] };
  return { source: { repository: 'StealthEyeLLC/baby-x', branch: 'test', commit: 'a'.repeat(40), tree: 'b'.repeat(40) }, skill: { skillId: 'skill-a', skillVersion: '1.0.0', bundleDigest: zero, manifestDigest: one, signerKeyId: 'key-a', signerIdentity: 'signer-a', signatureVerified: true, revocationStateDigest: two, capabilityGrantId: 'grant-a', capabilityGrantDigest: three }, deadline: '2026-07-29T12:00:00.000Z', atomicityMode: 'ATOMIC_WITHIN_PROVIDER', plan: { ...plan, planDigest: sha256(canonicalize(plan)) }, policy: { requested: true }, requestedProvider: 'HOST_ENVELOPE', riskClass: 'bounded', environmentDigest: zero };
}

function signedBundle(privateKey, overrides = {}) {
  const unsignedManifest = { schemaVersion: '1.0.0', bundleFormatVersion: '1.0.0', skillId: 'skill-a', skillVersion: '1.0.0', entrypoints: { main: 'index.js' }, operationDefinitions: [{ operation: 'filesystem.file.create' }], capabilityRequirements: ['filesystem'], providerRequirements: ['HOST_ENVELOPE'], resourceDeclarations: { path: 'safe' }, dependencyDigests: [], files: [{ path: 'index.js', type: 'file', mode: 420, size: 1, sha256: sha256('x'), symlinkTarget: null }], buildIdentity: { commit: 'a'.repeat(40) }, signerIdentity: 'signer-a', signatureAlgorithm: 'Ed25519', signerKeyId: 'key-1', createdAt: '2026-07-28T11:00:00.000Z', expiresAt: '2026-07-29T12:00:00.000Z', compatibilityRequirements: { rootFabric: '1' }, testManifest: { tests: ['unit'] }, ...overrides };
  const unsignedManifestDigest = sha256(canonicalize(unsignedManifest));
  const bundleDigest = sha256(canonicalize({ unsignedManifest, unsignedManifestDigest }));
  return { manifest: { ...unsignedManifest, bundleDigest }, signature: signCanonical(privateKey, { unsignedManifest, unsignedManifestDigest, bundleDigest }) };
}

test('A: compatibility manifest and strict schemas are deterministic and reject incompatible data', () => {
  const common = { sourceCommit, sourceTree, catalogDigest: zero };
  const left = createRootCompatibilityManifest({ ...common, providerContractVersions: { z: '1', a: '2' } });
  const right = createRootCompatibilityManifest({ ...common, providerContractVersions: { a: '2', z: '1' } });
  assert.deepEqual(left, right);
  assert.equal(left.digest, sha256(canonicalize(left.manifest)));
  assert.throws(() => requireCompatibleMajor('2.0.0', '1.0.0'), error => error.code === 'unsupported_schema');
  assert.throws(() => validateStrictVersionedRecord({ schemaVersion: '1.0.0', unknown: true }, 'effect'), error => error.code === 'invalid_request');
  assert.throws(() => validateStrictVersionedRecord({ schemaVersion: 'invalid' }, 'effect'));
  assert.deepEqual(readLegacyRootRecord({ schemaVersion: '0.1.0', record: { ok: true } }).record, { ok: true });
  assert.throws(() => readLegacyRootRecord({ schemaVersion: '0.1.0', record: {}, extra: true }));
  assert.throws(() => createRootCompatibilityManifest({ ...common, catalogVersion: '4.0.0' }), error => error.code === 'unsupported_schema');
});

test('B: durable transactions enforce transitions, replay, fencing, terminal immutability, pagination, index reconstruction and event chains', () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-ag-b-'));
  let now = '2026-07-28T12:00:00.000Z';
  try {
    const service = new RootEffectTransactionService(root, { now: () => now });
    const payload = transactionPayload();
    const created = service.create(payload, context('create-0001'));
    assert.equal(created.replayed, false);
    assert.equal(service.create(payload, context('create-0001')).replayed, true);
    assert.throws(() => service.create({ ...payload, riskClass: 'other' }, context('create-0001')), error => error.code === 'idempotency_conflict');
    assert.throws(() => service.commit({ transactionId: created.transaction.transactionId, expectedSequence: 1, fencingToken: 0, cleanupComplete: true, finalResultDigest: zero }, context('direct-commit')), error => error.code === 'transaction_state_conflict');
    const id = created.transaction.transactionId;
    let record = service.acquireLease({ transactionId: id, expectedSequence: 1, controllerId: 'controller-a', ttlMs: 60_000, takeoverReason: 'initial' }, context('lease-0001')).transaction;
    assert.equal(record.lease.fencingToken, 1);
    record = service.authorize({ transactionId: id, expectedSequence: record.lifecycle.sequence, fencingToken: 1, decisionDigest: zero, expiresAt: '2026-07-28T13:00:00.000Z', executionProvider: 'HOST_ENVELOPE', providerId: 'host', providerVersion: '1.0.0', providerContractVersion: '1.0.0', providerProfileDigest: one }, context('authorize-0001')).transaction;
    assert.throws(() => service.prepare({ transactionId: id, expectedSequence: record.lifecycle.sequence, fencingToken: 999, priorStateDigest: zero, artifactIds: [], snapshotReferences: [], rollbackReady: true, compensationReady: false }, context('stale-fence')), error => error.code === 'fencing_token_stale');
    record = service.prepare({ transactionId: id, expectedSequence: record.lifecycle.sequence, fencingToken: 1, priorStateDigest: zero, artifactIds: [], snapshotReferences: [], rollbackReady: true, compensationReady: false }, context('prepare-0001')).transaction;
    record = service.begin({ transactionId: id, expectedSequence: record.lifecycle.sequence, fencingToken: 1, activeJobIds: ['job-1'], allJobIds: ['job-1'], activeMachineIds: [], allMachineIds: [], unitNames: ['unit-1'], processIdentities: [], providerAttempts: [] }, context('begin-0001')).transaction;
    record = service.validate({ transactionId: id, expectedSequence: record.lifecycle.sequence, fencingToken: 1, specification: { kind: 'digest' }, validatorVersion: '1.0.0', expectedState: { digest: one }, observedState: { digest: one }, attempts: 1, result: 'SUCCEEDED', resultDigest: one, failureReason: null, executionTerminal: true }, context('validate-0001')).transaction;
    record = service.commit({ transactionId: id, expectedSequence: record.lifecycle.sequence, fencingToken: 1, cleanupComplete: true, finalResultDigest: two }, context('commit-0001')).transaction;
    assert.equal(record.lifecycle.persistedState, 'COMMITTED');
    assert.equal(record.lifecycle.terminal, true);
    assert.equal(verifyTransaction(record).valid, true);
    assert.equal(service.events({ transactionId: id, offset: 0, limit: 200 }).integrity.valid, true);
    assert.throws(() => service.acquireLease({ transactionId: id, expectedSequence: record.lifecycle.sequence, controllerId: 'controller-a', ttlMs: 60_000 }, context('terminal-lease')), error => error.code === 'transaction_state_conflict');

    const second = service.create({ ...payload, riskClass: 'second' }, context('create-0002')).transaction;
    let secondRecord = service.acquireLease({ transactionId: second.transactionId, expectedSequence: 1, controllerId: 'controller-a', ttlMs: 1_000 }, context('lease-0002')).transaction;
    now = '2026-07-28T12:00:02.000Z';
    secondRecord = service.acquireLease({ transactionId: second.transactionId, expectedSequence: secondRecord.lifecycle.sequence, controllerId: 'controller-b', ttlMs: 1_000, takeoverReason: 'expired takeover' }, context('lease-0003')).transaction;
    assert.equal(secondRecord.lease.fencingToken, 2);
    assert.equal(service.list({ offset: 0, limit: 1 }).transactions.length, 1);
    const rebuilt = new RootEffectTransactionService(root, { now: () => now });
    assert.equal(rebuilt.list({ offset: 0, limit: 200 }).transactions.length, 2);
    const authoritative = join(root, 'root-fabric', 'transactions', 'authoritative', 'records');
    const file = readdirSync(authoritative).find(name => name.endsWith('.json'));
    assert.ok(file);
    writeFileSync(join(authoritative, file), '{corrupt');
    const isolated = new RootEffectTransactionService(root, { now: () => now }).list({ offset: 0, limit: 200 });
    assert.ok(isolated.corruptRecordIds.length >= 1);
    assert.ok(isolated.transactions.length >= 1);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('C: signed bundles and grants enforce signatures, paths, expiry, revocation and semantic restrictions', () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-ag-c-'));
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  try {
    const trust = new RootTrustService(root, keyId => keyId === 'key-1' ? publicKey : undefined, { now: () => '2026-07-28T12:00:00.000Z' });
    const valid = signedBundle(privateKey);
    assert.equal(trust.bundleVerify(valid).verified, true);
    assert.throws(() => trust.bundleVerify({ ...valid, signature: 'AAAA' }), error => error.code === 'bundle_signature_invalid');
    assert.throws(() => trust.bundleVerify({ ...valid, manifest: { ...valid.manifest, files: [{ ...valid.manifest.files[0], sha256: zero }] } }), error => error.code === 'bundle_digest_mismatch');
    assert.equal(trust.bundleVerify(signedBundle(privateKey, { expiresAt: '2026-07-28T11:30:00.000Z' })).state, 'EXPIRED');
    assert.throws(() => trust.bundleVerify(signedBundle(privateKey, { files: [{ ...valid.manifest.files[0], path: '../escape' }] })), error => error.code === 'invalid_request');
    assert.throws(() => trust.bundleVerify(signedBundle(privateKey, { files: [{ path: 'link', type: 'symlink', mode: 511, size: 0, sha256: sha256(''), symlinkTarget: '../escape' }] })), error => error.code === 'symlink_escape');
    assert.throws(() => trust.bundleVerify(signedBundle(privateKey, { files: [valid.manifest.files[0], valid.manifest.files[0]] })), error => error.code === 'invalid_request');
    assert.throws(() => new RootTrustService(root, () => undefined).bundleVerify(valid), error => error.code === 'signer_revoked');
    const installed = trust.bundleInstall(valid, context('bundle-install')).bundle;
    const grantInput = { schemaVersion: '1.0.0', grantId: 'grant-a', skillId: 'skill-a', bundleDigest: installed.bundleDigest, ownerPrincipal: 'owner-a', allowedOperations: ['filesystem.file.create'], resourceSelectors: { path: ['safe'] }, allowedProviders: ['HOST_ENVELOPE'], effectClasses: ['REVERSIBLE'], limits: { cpu: 1, memoryBytes: 1_048_576 }, credentialReferences: ['credential-ref-a'], policyVersion: '1.0.0', issuedAt: '2026-07-28T12:00:00.000Z', expiresAt: '2026-07-29T12:00:00.000Z' };
    trust.grantInstall({ grant: grantInput }, context('grant-install'));
    const authorize = overrides => trust.authorize({ grantId: 'grant-a', bundleDigest: installed.bundleDigest, ownerPrincipal: 'owner-a', operation: 'filesystem.file.create', provider: 'HOST_ENVELOPE', effectClass: 'REVERSIBLE', resources: { path: 'safe' }, credentialReferences: ['credential-ref-a'], ...overrides });
    assert.equal(authorize({}).grantId, 'grant-a');
    assert.throws(() => authorize({ operation: 'process.exec' }), error => error.code === 'grant_denied');
    assert.throws(() => authorize({ provider: 'DISPOSABLE_MACHINE' }), error => error.code === 'grant_denied');
    assert.throws(() => authorize({ effectClass: 'IRREVERSIBLE' }), error => error.code === 'grant_denied');
    assert.throws(() => authorize({ resources: { path: 'other' } }), error => error.code === 'grant_denied');
    assert.throws(() => authorize({ credentialReferences: ['other-ref'] }), error => error.code === 'grant_denied');
    trust.grantRevoke({ grantId: 'grant-a', reason: 'test' }, context('grant-revoke'));
    assert.throws(() => authorize({}), error => error.code === 'grant_revoked');
    trust.bundleRevoke({ bundleDigest: installed.bundleDigest, reason: 'test' }, context('bundle-revoke'));
    assert.equal(trust.bundleGet({ bundleDigest: installed.bundleDigest }).bundle.state, 'REVOKED');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('D: broker is finite, replay-safe, deadline-bound, release-bound and signs deterministic results', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-ag-d-'));
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  try {
    let bindings = 0;
    const broker = new RootBrokerService({ stateRoot: root, brokerIdentity: 'broker-a', releaseCommit: 'a'.repeat(40), releaseTree: 'b'.repeat(40), signingKey: privateKey, verifyBinding: request => { bindings += 1; if (request.ownerPrincipalDigest !== zero) throw new Error('wrong principal'); }, receipt: (request, digest) => `receipt:${request.requestId}:${digest}`, now: () => '2026-07-28T12:00:00.000Z' });
    broker.register({ operation: 'filesystem.file.create', version: '1.0.0', async execute(input) { return { classification: 'SUCCEEDED', result: { created: input.path }, executionIdentity: { unit: 'u1' }, cleanupState: { complete: true } }; } });
    const input = { path: 'safe' };
    const request = { protocolVersion: '1.0.0', requestId: 'request-a', transactionId: 'transaction-a', transactionSequence: 7, fencingToken: 3, ownerPrincipalDigest: zero, skillBundleDigest: one, grantDigest: two, policyDecisionDigest: three, operation: 'filesystem.file.create', operationVersion: '1.0.0', operationInput: input, inputDigest: sha256(canonicalize(input)), deadline: '2026-07-28T13:00:00.000Z', nonce: 'nonce-a', selectedProvider: 'HOST_ENVELOPE', credentialReferences: [] };
    const response = await broker.handle(request);
    const { signature, ...unsigned } = response;
    assert.equal(verifyCanonical(publicKey, unsigned, signature), true);
    assert.equal(response.brokerReleaseCommit, 'a'.repeat(40));
    assert.equal(response.brokerReleaseTree, 'b'.repeat(40));
    assert.deepEqual(await broker.handle(request), response);
    assert.equal(bindings, 1);
    await assert.rejects(() => broker.handle({ ...request, nonce: 'other' }), error => error.code === 'broker_replay_detected');
    await assert.rejects(() => broker.handle({ ...request, requestId: 'b', protocolVersion: '2.0.0' }), error => error.code === 'broker_protocol_mismatch');
    await assert.rejects(() => broker.handle({ ...request, requestId: 'c', deadline: '2026-07-28T11:00:00.000Z' }), error => error.code === 'deadline_exceeded');
    await assert.rejects(() => broker.handle({ ...request, requestId: 'd', operation: 'unknown.operation' }), error => error.code === 'unsupported_operation');
    await assert.rejects(() => broker.handle({ ...request, requestId: 'e', ownerPrincipalDigest: one }), /wrong principal/);
    assert.throws(() => broker.register({ operation: 'filesystem.file.create', version: '1.0.0', async execute() { return { classification: 'SUCCEEDED', result: {} }; } }), error => error.code === 'resource_conflict');
    assert.equal(broker.describe().arbitraryShell, false);
    const source = readFileSync(join(process.cwd(), 'runtime/src/root-broker-main.ts'), 'utf8');
    assert.match(source, /getPeerCredentials/u);
    assert.match(source, /credentials\.uid !== allowedUid/u);
    assert.match(source, /maximumFrame = 1_048_576/u);
    assert.match(source, /exactly one canonical frame/u);
    assert.match(source, /activatedSocketFd/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('E: host envelopes constrain execution and preserve process, cgroup, boot, cancellation and freeze identities', async () => {
  const calls = [];
  const fake = { async run(options) { calls.push(['run', options]); return commandResult('ok'); }, async show() { return commandResult('Id=u.service\nInvocationID=inv-1\nMainPID=0\nExecMainStartTimestampMonotonic=42\nControlGroup=/baby-x-root.slice/u\nActiveState=inactive\nSubState=dead\nResult=success\n'); }, async kill(options) { calls.push(['kill', options]); return commandResult(); }, async raw(tool, argv) { calls.push(['raw', tool, argv]); return commandResult(); } };
  const provider = new HostEnvelopeProvider(fake);
  const input = { executable: '/usr/bin/true', argv: ['--help'], workingDirectory: '/tmp', user: 'root', group: 'root', environment: ['LANG=C'], timeoutMs: 1_000, cpuQuota: '25%', memoryMax: '64M', ioWeight: '100', tasksMax: 16, readOnlyPaths: ['/usr'], readWritePaths: ['/tmp'], inaccessiblePaths: ['/home'], restrictAddressFamilies: ['AF_UNIX'], systemCallFilter: ['@system-service'], capabilityBoundingSet: [], credentialPaths: [] };
  const request = { transactionId: 'transaction-a', transactionSequence: 1, inputDigest: sha256(canonicalize(input)) };
  const execution = await provider.execute(input, request);
  const rootRequestDigest = sha256(canonicalize(request));
  assert.equal(execution.executionIdentity.invocationId, 'inv-1');
  assert.equal(execution.executionIdentity.processStartTime, '42');
  assert.equal(execution.executionIdentity.systemdStartTimestamp, '42');
  assert.equal(execution.executionIdentity.cgroup, '/baby-x-root.slice/u');
  assert.ok(execution.executionIdentity.bootId);
  assert.equal(execution.executionIdentity.transactionId, 'transaction-a');
  assert.equal(execution.executionIdentity.requestDigest, rootRequestDigest);
  assert.equal(execution.executionIdentity.executablePath, '/usr/bin/true');
  const properties = calls.find(call => call[0] === 'run')[1].properties;
  const environmentTokens = properties.Environment.split(' ');
  assert.ok(environmentTokens.includes('BABYX_ROOT_TRANSACTION_ID=transaction-a'));
  assert.ok(environmentTokens.includes(`BABYX_ROOT_REQUEST_DIGEST=${rootRequestDigest}`));
  for (const name of ['NoNewPrivileges', 'ProtectSystem', 'RestrictNamespaces', 'KillMode', 'CPUQuota', 'MemoryMax', 'IOWeight', 'TasksMax']) assert.ok(properties[name]);
  assert.equal((await provider.cancel('u.service')).complete, true);
  assert.equal(calls.filter(call => call[0] === 'kill').length, 2);
  await provider.freeze('u.service', true);
  await provider.freeze('u.service', false);
  assert.throws(() => provider.profile({ ...input, executable: 'true' }, request), error => error.code === 'invalid_request');
  assert.throws(() => provider.profile({ ...input, environment: ['bad'] }, request), error => error.code === 'invalid_request');
  assert.throws(() => provider.profile({ ...input, environment: ['BABYX_ROOT_TRANSACTION_ID=forged'] }, request), error => error.code === 'invalid_request');
  assert.throws(() => provider.profile({ ...input, environment: [`BABYX_ROOT_REQUEST_DIGEST=${'f'.repeat(64)}`] }, request), error => error.code === 'invalid_request');
  const source = readFileSync(join(process.cwd(), 'runtime/src/root-fabric/host-envelope.ts'), 'utf8');
  assert.match(source, /InvocationID/u);
  assert.match(source, /ExecMainStartTimestampMonotonic/u);
  assert.match(source, /bootId/u);
  assert.match(source, /control-group/u);
});

test('F: filesystem effects confine paths, enforce CAS, reject links and races, fsync, atomically switch and restore', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-ag-f-'));
  const blobs = new Map();
  const artifacts = { async capture(_name, bytes) { const id = sha256(bytes); blobs.set(id, Buffer.from(bytes)); return { artifactId: id, sha256: id, size: bytes.length }; }, async read(id) { return blobs.get(id); } };
  const request = { transactionId: 'transaction-a', transactionSequence: 1, selectedProvider: 'HOST_ENVELOPE' };
  try {
    const effects = new RootFilesystemEffects({ artifacts });
    await effects.execute('filesystem.file.create', { root, path: 'a.txt', data: 'one', encoding: 'utf8', mode: 420, expectedAbsent: true }, request);
    assert.equal(filesystemState(join(root, 'a.txt')).mode, 420);
    await assert.rejects(() => effects.execute('filesystem.file.replace', { root, path: 'a.txt', data: 'bad', expectedSha256: zero }, request), error => error.code === 'expected_digest_mismatch');
    const replacement = await effects.execute('filesystem.file.replace', { root, path: 'a.txt', data: 'two', mode: 384, expectedSha256: sha256('one') }, request);
    assert.equal(readFileSync(join(root, 'a.txt'), 'utf8'), 'two');
    await effects.restore({ root, path: 'a.txt', priorState: replacement.result.priorState });
    assert.equal(readFileSync(join(root, 'a.txt'), 'utf8'), 'one');
    await assert.rejects(() => effects.execute('filesystem.file.create', { root, path: '../escape', data: 'x', expectedAbsent: true }, request), error => error.code === 'path_escape');
    mkdirSync(join(root, 'real')); symlinkSync(join(root, 'real'), join(root, 'link'));
    await assert.rejects(() => effects.execute('filesystem.file.create', { root, path: 'link/x', data: 'x', expectedAbsent: true }, request), error => error.code === 'symlink_escape');
    writeFileSync(join(root, 'hard-a'), 'x'); linkSync(join(root, 'hard-a'), join(root, 'hard-b'));
    await assert.rejects(() => effects.execute('filesystem.file.replace', { root, path: 'hard-a', data: 'y', expectedSha256: sha256('x') }, request), error => error.code === 'hardlink_rejected');
    await effects.execute('filesystem.symlink.replace', { root, path: 'current', target: 'release-a', expectedAbsent: true }, request);
    await effects.execute('filesystem.symlink.replace', { root, path: 'current', target: 'release-b', expectedTarget: 'release-a' }, request);
    await assert.rejects(() => effects.execute('filesystem.release-pointer.switch', { root, path: 'release', target: '/tmp/not-release', expectedAbsent: true }, request), error => error.code === 'policy_denied');
    await effects.execute('filesystem.release-pointer.switch', { root, path: 'release', target: '/opt/baby-x/releases/r1', expectedAbsent: true }, request);
    assert.equal(filesystemState(join(root, 'release')).symlinkTarget, '/opt/baby-x/releases/r1');
    const raceRoot = mkdtempSync(join(tmpdir(), 'babyx-ag-f-race-'));
    let raced = false;
    const racer = new RootFilesystemEffects({ artifacts, beforeMutation: ({ parent }) => { if (!raced) { raced = true; renameSync(parent, `${parent}.moved`); mkdirSync(parent); } } });
    await assert.rejects(() => racer.execute('filesystem.file.create', { root: raceRoot, path: 'race.txt', data: 'x', expectedAbsent: true }, request), error => error.code === 'parent_race');
    rmSync(raceRoot, { recursive: true, force: true }); rmSync(`${raceRoot}.moved`, { recursive: true, force: true });
    assert.equal(readdirSync(root).some(name => name.endsWith('.babyx.tmp') || name.endsWith('.babyx.link')), false);
    const source = readFileSync(join(process.cwd(), 'runtime/src/root-fabric/filesystem-effects.ts'), 'utf8');
    assert.match(source, /fsyncSync\(fd\)/u);
    assert.match(source, /syncParent/u);
    assert.match(source, /renameSync\(temporary, path\)/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('G: finite process, service, mount, snapshot, storage and network effects reuse bounded authorities', async () => {
  const calls = [];
  const systemd = { async show() { return commandResult('LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n'); }, async action(action, options) { calls.push(['action', action, options]); return commandResult(); }, async run() { return commandResult(); }, async kill() { return commandResult(); }, async raw() { return commandResult(); } };
  const storage = { async mountStatus(i) { calls.push(['mountStatus', i]); return {}; }, async mountCreate(i) { calls.push(['mountCreate', i]); return {}; }, async mountRemove(i) { calls.push(['mountRemove', i]); return {}; }, async prepareSnapshot(i) { calls.push(['prepareSnapshot', i]); return {}; }, async verifySnapshot(i) { calls.push(['verifySnapshot', i]); return {}; }, async rollbackSnapshot(i) { calls.push(['rollbackSnapshot', i]); return {}; }, async releaseSnapshot(i) { calls.push(['releaseSnapshot', i]); return {}; } };
  const network = { async portCheck(i) { calls.push(['portCheck', i]); return {}; }, async listenerVerify(i) { calls.push(['listenerVerify', i]); return {}; }, async applyOwnedRule(i) { calls.push(['applyOwnedRule', i]); return {}; }, async removeOwnedRule(i) { calls.push(['removeOwnedRule', i]); return {}; } };
  const registry = new RootEffectRegistry({ storage, network, systemd });
  assert.equal(registry.list().length, 31);
  assert.equal(new Set(registry.list().map(effect => effect.operation)).size, 31);
  assert.equal(registry.list().some(effect => effect.operation.includes('shell')), false);
  const request = { transactionId: 'tx', transactionSequence: 1, inputDigest: zero, selectedProvider: 'HOST_ENVELOPE' };
  await registry.adapter('service.restart').execute({ unit: 'demo.service', timeoutMs: 1_000 }, request);
  assert.equal(calls.some(call => call[0] === 'action' && call[1] === 'restart'), true);
  assert.equal((await registry.restoreService({ unit: 'demo.service', priorActive: true, priorEnabled: false })).restored, true);
  await registry.adapter('mount.status').execute({ target: '/mnt/babyx/a' }, request);
  await registry.adapter('snapshot.verify').execute({ snapshot: 'pool/babyx@s1' }, request);
  await registry.adapter('network.policy.apply-owned-rule').execute({ chain: 'input', ruleId: 'r1', expression: ['tcp'] }, request);

  const execCalls = [];
  const executor = { async run(options) { execCalls.push(options.argv); if (options.argv.includes('guid,createtxg')) return commandResult('guid\t123\ncreatetxg\t45\n'); return commandResult(); } };
  const storageAuthority = new RootStorageEffectAuthority({ executor, datasetRoots: ['babycert/base/noble', 'pool/babyx'], mountRoots: ['/mnt/babyx'] });
  await assert.rejects(() => storageAuthority.rollbackSnapshot({ snapshot: 'babycert/base/noble@golden-v1', expectedGuid: '9351137475418520293', expectedCreationTxg: '53' }), error => error.code === 'protected_source_mismatch');
  await assert.rejects(() => storageAuthority.verifySnapshot({ snapshot: 'pool/other@s1' }), error => error.code === 'policy_denied');
  await assert.rejects(() => storageAuthority.rollbackSnapshot({ snapshot: 'pool/babyx@s1', expectedGuid: '999', expectedCreationTxg: '45' }), error => error.code === 'protected_source_mismatch');
  await assert.rejects(() => storageAuthority.mountStatus({ target: '/mnt/other' }), error => error.code === 'policy_denied');
  assert.throws(() => new RootNetworkEffectAuthority({ executor, table: 'filter' }), error => error.code === 'policy_denied');
  const ownedNetwork = new RootNetworkEffectAuthority({ executor, table: 'babyx_root' });
  await ownedNetwork.applyOwnedRule({ chain: 'input', ruleId: 'r1', expression: ['tcp', 'dport', '443', 'accept'] });
  assert.equal(execCalls.at(-1).includes('babyx_root'), true);
});

test('A-G public surface is exact, dispatcher-backed, duplicate-free and contains no arbitrary root shell', () => {
  assert.equal(OPERATION_CATALOG_VERSION, '3.6.0');
  assert.equal(OPERATION_DEFINITIONS.length, 243);
  const root = OPERATION_DEFINITIONS.filter(definition => definition.operation.startsWith('babyx.root.')).map(definition => definition.operation);
  const original = ['babyx.root.describe', 'babyx.root.transaction.create', 'babyx.root.transaction.get', 'babyx.root.transaction.list', 'babyx.root.transaction.authorize', 'babyx.root.transaction.begin', 'babyx.root.transaction.observe', 'babyx.root.transaction.commit', 'babyx.root.transaction.rollback', 'babyx.root.transaction.events', 'babyx.root.transaction.verify'];
  assert.equal(root.length, 51);
  assert.equal(ROOT_FABRIC_OPERATION_NAMES.length, 40);
  assert.equal(new Set(root).size, 51);
  for (const operation of [...original, ...ROOT_FABRIC_OPERATION_NAMES]) assert.equal(root.includes(operation), true, operation);
  const forbiddenSuffixes = ['__checkpoint_k_not_implemented__'];
  assert.equal(root.some(operation => forbiddenSuffixes.some(suffix => operation.startsWith(`babyx.root.${suffix}`))), false);
  const source = readFileSync(join(process.cwd(), 'runtime/src/core.ts'), 'utf8');
  assert.match(source, /return \(await this\.rootFabricService\(\)\)\.execute\(operation, payload, context\)/u);
  assert.equal(root.some(operation => operation.includes('shell')), false);
});
