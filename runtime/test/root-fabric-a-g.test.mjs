import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalize, sha256, signCanonical } from '../../dist/runtime/core.js';
import { RootEffectTransactionService } from '../../dist/runtime/root-fabric/transactions.js';
import { verifyTransaction } from '../../dist/runtime/root-fabric/model.js';
import { RootTrustService } from '../../dist/runtime/root-fabric/trust.js';
import { RootBrokerService } from '../../dist/runtime/root-fabric/broker.js';
import { HostEnvelopeProvider, RootEffectRegistry } from '../../dist/runtime/root-fabric/effects.js';

const d = (value) => sha256(String(value));
const context = (key) => ({ subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner', idempotencyKey: `test-${key}` });
const future = (ms = 3_600_000) => new Date(Date.now() + ms).toISOString();

function planFor(operation = 'filesystem.file.replace', input = { root: '/tmp', path: 'x', data: 'x', encoding: 'utf8' }, effectClass = 'REVERSIBLE', atomicityMode = 'ATOMIC_WITHIN_PROVIDER') {
  const step = {
    stepId: 'step-1', sequence: 1, operation, operationVersion: '1.0.0', input,
    inputDigest: sha256(canonicalize(input)), resourceSelectors: { root: input.root ?? '/tmp', path: input.path ?? 'x' },
    effectClass, timeoutMs: 30_000, dependencies: [], preconditions: [], preparationRequirements: [],
    expectedObservations: [], validation: { kind: 'target-readback' }, rollbackOperation: effectClass === 'REVERSIBLE' ? operation : null,
    compensationOperation: effectClass === 'COMPENSATABLE' ? 'service.restart' : null,
    providerRequirements: ['HOST_ENVELOPE'], credentialReferences: [], restartBehavior: 'READBACK_BEFORE_RETRY',
  };
  return { atomicityMode, steps: [step], planDigest: sha256(canonicalize({ atomicityMode, steps: [step] })) };
}

function createPayload(plan = planFor()) {
  return {
    source: { repository: 'StealthEyeLLC/baby-x', branch: 'build/test', commit: 'a'.repeat(40), tree: 'b'.repeat(40) },
    skill: {
      skillId: 'root.test', skillVersion: '1.0.0', bundleDigest: d('bundle'), manifestDigest: d('manifest'), signerKeyId: 'test-key', signerIdentity: 'test-signer',
      signatureVerified: true, revocationStateDigest: d('revocation'), capabilityGrantId: 'grant-test', capabilityGrantDigest: d('grant'),
    },
    deadline: future(), atomicityMode: plan.atomicityMode, plan, policy: { requested: true }, requestedProvider: 'HOST_ENVELOPE', riskClass: 'high', environmentDigest: d('environment'),
  };
}

async function executing(service, prefix = 'tx') {
  let result = service.create(createPayload(), context(`${prefix}-create`));
  const id = result.transaction.transactionId;
  result = service.acquireLease({ transactionId: id, expectedSequence: 1, controllerId: 'controller-a', ttlMs: 60_000 }, context(`${prefix}-lease`));
  const fence = result.transaction.lease.fencingToken;
  result = service.authorize({ transactionId: id, expectedSequence: 2, fencingToken: fence, decisionDigest: d('decision'), expiresAt: future(), executionProvider: 'HOST_ENVELOPE', providerId: 'systemd-transient', providerVersion: '1.0.0', providerContractVersion: '1.0.0', providerProfileDigest: d('profile') }, context(`${prefix}-authorize`));
  result = service.prepare({ transactionId: id, expectedSequence: 3, fencingToken: fence, priorStateDigest: d('prior'), artifactIds: [], snapshotReferences: [], rollbackReady: true, compensationReady: false }, context(`${prefix}-prepare`));
  assert.equal(result.transaction.lifecycle.persistedState, 'READY');
  result = service.begin({ transactionId: id, expectedSequence: 5, fencingToken: fence, activeJobIds: ['job-1'], allJobIds: ['job-1'], activeMachineIds: [], allMachineIds: [], unitNames: ['babyx-root-test.service'], processIdentities: [{ unitName: 'babyx-root-test.service', invocationId: 'inv-1' }], providerAttempts: [] }, context(`${prefix}-begin`));
  return { id, fence, result };
}

test('A-B root effect transactions enforce full lifecycle, idempotency, fencing, and integrity', () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-root-fabric-tx-'));
  try {
    const service = new RootEffectTransactionService(root);
    const payload = createPayload();
    const first = service.create(payload, context('same-create'));
    const replay = service.create(payload, context('same-create'));
    assert.equal(replay.replayed, true);
    assert.equal(replay.transaction.transactionId, first.transaction.transactionId);
    assert.throws(() => service.create({ ...payload, riskClass: 'different' }, context('same-create')), /idempotency/u);
    let result = service.acquireLease({ transactionId: first.transaction.transactionId, expectedSequence: 1, controllerId: 'controller-a', ttlMs: 60_000 }, context('lease-a'));
    const fence = result.transaction.lease.fencingToken;
    assert.equal(fence, 1);
    assert.throws(() => service.authorize({ transactionId: first.transaction.transactionId, expectedSequence: 2, fencingToken: fence + 1, decisionDigest: d('decision'), expiresAt: future(), executionProvider: 'HOST_ENVELOPE', providerId: 'systemd-transient', providerVersion: '1', providerContractVersion: '1', providerProfileDigest: d('profile') }, context('stale-fence')), /fencing token/u);
    result = service.authorize({ transactionId: first.transaction.transactionId, expectedSequence: 2, fencingToken: fence, decisionDigest: d('decision'), expiresAt: future(), executionProvider: 'HOST_ENVELOPE', providerId: 'systemd-transient', providerVersion: '1', providerContractVersion: '1', providerProfileDigest: d('profile') }, context('auth'));
    result = service.prepare({ transactionId: first.transaction.transactionId, expectedSequence: 3, fencingToken: fence, priorStateDigest: d('prior'), artifactIds: [], snapshotReferences: [], rollbackReady: true, compensationReady: false }, context('prepare'));
    result = service.begin({ transactionId: first.transaction.transactionId, expectedSequence: 5, fencingToken: fence, activeJobIds: ['job-a'], allJobIds: ['job-a'], activeMachineIds: [], allMachineIds: [], unitNames: [], processIdentities: [], providerAttempts: [] }, context('begin'));
    result = service.validate({ transactionId: first.transaction.transactionId, expectedSequence: 6, fencingToken: fence, specification: { kind: 'digest' }, validatorVersion: '1', expectedState: { digest: d('target') }, observedState: { digest: d('target') }, attempts: 1, result: 'SUCCEEDED', resultDigest: d('validation'), failureReason: null, executionTerminal: true }, context('validate'));
    assert.equal(result.transaction.lifecycle.persistedState, 'COMMITTING');
    result = service.commit({ transactionId: first.transaction.transactionId, expectedSequence: 8, fencingToken: fence, cleanupComplete: true, finalResultDigest: d('final') }, context('commit'));
    assert.equal(result.transaction.lifecycle.persistedState, 'COMMITTED');
    assert.equal(verifyTransaction(result.transaction).valid, true);
    assert.equal(result.transaction.events.length, 9);
    assert.throws(() => service.begin({ transactionId: first.transaction.transactionId, expectedSequence: 9, fencingToken: fence }, context('invalid-after-terminal')), /does not permit/u);
    assert.throws(() => service.repair({ transactionId: first.transaction.transactionId, expectedSequence: 9, fencingToken: fence, nextState: 'COMMITTED', reason: 'bad repair' }, context('bad-repair')), /may not directly/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('C signed bundles and semantic grants reject invalid trust and resource escalation', () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-root-trust-'));
  try {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const service = new RootTrustService(root, (keyId) => keyId === 'test-key' ? publicKey : undefined);
    const unsignedManifest = {
      schemaVersion: '1.0.0', bundleFormatVersion: '1.0.0', skillId: 'root.test', skillVersion: '1.0.0', entrypoints: { main: 'index.js' },
      operationDefinitions: [{ operation: 'filesystem.file.replace' }], capabilityRequirements: ['filesystem.file.replace'], providerRequirements: ['HOST_ENVELOPE'],
      resourceDeclarations: { roots: ['/tmp/allowed'] }, dependencyDigests: [], files: [{ path: 'index.js', type: 'file', mode: 0o644, size: 1, sha256: d('x'), symlinkTarget: null }],
      buildIdentity: { commit: 'a'.repeat(40) }, signerIdentity: 'test-signer', signatureAlgorithm: 'Ed25519', signerKeyId: 'test-key', createdAt: new Date().toISOString(), expiresAt: future(), compatibilityRequirements: {}, testManifest: {},
    };
    const unsignedManifestDigest = sha256(canonicalize(unsignedManifest));
    const bundleDigest = sha256(canonicalize({ unsignedManifest, unsignedManifestDigest }));
    const signature = signCanonical(privateKey, { unsignedManifest, unsignedManifestDigest, bundleDigest });
    const manifest = { ...unsignedManifest, bundleDigest };
    const installed = service.bundleInstall({ manifest, signature }, context('bundle-install'));
    assert.equal(installed.bundle.signatureVerified, true);
    assert.throws(() => service.bundleVerify({ manifest, signature: `${signature.slice(0, -2)}AA` }), /signature/u);
    assert.throws(() => service.bundleVerify({ manifest: { ...manifest, files: [{ ...manifest.files[0], path: '../escape' }] }, signature }), /confined relative path/u);
    const grant = service.grantInstall({ grant: { schemaVersion: '1.0.0', grantId: 'grant-test', skillId: 'root.test', bundleDigest, ownerPrincipal: 'stealtheye-owner', allowedOperations: ['filesystem.file.replace'], resourceSelectors: { root: '/tmp/allowed', path: ['config.json'] }, allowedProviders: ['HOST_ENVELOPE'], effectClasses: ['REVERSIBLE'], limits: { runtimeMs: 30_000 }, credentialReferences: ['/run/credential-ref'], policyVersion: '1', issuedAt: new Date().toISOString(), expiresAt: future() } }, context('grant-install')).grant;
    assert.equal(service.authorize({ grantId: grant.grantId, bundleDigest, ownerPrincipal: 'stealtheye-owner', operation: 'filesystem.file.replace', provider: 'HOST_ENVELOPE', effectClass: 'REVERSIBLE', resources: { root: '/tmp/allowed', path: 'config.json' }, credentialReferences: ['/run/credential-ref'] }).grantId, 'grant-test');
    assert.throws(() => service.authorize({ grantId: grant.grantId, bundleDigest, ownerPrincipal: 'stealtheye-owner', operation: 'filesystem.file.replace', provider: 'HOST_ENVELOPE', effectClass: 'REVERSIBLE', resources: { root: '/tmp/other', path: 'config.json' } }), /resource selectors/u);
    service.grantRevoke({ grantId: grant.grantId, reason: 'test revoke' }, context('grant-revoke'));
    assert.throws(() => service.authorize({ grantId: grant.grantId, bundleDigest, ownerPrincipal: 'stealtheye-owner', operation: 'filesystem.file.replace', provider: 'HOST_ENVELOPE', effectClass: 'REVERSIBLE', resources: { root: '/tmp/allowed', path: 'config.json' } }), /not active/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('D broker is finite, signed, replay-safe, and rejects conflicting requests', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-root-broker-'));
  try {
    const { privateKey } = generateKeyPairSync('ed25519');
    let bindings = 0;
    const broker = new RootBrokerService({ stateRoot: root, brokerIdentity: 'broker-test', releaseCommit: 'a'.repeat(40), releaseTree: 'b'.repeat(40), signingKey: privateKey, verifyBinding: () => { bindings += 1; }, receipt: (request, resultDigest) => `receipt:${request.requestId}:${resultDigest}` });
    broker.register({ operation: 'filesystem.file.create', version: '1.0.0', execute: async (input) => ({ classification: 'SUCCEEDED', result: { echoed: input }, cleanupState: { clean: true } }) });
    const input = { root: '/tmp', path: 'x' };
    const request = { protocolVersion: '1.0.0', requestId: 'request-1', transactionId: 'rfx_test', transactionSequence: 1, fencingToken: 1, ownerPrincipalDigest: d('owner'), skillBundleDigest: d('bundle'), grantDigest: d('grant'), policyDecisionDigest: d('policy'), operation: 'filesystem.file.create', operationVersion: '1.0.0', operationInput: input, inputDigest: sha256(canonicalize(input)), deadline: future(), nonce: 'nonce-1', selectedProvider: 'HOST_ENVELOPE', credentialReferences: [] };
    const first = await broker.handle(request);
    const replay = await broker.handle(request);
    assert.equal(first.resultClassification, 'SUCCEEDED');
    assert.equal(replay.signature, first.signature);
    assert.equal(bindings, 1);
    await assert.rejects(() => broker.handle({ ...request, nonce: 'nonce-2' }), /replayed/u);
    await assert.rejects(() => broker.handle({ ...request, requestId: 'request-2', operation: 'root.shell' }), /not registered/u);
    await assert.rejects(() => broker.handle({ ...request, requestId: 'request-3', inputDigest: d('wrong') }), /input digest/u);
    assert.equal(broker.describe().arbitraryShell, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('E-G effects confine files, capture prior state, and build bounded host envelopes', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-root-effects-'));
  try {
    const allowed = join(root, 'allowed'); mkdirSync(allowed, { mode: 0o700 });
    const artifacts = [];
    const mockArtifacts = { capture: async (name, bytes, metadata) => { const artifactId = `artifact-${artifacts.length}`; artifacts.push({ artifactId, name, bytes: Buffer.from(bytes), metadata }); return { artifactId, sha256: sha256(bytes), size: bytes.length }; }, read: async (artifactId) => artifacts.find((entry) => entry.artifactId === artifactId).bytes };
    const noop = async () => ({ ok: true });
    const registry = new RootEffectRegistry({ storage: { prepareSnapshot: noop, verifySnapshot: noop, rollbackSnapshot: noop, releaseSnapshot: noop, mountCreate: noop, mountRemove: noop, mountStatus: noop }, network: { portCheck: noop, listenerVerify: noop, applyOwnedRule: noop, removeOwnedRule: noop }, artifacts: mockArtifacts });
    const request = { transactionId: 'rfx_effect', transactionSequence: 1, selectedProvider: 'HOST_ENVELOPE', inputDigest: d('input') };
    const create = registry.adapter('filesystem.file.create');
    await create.execute({ root: allowed, path: 'config.txt', data: 'first', encoding: 'utf8', mode: 0o600, expectedAbsent: true }, request);
    assert.equal(readFileSync(join(allowed, 'config.txt'), 'utf8'), 'first');
    const replaceInput = { root: allowed, path: 'config.txt', data: 'second', encoding: 'utf8', mode: 0o600, expectedSha256: sha256('first') };
    const replaced = await registry.adapter('filesystem.file.replace').execute(replaceInput, { ...request, inputDigest: sha256(canonicalize(replaceInput)) });
    assert.equal(readFileSync(join(allowed, 'config.txt'), 'utf8'), 'second');
    assert.equal(artifacts.length, 1);
    assert.equal(replaced.classification, 'SUCCEEDED');
    await assert.rejects(() => create.execute({ root: allowed, path: '../escape', data: 'x', encoding: 'utf8' }, request), /escapes|confined/u);
    symlinkSync('/tmp', join(allowed, 'link'));
    await assert.rejects(() => create.execute({ root: allowed, path: 'link/escape', data: 'x', encoding: 'utf8' }, request), /symlink/u);
    const calls = [];
    const mockSystemd = { run: async (options) => { calls.push(options); return { argv: options.argv, target: { kind: 'host' }, cwd: '/', startedAt: '', completedAt: '', durationMs: 0, exitCode: 0, signal: null, stdout: '', stderr: '', stdoutSha256: d(''), stderrSha256: d('') }; }, kill: async () => ({}), raw: async () => ({}) };
    const provider = new HostEnvelopeProvider(mockSystemd);
    await provider.execute({ executable: '/usr/bin/true', argv: [], workingDirectory: '/', user: 'nobody', group: 'nogroup', timeoutMs: 5_000, cpuQuota: '50%', memoryMax: '64M', ioWeight: '100', tasksMax: 16, readOnlyPaths: ['/usr'], readWritePaths: ['/tmp'], inaccessiblePaths: ['/home'], restrictAddressFamilies: ['AF_UNIX'], systemCallFilter: ['@system-service'], capabilityBoundingSet: [], credentialPaths: ['/tmp/credential-a', '/tmp/credential-b'] }, { ...request, transactionId: 'rfx_host', transactionSequence: 7, inputDigest: d('host') });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].properties.KillMode, 'control-group');
    assert.deepEqual(calls[0].propertyEntries, ['LoadCredential=credential-0:/tmp/credential-a', 'LoadCredential=credential-1:/tmp/credential-b']);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
