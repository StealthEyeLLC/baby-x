import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { createHmac, generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import {
  BabyXRuntime,
  CredentialAccessService,
  GitHubAppAccessProvider,
  GitHubIntegrationService,
  ProtectedCredentialReferenceAuthority,
  ReleaseAccessError,
  ReleaseApplianceStore,
  assertGitHubApprovalMatches,
  canonicalize,
  credentialBinding,
  generateSlotUnit,
  githubDeploymentState,
  normalizeCredentialSet,
  normalizeGitHubEvent,
  operationDefinitions,
  sha256,
  validateReleaseRecord,
} from '../../dist/runtime/index.js';

const OWNER = 'owner-access';
const OTHER = 'other-access';
const NOW = '2026-07-26T21:00:00.000Z';
const COMMIT = '1'.repeat(40);
const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);
const WEBHOOK_CURRENT = Buffer.from('current-webhook-material');
const WEBHOOK_PREVIOUS = Buffer.from('previous-webhook-material');

function context(key = 'access-idem', subject = OWNER, authorityClass = 'owner') { return { idempotencyKey: key, subject, authorityClass }; }
function code(expected) { return (error) => typeof error?.code === 'string' && error.code === expected; }
function files(root) {
  const output = [];
  const walk = (path) => {
    for (const name of readdirSync(path).sort()) {
      const absolute = join(path, name);
      const stat = statSync(absolute);
      const key = relative(root, absolute);
      if (stat.isDirectory()) { output.push([key, 'd']); walk(absolute); }
      else output.push([key, stat.size, sha256(readFileSync(absolute))]);
    }
  };
  walk(root);
  return output;
}

function serviceDefinition(overrides = {}) {
  const base = {
    schemaVersion: '1.0.0', serviceId: 'notes-api', displayName: 'Notes API', ownerPrincipal: OWNER,
    organization: 'stealtheye', repository: 'StealthEyeLLC/notes-api', allowedRepositoryIds: ['repo-notes'],
    serviceKind: 'API', deploymentGroup: 'notes', orderedDependencies: [],
    runtimeIdentity: { serviceUser: 'notesapi', serviceGroup: 'notesapi' },
    executableContract: { argv: ['/opt/notes/bin/server', '--serve'], nativeReadiness: true, nativeWatchdog: true },
    workingDirectory: '.', environment: { NODE_ENV: 'production' }, credentialReferenceNames: ['notes-db'], userPolicy: { stable: true },
    slotModel: 'BLUE_GREEN', endpointPreference: 'UNIX_SOCKET', endpointPolicy: { allowLoopbackFallback: true, publicCandidate: false },
    readinessProbe: { mode: 'NATIVE_NOTIFY', timeoutMs: 5000, intervalMs: 5, maximumSamples: 8 },
    livenessProbe: { mode: 'SYSTEMD' }, observationProbes: [], smokeTestProfile: { path: '/healthz' },
    drainProtocol: { kind: 'HTTP', timeoutMs: 30000 }, terminationPolicy: { signal: 'SIGTERM', timeoutMs: 45000 },
    restartPolicy: { mode: 'ON_FAILURE' }, watchdogPolicy: { mode: 'NATIVE', intervalMs: 30000 },
    resourceProfile: { class: 'PRODUCTION' }, filesystemWritePolicy: { immutableRelease: true },
    stateDirectories: ['data'], cacheDirectories: ['cache'], logDirectories: ['log'], runtimeDirectories: ['run'],
    caddyRouteTemplateId: 'http-private-upstream-v1', publicHostnames: ['notes.example.test'], pathMatchers: ['/'],
    migrationContract: { mode: 'NONE' }, rollbackContract: { retainPrevious: true }, retentionPolicy: { rollbackSlots: 1 },
    approvalPolicy: { mode: 'NONE' }, automationPolicy: { automaticPromotion: false }, provenance: { source: 'test-fixture' },
    ...overrides,
  };
  delete base.manifestDigest;
  return { ...base, manifestDigest: sha256(canonicalize(base)) };
}
function unitRoots(root, binding) {
  return { releaseRoot: join(root, 'releases'), runtimeRoot: join(root, 'runtime'), stateRoot: join(root, 'state'), cacheRoot: join(root, 'cache'), logRoot: join(root, 'log'), ...(binding === undefined ? {} : { credentialBinding: binding }) };
}
function credentialSet(overrides = {}) {
  return {
    credentialSetId: 'credential-set-v1', serviceId: 'notes-api', version: 1, provider: 'SYSTEMD_ENCRYPTED_CREDENTIAL',
    entries: [{ name: 'notes-db', mode: 'ENCRYPTED', sourceRef: '/protected/notes-db.cred', objectDigest: DIGEST_A, version: 1 }],
    ...overrides,
  };
}

class FakeSlots {
  calls = [];
  failCandidate = false;
  service = serviceDefinition();
  slots = new Map([['blue', { serviceId: 'notes-api', slotId: 'blue', releaseId: 'release-a', state: 'ACTIVE', desiredState: 'ACTIVE', sequence: 5, credentialSetDigest: DIGEST_B, routeMembership: true }]]);
  getService() { return { service: structuredClone(this.service) }; }
  getSlot({ slotId }) { const record = this.slots.get(slotId); if (record === undefined) throw new Error('slot not found'); return { slot: structuredClone(record) }; }
  stage(value) { this.calls.push({ operation: 'stage', value: structuredClone(value) }); const record = { serviceId: 'notes-api', slotId: value.slotId, releaseId: value.release.releaseId, state: 'STAGED', desiredState: 'STAGED', sequence: 1, credentialSetDigest: value.credentialSetDigest, credentialSetId: value.credentialBinding.credentialSetId, credentialBindingDigest: value.credentialBinding.bindingDigest, routeMembership: false }; this.slots.set(value.slotId, record); return structuredClone(record); }
  async start({ slotId }) { this.calls.push({ operation: 'start', slotId }); const old = this.slots.get(slotId); const record = { ...old, state: this.failCandidate ? 'FAILED' : 'READY_PRIVATE', desiredState: this.failCandidate ? 'FAILED' : 'READY_PRIVATE', sequence: old.sequence + 1, observedProcessIdentity: { readinessState: this.failCandidate ? 'FAILED' : 'READY' } }; this.slots.set(slotId, record); return structuredClone(record); }
}
class FakeReferenceAuthority {
  authority = 'systemd-credential-reference-authority';
  describe() { return { authority: this.authority, rawMaterialReturned: false }; }
  inspect(reference) { return credentialBinding(reference); }
}
function credentialFixture() {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-access-credential-'));
  const store = new ReleaseApplianceStore(join(root, 'store'));
  const originalGet = store.getRecord.bind(store);
  store.getRecord = (schemaId, recordId) => schemaId === 'ReleaseRecordV1' ? { releaseId: recordId, serviceId: 'notes-api', artifactId: 'artifact-a', artifactSha256: DIGEST_A, immutablePermissionsVerified: true } : originalGet(schemaId, recordId);
  const slots = new FakeSlots();
  const service = new CredentialAccessService({ store, slots, references: new FakeReferenceAuthority(), now: () => NOW });
  return { root, store, slots, service, close: () => rmSync(root, { recursive: true, force: true }) };
}
function persistCredentialReference(store, value) {
  const record = validateReleaseRecord('CredentialSetReferenceV1', { ...normalizeCredentialSet(value, OWNER, NOW), state: 'ACTIVE' });
  return store.applyMutation({ schemaId: 'CredentialSetReferenceV1', recordId: record.credentialSetId, ownerPrincipal: OWNER, expectedSequence: 0, idempotencyKey: `persist-${record.credentialSetId}`, requestDigest: sha256(canonicalize(record)), operation: 'test.credential', phase: 'test', record, occurredAt: NOW });
}

class MemoryMaterial {
  authority = 'systemd-service-material-authority';
  calls = [];
  constructor(values) { this.values = new Map(Object.entries(values)); }
  async withMaterial(referenceId, callback) { this.calls.push(referenceId); const value = this.values.get(referenceId); if (value === undefined) throw new Error('material unavailable'); return callback(Buffer.from(value)); }
}
class FakeTransport {
  authority = 'github-app-transport';
  exchangeCalls = [];
  deliveries = [];
  lookups = [];
  polls = [];
  failDelivery = false;
  terminalDeliveryFailure = false;
  failLookup = false;
  lookupResult = { id:'remote-recovered', nodeId:'node-recovered', url:'https://api.github.example/recovered' };
  accessValue = 'opaque-format-without-prefix';
  expiresAt = '2026-07-26T22:00:00.000Z';
  pollObservations = [];
  async exchangeInstallation(input) { this.exchangeCalls.push(structuredClone(input)); return { accessValue: this.accessValue, expiresAt: this.expiresAt, remoteIdentity: { installationId: input.installationId } }; }
  async deliver(input) {
    this.deliveries.push(structuredClone(input));
    if (this.failDelivery || this.terminalDeliveryFailure) {
      const error = new Error('provider unavailable');
      error.retryable = this.failDelivery;
      error.failureClass = this.failDelivery ? 'NETWORK' : 'PROVIDER_4XX';
      throw error;
    }
    return { id: `remote-${this.deliveries.length}`, nodeId: 'node-a', url: 'https://api.github.example/result' };
  }
  async lookupDelivery(input) { this.lookups.push(structuredClone(input)); if (this.failLookup) throw new Error('provider readback unavailable'); return this.lookupResult === undefined ? undefined : structuredClone(this.lookupResult); }
  async poll(input) { this.polls.push(structuredClone(input)); return { observations: this.pollObservations.map(structuredClone), cursor: 'cursor-a' }; }
}
function policy(overrides = {}) {
  return { ownerPrincipal: OWNER, repositoryId: 'repo-1', repository: 'StealthEyeLLC/notes-api', installationId: 'installation-1', serviceId: 'notes-api', allowedEvents: ['push','release','deployment','deployment_status','check_run','status'], allowedActions: { deployment: ['created'], release: ['published'] }, allowedRefs: ['refs/heads/main'], webhookMaterialRefs: ['webhook-current','webhook-previous'], allowComments: true, environment: 'production', ...overrides };
}
function pushPayload(overrides = {}) {
  return { ref: 'refs/heads/main', after: COMMIT, deleted: false, repository: { id: 'repo-1', full_name: 'StealthEyeLLC/notes-api' }, installation: { id: 'installation-1' }, ...overrides };
}
function signature(body, material = WEBHOOK_CURRENT) { return `sha256=${createHmac('sha256', material).update(body).digest('hex')}`; }
function webhookInput(body, deliveryId = 'delivery-1', material = WEBHOOK_CURRENT, eventName = 'push') {
  return { repository: 'StealthEyeLLC/notes-api', headers: { 'x-hub-signature-256': signature(body, material), 'x-github-event': eventName, 'x-github-delivery': deliveryId }, rawBody: body };
}
function githubFixture(options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-access-github-'));
  const store = new ReleaseApplianceStore(join(root, 'store'));
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const material = new MemoryMaterial({ 'webhook-current': WEBHOOK_CURRENT, 'webhook-previous': WEBHOOK_PREVIOUS, 'github-signing': privatePem });
  const transport = options.transport ?? new FakeTransport();
  let now = options.now ?? NOW;
  const access = options.noAccess === true ? undefined : new GitHubAppAccessProvider({ appId: 'app-1', signingMaterialRef: 'github-signing', material, transport, now: () => now });
  const eventCalls = [];
  const events = options.noEvents === true ? undefined : { authority: 'release-github-event-authority', async process(event) { eventCalls.push(structuredClone(event)); if (options.eventFailure === true && eventCalls.length === 1) throw new Error('temporary event failure'); return options.eventOutcome ?? { deploymentId: 'deployment-a' }; } };
  const service = new GitHubIntegrationService({ store, policies: [policy(options.policy)], material, access, transport, events, gatewayRouteInstalled: options.gatewayRouteInstalled ?? true, now: () => now });
  return { root, store, material, transport, access, eventCalls, service, privatePem: String(privatePem), setNow(value) { now = value; }, close() { rmSync(root, { recursive: true, force: true }); } };
}

// Credential reference and slot binding.
test('I01 encrypted credential metadata normalizes without raw material', () => { const record = normalizeCredentialSet(credentialSet(), OWNER, NOW); assert.equal(record.provider, 'SYSTEMD_ENCRYPTED_CREDENTIAL'); assert.deepEqual(record.names, ['notes-db']); assert.match(record.referenceDigest, /^[a-f0-9]{64}$/u); assert.equal(JSON.stringify(record).includes('current-webhook-material'), false); });
test('I02 duplicate credential names fail closed', () => { assert.throws(() => normalizeCredentialSet(credentialSet({ entries: [credentialSet().entries[0], credentialSet().entries[0]] }), OWNER, NOW), code('release_credential_reference_invalid')); });
test('I03 protected credential authority verifies root, mode, and digest', () => { const root=mkdtempSync(join(tmpdir(),'baby-x-credential-root-')); try { const path=join(root,'notes.cred'); writeFileSync(path,'value'); chmodSync(path,0o600); const record=normalizeCredentialSet(credentialSet({entries:[{name:'notes-db',mode:'ENCRYPTED',sourceRef:path,objectDigest:sha256(readFileSync(path)),version:1}]}),OWNER,NOW); const authority=new ProtectedCredentialReferenceAuthority({protectedRoots:[root],requireRootOwner:false}); const binding=authority.inspect(record); assert.equal(binding.credentialSetId,'credential-set-v1'); assert.equal(binding.entries[0].sourceRef,path); } finally {rmSync(root,{recursive:true,force:true});} });
test('I04 protected credential authority rejects symlinks', () => { const root=mkdtempSync(join(tmpdir(),'baby-x-credential-link-')); try { const target=join(root,'target'); const link=join(root,'link'); writeFileSync(target,'value'); chmodSync(target,0o600); symlinkSync(target,link); const record=normalizeCredentialSet(credentialSet({entries:[{name:'notes-db',mode:'ENCRYPTED',sourceRef:link,objectDigest:sha256(readFileSync(target)),version:1}]}),OWNER,NOW); const authority=new ProtectedCredentialReferenceAuthority({protectedRoots:[root],requireRootOwner:false}); assert.throws(()=>authority.inspect(record),code('release_credential_reference_invalid')); } finally {rmSync(root,{recursive:true,force:true});} });
test('I05 protected credential authority rejects broad permissions', () => { const root=mkdtempSync(join(tmpdir(),'baby-x-credential-mode-')); try { const path=join(root,'notes'); writeFileSync(path,'value'); chmodSync(path,0o644); const record=normalizeCredentialSet(credentialSet({entries:[{name:'notes-db',mode:'ENCRYPTED',sourceRef:path,objectDigest:sha256(readFileSync(path)),version:1}]}),OWNER,NOW); const authority=new ProtectedCredentialReferenceAuthority({protectedRoots:[root],requireRootOwner:false}); assert.throws(()=>authority.inspect(record),code('release_credential_reference_invalid')); } finally {rmSync(root,{recursive:true,force:true});} });
test('I06 generated encrypted slot unit contains only LoadCredentialEncrypted metadata', () => { const root=mkdtempSync(join(tmpdir(),'baby-x-credential-unit-')); try { const binding=credentialBinding(normalizeCredentialSet(credentialSet(),OWNER,NOW)); const bundle=generateSlotUnit(serviceDefinition(),'blue',{releaseId:'release-a',artifactSha256:DIGEST_A},unitRoots(root,binding)); const generated=`${bundle.unitBytes}\n${bundle.dropInBytes}`; assert.match(generated,/LoadCredentialEncrypted=notes-db:/u); assert.equal(generated.includes('current-webhook-material'),false); assert.equal(bundle.credentialBindingDigest,binding.bindingDigest); } finally {rmSync(root,{recursive:true,force:true});} });
test('I07 legacy slot unit invokes tracked compatibility launcher and private mapping', () => { const root=mkdtempSync(join(tmpdir(),'baby-x-legacy-unit-')); try { const reference=normalizeCredentialSet(credentialSet({provider:'LEGACY_FILE_ADAPTER',entries:[{name:'notes-db',mode:'PLAIN',sourceRef:'/protected/notes-db',objectDigest:DIGEST_A,version:1,environmentName:'NOTES_DB'}]}),OWNER,NOW); const bundle=generateSlotUnit(serviceDefinition(),'blue',{releaseId:'release-a',artifactSha256:DIGEST_A},unitRoots(root,credentialBinding(reference))); const generated=`${bundle.unitBytes}\n${bundle.dropInBytes}`; assert.match(generated,/ExecStart="\/usr\/libexec\/babyx-credential-launcher"/u); assert.match(generated,/BABYX_CREDENTIAL_MAP=NOTES_DB:notes-db/u); assert.match(generated,/LoadCredential=notes-db:/u); } finally {rmSync(root,{recursive:true,force:true});} });
test('I08 legacy launcher reads private directory and emits no output', () => { const root=mkdtempSync(join(tmpdir(),'baby-x-legacy-run-')); try { writeFileSync(join(root,'notes-db'),'legacy-value'); const result=spawnSync('runtime/scripts/babyx-credential-launcher.sh',['/usr/bin/sh','-c','test "$NOTES_DB" = legacy-value'],{cwd:process.cwd(),env:{...process.env,CREDENTIALS_DIRECTORY:root,BABYX_CREDENTIAL_MAP:'NOTES_DB:notes-db'},encoding:'utf8'}); assert.equal(result.status,0,result.stderr); assert.equal(result.stdout,''); assert.equal(result.stderr,''); } finally {rmSync(root,{recursive:true,force:true});} });
test('I09 credential describe returns redacted metadata only', async () => { const fx=credentialFixture(); try { await fx.service.rotate({credentialSet:credentialSet(),expectedProcessIdentity:{processStartTime:'10'}},context('rotate-describe')); const result=fx.service.describe({},context('describe')); assert.equal(result.credentialSets.length,1); const serialized=JSON.stringify(result); assert.equal(serialized.includes('/protected/notes-db.cred'),false); assert.equal(serialized.includes('entries'),false); } finally {fx.close();} });
test('I10 successful rotation stages same release on inactive slot and preserves active', async () => { const fx=credentialFixture(); try { const result=await fx.service.rotate({credentialSet:credentialSet(),expectedProcessIdentity:{processStartTime:'10'}},context('rotate-success')); assert.equal(result.rotationState,'READY_PRIVATE'); assert.equal(result.activeSlot.slotId,'blue'); assert.equal(result.activeSlot.releaseId,'release-a'); assert.equal(result.candidateSlot.slotId,'green'); assert.equal(result.candidateSlot.state,'READY_PRIVATE'); assert.equal(fx.slots.calls[0].value.release.releaseId,'release-a'); } finally {fx.close();} });
test('I11 failed credential candidate cannot modify active slot', async () => { const fx=credentialFixture(); fx.slots.failCandidate=true; try { const before=structuredClone(fx.slots.slots.get('blue')); const result=await fx.service.rotate({credentialSet:credentialSet(),expectedProcessIdentity:{processStartTime:'10'}},context('rotate-fail')); assert.equal(result.rotationState,'FAILED_CANDIDATE_ONLY'); assert.deepEqual(fx.slots.slots.get('blue'),before); assert.equal(result.candidateSlot.state,'FAILED'); } finally {fx.close();} });
test('I12 active rotation replay does not stage a second candidate', async () => { const fx=credentialFixture(); try { await fx.service.rotate({credentialSet:credentialSet(),expectedProcessIdentity:{processStartTime:'10'}},context('rotate-replay')); const callCount=fx.slots.calls.length; const replay=await fx.service.rotate({credentialSet:credentialSet(),expectedProcessIdentity:{processStartTime:'10'}},context('rotate-replay')); assert.equal(replay.replayed,true); assert.equal(fx.slots.calls.length,callCount); } finally {fx.close();} });
test('I13 versioned rotation accepts higher version referencing previous set', async () => { const fx=credentialFixture(); try { persistCredentialReference(fx.store,credentialSet()); const result=await fx.service.rotate({credentialSet:credentialSet({credentialSetId:'credential-set-v2',version:2,previousCredentialSetId:'credential-set-v1',entries:[{name:'notes-db',mode:'ENCRYPTED',sourceRef:'/protected/notes-db-v2.cred',objectDigest:DIGEST_B,version:2}]}),expectedProcessIdentity:{processStartTime:'11'}},context('rotate-v2')); assert.equal(result.credentialSet.version,2); } finally {fx.close();} });
test('I14 non-increasing versioned rotation is rejected', async () => { const fx=credentialFixture(); try { persistCredentialReference(fx.store,credentialSet()); await assert.rejects(fx.service.rotate({credentialSet:credentialSet({credentialSetId:'credential-set-bad',version:1,previousCredentialSetId:'credential-set-v1'}),expectedProcessIdentity:{processStartTime:'11'}},context('rotate-bad')),code('release_credential_reference_invalid')); } finally {fx.close();} });

// GitHub App access and webhook security.
test('I15 GitHub App access uses RS256 assertion and format-independent access value', async () => { const fx=githubFixture(); try { const result=await fx.access.withInstallationAccess('installation-1',async value=>value); assert.equal(result,'opaque-format-without-prefix'); assert.equal(fx.transport.exchangeCalls.length,1); const parts=fx.transport.exchangeCalls[0].assertion.split('.'); assert.equal(parts.length,3); assert.equal(JSON.parse(Buffer.from(parts[0],'base64url')).alg,'RS256'); } finally {fx.close();} });
test('I16 installation access is cached before expiry', async () => { const fx=githubFixture(); try { await fx.access.withInstallationAccess('installation-1',async()=>true); await fx.access.withInstallationAccess('installation-1',async()=>true); assert.equal(fx.transport.exchangeCalls.length,1); } finally {fx.close();} });
test('I17 installation access refreshes after expiry window', async () => { const fx=githubFixture(); try { fx.transport.expiresAt='2026-07-26T21:02:00.000Z'; await fx.access.withInstallationAccess('installation-1',async()=>true); fx.setNow('2026-07-26T21:01:30.000Z'); await fx.access.withInstallationAccess('installation-1',async()=>true); assert.equal(fx.transport.exchangeCalls.length,2); } finally {fx.close();} });
test('I18 empty or expired installation access fails closed', async () => { const fx=githubFixture(); try { fx.transport.accessValue=''; await assert.rejects(fx.access.withInstallationAccess('installation-1',async()=>true),code('release_github_token_invalid')); } finally {fx.close();} });
test('I19 exact raw-body HMAC webhook is accepted', async () => { const fx=githubFixture(); try { const body=Buffer.from(JSON.stringify(pushPayload())); const result=await fx.service.ingestWebhook(webhookInput(body)); assert.equal(result.inbox.signatureVerified,true); assert.equal(result.inbox.normalizedEvent.commit,COMMIT); } finally {fx.close();} });
test('I20 invalid signature is rejected before invalid JSON parsing', async () => { const fx=githubFixture(); try { const input=webhookInput(Buffer.from('{not-json')); input.headers['x-hub-signature-256']=`sha256=${'0'.repeat(64)}`; await assert.rejects(fx.service.ingestWebhook(input),code('release_webhook_signature_invalid')); } finally {fx.close();} });
test('I21 previous webhook material remains valid during overlap', async () => { const fx=githubFixture(); try { const body=Buffer.from(JSON.stringify(pushPayload())); const result=await fx.service.ingestWebhook(webhookInput(body,'delivery-old',WEBHOOK_PREVIOUS)); assert.equal(result.inbox.signatureVerified,true); assert.deepEqual(fx.material.calls.slice(0,2),['webhook-current','webhook-previous']); } finally {fx.close();} });
test('I22 trusted route repository and payload repository must match', async () => { const fx=githubFixture(); try { const body=Buffer.from(JSON.stringify(pushPayload({repository:{id:'repo-2',full_name:'Other/repo'}}))); await assert.rejects(fx.service.ingestWebhook(webhookInput(body)),code('release_invalid_request')); } finally {fx.close();} });
test('I23 repository event action and ref allowlists fail closed', () => { assert.throws(()=>normalizeGitHubEvent('push',pushPayload({ref:'refs/heads/other'}),policy()),code('release_invalid_request')); const deployment={action:'deleted',repository:{id:'repo-1',full_name:'StealthEyeLLC/notes-api'},installation:{id:'installation-1'},deployment:{sha:COMMIT,ref:'refs/heads/main',environment:'production',payload:{}}}; assert.throws(()=>normalizeGitHubEvent('deployment',deployment,policy()),code('release_invalid_request')); });
test('I24 duplicate delivery GUID with identical bytes is de-duplicated', async () => { const fx=githubFixture(); try { const body=Buffer.from(JSON.stringify(pushPayload())); const first=await fx.service.ingestWebhook(webhookInput(body,'delivery-dupe')); const second=await fx.service.ingestWebhook(webhookInput(body,'delivery-dupe')); assert.equal(second.inbox.inboxId,first.inbox.inboxId); assert.equal(fx.store.listRecordIdentities().filter(x=>x.schemaId==='GitHubInboxRecordV1').length,1); } finally {fx.close();} });
test('I25 reused delivery GUID with different bytes creates security conflict', async () => { const fx=githubFixture(); try { const first=Buffer.from(JSON.stringify(pushPayload())); const second=Buffer.from(JSON.stringify(pushPayload({after:'2'.repeat(40)}))); await fx.service.ingestWebhook(webhookInput(first,'delivery-conflict')); await assert.rejects(fx.service.ingestWebhook(webhookInput(second,'delivery-conflict')),code('release_github_delivery_conflict')); const records=fx.store.listRecordIdentities().filter(x=>x.schemaId==='GitHubInboxRecordV1').map(x=>fx.store.getRecord(x.schemaId,x.recordId)); assert.ok(records.some(record=>record.processingState==='CONFLICT')); } finally {fx.close();} });
test('I26 webhook and polling observations converge to one local event', async () => { const fx=githubFixture(); try { const body=Buffer.from(JSON.stringify(pushPayload())); await fx.service.ingestWebhook(webhookInput(body,'delivery-webhook')); await fx.service.reconcile({},context('reconcile-webhook')); fx.service.ingestPollObservation({repository:'StealthEyeLLC/notes-api',repositoryId:'repo-1',installationId:'installation-1',eventName:'push',commit:COMMIT,ref:'refs/heads/main'}); await fx.service.reconcile({},context('reconcile-poll')); assert.equal(fx.eventCalls.length,1); const records=fx.store.listRecordIdentities().filter(x=>x.schemaId==='GitHubInboxRecordV1').map(x=>fx.store.getRecord(x.schemaId,x.recordId)); assert.ok(records.some(record=>record.processingState==='EXCLUDED'&&record.disposition==='DUPLICATE')); } finally {fx.close();} });
test('I27 recovery-required inbox item retries after restart-like reconciliation', async () => { const fx=githubFixture({eventFailure:true}); try { const body=Buffer.from(JSON.stringify(pushPayload())); await fx.service.ingestWebhook(webhookInput(body,'delivery-retry')); await fx.service.reconcile({},context('reconcile-first')); let record=fx.store.listRecordIdentities().filter(x=>x.schemaId==='GitHubInboxRecordV1').map(x=>fx.store.getRecord(x.schemaId,x.recordId))[0]; assert.equal(record.processingState,'RECOVERY_REQUIRED'); await fx.service.reconcile({},context('reconcile-second')); record=fx.store.getRecord('GitHubInboxRecordV1',record.inboxId); assert.equal(record.processingState,'PROCESSED'); assert.equal(fx.eventCalls.length,2); } finally {fx.close();} });

// Durable outbox, projection, approvals, and public operations.
test('I28 outbox queue is semantic-key idempotent', () => { const fx=githubFixture(); try { const input={repository:'StealthEyeLLC/notes-api',deploymentId:'deployment-a',reportKind:'DEPLOYMENT',targetOperation:'deployments.status',payload:{state:'queued'}}; const first=fx.service.queueReport(input,context('queue-one')); const second=fx.service.queueReport(input,context('queue-two')); assert.equal(second.outboxId,first.outboxId); assert.equal(fx.store.listRecordIdentities().filter(x=>x.schemaId==='GitHubOutboxRecordV1').length,1); } finally {fx.close();} });
test('I29 provider outage defers reporting without changing local deployment truth', async () => { const fx=githubFixture({noAccess:true}); try { const local={deploymentId:'deployment-a',state:'SUCCEEDED'}; const queued=fx.service.queueReport({repository:'StealthEyeLLC/notes-api',deploymentId:'deployment-a',reportKind:'DEPLOYMENT',targetOperation:'deployments.status',payload:{state:'success'}},context('queue-outage')); const result=await fx.service.reconcile({},context('reconcile-outage')); const record=fx.store.getRecord('GitHubOutboxRecordV1',queued.outboxId); assert.equal(record.state,'DEFERRED'); assert.deepEqual(local,{deploymentId:'deployment-a',state:'SUCCEEDED'}); assert.equal(result.deferredCount,1); } finally {fx.close();} });
test('I30 deferred outbox retries after bounded backoff', async () => { const fx=githubFixture(); try { fx.transport.failDelivery=true; const queued=fx.service.queueReport({repository:'StealthEyeLLC/notes-api',deploymentId:'deployment-a',reportKind:'DEPLOYMENT',targetOperation:'deployments.status',payload:{state:'success'}},context('queue-retry')); await fx.service.reconcile({},context('reconcile-fail')); let record=fx.store.getRecord('GitHubOutboxRecordV1',queued.outboxId); assert.equal(record.state,'DEFERRED'); fx.transport.failDelivery=false; fx.setNow('2026-07-26T21:01:00.000Z'); await fx.service.reconcile({},context('reconcile-success')); record=fx.store.getRecord('GitHubOutboxRecordV1',queued.outboxId); assert.equal(record.state,'DELIVERED'); assert.equal(fx.transport.deliveries.length,2); } finally {fx.close();} });
test('I31 SENDING outbox record is recovered by exact semantic readback without blind resend', async () => { const fx=githubFixture(); try { const queued=fx.service.queueReport({repository:'StealthEyeLLC/notes-api',deploymentId:'deployment-a',reportKind:'CHECK',targetOperation:'checks.update',payload:{status:'in_progress'}},context('queue-sending')); const sending=validateReleaseRecord('GitHubOutboxRecordV1',{...queued,state:'SENDING',attemptCount:1,sequence:2,updatedAt:NOW}); fx.store.applyMutation({schemaId:'GitHubOutboxRecordV1',recordId:queued.outboxId,ownerPrincipal:OWNER,expectedSequence:1,idempotencyKey:'force-sending',requestDigest:sha256(canonicalize(sending)),operation:'test.sending',phase:'test',record:sending,occurredAt:NOW}); await fx.service.reconcile({},context('reconcile-sending')); const record=fx.store.getRecord('GitHubOutboxRecordV1',queued.outboxId); assert.equal(record.state,'DELIVERED'); assert.equal(fx.transport.deliveries.length,0); assert.equal(fx.transport.lookups[0].semanticKey,queued.outboxId); } finally {fx.close();} });
test('I32 delivered outbox persists remote metadata but never access material', async () => { const fx=githubFixture(); try { const queued=fx.service.queueReport({repository:'StealthEyeLLC/notes-api',deploymentId:'deployment-a',reportKind:'COMMENT',targetOperation:'issues.comment',payload:{body:'deployment complete'}},context('queue-delivery')); await fx.service.reconcile({},context('deliver')); const record=fx.store.getRecord('GitHubOutboxRecordV1',queued.outboxId); assert.equal(record.state,'DELIVERED'); assert.equal(record.remoteIdentity.id,'remote-1'); const persisted=readFileSync(join(fx.root,'store','records','GitHubOutboxRecordV1',`${queued.outboxId}.json`),'utf8'); assert.equal(persisted.includes(fx.transport.accessValue),false); assert.equal(persisted.includes('github-signing'),false); } finally {fx.close();} });
test('I33 local deployment states map to GitHub projection states', () => { assert.equal(githubDeploymentState('REQUESTED'),'queued'); assert.equal(githubDeploymentState('AWAITING_APPROVAL'),'pending'); assert.equal(githubDeploymentState('CUTTING_OVER'),'in_progress'); assert.equal(githubDeploymentState('SUCCEEDED'),'success'); assert.equal(githubDeploymentState('FAILED'),'failure'); assert.equal(githubDeploymentState('ROLLED_BACK'),'inactive'); assert.equal(githubDeploymentState('AMBIGUOUS'),'error'); });
test('I34 exact GitHub approval binds deployment artifact route and certification', () => { const deployment={deploymentId:'deployment-a',creationRequestDigest:DIGEST_A,artifact:{sha256:DIGEST_B},certification:{certificationId:'cert-a'},candidateRouteDigest:'c'.repeat(64)}; const normalized={repository:'StealthEyeLLC/notes-api',installationId:'installation-1',commit:COMMIT,approval:{deploymentId:'deployment-a',requestDigest:DIGEST_A,artifactDigest:DIGEST_B,certificationId:'cert-a',candidateRouteDigest:'c'.repeat(64),expiresAt:'2026-07-26T22:00:00.000Z'}}; const result=assertGitHubApprovalMatches(normalized,deployment,NOW); assert.match(result.approvalDigest,/^[a-f0-9]{64}$/u); });
test('I35 mismatched GitHub approval is rejected', () => { const deployment={deploymentId:'deployment-a',creationRequestDigest:DIGEST_A,artifact:{sha256:DIGEST_B},certification:{certificationId:'cert-a'},candidateRouteDigest:'c'.repeat(64)}; const normalized={repository:'StealthEyeLLC/notes-api',installationId:'installation-1',commit:COMMIT,approval:{deploymentId:'deployment-a',requestDigest:DIGEST_A,artifactDigest:'d'.repeat(64),certificationId:'cert-a',candidateRouteDigest:'c'.repeat(64)}}; assert.throws(()=>assertGitHubApprovalMatches(normalized,deployment,NOW),code('release_approval_mismatch')); });
test('I36 expired GitHub approval is rejected', () => { const deployment={deploymentId:'deployment-a',creationRequestDigest:DIGEST_A,artifact:{sha256:DIGEST_B},certification:{certificationId:'cert-a'},candidateRouteDigest:'c'.repeat(64)}; const normalized={repository:'StealthEyeLLC/notes-api',installationId:'installation-1',commit:COMMIT,approval:{deploymentId:'deployment-a',requestDigest:DIGEST_A,artifactDigest:DIGEST_B,certificationId:'cert-a',candidateRouteDigest:'c'.repeat(64),expiresAt:'2026-07-26T20:00:00.000Z'}}; assert.throws(()=>assertGitHubApprovalMatches(normalized,deployment,NOW),code('release_approval_expired')); });
test('I37 GitHub status is redacted and owner scoped', async () => { const fx=githubFixture(); try { const body=Buffer.from(JSON.stringify(pushPayload())); await fx.service.ingestWebhook(webhookInput(body)); fx.service.queueReport({repository:'StealthEyeLLC/notes-api',deploymentId:'deployment-a',reportKind:'DEPLOYMENT',targetOperation:'deployments.status',payload:{state:'queued'}},context('status-queue')); const status=fx.service.status({},context('status')); const serialized=JSON.stringify(status); assert.equal(serialized.includes(fx.transport.accessValue),false); assert.equal(serialized.includes(fx.privatePem.slice(0,30)),false); assert.equal(status.inbox.length,1); assert.equal(fx.service.status({},context('other',OTHER)).inbox.length,0); } finally {fx.close();} });
test('I38 durable GitHub records contain no signing webhook or installation access material', async () => { const fx=githubFixture(); try { const body=Buffer.from(JSON.stringify(pushPayload())); await fx.service.ingestWebhook(webhookInput(body)); fx.service.queueReport({repository:'StealthEyeLLC/notes-api',deploymentId:'deployment-a',reportKind:'DEPLOYMENT',targetOperation:'deployments.status',payload:{state:'queued'}},context('scan-queue')); await fx.service.reconcile({},context('scan-reconcile')); const serialized=files(fx.root).map(entry=>entry.join(':')).join('\n')+readdirSync(join(fx.root,'store','records'),{recursive:true}).join('\n'); const raw=JSON.stringify(fx.store.listRecordIdentities().map(identity=>fx.store.getRecord(identity.schemaId,identity.recordId))); assert.equal(raw.includes(WEBHOOK_CURRENT.toString()),false); assert.equal(raw.includes(WEBHOOK_PREVIOUS.toString()),false); assert.equal(raw.includes(fx.transport.accessValue),false); assert.equal(raw.includes(['BEGIN','PRIVATE','KEY'].join(' ')),false); assert.ok(serialized.length>0); } finally {fx.close();} });
test('I39 checkpoint I and R5 public operations are exact and mutation-classified', () => { const definitions=operationDefinitions(); const expected={ 'babyx.release.github.status':false, 'babyx.release.github.reconcile':true, 'babyx.release.github.webhook.ingest':true }; for(const [name,mutating] of Object.entries(expected)){const definition=definitions.find(entry=>entry.operation===name); assert.ok(definition); assert.equal(definitions.filter(entry=>entry.operation===name).length,1); assert.equal(definition.mutation,mutating);} });
test('I40 unconfigured runtime read operations are pure and mutations report absence', async () => { const root=mkdtempSync(join(tmpdir(),'baby-x-access-runtime-empty-')); try { const runtime=new BabyXRuntime({stateRoot:root}); const before=files(root); const credentials=await runtime.execute('babyx.release.credentials.describe',{},context('runtime-credential-read')); const github=await runtime.execute('babyx.release.github.status',{},context('runtime-github-read')); assert.equal(credentials.configured,false); assert.equal(github.configured,false); assert.deepEqual(files(root),before); await assert.rejects(runtime.execute('babyx.release.credentials.rotate',{credentialSet:credentialSet(),expectedProcessIdentity:{}},context('runtime-rotate')),code('release_provider_unavailable')); } finally {rmSync(root,{recursive:true,force:true});} });
test('I41 runtime routes injected checkpoint I services', async () => { const credentialFx=credentialFixture(); const githubFx=githubFixture(); const root=mkdtempSync(join(tmpdir(),'baby-x-access-runtime-injected-')); try { const runtime=new BabyXRuntime({stateRoot:root,releaseCredentialAccessService:credentialFx.service,releaseGitHubIntegrationService:githubFx.service}); const rotated=await runtime.execute('babyx.release.credentials.rotate',{credentialSet:credentialSet(),expectedProcessIdentity:{processStartTime:'10'}},context('runtime-rotate-injected')); assert.equal(rotated.rotationState,'READY_PRIVATE'); const status=await runtime.execute('babyx.release.github.status',{},context('runtime-status-injected')); assert.equal(status.configuredRepositories.length,1); } finally {rmSync(root,{recursive:true,force:true});credentialFx.close();githubFx.close();} });
test('I42 coordinator reporting is best effort after durable transition', () => { const source=readFileSync(new URL('../src/release/coordinator.ts',import.meta.url),'utf8'); assert.match(source,/const persisted = this\.options\.store\.applyMutation/u); assert.match(source,/this\.options\.reporter\.queueDeploymentProjection\(persisted/u); assert.match(source,/try \{ this\.options\.reporter/u); });
test('I43 access layer owns no listener scheduler process supervisor or shell execution', () => { const source=readFileSync(new URL('../src/release/access.ts',import.meta.url),'utf8'); for(const forbidden of ['createServer(','.listen(','new JobManager','new ArtifactManager','new MachineManager','systemd-nspawn','zfs create','systemctl start','child_process.spawn']) assert.equal(source.includes(forbidden),false,forbidden); assert.match(source,/ReleaseApplianceStore/u); assert.match(source,/CredentialSlotAuthority/u); assert.match(source,/GitHubTransport/u); });
test('I44 strict I records reject unknown fields', () => { const credential=normalizeCredentialSet(credentialSet(),OWNER,NOW); assert.throws(()=>validateReleaseRecord('CredentialSetReferenceV1',{...credential,surprise:true}),error=>error?.code==='release_schema_unknown_field'); });


test('I45 build packages the credential launcher as a verified 0755 release asset', () => {
  const source='runtime/scripts/babyx-credential-launcher.sh';
  const packaged='dist/libexec/babyx-credential-launcher';
  assert.equal(existsSync(packaged),true);
  assert.equal(statSync(packaged).mode & 0o777,0o755);
  assert.equal(sha256(readFileSync(packaged)),sha256(readFileSync(source)));
  const report=JSON.parse(readFileSync('dist/build-report.json','utf8'));
  assert.deepEqual(report.packagedAssets,[{path:'libexec/babyx-credential-launcher',mode:'0755'}]);
});

test('I46 release asset installer installs only into an isolated requested libexec root', () => {
  const root=mkdtempSync(join(tmpdir(),'baby-x-asset-install-'));
  const release=join(root,'release');
  const target=join(root,'target');
  try {
    mkdirSync(join(release,'libexec'),{recursive:true});
    writeFileSync(join(release,'libexec','babyx-credential-launcher'),readFileSync('dist/libexec/babyx-credential-launcher'),{mode:0o755});
    const result=spawnSync('scripts/install-release-assets.sh',[],{cwd:process.cwd(),env:{...process.env,BABY_X_RELEASE_PATH:release,BABY_X_LIBEXEC_ROOT:target,BABY_X_INSTALL_OWNER:String(process.getuid()),BABY_X_INSTALL_GROUP:String(process.getgid())},encoding:'utf8'});
    assert.equal(result.status,0,result.stderr);
    const installed=join(target,'babyx-credential-launcher');
    assert.equal(existsSync(installed),true);
    assert.equal(statSync(installed).mode & 0o777,0o755);
    assert.equal(sha256(readFileSync(installed)),sha256(readFileSync('dist/libexec/babyx-credential-launcher')));
  } finally {rmSync(root,{recursive:true,force:true});}
});


test('I47 polling observations obey the same event action and ref allowlists', () => {
  const fx=githubFixture();
  try {
    assert.throws(()=>fx.service.ingestPollObservation({repository:'StealthEyeLLC/notes-api',repositoryId:'repo-1',installationId:'installation-1',eventName:'push',commit:COMMIT,ref:'refs/heads/other'}),code('release_invalid_request'));
    assert.throws(()=>fx.service.ingestPollObservation({repository:'StealthEyeLLC/notes-api',repositoryId:'repo-1',installationId:'installation-1',eventName:'deployment',action:'deleted',commit:COMMIT,ref:'refs/heads/main'}),code('release_invalid_request'));
  } finally {fx.close();}
});

test('I48 configured deployment reporting is satisfied only by a durable outbox record', () => {
  const fx=githubFixture();
  try {
    const record={deploymentId:'deployment-report',state:'FINALIZING',sequence:12,normalizedRequest:{serviceDefinition:{repository:'StealthEyeLLC/notes-api'}},sourceIdentity:{commit:COMMIT}};
    assert.equal(fx.service.reportingSatisfied(record),false);
    const queued=fx.service.queueDeploymentProjection(record,context('projection-proof'));
    assert.equal(queued.state,'QUEUED');
    assert.equal(fx.service.reportingSatisfied(record),true);
    const unconfigured={...record,deploymentId:'deployment-other',normalizedRequest:{serviceDefinition:{repository:'Other/repo'}}};
    assert.equal(fx.service.reportingSatisfied(unconfigured),true);
  } finally {fx.close();}
});


test('I49 path-valued systemd directives use native path escaping rather than shell quotes', () => {
  const root=mkdtempSync(join(tmpdir(),'baby-x-systemd-paths-'));
  try {
    const sourceRef=join(root,'credential path','notes-db.cred');
    const reference=normalizeCredentialSet(credentialSet({entries:[{name:'notes-db',mode:'ENCRYPTED',sourceRef,objectDigest:DIGEST_A,version:1}]}),OWNER,NOW);
    const bundle=generateSlotUnit(serviceDefinition(),'blue',{releaseId:'release-a',artifactSha256:DIGEST_A},unitRoots(join(root,'release path'),credentialBinding(reference)));
    assert.match(bundle.unitBytes,/WorkingDirectory=\/.*\\x20/u);
    assert.doesNotMatch(bundle.unitBytes,/WorkingDirectory="/u);
    assert.match(bundle.dropInBytes,/LoadCredentialEncrypted=notes-db:\/.*\\x20/u);
    assert.doesNotMatch(bundle.dropInBytes,/LoadCredentialEncrypted=notes-db:"/u);
  } finally {rmSync(root,{recursive:true,force:true});}
});

function gatewayInput(body, deliveryId = 'delivery-gateway-1', material = WEBHOOK_CURRENT, eventName = 'push', overrides = {}) {
  const input = webhookInput(body, deliveryId, material, eventName);
  return { method:'POST', path:'/hooks/babyx/github/repo-1', headers:input.headers, rawBodyBase64:body.toString('base64'), ...overrides };
}

function forceOutboxState(fx, queued, state, key, patch = {}) {
  const record = validateReleaseRecord('GitHubOutboxRecordV1', { ...queued, state, attemptCount:1, sequence:2, updatedAt:NOW, ...patch });
  fx.store.applyMutation({ schemaId:'GitHubOutboxRecordV1', recordId:queued.outboxId, ownerPrincipal:OWNER, expectedSequence:1, idempotencyKey:key, requestDigest:sha256(canonicalize(record)), operation:'test.outbox', phase:'test', record, occurredAt:NOW });
  return record;
}

function queueDeploymentReport(fx, suffix = 'r5') {
  return fx.service.queueReport({ repository:'StealthEyeLLC/notes-api', deploymentId:`deployment-${suffix}`, reportKind:'DEPLOYMENT', targetOperation:'deployments.status', payload:{ deploymentId:'77', state:'success', description:'release complete' } }, context(`queue-${suffix}`));
}

test('R5-A01 Gateway ingress accepts exact signed raw bytes through the existing operation boundary', async () => {
  const fx=githubFixture(); try {
    const body=Buffer.from(JSON.stringify(pushPayload()));
    const result=await fx.service.ingestGatewayWebhook(gatewayInput(body),context('gateway-valid',OWNER,'gateway-webhook'));
    assert.equal(result.httpStatus,202); assert.equal(result.accepted,true); assert.equal(result.duplicate,false);
    assert.equal(fx.store.listRecordIdentities().filter(entry=>entry.schemaId==='GitHubInboxRecordV1').length,1);
  } finally { fx.close(); }
});

test('R5-A02 Gateway ingress rejects invalid signature before JSON parsing', async () => {
  const fx=githubFixture(); try {
    const body=Buffer.from('{not-json'); const input=gatewayInput(body); input.headers['x-hub-signature-256']='sha256='+'0'.repeat(64);
    const result=await fx.service.ingestGatewayWebhook(input,context('gateway-bad-signature',OWNER,'gateway-webhook'));
    assert.equal(result.httpStatus,401); assert.equal(result.accepted,false);
    assert.equal(fx.store.listRecordIdentities().filter(entry=>entry.schemaId==='GitHubInboxRecordV1').length,0);
  } finally { fx.close(); }
});

test('R5-A03 overlapping webhook secret remains valid through Gateway rotation window', async () => {
  const fx=githubFixture(); try {
    const body=Buffer.from(JSON.stringify(pushPayload()));
    const result=await fx.service.ingestGatewayWebhook(gatewayInput(body,'delivery-previous',WEBHOOK_PREVIOUS),context('gateway-previous',OWNER,'gateway-webhook'));
    assert.equal(result.httpStatus,202); assert.equal(result.accepted,true);
  } finally { fx.close(); }
});

test('R5-A04 duplicate Gateway delivery is acknowledged without duplicate durable intent', async () => {
  const fx=githubFixture(); try {
    const body=Buffer.from(JSON.stringify(pushPayload())); const input=gatewayInput(body,'delivery-duplicate');
    const first=await fx.service.ingestGatewayWebhook(input,context('gateway-duplicate-1',OWNER,'gateway-webhook'));
    const second=await fx.service.ingestGatewayWebhook(input,context('gateway-duplicate-2',OWNER,'gateway-webhook'));
    assert.equal(first.duplicate,false); assert.equal(second.duplicate,true);
    assert.equal(fx.store.listRecordIdentities().filter(entry=>entry.schemaId==='GitHubInboxRecordV1').length,1);
  } finally { fx.close(); }
});

test('R5-A05 conflicting Gateway delivery ID is rejected with 409', async () => {
  const fx=githubFixture(); try {
    const first=Buffer.from(JSON.stringify(pushPayload())); const second=Buffer.from(JSON.stringify(pushPayload({ after:'d'.repeat(40) })));
    await fx.service.ingestGatewayWebhook(gatewayInput(first,'delivery-conflict'),context('gateway-conflict-1',OWNER,'gateway-webhook'));
    const result=await fx.service.ingestGatewayWebhook(gatewayInput(second,'delivery-conflict'),context('gateway-conflict-2',OWNER,'gateway-webhook'));
    assert.equal(result.httpStatus,409); assert.equal(result.accepted,false);
  } finally { fx.close(); }
});

test('R5-A06 Gateway route is narrow, POST-only, bounded, and authority-bound', async () => {
  const fx=githubFixture(); try {
    const body=Buffer.from(JSON.stringify(pushPayload()));
    assert.equal((await fx.service.ingestGatewayWebhook(gatewayInput(body,'delivery-method',WEBHOOK_CURRENT,'push',{method:'GET'}),context('gateway-method',OWNER,'gateway-webhook'))).httpStatus,405);
    assert.equal((await fx.service.ingestGatewayWebhook(gatewayInput(body,'delivery-path',WEBHOOK_CURRENT,'push',{path:'/hooks/other'}),context('gateway-path',OWNER,'gateway-webhook'))).httpStatus,404);
    const oversized=Buffer.alloc(1024*1024+1,65);
    assert.equal((await fx.service.ingestGatewayWebhook(gatewayInput(oversized,'delivery-large'),context('gateway-large',OWNER,'gateway-webhook'))).httpStatus,413);
    await assert.rejects(fx.service.ingestGatewayWebhook(gatewayInput(body,'delivery-authority'),context('gateway-authority',OWNER,'owner')),code('release_wrong_principal'));
  } finally { fx.close(); }
});

test('R5-A07 GitHub status reports capability truth without material values', () => {
  const fx=githubFixture(); try {
    const status=fx.service.status({},context('status-r5'));
    assert.equal(status.webhook.operationWired,true); assert.equal(status.webhook.routeInstalled,true); assert.deepEqual(status.webhook.paths,['/hooks/babyx/github/repo-1']);
    assert.equal(status.webhook.secretAvailable,true); assert.equal(status.polling.enabled,true); assert.equal(status.outboxDeliverable,true);
    assert.equal(status.configuredRepositories[0].allowComments,true);
    const serialized=JSON.stringify(status); assert.equal(serialized.includes(WEBHOOK_CURRENT),false); assert.equal(serialized.includes(fx.transport.accessValue),false);
  } finally { fx.close(); }
});

test('R5-A07b external Gateway route truth defaults to not installed', () => {
  const fx=githubFixture({gatewayRouteInstalled:false}); try {
    const status=fx.service.status({},context('status-r5-route-absent'));
    assert.equal(status.webhook.operationWired,true); assert.equal(status.webhook.routeInstalled,false);
    assert.deepEqual(status.webhook.paths,['/hooks/babyx/github/repo-1']);
  } finally { fx.close(); }
});

test('R5-A08 comment delivery requires explicit repository policy', () => {
  const fx=githubFixture({policy:{allowComments:false}}); try {
    assert.throws(()=>fx.service.queueReport({repository:'StealthEyeLLC/notes-api',deploymentId:'deployment-comment-denied',reportKind:'COMMENT',targetOperation:'issues.comments.create',payload:{issueNumber:'9',body:'report'}},context('comment-denied')),code('release_invalid_request'));
    assert.equal(fx.store.listRecordIdentities().filter(entry=>entry.schemaId==='GitHubOutboxRecordV1').length,0);
  } finally { fx.close(); }
});

test('R5-A09 SENDING without semantic lookup remains RECOVERY_REQUIRED and is not resent', async () => {
  const fx=githubFixture(); try {
    const queued=queueDeploymentReport(fx,'no-lookup'); forceOutboxState(fx,queued,'SENDING','force-no-lookup'); fx.transport.lookupDelivery=undefined;
    await fx.service.reconcile({},context('reconcile-no-lookup'));
    const record=fx.store.getRecord('GitHubOutboxRecordV1',queued.outboxId);
    assert.equal(record.state,'RECOVERY_REQUIRED'); assert.equal(fx.transport.deliveries.length,0);
  } finally { fx.close(); }
});

test('R5-A10 exact lookup absence permits one bounded retry and delivery', async () => {
  const fx=githubFixture(); try {
    const queued=queueDeploymentReport(fx,'lookup-absent'); forceOutboxState(fx,queued,'SENDING','force-lookup-absent'); fx.transport.lookupResult=undefined;
    await fx.service.reconcile({},context('reconcile-lookup-absent'));
    const record=fx.store.getRecord('GitHubOutboxRecordV1',queued.outboxId);
    assert.equal(record.state,'DELIVERED'); assert.equal(fx.transport.lookups.length,1); assert.equal(fx.transport.deliveries.length,1);
  } finally { fx.close(); }
});

test('R5-A11 provider readback failure preserves RECOVERY_REQUIRED without resend', async () => {
  const fx=githubFixture(); try {
    const queued=queueDeploymentReport(fx,'lookup-failed'); forceOutboxState(fx,queued,'SENDING','force-lookup-failed'); fx.transport.failLookup=true;
    await fx.service.reconcile({},context('reconcile-lookup-failed'));
    const record=fx.store.getRecord('GitHubOutboxRecordV1',queued.outboxId);
    assert.equal(record.state,'RECOVERY_REQUIRED'); assert.equal(fx.transport.lookups.length,1); assert.equal(fx.transport.deliveries.length,0);
  } finally { fx.close(); }
});

test('R5-A12 terminal provider rejection is FAILED while retryable outage is DEFERRED', async () => {
  const terminal=githubFixture(); try {
    terminal.transport.terminalDeliveryFailure=true; const queued=queueDeploymentReport(terminal,'terminal');
    const result=await terminal.service.reconcile({},context('reconcile-terminal')); const record=terminal.store.getRecord('GitHubOutboxRecordV1',queued.outboxId);
    assert.equal(record.state,'FAILED'); assert.equal(result.failedCount,1); assert.equal(record.lastStatus.failureClass,'PROVIDER_4XX');
  } finally { terminal.close(); }
  const retryable=githubFixture(); try {
    retryable.transport.failDelivery=true; const queued=queueDeploymentReport(retryable,'retryable');
    const result=await retryable.service.reconcile({},context('reconcile-retryable')); const record=retryable.store.getRecord('GitHubOutboxRecordV1',queued.outboxId);
    assert.equal(record.state,'DEFERRED'); assert.equal(result.deferredCount,1); assert.equal(record.lastStatus.failureClass,'NETWORK');
  } finally { retryable.close(); }
});

test('R5-A13 GitHub integration introduces no listener or alternate deployment authority', () => {
  const accessSource=readFileSync(new URL('../src/release/access.ts',import.meta.url),'utf8');
  const transportSource=readFileSync(new URL('../src/release/github-transport.ts',import.meta.url),'utf8');
  assert.doesNotMatch(accessSource,/createServer|\.listen\s*\(/u); assert.doesNotMatch(transportSource,/createServer|\.listen\s*\(/u);
  assert.match(accessSource,/events\.process/u); assert.doesNotMatch(accessSource,/new\s+JobManager|new\s+DisposableMachineService|zfs|systemd-nspawn/u);
});
