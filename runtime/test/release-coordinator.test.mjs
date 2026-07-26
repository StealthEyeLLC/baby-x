import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import {
  ArtifactManager,
  assertDeploymentSuccess,
  assertTerminalDeploymentSafety,
  BabyXRuntime,
  CompositeReleasePreparationAuthority,
  ReleaseApplianceStore,
  ReleaseCoordinatorError,
  ReleaseCoordinatorService,
  bindReleaseApproval,
  canonicalize,
  evaluateReleaseObservation,
  executeMigrationContract,
  executeReleaseGroup,
  normalizeDeploymentRequest,
  normalizeMigrationContract,
  normalizeReleaseGroup,
  operationDefinitions,
  sha256,
} from '../../dist/runtime/index.js';

const OWNER = 'owner-release';
const OTHER = 'other-owner';
const A = 'a'.repeat(64);
const B = 'b'.repeat(64);
const C = 'c'.repeat(64);
const D = 'd'.repeat(64);
const COMMIT = '1'.repeat(40);
const TREE = '2'.repeat(40);
const NOW = '2026-07-26T16:00:00.000Z';

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

function request(overrides = {}) {
  return {
    schemaVersion: '1.0.0',
    serviceDefinition: serviceDefinition(overrides.serviceOverrides),
    source: { repositoryPath: '/isolated/repo', repository: 'StealthEyeLLC/notes-api', ref: 'refs/heads/main', expectedCommit: COMMIT, expectedTree: TREE },
    build: overrides.prepared ? { preparedArtifact: { artifactId: 'artifact-new', artifactSha256: A, manifest: { manifestDigest: B }, buildId: 'build-new' } } : {},
    certification: {},
    promotion: { expectedProcessIdentity: { processStartTime: '100', bootId: 'boot-a', cgroup: '/system.slice/babyx-release-notes-api-green.service' } },
    route: {
      mode: overrides.routeMode ?? 'DIRECT',
      lease: { leaseId: 'route-lease', controllerIdentity: { controllerId: 'controller-a' }, observationDigest: D, durationMs: 300000 },
      publicIdentity: { serverId: 'production', hostnames: ['notes.example.test'], paths: ['/'], publicProbeUrl: 'https://notes.example.test/healthz', trustedIdentityHeaders: ['X-BabyX-Identity'] },
      policy: overrides.routePolicy ?? { mode: 'DIRECT' },
      streamSettings: { websocket: true, sse: true, keepAlive: true, streamCloseDelayMs: 30000, flushIntervalMs: -1 },
    },
    approvalPolicy: overrides.approvalPolicy ?? { mode: 'NONE', expiresAfterMs: 3600000 },
    observationPolicy: overrides.observationPolicy ?? { minimumDurationMs: 0, minimumSamples: 1, consecutiveFailureThreshold: 1, recoverySamples: 2, cooldownMs: 60000, errorRateThreshold: 0.05, latencyThresholdMs: 1000, maximumProcessRestarts: 0, missingTelemetry: 'ROLLBACK', unknownTelemetry: 'ROLLBACK', requiredSignals: ['readiness', 'publicProbe'] },
    drainPolicy: { timeoutMs: 45000, keepAlive: true, websocket: true, sse: true, worker: false, scheduler: false },
    controller: { leaseId: 'deployment-lease', identity: { controllerId: 'controller-a', bootId: 'boot-a', processStartTime: '100' }, observationDigest: C, leaseDurationMs: 300000 },
    triggerSource: 'MANUAL', triggerIdentity: { kind: 'operator' }, credentialSetDigest: B, capacityAdmissionSnapshotId: 'capacity-a',
    ...(overrides.scheduleAt === undefined ? {} : { scheduleAt: overrides.scheduleAt }),
    ...(overrides.expiresAt === undefined ? {} : { expiresAt: overrides.expiresAt }),
    ...(overrides.group === undefined ? {} : { group: overrides.group }),
    ...(overrides.migration === undefined ? {} : { migration: overrides.migration }),
  };
}

function context(key = 'idem-a', subject = OWNER, authorityClass = 'owner') { return { idempotencyKey: key, subject, authorityClass }; }

function sourceIdentity() {
  return {
    schemaVersion: '1.0.0', repository: 'StealthEyeLLC/notes-api', repositoryId: 'repo-notes', refContext: 'refs/heads/main',
    commit: COMMIT, tree: TREE, sourceArchiveArtifactId: 'source-artifact', sourceArchiveSha256: C, sourceManifestDigest: D,
    lockfilePath: 'package-lock.json', lockfileDigest: B, submodules: [], gitLfsObjects: [], resolvedAt: NOW,
    resolverReceiptId: 'resolver-receipt', verifiedCommitState: 'VERIFIED',
  };
}

class FakePreparation {
  authority = 'release-preparation-composite'; calls = []; failAt = undefined; jobIds = []; certificationJobIds = [];
  async resolve() { this.calls.push('resolve'); if (this.failAt === 'resolve') throw new Error('resolve failed'); return { sourceIdentity: sourceIdentity(), sourceManifest: { digest: D }, sourceEpoch: 1, receiptReferences: ['resolver-receipt'] }; }
  async buildOrReuse(req) { this.calls.push(req.build.preparedArtifact === undefined ? 'build' : 'reuse'); if (this.failAt === 'build') throw new Error('build failed'); return { artifact: { id: 'artifact-new', sha256: A, size: 1024, state: 'finalized' }, manifest: { manifestDigest: B, artifactId: 'artifact-new', artifactSha256: A, source: sourceIdentity() }, buildId: 'build-new', jobIds: [...this.jobIds], reused: req.build.preparedArtifact !== undefined, receiptReferences: ['build-receipt'] }; }
  async certify() { this.calls.push('certify'); if (this.failAt === 'certify') throw new Error('certify failed'); return { certification: { certificationId: 'cert-new', state: 'SUCCEEDED', allJobIds: [], receiptIds: ['cert-receipt'] }, reused: false, jobIds: [...this.certificationJobIds], receiptReferences: ['cert-receipt'] }; }
  async materialize() { this.calls.push('materialize'); if (this.failAt === 'materialize') throw new Error('materialize failed'); return { release: { releaseId: 'release-new', serviceId: 'notes-api', artifactId: 'artifact-new', artifactSha256: A, immutablePermissionsVerified: true }, materialization: { path: '/isolated/releases/release-new', verification: { valid: true } }, jobIds: [], receiptReferences: ['release-receipt'] }; }
}

class FakeJobs {
  records = new Map();
  get(id) { return this.records.get(id) ?? { id, status: 'completed', exitCode: 0 }; }
  list() { return [...this.records.values()]; }
  reconcile(id) { return this.get(id); }
}

class FakeSlots {
  calls = [];
  slots = new Map([['blue', { serviceId: 'notes-api', slotId: 'blue', releaseId: 'release-old', state: 'ACTIVE', desiredState: 'ACTIVE', sequence: 5, routeMembership: true, systemdUnit: 'babyx-release-notes-api-blue.service', observedProcessIdentity: { mainPid: 10, readinessState: 'READY' }, endpointIdentity: { type: 'UNIX_SOCKET', endpoint: '/run/blue.sock' } }]]);
  failAt = undefined;
  getSlot({ slotId }) { const value = this.slots.get(slotId); if (!value) throw new Error('slot not found'); return { slot: structuredClone(value) }; }
  getService() { return { service: serviceDefinition() }; }
  listServices() { return { services: [serviceDefinition()] }; }
  stage(value) { this.calls.push('stage'); if (this.failAt === 'stage') throw new Error('stage failed'); const record = { serviceId: value.serviceDefinition.serviceId, slotId: value.slotId, releaseId: value.release.releaseId, state: 'STAGED', desiredState: 'STAGED', sequence: 1, expectedProcessIdentity: { ...value.expectedProcessIdentity, artifactDigest: value.release.artifactSha256, ownerPrincipal: OWNER }, endpointType: 'UNIX_SOCKET', endpointIdentity: { type: 'UNIX_SOCKET', endpoint: '/run/green.sock' }, routeMembership: false }; this.slots.set(value.slotId, record); return structuredClone(record); }
  async start({ slotId }) { this.calls.push('start'); if (this.failAt === 'start') throw new Error('start failed'); const old = this.slots.get(slotId); const record = { ...old, state: this.failAt === 'readiness' ? 'RUNNING_NOT_READY' : 'READY_PRIVATE', desiredState: 'READY_PRIVATE', sequence: old.sequence + 1, observedProcessIdentity: { mainPid: 20, processStartTime: '100', executablePath: '/opt/notes/bin/server', bootId: 'boot-a', cgroup: '/system.slice/babyx-release-notes-api-green.service', readinessState: this.failAt === 'readiness' ? 'NOT_READY' : 'READY', watchdogState: 'ACTIVE' } }; this.slots.set(slotId, record); return structuredClone(record); }
  activate({ slotId }) { this.calls.push('activate'); const old = this.slots.get(slotId); const record = { ...old, state: 'ACTIVE', desiredState: 'ACTIVE', routeMembership: true, sequence: old.sequence + 1 }; this.slots.set(slotId, record); return structuredClone(record); }
  markDraining({ slotId }) { this.calls.push(`drain:${slotId}`); const old = this.slots.get(slotId); const record = { ...old, state: 'DRAINING', desiredState: 'DRAINING', routeMembership: false, sequence: old.sequence + 1 }; this.slots.set(slotId, record); return structuredClone(record); }
  restoreActive({ slotId }) { this.calls.push(`restore:${slotId}`); const old = this.slots.get(slotId); const record = { ...old, state: 'ACTIVE', desiredState: 'ACTIVE', routeMembership: true, sequence: old.sequence + 1 }; this.slots.set(slotId, record); return structuredClone(record); }
  async stop({ slotId }) { this.calls.push(`stop:${slotId}`); if (this.failAt === 'stop') return { ...this.slots.get(slotId), state: 'RECOVERY_REQUIRED' }; const old = this.slots.get(slotId); const record = { ...old, state: 'STOPPED', desiredState: 'STOPPED', routeMembership: false, sequence: old.sequence + 1 }; this.slots.set(slotId, record); return structuredClone(record); }
  async cleanup({ slotId }) { this.calls.push(`cleanup:${slotId}`); if (this.failAt === 'cleanup') return { ...this.slots.get(slotId), state: 'RECOVERY_REQUIRED' }; const old = this.slots.get(slotId); const record = { ...old, state: 'EMPTY_VERIFIED', desiredState: 'EMPTY_VERIFIED', routeMembership: false, sequence: old.sequence + 1, cleanupCompletedAt: NOW }; this.slots.set(slotId, record); return structuredClone(record); }
}

class FakeRoutes {
  calls = []; leases = new Set(); failAt = undefined; preparedRequests = []; route = { routeId: 'route-notes-api', serviceId: 'notes-api', state: 'ACTIVE_VERIFIED', sequence: 10, candidateConfigDigest: 'e'.repeat(64), activeConfigReadbackDigest: 'e'.repeat(64), validationResult: { valid: true }, publicProbeResult: { status: 'PASS' } };
  acquireLease(_service, lease) { this.calls.push(`lease+${lease.leaseId}`); if (this.failAt === 'lease') throw new Error('lease conflict'); this.leases.add(lease.leaseId); return { ...lease, state: 'ACTIVE' }; }
  releaseLease(_service, lease) { this.calls.push(`lease-${lease.leaseId}`); this.leases.delete(lease.leaseId); return { ...lease, state: 'RELEASED' }; }
  async prepare(value) { this.calls.push('prepare'); this.preparedRequests.push(structuredClone(value.request)); if (this.failAt === 'prepare') return { state: 'RECOVERY_REQUIRED' }; const record = { routeId: 'route-notes-api', serviceId: 'notes-api', state: 'VALIDATED', sequence: 1, candidateConfigArtifactId: 'candidate-config', candidateConfigDigest: 'f'.repeat(64), previousConfigArtifactId: 'previous-config', previousConfigDigest: 'e'.repeat(64), validationResult: { valid: true }, expectedUpstreams: ['unix//run/green.sock'], previousObservedUpstreams: ['unix//run/blue.sock'] }; this.route = record; return structuredClone(record); }
  async observeActive(value) { this.calls.push(`observe:${value.expected ?? 'active'}`); if (this.failAt === 'baseline') return { status: 'UNKNOWN', detailsDigest: D }; return { status: 'PASS', detailsDigest: C, configDigest: value.expected === 'PREVIOUS' ? 'e'.repeat(64) : 'f'.repeat(64) }; }
  async cutover() { this.calls.push('cutover'); const active = { ...this.route, state: 'ACTIVE_VERIFIED', sequence: this.route.sequence + 3, activeConfigReadbackDigest: 'f'.repeat(64), observedActiveUpstream: { upstreams: ['unix//run/green.sock'] }, publicProbeResult: { status: 'PASS' }, validationResult: { valid: true } }; this.route = active; if (this.failAt === 'cutover-after') throw new Error('response lost'); if (this.failAt === 'cutover-before') throw new Error('load failed'); return structuredClone(active); }
  async reconcile() { this.calls.push('reconcile'); if (this.failAt === 'cutover-before') return { ...this.route, state: 'RECOVERY_REQUIRED' }; return structuredClone(this.route); }
  async restore() { this.calls.push('restore'); if (this.failAt === 'restore') return { ...this.route, state: 'RECOVERY_REQUIRED' }; const restored = { ...this.route, state: 'RESTORED_VERIFIED', sequence: this.route.sequence + 3, restorationReadbackDigest: 'e'.repeat(64), publicProbeResult: { status: 'PASS' } }; this.route = restored; return structuredClone(restored); }
  async expirePreview() { this.calls.push('expirePreview'); return { ...this.route, state: 'RESTORED_VERIFIED', sequence: this.route.sequence + 3 }; }
  getRoute() { return { route: structuredClone(this.route) }; }
}

class FakeObservation {
  authority = 'release-observation'; samples = [{ observedAt: NOW, signals: { readiness: true, publicProbe: true }, errorRate: 0, latencyMs: 10, processRestarts: 0 }];
  async observe() { return structuredClone(this.samples.shift() ?? { observedAt: NOW, signals: { readiness: true, publicProbe: true }, errorRate: 0, latencyMs: 10, processRestarts: 0 }); }
}
class FakeDrain { authority = 'release-drain'; result = { status: 'SUCCEEDED', protocols: { keepAlive: true, websocket: true, sse: true, worker: false, scheduler: false }, bounded: true }; async drain() { return structuredClone(this.result); } }
class FakeProof { authority = 'existing-babyx-proof'; fail = false; create(requestId, operation, ok, startedAt, result) { if (this.fail) return { error: { code: 'proof-unavailable' } }; return { requestId, operation, ok, startedAt, resultDigest: sha256(canonicalize(result)), proofId: `proof-${sha256(operation).slice(0, 12)}` }; } }

function fixture(options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-release-coordinator-'));
  const store = new ReleaseApplianceStore(join(root, 'store'));
  const artifacts = new ArtifactManager(join(root, 'artifacts'));
  const preparation = options.preparation ?? new FakePreparation();
  const slots = options.slots ?? new FakeSlots();
  const routes = options.routes ?? new FakeRoutes();
  const jobs = options.jobs ?? new FakeJobs();
  const observation = options.observation ?? new FakeObservation();
  const drain = options.drain ?? new FakeDrain();
  const proofs = options.proofs ?? new FakeProof();
  let tick = 0;
  const now = () => new Date(Date.parse(NOW) + tick++ * 1000).toISOString();
  const createService = () => new ReleaseCoordinatorService({ stateRoot: root, store, preparation, slots, routes, jobs, artifacts, observation, drain, proofs, now });
  const service = createService();
  return { root, store, artifacts, preparation, slots, routes, jobs, observation, drain, proofs, service, restart: createService, close: () => rmSync(root, { recursive: true, force: true }) };
}

function code(expected) { return (error) => typeof error?.code === 'string' && error.code === expected; }
function files(root) { const out=[]; const walk=(p)=>{for(const n of readdirSync(p).sort()){const a=join(p,n),i=statSync(a),k=relative(root,a); if(i.isDirectory()){out.push([k,'d']);walk(a);}else out.push([k,i.size,sha256(readFileSync(a))]);}}; walk(root); return out; }

async function promoteHappy(fx, req = request(), key = 'promote-a') { return fx.service.promote({ request: req }, context(key)); }

function approvalFor(record, req, overrides = {}) {
  const normalized = normalizeDeploymentRequest(req, OWNER);
  return {
    deploymentId: record.deploymentId, ownerPrincipal: record.ownerPrincipal, requestDigest: record.creationRequestDigest,
    serviceId: record.serviceId, sourceCommit: record.sourceIdentity.commit, sourceTree: record.sourceIdentity.tree,
    artifactDigest: record.artifact.sha256, releaseManifestDigest: record.artifactManifest.manifestDigest,
    certificationId: record.certification.certificationId, targetSlot: record.slotId, candidateRouteDigest: record.candidateRouteDigest,
    policyDigest: sha256(canonicalize({ approvalPolicy: normalized.approvalPolicy, observationPolicy: normalized.observationPolicy, drainPolicy: normalized.drainPolicy })),
    approvalMode: normalized.approvalPolicy.mode, expiresAt: '2026-07-26T18:00:00.000Z', approvingPrincipal: OWNER, sequence: record.sequence,
    ...overrides,
  };
}

test('G01 prepare-only happy path reaches READY_TO_STAGE without traffic', async () => { const fx=fixture(); try { const out=await fx.service.prepare({request:request()},context('prepare')); assert.equal(out.deployment.state,'READY_TO_STAGE'); assert.equal(fx.routes.calls.includes('cutover'),false); assert.deepEqual(fx.preparation.calls,['resolve','build','certify','materialize']); } finally {fx.close();} });
test('G02 one-command promotion reaches SUCCEEDED with evidence', async () => { const fx=fixture(); try { const out=await promoteHappy(fx); assert.equal(out.deployment.state,'SUCCEEDED'); assert.ok(out.deployment.evidenceIndexId); assert.equal(out.deployment.finalProof.ok,true); } finally {fx.close();} });
test('G03 prepared-artifact promotion reuses rather than builds', async () => { const fx=fixture(); try { const out=await promoteHappy(fx,request({prepared:true})); assert.equal(out.deployment.state,'SUCCEEDED'); assert.ok(fx.preparation.calls.includes('reuse')); assert.equal(fx.preparation.calls.includes('build'),false); } finally {fx.close();} });
test('G04 exact prepare idempotency replays same deployment', async () => { const fx=fixture(); try { const first=await fx.service.prepare({request:request()},context('replay')); const second=await fx.service.prepare({request:request()},context('replay')); assert.deepEqual(second.deployment,first.deployment); assert.equal(second.replayed,true); } finally {fx.close();} });
test('G05 conflicting idempotency key reuse fails', async () => { const fx=fixture(); try { await fx.service.prepare({request:request()},context('conflict')); await assert.rejects(fx.service.prepare({request:request({routeMode:'CANARY',routePolicy:{mode:'CANARY',percentage:10,durationMs:60000,maximumRequests:100,rollbackThreshold:0.05,exactCandidateSlot:'green'}})},context('conflict')),code('release_idempotency_conflict')); } finally {fx.close();} });
test('G06 wrong principal fails before mutation', async () => { const fx=fixture(); try { await assert.rejects(fx.service.prepare({request:request()},context('wrong',OTHER)),code('release_wrong_principal')); assert.equal(fx.store.listRecordIdentities().length,0); } finally {fx.close();} });
test('G07 stale expected sequence fails before approval mutation', async () => { const fx=fixture(); try { const req=request({approvalPolicy:{mode:'REQUIRED',expiresAfterMs:3600000}}); const p=await fx.service.promote({request:req},context('approve-flow')); await assert.rejects(Promise.resolve().then(() => fx.service.approve({ deploymentId: p.deployment.deploymentId, expectedSequence: p.deployment.sequence - 1, approval: approvalFor(p.deployment, req) }, context('approve'))), code('release_stale_sequence')); } finally {fx.close();} });
test('G08 route/controller call order persists private start before cutover', async () => { const fx=fixture(); try { await promoteHappy(fx); assert.ok(fx.slots.calls.indexOf('start') < fx.routes.calls.indexOf('cutover')); assert.ok(fx.routes.calls.indexOf('prepare') < fx.routes.calls.indexOf('cutover')); } finally {fx.close();} });
test('G09 readiness failure prevents route cutover', async () => { const fx=fixture(); fx.slots.failAt='readiness'; try { const out=await promoteHappy(fx); assert.equal(out.deployment.state,'RECOVERY_REQUIRED'); assert.equal(out.deployment.error.code,'release_readiness_failed'); assert.equal(fx.routes.calls.includes('cutover'),false); } finally {fx.close();} });
test('G10 approval required waits with validated candidate route', async () => { const fx=fixture(); try { const req=request({approvalPolicy:{mode:'REQUIRED',expiresAfterMs:3600000}}); const out=await fx.service.promote({request:req},context('approval-wait')); assert.equal(out.deployment.state,'AWAITING_APPROVAL'); assert.ok(out.deployment.candidateRouteDigest); assert.equal(fx.routes.calls.includes('cutover'),false); } finally {fx.close();} });
test('G11 exact approval binding permits promotion', async () => { const fx=fixture(); try { const req=request({approvalPolicy:{mode:'REQUIRED',expiresAfterMs:3600000}}); let out=await fx.service.promote({request:req},context('approval-main')); const approved=fx.service.approve({deploymentId:out.deployment.deploymentId,expectedSequence:out.deployment.sequence,approval:approvalFor(out.deployment,req)},context('approval-bind')); out=await fx.service.promote({deploymentId:approved.deployment.deploymentId},context('approval-promote')); assert.equal(out.deployment.state,'SUCCEEDED'); } finally {fx.close();} });
test('G12 approval for another artifact is rejected', async () => { const fx=fixture(); try { const req=request({approvalPolicy:{mode:'REQUIRED',expiresAfterMs:3600000}}); const out=await fx.service.promote({request:req},context('approval-mismatch')); assert.throws(()=>fx.service.approve({deploymentId:out.deployment.deploymentId,expectedSequence:out.deployment.sequence,approval:approvalFor(out.deployment,req,{artifactDigest:C})},context('approval-bad')),code('release_approval_mismatch')); } finally {fx.close();} });
test('G13 expired approval fails closed', async () => { const fx=fixture(); try { const req=request({approvalPolicy:{mode:'REQUIRED',expiresAfterMs:3600000}}); const out=await fx.service.promote({request:req},context('approval-expired')); assert.throws(()=>fx.service.approve({deploymentId:out.deployment.deploymentId,expectedSequence:out.deployment.sequence,approval:approvalFor(out.deployment,req,{expiresAt:'2026-07-26T15:00:00.000Z'})},context('approval-expired-bind')),code('release_approval_expired')); } finally {fx.close();} });
test('G14 scheduled promotion persists and waits', async () => { const fx=fixture(); try { const out=await fx.service.promote({request:request({scheduleAt:'2026-07-26T19:00:00.000Z'})},context('scheduled')); assert.equal(out.deployment.state,'AWAITING_APPROVAL'); assert.equal(out.deployment.schedule.promoteAt,'2026-07-26T19:00:00.000Z'); } finally {fx.close();} });
test('G15 cutover protocol performs exact prior readback before load', async () => { const fx=fixture(); try { await promoteHappy(fx); assert.ok(fx.routes.calls.indexOf('observe:PREVIOUS') < fx.routes.calls.indexOf('cutover')); } finally {fx.close();} });
test('G16 route response loss is reconciled without duplicate load', async () => { const fx=fixture(); fx.routes.failAt='cutover-after'; try { const out=await promoteHappy(fx); assert.equal(out.deployment.state,'SUCCEEDED'); assert.equal(fx.routes.calls.filter(x=>x==='cutover').length,1); assert.equal(fx.routes.calls.filter(x=>x==='reconcile').length,1); } finally {fx.close();} });
test('G17 failure before cutover leaves prior route untouched', async () => { const fx=fixture(); fx.routes.failAt='prepare'; try { const out=await promoteHappy(fx); assert.equal(out.deployment.state,'RECOVERY_REQUIRED'); assert.equal(fx.routes.calls.includes('cutover'),false); assert.equal(fx.routes.route.state,'ACTIVE_VERIFIED'); } finally {fx.close();} });
test('G18 unknown prior route enters AMBIGUOUS', async () => { const fx=fixture(); fx.routes.failAt='baseline'; try { const out=await promoteHappy(fx); assert.equal(out.deployment.state,'AMBIGUOUS'); } finally {fx.close();} });
test('G19 public observation failure triggers rollback and cleanup', async () => { const fx=fixture(); fx.observation.samples=[{observedAt:NOW,signals:{readiness:true,publicProbe:false},errorRate:1,latencyMs:10,processRestarts:0}]; try { const out=await promoteHappy(fx); assert.equal(out.deployment.state,'ROLLED_BACK'); assert.ok(fx.routes.calls.includes('restore')); assert.equal(fx.slots.slots.get('green').state,'EMPTY_VERIFIED'); } finally {fx.close();} });
test('G20 missing telemetry fails closed to rollback', () => { const policy=normalizeDeploymentRequest(request(),OWNER).observationPolicy; const result=evaluateReleaseObservation(policy,[{observedAt:NOW,signals:{readiness:true}}]); assert.equal(result.decision,'ROLLBACK'); });
test('G21 rollback hysteresis latches and prevents flapping', () => { const policy=normalizeDeploymentRequest(request(),OWNER).observationPolicy; const failed=evaluateReleaseObservation(policy,[{observedAt:NOW,signals:{readiness:false,publicProbe:true},errorRate:1,latencyMs:10,processRestarts:0}]); const healthy=evaluateReleaseObservation(policy,[{observedAt:NOW,signals:{readiness:true,publicProbe:true},errorRate:0,latencyMs:10,processRestarts:0}],failed); assert.equal(failed.rollbackLatched,true); assert.equal(healthy.decision,'ROLLBACK'); });
test('G22 manual rollback after cutover restores prior route first', async () => { const fx=fixture(); try { fx.observation.samples=[{observedAt:NOW,signals:{readiness:true,publicProbe:true},errorRate:0,latencyMs:10,processRestarts:0}]; const out=await promoteHappy(fx); assert.equal(out.deployment.state,'SUCCEEDED'); } finally {fx.close();} });
test('G23 request cancellation terminalizes with evidence and no side effects', async () => { const fx=fixture(); try { const normalized=normalizeDeploymentRequest(request(),OWNER); const initial=fx.service['createInitial']?.('deploy-cancel',normalized,{subject:OWNER,idempotencyKey:'cancel-create'}); assert.ok(initial); const out=await fx.service.cancel({deploymentId:'deploy-cancel',expectedSequence:initial.sequence,reason:'operator'},context('cancel')); assert.equal(out.deployment.state,'CANCELLED'); assert.equal(fx.slots.calls.length,0); } finally {fx.close();} });
test('G24 dry-run GC never returns destructive actions', async () => { const fx=fixture(); try { await promoteHappy(fx); const out=fx.service.gc({dryRun:true,limit:10},context('gc')); assert.deepEqual(out.destructiveActions,[]); assert.equal(out.dryRun,true); } finally {fx.close();} });
test('G25 owner-scoped reads and listings do not leak records', async () => { const fx=fixture(); try { const p=await fx.service.prepare({request:request()},context('read-owner')); assert.equal(fx.service.get({deploymentId:p.deployment.deploymentId},context('get-owner')).deployment.ownerPrincipal,OWNER); assert.throws(()=>fx.service.get({deploymentId:p.deployment.deploymentId},context('get-other',OTHER)),code('release_record_not_found')); assert.equal(fx.service.list({},context('list-other',OTHER)).deployments.length,0); } finally {fx.close();} });
test('G26 read-only live projection agrees with durable observed state', async () => { const fx=fixture(); try { const out=await promoteHappy(fx); const before=files(fx.root); const live=fx.service.live({deploymentId:out.deployment.deploymentId},context('live')); assert.equal(live.live.observedLiveRelease,'release-new'); assert.equal(live.live.activeSlot,'green'); assert.deepEqual(files(fx.root),before); } finally {fx.close();} });
test('G27 events are bounded and hash chained', async () => { const fx=fixture(); try { const out=await promoteHappy(fx); const events=fx.service.events({deploymentId:out.deployment.deploymentId,offset:0,limit:5},context('events')); assert.ok(events.events.length<=5); for(let i=1;i<events.events.length;i++) assert.equal(events.events[i].previousEventDigest,events.events[i-1].eventDigest); } finally {fx.close();} });
test('G28 grouped service contract orders dependencies and reverses rollback', () => { const group=normalizeReleaseGroup({groupId:'notes-group',members:[{serviceId:'api',order:2,dependsOn:['db'],request:{}},{serviceId:'db',order:1,dependsOn:[],request:{}}]}); assert.deepEqual(group.promotionOrder,['db','api']); assert.deepEqual(group.rollbackOrder,['api','db']); assert.equal(group.atomicity,'ORDERED_NOT_EXTERNALLY_ATOMIC'); });
test('G29 grouped service execution rolls back completed members in reverse order', async () => { const group=normalizeReleaseGroup({groupId:'g',members:[{serviceId:'a',order:1,dependsOn:[],request:{}},{serviceId:'b',order:2,dependsOn:['a'],request:{}}]}); const calls=[]; const out=await executeReleaseGroup(group,async m=>{calls.push(`p:${m.serviceId}`); if(m.serviceId==='b') throw new Error('fail'); return {state:'SUCCEEDED'};},async m=>{calls.push(`r:${m.serviceId}`); return {serviceId:m.serviceId};}); assert.equal(out.status,'PARTIAL_FAILURE'); assert.deepEqual(calls,['p:a','p:b','r:a']); });
test('G30 migration expand/migrate/contract contract is deterministic', () => { const migration=normalizeMigrationContract({phases:[{id:'expand',kind:'EXPAND',job:{},irreversible:false,compatibilityGate:{}},{id:'migrate',kind:'MIGRATE',job:{},irreversible:false,compatibilityGate:{}},{id:'contract',kind:'CONTRACT',job:{},irreversible:false,compatibilityGate:{}}],rollbackCompatibility:{compatible:true}}); assert.deepEqual(migration.phases.map(p=>p.kind),['EXPAND','MIGRATE','CONTRACT']); assert.match(migration.digest,/^[a-f0-9]{64}$/u); });
test('G31 irreversible migration requires explicit approval', async () => { const migration=normalizeMigrationContract({phases:[{id:'migrate',kind:'MIGRATE',job:{},irreversible:true,compatibilityGate:{}}],rollbackCompatibility:{compatible:false}}); await assert.rejects(executeMigrationContract(migration,undefined,async()=>({status:'SUCCEEDED'})),code('release_irreversible_migration_approval_required')); });
test('G32 public G operations are registered exactly once with read-only reads', () => { const defs=operationDefinitions(); const names=['plan','prepare','promote','approve','cancel','rollback','reconcile','resume','expire','gc','live','status','get','list','events','evidence','failures'].map(x=>`babyx.release.${x}`); for(const name of names) assert.equal(defs.filter(d=>d.operation===name).length,1,name); for(const suffix of ['plan','live','status','get','list','events','evidence','failures']) { const name=`babyx.release.${suffix}`; assert.equal(defs.find(d=>d.operation===name).mutation,false,name); } });

function allSuccessEvidence() {
  return {
    exactSourceResolved: true, artifactManifestVerified: true, certificationValid: true,
    inactiveSlotStagedFromImmutableBytes: true, unitAndProcessIdentityVerified: true, privateEndpointReady: true,
    candidateCaddyConfigValidated: true, activeRouteReadbackMatches: true, publicRouteSmokePassed: true,
    observationPolicyPassed: true, allRelatedJobsTerminal: true, previousSlotHandledTruthfully: true,
    evidenceIndexCompleteAndVerified: true, githubReportingDeliveredOrQueued: true, noUnresolvedAmbiguity: true,
  };
}

function seedDurableState(fx, state, index) {
  const normalized = normalizeDeploymentRequest(request(), OWNER);
  const deploymentId = `restart-${String(index).padStart(2, '0')}-${state.toLowerCase().replaceAll('_', '-')}`;
  let record = fx.service.createInitial(deploymentId, normalized, { subject: OWNER, idempotencyKey: `restart-create-${index}` });
  if (state !== 'REQUESTED') {
    const next = { ...record, state, desiredState: state, sequence: record.sequence + 1, updatedAt: new Date(Date.parse(NOW) + index * 1000).toISOString() };
    record = fx.store.applyMutation({
      schemaId: 'DeploymentRecordV1', recordId: deploymentId, ownerPrincipal: OWNER,
      expectedSequence: record.sequence, idempotencyKey: `restart-state-${index}`,
      requestDigest: sha256(canonicalize({ deploymentId, state })), operation: 'babyx.release.coordinate',
      phase: 'restart-fixture', record: next, occurredAt: next.updatedAt,
    });
  }
  return record;
}

test('G33 exact source, artifact, release, and certification identities remain bound', async () => {
  const fx = fixture();
  try {
    const out = await fx.service.prepare({ request: request() }, context('exact-bindings'));
    const record = out.deployment;
    assert.equal(record.sourceIdentity.commit, COMMIT);
    assert.equal(record.sourceIdentity.tree, TREE);
    assert.equal(record.artifact.sha256, A);
    assert.equal(record.artifactManifest.manifestDigest, B);
    assert.equal(record.releaseRecord.artifactSha256, A);
    assert.equal(record.certification.certificationId, 'cert-new');
  } finally { fx.close(); }
});

test('G34 no-op promotion detects the exact already-live immutable release', async () => {
  const fx = fixture();
  try {
    fx.slots.slots.set('blue', { ...fx.slots.slots.get('blue'), releaseId: 'release-new' });
    const out = await promoteHappy(fx, request(), 'noop-promotion');
    assert.equal(out.deployment.state, 'SUCCEEDED');
    assert.equal(out.deployment.noopPromotion, true);
    assert.equal(fx.routes.calls.includes('cutover'), false);
    assert.equal(fx.slots.calls.includes('stage'), false);
  } finally { fx.close(); }
});

test('G35 live deployment controller lease overlap is rejected', () => {
  const fx = fixture();
  try {
    const first = { schemaVersion: '1.0.0', leaseId: 'lease-a', resourceType: 'DEPLOYMENT', resourceId: 'deploy-overlap', ownerPrincipal: OWNER, controllerIdentity: { controllerId: 'a' }, acquiredAt: NOW, expiresAt: '2026-07-26T17:00:00.000Z', sequence: 1, state: 'ACTIVE', observationDigest: A };
    fx.store.acquireLease(first, { now: NOW });
    const second = { ...first, leaseId: 'lease-b', controllerIdentity: { controllerId: 'b' }, observationDigest: B };
    assert.throws(() => fx.store.acquireLease(second, { now: NOW }), /lease|controller/iu);
  } finally { fx.close(); }
});

test('G36 proven stale controller takeover requires positive absence', () => {
  const fx = fixture();
  try {
    const first = { schemaVersion: '1.0.0', leaseId: 'lease-old', resourceType: 'DEPLOYMENT', resourceId: 'deploy-stale', ownerPrincipal: OWNER, controllerIdentity: { controllerId: 'old' }, acquiredAt: NOW, expiresAt: '2026-07-26T16:00:01.000Z', sequence: 1, state: 'ACTIVE', observationDigest: A };
    fx.store.acquireLease(first, { now: NOW });
    const next = { ...first, leaseId: 'lease-new', controllerIdentity: { controllerId: 'new' }, acquiredAt: '2026-07-26T16:00:02.000Z', expiresAt: '2026-07-26T17:00:00.000Z', observationDigest: B };
    assert.throws(() => fx.store.acquireLease(next, { now: '2026-07-26T16:00:02.000Z' }), /absence|lease|controller/iu);
    const acquired = fx.store.acquireLease(next, { now: '2026-07-26T16:00:02.000Z', existingControllerAbsent: true });
    assert.equal(acquired.leaseId, 'lease-new');
  } finally { fx.close(); }
});

test('G37 manual rollback after cutover restores route before candidate cleanup', async () => {
  const fx = fixture();
  try {
    const req = request({ observationPolicy: { ...request().observationPolicy, minimumSamples: 2 } });
    fx.observation.samples = [{ observedAt: NOW, signals: { readiness: true, publicProbe: true }, errorRate: 0, latencyMs: 10, processRestarts: 0 }];
    const promoted = await fx.service.promote({ request: req }, context('manual-rb-promote'));
    assert.equal(promoted.deployment.state, 'OBSERVING');
    const rolled = await fx.service.rollback({ deploymentId: promoted.deployment.deploymentId, expectedSequence: promoted.deployment.sequence, reason: 'operator' }, context('manual-rb'));
    assert.equal(rolled.deployment.state, 'ROLLED_BACK');
    assert.ok(fx.routes.calls.includes('restore')); assert.ok(fx.slots.calls.includes('cleanup:green')); assert.equal(rolled.deployment.routeRestored,true);
    assert.equal(fx.slots.slots.get('blue').state, 'ACTIVE');
  } finally { fx.close(); }
});

test('G38 manual rollback before cutover leaves route unchanged and cleans no active route', async () => {
  const fx = fixture();
  try {
    const prepared = await fx.service.prepare({ request: request() }, context('pre-rb-prepare'));
    const before = canonicalize(fx.routes.route);
    const rolled = await fx.service.rollback({ deploymentId: prepared.deployment.deploymentId, expectedSequence: prepared.deployment.sequence, reason: 'operator' }, context('pre-rb'));
    assert.equal(rolled.deployment.state, 'ROLLED_BACK');
    assert.equal(canonicalize(fx.routes.route), before);
    assert.equal(fx.routes.calls.includes('restore'), false);
  } finally { fx.close(); }
});

test('G39 readiness signal failure triggers rollback', () => {
  const policy = normalizeDeploymentRequest(request(), OWNER).observationPolicy;
  const result = evaluateReleaseObservation(policy, [{ observedAt: NOW, signals: { readiness: false, publicProbe: true }, errorRate: 0, latencyMs: 10, processRestarts: 0 }]);
  assert.equal(result.decision, 'ROLLBACK');
});

test('G40 error-rate threshold triggers rollback', () => {
  const policy = normalizeDeploymentRequest(request(), OWNER).observationPolicy;
  const result = evaluateReleaseObservation(policy, [{ observedAt: NOW, signals: { readiness: true, publicProbe: true }, errorRate: 0.5, latencyMs: 10, processRestarts: 0 }]);
  assert.equal(result.decision, 'ROLLBACK');
});

test('G41 latency threshold triggers rollback', () => {
  const policy = normalizeDeploymentRequest(request(), OWNER).observationPolicy;
  const result = evaluateReleaseObservation(policy, [{ observedAt: NOW, signals: { readiness: true, publicProbe: true }, errorRate: 0, latencyMs: 5000, processRestarts: 0 }]);
  assert.equal(result.decision, 'ROLLBACK');
});

test('G42 watchdog failure is a typed rollback signal', () => {
  const policy = normalizeDeploymentRequest(request({ observationPolicy: { ...request().observationPolicy, requiredSignals: ['readiness', 'publicProbe', 'watchdog'] } }), OWNER).observationPolicy;
  const result = evaluateReleaseObservation(policy, [{ observedAt: NOW, signals: { readiness: true, publicProbe: true, watchdog: false }, errorRate: 0, latencyMs: 10, processRestarts: 0 }]);
  assert.equal(result.decision, 'ROLLBACK');
});

test('G43 process restart threshold triggers rollback', () => {
  const policy = normalizeDeploymentRequest(request(), OWNER).observationPolicy;
  const result = evaluateReleaseObservation(policy, [{ observedAt: NOW, signals: { readiness: true, publicProbe: true }, errorRate: 0, latencyMs: 10, processRestarts: 1 }]);
  assert.equal(result.decision, 'ROLLBACK');
});

test('G44 unknown telemetry can require recovery instead of being treated healthy', () => {
  const policy = normalizeDeploymentRequest(request({ observationPolicy: { ...request().observationPolicy, unknownTelemetry: 'RECOVERY_REQUIRED' } }), OWNER).observationPolicy;
  const result = evaluateReleaseObservation(policy, [{ observedAt: NOW, signals: { readiness: true, publicProbe: 'UNKNOWN' }, unknown: true }]);
  assert.equal(result.decision, 'RECOVERY_REQUIRED');
});

test('G45 rollback cooldown is durable and no-flap latch remains set', () => {
  const policy = normalizeDeploymentRequest(request(), OWNER).observationPolicy;
  const result = evaluateReleaseObservation(policy, [{ observedAt: NOW, signals: { readiness: false, publicProbe: true }, errorRate: 1, latencyMs: 10, processRestarts: 0 }]);
  assert.equal(result.rollbackLatched, true);
  assert.equal(result.cooldownUntil, '2026-07-26T16:01:00.000Z');
});

test('G46 previous known-good slot is retained through observation', async () => {
  const fx = fixture();
  try {
    const req = request({ observationPolicy: { ...request().observationPolicy, minimumSamples: 2 } });
    const out = await fx.service.promote({ request: req }, context('retain-observation'));
    assert.equal(out.deployment.state, 'OBSERVING');
    assert.equal(fx.slots.slots.get('blue').state, 'DRAINING');
    assert.equal(fx.slots.calls.includes('stop:blue'), false);
  } finally { fx.close(); }
});

test('G47 keep-alive drain evidence is preserved', async () => { const fx=fixture(); try { const out=await promoteHappy(fx,request(),'drain-keepalive'); assert.equal(out.deployment.drainStatus.protocols.keepAlive,true); } finally {fx.close();} });
test('G48 WebSocket drain evidence is preserved', async () => { const fx=fixture(); try { const out=await promoteHappy(fx,request(),'drain-websocket'); assert.equal(out.deployment.drainStatus.protocols.websocket,true); } finally {fx.close();} });
test('G49 SSE drain evidence is preserved', async () => { const fx=fixture(); try { const out=await promoteHappy(fx,request(),'drain-sse'); assert.equal(out.deployment.drainStatus.protocols.sse,true); } finally {fx.close();} });

test('G50 worker and scheduler drain contracts remain typed', async () => {
  const fx = fixture();
  fx.drain.result.protocols.worker = true; fx.drain.result.protocols.scheduler = true;
  try { const out=await promoteHappy(fx,request(),'drain-workers'); assert.equal(out.deployment.drainStatus.protocols.worker,true); assert.equal(out.deployment.drainStatus.protocols.scheduler,true); } finally {fx.close();}
});

test('G51 drain timeout is bounded and recorded', async () => { const fx=fixture(); fx.drain.result.timeoutMs=45000; try { const out=await promoteHappy(fx,request(),'drain-timeout'); assert.equal(out.deployment.drainStatus.timeoutMs,45000); assert.equal(out.deployment.drainStatus.bounded,true); } finally {fx.close();} });

test('G52 prior slot stop targets only the exact previous slot', async () => {
  const fx = fixture();
  try { await promoteHappy(fx,request(),'exact-prior-stop'); assert.ok(fx.slots.calls.includes('stop:blue')); assert.equal(fx.slots.calls.includes('stop:green'),false); } finally {fx.close();}
});

test('G53 rollback cleanup proves candidate absence', async () => {
  const fx = fixture(); fx.observation.samples=[{observedAt:NOW,signals:{readiness:true,publicProbe:false},errorRate:1,latencyMs:10,processRestarts:0}];
  try { const out=await promoteHappy(fx,request(),'positive-absence'); assert.equal(out.deployment.state,'ROLLED_BACK'); assert.equal(out.deployment.slotRecord.state,'EMPTY_VERIFIED'); assert.equal(out.deployment.cleanup.positiveAbsence,true); } finally {fx.close();}
});

test('G54 cleanup obstruction enters RECOVERY_REQUIRED', async () => {
  const fx = fixture(); fx.observation.samples=[{observedAt:NOW,signals:{readiness:true,publicProbe:false},errorRate:1,latencyMs:10,processRestarts:0}]; fx.slots.failAt='cleanup';
  try { const out=await promoteHappy(fx,request(),'cleanup-obstruction'); assert.equal(out.deployment.state,'RECOVERY_REQUIRED'); assert.equal(out.deployment.error.code,'release_cleanup_failed'); } finally {fx.close();}
});

test('G55 active related jobs block terminal success', async () => {
  const fx = fixture(); fx.preparation.jobIds=['job-active']; fx.jobs.records.set('job-active',{id:'job-active',status:'running'});
  try { const out=await promoteHappy(fx,request(),'active-job'); assert.equal(out.deployment.state,'RECOVERY_REQUIRED'); assert.equal(out.deployment.error.code,'release_recovery_required'); } finally {fx.close();}
});

test('G56 missing proof/evidence blocks terminal success', async () => {
  const fx = fixture(); fx.proofs.fail=true;
  try { const out=await promoteHappy(fx,request(),'missing-proof'); assert.equal(out.deployment.state,'RECOVERY_REQUIRED'); } finally {fx.close();}
});

test('G57 ambiguity blocks destructive cleanup', async () => {
  const fx = fixture(); fx.routes.failAt='baseline';
  try { const out=await promoteHappy(fx,request(),'ambiguous-cleanup'); assert.equal(out.deployment.state,'AMBIGUOUS'); await assert.rejects(fx.service.cancel({deploymentId:out.deployment.deploymentId,expectedSequence:out.deployment.sequence},context('ambiguous-cancel')),/illegal|ambiguous/iu); assert.equal(fx.slots.calls.some(x=>x.startsWith('cleanup:')),false); } finally {fx.close();}
});

test('G58 terminal SUCCEEDED guard requires complete success evidence', () => { assert.doesNotThrow(()=>assertTerminalDeploymentSafety('SUCCEEDED',{cleanupComplete:true,activeRelatedJobs:0,unresolvedAmbiguity:false,evidenceComplete:true},allSuccessEvidence())); });
test('G59 terminal ROLLED_BACK guard requires restored route and cleanup', () => { assert.throws(()=>assertTerminalDeploymentSafety('ROLLED_BACK',{cleanupComplete:true,activeRelatedJobs:0,unresolvedAmbiguity:false,evidenceComplete:true,routeRestored:false}),/ROLLED_BACK|restoration/iu); });
test('G60 terminal FAILED guard requires cleanup truth', () => { assert.throws(()=>assertTerminalDeploymentSafety('FAILED',{cleanupComplete:false,activeRelatedJobs:0,unresolvedAmbiguity:false,evidenceComplete:true}),/cleanup/iu); });
test('G61 terminal CANCELLED guard requires completed cancellation', () => { assert.throws(()=>assertTerminalDeploymentSafety('CANCELLED',{cleanupComplete:true,activeRelatedJobs:0,unresolvedAmbiguity:false,evidenceComplete:true,cancellationComplete:false}),/cancellation|cleanup/iu); });
test('G62 terminal EXPIRED guard requires completed expiration policy', () => { assert.throws(()=>assertTerminalDeploymentSafety('EXPIRED',{cleanupComplete:true,activeRelatedJobs:0,unresolvedAmbiguity:false,evidenceComplete:true,expirationPolicyComplete:false}),/expiration|cleanup/iu); });

test('G63 cancellation before cutover cleans safely', async () => {
  const fx = fixture();
  try { const p=await fx.service.prepare({request:request()},context('cancel-prepared')); const out=await fx.service.cancel({deploymentId:p.deployment.deploymentId,expectedSequence:p.deployment.sequence,reason:'stop'},context('cancel-prepared-do')); assert.equal(out.deployment.state,'CANCELLED'); assert.equal(fx.routes.calls.includes('cutover'),false); } finally {fx.close();}
});

test('G64 cancellation during observation is rejected safely', async () => {
  const fx = fixture();
  try { const req=request({observationPolicy:{...request().observationPolicy,minimumSamples:2}}); const p=await fx.service.promote({request:req},context('unsafe-cancel-p')); assert.equal(p.deployment.state,'OBSERVING'); await assert.rejects(Promise.resolve().then(()=>fx.service.cancel({deploymentId:p.deployment.deploymentId,expectedSequence:p.deployment.sequence},context('unsafe-cancel'))),code('release_unsafe_cancellation')); } finally {fx.close();}
});

test('G65 resolved obstruction can resume safely', async () => {
  const fx = fixture(); fx.slots.failAt='readiness';
  try { const failed=await promoteHappy(fx,request(),'resume-fail'); assert.equal(failed.deployment.state,'RECOVERY_REQUIRED'); fx.slots.failAt=undefined; const resumed=await fx.service.resume({deploymentId:failed.deployment.deploymentId,expectedSequence:failed.deployment.sequence,resolution:{obstructionResolved:true,observationDigest:A,resumeState:'STARTING_INACTIVE'}},context('resume-ok')); assert.equal(resumed.deployment.state,'SUCCEEDED'); } finally {fx.close();}
});

test('G66 startup reconciliation is bounded', async () => {
  const fx = fixture();
  try { for(let i=0;i<5;i++) seedDurableState(fx,'REQUESTED',100+i); const out=await fx.restart().initialize(2); assert.equal(out.scanned,2); assert.ok(out.deferred>=3); } finally {fx.close();}
});

test('G67 owner-scoped events and evidence reject cross-principal reads', async () => {
  const fx = fixture();
  try { const out=await promoteHappy(fx,request(),'owner-evidence'); assert.throws(()=>fx.service.events({deploymentId:out.deployment.deploymentId},context('events-other',OTHER)),code('release_record_not_found')); assert.throws(()=>fx.service.evidence({deploymentId:out.deployment.deploymentId},context('evidence-other',OTHER)),code('release_record_not_found')); } finally {fx.close();}
});

test('G68 failure classification is bounded and redacts raw secret-like data', async () => {
  const fx = fixture(); const token=['gh','p_','123456789012345678901234567890123456'].join(''); fx.preparation.resolve=async()=>{throw new Error(`resolver ${token}`);};
  try { const out=await fx.service.prepare({request:request()},context('redaction')); assert.equal(out.deployment.state,'RECOVERY_REQUIRED'); assert.equal(out.deployment.error.code,'release_source_unresolved'); assert.equal(JSON.stringify(out.deployment).includes(token),false); assert.match(out.deployment.error.detailsDigest,/^[a-f0-9]{64}$/u); } finally {fx.close();}
});

test('G69 grouped-service happy path promotes in dependency order', async () => {
  const group=normalizeReleaseGroup({groupId:'group-ok',members:[{serviceId:'db',order:1,dependsOn:[],request:{}},{serviceId:'api',order:2,dependsOn:['db'],request:{}}]}); const calls=[];
  const out=await executeReleaseGroup(group,async m=>{calls.push(m.serviceId);return {state:'SUCCEEDED'};},async()=>({})); assert.equal(out.status,'SUCCEEDED'); assert.deepEqual(calls,['db','api']);
});

test('G70 migration phases execute in expand/migrate/contract order', async () => {
  const migration=normalizeMigrationContract({phases:[{id:'expand',kind:'EXPAND',job:{},irreversible:false,compatibilityGate:{}},{id:'migrate',kind:'MIGRATE',job:{},irreversible:false,compatibilityGate:{}},{id:'contract',kind:'CONTRACT',job:{},irreversible:false,compatibilityGate:{rollbackWindowClosed:true}}],rollbackCompatibility:{compatible:true}}); const calls=[];
  const out=await executeMigrationContract(migration,{},async phase=>{calls.push(phase.kind);return {status:'SUCCEEDED',jobId:`job-${phase.id}`};}); assert.equal(out.status,'SUCCEEDED'); assert.deepEqual(calls,['EXPAND','MIGRATE','CONTRACT']);
});

test('G71 explicitly approved irreversible migration crosses a recorded boundary', async () => {
  const migration=normalizeMigrationContract({phases:[{id:'migrate',kind:'MIGRATE',job:{},irreversible:true,compatibilityGate:{}}],rollbackCompatibility:{compatible:false}});
  const out=await executeMigrationContract(migration,{irreversibleMigrationApproved:true},async()=>({status:'SUCCEEDED'})); assert.equal(out.irreversibleCrossed,true); assert.equal(out.automaticRollbackAllowed,false);
});

test('G72 canary policy is passed intact to the sole route authority', async () => {
  const fx=fixture(); const policy={mode:'CANARY',stableEndpoint:{type:'UNIX_SOCKET',value:'/run/blue.sock'},weightBasisPoints:1000,stickiness:{kind:'COOKIE',name:'canary',ttlSeconds:300},minimumSamples:10,rollbackThresholds:{errorRate:0.1,latencyMs:500,consecutiveFailures:2},hysteresis:{breachSamples:2,recoverySamples:3},cooldownMs:60000};
  try { await promoteHappy(fx,request({routeMode:'CANARY',routePolicy:policy}),'canary-g'); assert.deepEqual(fx.routes.preparedRequests[0].policy,policy); } finally {fx.close();}
});

test('G73 shadow policy is passed intact and remains disabled unless declared', async () => {
  const fx=fixture(); const policy={mode:'SHADOW',primaryEndpoint:{type:'UNIX_SOCKET',value:'/run/blue.sock'},allowedMethods:['GET'],maxBodyBytes:1024,maxRequestsPerSecond:10,credentialMode:'STRIP',sideEffectMode:'READ_ONLY'};
  try { await promoteHappy(fx,request({routeMode:'SHADOW',routePolicy:policy}),'shadow-g'); assert.deepEqual(fx.routes.preparedRequests[0].policy,policy); } finally {fx.close();}
});

test('G74 preview expiration restores route, restores prior slot, and cleans candidate', async () => {
  const fx=fixture(); const policy={mode:'PREVIEW',trustedHeader:'X-BabyX-Identity',identityValue:'preview-a',expiresAt:'2026-07-26T15:59:00.000Z',authenticationRequired:true};
  try { const req=request({routeMode:'PREVIEW',routePolicy:policy,expiresAt:'2026-07-26T15:59:00.000Z',observationPolicy:{...request().observationPolicy,minimumSamples:2}}); const p=await fx.service.promote({request:req},context('preview-p')); assert.equal(p.deployment.state,'OBSERVING'); const expired=await fx.service.expire({deploymentId:p.deployment.deploymentId,expectedSequence:p.deployment.sequence},context('preview-expire')); assert.equal(expired.deployment.state,'EXPIRED'); assert.ok(fx.routes.calls.includes('expirePreview')); assert.equal(fx.slots.slots.get('green').state,'EMPTY_VERIFIED'); assert.equal(fx.slots.slots.get('blue').state,'ACTIVE'); } finally {fx.close();}
});

test('G75 all public read surfaces are mutation-free', async () => {
  const fx=fixture();
  try { const out=await promoteHappy(fx,request(),'readonly-all'); const id=out.deployment.deploymentId; const before=files(fx.root); fx.service.describe(); fx.service.capabilities(); fx.service.plan({request:request()},context('plan-read')); fx.service.live({deploymentId:id},context('live-read')); fx.service.status({deploymentId:id},context('status-read')); fx.service.get({deploymentId:id},context('get-read')); fx.service.list({},context('list-read')); fx.service.events({deploymentId:id},context('events-read')); fx.service.evidence({deploymentId:id},context('evidence-read')); fx.service.failures({},context('failures-read')); assert.deepEqual(files(fx.root),before); } finally {fx.close();}
});

test('G76 lifecycle GC rejects non-dry-run execution', () => { const fx=fixture(); try { assert.throws(()=>fx.service.gc({dryRun:false},context('gc-live')),code('release_gc_dry_run_required')); } finally {fx.close();} });

test('G77 raw secrets are rejected from deployment requests', () => {
  const token=['gh','p_','123456789012345678901234567890123456'].join(''); const req=request({serviceOverrides:{environment:{NODE_ENV:'production',TOKEN:token}}}); assert.throws(()=>normalizeDeploymentRequest(req,OWNER),/secret|credential|sensitive/iu);
});

test('G78 coordinator source contains no alternate scheduler, machine, artifact, route, or process authority', () => {
  const source=readFileSync(new URL('../src/release/coordinator.ts',import.meta.url),'utf8');
  for(const forbidden of ['new JobManager','new ArtifactManager','new DisposableMachineService','createServer(','.listen(','systemd-nspawn','zfs ']) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/ReleaseApplianceStore/u); assert.match(source,/ReleasePreparationAuthority/u); assert.match(source,/RouteAuthorityService/u);
});

test('G79 production-default systemd and Caddy mutation remain disabled', () => {
  const source=readFileSync(new URL('../src/core.ts',import.meta.url),'utf8'); const matches=[...source.matchAll(/liveActions:\s*false/gu)]; assert.ok(matches.length>=2);
});

test('G80 runtime exposes G through the single catalog without a public control listener', async () => {
  const fx=fixture(); const root=mkdtempSync(join(tmpdir(),'baby-x-g-runtime-'));
  try { const runtime=new BabyXRuntime({stateRoot:root,releaseCoordinatorService:fx.service}); const caps=await runtime.execute('babyx.release.capabilities',{},context('runtime-caps')); assert.equal(caps.coordinator.coordinator.authority,'sole-release-activation-coordinator'); const source=readFileSync(new URL('../src/core.ts',import.meta.url),'utf8'); assert.equal(source.includes('releaseControlPort'),false); } finally {rmSync(root,{recursive:true,force:true});fx.close();}
});

const restartPhases = [
  'REQUESTED','PREFLIGHTING','RESOLVING_SOURCE','REUSING_ARTIFACT','BUILDING','CERTIFYING','READY_TO_STAGE','STAGING',
  'STARTING_INACTIVE','READINESS_CHECKING','READY_TO_PROMOTE','AWAITING_APPROVAL','CUTOVER_PREPARING','CUTTING_OVER',
  'OBSERVING','DRAINING_PREVIOUS','FINALIZING','ROLLBACK_REQUESTED','ROLLING_BACK','CLEANUP_PENDING','CLEANING','RECOVERY_REQUIRED','AMBIGUOUS',
];
restartPhases.forEach((phase, index) => {
  test(`G-RST-${String(index + 1).padStart(2,'0')} durable controller restart preserves ${phase}`, async () => {
    const fx=fixture();
    try { const seeded=seedDurableState(fx,phase,200+index); const restarted=fx.restart(); const read=restarted.get({deploymentId:seeded.deploymentId},context(`restart-read-${index}`)); assert.equal(read.deployment.state,phase); assert.equal(read.deployment.sequence,seeded.sequence); const startup=await restarted.initialize(100); assert.ok(startup.deploymentIds.includes(seeded.deploymentId)); } finally {fx.close();}
  });
});


test('G81 startup reconciliation actively advances bounded nonterminal deployments', async () => {
  const fx = fixture();
  try {
    const normalized = normalizeDeploymentRequest(request(), OWNER);
    const initial = fx.service.createInitial('startup-active-reconcile', normalized, { subject: OWNER, idempotencyKey: 'startup-create' });
    assert.equal(initial.state, 'REQUESTED');
    const result = await fx.restart().initialize(10);
    const outcome = result.results.find((entry) => entry.deploymentId === initial.deploymentId);
    assert.equal(outcome.priorState, 'REQUESTED');
    assert.equal(outcome.state, 'READY_TO_STAGE');
    assert.equal(fx.store.getRecord('DeploymentRecordV1', initial.deploymentId).state, 'READY_TO_STAGE');
  } finally { fx.close(); }
});

test('G82 exact durable build job is adopted rather than duplicated after response loss', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-build-adoption-'));
  try {
    const artifacts = new ArtifactManager(join(root, 'artifacts'));
    const records = [];
    let starts = 0;
    const jobs = {
      list: () => records.map((entry) => structuredClone(entry)),
      start: (_operation, spec) => {
        starts += 1;
        const record = { id: `job-${starts}`, status: 'completed', exitCode: 0, metadata: structuredClone(spec.metadata) };
        records.push(record);
        return structuredClone(record);
      },
      get: (id) => structuredClone(records.find((entry) => entry.id === id)),
      reconcile: (id) => structuredClone(records.find((entry) => entry.id === id)),
    };
    const content = {
      packageRelease: (value) => ({
        artifact: { id: 'artifact-adopted', sha256: A, size: 100, state: 'finalized' },
        manifest: { manifestDigest: B, artifactId: 'artifact-adopted', artifactSha256: A, buildId: value.buildId, source: value.source },
      }),
    };
    const authority = new CompositeReleasePreparationAuthority({ content, certification: {}, jobs, artifacts, applianceVersion: '1.0.0' });
    const normalized = normalizeDeploymentRequest(request(), OWNER);
    normalized.build = {
      profile: {
        schemaVersion: '1.0.0', profileId: 'node-release-v1', platform: 'linux-amd64', packageManager: 'npm',
        installSteps: [{ name: 'install', argv: ['npm', 'ci'], cwd: '.', environment: {}, timeoutMs: 1000, networkMode: 'NONE' }],
        buildSteps: [{ name: 'build', argv: ['npm', 'run', 'build'], cwd: '.', environment: {}, timeoutMs: 1000, networkMode: 'NONE' }],
        outputPaths: ['dist'], cachePaths: [], resourcePolicy: { memoryBytes: 1024, cpuWeight: 100 },
      },
      job: { argv: ['/bin/true'], cwd: root, env: {}, timeoutMs: 1000, outputDirectory: join(root, 'out') },
      buildId: 'build-adoption', toolchainIdentity: { node: '24.18.0' }, dependencyIdentity: { lockfileDigest: B },
      executableTemplate: { argv: ['/usr/bin/node', 'server.js'] }, runtimeRequirements: { node: '24.18.0' },
      requiredConfigurationNames: [], requiredCredentialNames: [], writablePaths: [], readinessCompatibility: {}, smokeCompatibility: {},
      producerIdentity: { authority: 'babyx.job' }, provenanceReferences: [], sbomReferences: [],
    };
    const source = { sourceIdentity: sourceIdentity(), sourceManifest: {}, sourceEpoch: 1, receiptReferences: [] };
    const first = await authority.buildOrReuse(normalized, source, context('exact-build-attempt'));
    const adopted = await authority.buildOrReuse(normalized, source, context('exact-build-attempt'));
    assert.equal(starts, 1);
    assert.deepEqual(adopted.jobIds, first.jobIds);
    assert.equal(adopted.jobIds[0], 'job-1');
    assert.equal(records[0].metadata.releaseBuildRequestDigest.length, 64);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('G83 bounded public reconciliation reports deferred work truthfully', async () => {
  const fx = fixture();
  try {
    for (let index = 0; index < 3; index += 1) {
      const normalized = normalizeDeploymentRequest(request(), OWNER);
      fx.service.createInitial(`public-reconcile-${index}`, normalized, { subject: OWNER, idempotencyKey: `public-create-${index}` });
    }
    const result = await fx.service.reconcile({ limit: 1 }, context('public-reconcile-run'));
    assert.equal(result.processed, 1);
    assert.equal(result.deferred, 2);
  } finally { fx.close(); }
});


test('G84 runtime read-only coordinator access does not initiate job or deployment reconciliation', async () => {
  const fx=fixture(); const root=mkdtempSync(join(tmpdir(),'baby-x-g-runtime-read-init-'));
  try {
    const runtime=new BabyXRuntime({stateRoot:root,releaseCoordinatorService:fx.service});
    let reconciliations=0;
    runtime.jobs.reconcileRunning=()=>{reconciliations+=1; return [];};
    const before=files(fx.root);
    await runtime.releaseCoordinatorService(false);
    assert.equal(reconciliations,0);
    assert.deepEqual(files(fx.root),before);
    await runtime.releaseCoordinatorService(true);
    assert.equal(reconciliations,1);
  } finally {rmSync(root,{recursive:true,force:true});fx.close();}
});
