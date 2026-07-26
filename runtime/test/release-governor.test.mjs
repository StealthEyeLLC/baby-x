import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import {
  ArtifactManager,
  BabyXRuntime,
  JobManager,
  ReleaseApplianceStore,
  ReleaseGovernorError,
  ReleaseResourceGovernor,
  RELEASE_CAPACITY_DEFAULTS,
  canonicalize,
  evaluateCapacity,
  evaluateGovernor,
  observeHostCapacity,
  operationDefinitions,
  pressureLevel,
  projectReleaseCapacity,
  releasePriorityProfile,
  sha256,
} from '../../dist/runtime/index.js';

const GIB = 1024 * 1024 * 1024;
const OWNER = 'owner-governor';
const NOW = '2026-07-26T20:00:00.000Z';
const DIGEST_A = 'a'.repeat(64);

function observation(overrides = {}) {
  return {
    observedAt: NOW,
    rootTotalBytes: 100 * GIB,
    rootAvailableBytes: 50 * GIB,
    rootAvailableInodes: 1_000_000,
    zfsPool: 'babycert',
    zfsTotalBytes: 20 * GIB,
    zfsAvailableBytes: 10 * GIB,
    memoryAvailableBytes: 8 * GIB,
    cpuPressure: { level: 'GREEN' },
    memoryPressure: { level: 'GREEN' },
    ioPressure: { level: 'GREEN' },
    ...overrides,
  };
}

function reservation(overrides = {}) {
  return {
    reservationId: 'reserve-a',
    purpose: 'RELEASE_ARTIFACT',
    workClass: 'HEAVYWEIGHT',
    rootBytes: GIB,
    zfsBytes: GIB,
    memoryBytes: 256 * 1024 * 1024,
    ownerPrincipal: OWNER,
    expiresAt: '2026-07-26T21:00:00.000Z',
    ...overrides,
  };
}

function context(key = 'governor-idem') { return { subject: OWNER, idempotencyKey: key, authorityClass: 'owner' }; }
function code(expected) { return (error) => typeof error?.code === 'string' && error.code === expected; }

function files(root) {
  const result = [];
  const walk = (path) => {
    for (const name of readdirSync(path).sort()) {
      const absolute = join(path, name);
      const stat = statSync(absolute);
      const key = relative(root, absolute);
      if (stat.isDirectory()) { result.push([key, 'd']); walk(absolute); }
      else result.push([key, stat.size, sha256(readFileSync(absolute))]);
    }
  };
  walk(root);
  return result;
}

function fixture(options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-release-governor-'));
  const store = new ReleaseApplianceStore(join(root, 'store'));
  const artifacts = new ArtifactManager(join(root, 'artifacts'));
  let currentObservation = observation(options.observation);
  let now = options.now ?? NOW;
  const priorityCalls = [];
  const priorityAuthority = options.priorityAuthority ?? {
    authority: 'existing-systemd-resource-authority',
    apply(request) { priorityCalls.push(structuredClone(request)); return { applied: true, target: request.target }; },
  };
  const createGovernor = () => new ReleaseResourceGovernor({
    store,
    artifacts,
    capacityProvider: () => structuredClone(currentObservation),
    priorityAuthority,
    now: () => now,
  });
  const governor = createGovernor();
  return {
    root, store, artifacts, governor, priorityCalls,
    restart: createGovernor,
    setObservation(value) { currentObservation = observation(value); },
    setNow(value) { now = value; },
    close() { rmSync(root, { recursive: true, force: true }); },
  };
}

function artifact(fx, name, bytes, metadata = {}) {
  const source = join(fx.root, `${name}.source`);
  writeFileSync(source, bytes);
  return fx.artifacts.create(name, source, metadata);
}

function persistEvidenceReference(fx, artifactId) {
  const record = {
    schemaVersion: '1.0.0',
    evidenceIndexId: 'evidence-governor',
    parentType: 'DEPLOYMENT',
    parentId: 'deployment-governor',
    finalState: 'SUCCEEDED',
    recordDigests: {},
    orderedEventDigests: [],
    jobSummaries: [],
    machineSummaries: [],
    artifactSummaries: [{ artifactId }],
    identityBindings: {},
    healthSummaries: [],
    cutoverConfigDigests: [],
    rollbackConfigDigests: [],
    credentialSetDigest: DIGEST_A,
    capacitySnapshotIds: [],
    githubReferences: [],
    cleanupProof: { complete: true },
    signerIdentity: { keyId: 'test' },
    signedReceiptIds: [],
    evidenceIndexDigest: 'b'.repeat(64),
    createdAt: NOW,
  };
  fx.store.applyMutation({
    schemaId: 'EvidenceIndexV1', recordId: record.evidenceIndexId, ownerPrincipal: OWNER,
    expectedSequence: 0, idempotencyKey: 'evidence-reference', requestDigest: sha256(canonicalize(record)),
    operation: 'test.evidence', phase: 'test', record, occurredAt: NOW,
  });
}

test('H01 frozen capacity defaults are exact', () => {
  assert.equal(RELEASE_CAPACITY_DEFAULTS.rootWarningBytes, 20 * GIB);
  assert.equal(RELEASE_CAPACITY_DEFAULTS.rootWarningPercent, 20);
  assert.equal(RELEASE_CAPACITY_DEFAULTS.rootBackgroundThrottleBytes, 15 * GIB);
  assert.equal(RELEASE_CAPACITY_DEFAULTS.rootStagingRejectBytes, 12 * GIB);
  assert.equal(RELEASE_CAPACITY_DEFAULTS.rootEmergencyBytes, 8 * GIB);
  assert.equal(RELEASE_CAPACITY_DEFAULTS.zfsWarningBytes, 3 * GIB);
  assert.equal(RELEASE_CAPACITY_DEFAULTS.zfsWarningPercent, 25);
  assert.equal(RELEASE_CAPACITY_DEFAULTS.zfsCloneRejectBytes, 2 * GIB);
  assert.equal(RELEASE_CAPACITY_DEFAULTS.memoryHeavyweightReserveBytes, 2 * GIB);
  assert.equal(RELEASE_CAPACITY_DEFAULTS.defaultHeavyweightConcurrency, 1);
  assert.equal(RELEASE_CAPACITY_DEFAULTS.maximumBackgroundConcurrency, 4);
});

test('H02 root warning and background throttle are conservative', () => {
  const warning = evaluateCapacity(observation({ rootAvailableBytes: 21 * GIB }), reservation({ rootBytes: 2 * GIB, zfsBytes: 0 }));
  assert.equal(warning.admission, 'THROTTLE');
  assert.equal(warning.rootWarning, true);
  const background = evaluateCapacity(observation({ rootAvailableBytes: 16 * GIB }), reservation({ purpose: 'BUILD_CACHE', workClass: 'BACKGROUND', rootBytes: 2 * GIB, zfsBytes: 0 }));
  assert.equal(background.admission, 'THROTTLE');
  assert.equal(background.backgroundThrottle, true);
});

test('H03 projected root below 12 GiB rejects staging', () => {
  const result = evaluateCapacity(observation({ rootAvailableBytes: 14 * GIB }), reservation({ rootBytes: 3 * GIB, zfsBytes: 0 }));
  assert.equal(result.admission, 'REJECT');
  assert.ok(result.reasons.includes('root_capacity_below_staging_floor'));
});

test('H04 production control may enter explicit emergency-only reserve', () => {
  const result = evaluateCapacity(observation({ rootAvailableBytes: 9 * GIB }), reservation({ workClass: 'PRODUCTION_CONTROL', rootBytes: 2 * GIB, zfsBytes: 0, memoryBytes: 0 }));
  assert.equal(result.admission, 'EMERGENCY_ONLY');
  assert.ok(result.reasons.includes('root_capacity_below_emergency_floor'));
});

test('H05 ZFS warning and clone floor are enforced', () => {
  const warning = evaluateCapacity(observation({ zfsAvailableBytes: 4 * GIB }), reservation({ purpose: 'DISPOSABLE_CLONE', zfsBytes: 1536 * 1024 * 1024, rootBytes: 0 }));
  assert.equal(warning.admission, 'THROTTLE');
  assert.equal(warning.zfsWarning, true);
  const rejected = evaluateCapacity(observation({ zfsAvailableBytes: 4 * GIB }), reservation({ purpose: 'DISPOSABLE_CLONE', zfsBytes: 3 * GIB, rootBytes: 0 }));
  assert.equal(rejected.admission, 'REJECT');
  assert.ok(rejected.reasons.includes('zfs_capacity_below_clone_floor'));
});

test('H06 memory and inode floors reject heavyweight work', () => {
  const memory = evaluateCapacity(observation({ memoryAvailableBytes: 2500 * 1024 * 1024 }), reservation({ memoryBytes: GIB, rootBytes: 0, zfsBytes: 0 }));
  assert.equal(memory.admission, 'REJECT');
  assert.ok(memory.reasons.includes('memory_capacity_below_heavyweight_reserve'));
  const inodes = evaluateCapacity(observation({ rootAvailableInodes: 9999 }), reservation({ rootBytes: 0, zfsBytes: 0, memoryBytes: 0 }));
  assert.equal(inodes.admission, 'REJECT');
  assert.ok(inodes.reasons.includes('root_inode_capacity_low'));
});

test('H07 durable reservation writes snapshot and singleton ledger', () => {
  const fx = fixture();
  try {
    const result = fx.governor.reserve(reservation());
    assert.equal(result.reservation.state, 'ACTIVE');
    assert.equal(result.ledger.sequence, 1);
    assert.equal(fx.store.hasRecord('CapacitySnapshotV1', result.snapshot.snapshotId), true);
    assert.equal(fx.store.hasRecord('CapacityReservationLedgerV1', 'release-capacity'), true);
  } finally { fx.close(); }
});

test('H08 exact reservation replay is idempotent', () => {
  const fx = fixture();
  try {
    const first = fx.governor.reserve(reservation());
    const second = fx.governor.reserve(reservation());
    assert.equal(second.replayed, true);
    assert.equal(second.reservation.requestDigest, first.reservation.requestDigest);
    assert.equal(fx.store.getRecord('CapacityReservationLedgerV1', 'release-capacity').sequence, 1);
  } finally { fx.close(); }
});

test('H09 conflicting reservation identity is rejected', () => {
  const fx = fixture();
  try {
    fx.governor.reserve(reservation());
    assert.throws(() => fx.governor.reserve(reservation({ rootBytes: 2 * GIB })), code('release_idempotency_conflict'));
  } finally { fx.close(); }
});

test('H10 two governor instances cannot overcommit shared capacity', () => {
  const fx = fixture({ observation: { rootAvailableBytes: 18 * GIB } });
  try {
    fx.governor.reserve(reservation({ reservationId: 'first', rootBytes: 4 * GIB, zfsBytes: 0 }));
    const second = fx.restart();
    assert.throws(() => second.reserve(reservation({ reservationId: 'second', rootBytes: 3 * GIB, zfsBytes: 0 })), code('release_capacity_insufficient'));
    const ledger = fx.store.getRecord('CapacityReservationLedgerV1', 'release-capacity');
    assert.equal(ledger.reservations.filter((entry) => entry.state === 'ACTIVE').length, 1);
  } finally { fx.close(); }
});

test('H11 release frees durable reservation totals', () => {
  const fx = fixture();
  try {
    fx.governor.reserve(reservation());
    const result = fx.governor.release('reserve-a', OWNER, 'complete');
    assert.equal(result.released, true);
    assert.equal(result.ledger.reservedRootBytes, 0);
    assert.equal(result.ledger.reservedZfsBytes, 0);
  } finally { fx.close(); }
});

test('H12 restart reads active reservations from authoritative ledger', () => {
  const fx = fixture();
  try {
    fx.governor.reserve(reservation({ rootBytes: 2 * GIB }));
    const restarted = fx.restart();
    const capacity = restarted.capacity({});
    assert.equal(capacity.activeReservations.length, 1);
    assert.equal(capacity.activeReservationTotals.rootBytes, 2 * GIB);
  } finally { fx.close(); }
});

test('H13 restart reconstruction expires stale leases deterministically', () => {
  const fx = fixture();
  try {
    fx.governor.reserve(reservation({ expiresAt: '2026-07-26T20:01:00.000Z' }));
    fx.setNow('2026-07-26T20:02:00.000Z');
    const result = fx.restart().reconstruct();
    assert.equal(result.repaired, true);
    assert.equal(result.ledger.reservedRootBytes, 0);
    assert.ok(result.ledger.reservations.some((entry) => entry.state === 'EXPIRED'));
  } finally { fx.close(); }
});

test('H14 read-only capacity projection does not mutate store or artifacts', () => {
  const fx = fixture();
  try {
    const before = files(fx.root);
    const result = fx.governor.capacity({ projection: reservation({ reservationId: 'projection' }) });
    assert.equal(result.readOnly, true);
    assert.equal(result.projection.request.reservationId, 'projection');
    assert.deepEqual(files(fx.root), before);
  } finally { fx.close(); }
});

test('H15 PSI green permits four background workers and one heavyweight', () => {
  const result = evaluateGovernor(observation(), 'ALLOW', 'GREEN');
  assert.equal(result.backgroundConcurrency, 4);
  assert.equal(result.heavyweightConcurrency, 1);
  assert.equal(result.productionControlConcurrency, 1);
});

test('H16 PSI yellow reduces background concurrency', () => {
  const result = evaluateGovernor(observation({ cpuPressure: { level: 'YELLOW' } }), 'ALLOW', 'GREEN');
  assert.equal(result.backgroundConcurrency, 1);
  assert.equal(result.heavyweightConcurrency, 1);
});

test('H17 PSI red pauses heavyweight and background work but not production control', () => {
  const result = evaluateGovernor(observation({ ioPressure: { level: 'RED' } }), 'ALLOW', 'GREEN');
  assert.equal(result.backgroundConcurrency, 0);
  assert.equal(result.heavyweightConcurrency, 0);
  assert.equal(result.productionControlConcurrency, 1);
  assert.equal(result.productionControlResponsive, true);
});

test('H18 unknown PSI fails closed for background work', () => {
  assert.equal(pressureLevel({ status: 'UNKNOWN' }), 'UNKNOWN');
  const result = evaluateGovernor(observation({ memoryPressure: { status: 'UNKNOWN' } }), 'ALLOW', 'GREEN');
  assert.equal(result.backgroundConcurrency, 0);
});

test('H19 production cgroup weights dominate heavyweight and background', () => {
  const production = releasePriorityProfile('PRODUCTION_CONTROL');
  const heavyweight = releasePriorityProfile('HEAVYWEIGHT');
  const background = releasePriorityProfile('BACKGROUND');
  assert.ok(Number(production.CPUWeight) > Number(heavyweight.CPUWeight));
  assert.ok(Number(heavyweight.CPUWeight) > Number(background.CPUWeight));
  assert.ok(Number(production.IOWeight) > Number(heavyweight.IOWeight));
  assert.ok(Number(heavyweight.IOWeight) > Number(background.IOWeight));
});

test('H20 priority enforcement uses only the injected systemd resource authority', async () => {
  const fx = fixture();
  try {
    const result = await fx.governor.enforcePriority({ target: 'job-build-a', workClass: 'BACKGROUND' }, context('priority'));
    assert.equal(result.applied, true);
    assert.equal(fx.priorityCalls.length, 1);
    assert.deepEqual(fx.priorityCalls[0].properties, releasePriorityProfile('BACKGROUND'));
  } finally { fx.close(); }
});

test('H21 active rollback and pinned artifacts are never eviction candidates', () => {
  const fx = fixture();
  try {
    const active = artifact(fx, 'active', Buffer.from('active'), { retentionClass: 'ACTIVE', lastAccessedAt: '2026-01-01T00:00:00.000Z' });
    const rollback = artifact(fx, 'rollback', Buffer.from('rollback'), { retentionClass: 'ROLLBACK', lastAccessedAt: '2026-01-01T00:00:01.000Z' });
    const pinned = artifact(fx, 'pinned', Buffer.from('pinned'), { retentionClass: 'CACHE', pinned: true, lastAccessedAt: '2026-01-01T00:00:02.000Z' });
    const decisions = new Map(fx.governor.planGc({ limit: 10 }).decisions.map((entry) => [entry.objectId, entry]));
    assert.equal(decisions.get(active.id).decision, 'RETAIN');
    assert.equal(decisions.get(rollback.id).decision, 'RETAIN');
    assert.equal(decisions.get(pinned.id).decision, 'RETAIN');
  } finally { fx.close(); }
});

test('H22 evidence-required artifacts are reference protected', () => {
  const fx = fixture();
  try {
    const item = artifact(fx, 'evidence-cache', Buffer.from('evidence-cache'), { retentionClass: 'CACHE', lastAccessedAt: '2026-01-01T00:00:00.000Z' });
    persistEvidenceReference(fx, item.id);
    const decision = fx.governor.planGc({ limit: 10 }).decisions.find((entry) => entry.objectId === item.id);
    assert.equal(decision.decision, 'RETAIN');
    assert.ok(decision.reasons.includes('protected-authoritative-reference'));
    assert.equal(decision.referenceCount, 1);
  } finally { fx.close(); }
});

test('H23 corrupt artifacts are quarantined in plan and never auto-evicted', () => {
  const fx = fixture();
  try {
    const item = artifact(fx, 'corrupt-cache', Buffer.from('before'), { retentionClass: 'CACHE' });
    writeFileSync(item.path, Buffer.from('after'));
    const decision = fx.governor.planGc({ limit: 10 }).decisions.find((entry) => entry.objectId === item.id);
    assert.equal(decision.decision, 'QUARANTINE');
    assert.ok(decision.reasons.includes('artifact-integrity-not-verified'));
  } finally { fx.close(); }
});

test('H24 unreferenced caches are selected in deterministic LRU order', () => {
  const fx = fixture();
  try {
    const old = artifact(fx, 'cache-old', Buffer.from('old'), { retentionClass: 'CACHE', lastAccessedAt: '2026-01-01T00:00:00.000Z' });
    const newer = artifact(fx, 'cache-newer', Buffer.from('newer'), { retentionClass: 'CACHE', lastAccessedAt: '2026-02-01T00:00:00.000Z' });
    const evictions = fx.governor.planGc({ limit: 10 }).decisions.filter((entry) => entry.decision === 'EVICT');
    assert.deepEqual(evictions.map((entry) => entry.objectId), [old.id, newer.id]);
  } finally { fx.close(); }
});

test('H25 GC candidate and byte limits are enforced', () => {
  const fx = fixture();
  try {
    const first = artifact(fx, 'cache-first', Buffer.alloc(8), { retentionClass: 'CACHE', lastAccessedAt: '2026-01-01T00:00:00.000Z' });
    const second = artifact(fx, 'cache-second', Buffer.alloc(8, 1), { retentionClass: 'CACHE', lastAccessedAt: '2026-01-02T00:00:00.000Z' });
    const plan = fx.governor.planGc({ limit: 2, maxBytes: 8 });
    assert.equal(plan.decisions.find((entry) => entry.objectId === first.id).decision, 'EVICT');
    assert.equal(plan.decisions.find((entry) => entry.objectId === second.id).decision, 'DEFER');
    assert.equal(plan.selectedBytes, 8);
  } finally { fx.close(); }
});

test('H26 GC dry-run returns reasons without mutation', () => {
  const fx = fixture();
  try {
    artifact(fx, 'cache-dry', Buffer.from('dry'), { retentionClass: 'CACHE' });
    const before = files(fx.root);
    const plan = fx.governor.gc({ dryRun: true, limit: 10 }, context('gc-dry'));
    assert.equal(plan.dryRun, true);
    assert.deepEqual(plan.destructiveActions, []);
    assert.ok(plan.decisions.every((entry) => entry.reasons.length > 0));
    assert.deepEqual(files(fx.root), before);
  } finally { fx.close(); }
});

test('H27 GC plan digest is stable across clock changes when state is unchanged', () => {
  const fx = fixture();
  try {
    artifact(fx, 'cache-stable', Buffer.from('stable'), { retentionClass: 'CACHE' });
    const first = fx.governor.planGc({ limit: 10 });
    fx.setNow('2026-07-26T20:10:00.000Z');
    const second = fx.governor.planGc({ limit: 10 });
    assert.equal(second.planDigest, first.planDigest);
    assert.notEqual(second.decidedAt, first.decidedAt);
  } finally { fx.close(); }
});

test('H28 live GC rejects missing or stale plan identity', () => {
  const fx = fixture();
  try {
    artifact(fx, 'cache-stale', Buffer.from('stale'), { retentionClass: 'CACHE' });
    assert.throws(() => fx.governor.gc({ dryRun: false }, context('gc-missing')), code('release_stale_sequence'));
    assert.throws(() => fx.governor.gc({ dryRun: false, planDigest: DIGEST_A }, context('gc-stale')), code('release_stale_sequence'));
  } finally { fx.close(); }
});

test('H29 live GC evicts only planned safe cache and persists retention evidence', () => {
  const fx = fixture();
  try {
    const cache = artifact(fx, 'cache-live', Buffer.from('cache-live'), { retentionClass: 'CACHE' });
    const active = artifact(fx, 'active-live', Buffer.from('active-live'), { retentionClass: 'ACTIVE' });
    const plan = fx.governor.gc({ dryRun: true, limit: 10 }, context('gc-plan'));
    const result = fx.governor.gc({ dryRun: false, limit: 10, planDigest: plan.planDigest }, context('gc-live'));
    assert.equal(result.destructiveActions.length, 1);
    assert.equal(result.destructiveActions[0].decision.objectId, cache.id);
    assert.throws(() => fx.artifacts.get(cache.id), /not found/iu);
    assert.equal(fx.artifacts.verify(active.id).valid, true);
    assert.equal(fx.store.hasRecord('RetentionDecisionV1', result.destructiveActions[0].decision.decisionId), true);
  } finally { fx.close(); }
});

test('H30 shared content blob remains until the final artifact record is removed', () => {
  const fx = fixture();
  try {
    const one = artifact(fx, 'shared-one', Buffer.from('same-bytes'), { retentionClass: 'CACHE' });
    const two = artifact(fx, 'shared-two', Buffer.from('same-bytes'), { retentionClass: 'CACHE' });
    assert.equal(one.path, two.path);
    const first = fx.artifacts.remove(one.id, one.sha256);
    assert.equal(first.sharedBlobRetained, true);
    assert.equal(existsSync(two.path), true);
    const second = fx.artifacts.remove(two.id, two.sha256);
    assert.equal(second.sharedBlobRetained, false);
    assert.equal(existsSync(two.path), false);
  } finally { fx.close(); }
});

test('H31 public capacity operation is exposed once and read-only', () => {
  const definitions = operationDefinitions().filter((entry) => entry.operation === 'babyx.release.capacity');
  assert.equal(definitions.length, 1);
  assert.equal(definitions[0].mutation, false);
});

test('H32 pristine runtime capacity read creates no release-appliance records', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-capacity-runtime-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root, releaseCapacityProvider: () => observation() });
    const before = files(root);
    const result = await runtime.execute('babyx.release.capacity', {}, context('runtime-capacity'));
    assert.equal(result.readOnly, true);
    assert.equal(result.observation.zfsPool, 'babycert');
    assert.deepEqual(files(root), before);
    assert.equal(existsSync(join(root, 'release-appliance', 'records')), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('H33 pure capacity projection preserves distinct root and ZFS observations', () => {
  const result = projectReleaseCapacity(observation({ rootAvailableBytes: 40 * GIB, zfsAvailableBytes: 5 * GIB }), {});
  assert.equal(result.observation.rootAvailableBytes, 40 * GIB);
  assert.equal(result.observation.zfsAvailableBytes, 5 * GIB);
});

test('H34 host observer is read-only and reports ext4/ZFS/PSI fields', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-host-capacity-'));
  try {
    const before = files(root);
    const result = observeHostCapacity({ rootPath: root, zfsDataset: 'missing-test-dataset', zfsPath: '/definitely/missing/zfs', now: () => NOW });
    assert.ok(result.rootTotalBytes > 0);
    assert.equal(result.zfsPool, 'missing-test-dataset:unavailable');
    assert.ok(result.cpuPressure.status === 'AVAILABLE' || result.cpuPressure.status === 'UNKNOWN');
    assert.deepEqual(files(root), before);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('H35 job stream and journal bounds are explicit', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-job-bounds-'));
  try {
    const jobs = new JobManager(root);
    assert.throws(() => jobs.read('missing', 'stdout', 0, 1024 * 1024 + 1), /1048576/u);
    const source = readFileSync(new URL('../src/systemd/manager.ts', import.meta.url), 'utf8');
    assert.match(source, /lines > 10_000/u);
    assert.doesNotMatch(source, /lines > 100_000/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('H36 content service routes persistent writes through shared reservations and releases them', () => {
  const source = readFileSync(new URL('../src/release/content.ts', import.meta.url), 'utf8');
  assert.match(source, /capacityAuthority\.reserve|capacityAuthority !== undefined/u);
  assert.match(source, /capacityAuthority\?\.release/u);
  assert.match(source, /MATERIALIZATION/u);
});

test('H37 governor creates no scheduler machine artifact process or destructive ZFS authority', () => {
  const source = readFileSync(new URL('../src/release/governor.ts', import.meta.url), 'utf8');
  for (const forbidden of ['new JobManager', 'new ArtifactManager', 'new DisposableMachineService', 'createServer(', '.listen(', 'systemd-nspawn', 'zfs create', 'zfs destroy', 'zfs clone', 'systemctl start', 'systemctl restart']) assert.equal(source.includes(forbidden), false, forbidden);
  assert.match(source, /ReleaseApplianceStore/u);
  assert.match(source, /ArtifactManager/u);
  assert.match(source, /PriorityEnforcementAuthority/u);
});
