import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import {
  BabyXRuntime,
  ReleaseApplianceStore,
  SlotRuntimeError,
  SlotRuntimeService,
  canonicalize,
  generateSlotUnit,
  normalizeServiceDefinition,
  operationDefinitions,
  sha256,
} from '../../dist/runtime/index.js';

const OWNER = 'owner-release';
const OTHER = 'other-owner';
const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);

function serviceDefinition(overrides = {}) {
  const base = {
    schemaVersion: '1.0.0',
    serviceId: 'notes-api',
    displayName: 'Notes API',
    ownerPrincipal: OWNER,
    organization: 'stealtheye',
    repository: 'StealthEyeLLC/notes-api',
    allowedRepositoryIds: ['repo-notes'],
    serviceKind: 'API',
    deploymentGroup: 'notes',
    orderedDependencies: [],
    runtimeIdentity: { serviceUser: 'notesapi', serviceGroup: 'notesapi' },
    executableContract: { argv: ['/opt/notes/bin/server', '--serve'], nativeReadiness: true, nativeWatchdog: true },
    workingDirectory: '.',
    environment: { NODE_ENV: 'production' },
    credentialReferenceNames: ['notes-db'],
    userPolicy: { stable: true },
    slotModel: 'BLUE_GREEN',
    endpointPreference: 'UNIX_SOCKET',
    endpointPolicy: { allowLoopbackFallback: true, publicCandidate: false },
    readinessProbe: { mode: 'NATIVE_NOTIFY', timeoutMs: 5000, intervalMs: 5, maximumSamples: 8 },
    livenessProbe: { mode: 'SYSTEMD' },
    observationProbes: [],
    smokeTestProfile: { path: '/healthz' },
    drainProtocol: { kind: 'HTTP', timeoutMs: 30000 },
    terminationPolicy: { signal: 'SIGTERM', timeoutMs: 45000 },
    restartPolicy: { mode: 'ON_FAILURE' },
    watchdogPolicy: { mode: 'NATIVE', intervalMs: 30000 },
    resourceProfile: { class: 'PRODUCTION' },
    filesystemWritePolicy: { immutableRelease: true },
    stateDirectories: ['data'],
    cacheDirectories: ['cache'],
    logDirectories: ['log'],
    runtimeDirectories: ['run'],
    caddyRouteTemplateId: 'http-private-upstream-v1',
    publicHostnames: ['notes.example.test'],
    pathMatchers: ['/'],
    migrationContract: { mode: 'NONE' },
    rollbackContract: { retainPrevious: true },
    retentionPolicy: { rollbackSlots: 1 },
    approvalPolicy: { mode: 'NONE' },
    automationPolicy: { automaticPromotion: false },
    provenance: { source: 'test-fixture' },
    ...overrides,
  };
  delete base.manifestDigest;
  return { ...base, manifestDigest: sha256(canonicalize(base)) };
}

function roots(root) {
  return {
    releaseRoot: join(root, 'releases'),
    runtimeRoot: join(root, 'runtime'),
    stateRoot: join(root, 'state'),
    cacheRoot: join(root, 'cache'),
    logRoot: join(root, 'log'),
  };
}

function release(overrides = {}) {
  return { releaseId: 'release-a', artifactId: 'artifact-a', artifactSha256: DIGEST_A, ...overrides };
}

function expectedIdentity(overrides = {}) {
  return {
    processStartTime: '100',
    bootId: 'boot-a',
    cgroup: '/system.slice/babyx-release-notes-api-blue.service',
    ...overrides,
  };
}

function context(key = 'idem-test', subject = OWNER, authorityClass = 'owner') {
  return { subject, idempotencyKey: key, authorityClass };
}

function absent(bundle, observedAt = '2026-07-26T16:00:00.000Z') {
  return {
    observedAt,
    unitExists: false,
    activeState: 'inactive',
    subState: 'dead',
    unitName: bundle.unitName,
    endpointExists: false,
    runtimePathExists: false,
    transientUnitExists: false,
    readinessState: 'UNKNOWN',
    watchdogState: bundle.nativeWatchdog ? 'UNKNOWN' : 'UNSUPPORTED',
  };
}

function running(bundle, overrides = {}) {
  return {
    observedAt: '2026-07-26T16:00:01.000Z',
    unitExists: true,
    activeState: 'active',
    subState: 'running',
    unitName: bundle.unitName,
    unitDigest: bundle.unitDigest,
    dropInDigest: bundle.dropInDigest,
    mainPid: 4242,
    processStartTime: '100',
    executablePath: bundle.executablePath,
    bootId: 'boot-a',
    cgroup: `/system.slice/${bundle.unitName}`,
    endpointExists: true,
    endpointOwner: { pid: 4242, unitName: bundle.unitName, serviceId: bundle.serviceId, slotId: bundle.slotId },
    runtimePathExists: true,
    transientUnitExists: false,
    readinessState: 'READY',
    watchdogState: bundle.nativeWatchdog ? 'ACTIVE' : 'UNSUPPORTED',
    ...overrides,
  };
}

class FakeSystemdAdapter {
  authority = 'slot-systemd-adapter';
  calls = [];
  current = undefined;
  bundle = undefined;
  valid = true;
  validationDiagnostics = [];
  startFailure = undefined;
  stopFailure = undefined;
  cleanupFailure = undefined;
  readyObservations = undefined;

  async validate(bundle) {
    this.calls.push('validate');
    this.bundle = bundle;
    return { valid: this.valid, validator: 'fake-systemd-analyze', version: '1.0.0', digest: sha256(canonicalize({ valid: this.valid, diagnostics: this.validationDiagnostics })), diagnostics: this.validationDiagnostics };
  }
  async install(bundle) {
    this.calls.push('install');
    this.bundle = bundle;
    return { installed: true };
  }
  async start(bundle) {
    this.calls.push('start');
    this.bundle = bundle;
    if (this.startFailure === 'before') throw new Error('fake start failed before effect');
    this.current = running(bundle, { readinessState: 'NOT_READY' });
    if (this.startFailure === 'after') throw new Error('fake response loss after start');
    return { accepted: true, responseDigest: DIGEST_B };
  }
  async stop(bundle) {
    this.calls.push('stop');
    if (this.stopFailure === 'foreign') {
      this.current = running(bundle, { processStartTime: 'foreign', endpointOwner: { pid: 9999, unitName: 'foreign.service' } });
      throw new Error('fake stop response loss with conflict');
    }
    this.current = absent(bundle);
    if (this.stopFailure === 'after') throw new Error('fake response loss after stop');
    if (this.stopFailure === 'before') {
      this.current = running(bundle);
      throw new Error('fake stop obstruction');
    }
    return { accepted: true };
  }
  async cleanup(bundle) {
    this.calls.push('cleanup');
    if (this.cleanupFailure) throw new Error('fake cleanup obstruction');
    this.current = absent(bundle);
    return { removed: true };
  }
  async observe(bundle) {
    this.calls.push('observe');
    this.bundle = bundle;
    return structuredClone(this.current ?? absent(bundle));
  }
  async waitReady(bundle) {
    this.calls.push('waitReady');
    if (this.readyObservations !== undefined) return structuredClone(this.readyObservations);
    this.current = running(bundle);
    return [structuredClone(this.current)];
  }
}

function fixture(options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-release-slot-'));
  const store = new ReleaseApplianceStore(join(root, 'store'));
  const adapter = options.adapter ?? new FakeSystemdAdapter();
  const jobs = options.jobs ?? { get(id) { return { id, status: 'completed' }; } };
  let tick = 0;
  const service = new SlotRuntimeService({
    stateRoot: root,
    store,
    jobs,
    systemd: adapter,
    now: () => `2026-07-26T16:00:${String(tick++).padStart(2, '0')}.000Z`,
  });
  return { root, store, adapter, service, close: () => rmSync(root, { recursive: true, force: true }) };
}

function stage(fx, options = {}) {
  return fx.service.stage({
    serviceDefinition: serviceDefinition(options.serviceOverrides),
    slotId: options.slotId ?? 'blue',
    release: release(options.releaseOverrides),
    credentialSetDigest: DIGEST_B,
    expectedProcessIdentity: expectedIdentity(options.identityOverrides),
    ...(options.endpointMode === undefined ? {} : { endpointMode: options.endpointMode }),
  }, context(options.key ?? 'stage-a', options.subject ?? OWNER));
}

function filesystemSnapshot(root) {
  const entries = [];
  function walk(path) {
    for (const name of readdirSync(path).sort()) {
      const absolute = join(path, name);
      const info = statSync(absolute);
      const key = relative(root, absolute);
      if (info.isDirectory()) { entries.push({ key, type: 'directory' }); walk(absolute); }
      else entries.push({ key, type: 'file', size: info.size, digest: sha256(readFileSync(absolute)) });
    }
  }
  walk(root);
  return entries;
}

function code(expected) {
  return (error) => error instanceof SlotRuntimeError && error.code === expected;
}

test('E01 deterministic service-definition normalization and stable manifest identity', () => {
  const first = normalizeServiceDefinition(serviceDefinition());
  const second = normalizeServiceDefinition(serviceDefinition({ allowedRepositoryIds: ['repo-notes'] }));
  assert.deepEqual(first, second);
  assert.equal(first.manifestDigest, serviceDefinition().manifestDigest);
});

test('E02 stable blue/green naming and deterministic runtime paths', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-slot-unit-'));
  try {
    const blue = generateSlotUnit(serviceDefinition(), 'blue', release(), roots(root));
    const green = generateSlotUnit(serviceDefinition(), 'green', release(), roots(root));
    assert.equal(blue.unitName, 'babyx-release-notes-api-blue.service');
    assert.equal(green.unitName, 'babyx-release-notes-api-green.service');
    assert.match(blue.runtimeRoot, /notes-api\/blue$/u);
    assert.match(green.runtimeRoot, /notes-api\/green$/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('E03 deterministic unit and drop-in bytes bind immutable root, user, endpoint, and writable roots', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-slot-unit-'));
  try {
    const a = generateSlotUnit(serviceDefinition(), 'blue', release(), roots(root));
    const b = generateSlotUnit(serviceDefinition(), 'blue', release(), roots(root));
    assert.equal(a.unitBytes, b.unitBytes);
    assert.equal(a.dropInBytes, b.dropInBytes);
    assert.match(a.unitBytes, /User=notesapi/u);
    assert.match(a.unitBytes, /ReadOnlyPaths=/u);
    assert.match(a.unitBytes, /ReadWritePaths=/u);
    assert.match(a.dropInBytes, /BABYX_ENDPOINT_TYPE=UNIX_SOCKET/u);
    assert.notEqual(a.runtimeRoot, a.stateRoot);
    assert.notEqual(a.cacheRoot, a.logRoot);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('E04 unit-name, path, service-user, and systemd-value injection are rejected', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-slot-unit-'));
  try {
    assert.throws(() => generateSlotUnit(serviceDefinition({ serviceId: '../evil' }), 'blue', release(), roots(root)));
    assert.throws(() => generateSlotUnit(serviceDefinition({ runtimeIdentity: { serviceUser: '-root', serviceGroup: 'root' } }), 'blue', release(), roots(root)));
    assert.throws(() => generateSlotUnit(serviceDefinition({ workingDirectory: '../../etc' }), 'blue', release(), roots(root)));
    assert.throws(() => generateSlotUnit(serviceDefinition({ executableContract: { argv: ['/bin/echo\nExecStart=/bin/sh'], nativeReadiness: true, nativeWatchdog: false } }), 'blue', release(), roots(root)));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('E05 validation failure occurs before install or start external mutation', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx);
    fx.adapter.valid = false;
    fx.adapter.validationDiagnostics = ['invalid unit'];
    await assert.rejects(fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('start-invalid')), code('release_unit_invalid'));
    assert.deepEqual(fx.adapter.calls.filter((call) => ['install', 'start'].includes(call)), []);
  } finally { fx.close(); }
});

test('E06 private Unix-socket candidate starts without public exposure', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx);
    const ready = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('start-unix'));
    assert.equal(ready.state, 'READY_PRIVATE');
    assert.equal(ready.endpointType, 'UNIX_SOCKET');
    assert.equal(ready.routeMembership, false);
    assert.match(ready.endpointIdentity.endpoint, /application\.sock$/u);
  } finally { fx.close(); }
});

test('E07 private loopback fallback is deterministic and policy-gated', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx, { endpointMode: 'LOOPBACK_TCP' });
    const ready = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('start-loopback'));
    assert.equal(ready.endpointType, 'LOOPBACK_TCP');
    assert.match(ready.endpointIdentity.endpoint, /^127\.0\.0\.1:[0-9]+$/u);
    assert.throws(() => stage(fx, { slotId: 'green', key: 'stage-green-loopback', endpointMode: 'LOOPBACK_TCP', serviceOverrides: { endpointPolicy: { allowLoopbackFallback: false } } }));
  } finally { fx.close(); }
});

test('E08 native readiness and watchdog declarations are generated and verified', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx);
    assert.match(staged.unitBundle.unitBytes, /Type=notify/u);
    assert.match(staged.unitBundle.unitBytes, /WatchdogSec=30s/u);
    const ready = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('start-native'));
    assert.equal(ready.observedProcessIdentity.readinessState, 'READY');
    assert.equal(ready.observedProcessIdentity.watchdogState, 'ACTIVE');
  } finally { fx.close(); }
});

test('E09 compatibility readiness polling succeeds when native readiness is unavailable', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx, { serviceOverrides: { executableContract: { argv: ['/opt/notes/bin/server'], nativeReadiness: false, nativeWatchdog: false }, readinessProbe: { mode: 'POLL', probeType: 'CONNECT', timeoutMs: 5000, intervalMs: 5, maximumSamples: 8 } } });
    const ready = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('start-poll'));
    assert.equal(ready.state, 'READY_PRIVATE');
    assert.equal(ready.observedProcessIdentity.watchdogState, 'UNSUPPORTED');
  } finally { fx.close(); }
});

test('E10 alive-but-not-ready and readiness timeout fail without activation', async () => {
  for (const observations of [
    [running({ unitName: 'babyx-release-notes-api-blue.service', unitDigest: DIGEST_A, dropInDigest: DIGEST_B, executablePath: '/opt/notes/bin/server', nativeWatchdog: true }, { readinessState: 'NOT_READY' })],
    [],
  ]) {
    const fx = fixture();
    try {
      const staged = stage(fx);
      const bundle = staged.unitBundle;
      fx.adapter.readyObservations = observations.length === 0 ? [] : [running(bundle, { readinessState: 'NOT_READY' })];
      const result = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context(`start-not-ready-${observations.length}`));
      assert.equal(result.state, 'FAILED');
      assert.equal(result.routeMembership, false);
    } finally { fx.close(); }
  }
});

test('E11 exact unit, MainPID, process start, executable, boot, cgroup, and endpoint readback is persisted', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx);
    const ready = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('start-identity'));
    const identity = ready.observedProcessIdentity;
    assert.equal(identity.unitName, staged.systemdUnit);
    assert.equal(identity.mainPid, 4242);
    assert.equal(identity.processStartTime, '100');
    assert.equal(identity.executablePath, '/opt/notes/bin/server');
    assert.equal(identity.bootId, 'boot-a');
    assert.equal(identity.cgroup, `/system.slice/${staged.systemdUnit}`);
    assert.equal(identity.listenerOwner.unitName, staged.systemdUnit);
  } finally { fx.close(); }
});

for (const [name, override] of [
  ['E12 PID reuse/process-start mismatch is rejected', { processStartTime: '101' }],
  ['E13 executable mismatch is rejected', { executablePath: '/tmp/foreign' }],
  ['E14 boot-ID mismatch is rejected', { bootId: 'boot-b' }],
  ['E15 cgroup/unit mismatch is rejected', { cgroup: '/system.slice/foreign.service' }],
  ['E16 endpoint ownership mismatch is rejected', { endpointOwner: { pid: 9999, unitName: 'foreign.service' } }],
]) {
  test(name, async () => {
    const fx = fixture();
    try {
      const staged = stage(fx);
      fx.adapter.current = running(staged.unitBundle, override);
      const result = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context(`start-conflict-${name.slice(1, 3)}`));
      assert.equal(result.state, 'AMBIGUOUS');
      assert.equal(fx.adapter.calls.includes('start'), false);
    } finally { fx.close(); }
  });
}

test('E17 foreign Unix socket or loopback listener remains untouched and ambiguous', async () => {
  for (const endpointMode of ['UNIX_SOCKET', 'LOOPBACK_TCP']) {
    const fx = fixture();
    try {
      const staged = stage(fx, { endpointMode, key: `stage-${endpointMode.toLowerCase().replaceAll('_', '-')}` });
      fx.adapter.current = running(staged.unitBundle, { endpointOwner: { pid: 9000, unitName: 'foreign.service' } });
      const result = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context(`start-${endpointMode.toLowerCase().replaceAll('_', '-')}`));
      assert.equal(result.state, 'AMBIGUOUS');
      assert.equal(fx.adapter.calls.includes('stop'), false);
      assert.equal(fx.adapter.calls.includes('cleanup'), false);
    } finally { fx.close(); }
  }
});

test('E18 response loss after successful start adopts exact readback without duplicate start', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx);
    fx.adapter.startFailure = 'after';
    const result = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('start-response-loss'));
    assert.equal(result.state, 'READY_PRIVATE');
    assert.equal(fx.adapter.calls.filter((call) => call === 'start').length, 1);
  } finally { fx.close(); }
});

test('E19 controller restart adopts exact existing slot and refuses conflicting process', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx);
    fx.adapter.current = running(staged.unitBundle);
    const adopted = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('start-adopt'));
    assert.equal(adopted.state, 'READY_PRIVATE');
    assert.equal(fx.adapter.calls.filter((call) => call === 'start').length, 0);
  } finally { fx.close(); }
  const conflict = fixture();
  try {
    const staged = stage(conflict);
    conflict.adapter.current = running(staged.unitBundle, { processStartTime: 'reused' });
    const refused = await conflict.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('start-refuse'));
    assert.equal(refused.state, 'AMBIGUOUS');
    assert.equal(conflict.adapter.calls.filter((call) => call === 'start').length, 0);
  } finally { conflict.close(); }
});

test('E20 stop targets exact owned unit and verifies process, listener, and socket absence', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx);
    const ready = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('start-stop'));
    const stopped = await fx.service.stop({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: ready.sequence }, context('stop-owned'));
    assert.equal(stopped.state, 'STOPPED');
    assert.equal(fx.adapter.calls.filter((call) => call === 'stop').length, 1);
    assert.equal(stopped.livenessObservations.at(-1).endpointExists, false);
    assert.equal(stopped.livenessObservations.at(-1).mainPid, undefined);
  } finally { fx.close(); }
});

test('E21 stop response loss recovers from positive absence and conflicting identity becomes ambiguous', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx);
    const ready = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('start-stop-loss'));
    fx.adapter.stopFailure = 'after';
    const stopped = await fx.service.stop({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: ready.sequence }, context('stop-loss'));
    assert.equal(stopped.state, 'STOPPED');
  } finally { fx.close(); }
  const foreign = fixture();
  try {
    const staged = stage(foreign);
    const ready = await foreign.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('start-foreign-stop'));
    foreign.adapter.stopFailure = 'foreign';
    const result = await foreign.service.stop({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: ready.sequence }, context('stop-foreign'));
    assert.equal(result.state, 'AMBIGUOUS');
  } finally { foreign.close(); }
});

test('E22 cleanup requires positive absence and obstruction enters RECOVERY_REQUIRED', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx);
    fx.adapter.cleanupFailure = true;
    const result = await fx.service.cleanup({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('cleanup-obstructed'));
    assert.equal(result.state, 'RECOVERY_REQUIRED');
  } finally { fx.close(); }
});

test('E23 cleanup success proves unit, process, endpoint, runtime path, and transient unit absence', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx);
    const result = await fx.service.cleanup({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('cleanup-verified'));
    assert.equal(result.state, 'EMPTY_VERIFIED');
    assert.equal(result.cleanupCompletedAt.endsWith('Z'), true);
    assert.equal(result.releaseId, undefined);
  } finally { fx.close(); }
});

test('E24 active slot and protected rollback target cleanup are rejected', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx);
    const ready = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('start-active'));
    const active = fx.service.activate({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: ready.sequence, routeReadbackVerified: true, routeDigest: DIGEST_A }, context('activate'));
    await assert.rejects(fx.service.cleanup({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: active.sequence }, context('cleanup-active')), code('release_invalid_state'));
  } finally { fx.close(); }
  const rollback = fixture();
  try {
    const staged = stage(rollback);
    await assert.rejects(rollback.service.cleanup({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence, protectedRollbackTarget: true }, context('cleanup-rollback')), code('release_invalid_state'));
  } finally { rollback.close(); }
});

test('E25 only READY_PRIVATE may become ACTIVE and route readback is mandatory', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx);
    assert.throws(() => fx.service.activate({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence, routeReadbackVerified: true, routeDigest: DIGEST_A }, context('activate-staged')), code('release_invalid_state'));
    const ready = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('start-before-activate'));
    assert.throws(() => fx.service.activate({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: ready.sequence, routeReadbackVerified: false, routeDigest: DIGEST_A }, context('activate-no-readback')), code('release_route_ambiguous'));
  } finally { fx.close(); }
});

test('E26 wrong principal and stale sequence fail before systemd mutation', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx);
    await assert.rejects(fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence }, context('wrong-owner', OTHER)), code('release_record_not_found'));
    await assert.rejects(fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: staged.sequence - 1 }, context('stale')), code('release_stale_sequence'));
    assert.equal(fx.adapter.calls.length, 0);
  } finally { fx.close(); }
});

test('E27 exact idempotent replay returns same durable result and conflicting reuse fails', () => {
  const fx = fixture();
  try {
    const first = stage(fx, { key: 'stage-replay' });
    const replay = stage(fx, { key: 'stage-replay' });
    assert.deepEqual(replay, first);
    assert.throws(() => stage(fx, { key: 'stage-replay', releaseOverrides: { releaseId: 'release-b' } }), code('release_idempotency_conflict'));
  } finally { fx.close(); }
});

test('E28 active related durable jobs block false cleanup success', async () => {
  const fx = fixture({ jobs: { get(id) { return { id, status: 'running' }; } } });
  try {
    const staged = stage(fx);
    const record = { ...staged, activeJobIds: ['job-running'], allJobIds: ['job-running'], sequence: staged.sequence + 1 };
    fx.store.applyMutation({ schemaId: 'SlotRecordV1', recordId: 'notes-api:blue', ownerPrincipal: OWNER, expectedSequence: staged.sequence, idempotencyKey: 'bind-job', requestDigest: sha256(canonicalize(record)), operation: 'test.bind-job', phase: 'test', record, occurredAt: '2026-07-26T16:01:00.000Z', childJobIds: ['job-running'] });
    await assert.rejects(fx.service.cleanup({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: record.sequence }, context('cleanup-running-job')), code('release_active_jobs'));
    assert.equal(fx.adapter.calls.includes('cleanup'), false);
  } finally { fx.close(); }
});

test('E29 public service and slot reads are owner scoped, strict, read-only, and registered once', async () => {
  const fx = fixture();
  try {
    const staged = stage(fx);
    const before = filesystemSnapshot(fx.root);
    assert.equal(fx.service.getService({ serviceId: 'notes-api' }, context('read-service')).service.serviceId, 'notes-api');
    assert.equal(fx.service.listServices({}, context('read-list')).services.length, 1);
    assert.equal(fx.service.getSlot({ serviceId: 'notes-api', slotId: 'blue' }, context('read-slot')).slot.sequence, staged.sequence);
    assert.throws(() => fx.service.getSlot({ serviceId: 'notes-api', slotId: 'blue' }, context('read-other', OTHER)), code('release_record_not_found'));
    assert.throws(() => fx.service.getService({ serviceId: 'notes-api', mutate: true }, context('read-strict')), code('release_invalid_request'));
    assert.deepEqual(filesystemSnapshot(fx.root), before);
    for (const operation of ['babyx.release.service.get', 'babyx.release.service.list', 'babyx.release.slot.get']) {
      const definitions = operationDefinitions().filter((entry) => entry.operation === operation);
      assert.equal(definitions.length, 1);
      assert.equal(definitions[0].mutation, false);
      assert.equal(definitions[0].input.additionalProperties, false);
      if (operation.endsWith('.get')) assert.ok(Array.isArray(definitions[0].input.required));
    }
  } finally { fx.close(); }
});

test('E30 runtime routes owner-scoped read operations without exposing slot mutation', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-slot-runtime-public-'));
  try {
    const adapter = new FakeSystemdAdapter();
    const runtime = new BabyXRuntime({ stateRoot: root, slotSystemdAdapter: adapter });
    await assert.rejects(runtime.execute('babyx.release.service.get', { serviceId: 'missing' }, context('runtime-read')), /not found/u);
    const names = operationDefinitions().map((entry) => entry.operation);
    assert.equal(names.includes('babyx.release.slot.start'), false);
    assert.equal(names.includes('babyx.release.slot.stop'), false);
    assert.equal(names.includes('babyx.release.slot.cleanup'), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('E31 slot runtime composes existing store, job, and narrow systemd authority without alternate process supervisor', () => {
  const source = readFileSync(new URL('../src/release/slot.ts', import.meta.url), 'utf8');
  assert.equal(source.includes('new JobManager'), false);
  assert.equal(source.includes('child_process.spawn('), false);
  assert.equal(source.includes('systemd-nspawn'), false);
  assert.equal(source.includes('zfs '), false);
  assert.match(source, /SlotSystemdAdapter/u);
  assert.match(source, /SlotJobAuthority/u);
});

test('E32 only one slot per service may remain ACTIVE', async () => {
  const fx = fixture();
  try {
    const blueStaged = stage(fx, { key: 'stage-blue' });
    const blueReady = await fx.service.start({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: blueStaged.sequence }, context('start-blue'));
    const blueActive = fx.service.activate({ serviceId: 'notes-api', slotId: 'blue', expectedSequence: blueReady.sequence, routeReadbackVerified: true, routeDigest: DIGEST_A }, context('activate-blue'));
    const greenStaged = stage(fx, { slotId: 'green', key: 'stage-green', identityOverrides: { cgroup: '/system.slice/babyx-release-notes-api-green.service' } });
    fx.adapter.current = undefined;
    const greenReady = await fx.service.start({ serviceId: 'notes-api', slotId: 'green', expectedSequence: greenStaged.sequence }, context('start-green'));
    assert.throws(() => fx.service.activate({ serviceId: 'notes-api', slotId: 'green', expectedSequence: greenReady.sequence, routeReadbackVerified: true, routeDigest: DIGEST_B }, context('activate-green-too-early')), code('release_invalid_state'));
    const draining = fx.service.markDraining({ serviceId: 'notes-api', slotId: 'blue', routeReadbackVerified: true }, context('drain-blue'));
    assert.equal(draining.state, 'DRAINING');
    const greenActive = fx.service.activate({ serviceId: 'notes-api', slotId: 'green', expectedSequence: greenReady.sequence, routeReadbackVerified: true, routeDigest: DIGEST_B }, context('activate-green'));
    assert.equal(greenActive.state, 'ACTIVE');
    assert.equal(blueActive.state, 'ACTIVE');
  } finally { fx.close(); }
});
