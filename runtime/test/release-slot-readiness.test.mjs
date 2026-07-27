import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  HostSystemdSlotAdapter,
  ReleaseApplianceStore,
  SlotRuntimeService,
  canonicalize,
  generateSlotUnit,
  normalizeServiceDefinition,
  sha256,
} from '../../dist/runtime/index.js';

const OWNER = 'owner-release';
let fixtureSequence = 0;

function serviceDefinition(overrides = {}) {
  fixtureSequence += 1;
  const base = {
    schemaVersion: '1.0.0',
    serviceId: `readiness-${fixtureSequence}`,
    displayName: 'Readiness fixture',
    ownerPrincipal: OWNER,
    organization: 'stealtheye',
    repository: 'StealthEyeLLC/readiness-fixture',
    allowedRepositoryIds: [],
    serviceKind: 'API',
    deploymentGroup: 'readiness',
    orderedDependencies: [],
    runtimeIdentity: { serviceUser: 'nobody', serviceGroup: 'nogroup' },
    executableContract: { argv: [process.execPath], nativeReadiness: false, nativeWatchdog: false },
    workingDirectory: '.',
    environment: {},
    credentialReferenceNames: [],
    userPolicy: {},
    slotModel: 'BLUE_GREEN',
    endpointPreference: 'UNIX_SOCKET',
    endpointPolicy: { allowLoopbackFallback: true },
    readinessProbe: {
      schemaVersion: '1.0.0',
      mode: 'POLL',
      probeType: 'HTTP',
      timeoutMs: 500,
      intervalMs: 10,
      maximumSamples: 20,
      connectTimeoutMs: 50,
      responseTimeoutMs: 50,
      maxResponseBytes: 4096,
      httpPath: '/healthz',
      expectedStatusCodes: [200],
    },
    livenessProbe: { mode: 'SYSTEMD' },
    observationProbes: [],
    smokeTestProfile: { path: '/healthz' },
    drainProtocol: { kind: 'HTTP' },
    terminationPolicy: { signal: 'SIGTERM' },
    restartPolicy: { mode: 'ON_FAILURE' },
    resourceProfile: { class: 'PRODUCTION' },
    filesystemWritePolicy: { immutableRelease: true },
    stateDirectories: [],
    cacheDirectories: [],
    logDirectories: [],
    runtimeDirectories: [],
    caddyRouteTemplateId: 'route-v1',
    publicHostnames: [],
    pathMatchers: [],
    rollbackContract: { retainPrevious: true },
    retentionPolicy: { rollbackSlots: 1 },
    approvalPolicy: { mode: 'NONE' },
    automationPolicy: { automaticPromotion: false },
    provenance: { source: 'readiness-test' },
  };
  const merged = { ...base, ...overrides };
  const unsigned = { ...merged };
  delete unsigned.manifestDigest;
  return { ...unsigned, manifestDigest: sha256(canonicalize(unsigned)) };
}

function makeFixture(overrides = {}, endpointMode) {
  const root = mkdtempSync(join(tmpdir(), 'babyx-readiness-'));
  const service = serviceDefinition(overrides);
  const bundle = generateSlotUnit(service, 'blue', {
    releaseId: 'release-a',
    artifactSha256: 'a'.repeat(64),
    ...(endpointMode === undefined ? {} : { endpointMode }),
  }, {
    releaseRoot: join(root, 'releases'),
    runtimeRoot: join(root, 'runtime'),
    stateRoot: join(root, 'state'),
    cacheRoot: join(root, 'cache'),
    logRoot: join(root, 'log'),
  });
  mkdirSync(bundle.runtimeRoot, { recursive: true });
  const fragmentPath = join(root, bundle.unitName);
  const dropInPath = join(root, '10-babyx-release.conf');
  writeFileSync(fragmentPath, bundle.unitBytes);
  writeFileSync(dropInPath, bundle.dropInBytes);
  let showCount = 0;
  const state = {
    mainPid: process.pid,
    type: bundle.nativeReadiness ? 'notify' : 'simple',
    activeState: 'active',
    subState: 'running',
    watchdogUSec: bundle.nativeWatchdog ? '30000000' : '0',
    watchdogTimestamp: bundle.nativeWatchdog ? '1' : '0',
    mutateShow: undefined,
  };
  const manager = {
    async show() {
      showCount += 1;
      state.mutateShow?.(showCount, state);
      const output = [
        'LoadState=loaded',
        `ActiveState=${state.activeState}`,
        `SubState=${state.subState}`,
        `MainPID=${state.mainPid}`,
        `ControlGroup=/system.slice/${bundle.unitName}`,
        `FragmentPath=${fragmentPath}`,
        `DropInPaths=${dropInPath}`,
        `Type=${state.type}`,
        'NotifyAccess=main',
        `WatchdogUSec=${state.watchdogUSec}`,
        `WatchdogTimestampMonotonic=${state.watchdogTimestamp}`,
      ].join('\n') + '\n';
      return { exitCode: 0, stdout: Buffer.from(output).toString('base64'), stderrSha256: '0'.repeat(64) };
    },
  };
  const adapter = new HostSystemdSlotAdapter({ manager, unitRoot: join(root, 'units'), validationRoot: join(root, 'validation') });
  return { root, service, bundle, adapter, state, close() { rmSync(root, { recursive: true, force: true }); } };
}

async function listenHttp(bundle, handler) {
  const server = createHttpServer(handler);
  await new Promise((resolvePromise, rejectPromise) => {
    server.once('error', rejectPromise);
    if (bundle.endpointType === 'UNIX_SOCKET') server.listen(bundle.endpoint, resolvePromise);
    else server.listen(Number(bundle.endpoint.split(':')[1]), '127.0.0.1', resolvePromise);
  });
  return server;
}

async function listenNet(bundle) {
  const server = createNetServer((socket) => socket.end());
  await new Promise((resolvePromise, rejectPromise) => {
    server.once('error', rejectPromise);
    if (bundle.endpointType === 'UNIX_SOCKET') server.listen(bundle.endpoint, resolvePromise);
    else server.listen(Number(bundle.endpoint.split(':')[1]), '127.0.0.1', resolvePromise);
  });
  return server;
}

async function closeServer(server) {
  server.closeAllConnections?.();
  await new Promise((resolvePromise) => server.close(resolvePromise));
}

test('R2-01 active/running without endpoint is never READY', async () => {
  const fx = makeFixture();
  try {
    const observed = await fx.adapter.observe(fx.bundle);
    assert.equal(observed.activeState, 'active');
    assert.equal(observed.subState, 'running');
    assert.equal(observed.endpointExists, false);
    assert.equal(observed.readinessState, 'ENDPOINT_ABSENT');
  } finally { fx.close(); }
});

test('R2-02 unhealthy HTTP response remains NOT_READY', async () => {
  const fx = makeFixture();
  const server = await listenHttp(fx.bundle, (_request, response) => { response.statusCode = 503; response.end('unhealthy'); });
  try {
    const observed = await fx.adapter.observe(fx.bundle);
    assert.equal(observed.readinessState, 'NOT_READY');
    assert.equal(observed.readinessHttpStatus, 503);
    assert.match(observed.readinessResponseDigest, /^[a-f0-9]{64}$/u);
  } finally { await closeServer(server); fx.close(); }
});

test('R2-03 readiness polling observes a later healthy response', async () => {
  let healthy = false;
  const fx = makeFixture();
  const server = await listenHttp(fx.bundle, (_request, response) => { response.statusCode = healthy ? 200 : 503; response.end(healthy ? 'ready' : 'warming'); });
  const timer = setTimeout(() => { healthy = true; }, 35);
  try {
    const observations = await fx.adapter.waitReady(fx.bundle, fx.bundle.readinessProbe);
    assert.ok(observations.length >= 2);
    assert.equal(observations[0].readinessState, 'NOT_READY');
    assert.equal(observations.at(-1).readinessState, 'READY');
  } finally { clearTimeout(timer); await closeServer(server); fx.close(); }
});

test('R2-04 endpoint owned by another process is never ready', async () => {
  const fx = makeFixture();
  const server = await listenHttp(fx.bundle, (_request, response) => response.end('ready'));
  fx.state.mainPid = 1;
  try {
    const observed = await fx.adapter.observe(fx.bundle);
    assert.equal(observed.endpointExists, true);
    assert.equal(observed.readinessState, 'ENDPOINT_OWNER_MISMATCH');
  } finally { await closeServer(server); fx.close(); }
});

test('R2-05 process replacement during polling terminates with identity truth', async () => {
  const fx = makeFixture();
  const server = await listenHttp(fx.bundle, (_request, response) => { response.statusCode = 503; response.end('warming'); });
  fx.state.mutateShow = (count, state) => { if (count >= 2) state.mainPid = 1; };
  try {
    const observations = await fx.adapter.waitReady(fx.bundle, fx.bundle.readinessProbe);
    assert.equal(observations[0].readinessState, 'NOT_READY');
    assert.equal(observations.at(-1).readinessState, 'ENDPOINT_OWNER_MISMATCH');
  } finally { await closeServer(server); fx.close(); }
});

test('R2-06 bounded response timeout is classified TIMEOUT', async () => {
  const fx = makeFixture({ readinessProbe: { ...serviceDefinition().readinessProbe, schemaVersion: '1.0.0', mode: 'POLL', probeType: 'HTTP', timeoutMs: 80, intervalMs: 5, maximumSamples: 1, connectTimeoutMs: 20, responseTimeoutMs: 20, maxResponseBytes: 128, httpPath: '/healthz', expectedStatusCodes: [200] } });
  const server = await listenHttp(fx.bundle, () => {});
  try {
    const observations = await fx.adapter.waitReady(fx.bundle, fx.bundle.readinessProbe);
    assert.equal(observations.at(-1).readinessState, 'TIMEOUT');
  } finally { await closeServer(server); fx.close(); }
});

test('R2-07 CONNECT probes work for Unix sockets and loopback TCP', async () => {
  for (const endpointMode of ['UNIX_SOCKET', 'LOOPBACK_TCP']) {
    const fx = makeFixture({
      endpointPreference: endpointMode,
      readinessProbe: { schemaVersion: '1.0.0', mode: 'POLL', probeType: 'CONNECT', endpointType: endpointMode, timeoutMs: 200, intervalMs: 5, maximumSamples: 2, connectTimeoutMs: 50, responseTimeoutMs: 50, maxResponseBytes: 128 },
    }, endpointMode);
    const server = await listenNet(fx.bundle);
    try { assert.equal((await fx.adapter.observe(fx.bundle)).readinessState, 'READY'); }
    finally { await closeServer(server); fx.close(); }
  }
});

test('R2-08 HTTP probes work for Unix sockets and loopback TCP', async () => {
  for (const endpointMode of ['UNIX_SOCKET', 'LOOPBACK_TCP']) {
    const fx = makeFixture({
      endpointPreference: endpointMode,
      readinessProbe: { schemaVersion: '1.0.0', mode: 'POLL', probeType: 'HTTP', endpointType: endpointMode, timeoutMs: 200, intervalMs: 5, maximumSamples: 2, connectTimeoutMs: 50, responseTimeoutMs: 50, maxResponseBytes: 128, httpPath: '/ready', expectedStatusCodes: [204] },
    }, endpointMode);
    const server = await listenHttp(fx.bundle, (_request, response) => { response.statusCode = 204; response.end(); });
    try { assert.equal((await fx.adapter.observe(fx.bundle)).readinessState, 'READY'); }
    finally { await closeServer(server); fx.close(); }
  }
});

test('R2-09 native notify truth remains distinct from compatibility polling', async () => {
  const nativeProbe = { schemaVersion: '1.0.0', mode: 'NATIVE_NOTIFY', probeType: 'SYSTEMD_NOTIFY', timeoutMs: 200, intervalMs: 5, maximumSamples: 2, connectTimeoutMs: 50, responseTimeoutMs: 50, maxResponseBytes: 128 };
  const fx = makeFixture({ executableContract: { argv: [process.execPath], nativeReadiness: true, nativeWatchdog: true }, readinessProbe: nativeProbe });
  const server = await listenNet(fx.bundle);
  try {
    const ready = await fx.adapter.observe(fx.bundle);
    assert.equal(ready.readinessMode, 'NATIVE_NOTIFY');
    assert.equal(ready.watchdogState, 'ACTIVE');
    assert.equal(ready.readinessState, 'READY');
    fx.state.type = 'simple';
    assert.equal((await fx.adapter.observe(fx.bundle)).readinessState, 'IDENTITY_MISMATCH');
  } finally { await closeServer(server); fx.close(); }
});

test('R2-10 compatibility readiness without an explicit probe fails closed', () => {
  const definition = serviceDefinition({ readinessProbe: { schemaVersion: '1.0.0', mode: 'POLL', timeoutMs: 100, intervalMs: 5, maximumSamples: 2 } });
  assert.throws(() => normalizeServiceDefinition(definition), /explicit probeType/u);
});

test('R2-11 capability reporting distinguishes native and compatibility readiness', () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-readiness-capability-'));
  try {
    const service = new SlotRuntimeService({
      store: new ReleaseApplianceStore(join(root, 'store')),
      systemd: { authority: 'slot-systemd-adapter' },
      stateRoot: join(root, 'state-root'),
    });
    const readiness = service.describe().readiness;
    assert.equal(readiness.nativeNotify.systemdTruth, true);
    assert.deepEqual(readiness.compatibilityPoll.probeTypes, ['CONNECT', 'HTTP']);
    assert.equal(readiness.activeRunningAloneIsReady, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
