import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import {
  ArtifactManager,
  BabyXRuntime,
  HostCaddyAdminAdapter,
  ReleaseApplianceStore,
  RouteAuthorityError,
  RouteAuthorityService,
  canonicalize,
  evaluateCanaryPolicy,
  generateTrustedCaddyConfig,
  observedRouteUpstreams,
  operationDefinitions,
  removeTrustedCaddyRoute,
  sha256,
} from '../../dist/runtime/index.js';

const OWNER = 'owner-release';
const OTHER = 'other-owner';
const OBS = 'a'.repeat(64);
const RELEASE = 'release-green';

function publicIdentity(overrides = {}) {
  return {
    serverId: 'production',
    hostnames: ['notes.example.test'],
    paths: ['/api/*'],
    publicProbeUrl: 'https://notes.example.test/healthz',
    trustedIdentityHeaders: ['X-BabyX-Identity'],
    ...overrides,
  };
}

function directRequest(endpoint = { type: 'UNIX_SOCKET', value: '/run/babyx/notes-api/green/application.sock' }, overrides = {}) {
  return {
    serviceId: 'notes-api',
    desiredActiveSlot: 'green',
    endpoint,
    publicIdentity: publicIdentity(),
    policy: { mode: 'DIRECT' },
    streamSettings: { websocket: true, sse: true, keepAlive: true, streamCloseDelayMs: 30000, flushIntervalMs: -1 },
    expectedReleaseIdentity: RELEASE,
    ...overrides,
  };
}

function canaryPolicy(overrides = {}) {
  return {
    mode: 'CANARY',
    stableEndpoint: { type: 'UNIX_SOCKET', value: '/run/babyx/notes-api/blue/application.sock' },
    weightBasisPoints: 1500,
    stickiness: { kind: 'COOKIE', name: 'babyx_canary', ttlSeconds: 900 },
    minimumSamples: 4,
    rollbackThresholds: { errorRate: 0.25, latencyMs: 500, consecutiveFailures: 2 },
    hysteresis: { breachSamples: 2, recoverySamples: 3 },
    cooldownMs: 60000,
    ...overrides,
  };
}

function shadowPolicy(overrides = {}) {
  return {
    mode: 'SHADOW',
    primaryEndpoint: { type: 'UNIX_SOCKET', value: '/run/babyx/notes-api/blue/application.sock' },
    allowedMethods: ['GET', 'HEAD'],
    maxBodyBytes: 1048576,
    maxRequestsPerSecond: 50,
    credentialMode: 'STRIP',
    sideEffectMode: 'READ_ONLY',
    ...overrides,
  };
}

function previewPolicy(expiresAt = '2026-07-26T18:00:00.000Z', overrides = {}) {
  return {
    mode: 'PREVIEW',
    trustedHeader: 'X-BabyX-Identity',
    identityValue: 'preview-42',
    expiresAt,
    authenticationRequired: true,
    ...overrides,
  };
}

function baseConfig() {
  return { admin: { disabled: false }, apps: { http: { servers: { production: { listen: [':443'], routes: [] } } } } };
}

function priorConfig() {
  return generateTrustedCaddyConfig(baseConfig(), directRequest({ type: 'UNIX_SOCKET', value: '/run/babyx/notes-api/blue/application.sock' }, { desiredActiveSlot: 'blue', expectedReleaseIdentity: 'release-blue' }), OWNER).config;
}

function context(key, subject = OWNER, authorityClass = 'owner') {
  return { idempotencyKey: key, subject, authorityClass };
}

function lease(id = 'route-lease-a', overrides = {}) {
  return {
    leaseId: id,
    controllerIdentity: { controllerId: id, bootId: 'boot-a', processStartTime: '100' },
    acquiredAt: '2026-07-26T16:00:00.000Z',
    expiresAt: '2026-07-26T20:00:00.000Z',
    observationDigest: OBS,
    existingControllerAbsent: false,
    ...overrides,
  };
}

function probe(kind, status = 'PASS', overrides = {}) {
  return {
    kind,
    status,
    observedAt: '2026-07-26T16:00:01.000Z',
    statusCode: status === 'PASS' ? (kind === 'ABSENCE' ? 404 : 200) : 503,
    latencyMs: 5,
    responseDigest: 'b'.repeat(64),
    observedReleaseIdentity: RELEASE,
    detailsDigest: 'c'.repeat(64),
    ...overrides,
  };
}

class FakeCaddyAdapter {
  authority = 'route-caddy-adapter';
  calls = [];
  currentConfig;
  validationValid = true;
  loadFailure = undefined;
  readbackOverride = undefined;
  probeQueues = { PRIVATE: [], PUBLIC: [], ABSENCE: [] };
  discovery = {
    available: true,
    executablePath: '/usr/bin/caddy',
    version: 'v2.10.0 test',
    modules: ['http.handlers.reverse_proxy', 'http.reverse_proxy.selection_policies.weighted_round_robin', 'http.handlers.request_mirror'],
    adminTransport: 'LOOPBACK',
    adminLocalOnly: true,
    autosaveCompatible: true,
    resumeCompatible: true,
    streamCloseDelaySupported: true,
  };

  constructor(config = priorConfig()) { this.currentConfig = structuredClone(config); }
  async discover() { this.calls.push('discover'); return structuredClone(this.discovery); }
  async capture() { this.calls.push('capture'); return this.observation(this.currentConfig); }
  async validate(bytes, requiredModules) {
    this.calls.push('validate');
    const candidateDigest = sha256(bytes);
    const missing = requiredModules.filter((module) => !this.discovery.modules.includes(module));
    return {
      valid: this.validationValid && missing.length === 0,
      installedVersion: this.discovery.version,
      candidateDigest,
      adaptedDigest: sha256(canonicalize({ candidateDigest, version: this.discovery.version })),
      diagnostics: this.validationValid && missing.length === 0 ? [] : ['invalid candidate'],
      requiredModules: [...requiredModules].sort(),
      availableModules: [...this.discovery.modules].sort(),
    };
  }
  async load(bytes, requestDigest) {
    this.calls.push('load');
    if (this.loadFailure === 'before') throw new Error('load failed before effect');
    this.currentConfig = JSON.parse(bytes.toString('utf8'));
    if (this.loadFailure === 'after') throw new Error('response lost after effect');
    return { accepted: true, statusCode: 200, responseDigest: sha256('ok'), requestDigest };
  }
  async readback(routeId) {
    this.calls.push('readback');
    if (this.readbackOverride !== undefined) return this.observation(this.readbackOverride, routeId);
    return this.observation(this.currentConfig, routeId);
  }
  async probe(request) {
    this.calls.push(`probe:${request.kind}`);
    const queue = this.probeQueues[request.kind];
    if (queue.length > 0) return structuredClone(queue.shift());
    return probe(request.kind);
  }
  observation(config, routeId) {
    const bytes = Buffer.from(canonicalize(config));
    const result = { observedAt: '2026-07-26T16:00:01.000Z', config: structuredClone(config), configDigest: sha256(bytes) };
    if (routeId !== undefined) {
      const upstreams = observedRouteUpstreams(config, routeId);
      result.routePresent = upstreams.length > 0;
      result.observedUpstreams = upstreams;
    }
    return result;
  }
}

function fixture(options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-release-route-'));
  const store = new ReleaseApplianceStore(join(root, 'store'));
  const artifacts = new ArtifactManager(join(root, 'artifacts'));
  const caddy = options.caddy ?? new FakeCaddyAdapter(options.baseConfig ?? priorConfig());
  let now = options.now ?? '2026-07-26T16:00:02.000Z';
  const service = new RouteAuthorityService({ stateRoot: root, store, artifacts, caddy, now: () => now });
  return {
    root, store, artifacts, caddy, service,
    setNow(value) { now = value; },
    close() { rmSync(root, { recursive: true, force: true }); },
  };
}

function acquire(fx, value = lease(), key = 'lease-acquire') {
  return fx.service.acquireLease('notes-api', value, context(key));
}

async function prepare(fx, options = {}) {
  const leaseValue = options.lease ?? lease();
  if (options.acquire !== false) acquire(fx, leaseValue, options.leaseKey ?? 'lease-acquire');
  return fx.service.prepare({ request: options.request ?? directRequest(), lease: leaseValue, ...(options.expectedSequence === undefined ? {} : { expectedSequence: options.expectedSequence }) }, context(options.key ?? 'route-prepare', options.subject ?? OWNER));
}

async function active(fx, options = {}) {
  const leaseValue = options.lease ?? lease();
  const prepared = await prepare(fx, { ...options, lease: leaseValue });
  const result = await fx.service.cutover({ serviceId: 'notes-api', lease: leaseValue, expectedSequence: prepared.sequence, publicProbeExpectedReleaseIdentity: RELEASE }, context(options.cutoverKey ?? 'route-cutover', options.subject ?? OWNER));
  return { prepared, result, lease: leaseValue };
}

function code(expected) {
  return (error) => (error instanceof RouteAuthorityError || typeof error?.code === 'string') && error.code === expected;
}

function snapshot(root) {
  const rows = [];
  function walk(path) {
    for (const name of readdirSync(path).sort()) {
      const absolute = join(path, name);
      const info = statSync(absolute);
      const key = relative(root, absolute);
      if (info.isDirectory()) { rows.push({ key, type: 'directory' }); walk(absolute); }
      else rows.push({ key, type: 'file', size: info.size, digest: sha256(readFileSync(absolute)) });
    }
  }
  walk(root);
  return rows;
}

test('F01 trusted route-template generation is deterministic', () => {
  const first = generateTrustedCaddyConfig(priorConfig(), directRequest(), OWNER);
  const second = generateTrustedCaddyConfig(priorConfig(), directRequest(), OWNER);
  assert.equal(first.digest, second.digest);
  assert.equal(first.bytes.toString('utf8'), second.bytes.toString('utf8'));
  assert.equal(first.templateId, 'http-private-upstream-v1');
});

test('F02 arbitrary untrusted Caddy JSON and unknown request fields are rejected', () => {
  assert.throws(() => generateTrustedCaddyConfig(priorConfig(), { ...directRequest(), rawCaddyJson: { admin: { listen: ':9999' } } }, OWNER), code('release_invalid_request'));
  assert.throws(() => generateTrustedCaddyConfig(priorConfig(), { ...directRequest(), endpoint: { type: 'LOOPBACK_TCP', value: '0.0.0.0:8080' } }, OWNER), code('release_invalid_request'));
});

test('F03 candidate generation replaces only the stable service route in a complete config', () => {
  const before = priorConfig();
  const generated = generateTrustedCaddyConfig(before, directRequest(), OWNER);
  assert.deepEqual(observedRouteUpstreams(generated.config, 'route-notes-api'), ['unix//run/babyx/notes-api/green/application.sock']);
  assert.equal(generated.config.admin.disabled, false);
  assert.equal(generated.config.apps.http.servers.production.listen[0], ':443');
  assert.deepEqual(observedRouteUpstreams(before, 'route-notes-api'), ['unix//run/babyx/notes-api/blue/application.sock']);
});

test('F04 installed-version validation succeeds and is bound into the durable route record', async () => {
  const fx = fixture();
  try {
    const record = await prepare(fx);
    assert.equal(record.state, 'VALIDATED');
    assert.equal(record.validationResult.valid, true);
    assert.equal(record.installedCaddyVersion, 'v2.10.0 test');
    assert.equal(record.installedCaddyCapabilities.autosaveCompatible, true);
    assert.equal(record.installedCaddyCapabilities.resumeCompatible, true);
  } finally { fx.close(); }
});

test('F05 validation failure occurs before load', async () => {
  const fx = fixture();
  try {
    fx.caddy.validationValid = false;
    const record = await prepare(fx);
    assert.equal(record.state, 'RECOVERY_REQUIRED');
    assert.equal(fx.caddy.calls.includes('load'), false);
  } finally { fx.close(); }
});

test('F06 invalid candidate leaves the prior config active', async () => {
  const fx = fixture();
  try {
    const before = canonicalize(fx.caddy.currentConfig);
    fx.caddy.validationValid = false;
    await prepare(fx);
    assert.equal(canonicalize(fx.caddy.currentConfig), before);
  } finally { fx.close(); }
});

test('F07 successful load is followed by exact config and upstream readback', async () => {
  const fx = fixture();
  try {
    const { result } = await active(fx);
    assert.equal(result.state, 'ACTIVE_VERIFIED');
    assert.equal(result.activeConfigReadbackDigest, result.candidateConfigDigest);
    assert.deepEqual(result.observedActiveUpstream.upstreams, result.expectedUpstreams);
    assert.ok(fx.caddy.calls.indexOf('load') < fx.caddy.calls.lastIndexOf('readback'));
  } finally { fx.close(); }
});

test('F08 API response loss after successful load recovers by readback', async () => {
  const fx = fixture();
  try {
    fx.caddy.loadFailure = 'after';
    const { result } = await active(fx);
    assert.equal(result.state, 'ACTIVE_VERIFIED');
    assert.equal(fx.caddy.calls.filter((call) => call === 'load').length, 1);
  } finally { fx.close(); }
});

test('F09 response loss never blindly repeats the Caddy load', async () => {
  const fx = fixture();
  try {
    fx.caddy.loadFailure = 'after';
    const { result, lease: leaseValue } = await active(fx);
    const replay = await fx.service.cutover({ serviceId: 'notes-api', lease: leaseValue, expectedSequence: result.sequence - 3, publicProbeExpectedReleaseIdentity: RELEASE }, context('route-cutover'));
    assert.equal(replay.state, 'ACTIVE_VERIFIED');
    assert.equal(fx.caddy.calls.filter((call) => call === 'load').length, 1);
  } finally { fx.close(); }
});

test('F10 unknown active configuration enters AMBIGUOUS', async () => {
  const fx = fixture();
  try {
    const prepared = await prepare(fx);
    fx.caddy.loadFailure = 'before';
    fx.caddy.readbackOverride = { apps: { http: { servers: { production: { listen: [':443'], routes: [{ '@id': 'foreign', handle: [] }] } } } } };
    const result = await fx.service.cutover({ serviceId: 'notes-api', lease: lease(), expectedSequence: prepared.sequence }, context('route-cutover-unknown'));
    assert.equal(result.state, 'AMBIGUOUS');
  } finally { fx.close(); }
});

test('F11 ambiguity blocks restoration and further destructive mutation', async () => {
  const fx = fixture();
  try {
    const prepared = await prepare(fx);
    fx.caddy.loadFailure = 'before';
    fx.caddy.readbackOverride = { apps: { http: { servers: { production: { routes: [{ '@id': 'foreign', handle: [] }] } } } } };
    const ambiguous = await fx.service.cutover({ serviceId: 'notes-api', lease: lease(), expectedSequence: prepared.sequence }, context('route-cutover-ambiguous'));
    await assert.rejects(fx.service.restore({ serviceId: 'notes-api', lease: lease(), expectedSequence: ambiguous.sequence }, context('route-restore-ambiguous')), code('release_route_ambiguous'));
    assert.equal(fx.caddy.calls.filter((call) => call === 'load').length, 1);
  } finally { fx.close(); }
});

test('F12 previous and candidate full configurations are preserved as exact artifacts and digests', async () => {
  const fx = fixture();
  try {
    const record = await prepare(fx);
    const prior = fx.artifacts.get(record.previousConfigArtifactId);
    const candidate = fx.artifacts.get(record.candidateConfigArtifactId);
    assert.equal(prior.state, 'finalized');
    assert.equal(candidate.state, 'finalized');
    assert.equal(prior.sha256, record.previousConfigDigest);
    assert.equal(candidate.sha256, record.candidateConfigDigest);
    assert.notEqual(prior.sha256, candidate.sha256);
  } finally { fx.close(); }
});

test('F13 exact previous configuration restoration succeeds', async () => {
  const fx = fixture();
  try {
    const { result, lease: leaseValue } = await active(fx);
    fx.caddy.probeQueues.PUBLIC.push(probe('PUBLIC'));
    const restored = await fx.service.restore({ serviceId: 'notes-api', lease: leaseValue, expectedSequence: result.sequence }, context('route-restore'));
    assert.equal(restored.state, 'RESTORED_VERIFIED');
    assert.equal(restored.restorationReadbackDigest, restored.previousConfigDigest);
    assert.deepEqual(observedRouteUpstreams(fx.caddy.currentConfig, 'route-notes-api'), ['unix//run/babyx/notes-api/blue/application.sock']);
  } finally { fx.close(); }
});

test('F14 restoration requires exact readback', async () => {
  const fx = fixture();
  try {
    const { result, lease: leaseValue } = await active(fx);
    fx.caddy.loadFailure = 'after';
    const restored = await fx.service.restore({ serviceId: 'notes-api', lease: leaseValue, expectedSequence: result.sequence }, context('route-restore-loss'));
    assert.equal(restored.state, 'RESTORED_VERIFIED');
    assert.equal(restored.restorationReadbackDigest, restored.previousConfigDigest);
  } finally { fx.close(); }
});

test('F15 restoration public probe failure remains RECOVERY_REQUIRED', async () => {
  const fx = fixture();
  try {
    const { result, lease: leaseValue } = await active(fx);
    fx.caddy.probeQueues.PUBLIC.push(probe('PUBLIC', 'FAIL'));
    const restored = await fx.service.restore({ serviceId: 'notes-api', lease: leaseValue, expectedSequence: result.sequence }, context('route-restore-probe-fail'));
    assert.equal(restored.state, 'RECOVERY_REQUIRED');
  } finally { fx.close(); }
});

test('F16 Unix-socket upstream generation and readback are exact', () => {
  const generated = generateTrustedCaddyConfig(baseConfig(), directRequest(), OWNER);
  assert.deepEqual(generated.expectedUpstreams, ['unix//run/babyx/notes-api/green/application.sock']);
  assert.deepEqual(observedRouteUpstreams(generated.config, generated.routeId), generated.expectedUpstreams);
});

test('F17 loopback upstream generation permits only private loopback', () => {
  const generated = generateTrustedCaddyConfig(baseConfig(), directRequest({ type: 'LOOPBACK_TCP', value: '127.0.0.1:31001' }), OWNER);
  assert.deepEqual(generated.expectedUpstreams, ['127.0.0.1:31001']);
  assert.throws(() => generateTrustedCaddyConfig(baseConfig(), directRequest({ type: 'LOOPBACK_TCP', value: '192.0.2.1:31001' }), OWNER), code('release_invalid_request'));
});

test('F18 wrong upstream readback is rejected as ambiguous', async () => {
  const fx = fixture();
  try {
    const prepared = await prepare(fx);
    fx.caddy.loadFailure = 'before';
    fx.caddy.readbackOverride = generateTrustedCaddyConfig(baseConfig(), directRequest({ type: 'LOOPBACK_TCP', value: '127.0.0.1:39999' }), OWNER).config;
    const result = await fx.service.cutover({ serviceId: 'notes-api', lease: lease(), expectedSequence: prepared.sequence }, context('route-wrong-upstream'));
    assert.equal(result.state, 'AMBIGUOUS');
  } finally { fx.close(); }
});

test('F19 private probe failure blocks validation and load', async () => {
  const fx = fixture();
  try {
    fx.caddy.probeQueues.PRIVATE.push(probe('PRIVATE', 'FAIL'));
    const result = await prepare(fx);
    assert.equal(result.state, 'RECOVERY_REQUIRED');
    assert.equal(fx.caddy.calls.includes('load'), false);
  } finally { fx.close(); }
});

test('F20 public probe failure restores the previous config', async () => {
  const fx = fixture();
  try {
    fx.caddy.probeQueues.PUBLIC.push(probe('PUBLIC', 'FAIL'), probe('PUBLIC', 'PASS'));
    const { result } = await active(fx);
    assert.equal(result.state, 'RESTORED_VERIFIED');
    assert.deepEqual(observedRouteUpstreams(fx.caddy.currentConfig, 'route-notes-api'), ['unix//run/babyx/notes-api/blue/application.sock']);
  } finally { fx.close(); }
});

test('F21 overlapping live route leases are rejected', () => {
  const fx = fixture();
  try {
    acquire(fx);
    assert.throws(() => fx.service.acquireLease('notes-api', lease('route-lease-b', { observationDigest: 'd'.repeat(64) }), context('lease-b')), /lease|controller/iu);
  } finally { fx.close(); }
});

test('F22 stale route-lease takeover requires positive controller absence', () => {
  const fx = fixture({ now: '2026-07-26T16:00:02.000Z' });
  try {
    acquire(fx, lease('route-lease-old', { expiresAt: '2026-07-26T16:01:00.000Z' }), 'lease-old');
    fx.setNow('2026-07-26T16:02:00.000Z');
    assert.throws(() => fx.service.acquireLease('notes-api', lease('route-lease-new', { acquiredAt: '2026-07-26T16:02:00.000Z', expiresAt: '2026-07-26T20:00:00.000Z', observationDigest: 'e'.repeat(64) }), context('lease-new-no-absence')), /absence|lease|controller/iu);
    const taken = fx.service.acquireLease('notes-api', lease('route-lease-new', { acquiredAt: '2026-07-26T16:02:00.000Z', expiresAt: '2026-07-26T20:00:00.000Z', observationDigest: 'e'.repeat(64), existingControllerAbsent: true }), context('lease-new'));
    assert.equal(taken.leaseId, 'route-lease-new');
  } finally { fx.close(); }
});

test('F23 released applications receive no Caddy admin endpoint or credentials', () => {
  const generated = generateTrustedCaddyConfig(baseConfig(), directRequest(), OWNER);
  const bytes = generated.bytes.toString('utf8');
  assert.equal(bytes.includes('2019'), false);
  assert.equal(bytes.includes('adminEndpoint'), false);
  assert.equal(bytes.includes('Authorization'), false);
});

test('F24 public Caddy admin listeners and unproven Unix admin sockets are rejected', () => {
  assert.throws(() => new HostCaddyAdminAdapter({ adminEndpoint: 'http://0.0.0.0:2019/', validationRoot: '/tmp/caddy-validate' }), code('release_public_admin_forbidden'));
  assert.throws(() => new HostCaddyAdminAdapter({ adminEndpoint: 'http://caddy.example.test:2019/', validationRoot: '/tmp/caddy-validate' }), code('release_public_admin_forbidden'));
  assert.throws(() => new HostCaddyAdminAdapter({ adminEndpoint: 'unix:/run/caddy/admin.sock', validationRoot: '/tmp/caddy-validate' }), code('release_provider_incompatible'));
  assert.doesNotThrow(() => new HostCaddyAdminAdapter({ adminEndpoint: 'unix:/run/caddy/admin.sock', unixSocketCapable: true, validationRoot: '/tmp/caddy-validate' }));
});

test('F25 autosave and resume compatibility are capability-bound', async () => {
  const fx = fixture();
  try {
    const record = await prepare(fx);
    assert.equal(record.installedCaddyCapabilities.autosaveCompatible, true);
    assert.equal(record.installedCaddyCapabilities.resumeCompatible, true);
  } finally { fx.close(); }
});

test('F26 WebSocket-compatible route avoids disabling upgrade handling', () => {
  const generated = generateTrustedCaddyConfig(baseConfig(), directRequest(), OWNER);
  const route = generated.config.apps.http.servers.production.routes.find((entry) => entry['@id'] === 'babyx-route-notes-api');
  assert.equal(route.handle[0].handler, 'reverse_proxy');
  assert.equal(route.handle[0].websocket, undefined);
});

test('F27 SSE route uses immediate flush behavior', () => {
  const generated = generateTrustedCaddyConfig(baseConfig(), directRequest(), OWNER);
  const route = generated.config.apps.http.servers.production.routes.find((entry) => entry['@id'] === 'babyx-route-notes-api');
  assert.equal(route.handle[0].flush_interval, -1);
});

test('F28 keep-alive behavior remains enabled across cutover', () => {
  const generated = generateTrustedCaddyConfig(baseConfig(), directRequest(), OWNER);
  const route = generated.config.apps.http.servers.production.routes.find((entry) => entry['@id'] === 'babyx-route-notes-api');
  assert.equal(route.handle[0].transport.keep_alive.enabled, true);
});

test('F29 stream close delay is bounded and deterministic', () => {
  const generated = generateTrustedCaddyConfig(baseConfig(), directRequest(), OWNER);
  const route = generated.config.apps.http.servers.production.routes.find((entry) => entry['@id'] === 'babyx-route-notes-api');
  assert.equal(route.handle[0].stream_close_delay, '30000ms');
  assert.throws(() => generateTrustedCaddyConfig(baseConfig(), directRequest(undefined, { streamSettings: { websocket: true, sse: false, keepAlive: true, streamCloseDelayMs: 300001, flushIntervalMs: 100 } }), OWNER), code('release_invalid_request'));
});

test('F30 canary weight generation is deterministic', () => {
  const request = directRequest(undefined, { policy: canaryPolicy() });
  const first = generateTrustedCaddyConfig(baseConfig(), request, OWNER);
  const second = generateTrustedCaddyConfig(baseConfig(), request, OWNER);
  const handler = first.config.apps.http.servers.production.routes[0].handle[0];
  assert.equal(first.digest, second.digest);
  assert.deepEqual(handler.upstreams.map((entry) => entry.weight), [8500, 1500]);
});

test('F31 canary request stickiness is typed and persisted', () => {
  const generated = generateTrustedCaddyConfig(baseConfig(), directRequest(undefined, { policy: canaryPolicy() }), OWNER);
  const selection = generated.config.apps.http.servers.production.routes[0].handle[0].load_balancing.selection_policy;
  assert.equal(selection.policy, 'weighted_round_robin');
  assert.deepEqual(selection.stickiness, { kind: 'COOKIE', name: 'babyx_canary', ttlSeconds: 900 });
});

test('F32 canary threshold evaluation triggers rollback', () => {
  const policy = canaryPolicy({ hysteresis: { breachSamples: 1, recoverySamples: 3 } });
  const result = evaluateCanaryPolicy(policy, [{ ok: true, latencyMs: 100 }, { ok: false, latencyMs: 900 }, { ok: false, latencyMs: 1000 }, { ok: false, latencyMs: 1100 }]);
  assert.equal(result.decision, 'ROLLBACK');
  assert.equal(result.latchedRollback, true);
});

test('F33 canary hysteresis prevents route flapping', () => {
  const policy = canaryPolicy();
  const samples = [{ ok: true, latencyMs: 100 }, { ok: false, latencyMs: 900 }, { ok: false, latencyMs: 1000 }, { ok: false, latencyMs: 1100 }];
  const first = evaluateCanaryPolicy(policy, samples);
  assert.equal(first.decision, 'CONTINUE');
  const second = evaluateCanaryPolicy(policy, samples, first);
  assert.equal(second.decision, 'ROLLBACK');
  const healthy = evaluateCanaryPolicy(policy, [{ ok: true, latencyMs: 20 }, { ok: true, latencyMs: 20 }, { ok: true, latencyMs: 20 }, { ok: true, latencyMs: 20 }], second);
  assert.equal(healthy.decision, 'ROLLBACK');
  assert.equal(healthy.noFlap, true);
});

test('F34 shadow response is isolated and never returned to the caller', () => {
  const generated = generateTrustedCaddyConfig(baseConfig(), directRequest(undefined, { policy: shadowPolicy() }), OWNER);
  const handlers = generated.config.apps.http.servers.production.routes[0].handle;
  assert.equal(handlers[0].handler, 'request_mirror');
  assert.equal(handlers[0].response_mode, 'discard');
  assert.equal(handlers[1].handler, 'reverse_proxy');
  assert.deepEqual(handlers[1].upstreams, [{ dial: 'unix//run/babyx/notes-api/blue/application.sock' }]);
});

test('F35 shadow side-effect and credential restrictions are enforced', () => {
  assert.throws(() => generateTrustedCaddyConfig(baseConfig(), directRequest(undefined, { policy: shadowPolicy({ allowedMethods: ['POST'] }) }), OWNER), code('release_shadow_side_effect_forbidden'));
  assert.throws(() => generateTrustedCaddyConfig(baseConfig(), directRequest(undefined, { policy: shadowPolicy({ credentialMode: 'FORWARD' }) }), OWNER), code('release_shadow_credential_forbidden'));
  const generated = generateTrustedCaddyConfig(baseConfig(), directRequest(undefined, { policy: shadowPolicy() }), OWNER);
  const mirror = generated.config.apps.http.servers.production.routes[0].handle[0];
  assert.deepEqual(mirror.strip_headers, ['Authorization', 'Cookie', 'Proxy-Authorization']);
  assert.equal(mirror.side_effect_mode, 'read_only');
});

test('F36 preview routing requires authentication', () => {
  assert.throws(() => generateTrustedCaddyConfig(baseConfig(), directRequest(undefined, { policy: previewPolicy(undefined, { authenticationRequired: false }) }), OWNER), code('release_preview_auth_required'));
  assert.throws(() => generateTrustedCaddyConfig(baseConfig(), directRequest(undefined, { publicIdentity: publicIdentity({ trustedIdentityHeaders: [] }), policy: previewPolicy() }), OWNER), code('release_preview_auth_required'));
});

test('F37 preview selection is constrained to a trusted identity header', () => {
  const generated = generateTrustedCaddyConfig(baseConfig(), directRequest(undefined, { policy: previewPolicy() }), OWNER);
  const route = generated.config.apps.http.servers.production.routes[0];
  assert.deepEqual(route.match[0].header, { 'X-BabyX-Identity': ['preview-42'] });
});

test('F38 preview expiration is persisted and enforced', async () => {
  const fx = fixture({ baseConfig: baseConfig() });
  try {
    const request = directRequest(undefined, { policy: previewPolicy('2026-07-26T16:10:00.000Z') });
    const prepared = await prepare(fx, { request });
    assert.equal(prepared.previewExpiresAt, '2026-07-26T16:10:00.000Z');
    await assert.rejects(fx.service.expirePreview({ serviceId: 'notes-api', lease: lease() }, context('preview-expire-early')), code('release_preview_not_expired'));
  } finally { fx.close(); }
});

test('F39 expired preview route is removed by exact previous-config restoration', async () => {
  const fx = fixture({ baseConfig: baseConfig() });
  try {
    const request = directRequest(undefined, { policy: previewPolicy('2026-07-26T16:10:00.000Z') });
    const { result, lease: leaseValue } = await active(fx, { request });
    assert.equal(result.state, 'ACTIVE_VERIFIED');
    fx.setNow('2026-07-26T16:11:00.000Z');
    fx.caddy.probeQueues.ABSENCE.push(probe('ABSENCE'));
    const expired = await fx.service.expirePreview({ serviceId: 'notes-api', lease: leaseValue }, context('preview-expire'));
    assert.equal(expired.state, 'RESTORED_VERIFIED');
    assert.equal(observedRouteUpstreams(fx.caddy.currentConfig, 'route-notes-api').length, 0);
  } finally { fx.close(); }
});

test('F40 preview cleanup records route removal truth', async () => {
  const fx = fixture({ baseConfig: baseConfig() });
  try {
    const { lease: leaseValue } = await active(fx, { request: directRequest(undefined, { policy: previewPolicy('2026-07-26T16:10:00.000Z') }) });
    fx.setNow('2026-07-26T16:11:00.000Z');
    fx.caddy.probeQueues.ABSENCE.push(probe('ABSENCE'));
    const expired = await fx.service.expirePreview({ serviceId: 'notes-api', lease: leaseValue }, context('preview-cleanup'));
    assert.equal(expired.previewCleanup.routeRemoved, true);
    assert.equal(expired.cleanupCompletedAt, '2026-07-26T16:11:00.000Z');
  } finally { fx.close(); }
});

test('F41 preview cleanup requires positive route absence', async () => {
  const removed = removeTrustedCaddyRoute(generateTrustedCaddyConfig(baseConfig(), directRequest(undefined, { policy: previewPolicy() }), OWNER).config, 'route-notes-api', 'production');
  assert.equal(removed.absent, true);
  assert.equal(observedRouteUpstreams(removed.config, 'route-notes-api').length, 0);
});

test('F42 wrong principal fails before Caddy mutation', async () => {
  const fx = fixture();
  try {
    const prepared = await prepare(fx);
    await assert.rejects(fx.service.cutover({ serviceId: 'notes-api', lease: lease(), expectedSequence: prepared.sequence }, context('wrong-principal', OTHER)), code('release_record_not_found'));
    assert.equal(fx.caddy.calls.includes('load'), false);
  } finally { fx.close(); }
});

test('F43 stale sequence fails before Caddy mutation', async () => {
  const fx = fixture();
  try {
    const prepared = await prepare(fx);
    await assert.rejects(fx.service.cutover({ serviceId: 'notes-api', lease: lease(), expectedSequence: prepared.sequence - 1 }, context('stale-sequence')), code('release_stale_sequence'));
    assert.equal(fx.caddy.calls.includes('load'), false);
  } finally { fx.close(); }
});

test('F44 exact idempotent route replay returns the same durable result', async () => {
  const fx = fixture();
  try {
    const first = await prepare(fx, { key: 'prepare-replay' });
    const replay = await prepare(fx, { key: 'prepare-replay', acquire: false });
    assert.deepEqual(replay, first);
  } finally { fx.close(); }
});

test('F45 conflicting route idempotency-key reuse fails closed', async () => {
  const fx = fixture();
  try {
    await prepare(fx, { key: 'prepare-conflict' });
    await assert.rejects(prepare(fx, { key: 'prepare-conflict', acquire: false, request: directRequest({ type: 'LOOPBACK_TCP', value: '127.0.0.1:32000' }) }), code('release_idempotency_conflict'));
  } finally { fx.close(); }
});

test('F46 route reads are owner-scoped, strict, and read-only', async () => {
  const fx = fixture();
  try {
    await prepare(fx);
    const before = snapshot(fx.root);
    const read = fx.service.getRoute({ serviceId: 'notes-api' }, context('read-route'));
    assert.equal(read.route.serviceId, 'notes-api');
    assert.throws(() => fx.service.getRoute({ serviceId: 'notes-api' }, context('read-route-other', OTHER)), code('release_record_not_found'));
    assert.throws(() => fx.service.getRoute({ serviceId: 'notes-api', mutate: true }, context('read-route-extra')), code('release_invalid_request'));
    assert.deepEqual(snapshot(fx.root), before);
  } finally { fx.close(); }
});

test('F47 route operation is registered exactly once and is read-only', () => {
  const definitions = operationDefinitions().filter((entry) => entry.operation === 'babyx.release.route.get');
  assert.equal(definitions.length, 1);
  assert.equal(definitions[0].mutation, false);
  assert.deepEqual(definitions[0].input.required, ['serviceId']);
  assert.equal(definitions[0].input.additionalProperties, false);
});

test('F48 route adapter creates no alternate ingress, process, artifact, or route authority', () => {
  const source = readFileSync(new URL('../src/release/route.ts', import.meta.url), 'utf8');
  assert.equal(source.includes('createServer('), false);
  assert.equal(source.includes('.listen('), false);
  assert.equal(source.includes('new JobManager'), false);
  assert.equal(source.includes('new ArtifactManager'), false);
  assert.equal(source.includes('systemd-nspawn'), false);
  assert.equal(source.includes('zfs '), false);
  assert.match(source, /RouteCaddyAdapter/u);
  assert.match(source, /ArtifactManager/u);
  assert.match(source, /ReleaseApplianceStore/u);
});

test('F49 raw credentials are rejected from config/request bytes', () => {
  assert.throws(() => generateTrustedCaddyConfig({ ...baseConfig(), marker: ['gh', 'p_', '123456789012345678901234567890123456'].join('') }, directRequest(), OWNER), /secret|credential|sensitive/iu);
});

test('F50 runtime exposes only owner-scoped route.get and no generic public config load operation', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-route-runtime-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root, routeCaddyAdapter: new FakeCaddyAdapter() });
    await assert.rejects(runtime.execute('babyx.release.route.get', { serviceId: 'missing' }, context('runtime-route-read')), /not found/iu);
    const names = operationDefinitions().map((entry) => entry.operation);
    assert.equal(names.includes('babyx.release.route.load'), false);
    assert.equal(names.includes('babyx.caddy.load'), false);
    assert.equal(names.includes('babyx.release.route.prepare'), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});


test('F51 non-streaming routes omit unsupported stream-close fields for installed-version compatibility', () => {
  const request = directRequest(undefined, { streamSettings: { websocket: false, sse: false, keepAlive: true, streamCloseDelayMs: 0, flushIntervalMs: 100 } });
  const generated = generateTrustedCaddyConfig(baseConfig(), request, OWNER);
  const handler = generated.config.apps.http.servers.production.routes[0].handle[0];
  assert.equal(handler.stream_close_delay, undefined);
  assert.equal(handler.flush_interval, '100ms');
});


test('F52 streaming cutover fails closed when installed Caddy lacks bounded stream-close support', async () => {
  const fx = fixture();
  try {
    fx.caddy.discovery.streamCloseDelaySupported = false;
    const result = await prepare(fx);
    assert.equal(result.state, 'RECOVERY_REQUIRED');
    assert.equal(fx.caddy.calls.includes('load'), false);
    assert.equal(result.error.code, 'release_provider_incompatible');
  } finally { fx.close(); }
});
