import { spawnSync } from 'node:child_process';
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { dirname, isAbsolute, join, normalize, resolve, sep } from 'node:path';
import { randomUUID } from 'node:crypto';
import { ArtifactManager } from '../artifacts/manager.ts';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { assertReleaseTransition } from './compatibility.ts';
import { assertNoRawSecrets, boundedReleaseError, validateReleaseRecord } from './schemas.ts';
import { ReleaseApplianceStore, ReleaseStoreError } from './store.ts';

export const ROUTE_ADAPTER_CONTRACT_VERSION = '1.0.0' as const;
export const ROUTE_TEMPLATE_IDS = ['http-private-upstream-v1', 'http-canary-v1', 'http-shadow-v1', 'http-preview-v1'] as const;
export type RouteTemplateId = typeof ROUTE_TEMPLATE_IDS[number];
export type RouteMode = 'DIRECT' | 'CANARY' | 'SHADOW' | 'PREVIEW';
export type RouteEndpointType = 'UNIX_SOCKET' | 'LOOPBACK_TCP';

const IDENTIFIER = /^[a-z0-9][a-z0-9.-]{0,63}$/u;
const HEADER = /^[A-Za-z][A-Za-z0-9-]{0,63}$/u;
const HOSTNAME = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const LOOPBACK = /^127\.0\.0\.1:([1-9][0-9]{0,4})$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const MAX_CONFIG_BYTES = 16 * 1024 * 1024;
const MAX_MODULES = 4096;
const MAX_PROBE_SAMPLES = 1024;

export class RouteAuthorityError extends Error {
  constructor(readonly code: string, message: string, readonly details: JsonObject = {}, readonly phase?: string) {
    super(message);
    this.name = 'RouteAuthorityError';
  }
}

export interface RouteEndpoint extends JsonObject {
  type: RouteEndpointType;
  value: string;
}

export interface RouteStreamSettings extends JsonObject {
  websocket: boolean;
  sse: boolean;
  keepAlive: boolean;
  streamCloseDelayMs: number;
  flushIntervalMs: number;
}

export interface CaddyDiscovery extends JsonObject {
  available: boolean;
  executablePath: string;
  version: string;
  modules: string[];
  adminTransport: 'UNIX_SOCKET' | 'LOOPBACK';
  adminLocalOnly: boolean;
  autosaveCompatible: boolean;
  resumeCompatible: boolean;
  streamCloseDelaySupported: boolean;
}

export interface CaddyValidationResult extends JsonObject {
  valid: boolean;
  installedVersion: string;
  candidateDigest: string;
  adaptedDigest: string;
  diagnostics: string[];
  requiredModules: string[];
  availableModules: string[];
}

export interface CaddyConfigObservation extends JsonObject {
  observedAt: string;
  config: JsonObject;
  configDigest: string;
  routePresent?: boolean;
  observedUpstreams?: string[];
}

export interface RouteProbeRequest extends JsonObject {
  kind: 'PRIVATE' | 'PUBLIC' | 'ABSENCE';
  serviceId: string;
  routeId: string;
  endpoint?: RouteEndpoint;
  publicIdentity?: JsonObject;
  expectedUpstreams: string[];
  expectedReleaseIdentity?: string;
  timeoutMs: number;
}

export interface RouteProbeResult extends JsonObject {
  kind: 'PRIVATE' | 'PUBLIC' | 'ABSENCE';
  status: 'PASS' | 'FAIL' | 'TIMEOUT' | 'UNKNOWN';
  observedAt: string;
  statusCode?: number;
  latencyMs?: number;
  responseDigest?: string;
  observedReleaseIdentity?: string;
  detailsDigest: string;
}

export interface RouteCaddyAdapter {
  readonly authority: 'route-caddy-adapter';
  discover(): Promise<CaddyDiscovery>;
  capture(): Promise<CaddyConfigObservation>;
  validate(configBytes: Buffer, requiredModules: string[]): Promise<CaddyValidationResult>;
  load(configBytes: Buffer, requestDigest: string): Promise<JsonObject>;
  readback(routeId?: string): Promise<CaddyConfigObservation>;
  probe(request: RouteProbeRequest): Promise<RouteProbeResult>;
}

export interface RouteAuthorityOptions {
  stateRoot: string;
  store: ReleaseApplianceStore;
  artifacts: ArtifactManager;
  caddy: RouteCaddyAdapter;
  now?: () => string;
}

interface NormalizedRouteRequest {
  serviceId: string;
  routeId: string;
  ownerPrincipal: string;
  desiredActiveSlot: 'blue' | 'green';
  endpoint: RouteEndpoint;
  publicIdentity: JsonObject;
  templateId: RouteTemplateId;
  mode: RouteMode;
  streamSettings: RouteStreamSettings;
  policy: JsonObject;
  expectedReleaseIdentity?: string;
  requestDigest: string;
  requiredModules: string[];
}

interface RouteLeaseRequest {
  leaseId: string;
  controllerIdentity: JsonObject;
  acquiredAt: string;
  expiresAt: string;
  observationDigest: string;
  existingControllerAbsent: boolean;
}

function object(value: unknown, field: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new RouteAuthorityError('release_invalid_request', `${field} must be an object`);
  return value as JsonObject;
}

function strictObject(value: unknown, field: string, allowed: readonly string[]): JsonObject {
  const result = object(value, field);
  const unknown = Object.keys(result).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw new RouteAuthorityError('release_invalid_request', `${field} contains unsupported property ${unknown.sort()[0]}`);
  return result;
}

function text(value: unknown, field: string, maximum = 4096): string {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || Buffer.byteLength(value) > maximum) throw new RouteAuthorityError('release_invalid_request', `${field} must be a bounded non-empty NUL-free string`);
  return value;
}

function identifier(value: unknown, field: string): string {
  const result = text(value, field, 64);
  if (!IDENTIFIER.test(result) || result === '.' || result === '..') throw new RouteAuthorityError('release_invalid_request', `${field} must be a lowercase bounded identifier`);
  return result;
}

function digest(value: unknown, field: string): string {
  const result = text(value, field, 64);
  if (!DIGEST.test(result)) throw new RouteAuthorityError('release_invalid_request', `${field} must be a lowercase SHA-256 digest`);
  return result;
}

function integer(value: unknown, field: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new RouteAuthorityError('release_invalid_request', `${field} must be an integer between ${minimum} and ${maximum}`);
  return Number(value);
}

function number(value: unknown, field: string, minimum: number, maximum: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum || value > maximum) throw new RouteAuthorityError('release_invalid_request', `${field} must be a finite number between ${minimum} and ${maximum}`);
  return value;
}

function boolean(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') throw new RouteAuthorityError('release_invalid_request', `${field} must be boolean`);
  return value;
}

function timestamp(value: unknown, field: string): string {
  const result = text(value, field, 64);
  const parsed = Date.parse(result);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== result) throw new RouteAuthorityError('release_invalid_request', `${field} must be a canonical ISO timestamp`);
  return result;
}

function safePath(value: unknown, field: string): string {
  const result = text(value, field);
  if (!isAbsolute(result) || normalize(result) !== result || result.includes('/../') || result.endsWith('/..')) throw new RouteAuthorityError('release_invalid_request', `${field} must be a normalized absolute path`);
  return result;
}

function stringArray(value: unknown, field: string, maximum: number, normalizeEntry: (entry: unknown, field: string) => string = text): string[] {
  if (!Array.isArray(value) || value.length > maximum) throw new RouteAuthorityError('release_invalid_request', `${field} must be a bounded array`);
  return [...new Set(value.map((entry, index) => normalizeEntry(entry, `${field}[${index}]`)))].sort();
}

function hostname(value: unknown, field: string): string {
  const result = text(value, field, 253).toLowerCase();
  if (!HOSTNAME.test(result) || result === 'localhost') throw new RouteAuthorityError('release_invalid_request', `${field} must be a trusted non-local hostname`);
  return result;
}

function routePath(value: unknown, field: string): string {
  const result = text(value, field, 1024);
  if (!result.startsWith('/') || result.includes('\0') || result.includes('..')) throw new RouteAuthorityError('release_invalid_request', `${field} must be an absolute route path without traversal`);
  return result;
}

function headerName(value: unknown, field: string): string {
  const result = text(value, field, 64);
  if (!HEADER.test(result)) throw new RouteAuthorityError('release_invalid_request', `${field} must be a safe HTTP header name`);
  return result;
}

function exactContext(context: RuntimeExecutionContext): { subject: string; idempotencyKey: string } {
  return { subject: identifier(context.subject, 'context.subject'), idempotencyKey: identifier(context.idempotencyKey, 'context.idempotencyKey') };
}

function routeIdFor(serviceId: string): string { return identifier(`route-${serviceId}`, 'routeId'); }
function caddyRouteId(routeId: string): string { return `babyx-${routeId}`; }

function endpoint(value: unknown, field = 'endpoint'): RouteEndpoint {
  const input = strictObject(value, field, ['type', 'value']);
  const type = input.type === 'UNIX_SOCKET' ? 'UNIX_SOCKET' : input.type === 'LOOPBACK_TCP' ? 'LOOPBACK_TCP' : (() => { throw new RouteAuthorityError('release_invalid_request', `${field}.type is invalid`); })();
  const endpointValue = type === 'UNIX_SOCKET' ? safePath(input.value, `${field}.value`) : text(input.value, `${field}.value`, 64);
  if (type === 'LOOPBACK_TCP') {
    const match = LOOPBACK.exec(endpointValue);
    if (match === null || Number(match[1]) > 65535) throw new RouteAuthorityError('release_invalid_request', `${field}.value must be a private loopback listener`);
  }
  return { type, value: endpointValue };
}

function caddyDial(value: RouteEndpoint): string {
  return value.type === 'UNIX_SOCKET' ? `unix/${value.value}` : value.value;
}

function streamSettings(value: unknown): RouteStreamSettings {
  const input = strictObject(value ?? {}, 'streamSettings', ['websocket', 'sse', 'keepAlive', 'streamCloseDelayMs', 'flushIntervalMs']);
  const websocket = input.websocket === undefined ? true : boolean(input.websocket, 'streamSettings.websocket');
  const sse = input.sse === undefined ? false : boolean(input.sse, 'streamSettings.sse');
  const keepAlive = input.keepAlive === undefined ? true : boolean(input.keepAlive, 'streamSettings.keepAlive');
  const streamCloseDelayMs = input.streamCloseDelayMs === undefined ? 30_000 : integer(input.streamCloseDelayMs, 'streamSettings.streamCloseDelayMs', 0, 300_000);
  const flushIntervalMs = input.flushIntervalMs === undefined ? (sse ? -1 : 100) : integer(input.flushIntervalMs, 'streamSettings.flushIntervalMs', -1, 60_000);
  return { websocket, sse, keepAlive, streamCloseDelayMs, flushIntervalMs };
}

function publicIdentity(value: unknown): JsonObject {
  const input = strictObject(value, 'publicIdentity', ['serverId', 'hostnames', 'paths', 'publicProbeUrl', 'trustedIdentityHeaders']);
  const serverId = identifier(input.serverId, 'publicIdentity.serverId');
  const hostnames = stringArray(input.hostnames, 'publicIdentity.hostnames', 32, hostname);
  if (hostnames.length === 0) throw new RouteAuthorityError('release_invalid_request', 'publicIdentity.hostnames must not be empty');
  const paths = stringArray(input.paths, 'publicIdentity.paths', 32, routePath);
  if (paths.length === 0) throw new RouteAuthorityError('release_invalid_request', 'publicIdentity.paths must not be empty');
  const trustedIdentityHeaders = input.trustedIdentityHeaders === undefined ? [] : stringArray(input.trustedIdentityHeaders, 'publicIdentity.trustedIdentityHeaders', 16, headerName);
  const publicProbeUrl = input.publicProbeUrl === undefined ? undefined : text(input.publicProbeUrl, 'publicIdentity.publicProbeUrl', 2048);
  if (publicProbeUrl !== undefined) {
    const parsed = new URL(publicProbeUrl);
    if (!['http:', 'https:'].includes(parsed.protocol) || !hostnames.includes(parsed.hostname.toLowerCase())) throw new RouteAuthorityError('release_invalid_request', 'public probe URL must use a declared public hostname');
  }
  return { serverId, hostnames, paths, trustedIdentityHeaders, ...(publicProbeUrl === undefined ? {} : { publicProbeUrl }) };
}

function directPolicy(value: JsonObject): JsonObject {
  const input = strictObject(value, 'policy', ['mode']);
  if (input.mode !== 'DIRECT') throw new RouteAuthorityError('release_invalid_request', 'direct route policy mode is invalid');
  return { mode: 'DIRECT' };
}

function canaryPolicy(value: JsonObject): JsonObject {
  const input = strictObject(value, 'policy', ['mode', 'stableEndpoint', 'weightBasisPoints', 'stickiness', 'minimumSamples', 'rollbackThresholds', 'hysteresis', 'cooldownMs']);
  if (input.mode !== 'CANARY') throw new RouteAuthorityError('release_invalid_request', 'canary route policy mode is invalid');
  const stableEndpoint = endpoint(input.stableEndpoint, 'policy.stableEndpoint');
  const weightBasisPoints = integer(input.weightBasisPoints, 'policy.weightBasisPoints', 1, 9999);
  const stickinessInput = strictObject(input.stickiness, 'policy.stickiness', ['kind', 'name', 'ttlSeconds']);
  const kind = stickinessInput.kind === 'COOKIE' ? 'COOKIE' : stickinessInput.kind === 'HEADER' ? 'HEADER' : (() => { throw new RouteAuthorityError('release_invalid_request', 'policy.stickiness.kind is invalid'); })();
  const name = kind === 'COOKIE' ? text(stickinessInput.name, 'policy.stickiness.name', 64) : headerName(stickinessInput.name, 'policy.stickiness.name');
  const ttlSeconds = integer(stickinessInput.ttlSeconds, 'policy.stickiness.ttlSeconds', 1, 604800);
  const minimumSamples = integer(input.minimumSamples, 'policy.minimumSamples', 1, 1_000_000);
  const thresholdsInput = strictObject(input.rollbackThresholds, 'policy.rollbackThresholds', ['errorRate', 'latencyMs', 'consecutiveFailures']);
  const rollbackThresholds = {
    errorRate: number(thresholdsInput.errorRate, 'policy.rollbackThresholds.errorRate', 0, 1),
    latencyMs: number(thresholdsInput.latencyMs, 'policy.rollbackThresholds.latencyMs', 1, 3_600_000),
    consecutiveFailures: integer(thresholdsInput.consecutiveFailures, 'policy.rollbackThresholds.consecutiveFailures', 1, 10_000),
  };
  const hysteresisInput = strictObject(input.hysteresis, 'policy.hysteresis', ['breachSamples', 'recoverySamples']);
  const hysteresis = {
    breachSamples: integer(hysteresisInput.breachSamples, 'policy.hysteresis.breachSamples', 1, 10_000),
    recoverySamples: integer(hysteresisInput.recoverySamples, 'policy.hysteresis.recoverySamples', 1, 10_000),
  };
  const cooldownMs = integer(input.cooldownMs, 'policy.cooldownMs', 0, 86_400_000);
  return { mode: 'CANARY', stableEndpoint, weightBasisPoints, stickiness: { kind, name, ttlSeconds }, minimumSamples, rollbackThresholds, hysteresis, cooldownMs };
}

function shadowPolicy(value: JsonObject): JsonObject {
  const input = strictObject(value, 'policy', ['mode', 'primaryEndpoint', 'allowedMethods', 'maxBodyBytes', 'maxRequestsPerSecond', 'credentialMode', 'sideEffectMode']);
  if (input.mode !== 'SHADOW') throw new RouteAuthorityError('release_invalid_request', 'shadow route policy mode is invalid');
  const primaryEndpoint = endpoint(input.primaryEndpoint, 'policy.primaryEndpoint');
  const allowedMethods = stringArray(input.allowedMethods, 'policy.allowedMethods', 8, (entry, field) => text(entry, field, 16).toUpperCase());
  if (allowedMethods.length === 0 || allowedMethods.some((method) => !['GET', 'HEAD', 'OPTIONS'].includes(method))) throw new RouteAuthorityError('release_shadow_side_effect_forbidden', 'shadow routing is restricted to safe idempotent methods');
  const credentialMode = input.credentialMode === 'STRIP' ? 'STRIP' : (() => { throw new RouteAuthorityError('release_shadow_credential_forbidden', 'shadow requests must strip caller credentials'); })();
  const sideEffectMode = input.sideEffectMode === 'READ_ONLY' ? 'READ_ONLY' : (() => { throw new RouteAuthorityError('release_shadow_side_effect_forbidden', 'shadow target must be declared read-only'); })();
  return {
    mode: 'SHADOW', primaryEndpoint, allowedMethods,
    maxBodyBytes: integer(input.maxBodyBytes, 'policy.maxBodyBytes', 0, 10 * 1024 * 1024),
    maxRequestsPerSecond: integer(input.maxRequestsPerSecond, 'policy.maxRequestsPerSecond', 1, 100_000),
    credentialMode, sideEffectMode, responseMode: 'DISCARD',
  };
}

function previewPolicy(value: JsonObject, identity: JsonObject): JsonObject {
  const input = strictObject(value, 'policy', ['mode', 'trustedHeader', 'identityValue', 'expiresAt', 'authenticationRequired']);
  if (input.mode !== 'PREVIEW') throw new RouteAuthorityError('release_invalid_request', 'preview route policy mode is invalid');
  if (input.authenticationRequired !== true) throw new RouteAuthorityError('release_preview_auth_required', 'preview routes require authenticated identity selection');
  const trustedHeader = headerName(input.trustedHeader, 'policy.trustedHeader');
  const trusted = identity.trustedIdentityHeaders as string[];
  if (!trusted.includes(trustedHeader)) throw new RouteAuthorityError('release_preview_auth_required', 'preview selector header is not trusted by the service route identity');
  const identityValue = identifier(input.identityValue, 'policy.identityValue');
  const expiresAt = timestamp(input.expiresAt, 'policy.expiresAt');
  return { mode: 'PREVIEW', trustedHeader, identityValue, expiresAt, authenticationRequired: true };
}

function normalizePolicy(value: unknown, identity: JsonObject): { mode: RouteMode; policy: JsonObject; templateId: RouteTemplateId; requiredModules: string[] } {
  const input = object(value, 'policy');
  switch (input.mode) {
    case 'DIRECT': return { mode: 'DIRECT', policy: directPolicy(input), templateId: 'http-private-upstream-v1', requiredModules: ['http.handlers.reverse_proxy'] };
    case 'CANARY': return { mode: 'CANARY', policy: canaryPolicy(input), templateId: 'http-canary-v1', requiredModules: ['http.handlers.reverse_proxy', 'http.reverse_proxy.selection_policies.weighted_round_robin'] };
    case 'SHADOW': return { mode: 'SHADOW', policy: shadowPolicy(input), templateId: 'http-shadow-v1', requiredModules: ['http.handlers.reverse_proxy', 'http.handlers.request_mirror'] };
    case 'PREVIEW': return { mode: 'PREVIEW', policy: previewPolicy(input, identity), templateId: 'http-preview-v1', requiredModules: ['http.handlers.reverse_proxy'] };
    default: throw new RouteAuthorityError('release_invalid_request', 'policy.mode is unsupported');
  }
}

function normalizeRouteRequest(value: unknown, ownerPrincipal: string): NormalizedRouteRequest {
  const input = strictObject(value, 'routeRequest', ['serviceId', 'desiredActiveSlot', 'endpoint', 'publicIdentity', 'policy', 'streamSettings', 'expectedReleaseIdentity']);
  assertNoRawSecrets(input);
  const serviceId = identifier(input.serviceId, 'serviceId');
  const desiredActiveSlot = input.desiredActiveSlot === 'blue' ? 'blue' : input.desiredActiveSlot === 'green' ? 'green' : (() => { throw new RouteAuthorityError('release_invalid_request', 'desiredActiveSlot must be blue or green'); })();
  const identity = publicIdentity(input.publicIdentity);
  const endpointValue = endpoint(input.endpoint);
  const policyValue = normalizePolicy(input.policy, identity);
  const streams = streamSettings(input.streamSettings);
  const expectedReleaseIdentity = input.expectedReleaseIdentity === undefined ? undefined : identifier(input.expectedReleaseIdentity, 'expectedReleaseIdentity');
  const normalized: Omit<NormalizedRouteRequest, 'requestDigest'> = {
    serviceId,
    routeId: routeIdFor(serviceId),
    ownerPrincipal,
    desiredActiveSlot,
    endpoint: endpointValue,
    publicIdentity: identity,
    templateId: policyValue.templateId,
    mode: policyValue.mode,
    streamSettings: streams,
    policy: policyValue.policy,
    ...(expectedReleaseIdentity === undefined ? {} : { expectedReleaseIdentity }),
    requiredModules: [...policyValue.requiredModules].sort(),
  };
  return { ...normalized, requestDigest: sha256(canonicalize(normalized)) };
}

function normalizeLease(value: unknown): RouteLeaseRequest {
  const input = strictObject(value, 'lease', ['leaseId', 'controllerIdentity', 'acquiredAt', 'expiresAt', 'observationDigest', 'existingControllerAbsent']);
  const acquiredAt = timestamp(input.acquiredAt, 'lease.acquiredAt');
  const expiresAt = timestamp(input.expiresAt, 'lease.expiresAt');
  if (Date.parse(expiresAt) <= Date.parse(acquiredAt)) throw new RouteAuthorityError('release_invalid_request', 'lease expiry must follow acquisition');
  return {
    leaseId: identifier(input.leaseId, 'lease.leaseId'),
    controllerIdentity: object(input.controllerIdentity, 'lease.controllerIdentity'),
    acquiredAt,
    expiresAt,
    observationDigest: digest(input.observationDigest, 'lease.observationDigest'),
    existingControllerAbsent: input.existingControllerAbsent === undefined ? false : boolean(input.existingControllerAbsent, 'lease.existingControllerAbsent'),
  };
}

function ensureObjectParent(target: JsonObject, key: string): JsonObject {
  const current = target[key];
  if (current === undefined) { const created: JsonObject = {}; target[key] = created; return created; }
  return object(current, key);
}

function routeMatcher(request: NormalizedRouteRequest): JsonObject[] {
  const hosts = request.publicIdentity.hostnames as string[];
  const paths = request.publicIdentity.paths as string[];
  const matcher: JsonObject = { host: hosts, path: paths };
  if (request.mode === 'PREVIEW') {
    const policy = request.policy;
    matcher.header = { [String(policy.trustedHeader)]: [String(policy.identityValue)] };
  }
  return [matcher];
}

function reverseProxyHandler(upstreams: JsonObject[], streams: RouteStreamSettings, loadBalancing?: JsonObject): JsonObject {
  return {
    handler: 'reverse_proxy',
    upstreams,
    ...(loadBalancing === undefined ? {} : { load_balancing: loadBalancing }),
    ...(streams.streamCloseDelayMs > 0 && (streams.websocket || streams.sse) ? { stream_close_delay: `${streams.streamCloseDelayMs}ms` } : {}),
    flush_interval: streams.sse ? -1 : `${streams.flushIntervalMs}ms`,
    transport: { protocol: 'http', keep_alive: { enabled: streams.keepAlive } },
  };
}

function trustedRoute(request: NormalizedRouteRequest): JsonObject {
  const candidateDial = caddyDial(request.endpoint);
  let handle: JsonObject[];
  if (request.mode === 'DIRECT' || request.mode === 'PREVIEW') {
    handle = [reverseProxyHandler([{ dial: candidateDial }], request.streamSettings)];
  } else if (request.mode === 'CANARY') {
    const policy = request.policy;
    const stableDial = caddyDial(policy.stableEndpoint as RouteEndpoint);
    handle = [reverseProxyHandler([
      { dial: stableDial, weight: 10_000 - Number(policy.weightBasisPoints) },
      { dial: candidateDial, weight: Number(policy.weightBasisPoints) },
    ], request.streamSettings, {
      selection_policy: {
        policy: 'weighted_round_robin',
        stickiness: policy.stickiness,
      },
    })];
  } else {
    const policy = request.policy;
    const primaryDial = caddyDial(policy.primaryEndpoint as RouteEndpoint);
    handle = [{
      handler: 'request_mirror',
      upstream: candidateDial,
      allowed_methods: policy.allowedMethods,
      max_body_bytes: policy.maxBodyBytes,
      max_requests_per_second: policy.maxRequestsPerSecond,
      strip_headers: ['Authorization', 'Cookie', 'Proxy-Authorization'],
      response_mode: 'discard',
      side_effect_mode: 'read_only',
    }, reverseProxyHandler([{ dial: primaryDial }], request.streamSettings)];
  }
  return {
    '@id': caddyRouteId(request.routeId),
    match: routeMatcher(request),
    handle,
    terminal: true,
  };
}

function serverRoutes(config: JsonObject, serverId: string): JsonObject[] {
  const apps = ensureObjectParent(config, 'apps');
  const http = ensureObjectParent(apps, 'http');
  const servers = ensureObjectParent(http, 'servers');
  const existing = servers[serverId];
  const server = existing === undefined ? ({ listen: [':443'], routes: [] } as JsonObject) : object(existing, `servers.${serverId}`);
  servers[serverId] = server;
  const routes = server.routes;
  if (routes === undefined) { const created: JsonObject[] = []; server.routes = created; return created; }
  if (!Array.isArray(routes) || routes.some((route) => route === null || typeof route !== 'object' || Array.isArray(route))) throw new RouteAuthorityError('release_caddy_config_invalid', 'Caddy server routes must be an object array');
  return routes as JsonObject[];
}

export function generateTrustedCaddyConfig(baseConfigValue: unknown, requestValue: unknown, ownerPrincipal = 'owner-release'): { config: JsonObject; bytes: Buffer; digest: string; expectedUpstreams: string[]; routeId: string; templateId: RouteTemplateId; requiredModules: string[] } {
  const baseConfig = structuredClone(object(baseConfigValue, 'baseConfig'));
  assertNoRawSecrets(baseConfig);
  const request = normalizeRouteRequest(requestValue, identifier(ownerPrincipal, 'ownerPrincipal'));
  const routes = serverRoutes(baseConfig, String(request.publicIdentity.serverId));
  const targetId = caddyRouteId(request.routeId);
  const retained = routes.filter((route) => route['@id'] !== targetId);
  const route = trustedRoute(request);
  retained.push(route);
  retained.sort((left, right) => String(left['@id'] ?? canonicalize(left)).localeCompare(String(right['@id'] ?? canonicalize(right))));
  const apps = object(baseConfig.apps, 'apps');
  const http = object(apps.http, 'apps.http');
  const servers = object(http.servers, 'apps.http.servers');
  const server = object(servers[String(request.publicIdentity.serverId)], 'server');
  server.routes = retained;
  const bytes = Buffer.from(canonicalize(baseConfig), 'utf8');
  if (bytes.length > MAX_CONFIG_BYTES) throw new RouteAuthorityError('release_config_too_large', 'candidate Caddy configuration exceeds the bounded limit');
  const expectedUpstreams = request.mode === 'CANARY'
    ? [caddyDial(request.policy.stableEndpoint as RouteEndpoint), caddyDial(request.endpoint)].sort()
    : request.mode === 'SHADOW'
      ? [caddyDial(request.policy.primaryEndpoint as RouteEndpoint), caddyDial(request.endpoint)].sort()
      : [caddyDial(request.endpoint)];
  return { config: baseConfig, bytes, digest: sha256(bytes), expectedUpstreams, routeId: request.routeId, templateId: request.templateId, requiredModules: request.requiredModules };
}

export function removeTrustedCaddyRoute(baseConfigValue: unknown, routeId: string, serverId: string): { config: JsonObject; bytes: Buffer; digest: string; absent: boolean } {
  const config = structuredClone(object(baseConfigValue, 'baseConfig'));
  assertNoRawSecrets(config);
  const routes = serverRoutes(config, identifier(serverId, 'serverId'));
  const targetId = caddyRouteId(identifier(routeId, 'routeId'));
  const retained = routes.filter((route) => route['@id'] !== targetId);
  const apps = object(config.apps, 'apps');
  const http = object(apps.http, 'apps.http');
  const servers = object(http.servers, 'apps.http.servers');
  object(servers[serverId], 'server').routes = retained;
  const bytes = Buffer.from(canonicalize(config), 'utf8');
  return { config, bytes, digest: sha256(bytes), absent: findRoute(config, routeId) === undefined };
}

function findRoute(config: JsonObject, routeId: string): JsonObject | undefined {
  const targetId = caddyRouteId(routeId);
  const apps = config.apps;
  if (apps === null || typeof apps !== 'object' || Array.isArray(apps)) return undefined;
  const http = (apps as JsonObject).http;
  if (http === null || typeof http !== 'object' || Array.isArray(http)) return undefined;
  const servers = (http as JsonObject).servers;
  if (servers === null || typeof servers !== 'object' || Array.isArray(servers)) return undefined;
  for (const server of Object.values(servers as JsonObject)) {
    if (server === null || typeof server !== 'object' || Array.isArray(server)) continue;
    const routes = (server as JsonObject).routes;
    if (!Array.isArray(routes)) continue;
    for (const route of routes) if (route !== null && typeof route === 'object' && !Array.isArray(route) && (route as JsonObject)['@id'] === targetId) return route as JsonObject;
  }
  return undefined;
}

function collectDials(value: unknown, output: Set<string>): void {
  if (Array.isArray(value)) { for (const entry of value) collectDials(entry, output); return; }
  if (value === null || typeof value !== 'object') return;
  const objectValue = value as JsonObject;
  if (typeof objectValue.dial === 'string') output.add(objectValue.dial);
  if (typeof objectValue.upstream === 'string') output.add(objectValue.upstream);
  for (const nested of Object.values(objectValue)) collectDials(nested, output);
}

export function observedRouteUpstreams(configValue: unknown, routeId: string): string[] {
  const config = object(configValue, 'config');
  const route = findRoute(config, identifier(routeId, 'routeId'));
  if (route === undefined) return [];
  const result = new Set<string>();
  collectDials(route, result);
  return [...result].sort();
}

export function evaluateCanaryPolicy(policyValue: unknown, samplesValue: unknown, stateValue: unknown = {}): JsonObject {
  const policy = canaryPolicy(object(policyValue, 'policy'));
  if (!Array.isArray(samplesValue) || samplesValue.length > MAX_PROBE_SAMPLES) throw new RouteAuthorityError('release_invalid_request', 'canary samples must be a bounded array');
  const samples = samplesValue.map((entry, index) => {
    const sample = strictObject(entry, `samples[${index}]`, ['ok', 'latencyMs']);
    return { ok: boolean(sample.ok, `samples[${index}].ok`), latencyMs: number(sample.latencyMs, `samples[${index}].latencyMs`, 0, 3_600_000) };
  });
  const state = strictObject(stateValue, 'state', ['decision', 'breach', 'breachStreak', 'recoveryStreak', 'latchedRollback', 'lastDecisionAt', 'errorRate', 'p95LatencyMs', 'consecutiveFailures', 'sampleCount', 'noFlap']);
  const thresholds = policy.rollbackThresholds as JsonObject;
  const hysteresis = policy.hysteresis as JsonObject;
  const failures = samples.filter((sample) => !sample.ok).length;
  const errorRate = samples.length === 0 ? 1 : failures / samples.length;
  const latency = samples.length === 0 ? Number.POSITIVE_INFINITY : [...samples].map((sample) => sample.latencyMs).sort((a, b) => a - b)[Math.max(0, Math.ceil(samples.length * 0.95) - 1)];
  const consecutiveFailures = (() => { let count = 0; for (let index = samples.length - 1; index >= 0 && !samples[index].ok; index -= 1) count += 1; return count; })();
  const breach = samples.length < Number(policy.minimumSamples)
    || errorRate > Number(thresholds.errorRate)
    || latency > Number(thresholds.latencyMs)
    || consecutiveFailures >= Number(thresholds.consecutiveFailures);
  const breachStreak = breach ? integer(state.breachStreak ?? 0, 'state.breachStreak', 0, 1_000_000) + 1 : 0;
  const recoveryStreak = breach ? 0 : integer(state.recoveryStreak ?? 0, 'state.recoveryStreak', 0, 1_000_000) + 1;
  const latchedRollback = state.latchedRollback === true || breachStreak >= Number(hysteresis.breachSamples);
  return {
    decision: latchedRollback ? 'ROLLBACK' : breach ? 'CONTINUE' : 'HEALTHY',
    breach,
    breachStreak,
    recoveryStreak,
    latchedRollback,
    errorRate,
    p95LatencyMs: Number.isFinite(latency) ? latency : null,
    consecutiveFailures,
    sampleCount: samples.length,
    noFlap: latchedRollback,
  };
}

function durableWrite(path: string, bytes: Buffer): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const descriptor = openSync(temporary, 'wx', 0o600);
  try { writeFileSync(descriptor, bytes); fsyncSync(descriptor); } finally { closeSync(descriptor); }
  renameSync(temporary, path);
  const directory = openSync(dirname(path), 'r');
  try { fsyncSync(directory); } finally { closeSync(directory); }
}

function localAdmin(value: string, unixSocketCapable: boolean): { transport: 'UNIX_SOCKET' | 'LOOPBACK'; socketPath?: string; host?: string; port?: number } {
  if (value.startsWith('unix:')) {
    if (!unixSocketCapable) throw new RouteAuthorityError('release_provider_incompatible', 'Unix-socket Caddy administration is not capability-proven');
    const path = safePath(value.slice('unix:'.length), 'adminEndpoint');
    return { transport: 'UNIX_SOCKET', socketPath: path };
  }
  const parsed = new URL(value);
  if (parsed.protocol !== 'http:' || !['127.0.0.1', '[::1]', '::1'].includes(parsed.hostname) || parsed.username.length > 0 || parsed.password.length > 0 || parsed.pathname !== '/') throw new RouteAuthorityError('release_public_admin_forbidden', 'Caddy admin endpoint must be unauthenticated local HTTP or a proven local Unix socket');
  const port = Number(parsed.port || 80);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new RouteAuthorityError('release_invalid_request', 'Caddy admin port is invalid');
  return { transport: 'LOOPBACK', host: parsed.hostname === '[::1]' ? '::1' : parsed.hostname, port };
}

function boundedLines(value: string): string[] { return value.split(/\r?\n/u).filter(Boolean).slice(0, 128).map((line) => line.slice(0, 1024)); }

export class HostCaddyAdminAdapter implements RouteCaddyAdapter {
  readonly authority = 'route-caddy-adapter' as const;
  private readonly endpoint: ReturnType<typeof localAdmin>;
  private readonly caddyPath: string;
  private readonly validationRoot: string;
  private readonly liveActions: boolean;
  private readonly now: () => string;

  constructor(options: { adminEndpoint: string; unixSocketCapable?: boolean; caddyPath?: string; validationRoot: string; liveActions?: boolean; now?: () => string }) {
    this.endpoint = localAdmin(options.adminEndpoint, options.unixSocketCapable === true);
    this.caddyPath = options.caddyPath ?? '/usr/bin/caddy';
    this.validationRoot = resolve(options.validationRoot);
    this.liveActions = options.liveActions === true;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  async discover(): Promise<CaddyDiscovery> {
    const versionResult = spawnSync(this.caddyPath, ['version'], { encoding: 'utf8', timeout: 15_000, maxBuffer: 1024 * 1024 });
    const modulesResult = spawnSync(this.caddyPath, ['list-modules', '--packages'], { encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024 });
    const modules = modulesResult.status === 0 ? modulesResult.stdout.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean).slice(0, MAX_MODULES).sort() : [];
    const streamCloseDelaySupported = versionResult.status === 0 && modules.includes('http.handlers.reverse_proxy')
      ? this.probeStreamCloseDelayCapability()
      : false;
    return {
      available: versionResult.status === 0,
      executablePath: this.caddyPath,
      version: versionResult.status === 0 ? versionResult.stdout.trim().slice(0, 256) : 'UNAVAILABLE',
      modules,
      adminTransport: this.endpoint.transport,
      adminLocalOnly: true,
      autosaveCompatible: true,
      resumeCompatible: true,
      streamCloseDelaySupported,
    };
  }

  private probeStreamCloseDelayCapability(): boolean {
    mkdirSync(this.validationRoot, { recursive: true, mode: 0o700 });
    const bytes = Buffer.from(canonicalize({ apps: { http: { servers: { probe: { listen: ['127.0.0.1:0'], routes: [{ handle: [{ handler: 'reverse_proxy', upstreams: [{ dial: '127.0.0.1:1' }], stream_close_delay: '1s' }] }] } } } } }), 'utf8');
    const path = join(this.validationRoot, `capability-stream-close-${sha256(bytes)}.json`);
    durableWrite(path, bytes);
    try {
      const result = spawnSync(this.caddyPath, ['validate', '--config', path], { encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024 });
      return result.status === 0;
    } finally {
      rmSync(path, { force: true });
    }
  }

  private adminRequest(method: string, path: string, body?: Buffer): Promise<{ statusCode: number; bytes: Buffer; headers: JsonObject }> {
    return new Promise((resolvePromise, rejectPromise) => {
      const request = httpRequest({
        method,
        path,
        ...(this.endpoint.transport === 'UNIX_SOCKET' ? { socketPath: this.endpoint.socketPath } : { host: this.endpoint.host, port: this.endpoint.port }),
        headers: body === undefined ? { accept: 'application/json' } : { 'content-type': 'application/json', 'content-length': String(body.length), accept: 'application/json' },
        timeout: 30_000,
      }, (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_CONFIG_BYTES) { response.destroy(new RouteAuthorityError('release_config_too_large', 'Caddy admin response exceeded the bounded limit')); return; }
          chunks.push(chunk);
        });
        response.on('end', () => resolvePromise({ statusCode: response.statusCode ?? 0, bytes: Buffer.concat(chunks), headers: response.headers as JsonObject }));
      });
      request.on('timeout', () => request.destroy(new RouteAuthorityError('release_caddy_timeout', 'Caddy admin request timed out')));
      request.on('error', rejectPromise);
      if (body !== undefined) request.write(body);
      request.end();
    });
  }

  async capture(): Promise<CaddyConfigObservation> {
    const response = await this.adminRequest('GET', '/config/');
    if (response.statusCode < 200 || response.statusCode >= 300) throw new RouteAuthorityError('release_caddy_read_failed', 'Caddy active configuration capture failed', { statusCode: response.statusCode, responseDigest: sha256(response.bytes) });
    const config = object(JSON.parse(response.bytes.toString('utf8')), 'activeConfig');
    assertNoRawSecrets(config);
    const bytes = Buffer.from(canonicalize(config), 'utf8');
    return { observedAt: this.now(), config, configDigest: sha256(bytes) };
  }

  async validate(configBytes: Buffer, requiredModules: string[]): Promise<CaddyValidationResult> {
    if (configBytes.length > MAX_CONFIG_BYTES) throw new RouteAuthorityError('release_config_too_large', 'candidate configuration exceeds validation limit');
    const discovery = await this.discover();
    const missing = requiredModules.filter((module) => !discovery.modules.includes(module));
    mkdirSync(this.validationRoot, { recursive: true, mode: 0o700 });
    const path = join(this.validationRoot, `${sha256(configBytes)}.json`);
    durableWrite(path, configBytes);
    const result = missing.length === 0 && discovery.available
      ? spawnSync(this.caddyPath, ['validate', '--config', path], { encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024 })
      : { status: 1, stdout: '', stderr: missing.length > 0 ? `missing modules: ${missing.join(',')}` : 'caddy unavailable' };
    rmSync(path, { force: true });
    const diagnostics = boundedLines(`${result.stdout ?? ''}\n${result.stderr ?? ''}`);
    return {
      valid: result.status === 0,
      installedVersion: discovery.version,
      candidateDigest: sha256(configBytes),
      adaptedDigest: sha256(canonicalize({ candidateDigest: sha256(configBytes), version: discovery.version, diagnostics })),
      diagnostics,
      requiredModules: [...requiredModules].sort(),
      availableModules: discovery.modules,
    };
  }

  async load(configBytes: Buffer, requestDigest: string): Promise<JsonObject> {
    digest(requestDigest, 'requestDigest');
    if (!this.liveActions) throw new RouteAuthorityError('release_provider_unavailable', 'live Caddy mutation is disabled for this adapter');
    const response = await this.adminRequest('POST', '/load', configBytes);
    if (response.statusCode < 200 || response.statusCode >= 300) throw new RouteAuthorityError('release_caddy_load_failed', 'Caddy load failed', { statusCode: response.statusCode, responseDigest: sha256(response.bytes) });
    return { accepted: true, statusCode: response.statusCode, responseDigest: sha256(response.bytes), requestDigest };
  }

  async readback(routeId?: string): Promise<CaddyConfigObservation> {
    const observation = await this.capture();
    if (routeId === undefined) return observation;
    const upstreams = observedRouteUpstreams(observation.config, routeId);
    return { ...observation, routePresent: upstreams.length > 0, observedUpstreams: upstreams };
  }

  async probe(input: RouteProbeRequest): Promise<RouteProbeResult> {
    const started = Date.now();
    try {
      const result = await this.probeRequest(input);
      const observedReleaseIdentity = typeof result.headers['x-babyx-release-id'] === 'string' ? result.headers['x-babyx-release-id'] : undefined;
      const identityMatches = input.expectedReleaseIdentity === undefined || observedReleaseIdentity === input.expectedReleaseIdentity;
      const status = input.kind === 'ABSENCE'
        ? (result.statusCode === 404 ? 'PASS' : 'FAIL')
        : (result.statusCode >= 200 && result.statusCode < 400 && identityMatches ? 'PASS' : 'FAIL');
      const details = { statusCode: result.statusCode, responseDigest: sha256(result.bytes), observedReleaseIdentity: observedReleaseIdentity ?? null };
      return { kind: input.kind, status, observedAt: this.now(), statusCode: result.statusCode, latencyMs: Date.now() - started, responseDigest: sha256(result.bytes), ...(observedReleaseIdentity === undefined ? {} : { observedReleaseIdentity }), detailsDigest: sha256(canonicalize(details)) };
    } catch (error) {
      const details = boundedReleaseError(error, 'release_probe_failed', true, 'probe');
      return { kind: input.kind, status: error instanceof RouteAuthorityError && error.code === 'release_caddy_timeout' ? 'TIMEOUT' : 'FAIL', observedAt: this.now(), latencyMs: Date.now() - started, detailsDigest: sha256(canonicalize(details)) };
    }
  }

  private probeRequest(input: RouteProbeRequest): Promise<{ statusCode: number; bytes: Buffer; headers: JsonObject }> {
    if (input.kind === 'PRIVATE') {
      if (input.endpoint === undefined) throw new RouteAuthorityError('release_invalid_request', 'private probe requires endpoint');
      const target = endpoint(input.endpoint, 'probe.endpoint');
      return this.genericRequest(target.type === 'UNIX_SOCKET'
        ? { protocol: 'http:', socketPath: target.value, path: '/healthz', hostHeader: 'localhost' }
        : { protocol: 'http:', host: '127.0.0.1', port: Number(target.value.split(':')[1]), path: '/healthz', hostHeader: 'localhost' }, input.timeoutMs);
    }
    const identity = publicIdentity(input.publicIdentity);
    const urlValue = identity.publicProbeUrl;
    if (typeof urlValue !== 'string') throw new RouteAuthorityError('release_invalid_request', 'public probe URL is required');
    const parsed = new URL(urlValue);
    return this.genericRequest({ protocol: parsed.protocol, host: parsed.hostname, port: parsed.port === '' ? undefined : Number(parsed.port), path: `${parsed.pathname}${parsed.search}`, hostHeader: parsed.hostname }, input.timeoutMs);
  }

  private genericRequest(target: { protocol: string; socketPath?: string; host?: string; port?: number; path: string; hostHeader: string }, timeoutMs: number): Promise<{ statusCode: number; bytes: Buffer; headers: JsonObject }> {
    return new Promise((resolvePromise, rejectPromise) => {
      const requester = target.protocol === 'https:' ? httpsRequest : httpRequest;
      const request = requester({ method: 'GET', ...(target.socketPath === undefined ? { host: target.host, port: target.port } : { socketPath: target.socketPath }), path: target.path, headers: { host: target.hostHeader, connection: 'keep-alive' }, timeout: timeoutMs }, (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk: Buffer) => { size += chunk.length; if (size <= 1024 * 1024) chunks.push(chunk); });
        response.on('end', () => resolvePromise({ statusCode: response.statusCode ?? 0, bytes: Buffer.concat(chunks), headers: response.headers as JsonObject }));
      });
      request.on('timeout', () => request.destroy(new RouteAuthorityError('release_caddy_timeout', 'route probe timed out')));
      request.on('error', rejectPromise);
      request.end();
    });
  }
}

function artifactBytes(manager: ArtifactManager, artifactId: string): Buffer {
  const record = manager.get(artifactId);
  if (record.state !== 'finalized') throw new RouteAuthorityError('release_artifact_invalid', 'configuration artifact is not finalized');
  if (Number(record.size) > MAX_CONFIG_BYTES) throw new RouteAuthorityError('release_config_too_large', 'configuration artifact exceeds bounded load limit');
  const chunks: Buffer[] = [];
  let offset = 0;
  while (offset < Number(record.size)) {
    const part = manager.download(artifactId, offset, Math.min(65_536, Number(record.size) - offset));
    chunks.push(Buffer.from(String(part.data), 'base64'));
    offset = Number(part.offset);
  }
  const bytes = Buffer.concat(chunks);
  if (sha256(bytes) !== record.sha256) throw new RouteAuthorityError('release_artifact_invalid', 'configuration artifact digest does not match');
  return bytes;
}

function storeBytes(manager: ArtifactManager, name: string, bytes: Buffer, metadata: JsonObject): JsonObject {
  assertNoRawSecrets(metadata);
  const record = manager.begin(name, metadata);
  manager.upload(String(record.id), 0, bytes);
  return manager.finalize(String(record.id), bytes.length, sha256(bytes));
}

function parseConfig(bytes: Buffer): JsonObject {
  if (bytes.length > MAX_CONFIG_BYTES) throw new RouteAuthorityError('release_config_too_large', 'configuration exceeds bounded limit');
  const value = object(JSON.parse(bytes.toString('utf8')), 'configuration');
  assertNoRawSecrets(value);
  return value;
}

function sameStrings(left: unknown, right: unknown): boolean {
  return Array.isArray(left) && Array.isArray(right) && canonicalize([...left].map(String).sort()) === canonicalize([...right].map(String).sort());
}

function ownerFromEvents(store: ReleaseApplianceStore, routeId: string): string | undefined {
  const event = store.events('RouteRecordV1', routeId, 0, 1).at(0);
  return typeof event?.ownerPrincipal === 'string' ? event.ownerPrincipal : undefined;
}

function idempotencyReplay(store: ReleaseApplianceStore, routeId: string, key: string, requestDigest: string): JsonObject | undefined {
  if (!store.hasRecord('RouteRecordV1', routeId)) return undefined;
  const event = store.events('RouteRecordV1', routeId, 0, 10_000).find((candidate) => candidate.idempotencyKey === key);
  if (event === undefined) return undefined;
  if (event.requestDigest !== requestDigest) throw new RouteAuthorityError('release_idempotency_conflict', 'idempotency key was reused with a different route request');
  return store.getRecord('RouteRecordV1', routeId);
}

export class RouteAuthorityService {
  private readonly now: () => string;

  constructor(private readonly options: RouteAuthorityOptions) {
    this.now = options.now ?? (() => new Date().toISOString());
  }

  describe(): JsonObject {
    return {
      contractVersion: ROUTE_ADAPTER_CONTRACT_VERSION,
      authority: 'route-caddy-adapter',
      artifactAuthority: 'existing-babyx-artifact',
      routeTemplates: [...ROUTE_TEMPLATE_IDS],
      publicMutationExposed: false,
      productionMutationEnabledByDefault: false,
    };
  }

  acquireLease(serviceIdValue: unknown, leaseValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const authenticated = exactContext(context);
    const serviceId = identifier(serviceIdValue, 'serviceId');
    const routeId = routeIdFor(serviceId);
    const lease = normalizeLease(leaseValue);
    return this.options.store.acquireLease(validateReleaseRecord('ControllerLeaseV1', {
      schemaVersion: '1.0.0',
      leaseId: lease.leaseId,
      resourceType: 'ROUTE',
      resourceId: routeId,
      ownerPrincipal: authenticated.subject,
      controllerIdentity: lease.controllerIdentity,
      acquiredAt: lease.acquiredAt,
      expiresAt: lease.expiresAt,
      sequence: 1,
      state: 'ACTIVE',
      observationDigest: lease.observationDigest,
    }), { existingControllerAbsent: lease.existingControllerAbsent, now: this.now() });
  }

  releaseLease(serviceIdValue: unknown, leaseValue: unknown, context: RuntimeExecutionContext): JsonObject | undefined {
    const authenticated = exactContext(context);
    const serviceId = identifier(serviceIdValue, 'serviceId');
    const lease = normalizeLease(leaseValue);
    return this.options.store.releaseLease('ROUTE', routeIdFor(serviceId), lease.leaseId, authenticated.subject, lease.observationDigest, this.now());
  }

  async prepare(value: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = exactContext(context);
    const request = normalizeRouteRequest(value.request, authenticated.subject);
    const lease = normalizeLease(value.lease);
    const expectedSequence = value.expectedSequence === undefined ? (this.options.store.hasRecord('RouteRecordV1', request.routeId) ? Number(this.options.store.getRecord('RouteRecordV1', request.routeId).sequence) : 0) : integer(value.expectedSequence, 'expectedSequence', 0, Number.MAX_SAFE_INTEGER);
    const operationDigest = sha256(canonicalize({ request: request.requestDigest, leaseId: lease.leaseId }));
    const replay = idempotencyReplay(this.options.store, request.routeId, authenticated.idempotencyKey, operationDigest);
    if (replay !== undefined && ['VALIDATED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'].includes(String(replay.state))) return replay;
    this.assertLease(request.routeId, lease, authenticated.subject);
    let record: JsonObject;
    if (!this.options.store.hasRecord('RouteRecordV1', request.routeId)) {
      if (expectedSequence !== 0) throw new RouteAuthorityError('release_stale_sequence', 'new route expected sequence must be zero');
      record = validateReleaseRecord('RouteRecordV1', {
        schemaVersion: '1.0.0',
        routeId: request.routeId,
        serviceId: request.serviceId,
        ownerPrincipal: authenticated.subject,
        publicIdentity: request.publicIdentity,
        desiredActiveSlot: request.desiredActiveSlot,
        templateId: request.templateId,
        routeMode: request.mode,
        expectedUpstreams: request.mode === 'CANARY' ? [caddyDial(request.policy.stableEndpoint as RouteEndpoint), caddyDial(request.endpoint)].sort() : request.mode === 'SHADOW' ? [caddyDial(request.policy.primaryEndpoint as RouteEndpoint), caddyDial(request.endpoint)].sort() : [caddyDial(request.endpoint)],
        streamSettings: request.streamSettings,
        routePolicy: request.policy,
        routeLeaseId: lease.leaseId,
        routeLeaseObservationDigest: lease.observationDigest,
        operationRequestDigest: operationDigest,
        operationIdempotencyKey: authenticated.idempotencyKey,
        state: 'OBSERVED',
        sequence: 1,
      });
      record = this.options.store.applyMutation({ schemaId: 'RouteRecordV1', recordId: request.routeId, ownerPrincipal: authenticated.subject, expectedSequence: 0, idempotencyKey: authenticated.idempotencyKey, requestDigest: operationDigest, operation: 'babyx.release.route.coordinate', phase: 'observe-intent', record, occurredAt: this.now() });
    } else {
      record = this.ownerRoute(request.routeId, authenticated.subject);
      if (Number(record.sequence) !== expectedSequence) throw new RouteAuthorityError('release_stale_sequence', 'expected sequence does not match route record');
      if (!['ACTIVE_VERIFIED', 'RESTORED_VERIFIED', 'OBSERVED', 'RECOVERY_REQUIRED'].includes(String(record.state))) throw new RouteAuthorityError('release_invalid_state', 'route cannot prepare a new candidate from its current state', { state: record.state });
    }
    if (record.state !== 'PREPARING') record = this.transition(record, authenticated.subject, 'PREPARING', 'prepare-intent', `${authenticated.idempotencyKey}-intent`, sha256(canonicalize({ operationDigest, phase: 'prepare-intent' })), {
      publicIdentity: request.publicIdentity,
      desiredActiveSlot: request.desiredActiveSlot,
      templateId: request.templateId,
      routeMode: request.mode,
      expectedUpstreams: request.mode === 'CANARY' ? [caddyDial(request.policy.stableEndpoint as RouteEndpoint), caddyDial(request.endpoint)].sort() : request.mode === 'SHADOW' ? [caddyDial(request.policy.primaryEndpoint as RouteEndpoint), caddyDial(request.endpoint)].sort() : [caddyDial(request.endpoint)],
      streamSettings: request.streamSettings,
      routePolicy: request.policy,
      routeLeaseId: lease.leaseId,
      routeLeaseObservationDigest: lease.observationDigest,
      operationRequestDigest: operationDigest,
      operationIdempotencyKey: authenticated.idempotencyKey,
      ambiguity: undefined,
      error: undefined,
    });
    try {
      const captured = await this.options.caddy.capture();
      assertNoRawSecrets(captured.config);
      const previousBytes = Buffer.from(canonicalize(captured.config), 'utf8');
      const previousArtifact = storeBytes(this.options.artifacts, `${request.routeId}-previous-caddy.json`, previousBytes, { kind: 'CADDY_PREVIOUS_CONFIG', routeId: request.routeId, serviceId: request.serviceId, ownerPrincipal: authenticated.subject, configDigest: sha256(previousBytes) });
      const generated = generateTrustedCaddyConfig(captured.config, value.request, authenticated.subject);
      const candidateArtifact = storeBytes(this.options.artifacts, `${request.routeId}-candidate-caddy.json`, generated.bytes, { kind: 'CADDY_CANDIDATE_CONFIG', routeId: request.routeId, serviceId: request.serviceId, ownerPrincipal: authenticated.subject, configDigest: generated.digest, templateId: generated.templateId });
      const previousObservedUpstreams = observedRouteUpstreams(captured.config, request.routeId);
      record = this.transition(record, authenticated.subject, 'PREPARING', 'config-artifacts', `${authenticated.idempotencyKey}-artifacts`, sha256(canonicalize({ operationDigest, previous: previousArtifact.sha256, candidate: candidateArtifact.sha256 })), {
        previousConfigArtifactId: previousArtifact.id,
        previousConfigDigest: previousArtifact.sha256,
        previousObservedUpstreams,
        candidateConfigArtifactId: candidateArtifact.id,
        candidateConfigDigest: candidateArtifact.sha256,
        configGenerationDigest: generated.digest,
        currentConfigCapture: { observedAt: captured.observedAt, configDigest: captured.configDigest },
      }, [{ artifactId: previousArtifact.id, artifactSha256: previousArtifact.sha256 }, { artifactId: candidateArtifact.id, artifactSha256: candidateArtifact.sha256 }]);
      const discovery = await this.options.caddy.discover();
      if (!discovery.available || !discovery.adminLocalOnly) throw new RouteAuthorityError('release_provider_incompatible', 'installed Caddy or local-only administration is unavailable');
      if ((request.streamSettings.websocket || request.streamSettings.sse) && request.streamSettings.streamCloseDelayMs > 0 && discovery.streamCloseDelaySupported !== true) throw new RouteAuthorityError('release_provider_incompatible', 'installed Caddy cannot preserve bounded upgraded-stream close behavior');
      const validation = await this.options.caddy.validate(generated.bytes, generated.requiredModules);
      if (!validation.valid || validation.candidateDigest !== generated.digest) throw new RouteAuthorityError('release_caddy_validation_failed', 'candidate Caddy configuration failed installed-version validation', { validationDigest: sha256(canonicalize(validation)) });
      const privateProbe = await this.options.caddy.probe({ kind: 'PRIVATE', serviceId: request.serviceId, routeId: request.routeId, endpoint: request.endpoint, expectedUpstreams: generated.expectedUpstreams, ...(request.expectedReleaseIdentity === undefined ? {} : { expectedReleaseIdentity: request.expectedReleaseIdentity }), timeoutMs: 30_000 });
      if (privateProbe.status !== 'PASS') throw new RouteAuthorityError('release_private_probe_failed', 'candidate private probe failed', { probeDigest: privateProbe.detailsDigest });
      return this.transition(record, authenticated.subject, 'VALIDATED', 'candidate-validated', `${authenticated.idempotencyKey}-validated`, sha256(canonicalize({ operationDigest, validation, privateProbe })), {
        validationResult: validation,
        installedCaddyVersion: validation.installedVersion,
        installedCaddyCapabilities: { modules: validation.availableModules, adminTransport: discovery.adminTransport, autosaveCompatible: discovery.autosaveCompatible, resumeCompatible: discovery.resumeCompatible, streamCloseDelaySupported: discovery.streamCloseDelaySupported },
        privateProbeResult: privateProbe,
        ...(request.mode === 'PREVIEW' ? { previewExpiresAt: request.policy.expiresAt } : {}),
      });
    } catch (error) {
      return this.recovery(record, authenticated.subject, 'prepare-failed', error, operationDigest);
    }
  }

  async cutover(value: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = exactContext(context);
    const serviceId = identifier(value.serviceId, 'serviceId');
    const routeId = routeIdFor(serviceId);
    const lease = normalizeLease(value.lease);
    let record = this.ownerRoute(routeId, authenticated.subject);
    const requestDigest = sha256(canonicalize({ routeId, candidateConfigDigest: record.candidateConfigDigest, leaseId: lease.leaseId, action: 'cutover' }));
    const replay = idempotencyReplay(this.options.store, routeId, authenticated.idempotencyKey, requestDigest);
    if (replay !== undefined && ['ACTIVE_VERIFIED', 'RESTORED_VERIFIED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'].includes(String(replay.state))) return replay;
    const expectedSequence = integer(value.expectedSequence, 'expectedSequence', 0, Number.MAX_SAFE_INTEGER);
    if (Number(record.sequence) !== expectedSequence) throw new RouteAuthorityError('release_stale_sequence', 'expected sequence does not match route record');
    this.assertLease(routeId, lease, authenticated.subject);
    if (record.state === 'AMBIGUOUS') throw new RouteAuthorityError('release_route_ambiguous', 'ambiguous route blocks further destructive mutation');
    if (record.state !== 'VALIDATED') throw new RouteAuthorityError('release_invalid_state', 'route must be VALIDATED before load');
    const bytes = artifactBytes(this.options.artifacts, text(record.candidateConfigArtifactId, 'candidateConfigArtifactId'));
    if (sha256(bytes) !== record.candidateConfigDigest) throw new RouteAuthorityError('release_artifact_invalid', 'candidate config artifact digest mismatch');
    record = this.transition(record, authenticated.subject, 'LOADING', 'load-intent', authenticated.idempotencyKey, requestDigest, { loadRequestDigest: requestDigest, loadIntent: { candidateConfigDigest: record.candidateConfigDigest, routeLeaseId: lease.leaseId, intendedAt: this.now() } });
    let response: JsonObject | undefined;
    let loadError: unknown;
    try { response = await this.options.caddy.load(bytes, requestDigest); } catch (error) { loadError = error; }
    if (response !== undefined) {
      record = this.transition(record, authenticated.subject, 'VERIFYING', 'load-response', `${authenticated.idempotencyKey}-response`, sha256(canonicalize({ requestDigest, response })), { loadResponseDigest: sha256(canonicalize(response)), apiResponse: { digest: sha256(canonicalize(response)) } });
    }
    return this.reconcileLoaded(record, authenticated.subject, lease, requestDigest, loadError, value.publicProbeExpectedReleaseIdentity === undefined ? undefined : identifier(value.publicProbeExpectedReleaseIdentity, 'publicProbeExpectedReleaseIdentity'));
  }

  async restore(value: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = exactContext(context);
    const serviceId = identifier(value.serviceId, 'serviceId');
    const routeId = routeIdFor(serviceId);
    const lease = normalizeLease(value.lease);
    let record = this.ownerRoute(routeId, authenticated.subject);
    const requestDigest = sha256(canonicalize({ routeId, previousConfigDigest: record.previousConfigDigest, leaseId: lease.leaseId, action: 'restore' }));
    const replay = idempotencyReplay(this.options.store, routeId, authenticated.idempotencyKey, requestDigest);
    if (replay !== undefined && ['RESTORED_VERIFIED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'].includes(String(replay.state))) return replay;
    const expectedSequence = integer(value.expectedSequence, 'expectedSequence', 0, Number.MAX_SAFE_INTEGER);
    if (Number(record.sequence) !== expectedSequence) throw new RouteAuthorityError('release_stale_sequence', 'expected sequence does not match route record');
    this.assertLease(routeId, lease, authenticated.subject);
    if (record.state === 'AMBIGUOUS') throw new RouteAuthorityError('release_route_ambiguous', 'ambiguous route blocks restoration until identity is resolved');
    if (!['ACTIVE_VERIFIED', 'VERIFYING', 'RECOVERY_REQUIRED', 'RESTORE_REQUESTED'].includes(String(record.state))) throw new RouteAuthorityError('release_invalid_state', 'route cannot restore from its current state', { state: record.state });
    if (record.state !== 'RESTORE_REQUESTED') record = this.transition(record, authenticated.subject, 'RESTORE_REQUESTED', 'restore-intent', authenticated.idempotencyKey, requestDigest, { restoreRequestDigest: requestDigest });
    return this.restoreInternal(record, authenticated.subject, lease, requestDigest, value.publicProbeExpectedReleaseIdentity === undefined ? undefined : identifier(value.publicProbeExpectedReleaseIdentity, 'publicProbeExpectedReleaseIdentity'));
  }

  async reconcile(value: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = exactContext(context);
    const serviceId = identifier(value.serviceId, 'serviceId');
    const routeId = routeIdFor(serviceId);
    const lease = normalizeLease(value.lease);
    const record = this.ownerRoute(routeId, authenticated.subject);
    this.assertLease(routeId, lease, authenticated.subject);
    if (record.state === 'LOADING' || record.state === 'VERIFYING') return this.reconcileLoaded(record, authenticated.subject, lease, digest(record.loadRequestDigest, 'loadRequestDigest'), new RouteAuthorityError('release_response_lost', 'reconciling unresolved route load'));
    if (record.state === 'RESTORING' || record.state === 'RESTORE_REQUESTED') return this.restoreInternal(record, authenticated.subject, lease, digest(record.restoreRequestDigest, 'restoreRequestDigest'));
    return record;
  }

  async expirePreview(value: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = exactContext(context);
    const serviceId = identifier(value.serviceId, 'serviceId');
    const routeId = routeIdFor(serviceId);
    const lease = normalizeLease(value.lease);
    const record = this.ownerRoute(routeId, authenticated.subject);
    if (record.routeMode !== 'PREVIEW') throw new RouteAuthorityError('release_invalid_state', 'only preview routes may expire through preview cleanup');
    if (Date.parse(timestamp(record.previewExpiresAt, 'previewExpiresAt')) > Date.parse(this.now())) throw new RouteAuthorityError('release_preview_not_expired', 'preview route has not expired');
    const restored = await this.restore({ serviceId, lease, expectedSequence: record.sequence }, { ...context, idempotencyKey: authenticated.idempotencyKey });
    if (restored.state !== 'RESTORED_VERIFIED') return restored;
    const observation = await this.options.caddy.readback(routeId);
    const absent = observedRouteUpstreams(observation.config, routeId).length === 0;
    if (!absent && (record.previousObservedUpstreams as string[]).length === 0) return this.ambiguous(restored, authenticated.subject, 'preview-absence-unproven', new RouteAuthorityError('release_preview_cleanup_failed', 'preview route absence was not proven'), sha256(canonicalize({ routeId, observation: observation.configDigest })));
    return this.transition(restored, authenticated.subject, 'RESTORED_VERIFIED', 'preview-cleanup-verified', `${authenticated.idempotencyKey}-absence`, sha256(canonicalize({ routeId, observation: observation.configDigest, absent })), { previewCleanup: { routeRemoved: absent || (record.previousObservedUpstreams as string[]).length > 0, positiveAbsence: absent, observedAt: observation.observedAt, observationDigest: observation.configDigest }, cleanupCompletedAt: this.now(), routeAbsent: absent });
  }

  getRoute(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const input = strictObject(payload, 'payload', ['serviceId']);
    const routeId = routeIdFor(identifier(input.serviceId, 'serviceId'));
    const record = this.ownerRoute(routeId, context.authorityClass === 'unrestricted-owner' ? undefined : context.subject);
    return { operation: 'babyx.release.route.get', route: record };
  }

  private assertLease(routeId: string, lease: RouteLeaseRequest, ownerPrincipal: string): void {
    const current = this.options.store.getLease('ROUTE', routeId);
    if (current === undefined || current.state !== 'ACTIVE' || current.leaseId !== lease.leaseId || current.ownerPrincipal !== ownerPrincipal || current.observationDigest !== lease.observationDigest || Date.parse(String(current.expiresAt)) <= Date.parse(this.now())) throw new RouteAuthorityError('release_controller_conflict', 'exact active route lease is required');
  }

  private ownerRoute(routeId: string, subject?: string): JsonObject {
    let record: JsonObject;
    try { record = this.options.store.getRecord('RouteRecordV1', routeId); } catch (error) {
      if (error instanceof ReleaseStoreError && error.code === 'release_record_not_found') throw new RouteAuthorityError('release_record_not_found', 'route was not found');
      throw error;
    }
    const owner = typeof record.ownerPrincipal === 'string' ? record.ownerPrincipal : ownerFromEvents(this.options.store, routeId);
    if (subject !== undefined && owner !== subject) throw new RouteAuthorityError('release_record_not_found', 'route was not found');
    return record;
  }

  private async reconcileLoaded(recordValue: JsonObject, ownerPrincipal: string, lease: RouteLeaseRequest, requestDigest: string, loadError?: unknown, expectedReleaseIdentity?: string): Promise<JsonObject> {
    let record = recordValue;
    const observation = await this.options.caddy.readback(String(record.routeId));
    const upstreams = observedRouteUpstreams(observation.config, String(record.routeId));
    const candidateMatches = observation.configDigest === record.candidateConfigDigest && sameStrings(upstreams, record.expectedUpstreams);
    const previousMatches = observation.configDigest === record.previousConfigDigest && sameStrings(upstreams, record.previousObservedUpstreams);
    if (!candidateMatches) {
      if (previousMatches) return this.recovery(record, ownerPrincipal, 'load-not-observed', loadError ?? new RouteAuthorityError('release_caddy_load_unobserved', 'candidate load was not observed and prior config remains active'), requestDigest, { activeConfigReadbackDigest: observation.configDigest, observedActiveUpstream: { upstreams } });
      return this.ambiguous(record, ownerPrincipal, 'load-readback-ambiguous', loadError ?? new RouteAuthorityError('release_route_ambiguous', 'active Caddy config does not match candidate or prior config'), requestDigest, { activeConfigReadbackDigest: observation.configDigest, observedActiveUpstream: { upstreams } });
    }
    if (record.state === 'LOADING') record = this.transition(record, ownerPrincipal, 'VERIFYING', 'load-readback', `${record.operationIdempotencyKey}-readback`, sha256(canonicalize({ requestDigest, observation: observation.configDigest })), { activeConfigReadbackDigest: observation.configDigest, activeConfigReadback: { observedAt: observation.observedAt, configDigest: observation.configDigest }, observedActiveUpstream: { upstreams } });
    const publicProbe = await this.options.caddy.probe({ kind: 'PUBLIC', serviceId: String(record.serviceId), routeId: String(record.routeId), publicIdentity: record.publicIdentity as JsonObject, expectedUpstreams: record.expectedUpstreams as string[], ...(expectedReleaseIdentity === undefined ? {} : { expectedReleaseIdentity }), timeoutMs: 30_000 });
    if (publicProbe.status !== 'PASS') {
      const requested = this.transition(record, ownerPrincipal, 'RESTORE_REQUESTED', 'public-probe-failed', `${record.operationIdempotencyKey}-probe-restore`, sha256(canonicalize({ requestDigest, publicProbe })), { publicProbeResult: publicProbe, rollbackAt: this.now() });
      return this.restoreInternal(requested, ownerPrincipal, lease, sha256(canonicalize({ requestDigest, reason: 'public-probe-failed' })));
    }
    return this.transition(record, ownerPrincipal, 'ACTIVE_VERIFIED', 'active-route-verified', `${record.operationIdempotencyKey}-active`, sha256(canonicalize({ requestDigest, observation: observation.configDigest, publicProbe })), { activeConfigReadbackDigest: observation.configDigest, activeConfigReadback: { observedAt: observation.observedAt, configDigest: observation.configDigest }, observedActiveUpstream: { upstreams }, publicProbeResult: publicProbe, cutoverAt: this.now(), ambiguity: undefined, error: undefined });
  }

  private async restoreInternal(recordValue: JsonObject, ownerPrincipal: string, lease: RouteLeaseRequest, requestDigest: string, expectedReleaseIdentity?: string): Promise<JsonObject> {
    let record = recordValue;
    if (record.state !== 'RESTORING') record = this.transition(record, ownerPrincipal, 'RESTORING', 'restore-load-intent', `${record.operationIdempotencyKey}-restore-load`, sha256(canonicalize({ requestDigest, previousConfigDigest: record.previousConfigDigest, leaseId: lease.leaseId })), { restoreLoadIntent: { previousConfigDigest: record.previousConfigDigest, routeLeaseId: lease.leaseId, intendedAt: this.now() } });
    const bytes = artifactBytes(this.options.artifacts, text(record.previousConfigArtifactId, 'previousConfigArtifactId'));
    if (sha256(bytes) !== record.previousConfigDigest) return this.recovery(record, ownerPrincipal, 'restore-artifact-invalid', new RouteAuthorityError('release_artifact_invalid', 'previous config artifact digest mismatch'), requestDigest);
    let response: JsonObject | undefined;
    let loadError: unknown;
    try { response = await this.options.caddy.load(bytes, requestDigest); } catch (error) { loadError = error; }
    const observation = await this.options.caddy.readback(String(record.routeId));
    const upstreams = observedRouteUpstreams(observation.config, String(record.routeId));
    if (observation.configDigest !== record.previousConfigDigest || !sameStrings(upstreams, record.previousObservedUpstreams)) {
      if (observation.configDigest === record.candidateConfigDigest && sameStrings(upstreams, record.expectedUpstreams)) return this.recovery(record, ownerPrincipal, 'restore-not-observed', loadError ?? new RouteAuthorityError('release_restore_unobserved', 'prior config restoration was not observed and candidate remains active'), requestDigest, { restorationReadbackDigest: observation.configDigest });
      return this.ambiguous(record, ownerPrincipal, 'restore-readback-ambiguous', loadError ?? new RouteAuthorityError('release_route_ambiguous', 'active config matches neither prior nor candidate during restoration'), requestDigest, { restorationReadbackDigest: observation.configDigest });
    }
    const publicProbe = await this.options.caddy.probe({ kind: (record.previousObservedUpstreams as string[]).length === 0 ? 'ABSENCE' : 'PUBLIC', serviceId: String(record.serviceId), routeId: String(record.routeId), publicIdentity: record.publicIdentity as JsonObject, expectedUpstreams: record.previousObservedUpstreams as string[], ...(expectedReleaseIdentity === undefined ? {} : { expectedReleaseIdentity }), timeoutMs: 30_000 });
    if (publicProbe.status !== 'PASS') return this.recovery(record, ownerPrincipal, 'restore-public-probe-failed', new RouteAuthorityError('release_public_probe_failed', 'restored route public probe failed', { probeDigest: publicProbe.detailsDigest }), requestDigest, { restorationPublicProbe: publicProbe });
    return this.transition(record, ownerPrincipal, 'RESTORED_VERIFIED', 'restore-verified', `${record.operationIdempotencyKey}-restored`, sha256(canonicalize({ requestDigest, responseDigest: response === undefined ? null : sha256(canonicalize(response)), observation: observation.configDigest, publicProbe })), { restorationResponseDigest: response === undefined ? undefined : sha256(canonicalize(response)), restorationReadbackDigest: observation.configDigest, restorationPublicProbe: publicProbe, observedActiveUpstream: { upstreams }, rollbackAt: this.now(), ambiguity: undefined, error: undefined });
  }

  private transition(record: JsonObject, ownerPrincipal: string, state: string, phase: string, idempotencyKey: string, requestDigest: string, patch: JsonObject, artifactReferences: JsonObject[] = []): JsonObject {
    const prior = String(record.state);
    if (prior !== state) assertReleaseTransition('route', prior, state);
    const sequence = integer(record.sequence, 'route.sequence', 0, Number.MAX_SAFE_INTEGER);
    const draft: JsonObject = { ...record };
    for (const [key, value] of Object.entries(patch)) {
      if (value === undefined) delete draft[key];
      else draft[key] = value;
    }
    const candidate = validateReleaseRecord('RouteRecordV1', { ...draft, state, sequence: sequence + 1 });
    const normalizedIdempotencyKey = IDENTIFIER.test(idempotencyKey) && idempotencyKey.length <= 64 ? idempotencyKey : `route-${sha256(idempotencyKey).slice(0, 56)}`;
    return this.options.store.applyMutation({ schemaId: 'RouteRecordV1', recordId: String(record.routeId), ownerPrincipal, expectedSequence: sequence, idempotencyKey: normalizedIdempotencyKey, requestDigest, operation: 'babyx.release.route.coordinate', phase: identifier(phase, 'phase'), record: candidate, occurredAt: this.now(), observationDigest: patch.activeConfigReadbackDigest === undefined ? undefined : String(patch.activeConfigReadbackDigest), artifactReferences });
  }

  private structuredError(error: unknown, fallbackCode: string, retryable: boolean, phase: string): JsonObject {
    const bounded = boundedReleaseError(error, fallbackCode, retryable, phase);
    const code = error instanceof RouteAuthorityError ? error.code : bounded.code;
    const details = error instanceof RouteAuthorityError ? error.details : bounded.details ?? {};
    return { code, message: bounded.message, retryable: bounded.retryable, phase: bounded.phase, productionImpact: 'UNKNOWN', detailsDigest: sha256(canonicalize(details)) };
  }

  private recovery(record: JsonObject, ownerPrincipal: string, phase: string, error: unknown, requestDigest: string, patch: JsonObject = {}): JsonObject {
    const structured = this.structuredError(error, 'release_recovery_required', true, phase);
    return this.transition(record, ownerPrincipal, 'RECOVERY_REQUIRED', phase, `${record.operationIdempotencyKey}-${phase}`, sha256(canonicalize({ requestDigest, structured })), { ...patch, error: structured });
  }

  private ambiguous(record: JsonObject, ownerPrincipal: string, phase: string, error: unknown, requestDigest: string, patch: JsonObject = {}): JsonObject {
    const structured = this.structuredError(error, 'release_route_ambiguous', false, phase);
    return this.transition(record, ownerPrincipal, 'AMBIGUOUS', phase, `${record.operationIdempotencyKey}-${phase}`, sha256(canonicalize({ requestDigest, structured })), { ...patch, ambiguity: { code: structured.code, detailsDigest: structured.detailsDigest }, error: structured });
  }
}
