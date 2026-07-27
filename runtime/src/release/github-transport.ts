import { request as httpsRequest } from 'node:https';
import { URL } from 'node:url';
import { canonicalize, sha256 } from '../core.js';
import type { JsonObject } from '../core.js';
import type { GitHubTransport } from './access.js';

const MAX_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 2;
const USER_AGENT = 'baby-x-release-appliance/1.0';

export type GitHubFailureClass =
  | 'AUTHENTICATION' | 'AUTHORIZATION' | 'RATE_LIMITED' | 'TIMEOUT' | 'NETWORK'
  | 'PROVIDER_4XX' | 'PROVIDER_5XX' | 'MALFORMED_RESPONSE' | 'POLICY_CONFLICT' | 'UNKNOWN';

export class GitHubTransportError extends Error {
  readonly code = 'release_github_transport_failed';
  constructor(
    readonly failureClass: GitHubFailureClass,
    readonly retryable: boolean,
    message: string,
    readonly details: JsonObject = {},
  ) { super(message); this.name = 'GitHubTransportError'; }
}

export interface GitHubHttpRequest {
  method: 'GET' | 'POST' | 'PATCH';
  url: string;
  headers: Record<string, string>;
  body?: Buffer;
  timeoutMs: number;
  maxResponseBytes: number;
  maxRedirects: number;
}
export interface GitHubHttpResponse { statusCode: number; headers: Record<string, string>; body: Buffer; }
export interface GitHubHttpClient { request(input: GitHubHttpRequest): Promise<GitHubHttpResponse>; }

function headerMap(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  return Object.fromEntries(Object.entries(headers).flatMap(([key, value]) => value === undefined ? [] : [[key.toLowerCase(), Array.isArray(value) ? value.join(',') : value]]));
}

export class NodeHttpsGitHubClient implements GitHubHttpClient {
  async request(input: GitHubHttpRequest): Promise<GitHubHttpResponse> {
    const execute = async (urlValue: string, redirects: number): Promise<GitHubHttpResponse> => {
      const url = new URL(urlValue);
      if (url.protocol !== 'https:') throw new GitHubTransportError('POLICY_CONFLICT', false, 'GitHub transport requires HTTPS');
      return new Promise<GitHubHttpResponse>((resolvePromise, rejectPromise) => {
        const request = httpsRequest(url, { method:input.method, headers:input.headers, timeout:input.timeoutMs }, (response) => {
          const statusCode = response.statusCode ?? 0;
          const headers = headerMap(response.headers as Record<string, string | string[] | undefined>);
          if ([301, 302, 307, 308].includes(statusCode)) {
            response.resume();
            const location = headers.location;
            if (location === undefined || redirects >= input.maxRedirects) return rejectPromise(new GitHubTransportError('POLICY_CONFLICT', false, 'GitHub redirect policy rejected response'));
            const target = new URL(location, url);
            if (target.protocol !== 'https:' || target.origin !== url.origin) return rejectPromise(new GitHubTransportError('POLICY_CONFLICT', false, 'GitHub redirect left the configured HTTPS origin'));
            void execute(target.toString(), redirects + 1).then(resolvePromise, rejectPromise);
            return;
          }
          const chunks: Buffer[] = [];
          let bytes = 0;
          response.on('data', (chunk: Buffer) => {
            bytes += chunk.length;
            if (bytes > input.maxResponseBytes) {
              request.destroy(new GitHubTransportError('MALFORMED_RESPONSE', false, 'GitHub response exceeded the configured bound'));
              return;
            }
            chunks.push(Buffer.from(chunk));
          });
          response.on('end', () => resolvePromise({ statusCode, headers, body:Buffer.concat(chunks) }));
        });
        request.on('timeout', () => request.destroy(new GitHubTransportError('TIMEOUT', true, 'GitHub request timed out')));
        request.on('error', (error) => rejectPromise(error instanceof GitHubTransportError ? error : new GitHubTransportError('NETWORK', true, 'GitHub network request failed', { errorDigest:sha256(error.message) })));
        if (input.body !== undefined) request.write(input.body);
        request.end();
      });
    };
    return execute(input.url, 0);
  }
}

function retryAfter(headers: Record<string, string>): number | undefined {
  const raw = headers['retry-after'];
  if (raw === undefined) return undefined;
  const seconds = Number(raw);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(24 * 60 * 60 * 1000, Math.floor(seconds * 1000));
  const timestamp = Date.parse(raw);
  return Number.isFinite(timestamp) ? Math.max(0, timestamp - Date.now()) : undefined;
}

function classify(statusCode: number, headers: Record<string, string>, body: Buffer): never {
  const delay = retryAfter(headers);
  const details: JsonObject = { statusCode, responseDigest:sha256(body), ...(delay === undefined ? {} : { retryAfterMs:delay }) };
  if (statusCode === 401) throw new GitHubTransportError('AUTHENTICATION', false, 'GitHub authentication failed', details);
  if (statusCode === 403 && (headers['x-ratelimit-remaining'] === '0' || delay !== undefined)) throw new GitHubTransportError('RATE_LIMITED', true, 'GitHub rate limit was reached', details);
  if (statusCode === 403) throw new GitHubTransportError('AUTHORIZATION', false, 'GitHub authorization failed', details);
  if (statusCode === 409) throw new GitHubTransportError('POLICY_CONFLICT', true, 'GitHub reported a provider conflict', details);
  if (statusCode === 429) throw new GitHubTransportError('RATE_LIMITED', true, 'GitHub rate limit was reached', details);
  if (statusCode >= 500) throw new GitHubTransportError('PROVIDER_5XX', true, 'GitHub provider failed', details);
  if (statusCode >= 400) throw new GitHubTransportError('PROVIDER_4XX', false, 'GitHub rejected the request', details);
  throw new GitHubTransportError('UNKNOWN', false, 'GitHub returned an unexpected response', details);
}

function parseJsonValue(response: GitHubHttpResponse, expected: readonly number[], maximumBytes: number): unknown {
  if (response.body.length > maximumBytes) throw new GitHubTransportError('MALFORMED_RESPONSE', false, 'GitHub response exceeded the configured bound', { responseDigest:sha256(response.body) });
  if (!expected.includes(response.statusCode)) classify(response.statusCode, response.headers, response.body);
  if (response.body.length === 0) return {};
  try { return JSON.parse(response.body.toString('utf8')) as unknown; }
  catch { throw new GitHubTransportError('MALFORMED_RESPONSE', false, 'GitHub returned malformed JSON', { statusCode:response.statusCode, responseDigest:sha256(response.body) }); }
}

function repository(value: string): string {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(value)) throw new GitHubTransportError('POLICY_CONFLICT', false, 'repository identity is invalid');
  return value;
}
function id(value: unknown, label: string): string {
  if ((typeof value !== 'string' && typeof value !== 'number') || !/^[A-Za-z0-9_.:-]+$/u.test(String(value))) throw new GitHubTransportError('POLICY_CONFLICT', false, `${label} is invalid`);
  return String(value);
}
function object(value: unknown, label: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new GitHubTransportError('MALFORMED_RESPONSE', false, `${label} must be an object`);
  return value as JsonObject;
}
function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new GitHubTransportError('MALFORMED_RESPONSE', false, `${label} must be an array`);
  return value;
}
function without(value: JsonObject, keys: readonly string[]): JsonObject {
  return Object.fromEntries(Object.entries(value).filter(([key]) => !keys.includes(key)));
}
function marker(semanticKey: string): string { return `babyx-${sha256(semanticKey).slice(0, 32)}`; }
function boundedMarked(prefix: string, semantic: string, maximum: number): string {
  const suffix = `[${semantic}]`;
  return `${prefix.slice(0, Math.max(0, maximum - suffix.length - 1))}${prefix.length === 0 ? '' : ' '}${suffix}`.slice(0, maximum);
}
function responseIdentity(value: JsonObject): JsonObject {
  return { id:value.id ?? null, nodeId:value.node_id ?? value.nodeId ?? null, url:value.url ?? value.html_url ?? null };
}

export interface ConcreteGitHubTransportOptions {
  client?: GitHubHttpClient;
  apiBaseUrl?: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  maxRedirects?: number;
  now?: () => string;
}

export class ConcreteGitHubAppTransport implements GitHubTransport {
  readonly authority = 'github-app-transport' as const;
  private readonly client: GitHubHttpClient;
  private readonly apiBaseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly maxRedirects: number;
  private readonly now: () => string;
  private lastSuccessfulProviderContact?: string;
  private lastFailure?: JsonObject;
  constructor(options: ConcreteGitHubTransportOptions = {}) {
    this.client = options.client ?? new NodeHttpsGitHubClient();
    const base = new URL(options.apiBaseUrl ?? 'https://api.github.com');
    if (base.protocol !== 'https:') throw new GitHubTransportError('POLICY_CONFLICT', false, 'GitHub API base must use HTTPS');
    this.apiBaseUrl = base.toString().replace(/\/$/u, '');
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxResponseBytes = options.maxResponseBytes ?? MAX_RESPONSE_BYTES;
    this.maxRedirects = options.maxRedirects ?? MAX_REDIRECTS;
    this.now = options.now ?? (() => new Date().toISOString());
  }
  describe(): JsonObject {
    return { implemented:true, providerConfigured:true, httpsOnly:true, boundedTimeoutMs:this.timeoutMs, boundedResponseBytes:this.maxResponseBytes, maxRedirects:this.maxRedirects, semanticReadback:true, ...(this.lastSuccessfulProviderContact === undefined ? {} : { lastSuccessfulProviderContact:this.lastSuccessfulProviderContact }), ...(this.lastFailure === undefined ? {} : { lastRedactedFailure:this.lastFailure }) };
  }
  private async callValue(method: 'GET'|'POST'|'PATCH', path: string, access: string, payload?: JsonObject, expected: readonly number[] = [200, 201]): Promise<unknown> {
    const body = payload === undefined ? undefined : Buffer.from(canonicalize(payload));
    try {
      const response = await this.client.request({ method, url:`${this.apiBaseUrl}${path}`, headers:{ Accept:'application/vnd.github+json', Authorization:access, 'User-Agent':USER_AGENT, 'X-GitHub-Api-Version':'2022-11-28', ...(body === undefined ? {} : { 'Content-Type':'application/json', 'Content-Length':String(body.length) }) }, ...(body === undefined ? {} : { body }), timeoutMs:this.timeoutMs, maxResponseBytes:this.maxResponseBytes, maxRedirects:this.maxRedirects });
      const parsed = parseJsonValue(response, expected, this.maxResponseBytes);
      this.lastSuccessfulProviderContact = this.now(); this.lastFailure = undefined;
      return parsed;
    } catch (error) {
      const failure = error instanceof GitHubTransportError ? error : new GitHubTransportError('UNKNOWN', false, 'GitHub transport failed');
      this.lastFailure = { failureClass:failure.failureClass, retryable:failure.retryable, errorDigest:sha256(failure.message), ...failure.details };
      throw failure;
    }
  }
  private async callObject(method: 'GET'|'POST'|'PATCH', path: string, access: string, payload?: JsonObject, expected?: readonly number[]): Promise<JsonObject> {
    return object(await this.callValue(method, path, access, payload, expected), 'GitHub response');
  }
  private async callArray(path: string, access: string): Promise<JsonObject[]> {
    return array(await this.callValue('GET', path, access), 'GitHub response').map((entry, index) => object(entry, `GitHub response[${index}]`));
  }
  async exchangeInstallation(input: { appId:string; installationId:string; assertion:string; permissions:JsonObject }): Promise<{ accessValue:string; expiresAt:string; remoteIdentity?:JsonObject }> {
    const result = await this.callObject('POST', `/app/installations/${encodeURIComponent(id(input.installationId,'installationId'))}/access_tokens`, `Bearer ${input.assertion}`, { permissions:input.permissions });
    if (typeof result.token !== 'string' || result.token.length < 1 || result.token.length > 4096 || typeof result.expires_at !== 'string' || !Number.isFinite(Date.parse(result.expires_at))) throw new GitHubTransportError('MALFORMED_RESPONSE', false, 'GitHub installation token response is invalid', { responseDigest:sha256(canonicalize(result)) });
    return { accessValue:result.token, expiresAt:result.expires_at, remoteIdentity:{ installationId:input.installationId, permissionsDigest:sha256(canonicalize(result.permissions ?? {})), repositorySelection:result.repository_selection ?? null } };
  }
  async deliver(input: { accessValue:string; semanticKey:string; repository:string; targetOperation:string; payload:JsonObject }): Promise<JsonObject> {
    const repo = repository(input.repository);
    const payload = object(input.payload, 'payload');
    const semantic = marker(input.semanticKey);
    if (input.targetOperation === 'deployments.status') {
      const body = without(payload, ['deploymentId']);
      body.description = boundedMarked(typeof body.description === 'string' ? body.description : '', semantic, 140);
      return this.callObject('POST', `/repos/${repo}/deployments/${encodeURIComponent(id(payload.deploymentId,'deploymentId'))}/statuses`, `Bearer ${input.accessValue}`, body);
    }
    if (input.targetOperation === 'statuses.create') {
      const body = without(payload, ['sha']);
      body.context = boundedMarked(typeof body.context === 'string' ? body.context : '', semantic, 100);
      return this.callObject('POST', `/repos/${repo}/statuses/${encodeURIComponent(id(payload.sha,'sha'))}`, `Bearer ${input.accessValue}`, body);
    }
    if (input.targetOperation === 'checks.create') return this.callObject('POST', `/repos/${repo}/check-runs`, `Bearer ${input.accessValue}`, { ...payload, external_id:semantic });
    if (input.targetOperation === 'checks.update') return this.callObject('PATCH', `/repos/${repo}/check-runs/${encodeURIComponent(id(payload.checkRunId,'checkRunId'))}`, `Bearer ${input.accessValue}`, { ...without(payload, ['checkRunId']), external_id:semantic });
    if (input.targetOperation === 'issues.comments.create') {
      const body = without(payload, ['issueNumber']);
      body.body = `${typeof body.body === 'string' ? body.body : ''}\n<!-- ${semantic} -->`.slice(0, 65_536);
      return this.callObject('POST', `/repos/${repo}/issues/${encodeURIComponent(id(payload.issueNumber,'issueNumber'))}/comments`, `Bearer ${input.accessValue}`, body);
    }
    throw new GitHubTransportError('POLICY_CONFLICT', false, 'GitHub target operation is not allowed');
  }
  async lookupDelivery(input: { accessValue:string; semanticKey:string; repository:string; targetOperation:string; payload:JsonObject }): Promise<JsonObject | undefined> {
    const repo = repository(input.repository);
    const payload = object(input.payload, 'payload');
    const semantic = marker(input.semanticKey);
    if (input.targetOperation === 'deployments.status') {
      const values = await this.callArray(`/repos/${repo}/deployments/${encodeURIComponent(id(payload.deploymentId,'deploymentId'))}/statuses?per_page=100`, `Bearer ${input.accessValue}`);
      const found = values.find((value) => typeof value.description === 'string' && value.description.includes(`[${semantic}]`));
      return found === undefined ? undefined : responseIdentity(found);
    }
    if (input.targetOperation === 'statuses.create') {
      const values = await this.callArray(`/repos/${repo}/commits/${encodeURIComponent(id(payload.sha,'sha'))}/statuses?per_page=100`, `Bearer ${input.accessValue}`);
      const found = values.find((value) => typeof value.context === 'string' && value.context.includes(`[${semantic}]`));
      return found === undefined ? undefined : responseIdentity(found);
    }
    if (input.targetOperation === 'checks.create') {
      const values = object(await this.callValue('GET', `/repos/${repo}/commits/${encodeURIComponent(id(payload.head_sha,'head_sha'))}/check-runs?per_page=100`, `Bearer ${input.accessValue}`), 'check-runs response');
      const found = array(values.check_runs, 'check_runs').map((entry, index) => object(entry, `check_runs[${index}]`)).find((value) => value.external_id === semantic);
      return found === undefined ? undefined : responseIdentity(found);
    }
    if (input.targetOperation === 'checks.update') {
      const value = await this.callObject('GET', `/repos/${repo}/check-runs/${encodeURIComponent(id(payload.checkRunId,'checkRunId'))}`, `Bearer ${input.accessValue}`);
      return value.external_id === semantic ? responseIdentity(value) : undefined;
    }
    if (input.targetOperation === 'issues.comments.create') {
      const values = await this.callArray(`/repos/${repo}/issues/${encodeURIComponent(id(payload.issueNumber,'issueNumber'))}/comments?per_page=100`, `Bearer ${input.accessValue}`);
      const found = values.find((value) => typeof value.body === 'string' && value.body.includes(`<!-- ${semantic} -->`));
      return found === undefined ? undefined : responseIdentity(found);
    }
    throw new GitHubTransportError('POLICY_CONFLICT', false, 'GitHub target operation is not allowed');
  }
  async poll(input: { accessValue:string; repository:string; repositoryId:string; installationId:string; cursor?:string; allowedRefs?:string[] }): Promise<{ observations:JsonObject[]; cursor?:string }> {
    const repo = repository(input.repository);
    const refs = [...new Set(input.allowedRefs ?? [])].sort();
    const observations: JsonObject[] = [];
    for (const ref of refs) {
      if (!/^refs\/(heads|tags)\/[A-Za-z0-9._/-]+$/u.test(ref)) throw new GitHubTransportError('POLICY_CONFLICT', false, 'poll ref is invalid');
      const result = await this.callObject('GET', `/repos/${repo}/git/ref/${encodeURIComponent(ref.replace(/^refs\//u,''))}`, `Bearer ${input.accessValue}`);
      const objectValue = object(result.object, 'ref.object');
      const commit = id(objectValue.sha, 'ref.object.sha');
      observations.push({ repository:repo, repositoryId:input.repositoryId, installationId:input.installationId, eventName:'push', ref, commit });
    }
    const cursor = sha256(canonicalize(observations));
    return { observations, cursor:cursor === input.cursor ? input.cursor : cursor };
  }
}
