import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ConcreteGitHubAppTransport,
  GitHubTransportError,
  sha256,
} from '../../dist/runtime/index.js';

const NOW = '2026-07-27T04:30:00.000Z';
const TOKEN = 'installation-token-synthetic-value';
const ACCESS = 'access-token-synthetic-value';
const SEMANTIC_KEY = 'github-outbox-semantic-key';
const MARKER = `babyx-${sha256(SEMANTIC_KEY).slice(0, 32)}`;

function response(statusCode, value, headers = {}) {
  return { statusCode, headers, body:Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)) };
}

class QueueClient {
  requests = [];
  queue = [];
  enqueue(value) { this.queue.push(value); return this; }
  async request(input) {
    this.requests.push({
      ...input,
      headers:structuredClone(input.headers),
      body:input.body === undefined ? undefined : Buffer.from(input.body),
    });
    const next = this.queue.shift();
    if (next instanceof Error) throw next;
    if (typeof next === 'function') return next(input);
    if (next === undefined) throw new Error('unexpected request');
    return next;
  }
}

function transport(client, overrides = {}) {
  return new ConcreteGitHubAppTransport({ client, now:() => NOW, ...overrides });
}

function delivery(targetOperation, payload) {
  return { accessValue:ACCESS, semanticKey:SEMANTIC_KEY, repository:'StealthEyeLLC/baby-x', targetOperation, payload };
}

test('R5-T01 installation token exchange uses bounded HTTPS request and never reports token material', async () => {
  const client = new QueueClient().enqueue(response(201, { token:TOKEN, expires_at:'2026-07-27T05:30:00.000Z', permissions:{ deployments:'write' }, repository_selection:'selected' }));
  const instance = transport(client);
  const result = await instance.exchangeInstallation({ appId:'123', installationId:'456', assertion:'jwt-synthetic', permissions:{ deployments:'write' } });
  assert.equal(result.accessValue, TOKEN);
  assert.equal(result.expiresAt, '2026-07-27T05:30:00.000Z');
  assert.equal(client.requests[0].method, 'POST');
  assert.equal(client.requests[0].url, 'https://api.github.com/app/installations/456/access_tokens');
  assert.equal(client.requests[0].headers.Authorization, 'Bearer jwt-synthetic');
  assert.equal(client.requests[0].timeoutMs, 10_000);
  assert.equal(client.requests[0].maxResponseBytes, 1024 * 1024);
  assert.doesNotMatch(JSON.stringify(instance.describe()), new RegExp(TOKEN, 'u'));
  assert.doesNotMatch(JSON.stringify(instance), new RegExp(TOKEN, 'u'));
});

test('R5-T02 malformed or expired installation token responses fail closed', async (t) => {
  for (const [name, body] of [
    ['missing token', { expires_at:'2026-07-27T05:30:00.000Z' }],
    ['invalid expiry', { token:TOKEN, expires_at:'not-a-time' }],
    ['empty token', { token:'', expires_at:'2026-07-27T05:30:00.000Z' }],
  ]) await t.test(name, async () => {
    const instance = transport(new QueueClient().enqueue(response(201, body)));
    await assert.rejects(instance.exchangeInstallation({ appId:'123', installationId:'456', assertion:'jwt', permissions:{} }), (error) => error instanceof GitHubTransportError && error.failureClass === 'MALFORMED_RESPONSE');
  });
});

test('R5-T03 HTTP provider classes are exact and retryability is preserved', async (t) => {
  const cases = [
    [401, {}, 'AUTHENTICATION', false],
    [403, {}, 'AUTHORIZATION', false],
    [404, {}, 'PROVIDER_4XX', false],
    [409, {}, 'POLICY_CONFLICT', true],
    [422, {}, 'PROVIDER_4XX', false],
    [429, { 'retry-after':'7' }, 'RATE_LIMITED', true],
    [500, {}, 'PROVIDER_5XX', true],
    [503, {}, 'PROVIDER_5XX', true],
  ];
  for (const [status, headers, failureClass, retryable] of cases) await t.test(String(status), async () => {
    const instance = transport(new QueueClient().enqueue(response(status, { message:'provider diagnostic synthetic-secret' }, headers)));
    await assert.rejects(instance.exchangeInstallation({ appId:'123', installationId:'456', assertion:'jwt', permissions:{} }), (error) => {
      assert.equal(error.failureClass, failureClass);
      assert.equal(error.retryable, retryable);
      if (status === 429) assert.equal(error.details.retryAfterMs, 7000);
      assert.doesNotMatch(JSON.stringify(instance.describe()), /synthetic-secret/u);
      return true;
    });
  });
});

test('R5-T04 403 rate-limit headers classify RATE_LIMITED', async () => {
  const instance = transport(new QueueClient().enqueue(response(403, { message:'rate limited' }, { 'x-ratelimit-remaining':'0', 'retry-after':'3' })));
  await assert.rejects(instance.exchangeInstallation({ appId:'123', installationId:'456', assertion:'jwt', permissions:{} }), (error) => error.failureClass === 'RATE_LIMITED' && error.retryable === true && error.details.retryAfterMs === 3000);
});

test('R5-T05 timeout and network failures remain redacted', async (t) => {
  for (const failure of [
    new GitHubTransportError('TIMEOUT', true, 'timeout with token=synthetic-secret'),
    new GitHubTransportError('NETWORK', true, 'network with token=synthetic-secret'),
  ]) await t.test(failure.failureClass, async () => {
    const instance = transport(new QueueClient().enqueue(failure));
    await assert.rejects(instance.exchangeInstallation({ appId:'123', installationId:'456', assertion:'jwt', permissions:{} }), (error) => error.failureClass === failure.failureClass);
    assert.doesNotMatch(JSON.stringify(instance.describe()), /synthetic-secret/u);
  });
});

test('R5-T06 oversized and malformed responses fail closed', async (t) => {
  await t.test('oversized', async () => {
    const instance = transport(new QueueClient().enqueue({ statusCode:201, headers:{}, body:Buffer.alloc(1025, 65) }), { maxResponseBytes:1024 });
    await assert.rejects(instance.exchangeInstallation({ appId:'123', installationId:'456', assertion:'jwt', permissions:{} }), (error) => error.failureClass === 'MALFORMED_RESPONSE');
  });
  await t.test('malformed JSON', async () => {
    const instance = transport(new QueueClient().enqueue(response(201, '{bad-json')));
    await assert.rejects(instance.exchangeInstallation({ appId:'123', installationId:'456', assertion:'jwt', permissions:{} }), (error) => error.failureClass === 'MALFORMED_RESPONSE');
  });
});

test('R5-T07 non-HTTPS API configuration is rejected before requests', () => {
  assert.throws(() => new ConcreteGitHubAppTransport({ apiBaseUrl:'http://127.0.0.1:9999' }), (error) => error.failureClass === 'POLICY_CONFLICT');
});

test('R5-T08 deployment status delivery uses native bounded semantic description', async () => {
  const client = new QueueClient().enqueue(response(201, { id:1, node_id:'node-1', url:'https://api.github.test/status/1' }));
  await transport(client).deliver(delivery('deployments.status', { deploymentId:'77', state:'success', description:'release complete' }));
  const request = client.requests[0];
  assert.equal(request.url, 'https://api.github.com/repos/StealthEyeLLC/baby-x/deployments/77/statuses');
  const body = JSON.parse(request.body.toString('utf8'));
  assert.equal(body.deploymentId, undefined);
  assert.match(body.description, new RegExp(`\\[${MARKER}\\]`, 'u'));
  assert.ok(body.description.length <= 140);
});

test('R5-T09 commit status delivery uses native bounded context', async () => {
  const client = new QueueClient().enqueue(response(201, { id:2 }));
  await transport(client).deliver(delivery('statuses.create', { sha:'a'.repeat(40), state:'success', context:'Baby-X release' }));
  const body = JSON.parse(client.requests[0].body.toString('utf8'));
  assert.equal(body.sha, undefined);
  assert.match(body.context, new RegExp(`\\[${MARKER}\\]`, 'u'));
  assert.ok(body.context.length <= 100);
});

test('R5-T10 check create/update and comments use provider-supported semantic fields', async () => {
  const client = new QueueClient()
    .enqueue(response(201, { id:3 }))
    .enqueue(response(200, { id:4 }))
    .enqueue(response(201, { id:5 }));
  const instance = transport(client);
  await instance.deliver(delivery('checks.create', { name:'Baby-X', head_sha:'b'.repeat(40) }));
  await instance.deliver(delivery('checks.update', { checkRunId:'4', status:'completed' }));
  await instance.deliver(delivery('issues.comments.create', { issueNumber:'9', body:'release report' }));
  const createBody = JSON.parse(client.requests[0].body.toString('utf8'));
  const updateBody = JSON.parse(client.requests[1].body.toString('utf8'));
  const commentBody = JSON.parse(client.requests[2].body.toString('utf8'));
  assert.equal(createBody.external_id, MARKER);
  assert.equal(updateBody.external_id, MARKER);
  assert.equal(updateBody.checkRunId, undefined);
  assert.match(commentBody.body, new RegExp(`<!-- ${MARKER} -->`, 'u'));
  assert.equal(commentBody.issueNumber, undefined);
});

test('R5-T11 semantic lookup recovers deployment, status, check, and comment identities', async (t) => {
  const cases = [
    ['deployments.status', { deploymentId:'77' }, [{ id:1, description:`ok [${MARKER}]`, url:'u1' }]],
    ['statuses.create', { sha:'a'.repeat(40) }, [{ id:2, context:`ci [${MARKER}]`, url:'u2' }]],
    ['checks.create', { head_sha:'b'.repeat(40) }, { check_runs:[{ id:3, external_id:MARKER, url:'u3' }] }],
    ['checks.update', { checkRunId:'4' }, { id:4, external_id:MARKER, url:'u4' }],
    ['issues.comments.create', { issueNumber:'9' }, [{ id:5, body:`report\n<!-- ${MARKER} -->`, url:'u5' }]],
  ];
  for (const [operation, payload, providerBody] of cases) await t.test(operation, async () => {
    const result = await transport(new QueueClient().enqueue(response(200, providerBody))).lookupDelivery(delivery(operation, payload));
    assert.notEqual(result, undefined);
    assert.ok(result.id !== null);
  });
});

test('R5-T12 semantic lookup returns undefined only after successful exact readback', async () => {
  const result = await transport(new QueueClient().enqueue(response(200, []))).lookupDelivery(delivery('deployments.status', { deploymentId:'77' }));
  assert.equal(result, undefined);
});

test('R5-T13 polling is restricted to declared refs and produces a stable cursor', async () => {
  const commit = 'c'.repeat(40);
  const client = new QueueClient().enqueue(response(200, { object:{ sha:commit } }));
  const instance = transport(client);
  const first = await instance.poll({ accessValue:ACCESS, repository:'StealthEyeLLC/baby-x', repositoryId:'repo-1', installationId:'456', allowedRefs:['refs/heads/main'] });
  assert.equal(first.observations.length, 1);
  assert.equal(first.observations[0].commit, commit);
  assert.equal(first.observations[0].ref, 'refs/heads/main');
  const secondClient = new QueueClient().enqueue(response(200, { object:{ sha:commit } }));
  const second = await transport(secondClient).poll({ accessValue:ACCESS, repository:'StealthEyeLLC/baby-x', repositoryId:'repo-1', installationId:'456', allowedRefs:['refs/heads/main'], cursor:first.cursor });
  assert.equal(second.cursor, first.cursor);
});

test('R5-T14 invalid repositories, refs, and target operations fail before external effects', async (t) => {
  const client = new QueueClient();
  const instance = transport(client);
  await assert.rejects(instance.deliver({ ...delivery('deployments.status', { deploymentId:'1' }), repository:'invalid' }), (error) => error.failureClass === 'POLICY_CONFLICT');
  await assert.rejects(instance.poll({ accessValue:ACCESS, repository:'StealthEyeLLC/baby-x', repositoryId:'r', installationId:'i', allowedRefs:['main'] }), (error) => error.failureClass === 'POLICY_CONFLICT');
  await assert.rejects(instance.deliver(delivery('admin.delete', {})), (error) => error.failureClass === 'POLICY_CONFLICT');
  assert.equal(client.requests.length, 0);
});
