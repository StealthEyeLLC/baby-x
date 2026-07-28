import { createServer } from 'node:http';
import { BabyXClient } from './client.js';
import { loadConfig } from './config.js';
import { dynamicCatalog } from './catalog.js';
import { CALL_X_TOOL, callX } from './tool.js';
import { OAuthStateStore } from './oauth-state-durable.js';
import { oauthMetadata, protectedResource, registerClient, exchangeCode } from './oauth-server.js';

export async function readJsonBody(request, maximumBytes = 1_048_576) {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) throw new Error('maximum body size must be a positive safe integer');
  const declared = request.headers?.['content-length'];
  if (declared !== undefined) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0) throw Object.assign(new Error('invalid content-length'), { statusCode: 400 });
    if (length > maximumBytes) throw Object.assign(new Error('request body too large'), { statusCode: 413 });
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (bytes.length > maximumBytes - total) {
      request.resume?.();
      throw Object.assign(new Error('request body too large'), { statusCode: 413 });
    }
    total += bytes.length;
    chunks.push(bytes);
  }
  if (total === 0) return {};
  try { return JSON.parse(Buffer.concat(chunks, total).toString('utf8')); }
  catch { throw Object.assign(new Error('invalid JSON body'), { statusCode: 400 }); }
}

function json(response, status, value, headers = {}) {
  const encoded = Buffer.from(JSON.stringify(value));
  response.writeHead(status, { 'content-type': 'application/json', 'content-length': encoded.length, ...headers });
  response.end(encoded);
}

export function createGatewayServer(options = {}) {
  const config = options.config ?? loadConfig();
  const client = options.client ?? new BabyXClient(config);
  const oauth = options.oauthStore ?? new OAuthStateStore(config.statePath);
  return createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? '/', config.issuer);
      if (request.method === 'GET' && url.pathname === '/healthz') {
        const catalog = await dynamicCatalog(client);
        json(response, 200, {
          ok: true,
          product: 'baby-x-gateway',
          publicTool: 'call_x',
          runtime: {
            product: catalog.product,
            protocol: catalog.protocol,
            repository: catalog.repository ?? null,
            sourceCommit: catalog.sourceCommit ?? null,
            sourceTree: catalog.sourceTree ?? null,
            release: catalog.release ?? null,
            operationCatalogVersion: catalog.operationCatalogVersion ?? null,
            operationCatalogSha256: catalog.operationCatalogSha256 ?? null,
            operationCount: catalog.operations.length,
            catalog: catalog.catalog ?? null,
          },
        });
        return;
      }
      if (request.method === 'GET' && (url.pathname === '/.well-known/oauth-protected-resource' || url.pathname === '/.well-known/oauth-protected-resource/mcp')) { json(response, 200, protectedResource(config)); return; }
      if (request.method === 'GET' && url.pathname === '/.well-known/oauth-authorization-server') { json(response, 200, oauthMetadata(config)); return; }
      if (request.method === 'POST' && url.pathname === '/oauth/register') { json(response, 201, registerClient(oauth, await readJsonBody(request, config.maxHttpBodyBytes))); return; }
      if (request.method === 'POST' && url.pathname === '/oauth/token') { json(response, 200, exchangeCode(oauth, await readJsonBody(request, config.maxHttpBodyBytes))); return; }
      if (request.method === 'POST' && url.pathname === '/mcp') {
        const message = await readJsonBody(request, config.maxHttpBodyBytes);
        let result;
        if (message.method === 'initialize') result = { protocolVersion: '2025-06-18', serverInfo: { name: 'baby-x-gateway', version: '0.1.0' }, capabilities: { tools: {} } };
        else if (message.method === 'tools/list') result = { tools: [CALL_X_TOOL] };
        else if (message.method === 'tools/call' && message.params?.name === 'call_x') result = await callX(client, message.params.arguments);
        else throw new Error('unsupported MCP method or tool');
        json(response, 200, { jsonrpc: '2.0', id: message.id ?? null, result });
        return;
      }
      json(response, 404, { error: 'not found' });
    } catch (error) {
      const status = error && typeof error === 'object' && Number.isInteger(error.statusCode) ? error.statusCode : 500;
      if (!response.headersSent) json(response, status, { error: error instanceof Error ? error.message : String(error) });
      else response.destroy();
    }
  });
}
