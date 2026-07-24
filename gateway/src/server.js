import { createServer } from 'node:http';
import { BabyXClient } from './client.js';
import { loadConfig } from './config.js';
import { dynamicCatalog } from './catalog.js';
import { CALL_X_TOOL, callX } from './tool.js';
import { OAuthStateStore } from './oauth-state-durable.js';
import { oauthMetadata, protectedResource, registerClient, exchangeCode } from './oauth-server.js';

async function body(request) { const chunks = []; for await (const chunk of request) chunks.push(chunk); if (chunks.length === 0) return {}; return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
function json(response, status, value, headers = {}) { const encoded = Buffer.from(JSON.stringify(value)); response.writeHead(status, { 'content-type': 'application/json', 'content-length': encoded.length, ...headers }); response.end(encoded); }

export function createGatewayServer(options = {}) {
  const config = options.config ?? loadConfig(); const client = options.client ?? new BabyXClient(config); const oauth = options.oauthStore ?? new OAuthStateStore(config.statePath);
  return createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? '/', config.issuer);
      if (request.method === 'GET' && url.pathname === '/healthz') { const catalog = await dynamicCatalog(client); json(response, 200, { ok: true, product: 'baby-x-gateway', publicTool: 'call_x', runtime: { product: catalog.product, protocol: catalog.protocol, operationCount: catalog.operations.length } }); return; }
      if (request.method === 'GET' && (url.pathname === '/.well-known/oauth-protected-resource' || url.pathname === '/.well-known/oauth-protected-resource/mcp')) { json(response, 200, protectedResource(config)); return; }
      if (request.method === 'GET' && url.pathname === '/.well-known/oauth-authorization-server') { json(response, 200, oauthMetadata(config)); return; }
      if (request.method === 'POST' && url.pathname === '/oauth/register') { json(response, 201, registerClient(oauth, await body(request))); return; }
      if (request.method === 'POST' && url.pathname === '/oauth/token') { json(response, 200, exchangeCode(oauth, await body(request))); return; }
      if (request.method === 'POST' && url.pathname === '/mcp') {
        const message = await body(request); let result;
        if (message.method === 'initialize') result = { protocolVersion: '2025-06-18', serverInfo: { name: 'baby-x-gateway', version: '0.1.0' }, capabilities: { tools: {} } };
        else if (message.method === 'tools/list') result = { tools: [CALL_X_TOOL] };
        else if (message.method === 'tools/call' && message.params?.name === 'call_x') result = await callX(client, message.params.arguments);
        else throw new Error('unsupported MCP method or tool');
        json(response, 200, { jsonrpc: '2.0', id: message.id ?? null, result }); return;
      }
      json(response, 404, { error: 'not found' });
    } catch (error) { json(response, 500, { error: error instanceof Error ? error.message : String(error) }); }
  });
}
