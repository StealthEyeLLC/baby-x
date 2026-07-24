#!/usr/bin/env node
import { loadConfig } from './config.js';
import { createGatewayServer } from './server.js';
const config = loadConfig();
createGatewayServer({ config }).listen(config.port, config.host, () => process.stdout.write(`${JSON.stringify({ product: 'baby-x-gateway', host: config.host, port: config.port, tool: 'call_x' })}\n`));
