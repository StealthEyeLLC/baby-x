#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import process from 'node:process';

const [configurationPath, ...paths] = process.argv.slice(2);
if (!configurationPath) throw new Error('critical-path configuration is required');
const configuration = JSON.parse(readFileSync(configurationPath, 'utf8'));
if (configuration?.schemaVersion !== '1.0.0' || !Array.isArray(configuration.rules)) {
  throw new Error('critical-path configuration is malformed');
}
const matches = [];
for (const path of paths) {
  if (typeof path !== 'string' || path.length === 0 || path.startsWith('/') || path.includes('\0')) {
    throw new Error('changed repository path is invalid');
  }
  for (const rule of configuration.rules) {
    if (typeof rule?.id !== 'string' || !Array.isArray(rule.prefixes)) throw new Error('critical-path rule is malformed');
    for (const prefix of rule.prefixes) {
      if (path === prefix || path.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`)) {
        matches.push({ path, rule: rule.id, prefix });
      }
    }
  }
}
process.stdout.write(`${JSON.stringify({ critical: matches.length > 0, matches })}\n`);
if (matches.length > 0) process.exitCode = 42;
