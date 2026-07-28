#!/usr/bin/env -S node --experimental-strip-types
import { createCanonicalRuntime } from '../release-runtime.ts';
import { startRuntimeServer } from '../server.ts';

const command = process.argv[2] ?? 'serve';
const runtime = createCanonicalRuntime();

if (command === 'describe') {
  process.stdout.write(`${JSON.stringify(runtime.describe(), null, 2)}\n`);
} else if (command === 'health') {
  process.stdout.write(`${JSON.stringify(runtime.health(), null, 2)}\n`);
} else if (command === 'call') {
  const operation = process.argv[3];
  if (!operation) throw new Error('operation is required');
  const payload = process.argv[4] ? JSON.parse(process.argv[4]) as Record<string, unknown> : {};
  const result = await runtime.execute(operation, payload);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} else if (command === 'serve') {
  startRuntimeServer(runtime);
} else {
  throw new Error(`unknown command: ${command}`);
}
