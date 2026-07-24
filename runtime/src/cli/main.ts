#!/usr/bin/env -S node --experimental-strip-types
import { BabyXRuntime } from '../core.ts';
import { startRuntimeServer } from '../server.ts';

const command = process.argv[2] ?? 'serve';
if (command === 'describe') {
  process.stdout.write(`${JSON.stringify(new BabyXRuntime().describe(), null, 2)}\n`);
} else if (command === 'health') {
  process.stdout.write(`${JSON.stringify(new BabyXRuntime().health(), null, 2)}\n`);
} else if (command === 'call') {
  const operation = process.argv[3];
  if (!operation) throw new Error('operation is required');
  const payload = process.argv[4] ? JSON.parse(process.argv[4]) as Record<string, unknown> : {};
  const result = await new BabyXRuntime().execute(operation, payload);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} else if (command === 'serve') {
  startRuntimeServer();
} else {
  throw new Error(`unknown command: ${command}`);
}
