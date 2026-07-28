#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import process from 'node:process';
import { verifyRelease } from './lib/release-contract.mjs';

function parse(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith('--') || value === undefined) throw new Error('verify-release arguments must be --name value pairs');
    result[key.slice(2)] = value;
  }
  return result;
}

export function verifyReleaseCommand(argv) {
  const args = parse(argv);
  if (!args.release) throw new Error('--release is required');
  const expected = Object.fromEntries(
    ['repository', 'branch', 'commit', 'tree', 'parent', 'releaseIdentity']
      .filter((name) => args[name] !== undefined)
      .map((name) => [name, args[name]]),
  );
  return verifyRelease(args.release, expected, {
    releaseRoot: args['release-root'],
    requireImmutable: args['allow-mutable'] !== '1',
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    process.stdout.write(`${JSON.stringify(verifyReleaseCommand(process.argv.slice(2)))}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
