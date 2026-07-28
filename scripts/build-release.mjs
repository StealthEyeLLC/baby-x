#!/usr/bin/env node
import { mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import process from 'node:process';
import { RELEASE_NODE_VERSION, RELEASE_NPM_VERSION, stageRelease } from './lib/release-contract.mjs';

function argumentsFrom(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (!key?.startsWith('--')) throw new Error(`unexpected argument: ${key ?? ''}`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) throw new Error(`${key} requires a value`);
    values[key.slice(2)] = value;
    index += 1;
  }
  return values;
}

function git(sourceRoot, argv) {
  const result = spawnSync('/usr/bin/git', ['-C', sourceRoot, ...argv], { encoding: 'utf8', timeout: 30_000 });
  if (result.status !== 0) throw new Error(`git ${argv.join(' ')} failed: ${result.stderr.trim()}`);
  return result.stdout.trim();
}

function exactTool(path, expected) {
  const result = spawnSync(path, ['--version'], { encoding: 'utf8', timeout: 10_000 });
  if (result.status !== 0) throw new Error(`${path} --version failed`);
  const observed = result.stdout.trim();
  if (observed !== expected) throw new Error(`${path} version mismatch: expected ${expected}, observed ${observed}`);
  return observed;
}

async function catalogFacts(sourceRoot) {
  const temporary = mkdtempSync(join(tmpdir(), 'baby-x-k-catalog-'));
  try {
    const definitions = await import(pathToFileURL(join(sourceRoot, 'dist', 'runtime', 'operations', 'definitions.js')).href);
    const service = await import(pathToFileURL(join(sourceRoot, 'dist', 'runtime', 'root-fabric', 'service.js')).href);
    const core = await import(pathToFileURL(join(sourceRoot, 'dist', 'runtime', 'core.js')).href);
    const operations = definitions.OPERATION_DEFINITIONS;
    const names = operations.map((entry) => entry.operation);
    const runtime = new core.BabyXRuntime({ stateRoot: temporary, sourceCommit: '0'.repeat(40), sourceTree: '0'.repeat(40) });
    const registry = await runtime.execute('babyx.root.effect.registry', {}, { subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner' });
    return {
      catalogVersion: definitions.OPERATION_CATALOG_VERSION,
      catalogSha256: core.sha256(core.canonicalize(operations)),
      totalOperations: operations.length,
      rootOperations: names.filter((name) => name.startsWith('babyx.root.')).length,
      rootFabricDispatcherOperations: service.ROOT_FABRIC_OPERATION_NAMES.length,
      typedEffects: registry.effects.length,
      duplicateOperations: names.length - new Set(names).size,
    };
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

export async function buildReleaseFromRepository(options) {
  const sourceRoot = realpathSync(options.sourceRoot);
  const head = git(sourceRoot, ['rev-parse', 'HEAD']);
  const tree = git(sourceRoot, ['rev-parse', 'HEAD^{tree}']);
  const parent = git(sourceRoot, ['rev-parse', 'HEAD^']);
  const branch = git(sourceRoot, ['branch', '--show-current']);
  if (head !== options.commit || tree !== options.tree || parent !== options.parent || branch !== options.branch) {
    throw new Error('local repository identity does not match the approved release subject');
  }
  if (git(sourceRoot, ['status', '--porcelain']) !== '') throw new Error('release source worktree is not clean');
  const remote = git(sourceRoot, ['remote', 'get-url', 'origin']);
  if (remote !== 'https://github.com/StealthEyeLLC/baby-x.git' || /@|token|github_pat_|ghs_/iu.test(remote)) {
    throw new Error('release source remote is not the canonical credential-free URL');
  }
  const builtAt = git(sourceRoot, ['show', '-s', '--format=%cI', options.commit]);
  exactTool('/opt/node-v24.18.0-linux-x64/bin/node', RELEASE_NODE_VERSION);
  exactTool('/opt/node-v24.18.0-linux-x64/bin/npm', RELEASE_NPM_VERSION);
  const report = JSON.parse(readFileSync(join(sourceRoot, 'dist', 'build-report.json'), 'utf8'));
  if (report.node !== RELEASE_NODE_VERSION) throw new Error('build report Node.js identity mismatch');
  if (report.peerCredentialAddon !== 'built') throw new Error('required peer-credential native release output was not built');
  if (!['built', 'not-built'].includes(report.seccompSupervisor)) throw new Error('seccomp supervisor build report is invalid');
  return stageRelease({
    sourceRoot,
    releaseRoot: options.releaseRoot,
    repository: options.repository,
    branch: options.branch,
    commit: options.commit,
    tree: options.tree,
    parent: options.parent,
    builtAt,
    nodeVersion: RELEASE_NODE_VERSION,
    npmVersion: RELEASE_NPM_VERSION,
    catalog: await catalogFacts(sourceRoot),
  });
}

async function main() {
  const args = argumentsFrom(process.argv.slice(2));
  for (const name of ['source', 'release-root', 'repository', 'branch', 'commit', 'tree', 'parent']) {
    if (!args[name]) throw new Error(`--${name} is required`);
  }
  const result = await buildReleaseFromRepository({
    sourceRoot: args.source,
    releaseRoot: args['release-root'],
    repository: args.repository,
    branch: args.branch,
    commit: args.commit,
    tree: args.tree,
    parent: args.parent,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
