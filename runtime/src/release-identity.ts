import { createHash } from 'node:crypto';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { JsonObject, RuntimeOptions } from './core.ts';

export interface VerifiedReleaseIdentity extends JsonObject {
  schemaVersion: '1.0.0';
  repository: 'StealthEyeLLC/baby-x';
  branch: string;
  commit: string;
  tree: string;
  parent: string;
  releaseIdentity: string;
  catalogVersion: '3.4.0';
  catalogSha256: '87cdc4ab4ab24b193352dab07f9bf92a755bc4e7f2b1f4d8ec88936f47a5f900';
  totalOperations: 230;
  rootOperations: 51;
  rootFabricDispatcherOperations: 40;
  typedEffects: 31;
  duplicateOperations: 0;
  releaseManifestPath: string;
  releaseManifestSha256: string;
}

function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

function exactSha(value: unknown, name: string): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{40}$/u.test(value)) throw new Error(`release ${name} is invalid`);
  return value;
}

function exactInteger(value: unknown, expected: number, name: string): number {
  if (value !== expected) throw new Error(`release ${name} mismatch`);
  return expected;
}

function defaultManifestPath(): string {
  return fileURLToPath(new URL('../release.json', import.meta.url));
}

export function loadVerifiedReleaseIdentity(options: { required?: boolean; manifestPath?: string } = {}): VerifiedReleaseIdentity | null {
  const required = options.required ?? process.env.BABY_X_REQUIRE_RELEASE_IDENTITY === '1';
  const configured = options.manifestPath ?? process.env.BABY_X_RELEASE_MANIFEST ?? defaultManifestPath();
  if (!existsSync(configured)) {
    if (required) throw new Error('canonical release manifest is required');
    return null;
  }
  const path = realpathSync(configured);
  let value: JsonObject;
  try {
    value = JSON.parse(readFileSync(path, 'utf8')) as JsonObject;
  } catch (error) {
    throw new Error(`canonical release manifest is malformed: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('canonical release manifest must be an object');
  if (value.schemaVersion !== '1.0.0' || value.repository !== 'StealthEyeLLC/baby-x') throw new Error('canonical release manifest identity mismatch');
  const commit = exactSha(value.commit, 'commit');
  const tree = exactSha(value.tree, 'tree');
  const parent = exactSha(value.parent, 'parent');
  const releaseIdentity = `${commit}-${tree}`;
  if (value.releaseIdentity !== releaseIdentity) throw new Error('canonical release identity mismatch');
  if (typeof value.branch !== 'string' || value.branch.length === 0) throw new Error('canonical release branch is invalid');
  if (value.catalogVersion !== '3.4.0') throw new Error('canonical release catalog version mismatch');
  if (value.catalogSha256 !== '87cdc4ab4ab24b193352dab07f9bf92a755bc4e7f2b1f4d8ec88936f47a5f900') {
    throw new Error('canonical release catalog digest mismatch');
  }
  exactInteger(value.totalOperations, 230, 'operation count');
  exactInteger(value.rootOperations, 51, 'root operation count');
  exactInteger(value.rootFabricDispatcherOperations, 40, 'root fabric operation count');
  exactInteger(value.typedEffects, 31, 'typed effect count');
  exactInteger(value.duplicateOperations, 0, 'duplicate operation count');
  const sidecar = join(dirname(path), 'release.sha256');
  if (!existsSync(sidecar)) throw new Error('canonical release manifest digest sidecar is absent');
  const expectedDigest = readFileSync(sidecar, 'utf8').trim();
  if (!/^[a-f0-9]{64}$/u.test(expectedDigest) || expectedDigest !== sha256(readFileSync(path))) {
    throw new Error('canonical release manifest digest mismatch');
  }
  return {
    ...value,
    schemaVersion: '1.0.0',
    repository: 'StealthEyeLLC/baby-x',
    branch: value.branch,
    commit,
    tree,
    parent,
    releaseIdentity,
    catalogVersion: '3.4.0',
    catalogSha256: '87cdc4ab4ab24b193352dab07f9bf92a755bc4e7f2b1f4d8ec88936f47a5f900',
    totalOperations: 230,
    rootOperations: 51,
    rootFabricDispatcherOperations: 40,
    typedEffects: 31,
    duplicateOperations: 0,
    releaseManifestPath: path,
    releaseManifestSha256: expectedDigest,
  } as VerifiedReleaseIdentity;
}

export function releaseBoundRuntimeOptions(options: RuntimeOptions = {}): RuntimeOptions {
  const identity = loadVerifiedReleaseIdentity();
  if (identity === null) return options;
  if (process.env.BABY_X_SOURCE_COMMIT !== undefined || process.env.BABY_X_SOURCE_TREE !== undefined) {
    throw new Error('runtime release identity must not be supplied by the startup environment');
  }
  if (options.sourceCommit !== undefined && options.sourceCommit !== identity.commit) throw new Error('runtime source commit conflicts with the immutable release');
  if (options.sourceTree !== undefined && options.sourceTree !== identity.tree) throw new Error('runtime source tree conflicts with the immutable release');
  return { ...options, sourceCommit: identity.commit, sourceTree: identity.tree };
}
