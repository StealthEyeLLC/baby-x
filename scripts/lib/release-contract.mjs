import {
  chmodSync,
  closeSync,
  copyFileSync,
  cpSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';

export const RELEASE_SCHEMA_VERSION = '1.0.0';
export const RELEASE_REPOSITORY = 'StealthEyeLLC/baby-x';
export const RELEASE_NODE_VERSION = 'v24.18.0';
export const RELEASE_NPM_VERSION = '11.16.0';
export const CANONICAL_UNITS = Object.freeze([
  'baby-x-root.slice',
  'baby-x-root-broker.socket',
  'baby-x-root-broker.service',
  'baby-x.socket',
  'baby-x.service',
  'baby-x-gateway.service',
]);
export const RELEASE_META_FILES = new Set([
  'build-manifest.json',
  'runtime-manifest.json',
  'release.json',
  'release.sha256',
]);

export function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function digestFile(path) {
  return sha256(readFileSync(path));
}

export function assertSha(value, name) {
  if (typeof value !== 'string' || !/^[a-f0-9]{40}$/u.test(value)) {
    throw new Error(`${name} must be an exact 40-character Git SHA`);
  }
  return value;
}

export function assertDigest(value, name) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/u.test(value)) {
    throw new Error(`${name} must be an exact SHA-256 digest`);
  }
  return value;
}

export function assertIdentifier(value, name = 'identifier') {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

export function releaseIdentity(commit, tree) {
  return `${assertSha(commit, 'commit')}-${assertSha(tree, 'tree')}`;
}

export function pathInside(root, candidate, name = 'path') {
  const absoluteRoot = resolve(root);
  const absolute = resolve(candidate);
  if (absolute !== absoluteRoot && !absolute.startsWith(`${absoluteRoot}${sep}`)) {
    throw new Error(`${name} escapes its confinement root`);
  }
  return absolute;
}

export function atomicWrite(path, bytes, mode = 0o600) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const descriptor = openSync(temporary, 'wx', mode);
  try {
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  renameSync(temporary, path);
  fsyncDirectory(dirname(path));
}

export function atomicWriteJson(path, value, mode = 0o600) {
  atomicWrite(path, `${canonicalize(value)}\n`, mode);
}

export function fsyncDirectory(path) {
  const descriptor = openSync(path, 'r');
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function sortedEntries(path) {
  return readdirSync(path, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
}

export function walkRelease(root, options = {}) {
  const files = [];
  const directories = [];
  const visit = (directory) => {
    directories.push(directory);
    for (const entry of sortedEntries(directory)) {
      const path = join(directory, entry.name);
      const metadata = lstatSync(path);
      if (metadata.isSymbolicLink()) throw new Error(`release payload contains a symlink: ${relative(root, path)}`);
      if (metadata.isDirectory()) {
        visit(path);
      } else if (metadata.isFile()) {
        const name = relative(root, path).split(sep).join('/');
        if (!options.exclude?.has(name)) files.push({ path, name, metadata });
      } else {
        throw new Error(`release payload contains a non-regular path: ${relative(root, path)}`);
      }
    }
  };
  visit(root);
  return { files, directories };
}

export function createFileManifest(root, exclude = RELEASE_META_FILES) {
  const { files } = walkRelease(root, { exclude });
  return {
    schemaVersion: '1.0.0',
    files: files.map(({ path, name, metadata }) => ({
      path: name,
      sha256: digestFile(path),
      size: metadata.size,
      mode: metadata.mode & 0o777,
    })),
  };
}

export function fsyncTree(root) {
  const { files, directories } = walkRelease(root);
  for (const { path } of files) {
    const descriptor = openSync(path, 'r');
    try {
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
  }
  for (const directory of [...directories].reverse()) fsyncDirectory(directory);
}

export function makeImmutable(root) {
  const { files, directories } = walkRelease(root);
  for (const { path, metadata } of files) {
    chmodSync(path, metadata.mode & 0o111 ? 0o555 : 0o444);
  }
  for (const directory of [...directories].reverse()) chmodSync(directory, 0o555);
}

function parseJson(path, name) {
  let value;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`${name} is malformed: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value;
}

function assertReleaseManifest(manifest) {
  if (manifest.schemaVersion !== RELEASE_SCHEMA_VERSION) throw new Error('release manifest schema version mismatch');
  if (manifest.repository !== RELEASE_REPOSITORY) throw new Error('release repository mismatch');
  assertSha(manifest.commit, 'release commit');
  assertSha(manifest.tree, 'release tree');
  assertSha(manifest.parent, 'release parent');
  if (manifest.releaseIdentity !== releaseIdentity(manifest.commit, manifest.tree)) throw new Error('release identity mismatch');
  if (manifest.nodeVersion !== RELEASE_NODE_VERSION) throw new Error('release Node.js version mismatch');
  if (manifest.npmVersion !== RELEASE_NPM_VERSION) throw new Error('release npm version mismatch');
  for (const field of [
    'packageJsonSha256',
    'packageLockSha256',
    'buildManifestSha256',
    'runtimeManifestSha256',
    'serviceInventorySha256',
    'catalogSha256',
  ]) assertDigest(manifest[field], `release ${field}`);
  if (manifest.catalogSha256 !== '87cdc4ab4ab24b193352dab07f9bf92a755bc4e7f2b1f4d8ec88936f47a5f900') {
    throw new Error('release operation catalog digest mismatch');
  }
  for (const [field, expected] of [
    ['catalogVersion', '3.4.0'],
    ['totalOperations', 230],
    ['rootOperations', 51],
    ['rootFabricDispatcherOperations', 40],
    ['typedEffects', 31],
    ['duplicateOperations', 0],
  ]) {
    if (manifest[field] !== expected) throw new Error(`release ${field} mismatch`);
  }
  if (!Number.isFinite(Date.parse(manifest.builtAt))) throw new Error('release builtAt is invalid');
}

function compareExpected(manifest, expected) {
  for (const key of ['repository', 'branch', 'commit', 'tree', 'parent', 'releaseIdentity']) {
    if (expected[key] !== undefined && manifest[key] !== expected[key]) throw new Error(`release ${key} does not match the approved identity`);
  }
}

function verifyManifestFiles(root, manifestValue) {
  if (manifestValue.schemaVersion !== '1.0.0' || !Array.isArray(manifestValue.files)) throw new Error('build manifest shape is invalid');
  const expectedPaths = [];
  let prior = '';
  for (const item of manifestValue.files) {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) throw new Error('build manifest file entry is invalid');
    if (typeof item.path !== 'string' || item.path.length === 0 || isAbsolute(item.path) || item.path.includes('\0')) throw new Error('build manifest path is invalid');
    if (item.path <= prior) throw new Error('build manifest paths are not strictly sorted');
    prior = item.path;
    assertDigest(item.sha256, `build manifest digest for ${item.path}`);
    if (!Number.isSafeInteger(item.size) || item.size < 0) throw new Error(`build manifest size for ${item.path} is invalid`);
    if (!Number.isSafeInteger(item.mode) || item.mode < 0 || item.mode > 0o777) throw new Error(`build manifest mode for ${item.path} is invalid`);
    const path = pathInside(root, join(root, item.path), 'build manifest path');
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error(`release file is not regular: ${item.path}`);
    if (metadata.size !== item.size || digestFile(path) !== item.sha256) throw new Error(`release file digest or size mismatch: ${item.path}`);
    expectedPaths.push(item.path);
  }
  const actualPaths = walkRelease(root, { exclude: RELEASE_META_FILES }).files.map(({ name }) => name);
  if (canonicalize(actualPaths) !== canonicalize(expectedPaths)) throw new Error('release payload contains missing or unmanifested files');
}

function verifyRuntimeManifest(root, runtimeManifest) {
  if (runtimeManifest.schemaVersion !== '1.0.0' || runtimeManifest.releaseIdentity === undefined || runtimeManifest.entrypoints === null || typeof runtimeManifest.entrypoints !== 'object') {
    throw new Error('runtime manifest shape is invalid');
  }
  const required = ['runtime', 'gateway', 'rootBroker', 'health', 'releaseVerifier'];
  for (const name of required) {
    const entry = runtimeManifest.entrypoints[name];
    if (entry === null || typeof entry !== 'object' || typeof entry.path !== 'string') throw new Error(`runtime manifest entrypoint ${name} is invalid`);
    assertDigest(entry.sha256, `runtime manifest entrypoint ${name}`);
    const path = pathInside(root, join(root, entry.path), 'runtime entrypoint');
    if (!lstatSync(path).isFile() || digestFile(path) !== entry.sha256) throw new Error(`runtime entrypoint ${name} digest mismatch`);
  }
  if (runtimeManifest.units === null || typeof runtimeManifest.units !== 'object') throw new Error('runtime manifest units are invalid');
  for (const unit of CANONICAL_UNITS) {
    const digest = runtimeManifest.units[unit];
    assertDigest(digest, `runtime unit ${unit}`);
    if (digestFile(join(root, 'ops', 'systemd', unit)) !== digest) throw new Error(`runtime unit ${unit} digest mismatch`);
  }
}

export function verifyRelease(releasePath, expected = {}, options = {}) {
  const root = realpathSync(releasePath);
  if (options.releaseRoot !== undefined) pathInside(realpathSync(options.releaseRoot), root, 'release path');
  const metadata = lstatSync(root);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error('release path must be a real directory');
  const manifestPath = join(root, 'release.json');
  const manifest = parseJson(manifestPath, 'release manifest');
  assertReleaseManifest(manifest);
  compareExpected(manifest, expected);
  const sidecar = readFileSync(join(root, 'release.sha256'), 'utf8').trim();
  assertDigest(sidecar, 'release manifest sidecar');
  if (sidecar !== digestFile(manifestPath)) throw new Error('release manifest digest mismatch');
  if (digestFile(join(root, 'package.json')) !== manifest.packageJsonSha256) throw new Error('release package.json digest mismatch');
  if (digestFile(join(root, 'package-lock.json')) !== manifest.packageLockSha256) throw new Error('release package-lock.json digest mismatch');
  if (digestFile(join(root, 'build-manifest.json')) !== manifest.buildManifestSha256) throw new Error('release build manifest digest mismatch');
  if (digestFile(join(root, 'runtime-manifest.json')) !== manifest.runtimeManifestSha256) throw new Error('release runtime manifest digest mismatch');
  if (digestFile(join(root, 'ops', 'service-inventory.json')) !== manifest.serviceInventorySha256) throw new Error('release service inventory digest mismatch');
  const buildManifest = parseJson(join(root, 'build-manifest.json'), 'build manifest');
  verifyManifestFiles(root, buildManifest);
  const runtimeManifest = parseJson(join(root, 'runtime-manifest.json'), 'runtime manifest');
  if (runtimeManifest.releaseIdentity !== manifest.releaseIdentity) throw new Error('runtime and release identities differ');
  verifyRuntimeManifest(root, runtimeManifest);
  if (options.requireImmutable !== false) {
    const { files, directories } = walkRelease(root);
    for (const { path, metadata: fileMetadata } of files) {
      if ((fileMetadata.mode & 0o222) !== 0) throw new Error(`release file is mutable: ${relative(root, path)}`);
    }
    for (const directory of directories) {
      if ((lstatSync(directory).mode & 0o222) !== 0) throw new Error(`release directory is mutable: ${relative(root, directory) || '.'}`);
    }
  }
  return { releasePath: root, releaseManifestSha256: sidecar, manifest };
}

function copyPayload(sourceRoot, staging) {
  for (const name of ['package.json', 'package-lock.json']) copyFileSync(join(sourceRoot, name), join(staging, name));
  for (const name of ['runtime', 'gateway']) {
    const source = join(sourceRoot, 'dist', name);
    if (!existsSync(source)) throw new Error(`compiled ${name} output is missing`);
    cpSync(source, join(staging, name), { recursive: true, dereference: true, errorOnExist: true });
  }
  if (existsSync(join(sourceRoot, 'dist', 'build'))) cpSync(join(sourceRoot, 'dist', 'build'), join(staging, 'build'), { recursive: true, dereference: true, errorOnExist: true });
  cpSync(join(sourceRoot, 'ops'), join(staging, 'ops'), { recursive: true, dereference: true, errorOnExist: true });
  mkdirSync(join(staging, 'scripts', 'lib'), { recursive: true, mode: 0o755 });
  for (const name of [
    'verify-local.sh',
    'verify-local.mjs',
    'rollback-local.sh',
    'activate-release.mjs',
    'verify-release.mjs',
    'root-broker-smoke.mjs',
    'provision-local-keys.sh',
  ]) {
    copyFileSync(join(sourceRoot, 'scripts', name), join(staging, 'scripts', name));
  }
  copyFileSync(join(sourceRoot, 'scripts', 'lib', 'release-contract.mjs'), join(staging, 'scripts', 'lib', 'release-contract.mjs'));
}

function runtimeManifest(staging, identity) {
  const entries = {
    runtime: 'runtime/cli/main.js',
    gateway: 'gateway/main.js',
    rootBroker: 'runtime/root-broker-entry.js',
    health: 'scripts/verify-local.sh',
    releaseVerifier: 'scripts/verify-release.mjs',
  };
  return {
    schemaVersion: '1.0.0',
    releaseIdentity: identity,
    entrypoints: Object.fromEntries(Object.entries(entries).map(([name, path]) => [name, { path, sha256: digestFile(join(staging, path)) }])),
    units: Object.fromEntries(CANONICAL_UNITS.map((unit) => [unit, digestFile(join(staging, 'ops', 'systemd', unit))])),
  };
}

export function stageRelease(options) {
  const sourceRoot = realpathSync(options.sourceRoot);
  const releaseRoot = resolve(options.releaseRoot);
  const commit = assertSha(options.commit, 'candidate commit');
  const tree = assertSha(options.tree, 'candidate tree');
  const parent = assertSha(options.parent, 'candidate parent');
  const identity = releaseIdentity(commit, tree);
  if (options.repository !== RELEASE_REPOSITORY) throw new Error('only the canonical Baby-X repository may be staged');
  if (typeof options.branch !== 'string' || options.branch.length === 0) throw new Error('candidate branch is required');
  if (options.nodeVersion !== RELEASE_NODE_VERSION || options.npmVersion !== RELEASE_NPM_VERSION) throw new Error('candidate toolchain identity mismatch');
  if (!Number.isFinite(Date.parse(options.builtAt))) throw new Error('candidate builtAt must be an ISO timestamp');
  for (const [field, expected] of [
    ['catalogVersion', '3.4.0'],
    ['totalOperations', 230],
    ['rootOperations', 51],
    ['rootFabricDispatcherOperations', 40],
    ['typedEffects', 31],
    ['duplicateOperations', 0],
  ]) {
    if (options.catalog?.[field] !== expected) throw new Error(`candidate catalog ${field} mismatch`);
  }
  if (options.catalog?.catalogSha256 !== '87cdc4ab4ab24b193352dab07f9bf92a755bc4e7f2b1f4d8ec88936f47a5f900') {
    throw new Error('candidate operation catalog digest mismatch');
  }
  mkdirSync(releaseRoot, { recursive: true, mode: 0o755 });
  const candidate = join(releaseRoot, identity);
  if (existsSync(candidate)) {
    const verified = verifyRelease(candidate, { repository: options.repository, branch: options.branch, commit, tree, parent, releaseIdentity: identity }, { releaseRoot });
    return { ...verified, reused: true };
  }
  const staging = join(releaseRoot, `.${identity}.staging.${process.pid}.${randomUUID()}`);
  mkdirSync(staging, { mode: 0o700 });
  try {
    if (statSync(staging).dev !== statSync(releaseRoot).dev) throw new Error('release staging and target roots must use the same filesystem');
    copyPayload(sourceRoot, staging);
    const buildManifest = createFileManifest(staging);
    atomicWriteJson(join(staging, 'build-manifest.json'), buildManifest, 0o444);
    const runtime = runtimeManifest(staging, identity);
    atomicWriteJson(join(staging, 'runtime-manifest.json'), runtime, 0o444);
    const manifest = {
      schemaVersion: RELEASE_SCHEMA_VERSION,
      repository: options.repository,
      branch: options.branch,
      commit,
      tree,
      parent,
      releaseIdentity: identity,
      catalogVersion: options.catalog.catalogVersion,
      catalogSha256: options.catalog.catalogSha256,
      totalOperations: options.catalog.totalOperations,
      rootOperations: options.catalog.rootOperations,
      rootFabricDispatcherOperations: options.catalog.rootFabricDispatcherOperations,
      typedEffects: options.catalog.typedEffects,
      duplicateOperations: options.catalog.duplicateOperations,
      packageJsonSha256: digestFile(join(staging, 'package.json')),
      packageLockSha256: digestFile(join(staging, 'package-lock.json')),
      buildManifestSha256: digestFile(join(staging, 'build-manifest.json')),
      runtimeManifestSha256: digestFile(join(staging, 'runtime-manifest.json')),
      serviceInventorySha256: digestFile(join(staging, 'ops', 'service-inventory.json')),
      builtAt: options.builtAt,
      nodeVersion: options.nodeVersion,
      npmVersion: options.npmVersion,
    };
    atomicWriteJson(join(staging, 'release.json'), manifest, 0o444);
    atomicWrite(join(staging, 'release.sha256'), `${digestFile(join(staging, 'release.json'))}\n`, 0o444);
    verifyRelease(staging, { repository: options.repository, branch: options.branch, commit, tree, parent, releaseIdentity: identity }, { releaseRoot, requireImmutable: false });
    fsyncTree(staging);
    makeImmutable(staging);
    verifyRelease(staging, { repository: options.repository, branch: options.branch, commit, tree, parent, releaseIdentity: identity }, { releaseRoot });
    try {
      renameSync(staging, candidate);
    } catch (error) {
      if (!existsSync(candidate)) throw error;
      rmSync(staging, { recursive: true, force: true });
      const verified = verifyRelease(candidate, { repository: options.repository, branch: options.branch, commit, tree, parent, releaseIdentity: identity }, { releaseRoot });
      return { ...verified, reused: true };
    }
    fsyncDirectory(releaseRoot);
    const verified = verifyRelease(candidate, { repository: options.repository, branch: options.branch, commit, tree, parent, releaseIdentity: identity }, { releaseRoot });
    return { ...verified, reused: false };
  } catch (error) {
    if (existsSync(staging)) {
      try {
        chmodSync(staging, 0o700);
        const { files, directories } = walkRelease(staging);
        for (const { path } of files) chmodSync(path, 0o600);
        for (const directory of directories) chmodSync(directory, 0o700);
      } catch {}
      rmSync(staging, { recursive: true, force: true });
    }
    throw error;
  }
}
