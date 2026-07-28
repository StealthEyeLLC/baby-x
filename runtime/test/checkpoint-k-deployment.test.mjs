import assert from 'node:assert/strict';
import {
  chmodSync,
  cpSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test, { after, before } from 'node:test';
import {
  CANONICAL_UNITS,
  RELEASE_REPOSITORY,
  digestFile,
  stageRelease,
  verifyRelease,
} from '../../scripts/lib/release-contract.mjs';
import {
  assertActivationJournal,
  atomicLink,
  pointerTarget,
  requestDigest,
} from '../../scripts/activate-release.mjs';
import { resolveRuntimeListenOptions } from '../../dist/runtime/server.js';

const COMMIT = 'a'.repeat(40);
const TREE = 'b'.repeat(40);
const PARENT = 'c'.repeat(40);
const CATALOG_SHA256 = '87cdc4ab4ab24b193352dab07f9bf92a755bc4e7f2b1f4d8ec88936f47a5f900';
let temporary;
let releaseRoot;
let releasePath;

function catalog() {
  return {
    catalogVersion: '3.4.0',
    catalogSha256: CATALOG_SHA256,
    totalOperations: 230,
    rootOperations: 51,
    rootFabricDispatcherOperations: 40,
    typedEffects: 31,
    duplicateOperations: 0,
  };
}

function makeWritable(path) {
  const metadata = lstatSync(path);
  chmodSync(path, metadata.isDirectory() ? 0o700 : 0o600);
  if (metadata.isDirectory()) {
    for (const name of readdirSync(path)) makeWritable(join(path, name));
  }
}

function variant(name) {
  const destination = join(releaseRoot, name);
  cpSync(releasePath, destination, { recursive: true });
  return destination;
}

before(() => {
  temporary = mkdtempSync(join(tmpdir(), 'baby-x-checkpoint-k-'));
  releaseRoot = join(temporary, 'releases');
  mkdirSync(releaseRoot);
  const staged = stageRelease({
    sourceRoot: process.cwd(),
    releaseRoot,
    repository: RELEASE_REPOSITORY,
    branch: 'build/baby-x-transactional-root-authority-k-deployment-v1',
    commit: COMMIT,
    tree: TREE,
    parent: PARENT,
    builtAt: '2026-07-28T00:00:00.000Z',
    nodeVersion: 'v24.18.0',
    npmVersion: '11.16.0',
    catalog: catalog(),
  });
  releasePath = staged.releasePath;
});

after(() => {
  if (temporary) {
    makeWritable(temporary);
    rmSync(temporary, { recursive: true, force: true });
  }
});

test('K stages and reuses one fully verified immutable release', () => {
  const first = verifyRelease(releasePath, {
    repository: RELEASE_REPOSITORY,
    commit: COMMIT,
    tree: TREE,
    parent: PARENT,
  }, { releaseRoot });
  assert.equal(first.manifest.catalogSha256, CATALOG_SHA256);
  const second = stageRelease({
    sourceRoot: process.cwd(),
    releaseRoot,
    repository: RELEASE_REPOSITORY,
    branch: 'build/baby-x-transactional-root-authority-k-deployment-v1',
    commit: COMMIT,
    tree: TREE,
    parent: PARENT,
    builtAt: '2026-07-28T00:00:00.000Z',
    nodeVersion: 'v24.18.0',
    npmVersion: '11.16.0',
    catalog: catalog(),
  });
  assert.equal(second.reused, true);
  for (const unit of CANONICAL_UNITS) {
    const inventory = JSON.parse(readFileSync(join(releasePath, 'ops/service-inventory.json'), 'utf8'));
    assert.equal(digestFile(join(releasePath, 'ops/systemd', unit)), inventory.services[unit].sha256);
  }
});

test('K rejects wrong approved commit, tree, and parent identities', () => {
  assert.throws(() => verifyRelease(releasePath, { commit: 'd'.repeat(40) }, { releaseRoot }), /commit does not match/u);
  assert.throws(() => verifyRelease(releasePath, { tree: 'd'.repeat(40) }, { releaseRoot }), /tree does not match/u);
  assert.throws(() => verifyRelease(releasePath, { parent: 'd'.repeat(40) }, { releaseRoot }), /parent does not match/u);
});

test('K rejects malformed and altered release manifests', () => {
  const malformed = variant('malformed');
  makeWritable(malformed);
  writeFileSync(join(malformed, 'release.json'), '{');
  assert.throws(() => verifyRelease(malformed, {}, { releaseRoot }), /release manifest is malformed/u);

  const altered = variant('altered');
  makeWritable(altered);
  const manifest = JSON.parse(readFileSync(join(altered, 'release.json'), 'utf8'));
  manifest.totalOperations = 229;
  writeFileSync(join(altered, 'release.json'), `${JSON.stringify(manifest)}\n`);
  assert.throws(() => verifyRelease(altered, {}, { releaseRoot }), /totalOperations mismatch|operation count mismatch|manifest digest mismatch/u);
});

test('K rejects wrong lockfile/build bytes and incomplete releases', () => {
  const lock = variant('wrong-lock');
  makeWritable(lock);
  writeFileSync(join(lock, 'package-lock.json'), '{}\n');
  assert.throws(() => verifyRelease(lock, {}, { releaseRoot }), /package-lock.json digest mismatch|file digest/u);

  const build = variant('wrong-build');
  makeWritable(build);
  writeFileSync(join(build, 'runtime/cli/main.js'), 'throw new Error("altered");\n');
  assert.throws(() => verifyRelease(build, {}, { releaseRoot }), /file digest|entrypoint/u);

  const incomplete = variant('incomplete');
  makeWritable(incomplete);
  rmSync(join(incomplete, 'gateway/main.js'));
  assert.throws(() => verifyRelease(incomplete, {}, { releaseRoot }), /ENOENT|missing|entrypoint/u);
});

test('K detects mutable releases and conflicting pre-existing candidates', () => {
  const mutable = variant('mutable');
  chmodSync(join(mutable, 'package.json'), 0o644);
  assert.throws(() => verifyRelease(mutable, {}, { releaseRoot }), /release file is mutable/u);

  const conflictRoot = join(temporary, 'conflict-releases');
  mkdirSync(conflictRoot);
  const conflict = stageRelease({
    sourceRoot: process.cwd(),
    releaseRoot: conflictRoot,
    repository: RELEASE_REPOSITORY,
    branch: 'build/baby-x-transactional-root-authority-k-deployment-v1',
    commit: COMMIT,
    tree: TREE,
    parent: PARENT,
    builtAt: '2026-07-28T00:00:00.000Z',
    nodeVersion: 'v24.18.0',
    npmVersion: '11.16.0',
    catalog: catalog(),
  }).releasePath;
  makeWritable(conflict);
  writeFileSync(join(conflict, 'package.json'), '{}\n');
  assert.throws(() => stageRelease({
    sourceRoot: process.cwd(),
    releaseRoot: conflictRoot,
    repository: RELEASE_REPOSITORY,
    branch: 'build/baby-x-transactional-root-authority-k-deployment-v1',
    commit: COMMIT,
    tree: TREE,
    parent: PARENT,
    builtAt: '2026-07-28T00:00:00.000Z',
    nodeVersion: 'v24.18.0',
    npmVersion: '11.16.0',
    catalog: catalog(),
  }), /digest|mutable/u);
});

test('K pointer validation confines targets and atomic replacement leaves no temporary pointer', () => {
  const install = join(temporary, 'pointer-install');
  const releases = join(install, 'releases');
  const one = join(releases, 'one');
  const two = join(releases, 'two');
  const outside = join(temporary, 'outside');
  mkdirSync(one, { recursive: true });
  mkdirSync(two);
  mkdirSync(outside);
  symlinkSync(one, join(install, 'current'));
  assert.equal(pointerTarget(join(install, 'current'), releases), one);
  atomicLink(two, join(install, 'current'));
  assert.equal(pointerTarget(join(install, 'current'), releases), two);
  assert.equal(readlinkSync(join(install, 'current')), two);
  assert.equal(readdirSync(install).some((name) => name.startsWith('current.tmp.')), false);
  atomicLink(outside, join(install, 'current'));
  assert.throws(() => pointerTarget(join(install, 'current'), releases), /escapes/u);
});

test('K activation journals and request identities are strict and idempotent', () => {
  const digestInput = {
    deploymentId: 'baby-x-fast-a',
    candidate: releasePath,
    commit: COMMIT,
    tree: TREE,
    expectedCurrentCommit: 'd'.repeat(40),
    expectedCurrentTree: 'e'.repeat(40),
    reason: 'checkpoint K test',
  };
  assert.equal(requestDigest(digestInput), requestDigest({ ...digestInput }));
  assert.notEqual(requestDigest(digestInput), requestDigest({ ...digestInput, tree: 'f'.repeat(40) }));
  assert.throws(() => assertActivationJournal({ deploymentId: 'x' }), /missing required fields/u);
});

test('K socket activation accepts only the exact systemd descriptor identity', () => {
  assert.deepEqual(resolveRuntimeListenOptions('/run/horsey/baby-x.sock', {}, 10), { path: '/run/horsey/baby-x.sock' });
  assert.deepEqual(resolveRuntimeListenOptions('/ignored', { LISTEN_PID: '10', LISTEN_FDS: '1', LISTEN_FDNAMES: 'baby-x' }, 10), { fd: 3 });
  assert.throws(() => resolveRuntimeListenOptions('/ignored', { LISTEN_PID: '10', LISTEN_FDS: '2' }, 10), /exactly one/u);
  assert.throws(() => resolveRuntimeListenOptions('/ignored', { LISTEN_PID: '10', LISTEN_FDS: '1', LISTEN_FDNAMES: 'wrong' }, 10), /descriptor name/u);
});

test('K critical-path routing identifies deployment authority changes', () => {
  const result = spawnSync(process.execPath, [
    'scripts/critical-paths.mjs',
    'ops/fast-lane-critical-paths.json',
    'scripts/activate-release.mjs',
    'runtime/src/core.ts',
  ], { cwd: process.cwd(), encoding: 'utf8' });
  assert.equal(result.status, 42);
  const report = JSON.parse(result.stdout);
  assert.equal(report.critical, true);
  assert.deepEqual(report.matches.map((entry) => entry.rule), ['release-activation']);
});

test('K canonical units preserve separate unprivileged runtime/gateway and sole root broker', () => {
  const units = Object.fromEntries(CANONICAL_UNITS.map((unit) => [
    unit,
    readFileSync(join('ops/systemd', unit), 'utf8'),
  ]));
  assert.match(units['baby-x.service'], /^User=fix-exec$/mu);
  assert.match(units['baby-x-gateway.service'], /^User=fix-mcp$/mu);
  assert.match(units['baby-x-root-broker.service'], /^User=root$/mu);
  assert.match(units['baby-x-root-broker.socket'], /^ListenStream=\/run\/baby-x\/root-broker\.sock$/mu);
  assert.doesNotMatch(units['baby-x-root-broker.socket'], /ListenStream=.*:/u);
  assert.match(units['baby-x-root-broker.socket'], /^SocketMode=0660$/mu);
  assert.match(units['baby-x-root-broker.socket'], /^SocketGroup=horsey$/mu);
  for (const value of Object.values(units)) {
    assert.doesNotMatch(value, /\/tmp|\/home\/|workspace/u);
  }
});
