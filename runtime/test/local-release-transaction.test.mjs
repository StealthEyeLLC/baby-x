import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const repository = process.cwd();
const installSource = readFileSync(join(repository, 'scripts', 'install-local.sh'));
const rollbackSource = readFileSync(join(repository, 'scripts', 'rollback-local.sh'));

function executable(path, data) {
  writeFileSync(path, data, { mode: 0o755 });
  chmodSync(path, 0o755);
}

function verificationScript() {
  return `#!/usr/bin/env bash
set -euo pipefail
target=$(readlink -f "$BABY_X_INSTALL_ROOT/current")
printf '%s\\n' "$target" >> "$BABY_X_INSTALL_ROOT/verify.log"
[[ ! -e "$target/FAIL_VERIFY" ]]
`;
}

function release(root, name, fail = false) {
  const path = join(root, 'releases', name);
  mkdirSync(join(path, 'scripts'), { recursive: true });
  executable(join(path, 'scripts', 'verify-local.sh'), verificationScript());
  writeFileSync(join(path, 'VERSION'), `${name}\n`);
  if (fail) writeFileSync(join(path, 'FAIL_VERIFY'), 'fail\n');
  return path;
}

function prepareDist(workspace, name, fail = false) {
  const dist = join(workspace, 'dist');
  rmSync(dist, { recursive: true, force: true });
  mkdirSync(join(dist, 'scripts'), { recursive: true });
  executable(join(dist, 'scripts', 'verify-local.sh'), verificationScript());
  writeFileSync(join(dist, 'VERSION'), `${name}\n`);
  if (fail) writeFileSync(join(dist, 'FAIL_VERIFY'), 'fail\n');
}

function run(path, workspace, root, extra = {}) {
  return spawnSync('/bin/bash', [path], {
    cwd: workspace,
    encoding: 'utf8',
    env: { ...process.env, BABY_X_INSTALL_ROOT: root, BABY_X_INSTALL_UNITS: '0', ...extra },
  });
}

function target(root, name) {
  return realpathSync(join(root, name));
}

test('local release activation and rollback preserve only verified pointer state', () => {
  const temporary = mkdtempSync(join(tmpdir(), 'baby-x-local-release-'));
  const workspace = join(temporary, 'workspace');
  const root = join(temporary, 'install');
  try {
    mkdirSync(join(workspace, 'scripts'), { recursive: true });
    mkdirSync(join(root, 'releases'), { recursive: true });
    executable(join(workspace, 'scripts', 'install-local.sh'), installSource);
    executable(join(workspace, 'scripts', 'rollback-local.sh'), rollbackSource);

    const releaseA = release(root, 'release-a');
    const releaseP = release(root, 'release-p');
    symlinkSync(releaseA, join(root, 'current'));
    symlinkSync(releaseP, join(root, 'previous'));

    prepareDist(workspace, 'release-b');
    const installed = run(join(workspace, 'scripts', 'install-local.sh'), workspace, root, { BABY_X_RELEASE_ID: 'release-b' });
    assert.equal(installed.status, 0, installed.stderr);
    const releaseB = join(root, 'releases', 'release-b');
    assert.equal(target(root, 'current'), releaseB);
    assert.equal(target(root, 'previous'), releaseA);

    prepareDist(workspace, 'release-c', true);
    const rejected = run(join(workspace, 'scripts', 'install-local.sh'), workspace, root, { BABY_X_RELEASE_ID: 'release-c' });
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /automatic rollback restored/u);
    assert.equal(target(root, 'current'), releaseB);
    assert.equal(target(root, 'previous'), releaseA);
    assert.equal(existsSync(join(root, 'releases', 'release-c')), true);

    const rolledBack = run(join(workspace, 'scripts', 'rollback-local.sh'), workspace, root);
    assert.equal(rolledBack.status, 0, rolledBack.stderr);
    assert.equal(target(root, 'current'), releaseA);
    assert.equal(target(root, 'previous'), releaseB);

    writeFileSync(join(releaseB, 'FAIL_VERIFY'), 'fail\n');
    const rejectedRollback = run(join(workspace, 'scripts', 'rollback-local.sh'), workspace, root);
    assert.notEqual(rejectedRollback.status, 0);
    assert.match(rejectedRollback.stderr, /failed safely/u);
    assert.equal(target(root, 'current'), releaseA);
    assert.equal(target(root, 'previous'), releaseB);

    rmSync(join(releaseB, 'FAIL_VERIFY'));
    const restored = run(join(workspace, 'scripts', 'rollback-local.sh'), workspace, root);
    assert.equal(restored.status, 0, restored.stderr);
    assert.equal(target(root, 'current'), releaseB);
    assert.equal(target(root, 'previous'), releaseA);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
