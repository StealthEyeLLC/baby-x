import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import test from 'node:test';
import { executableFromPath } from '../../scripts/executable-path.mjs';

test('tool discovery resolves only executable files from the declared PATH', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-tool-path-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const first = join(root, 'first');
  const second = join(root, 'second');
  mkdirSync(first);
  mkdirSync(second);
  writeFileSync(join(first, 'cargo'), '#!/bin/sh\nexit 0\n');
  writeFileSync(join(second, 'cargo'), '#!/bin/sh\nexit 0\n');
  chmodSync(join(second, 'cargo'), 0o755);
  assert.equal(executableFromPath('cargo', [first, second].join(delimiter)), join(second, 'cargo'));
});

test('tool discovery does not consult login-shell or profile paths', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-tool-profile-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const declared = join(root, 'declared');
  const profileOnly = join(root, 'profile-only');
  mkdirSync(declared);
  mkdirSync(profileOnly);
  writeFileSync(join(profileOnly, 'cargo'), '#!/bin/sh\nexit 0\n');
  chmodSync(join(profileOnly, 'cargo'), 0o755);
  assert.equal(executableFromPath('cargo', declared), '');
});

test('tool discovery rejects shell syntax and skips empty PATH segments', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-tool-empty-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(join(root, 'cargo'), '#!/bin/sh\nexit 0\n');
  chmodSync(join(root, 'cargo'), 0o755);
  const previous = process.cwd();
  process.chdir(root);
  try {
    assert.equal(executableFromPath('cargo', delimiter), '');
    assert.throws(() => executableFromPath('cargo;echo unsafe', root), /invalid executable name/u);
  } finally {
    process.chdir(previous);
  }
});
