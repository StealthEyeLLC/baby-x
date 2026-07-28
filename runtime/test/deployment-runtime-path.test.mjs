import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const workerUnit = readFileSync('ops/systemd/baby-x.service', 'utf8');
const verifier = readFileSync('scripts/verify-local.sh', 'utf8');
const installer = readFileSync('scripts/install-local.sh', 'utf8');
const rollback = readFileSync('scripts/rollback-local.sh', 'utf8');
const tmpfiles = readFileSync('ops/tmpfiles/baby-x.conf', 'utf8');

test('systemd worker executes the compiled immutable runtime', () => {
  assert.match(workerUnit, /ExecStart=\/opt\/node-v24\.18\.0-linux-x64\/bin\/node \/opt\/baby-x\/current\/runtime\/cli\/main\.js serve/u);
  assert.doesNotMatch(workerUnit, /\/runtime\/src\//u);
});

test('deployment verification proves gateway to socket to runtime health', () => {
  assert.match(verifier, /\/healthz/u);
  assert.match(verifier, /gateway\.runtime\?\.product !== direct\.product/u);
  assert.match(verifier, /gateway\.runtime\?\.operationCount !== direct\.operations\?\.length/u);
  assert.match(verifier, /systemctl is-active baby-x\.service/u);
  assert.match(verifier, /\[\[ "\$worker_state" == active \]\]/u);
});


test('fast deployment installs, verifies, and safely rolls back the root provider', () => {
  for (const script of [installer, rollback]) {
    assert.match(script, /baby-x-root-provider\.service/u);
    assert.match(script, /baby-x-root-provider\.socket/u);
    assert.match(script, /provision-microvm-assets\.sh/u);
    assert.match(script, /systemctl enable baby-x-root-provider\.socket/u);
  }
  assert.match(verifier, /systemctl is-enabled --quiet baby-x-root-provider\.socket/u);
  assert.match(verifier, /systemctl is-active --quiet baby-x-root-provider\.socket/u);
  assert.match(verifier, /MicrovmArtifactRegistry/u);
  assert.match(verifier, /resolvedManifestDigest/u);
  assert.match(tmpfiles, /d \/run\/baby-x\/microvm 0700 root root -/u);
  assert.match(tmpfiles, /d \/var\/lib\/baby-x\/root-platform\/microvm\/assets 0700 root root -/u);
});
