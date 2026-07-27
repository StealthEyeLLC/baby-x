import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const workerUnit = readFileSync('ops/systemd/baby-x.service', 'utf8');
const verifier = readFileSync('scripts/verify-local.sh', 'utf8');

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
