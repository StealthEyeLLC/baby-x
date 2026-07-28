import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const repository = process.cwd();
const script = join(repository, 'scripts', 'provision-local-keys.sh');

function run(configRoot) {
  return spawnSync('/bin/bash', [script], {
    cwd: repository,
    encoding: 'utf8',
    env: {
      ...process.env,
      BABY_X_CONFIG_ROOT: configRoot,
      BABY_X_NODE_BIN: '/opt/node-v24.18.0-linux-x64/bin/node',
    },
  });
}

function digest(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function accountId(args) {
  const result = spawnSync('/usr/bin/id', args, { encoding: 'utf8' });
  if (result.status !== 0) return null;
  return Number(result.stdout.trim());
}

function groupId(name) {
  const result = spawnSync('/usr/bin/getent', ['group', name], { encoding: 'utf8' });
  if (result.status !== 0) return null;
  return Number(result.stdout.trim().split(':')[2]);
}

test('key provisioning is durable, idempotent, private, and complete', (context) => {
  const fixUid = accountId(['-u', 'fix-mcp']);
  const horseyGid = groupId('horsey');
  if (process.getuid?.() !== 0 || fixUid === null || horseyGid === null) {
    context.skip('requires root and the deployment service account');
    return;
  }

  const temporary = mkdtempSync(join(tmpdir(), 'baby-x-keys-'));
  const partial = mkdtempSync(join(tmpdir(), 'baby-x-partial-keys-'));
  try {
    const first = run(temporary);
    assert.equal(first.status, 0, first.stderr);
    assert.doesNotMatch(first.stdout, /PRIVATE KEY/u);
    assert.match(first.stdout, new RegExp(`gateway_uid=${fixUid}\\n`, 'u'));

    const expected = new Map([
      ['gateway-authority-private.pem', { mode: 0o600, uid: fixUid, gid: horseyGid }],
      ['gateway-authority-public.pem', { mode: 0o640, uid: 0, gid: horseyGid }],
      ['proof-private.pem', { mode: 0o600, uid: 0, gid: 0 }],
      ['proof-public.pem', { mode: 0o640, uid: 0, gid: horseyGid }],
      ['runtime-key-environment', { mode: 0o640, uid: 0, gid: horseyGid }],
      ['gateway-key-environment', { mode: 0o640, uid: 0, gid: horseyGid }],
    ]);

    for (const [name, identity] of expected) {
      const metadata = statSync(join(temporary, name));
      assert.equal(metadata.mode & 0o777, identity.mode, name);
      assert.equal(metadata.uid, identity.uid, name);
      assert.equal(metadata.gid, identity.gid, name);
    }

    assert.equal(
      readFileSync(join(temporary, 'runtime-key-environment'), 'utf8'),
      `BABY_X_GATEWAY_UID=${fixUid}\nBABY_X_GATEWAY_PUBLIC_KEY=${temporary}/gateway-authority-public.pem\nBABY_X_PROOF_PRIVATE_KEY=${temporary}/proof-private.pem\nBABY_X_PROOF_KEY_ID=baby-x-proof-v1\n`,
    );
    assert.equal(
      readFileSync(join(temporary, 'gateway-key-environment'), 'utf8'),
      `BABY_X_GATEWAY_PRIVATE_KEY=${temporary}/gateway-authority-private.pem\nBABY_X_PROOF_PUBLIC_KEY=${temporary}/proof-public.pem\n`,
    );

    const before = [...expected.keys()].filter((name) => name.endsWith('.pem')).map((name) => [name, digest(join(temporary, name))]);
    const second = run(temporary);
    assert.equal(second.status, 0, second.stderr);
    for (const [name, expectedDigest] of before) assert.equal(digest(join(temporary, name)), expectedDigest, name);

    mkdirSync(partial, { recursive: true });
    const partialKey = join(partial, 'gateway-authority-private.pem');
    writeFileSync(partialKey, 'partial\n');
    chmodSync(partialKey, 0o600);
    const rejected = run(partial);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /partial Baby-X key material exists/u);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
    rmSync(partial, { recursive: true, force: true });
  }
});

test('immutable build contains key provisioning and key-wired units', () => {
  assert.equal(readFileSync('dist/scripts/provision-local-keys.sh').equals(readFileSync('scripts/provision-local-keys.sh')), true);
  const report = JSON.parse(readFileSync('dist/build-report.json', 'utf8'));
  assert.equal(report.copiedDeploymentFiles, 12);
  const runtimeUnit = readFileSync('dist/ops/systemd/baby-x.service', 'utf8');
  const gatewayUnit = readFileSync('dist/ops/systemd/baby-x-gateway.service', 'utf8');
  assert.match(runtimeUnit, /EnvironmentFile=-\/etc\/baby-x\/runtime-key-environment/u);
  assert.match(gatewayUnit, /EnvironmentFile=-\/etc\/baby-x\/gateway-key-environment/u);
});
