import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime } from '../src/core.ts';

function text(value) { return Buffer.from(value, 'base64').toString('utf8'); }

test('raw host execution preserves root identity, cwd, environment, stderr and nonzero status', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-exec-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const uid = await runtime.execute('babyx.exec', { target: { kind: 'host' }, argv: ['/usr/bin/id', '-u'], cwd: '/' });
    assert.equal(text(uid.stdout).trim(), '0');
    assert.equal(uid.exitCode, 0);
    const shell = await runtime.execute('babyx.shell', { target: { kind: 'host' }, command: 'printf "%s:%s" "$PWD" "$BABY_X_TEST"; printf failure >&2; exit 7', cwd: '/tmp', env: { BABY_X_TEST: 'unrestricted' } });
    assert.equal(text(shell.stdout), '/tmp:unrestricted');
    assert.equal(text(shell.stderr), 'failure');
    assert.equal(shell.exitCode, 7);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('raw provider escape hatches do not inspect valid powerful arguments', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-raw-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    const result = await runtime.execute('babyx.systemd.raw', { tool: '/usr/bin/printf', argv: ['--', 'CapabilityBoundingSet=~CAP_SYS_ADMIN'] });
    assert.equal(text(result.stdout), '--');
    await assert.rejects(() => runtime.execute('babyx.machine.raw', { tool: '/usr/bin/printf', argv: ['bad\0argument'] }), /NUL-free/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
