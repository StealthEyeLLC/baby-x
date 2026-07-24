import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime } from '../src/core.ts';

test('god-mode provider discovery tells the truth about environmental availability', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-god-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root });
    for (const operation of ['babyx.trace.describe', 'babyx.debug.describe', 'babyx.checkpoint.describe', 'babyx.packet.describe', 'babyx.syscall.describe', 'babyx.machine.describe']) {
      const result = await runtime.execute(operation, {});
      assert.equal(result.operation, operation);
      assert.equal(typeof result.available, 'boolean');
    }
    const missing = await runtime.execute('babyx.debug.raw', { tool: '/definitely/missing/gdb', argv: ['--version'] });
    assert.ok(missing.exitCode !== 0 || text(missing.stderr).length > 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
function text(value) { return Buffer.from(value ?? '', 'base64').toString('utf8'); }
