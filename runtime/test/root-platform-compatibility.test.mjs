import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { OPERATION_CATALOG_VERSION, OPERATION_DEFINITIONS } from '../../dist/runtime/operations/definitions.js';
import { SovereignRootPlatformService } from '../../dist/runtime/root-platform/service.js';
import { ROOT_PLATFORM_PROVIDER_VERSION, ROOT_PLATFORM_SCHEMA_VERSION, PROVIDER_SUPPORT_STATES } from '../../dist/runtime/root-platform/schemas.js';
import { canonicalize, sha256 } from '../../dist/runtime/core.js';

function service(root) {
  return new SovereignRootPlatformService({
    stateRoot: root,
    identity: { runningCommit: 'a'.repeat(40), runningTree: 'b'.repeat(40), protocolVersion: 'QRT1/1.0.0', catalogVersion: OPERATION_CATALOG_VERSION, catalogDigest: sha256(canonicalize(OPERATION_DEFINITIONS)) },
  });
}

test('platform description is deterministic and preserves Prompt 1 identity', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-platform-'));
  try {
    const instance = service(root);
    const first = instance.platformDescribe();
    const second = instance.platformDescribe();
    assert.equal(ROOT_PLATFORM_SCHEMA_VERSION, '2.0.0');
    assert.equal(ROOT_PLATFORM_PROVIDER_VERSION, 'sovereign-root-platform@2');
    assert.equal(OPERATION_CATALOG_VERSION, '7.0.0');
    assert.equal(first.platformDigest, second.platformDigest);
    assert.equal(first.prompt1.commit, 'fef1cb3b76a5c6f5beb1ca73499c4d1e5cafe713');
    assert.equal(first.prompt1.tree, 'a98cee4adfed2912bffda2a2fdf5928bcd0b66bf');
    assert.equal(first.migration.prompt1HistoriesRewritten, false);
    for (const provider of first.providers) assert.ok(PROVIDER_SUPPORT_STATES.includes(provider.supportState));
    for (const key of ['architecture', 'kernel', 'systemd', 'cgroup', 'kvm', 'seccomp', 'seccompNotification', 'landlock', 'bpf', 'btf', 'bpfLsm', 'tpm', 'measuredBootEventLog', 'ima', 'vsock', 'tap', 'criu', 'rr', 'zfs', 'nspawn']) assert.ok(key in first.host, key);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('catalog preserves Prompt 1 operations and adds the compact Checkpoint A surface once', () => {
  const names = OPERATION_DEFINITIONS.map((entry) => entry.operation);
  assert.equal(new Set(names).size, names.length);
  const required = ['babyx.root.platform.describe', 'babyx.root.provider.list', 'babyx.root.provider.get', 'babyx.root.provider.reconcile'];
  for (const name of required) assert.equal(names.filter((entry) => entry === name).length, 1, name);
  const originalRoot = ['babyx.root.describe', 'babyx.root.transaction.create', 'babyx.root.transaction.get', 'babyx.root.transaction.list', 'babyx.root.transaction.authorize', 'babyx.root.transaction.begin', 'babyx.root.transaction.observe', 'babyx.root.transaction.commit', 'babyx.root.transaction.rollback', 'babyx.root.transaction.events', 'babyx.root.transaction.verify'];
  for (const name of originalRoot) assert.ok(names.includes(name), name);
});
