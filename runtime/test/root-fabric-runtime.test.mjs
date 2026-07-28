import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime } from '../../dist/runtime/core.js';
import { OPERATION_CATALOG_VERSION, OPERATION_DEFINITIONS } from '../../dist/runtime/operations/definitions.js';
import { ROOT_FABRIC_OPERATION_NAMES } from '../../dist/runtime/root-fabric/service.js';

const legacyRoots = [
  'babyx.root.describe',
  'babyx.root.transaction.create',
  'babyx.root.transaction.get',
  'babyx.root.transaction.list',
  'babyx.root.transaction.authorize',
  'babyx.root.transaction.begin',
  'babyx.root.transaction.observe',
  'babyx.root.transaction.commit',
  'babyx.root.transaction.rollback',
  'babyx.root.transaction.events',
  'babyx.root.transaction.verify',
];

test('A-J runtime and canonical catalog expose the complete backward-compatible root fabric', async () => {
  const root = mkdtempSync(join(tmpdir(), 'babyx-root-runtime-'));
  const previousCredentialRoot = process.env.BABYX_ROOT_CREDENTIAL_ROOT;
  const previousDatasetRoots = process.env.BABYX_ROOT_DATASET_ROOTS;
  const previousMountRoots = process.env.BABYX_ROOT_MOUNT_ROOTS;
  try {
    process.env.BABYX_ROOT_CREDENTIAL_ROOT = join(root, 'run', 'credentials');
    process.env.BABYX_ROOT_DATASET_ROOTS = 'babyx-test';
    process.env.BABYX_ROOT_MOUNT_ROOTS = join(root, 'mounts');
    const runtime = new BabyXRuntime({ stateRoot: root, sourceCommit: 'a'.repeat(40), sourceTree: 'b'.repeat(40) });
    const description = runtime.describe();
    const operations = description.operations.map((entry) => entry.operation);
    assert.equal(OPERATION_CATALOG_VERSION, '3.1.0');
    assert.equal(OPERATION_DEFINITIONS.length, 230);
    assert.equal(description.operations.length, 230);
    assert.equal(new Set(operations).size, 230);
    for (const operation of legacyRoots) assert.equal(operations.includes(operation), true, `${operation} missing`);
    for (const operation of ROOT_FABRIC_OPERATION_NAMES) assert.equal(operations.includes(operation), true, `${operation} missing`);
    assert.equal(operations.filter((operation) => operation.startsWith('babyx.root.')).length, 51);
    for (const operation of ROOT_FABRIC_OPERATION_NAMES) {
      const definition = OPERATION_DEFINITIONS.find((entry) => entry.operation === operation);
      assert.ok(definition, `${operation} has no catalog definition`);
      assert.equal(definition.input.additionalProperties, false, `${operation} input is not strict`);
    }
    const compatibility = await runtime.execute('babyx.root.compatibility.get', {});
    assert.equal(compatibility.manifest.rootFabricVersion, '1.0.0');
    assert.equal(compatibility.manifest.catalogVersion, '3.1.0');
    assert.equal(compatibility.manifest.operationCount, 40);
    assert.equal(typeof compatibility.digest, 'string');
    assert.equal(compatibility.digest.length, 64);
    const registry = await runtime.execute('babyx.root.effect.registry', {});
    assert.equal(registry.effects.length, 31);
    assert.equal(registry.effects.some((entry) => entry.operation === 'filesystem.file.replace'), true);
    assert.equal(registry.effects.some((entry) => entry.operation === 'process.exec'), true);
    assert.equal(registry.effects.some((entry) => entry.operation === 'snapshot.rollback'), true);
    assert.equal(registry.effects.some((entry) => entry.operation === 'network.policy.apply-owned-rule'), true);
    const brokerMain = readFileSync('runtime/src/root-broker-main.ts', 'utf8');
    assert.doesNotMatch(brokerMain, /root\.shell|bash -c|sudo passthrough/u);
    assert.match(brokerMain, /getPeerCredentials/u);
    assert.match(brokerMain, /for \(const adapter of effects\.adapters\(\)\) broker\.register/u);
    const rootctl = readFileSync('runtime/src/rootctl.ts', 'utf8');
    assert.match(rootctl, /status.*freeze.*unfreeze.*kill-transaction.*kill-skill.*kill-all.*reconcile/su);
    assert.doesNotMatch(rootctl, /spawn|execFile|bash|sh -c/u);
    const socketUnit = readFileSync('ops/systemd/baby-x-root-broker.socket', 'utf8');
    assert.match(socketUnit, /ListenStream=\/run\/baby-x\/root-broker\.sock/u);
    assert.doesNotMatch(socketUnit, /ListenStream=\d/u);
  } finally {
    if (previousCredentialRoot === undefined) delete process.env.BABYX_ROOT_CREDENTIAL_ROOT; else process.env.BABYX_ROOT_CREDENTIAL_ROOT = previousCredentialRoot;
    if (previousDatasetRoots === undefined) delete process.env.BABYX_ROOT_DATASET_ROOTS; else process.env.BABYX_ROOT_DATASET_ROOTS = previousDatasetRoots;
    if (previousMountRoots === undefined) delete process.env.BABYX_ROOT_MOUNT_ROOTS; else process.env.BABYX_ROOT_MOUNT_ROOTS = previousMountRoots;
    rmSync(root, { recursive: true, force: true });
  }
});
