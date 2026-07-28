import assert from 'node:assert/strict';
import test from 'node:test';
import { dynamicCatalog } from '../../dist/gateway/catalog.js';

test('K gateway preserves immutable runtime and catalog identity in health readback', async () => {
  const result = {
    product: 'baby-x',
    protocol: 'QRT1/1.0.0',
    repository: 'StealthEyeLLC/baby-x',
    sourceCommit: 'a'.repeat(40),
    sourceTree: 'b'.repeat(40),
    release: { releaseIdentity: `${'a'.repeat(40)}-${'b'.repeat(40)}` },
    catalog: { totalOperations: 230 },
    operationCatalogVersion: '3.4.0',
    operationCatalogSha256: '87cdc4ab4ab24b193352dab07f9bf92a755bc4e7f2b1f4d8ec88936f47a5f900',
    operations: Array.from({ length: 230 }, (_, index) => ({ operation: `operation.${index}` })),
  };
  const client = { async call() { return { result }; } };
  const catalog = await dynamicCatalog(client);
  assert.equal(catalog.repository, result.repository);
  assert.equal(catalog.sourceCommit, result.sourceCommit);
  assert.equal(catalog.sourceTree, result.sourceTree);
  assert.deepEqual(catalog.release, result.release);
  assert.deepEqual(catalog.catalog, result.catalog);
  assert.equal(catalog.operationCatalogVersion, '3.4.0');
  assert.equal(catalog.operationCatalogSha256, result.operationCatalogSha256);
  assert.equal(catalog.operations.length, 230);
});
