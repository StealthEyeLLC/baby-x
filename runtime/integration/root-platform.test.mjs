import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime } from '../../dist/runtime/core.js';
import { SovereignRootPlatformService } from '../../dist/runtime/root-platform/service.js';

const context = (key) => ({ subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner', idempotencyKey: key });

test('root platform public operations dispatch and reconciliation survives restart', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-root-platform-integration-'));
  try {
    const options = { stateRoot: root, sourceCommit: 'a'.repeat(40), sourceTree: 'b'.repeat(40) };
    const first = new BabyXRuntime(options);
    const platform = await first.execute('babyx.root.platform.describe', {});
    assert.equal(platform.protocol, 'QRT1/1.0.0');
    const listed = await first.execute('babyx.root.provider.list', {});
    assert.deepEqual(listed.providers.map((entry) => entry.providerId), ['attestation-gated-secret-lease', 'bpf-lsm', 'firecracker-cold-boot', 'hardware-tpm', 'host-capability-probe', 'ima-measurement-evidence', 'landlock', 'measured-boot-evidence', 'prompt1-root-authority', 'seccomp-filter', 'seccomp-notify', 'software-tpm-fixture', 'sovereign-platform-core', 'sovereign-x509-svid', 'spire-workload-api']);
    const fetched = await first.execute('babyx.root.provider.get', { providerId: 'sovereign-platform-core' });
    assert.equal(fetched.provider.supportState, 'SUPPORTED');
    const reconciled = await first.execute('babyx.root.provider.reconcile', { providerId: 'sovereign-platform-core' }, context('platform-reconcile-0001'));
    const restarted = new BabyXRuntime(options);
    const replayed = await restarted.execute('babyx.root.provider.reconcile', { providerId: 'sovereign-platform-core' }, context('platform-reconcile-0001'));
    assert.deepEqual(replayed.reconciliation, reconciled.reconciliation);
    const after = await restarted.execute('babyx.root.provider.get', { providerId: 'sovereign-platform-core' });
    assert.equal(after.latestReconciliation.recordDigest, reconciled.reconciliation.recordDigest);
    await assert.rejects(() => restarted.execute('babyx.root.provider.reconcile', { providerId: 'prompt1-root-authority' }, context('platform-reconcile-0001')), (error) => error.code === 'root_platform_idempotency_conflict');
    await assert.rejects(() => restarted.execute('babyx.root.provider.get', { providerId: 'missing' }), (error) => error.code === 'root_platform_provider_not_found');
    const prompt1 = await restarted.execute('babyx.root.describe', {});
    assert.equal(prompt1.authority, 'coordination-only');
    const digest = 'c'.repeat(64);
    const legacy = await restarted.execute('babyx.root.transaction.create', {
      source: { repository: 'StealthEyeLLC/baby-x', branch: 'build/baby-x-god-mode-v1', commit: 'd'.repeat(40), tree: 'e'.repeat(40) },
      intent: { purpose: 'compatibility-read', mutationDigest: digest, targetDigest: digest, rollbackDigest: digest, requiredAuthorities: ['fixture-authority'], requiredVerifications: ['fixture-verification'] },
    }, context('prompt1-compatibility-create'));
    const platformService = new SovereignRootPlatformService({
      stateRoot: root,
      identity: { runningCommit: 'a'.repeat(40), runningTree: 'b'.repeat(40), protocolVersion: 'QRT1/1.0.0', catalogVersion: platform.catalogVersion, catalogDigest: platform.catalogDigest },
    });
    const compatibility = platformService.verifyPrompt1Record(legacy.transaction);
    assert.deepEqual(compatibility, { compatible: true, prompt1RecordPreserved: true, sidecarOnly: true, errors: [] });
  } finally { rmSync(root, { recursive: true, force: true }); }
});
