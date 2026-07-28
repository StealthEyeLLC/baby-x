import assert from 'node:assert/strict';
import test from 'node:test';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import {
  createRequestDigest,
  normalizeCreateRequest,
  normalizeExecRequest,
  normalizeListRequest,
  normalizePoolRequest,
  normalizeRestoreRequest,
  normalizeSnapshotRequest,
  normalizeVmSelector,
} from '../../dist/runtime/root-platform/microvm/schemas.js';
import { canonicalize, sha256 } from '../../dist/runtime/core.js';
import { MicrovmArtifactRegistry } from '../../dist/runtime/root-platform/microvm/artifacts.js';
import {
  initialMicrovmRecord,
  MicrovmRecordStore,
  verifyMicrovmEvent,
  verifyMicrovmRecord,
} from '../../dist/runtime/root-platform/microvm/records.js';
import {
  initialPoolRecord,
  initialSnapshotRecord,
  SnapshotPoolStore,
  verifyPoolRecord,
  verifySnapshotRecord,
} from '../../dist/runtime/root-platform/microvm/snapshot-store.js';

const digest = (character) => character.repeat(64);
const createPayload = {
  transactionId: 'rtx_microvm_unit_0001',
  skillBundleDigest: digest('a'),
  grantDigest: digest('b'),
  policyDigest: digest('c'),
  kernelDigest: digest('d'),
  rootImageDigest: digest('e'),
};

function initial(now = '2026-07-28T00:00:00.000Z') {
  const request = normalizeCreateRequest(createPayload);
  return initialMicrovmRecord({
    vmId: 'mvm_0123456789abcdef0123456789abcdef',
    ownerPrincipal: 'owner:microvm-unit',
    request,
    requestDigest: createRequestDigest('owner:microvm-unit', request),
    idempotencyKey: 'microvm-unit-create-0001',
    artifacts: {
      firecrackerDigest: digest('f'),
      kernelDigest: digest('d'),
      rootImageDigest: digest('e'),
      guestAgentDigest: digest('1'),
      guestAgentProtocol: 'BABYX-GUEST/1.0.0',
    },
    writableLayerIdentity: '/tmp/microvm-unit/rootfs.ext4',
    writableLayerDigest: digest('2'),
    systemdUnit: 'baby-x-microvm-0123456789abcdef0123456789abcdef.service',
    vsockCid: 10000,
    vsockSocketIdentity: '/tmp/microvm-unit/vsock.sock',
    hostBootId: '11111111-1111-4111-8111-111111111111',
    now,
  });
}

test('microVM schemas are strict, bounded, digest-bound, and default to no network', () => {
  const normalized = normalizeCreateRequest(createPayload);
  assert.deepEqual(normalized, {
    ...createPayload,
    firecrackerVersion: 'v1.15.1',
    vcpuCount: 1,
    memoryMiB: 256,
    networkMode: 'NONE',
  });
  assert.equal(createRequestDigest('owner:microvm-unit', normalized), createRequestDigest('owner:microvm-unit', normalizeCreateRequest(createPayload)));
  assert.throws(() => normalizeCreateRequest({ ...createPayload, unexpected: true }), (error) => error.code === 'microvm_invalid_request');
  assert.throws(() => normalizeCreateRequest({ ...createPayload, firecrackerVersion: 'v1.16.1' }), (error) => error.code === 'microvm_invalid_request');
  assert.throws(() => normalizeCreateRequest({ ...createPayload, networkMode: 'TAP' }), (error) => error.code === 'microvm_invalid_request');
  assert.throws(() => normalizeCreateRequest({ ...createPayload, memoryMiB: 127 }), (error) => error.code === 'microvm_invalid_request');
  assert.throws(() => normalizeVmSelector({ vmId: 'bad' }), (error) => error.code === 'microvm_invalid_request');
  assert.deepEqual(normalizeListRequest({ lifecycle: 'READY', offset: 2, limit: 3 }), { ownerPrincipal: undefined, lifecycle: 'READY', offset: 2, limit: 3 });
  assert.deepEqual(normalizeExecRequest({ vmId: 'mvm_0123456789abcdef0123456789abcdef', action: 'ECHO', taskId: 'task_echo_0001', input: 'hello' }).request, { action: 'ECHO', taskId: 'task_echo_0001', input: 'hello' });
  assert.throws(() => normalizeExecRequest({ vmId: 'mvm_0123456789abcdef0123456789abcdef', action: 'ECHO', taskId: 'task_echo_0001', input: 'x'.repeat(1025) }), (error) => error.code === 'microvm_invalid_request');
});

test('microVM snapshot, restore, and pool schemas are strict and bounded', () => {
  const now = new Date('2026-07-28T00:00:00.000Z');
  const vmId = 'mvm_0123456789abcdef0123456789abcdef';
  const snapshotId = 'mvs_0123456789abcdef0123456789abcdef';
  const poolId = 'mvp_0123456789abcdef0123456789abcdef';
  const snapshot = normalizeSnapshotRequest({ vmId }, now);
  assert.deepEqual(snapshot, { vmId, expiresAt: '2026-07-29T00:00:00.000Z' });
  assert.throws(() => normalizeSnapshotRequest({ vmId, unexpected: true }, now), (error) => error.code === 'microvm_invalid_request');
  assert.throws(() => normalizeSnapshotRequest({ vmId, expiresAt: '2026-07-27T00:00:00.000Z' }, now), (error) => error.code === 'microvm_invalid_request');

  const restore = normalizeRestoreRequest({
    snapshotId,
    transactionId: 'rtx_snapshot_restore_0001',
    skillBundleDigest: digest('a'),
    grantDigest: digest('b'),
    policyDigest: digest('c'),
  });
  assert.equal(restore.networkMode, 'NONE');
  assert.throws(() => normalizeRestoreRequest({ ...restore, networkMode: 'TAP' }), (error) => error.code === 'microvm_invalid_request');

  const reconcile = normalizePoolRequest({ action: 'RECONCILE', snapshotId }, now);
  assert.deepEqual(reconcile, {
    action: 'RECONCILE',
    poolId: undefined,
    snapshotId,
    desiredWarmCount: 1,
    expiresAt: '2026-07-29T00:00:00.000Z',
  });
  assert.throws(() => normalizePoolRequest({ action: 'RECONCILE', snapshotId, maximumWarmCount: 2 }, now), (error) => error.code === 'microvm_invalid_request');
  assert.throws(() => normalizePoolRequest({ action: 'ACQUIRE', poolId }), (error) => error.code === 'microvm_invalid_request');
  assert.deepEqual(normalizePoolRequest({
    action: 'ACQUIRE',
    poolId,
    transactionId: 'rtx_pool_acquire_0001',
    skillBundleDigest: digest('d'),
    grantDigest: digest('e'),
    policyDigest: digest('f'),
  }, now), {
    action: 'ACQUIRE',
    poolId,
    transactionId: 'rtx_pool_acquire_0001',
    skillBundleDigest: digest('d'),
    grantDigest: digest('e'),
    policyDigest: digest('f'),
  });
  assert.deepEqual(normalizePoolRequest({ action: 'RELEASE', poolId, vmId }, now), { action: 'RELEASE', poolId, vmId });
});

test('snapshot and warm-pool records are durable, digest-bound, restart-safe, and idempotent', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-microvm-snapshot-store-'));
  const ownerPrincipal = 'owner:microvm-snapshot-unit';
  const now = '2026-07-28T00:00:00.000Z';
  const expiresAt = '2026-07-29T00:00:00.000Z';
  try {
    const store = new SnapshotPoolStore(root, { now: () => now });
    const snapshotClaim = store.claimSnapshot(ownerPrincipal, 'snapshot-unit-0001', digest('1'));
    assert.equal(snapshotClaim.replayed, false);
    assert.match(snapshotClaim.snapshotId, /^mvs_[a-f0-9]{32}$/u);
    assert.deepEqual(store.claimSnapshot(ownerPrincipal, 'snapshot-unit-0001', digest('1')), { snapshotId: snapshotClaim.snapshotId, replayed: true });
    assert.throws(() => store.claimSnapshot(ownerPrincipal, 'snapshot-unit-0001', digest('2')), (error) => error.code === 'microvm_idempotency_conflict');

    const snapshot = initialSnapshotRecord({
      snapshotId: snapshotClaim.snapshotId,
      ownerPrincipal,
      requestDigest: digest('1'),
      idempotencyKeyDigest: digest('2'),
      sourceVmId: 'mvm_0123456789abcdef0123456789abcdef',
      sourceTransactionId: 'rtx_snapshot_source_0001',
      providerVersion: 'firecracker-v1.15.1+babyx-provider-1.1.0',
      firecrackerDigest: digest('3'),
      cpuArchitecture: 'x64',
      cpuFingerprint: digest('4'),
      kernelDigest: digest('5'),
      baseRootImageDigest: digest('6'),
      writableDiskDigest: null,
      memoryDigest: null,
      vmStateDigest: null,
      memoryPath: '/tmp/snapshot/memory.bin',
      vmStatePath: '/tmp/snapshot/vmstate.bin',
      diskPath: '/tmp/snapshot/rootfs.ext4',
      guestCid: 10000,
      vcpuCount: 1,
      memoryMiB: 128,
      skillBundleDigest: digest('7'),
      grantDigest: digest('8'),
      policyDigest: digest('9'),
      vsockResetRequired: true,
      networkResetRequired: true,
      rngReseedingRequired: true,
      vmGenIdHandling: 'FIRECRACKER_LOAD_UPDATES',
      credentialAbsence: {
        taskStateEmpty: false,
        guestTokenCleared: false,
        guestIdentityCleared: false,
        hostTokenAbsent: false,
        diskTokenAbsent: false,
        verifiedAt: null,
        verificationDigest: null,
      },
      expiresAt,
      revokedAt: null,
      error: null,
      now,
    });
    store.createSnapshot(snapshot);
    const ready = store.transitionSnapshot(snapshot.snapshotId, 'READY', {
      writableDiskDigest: digest('a'),
      memoryDigest: digest('b'),
      vmStateDigest: digest('c'),
      credentialAbsence: {
        taskStateEmpty: true,
        guestTokenCleared: true,
        guestIdentityCleared: true,
        hostTokenAbsent: true,
        diskTokenAbsent: true,
        verifiedAt: now,
        verificationDigest: digest('d'),
      },
    });
    assert.equal(verifySnapshotRecord(ready).valid, true);

    const poolClaim = store.claimPool(ownerPrincipal, 'pool-unit-0001', digest('e'));
    assert.equal(poolClaim.replayed, false);
    const pool = initialPoolRecord({ poolId: poolClaim.poolId, ownerPrincipal, snapshotId: ready.snapshotId, desiredWarmCount: 1, expiresAt, now });
    store.createPool(pool);
    const healthy = store.updatePool(pool.poolId, {
      status: 'HEALTHY',
      availableVmIds: ['mvm_fedcba9876543210fedcba9876543210'],
      health: { ok: true, availableCount: 1, leasedCount: 0, failedCount: 0 },
    });
    assert.equal(verifyPoolRecord(healthy).valid, true);
    assert.throws(() => store.updatePool(pool.poolId, { maximumWarmCount: 2 }), (error) => error.code === 'microvm_ambiguous');

    const restarted = new SnapshotPoolStore(root, { now: () => now });
    assert.equal(restarted.getSnapshot(ready.snapshotId).recordDigest, ready.recordDigest);
    assert.equal(restarted.getPool(healthy.poolId).recordDigest, healthy.recordDigest);
    assert.deepEqual(restarted.verify(), {
      ok: true,
      snapshots: 1,
      pools: 1,
      corruptSnapshotIds: [],
      corruptPoolIds: [],
      invalidSnapshots: [],
      invalidPools: [],
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('microVM record and event chains remain valid across transitions and restart', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-microvm-store-'));
  try {
    const record = initial();
    assert.deepEqual(verifyMicrovmRecord(record), { valid: true, errors: [] });
    let sequence = 0;
    const now = () => `2026-07-28T00:00:${String(sequence++).padStart(2, '0')}.000Z`;
    const store = new MicrovmRecordStore(root, now);
    store.create(record);
    store.transition(record.vmId, 'PREPARING', 'PREPARE', {}, { phase: 'prepare' });
    store.transition(record.vmId, 'STARTING', 'START', {}, { phase: 'start' });
    store.transition(record.vmId, 'BOOTING', 'PROCESS_READY', {
      processIdentity: {
        pid: 1234,
        processStartTime: '987654',
        executablePath: '/opt/firecracker',
        executableDigest: digest('f'),
      },
      cgroup: '0::/system.slice/test.service',
    }, { pid: 1234 });
    const ready = store.transition(record.vmId, 'READY', 'GUEST_READY', { guestBootId: '22222222-2222-4222-8222-222222222222', guestAgentState: 'READY' }, { guestBootId: '22222222-2222-4222-8222-222222222222' });
    assert.equal(ready.sequence, 5);
    assert.equal(verifyMicrovmRecord(ready).valid, true);
    const events = store.eventsFor(record.vmId);
    assert.equal(events.length, 5);
    for (let index = 0; index < events.length; index += 1) {
      assert.equal(verifyMicrovmEvent(events[index]).valid, true);
      assert.equal(events[index].sequence, index + 1);
      assert.equal(events[index].priorEventDigest, index === 0 ? null : events[index - 1].eventDigest);
    }
    const restarted = new MicrovmRecordStore(root);
    assert.equal(restarted.get(record.vmId).recordDigest, ready.recordDigest);
    assert.deepEqual(restarted.reconcileIntegrity(), {
      ok: true,
      records: 1,
      events: 5,
      corruptRecordIds: [],
      corruptEventIds: [],
      invalidRecords: [],
      invalidEvents: [],
    });
    const persisted = JSON.parse(readFileSync(join(root, 'root-platform/microvm/vms/records', `${record.vmId}.json`), 'utf8'));
    assert.equal(persisted.recordDigest, ready.recordDigest);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});


test('microVM asset registry rejects binary, root-image, and symlink substitution', { skip: existsSync(process.env.BABY_X_MICROVM_ASSET_ROOT ?? '') ? false : 'requires provisioned exact microVM assets' }, () => {
  const sourceRoot = process.env.BABY_X_MICROVM_ASSET_ROOT;
  const source = new MicrovmArtifactRegistry(sourceRoot).load();
  const root = mkdtempSync(join(tmpdir(), 'baby-x-microvm-assets-'));
  try {
    mkdirSync(join(root, 'bin'), { recursive: true });
    mkdirSync(join(root, 'images'), { recursive: true });
    const mappings = [
      ['firecrackerPath', 'bin/firecracker-v1.15.1-x86_64'],
      ['jailerPath', 'bin/jailer-v1.15.1-x86_64'],
      ['kernelPath', 'images/vmlinux-6.1.155'],
      ['baseRootImagePath', 'images/baby-x-rootfs-v1.ext4'],
      ['guestAgentPath', 'bin/baby-x-microvm-guest-agent'],
    ];
    const unsigned = { ...source };
    delete unsigned.resolvedManifestDigest;
    for (const [key, relative] of mappings) {
      const destination = join(root, relative);
      copyFileSync(source[key], destination);
      unsigned[key] = destination;
    }
    const writeManifest = () => writeFileSync(join(root, 'resolved-manifest.json'), `${canonicalize({ ...unsigned, resolvedManifestDigest: sha256(canonicalize(unsigned)) })}\n`);
    writeManifest();
    assert.equal(new MicrovmArtifactRegistry(root).load().firecrackerDigest, source.firecrackerDigest);

    writeFileSync(unsigned.firecrackerPath, 'substituted-firecracker');
    assert.throws(() => new MicrovmArtifactRegistry(root).load(), (error) => error.code === 'microvm_asset_integrity_failure' && /Firecracker binary digest mismatch/u.test(error.message));
    copyFileSync(source.firecrackerPath, unsigned.firecrackerPath);

    writeFileSync(unsigned.baseRootImagePath, 'substituted-root-image');
    assert.throws(() => new MicrovmArtifactRegistry(root).load(), (error) => error.code === 'microvm_asset_integrity_failure' && /base root image digest mismatch/u.test(error.message));
    copyFileSync(source.baseRootImagePath, unsigned.baseRootImagePath);

    rmSync(unsigned.guestAgentPath);
    symlinkSync(source.guestAgentPath, unsigned.guestAgentPath);
    assert.throws(() => new MicrovmArtifactRegistry(root).load(), (error) => error.code === 'microvm_asset_integrity_failure' && /escapes the provider asset root/u.test(error.message));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('microVM startup ignores a transient pre-exec MainPID but accepts only the expected executable digest', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-microvm-startup-race-'));
  const child = spawn('/usr/bin/sleep', ['30'], { stdio: 'ignore' });
  try {
    assert.ok(child.pid);
    const expectedPath = realpathSync('/usr/bin/sleep');
    const expectedDigest = sha256(readFileSync(expectedPath));
    let observations = 0;
    const run = (_command, args) => {
      if (args[0] === 'show') {
        observations += 1;
        return { status: 0, stdout: `${observations === 1 ? process.pid : child.pid}\n`, stderr: '' };
      }
      return { status: 0, stdout: '', stderr: '' };
    };
    const { FirecrackerMicrovmProvider } = await import('../../dist/runtime/root-platform/microvm/provider.js');
    const provider = new FirecrackerMicrovmProvider({ stateRoot: root, assetRoot: root, run });
    const identity = await provider.waitForProcess('baby-x-microvm-startup-race.service', expectedDigest);
    assert.equal(identity.pid, child.pid);
    assert.equal(identity.executablePath, expectedPath);
    assert.equal(identity.executableDigest, expectedDigest);
    assert.ok(observations >= 2);
  } finally {
    child.kill('SIGKILL');
    rmSync(root, { recursive: true, force: true });
  }
});

test('microVM reconciliation stops provider-owned orphan units without inventing records', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-microvm-orphan-'));
  let active = true;
  const calls = [];
  const run = (command, args) => {
    calls.push([command, ...args]);
    if (args[0] === 'list-units') return { status: 0, stdout: 'baby-x-microvm-0123456789abcdef0123456789abcdef.service loaded active running orphan\n', stderr: '' };
    if (args[0] === 'stop') { active = false; return { status: 0, stdout: '', stderr: '' }; }
    if (args[0] === 'is-active') return { status: active ? 0 : 3, stdout: active ? 'active\n' : 'inactive\n', stderr: '' };
    if (args[0] === 'kill') { active = false; return { status: 0, stdout: '', stderr: '' }; }
    return { status: 0, stdout: '', stderr: '' };
  };
  try {
    const { FirecrackerMicrovmProvider } = await import('../../dist/runtime/root-platform/microvm/provider.js');
    const provider = new FirecrackerMicrovmProvider({ stateRoot: root, assetRoot: root, run });
    const result = await provider.reconcile();
    assert.deepEqual(result.orphanUnits, ['baby-x-microvm-0123456789abcdef0123456789abcdef.service']);
    assert.equal(result.ok, true);
    assert.equal(result.integrity.records, 0);
    assert.ok(calls.some((argv) => argv[1] === 'stop'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
