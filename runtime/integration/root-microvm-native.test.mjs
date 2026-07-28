import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { existsSync, mkdtempSync, readFileSync, readlinkSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { BabyXRuntime } from '../../dist/runtime/core.js';
import { MicrovmArtifactRegistry } from '../../dist/runtime/root-platform/microvm/artifacts.js';
import { RootProviderClient } from '../../dist/runtime/root-platform/microvm/provider-client.js';
import { startRootProviderServer } from '../../dist/runtime/root-platform/microvm/provider-server.js';
import { FirecrackerMicrovmProvider } from '../../dist/runtime/root-platform/microvm/provider.js';
import { guestCall } from '../../dist/runtime/root-platform/microvm/vsock.js';

const assetRoot = resolve(process.env.BABY_X_MICROVM_ASSET_ROOT ?? '.baby-x-test-assets');
const livePrerequisites = process.getuid?.() === 0 && existsSync('/run/systemd/system') && existsSync('/dev/kvm') && existsSync('/dev/vhost-vsock') && existsSync(join(assetRoot, 'resolved-manifest.json'));
const context = (idempotencyKey) => ({ subject: 'owner:microvm-native', authorityClass: 'unrestricted-owner', idempotencyKey });
const sleep = (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));

async function closeServer(server) {
  if (!server.listening) return;
  server.close();
  await once(server, 'close');
}

function active(unit) {
  return spawnSync('/usr/bin/systemctl', ['is-active', '--quiet', unit]).status === 0;
}

async function stopAndReset(unit) {
  spawnSync('/usr/bin/systemctl', ['stop', unit], { encoding: 'utf8' });
  for (let index = 0; index < 100 && active(unit); index += 1) await sleep(25);
  spawnSync('/usr/bin/systemctl', ['reset-failed', unit], { encoding: 'utf8' });
}

test('cold-boot Firecracker provider preserves identity across restart and classifies crash before cleanup', { skip: livePrerequisites ? false : 'requires root, systemd, KVM, vhost-vsock, and provisioned exact assets', timeout: 120_000 }, async () => {
  const stateRoot = mkdtempSync(join(tmpdir(), 'baby-x-microvm-native-'));
  const socketPath = join(stateRoot, 'root-provider.sock');
  const runtimeRoot = join(tmpdir(), `bxm-${basename(stateRoot).slice(-6)}`);
  const priorSocket = process.env.BABY_X_ROOT_PROVIDER_SOCKET;
  const priorState = process.env.BABY_X_STATE_ROOT;
  const priorAssets = process.env.BABY_X_MICROVM_ASSET_ROOT;
  process.env.BABY_X_ROOT_PROVIDER_SOCKET = socketPath;
  process.env.BABY_X_STATE_ROOT = stateRoot;
  process.env.BABY_X_MICROVM_ASSET_ROOT = assetRoot;
  let server;
  const units = new Set();
  try {
    const artifacts = new MicrovmArtifactRegistry(assetRoot).load();
    let provider = new FirecrackerMicrovmProvider({ stateRoot, assetRoot, runtimeRoot });
    server = startRootProviderServer(provider, { socketPath, allowedUid: process.getuid(), listen: { path: socketPath } });
    await once(server, 'listening');
    const options = { stateRoot, sourceCommit: 'a'.repeat(40), sourceTree: 'b'.repeat(40) };
    const runtime = new BabyXRuntime(options);
    const request = {
      transactionId: 'rtx_microvm_native_0001',
      skillBundleDigest: '1'.repeat(64),
      grantDigest: '2'.repeat(64),
      policyDigest: '3'.repeat(64),
      firecrackerVersion: 'v1.15.1',
      kernelDigest: artifacts.kernelDigest,
      rootImageDigest: artifacts.baseRootImageDigest,
      vcpuCount: 1,
      memoryMiB: 128,
      networkMode: 'NONE',
    };
    const created = await runtime.execute('babyx.root.microvm.create', request, context('microvm-native-create-0001'));
    units.add(created.microvm.systemdUnit);
    assert.equal(created.replayed, false);
    assert.equal(created.microvm.lifecycle, 'READY');
    assert.equal(created.microvm.networkMode, 'NONE');
    assert.match(created.microvm.guestBootId, /^[a-f0-9-]{36}$/u);
    const replay = await runtime.execute('babyx.root.microvm.create', request, context('microvm-native-create-0001'));
    assert.equal(replay.replayed, true);
    assert.equal(replay.microvm.vmId, created.microvm.vmId);
    const echoed = await runtime.execute('babyx.root.microvm.exec', { vmId: created.microvm.vmId, action: 'ECHO', taskId: 'task_echo_0001', input: 'sovereign-root' }, context('microvm-native-echo-0001'));
    assert.equal(echoed.task.output, 'sovereign-root');
    const sleeping = await runtime.execute('babyx.root.microvm.exec', { vmId: created.microvm.vmId, action: 'SLEEP', taskId: 'task_sleep_0001', durationMs: 5_000 }, context('microvm-native-sleep-0001'));
    assert.equal(sleeping.task.state, 'RUNNING');
    await runtime.execute('babyx.root.microvm.exec', { vmId: created.microvm.vmId, action: 'CANCEL', taskId: 'task_sleep_0001' }, context('microvm-native-cancel-0001'));
    await sleep(100);
    const status = await runtime.execute('babyx.root.microvm.exec', { vmId: created.microvm.vmId, action: 'STATUS', taskId: 'task_sleep_0001' }, context('microvm-native-status-0001'));
    assert.equal(status.task.state, 'CANCELLED');
    await assert.rejects(() => guestCall(created.microvm.vsockSocketIdentity, 'f'.repeat(64), 'HEALTH'), (error) => error.code === 'microvm_guest_authentication_failed');
    await assert.rejects(() => runtime.execute('babyx.root.microvm.create', { ...request, kernelDigest: '0'.repeat(64) }, context('microvm-native-bad-kernel-0001')), (error) => error.code === 'microvm_asset_integrity_failure');

    const processBeforeRestart = created.microvm.processIdentity;
    const guestBootBeforeRestart = created.microvm.guestBootId;
    await closeServer(server);
    provider = new FirecrackerMicrovmProvider({ stateRoot, assetRoot, runtimeRoot });
    const restartObservation = await provider.reconcile();
    assert.ok(restartObservation.healthy.includes(created.microvm.vmId));
    server = startRootProviderServer(provider, { socketPath, allowedUid: process.getuid(), listen: { path: socketPath } });
    await once(server, 'listening');
    const restartedRuntime = new BabyXRuntime(options);
    const adopted = (await restartedRuntime.execute('babyx.root.microvm.get', { vmId: created.microvm.vmId }, context('microvm-native-get-after-restart-0001'))).microvm;
    assert.deepEqual(adopted.processIdentity, processBeforeRestart);
    assert.equal(adopted.guestBootId, guestBootBeforeRestart);

    const second = await restartedRuntime.execute('babyx.root.microvm.create', { ...request, transactionId: 'rtx_microvm_native_0002' }, context('microvm-native-create-0002'));
    units.add(second.microvm.systemdUnit);
    const recordedProcess = second.microvm.processIdentity;
    assert.ok(recordedProcess);
    const observedExecutable = readlinkSync(`/proc/${recordedProcess.pid}/exe`);
    const observedDigest = createHash('sha256').update(readFileSync(observedExecutable)).digest('hex');
    assert.equal(observedExecutable, recordedProcess.executablePath);
    assert.equal(observedDigest, recordedProcess.executableDigest);
    process.kill(recordedProcess.pid, 'SIGKILL');
    for (let index = 0; index < 200 && existsSync(`/proc/${recordedProcess.pid}`); index += 1) await sleep(25);
    const crashObservation = await new RootProviderClient(socketPath).call('reconcile', {}, context('microvm-native-crash-reconcile-0001'));
    assert.ok(crashObservation.lost.includes(second.microvm.vmId));
    const lost = (await restartedRuntime.execute('babyx.root.microvm.get', { vmId: second.microvm.vmId }, context('microvm-native-lost-get-0001'))).microvm;
    assert.equal(lost.lifecycle, 'LOST');
    assert.equal(lost.error.code, 'microvm_process_identity_conflict');
    const lostCleaned = (await restartedRuntime.execute('babyx.root.microvm.remove', { vmId: second.microvm.vmId }, context('microvm-native-lost-remove-0001'))).microvm;
    assert.equal(lostCleaned.lifecycle, 'CLEANED');
    assert.deepEqual({ processAbsent: lostCleaned.cleanup.processAbsent, socketAbsent: lostCleaned.cleanup.socketAbsent, writableLayerAbsent: lostCleaned.cleanup.writableLayerAbsent }, { processAbsent: true, socketAbsent: true, writableLayerAbsent: true });

    const stopped = (await restartedRuntime.execute('babyx.root.microvm.stop', { vmId: created.microvm.vmId }, context('microvm-native-stop-0001'))).microvm;
    assert.equal(stopped.lifecycle, 'STOPPED');
    const cleaned = (await restartedRuntime.execute('babyx.root.microvm.remove', { vmId: created.microvm.vmId }, context('microvm-native-remove-0001'))).microvm;
    assert.equal(cleaned.lifecycle, 'CLEANED');
    assert.deepEqual({ processAbsent: cleaned.cleanup.processAbsent, socketAbsent: cleaned.cleanup.socketAbsent, writableLayerAbsent: cleaned.cleanup.writableLayerAbsent }, { processAbsent: true, socketAbsent: true, writableLayerAbsent: true });
    const records = readdirSync(join(stateRoot, 'root-platform/microvm/vms/records')).map((name) => JSON.parse(readFileSync(join(stateRoot, 'root-platform/microvm/vms/records', name), 'utf8')));
    assert.equal(records.every((record) => record.lifecycle === 'CLEANED'), true);
  } finally {
    if (server) await closeServer(server);
    for (const unit of units) await stopAndReset(unit);
    if (priorSocket === undefined) delete process.env.BABY_X_ROOT_PROVIDER_SOCKET; else process.env.BABY_X_ROOT_PROVIDER_SOCKET = priorSocket;
    if (priorState === undefined) delete process.env.BABY_X_STATE_ROOT; else process.env.BABY_X_STATE_ROOT = priorState;
    if (priorAssets === undefined) delete process.env.BABY_X_MICROVM_ASSET_ROOT; else process.env.BABY_X_MICROVM_ASSET_ROOT = priorAssets;
    rmSync(stateRoot, { recursive: true, force: true });
    rmSync(runtimeRoot, { recursive: true, force: true });
  }
});
