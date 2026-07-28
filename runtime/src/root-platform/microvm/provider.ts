import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { arch, cpus } from 'node:os';
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, readlinkSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import { MicrovmArtifactRegistry } from './artifacts.ts';
import { MicrovmError } from './errors.ts';
import { firecrackerApi } from './firecracker-api.ts';
import { initialMicrovmRecord, MicrovmRecordStore, type MicrovmProcessIdentity, type MicrovmRecord } from './records.ts';
import { createRequestDigest, normalizeCreateRequest, normalizeExecRequest, normalizeListRequest, normalizePoolRequest, normalizeRestoreRequest, normalizeSnapshotRequest, normalizeVmSelector, type MicrovmCreateRequest, type MicrovmExecAction, type MicrovmRestoreRequest } from './schemas.ts';
import { initialPoolRecord, initialSnapshotRecord, SnapshotPoolStore, type MicrovmPoolRecord, type MicrovmSnapshotRecord } from './snapshot-store.ts';
import { guestBootstrap, guestCall, type GuestResponse } from './vsock.ts';

interface ProviderContext extends JsonObject { ownerPrincipal: string; idempotencyKey: string }
interface CommandResult { status: number | null; stdout: string; stderr: string }
type CommandRunner = (command: string, args: string[], timeoutMs?: number) => CommandResult;

function defaultRun(command: string, args: string[], timeoutMs = 30_000): CommandResult {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 4_194_304 });
  return { status: result.status, stdout: String(result.stdout ?? ''), stderr: String(result.stderr ?? result.error?.message ?? '') };
}
function requireSuccess(result: CommandResult, code: 'microvm_provider_unavailable' | 'microvm_cleanup_failed', message: string): void {
  if (result.status !== 0) throw new MicrovmError(code, message, { status: result.status, stderrDigest: sha256(result.stderr.slice(0, 4096)) });
}
function readHostBootId(): string { return readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(); }
function processStartTime(pid: number): string { const stat = readFileSync(`/proc/${pid}/stat`, 'utf8'); const rest = stat.slice(stat.lastIndexOf(')') + 2).split(' '); return rest[19] ?? ''; }
function processCgroup(pid: number): string { return readFileSync(`/proc/${pid}/cgroup`, 'utf8').trim().slice(0, 4096); }
function executableDigest(path: string): string { return sha256(readFileSync(path)); }
function sleep(ms: number): Promise<void> { return new Promise((resolve) => setTimeout(resolve, ms)); }
function owner(context: ProviderContext): string {
  if (typeof context.ownerPrincipal !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(context.ownerPrincipal)) throw new MicrovmError('microvm_invalid_request', 'owner principal is invalid');
  return context.ownerPrincipal;
}
function boundedIdempotency(context: ProviderContext): string {
  if (typeof context.idempotencyKey !== 'string' || context.idempotencyKey.length < 8 || context.idempotencyKey.length > 256 || context.idempotencyKey.includes('\0')) throw new MicrovmError('microvm_invalid_request', 'a bounded idempotency key is required');
  return context.idempotencyKey;
}
function tokenPath(vmRoot: string): string { return join(vmRoot, 'guest.token'); }
function cpuFingerprint(): string {
  const cpu = cpus()[0];
  const flags = existsSync('/proc/cpuinfo') ? (readFileSync('/proc/cpuinfo', 'utf8').match(/^flags\s*:\s*(.*)$/mu)?.[1] ?? '') : '';
  return sha256(canonicalize({ architecture: arch(), model: cpu?.model ?? 'unknown', flags: flags.split(/\s+/u).filter(Boolean).sort() }));
}
function identityDigest(response: GuestResponse, key: 'workloadIdentity' | 'randomEpoch'): string {
  const value = response[key];
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/u.test(value)) throw new MicrovmError('microvm_guest_protocol_failed', `guest ${key} is invalid`);
  return sha256(value);
}

export class FirecrackerMicrovmProvider {
  readonly store: MicrovmRecordStore;
  readonly artifacts: MicrovmArtifactRegistry;
  readonly snapshotPools: SnapshotPoolStore;
  private readonly root: string;
  private readonly runtimeRoot: string;
  private readonly snapshotRoot: string;
  private readonly run: CommandRunner;
  private readonly now: () => string;

  constructor(options: { stateRoot: string; assetRoot?: string; runtimeRoot?: string; run?: CommandRunner; now?: () => string }) {
    this.root = join(options.stateRoot, 'root-platform', 'microvm', 'instances');
    this.runtimeRoot = options.runtimeRoot ?? process.env.BABY_X_MICROVM_RUNTIME_ROOT ?? '/run/baby-x/microvm';
    this.snapshotRoot = join(options.stateRoot, 'root-platform', 'microvm', 'snapshot-data');
    mkdirSync(this.root, { recursive: true, mode: 0o700 });
    mkdirSync(this.runtimeRoot, { recursive: true, mode: 0o700 });
    mkdirSync(this.snapshotRoot, { recursive: true, mode: 0o700 });
    this.store = new MicrovmRecordStore(options.stateRoot, { now: options.now });
    this.snapshotPools = new SnapshotPoolStore(options.stateRoot, { now: options.now });
    this.artifacts = new MicrovmArtifactRegistry(options.assetRoot);
    this.run = options.run ?? defaultRun;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  describe(): JsonObject {
    return {
      providerId: 'firecracker-cold-boot', implementationVersion: '1.1.0', contractVersion: 'microvm-provider@1', artifact: this.artifacts.probe(), networkDefault: 'NONE', guestProtocol: 'BABYX-GUEST/1.0.0',
      snapshotSupport: { full: true, diff: false, sourceIsDestroyed: true, vmGenIdUpdatedByFirecracker: true, inheritedGuestCid: true },
      poolSupport: { maximumWarmCount: 1, limitation: 'Firecracker v1.15.1 snapshot guest CID cannot be rewritten; instances are one-time and destroyed on release' },
      operations: ['create', 'get', 'list', 'exec', 'stop', 'remove', 'snapshot', 'restore', 'poolReconcile', 'reconcile'],
    };
  }

  async create(payload: unknown, context: ProviderContext): Promise<JsonObject> {
    const ownerPrincipal = owner(context);
    const idempotencyKey = boundedIdempotency(context);
    const request = normalizeCreateRequest(payload);
    const artifacts = this.artifacts.load();
    if (request.kernelDigest !== artifacts.kernelDigest) throw new MicrovmError('microvm_asset_integrity_failure', 'requested kernel digest does not match the provider registry');
    if (request.rootImageDigest !== artifacts.baseRootImageDigest) throw new MicrovmError('microvm_asset_integrity_failure', 'requested root image digest does not match the provider registry');
    if (!existsSync('/dev/kvm') || !existsSync('/dev/vhost-vsock')) throw new MicrovmError('microvm_provider_unavailable', 'KVM and vhost-vsock are required');
    const requestDigest = createRequestDigest(ownerPrincipal, request);
    const claim = this.store.claim(ownerPrincipal, idempotencyKey, requestDigest);
    if (claim.replayed) return { microvm: this.store.get(claim.vmId), replayed: true };
    return this.coldCreate(claim.vmId, ownerPrincipal, request, requestDigest, idempotencyKey, artifacts);
  }

  private async coldCreate(vmId: string, ownerPrincipal: string, request: MicrovmCreateRequest, requestDigest: string, idempotencyKey: string, artifacts: ReturnType<MicrovmArtifactRegistry['load']>): Promise<JsonObject> {
    const vmRoot = join(this.root, vmId);
    const vmRuntimeRoot = join(this.runtimeRoot, vmId.slice(4));
    mkdirSync(vmRoot, { recursive: true, mode: 0o700 });
    mkdirSync(vmRuntimeRoot, { recursive: true, mode: 0o700 });
    const writable = join(vmRoot, 'rootfs.ext4');
    const runtimeDrivePath = join(vmRuntimeRoot, 'rootfs.ext4');
    copyFileSync(artifacts.baseRootImagePath, writable);
    symlinkSync(writable, runtimeDrivePath);
    const token = randomBytes(32).toString('hex');
    const tokenSource = join(vmRoot, 'token.source');
    writeFileSync(tokenSource, token, { mode: 0o600 });
    const debugfs = this.run('/usr/sbin/debugfs', ['-w', '-R', `write ${tokenSource} /etc/babyx-auth-token`, writable]);
    rmSync(tokenSource, { force: true });
    requireSuccess(debugfs, 'microvm_provider_unavailable', 'guest authentication injection failed');
    writeFileSync(tokenPath(vmRoot), token, { mode: 0o600 });
    const writableDigest = sha256(readFileSync(writable));
    const systemdUnit = `baby-x-microvm-${vmId.slice(4)}.service`;
    const vsockPath = join(vmRuntimeRoot, 'vsock.sock');
    const vsockCid = this.allocateVsockCid();
    const record = initialMicrovmRecord({ vmId, ownerPrincipal, request, requestDigest, idempotencyKey, artifacts: { firecrackerDigest: artifacts.firecrackerDigest, kernelDigest: artifacts.kernelDigest, rootImageDigest: artifacts.baseRootImageDigest, guestAgentDigest: artifacts.guestAgentDigest, guestAgentProtocol: artifacts.guestAgentProtocol }, writableLayerIdentity: writable, writableLayerDigest: writableDigest, systemdUnit, vsockCid, vsockSocketIdentity: vsockPath, hostBootId: readHostBootId(), now: this.now() });
    this.store.create(record);
    try {
      this.store.transition(vmId, 'PREPARING', 'PREPARE', {}, { vmRootDigest: sha256(vmRoot), runtimeRootDigest: sha256(vmRuntimeRoot) });
      const configPath = join(vmRuntimeRoot, 'firecracker.json');
      const apiPath = join(vmRuntimeRoot, 'api.sock');
      const logPath = join(vmRuntimeRoot, 'firecracker.log');
      const config = { 'boot-source': { kernel_image_path: artifacts.kernelPath, boot_args: 'console=ttyS0 reboot=k panic=1 pci=off nomodules random.trust_cpu=on root=/dev/vda rw init=/sbin/init' }, drives: [{ drive_id: 'rootfs', path_on_host: 'rootfs.ext4', is_root_device: true, is_read_only: false, cache_type: 'Unsafe' }], 'machine-config': { vcpu_count: request.vcpuCount, mem_size_mib: request.memoryMiB, smt: false }, vsock: { guest_cid: vsockCid, uds_path: 'vsock.sock' } };
      writeFileSync(configPath, `${canonicalize(config as JsonObject)}\n`, { mode: 0o600 });
      writeFileSync(logPath, '', { mode: 0o600 });
      this.store.transition(vmId, 'STARTING', 'START', {}, { configDigest: sha256(canonicalize(config as JsonObject)) });
      const start = this.run('/usr/bin/systemd-run', ['--quiet', `--unit=${systemdUnit}`, '--property=Type=simple', '--property=KillMode=mixed', '--property=TimeoutStopSec=10s', '--property=PrivateNetwork=yes', '--property=NoNewPrivileges=no', `--property=WorkingDirectory=${vmRuntimeRoot}`, artifacts.firecrackerPath, '--id', vmId.slice(4), '--api-sock', 'api.sock', '--config-file', 'firecracker.json', '--log-path', 'firecracker.log', '--level', 'Info'], 30_000);
      requireSuccess(start, 'microvm_provider_unavailable', 'Firecracker process could not be started');
      const identity = await this.waitForProcess(systemdUnit, artifacts.firecrackerDigest);
      this.store.transition(vmId, 'BOOTING', 'PROCESS_READY', { processIdentity: identity, cgroup: processCgroup(identity.pid) }, { pid: identity.pid, processStartTime: identity.processStartTime });
      const health = await this.waitForGuest(vsockPath, token, 10_000);
      const guestBootId = typeof health.bootId === 'string' ? health.bootId : null;
      const ready = this.store.transition(vmId, 'READY', 'GUEST_READY', { guestAgentState: 'READY', guestBootId, workloadIdentityDigest: identityDigest(health, 'workloadIdentity'), randomEpochDigest: identityDigest(health, 'randomEpoch') }, { healthDigest: sha256(canonicalize(health as JsonObject)) });
      return { microvm: ready, replayed: false };
    } catch (error) {
      const code = error instanceof MicrovmError ? error.code : 'microvm_provider_unavailable';
      const message = error instanceof Error ? error.message : String(error);
      try { this.store.transition(vmId, 'FAILED', 'CREATE_FAILED', { guestAgentState: 'FAILED', error: { code, message, phase: 'create' }, cleanup: { requested: true, completed: false, processAbsent: false, socketAbsent: false, writableLayerAbsent: false, completedAt: null } }, { code }); } catch {}
      await this.cleanupEffects(record, true);
      try { this.store.transition(vmId, 'FAILED', 'CREATE_FAILURE_CLEANED', { cleanup: { requested: true, completed: true, processAbsent: !this.unitActive(record.systemdUnit), socketAbsent: !existsSync(record.vsockSocketIdentity), writableLayerAbsent: !existsSync(record.writableLayerIdentity), completedAt: this.now() } }, { code }); } catch {}
      throw error;
    }
  }

  get(payload: unknown, context: ProviderContext): JsonObject { const { vmId } = normalizeVmSelector(payload); return { microvm: this.owned(vmId, owner(context)) }; }
  list(payload: unknown, context: ProviderContext): JsonObject { const filters = normalizeListRequest(payload); const ownerPrincipal = owner(context); return this.store.list({ ...filters, ownerPrincipal: filters.ownerPrincipal ?? ownerPrincipal }); }

  async exec(payload: unknown, context: ProviderContext): Promise<JsonObject> {
    const { vmId, request } = normalizeExecRequest(payload);
    let record = this.owned(vmId, owner(context));
    if (record.lifecycle !== 'READY' && record.lifecycle !== 'RUNNING') throw new MicrovmError('microvm_state_conflict', 'microVM is not ready for execution', { lifecycle: record.lifecycle });
    this.assertProcess(record);
    const token = readFileSync(tokenPath(join(this.root, vmId)), 'utf8').trim();
    const response = await guestCall(record.vsockSocketIdentity, token, this.guestCommand(request), request.action === 'SLEEP' ? 5_000 : 10_000);
    if (request.action === 'SLEEP' && response.ok === true && response.state === 'RUNNING') record = this.store.transition(vmId, 'RUNNING', 'TASK_STARTED', {}, { taskId: request.taskId });
    if (request.action === 'STATUS' && (response.state === 'COMPLETED' || response.state === 'CANCELLED' || response.state === 'FAILED') && record.lifecycle === 'RUNNING') record = this.store.transition(vmId, 'READY', 'TASK_TERMINAL', {}, { taskId: request.taskId, state: String(response.state) });
    const publicResponse = { ...response };
    if (typeof publicResponse.resultHex === 'string') { publicResponse.output = Buffer.from(publicResponse.resultHex, 'hex').toString('utf8'); delete publicResponse.resultHex; }
    return { vmId, task: publicResponse, microvmSequence: record.sequence };
  }

  async snapshot(payload: unknown, context: ProviderContext): Promise<JsonObject> {
    const ownerPrincipal = owner(context);
    const idempotencyKey = boundedIdempotency(context);
    const request = normalizeSnapshotRequest(payload, new Date(this.now()));
    const requestDigest = sha256(canonicalize({ operation: 'babyx.root.microvm.snapshot', ownerPrincipal, request }));
    const claim = this.snapshotPools.claimSnapshot(ownerPrincipal, idempotencyKey, requestDigest);
    if (claim.replayed) {
      const snapshot = this.snapshotPools.getSnapshot(claim.snapshotId);
      return { snapshot, sourceMicrovm: this.store.get(snapshot.sourceVmId), replayed: true };
    }
    const source = this.owned(request.vmId, ownerPrincipal);
    if (source.lifecycle !== 'READY') throw new MicrovmError('microvm_state_conflict', 'only an idle READY microVM can become a snapshot template', { lifecycle: source.lifecycle });
    this.assertProcess(source);
    const snapshotId = claim.snapshotId;
    const dataRoot = join(this.snapshotRoot, snapshotId);
    mkdirSync(dataRoot, { recursive: true, mode: 0o700 });
    const memoryPath = join(dataRoot, 'memory.bin');
    const vmStatePath = join(dataRoot, 'vmstate.bin');
    const diskPath = join(dataRoot, 'rootfs.ext4');
    const initial = initialSnapshotRecord({ snapshotId, ownerPrincipal, requestDigest, idempotencyKeyDigest: sha256(idempotencyKey), sourceVmId: source.vmId, sourceTransactionId: source.transactionId, providerVersion: 'firecracker-v1.15.1+babyx-provider-1.1.0', firecrackerDigest: source.firecrackerDigest, cpuArchitecture: arch(), cpuFingerprint: cpuFingerprint(), kernelDigest: source.kernelDigest, baseRootImageDigest: source.rootImageDigest, writableDiskDigest: null, memoryDigest: null, vmStateDigest: null, memoryPath, vmStatePath, diskPath, guestCid: source.vsockCid, vcpuCount: source.vcpuCount, memoryMiB: source.memoryMiB, skillBundleDigest: source.skillBundleDigest, grantDigest: source.grantDigest, policyDigest: source.policyDigest, vsockResetRequired: true, networkResetRequired: true, rngReseedingRequired: true, vmGenIdHandling: 'FIRECRACKER_LOAD_UPDATES', credentialAbsence: { taskStateEmpty: false, guestTokenCleared: false, guestIdentityCleared: false, hostTokenAbsent: false, diskTokenAbsent: false, verifiedAt: null, verificationDigest: null }, expiresAt: request.expiresAt, revokedAt: null, error: null, now: this.now() });
    this.snapshotPools.createSnapshot(initial);
    const vmRoot = join(this.root, source.vmId);
    const vmRuntimeRoot = join(this.runtimeRoot, source.vmId.slice(4));
    const tokenFile = tokenPath(vmRoot);
    const token = readFileSync(tokenFile, 'utf8').trim();
    const apiSocket = join(vmRuntimeRoot, 'api.sock');
    let paused = false;
    try {
      const prepared = await guestCall(source.vsockSocketIdentity, token, 'PREPARE_SNAPSHOT', 5_000);
      if (prepared.ok !== true || prepared.taskStateEmpty !== true || prepared.credentialCleared !== true || prepared.identityCleared !== true) throw new MicrovmError('microvm_state_conflict', 'guest refused snapshot preparation', { responseDigest: sha256(canonicalize(prepared as JsonObject)) });
      if (!this.diskTokenAbsent(source.writableLayerIdentity)) throw new MicrovmError('microvm_state_conflict', 'guest token remains in the writable disk');
      await firecrackerApi(apiSocket, 'PATCH', '/vm', { state: 'Paused' });
      paused = true;
      await firecrackerApi(apiSocket, 'PUT', '/snapshot/create', { snapshot_type: 'Full', snapshot_path: vmStatePath, mem_file_path: memoryPath });
      copyFileSync(source.writableLayerIdentity, diskPath);
      chmodSync(memoryPath, 0o400); chmodSync(vmStatePath, 0o400); chmodSync(diskPath, 0o400);
      if (!this.diskTokenAbsent(diskPath)) throw new MicrovmError('microvm_state_conflict', 'snapshot disk contains a guest token');
      rmSync(tokenFile, { force: true });
      let sourceRecord = this.store.transition(source.vmId, 'STOPPING', 'SNAPSHOT_SOURCE_STOPPING', {}, { snapshotId });
      await this.stopUnit(source.systemdUnit);
      sourceRecord = this.store.transition(source.vmId, 'STOPPED', 'SNAPSHOT_SOURCE_STOPPED', { processIdentity: null, cgroup: '', guestAgentState: 'STOPPED' }, { snapshotId });
      sourceRecord = this.store.transition(source.vmId, 'CLEANING', 'SNAPSHOT_SOURCE_CLEANING', { cleanup: { ...sourceRecord.cleanup, requested: true } }, { snapshotId });
      rmSync(vmRoot, { recursive: true, force: true });
      rmSync(vmRuntimeRoot, { recursive: true, force: true });
      this.run('/usr/bin/systemctl', ['reset-failed', source.systemdUnit], 10_000);
      const cleanup = { requested: true, completed: true, processAbsent: !this.unitActive(source.systemdUnit), socketAbsent: !existsSync(source.vsockSocketIdentity), writableLayerAbsent: !existsSync(source.writableLayerIdentity), completedAt: this.now() };
      if (!cleanup.processAbsent || !cleanup.socketAbsent || !cleanup.writableLayerAbsent) throw new MicrovmError('microvm_cleanup_failed', 'snapshot source cleanup could not be verified', cleanup);
      this.store.transition(source.vmId, 'CLEANED', 'SNAPSHOT_SOURCE_CLEANED', { cleanup }, { snapshotId });
      const credentialAbsenceBase = { taskStateEmpty: true, guestTokenCleared: true, guestIdentityCleared: true, hostTokenAbsent: !existsSync(tokenFile), diskTokenAbsent: this.diskTokenAbsent(diskPath), verifiedAt: this.now() };
      const credentialAbsence = { ...credentialAbsenceBase, verificationDigest: sha256(canonicalize(credentialAbsenceBase)) };
      const ready = this.snapshotPools.transitionSnapshot(snapshotId, 'READY', { writableDiskDigest: sha256(readFileSync(diskPath)), memoryDigest: sha256(readFileSync(memoryPath)), vmStateDigest: sha256(readFileSync(vmStatePath)), credentialAbsence });
      return { snapshot: ready, sourceMicrovm: this.store.get(source.vmId), replayed: false };
    } catch (error) {
      if (paused && this.unitActive(source.systemdUnit)) {
        try { await firecrackerApi(apiSocket, 'PATCH', '/vm', { state: 'Resumed' }); } catch {}
        try { await guestBootstrap(source.vsockSocketIdentity, token, 5_000); } catch {}
      }
      const code = error instanceof MicrovmError ? error.code : 'microvm_provider_unavailable';
      const message = (error instanceof Error ? error.message : String(error)).slice(0, 512);
      try { this.snapshotPools.transitionSnapshot(snapshotId, 'FAILED', { error: { code, message } }); } catch {}
      if (!this.unitActive(source.systemdUnit)) await this.cleanupEffects(source, false);
      rmSync(dataRoot, { recursive: true, force: true });
      throw error;
    }
  }

  async restore(payload: unknown, context: ProviderContext): Promise<JsonObject> {
    const request = normalizeRestoreRequest(payload);
    return this.restoreInternal(request, context, null, 'NONE');
  }

  private async restoreInternal(request: MicrovmRestoreRequest, context: ProviderContext, poolId: string | null, leaseState: 'NONE' | 'AVAILABLE' | 'LEASED'): Promise<JsonObject> {
    const ownerPrincipal = owner(context);
    const idempotencyKey = boundedIdempotency(context);
    const snapshot = this.snapshotPools.getSnapshot(request.snapshotId);
    this.assertSnapshotUsable(snapshot, ownerPrincipal);
    const artifacts = this.artifacts.load();
    if (snapshot.firecrackerDigest !== artifacts.firecrackerDigest || snapshot.kernelDigest !== artifacts.kernelDigest || snapshot.baseRootImageDigest !== artifacts.baseRootImageDigest) throw new MicrovmError('microvm_asset_integrity_failure', 'snapshot provider artifacts are incompatible');
    if (snapshot.cpuArchitecture !== arch() || snapshot.cpuFingerprint !== cpuFingerprint()) throw new MicrovmError('microvm_asset_integrity_failure', 'snapshot CPU is incompatible with this host');
    this.verifySnapshotFiles(snapshot);
    const requestDigest = sha256(canonicalize({ operation: 'babyx.root.microvm.restore', ownerPrincipal, request, snapshotRecordDigest: snapshot.recordDigest, poolId, leaseState }));
    const claim = this.store.claim(ownerPrincipal, idempotencyKey, requestDigest);
    if (claim.replayed) return { microvm: this.store.get(claim.vmId), snapshot, replayed: true, coldFallback: false };
    const vmId = claim.vmId;
    const vmRoot = join(this.root, vmId);
    const vmRuntimeRoot = join(this.runtimeRoot, vmId.slice(4));
    mkdirSync(vmRoot, { recursive: true, mode: 0o700 });
    mkdirSync(vmRuntimeRoot, { recursive: true, mode: 0o700 });
    const writable = join(vmRoot, 'rootfs.ext4');
    copyFileSync(snapshot.diskPath, writable);
    chmodSync(writable, 0o600);
    symlinkSync(writable, join(vmRuntimeRoot, 'rootfs.ext4'));
    const token = randomBytes(32).toString('hex');
    writeFileSync(tokenPath(vmRoot), token, { mode: 0o600 });
    const systemdUnit = `baby-x-microvm-${vmId.slice(4)}.service`;
    const vsockPath = join(vmRuntimeRoot, 'vsock.sock');
    const createRequest: MicrovmCreateRequest = { transactionId: request.transactionId, skillBundleDigest: request.skillBundleDigest, grantDigest: request.grantDigest, policyDigest: request.policyDigest, firecrackerVersion: 'v1.15.1', kernelDigest: snapshot.kernelDigest, rootImageDigest: snapshot.baseRootImageDigest, vcpuCount: snapshot.vcpuCount, memoryMiB: snapshot.memoryMiB, networkMode: 'NONE' };
    const initialBase = initialMicrovmRecord({ vmId, ownerPrincipal, request: createRequest, requestDigest, idempotencyKey, artifacts: { firecrackerDigest: artifacts.firecrackerDigest, kernelDigest: artifacts.kernelDigest, rootImageDigest: artifacts.baseRootImageDigest, guestAgentDigest: artifacts.guestAgentDigest, guestAgentProtocol: artifacts.guestAgentProtocol }, writableLayerIdentity: writable, writableLayerDigest: sha256(readFileSync(writable)), systemdUnit, vsockCid: snapshot.guestCid, vsockSocketIdentity: vsockPath, hostBootId: readHostBootId(), now: this.now() });
    const { recordDigest: _initialDigest, ...initialUnsigned } = initialBase;
    const initial = { ...initialUnsigned, sourceSnapshotId: snapshot.snapshotId, poolId, leaseState, inheritedGuestCid: true, recordDigest: sha256(canonicalize({ ...initialUnsigned, sourceSnapshotId: snapshot.snapshotId, poolId, leaseState, inheritedGuestCid: true })) } as MicrovmRecord;
    this.store.create(initial);
    try {
      this.store.transition(vmId, 'PREPARING', 'RESTORE_PREPARING', {}, { snapshotId: snapshot.snapshotId });
      writeFileSync(join(vmRuntimeRoot, 'firecracker.log'), '', { mode: 0o600 });
      this.store.transition(vmId, 'STARTING', 'RESTORE_STARTING', {}, { snapshotId: snapshot.snapshotId });
      const start = this.run('/usr/bin/systemd-run', ['--quiet', `--unit=${systemdUnit}`, '--property=Type=simple', '--property=KillMode=mixed', '--property=TimeoutStopSec=10s', '--property=PrivateNetwork=yes', '--property=NoNewPrivileges=no', `--property=WorkingDirectory=${vmRuntimeRoot}`, artifacts.firecrackerPath, '--id', vmId.slice(4), '--api-sock', 'api.sock', '--log-path', 'firecracker.log', '--level', 'Info'], 30_000);
      requireSuccess(start, 'microvm_provider_unavailable', 'snapshot Firecracker process could not be started');
      const identity = await this.waitForProcess(systemdUnit, artifacts.firecrackerDigest);
      this.store.transition(vmId, 'BOOTING', 'RESTORE_PROCESS_READY', { processIdentity: identity, cgroup: processCgroup(identity.pid) }, { snapshotId: snapshot.snapshotId, pid: identity.pid });
      const apiSocket = join(vmRuntimeRoot, 'api.sock');
      await this.waitForPath(apiSocket, 10_000);
      await firecrackerApi(apiSocket, 'PUT', '/snapshot/load', { snapshot_path: snapshot.vmStatePath, mem_backend: { backend_type: 'File', backend_path: snapshot.memoryPath }, enable_diff_snapshots: false, resume_vm: true }, 20_000);
      await this.waitForPath(vsockPath, 10_000);
      const bootstrapped = await guestBootstrap(vsockPath, token, 10_000);
      const health = bootstrapped.ok === true ? bootstrapped : await this.waitForGuest(vsockPath, token, 10_000);
      const ready = this.store.transition(vmId, 'READY', 'SNAPSHOT_RESTORED', { guestAgentState: 'READY', guestBootId: typeof health.bootId === 'string' ? health.bootId : null, workloadIdentityDigest: identityDigest(health, 'workloadIdentity'), randomEpochDigest: identityDigest(health, 'randomEpoch'), sourceSnapshotId: snapshot.snapshotId, poolId, leaseState, inheritedGuestCid: true }, { snapshotId: snapshot.snapshotId, vmGenIdUpdated: true, newVsockSocketIdentity: vsockPath, inheritedGuestCid: snapshot.guestCid });
      return { microvm: ready, snapshot, replayed: false, coldFallback: false };
    } catch (error) {
      const code = error instanceof MicrovmError ? error.code : 'microvm_provider_unavailable';
      const message = error instanceof Error ? error.message : String(error);
      try { this.store.transition(vmId, 'FAILED', 'RESTORE_FAILED', { guestAgentState: 'FAILED', error: { code, message, phase: 'restore' } }, { snapshotId: snapshot.snapshotId, code }); } catch {}
      await this.cleanupEffects(initial, true);
      throw error;
    }
  }

  async poolReconcile(payload: unknown, context: ProviderContext): Promise<JsonObject> {
    const ownerPrincipal = owner(context);
    const idempotencyKey = boundedIdempotency(context);
    const action = normalizePoolRequest(payload, new Date(this.now()));
    const actionDigest = sha256(canonicalize({ operation: 'babyx.root.microvm.pool.reconcile', ownerPrincipal, action }));
    const priorAction = this.snapshotPools.getPoolAction(ownerPrincipal, idempotencyKey);
    if (priorAction !== undefined) {
      if (priorAction.requestDigest !== actionDigest) throw new MicrovmError('microvm_idempotency_conflict', 'idempotency key belongs to another pool action');
      const pool = this.snapshotPools.getPool(priorAction.record.poolId);
      const microvm = priorAction.record.vmId === null ? null : this.store.get(priorAction.record.vmId);
      return { pool, ...(microvm === null ? {} : { microvm }), replayed: true, action: priorAction.record.action };
    }
    if (action.action === 'RECONCILE') {
      const snapshot = this.snapshotPools.getSnapshot(action.snapshotId);
      this.assertSnapshotUsable(snapshot, ownerPrincipal);
      let pool: MicrovmPoolRecord;
      if (action.poolId === undefined) {
        const requestDigest = sha256(canonicalize({ operation: 'babyx.root.microvm.pool.reconcile', ownerPrincipal, action }));
        const claim = this.snapshotPools.claimPool(ownerPrincipal, context.idempotencyKey, requestDigest);
        if (claim.replayed) pool = this.snapshotPools.getPool(claim.poolId);
        else { pool = initialPoolRecord({ poolId: claim.poolId, ownerPrincipal, snapshotId: action.snapshotId, desiredWarmCount: action.desiredWarmCount, expiresAt: action.expiresAt, now: this.now() }); this.snapshotPools.createPool(pool); }
      } else {
        pool = this.snapshotPools.getPool(action.poolId);
        if (pool.ownerPrincipal !== ownerPrincipal || pool.snapshotId !== action.snapshotId) throw new MicrovmError('microvm_not_found', 'pool was not found for this owner and snapshot');
        pool = this.snapshotPools.updatePool(pool.poolId, { desiredWarmCount: action.desiredWarmCount, expiresAt: action.expiresAt, generation: pool.generation + 1 });
      }
      const result = await this.reconcilePool(pool);
      const returnedPool = result.pool as MicrovmPoolRecord;
      this.snapshotPools.claimPoolAction(ownerPrincipal, idempotencyKey, actionDigest, { action: 'RECONCILE', poolId: returnedPool.poolId, vmId: null });
      return { ...result, replayed: false };
    }
    if (action.action === 'ACQUIRE') {
      const result = await this.acquirePool(action.poolId, action, context);
      const microvm = result.microvm as MicrovmRecord;
      this.snapshotPools.claimPoolAction(ownerPrincipal, idempotencyKey, actionDigest, { action: 'ACQUIRE', poolId: action.poolId, vmId: microvm.vmId });
      return { ...result, replayed: false };
    }
    const result = await this.releasePool(action.poolId, action.vmId, context);
    this.snapshotPools.claimPoolAction(ownerPrincipal, idempotencyKey, actionDigest, { action: 'RELEASE', poolId: action.poolId, vmId: action.vmId });
    return { ...result, replayed: false };
  }

  private async reconcilePool(poolValue: MicrovmPoolRecord): Promise<JsonObject> {
    let pool = this.snapshotPools.getPool(poolValue.poolId);
    if (Date.parse(pool.expiresAt) <= Date.parse(this.now())) {
      for (const vmId of pool.availableVmIds) { try { await this.remove({ vmId }, { ownerPrincipal: pool.ownerPrincipal, idempotencyKey: `expire-${pool.poolId}-${vmId}` }); } catch {} }
      pool = this.snapshotPools.updatePool(pool.poolId, { status: 'EXPIRED', availableVmIds: [], health: { ok: false, reason: 'expired' } });
      return { pool, reconciled: true };
    }
    const available: string[] = [];
    let failedCount = pool.failedCount;
    for (const vmId of pool.availableVmIds) {
      try { const vm = this.store.get(vmId); this.assertProcess(vm); if (vm.lifecycle === 'READY' && vm.poolId === pool.poolId && vm.leaseState === 'AVAILABLE') available.push(vmId); else failedCount += 1; }
      catch { failedCount += 1; }
    }
    while (available.length > pool.desiredWarmCount) {
      const vmId = available.pop() as string;
      try { await this.remove({ vmId }, { ownerPrincipal: pool.ownerPrincipal, idempotencyKey: `pool-scale-down-${pool.poolId}-${pool.generation}-${vmId}` }); } catch { failedCount += 1; }
    }
    if (available.length < pool.desiredWarmCount && pool.leases.length === 0) {
      const snapshot = this.snapshotPools.getSnapshot(pool.snapshotId);
      try {
        const warmRequest: MicrovmRestoreRequest = { snapshotId: snapshot.snapshotId, transactionId: `rtx_pool_${pool.poolId.slice(4)}_${pool.generation}`, skillBundleDigest: snapshot.skillBundleDigest, grantDigest: snapshot.grantDigest, policyDigest: snapshot.policyDigest, networkMode: 'NONE' };
        const restored = await this.restoreInternal(warmRequest, { ownerPrincipal: pool.ownerPrincipal, idempotencyKey: `pool-warm-${pool.poolId}-${pool.generation}` }, pool.poolId, 'AVAILABLE');
        available.push(String((restored.microvm as MicrovmRecord).vmId));
      } catch { failedCount += 1; }
    }
    const healthy = available.length === pool.desiredWarmCount;
    pool = this.snapshotPools.updatePool(pool.poolId, { availableVmIds: available.sort(), failedCount, status: healthy ? 'HEALTHY' : 'DEGRADED', health: { ok: healthy, availableCount: available.length, leasedCount: pool.leases.length, failedCount, maximumWarmCountReason: 'firecracker_v1_15_snapshot_guest_cid_is_immutable' } });
    return { pool, reconciled: true };
  }

  private async acquirePool(poolId: string, action: Extract<ReturnType<typeof normalizePoolRequest>, { action: 'ACQUIRE' }>, context: ProviderContext): Promise<JsonObject> {
    const ownerPrincipal = owner(context);
    let pool = this.snapshotPools.getPool(poolId);
    if (pool.ownerPrincipal !== ownerPrincipal) throw new MicrovmError('microvm_not_found', 'pool was not found for this owner');
    if (pool.leases.length >= pool.maximumWarmCount) throw new MicrovmError('microvm_state_conflict', 'pool has no lease capacity');
    let vm: MicrovmRecord | null = null;
    let warm = false;
    while (pool.availableVmIds.length > 0 && vm === null) {
      const vmId = pool.availableVmIds[0] as string;
      try {
        const candidate = this.store.get(vmId);
        this.assertProcess(candidate);
        const token = readFileSync(tokenPath(join(this.root, vmId)), 'utf8').trim();
        const rotated = await guestCall(candidate.vsockSocketIdentity, token, 'ROTATE_IDENTITY', 5_000);
        if (rotated.ok !== true) throw new MicrovmError('microvm_state_conflict', 'warm instance contamination check failed');
        vm = this.store.transition(vmId, 'READY', 'POOL_ACQUIRED', { transactionId: action.transactionId, skillBundleDigest: action.skillBundleDigest, grantDigest: action.grantDigest, policyDigest: action.policyDigest, poolId, leaseState: 'LEASED', workloadIdentityDigest: identityDigest(rotated, 'workloadIdentity'), randomEpochDigest: identityDigest(rotated, 'randomEpoch') }, { poolId, transactionId: action.transactionId });
        warm = true;
      } catch {
        try { await this.remove({ vmId }, { ownerPrincipal, idempotencyKey: `pool-contaminated-${poolId}-${vmId}` }); } catch {}
        pool = this.snapshotPools.updatePool(poolId, { availableVmIds: pool.availableVmIds.filter((entry) => entry !== vmId), failedCount: pool.failedCount + 1 });
      }
    }
    if (vm === null) {
      const restored = await this.restoreInternal({ snapshotId: pool.snapshotId, transactionId: action.transactionId, skillBundleDigest: action.skillBundleDigest, grantDigest: action.grantDigest, policyDigest: action.policyDigest, networkMode: 'NONE' }, { ownerPrincipal, idempotencyKey: `pool-cold-fallback-${context.idempotencyKey}` }, poolId, 'LEASED');
      vm = restored.microvm as MicrovmRecord;
    }
    const lease = { vmId: vm.vmId, transactionId: action.transactionId, ownerPrincipal, acquiredAt: this.now() };
    pool = this.snapshotPools.updatePool(poolId, { availableVmIds: pool.availableVmIds.filter((entry) => entry !== vm?.vmId), leases: [...pool.leases, lease], status: 'HEALTHY', health: { ok: true, availableCount: pool.availableVmIds.filter((entry) => entry !== vm?.vmId).length, leasedCount: pool.leases.length + 1, failedCount: pool.failedCount } });
    return { pool, microvm: vm, warm, coldFallback: !warm };
  }

  private async releasePool(poolId: string, vmId: string, context: ProviderContext): Promise<JsonObject> {
    const ownerPrincipal = owner(context);
    let pool = this.snapshotPools.getPool(poolId);
    if (pool.ownerPrincipal !== ownerPrincipal) throw new MicrovmError('microvm_not_found', 'pool was not found for this owner');
    const lease = pool.leases.find((entry) => entry.vmId === vmId);
    if (lease === undefined) throw new MicrovmError('microvm_state_conflict', 'microVM is not leased from this pool');
    await this.remove({ vmId }, { ownerPrincipal, idempotencyKey: `pool-release-${context.idempotencyKey}` });
    pool = this.snapshotPools.updatePool(poolId, { leases: pool.leases.filter((entry) => entry.vmId !== vmId), generation: pool.generation + 1, status: 'DEGRADED', health: { ok: false, reason: 'replenishing_after_destroy' } });
    const reconciled = await this.reconcilePool(pool);
    return { ...reconciled, releasedVmId: vmId, destroyed: true };
  }

  async stop(payload: unknown, context: ProviderContext): Promise<JsonObject> {
    const { vmId } = normalizeVmSelector(payload);
    let record = this.owned(vmId, owner(context));
    if (record.lifecycle === 'STOPPED' || record.lifecycle === 'CLEANED') return { microvm: record, replayed: true };
    record = this.store.transition(vmId, 'STOPPING', 'STOP_REQUESTED', {}, {});
    const tokenFile = tokenPath(join(this.root, vmId));
    if (existsSync(tokenFile) && existsSync(record.vsockSocketIdentity)) { try { await guestCall(record.vsockSocketIdentity, readFileSync(tokenFile, 'utf8').trim(), 'SHUTDOWN', 3_000); } catch {} }
    await this.stopUnit(record.systemdUnit);
    if (this.unitActive(record.systemdUnit)) throw new MicrovmError('microvm_cleanup_failed', 'Firecracker process did not stop');
    const stopped = this.store.transition(vmId, 'STOPPED', 'STOPPED', { guestAgentState: 'STOPPED', processIdentity: null, cgroup: '', cleanup: { ...record.cleanup, processAbsent: true } }, { processAbsent: true });
    return { microvm: stopped, replayed: false };
  }

  async remove(payload: unknown, context: ProviderContext): Promise<JsonObject> {
    const { vmId } = normalizeVmSelector(payload);
    let record = this.owned(vmId, owner(context));
    if (record.lifecycle === 'CLEANED') return { microvm: record, replayed: true };
    if (record.lifecycle !== 'STOPPED' && record.lifecycle !== 'LOST' && record.lifecycle !== 'FAILED') await this.stop({ vmId }, context);
    record = this.store.get(vmId);
    record = this.store.transition(vmId, 'CLEANING', 'REMOVE_REQUESTED', { cleanup: { ...record.cleanup, requested: true } }, {});
    rmSync(join(this.root, vmId), { recursive: true, force: true });
    rmSync(join(this.runtimeRoot, vmId.slice(4)), { recursive: true, force: true });
    this.run('/usr/bin/systemctl', ['reset-failed', record.systemdUnit], 10_000);
    const processAbsent = !this.unitActive(record.systemdUnit);
    const socketAbsent = !existsSync(record.vsockSocketIdentity);
    const writableLayerAbsent = !existsSync(record.writableLayerIdentity);
    if (!processAbsent || !socketAbsent || !writableLayerAbsent) throw new MicrovmError('microvm_cleanup_failed', 'microVM resource cleanup could not be verified', { processAbsent, socketAbsent, writableLayerAbsent });
    const cleaned = this.store.transition(vmId, 'CLEANED', 'CLEANED', { cleanup: { requested: true, completed: true, processAbsent, socketAbsent, writableLayerAbsent, completedAt: this.now() } }, { processAbsent, socketAbsent, writableLayerAbsent });
    return { microvm: cleaned, replayed: false };
  }

  async reconcile(): Promise<JsonObject> {
    const updated: string[] = [];
    const healthy: string[] = [];
    const lost: string[] = [];
    for (const record of this.store.all()) {
      if (!['STARTING', 'BOOTING', 'READY', 'RUNNING', 'STOPPING'].includes(record.lifecycle)) continue;
      try {
        this.assertProcess(record);
        if (record.lifecycle === 'READY' || record.lifecycle === 'RUNNING') {
          const token = readFileSync(tokenPath(join(this.root, record.vmId)), 'utf8').trim();
          await guestCall(record.vsockSocketIdentity, token, 'HEALTH', 2_000);
        }
        healthy.push(record.vmId);
      } catch (error) {
        const code = error instanceof MicrovmError ? error.code : 'microvm_process_identity_conflict';
        const message = (error instanceof Error ? error.message : String(error)).slice(0, 512);
        this.store.transition(record.vmId, 'LOST', 'RECONCILE_LOST', { guestAgentState: 'FAILED', error: { code, message, phase: 'reconcile' } }, { code, messageDigest: sha256(message) });
        updated.push(record.vmId); lost.push(record.vmId);
      }
    }
    const orphans = this.findOrphanUnits();
    for (const unit of orphans) await this.stopUnit(unit);
    const poolResults: JsonObject[] = [];
    for (const pool of this.snapshotPools.allPools()) { try { poolResults.push(await this.reconcilePool(pool)); } catch {} }
    return { ok: orphans.every((unit) => !this.unitActive(unit)), healthy, lost, updated, orphanUnits: orphans, integrity: this.store.reconcileIntegrity(), snapshotPoolIntegrity: this.snapshotPools.verify(), poolResults };
  }

  private owned(vmId: string, ownerPrincipal: string): MicrovmRecord { const record = this.store.get(vmId); if (record.ownerPrincipal !== ownerPrincipal) throw new MicrovmError('microvm_not_found', 'microVM was not found for this owner'); return record; }
  private guestCommand(request: MicrovmExecAction): string { if (request.action === 'ECHO') return `EXEC ECHO_HEX ${request.taskId} ${Buffer.from(request.input, 'utf8').toString('hex')}`; if (request.action === 'SLEEP') return `EXEC SLEEP_MS ${request.taskId} ${request.durationMs}`; return `${request.action} ${request.taskId}`; }
  private allocateVsockCid(): number { const used = new Set(this.store.all().filter((record) => !['CLEANED', 'FAILED', 'LOST'].includes(record.lifecycle)).map((record) => record.vsockCid)); for (let cid = 10_000; cid < 65_535; cid++) if (!used.has(cid)) return cid; throw new MicrovmError('microvm_provider_unavailable', 'no vsock CID is available'); }
  private async waitForProcess(unit: string, expectedDigest: string): Promise<MicrovmProcessIdentity> {
    let observedMismatch: { pid: number; executableDigest: string } | null = null;
    for (let i = 0; i < 200; i++) {
      const show = this.run('/usr/bin/systemctl', ['show', '--value', '-p', 'MainPID', unit], 5_000);
      const pid = Number(show.stdout.trim());
      if (Number.isSafeInteger(pid) && pid > 1 && existsSync(`/proc/${pid}`)) {
        const executablePath = readlinkSync(`/proc/${pid}/exe`);
        const identity = { pid, processStartTime: processStartTime(pid), executablePath, executableDigest: executableDigest(executablePath) };
        if (identity.executableDigest === expectedDigest) return identity;
        observedMismatch = { pid, executableDigest: identity.executableDigest };
      }
      await sleep(50);
    }
    if (observedMismatch !== null) throw new MicrovmError('microvm_process_identity_conflict', 'Firecracker executable digest mismatch', { pid: observedMismatch.pid, observedDigest: observedMismatch.executableDigest, expectedDigest });
    throw new MicrovmError('microvm_provider_unavailable', 'Firecracker process readiness deadline exceeded');
  }
  private async waitForPath(path: string, timeoutMs: number): Promise<void> { const deadline = Date.now() + timeoutMs; while (Date.now() < deadline) { if (existsSync(path)) return; await sleep(50); } throw new MicrovmError('microvm_provider_unavailable', 'provider path readiness deadline exceeded', { pathDigest: sha256(path) }); }
  private async waitForGuest(vsockPath: string, token: string, timeoutMs: number): Promise<GuestResponse> { const deadline = Date.now() + timeoutMs; let last: unknown; while (Date.now() < deadline) { try { const response = await guestCall(vsockPath, token, 'HEALTH', 1_000); if (response.ok === true) return response; last = response; } catch (error) { last = error; } await sleep(50); } throw new MicrovmError('microvm_guest_protocol_failed', 'guest readiness deadline exceeded', { lastError: last instanceof Error ? last.message : String(last) }); }
  private unitActive(unit: string): boolean { return this.run('/usr/bin/systemctl', ['is-active', '--quiet', unit], 5_000).status === 0; }
  private assertProcess(record: MicrovmRecord): void { if (record.processIdentity === null || !existsSync(`/proc/${record.processIdentity.pid}`)) throw new MicrovmError('microvm_process_identity_conflict', 'Firecracker process is absent'); const observedStart = processStartTime(record.processIdentity.pid); const observedExe = readlinkSync(`/proc/${record.processIdentity.pid}/exe`); if (observedStart !== record.processIdentity.processStartTime || observedExe !== record.processIdentity.executablePath || executableDigest(observedExe) !== record.processIdentity.executableDigest) throw new MicrovmError('microvm_process_identity_conflict', 'Firecracker process identity conflict'); }
  private async stopUnit(unit: string): Promise<void> { this.run('/usr/bin/systemctl', ['stop', unit], 15_000); for (let i = 0; i < 100; i++) { if (!this.unitActive(unit)) return; await sleep(50); } this.run('/usr/bin/systemctl', ['kill', '--kill-whom=main', '--signal=SIGKILL', unit], 5_000); for (let i = 0; i < 100; i++) { if (!this.unitActive(unit)) return; await sleep(50); } }
  private async cleanupEffects(record: MicrovmRecord, removeFiles: boolean): Promise<void> { await this.stopUnit(record.systemdUnit); this.run('/usr/bin/systemctl', ['reset-failed', record.systemdUnit], 10_000); if (removeFiles) { rmSync(join(this.root, record.vmId), { recursive: true, force: true }); rmSync(join(this.runtimeRoot, record.vmId.slice(4)), { recursive: true, force: true }); } }
  private findOrphanUnits(): string[] { const result = this.run('/usr/bin/systemctl', ['list-units', '--all', '--plain', '--no-legend', 'baby-x-microvm-*.service'], 10_000); if (result.status !== 0) return []; const known = new Set(this.store.all().filter((record) => ['STARTING', 'BOOTING', 'READY', 'RUNNING', 'STOPPING'].includes(record.lifecycle)).map((record) => record.systemdUnit)); return result.stdout.split('\n').map((line) => line.trim().split(/\s+/u)[0]).filter((unit) => unit && unit.endsWith('.service') && !known.has(unit)); }
  private diskTokenAbsent(path: string): boolean { const result = this.run('/usr/sbin/debugfs', ['-R', 'stat /etc/babyx-auth-token', path], 10_000); return !/\bInode:\s*\d+/u.test(result.stdout) && /not found|File not found|ext2_lookup/u.test(`${result.stdout}\n${result.stderr}`); }
  private assertSnapshotUsable(snapshot: MicrovmSnapshotRecord, ownerPrincipal: string): void { if (snapshot.ownerPrincipal !== ownerPrincipal) throw new MicrovmError('microvm_not_found', 'snapshot was not found for this owner'); if (snapshot.status !== 'READY') throw new MicrovmError('microvm_state_conflict', 'snapshot is not READY', { status: snapshot.status }); if (Date.parse(snapshot.expiresAt) <= Date.parse(this.now())) throw new MicrovmError('microvm_state_conflict', 'snapshot is expired'); if (!snapshot.credentialAbsence.taskStateEmpty || !snapshot.credentialAbsence.guestTokenCleared || !snapshot.credentialAbsence.guestIdentityCleared || !snapshot.credentialAbsence.hostTokenAbsent || !snapshot.credentialAbsence.diskTokenAbsent) throw new MicrovmError('microvm_state_conflict', 'snapshot credential-absence proof is incomplete'); }
  private verifySnapshotFiles(snapshot: MicrovmSnapshotRecord): void { const entries: Array<[string, string | null, string]> = [[snapshot.memoryPath, snapshot.memoryDigest, 'memory'], [snapshot.vmStatePath, snapshot.vmStateDigest, 'VM state'], [snapshot.diskPath, snapshot.writableDiskDigest, 'writable disk']]; for (const [path, digest, name] of entries) { if (!existsSync(path) || digest === null || sha256(readFileSync(path)) !== digest) throw new MicrovmError('microvm_asset_integrity_failure', `snapshot ${name} digest mismatch`); } }
}
