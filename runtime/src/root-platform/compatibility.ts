import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { arch, release } from 'node:os';
import { canonicalize, sha256, type JsonObject } from '../core.ts';
import { ROOT_TRANSACTION_PROVIDER_VERSION, ROOT_TRANSACTION_SCHEMA_VERSION } from '../root-authority/service.ts';
import { PROVIDER_CONTRACT_VERSION, ROOT_PLATFORM_PROVIDER_VERSION, ROOT_PLATFORM_SCHEMA_VERSION, type ProviderDefinition, type ProviderObservation } from './schemas.ts';
import type { RootPlatformProvider } from './provider-registry.ts';
import { mediationProviders } from './mediation/providers.ts';
import { identityProviders } from './identity/providers.ts';
import { trustProviders } from './trust/providers.ts';
import { MicrovmArtifactRegistry } from './microvm/artifacts.ts';

export const PROMPT1_COMMIT = 'fef1cb3b76a5c6f5beb1ca73499c4d1e5cafe713' as const;
export const PROMPT1_TREE = 'a98cee4adfed2912bffda2a2fdf5928bcd0b66bf' as const;

function command(name: string, args: string[]): { available: boolean; path: string | null; output: string | null } {
  const locate = spawnSync('/usr/bin/env', ['bash', '-lc', `command -v -- ${JSON.stringify(name)}`], { encoding: 'utf8', timeout: 2_000 });
  const path = locate.status === 0 ? locate.stdout.trim() : '';
  if (!path) return { available: false, path: null, output: null };
  const result = spawnSync(path, args, { encoding: 'utf8', timeout: 3_000 });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`.trim();
  return { available: result.status === 0, path, output: output || null };
}

function readable(path: string): boolean {
  try { readFileSync(path); return true; } catch { return false; }
}

function firstReadable(paths: string[]): string | null { return paths.find((path) => readable(path)) ?? null; }

function kernelConfig(name: string): boolean {
  const path = `/boot/config-${release()}`;
  if (!readable(path)) return false;
  return readFileSync(path, 'utf8').split('\n').includes(`${name}=y`);
}

function device(path: string): JsonObject {
  if (!existsSync(path)) return { available: false, path };
  try {
    const stat = statSync(path);
    return { available: true, path, mode: stat.mode & 0o777, characterDevice: stat.isCharacterDevice() };
  } catch { return { available: false, path }; }
}

export function probeHostCapabilities(): JsonObject {
  const cgroupV2 = existsSync('/sys/fs/cgroup/cgroup.controllers');
  const lsmPath = firstReadable(['/sys/kernel/security/lsm']);
  const activeLsms = lsmPath === null ? [] : readFileSync(lsmPath, 'utf8').trim().split(',').filter(Boolean);
  const seccompStatus = firstReadable(['/proc/self/status']);
  const seccompLine = seccompStatus === null ? null : readFileSync(seccompStatus, 'utf8').split('\n').find((line) => line.startsWith('Seccomp:')) ?? null;
  const landlockPath = firstReadable(['/sys/kernel/security/landlock']);
  const measuredBootPath = firstReadable(['/sys/kernel/security/tpm0/binary_bios_measurements', '/sys/kernel/security/tpm1/binary_bios_measurements']);
  const imaPath = firstReadable(['/sys/kernel/security/ima/ascii_runtime_measurements', '/sys/kernel/security/ima/binary_runtime_measurements']);
  const criu = command('criu', ['--version']);
  const rr = command('rr', ['--version']);
  const zfs = command('zfs', ['--version']);
  const nspawn = command('systemd-nspawn', ['--version']);
  return {
    architecture: arch(),
    kernel: release(),
    systemd: { available: existsSync('/run/systemd/system'), path: '/run/systemd/system' },
    cgroup: { mode: cgroupV2 ? 'unified-v2' : existsSync('/sys/fs/cgroup') ? 'legacy-or-hybrid' : 'unavailable', controllersReadable: readable('/sys/fs/cgroup/cgroup.controllers') },
    kvm: device('/dev/kvm'),
    seccomp: { available: kernelConfig('CONFIG_SECCOMP') || seccompLine !== null, processMode: seccompLine?.split(':')[1]?.trim() ?? null },
    seccompNotification: { available: kernelConfig('CONFIG_SECCOMP_USER_NOTIF'), pidfd: kernelConfig('CONFIG_PIDFD') || existsSync('/proc/self/fd') },
    landlock: { available: landlockPath !== null, securityfsPath: landlockPath, kernelConfigured: kernelConfig('CONFIG_SECURITY_LANDLOCK') },
    bpf: { available: existsSync('/sys/fs/bpf'), filesystem: '/sys/fs/bpf' },
    btf: { available: readable('/sys/kernel/btf/vmlinux'), path: '/sys/kernel/btf/vmlinux' },
    bpfLsm: { available: activeLsms.includes('bpf'), activeLsms },
    tpm: { available: existsSync('/dev/tpmrm0') || existsSync('/dev/tpm0'), resourceManager: device('/dev/tpmrm0'), raw: device('/dev/tpm0') },
    measuredBootEventLog: { available: measuredBootPath !== null, path: measuredBootPath },
    ima: { available: imaPath !== null, path: imaPath },
    vsock: { available: existsSync('/dev/vhost-vsock') || readable('/proc/net/vsock'), device: device('/dev/vhost-vsock') },
    tap: { available: existsSync('/dev/net/tun'), device: device('/dev/net/tun') },
    criu,
    rr,
    zfs,
    nspawn,
  };
}

function configurationDigest(value: JsonObject): string { return sha256(canonicalize(value)); }

function definition(input: Omit<ProviderDefinition, 'contractVersion' | 'configurationDigest'> & { configuration: JsonObject }): ProviderDefinition {
  const { configuration, ...rest } = input;
  return { ...rest, contractVersion: PROVIDER_CONTRACT_VERSION, configurationDigest: configurationDigest(configuration) };
}

export function defaultProviders(identity: { runningCommit: string; runningTree: string }): RootPlatformProvider[] {
  const prompt1Definition = definition({
    providerId: 'prompt1-root-authority', family: 'root-authority', implementationVersion: ROOT_TRANSACTION_PROVIDER_VERSION,
    requiredCapabilities: [], limits: { maximumEventsPerTransaction: 10_000 }, restartBehavior: 'durable_record_reconciliation',
    cancellationBehavior: 'state_transition_only', cleanupBehavior: 'records_are_authoritative_and_retained', errors: ['root_integrity_failure'],
    configuration: { schemaVersion: ROOT_TRANSACTION_SCHEMA_VERSION, commit: PROMPT1_COMMIT, tree: PROMPT1_TREE },
  });
  const platformDefinition = definition({
    providerId: 'sovereign-platform-core', family: 'platform', implementationVersion: ROOT_PLATFORM_PROVIDER_VERSION,
    requiredCapabilities: ['filesystem'], limits: { maximumProviders: 256, maximumPageSize: 1_000 }, restartBehavior: 'rebuild_registry_and_reconcile_sidecars',
    cancellationBehavior: 'reconciliation_is_atomic', cleanupBehavior: 'sidecar_records_are_retained', errors: ['root_platform_integrity_failure'],
    configuration: { schemaVersion: ROOT_PLATFORM_SCHEMA_VERSION, runningCommit: identity.runningCommit, runningTree: identity.runningTree },
  });
  const probeDefinition = definition({
    providerId: 'host-capability-probe', family: 'capability-probe', implementationVersion: 'linux-host-capability-probe@1',
    requiredCapabilities: ['procfs', 'sysfs'], limits: { maximumCommandDurationMs: 3_000 }, restartBehavior: 'reprobe_from_live_host',
    cancellationBehavior: 'bounded_synchronous_probes', cleanupBehavior: 'no_owned_resources', errors: ['host_probe_failed'],
    configuration: { probeSet: ['architecture', 'kernel', 'systemd', 'cgroup', 'kvm', 'seccomp', 'landlock', 'bpf', 'tpm', 'vsock', 'tap', 'criu', 'rr', 'zfs', 'nspawn'] },
  });
  const microvmRegistry = new MicrovmArtifactRegistry();
  const firecrackerDefinition = definition({
    providerId: 'firecracker-cold-boot', family: 'microvm', implementationVersion: 'firecracker-v1.15.1+babyx-provider-1.1.0',
    requiredCapabilities: ['kvm', 'vsock', 'systemd'], limits: { maximumVcpus: 8, maximumMemoryMiB: 4096, maximumGuestRequestBytes: 4096, maximumWarmCount: 1 }, restartBehavior: 'reconcile_exact_process_and_guest_identity',
    cancellationBehavior: 'typed_guest_task_cancellation_only', cleanupBehavior: 'stop_process_remove_socket_and_writable_layer_verify_absence', errors: ['microvm_asset_integrity_failure','microvm_process_identity_conflict','microvm_cleanup_failed'],
    configuration: { firecrackerVersion: 'v1.15.1', kernelDigest: 'e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2', networkDefault: 'NONE', guestProtocol: 'BABYX-GUEST/1.0.0' },
  });
  return [
    { definition: prompt1Definition, probe: (): ProviderObservation => ({ supportState: 'SUPPORTED', executableIdentity: `${identity.runningCommit}:${identity.runningTree}`, health: { ok: true, coordinationOnly: true }, observedCapabilities: [] }) },
    { definition: platformDefinition, probe: (): ProviderObservation => ({ supportState: 'SUPPORTED', executableIdentity: `${process.execPath}:${identity.runningCommit}:${identity.runningTree}`, health: { ok: true, schemaVersion: ROOT_PLATFORM_SCHEMA_VERSION }, observedCapabilities: ['filesystem'] }) },
    { definition: probeDefinition, probe: (): ProviderObservation => { const capabilities = probeHostCapabilities(); return { supportState: 'SUPPORTED', executableIdentity: process.execPath, health: { ok: true, capabilityDigest: sha256(canonicalize(capabilities)) }, observedCapabilities: ['procfs', 'sysfs'] }; } },
    { definition: firecrackerDefinition, probe: (): ProviderObservation => { const observed = microvmRegistry.probe() as { supportState: ProviderObservation['supportState']; health: JsonObject }; let executableIdentity = 'firecracker-v1.15.1:unavailable'; try { const artifacts = microvmRegistry.load(); executableIdentity = `${artifacts.firecrackerPath}:${artifacts.firecrackerDigest}`; } catch {} return { supportState: observed.supportState, executableIdentity, health: observed.health, observedCapabilities: observed.supportState === 'SUPPORTED' ? ['kvm','vsock','systemd'] : [] }; } },
    ...mediationProviders(),
    ...identityProviders(),
    ...trustProviders(),
  ];
}
