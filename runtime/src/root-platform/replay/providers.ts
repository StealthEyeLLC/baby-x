import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { arch, release } from 'node:os';
import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import { MicrovmArtifactRegistry } from '../microvm/artifacts.ts';
import type { RootPlatformProvider } from '../provider-registry.ts';
import { PROVIDER_CONTRACT_VERSION, type ProviderDefinition, type ProviderObservation } from '../schemas.ts';
import { ROOT_REPLAY_PROVIDER_VERSION, ROOT_REPLAY_SCHEMA_VERSION } from './records.ts';

function definition(input: Omit<ProviderDefinition, 'contractVersion' | 'configurationDigest'> & { configuration: JsonObject }): ProviderDefinition {
  const { configuration, ...rest } = input;
  return { ...rest, contractVersion: PROVIDER_CONTRACT_VERSION, configurationDigest: sha256(canonicalize(configuration)) };
}

function executable(name: string, fixedPath?: string): { available: boolean; path: string | null; version: string | null } {
  const path = fixedPath !== undefined && existsSync(fixedPath)
    ? fixedPath
    : spawnSync('/usr/bin/env', ['bash', '-lc', `command -v -- ${JSON.stringify(name)}`], { encoding: 'utf8', timeout: 2000 }).stdout.trim();
  if (!path) return { available: false, path: null, version: null };
  const result = spawnSync(path, ['--version'], { encoding: 'utf8', timeout: 3000 });
  const version = `${result.stdout ?? ''}${result.stderr ?? ''}`.trim().split('\n')[0] || null;
  return { available: result.status === 0, path, version };
}

function provider(def: ProviderDefinition, probe: () => ProviderObservation): RootPlatformProvider { return { definition: def, probe }; }

export function replayProviders(): RootPlatformProvider[] {
  const request = definition({
    providerId: 'request-replay', family: 'replay', implementationVersion: `${ROOT_REPLAY_PROVIDER_VERSION}+request`,
    requiredCapabilities: ['filesystem'], limits: { maximumCanonicalInputBytes: 1048576 }, restartBehavior: 'resume_from_digest_sealed_replay_record',
    cancellationBehavior: 'coordination_only_no_effect_to_cancel', cleanupBehavior: 'durable_sidecar_records_are_retained', errors: ['root_replay_integrity_failure', 'root_replay_secret_material_rejected'],
    configuration: { schemaVersion: ROOT_REPLAY_SCHEMA_VERSION, dryRunDefault: true, executesEffects: false },
  });
  const observation = definition({
    providerId: 'observation-replay', family: 'replay', implementationVersion: `${ROOT_REPLAY_PROVIDER_VERSION}+observation`,
    requiredCapabilities: ['filesystem'], limits: { maximumEvents: 10000, maximumObservations: 10000 }, restartBehavior: 'recompute_from_authoritative_transaction_record',
    cancellationBehavior: 'bounded_synchronous_verification', cleanupBehavior: 'no_owned_resources', errors: ['root_replay_source_integrity_failure'],
    configuration: { schemaVersion: ROOT_REPLAY_SCHEMA_VERSION, mutationFree: true },
  });
  const criu = definition({
    providerId: 'criu-checkpoint-restore', family: 'checkpoint-replay', implementationVersion: `${ROOT_REPLAY_PROVIDER_VERSION}+criu`,
    requiredCapabilities: ['criu', 'procfs'], limits: { maximumRestoreAttemptsPerCheckpoint: 1000 }, restartBehavior: 'durable_checkpoint_record_and_exact_compatibility_revalidation',
    cancellationBehavior: 'delegate_to_existing_command_authority', cleanupBehavior: 'checkpoint_images_are_external_authoritative_artifacts', errors: ['root_replay_provider_unavailable', 'root_replay_compatibility_mismatch', 'root_replay_restore_failed'],
    configuration: { schemaVersion: ROOT_REPLAY_SCHEMA_VERSION, executable: '/usr/sbin/criu', exactArgv: true },
  });
  const rr = definition({
    providerId: 'rr-forensic-replay', family: 'checkpoint-replay', implementationVersion: `${ROOT_REPLAY_PROVIDER_VERSION}+rr`,
    requiredCapabilities: ['rr', 'ptrace', 'perf-events'], limits: { maximumTraceReferenceBytes: 4096 }, restartBehavior: 'reopen_exact_digest_bound_trace',
    cancellationBehavior: 'delegate_to_existing_command_authority', cleanupBehavior: 'trace_artifacts_are_external_authoritative_artifacts', errors: ['root_replay_provider_unavailable', 'root_replay_trace_integrity_failure', 'root_replay_restore_failed'],
    configuration: { schemaVersion: ROOT_REPLAY_SCHEMA_VERSION, forensicOnly: true, mutationAuthority: false },
  });
  const microvm = definition({
    providerId: 'microvm-snapshot-replay', family: 'checkpoint-replay', implementationVersion: `${ROOT_REPLAY_PROVIDER_VERSION}+microvm`,
    requiredCapabilities: ['kvm', 'vsock', 'systemd'], limits: { maximumWarmCount: 1 }, restartBehavior: 'reuse_existing_microvm_snapshot_authority',
    cancellationBehavior: 'delegate_to_existing_microvm_authority', cleanupBehavior: 'reuse_existing_microvm_cleanup_and_absence_verification', errors: ['root_replay_provider_unavailable', 'root_replay_compatibility_mismatch', 'root_replay_restore_failed'],
    configuration: { schemaVersion: ROOT_REPLAY_SCHEMA_VERSION, snapshotAuthority: 'babyx.root.microvm.snapshot', restoreAuthority: 'babyx.root.microvm.restore' },
  });
  return [
    provider(request, () => ({ supportState: 'SUPPORTED', executableIdentity: process.execPath, health: { ok: true, dryRunDefault: true, executesEffects: false }, observedCapabilities: ['filesystem'] })),
    provider(observation, () => ({ supportState: 'SUPPORTED', executableIdentity: process.execPath, health: { ok: true, mutationFree: true }, observedCapabilities: ['filesystem'] })),
    provider(criu, () => { const probe = executable('criu', '/usr/sbin/criu'); return { supportState: probe.available ? 'SUPPORTED' : 'UNAVAILABLE', executableIdentity: probe.path, health: { ok: probe.available, version: probe.version, architecture: arch(), kernelRelease: release() }, observedCapabilities: probe.available ? ['criu', 'procfs'] : ['procfs'] }; }),
    provider(rr, () => { const probe = executable('rr'); const paranoid = existsSync('/proc/sys/kernel/perf_event_paranoid') ? Number(spawnSync('/bin/cat', ['/proc/sys/kernel/perf_event_paranoid'], { encoding: 'utf8' }).stdout.trim()) : null; const supported = probe.available && (paranoid === null || paranoid <= 1); return { supportState: supported ? 'SUPPORTED' : 'UNAVAILABLE', executableIdentity: probe.path, health: { ok: supported, version: probe.version, perfEventParanoid: paranoid, ptraceScopePath: '/proc/sys/kernel/yama/ptrace_scope' }, observedCapabilities: supported ? ['rr', 'ptrace', 'perf-events'] : [] }; }),
    provider(microvm, () => { const probe = new MicrovmArtifactRegistry().probe() as { supportState: ProviderObservation['supportState']; health: JsonObject }; return { supportState: probe.supportState, executableIdentity: 'babyx.root.microvm.snapshot', health: { ...probe.health, delegated: true }, observedCapabilities: probe.supportState === 'SUPPORTED' ? ['kvm', 'vsock', 'systemd'] : [] }; }),
  ];
}
