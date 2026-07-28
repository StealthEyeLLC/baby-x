import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import type { RootPlatformProvider } from '../provider-registry.ts';
import { PROVIDER_CONTRACT_VERSION, type ProviderDefinition, type ProviderObservation } from '../schemas.ts';
import { BpfLsmController } from './bpf-lsm.ts';
import { NativeMediationRunner, type NativeMediationComponent } from './native.ts';
import { MEDIATION_PROVIDER_CONTRACT_VERSION } from './schemas.ts';
import { runtimeArchitecture, syscallNames } from './syscall-tables.ts';

function definition(input: Omit<ProviderDefinition, 'contractVersion' | 'configurationDigest'> & { configuration: JsonObject }): ProviderDefinition {
  const { configuration, ...rest } = input;
  return { ...rest, contractVersion: PROVIDER_CONTRACT_VERSION, configurationDigest: sha256(canonicalize(configuration)) };
}

function nativeProvider(providerId: string, component: NativeMediationComponent, requiredCapabilities: string[]): RootPlatformProvider {
  const providerDefinition = definition({
    providerId,
    family: 'mediation',
    implementationVersion: 'baby-x-mediation-supervisor@1.0.0',
    requiredCapabilities,
    limits: { maximumRules: 64, maximumArgumentConstraints: 128, maximumDecisionEvents: 1_000, maximumDeadlineMs: 60_000 },
    restartBehavior: 'profiles_are_durable_and_live_support_is_reprobed',
    cancellationBehavior: 'supervisor_deadline_and_child_process_termination',
    cleanupBehavior: 'listener_descriptors_and_child_processes_are_closed_or_reaped',
    errors: ['mediation_native_unavailable', 'mediation_native_failed', 'mediation_profile_revoked'],
    configuration: { contractVersion: MEDIATION_PROVIDER_CONTRACT_VERSION, component, architecture: runtimeArchitecture(), syscalls: syscallNames(runtimeArchitecture()) },
  });
  return {
    definition: providerDefinition,
    probe(): ProviderObservation {
      try {
        const runner = new NativeMediationRunner();
        const probe = runner.probe(component);
        return { supportState: probe.ok ? 'SUPPORTED' : 'FAILED', executableIdentity: `${probe.binaryPath}:${probe.binaryDigest}`, health: { ok: probe.ok, probe: probe.details, error: probe.error }, observedCapabilities: probe.ok ? requiredCapabilities : [] };
      } catch (error) {
        return { supportState: 'FAILED', executableIdentity: null, health: { ok: false, error: error instanceof Error ? error.message : 'native mediation probe failed' }, observedCapabilities: [] };
      }
    },
  };
}

export function mediationProviders(): RootPlatformProvider[] {
  const bpf = new BpfLsmController();
  const bpfDefinition = definition({
    providerId: 'bpf-lsm', family: 'mediation', implementationVersion: 'baby-x-bpf-lsm-observer@1.0.0',
    requiredCapabilities: ['bpf', 'btf', 'bpf-lsm'], limits: { mode: 'observation-only', maximumHooks: 32 },
    restartBehavior: 'pinned_program_health_is_reconciled', cancellationBehavior: 'detach_pinned_programs', cleanupBehavior: 'remove_provider_owned_pin_root',
    errors: ['mediation_bpf_unavailable', 'mediation_native_failed'],
    configuration: { contractVersion: MEDIATION_PROVIDER_CONTRACT_VERSION, sourceDigest: bpf.sourceDigest, objectDigest: bpf.objectDigest, enforcementEnabled: false },
  });
  return [
    nativeProvider('seccomp-filter', 'filter', ['seccomp-filter']),
    nativeProvider('seccomp-notify', 'notify', ['seccomp-filter', 'seccomp-user-notification', 'procfs', 'cgroup']),
    nativeProvider('landlock', 'landlock', ['landlock']),
    {
      definition: bpfDefinition,
      probe(): ProviderObservation {
        const observed = bpf.probe();
        const supportState = String(observed.supportState) as ProviderObservation['supportState'];
        return { supportState, executableIdentity: bpf.objectPath === null || bpf.objectDigest === null ? null : `${bpf.objectPath}:${bpf.objectDigest}`, health: observed.health as JsonObject, observedCapabilities: supportState === 'EXPERIMENTAL' ? ['bpf', 'btf', 'bpf-lsm'] : [] };
      },
    },
  ];
}
