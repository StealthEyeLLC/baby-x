import { spawnSync } from 'node:child_process';
import { closeSync, existsSync, openSync, readFileSync, readSync, statSync } from 'node:fs';
import { arch, release } from 'node:os';
import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import type { RootPlatformProvider } from '../provider-registry.ts';
import { PROVIDER_CONTRACT_VERSION, type ProviderDefinition, type ProviderObservation, type ProviderSupportState } from '../schemas.ts';
import { ROOT_IDENTITY_PROVIDER_VERSION, ROOT_IDENTITY_SCHEMA_VERSION, ROOT_TRUST_DOMAIN, type AttestationQuote, type PcrValue } from './schemas.ts';

const SOFTWARE_TPM_FIXTURE_KEY = 'baby-x-software-tpm-fixture-v1';
const EVENT_LOG_PATHS = ['/sys/kernel/security/tpm0/binary_bios_measurements', '/sys/kernel/security/tpm1/binary_bios_measurements'];
const IMA_PATHS = ['/sys/kernel/security/ima/ascii_runtime_measurements', '/sys/kernel/security/ima/binary_runtime_measurements'];
const SPIRE_AGENT_SOCKET = '/run/spire/sockets/agent.sock';

function commandPath(name: string): string | null {
  const result = spawnSync('/usr/bin/env', ['bash', '-lc', `command -v -- ${JSON.stringify(name)}`], { encoding: 'utf8', timeout: 2_000 });
  const path = result.status === 0 ? result.stdout.trim() : '';
  return path || null;
}

function boundedRead(path: string, maximumBytes = 4 * 1024 * 1024): Buffer | null {
  if (!existsSync(path)) return null;
  let fd: number | undefined;
  try {
    const size = Math.min(statSync(path).size || maximumBytes, maximumBytes);
    const target = Buffer.alloc(size);
    fd = openSync(path, 'r');
    const count = readSync(fd, target, 0, size, 0);
    return target.subarray(0, count);
  } catch { return null; }
  finally { if (fd !== undefined) closeSync(fd); }
}

function firstReadable(paths: readonly string[]): { path: string; data: Buffer } | null {
  for (const path of paths) { const data = boundedRead(path); if (data !== null) return { path, data }; }
  return null;
}

function definition(input: Omit<ProviderDefinition, 'contractVersion' | 'configurationDigest'> & { configuration: JsonObject }): ProviderDefinition {
  const { configuration, ...rest } = input;
  return { ...rest, contractVersion: PROVIDER_CONTRACT_VERSION, configurationDigest: sha256(canonicalize(configuration)) };
}

function provider(definitionValue: ProviderDefinition, probe: () => ProviderObservation): RootPlatformProvider { return { definition: definitionValue, probe }; }

export function hardwareTpmSupport(): { supportState: ProviderSupportState; health: JsonObject; executableIdentity: string | null } {
  const device = existsSync('/dev/tpmrm0') ? '/dev/tpmrm0' : existsSync('/dev/tpm0') ? '/dev/tpm0' : null;
  const getcap = commandPath('tpm2_getcap');
  const quote = commandPath('tpm2_quote');
  if (device === null) return { supportState: 'UNAVAILABLE', executableIdentity: null, health: { ok: false, reason: 'hardware_tpm_device_absent', privateKeyExport: false } };
  if (getcap === null || quote === null) return { supportState: 'DEGRADED', executableIdentity: device, health: { ok: false, reason: 'tpm2_tools_absent', device, privateKeyExport: false } };
  const result = spawnSync(getcap, ['properties-fixed'], { encoding: 'utf8', timeout: 3_000 });
  return result.status === 0
    ? { supportState: 'SUPPORTED', executableIdentity: `${device}:${getcap}:${quote}`, health: { ok: true, device, privateKeyExport: false, quoteCommand: quote } }
    : { supportState: 'FAILED', executableIdentity: `${device}:${getcap}:${quote}`, health: { ok: false, reason: 'tpm_capability_probe_failed', status: result.status, privateKeyExport: false } };
}

export function measuredBootEvidence(): JsonObject {
  const eventLog = firstReadable(EVENT_LOG_PATHS);
  const ima = firstReadable(IMA_PATHS);
  const bootId = readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
  const commandLine = readFileSync('/proc/cmdline', 'utf8').trim();
  const kernelIdentity = existsSync('/proc/version_signature') ? readFileSync('/proc/version_signature', 'utf8').trim() : `${arch()}:${release()}`;
  const secureBoot = existsSync('/sys/firmware/efi/efivars') ? 'UNKNOWN_EFI_PRESENT' : 'UNAVAILABLE';
  const evidence = {
    hostIdentity: sha256(canonicalize({ architecture: arch(), kernel: release() })),
    bootId,
    secureBoot,
    pcrValues: [],
    eventLog: eventLog === null ? { available: false, path: null, digest: null, boundedBytes: 0 } : { available: true, path: eventLog.path, digest: sha256(eventLog.data), boundedBytes: eventLog.data.length },
    kernelIdentity: sha256(kernelIdentity),
    initrdIdentity: null,
    commandLineIdentity: sha256(commandLine),
    ima: ima === null ? { available: false, path: null, digest: null, boundedBytes: 0 } : { available: true, path: ima.path, digest: sha256(ima.data), boundedBytes: ima.data.length },
    measurementPolicy: 'observe-only',
  };
  return { ...evidence, evidenceDigest: sha256(canonicalize(evidence)) };
}

function unsignedQuote(quote: AttestationQuote): JsonObject {
  const { signature: _signature, ...unsigned } = quote;
  return unsigned;
}

export function signSoftwareAttestationQuote(quote: Omit<AttestationQuote, 'signature'>): string {
  return sha256(canonicalize({ fixtureKey: SOFTWARE_TPM_FIXTURE_KEY, quote }));
}

export function verifySoftwareAttestationQuote(quote: AttestationQuote): boolean {
  return quote.signature === sha256(canonicalize({ fixtureKey: SOFTWARE_TPM_FIXTURE_KEY, quote: unsignedQuote(quote) }));
}

export function createSoftwareAttestationQuote(input: {
  nonce: string;
  pcrs: PcrValue[];
  observedAt: string;
  bootId?: string;
  eventLogDigest?: string | null;
  imaDigest?: string | null;
  attestationKeyId?: string;
}): AttestationQuote {
  const unsigned: Omit<AttestationQuote, 'signature'> = {
    providerId: 'software-tpm-fixture', nonce: input.nonce, pcrs: structuredClone(input.pcrs),
    eventLogDigest: input.eventLogDigest ?? null, imaDigest: input.imaDigest ?? null,
    bootId: input.bootId ?? 'software-tpm-fixture-boot', observedAt: input.observedAt,
    attestationKeyId: input.attestationKeyId ?? 'software-tpm-fixture-ak-v1',
  };
  return { ...unsigned, signature: signSoftwareAttestationQuote(unsigned) };
}

export function identityProviders(): RootPlatformProvider[] {
  const hardware = definition({
    providerId: 'hardware-tpm', family: 'attestation', implementationVersion: 'tpm2-tools-provider@1', requiredCapabilities: ['tpm-device', 'tpm2-getcap', 'tpm2-quote'],
    limits: { maximumPcrs: 24, maximumQuoteAgeSeconds: 900 }, restartBehavior: 'reprobe_device_and_attestation_key', cancellationBehavior: 'quote_generation_is_bounded',
    cleanupBehavior: 'no_private_key_export_attestation_keys_remain_tpm_resident', errors: ['tpm_unavailable', 'tpm_quote_failed', 'tpm_pcr_mismatch', 'tpm_nonce_replay'],
    configuration: { schemaVersion: ROOT_IDENTITY_SCHEMA_VERSION, keyExport: false },
  });
  const software = definition({
    providerId: 'software-tpm-fixture', family: 'attestation', implementationVersion: 'software-tpm-fixture@1', requiredCapabilities: [],
    limits: { maximumPcrs: 24, testOnly: 1 }, restartBehavior: 'deterministic_fixture_verification', cancellationBehavior: 'not_applicable', cleanupBehavior: 'no_live_host_resources',
    errors: ['fixture_signature_invalid', 'fixture_nonce_replay'], configuration: { fixtureKeyDigest: sha256(SOFTWARE_TPM_FIXTURE_KEY), productionEnabled: false },
  });
  const measuredBoot = definition({
    providerId: 'measured-boot-evidence', family: 'attestation-evidence', implementationVersion: 'linux-measured-boot-reader@1', requiredCapabilities: ['securityfs-event-log'],
    limits: { maximumEvidenceBytes: 4 * 1024 * 1024 }, restartBehavior: 'reobserve_current_boot', cancellationBehavior: 'bounded_read', cleanupBehavior: 'no_owned_resources',
    errors: ['event_log_unavailable', 'event_log_unreadable'], configuration: { mode: 'observe-only', paths: EVENT_LOG_PATHS },
  });
  const ima = definition({
    providerId: 'ima-measurement-evidence', family: 'attestation-evidence', implementationVersion: 'linux-ima-reader@1', requiredCapabilities: ['ima-measurements'],
    limits: { maximumEvidenceBytes: 4 * 1024 * 1024 }, restartBehavior: 'reobserve_current_boot', cancellationBehavior: 'bounded_read', cleanupBehavior: 'never_enables_host_appraisal_policy',
    errors: ['ima_unavailable', 'ima_unreadable'], configuration: { mode: 'observe-only', appraisalMutation: false, paths: IMA_PATHS },
  });
  const spire = definition({
    providerId: 'spire-workload-api', family: 'workload-identity', implementationVersion: 'spire@1.12.4', requiredCapabilities: ['spire-agent', 'workload-api-socket'],
    limits: { maximumSelectors: 16, maximumSvidTtlSeconds: 3600 }, restartBehavior: 'reconnect_workload_api_and_rotate_svid', cancellationBehavior: 'issuance_is_bounded', cleanupBehavior: 'revoke_registration_and_remove_workload_material',
    errors: ['spire_unavailable', 'selector_mismatch', 'svid_issuance_failed'], configuration: { version: '1.12.4', trustDomain: ROOT_TRUST_DOMAIN, workloadApiSocket: SPIRE_AGENT_SOCKET },
  });
  const sovereignSvid = definition({
    providerId: 'sovereign-x509-svid', family: 'workload-identity', implementationVersion: `${ROOT_IDENTITY_PROVIDER_VERSION}+openssl`, requiredCapabilities: ['openssl'],
    limits: { maximumSelectors: 16, maximumSvidTtlSeconds: 3600 }, restartBehavior: 'durable_identity_record_and_material_reconciliation', cancellationBehavior: 'issuance_is_bounded', cleanupBehavior: 'private_key_removed_on_revoke_or_expiry',
    errors: ['openssl_unavailable', 'svid_issuance_failed'], configuration: { trustDomain: ROOT_TRUST_DOMAIN, experimentalFallback: true, privateKeyExport: false },
  });
  const secret = definition({
    providerId: 'attestation-gated-secret-lease', family: 'credential', implementationVersion: 'attestation-gated-secret-lease@1', requiredCapabilities: ['filesystem-secret-reference'],
    limits: { maximumTtlSeconds: 3600, maximumSecretBytes: 1024 * 1024 }, restartBehavior: 'expire_or_reconcile_durable_lease_records', cancellationBehavior: 'lease_revoke_is_atomic', cleanupBehavior: 'secret_values_never_persisted_or_returned',
    errors: ['secret_reference_unavailable', 'identity_invalid', 'attestation_stale', 'lease_expired'], configuration: { metadataOnly: true, secretValuesReturned: false },
  });
  return [
    provider(hardware, (): ProviderObservation => { const observed = hardwareTpmSupport(); return { ...observed, observedCapabilities: observed.supportState === 'SUPPORTED' ? ['tpm-device', 'tpm2-getcap', 'tpm2-quote'] : [] }; }),
    provider(software, (): ProviderObservation => ({ supportState: 'EXPERIMENTAL', executableIdentity: `fixture:${sha256(SOFTWARE_TPM_FIXTURE_KEY)}`, health: { ok: true, testOnly: true, productionEnabled: false }, observedCapabilities: [] })),
    provider(measuredBoot, (): ProviderObservation => { const evidence = measuredBootEvidence() as { eventLog: { available: boolean; path: string | null }; evidenceDigest: string }; return { supportState: evidence.eventLog.available ? 'SUPPORTED' : 'UNAVAILABLE', executableIdentity: evidence.eventLog.path, health: { ok: evidence.eventLog.available, evidenceDigest: evidence.evidenceDigest, trustedBootClaimed: false }, observedCapabilities: evidence.eventLog.available ? ['securityfs-event-log'] : [] }; }),
    provider(ima, (): ProviderObservation => { const evidence = measuredBootEvidence() as { ima: { available: boolean; path: string | null; digest: string | null } }; return { supportState: evidence.ima.available ? 'SUPPORTED' : 'UNAVAILABLE', executableIdentity: evidence.ima.path, health: { ok: evidence.ima.available, digest: evidence.ima.digest, appraisalMutation: false }, observedCapabilities: evidence.ima.available ? ['ima-measurements'] : [] }; }),
    provider(spire, (): ProviderObservation => { const server = commandPath('spire-server'); const agent = commandPath('spire-agent'); const socket = existsSync(SPIRE_AGENT_SOCKET); const dependencies = server !== null && agent !== null && socket; const enabled = process.env.BABYX_SPIRE_WORKLOAD_API_ENABLED === '1'; const supportState: ProviderSupportState = !dependencies ? 'UNAVAILABLE' : enabled ? 'SUPPORTED' : 'DISABLED'; return { supportState, executableIdentity: dependencies ? `${server}:${agent}:${SPIRE_AGENT_SOCKET}` : null, health: { ok: dependencies && enabled, serverAvailable: server !== null, agentAvailable: agent !== null, workloadApiSocket: socket, enabled, trustDomain: ROOT_TRUST_DOMAIN }, observedCapabilities: dependencies ? ['spire-agent', 'workload-api-socket'] : [] }; }),
    provider(sovereignSvid, (): ProviderObservation => { const openssl = commandPath('openssl'); return { supportState: openssl === null ? 'UNAVAILABLE' : 'EXPERIMENTAL', executableIdentity: openssl, health: { ok: openssl !== null, sovereignFallback: true, trustDomain: ROOT_TRUST_DOMAIN, privateKeyExport: false }, observedCapabilities: openssl === null ? [] : ['openssl'] }; }),
    provider(secret, (): ProviderObservation => ({ supportState: 'SUPPORTED', executableIdentity: process.execPath, health: { ok: true, secretValuesReturned: false, maximumSecretBytes: 1024 * 1024 }, observedCapabilities: ['filesystem-secret-reference'] })),
  ];
}
