import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import type { RootPlatformProvider } from '../provider-registry.ts';
import { PROVIDER_CONTRACT_VERSION, type ProviderDefinition, type ProviderObservation } from '../schemas.ts';
import { ROOT_TRUST_PROVIDER_VERSION, ROOT_TRUST_SCHEMA_VERSION } from './schemas.ts';

function definition(input: Omit<ProviderDefinition, 'contractVersion' | 'configurationDigest'> & { configuration: JsonObject }): ProviderDefinition {
  const { configuration, ...rest } = input;
  return { ...rest, contractVersion: PROVIDER_CONTRACT_VERSION, configurationDigest: sha256(canonicalize(configuration)) };
}
function provider(definitionValue: ProviderDefinition, probe: () => ProviderObservation): RootPlatformProvider { return { definition: definitionValue, probe }; }
function skopeoVersion(): { path: string | null; version: string | null } {
  if (!existsSync('/usr/bin/skopeo')) return { path: null, version: null };
  const result = spawnSync('/usr/bin/skopeo', ['--version'], { encoding: 'utf8', timeout: 2_000 });
  return result.status === 0 ? { path: '/usr/bin/skopeo', version: result.stdout.trim() } : { path: '/usr/bin/skopeo', version: null };
}

export function trustProviders(): RootPlatformProvider[] {
  const oci = definition({
    providerId: 'oci-skill-bundle', family: 'bundle-trust', implementationVersion: 'oci-skill-bundle@1', requiredCapabilities: ['skopeo', 'sha256'],
    limits: { maximumManifestBytes: 16 * 1024 * 1024, maximumLayerBytes: 1024 * 1024 * 1024, maximumLayers: 128 },
    restartBehavior: 'reverify_cached_content_and_durable_records', cancellationBehavior: 'bounded_registry_commands', cleanupBehavior: 'atomic_cache_temp_removal',
    errors: ['mutable_tag_rejected', 'manifest_digest_mismatch', 'media_type_rejected', 'registry_failure'],
    configuration: { schemaVersion: ROOT_TRUST_SCHEMA_VERSION, manifestIdentity: 'sha256-digest-only', tagsDiscoveryOnly: true },
  });
  const signature = definition({
    providerId: 'sigstore-offline-verifier', family: 'bundle-trust', implementationVersion: 'sigstore-bundle-v0.3-offline@1', requiredCapabilities: ['node-crypto', 'local-trust-roots'],
    limits: { maximumTrustedKeys: 32, maximumTlogEntries: 16 }, restartBehavior: 'durable_verification_readback', cancellationBehavior: 'verification_is_bounded', cleanupBehavior: 'no_owned_live_resources',
    errors: ['signature_invalid', 'signer_revoked', 'certificate_identity_mismatch', 'transparency_required'],
    configuration: { bundleMediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.3', publicKeylessInfrastructureRequired: false, onlineRekorRequired: false },
  });
  const provenance = definition({
    providerId: 'slsa-in-toto-verifier', family: 'provenance', implementationVersion: 'slsa-v1-in-toto-v1-dsse@1', requiredCapabilities: ['node-crypto'],
    limits: { maximumEnvelopeBytes: 8 * 1024 * 1024, maximumDescriptors: 256 }, restartBehavior: 'durable_verification_readback', cancellationBehavior: 'verification_is_bounded', cleanupBehavior: 'no_owned_live_resources',
    errors: ['dsse_signature_invalid', 'source_mismatch', 'builder_mismatch', 'dependency_mismatch'],
    configuration: { predicateType: 'https://slsa.dev/provenance/v1', statementType: 'https://in-toto.io/Statement/v1' },
  });
  const transparency = definition({
    providerId: 'transparency-monitor', family: 'transparency', implementationVersion: `${ROOT_TRUST_PROVIDER_VERSION}+rfc6962`, requiredCapabilities: ['node-crypto', 'proof-authority'],
    limits: { maximumProofHashes: 256, maximumCheckpointAgeSeconds: 31_536_000 }, restartBehavior: 'reclassify_checkpoint_freshness_from_durable_monitor', cancellationBehavior: 'verification_is_bounded', cleanupBehavior: 'no_second_proof_authority',
    errors: ['inclusion_failure', 'consistency_failure', 'stale_checkpoint', 'conflicting_checkpoint'],
    configuration: { proofAuthority: 'existing-baby-x-proof-authority', publicMonitorEnabled: false, sovereignOfflineVerification: true },
  });
  return [
    provider(oci, (): ProviderObservation => { const observed = skopeoVersion(); return { supportState: observed.version === null ? 'UNAVAILABLE' : 'SUPPORTED', executableIdentity: observed.path === null ? null : `${observed.path}:${observed.version}`, health: { ok: observed.version !== null, version: observed.version, digestPinnedExecution: true, mutableTagsDiscoveryOnly: true }, observedCapabilities: observed.version === null ? ['sha256'] : ['skopeo', 'sha256'] }; }),
    provider(signature, (): ProviderObservation => ({ supportState: 'SUPPORTED', executableIdentity: process.execPath, health: { ok: true, keyed: true, configuredKeyless: true, offlineBundles: true, publicKeylessInfrastructureRequired: false }, observedCapabilities: ['node-crypto', 'local-trust-roots'] })),
    provider(provenance, (): ProviderObservation => ({ supportState: 'SUPPORTED', executableIdentity: process.execPath, health: { ok: true, dsse: true, inTotoStatementV1: true, slsaProvenanceV1: true }, observedCapabilities: ['node-crypto'] })),
    provider(transparency, (): ProviderObservation => ({ supportState: 'DEGRADED', executableIdentity: process.execPath, health: { ok: true, offlineVerification: true, publicMonitorEnabled: false, proofAuthority: 'existing-baby-x-proof-authority' }, observedCapabilities: ['node-crypto', 'proof-authority'] })),
  ];
}
