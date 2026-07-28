import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { verifyRootTransactionRecord, type RootTransactionRecord } from '../root-authority/service.ts';
import { defaultProviders, probeHostCapabilities, PROMPT1_COMMIT, PROMPT1_TREE } from './compatibility.ts';
import { RootPlatformError } from './errors.ts';
import { ProviderRegistry, type RootPlatformProvider } from './provider-registry.ts';
import { ProviderReconciler } from './reconciliation.ts';
import { ProviderReconciliationStore } from './records.ts';
import { ROOT_PLATFORM_PROVIDER_VERSION, ROOT_PLATFORM_SCHEMA_VERSION, page, providerIdentifier, strictPayload, supportState, type ProviderSupportState } from './schemas.ts';

export interface SovereignRootPlatformIdentity {
  runningCommit: string;
  runningTree: string;
  protocolVersion: string;
  catalogVersion: string;
  catalogDigest: string;
}

export class SovereignRootPlatformService {
  private readonly registry: ProviderRegistry;
  private readonly records: ProviderReconciliationStore;
  private readonly reconciler: ProviderReconciler;

  constructor(options: { stateRoot: string; identity: SovereignRootPlatformIdentity; providers?: readonly RootPlatformProvider[]; now?: () => string }) {
    this.identity = structuredClone(options.identity);
    this.registry = new ProviderRegistry(options.providers ?? defaultProviders(this.identity));
    this.records = new ProviderReconciliationStore(options.stateRoot, { now: options.now });
    this.reconciler = new ProviderReconciler(this.registry, this.records);
  }

  private readonly identity: SovereignRootPlatformIdentity;

  platformDescribe(): JsonObject {
    const providers = this.registry.list();
    const host = probeHostCapabilities();
    const description = {
      schemaVersion: ROOT_PLATFORM_SCHEMA_VERSION,
      prompt1: { commit: PROMPT1_COMMIT, tree: PROMPT1_TREE },
      running: { commit: this.identity.runningCommit, tree: this.identity.runningTree },
      protocol: this.identity.protocolVersion,
      catalogVersion: this.identity.catalogVersion,
      catalogDigest: this.identity.catalogDigest,
      prompt1RootProviderVersion: 'transactional-root-authority@1',
      prompt2PlatformVersion: ROOT_PLATFORM_PROVIDER_VERSION,
      providerRegistryDigest: this.registry.registryDigest(),
      host,
      providers,
      migration: { prompt1RecordsReadable: true, prompt1RecordsVerifiable: true, strategy: 'sidecar-only', prompt1HistoriesRewritten: false },
    };
    return { ...description, platformDigest: sha256(canonicalize(description)) };
  }

  providerList(payloadValue: unknown): JsonObject {
    const payload = strictPayload(payloadValue, 'provider list payload', ['family', 'supportState', 'offset', 'limit']);
    const family = payload.family === undefined ? undefined : providerIdentifier(payload.family, 'family');
    const state = payload.supportState === undefined ? undefined : supportState(payload.supportState);
    const pagination = page(payload);
    const all = this.registry.list({ family, supportState: state as ProviderSupportState | undefined });
    const providers = all.slice(pagination.offset, pagination.offset + pagination.limit);
    return { providers, offset: pagination.offset, limit: pagination.limit, total: all.length, nextOffset: pagination.offset + providers.length < all.length ? pagination.offset + providers.length : null, providerRegistryDigest: this.registry.registryDigest() };
  }

  providerGet(payloadValue: unknown): JsonObject {
    const payload = strictPayload(payloadValue, 'provider get payload', ['providerId']);
    const providerId = providerIdentifier(payload.providerId);
    return { provider: this.registry.get(providerId), latestReconciliation: this.records.latest(providerId) };
  }

  providerReconcile(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject { return this.reconciler.reconcile(payloadValue, context); }

  verifyPrompt1Record(record: RootTransactionRecord): JsonObject {
    const verification = verifyRootTransactionRecord(record);
    return { compatible: verification.valid, prompt1RecordPreserved: true, sidecarOnly: true, errors: verification.errors };
  }

  assertKnownProvider(providerId: string): JsonObject {
    try { return this.registry.get(providerIdentifier(providerId)); }
    catch (error) {
      if (error instanceof RootPlatformError) throw error;
      throw new RootPlatformError('root_platform_provider_not_found', 'provider is unknown');
    }
  }
}
