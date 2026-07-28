import { canonicalize, sha256, type JsonObject } from '../core.ts';
import { RootPlatformError } from './errors.ts';
import { sealProviderDescriptor, supportState, validateProviderDefinition, type ProviderDefinition, type ProviderDescriptor, type ProviderObservation, type ProviderSupportState } from './schemas.ts';

export interface RootPlatformProvider {
  readonly definition: ProviderDefinition;
  probe(): ProviderObservation;
}

function failedObservation(error: unknown): ProviderObservation {
  return {
    supportState: 'FAILED',
    executableIdentity: null,
    health: { ok: false, error: error instanceof RootPlatformError ? error.code : 'root_platform_provider_failed' },
    observedCapabilities: [],
  };
}

export class ProviderRegistry {
  private readonly providers = new Map<string, RootPlatformProvider>();

  constructor(providers: readonly RootPlatformProvider[]) {
    for (const provider of providers) {
      const definition = validateProviderDefinition(provider.definition);
      if (this.providers.has(definition.providerId)) throw new RootPlatformError('root_platform_duplicate_provider', `duplicate provider: ${definition.providerId}`, { providerId: definition.providerId });
      this.providers.set(definition.providerId, { definition, probe: provider.probe.bind(provider) });
    }
  }

  registryDigest(): string {
    const definitions = [...this.providers.values()].map((provider) => provider.definition).sort((left, right) => left.providerId.localeCompare(right.providerId));
    return sha256(canonicalize(definitions));
  }

  get(providerId: string): ProviderDescriptor {
    const provider = this.providers.get(providerId);
    if (provider === undefined) throw new RootPlatformError('root_platform_provider_not_found', `unknown provider: ${providerId}`, { providerId });
    let observation: ProviderObservation;
    try { observation = provider.probe(); }
    catch (error) { observation = failedObservation(error); }
    return sealProviderDescriptor(provider.definition, observation);
  }

  list(filters: { family?: string; supportState?: ProviderSupportState } = {}): ProviderDescriptor[] {
    return [...this.providers.keys()]
      .sort()
      .map((providerId) => this.get(providerId))
      .filter((provider) => filters.family === undefined || provider.family === filters.family)
      .filter((provider) => filters.supportState === undefined || provider.supportState === filters.supportState);
  }

  assertSupportState(value: unknown): ProviderSupportState { return supportState(value); }

  describe(): JsonObject {
    const providers = this.list();
    return { contractVersion: providers[0]?.contractVersion ?? null, providerCount: providers.length, providerRegistryDigest: this.registryDigest(), providers };
  }
}
