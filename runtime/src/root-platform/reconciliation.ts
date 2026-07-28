import type { JsonObject, RuntimeExecutionContext } from '../core.ts';
import { ProviderRegistry } from './provider-registry.ts';
import { ProviderReconciliationStore } from './records.ts';
import { providerIdentifier, strictPayload } from './schemas.ts';

export class ProviderReconciler {
  constructor(private readonly registry: ProviderRegistry, private readonly records: ProviderReconciliationStore) {}

  reconcile(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictPayload(payloadValue, 'provider reconcile payload', ['providerId']);
    const providerId = providerIdentifier(payload.providerId);
    const provider = this.registry.get(providerId);
    const reconciliation = this.records.reconcile(provider, context);
    return { provider, reconciliation };
  }
}
