import { canonicalize, sha256, type JsonObject } from '../core.ts';
import { ROOT_BROKER_PROTOCOL_VERSION, ROOT_FABRIC_PROVIDER_VERSION, ROOT_FABRIC_SCHEMA_VERSION, ROOT_FABRIC_VERSION, RootFabricError, strictObject, text } from './model.ts';

export const ROOT_A_G_CATALOG_VERSION = '3.1.0' as const;
export const ROOT_A_G_COMPATIBILITY_VERSION = '1.0.0' as const;
export const ROOT_A_G_SCHEMA_IDENTIFIERS = Object.freeze({
  transaction: ROOT_FABRIC_SCHEMA_VERSION,
  event: ROOT_FABRIC_SCHEMA_VERSION,
  effect: '1.0.0',
  grant: '1.0.0',
  bundle: '1.0.0',
  brokerProtocol: ROOT_BROKER_PROTOCOL_VERSION,
  observationReference: '1.0.0',
  credentialReference: '1.0.0',
});

export const ROOT_A_G_RECORD_KEYS = Object.freeze({
  transaction: ['schemaVersion', 'providerVersion', 'transactionId', 'transactionKind', 'ownerPrincipal', 'skill', 'request', 'lifecycle', 'lease', 'policy', 'routing', 'plan', 'preparation', 'execution', 'observations', 'validation', 'rollback', 'compensation', 'credentials', 'cleanup', 'evidence', 'error', 'events', 'eventHeadDigest', 'recordDigest'],
  event: ['schemaVersion', 'eventId', 'transactionId', 'sequence', 'stateGeneration', 'ownerPrincipalDigest', 'skillBundleDigest', 'operation', 'phase', 'priorState', 'nextState', 'requestDigest', 'idempotencyKeyDigest', 'occurredAt', 'fencingToken', 'provider', 'references', 'observationDigest', 'previousEventDigest', 'eventDigest'],
  effect: ['schemaVersion', 'operation', 'version', 'effectClass', 'atomicityModes', 'providers', 'requiredCapabilities', 'restartBehavior', 'cancellable', 'timeoutMs', 'rollbackOperation', 'compensationOperation'],
  grant: ['schemaVersion', 'grantId', 'ownerPrincipal', 'bundleDigest', 'operations', 'providers', 'effectClasses', 'resources', 'credentialReferences', 'limits', 'issuedAt', 'expiresAt', 'revokedAt', 'grantDigest'],
  bundle: ['schemaVersion', 'skillId', 'skillVersion', 'manifest', 'files', 'signerKeyId', 'signerIdentity', 'signature', 'issuedAt', 'expiresAt', 'bundleDigest'],
  broker: ['protocolVersion', 'requestId', 'transactionId', 'transactionSequence', 'fencingToken', 'ownerPrincipalDigest', 'skillBundleDigest', 'grantDigest', 'policyDecisionDigest', 'operation', 'operationVersion', 'operationInput', 'inputDigest', 'deadline', 'nonce', 'selectedProvider', 'credentialReferences'],
} as const);

export interface RootCompatibilityOptions {
  sourceCommit: string;
  sourceTree: string;
  catalogVersion?: string;
  catalogDigest: string;
  providerContractVersions?: Readonly<Record<string, string>>;
}

function major(version: string): number {
  const match = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u.exec(version);
  if (match === null) throw new RootFabricError('unsupported_schema', 'schema version must be exact semantic version');
  return Number(match[1]);
}

export function requireCompatibleMajor(value: unknown, expected: string, field = 'schemaVersion'): string {
  const version = text(value, field, 64);
  if (major(version) !== major(expected)) throw new RootFabricError('unsupported_schema', `${field} major version is unsupported`, { expected, observed: version });
  return version;
}

export function validateStrictVersionedRecord(value: unknown, kind: keyof typeof ROOT_A_G_RECORD_KEYS): JsonObject {
  const record = strictObject(value, `${kind} record`, ROOT_A_G_RECORD_KEYS[kind]);
  const versionField = kind === 'broker' ? 'protocolVersion' : 'schemaVersion';
  const expected = kind === 'broker' ? ROOT_BROKER_PROTOCOL_VERSION : kind === 'transaction' || kind === 'event' ? ROOT_FABRIC_SCHEMA_VERSION : '1.0.0';
  requireCompatibleMajor(record[versionField], expected, versionField);
  return record;
}

export function readLegacyRootRecord(value: unknown): JsonObject {
  const record = strictObject(value, 'legacy root record', ['schemaVersion', 'record']);
  const version = text(record.schemaVersion, 'schemaVersion', 64);
  if (version !== '0.1.0' && major(version) !== major(ROOT_FABRIC_SCHEMA_VERSION)) throw new RootFabricError('unsupported_schema', 'legacy root record version is unsupported');
  return record;
}

export function createRootCompatibilityManifest(options: RootCompatibilityOptions): { manifest: JsonObject; digest: string } {
  const catalogVersion = options.catalogVersion ?? ROOT_A_G_CATALOG_VERSION;
  requireCompatibleMajor(catalogVersion, ROOT_A_G_CATALOG_VERSION, 'catalogVersion');
  const providerContracts = Object.fromEntries(Object.entries(options.providerContractVersions ?? {
    rootFabric: ROOT_FABRIC_PROVIDER_VERSION,
    hostEnvelope: 'systemd-transient@1',
    storage: 'existing-storage-authority@1',
    network: 'baby-x-owned-network-namespace@1',
  }).sort(([left], [right]) => left.localeCompare(right)));
  const manifest: JsonObject = {
    compatibilityVersion: ROOT_A_G_COMPATIBILITY_VERSION,
    rootFabricVersion: ROOT_FABRIC_VERSION,
    schemaIdentifiers: ROOT_A_G_SCHEMA_IDENTIFIERS,
    catalogVersion,
    catalogDigest: options.catalogDigest,
    sourceCommit: options.sourceCommit,
    sourceTree: options.sourceTree,
    providerContracts,
    migrationPaths: { '0.1.0': 'read-only', '1.0.0': 'native' },
    prompt1: { originalRootOperations: 11, newAGOperations: 26, expectedRootOperations: 37, typedEffects: 31 },
    forwardCompatibility: { unknownFields: 'reject', unknownMajorVersions: 'reject', observationReferences: 'identifier-only', credentialReferences: 'identifier-only' },
  };
  return { manifest, digest: sha256(canonicalize(manifest)) };
}
