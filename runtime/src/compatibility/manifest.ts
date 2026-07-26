import { createHash } from 'node:crypto';

export const COMPATIBILITY_MANIFEST_SCHEMA_VERSION = '1.0.0' as const;
export const BABY_X_CORE_COMPATIBILITY_VERSION = '2.0.0' as const;
export const OPERATION_CATALOG_VERSION = '2.0.0' as const;
export const TRANSACTION_LEGACY_SCHEMA_VERSION = '1.0.0' as const;
export const TRANSACTION_SCHEMA_VERSION = '1.1.0' as const;

export type DurableSchemaDomain =
  | 'durableJob'
  | 'machineRecord'
  | 'machineEvent'
  | 'machineTombstone'
  | 'artifact'
  | 'receipt'
  | 'proofContract'
  | 'certification'
  | 'executionPolicy'
  | 'candidateRacing'
  | 'transaction';

export class CoreCompatibilityError extends Error {
  constructor(readonly code: string, message: string, readonly details: Readonly<Record<string, unknown>> = {}) {
    super(message);
    this.name = 'CoreCompatibilityError';
  }
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const object = value as Record<string, unknown>;
  return '{' + Object.keys(object).sort().map((key) => JSON.stringify(key) + ':' + canonicalize(object[key])).join(',') + '}';
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const entry of Object.values(value as Record<string, unknown>)) deepFreeze(entry);
  }
  return value;
}

const manifestDraft = {
  manifestSchemaVersion: COMPATIBILITY_MANIFEST_SCHEMA_VERSION,
  babyXCoreCompatibilityVersion: BABY_X_CORE_COMPATIBILITY_VERSION,
  operationCatalogVersion: OPERATION_CATALOG_VERSION,
  durableJobSchemaVersion: '1.0.0',
  durableJobReconciliationVersion: '1.0.0',
  machineRecordSchemaVersion: '1.0.0',
  machineEventSchemaVersion: '1.0.0',
  machineTombstoneSchemaVersion: '1.0.0',
  artifactSchemaVersion: '1.0.0',
  receiptSchemaVersion: '1.0.0',
  proofContractVersion: '1',
  certificationSchemaVersion: '1.0.0',
  executionPolicyVersion: '1.0.0',
  candidateRacingVersion: '1.0.0',
  transactionSchemaVersion: TRANSACTION_SCHEMA_VERSION,
  schemas: {
    durableJob: { current: '1.0.0', readable: ['1.0.0'], unknownNewer: 'reject' },
    machineRecord: { current: '1.0.0', readable: ['1.0.0'], unknownNewer: 'reject' },
    machineEvent: { current: '1.0.0', readable: ['1.0.0'], unknownNewer: 'reject' },
    machineTombstone: { current: '1.0.0', readable: ['1.0.0'], unknownNewer: 'reject' },
    artifact: { current: '1.0.0', readable: ['1.0.0'], unknownNewer: 'reject' },
    receipt: { current: '1.0.0', readable: ['1.0.0'], unknownNewer: 'reject' },
    proofContract: { current: '1', readable: ['1'], unknownNewer: 'reject' },
    certification: { current: '1.0.0', readable: ['1.0.0'], unknownNewer: 'reject' },
    executionPolicy: { current: '1.0.0', readable: ['1.0.0'], unknownNewer: 'reject' },
    candidateRacing: { current: '1.0.0', readable: ['1.0.0'], unknownNewer: 'reject' },
    transaction: { current: TRANSACTION_SCHEMA_VERSION, readable: [TRANSACTION_LEGACY_SCHEMA_VERSION, TRANSACTION_SCHEMA_VERSION], unknownNewer: 'reject' },
  },
  supportedProviderContracts: [
    { providerId: 'zfs-nspawn-disposable@1', contractVersion: '1.0.0', readableMachineSchemaVersions: ['1.0.0'] },
  ],
  supportedMigrationPaths: [
    {
      from: 'god-mode-v1-durable-records',
      to: 'transaction-foundation-v2',
      mode: 'explicit-additive',
      authoritativeRecordRewrite: false,
      migrationRequired: false,
    },
  ],
  godModeV1DurableRecordCompatibility: {
    readable: true,
    writableWithoutMigration: true,
    silentAuthoritativeRewrite: false,
    readableSchemaVersions: {
      durableJob: ['1.0.0'],
      machineRecord: ['1.0.0'],
      machineEvent: ['1.0.0'],
      machineTombstone: ['1.0.0'],
      artifact: ['1.0.0'],
      receipt: ['1.0.0'],
      proofContract: ['1'],
      certification: ['1.0.0'],
      executionPolicy: ['1.0.0'],
      candidateRacing: ['1.0.0'],
    },
  },
  unknownNewerSchemaBehavior: {
    action: 'reject',
    failClosed: true,
    errorCode: 'core_schema_unsupported',
    authoritativeRecordRewrite: false,
  },
  frozenRollback: {
    branch: 'build/baby-x-god-mode-v1',
    evidenceCommit: 'b8dcc150ddc175b2ad00099df405b8a3bf0e843a',
    evidenceTree: '2045a746e0c6d928cf3354fd0ef9544918fbf514',
  },
  certifiedImplementation: {
    commit: 'ec6a955983753e30e4ed35bd3cceae348737bd6a',
    tree: 'd56f37dffcfb079151258aa47a7c9d19294d3ba0',
  },
  protectedSourceSnapshot: {
    name: 'babycert/base/noble@golden-v1',
    expectedGuid: '9351137475418520293',
    expectedCreationTxg: '53',
  },
} as const;

export const FROZEN_CORE_COMPATIBILITY_MANIFEST = deepFreeze(manifestDraft);

export type CoreCompatibilityManifest = typeof FROZEN_CORE_COMPATIBILITY_MANIFEST;

export function coreCompatibilityManifest(): CoreCompatibilityManifest {
  return structuredClone(FROZEN_CORE_COMPATIBILITY_MANIFEST);
}

export function compatibilityManifestCanonical(): string {
  return canonicalize(FROZEN_CORE_COMPATIBILITY_MANIFEST);
}

export function compatibilityManifestDigest(): string {
  return sha256(compatibilityManifestCanonical());
}

export function assertCompatibilityManifest(value: unknown): CoreCompatibilityManifest {
  if (canonicalize(value) !== compatibilityManifestCanonical()) {
    throw new CoreCompatibilityError('core_manifest_incompatible', 'compatibility manifest is not the exact supported canonical manifest');
  }
  return structuredClone(FROZEN_CORE_COMPATIBILITY_MANIFEST);
}

export function assertReadableSchema(domain: string, schemaVersion: string): void {
  const schemas = FROZEN_CORE_COMPATIBILITY_MANIFEST.schemas as Readonly<Record<string, { readonly readable: readonly string[] }>>;
  const schema = schemas[domain];
  if (schema === undefined || !schema.readable.includes(schemaVersion)) {
    throw new CoreCompatibilityError('core_schema_unsupported', 'durable schema version is not readable', { domain, schemaVersion });
  }
}

export function assertProviderCompatibility(providerId: string, contractVersion: string): void {
  const supported = FROZEN_CORE_COMPATIBILITY_MANIFEST.supportedProviderContracts
    .some((provider) => provider.providerId === providerId && provider.contractVersion === contractVersion);
  if (!supported) throw new CoreCompatibilityError('core_provider_incompatible', 'provider contract is not compatible', { providerId, contractVersion });
}

export interface CoreCompatibilityReportOptions {
  currentSourceCommit?: string | null;
  currentSourceTree?: string | null;
}

export function describeCoreCompatibility(options: CoreCompatibilityReportOptions = {}): Record<string, unknown> {
  const manifest = coreCompatibilityManifest();
  return {
    operation: 'babyx.core.compatibility',
    readOnly: true,
    manifestSchemaVersion: manifest.manifestSchemaVersion,
    manifestDigest: compatibilityManifestDigest(),
    currentDevelopmentCompatibilityIdentity: {
      branch: 'build/baby-x-transactional-tool-fabric-v2',
      babyXCoreCompatibilityVersion: manifest.babyXCoreCompatibilityVersion,
      operationCatalogVersion: manifest.operationCatalogVersion,
      sourceCommit: options.currentSourceCommit ?? null,
      sourceTree: options.currentSourceTree ?? null,
    },
    frozenBaselineIdentity: structuredClone(manifest.frozenRollback),
    certifiedImplementationIdentity: structuredClone(manifest.certifiedImplementation),
    readablePriorSchemaVersions: Object.fromEntries(
      Object.entries(manifest.schemas).map(([domain, schema]) => [domain, [...schema.readable]]),
    ),
    unsupportedNewerVersions: structuredClone(manifest.unknownNewerSchemaBehavior),
    providerCompatibility: structuredClone(manifest.supportedProviderContracts),
    transactionSchemaSupport: structuredClone(manifest.schemas.transaction),
    migrationRequirementStatus: {
      required: false,
      mode: 'explicit-additive',
      authoritativeRecordRewrite: false,
      paths: structuredClone(manifest.supportedMigrationPaths),
    },
    manifest,
  };
}
