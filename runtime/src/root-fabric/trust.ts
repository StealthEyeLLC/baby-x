import { join, posix } from 'node:path';
import { canonicalize, sha256, verifyCanonical, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../storage/record-store.ts';
import { RootFabricError, contextPrincipal, digest, idempotency, identifier, integer, object, strictObject, stringArray, text, timestamp, type RootEffectClass, type RootExecutionProvider } from './model.ts';

export const ROOT_BUNDLE_SCHEMA_VERSION = '1.0.0' as const;
export const ROOT_GRANT_SCHEMA_VERSION = '1.0.0' as const;

export interface BundleFileEntry extends JsonObject {
  path: string;
  type: 'file' | 'directory' | 'symlink';
  mode: number;
  size: number;
  sha256: string;
  symlinkTarget: string | null;
}

export interface RootSkillBundleRecord extends JsonObject {
  schemaVersion: typeof ROOT_BUNDLE_SCHEMA_VERSION;
  bundleFormatVersion: '1.0.0';
  skillId: string;
  skillVersion: string;
  entrypoints: JsonObject;
  operationDefinitions: JsonObject[];
  capabilityRequirements: string[];
  providerRequirements: RootExecutionProvider[];
  resourceDeclarations: JsonObject;
  dependencyDigests: string[];
  files: BundleFileEntry[];
  buildIdentity: JsonObject;
  signerIdentity: string;
  signatureAlgorithm: 'Ed25519';
  signerKeyId: string;
  createdAt: string;
  expiresAt: string;
  compatibilityRequirements: JsonObject;
  testManifest: JsonObject;
  unsignedManifestDigest: string;
  bundleDigest: string;
  signature: string;
  signatureVerified: boolean;
  state: 'ACTIVE' | 'EXPIRED' | 'REVOKED' | 'INVALID';
  revokedAt: string | null;
  revocationReason: string | null;
  recordDigest: string;
}

export interface RootCapabilityGrantRecord extends JsonObject {
  schemaVersion: typeof ROOT_GRANT_SCHEMA_VERSION;
  grantId: string;
  skillId: string;
  bundleDigest: string;
  ownerPrincipal: string;
  allowedOperations: string[];
  resourceSelectors: JsonObject;
  allowedProviders: RootExecutionProvider[];
  effectClasses: RootEffectClass[];
  limits: JsonObject;
  credentialReferences: string[];
  policyVersion: string;
  issuedAt: string;
  expiresAt: string;
  state: 'ACTIVE' | 'EXPIRED' | 'REVOKED' | 'SUPERSEDED' | 'INVALID';
  revokedAt: string | null;
  revocationReason: string | null;
  grantDigest: string;
  recordDigest: string;
}

type PublicKeyResolver = (keyId: string) => string | Buffer | undefined;
const PROVIDERS = new Set<RootExecutionProvider>(['HOST_ENVELOPE', 'DISPOSABLE_MACHINE']);
const EFFECT_CLASSES = new Set<RootEffectClass>(['REVERSIBLE', 'COMPENSATABLE', 'IRREVERSIBLE']);

function unsigned<T extends JsonObject>(record: T): JsonObject {
  const { recordDigest: _recordDigest, ...rest } = record;
  return rest;
}

function seal<T extends JsonObject>(record: Omit<T, 'recordDigest'>): T {
  return { ...record, recordDigest: sha256(canonicalize(record)) } as T;
}

function verifySealed(record: JsonObject): boolean {
  return typeof record.recordDigest === 'string' && record.recordDigest === sha256(canonicalize(unsigned(record)));
}

function normalizedPath(value: unknown, field: string): string {
  const path = text(value, field, 1_024);
  if (path.startsWith('/') || path.includes('\0') || path.split('/').includes('..')) throw new RootFabricError('invalid_request', `${field} is not a confined relative path`);
  const normalized = posix.normalize(path);
  if (normalized === '.' || normalized.startsWith('../') || normalized !== path) throw new RootFabricError('invalid_request', `${field} is not canonically normalized`);
  return normalized;
}

function normalizeFile(value: unknown, index: number): BundleFileEntry {
  const entry = strictObject(value, `files[${index}]`, ['path', 'type', 'mode', 'size', 'sha256', 'symlinkTarget']);
  const type = text(entry.type, `files[${index}].type`, 16);
  if (!['file', 'directory', 'symlink'].includes(type)) throw new RootFabricError('invalid_request', 'bundle file type is unsupported');
  const symlinkTarget = entry.symlinkTarget === null || entry.symlinkTarget === undefined ? null : text(entry.symlinkTarget, `files[${index}].symlinkTarget`, 1_024);
  if (type === 'symlink') {
    if (symlinkTarget === null || symlinkTarget.startsWith('/') || symlinkTarget.split('/').includes('..')) throw new RootFabricError('symlink_escape', 'bundle symlink target escapes the bundle root');
  } else if (symlinkTarget !== null) throw new RootFabricError('invalid_request', 'only symlinks may define symlinkTarget');
  return {
    path: normalizedPath(entry.path, `files[${index}].path`),
    type: type as BundleFileEntry['type'], mode: integer(entry.mode, `files[${index}].mode`, 0, 0o7777),
    size: integer(entry.size, `files[${index}].size`, 0, 268_435_456), sha256: digest(entry.sha256, `files[${index}].sha256`), symlinkTarget,
  };
}

function normalizeProviderList(value: unknown, field: string): RootExecutionProvider[] {
  return stringArray(value, field, 2, false).map((provider) => {
    if (!PROVIDERS.has(provider as RootExecutionProvider)) throw new RootFabricError('unsupported_provider', `${field} contains unsupported provider ${provider}`);
    return provider as RootExecutionProvider;
  }).sort();
}

function normalizeEffectClasses(value: unknown): RootEffectClass[] {
  return stringArray(value, 'effectClasses', 3, false).map((effectClass) => {
    if (!EFFECT_CLASSES.has(effectClass as RootEffectClass)) throw new RootFabricError('invalid_request', `unsupported effect class ${effectClass}`);
    return effectClass as RootEffectClass;
  }).sort();
}

function selectorAllows(expected: unknown, actual: unknown): boolean {
  if (Array.isArray(expected)) return expected.some((candidate) => candidate === actual);
  if (expected !== null && typeof expected === 'object' && !Array.isArray(expected)) {
    if (actual === null || typeof actual !== 'object' || Array.isArray(actual)) return false;
    return Object.entries(expected as JsonObject).every(([key, value]) => selectorAllows(value, (actual as JsonObject)[key]));
  }
  return expected === actual;
}

export class RootTrustService {
  private readonly bundles: DurableRecordStore<RootSkillBundleRecord>;
  private readonly bundleClaims: DurableClaimStore<RootSkillBundleRecord>;
  private readonly grants: DurableRecordStore<RootCapabilityGrantRecord>;
  private readonly grantClaims: DurableClaimStore<RootCapabilityGrantRecord>;
  private readonly now: () => string;

  constructor(stateRoot: string, private readonly publicKey: PublicKeyResolver, options: { now?: () => string } = {}) {
    const root = join(stateRoot, 'root-fabric', 'trust');
    this.bundles = new DurableRecordStore(join(root, 'bundles'));
    this.bundleClaims = new DurableClaimStore(join(root, 'bundle-claims'));
    this.grants = new DurableRecordStore(join(root, 'grants'));
    this.grantClaims = new DurableClaimStore(join(root, 'grant-claims'));
    this.now = options.now ?? (() => new Date().toISOString());
  }

  bundleVerify(payloadValue: unknown): JsonObject {
    const payload = strictObject(payloadValue, 'bundle verify payload', ['manifest', 'signature']);
    const manifest = strictObject(payload.manifest, 'manifest', ['schemaVersion', 'bundleFormatVersion', 'skillId', 'skillVersion', 'entrypoints', 'operationDefinitions', 'capabilityRequirements', 'providerRequirements', 'resourceDeclarations', 'dependencyDigests', 'files', 'buildIdentity', 'signerIdentity', 'signatureAlgorithm', 'signerKeyId', 'createdAt', 'expiresAt', 'compatibilityRequirements', 'testManifest', 'bundleDigest']);
    if (manifest.schemaVersion !== ROOT_BUNDLE_SCHEMA_VERSION || manifest.bundleFormatVersion !== '1.0.0') throw new RootFabricError('unsupported_schema', 'bundle schema or format is unsupported');
    if (manifest.signatureAlgorithm !== 'Ed25519') throw new RootFabricError('bundle_signature_invalid', 'bundle signature algorithm must be Ed25519');
    if (!Array.isArray(manifest.operationDefinitions) || manifest.operationDefinitions.length > 256 || manifest.operationDefinitions.some((entry) => entry === null || typeof entry !== 'object' || Array.isArray(entry))) throw new RootFabricError('invalid_request', 'operationDefinitions must be a bounded object array');
    if (!Array.isArray(manifest.files) || manifest.files.length > 100_000) throw new RootFabricError('invalid_request', 'files must be a bounded array');
    const files = manifest.files.map(normalizeFile).sort((left, right) => left.path.localeCompare(right.path));
    if (new Set(files.map((entry) => entry.path)).size !== files.length) throw new RootFabricError('invalid_request', 'bundle contains duplicate normalized paths');
    const createdAt = timestamp(manifest.createdAt, 'createdAt');
    const expiresAt = timestamp(manifest.expiresAt, 'expiresAt');
    if (Date.parse(expiresAt) <= Date.parse(createdAt)) throw new RootFabricError('bundle_expired', 'bundle expiry must follow creation');
    const unsignedManifest = {
      schemaVersion: ROOT_BUNDLE_SCHEMA_VERSION, bundleFormatVersion: '1.0.0', skillId: identifier(manifest.skillId, 'skillId'),
      skillVersion: text(manifest.skillVersion, 'skillVersion', 128), entrypoints: object(manifest.entrypoints, 'entrypoints'),
      operationDefinitions: manifest.operationDefinitions as JsonObject[], capabilityRequirements: stringArray(manifest.capabilityRequirements, 'capabilityRequirements', 512),
      providerRequirements: normalizeProviderList(manifest.providerRequirements, 'providerRequirements'), resourceDeclarations: object(manifest.resourceDeclarations, 'resourceDeclarations'),
      dependencyDigests: stringArray(manifest.dependencyDigests, 'dependencyDigests', 4096).map((value, index) => digest(value, `dependencyDigests[${index}]`)).sort(), files,
      buildIdentity: object(manifest.buildIdentity, 'buildIdentity'), signerIdentity: identifier(manifest.signerIdentity, 'signerIdentity'), signatureAlgorithm: 'Ed25519' as const,
      signerKeyId: identifier(manifest.signerKeyId, 'signerKeyId'), createdAt, expiresAt, compatibilityRequirements: object(manifest.compatibilityRequirements, 'compatibilityRequirements'), testManifest: object(manifest.testManifest, 'testManifest'),
    };
    const unsignedManifestDigest = sha256(canonicalize(unsignedManifest));
    const bundleDigest = digest(manifest.bundleDigest, 'bundleDigest');
    if (bundleDigest !== sha256(canonicalize({ unsignedManifest, unsignedManifestDigest }))) throw new RootFabricError('bundle_digest_mismatch', 'bundle digest does not match the canonical manifest');
    const key = this.publicKey(unsignedManifest.signerKeyId);
    if (key === undefined) throw new RootFabricError('signer_revoked', 'bundle signer is not trusted');
    const signature = text(payload.signature, 'signature', 8_192);
    if (!verifyCanonical(key, { unsignedManifest, unsignedManifestDigest, bundleDigest }, signature)) throw new RootFabricError('bundle_signature_invalid', 'bundle signature verification failed');
    const state = Date.parse(expiresAt) <= Date.parse(this.now()) ? 'EXPIRED' : 'ACTIVE';
    return { verified: state === 'ACTIVE', state, record: seal<RootSkillBundleRecord>({ ...unsignedManifest, unsignedManifestDigest, bundleDigest, signature, signatureVerified: true, state, revokedAt: null, revocationReason: null } as Omit<RootSkillBundleRecord, 'recordDigest'>) };
  }

  bundleInstall(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'bundle install payload', ['manifest', 'signature']);
    const verification = this.bundleVerify(payload) as { verified: boolean; state: string; record: RootSkillBundleRecord };
    if (!verification.verified) throw new RootFabricError('bundle_expired', 'expired bundle cannot be installed');
    const principal = contextPrincipal(context, this.now());
    const idem = idempotency(context);
    const request = sha256(canonicalize({ operation: 'babyx.root.bundle.install', principal: principal.principalDigest, bundleDigest: verification.record.bundleDigest }));
    const key = `${principal.principalDigest}:${idem.key}`;
    const existing = this.bundleClaims.get(key);
    if (existing !== undefined) {
      if (existing.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another bundle install');
      if (!this.bundles.has(existing.recordId)) this.bundles.create(existing.recordId, existing.record);
      return { bundle: this.bundles.get(existing.recordId), replayed: true };
    }
    const claim = this.bundleClaims.claim(key, request, verification.record.bundleDigest, verification.record);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another bundle install');
    if (!this.bundles.has(claim.recordId)) this.bundles.create(claim.recordId, claim.record);
    return { bundle: this.bundles.get(claim.recordId), replayed: claim.recordId !== verification.record.bundleDigest };
  }

  bundleGet(payloadValue: unknown): JsonObject {
    const payload = strictObject(payloadValue, 'bundle get payload', ['bundleDigest']);
    const record = this.bundles.get(digest(payload.bundleDigest, 'bundleDigest'));
    if (!verifySealed(record)) throw new RootFabricError('corrupt_record', 'bundle record integrity failed');
    return { bundle: this.refreshBundle(record) };
  }

  bundleList(payloadValue: unknown): JsonObject {
    const payload = strictObject(payloadValue ?? {}, 'bundle list payload', ['state', 'offset', 'limit']);
    const state = payload.state === undefined ? undefined : text(payload.state, 'state', 32);
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, 10_000_000);
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, 200);
    const scan = this.bundles.scan((record) => state === undefined || this.refreshBundle(record).state === state, offset, limit);
    return { bundles: scan.records.filter(verifySealed).map((record) => this.refreshBundle(record)), offset, limit, total: scan.total, nextOffset: scan.nextOffset, corruptRecordIds: scan.corruptRecordIds };
  }

  bundleRevoke(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'bundle revoke payload', ['bundleDigest', 'reason']);
    contextPrincipal(context, this.now()); idempotency(context);
    const bundleDigest = digest(payload.bundleDigest, 'bundleDigest');
    const current = this.bundles.get(bundleDigest);
    if (current.state === 'REVOKED') return { bundle: current, replayed: true };
    const next = seal<RootSkillBundleRecord>({ ...unsigned(current), state: 'REVOKED', revokedAt: this.now(), revocationReason: text(payload.reason, 'reason', 1_024) } as Omit<RootSkillBundleRecord, 'recordDigest'>);
    this.bundles.put(bundleDigest, next);
    return { bundle: next, replayed: false };
  }

  grantInstall(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'grant install payload', ['grant']);
    const grant = strictObject(payload.grant, 'grant', ['schemaVersion', 'grantId', 'skillId', 'bundleDigest', 'ownerPrincipal', 'allowedOperations', 'resourceSelectors', 'allowedProviders', 'effectClasses', 'limits', 'credentialReferences', 'policyVersion', 'issuedAt', 'expiresAt']);
    if (grant.schemaVersion !== ROOT_GRANT_SCHEMA_VERSION) throw new RootFabricError('unsupported_schema', 'grant schema is unsupported');
    const owner = contextPrincipal(context, this.now());
    if (identifier(grant.ownerPrincipal, 'ownerPrincipal') !== owner.principalId) throw new RootFabricError('principal_mismatch', 'grant owner must match the authenticated principal');
    const bundleDigest = digest(grant.bundleDigest, 'bundleDigest');
    const bundle = this.refreshBundle(this.bundles.get(bundleDigest));
    if (bundle.state !== 'ACTIVE') throw new RootFabricError(bundle.state === 'REVOKED' ? 'bundle_revoked' : 'bundle_expired', 'grant cannot target an inactive bundle');
    if (bundle.skillId !== grant.skillId) throw new RootFabricError('grant_denied', 'grant Skill does not match bundle Skill');
    const issuedAt = timestamp(grant.issuedAt, 'issuedAt');
    const expiresAt = timestamp(grant.expiresAt, 'expiresAt');
    if (Date.parse(expiresAt) <= Date.parse(issuedAt) || Date.parse(expiresAt) <= Date.parse(this.now())) throw new RootFabricError('grant_expired', 'grant expiry is invalid or already elapsed');
    const recordBase = {
      schemaVersion: ROOT_GRANT_SCHEMA_VERSION, grantId: identifier(grant.grantId, 'grantId'), skillId: identifier(grant.skillId, 'skillId'), bundleDigest,
      ownerPrincipal: owner.principalId, allowedOperations: stringArray(grant.allowedOperations, 'allowedOperations', 512, false).map((value) => identifier(value, 'allowedOperation')).sort(),
      resourceSelectors: object(grant.resourceSelectors, 'resourceSelectors'), allowedProviders: normalizeProviderList(grant.allowedProviders, 'allowedProviders'),
      effectClasses: normalizeEffectClasses(grant.effectClasses), limits: object(grant.limits, 'limits'), credentialReferences: stringArray(grant.credentialReferences, 'credentialReferences', 256).sort(),
      policyVersion: text(grant.policyVersion, 'policyVersion', 64), issuedAt, expiresAt, state: 'ACTIVE' as const, revokedAt: null, revocationReason: null,
    };
    const grantDigest = sha256(canonicalize(recordBase));
    const record = seal<RootCapabilityGrantRecord>({ ...recordBase, grantDigest } as Omit<RootCapabilityGrantRecord, 'recordDigest'>);
    const idem = idempotency(context);
    const request = sha256(canonicalize({ operation: 'babyx.root.grant.install', principal: owner.principalDigest, grantDigest }));
    const claimKey = `${owner.principalDigest}:${idem.key}`;
    const existing = this.grantClaims.get(claimKey);
    if (existing !== undefined) {
      if (existing.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another grant install');
      if (!this.grants.has(existing.recordId)) this.grants.create(existing.recordId, existing.record);
      return { grant: this.grants.get(existing.recordId), replayed: true };
    }
    const claim = this.grantClaims.claim(claimKey, request, record.grantId, record);
    if (claim.requestDigest !== request) throw new RootFabricError('idempotency_conflict', 'idempotency key belongs to another grant install');
    if (!this.grants.has(claim.recordId)) this.grants.create(claim.recordId, claim.record);
    return { grant: this.grants.get(claim.recordId), replayed: claim.recordId !== record.grantId };
  }

  grantGet(payloadValue: unknown): JsonObject {
    const payload = strictObject(payloadValue, 'grant get payload', ['grantId']);
    const record = this.grants.get(identifier(payload.grantId, 'grantId'));
    if (!verifySealed(record)) throw new RootFabricError('corrupt_record', 'grant record integrity failed');
    return { grant: this.refreshGrant(record) };
  }

  grantList(payloadValue: unknown): JsonObject {
    const payload = strictObject(payloadValue ?? {}, 'grant list payload', ['state', 'ownerPrincipal', 'offset', 'limit']);
    const state = payload.state === undefined ? undefined : text(payload.state, 'state', 32);
    const ownerPrincipal = payload.ownerPrincipal === undefined ? undefined : identifier(payload.ownerPrincipal, 'ownerPrincipal');
    const offset = payload.offset === undefined ? 0 : integer(payload.offset, 'offset', 0, 10_000_000);
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, 200);
    const scan = this.grants.scan((record) => (state === undefined || this.refreshGrant(record).state === state) && (ownerPrincipal === undefined || record.ownerPrincipal === ownerPrincipal), offset, limit);
    return { grants: scan.records.filter(verifySealed).map((record) => this.refreshGrant(record)), offset, limit, total: scan.total, nextOffset: scan.nextOffset, corruptRecordIds: scan.corruptRecordIds };
  }

  grantRevoke(payloadValue: unknown, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'grant revoke payload', ['grantId', 'reason']);
    const owner = contextPrincipal(context, this.now()); idempotency(context);
    const grantId = identifier(payload.grantId, 'grantId');
    const current = this.grants.get(grantId);
    if (current.ownerPrincipal !== owner.principalId) throw new RootFabricError('principal_mismatch', 'grant owner mismatch');
    if (current.state === 'REVOKED') return { grant: current, replayed: true };
    const next = seal<RootCapabilityGrantRecord>({ ...unsigned(current), state: 'REVOKED', revokedAt: this.now(), revocationReason: text(payload.reason, 'reason', 1_024) } as Omit<RootCapabilityGrantRecord, 'recordDigest'>);
    this.grants.put(grantId, next);
    return { grant: next, replayed: false };
  }

  authorize(input: { grantId: string; bundleDigest: string; ownerPrincipal: string; operation: string; provider: RootExecutionProvider; effectClass: RootEffectClass; resources: JsonObject; credentialReferences?: string[] }): RootCapabilityGrantRecord {
    const grant = this.refreshGrant(this.grants.get(identifier(input.grantId, 'grantId')));
    if (grant.state !== 'ACTIVE') throw new RootFabricError(grant.state === 'REVOKED' ? 'grant_revoked' : 'grant_expired', 'grant is not active');
    const bundle = this.refreshBundle(this.bundles.get(digest(input.bundleDigest, 'bundleDigest')));
    if (bundle.state !== 'ACTIVE') throw new RootFabricError(bundle.state === 'REVOKED' ? 'bundle_revoked' : 'bundle_expired', 'bundle is not active');
    if (grant.bundleDigest !== bundle.bundleDigest || grant.ownerPrincipal !== input.ownerPrincipal || !grant.allowedOperations.includes(input.operation) || !grant.allowedProviders.includes(input.provider) || !grant.effectClasses.includes(input.effectClass)) throw new RootFabricError('grant_denied', 'semantic capability grant does not authorize the requested effect');
    if (!selectorAllows(grant.resourceSelectors, input.resources)) throw new RootFabricError('grant_denied', 'resource selectors do not authorize the requested target');
    for (const reference of input.credentialReferences ?? []) if (!grant.credentialReferences.includes(reference)) throw new RootFabricError('grant_denied', 'credential reference is not allowed by the grant');
    return grant;
  }

  private refreshBundle(record: RootSkillBundleRecord): RootSkillBundleRecord {
    if (!verifySealed(record)) throw new RootFabricError('corrupt_record', 'bundle record integrity failed');
    if (record.state === 'ACTIVE' && Date.parse(record.expiresAt) <= Date.parse(this.now())) return seal<RootSkillBundleRecord>({ ...unsigned(record), state: 'EXPIRED' } as Omit<RootSkillBundleRecord, 'recordDigest'>);
    return record;
  }

  private refreshGrant(record: RootCapabilityGrantRecord): RootCapabilityGrantRecord {
    if (!verifySealed(record)) throw new RootFabricError('corrupt_record', 'grant record integrity failed');
    if (record.state === 'ACTIVE' && Date.parse(record.expiresAt) <= Date.parse(this.now())) return seal<RootCapabilityGrantRecord>({ ...unsigned(record), state: 'EXPIRED' } as Omit<RootCapabilityGrantRecord, 'recordDigest'>);
    return record;
  }
}
