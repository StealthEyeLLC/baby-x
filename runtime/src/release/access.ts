import { createHmac, createSign, timingSafeEqual } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute, relative, sep } from 'node:path';
import { canonicalize, sha256, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import type { SlotCredentialBinding } from './slot.ts';
import { assertNoRawSecrets, validateReleaseRecord } from './schemas.ts';
import { ReleaseApplianceStore } from './store.ts';

const MAX_WEBHOOK_BYTES = 1024 * 1024;
const MAX_RECONCILE = 100;
const MAX_RECORDS = 10_000;
const MAX_ACCESS_BYTES = 4096;
const DEFAULT_BACKOFF_MS = 30_000;
const MAX_BACKOFF_MS = 60 * 60 * 1000;
const LEGACY_LAUNCHER = '/usr/libexec/babyx-credential-launcher';
const SHA40 = /^[a-f0-9]{40}$/u;
const ENVIRONMENT_NAME = /^[A-Z_][A-Z0-9_]{0,127}$/u;
const REPOSITORY_NAME = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;

export class ReleaseAccessError extends Error {
  constructor(readonly code: string, message: string, readonly details: JsonObject = {}) { super(message); this.name = 'ReleaseAccessError'; }
}

function isObject(value: unknown): value is JsonObject { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function object(value: unknown, name: string): JsonObject { if (!isObject(value)) throw new ReleaseAccessError('release_invalid_request', `${name} must be an object`); return value; }
function text(value: unknown, name: string, maximum = 1024): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || value.includes('\0')) throw new ReleaseAccessError('release_invalid_request', `${name} must be a bounded string`);
  return value;
}
function identifier(value: unknown, name: string): string {
  const result = text(value, name, 256);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$/u.test(result)) throw new ReleaseAccessError('release_invalid_request', `${name} must be an identifier`);
  return result;
}
function integer(value: unknown, name: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new ReleaseAccessError('release_invalid_request', `${name} must be an integer between ${minimum} and ${maximum}`);
  return Number(value);
}
function timestamp(value: unknown, name: string): string {
  const result = text(value, name, 128);
  if (!result.endsWith('Z') || Number.isNaN(Date.parse(result))) throw new ReleaseAccessError('release_invalid_request', `${name} must be an absolute UTC timestamp`);
  return result;
}
function digest(value: unknown, name: string): string {
  const result = text(value, name, 64);
  if (!/^[a-f0-9]{64}$/u.test(result)) throw new ReleaseAccessError('release_invalid_request', `${name} must be a lowercase sha256 digest`);
  return result;
}
function strictObject(value: unknown, name: string, allowed: readonly string[], required: readonly string[] = []): JsonObject {
  const result = object(value, name);
  for (const key of Object.keys(result)) if (!allowed.includes(key)) throw new ReleaseAccessError('release_invalid_request', `${name} contains unsupported property ${key}`);
  for (const key of required) if (result[key] === undefined) throw new ReleaseAccessError('release_invalid_request', `${name}.${key} is required`);
  return result;
}
function context(value: RuntimeExecutionContext): { subject: string; idempotencyKey: string; authorityClass: string } {
  return { subject: identifier(value.subject, 'context.subject'), idempotencyKey: identifier(value.idempotencyKey, 'context.idempotencyKey'), authorityClass: typeof value.authorityClass === 'string' ? value.authorityClass : 'owner' };
}
function base64url(value: Buffer | string): string { return Buffer.from(value).toString('base64url'); }
function sortedUnique(values: Iterable<string>): string[] { return [...new Set(values)].sort(); }
function safeStructuredError(code: string, phase: string, retryable: boolean): JsonObject {
  return { code, message: code === 'release_github_unavailable' ? 'GitHub provider is unavailable' : 'release access operation failed', retryable, phase, productionImpact: 'NONE', detailsDigest: sha256(canonicalize({ code, phase })) };
}
function ownerVisible(record: JsonObject, value: RuntimeExecutionContext): boolean { return value.authorityClass === 'unrestricted-owner' || record.ownerPrincipal === value.subject; }
function listRecords(store: ReleaseApplianceStore, schemaId: string): JsonObject[] {
  return store.listRecordIdentities(MAX_RECORDS).filter((identity) => identity.schemaId === schemaId).map((identity) => store.getRecord(identity.schemaId, identity.recordId));
}
function apply(store: ReleaseApplianceStore, schemaId: string, recordId: string, ownerPrincipal: string, expectedSequence: number, idempotencyKey: string, operation: string, phase: string, record: JsonObject, occurredAt: string): JsonObject {
  return store.applyMutation({ schemaId, recordId, ownerPrincipal, expectedSequence, idempotencyKey, requestDigest: sha256(canonicalize(record)), operation, phase, record, occurredAt, observationDigest: sha256(canonicalize({ schemaId, recordId, state: record.state ?? record.processingState ?? null, sequence: record.sequence ?? null })) });
}

export interface CredentialReferenceAuthority {
  readonly authority: 'systemd-credential-reference-authority';
  describe(): JsonObject;
  inspect(reference: JsonObject): SlotCredentialBinding;
}

export interface ProtectedCredentialReferenceOptions {
  protectedRoots: string[];
  launcherPath?: string;
  requireRootOwner?: boolean;
}

function normalizeCredentialEntry(value: unknown): JsonObject {
  const entry = strictObject(value, 'credential entry', ['name','mode','sourceRef','objectDigest','version','environmentName'], ['name','mode','sourceRef','objectDigest','version']);
  const name = identifier(entry.name, 'credential entry name');
  const mode = String(entry.mode);
  if (!['PLAIN','ENCRYPTED'].includes(mode)) throw new ReleaseAccessError('release_credential_reference_invalid', 'credential entry mode is invalid');
  const sourceRef = text(entry.sourceRef, 'credential source reference', 4096);
  if (!isAbsolute(sourceRef) || sourceRef.includes('\n') || sourceRef.includes('\r')) throw new ReleaseAccessError('release_credential_reference_invalid', 'credential source reference must be an absolute path');
  const environmentName = entry.environmentName === undefined ? undefined : text(entry.environmentName, 'environmentName', 128);
  if (environmentName !== undefined && !ENVIRONMENT_NAME.test(environmentName)) throw new ReleaseAccessError('release_credential_reference_invalid', 'legacy environment mapping is invalid');
  return { name, mode, sourceRef, objectDigest: digest(entry.objectDigest, 'credential object digest'), version: integer(entry.version, 'credential version', 1), ...(environmentName === undefined ? {} : { environmentName }) };
}

export function normalizeCredentialSet(value: unknown, ownerPrincipal: string, now = new Date().toISOString()): JsonObject {
  const input = strictObject(value, 'credential set', ['credentialSetId','serviceId','version','provider','entries','previousCredentialSetId','overlapUntil'], ['credentialSetId','serviceId','version','provider','entries']);
  const provider = String(input.provider);
  if (!['SYSTEMD_CREDENTIAL','SYSTEMD_ENCRYPTED_CREDENTIAL','LEGACY_FILE_ADAPTER'].includes(provider)) throw new ReleaseAccessError('release_credential_reference_invalid', 'credential provider is invalid');
  if (!Array.isArray(input.entries) || input.entries.length < 1 || input.entries.length > 256) throw new ReleaseAccessError('release_credential_reference_invalid', 'credential entries must be a bounded non-empty array');
  const entries = input.entries.map(normalizeCredentialEntry).sort((left, right) => String(left.name).localeCompare(String(right.name)));
  const names = sortedUnique(entries.map((entry) => String(entry.name)));
  if (names.length !== entries.length) throw new ReleaseAccessError('release_credential_reference_invalid', 'credential names must be unique');
  if (provider === 'SYSTEMD_ENCRYPTED_CREDENTIAL' && entries.some((entry) => entry.mode !== 'ENCRYPTED')) throw new ReleaseAccessError('release_credential_reference_invalid', 'encrypted provider requires encrypted entries');
  if (provider === 'SYSTEMD_CREDENTIAL' && entries.some((entry) => entry.mode !== 'PLAIN')) throw new ReleaseAccessError('release_credential_reference_invalid', 'plain provider requires plain entries');
  if (provider === 'LEGACY_FILE_ADAPTER' && entries.some((entry) => entry.environmentName === undefined)) throw new ReleaseAccessError('release_credential_reference_invalid', 'legacy entries require environmentName');
  const referenceBase: JsonObject = {
    schemaVersion: '1.0.0', credentialSetId: identifier(input.credentialSetId, 'credentialSetId'), ownerPrincipal, serviceId: identifier(input.serviceId, 'serviceId'),
    version: integer(input.version, 'credential version', 1), names, provider, entries,
    ...(input.previousCredentialSetId === undefined ? {} : { previousCredentialSetId: identifier(input.previousCredentialSetId, 'previousCredentialSetId') }),
    ...(input.overlapUntil === undefined ? {} : { overlapUntil: timestamp(input.overlapUntil, 'overlapUntil') }),
  };
  const referenceDigest = sha256(canonicalize({ credentialSetId: referenceBase.credentialSetId, serviceId: referenceBase.serviceId, version: referenceBase.version, names, provider, entries, previousCredentialSetId: referenceBase.previousCredentialSetId ?? null, overlapUntil: referenceBase.overlapUntil ?? null }));
  const compatibilityLauncher = provider === 'LEGACY_FILE_ADAPTER' ? { path: LEGACY_LAUNCHER, environmentMap: Object.fromEntries(entries.map((entry) => [String(entry.environmentName), String(entry.name)])) } : undefined;
  const bindingDigest = sha256(canonicalize({ credentialSetId: referenceBase.credentialSetId, referenceDigest, provider, names, entries, compatibilityLauncher: compatibilityLauncher ?? null }));
  return validateReleaseRecord('CredentialSetReferenceV1', { ...referenceBase, referenceDigest, bindingDigest, state: 'ROTATING', sequence: 1, ...(compatibilityLauncher === undefined ? {} : { compatibilityLauncher }), createdAt: now, updatedAt: now });
}

export function credentialBinding(referenceValue: JsonObject): SlotCredentialBinding {
  const reference = validateReleaseRecord('CredentialSetReferenceV1', referenceValue);
  return {
    credentialSetId: String(reference.credentialSetId), referenceDigest: String(reference.referenceDigest), bindingDigest: String(reference.bindingDigest),
    provider: reference.provider as SlotCredentialBinding['provider'], names: (reference.names as string[]).map(String), entries: (reference.entries as JsonObject[]).map((entry) => structuredClone(entry)),
    ...(reference.compatibilityLauncher === undefined ? {} : { compatibilityLauncher: structuredClone(reference.compatibilityLauncher) as SlotCredentialBinding['compatibilityLauncher'] }),
  };
}

export class ProtectedCredentialReferenceAuthority implements CredentialReferenceAuthority {
  readonly authority = 'systemd-credential-reference-authority' as const;
  private readonly roots: string[];
  private readonly launcherPath: string;
  constructor(private readonly options: ProtectedCredentialReferenceOptions) {
    if (options.protectedRoots.length < 1) throw new ReleaseAccessError('release_invalid_request', 'at least one protected credential root is required');
    this.roots = options.protectedRoots.map((root) => realpathSync(root));
    this.launcherPath = options.launcherPath ?? LEGACY_LAUNCHER;
  }
  describe(): JsonObject { return { authority: this.authority, providers: ['SYSTEMD_CREDENTIAL','SYSTEMD_ENCRYPTED_CREDENTIAL','LEGACY_FILE_ADAPTER'], encryptedAtRestPreferred: true, launcherPath: this.launcherPath, rawMaterialReturned: false }; }
  inspect(referenceValue: JsonObject): SlotCredentialBinding {
    const reference = validateReleaseRecord('CredentialSetReferenceV1', referenceValue);
    for (const entry of reference.entries as JsonObject[]) {
      const declaredSource = String(entry.sourceRef);
      const declaredStat = lstatSync(declaredSource);
      if (declaredStat.isSymbolicLink()) throw new ReleaseAccessError('release_credential_reference_invalid', 'credential source must not be a symbolic link');
      const source = realpathSync(declaredSource);
      const allowed = this.roots.some((root) => source === root || (!relative(root, source).startsWith(`..${sep}`) && relative(root, source) !== '..' && !isAbsolute(relative(root, source))));
      if (!allowed) throw new ReleaseAccessError('release_credential_reference_invalid', 'credential source is outside protected roots');
      const stat = lstatSync(source);
      if (!stat.isFile()) throw new ReleaseAccessError('release_credential_reference_invalid', 'credential source must be a regular file');
      if ((stat.mode & 0o077) !== 0) throw new ReleaseAccessError('release_credential_reference_invalid', 'credential source permissions are too broad');
      if (this.options.requireRootOwner !== false && stat.uid !== 0) throw new ReleaseAccessError('release_credential_reference_invalid', 'credential source must be root-owned');
      if (sha256(readFileSync(source)) !== entry.objectDigest) throw new ReleaseAccessError('release_credential_reference_invalid', 'credential object digest mismatch');
    }
    return credentialBinding(reference);
  }
}

export interface CredentialSlotAuthority {
  getService(payload: JsonObject, context: RuntimeExecutionContext): JsonObject;
  getSlot(payload: JsonObject, context: RuntimeExecutionContext): JsonObject;
  stage(payload: JsonObject, context: RuntimeExecutionContext): JsonObject;
  start(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
}

export interface CredentialAccessServiceOptions {
  store: ReleaseApplianceStore;
  slots: CredentialSlotAuthority;
  references: CredentialReferenceAuthority;
  now?: () => string;
}

export class CredentialAccessService {
  private readonly now: () => string;
  constructor(private readonly options: CredentialAccessServiceOptions) { this.now = options.now ?? (() => new Date().toISOString()); }
  describe(payload: JsonObject = {}, requestContext: RuntimeExecutionContext = {}): JsonObject {
    strictObject(payload, 'credentials describe request', ['serviceId']);
    const records = listRecords(this.options.store, 'CredentialSetReferenceV1').filter((record) => ownerVisible(record, requestContext) && (payload.serviceId === undefined || record.serviceId === payload.serviceId));
    return { operation: 'babyx.release.credentials.describe', readOnly: true, capabilities: this.options.references.describe(), credentialSets: records.map((record) => ({ credentialSetId: record.credentialSetId, serviceId: record.serviceId, version: record.version, names: record.names, provider: record.provider, referenceDigest: record.referenceDigest, state: record.state, createdAt: record.createdAt, updatedAt: record.updatedAt, rotatedAt: record.rotatedAt ?? null })).sort((a,b) => String(a.credentialSetId).localeCompare(String(b.credentialSetId))) };
  }
  async rotate(payloadValue: JsonObject, requestContext: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = context(requestContext);
    const payload = strictObject(payloadValue, 'credential rotation request', ['credentialSet','expectedProcessIdentity','endpointMode'], ['credentialSet','expectedProcessIdentity']);
    let reference = normalizeCredentialSet(payload.credentialSet, authenticated.subject, this.now());
    if (reference.previousCredentialSetId !== undefined) {
      const previousId = String(reference.previousCredentialSetId);
      if (!this.options.store.hasRecord('CredentialSetReferenceV1', previousId)) throw new ReleaseAccessError('release_credential_reference_invalid', 'previous credential set does not exist');
      const previous = this.options.store.getRecord('CredentialSetReferenceV1', previousId);
      if (previous.ownerPrincipal !== authenticated.subject || previous.serviceId !== reference.serviceId) throw new ReleaseAccessError('release_wrong_principal', 'previous credential set is not owned by this service principal');
      if (Number(reference.version) <= Number(previous.version)) throw new ReleaseAccessError('release_credential_reference_invalid', 'rotated credential version must increase');
    }
    const binding = this.options.references.inspect(reference);
    const id = String(reference.credentialSetId);
    if (this.options.store.hasRecord('CredentialSetReferenceV1', id)) {
      const existing = this.options.store.getRecord('CredentialSetReferenceV1', id);
      if (existing.referenceDigest !== reference.referenceDigest) throw new ReleaseAccessError('release_idempotency_conflict', 'credential set identity is bound to different metadata');
      if (existing.state === 'ACTIVE') return { operation: 'babyx.release.credentials.rotate', replayed: true, credentialSet: { credentialSetId: existing.credentialSetId, serviceId: existing.serviceId, version: existing.version, names: existing.names, provider: existing.provider, referenceDigest: existing.referenceDigest, state: existing.state }, rotationState: 'READY_PRIVATE' };
      reference = existing;
    } else reference = apply(this.options.store, 'CredentialSetReferenceV1', id, authenticated.subject, 0, authenticated.idempotencyKey, 'babyx.release.credentials.rotate', 'credential-reference', reference, this.now());
    const serviceId = String(reference.serviceId);
    const service = object(this.options.slots.getService({ serviceId }, requestContext).service, 'service');
    const getSlot = (slotId: 'blue'|'green'): JsonObject | undefined => { try { return object(this.options.slots.getSlot({ serviceId, slotId }, requestContext).slot, 'slot'); } catch { return undefined; } };
    const blue = getSlot('blue'); const green = getSlot('green');
    const activeEntries = [['blue', blue], ['green', green]].filter((entry) => entry[1]?.state === 'ACTIVE') as Array<['blue'|'green', JsonObject]>;
    if (activeEntries.length !== 1) throw new ReleaseAccessError('release_credential_rotation_failed', 'credential rotation requires exactly one active slot');
    const [activeSlotId, activeBefore] = activeEntries[0];
    const inactiveSlotId = activeSlotId === 'blue' ? 'green' : 'blue';
    const inactiveBefore = inactiveSlotId === 'blue' ? blue : green;
    if (inactiveBefore !== undefined && !['EMPTY','EMPTY_VERIFIED'].includes(String(inactiveBefore.state))) throw new ReleaseAccessError('release_credential_rotation_failed', 'inactive slot is not positively empty', { inactiveSlotId, state: inactiveBefore.state });
    const releaseId = identifier(activeBefore.releaseId, 'active releaseId');
    const release = this.options.store.getRecord('ReleaseRecordV1', releaseId);
    if (reference.version <= 0) throw new ReleaseAccessError('release_credential_rotation_failed', 'credential version is invalid');
    const stageContext = { ...requestContext, idempotencyKey: `credential-stage-${sha256(`${authenticated.idempotencyKey}:${id}`).slice(0,40)}` };
    const staged = this.options.slots.stage({ serviceDefinition: service, slotId: inactiveSlotId, release, credentialSetDigest: reference.referenceDigest, credentialBinding: binding, expectedProcessIdentity: object(payload.expectedProcessIdentity, 'expectedProcessIdentity'), ...(payload.endpointMode === undefined ? {} : { endpointMode: payload.endpointMode }) }, stageContext);
    const started = await this.options.slots.start({ serviceId, slotId: inactiveSlotId, expectedSequence: staged.sequence }, { ...requestContext, idempotencyKey: `credential-start-${sha256(`${authenticated.idempotencyKey}:${id}`).slice(0,40)}` });
    const activeAfter = object(this.options.slots.getSlot({ serviceId, slotId: activeSlotId }, requestContext).slot, 'active slot');
    if (activeAfter.state !== 'ACTIVE' || activeAfter.releaseId !== activeBefore.releaseId || activeAfter.credentialSetDigest !== activeBefore.credentialSetDigest) throw new ReleaseAccessError('release_process_ambiguous', 'active production slot changed during credential rotation');
    const success = started.state === 'READY_PRIVATE';
    if (success && Number(reference.sequence) === 1) {
      const updated = validateReleaseRecord('CredentialSetReferenceV1', { ...reference, state: 'ACTIVE', sequence: 2, updatedAt: this.now(), rotatedAt: this.now(), validation: { candidateSlotId: inactiveSlotId, candidateState: started.state, activeSlotPreserved: true } });
      reference = apply(this.options.store, 'CredentialSetReferenceV1', id, authenticated.subject, 1, `${authenticated.idempotencyKey}-ready`, 'babyx.release.credentials.rotate', 'candidate-ready', updated, this.now());
    }
    return { operation: 'babyx.release.credentials.rotate', credentialSet: { credentialSetId: reference.credentialSetId, serviceId, version: reference.version, names: reference.names, provider: reference.provider, referenceDigest: reference.referenceDigest, state: reference.state }, activeSlot: { slotId: activeSlotId, releaseId: activeAfter.releaseId, credentialSetDigest: activeAfter.credentialSetDigest }, candidateSlot: started, rotationState: success ? 'READY_PRIVATE' : 'FAILED_CANDIDATE_ONLY' };
  }
}

export interface MaterialAuthority {
  readonly authority: 'systemd-service-material-authority';
  withMaterial<T>(referenceId: string, callback: (bytes: Buffer) => Promise<T> | T): Promise<T>;
}

export interface GitHubTransport {
  readonly authority: 'github-app-transport';
  exchangeInstallation(input: { appId: string; installationId: string; assertion: string; permissions: JsonObject }): Promise<{ accessValue: string; expiresAt: string; remoteIdentity?: JsonObject }>;
  deliver(input: { accessValue: string; semanticKey: string; repository: string; targetOperation: string; payload: JsonObject }): Promise<JsonObject>;
  poll?(input: { accessValue: string; repository: string; repositoryId: string; installationId: string; cursor?: string }): Promise<{ observations: JsonObject[]; cursor?: string }>;
}

export interface GitHubRepositoryPolicy extends JsonObject {
  ownerPrincipal: string;
  repositoryId: string;
  repository: string;
  installationId: string;
  serviceId: string;
  allowedEvents: string[];
  allowedActions?: JsonObject;
  allowedRefs?: string[];
  webhookMaterialRefs: string[];
  environment?: string;
}

export interface GitHubAccessProviderOptions {
  appId: string;
  signingMaterialRef: string;
  material: MaterialAuthority;
  transport: GitHubTransport;
  permissions?: JsonObject;
  now?: () => string;
}

export class GitHubAppAccessProvider {
  private readonly now: () => string;
  private readonly cache = new Map<string, { accessValue: string; expiresAt: string }>();
  constructor(private readonly options: GitHubAccessProviderOptions) { this.now = options.now ?? (() => new Date().toISOString()); }
  describe(): JsonObject { return { provider: 'GITHUB_APP', appId: this.options.appId, signingMaterialReferenceConfigured: this.options.signingMaterialRef.length > 0, cachedInstallationCount: this.cache.size, accessPersistence: 'MEMORY_ONLY', accessFormatAssumption: 'NONE' }; }
  private async assertion(): Promise<string> {
    const nowSeconds = Math.floor(Date.parse(this.now()) / 1000);
    const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const payload = base64url(JSON.stringify({ iss: this.options.appId, iat: nowSeconds - 60, exp: nowSeconds + 540 }));
    const unsigned = `${header}.${payload}`;
    return this.options.material.withMaterial(this.options.signingMaterialRef, (bytes) => {
      const signer = createSign('RSA-SHA256'); signer.update(unsigned); signer.end();
      return `${unsigned}.${base64url(signer.sign(bytes))}`;
    });
  }
  async withInstallationAccess<T>(installationIdValue: string, callback: (accessValue: string) => Promise<T>): Promise<T> {
    const installationId = identifier(installationIdValue, 'installationId');
    let cached = this.cache.get(installationId);
    if (cached === undefined || Date.parse(cached.expiresAt) <= Date.parse(this.now()) + 60_000) {
      const assertion = await this.assertion();
      const exchanged = await this.options.transport.exchangeInstallation({ appId: this.options.appId, installationId, assertion, permissions: this.options.permissions ?? { contents: 'read', metadata: 'read', deployments: 'write', checks: 'write' } });
      if (typeof exchanged.accessValue !== 'string' || Buffer.byteLength(exchanged.accessValue) < 1 || Buffer.byteLength(exchanged.accessValue) > MAX_ACCESS_BYTES) throw new ReleaseAccessError('release_github_token_invalid', 'GitHub installation access material is invalid');
      const expiresAt = timestamp(exchanged.expiresAt, 'installation access expiry');
      if (Date.parse(expiresAt) <= Date.parse(this.now())) throw new ReleaseAccessError('release_github_token_invalid', 'GitHub installation access material is already expired');
      cached = { accessValue: exchanged.accessValue, expiresAt };
      this.cache.set(installationId, cached);
    }
    return callback(cached.accessValue);
  }
}

function normalizePolicy(value: GitHubRepositoryPolicy): GitHubRepositoryPolicy {
  const input = strictObject(value, 'GitHub repository policy', ['ownerPrincipal','repositoryId','repository','installationId','serviceId','allowedEvents','allowedActions','allowedRefs','webhookMaterialRefs','environment'], ['ownerPrincipal','repositoryId','repository','installationId','serviceId','allowedEvents','webhookMaterialRefs']);
  const repository = text(input.repository, 'repository', 256);
  if (!REPOSITORY_NAME.test(repository)) throw new ReleaseAccessError('release_invalid_request', 'repository must be owner/name');
  if (!Array.isArray(input.allowedEvents) || !Array.isArray(input.webhookMaterialRefs)) throw new ReleaseAccessError('release_invalid_request', 'allowedEvents and webhookMaterialRefs must be arrays');
  return {
    ownerPrincipal: identifier(input.ownerPrincipal,'ownerPrincipal'), repositoryId: identifier(input.repositoryId,'repositoryId'), repository,
    installationId: identifier(input.installationId,'installationId'), serviceId: identifier(input.serviceId,'serviceId'),
    allowedEvents: sortedUnique(input.allowedEvents.map((entry) => identifier(entry,'eventName'))),
    allowedActions: input.allowedActions === undefined ? {} : object(input.allowedActions,'allowedActions'),
    allowedRefs: input.allowedRefs === undefined ? [] : sortedUnique((input.allowedRefs as unknown[]).map((entry) => text(entry,'allowedRef',256))),
    webhookMaterialRefs: sortedUnique(input.webhookMaterialRefs.map((entry) => identifier(entry,'webhookMaterialRef'))),
    ...(input.environment === undefined ? {} : { environment: text(input.environment,'environment',128) }),
  };
}

function exactSha(value: unknown, name: string): string { const result = text(value,name,40).toLowerCase(); if (!SHA40.test(result)) throw new ReleaseAccessError('release_invalid_request', `${name} must be an exact commit sha`); return result; }
function safeAction(value: unknown): string | undefined { return value === undefined || value === null || value === '' ? undefined : identifier(value,'action'); }

export function normalizeGitHubEvent(eventNameValue: string, payloadValue: JsonObject, policyValue: GitHubRepositoryPolicy): JsonObject {
  const eventName = identifier(eventNameValue,'eventName'); const policy = normalizePolicy(policyValue); const payload = object(payloadValue,'GitHub payload');
  const repository = object(payload.repository,'repository'); const installation = object(payload.installation,'installation');
  if (String(repository.id) !== policy.repositoryId || repository.full_name !== policy.repository || String(installation.id) !== policy.installationId) throw new ReleaseAccessError('release_invalid_request','repository or installation identity is not allowed');
  if (!policy.allowedEvents.includes(eventName)) throw new ReleaseAccessError('release_invalid_request','GitHub event is not allowed');
  const action = safeAction(payload.action);
  const allowedActions = policy.allowedActions?.[eventName];
  if (Array.isArray(allowedActions) && action !== undefined && !allowedActions.map(String).includes(action)) throw new ReleaseAccessError('release_invalid_request','GitHub event action is not allowed');
  let normalized: JsonObject;
  if (eventName === 'push') {
    const commit = exactSha(payload.after,'push after'); const ref = text(payload.ref,'push ref',256); if (payload.deleted === true) throw new ReleaseAccessError('release_invalid_request','deleted refs are not deployable');
    if ((policy.allowedRefs ?? []).length > 0 && !(policy.allowedRefs ?? []).includes(ref)) throw new ReleaseAccessError('release_invalid_request','push ref is not allowed');
    normalized = { kind:'SOURCE',eventName,repositoryId:policy.repositoryId,repository:policy.repository,installationId:policy.installationId,serviceId:policy.serviceId,commit,ref,source:'GITHUB' };
  } else if (eventName === 'release') {
    const release = object(payload.release,'release'); const commit = exactSha(release.target_commitish,'release target commit'); const tag = text(release.tag_name,'release tag',256);
    normalized = { kind:'SOURCE',eventName,action,repositoryId:policy.repositoryId,repository:policy.repository,installationId:policy.installationId,serviceId:policy.serviceId,commit,ref:`refs/tags/${tag}`,releaseId:String(release.id),source:'GITHUB' };
  } else if (eventName === 'deployment') {
    const deployment = object(payload.deployment,'deployment'); const commit = exactSha(deployment.sha,'deployment sha');
    const approvalPayload = isObject(deployment.payload) ? deployment.payload : undefined;
    const approval = approvalPayload?.deploymentId === undefined ? undefined : {
      deploymentId: approvalPayload.deploymentId,
      requestDigest: approvalPayload.requestDigest,
      artifactDigest: approvalPayload.artifactDigest,
      certificationId: approvalPayload.certificationId,
      candidateRouteDigest: approvalPayload.candidateRouteDigest,
      ...(approvalPayload.expiresAt === undefined ? {} : { expiresAt: approvalPayload.expiresAt }),
    };
    normalized = { kind: approval?.deploymentId === undefined ? 'DEPLOYMENT' : 'APPROVAL',eventName,action,repositoryId:policy.repositoryId,repository:policy.repository,installationId:policy.installationId,serviceId:policy.serviceId,commit,ref:String(deployment.ref ?? ''),environment:String(deployment.environment ?? policy.environment ?? 'production'),...(approval === undefined ? {} : { approval }),source:'GITHUB' };
  } else if (eventName === 'deployment_status') {
    const deployment = object(payload.deployment,'deployment'); const status = object(payload.deployment_status,'deployment_status'); normalized = { kind:'INFORMATIONAL',eventName,action,repositoryId:policy.repositoryId,repository:policy.repository,installationId:policy.installationId,serviceId:policy.serviceId,commit:exactSha(deployment.sha,'deployment sha'),state:String(status.state),source:'GITHUB' };
  } else if (eventName === 'check_run') {
    const run = object(payload.check_run,'check_run'); normalized = { kind:'INFORMATIONAL',eventName,action,repositoryId:policy.repositoryId,repository:policy.repository,installationId:policy.installationId,serviceId:policy.serviceId,commit:exactSha(object(run.check_suite,'check_suite').head_sha,'check head sha'),name:String(run.name),conclusion:String(run.conclusion ?? ''),source:'GITHUB' };
  } else if (eventName === 'status') {
    normalized = { kind:'INFORMATIONAL',eventName,repositoryId:policy.repositoryId,repository:policy.repository,installationId:policy.installationId,serviceId:policy.serviceId,commit:exactSha(payload.sha,'status sha'),state:String(payload.state),context:String(payload.context ?? ''),source:'GITHUB' };
  } else throw new ReleaseAccessError('release_invalid_request','unsupported GitHub event');
  assertNoRawSecrets(normalized);
  return normalized;
}

export function assertGitHubApprovalMatches(normalizedEventValue: JsonObject, deploymentValue: JsonObject, now = new Date().toISOString()): JsonObject {
  const normalized = object(normalizedEventValue,'normalized event'); const approval = object(normalized.approval,'approval'); const deployment = object(deploymentValue,'deployment');
  const expected = { deploymentId:deployment.deploymentId, requestDigest:deployment.creationRequestDigest, artifactDigest:object(deployment.artifact,'artifact').sha256, certificationId:object(deployment.certification,'certification').certificationId, candidateRouteDigest:deployment.candidateRouteDigest };
  for (const [key,value] of Object.entries(expected)) if (approval[key] !== value) throw new ReleaseAccessError('release_approval_mismatch',`GitHub approval does not match ${key}`);
  if (approval.expiresAt !== undefined && Date.parse(timestamp(approval.expiresAt,'approval expiresAt')) <= Date.parse(now)) throw new ReleaseAccessError('release_approval_expired','GitHub approval has expired');
  return { ...approval, source:'GITHUB', repository:normalized.repository, installationId:normalized.installationId, commit:normalized.commit, verifiedAt:now, approvalDigest:sha256(canonicalize({approval,repository:normalized.repository,installationId:normalized.installationId,commit:normalized.commit})) };
}

export interface GitHubEventAuthority {
  readonly authority: 'release-github-event-authority';
  process(event: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> | JsonObject;
}

export interface GitHubIntegrationServiceOptions {
  store: ReleaseApplianceStore;
  policies: GitHubRepositoryPolicy[];
  material: MaterialAuthority;
  access?: GitHubAppAccessProvider;
  transport?: GitHubTransport;
  events?: GitHubEventAuthority;
  now?: () => string;
}

export function githubDeploymentState(localStateValue: unknown): string {
  const localState=String(localStateValue);
  if(localState==='REQUESTED')return 'queued';
  if(localState==='AWAITING_APPROVAL')return 'pending';
  if(localState==='SUCCEEDED')return 'success';
  if(localState==='ROLLED_BACK'||localState==='CANCELLED'||localState==='EXPIRED')return 'inactive';
  if(localState==='FAILED')return 'failure';
  if(localState==='RECOVERY_REQUIRED'||localState==='AMBIGUOUS')return 'error';
  return 'in_progress';
}

export class GitHubIntegrationService {
  private readonly now: () => string;
  private readonly policies: GitHubRepositoryPolicy[];
  constructor(private readonly options: GitHubIntegrationServiceOptions) { this.now=options.now??(()=>new Date().toISOString()); this.policies=options.policies.map(normalizePolicy); }
  private policyByRepository(repository: string): GitHubRepositoryPolicy { const policy=this.policies.find((item)=>item.repository===repository); if(policy===undefined)throw new ReleaseAccessError('release_invalid_request','repository is not configured'); return policy; }
  private policyFromPayload(payload: JsonObject): GitHubRepositoryPolicy { return this.policyByRepository(String(object(payload.repository,'repository').full_name)); }
  private async verifyRaw(rawBody: Buffer, signature: string, policy: GitHubRepositoryPolicy): Promise<boolean> {
    if (!/^sha256=[a-f0-9]{64}$/u.test(signature)) return false;
    const supplied=Buffer.from(signature.slice(7),'hex');
    for(const reference of policy.webhookMaterialRefs){ const valid=await this.options.material.withMaterial(reference,(bytes)=>{const expected=createHmac('sha256',bytes).update(rawBody).digest();return expected.length===supplied.length&&timingSafeEqual(expected,supplied);}); if(valid)return true; }
    return false;
  }
  private persistInbox(input: { deliveryId:string; source:'WEBHOOK'|'POLL'; rawDigest:string; signatureVerified:boolean; eventName:string; normalized:JsonObject; policy:GitHubRepositoryPolicy; receivedAt:string }): JsonObject {
    const recordId=`github-inbox-${sha256(input.deliveryId).slice(0,40)}`;
    if(this.options.store.hasRecord('GitHubInboxRecordV1',recordId)){
      const existing=this.options.store.getRecord('GitHubInboxRecordV1',recordId);
      if(existing.bodySha256===input.rawDigest)return existing;
      const conflictId=`${recordId}-conflict-${input.rawDigest.slice(0,12)}`;
      const conflict=validateReleaseRecord('GitHubInboxRecordV1',{schemaVersion:'1.0.0',inboxId:conflictId,ownerPrincipal:input.policy.ownerPrincipal,deliveryId:`${input.deliveryId}:conflict:${input.rawDigest.slice(0,12)}`,source:input.source,repositoryId:input.policy.repositoryId,repository:input.policy.repository,installationId:input.policy.installationId,eventName:input.eventName,bodySha256:input.rawDigest,signatureVerified:input.signatureVerified,receivedAt:input.receivedAt,normalizedEvent:input.normalized,normalizedRequestDigest:sha256(canonicalize(input.normalized)),convergenceKey:sha256(canonicalize({repositoryId:input.policy.repositoryId,eventName:input.eventName,normalized:input.normalized})),processingState:'CONFLICT',disposition:'REJECTED',sequence:1,error:safeStructuredError('release_github_delivery_conflict','webhook-deduplication',false)});
      if(!this.options.store.hasRecord('GitHubInboxRecordV1',conflictId))apply(this.options.store,'GitHubInboxRecordV1',conflictId,input.policy.ownerPrincipal,0,`github-conflict-${sha256(`${input.deliveryId}:${input.rawDigest}`).slice(0,40)}`,'babyx.release.github.ingest','delivery-conflict',conflict,input.receivedAt);
      throw new ReleaseAccessError('release_github_delivery_conflict','GitHub delivery GUID was reused with different bytes');
    }
    const normalizedRequestDigest=sha256(canonicalize(input.normalized)); const convergenceKey=sha256(canonicalize({repositoryId:input.policy.repositoryId,kind:input.normalized.kind,commit:input.normalized.commit??null,ref:input.normalized.ref??null,serviceId:input.policy.serviceId,approval:input.normalized.approval??null}));
    const record=validateReleaseRecord('GitHubInboxRecordV1',{schemaVersion:'1.0.0',inboxId:recordId,ownerPrincipal:input.policy.ownerPrincipal,deliveryId:input.deliveryId,source:input.source,repositoryId:input.policy.repositoryId,repository:input.policy.repository,installationId:input.policy.installationId,eventName:input.eventName,...(input.normalized.action===undefined?{}:{action:input.normalized.action}),bodySha256:input.rawDigest,signatureVerified:input.signatureVerified,receivedAt:input.receivedAt,normalizedEvent:input.normalized,normalizedRequestDigest,convergenceKey,processingState:'RECEIVED',disposition:'ACCEPTED',sequence:1});
    return apply(this.options.store,'GitHubInboxRecordV1',recordId,input.policy.ownerPrincipal,0,`github-inbox-${sha256(input.deliveryId).slice(0,40)}`,'babyx.release.github.ingest','inbox-received',record,input.receivedAt);
  }
  async ingestWebhook(inputValue: JsonObject): Promise<JsonObject> {
    const input=strictObject(inputValue,'webhook input',['repository','headers','rawBody'],['repository','headers','rawBody']);
    const policy=this.policyByRepository(text(input.repository,'repository',256));
    const headers=object(input.headers,'headers');
    const rawBody=Buffer.isBuffer(input.rawBody)?input.rawBody:Buffer.from(input.rawBody as string|Uint8Array);
    if(rawBody.length<1||rawBody.length>MAX_WEBHOOK_BYTES)throw new ReleaseAccessError('release_invalid_request','webhook body size is out of bounds');
    const signature=text(headers['x-hub-signature-256']??headers['X-Hub-Signature-256'],'X-Hub-Signature-256',80);
    const eventName=identifier(headers['x-github-event']??headers['X-GitHub-Event'],'X-GitHub-Event');
    const deliveryId=identifier(headers['x-github-delivery']??headers['X-GitHub-Delivery'],'X-GitHub-Delivery');
    if(!(await this.verifyRaw(rawBody,signature,policy)))throw new ReleaseAccessError('release_webhook_signature_invalid','webhook signature verification failed');
    let parsed:JsonObject;
    try{parsed=object(JSON.parse(rawBody.toString('utf8')),'webhook JSON');}catch{throw new ReleaseAccessError('release_invalid_request','webhook JSON is invalid');}
    const normalized=normalizeGitHubEvent(eventName,parsed,policy);
    return {operation:'babyx.release.github.ingest',inbox:this.persistInbox({deliveryId,source:'WEBHOOK',rawDigest:sha256(rawBody),signatureVerified:true,eventName,normalized,policy,receivedAt:this.now()})};
  }
  ingestPollObservation(observationValue: JsonObject): JsonObject {
    const observation=strictObject(observationValue,'poll observation',['repository','repositoryId','installationId','eventName','commit','ref','action'],['repository','repositoryId','installationId','eventName','commit']);
    const policy=this.policyByRepository(String(observation.repository));
    if(String(observation.repositoryId)!==policy.repositoryId||String(observation.installationId)!==policy.installationId)throw new ReleaseAccessError('release_invalid_request','poll identity is not configured');
    const eventName=identifier(observation.eventName,'eventName');
    if(!policy.allowedEvents.includes(eventName))throw new ReleaseAccessError('release_invalid_request','poll event is not allowed');
    const action=observation.action===undefined?undefined:identifier(observation.action,'action');
    const allowedActions=policy.allowedActions?.[eventName];
    if(Array.isArray(allowedActions)&&action!==undefined&&!allowedActions.map(String).includes(action))throw new ReleaseAccessError('release_invalid_request','poll action is not allowed');
    const ref=observation.ref===undefined?undefined:text(observation.ref,'ref',256);
    if(ref!==undefined&&(policy.allowedRefs??[]).length>0&&!(policy.allowedRefs??[]).includes(ref))throw new ReleaseAccessError('release_invalid_request','poll ref is not allowed');
    const normalized:JsonObject={kind:'SOURCE',eventName,repositoryId:policy.repositoryId,repository:policy.repository,installationId:policy.installationId,serviceId:policy.serviceId,commit:exactSha(observation.commit,'commit'),...(ref===undefined?{}:{ref}),...(action===undefined?{}:{action}),source:'GITHUB'};
    const deliveryId=`poll-${sha256(canonicalize({repositoryId:policy.repositoryId,eventName:normalized.eventName,commit:normalized.commit,ref:normalized.ref??null,action:normalized.action??null})).slice(0,40)}`;
    const rawDigest=sha256(canonicalize(normalized));
    return {operation:'babyx.release.github.poll.ingest',inbox:this.persistInbox({deliveryId,source:'POLL',rawDigest,signatureVerified:true,eventName:String(normalized.eventName),normalized,policy,receivedAt:this.now()})};
  }
  queueReport(inputValue: JsonObject, requestContext: RuntimeExecutionContext): JsonObject {
    const authenticated=context(requestContext); const input=strictObject(inputValue,'GitHub report',['repository','deploymentId','reportKind','targetOperation','payload'],['repository','deploymentId','reportKind','targetOperation','payload']); const policy=this.policyByRepository(String(input.repository)); if(policy.ownerPrincipal!==authenticated.subject)throw new ReleaseAccessError('release_wrong_principal','repository policy owner does not match'); const payload=object(input.payload,'report payload'); assertNoRawSecrets(payload); const payloadDigest=sha256(canonicalize(payload)); const reportKind=String(input.reportKind); if(!['DEPLOYMENT','CHECK','COMMENT'].includes(reportKind))throw new ReleaseAccessError('release_invalid_request','reportKind is invalid'); const outboxId=`github-outbox-${sha256(canonicalize({repository:policy.repository,deploymentId:input.deploymentId,reportKind,targetOperation:input.targetOperation,payloadDigest})).slice(0,40)}`;
    if(this.options.store.hasRecord('GitHubOutboxRecordV1',outboxId))return this.options.store.getRecord('GitHubOutboxRecordV1',outboxId);
    const now=this.now(); const record=validateReleaseRecord('GitHubOutboxRecordV1',{schemaVersion:'1.0.0',outboxId,ownerPrincipal:authenticated.subject,repositoryId:policy.repositoryId,repository:policy.repository,installationId:policy.installationId,deploymentId:identifier(input.deploymentId,'deploymentId'),reportKind,targetOperation:identifier(input.targetOperation,'targetOperation'),payloadDigest,payload,state:'QUEUED',attemptCount:0,sequence:1,createdAt:now,updatedAt:now,nextAttemptAt:now}); return apply(this.options.store,'GitHubOutboxRecordV1',outboxId,authenticated.subject,0,authenticated.idempotencyKey,'babyx.release.github.queue','outbox-queued',record,now);
  }
  private deploymentProjection(recordValue: JsonObject): { policy: GitHubRepositoryPolicy; input: JsonObject; outboxId: string } | undefined {
    const record=object(recordValue,'deployment');
    const normalized=object(record.normalizedRequest,'normalizedRequest');
    const service=object(normalized.serviceDefinition,'serviceDefinition');
    const repository=String(service.repository);
    const policy=this.policies.find((item)=>item.repository===repository);
    if(policy===undefined)return undefined;
    const source=isObject(record.sourceIdentity)?record.sourceIdentity:{};
    const payload={state:githubDeploymentState(record.state),description:`Baby-X ${String(record.state)}`.slice(0,140),environment:String(policy.environment??'production'),sha:String(source.commit??''),deploymentId:record.deploymentId,sequence:record.sequence,localState:record.state,evidenceDigest:record.evidenceIndexDigest??null};
    const input={repository,deploymentId:record.deploymentId,reportKind:'DEPLOYMENT',targetOperation:'deployments.status',payload};
    const payloadDigest=sha256(canonicalize(payload));
    const outboxId=`github-outbox-${sha256(canonicalize({repository,deploymentId:record.deploymentId,reportKind:'DEPLOYMENT',targetOperation:'deployments.status',payloadDigest})).slice(0,40)}`;
    return {policy,input,outboxId};
  }
  queueDeploymentProjection(recordValue: JsonObject, requestContext: RuntimeExecutionContext): JsonObject {
    const projection=this.deploymentProjection(recordValue);
    if(projection===undefined)return {queued:false,reason:'repository-not-configured'};
    return this.queueReport(projection.input,{...requestContext,subject:projection.policy.ownerPrincipal,idempotencyKey:`github-projection-${sha256(`${projection.input.deploymentId}:${object(projection.input.payload,'payload').sequence}`).slice(0,40)}`});
  }
  reportingSatisfied(recordValue: JsonObject): boolean {
    const projection=this.deploymentProjection(recordValue);
    if(projection===undefined)return true;
    if(!this.options.store.hasRecord('GitHubOutboxRecordV1',projection.outboxId))return false;
    const outbox=this.options.store.getRecord('GitHubOutboxRecordV1',projection.outboxId);
    return ['QUEUED','SENDING','DELIVERED','DEFERRED'].includes(String(outbox.state));
  }
  private transitionInbox(record: JsonObject, patch: JsonObject, phase: string): JsonObject {
    const now=this.now(); const sequence=integer(record.sequence,'inbox sequence'); const merged:JsonObject={...record,...patch,sequence:sequence+1};
    for(const [key,value] of Object.entries(merged))if(value===undefined)delete merged[key];
    const candidate=validateReleaseRecord('GitHubInboxRecordV1',merged);
    return apply(this.options.store,'GitHubInboxRecordV1',String(record.inboxId),String(record.ownerPrincipal),sequence,`github-inbox-${String(record.inboxId)}-${sequence+1}-${phase}`,'babyx.release.github.reconcile',phase,candidate,now);
  }
  private transitionOutbox(record: JsonObject, patch: JsonObject, phase: string): JsonObject {
    const now=this.now(); const sequence=integer(record.sequence,'outbox sequence'); const merged:JsonObject={...record,...patch,sequence:sequence+1,updatedAt:now};
    for(const [key,value] of Object.entries(merged))if(value===undefined)delete merged[key];
    const candidate=validateReleaseRecord('GitHubOutboxRecordV1',merged);
    return apply(this.options.store,'GitHubOutboxRecordV1',String(record.outboxId),String(record.ownerPrincipal),sequence,`github-outbox-${String(record.outboxId)}-${sequence+1}-${phase}`,'babyx.release.github.reconcile',phase,candidate,now);
  }
  async reconcile(payloadValue: JsonObject = {}, requestContext: RuntimeExecutionContext): Promise<JsonObject> {
    context(requestContext); const payload=strictObject(payloadValue,'GitHub reconcile',['limit','poll'],[]); const limit=payload.limit===undefined?50:integer(payload.limit,'limit',1,MAX_RECONCILE); const now=this.now(); const processed:JsonObject[]=[]; const delivered:JsonObject[]=[];
    if(payload.poll===true&&this.options.transport?.poll!==undefined&&this.options.access!==undefined){for(const policy of this.policies.slice(0,limit)){try{const result=await this.options.access.withInstallationAccess(policy.installationId,(accessValue)=>this.options.transport!.poll!({accessValue,repository:policy.repository,repositoryId:policy.repositoryId,installationId:policy.installationId}));for(const observation of result.observations.slice(0,limit))this.ingestPollObservation({...observation,repository:policy.repository,repositoryId:policy.repositoryId,installationId:policy.installationId});}catch{}}}
    const inbox=listRecords(this.options.store,'GitHubInboxRecordV1').filter((record)=>['RECEIVED','RECOVERY_REQUIRED'].includes(String(record.processingState))).sort((a,b)=>String(a.receivedAt).localeCompare(String(b.receivedAt))).slice(0,limit);
    for(const record of inbox){const duplicate=listRecords(this.options.store,'GitHubInboxRecordV1').find((other)=>other.inboxId!==record.inboxId&&other.convergenceKey===record.convergenceKey&&other.processingState==='PROCESSED');if(duplicate!==undefined){processed.push(this.transitionInbox(record,{processingState:'EXCLUDED',disposition:'DUPLICATE',processedAt:now,deploymentId:duplicate.deploymentId??undefined,exclusionReason:'converged-with-processed-delivery'},'inbox-converged'));continue;}if(this.options.events===undefined){processed.push(this.transitionInbox(record,{processingState:'RECOVERY_REQUIRED',disposition:'DEFERRED',error:safeStructuredError('release_provider_unavailable','inbox-processing',true)},'inbox-deferred'));continue;}try{const outcome=await this.options.events.process(object(record.normalizedEvent,'normalizedEvent'),{...requestContext,subject:record.ownerPrincipal,idempotencyKey:`github-event-${record.normalizedRequestDigest}`});processed.push(this.transitionInbox(record,{processingState:outcome.exclusionReason===undefined?'PROCESSED':'EXCLUDED',disposition:outcome.exclusionReason===undefined?'ACCEPTED':'REJECTED',processedAt:now,...(outcome.deploymentId===undefined?{}:{deploymentId:outcome.deploymentId}),...(outcome.exclusionReason===undefined?{}:{exclusionReason:outcome.exclusionReason}),error:undefined},'inbox-processed'));}catch{processed.push(this.transitionInbox(record,{processingState:'RECOVERY_REQUIRED',disposition:'DEFERRED',error:safeStructuredError('release_recovery_required','inbox-processing',true)},'inbox-recovery'));}}
    const outbox=listRecords(this.options.store,'GitHubOutboxRecordV1').filter((record)=>['QUEUED','DEFERRED','SENDING'].includes(String(record.state))&&(record.nextAttemptAt===undefined||Date.parse(String(record.nextAttemptAt))<=Date.parse(now))).sort((a,b)=>String(a.createdAt).localeCompare(String(b.createdAt))).slice(0,limit);
    for(let record of outbox){if(this.options.access===undefined||this.options.transport===undefined){delivered.push(this.transitionOutbox(record,{state:'DEFERRED',attemptCount:Number(record.attemptCount)+1,nextAttemptAt:new Date(Date.parse(now)+DEFAULT_BACKOFF_MS).toISOString(),error:safeStructuredError('release_github_unavailable','outbox-delivery',true)},'outbox-deferred'));continue;}record=this.transitionOutbox(record,{state:'SENDING',attemptCount:Number(record.attemptCount)+1,error:undefined},'outbox-sending');try{const response=await this.options.access.withInstallationAccess(String(record.installationId),(accessValue)=>this.options.transport!.deliver({accessValue,semanticKey:String(record.outboxId),repository:String(record.repository),targetOperation:String(record.targetOperation),payload:object(record.payload,'outbox payload')}));const remoteIdentity={id:response.id??null,nodeId:response.nodeId??null,urlDigest:response.url===undefined?null:sha256(String(response.url))};delivered.push(this.transitionOutbox(record,{state:'DELIVERED',deliveredAt:this.now(),nextAttemptAt:undefined,remoteIdentity,lastStatus:{status:'DELIVERED',responseDigest:sha256(canonicalize(remoteIdentity))},error:undefined},'outbox-delivered'));}catch{const delay=Math.min(MAX_BACKOFF_MS,DEFAULT_BACKOFF_MS*2**Math.min(8,Number(record.attemptCount)));delivered.push(this.transitionOutbox(record,{state:'DEFERRED',nextAttemptAt:new Date(Date.parse(this.now())+delay).toISOString(),lastStatus:{status:'DEFERRED'},error:safeStructuredError('release_github_unavailable','outbox-delivery',true)},'outbox-retry'));}}
    return {operation:'babyx.release.github.reconcile',processedInbox:processed.map((record)=>record.inboxId),reconciledOutbox:delivered.map((record)=>record.outboxId),processedCount:processed.length,deliveredCount:delivered.filter((record)=>record.state==='DELIVERED').length,deferredCount:delivered.filter((record)=>record.state==='DEFERRED').length};
  }
  status(payloadValue: JsonObject = {}, requestContext: RuntimeExecutionContext = {}): JsonObject {
    const payload=strictObject(payloadValue,'GitHub status',['repository','limit']); const limit=payload.limit===undefined?100:integer(payload.limit,'limit',1,200); const visible=(record:JsonObject)=>ownerVisible(record,requestContext)&&(payload.repository===undefined||record.repository===payload.repository); const inbox=listRecords(this.options.store,'GitHubInboxRecordV1').filter(visible).sort((a,b)=>String(b.receivedAt).localeCompare(String(a.receivedAt))).slice(0,limit); const outbox=listRecords(this.options.store,'GitHubOutboxRecordV1').filter(visible).sort((a,b)=>String(b.createdAt).localeCompare(String(a.createdAt))).slice(0,limit); return {operation:'babyx.release.github.status',readOnly:true,configuredRepositories:this.policies.map((policy)=>({repositoryId:policy.repositoryId,repository:policy.repository,installationId:policy.installationId,serviceId:policy.serviceId,events:policy.allowedEvents})),provider:this.options.access?.describe()??{provider:'UNCONFIGURED'},inbox:inbox.map((record)=>({inboxId:record.inboxId,deliveryId:record.deliveryId,source:record.source,repository:record.repository,eventName:record.eventName,receivedAt:record.receivedAt,processingState:record.processingState,disposition:record.disposition,deploymentId:record.deploymentId??null})),outbox:outbox.map((record)=>({outboxId:record.outboxId,repository:record.repository,deploymentId:record.deploymentId,reportKind:record.reportKind,state:record.state,attemptCount:record.attemptCount,nextAttemptAt:record.nextAttemptAt??null,deliveredAt:record.deliveredAt??null})),counts:{inbox:inbox.length,outbox:outbox.length,queued:outbox.filter((record)=>record.state==='QUEUED').length,deferred:outbox.filter((record)=>record.state==='DEFERRED').length,delivered:outbox.filter((record)=>record.state==='DELIVERED').length}};
  }
}
