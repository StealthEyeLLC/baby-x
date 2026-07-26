import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, normalize } from 'node:path';
import { canonicalize, sha256, type JobRecord, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import type { CertificationService } from '../certification/service.ts';
import type { ArtifactAuthority } from './content.ts';
import { assertNoRawSecrets, boundedReleaseError, validateReleaseRecord } from './schemas.ts';
import { ReleaseApplianceStore, ReleaseStoreError } from './store.ts';

export const RELEASE_CERTIFICATION_PROFILE_SCHEMA_VERSION = '1.0.0' as const;
export const RELEASE_CERTIFICATION_REQUEST_SCHEMA_VERSION = '1.0.0' as const;
export const RELEASE_CERTIFICATION_STEP_KINDS = ['dependency', 'startup', 'readiness', 'smoke', 'migration', 'worker', 'security', 'resource', 'streams', 'shutdown', 'integration', 'acceptance'] as const;
export type ReleaseCertificationStepKind = typeof RELEASE_CERTIFICATION_STEP_KINDS[number];

export interface ReleaseCertificationStep extends JsonObject {
  id: string;
  kind: ReleaseCertificationStepKind;
  argv: string[];
  cwd: string;
  timeoutMs: number;
  required: boolean;
}

export interface ReleaseCertificationProfile extends JsonObject {
  schemaVersion: typeof RELEASE_CERTIFICATION_PROFILE_SCHEMA_VERSION;
  id: string;
  version: string;
  steps: ReleaseCertificationStep[];
  requiredCredentialNames: string[];
  endpointContract: JsonObject;
  profileDigest: string;
}

export interface ReleaseCertificationAuthority {
  run(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
}

export interface ReleaseCertificationJobAuthority {
  reconcile(id: string): JobRecord;
}

export interface ReleaseCertificationOptions {
  stateRoot: string;
  store: ReleaseApplianceStore;
  artifacts: ArtifactAuthority;
  certification: ReleaseCertificationAuthority | CertificationService;
  jobs: ReleaseCertificationJobAuthority;
  now?: () => string;
}

interface NormalizedRequest extends JsonObject {
  schemaVersion: typeof RELEASE_CERTIFICATION_REQUEST_SCHEMA_VERSION;
  artifactId: string;
  artifactSha256: string;
  manifest: JsonObject;
  manifestDigest: string;
  manifestFileDigest: string;
  serviceDefinitionDigest: string;
  profile: ReleaseCertificationProfile;
  baseSnapshot: { name: string; guid: string; creationTxg: number };
  machine: JsonObject;
  runtimeIdentity: JsonObject;
  dependencyIdentity: JsonObject;
  applianceCompatibilityVersion: string;
  externalContractIdentities: JsonObject;
  securityPolicyVersion: string;
  invalidationConditions: JsonObject[];
  expiresAt?: string;
  reuseIdentity: string;
}

interface ChildCertification extends JsonObject {
  certificationId: string;
  state: string;
  machineId: string | null;
  jobIds: string[];
  steps: JsonObject[];
  evidence: JsonObject;
  cleanup: JsonObject;
  proofReferences: string[];
  testResult: JsonObject;
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@+\/-]{0,255}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const ARTIFACT_DESTINATION = '/run/baby-x/release-artifact.tar.zst';
const MANIFEST_DESTINATION = '/run/baby-x/release-manifest.json';
const RELEASE_DESTINATION = '/var/tmp/baby-x-certification/release';

export class ReleaseCertificationError extends Error {
  constructor(readonly code: string, message: string, readonly details: JsonObject = {}, readonly phase?: string) {
    super(message);
    this.name = 'ReleaseCertificationError';
  }
}

function object(value: unknown, field: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ReleaseCertificationError('release_invalid_request', `${field} must be an object`);
  return value as JsonObject;
}

function strictObject(value: unknown, field: string, allowed: readonly string[], required: readonly string[] = allowed): JsonObject {
  const result = object(value, field);
  const unknown = Object.keys(result).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw new ReleaseCertificationError('release_invalid_request', `${field} contains unsupported properties`, { properties: unknown.sort() });
  for (const key of required) if (result[key] === undefined) throw new ReleaseCertificationError('release_invalid_request', `${field}.${key} is required`);
  return result;
}

function text(value: unknown, field: string, maximum = 1024): string {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || Buffer.byteLength(value) > maximum) throw new ReleaseCertificationError('release_invalid_request', `${field} must be a bounded non-empty NUL-free string`);
  return value;
}

function identifier(value: unknown, field: string): string {
  const result = text(value, field, 256);
  if (!IDENTIFIER.test(result)) throw new ReleaseCertificationError('release_invalid_request', `${field} must be a bounded identifier`);
  return result;
}

function digest(value: unknown, field: string): string {
  const result = text(value, field, 64);
  if (!DIGEST.test(result)) throw new ReleaseCertificationError('release_invalid_request', `${field} must be a lowercase SHA-256 digest`);
  return result;
}

function integer(value: unknown, field: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new ReleaseCertificationError('release_invalid_request', `${field} must be an integer between ${minimum} and ${maximum}`);
  return Number(value);
}

function absolutePath(value: unknown, field: string): string {
  const result = text(value, field, 4096);
  if (!isAbsolute(result) || normalize(result) !== result) throw new ReleaseCertificationError('release_invalid_request', `${field} must be a normalized absolute path`);
  return result;
}

function timestamp(value: unknown, field: string): string {
  const result = text(value, field, 64);
  if (!result.endsWith('Z') || !Number.isFinite(Date.parse(result))) throw new ReleaseCertificationError('release_invalid_request', `${field} must be an absolute UTC timestamp`);
  return result;
}

function exactArgv(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 128) throw new ReleaseCertificationError('release_invalid_request', `${field} must be a non-empty bounded string array`);
  return value.map((entry, index) => text(entry, `${field}[${index}]`, 4096));
}

function sortedIdentifiers(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length > 256) throw new ReleaseCertificationError('release_invalid_request', `${field} must be a bounded string array`);
  return [...new Set(value.map((entry, index) => identifier(entry, `${field}[${index}]`)))].sort();
}

function normalizedJson(value: unknown, field: string): JsonObject {
  const result = structuredClone(object(value, field));
  assertNoRawSecrets(result);
  return JSON.parse(canonicalize(result)) as JsonObject;
}

function normalizeStep(value: unknown, index: number): ReleaseCertificationStep {
  const field = `profile.steps[${index}]`;
  const step = strictObject(value, field, ['id', 'kind', 'argv', 'cwd', 'timeoutMs', 'required']);
  const kind = text(step.kind, `${field}.kind`, 32) as ReleaseCertificationStepKind;
  if (!RELEASE_CERTIFICATION_STEP_KINDS.includes(kind)) throw new ReleaseCertificationError('release_invalid_request', `${field}.kind is unsupported`, { kind });
  if (typeof step.required !== 'boolean') throw new ReleaseCertificationError('release_invalid_request', `${field}.required must be boolean`);
  return { id: identifier(step.id, `${field}.id`), kind, argv: exactArgv(step.argv, `${field}.argv`), cwd: absolutePath(step.cwd, `${field}.cwd`), timeoutMs: integer(step.timeoutMs, `${field}.timeoutMs`, 1, 86_400_000), required: step.required };
}

export function normalizeReleaseCertificationProfile(value: unknown): ReleaseCertificationProfile {
  const profile = strictObject(value, 'profile', ['schemaVersion', 'id', 'version', 'steps', 'requiredCredentialNames', 'endpointContract']);
  if (profile.schemaVersion !== RELEASE_CERTIFICATION_PROFILE_SCHEMA_VERSION) throw new ReleaseCertificationError('release_invalid_request', `profile.schemaVersion must be ${RELEASE_CERTIFICATION_PROFILE_SCHEMA_VERSION}`);
  if (!Array.isArray(profile.steps) || profile.steps.length === 0 || profile.steps.length > 64) throw new ReleaseCertificationError('release_invalid_request', 'profile.steps must contain between one and 64 steps');
  const steps = profile.steps.map(normalizeStep);
  const ids = new Set<string>();
  for (const step of steps) {
    if (ids.has(step.id)) throw new ReleaseCertificationError('release_invalid_request', 'profile step IDs must be unique', { id: step.id });
    ids.add(step.id);
  }
  const normalized = { schemaVersion: RELEASE_CERTIFICATION_PROFILE_SCHEMA_VERSION, id: identifier(profile.id, 'profile.id'), version: identifier(profile.version, 'profile.version'), steps, requiredCredentialNames: sortedIdentifiers(profile.requiredCredentialNames, 'profile.requiredCredentialNames'), endpointContract: normalizedJson(profile.endpointContract, 'profile.endpointContract') };
  return { ...normalized, profileDigest: sha256(canonicalize(normalized)) };
}

function normalizeMachine(value: unknown): JsonObject {
  const machine = structuredClone(object(value, 'machine'));
  identifier(machine.machineName, 'machine.machineName');
  const clone = object(machine.clone, 'machine.clone');
  if (absolutePath(clone.mountpoint, 'machine.clone.mountpoint') === '/') throw new ReleaseCertificationError('release_invalid_request', 'machine.clone.mountpoint must be below root');
  if (absolutePath(clone.expectedRootPrefix, 'machine.clone.expectedRootPrefix') === '/') throw new ReleaseCertificationError('release_invalid_request', 'machine.clone.expectedRootPrefix must be below root');
  const launch = object(machine.launch, 'machine.launch');
  if (!Array.isArray(launch.binds) || !Array.isArray(launch.environment)) throw new ReleaseCertificationError('release_invalid_request', 'machine launch binds and environment must be arrays');
  for (const [index, entry] of launch.environment.entries()) {
    const environment = object(entry, `machine.launch.environment[${index}]`);
    if (environment.value !== undefined || typeof environment.secretReference !== 'string' || environment.redacted !== true) throw new ReleaseCertificationError('release_secret_material_rejected', 'machine environment must use redacted credential references only', { index });
  }
  return JSON.parse(canonicalize(machine)) as JsonObject;
}

function semver(value: string): [number, number, number] {
  const match = value.match(/^(\d+)\.(\d+)\.(\d+)$/u);
  if (match === null) throw new ReleaseCertificationError('release_invalid_request', 'appliance compatibility versions must use major.minor.patch');
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function compareSemver(left: string, right: string): number {
  const a = semver(left);
  const b = semver(right);
  for (let index = 0; index < 3; index += 1) {
    const difference = (a[index] as number) - (b[index] as number);
    if (difference !== 0) return difference;
  }
  return 0;
}

function canonicalManifestDigest(manifest: JsonObject): string {
  const unsigned = { ...manifest };
  delete unsigned.manifestDigest;
  return sha256(canonicalize(unsigned));
}

function normalizeRequest(value: unknown): NormalizedRequest {
  const request = strictObject(value, 'release certification request', ['schemaVersion', 'artifactId', 'artifactSha256', 'manifest', 'serviceDefinitionDigest', 'profile', 'baseSnapshot', 'machine', 'runtimeIdentity', 'dependencyIdentity', 'applianceCompatibilityVersion', 'externalContractIdentities', 'securityPolicyVersion', 'invalidationConditions', 'expiresAt'], ['schemaVersion', 'artifactId', 'artifactSha256', 'manifest', 'serviceDefinitionDigest', 'profile', 'baseSnapshot', 'machine', 'runtimeIdentity', 'dependencyIdentity', 'applianceCompatibilityVersion', 'externalContractIdentities', 'securityPolicyVersion']);
  if (request.schemaVersion !== RELEASE_CERTIFICATION_REQUEST_SCHEMA_VERSION) throw new ReleaseCertificationError('release_invalid_request', `schemaVersion must be ${RELEASE_CERTIFICATION_REQUEST_SCHEMA_VERSION}`);
  const manifest = validateReleaseRecord('ReleaseArtifactManifestV1', request.manifest);
  const manifestDigest = digest(manifest.manifestDigest, 'manifest.manifestDigest');
  const observedManifestDigest = canonicalManifestDigest(manifest);
  if (manifestDigest !== observedManifestDigest) throw new ReleaseCertificationError('release_artifact_invalid', 'release artifact manifest digest does not match canonical content', { manifestDigest, observedManifestDigest }, 'manifest');
  const profile = normalizeReleaseCertificationProfile(request.profile);
  const snapshot = strictObject(request.baseSnapshot, 'baseSnapshot', ['name', 'guid', 'creationTxg']);
  const invalidationConditions = request.invalidationConditions === undefined ? [] : Array.isArray(request.invalidationConditions) ? request.invalidationConditions.map((entry, index) => normalizedJson(entry, `invalidationConditions[${index}]`)) : (() => { throw new ReleaseCertificationError('release_invalid_request', 'invalidationConditions must be an array'); })();
  const normalized = {
    schemaVersion: RELEASE_CERTIFICATION_REQUEST_SCHEMA_VERSION,
    artifactId: identifier(request.artifactId, 'artifactId'),
    artifactSha256: digest(request.artifactSha256, 'artifactSha256'),
    manifest,
    manifestDigest,
    manifestFileDigest: sha256(`${canonicalize(manifest)}\n`),
    serviceDefinitionDigest: digest(request.serviceDefinitionDigest, 'serviceDefinitionDigest'),
    profile,
    baseSnapshot: { name: text(snapshot.name, 'baseSnapshot.name', 256), guid: text(snapshot.guid, 'baseSnapshot.guid', 256), creationTxg: integer(snapshot.creationTxg, 'baseSnapshot.creationTxg', 1) },
    machine: normalizeMachine(request.machine),
    runtimeIdentity: normalizedJson(request.runtimeIdentity, 'runtimeIdentity'),
    dependencyIdentity: normalizedJson(request.dependencyIdentity, 'dependencyIdentity'),
    applianceCompatibilityVersion: text(request.applianceCompatibilityVersion, 'applianceCompatibilityVersion', 64),
    externalContractIdentities: normalizedJson(request.externalContractIdentities, 'externalContractIdentities'),
    securityPolicyVersion: identifier(request.securityPolicyVersion, 'securityPolicyVersion'),
    invalidationConditions,
    ...(request.expiresAt === undefined ? {} : { expiresAt: timestamp(request.expiresAt, 'expiresAt') }),
  };
  const reuseIdentity = sha256(canonicalize({ kind: 'release-certification-reuse-v1', artifactSha256: normalized.artifactSha256, manifestDigest, profile: { id: profile.id, version: profile.version, digest: profile.profileDigest }, serviceDefinitionDigest: normalized.serviceDefinitionDigest, baseSnapshot: normalized.baseSnapshot, runtimeIdentity: normalized.runtimeIdentity, dependencyIdentity: normalized.dependencyIdentity, applianceCompatibilityVersion: normalized.applianceCompatibilityVersion, externalContractIdentities: normalized.externalContractIdentities, securityPolicyVersion: normalized.securityPolicyVersion }));
  return { ...normalized, reuseIdentity };
}

function requiredContext(context: RuntimeExecutionContext): { subject: string; idempotencyKey: string } {
  return { subject: identifier(context.subject, 'context.subject'), idempotencyKey: identifier(context.idempotencyKey, 'context.idempotencyKey') };
}

function childCertification(value: JsonObject): ChildCertification {
  const certification = object(value.certification, 'certification authority result');
  const profile = object(certification.profile, 'certification.profile');
  return {
    certificationId: identifier(certification.certificationId, 'certification.certificationId'),
    state: text(certification.state, 'certification.state', 64),
    machineId: certification.machineId === null || certification.machineId === undefined ? null : identifier(certification.machineId, 'certification.machineId'),
    jobIds: Array.isArray(certification.jobIds) ? certification.jobIds.map((entry, index) => identifier(entry, `certification.jobIds[${index}]`)) : [],
    steps: Array.isArray(profile.steps) ? profile.steps.filter((entry): entry is JsonObject => entry !== null && typeof entry === 'object' && !Array.isArray(entry)) : [],
    evidence: object(certification.evidence, 'certification.evidence'),
    cleanup: object(certification.cleanup, 'certification.cleanup'),
    proofReferences: Array.isArray(certification.proofReferences) ? certification.proofReferences.filter((entry): entry is string => typeof entry === 'string') : [],
    testResult: object(certification.testResult, 'certification.testResult'),
  };
}

function phaseResult(kinds: readonly ReleaseCertificationStepKind[], profile: ReleaseCertificationProfile, child: ChildCertification): JsonObject {
  const ids = new Set(profile.steps.filter((step) => kinds.includes(step.kind)).map((step) => step.id));
  const records = child.steps.filter((step) => typeof step.id === 'string' && ids.has(step.id));
  if (records.length === 0) return { status: 'NOT_APPLICABLE', kinds, steps: [] };
  const failed = records.find((step) => step.state === 'failed');
  const incomplete = records.find((step) => step.state !== 'passed' && step.state !== 'failed');
  return { status: failed !== undefined ? 'FAILED' : incomplete !== undefined ? 'INCOMPLETE' : 'PASSED', kinds, steps: records, ...(failed === undefined ? {} : { failedStepId: failed.id }) };
}

function recordProfile(request: NormalizedRequest, childCertificationId?: string): JsonObject {
  return { id: request.profile.id, version: request.profile.version, digest: request.profile.profileDigest, reuseIdentity: request.reuseIdentity, runtimeIdentity: request.runtimeIdentity, dependencyIdentity: request.dependencyIdentity, applianceCompatibilityVersion: request.applianceCompatibilityVersion, externalContractIdentities: request.externalContractIdentities, securityPolicyVersion: request.securityPolicyVersion, ...(childCertificationId === undefined ? {} : { childCertificationId }) };
}

function activeInvalidation(request: NormalizedRequest): JsonObject | undefined {
  const identities = new Set([request.artifactId, request.artifactSha256, request.manifestDigest, request.serviceDefinitionDigest, request.profile.profileDigest, sha256(canonicalize(request.dependencyIdentity)), request.securityPolicyVersion]);
  return request.invalidationConditions.find((condition) => condition.active === true && Array.isArray(condition.references) && condition.references.some((reference) => typeof reference === 'string' && identities.has(reference)));
}

function ownerFromEvents(store: ReleaseApplianceStore, certificationId: string): string | undefined {
  const first = store.events('CertificationRecordV1', certificationId, 0, 1).at(0);
  return typeof first?.ownerPrincipal === 'string' ? first.ownerPrincipal : undefined;
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, 'r');
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

export class ReleaseCertificationService {
  private readonly inputRoot: string;
  private readonly now: () => string;

  constructor(private readonly options: ReleaseCertificationOptions) {
    this.inputRoot = join(options.stateRoot, 'release-certification', 'inputs');
    mkdirSync(this.inputRoot, { recursive: true, mode: 0o700 });
    this.now = options.now ?? (() => new Date().toISOString());
  }

  describe(): JsonObject {
    return { operation: 'babyx.release.certification.describe', schemaVersion: RELEASE_CERTIFICATION_REQUEST_SCHEMA_VERSION, profileSchemaVersion: RELEASE_CERTIFICATION_PROFILE_SCHEMA_VERSION, lifecycleAuthority: 'baby-x-certification-service', machineAuthority: 'baby-x-disposable-machine-service', executionAuthority: 'baby-x-durable-jobs', artifactAuthority: 'baby-x-artifacts', releaseRecordAuthority: 'baby-x-release-store', supportedStepKinds: [...RELEASE_CERTIFICATION_STEP_KINDS], successRequires: ['exact-artifact-integrity', 'exact-manifest-integrity', 'required-profile-steps', 'terminal-related-jobs', 'verified-evidence-index', 'positive-cleanup-absence', 'source-preservation'] };
  }

  async certify(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const authenticated = requiredContext(context);
    const request = normalizeRequest(payload);
    const reusable = this.findReusable(request, authenticated.subject);
    if (reusable !== undefined) return { operation: 'babyx.release.certification.certify', certification: reusable, reused: true };
    const certificationId = `cert_${sha256(canonicalize({ ownerPrincipal: authenticated.subject, reuseIdentity: request.reuseIdentity })).slice(0, 40)}`;
    const requestDigest = sha256(canonicalize({ ownerPrincipal: authenticated.subject, request }));
    let record = this.ensureInitialRecord(certificationId, authenticated, request, requestDigest);
    if (['SUCCEEDED', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'].includes(String(record.state))) return { operation: 'babyx.release.certification.certify', certification: record, reused: false, replayed: true };
    try {
      const preflight = this.preflight(request);
      record = this.transition(record, authenticated.subject, 'MATERIALIZING', 'preflight', { artifactIntegrityResult: preflight.artifactIntegrityResult, dependencyResult: preflight.dependencyResult }, requestDigest);
      const manifestPath = this.persistManifest(request);
      record = this.transition(record, authenticated.subject, 'STARTING', 'child-start', {}, requestDigest);
      const child = await this.options.certification.run(this.childRequest(request, preflight.artifactPath, manifestPath), { ...context, subject: authenticated.subject, idempotencyKey: `release-cert-${request.reuseIdentity}` });
      return this.finish(record, authenticated.subject, request, requestDigest, childCertification(child));
    } catch (error) {
      return this.fail(record, authenticated.subject, request, requestDigest, error);
    }
  }

  async resume(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const body = strictObject(payload, 'release certification resume request', ['certificationId', 'request']);
    const request = normalizeRequest(body.request);
    const authenticated = requiredContext(context);
    const expectedId = identifier(body.certificationId, 'certificationId');
    const actualId = `cert_${sha256(canonicalize({ ownerPrincipal: authenticated.subject, reuseIdentity: request.reuseIdentity })).slice(0, 40)}`;
    if (expectedId !== actualId) throw new ReleaseCertificationError('release_certification_stale', 'resume identity does not match the durable certification ID');
    const result = await this.certify(object(body.request, 'request'), context);
    return { ...result, operation: 'babyx.release.certification.resume' };
  }

  get(payload: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const body = strictObject(payload, 'release certification get request', ['certificationId']);
    const record = this.options.store.getRecord('CertificationRecordV1', identifier(body.certificationId, 'certificationId'));
    if (context.authorityClass !== 'unrestricted-owner' && ownerFromEvents(this.options.store, String(record.certificationId)) !== context.subject) throw new ReleaseCertificationError('release_record_not_found', 'release certification was not found');
    return { operation: 'babyx.release.certification.get', certification: record };
  }

  list(payload: JsonObject = {}, context: RuntimeExecutionContext): JsonObject {
    const body = strictObject(payload, 'release certification list request', ['state', 'offset', 'limit'], []);
    const state = body.state === undefined ? undefined : text(body.state, 'state', 64);
    const offset = body.offset === undefined ? 0 : integer(body.offset, 'offset');
    const limit = body.limit === undefined ? 50 : integer(body.limit, 'limit', 1, 200);
    const records = this.options.store.listRecordIdentities(10_000).filter((identity) => identity.schemaId === 'CertificationRecordV1').map((identity) => this.options.store.getRecord(identity.schemaId, identity.recordId)).filter((record) => state === undefined || record.state === state).filter((record) => context.authorityClass === 'unrestricted-owner' || ownerFromEvents(this.options.store, String(record.certificationId)) === context.subject).sort((left, right) => String(left.certificationId).localeCompare(String(right.certificationId)));
    const selected = records.slice(offset, offset + limit);
    return { operation: 'babyx.release.certification.list', certifications: selected, offset, limit, total: records.length, nextOffset: offset + selected.length < records.length ? offset + selected.length : null };
  }

  private ensureInitialRecord(certificationId: string, authenticated: { subject: string; idempotencyKey: string }, request: NormalizedRequest, requestDigest: string): JsonObject {
    if (this.options.store.hasRecord('CertificationRecordV1', certificationId)) {
      const record = this.options.store.getRecord('CertificationRecordV1', certificationId);
      if (ownerFromEvents(this.options.store, certificationId) !== authenticated.subject) throw new ReleaseCertificationError('release_wrong_principal', 'release certification identity belongs to another principal');
      return record;
    }
    const createdAt = this.now();
    const record = validateReleaseRecord('CertificationRecordV1', { schemaVersion: '1.0.0', certificationId, artifactId: request.artifactId, artifactSha256: request.artifactSha256, manifestDigest: request.manifestDigest, serviceDefinitionDigest: request.serviceDefinitionDigest, profile: recordProfile(request), profileDigest: request.profile.profileDigest, baseSnapshotName: request.baseSnapshot.name, baseSnapshotGuid: request.baseSnapshot.guid, baseSnapshotCreationTxg: request.baseSnapshot.creationTxg, machineId: 'pending', activeJobIds: [], allJobIds: [], dependencyResult: { status: 'PENDING' }, startupResult: { status: 'PENDING' }, readinessResult: { status: 'PENDING' }, smokeResult: { status: 'PENDING' }, integrationResult: { status: 'PENDING' }, securityResult: { status: 'PENDING' }, acceptanceResult: { status: 'PENDING' }, artifactIntegrityResult: { status: 'PENDING' }, cleanupResult: { status: 'PENDING' }, sourcePreservationResult: { status: 'PENDING' }, evidenceIndexId: 'pending', receiptIds: [], invalidationConditions: request.invalidationConditions, ...(request.expiresAt === undefined ? {} : { expiresAt: request.expiresAt }), state: 'REQUESTED', sequence: 1, createdAt, updatedAt: createdAt });
    return this.options.store.applyMutation({ schemaId: 'CertificationRecordV1', recordId: certificationId, ownerPrincipal: authenticated.subject, expectedSequence: 0, idempotencyKey: authenticated.idempotencyKey, requestDigest, operation: 'babyx.release.certification.certify', phase: 'request', record, occurredAt: createdAt, artifactReferences: [{ artifactId: request.artifactId, artifactSha256: request.artifactSha256 }] });
  }

  private transition(record: JsonObject, ownerPrincipal: string, state: string, phase: string, patch: JsonObject, requestDigest: string): JsonObject {
    const sequence = integer(record.sequence, 'record.sequence');
    const occurredAt = this.now();
    const candidate = validateReleaseRecord('CertificationRecordV1', { ...record, ...patch, state, sequence: sequence + 1, updatedAt: occurredAt, ...(['SUCCEEDED', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS'].includes(state) ? { completedAt: occurredAt } : {}) });
    return this.options.store.applyMutation({ schemaId: 'CertificationRecordV1', recordId: String(record.certificationId), ownerPrincipal, expectedSequence: sequence, idempotencyKey: `${record.certificationId}-${sequence + 1}-${phase}`, requestDigest: sha256(canonicalize({ requestDigest, state, phase, patch })), operation: 'babyx.release.certification.certify', phase, record: candidate, occurredAt, childJobIds: Array.isArray(candidate.allJobIds) ? candidate.allJobIds as string[] : [], artifactReferences: [{ artifactId: candidate.artifactId, artifactSha256: candidate.artifactSha256 }], receiptReferences: Array.isArray(candidate.receiptIds) ? candidate.receiptIds as string[] : [] });
  }

  private preflight(request: NormalizedRequest): { artifactPath: string; artifactIntegrityResult: JsonObject; dependencyResult: JsonObject } {
    const artifact = this.options.artifacts.get(request.artifactId);
    if (artifact.state !== 'finalized' || artifact.sha256 !== request.artifactSha256 || this.options.artifacts.verify(request.artifactId).valid !== true) throw new ReleaseCertificationError('release_artifact_invalid', 'release artifact failed exact integrity verification', { artifactId: request.artifactId, expectedSha256: request.artifactSha256, observedSha256: artifact.sha256 }, 'artifact');
    if (request.manifest.artifactId !== request.artifactId || request.manifest.artifactSha256 !== request.artifactSha256) throw new ReleaseCertificationError('release_artifact_invalid', 'release manifest does not bind the requested artifact identity', {}, 'manifest');
    if (request.manifest.serviceDefinitionDigest !== request.serviceDefinitionDigest) throw new ReleaseCertificationError('release_certification_stale', 'service definition digest differs from artifact manifest', { requested: request.serviceDefinitionDigest, manifest: request.manifest.serviceDefinitionDigest }, 'manifest');
    if (canonicalize(request.manifest.dependencyIdentity) !== canonicalize(request.dependencyIdentity)) throw new ReleaseCertificationError('release_certification_stale', 'dependency identity differs from artifact manifest', {}, 'dependency');
    const minimumVersion = text(request.manifest.minimumApplianceVersion, 'manifest.minimumApplianceVersion', 64);
    if (compareSemver(request.applianceCompatibilityVersion, minimumVersion) < 0) throw new ReleaseCertificationError('release_certification_stale', 'appliance compatibility version is below artifact minimum', { requested: request.applianceCompatibilityVersion, minimumVersion }, 'compatibility');
    const invalidation = activeInvalidation(request);
    if (invalidation !== undefined) throw new ReleaseCertificationError('release_certification_stale', 'release certification identity is actively invalidated', { invalidationDigest: sha256(canonicalize(invalidation)) }, 'invalidation');
    const artifactPath = absolutePath(artifact.path, 'artifact.path');
    if (!existsSync(artifactPath) || !statSync(artifactPath).isFile()) throw new ReleaseCertificationError('release_artifact_invalid', 'artifact authority path is absent or not a regular file', { artifactPath }, 'artifact');
    return { artifactPath, artifactIntegrityResult: { status: 'PASSED', artifactId: request.artifactId, artifactSha256: request.artifactSha256, manifestDigest: request.manifestDigest, verifiedAt: this.now() }, dependencyResult: { status: 'PASSED', dependencyIdentityDigest: sha256(canonicalize(request.dependencyIdentity)) } };
  }

  private persistManifest(request: NormalizedRequest): string {
    const path = join(this.inputRoot, `${request.reuseIdentity}.manifest.json`);
    const bytes = Buffer.from(`${canonicalize(request.manifest)}\n`, 'utf8');
    if (existsSync(path)) {
      if (sha256(readFileSync(path)) !== request.manifestFileDigest) throw new ReleaseCertificationError('release_artifact_invalid', 'durable manifest input conflicts with the exact certification identity', { path }, 'manifest');
      return path;
    }
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const descriptor = openSync(path, 'wx', 0o400);
    try { writeFileSync(descriptor, bytes); fsyncSync(descriptor); } finally { closeSync(descriptor); }
    fsyncDirectory(dirname(path));
    return path;
  }

  private childRequest(request: NormalizedRequest, artifactPath: string, manifestPath: string): JsonObject {
    const machine = structuredClone(request.machine);
    const launch = object(machine.launch, 'machine.launch');
    const binds = Array.isArray(launch.binds) ? [...launch.binds] : [];
    binds.push({ source: artifactPath, destination: ARTIFACT_DESTINATION, mode: 'ro', recursive: false }, { source: manifestPath, destination: MANIFEST_DESTINATION, mode: 'ro', recursive: false });
    launch.binds = binds;
    const source = object(request.manifest.source, 'manifest.source');
    const generated = [
      { id: 'release-artifact-integrity', phase: 'artifact', argv: ['/usr/bin/bash', '-eu', '-o', 'pipefail', '-c', `printf '%s  %s\\n' '${request.artifactSha256}' '${ARTIFACT_DESTINATION}' | /usr/bin/sha256sum -c -`], cwd: '/', timeoutMs: 60_000, required: true },
      { id: 'release-manifest-integrity', phase: 'manifest', argv: ['/usr/bin/bash', '-eu', '-o', 'pipefail', '-c', `printf '%s  %s\\n' '${request.manifestFileDigest}' '${MANIFEST_DESTINATION}' | /usr/bin/sha256sum -c -`], cwd: '/', timeoutMs: 60_000, required: true },
      { id: 'release-materialization', phase: 'runtime', argv: ['/usr/bin/bash', '-eu', '-o', 'pipefail', '-c', `rm -rf '${RELEASE_DESTINATION}' && mkdir -p '${RELEASE_DESTINATION}' && /usr/bin/zstd -q -d -c '${ARTIFACT_DESTINATION}' | /usr/bin/tar -x -f - -C '${RELEASE_DESTINATION}' && test -f '${RELEASE_DESTINATION}/meta/release-payload-manifest.json'`], cwd: '/', timeoutMs: 300_000, required: true },
    ];
    return { schemaVersion: '1.0.0', source: { commit: source.commit, tree: source.tree, snapshot: request.baseSnapshot.name, expectedGuid: request.baseSnapshot.guid }, machine, profile: { id: request.profile.id, version: request.profile.version, steps: [...generated, ...request.profile.steps.map((step) => ({ id: step.id, phase: step.kind, argv: step.argv, cwd: step.cwd, timeoutMs: step.timeoutMs, required: step.required }))] }, retention: { preserveOnFailure: false, ...(request.expiresAt === undefined ? {} : { expiresAt: request.expiresAt }) } };
  }

  private finish(recordValue: JsonObject, ownerPrincipal: string, request: NormalizedRequest, requestDigest: string, child: ChildCertification): JsonObject {
    const record = this.options.store.getRecord('CertificationRecordV1', String(recordValue.certificationId));
    const jobs = child.jobIds.map((jobId) => this.options.jobs.reconcile(jobId));
    const activeJobIds = jobs.filter((job) => job.status === 'running').map((job) => job.id).sort();
    const evidenceIndexId = child.evidence.indexArtifactReference;
    let evidenceValid = false;
    if (typeof evidenceIndexId === 'string' && evidenceIndexId.length > 0) {
      try { evidenceValid = this.options.artifacts.verify(evidenceIndexId).valid === true; } catch { evidenceValid = false; }
    }
    const cleanupPassed = child.cleanup.destroyStatus === 'succeeded' && child.cleanup.absenceVerified === true;
    const sourcePreserved = child.cleanup.sourcePreserved === true;
    const requiredStepsPassed = request.profile.steps.filter((step) => step.required).every((step) => child.steps.find((candidate) => candidate.id === step.id)?.state === 'passed');
    const success = child.state === 'SUCCEEDED' && child.testResult.status === 'passed' && requiredStepsPassed && activeJobIds.length === 0 && evidenceValid && cleanupPassed && sourcePreserved;
    const finalState = success ? 'SUCCEEDED' : activeJobIds.length > 0 || child.state === 'RECOVERY_REQUIRED' || !cleanupPassed ? 'RECOVERY_REQUIRED' : child.state === 'AMBIGUOUS' ? 'AMBIGUOUS' : 'FAILED';
    const startupResult = phaseResult(['startup'], request.profile, child);
    const readinessResult = phaseResult(['readiness'], request.profile, child);
    const smokeResult = phaseResult(['smoke'], request.profile, child);
    const integrationResult = phaseResult(['migration', 'worker', 'streams', 'shutdown', 'integration'], request.profile, child);
    const securityResult = phaseResult(['security', 'resource'], request.profile, child);
    const acceptanceResult = phaseResult(['acceptance'], request.profile, child);
    const failedPhase = [['startup', startupResult], ['readiness', readinessResult], ['smoke', smokeResult], ['integration', integrationResult], ['security', securityResult], ['acceptance', acceptanceResult]].find(([, result]) => (result as JsonObject).status === 'FAILED')?.[0];
    const patch: JsonObject = { profile: recordProfile(request, child.certificationId), machineId: child.machineId ?? 'unknown', activeJobIds, allJobIds: [...child.jobIds].sort(), startupResult, readinessResult, smokeResult, integrationResult, securityResult, acceptanceResult: { ...acceptanceResult, childState: child.state, requiredStepsPassed, terminalJobsVerified: activeJobIds.length === 0, evidenceVerified: evidenceValid }, cleanupResult: child.cleanup, sourcePreservationResult: { status: sourcePreserved ? 'PASSED' : 'FAILED', sourceSnapshot: request.baseSnapshot, preserved: sourcePreserved }, evidenceIndexId: typeof evidenceIndexId === 'string' && evidenceIndexId.length > 0 ? evidenceIndexId : 'missing', receiptIds: [...new Set(child.proofReferences)].sort(), ...(success ? {} : { error: { code: finalState === 'RECOVERY_REQUIRED' ? 'release_recovery_required' : 'release_certification_failed', message: activeJobIds.length > 0 ? 'related durable jobs remain active' : !evidenceValid ? 'certification evidence could not be verified' : !cleanupPassed ? 'certification cleanup was not positively verified' : 'release certification failed', retryable: finalState === 'RECOVERY_REQUIRED', ...(typeof failedPhase === 'string' ? { phase: failedPhase } : {}), productionImpact: 'NONE', detailsDigest: sha256(canonicalize({ childState: child.state, activeJobIds, evidenceValid, cleanupPassed, sourcePreserved, requiredStepsPassed })) } }) };
    const final = this.transition(record, ownerPrincipal, finalState, 'result', patch, requestDigest);
    return { operation: 'babyx.release.certification.certify', certification: final, reused: false, childCertificationId: child.certificationId };
  }

  private fail(recordValue: JsonObject, ownerPrincipal: string, request: NormalizedRequest, requestDigest: string, error: unknown): JsonObject {
    const record = this.options.store.getRecord('CertificationRecordV1', String(recordValue.certificationId));
    const sourceCode = error instanceof ReleaseCertificationError ? error.code : error instanceof ReleaseStoreError ? error.code : 'release_certification_failed';
    const code = sourceCode === 'release_artifact_invalid' ? 'release_artifact_invalid' : sourceCode === 'release_certification_stale' ? 'release_certification_stale' : 'release_certification_failed';
    const phase = error instanceof ReleaseCertificationError && error.phase !== undefined ? error.phase : String(record.state).toLowerCase();
    const failure = boundedReleaseError(error, code, false, phase);
    const recoveryRequired = ['starting', 'cleanup'].includes(phase);
    const state = recoveryRequired ? 'RECOVERY_REQUIRED' : 'FAILED';
    const final = this.transition(record, ownerPrincipal, state, 'failure', { acceptanceResult: { status: 'FAILED', error: failure }, sourcePreservationResult: { status: 'UNKNOWN', sourceSnapshot: request.baseSnapshot }, error: { code: code === 'release_artifact_invalid' || code === 'release_certification_stale' ? code : recoveryRequired ? 'release_recovery_required' : 'release_certification_failed', message: String(failure.message), retryable: recoveryRequired, phase, productionImpact: 'NONE', detailsDigest: sha256(canonicalize(failure)) } }, requestDigest);
    return { operation: 'babyx.release.certification.certify', certification: final, reused: false };
  }

  private findReusable(request: NormalizedRequest, ownerPrincipal: string): JsonObject | undefined {
    if (activeInvalidation(request) !== undefined) return undefined;
    const records = this.options.store.listRecordIdentities(10_000).filter((identity) => identity.schemaId === 'CertificationRecordV1').map((identity) => this.options.store.getRecord(identity.schemaId, identity.recordId));
    for (const record of records) {
      if (record.state !== 'SUCCEEDED' || object(record.profile, 'record.profile').reuseIdentity !== request.reuseIdentity || ownerFromEvents(this.options.store, String(record.certificationId)) !== ownerPrincipal) continue;
      if (record.expiresAt !== undefined && Date.parse(String(record.expiresAt)) <= Date.parse(this.now())) continue;
      const evidenceIndexId = String(record.evidenceIndexId);
      if (evidenceIndexId === 'pending' || evidenceIndexId === 'missing') continue;
      try { if (this.options.artifacts.verify(evidenceIndexId).valid !== true) continue; } catch { continue; }
      return record;
    }
    return undefined;
  }
}
