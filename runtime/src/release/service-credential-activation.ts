import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { canonicalize, sha256, type JsonObject } from '../core.ts';
import { ProtectedCredentialReferenceAuthority } from './access.ts';
import { ServiceCredentialBootstrapService } from './service-credential-bootstrap.ts';
import {
  DurableJobServiceAccountLookup,
  ServiceCredentialFilesystemAuthority,
  ServiceCredentialIssuanceError,
  type ServiceAccountLookupRunner,
} from './service-credential-issuer.ts';
import {
  BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
  BABY_X_PRODUCTION_GATEWAY_ACCOUNT,
  BABY_X_PRODUCTION_GATEWAY_UID,
  SERVICE_CREDENTIAL_ALGORITHM,
  SERVICE_CREDENTIAL_PRIVATE_ENCODING,
  SERVICE_CREDENTIAL_PUBLIC_ENCODING,
  ServiceCredentialContractError,
  describeServiceCredentialProfile,
  serviceCredentialCompatibilityDigest,
  serviceCredentialProfileDigest,
  type ServiceCredentialBootstrapPlanInput,
} from './service-credentials.ts';
import { ReleaseApplianceStore, ReleaseStoreError } from './store.ts';

const GENERATION_SCHEMA = 'ServiceCredentialGenerationV1';
const PROFILE_STATE_SCHEMA = 'ServiceCredentialProfileStateV1';
const REFERENCE_SCHEMA = 'CredentialSetReferenceV1';
const PRIVATE_MODE = 0o400;
const PUBLIC_MODE = 0o640;
const MATERIALIZED_METADATA_MODE = 0o640;
const MATERIALIZED_UNIT_MODE = 0o644;
const DIRECTORY_MODE = 0o700;
const FORBIDDEN_AUTHORITY_PATH = '/etc/stealtheye-quirt/authority.key';

export interface ServiceCredentialActivationOptions {
  store: ReleaseApplianceStore;
  bootstrap: ServiceCredentialBootstrapService;
  issuer: ServiceCredentialFilesystemAuthority;
  privateRoots: string[];
  publicRoots: string[];
  privateOwnerUid?: number;
  privateOwnerGid?: number;
  publicOwnerUid?: number;
  publicOwnerGid?: number;
  now?: () => string;
  productionMaterializationAuthorized?: boolean;
}

export interface ServiceCredentialAuthorityOptions extends ServiceCredentialActivationOptions {
  accountLookup: ServiceAccountLookupRunner;
  stagingRoot: string;
}

export interface ServiceCredentialMaterializationPlan extends JsonObject {
  schemaVersion: '1.0.0';
  profileId: string;
  generationId: string;
  compatibilityDigest: string;
  verificationDigest: string;
  targetRoot: string;
  files: JsonObject[];
  privateReferences: JsonObject[];
  publicFingerprints: JsonObject[];
  planDigest: string;
}

export class ServiceCredentialActivationError extends Error {
  constructor(readonly code: string, message: string, readonly details: JsonObject = {}) {
    super(message);
    this.name = 'ServiceCredentialActivationError';
  }
}

function id(value: unknown, name: string): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$/u.test(value)) {
    throw new ServiceCredentialActivationError('release_credential_bootstrap_invalid_request', `${name} must be a bounded identifier`);
  }
  return value;
}



function owner(context: JsonObject): string {
  return id(context.subject ?? context.ownerPrincipal, 'ownerPrincipal');
}

function idem(context: JsonObject): string {
  return id(context.idempotencyKey, 'idempotencyKey');
}

function within(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel));
}

function assertRegular(path: string, expectedUid: number, expectedGid: number, mode: number): void {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.isBlockDevice() || stat.isCharacterDevice() || stat.isFIFO() || stat.isSocket()) {
    throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'credential path is not a regular file');
  }
  if (stat.nlink !== 1) throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'credential path is hard linked');
  if (stat.uid !== expectedUid || stat.gid !== expectedGid) throw new ServiceCredentialActivationError('release_credential_bootstrap_identity_mismatch', 'credential ownership does not match the generation contract');
  if ((stat.mode & 0o777) !== mode) throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'credential mode does not match the generation contract');
}

function assertUnderRoots(path: string, roots: readonly string[], kind: string): void {
  const absolute = resolve(path);
  if (!roots.some((root) => within(resolve(root), absolute))) throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', `${kind} credential path is outside approved roots`);
  if (absolute === FORBIDDEN_AUTHORITY_PATH || absolute.startsWith(`${FORBIDDEN_AUTHORITY_PATH}/`)) throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'unrelated Quirt authority path is forbidden');
}

function strictPrivate(path: string): ReturnType<typeof createPrivateKey> {
  try {
    const key = createPrivateKey(readFileSync(path));
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('algorithm mismatch');
    return key;
  } catch {
    throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'private credential is not a valid Ed25519 PKCS8 PEM key');
  }
}

function strictPublic(path: string): ReturnType<typeof createPublicKey> {
  try {
    const key = createPublicKey(readFileSync(path));
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('algorithm mismatch');
    return key;
  } catch {
    throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'public credential is not a valid Ed25519 SPKI PEM key');
  }
}

function fingerprint(key: ReturnType<typeof createPublicKey>): string {
  return sha256(key.export({ type: 'spki', format: 'der' }) as Buffer);
}

function verifyRelationship(privateKey: ReturnType<typeof createPrivateKey>, publicKey: ReturnType<typeof createPublicKey>): void {
  const message = Buffer.from('baby-x-service-credential-relationship-v1', 'utf8');
  const signature = sign(null, message, privateKey);
  try {
    if (!verify(null, message, publicKey, signature)) throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'private/public relationship verification failed');
  } finally { signature.fill(0); }
}

function safeRoot(pathValue: string, productionAuthorized: boolean): string {
  const root = resolve(pathValue);
  if (!productionAuthorized && root === '/') throw new ServiceCredentialActivationError('release_credential_bootstrap_materialization_failed', 'production root materialization is not authorized at Checkpoint K.5');
  if (!productionAuthorized && ['/etc/baby-x', '/opt/baby-x', '/var/lib/baby-x'].some((prefix) => root === prefix || root.startsWith(`${prefix}/`))) {
    throw new ServiceCredentialActivationError('release_credential_bootstrap_materialization_failed', 'production Baby-X path materialization is not authorized at Checkpoint K.5');
  }
  mkdirSync(root, { recursive: true, mode: DIRECTORY_MODE });
  const stat = lstatSync(root);
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new ServiceCredentialActivationError('release_credential_bootstrap_materialization_failed', 'materialization root must be a real directory');
  chmodSync(root, DIRECTORY_MODE);
  return root;
}

function ensureParents(root: string, target: string): void {
  if (!within(root, target)) throw new ServiceCredentialActivationError('release_credential_bootstrap_materialization_failed', 'materialization path escapes target root');
  const rel = relative(root, dirname(target));
  let current = root;
  if (rel === '') return;
  for (const segment of rel.split(sep)) {
    if (!segment || segment === '.' || segment === '..') throw new ServiceCredentialActivationError('release_credential_bootstrap_materialization_failed', 'unsafe materialization path segment');
    current = join(current, segment);
    if (!existsSync(current)) mkdirSync(current, { mode: DIRECTORY_MODE });
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new ServiceCredentialActivationError('release_credential_bootstrap_materialization_failed', 'materialization parent is not a real directory');
  }
}

function fsyncDir(path: string): void {
  const fd = openSync(path, fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0));
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function atomicMaterialize(root: string, relativePath: string, bytes: Buffer, mode: number): JsonObject {
  if (isAbsolute(relativePath) || relativePath.split('/').some((part) => !part || part === '.' || part === '..')) throw new ServiceCredentialActivationError('release_credential_bootstrap_materialization_failed', 'invalid relative materialization path');
  const target = resolve(root, relativePath);
  ensureParents(root, target);
  const parent = dirname(target);
  const temporary = join(parent, `.${target.slice(parent.length + 1)}.tmp-${process.pid}`);
  if (existsSync(target)) {
    const stat = lstatSync(target);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) throw new ServiceCredentialActivationError('release_credential_bootstrap_materialization_failed', 'preexisting materialization target is unsafe');
    const existing = readFileSync(target);
    if (sha256(existing) !== sha256(bytes) || (stat.mode & 0o777) !== mode) throw new ServiceCredentialActivationError('release_credential_bootstrap_materialization_failed', 'preexisting materialization target conflicts with the plan');
    return { path: target, digest: sha256(bytes), mode: mode.toString(8).padStart(4, '0'), replayed: true };
  }
  let fd: number | undefined;
  try {
    fd = openSync(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0), mode);
    writeFileSync(fd, bytes);
    fsyncSync(fd);
    closeSync(fd); fd = undefined;
    chmodSync(temporary, mode);
    renameSync(temporary, target);
    fsyncDir(parent);
    const stat = lstatSync(target);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o777) !== mode || sha256(readFileSync(target)) !== sha256(bytes)) {
      throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'materialization readback failed');
    }
    return { path: target, digest: sha256(bytes), mode: mode.toString(8).padStart(4, '0'), replayed: false };
  } catch (error) {
    if (fd !== undefined) { try { closeSync(fd); } catch { /* best effort */ } }
    if (existsSync(temporary)) { try { unlinkSync(temporary); fsyncDir(parent); } catch { /* checked below */ } }
    if (existsSync(temporary)) throw new ServiceCredentialActivationError('release_credential_bootstrap_cleanup_failed', 'temporary materialization file survived failure');
    throw error;
  }
}

export class ServiceCredentialActivationService {
  private readonly now: () => string;
  private readonly privateRoots: string[];
  private readonly publicRoots: string[];
  private readonly privateUid: number;
  private readonly privateGid: number;
  private readonly publicUid: number;
  private readonly publicGid: number;
  private readonly referenceAuthority: ProtectedCredentialReferenceAuthority;

  constructor(readonly options: ServiceCredentialActivationOptions) {
    this.now = options.now ?? (() => new Date().toISOString());
    this.privateRoots = options.privateRoots.map((root) => resolve(root));
    this.publicRoots = options.publicRoots.map((root) => resolve(root));
    this.privateUid = options.privateOwnerUid ?? 0;
    this.privateGid = options.privateOwnerGid ?? 0;
    this.publicUid = options.publicOwnerUid ?? 0;
    this.publicGid = options.publicOwnerGid ?? 0;
    this.referenceAuthority = new ProtectedCredentialReferenceAuthority({ protectedRoots: this.privateRoots, requireRootOwner: this.privateUid === 0 });
  }

  private generation(generationId: string): JsonObject {
    const generation = this.options.store.getRecord(GENERATION_SCHEMA, id(generationId, 'generationId'));
    if (generation.profileId !== BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID || generation.profileDigest !== serviceCredentialProfileDigest() || generation.compatibilityDigest !== serviceCredentialCompatibilityDigest()) {
      throw new ServiceCredentialActivationError('release_credential_bootstrap_incompatible', 'credential generation is incompatible with the certified Baby-X controller');
    }
    if (generation.state === 'REVOKED') throw new ServiceCredentialActivationError('release_credential_bootstrap_revoked', 'credential generation is revoked');
    if (generation.state === 'AMBIGUOUS' || generation.state === 'FAILED') throw new ServiceCredentialActivationError('release_credential_bootstrap_ambiguous', `credential generation state ${String(generation.state)} is not usable`);
    return generation;
  }

  private reference(generation: JsonObject): JsonObject {
    if (!Array.isArray(generation.privateReferences) || generation.privateReferences.length !== 2) throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'credential generation requires exactly two private references');
    const setIds = new Set(generation.privateReferences.map((entry) => String((entry as JsonObject).credentialSetId)));
    if (setIds.size !== 1) throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'private references do not share one credential set');
    const reference = this.options.store.getRecord(REFERENCE_SCHEMA, [...setIds][0]!);
    try {
      this.referenceAuthority.inspect(reference);
    } catch (error) {
      if (error instanceof ServiceCredentialActivationError) throw error;
      const causeCode = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : 'credential_reference_verification_failed';
      throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'private credential reference verification failed', { causeCode });
    }
    return reference;
  }

  verifyGeneration(generationId: string): JsonObject {
    const generation = this.generation(generationId);
    const reference = this.reference(generation);
    if (!Array.isArray(reference.entries) || reference.entries.length !== 2) throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'credential set must contain exactly two private entries');
    const entries = new Map((reference.entries as JsonObject[]).map((entry) => [String(entry.name), entry]));
    const gatewayEntry = entries.get('baby-x-gateway-authority-private');
    const proofEntry = entries.get('baby-x-proof-private');
    if (gatewayEntry === undefined || proofEntry === undefined) throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'credential set names do not match the Baby-X profile');
    for (const entry of [gatewayEntry, proofEntry]) {
      const path = String(entry.sourceRef);
      assertUnderRoots(path, this.privateRoots, 'private');
      assertRegular(path, this.privateUid, this.privateGid, PRIVATE_MODE);
      if (sha256(readFileSync(path)) !== entry.objectDigest) throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'private credential digest mismatch');
    }
    if (!Array.isArray(generation.publicMaterials) || generation.publicMaterials.length !== 1) throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'generation requires exactly one proof public material');
    const publicMaterial = generation.publicMaterials[0] as JsonObject;
    const publicPath = String(publicMaterial.path);
    assertUnderRoots(publicPath, this.publicRoots, 'public');
    assertRegular(publicPath, this.publicUid, this.publicGid, PUBLIC_MODE);
    if (sha256(readFileSync(publicPath)) !== publicMaterial.objectDigest) throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'public credential digest mismatch');
    const gatewayPrivate = strictPrivate(String(gatewayEntry.sourceRef));
    const proofPrivate = strictPrivate(String(proofEntry.sourceRef));
    const proofPublic = strictPublic(publicPath);
    const derivedGatewayPublic = createPublicKey(gatewayPrivate);
    const derivedProofPublic = createPublicKey(proofPrivate);
    verifyRelationship(proofPrivate, proofPublic);
    if (fingerprint(derivedProofPublic) !== fingerprint(proofPublic)) throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'proof public material does not correspond to the proof private reference');
    const fingerprintMap = new Map((generation.publicFingerprints as JsonObject[]).map((entry) => [String(entry.name), String(entry.fingerprintSha256)]));
    if (fingerprintMap.get('gateway-authority-public') !== fingerprint(derivedGatewayPublic) || fingerprintMap.get('proof-public') !== fingerprint(proofPublic)) {
      throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'public fingerprint mismatch');
    }
    const binding = generation.serviceIdentityBinding as JsonObject;
    if (binding.accountName !== BABY_X_PRODUCTION_GATEWAY_ACCOUNT || binding.observedUid !== BABY_X_PRODUCTION_GATEWAY_UID || binding.reverseUidAccountName !== BABY_X_PRODUCTION_GATEWAY_ACCOUNT) {
      throw new ServiceCredentialActivationError('release_credential_bootstrap_identity_mismatch', 'generation service identity binding no longer matches fix-mcp UID 997');
    }
    const observation = {
      generationId: generation.generationId,
      profileId: generation.profileId,
      privateReferences: [
        { referenceId: (generation.privateReferences[0] as JsonObject).referenceId, name: (generation.privateReferences[0] as JsonObject).name, objectDigest: (generation.privateReferences[0] as JsonObject).objectDigest },
        { referenceId: (generation.privateReferences[1] as JsonObject).referenceId, name: (generation.privateReferences[1] as JsonObject).name, objectDigest: (generation.privateReferences[1] as JsonObject).objectDigest },
      ],
      publicMaterials: [{ referenceId: publicMaterial.referenceId, name: publicMaterial.name, objectDigest: publicMaterial.objectDigest }],
      publicFingerprints: generation.publicFingerprints,
      serviceIdentity: {
        accountName: binding.accountName,
        observedUid: binding.observedUid,
        observedGid: binding.observedGid,
        reverseUidAccountName: binding.reverseUidAccountName,
        lookupSource: binding.lookupSource,
        bindingDigest: binding.bindingDigest,
      },
      algorithm: SERVICE_CREDENTIAL_ALGORITHM,
      privateEncoding: SERVICE_CREDENTIAL_PRIVATE_ENCODING,
      publicEncoding: SERVICE_CREDENTIAL_PUBLIC_ENCODING,
      keyRelationships: [
        { name: 'gateway-authority', verified: true },
        { name: 'proof', verified: true },
      ],
      ownershipVerified: true,
      modesVerified: true,
      privateReferenceAuthority: this.referenceAuthority.authority,
      temporaryMaterialAbsent: this.temporaryFiles().length === 0,
      forbiddenAuthorityUntouched: true,
      compatibilityDigest: generation.compatibilityDigest,
    };
    if (!observation.temporaryMaterialAbsent) throw new ServiceCredentialActivationError('release_credential_bootstrap_verification_failed', 'temporary credential material remains');
    return {
      schemaVersion: '1.0.0',
      verificationId: `scv-${sha256(canonicalize(observation)).slice(0, 40)}`,
      generationId: generation.generationId,
      profileId: generation.profileId,
      publicFingerprints: structuredClone(generation.publicFingerprints as JsonObject[]),
      keyRelationships: observation.keyRelationships,
      serviceIdentity: observation.serviceIdentity,
      ownershipChecks: [{ kind: 'PRIVATE', verified: true }, { kind: 'PUBLIC', verified: true }],
      modeChecks: [{ kind: 'PRIVATE', mode: '0400', verified: true }, { kind: 'PUBLIC', mode: '0640', verified: true }],
      temporaryMaterialCleanup: { temporaryMaterialAbsent: true, positiveAbsenceVerified: true },
      forbiddenAuthorityChecks: [{ path: FORBIDDEN_AUTHORITY_PATH, accessed: false, verified: true }],
      compatibilityDigest: generation.compatibilityDigest,
      observationDigest: sha256(canonicalize(observation)),
      verifiedAt: this.now(),
      publicOnly: true,
    };
  }

  private mutateGeneration(generation: JsonObject, nextState: string, patch: JsonObject, operation: string): JsonObject {
    if (generation.state === nextState && Object.entries(patch).every(([key, value]) => canonicalize(generation[key]) === canonicalize(value))) return generation;
    const occurredAt = this.now();
    const candidate: JsonObject = { ...generation, ...patch, state: nextState, sequence: Number(generation.sequence) + 1, updatedAt: occurredAt };
    const requestDigest = sha256(canonicalize({ generationId: generation.generationId, priorSequence: generation.sequence, nextState, patch }));
    return this.options.store.applyMutation({
      schemaId: GENERATION_SCHEMA,
      recordId: String(generation.generationId),
      ownerPrincipal: String(generation.ownerPrincipal),
      expectedSequence: Number(generation.sequence),
      idempotencyKey: `scg-state-${requestDigest.slice(0, 40)}`,
      requestDigest,
      operation,
      phase: 'generation-state',
      record: candidate,
      occurredAt,
    });
  }

  activateGeneration(generationIdValue: string, ownerPrincipalValue: string): JsonObject {
    const generationId = id(generationIdValue, 'generationId');
    const ownerPrincipal = id(ownerPrincipalValue, 'ownerPrincipal');
    const verification = this.verifyGeneration(generationId);
    let target = this.generation(generationId);
    if (target.ownerPrincipal !== ownerPrincipal) throw new ServiceCredentialActivationError('release_credential_bootstrap_identity_mismatch', 'generation owner does not match activation principal');
    const currentProfile = this.options.bootstrap.active(BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID);
    if (currentProfile.activeGenerationId === generationId) {
      if (currentProfile.previousGenerationId !== undefined && currentProfile.previousGenerationId !== generationId) {
        let previous = this.options.store.getRecord(GENERATION_SCHEMA, String(currentProfile.previousGenerationId));
        if (previous.state !== 'RETIRED' && previous.state !== 'REVOKED') this.mutateGeneration(previous, 'RETIRED', { successorGenerationId: generationId, retiredAt: previous.retiredAt ?? this.now() }, 'babyx.release.credential-bootstrap.activate');
      }
      return { active: currentProfile, generation: target, verification, replayed: true };
    }
    const previousGenerationId = currentProfile.activeGenerationId === null || currentProfile.activeGenerationId === undefined ? undefined : String(currentProfile.activeGenerationId);
    target = this.mutateGeneration(target, 'ACTIVE', {
      ...(previousGenerationId === undefined ? {} : { predecessorGenerationId: previousGenerationId }),
      activatedAt: target.activatedAt ?? this.now(),
    }, 'babyx.release.credential-bootstrap.activate');
    const occurredAt = this.now();
    const profileSequence = currentProfile.state === 'EMPTY' ? 0 : Number(currentProfile.sequence);
    const generationIds = [...new Set([...(Array.isArray(currentProfile.generationIds) ? currentProfile.generationIds.map(String) : []), generationId])];
    const profileRecord: JsonObject = {
      schemaVersion: '1.0.0',
      profileStateId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
      ownerPrincipal,
      profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
      profileDigest: serviceCredentialProfileDigest(),
      state: previousGenerationId === undefined ? 'ACTIVE' : 'ROLLBACK_READY',
      activeGenerationId: generationId,
      ...(previousGenerationId === undefined ? {} : { previousGenerationId }),
      generationIds,
      compatibilityDigest: serviceCredentialCompatibilityDigest(),
      sequence: profileSequence + 1,
      createdAt: currentProfile.state === 'EMPTY' ? occurredAt : currentProfile.createdAt,
      updatedAt: occurredAt,
    };
    const profileDigest = sha256(canonicalize({ prior: currentProfile, next: profileRecord }));
    const active = this.options.store.applyMutation({
      schemaId: PROFILE_STATE_SCHEMA,
      recordId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
      ownerPrincipal,
      expectedSequence: profileSequence,
      idempotencyKey: `scp-activate-${profileDigest.slice(0, 40)}`,
      requestDigest: profileDigest,
      operation: 'babyx.release.credential-bootstrap.activate',
      phase: 'atomic-active-generation-switch',
      record: profileRecord,
      occurredAt,
    });
    if (previousGenerationId !== undefined && previousGenerationId !== generationId) {
      let previous = this.options.store.getRecord(GENERATION_SCHEMA, previousGenerationId);
      if (previous.state !== 'REVOKED') previous = this.mutateGeneration(previous, 'RETIRED', { successorGenerationId: generationId, retiredAt: previous.retiredAt ?? this.now() }, 'babyx.release.credential-bootstrap.activate');
    }
    return { active, generation: target, verification, replayed: false };
  }

  rollback(targetGenerationIdValue: string, ownerPrincipalValue: string): JsonObject {
    const targetGenerationId = id(targetGenerationIdValue, 'targetGenerationId');
    const ownerPrincipal = id(ownerPrincipalValue, 'ownerPrincipal');
    const active = this.options.bootstrap.active(BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID);
    if (active.state === 'EMPTY' || active.activeGenerationId === null || active.activeGenerationId === undefined) throw new ServiceCredentialActivationError('release_credential_bootstrap_invalid_state', 'no active generation exists to roll back');
    const currentGenerationId = String(active.activeGenerationId);
    if (currentGenerationId === targetGenerationId) return { active, target: this.generation(targetGenerationId), replayed: true };
    if (!Array.isArray(active.generationIds) || !active.generationIds.includes(targetGenerationId)) throw new ServiceCredentialActivationError('release_credential_bootstrap_invalid_request', 'rollback target is not in the bounded profile generation history');
    const result = this.activateGeneration(targetGenerationId, ownerPrincipal);
    return { ...result, rolledBackFromGenerationId: currentGenerationId, regenerated: false };
  }

  revoke(generationIdValue: string, ownerPrincipalValue: string, reasonValue: string): JsonObject {
    const generationId = id(generationIdValue, 'generationId');
    const ownerPrincipal = id(ownerPrincipalValue, 'ownerPrincipal');
    if (typeof reasonValue !== 'string' || reasonValue.length < 1 || reasonValue.length > 1_024) throw new ServiceCredentialActivationError('release_credential_bootstrap_invalid_request', 'revocation reason must be 1-1024 characters');
    const active = this.options.bootstrap.active(BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID);
    if (active.activeGenerationId === generationId) throw new ServiceCredentialActivationError('release_credential_bootstrap_invalid_state', 'active generation must be rolled back before revocation');
    const rawGeneration = this.options.store.getRecord(GENERATION_SCHEMA, generationId);
    if (rawGeneration.state === 'REVOKED') return { generationId, state: 'REVOKED', revocationReasonDigest: rawGeneration.revocationReasonDigest, evidencePreserved: true, privateMaterialDestroyed: false, replayed: true };
    const generation = this.generation(generationId);
    if (generation.ownerPrincipal !== ownerPrincipal) throw new ServiceCredentialActivationError('release_credential_bootstrap_identity_mismatch', 'generation owner does not match revocation principal');
    const revoked = this.mutateGeneration(generation, 'REVOKED', { revokedAt: this.now(), revocationReasonDigest: sha256(reasonValue) }, 'babyx.release.credential-bootstrap.revoke');
    return { generationId, state: revoked.state, revocationReasonDigest: revoked.revocationReasonDigest, evidencePreserved: true, privateMaterialDestroyed: false };
  }

  active(): JsonObject {
    const active = this.options.bootstrap.active(BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID);
    if (active.state === 'EMPTY') return active;
    const generation = this.generation(String(active.activeGenerationId));
    return {
      ...active,
      activeGeneration: {
        generationId: generation.generationId,
        state: generation.state,
        ordinal: generation.ordinal,
        publicFingerprints: generation.publicFingerprints,
        serviceIdentityBinding: generation.serviceIdentityBinding,
        verificationDigest: generation.verificationDigest,
      },
      rawPrivateMaterialReturned: false,
    };
  }

  private temporaryFiles(): string[] {
    const found: string[] = [];
    const walk = (root: string): void => {
      if (!existsSync(root)) return;
      for (const entry of readdirSync(root, { withFileTypes: true })) {
        const path = join(root, entry.name);
        if (entry.isSymbolicLink()) continue;
        if (entry.isDirectory()) walk(path);
        else if (entry.name.includes('.tmp-')) found.push(path);
      }
    };
    for (const root of [...this.privateRoots, ...this.publicRoots]) walk(root);
    return found.sort();
  }

  cleanTemporaryState(): JsonObject {
    const before = this.temporaryFiles();
    const removed: string[] = [];
    for (const path of before) {
      const stat = lstatSync(path);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new ServiceCredentialActivationError('release_credential_bootstrap_cleanup_failed', 'unsafe temporary object cannot be cleaned automatically');
      unlinkSync(path);
      fsyncDir(dirname(path));
      removed.push(path);
    }
    const after = this.temporaryFiles();
    if (after.length > 0) throw new ServiceCredentialActivationError('release_credential_bootstrap_cleanup_failed', 'temporary material remains after cleanup');
    return { removedCount: removed.length, removedDigests: removed.map((path) => sha256(path)), temporaryMaterialAbsent: true, positiveAbsenceVerified: true };
  }

  materializationPlan(generationIdValue: string, targetRootValue: string): ServiceCredentialMaterializationPlan {
    const generationId = id(generationIdValue, 'generationId');
    const active = this.options.bootstrap.active(BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID);
    if (active.activeGenerationId !== generationId) throw new ServiceCredentialActivationError('release_credential_bootstrap_invalid_state', 'installer requires the exact active verified credential generation');
    const verification = this.verifyGeneration(generationId);
    const generation = this.generation(generationId);
    const reference = this.reference(generation);
    const entries = new Map((reference.entries as JsonObject[]).map((entry) => [String(entry.name), entry]));
    const gateway = entries.get('baby-x-gateway-authority-private')!;
    const proof = entries.get('baby-x-proof-private')!;
    const publicMaterial = generation.publicMaterials[0] as JsonObject;
    const targetRoot = resolve(targetRootValue);
    const controllerDropIn = `[Service]\nLoadCredential=baby-x-proof-private:${String(proof.sourceRef)}\nEnvironment=BABY_X_PROOF_PRIVATE_KEY=%d/baby-x-proof-private\nEnvironment=BABY_X_GATEWAY_UID=${BABY_X_PRODUCTION_GATEWAY_UID}\n`;
    const gatewayDropIn = `[Service]\nLoadCredential=baby-x-gateway-authority-private:${String(gateway.sourceRef)}\nEnvironment=BABY_X_GATEWAY_PRIVATE_KEY=%d/baby-x-gateway-authority-private\nEnvironment=BABY_X_PROOF_PUBLIC_KEY=/etc/baby-x/proof-public.pem\nEnvironment=BABY_X_GATEWAY_UID=${BABY_X_PRODUCTION_GATEWAY_UID}\n`;
    const metadata = {
      schemaVersion: '1.0.0',
      profileId: generation.profileId,
      generationId,
      compatibilityDigest: generation.compatibilityDigest,
      verificationDigest: generation.verificationDigest,
      publicFingerprints: generation.publicFingerprints,
      serviceIdentity: verification.serviceIdentity,
      privateReferences: generation.privateReferences,
      publicMaterialReference: { referenceId: publicMaterial.referenceId, objectDigest: publicMaterial.objectDigest },
      rawPrivateMaterialIncluded: false,
    };
    const files: JsonObject[] = [
      { relativePath: 'etc/baby-x/proof-public.pem', sourcePath: publicMaterial.path, digest: publicMaterial.objectDigest, mode: '0640', kind: 'PUBLIC_MATERIAL' },
      { relativePath: 'etc/baby-x/credential-generation.json', bytesBase64: Buffer.from(`${JSON.stringify(metadata, null, 2)}\n`).toString('base64'), digest: sha256(`${JSON.stringify(metadata, null, 2)}\n`), mode: '0640', kind: 'PUBLIC_METADATA' },
      { relativePath: 'etc/systemd/system/baby-x.service.d/20-service-credentials.conf', bytesBase64: Buffer.from(controllerDropIn).toString('base64'), digest: sha256(controllerDropIn), mode: '0644', kind: 'SYSTEMD_BINDING' },
      { relativePath: 'etc/systemd/system/baby-x-gateway.service.d/20-service-credentials.conf', bytesBase64: Buffer.from(gatewayDropIn).toString('base64'), digest: sha256(gatewayDropIn), mode: '0644', kind: 'SYSTEMD_BINDING' },
    ];
    const base: JsonObject = {
      schemaVersion: '1.0.0',
      profileId: generation.profileId,
      generationId,
      compatibilityDigest: generation.compatibilityDigest,
      verificationDigest: generation.verificationDigest,
      targetRoot,
      files,
      privateReferences: generation.privateReferences,
      publicFingerprints: generation.publicFingerprints,
    };
    return { ...base, planDigest: sha256(canonicalize(base)) } as ServiceCredentialMaterializationPlan;
  }

  materialize(planValue: ServiceCredentialMaterializationPlan, dryRun = true): JsonObject {
    const plan = structuredClone(planValue);
    const withoutDigest = Object.fromEntries(Object.entries(plan).filter(([key]) => key !== 'planDigest'));
    if (sha256(canonicalize(withoutDigest)) !== plan.planDigest) throw new ServiceCredentialActivationError('release_credential_bootstrap_materialization_failed', 'materialization plan digest mismatch');
    const targetRoot = resolve(String(plan.targetRoot));
    const productionAuthorized = this.options.productionMaterializationAuthorized === true;
    if (!productionAuthorized && (targetRoot === '/' || ['/etc/baby-x', '/opt/baby-x', '/var/lib/baby-x'].some((prefix) => targetRoot === prefix || targetRoot.startsWith(`${prefix}/`)))) {
      throw new ServiceCredentialActivationError('release_credential_bootstrap_materialization_failed', 'production Baby-X materialization is not authorized at Checkpoint K.5');
    }
    if (dryRun) return { plan, dryRun: true, applied: false, productionMutation: false, filesystemEffects: false };
    const root = safeRoot(targetRoot, productionAuthorized);
    const outputs: JsonObject[] = [];
    for (const file of plan.files as JsonObject[]) {
      const bytes = file.sourcePath === undefined ? Buffer.from(String(file.bytesBase64), 'base64') : readFileSync(String(file.sourcePath));
      if (sha256(bytes) !== file.digest) throw new ServiceCredentialActivationError('release_credential_bootstrap_materialization_failed', 'materialization source digest mismatch');
      const mode = String(file.mode) === '0644' ? MATERIALIZED_UNIT_MODE : String(file.mode) === '0640' ? MATERIALIZED_METADATA_MODE : PUBLIC_MODE;
      outputs.push(atomicMaterialize(root, String(file.relativePath), bytes, mode));
    }
    const temporary = readdirSync(root, { recursive: true, withFileTypes: true }).filter((entry) => entry.name.includes('.tmp-'));
    if (temporary.length > 0) throw new ServiceCredentialActivationError('release_credential_bootstrap_cleanup_failed', 'materialization temporary files remain');
    return { planDigest: plan.planDigest, generationId: plan.generationId, dryRun: false, applied: true, outputs, readbackVerified: true, temporaryMaterialAbsent: true, productionMutation: root === '/' };
  }
}

export class ServiceCredentialAuthority {
  readonly activation: ServiceCredentialActivationService;
  constructor(readonly options: ServiceCredentialAuthorityOptions) {
    this.activation = new ServiceCredentialActivationService(options);
  }

  describe(): JsonObject { return { ...this.options.bootstrap.describe(), issuance: this.options.issuer.describe(), activation: { atomicSourceOfTruth: PROFILE_STATE_SCHEMA, rollbackRegenerates: false, revocationDestroysEvidence: false }, materialization: { defaultRoot: this.options.stagingRoot, productionEnabled: this.options.productionMaterializationAuthorized === true } }; }
  profiles(): JsonObject { return this.options.bootstrap.profiles(); }
  compatibility(): JsonObject { return describeServiceCredentialProfile(); }
  plan(payload: JsonObject, context: JsonObject): JsonObject {
    return this.options.bootstrap.plan({
      ownerPrincipal: owner(context),
      idempotencyKey: idem(context),
      profileId: String(payload.profileId),
      expectedCompatibilityIdentity: String(payload.expectedCompatibilityIdentity),
      policyDecision: payload.policyDecision as JsonObject,
      ...(payload.rotationPredecessorGenerationId === undefined ? {} : { rotationPredecessorGenerationId: String(payload.rotationPredecessorGenerationId) }),
    });
  }
  get(payload: JsonObject): JsonObject { return this.options.bootstrap.get(String(payload.transactionId)); }
  list(payload: JsonObject): JsonObject { return this.options.bootstrap.list(payload as { offset?: number; limit?: number; state?: string; profileId?: string }); }
  events(payload: JsonObject): JsonObject { return this.options.bootstrap.events(String(payload.transactionId), Number(payload.offset ?? 0), Number(payload.limit ?? 100)); }
  verify(payload: JsonObject): JsonObject { return this.activation.verifyGeneration(String(payload.generationId)); }
  active(): JsonObject { return this.activation.active(); }

  private assertDeclaredEffects(payload: JsonObject, plan: JsonObject): void {
    if (!Array.isArray(payload.declaredEffects) || canonicalize(payload.declaredEffects) !== canonicalize(plan.declaredEffects)) {
      throw new ServiceCredentialActivationError('release_credential_bootstrap_invalid_request', 'declared effects must exactly match the immutable bootstrap plan');
    }
  }

  async ensure(payload: JsonObject, context: JsonObject): Promise<JsonObject> {
    const ownerPrincipal = owner(context); const idempotencyKey = idem(context);
    const request: ServiceCredentialBootstrapPlanInput = {
      ownerPrincipal, idempotencyKey,
      profileId: String(payload.profileId),
      expectedCompatibilityIdentity: String(payload.expectedCompatibilityIdentity),
      policyDecision: payload.policyDecision as JsonObject,
    };
    const immutablePlan = this.options.bootstrap.plan(request);
    this.assertDeclaredEffects(payload, immutablePlan);
    const transaction = this.options.bootstrap.requestBootstrap(request);
    const issued = await this.options.issuer.issueWithAuthoritativeAccountLookup({ transactionId: String(transaction.transactionId), ownerPrincipal, expectedSequence: Number(transaction.sequence), idempotencyKey }, this.options.accountLookup);
    const activated = this.activation.activateGeneration(String((issued.transaction as JsonObject).generationId), ownerPrincipal);
    return { transaction: issued.transaction, generation: issued.generation, active: activated.active, replayed: issued.replayed && activated.replayed, rawPrivateMaterialReturned: false };
  }

  reconcile(payload: JsonObject, context: JsonObject): JsonObject {
    const transactionId = String(payload.transactionId);
    const transaction = this.options.bootstrap.get(transactionId);
    const active = this.activation.active();
    const generationId = transaction.generationId === undefined ? null : String(transaction.generationId);
    let observation: 'NO_EXTERNAL_EFFECT' | 'EXTERNAL_EFFECT_ABSENT' | 'EXTERNAL_STATE_UNKNOWN' | 'EXTERNAL_EFFECT_OBSERVED' = 'EXTERNAL_STATE_UNKNOWN';
    let verificationDigest: string | null = null;
    if (generationId !== null) {
      try {
        const verification = this.activation.verifyGeneration(generationId);
        verificationDigest = String(verification.verificationDigest ?? verification.observationDigest ?? sha256(canonicalize(verification)));
        observation = 'EXTERNAL_EFFECT_OBSERVED';
      } catch {
        observation = 'EXTERNAL_STATE_UNKNOWN';
      }
    } else if (['REQUESTED', 'PLANNING'].includes(String(transaction.state))) observation = 'NO_EXTERNAL_EFFECT';
    const observationDigest = sha256(canonicalize({ transactionId, state: transaction.state, sequence: transaction.sequence, generationId, activeGenerationId: active.activeGenerationId ?? null, verificationDigest, observation }));
    return this.options.bootstrap.reconcile({ transactionId, ownerPrincipal: owner(context), expectedSequence: Number(payload.expectedSequence), observation, observationDigest });
  }

  async rotate(payload: JsonObject, context: JsonObject): Promise<JsonObject> {
    const ownerPrincipal = owner(context); const idempotencyKey = idem(context);
    const activeBefore = this.activation.active();
    if (activeBefore.state === 'EMPTY' || activeBefore.activeGenerationId === undefined || activeBefore.activeGenerationId === null) throw new ServiceCredentialActivationError('release_credential_bootstrap_invalid_state', 'rotation requires an active generation');
    const predecessor = String(activeBefore.activeGenerationId);
    const request = { ownerPrincipal, idempotencyKey, profileId: String(payload.profileId), expectedCompatibilityIdentity: String(payload.expectedCompatibilityIdentity), policyDecision: payload.policyDecision as JsonObject, rotationPredecessorGenerationId: predecessor };
    const immutablePlan = this.options.bootstrap.plan(request);
    this.assertDeclaredEffects(payload, immutablePlan);
    const transaction = this.options.bootstrap.requestBootstrap(request);
    const issued = await this.options.issuer.issueWithAuthoritativeAccountLookup({ transactionId: String(transaction.transactionId), ownerPrincipal, expectedSequence: Number(transaction.sequence), idempotencyKey, ordinal: Number((activeBefore.activeGeneration as JsonObject).ordinal ?? 1) + 1 }, this.options.accountLookup);
    const activeAfter = this.activation.activateGeneration(String((issued.transaction as JsonObject).generationId), ownerPrincipal);
    return { predecessorGenerationId: predecessor, transaction: issued.transaction, generation: issued.generation, active: activeAfter.active, priorRemainedActiveUntilVerification: true, rawPrivateMaterialReturned: false };
  }

  rollback(payload: JsonObject, context: JsonObject): JsonObject {
    if (String(payload.profileId) !== BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID) throw new ServiceCredentialActivationError('release_credential_bootstrap_invalid_request', 'unsupported rollback service credential profile');
    const active = this.options.bootstrap.active(BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID);
    const expectedSequence = Number(payload.expectedSequence);
    const currentSequence = Number(active.sequence);
    const alreadyObserved = String(active.activeGenerationId ?? '') === String(payload.targetGenerationId);
    if (expectedSequence !== currentSequence && !(alreadyObserved && expectedSequence === currentSequence - 1)) throw new ServiceCredentialActivationError('release_credential_bootstrap_sequence_conflict', 'rollback expected sequence does not match active profile state');
    return this.activation.rollback(String(payload.targetGenerationId), owner(context));
  }
  revoke(payload: JsonObject, context: JsonObject): JsonObject {
    const generation = this.options.store.getRecord(GENERATION_SCHEMA, String(payload.generationId));
    const expectedSequence = Number(payload.expectedSequence);
    const currentSequence = Number(generation.sequence);
    const alreadyObserved = generation.state === 'REVOKED';
    if (expectedSequence !== currentSequence && !(alreadyObserved && expectedSequence === currentSequence - 1)) throw new ServiceCredentialActivationError('release_credential_bootstrap_sequence_conflict', 'revocation expected sequence does not match credential generation');
    return this.activation.revoke(String(payload.generationId), owner(context), String(payload.reason));
  }
  clean(): JsonObject { return this.activation.cleanTemporaryState(); }
  materializationPlan(generationId: string, targetRoot = this.options.stagingRoot): ServiceCredentialMaterializationPlan { return this.activation.materializationPlan(generationId, targetRoot); }
}

export { DurableJobServiceAccountLookup, ServiceCredentialFilesystemAuthority, ServiceCredentialIssuanceError, ServiceCredentialContractError, ReleaseStoreError };
