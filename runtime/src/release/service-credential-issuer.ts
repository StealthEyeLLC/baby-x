import {
  constants as fsConstants,
  chmodSync,
  chownSync,
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { canonicalize, sha256, type JsonObject } from '../core.ts';
import { normalizeCredentialSet, ProtectedCredentialReferenceAuthority } from './access.ts';
import { ServiceCredentialBootstrapService } from './service-credential-bootstrap.ts';
import {
  BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID,
  BABY_X_PRODUCTION_GATEWAY_ACCOUNT,
  BABY_X_PRODUCTION_GATEWAY_UID,
  SERVICE_CREDENTIAL_ALGORITHM,
  serviceCredentialCompatibilityDigest,
  SERVICE_CREDENTIAL_PRIVATE_ENCODING,
  SERVICE_CREDENTIAL_PUBLIC_ENCODING,
} from './service-credentials.ts';
import { ReleaseApplianceStore, ReleaseStoreError } from './store.ts';
import { validateReleaseRecord } from './schemas.ts';

const GENERATION_SCHEMA = 'ServiceCredentialGenerationV1';
const CREDENTIAL_REFERENCE_SCHEMA = 'CredentialSetReferenceV1';
const PRIVATE_MODE = 0o400;
const PUBLIC_MODE = 0o640;
const DIRECTORY_MODE = 0o700;
const FORBIDDEN_AUTHORITY_PATH = '/etc/stealtheye-quirt/authority.key';
const PRODUCTION_PATH_PREFIXES = ['/etc/baby-x', '/opt/baby-x', '/var/lib/baby-x'];

export type ServiceCredentialIssuerFaultStage =
  | 'before_generation'
  | 'after_gateway_private_write'
  | 'after_proof_private_write'
  | 'after_public_write'
  | 'before_reference_persist'
  | 'after_reference_persist'
  | 'before_verification'
  | 'after_generation_persist';

export interface ServiceIdentityObservation extends JsonObject {
  accountName: string;
  observedUid: number;
  observedGid: number;
  reverseUidAccountName: string;
  lookupSource: string;
  verifiedAt: string;
}

export interface ServiceCredentialIdentityJobRecord extends JsonObject {
  id: string;
  status: 'running' | 'completed' | 'failed' | 'cancelled' | 'lost';
  exitCode?: number | null;
}

export interface ServiceCredentialIdentityJobAuthority {
  readonly authority: 'existing-babyx-job';
  start(operation: string, payload: JsonObject): ServiceCredentialIdentityJobRecord;
  get(id: string): ServiceCredentialIdentityJobRecord;
  read(id: string, stream: 'stdout' | 'stderr', offset?: number, limit?: number): JsonObject;
  reconcile?(id: string): ServiceCredentialIdentityJobRecord;
}

export interface ServiceAccountLookupRunner {
  readonly authority: 'durable-job-authority';
  lookup(accountName: string, expectedUid: number): Promise<ServiceIdentityObservation>;
}

export interface DurableJobServiceAccountLookupOptions {
  jobs: ServiceCredentialIdentityJobAuthority;
  now?: () => string;
  pollIntervalMs?: number;
  timeoutMs?: number;
}

export interface ServiceCredentialFilesystemOptions {
  store: ReleaseApplianceStore;
  bootstrap: ServiceCredentialBootstrapService;
  privateRoot: string;
  publicRoot: string;
  privateOwnerUid?: number;
  privateOwnerGid?: number;
  publicOwnerUid?: number;
  publicOwnerGid?: number;
  productionMaterializationAuthorized?: boolean;
  now?: () => string;
  faultInjector?: (stage: ServiceCredentialIssuerFaultStage, context: JsonObject) => void;
}

export interface IssueServiceCredentialInput {
  transactionId: string;
  ownerPrincipal: string;
  expectedSequence: number;
  idempotencyKey: string;
  identityObservation: ServiceIdentityObservation;
  ordinal?: number;
}

export class ServiceCredentialIssuanceError extends Error {
  constructor(readonly code: string, message: string, readonly details: JsonObject = {}) {
    super(message);
    this.name = 'ServiceCredentialIssuanceError';
  }
}

function identifier(value: unknown, name: string): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$/u.test(value)) {
    throw new ServiceCredentialIssuanceError('release_credential_bootstrap_invalid_request', `${name} must be a bounded identifier`);
  }
  return value;
}

function safeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_invalid_request', `${name} must be a non-negative safe integer`);
  return Number(value);
}

function timestamp(value: unknown, name: string): string {
  if (typeof value !== 'string' || !value.endsWith('Z') || Number.isNaN(Date.parse(value))) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_invalid_request', `${name} must be an absolute UTC timestamp`);
  return value;
}

function safeRelative(value: string, name: string): string {
  if (value.length < 1 || isAbsolute(value) || value.includes('\0')) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_invalid_request', `${name} must be a relative path`);
  const segments = value.split('/');
  if (segments.some((segment) => segment.length < 1 || segment === '.' || segment === '..' || !/^[A-Za-z0-9._-]+$/u.test(segment))) {
    throw new ServiceCredentialIssuanceError('release_credential_bootstrap_invalid_request', `${name} contains an unsafe segment`);
  }
  return segments.join('/');
}

function within(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel));
}

function isProductionPath(path: string): boolean {
  return PRODUCTION_PATH_PREFIXES.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}

function ensureRoot(path: string, productionAuthorized: boolean): string {
  const absolute = resolve(path);
  const forbiddenRoot = resolve(dirname(FORBIDDEN_AUTHORITY_PATH));
  if (!productionAuthorized && isProductionPath(absolute)) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_materialization_failed', `production credential path is not authorized at Checkpoint K.5: ${absolute}`);
  if (absolute === forbiddenRoot || absolute.startsWith(`${forbiddenRoot}${sep}`) || absolute === FORBIDDEN_AUTHORITY_PATH) {
    throw new ServiceCredentialIssuanceError('release_credential_bootstrap_materialization_failed', 'unrelated Quirt authority path is forbidden');
  }
  mkdirSync(absolute, { recursive: true, mode: DIRECTORY_MODE });
  chmodSync(absolute, DIRECTORY_MODE);
  const stat = lstatSync(absolute);
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_materialization_failed', 'credential root must be a real directory');
  return realpathSync(absolute);
}

function ensureSafeDirectory(root: string, path: string): void {
  if (!within(root, path)) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_materialization_failed', 'credential path escapes approved root');
  const rel = relative(root, path);
  let current = root;
  if (rel === '') return;
  for (const segment of rel.split(sep)) {
    current = resolve(current, segment);
    if (!existsSync(current)) mkdirSync(current, { mode: DIRECTORY_MODE });
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_materialization_failed', 'credential parent contains a non-directory or symlink');
    chmodSync(current, DIRECTORY_MODE);
  }
}

function fsyncDirectory(path: string): void {
  const fd = openSync(path, fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0));
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function assertRegularSingleLink(path: string, expectedUid: number, expectedGid: number, expectedMode: number): void {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.isBlockDevice() || stat.isCharacterDevice() || stat.isFIFO() || stat.isSocket()) {
    throw new ServiceCredentialIssuanceError('release_credential_bootstrap_materialization_failed', 'credential object must be a regular file');
  }
  if (stat.nlink !== 1) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_materialization_failed', 'credential object must not be hard linked');
  if (stat.uid !== expectedUid || stat.gid !== expectedGid) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_identity_mismatch', 'credential object ownership mismatch');
  if ((stat.mode & 0o777) !== expectedMode) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_materialization_failed', 'credential object mode mismatch');
}

function removeStaleTemporaryFiles(parent: string, basename: string): number {
  let removed = 0;
  for (const name of readdirSync(parent)) {
    if (!name.startsWith(`.${basename}.tmp-`)) continue;
    const path = resolve(parent, name);
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_cleanup_failed', 'unsafe stale temporary credential object');
    unlinkSync(path);
    removed += 1;
  }
  if (removed > 0) fsyncDirectory(parent);
  return removed;
}

function atomicWriteExact(root: string, relativePath: string, bytes: Buffer, uid: number, gid: number, mode: number): { path: string; digest: string; replayed: boolean; staleTemporaryFilesRemoved: number } {
  const rel = safeRelative(relativePath, 'credential relative path');
  const target = resolve(root, rel);
  if (!within(root, target)) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_materialization_failed', 'credential target escapes approved root');
  const parent = dirname(target);
  ensureSafeDirectory(root, parent);
  const basename = target.slice(parent.length + 1);
  const staleTemporaryFilesRemoved = removeStaleTemporaryFiles(parent, basename);
  const digest = sha256(bytes);
  if (existsSync(target)) {
    assertRegularSingleLink(target, uid, gid, mode);
    if (sha256(readFileSync(target)) !== digest) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_materialization_failed', 'preexisting credential object conflicts with issued generation');
    return { path: target, digest, replayed: true, staleTemporaryFilesRemoved };
  }
  const temporary = resolve(parent, `.${basename}.tmp-${process.pid}-${randomUUID()}`);
  let fd: number | undefined;
  try {
    fd = openSync(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0), mode);
    writeFileSync(fd, bytes);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    chownSync(temporary, uid, gid);
    chmodSync(temporary, mode);
    assertRegularSingleLink(temporary, uid, gid, mode);
    linkSync(temporary, target);
    unlinkSync(temporary);
    fsyncDirectory(parent);
    assertRegularSingleLink(target, uid, gid, mode);
    if (sha256(readFileSync(target)) !== digest) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_verification_failed', 'credential object readback digest mismatch');
    return { path: target, digest, replayed: false, staleTemporaryFilesRemoved };
  } catch (error) {
    if (fd !== undefined) { try { closeSync(fd); } catch { /* best effort */ } }
    if (existsSync(temporary)) { try { unlinkSync(temporary); fsyncDirectory(parent); } catch { /* reported below */ } }
    if (existsSync(temporary)) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_cleanup_failed', 'temporary credential object survived failed atomic write');
    throw error;
  }
}

function pem(label: 'PRIVATE KEY' | 'PUBLIC KEY', der: Buffer): Buffer {
  const body = der.toString('base64').replace(/.{1,64}/gu, '$&\n');
  return Buffer.from(`-----BEGIN ${label}-----\n${body}-----END ${label}-----\n`, 'ascii');
}

function generatePrivatePem(): Buffer {
  const pair = generateKeyPairSync('ed25519');
  const der = pair.privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
  try { return pem('PRIVATE KEY', der); } finally { der.fill(0); }
}

function privateKeyFromPem(bytes: Buffer): KeyObject {
  let key: KeyObject;
  try { key = createPrivateKey({ key: bytes, format: 'pem' }); }
  catch { throw new ServiceCredentialIssuanceError('release_credential_bootstrap_verification_failed', 'private credential encoding is invalid'); }
  if (key.asymmetricKeyType !== 'ed25519') throw new ServiceCredentialIssuanceError('release_credential_bootstrap_verification_failed', 'private credential algorithm substitution rejected');
  return key;
}

function publicPemFromPrivate(privateKey: KeyObject): { pem: Buffer; der: Buffer; fingerprint: string } {
  const publicKey = createPublicKey(privateKey);
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new ServiceCredentialIssuanceError('release_credential_bootstrap_verification_failed', 'public credential algorithm substitution rejected');
  const der = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  return { pem: pem('PUBLIC KEY', der), der, fingerprint: sha256(der) };
}

function verifyPair(privateKey: KeyObject, publicDer: Buffer): void {
  const publicKey = createPublicKey({ key: publicDer, format: 'der', type: 'spki' });
  const challenge = randomBytes(64);
  try {
    const signature = sign(null, challenge, privateKey);
    try {
      if (!verify(null, challenge, publicKey, signature)) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_verification_failed', 'private/public credential relationship check failed');
    } finally { signature.fill(0); }
  } finally { challenge.fill(0); }
}

export class DurableJobServiceAccountLookup implements ServiceAccountLookupRunner {
  readonly authority = 'durable-job-authority' as const;
  private readonly now: () => string;
  private readonly pollIntervalMs: number;
  private readonly timeoutMs: number;

  constructor(private readonly options: DurableJobServiceAccountLookupOptions) {
    if (options.jobs.authority !== 'existing-babyx-job') throw new ServiceCredentialIssuanceError('release_credential_bootstrap_invalid_request', 'service identity lookup must reuse the existing Baby-X Job Authority');
    this.now = options.now ?? (() => new Date().toISOString());
    this.pollIntervalMs = options.pollIntervalMs ?? 25;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    if (!Number.isSafeInteger(this.pollIntervalMs) || this.pollIntervalMs < 1 || this.pollIntervalMs > 1_000) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_invalid_request', 'pollIntervalMs must be between 1 and 1000');
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 100 || this.timeoutMs > 60_000) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_invalid_request', 'timeoutMs must be between 100 and 60000');
  }

  private async runGetent(query: string, purpose: string): Promise<{ line: string; jobId: string }> {
    const record = this.options.jobs.start('babyx.release.credential-bootstrap.identity-lookup', {
      argv: ['/usr/bin/getent', 'passwd', query],
      cwd: '/',
      env: {},
      timeoutMs: this.timeoutMs,
      metadata: { purpose, credentialProfile: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID, containsSecretMaterial: false },
    });
    const deadline = Date.now() + this.timeoutMs;
    let current = record;
    while (current.status === 'running' && Date.now() < deadline) {
      await new Promise<void>((resolvePromise) => setTimeout(resolvePromise, this.pollIntervalMs));
      current = this.options.jobs.get(record.id);
    }
    if (current.status === 'running' && this.options.jobs.reconcile !== undefined) current = this.options.jobs.reconcile(record.id);
    if (current.status !== 'completed' || current.exitCode !== 0) {
      throw new ServiceCredentialIssuanceError('release_credential_bootstrap_identity_mismatch', `authoritative account lookup failed for ${purpose}`, { jobId: record.id, status: current.status, exitCode: current.exitCode ?? null });
    }
    const read = this.options.jobs.read(record.id, 'stdout', 0, 4_096);
    if (read.encoding !== 'base64' || typeof read.data !== 'string' || read.eof !== true) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_identity_mismatch', 'account lookup output was not a complete bounded durable job stream', { jobId: record.id });
    const text = Buffer.from(read.data, 'base64').toString('utf8');
    const lines = text.split(/\r?\n/u).filter((line) => line.length > 0);
    if (lines.length !== 1) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_identity_mismatch', 'account lookup returned an absent or ambiguous identity', { jobId: record.id, lineCount: lines.length });
    return { line: lines[0]!, jobId: record.id };
  }

  async lookup(accountNameValue: string, expectedUidValue: number): Promise<ServiceIdentityObservation> {
    const accountName = identifier(accountNameValue, 'accountName');
    const expectedUid = safeInteger(expectedUidValue, 'expectedUid');
    const byName = await this.runGetent(accountName, 'ACCOUNT_NAME_TO_UID');
    const parsedName = parseGetentPasswd(byName.line, accountName);
    if (parsedName.uid !== expectedUid) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_identity_mismatch', `service account ${accountName} did not resolve to exact UID ${expectedUid}`, { observedUid: parsedName.uid, expectedUid, jobId: byName.jobId });
    const byUid = await this.runGetent(String(expectedUid), 'UID_TO_ACCOUNT_NAME');
    const parsedUid = parseGetentPasswd(byUid.line, accountName);
    if (parsedUid.uid !== expectedUid || parsedUid.accountName !== accountName) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_identity_mismatch', 'reverse UID lookup did not resolve to the exact expected service principal', { expectedUid, accountName, jobId: byUid.jobId });
    return {
      accountName,
      observedUid: expectedUid,
      observedGid: Number(parsedName.gid),
      reverseUidAccountName: String(parsedUid.accountName),
      lookupSource: 'DURABLE_JOB_AUTHORITY_GETENT',
      verifiedAt: this.now(),
      forwardLookupJobId: byName.jobId,
      reverseLookupJobId: byUid.jobId,
      observationDigest: sha256(canonicalize({ accountName, expectedUid, observedGid: parsedName.gid, forwardLookupJobId: byName.jobId, reverseLookupJobId: byUid.jobId })),
    } as ServiceIdentityObservation;
  }
}

export function parseGetentPasswd(lineValue: string, expectedName: string): JsonObject {
  const line = lineValue.trim();
  const fields = line.split(':');
  if (fields.length !== 7) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_identity_mismatch', 'account lookup returned malformed passwd data');
  const [accountName, , uidText, gidText, , home, shell] = fields;
  if (accountName !== expectedName) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_identity_mismatch', 'account lookup returned the wrong principal');
  const uid = Number(uidText); const gid = Number(gidText);
  if (!Number.isSafeInteger(uid) || uid < 0 || !Number.isSafeInteger(gid) || gid < 0) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_identity_mismatch', 'account lookup returned invalid UID or GID');
  return { accountName, uid, gid, home, shell };
}

export function validateServiceIdentityObservation(value: ServiceIdentityObservation): JsonObject {
  const accountName = identifier(value.accountName, 'identity accountName');
  const observedUid = safeInteger(value.observedUid, 'identity observedUid');
  const observedGid = safeInteger(value.observedGid, 'identity observedGid');
  const reverseUidAccountName = identifier(value.reverseUidAccountName, 'identity reverseUidAccountName');
  const lookupSource = identifier(value.lookupSource, 'identity lookupSource');
  const verifiedAt = timestamp(value.verifiedAt, 'identity verifiedAt');
  if (accountName !== BABY_X_PRODUCTION_GATEWAY_ACCOUNT || observedUid !== BABY_X_PRODUCTION_GATEWAY_UID || reverseUidAccountName !== BABY_X_PRODUCTION_GATEWAY_ACCOUNT) {
    throw new ServiceCredentialIssuanceError('release_credential_bootstrap_identity_mismatch', 'fix-mcp service identity or exact UID 997 invariant failed');
  }
  return {
    accountName,
    observedUid,
    observedGid,
    reverseUidAccountName,
    lookupSource,
    verifiedAt,
    expectedAccountName: BABY_X_PRODUCTION_GATEWAY_ACCOUNT,
    expectedUid: BABY_X_PRODUCTION_GATEWAY_UID,
    bindingDigest: sha256(canonicalize({ accountName, observedUid, observedGid, reverseUidAccountName, lookupSource })),
  };
}

interface IssuedMaterial {
  credentialSetId: string;
  gatewayReferenceId: string;
  proofReferenceId: string;
  referenceDigest: string;
  bindingDigest: string;
  privateReferences: JsonObject[];
  publicMaterials: JsonObject[];
  publicFingerprints: JsonObject[];
  verification: JsonObject;
  temporaryCleanup: JsonObject;
}

export class ServiceCredentialFilesystemAuthority {
  readonly authority = 'systemd-credential-reference-authority' as const;
  private readonly privateRoot: string;
  private readonly publicRoot: string;
  private readonly privateUid: number;
  private readonly privateGid: number;
  private readonly publicUid: number;
  private readonly publicGid: number;
  private readonly now: () => string;
  private readonly references: ProtectedCredentialReferenceAuthority;

  constructor(private readonly options: ServiceCredentialFilesystemOptions) {
    const authorized = options.productionMaterializationAuthorized === true;
    this.privateRoot = ensureRoot(options.privateRoot, authorized);
    this.publicRoot = ensureRoot(options.publicRoot, authorized);
    this.privateUid = options.privateOwnerUid ?? 0;
    this.privateGid = options.privateOwnerGid ?? 0;
    this.publicUid = options.publicOwnerUid ?? 0;
    this.publicGid = options.publicOwnerGid ?? 0;
    this.now = options.now ?? (() => new Date().toISOString());
    this.references = new ProtectedCredentialReferenceAuthority({ protectedRoots: [this.privateRoot], requireRootOwner: this.privateUid === 0 });
  }

  describe(): JsonObject {
    return {
      authority: this.authority,
      extension: 'service-credential-issuance-v1',
      algorithm: SERVICE_CREDENTIAL_ALGORITHM,
      privateEncoding: SERVICE_CREDENTIAL_PRIVATE_ENCODING,
      publicEncoding: SERVICE_CREDENTIAL_PUBLIC_ENCODING,
      rawMaterialReturned: false,
      forbiddenAuthorityPath: FORBIDDEN_AUTHORITY_PATH,
      productionMaterializationAuthorized: this.options.productionMaterializationAuthorized === true,
    };
  }

  verifyGeneration(generationIdValue: string): JsonObject {
    const generationId = identifier(generationIdValue, 'generationId');
    const generation = this.options.store.getRecord(GENERATION_SCHEMA, generationId);
    const state = String(generation.state);
    if (state === 'REVOKED') throw new ServiceCredentialIssuanceError('release_credential_bootstrap_revoked', 'revoked credential generations cannot be verified for consumption');
    if (!['READY', 'ACTIVE', 'RETIRED'].includes(state)) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_invalid_state', `credential generation ${generationId} is not verified and consumable`);
    if (generation.compatibilityDigest !== serviceCredentialCompatibilityDigest()) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_incompatible', 'credential generation compatibility identity no longer matches the certified controller');

    const privateReferences = Array.isArray(generation.privateReferences) ? generation.privateReferences as JsonObject[] : [];
    const credentialSetIds = [...new Set(privateReferences.map((entry) => String(entry.credentialSetId ?? '')).filter((value) => value.length > 0))];
    if (credentialSetIds.length !== 1) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_verification_failed', 'credential generation does not resolve to exactly one private credential set');
    const credentialReference = this.options.store.getRecord(CREDENTIAL_REFERENCE_SCHEMA, credentialSetIds[0]!);
    const entries = Array.isArray(credentialReference.entries) ? credentialReference.entries as JsonObject[] : [];
    const gatewayEntry = entries.find((entry) => entry.name === 'baby-x-gateway-authority-private');
    const proofEntry = entries.find((entry) => entry.name === 'baby-x-proof-private');
    if (gatewayEntry === undefined || proofEntry === undefined) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_verification_failed', 'private credential reference set is incomplete');

    const publicMaterials = Array.isArray(generation.publicMaterials) ? generation.publicMaterials as JsonObject[] : [];
    const proofPublic = publicMaterials.find((entry) => entry.name === 'proof-public');
    if (proofPublic === undefined || typeof proofPublic.path !== 'string') throw new ServiceCredentialIssuanceError('release_credential_bootstrap_verification_failed', 'proof public material reference is incomplete');

    const gatewayPath = String(gatewayEntry.sourceRef ?? '');
    const proofPath = String(proofEntry.sourceRef ?? '');
    assertRegularSingleLink(gatewayPath, this.privateUid, this.privateGid, PRIVATE_MODE);
    assertRegularSingleLink(proofPath, this.privateUid, this.privateGid, PRIVATE_MODE);
    assertRegularSingleLink(proofPublic.path, this.publicUid, this.publicGid, PUBLIC_MODE);

    const gatewayBytes = readFileSync(gatewayPath);
    const proofBytes = readFileSync(proofPath);
    const publicBytes = readFileSync(proofPublic.path);
    try {
      if (sha256(gatewayBytes) !== gatewayEntry.objectDigest || sha256(proofBytes) !== proofEntry.objectDigest || sha256(publicBytes) !== proofPublic.objectDigest) {
        throw new ServiceCredentialIssuanceError('release_credential_bootstrap_verification_failed', 'credential object digest readback mismatch');
      }
      const gatewayPrivate = privateKeyFromPem(gatewayBytes);
      const proofPrivate = privateKeyFromPem(proofBytes);
      const gatewayDerived = publicPemFromPrivate(gatewayPrivate);
      const proofDerived = publicPemFromPrivate(proofPrivate);
      const observedPublic = createPublicKey(publicBytes);
      if (observedPublic.asymmetricKeyType !== 'ed25519') throw new ServiceCredentialIssuanceError('release_credential_bootstrap_verification_failed', 'proof public material algorithm is not Ed25519');
      const observedDer = Buffer.from(observedPublic.export({ type: 'spki', format: 'der' }));
      try {
        verifyPair(gatewayPrivate, gatewayDerived.der);
        verifyPair(proofPrivate, observedDer);
        if (!proofDerived.der.equals(observedDer)) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_verification_failed', 'proof private and public material do not correspond');
        const expectedFingerprints = new Map((Array.isArray(generation.publicFingerprints) ? generation.publicFingerprints as JsonObject[] : []).map((entry) => [String(entry.name), String(entry.fingerprintSha256)]));
        if (expectedFingerprints.get('gateway-authority-public') !== gatewayDerived.fingerprint || expectedFingerprints.get('proof-public') !== sha256(observedDer)) {
          throw new ServiceCredentialIssuanceError('release_credential_bootstrap_verification_failed', 'public fingerprint readback mismatch');
        }
        const identity = validateServiceIdentityObservation(generation.serviceIdentityBinding as ServiceIdentityObservation);
        const temporaryNames = [
          ...readdirSync(dirname(gatewayPath)),
          ...readdirSync(dirname(proofPublic.path)),
        ].filter((name) => name.includes('.tmp-'));
        if (temporaryNames.length !== 0) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_verification_failed', 'temporary credential material remains after issuance');
        const observation = {
          generationId,
          state,
          profileId: generation.profileId,
          publicFingerprints: generation.publicFingerprints,
          serviceIdentity: identity,
          ownershipChecks: [
            { name: 'gateway-authority-private', uid: this.privateUid, gid: this.privateGid, mode: '0400', verified: true },
            { name: 'proof-private', uid: this.privateUid, gid: this.privateGid, mode: '0400', verified: true },
            { name: 'proof-public', uid: this.publicUid, gid: this.publicGid, mode: '0640', verified: true },
          ],
          modeChecks: { privateMode: '0400', publicMode: '0640', verified: true },
          keyRelationships: [
            { name: 'gateway-authority', algorithm: SERVICE_CREDENTIAL_ALGORITHM, verified: true },
            { name: 'proof', algorithm: SERVICE_CREDENTIAL_ALGORITHM, verified: true },
          ],
          temporaryMaterialCleanup: { temporaryMaterialAbsent: true, positiveAbsenceVerified: true },
          forbiddenAuthorityChecks: [{ path: FORBIDDEN_AUTHORITY_PATH, accessed: false, verified: true }],
          compatibilityDigest: generation.compatibilityDigest,
          verifiedAt: this.now(),
        };
        return {
          verificationId: `scv-${sha256(canonicalize(observation)).slice(0, 40)}`,
          ...observation,
          observationDigest: sha256(canonicalize(observation)),
          rawPrivateMaterialReturned: false,
        };
      } finally {
        gatewayDerived.pem.fill(0); gatewayDerived.der.fill(0);
        proofDerived.pem.fill(0); proofDerived.der.fill(0); observedDer.fill(0);
      }
    } finally {
      gatewayBytes.fill(0); proofBytes.fill(0); publicBytes.fill(0);
    }
  }

  private inject(stage: ServiceCredentialIssuerFaultStage, context: JsonObject): void {
    this.options.faultInjector?.(stage, structuredClone(context));
  }

  private persistCredentialReference(reference: JsonObject, ownerPrincipal: string): JsonObject {
    const id = String(reference.credentialSetId);
    if (this.options.store.hasRecord(CREDENTIAL_REFERENCE_SCHEMA, id)) {
      const existing = this.options.store.getRecord(CREDENTIAL_REFERENCE_SCHEMA, id);
      if (existing.referenceDigest !== reference.referenceDigest || existing.bindingDigest !== reference.bindingDigest) {
        throw new ServiceCredentialIssuanceError('release_idempotency_conflict', 'credential set generation identity conflicts with durable reference');
      }
      return existing;
    }
    return this.options.store.applyMutation({
      schemaId: CREDENTIAL_REFERENCE_SCHEMA,
      recordId: id,
      ownerPrincipal,
      expectedSequence: 0,
      idempotencyKey: `scr-${sha256(id).slice(0, 48)}`,
      requestDigest: sha256(canonicalize(reference)),
      operation: 'babyx.release.credential-bootstrap.ensure',
      phase: 'private-reference-persistence',
      record: reference,
      occurredAt: this.now(),
    });
  }

  private recoverOrGeneratePrivate(relativePath: string): { path: string; digest: string; privateKey: KeyObject; replayed: boolean; staleTemporaryFilesRemoved: number } {
    const target = resolve(this.privateRoot, safeRelative(relativePath, 'private credential path'));
    if (existsSync(target)) {
      assertRegularSingleLink(target, this.privateUid, this.privateGid, PRIVATE_MODE);
      const bytes = readFileSync(target);
      try {
        const privateKey = privateKeyFromPem(bytes);
        return { path: target, digest: sha256(bytes), privateKey, replayed: true, staleTemporaryFilesRemoved: removeStaleTemporaryFiles(dirname(target), target.slice(dirname(target).length + 1)) };
      } finally { bytes.fill(0); }
    }
    const bytes = generatePrivatePem();
    try {
      const written = atomicWriteExact(this.privateRoot, relativePath, bytes, this.privateUid, this.privateGid, PRIVATE_MODE);
      return { ...written, privateKey: privateKeyFromPem(bytes) };
    } finally { bytes.fill(0); }
  }

  issueMaterial(generationIdValue: string, ownerPrincipalValue: string, ordinalValue = 1): IssuedMaterial {
    const generationId = identifier(generationIdValue, 'generationId');
    const ownerPrincipal = identifier(ownerPrincipalValue, 'ownerPrincipal');
    const ordinal = safeInteger(ordinalValue, 'ordinal');
    if (ordinal < 1) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_invalid_request', 'ordinal must be at least one');
    this.inject('before_generation', { generationId, ownerPrincipal, ordinal });
    const gateway = this.recoverOrGeneratePrivate(`generations/${generationId}/gateway-authority-private.pem`);
    this.inject('after_gateway_private_write', { generationId, objectDigest: gateway.digest, replayed: gateway.replayed });
    const proof = this.recoverOrGeneratePrivate(`generations/${generationId}/proof-private.pem`);
    this.inject('after_proof_private_write', { generationId, objectDigest: proof.digest, replayed: proof.replayed });
    const gatewayPublic = publicPemFromPrivate(gateway.privateKey);
    const proofPublic = publicPemFromPrivate(proof.privateKey);
    try {
      verifyPair(gateway.privateKey, gatewayPublic.der);
      verifyPair(proof.privateKey, proofPublic.der);
      const publicWrite = atomicWriteExact(this.publicRoot, `generations/${generationId}/proof-public.pem`, proofPublic.pem, this.publicUid, this.publicGid, PUBLIC_MODE);
      this.inject('after_public_write', { generationId, objectDigest: publicWrite.digest, replayed: publicWrite.replayed });
      const credentialSetId = `scs-${sha256(canonicalize({ generationId, profileId: BABY_X_PRODUCTION_CONTROLLER_PROFILE_ID })).slice(0, 40)}`;
      const gatewayReferenceId = `scr-${sha256(`${generationId}:gateway-authority-private`).slice(0, 40)}`;
      const proofReferenceId = `scr-${sha256(`${generationId}:proof-private`).slice(0, 40)}`;
      const reference = normalizeCredentialSet({
        credentialSetId,
        serviceId: 'baby-x',
        version: ordinal,
        provider: 'SYSTEMD_CREDENTIAL',
        entries: [
          { name: 'baby-x-gateway-authority-private', mode: 'PLAIN', sourceRef: gateway.path, objectDigest: gateway.digest, version: ordinal },
          { name: 'baby-x-proof-private', mode: 'PLAIN', sourceRef: proof.path, objectDigest: proof.digest, version: ordinal },
        ],
      }, ownerPrincipal, this.now());
      this.references.inspect(reference);
      this.inject('before_reference_persist', { generationId, credentialSetId });
      const persistedReference = this.persistCredentialReference(reference, ownerPrincipal);
      this.inject('after_reference_persist', { generationId, credentialSetId, referenceDigest: persistedReference.referenceDigest });
      this.inject('before_verification', { generationId });
      const verification = {
        algorithm: SERVICE_CREDENTIAL_ALGORITHM,
        privateEncoding: SERVICE_CREDENTIAL_PRIVATE_ENCODING,
        publicEncoding: SERVICE_CREDENTIAL_PUBLIC_ENCODING,
        gatewayRelationshipVerified: true,
        proofRelationshipVerified: true,
        privateReferenceAuthority: this.references.authority,
        privateReferenceReadbackVerified: true,
        publicReadbackVerified: sha256(readFileSync(publicWrite.path)) === publicWrite.digest,
        privateModesVerified: [gateway.path, proof.path].every((path) => (lstatSync(path).mode & 0o777) === PRIVATE_MODE),
        publicModeVerified: (lstatSync(publicWrite.path).mode & 0o777) === PUBLIC_MODE,
        temporaryMaterialAbsent: [
          ...readdirSync(dirname(gateway.path)).filter((name) => name.includes('.tmp-')),
          ...readdirSync(dirname(proof.path)).filter((name) => name.includes('.tmp-')),
          ...readdirSync(dirname(publicWrite.path)).filter((name) => name.includes('.tmp-')),
        ].length === 0,
        forbiddenAuthorityUntouched: true,
        verifiedAt: this.now(),
      };
      if (!verification.publicReadbackVerified || !verification.privateModesVerified || !verification.publicModeVerified || !verification.temporaryMaterialAbsent) {
        throw new ServiceCredentialIssuanceError('release_credential_bootstrap_verification_failed', 'issued credential verification facts are incomplete');
      }
      return {
        credentialSetId,
        gatewayReferenceId,
        proofReferenceId,
        referenceDigest: String(persistedReference.referenceDigest),
        bindingDigest: String(persistedReference.bindingDigest),
        privateReferences: [
          { referenceId: gatewayReferenceId, credentialSetId, name: 'gateway-authority-private', objectDigest: gateway.digest },
          { referenceId: proofReferenceId, credentialSetId, name: 'proof-private', objectDigest: proof.digest },
        ],
        publicMaterials: [{ referenceId: `spm-${sha256(`${generationId}:proof-public`).slice(0, 40)}`, name: 'proof-public', path: publicWrite.path, objectDigest: publicWrite.digest, encoding: SERVICE_CREDENTIAL_PUBLIC_ENCODING }],
        publicFingerprints: [
          { name: 'gateway-authority-public', algorithm: SERVICE_CREDENTIAL_ALGORITHM, fingerprintSha256: gatewayPublic.fingerprint },
          { name: 'proof-public', algorithm: SERVICE_CREDENTIAL_ALGORITHM, fingerprintSha256: proofPublic.fingerprint },
        ],
        verification,
        temporaryCleanup: {
          staleTemporaryFilesRemoved: gateway.staleTemporaryFilesRemoved + proof.staleTemporaryFilesRemoved + publicWrite.staleTemporaryFilesRemoved,
          temporaryMaterialAbsent: verification.temporaryMaterialAbsent,
          positiveAbsenceVerified: true,
        },
      };
    } finally {
      gatewayPublic.pem.fill(0); gatewayPublic.der.fill(0);
      proofPublic.pem.fill(0); proofPublic.der.fill(0);
    }
  }

  persistGeneration(transaction: JsonObject, identityBinding: JsonObject, material: IssuedMaterial, ordinal: number): JsonObject {
    const generationId = String(transaction.generationId);
    if (this.options.store.hasRecord(GENERATION_SCHEMA, generationId)) {
      const existing = this.options.store.getRecord(GENERATION_SCHEMA, generationId);
      if (existing.profileDigest !== transaction.profileDigest || existing.compatibilityDigest !== transaction.compatibilityDigest) {
        throw new ServiceCredentialIssuanceError('release_idempotency_conflict', 'generation identity conflicts with durable metadata');
      }
      return existing;
    }
    const now = this.now();
    const verificationDigest = sha256(canonicalize({
      privateReferences: material.privateReferences,
      publicMaterials: material.publicMaterials,
      publicFingerprints: material.publicFingerprints,
      serviceIdentityBinding: identityBinding,
      verification: material.verification,
    }));
    const record = validateReleaseRecord(GENERATION_SCHEMA, {
      schemaVersion: '1.0.0',
      generationId,
      ownerPrincipal: transaction.ownerPrincipal,
      profileId: transaction.profileId,
      profileDigest: transaction.profileDigest,
      ordinal,
      state: 'READY',
      ...(transaction.rotationPredecessorGenerationId === undefined ? {} : { predecessorGenerationId: transaction.rotationPredecessorGenerationId }),
      privateReferences: material.privateReferences,
      publicMaterials: material.publicMaterials,
      publicFingerprints: material.publicFingerprints,
      serviceIdentityBinding: identityBinding,
      compatibilityDigest: transaction.compatibilityDigest,
      verificationDigest,
      sequence: 1,
      createdAt: now,
      updatedAt: now,
    });
    const persisted = this.options.store.applyMutation({
      schemaId: GENERATION_SCHEMA,
      recordId: generationId,
      ownerPrincipal: String(transaction.ownerPrincipal),
      expectedSequence: 0,
      idempotencyKey: `scg-${sha256(generationId).slice(0, 48)}`,
      requestDigest: sha256(canonicalize(record)),
      operation: 'babyx.release.credential-bootstrap.ensure',
      phase: 'generation-persistence',
      record,
      occurredAt: now,
    });
    this.inject('after_generation_persist', { generationId, verificationDigest });
    return persisted;
  }

  issue(inputValue: IssueServiceCredentialInput): JsonObject {
    const input = structuredClone(inputValue);
    const transactionId = identifier(input.transactionId, 'transactionId');
    const ownerPrincipal = identifier(input.ownerPrincipal, 'ownerPrincipal');
    const ordinal = input.ordinal === undefined ? 1 : safeInteger(input.ordinal, 'ordinal');
    let transaction = this.options.bootstrap.get(transactionId);
    if (transaction.ownerPrincipal !== ownerPrincipal) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_identity_mismatch', 'owner principal does not match bootstrap transaction');
    const idempotencyKey = identifier(input.idempotencyKey, 'idempotencyKey');
    if (transaction.idempotencyKey !== idempotencyKey) throw new ServiceCredentialIssuanceError('release_idempotency_conflict', 'bootstrap retry idempotency identity does not match durable transaction');
    const expectedSequence = safeInteger(input.expectedSequence, 'expectedSequence');
    if (expectedSequence > Number(transaction.sequence)) throw new ReleaseStoreError('release_stale_sequence', 'expected sequence is ahead of durable bootstrap transaction');
    if (transaction.state === 'READY') return this.publicResult(transaction, this.options.store.getRecord(GENERATION_SCHEMA, String(transaction.generationId)), true);
    const identityBinding = validateServiceIdentityObservation(input.identityObservation);
    if (transaction.state === 'RECOVERY_REQUIRED') transaction = this.options.bootstrap.transition({ transactionId, ownerPrincipal, expectedSequence: Number(transaction.sequence), nextState: 'GENERATING', operation: 'babyx.release.credential-bootstrap.reconcile', phase: 'issuance-recovery' });
    if (transaction.state === 'REQUESTED') transaction = this.options.bootstrap.transition({ transactionId, ownerPrincipal, expectedSequence: Number(transaction.sequence), nextState: 'PLANNING', operation: 'babyx.release.credential-bootstrap.ensure', phase: 'planning' });
    if (transaction.state === 'PLANNING') transaction = this.options.bootstrap.transition({ transactionId, ownerPrincipal, expectedSequence: Number(transaction.sequence), nextState: 'GENERATING', operation: 'babyx.release.credential-bootstrap.ensure', phase: 'generation-intent', patch: { serviceIdentityBinding: identityBinding } });
    if (!['GENERATING','PERSISTING_REFERENCES','BINDING_IDENTITY','MATERIALIZING_PUBLIC_STATE','VERIFYING'].includes(String(transaction.state))) throw new ServiceCredentialIssuanceError('release_credential_bootstrap_invalid_state', `issuance cannot resume from ${String(transaction.state)}`);
    const material = this.issueMaterial(String(transaction.generationId), ownerPrincipal, ordinal);
    if (transaction.state === 'GENERATING') transaction = this.options.bootstrap.transition({
      transactionId, ownerPrincipal, expectedSequence: Number(transaction.sequence), nextState: 'PERSISTING_REFERENCES',
      operation: 'babyx.release.credential-bootstrap.ensure', phase: 'reference-persistence',
      patch: {
        credentialReferenceIds: [material.gatewayReferenceId, material.proofReferenceId],
        publicMaterialReferences: material.publicMaterials,
        cleanup: { ...transaction.cleanup as JsonObject, ...material.temporaryCleanup, productionPathsTouched: false },
      },
    });
    if (transaction.state === 'PERSISTING_REFERENCES') transaction = this.options.bootstrap.transition({ transactionId, ownerPrincipal, expectedSequence: Number(transaction.sequence), nextState: 'BINDING_IDENTITY', operation: 'babyx.release.credential-bootstrap.ensure', phase: 'identity-binding', patch: { serviceIdentityBinding: identityBinding } });
    if (transaction.state === 'BINDING_IDENTITY') transaction = this.options.bootstrap.transition({ transactionId, ownerPrincipal, expectedSequence: Number(transaction.sequence), nextState: 'MATERIALIZING_PUBLIC_STATE', operation: 'babyx.release.credential-bootstrap.ensure', phase: 'public-material-readback', patch: { publicMaterialReferences: material.publicMaterials } });
    if (transaction.state === 'MATERIALIZING_PUBLIC_STATE') transaction = this.options.bootstrap.transition({
      transactionId, ownerPrincipal, expectedSequence: Number(transaction.sequence), nextState: 'VERIFYING',
      operation: 'babyx.release.credential-bootstrap.ensure', phase: 'cryptographic-verification',
      patch: { verification: { ...material.verification, publicFingerprints: material.publicFingerprints, referenceDigest: material.referenceDigest, bindingDigest: material.bindingDigest } },
    });
    const generation = this.persistGeneration(transaction, identityBinding, material, ordinal);
    const facts = {
      privateReferencesDurable: true,
      publicMaterialDurable: true,
      keyRelationshipVerified: true,
      serviceIdentityVerified: true,
      expectedUidVerified: true,
      ownershipVerified: true,
      modesVerified: true,
      temporaryMaterialAbsent: true,
      forbiddenAuthorityUntouched: true,
    };
    transaction = this.options.bootstrap.transition({
      transactionId, ownerPrincipal, expectedSequence: Number(transaction.sequence), nextState: 'READY',
      operation: 'babyx.release.credential-bootstrap.ensure', phase: 'ready',
      patch: { evidenceReferences: [{ kind: 'GENERATION', generationId: generation.generationId, verificationDigest: generation.verificationDigest }] },
      readyFacts: facts,
    });
    return this.publicResult(transaction, generation, false);
  }

  async issueWithAuthoritativeAccountLookup(
    input: Omit<IssueServiceCredentialInput, 'identityObservation'>,
    lookup: ServiceAccountLookupRunner,
  ): Promise<JsonObject> {
    if (lookup.authority !== 'durable-job-authority') throw new ServiceCredentialIssuanceError('release_credential_bootstrap_invalid_request', 'service identity lookup must use the durable Job Authority');
    const identityObservation = await lookup.lookup(BABY_X_PRODUCTION_GATEWAY_ACCOUNT, BABY_X_PRODUCTION_GATEWAY_UID);
    return this.issue({ ...input, identityObservation });
  }

  private publicResult(transaction: JsonObject, generation: JsonObject, replayed: boolean): JsonObject {
    return {
      transaction: {
        transactionId: transaction.transactionId,
        state: transaction.state,
        sequence: transaction.sequence,
        generationId: transaction.generationId,
        profileId: transaction.profileId,
        compatibilityDigest: transaction.compatibilityDigest,
      },
      generation: {
        generationId: generation.generationId,
        state: generation.state,
        ordinal: generation.ordinal,
        publicFingerprints: generation.publicFingerprints,
        verificationDigest: generation.verificationDigest,
        serviceIdentityBinding: generation.serviceIdentityBinding,
      },
      replayed,
      rawPrivateMaterialReturned: false,
    };
  }
}
