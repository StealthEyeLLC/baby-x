import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import { RootTrustError } from './errors.ts';

export const ROOT_TRUST_SCHEMA_VERSION = '1.0.0' as const;
export const ROOT_TRUST_PROVIDER_VERSION = 'oci-trust-provenance-transparency@1' as const;
export const OCI_MANIFEST_MEDIA_TYPE = 'application/vnd.oci.image.manifest.v1+json' as const;
export const OCI_INDEX_MEDIA_TYPE = 'application/vnd.oci.image.index.v1+json' as const;
export const SKILL_CONFIG_MEDIA_TYPE = 'application/vnd.stealtheye.babyx.skill.config.v1+json' as const;
export const SKILL_LAYER_MEDIA_TYPES = [
  'application/vnd.stealtheye.babyx.skill.layer.v1.tar+gzip',
  'application/vnd.oci.image.layer.v1.tar+gzip',
] as const;
export const SIGSTORE_BUNDLE_MEDIA_TYPE = 'application/vnd.dev.sigstore.bundle+json;version=0.3' as const;
export const IN_TOTO_STATEMENT_TYPE = 'https://in-toto.io/Statement/v1' as const;
export const SLSA_PROVENANCE_TYPE = 'https://slsa.dev/provenance/v1' as const;
export const DSSE_PAYLOAD_TYPE = 'application/vnd.in-toto+json' as const;

export interface BundleResolveRequest extends JsonObject {
  reference: string;
  expectedManifestDigest: string | null;
  discoveryOnly: boolean;
}
export interface BundleGetRequest extends JsonObject { bundleId: string; }
export interface BundleCacheRequest extends JsonObject { bundleId: string; }
export interface SigstoreMessageDigest extends JsonObject { algorithm: 'SHA2_256'; digest: string; }
export interface SigstoreMessageSignature extends JsonObject { messageDigest: SigstoreMessageDigest; signature: string; }
export interface SigstoreTlogEntry extends JsonObject {
  logId: string;
  entryDigest: string;
  checkpointDigest: string;
  integratedTime: string;
}
export interface SigstoreBundle extends JsonObject {
  mediaType: typeof SIGSTORE_BUNDLE_MEDIA_TYPE;
  verificationMaterial: {
    kind: 'KEYED' | 'KEYLESS';
    publicKeyHint: string | null;
    certificatePem: string | null;
    issuerCertificatePem: string | null;
    tlogEntries: SigstoreTlogEntry[];
  } & JsonObject;
  messageSignature: SigstoreMessageSignature;
}
export interface SignatureTrustPolicy extends JsonObject {
  trustedPublicKeys: string[];
  trustedRootCertificates: string[];
  expectedIssuer: string | null;
  expectedSubject: string | null;
  revokedSignerDigests: string[];
  requireTransparency: boolean;
}
export interface BundleVerifyRequest extends JsonObject {
  bundleId: string;
  signatureBundle: SigstoreBundle;
  trustPolicy: SignatureTrustPolicy;
}
export interface DigestDescriptor extends JsonObject { name: string; digest: string; }
export interface DsseSignature extends JsonObject { keyid: string; sig: string; }
export interface DsseEnvelope extends JsonObject {
  payloadType: typeof DSSE_PAYLOAD_TYPE;
  payload: string;
  signatures: DsseSignature[];
}
export interface ProvenanceExpectation extends JsonObject {
  sourceRepository: string;
  sourceCommit: string;
  sourceTree: string;
  builderId: string;
  workflowId: string;
  materials: DigestDescriptor[];
  dependencies: DigestDescriptor[];
  products: DigestDescriptor[];
}
export interface ProvenanceVerifyRequest extends JsonObject {
  bundleId: string;
  envelope: DsseEnvelope;
  verificationKeyPem: string;
  expected: ProvenanceExpectation;
}
export interface TransparencyCheckpoint extends JsonObject {
  logId: string;
  treeSize: number;
  rootHash: string;
  issuedAt: string;
  signerKeyId: string;
  signature: string;
}
export interface InclusionProof extends JsonObject { leafIndex: number; treeSize: number; hashes: string[]; }
export interface ConsistencyProof extends JsonObject { firstSize: number; secondSize: number; hashes: string[]; }
export interface TransparencyVerifyRequest extends JsonObject {
  logId: string;
  entryDigest: string;
  checkpoint: TransparencyCheckpoint;
  checkpointPublicKeyPem: string;
  inclusionProof: InclusionProof;
  consistencyProof: ConsistencyProof | null;
  maximumCheckpointAgeSeconds: number;
}
export interface TransparencyStatusRequest extends JsonObject { logId: string; }

const SHA256 = /^[a-f0-9]{64}$/u;
const OCI_DIGEST = /^sha256:([a-f0-9]{64})$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,511}$/u;
const BUNDLE_ID = /^bnd_[a-f0-9]{32}$/u;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const PEM_PUBLIC = /^-----BEGIN (?:PUBLIC KEY|CERTIFICATE)-----[\s\S]+-----END (?:PUBLIC KEY|CERTIFICATE)-----\s*$/u;

function invalid(message: string, details: JsonObject = {}): never { throw new RootTrustError('root_trust_invalid_request', message, details); }
function object(value: unknown, field: string): JsonObject { if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid(`${field} must be an object`); return value as JsonObject; }
function allowed(value: JsonObject, field: string, keys: readonly string[]): void { const set = new Set(keys); const unknown = Object.keys(value).filter((key) => !set.has(key)); if (unknown.length > 0) invalid(`${field} contains unsupported properties`, { properties: unknown }); }
function text(value: unknown, field: string, maximum = 8_192): string { if (typeof value !== 'string' || value.length < 1 || value.length > maximum || value.includes('\0')) invalid(`${field} must be a bounded non-empty NUL-free string`); return value; }
function id(value: unknown, field: string, expression = IDENTIFIER): string { const result = text(value, field, 512); if (!expression.test(result)) invalid(`${field} is invalid`); return result; }
function digest(value: unknown, field: string): string { const result = text(value, field, 64); if (!SHA256.test(result)) invalid(`${field} must be a lowercase SHA-256 digest`); return result; }
function ociDigest(value: unknown, field: string): string { const result = text(value, field, 71); if (!OCI_DIGEST.test(result)) invalid(`${field} must be sha256:<lowercase digest>`); return result; }
function integer(value: unknown, field: string, minimum: number, maximum: number): number { const result = Number(value); if (!Number.isSafeInteger(result) || result < minimum || result > maximum) invalid(`${field} must be an integer between ${minimum} and ${maximum}`); return result; }
function timestamp(value: unknown, field: string): string { const result = text(value, field, 64); const parsed = Date.parse(result); if (!Number.isFinite(parsed)) invalid(`${field} must be an ISO-8601 timestamp`); return new Date(parsed).toISOString(); }
function boolean(value: unknown, field: string): boolean { if (typeof value !== 'boolean') invalid(`${field} must be boolean`); return value; }
function base64(value: unknown, field: string, maximum = 8 * 1024 * 1024): string { const result = text(value, field, maximum); if (!BASE64.test(result)) invalid(`${field} must be canonical base64`); return result; }
function pem(value: unknown, field: string): string { const result = text(value, field, 64 * 1024); if (!PEM_PUBLIC.test(result)) invalid(`${field} must be one public key or certificate PEM`); return result; }
function nullablePem(value: unknown, field: string): string | null { return value === null ? null : pem(value, field); }
function nullableText(value: unknown, field: string, maximum = 512): string | null { return value === null ? null : text(value, field, maximum); }
function stringArray(value: unknown, field: string, maximumItems: number, parser: (entry: unknown, field: string) => string): string[] {
  if (!Array.isArray(value) || value.length > maximumItems) invalid(`${field} must be a bounded array`);
  const entries = value.map((entry, index) => parser(entry, `${field}[${index}]`));
  if (new Set(entries).size !== entries.length) invalid(`${field} contains duplicates`);
  return entries.sort();
}
function descriptors(value: unknown, field: string): DigestDescriptor[] {
  if (!Array.isArray(value) || value.length > 256) invalid(`${field} must be a bounded array`);
  const result = value.map((entry, index) => {
    const item = object(entry, `${field}[${index}]`); allowed(item, `${field}[${index}]`, ['name', 'digest']);
    return { name: text(item.name, `${field}[${index}].name`, 1_024), digest: digest(item.digest, `${field}[${index}].digest`) };
  }).sort((left, right) => `${left.name}:${left.digest}`.localeCompare(`${right.name}:${right.digest}`));
  if (new Set(result.map((entry) => `${entry.name}:${entry.digest}`)).size !== result.length) invalid(`${field} contains duplicates`);
  return result;
}

export function normalizeBundleResolve(value: unknown): BundleResolveRequest {
  const payload = object(value, 'bundle resolve payload'); allowed(payload, 'bundle resolve payload', ['reference', 'expectedManifestDigest', 'discoveryOnly']);
  const reference = text(payload.reference, 'reference', 4_096);
  const discoveryOnly = payload.discoveryOnly === undefined ? false : boolean(payload.discoveryOnly, 'discoveryOnly');
  const exact = reference.match(/@sha256:([a-f0-9]{64})$/u);
  const expectedManifestDigest = payload.expectedManifestDigest === undefined || payload.expectedManifestDigest === null ? null : ociDigest(payload.expectedManifestDigest, 'expectedManifestDigest');
  if (exact === null && !discoveryOnly) invalid('mutable OCI tags may be used only for discovery');
  if (exact !== null && expectedManifestDigest !== null && expectedManifestDigest !== `sha256:${exact[1]}`) invalid('expectedManifestDigest conflicts with the digest-pinned reference');
  if (!reference.startsWith('oci-layout:') && !reference.startsWith('docker://')) invalid('reference must use oci-layout: or docker://');
  return { reference, expectedManifestDigest: expectedManifestDigest ?? (exact === null ? null : `sha256:${exact[1]}`), discoveryOnly };
}
export function normalizeBundleGet(value: unknown): BundleGetRequest { const payload = object(value, 'bundle get payload'); allowed(payload, 'bundle get payload', ['bundleId']); return { bundleId: id(payload.bundleId, 'bundleId', BUNDLE_ID) }; }
export const normalizeBundleCache = normalizeBundleGet;

function normalizeTlogEntries(value: unknown): SigstoreTlogEntry[] {
  if (!Array.isArray(value) || value.length > 16) invalid('verificationMaterial.tlogEntries must be bounded');
  return value.map((entry, index) => {
    const item = object(entry, `verificationMaterial.tlogEntries[${index}]`); allowed(item, `verificationMaterial.tlogEntries[${index}]`, ['logId','entryDigest','checkpointDigest','integratedTime']);
    return { logId: id(item.logId, `verificationMaterial.tlogEntries[${index}].logId`), entryDigest: digest(item.entryDigest, `verificationMaterial.tlogEntries[${index}].entryDigest`), checkpointDigest: digest(item.checkpointDigest, `verificationMaterial.tlogEntries[${index}].checkpointDigest`), integratedTime: timestamp(item.integratedTime, `verificationMaterial.tlogEntries[${index}].integratedTime`) };
  });
}
export function normalizeBundleVerify(value: unknown): BundleVerifyRequest {
  const payload = object(value, 'bundle verify payload'); allowed(payload, 'bundle verify payload', ['bundleId','signatureBundle','trustPolicy']);
  const bundle = object(payload.signatureBundle, 'signatureBundle'); allowed(bundle, 'signatureBundle', ['mediaType','verificationMaterial','messageSignature']);
  if (bundle.mediaType !== SIGSTORE_BUNDLE_MEDIA_TYPE) invalid('signatureBundle.mediaType is unsupported');
  const material = object(bundle.verificationMaterial, 'verificationMaterial'); allowed(material, 'verificationMaterial', ['kind','publicKeyHint','certificatePem','issuerCertificatePem','tlogEntries']);
  if (material.kind !== 'KEYED' && material.kind !== 'KEYLESS') invalid('verificationMaterial.kind is unsupported');
  const message = object(bundle.messageSignature, 'messageSignature'); allowed(message, 'messageSignature', ['messageDigest','signature']);
  const messageDigest = object(message.messageDigest, 'messageSignature.messageDigest'); allowed(messageDigest, 'messageSignature.messageDigest', ['algorithm','digest']);
  if (messageDigest.algorithm !== 'SHA2_256') invalid('message digest algorithm must be SHA2_256');
  const normalizedBundle: SigstoreBundle = {
    mediaType: SIGSTORE_BUNDLE_MEDIA_TYPE,
    verificationMaterial: {
      kind: material.kind,
      publicKeyHint: material.publicKeyHint === null ? null : digest(material.publicKeyHint, 'verificationMaterial.publicKeyHint'),
      certificatePem: nullablePem(material.certificatePem, 'verificationMaterial.certificatePem'),
      issuerCertificatePem: nullablePem(material.issuerCertificatePem, 'verificationMaterial.issuerCertificatePem'),
      tlogEntries: normalizeTlogEntries(material.tlogEntries ?? []),
    },
    messageSignature: { messageDigest: { algorithm: 'SHA2_256', digest: base64(messageDigest.digest, 'messageSignature.messageDigest.digest', 128) }, signature: base64(message.signature, 'messageSignature.signature', 16_384) },
  };
  if (normalizedBundle.verificationMaterial.kind === 'KEYED' && (normalizedBundle.verificationMaterial.certificatePem !== null || normalizedBundle.verificationMaterial.issuerCertificatePem !== null)) invalid('KEYED verification must not include certificates');
  if (normalizedBundle.verificationMaterial.kind === 'KEYLESS' && (normalizedBundle.verificationMaterial.certificatePem === null || normalizedBundle.verificationMaterial.issuerCertificatePem === null)) invalid('KEYLESS verification requires leaf and issuer certificates');
  const policy = object(payload.trustPolicy, 'trustPolicy'); allowed(policy, 'trustPolicy', ['trustedPublicKeys','trustedRootCertificates','expectedIssuer','expectedSubject','revokedSignerDigests','requireTransparency']);
  const trustPolicy: SignatureTrustPolicy = {
    trustedPublicKeys: stringArray(policy.trustedPublicKeys ?? [], 'trustPolicy.trustedPublicKeys', 32, pem),
    trustedRootCertificates: stringArray(policy.trustedRootCertificates ?? [], 'trustPolicy.trustedRootCertificates', 32, pem),
    expectedIssuer: nullableText(policy.expectedIssuer, 'trustPolicy.expectedIssuer', 1_024),
    expectedSubject: nullableText(policy.expectedSubject, 'trustPolicy.expectedSubject', 1_024),
    revokedSignerDigests: stringArray(policy.revokedSignerDigests ?? [], 'trustPolicy.revokedSignerDigests', 256, digest),
    requireTransparency: boolean(policy.requireTransparency ?? false, 'trustPolicy.requireTransparency'),
  };
  return { bundleId: id(payload.bundleId, 'bundleId', BUNDLE_ID), signatureBundle: normalizedBundle, trustPolicy };
}

export function normalizeProvenanceVerify(value: unknown): ProvenanceVerifyRequest {
  const payload = object(value, 'provenance verify payload'); allowed(payload, 'provenance verify payload', ['bundleId','envelope','verificationKeyPem','expected']);
  const envelope = object(payload.envelope, 'envelope'); allowed(envelope, 'envelope', ['payloadType','payload','signatures']);
  if (envelope.payloadType !== DSSE_PAYLOAD_TYPE) invalid('envelope.payloadType is unsupported');
  if (!Array.isArray(envelope.signatures) || envelope.signatures.length < 1 || envelope.signatures.length > 16) invalid('envelope.signatures must be a bounded non-empty array');
  const signatures = envelope.signatures.map((entry, index) => { const item = object(entry, `envelope.signatures[${index}]`); allowed(item, `envelope.signatures[${index}]`, ['keyid','sig']); return { keyid: digest(item.keyid, `envelope.signatures[${index}].keyid`), sig: base64(item.sig, `envelope.signatures[${index}].sig`, 16_384) }; });
  const expectedValue = object(payload.expected, 'expected'); allowed(expectedValue, 'expected', ['sourceRepository','sourceCommit','sourceTree','builderId','workflowId','materials','dependencies','products']);
  const expected: ProvenanceExpectation = {
    sourceRepository: text(expectedValue.sourceRepository, 'expected.sourceRepository', 2_048),
    sourceCommit: id(expectedValue.sourceCommit, 'expected.sourceCommit', /^[a-f0-9]{40}$/u),
    sourceTree: id(expectedValue.sourceTree, 'expected.sourceTree', /^[a-f0-9]{40}$/u),
    builderId: text(expectedValue.builderId, 'expected.builderId', 2_048),
    workflowId: text(expectedValue.workflowId, 'expected.workflowId', 2_048),
    materials: descriptors(expectedValue.materials, 'expected.materials'),
    dependencies: descriptors(expectedValue.dependencies, 'expected.dependencies'),
    products: descriptors(expectedValue.products, 'expected.products'),
  };
  return { bundleId: id(payload.bundleId, 'bundleId', BUNDLE_ID), envelope: { payloadType: DSSE_PAYLOAD_TYPE, payload: base64(envelope.payload, 'envelope.payload', 8 * 1024 * 1024), signatures }, verificationKeyPem: pem(payload.verificationKeyPem, 'verificationKeyPem'), expected };
}

export function normalizeTransparencyVerify(value: unknown): TransparencyVerifyRequest {
  const payload = object(value, 'transparency verify payload'); allowed(payload, 'transparency verify payload', ['logId','entryDigest','checkpoint','checkpointPublicKeyPem','inclusionProof','consistencyProof','maximumCheckpointAgeSeconds']);
  const logId = id(payload.logId, 'logId');
  const checkpointValue = object(payload.checkpoint, 'checkpoint'); allowed(checkpointValue, 'checkpoint', ['logId','treeSize','rootHash','issuedAt','signerKeyId','signature']);
  const checkpoint: TransparencyCheckpoint = { logId: id(checkpointValue.logId, 'checkpoint.logId'), treeSize: integer(checkpointValue.treeSize, 'checkpoint.treeSize', 1, Number.MAX_SAFE_INTEGER), rootHash: digest(checkpointValue.rootHash, 'checkpoint.rootHash'), issuedAt: timestamp(checkpointValue.issuedAt, 'checkpoint.issuedAt'), signerKeyId: digest(checkpointValue.signerKeyId, 'checkpoint.signerKeyId'), signature: base64(checkpointValue.signature, 'checkpoint.signature', 16_384) };
  if (checkpoint.logId !== logId) invalid('checkpoint.logId must match logId');
  const inclusionValue = object(payload.inclusionProof, 'inclusionProof'); allowed(inclusionValue, 'inclusionProof', ['leafIndex','treeSize','hashes']);
  const inclusionProof: InclusionProof = { leafIndex: integer(inclusionValue.leafIndex, 'inclusionProof.leafIndex', 0, Number.MAX_SAFE_INTEGER), treeSize: integer(inclusionValue.treeSize, 'inclusionProof.treeSize', 1, Number.MAX_SAFE_INTEGER), hashes: stringArray(inclusionValue.hashes ?? [], 'inclusionProof.hashes', 256, digest) };
  if (inclusionProof.treeSize !== checkpoint.treeSize || inclusionProof.leafIndex >= inclusionProof.treeSize) invalid('inclusion proof bounds do not match the checkpoint');
  let consistencyProof: ConsistencyProof | null = null;
  if (payload.consistencyProof !== null && payload.consistencyProof !== undefined) {
    const consistency = object(payload.consistencyProof, 'consistencyProof'); allowed(consistency, 'consistencyProof', ['firstSize','secondSize','hashes']);
    consistencyProof = { firstSize: integer(consistency.firstSize, 'consistencyProof.firstSize', 1, Number.MAX_SAFE_INTEGER), secondSize: integer(consistency.secondSize, 'consistencyProof.secondSize', 1, Number.MAX_SAFE_INTEGER), hashes: stringArray(consistency.hashes ?? [], 'consistencyProof.hashes', 256, digest) };
    if (consistencyProof.secondSize !== checkpoint.treeSize || consistencyProof.firstSize > consistencyProof.secondSize) invalid('consistency proof bounds do not match the checkpoint');
  }
  return { logId, entryDigest: digest(payload.entryDigest, 'entryDigest'), checkpoint, checkpointPublicKeyPem: pem(payload.checkpointPublicKeyPem, 'checkpointPublicKeyPem'), inclusionProof, consistencyProof, maximumCheckpointAgeSeconds: integer(payload.maximumCheckpointAgeSeconds ?? 86_400, 'maximumCheckpointAgeSeconds', 1, 31_536_000) };
}
export function normalizeTransparencyStatus(value: unknown): TransparencyStatusRequest { const payload = object(value, 'transparency status payload'); allowed(payload, 'transparency status payload', ['logId']); return { logId: id(payload.logId, 'logId') }; }

export function trustRequestDigest(operation: string, ownerPrincipal: string, payload: JsonObject): string { return sha256(canonicalize({ operation, ownerPrincipal, payload })); }
export function manifestHex(value: string): string { const match = OCI_DIGEST.exec(value); if (match === null) invalid('manifest digest is invalid'); return match[1] as string; }
