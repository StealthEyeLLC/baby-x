import {
  X509Certificate,
  createPublicKey,
  timingSafeEqual,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import { canonicalize, sha256, verifyCanonical, type JsonObject } from '../../core.ts';
import { RootTrustError } from './errors.ts';
import {
  DSSE_PAYLOAD_TYPE,
  IN_TOTO_STATEMENT_TYPE,
  SLSA_PROVENANCE_TYPE,
  type ConsistencyProof,
  type DigestDescriptor,
  type DsseEnvelope,
  type ProvenanceExpectation,
  type SigstoreBundle,
  type SignatureTrustPolicy,
  type TransparencyCheckpoint,
  type InclusionProof,
} from './schemas.ts';

function fail(code: string, message: string, details: JsonObject = {}): never {
  throw new RootTrustError(code, message, details);
}

function sameBytes(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

function publicKeyDigest(key: KeyObject): string {
  return sha256(key.export({ format: 'der', type: 'spki' }) as Buffer);
}

function certificateDigest(certificate: X509Certificate): string {
  return sha256(certificate.raw);
}

function manifestDigestBytes(manifestDigest: string): Buffer {
  const match = /^sha256:([a-f0-9]{64})$/u.exec(manifestDigest);
  if (match === null) fail('root_bundle_digest_invalid', 'bundle manifest digest is invalid');
  return Buffer.from(match[1] as string, 'hex');
}

function verifySignature(key: KeyObject, data: Buffer, signatureBase64: string): boolean {
  try { return cryptoVerify(null, data, key, Buffer.from(signatureBase64, 'base64')); }
  catch { return false; }
}

function certificateMatchesSubject(certificate: X509Certificate, expected: string): boolean {
  if (certificate.subject === expected) return true;
  const alternatives = certificate.subjectAltName ?? '';
  return alternatives.split(/,\s*/u).some((entry) => entry === expected || entry === `URI:${expected}` || entry === `email:${expected}` || entry === `DNS:${expected}`);
}

function certificateMatchesIssuer(certificate: X509Certificate, expected: string): boolean {
  return certificate.issuer === expected || certificate.issuer.includes(expected);
}

function verifyCertificateChain(leaf: X509Certificate, issuer: X509Certificate, roots: readonly string[], nowMs: number): void {
  if (!leaf.verify(issuer.publicKey)) fail('root_bundle_certificate_chain_invalid', 'leaf certificate is not signed by the supplied issuer');
  const trusted = roots.some((pem) => {
    try {
      const root = new X509Certificate(pem);
      return sameBytes(root.raw, issuer.raw) || (issuer.verify(root.publicKey) && issuer.issuer === root.subject);
    } catch { return false; }
  });
  if (!trusted) fail('root_bundle_certificate_untrusted', 'certificate chain does not terminate at a configured local trust root');
  for (const [label, certificate] of [['leaf', leaf], ['issuer', issuer]] as const) {
    if (nowMs < Date.parse(certificate.validFrom) || nowMs > Date.parse(certificate.validTo)) {
      fail('root_bundle_certificate_expired', `${label} certificate is outside its validity interval`);
    }
  }
}

export interface SignatureVerificationResult extends JsonObject {
  verified: true;
  verificationKind: 'KEYED' | 'KEYLESS';
  signerDigest: string;
  signatureBundleDigest: string;
  transparencyEntryDigests: string[];
}

export function verifySigstoreBundle(
  manifestDigest: string,
  bundle: SigstoreBundle,
  policy: SignatureTrustPolicy,
  nowMs = Date.now(),
): SignatureVerificationResult {
  const digestBytes = manifestDigestBytes(manifestDigest);
  const declaredDigest = Buffer.from(bundle.messageSignature.messageDigest.digest, 'base64');
  if (!sameBytes(digestBytes, declaredDigest)) fail('root_bundle_signature_digest_mismatch', 'signature bundle message digest does not match the OCI manifest digest');

  let key: KeyObject;
  let signerDigest: string;
  if (bundle.verificationMaterial.kind === 'KEYED') {
    if (policy.trustedPublicKeys.length === 0) fail('root_bundle_signature_untrusted', 'keyed verification requires at least one configured public key');
    const candidates = policy.trustedPublicKeys.map((pem) => createPublicKey(pem));
    const selected = bundle.verificationMaterial.publicKeyHint === null
      ? candidates.find((candidate) => verifySignature(candidate, digestBytes, bundle.messageSignature.signature))
      : candidates.find((candidate) => publicKeyDigest(candidate) === bundle.verificationMaterial.publicKeyHint);
    if (selected === undefined) fail('root_bundle_signature_untrusted', 'no configured public key matches the signature bundle');
    key = selected;
    signerDigest = publicKeyDigest(key);
  } else {
    const leafPem = bundle.verificationMaterial.certificatePem;
    const issuerPem = bundle.verificationMaterial.issuerCertificatePem;
    if (leafPem === null || issuerPem === null) fail('root_bundle_certificate_chain_invalid', 'keyless verification requires leaf and issuer certificates');
    const leaf = new X509Certificate(leafPem);
    const issuer = new X509Certificate(issuerPem);
    verifyCertificateChain(leaf, issuer, policy.trustedRootCertificates, nowMs);
    if (policy.expectedIssuer !== null && !certificateMatchesIssuer(leaf, policy.expectedIssuer)) fail('root_bundle_certificate_identity_mismatch', 'certificate issuer does not match policy');
    if (policy.expectedSubject !== null && !certificateMatchesSubject(leaf, policy.expectedSubject)) fail('root_bundle_certificate_identity_mismatch', 'certificate subject does not match policy');
    key = leaf.publicKey;
    signerDigest = certificateDigest(leaf);
  }

  if (policy.revokedSignerDigests.includes(signerDigest)) fail('root_bundle_signer_revoked', 'the resolved signer is revoked', { signerDigest });
  if (!verifySignature(key, digestBytes, bundle.messageSignature.signature)) fail('root_bundle_signature_invalid', 'signature verification failed');
  if (policy.requireTransparency && bundle.verificationMaterial.tlogEntries.length === 0) fail('root_bundle_transparency_required', 'policy requires offline transparency evidence');

  return {
    verified: true,
    verificationKind: bundle.verificationMaterial.kind,
    signerDigest,
    signatureBundleDigest: sha256(canonicalize(bundle)),
    transparencyEntryDigests: bundle.verificationMaterial.tlogEntries.map((entry) => entry.entryDigest).sort(),
  };
}

export function dssePae(payloadType: string, payload: Buffer): Buffer {
  const type = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, 'utf8'),
    type,
    Buffer.from(` ${payload.length} `, 'utf8'),
    payload,
  ]);
}

function normalizeDescriptors(value: unknown, field: string): DigestDescriptor[] {
  if (!Array.isArray(value)) fail('root_provenance_invalid', `${field} must be an array`);
  return value.map((entry, index) => {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) fail('root_provenance_invalid', `${field}[${index}] must be an object`);
    const item = entry as Record<string, unknown>;
    const name = String(item.name ?? item.uri ?? '');
    const digestValue = item.digest;
    let digest = '';
    if (typeof digestValue === 'string') digest = digestValue;
    else if (digestValue !== null && typeof digestValue === 'object' && !Array.isArray(digestValue)) digest = String((digestValue as Record<string, unknown>).sha256 ?? '');
    if (!name || !/^[a-f0-9]{64}$/u.test(digest)) fail('root_provenance_invalid', `${field}[${index}] has an invalid name or digest`);
    return { name, digest };
  }).sort((left, right) => `${left.name}:${left.digest}`.localeCompare(`${right.name}:${right.digest}`));
}

function equalDescriptors(actual: readonly DigestDescriptor[], expected: readonly DigestDescriptor[]): boolean {
  return canonicalize(actual) === canonicalize(expected);
}

export interface ProvenanceVerificationResult extends JsonObject {
  verified: true;
  envelopeDigest: string;
  statementDigest: string;
  signerDigest: string;
  predicateType: typeof SLSA_PROVENANCE_TYPE;
}

export function verifySlsaProvenance(
  envelope: DsseEnvelope,
  verificationKeyPem: string,
  expected: ProvenanceExpectation,
): ProvenanceVerificationResult {
  if (envelope.payloadType !== DSSE_PAYLOAD_TYPE) fail('root_provenance_payload_type_invalid', 'DSSE payload type is unsupported');
  const payload = Buffer.from(envelope.payload, 'base64');
  const key = createPublicKey(verificationKeyPem);
  const signerDigest = publicKeyDigest(key);
  const matching = envelope.signatures.some((signature) => signature.keyid === signerDigest && verifySignature(key, dssePae(envelope.payloadType, payload), signature.sig));
  if (!matching) fail('root_provenance_signature_invalid', 'DSSE signature verification failed');

  let statement: Record<string, unknown>;
  try {
    const parsed = JSON.parse(payload.toString('utf8')) as unknown;
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not object');
    statement = parsed as Record<string, unknown>;
  } catch { fail('root_provenance_invalid', 'DSSE payload is not a valid in-toto statement'); }
  if (statement._type !== IN_TOTO_STATEMENT_TYPE) fail('root_provenance_statement_type_invalid', 'in-toto statement type is unsupported');
  if (statement.predicateType !== SLSA_PROVENANCE_TYPE) fail('root_provenance_predicate_type_invalid', 'SLSA predicate type is unsupported');
  const predicate = statement.predicate as Record<string, unknown> | undefined;
  const buildDefinition = predicate?.buildDefinition as Record<string, unknown> | undefined;
  const runDetails = predicate?.runDetails as Record<string, unknown> | undefined;
  const builder = runDetails?.builder as Record<string, unknown> | undefined;
  const external = buildDefinition?.externalParameters as Record<string, unknown> | undefined;
  const source = external?.source as Record<string, unknown> | undefined;
  const internal = buildDefinition?.internalParameters as Record<string, unknown> | undefined;

  if (String(source?.repository ?? '') !== expected.sourceRepository) fail('root_provenance_source_mismatch', 'source repository does not match expectation');
  if (String(source?.commit ?? '') !== expected.sourceCommit) fail('root_provenance_source_mismatch', 'source commit does not match expectation');
  if (String(source?.tree ?? '') !== expected.sourceTree) fail('root_provenance_source_mismatch', 'source tree does not match expectation');
  if (String(builder?.id ?? '') !== expected.builderId) fail('root_provenance_builder_mismatch', 'builder identity does not match expectation');
  if (String(buildDefinition?.buildType ?? '') !== expected.workflowId) fail('root_provenance_workflow_mismatch', 'workflow identity does not match expectation');

  const materials = normalizeDescriptors(buildDefinition?.resolvedDependencies ?? [], 'predicate.buildDefinition.resolvedDependencies');
  const dependencies = normalizeDescriptors(internal?.dependencies ?? [], 'predicate.buildDefinition.internalParameters.dependencies');
  const products = normalizeDescriptors(statement.subject ?? [], 'statement.subject');
  if (!equalDescriptors(materials, expected.materials)) fail('root_provenance_material_mismatch', 'provenance materials do not match expectation');
  if (!equalDescriptors(dependencies, expected.dependencies)) fail('root_provenance_dependency_mismatch', 'provenance dependencies do not match expectation');
  if (!equalDescriptors(products, expected.products)) fail('root_provenance_product_mismatch', 'provenance products do not match expectation');

  return {
    verified: true,
    envelopeDigest: sha256(canonicalize(envelope)),
    statementDigest: sha256(payload),
    signerDigest,
    predicateType: SLSA_PROVENANCE_TYPE,
  };
}

function hashLeaf(entryDigest: string): Buffer {
  return Buffer.from(sha256(Buffer.concat([Buffer.from([0]), Buffer.from(entryDigest, 'hex')])), 'hex');
}
function hashNode(left: Buffer, right: Buffer): Buffer {
  return Buffer.from(sha256(Buffer.concat([Buffer.from([1]), left, right])), 'hex');
}

export function transparencyLeafHash(entryDigest: string): string { return hashLeaf(entryDigest).toString('hex'); }
export function transparencyNodeHash(left: string, right: string): string { return hashNode(Buffer.from(left, 'hex'), Buffer.from(right, 'hex')).toString('hex'); }

export function verifyInclusionProof(entryDigest: string, proof: InclusionProof, expectedRootHash: string): boolean {
  let computed = hashLeaf(entryDigest);
  let index = proof.leafIndex;
  let last = proof.treeSize - 1;
  for (const hash of proof.hashes) {
    const sibling = Buffer.from(hash, 'hex');
    if ((index & 1) === 1 || index === last) computed = hashNode(sibling, computed);
    else computed = hashNode(computed, sibling);
    index >>= 1;
    last >>= 1;
  }
  return index === 0 && sameBytes(computed, Buffer.from(expectedRootHash, 'hex'));
}

export function verifyConsistencyProof(
  oldSize: number,
  newSize: number,
  oldRootHash: string,
  newRootHash: string,
  proof: ConsistencyProof,
): boolean {
  if (proof.firstSize !== oldSize || proof.secondSize !== newSize || oldSize > newSize || oldSize < 1) return false;
  if (oldSize === newSize) return proof.hashes.length === 0 && oldRootHash === newRootHash;
  let first = oldSize - 1;
  let second = newSize - 1;
  while ((first & 1) === 1) { first >>= 1; second >>= 1; }
  let index = 0;
  let firstHash: Buffer;
  let secondHash: Buffer;
  if (first === 0) {
    firstHash = Buffer.from(oldRootHash, 'hex');
    secondHash = Buffer.from(oldRootHash, 'hex');
  } else {
    if (proof.hashes.length === 0) return false;
    firstHash = Buffer.from(proof.hashes[index] as string, 'hex');
    secondHash = Buffer.from(proof.hashes[index] as string, 'hex');
    index += 1;
  }
  for (; index < proof.hashes.length; index += 1) {
    if (second === 0) return false;
    const node = Buffer.from(proof.hashes[index] as string, 'hex');
    if ((first & 1) === 1 || first === second) {
      firstHash = hashNode(node, firstHash);
      secondHash = hashNode(node, secondHash);
      while (first !== 0 && (first & 1) === 0) { first >>= 1; second >>= 1; }
    } else {
      secondHash = hashNode(secondHash, node);
    }
    first >>= 1;
    second >>= 1;
  }
  return second === 0
    && sameBytes(firstHash, Buffer.from(oldRootHash, 'hex'))
    && sameBytes(secondHash, Buffer.from(newRootHash, 'hex'));
}

export function verifySignedCheckpoint(checkpoint: TransparencyCheckpoint, publicKeyPem: string): boolean {
  const { signature, ...unsigned } = checkpoint;
  return verifyCanonical(publicKeyPem, unsigned, signature);
}
