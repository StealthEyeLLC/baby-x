import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import { RootIdentityError } from './errors.ts';

export const ROOT_IDENTITY_SCHEMA_VERSION = '1.0.0' as const;
export const ROOT_IDENTITY_PROVIDER_VERSION = 'attested-workload-identity@1' as const;
export const ROOT_TRUST_DOMAIN = 'babyx.stealtheye.internal' as const;
export const ROOT_IDENTITY_PROVIDERS = ['hardware-tpm', 'software-tpm-fixture'] as const;
export const ROOT_SVID_ISSUERS = ['spire-workload-api', 'sovereign-x509-svid'] as const;
export const ROOT_SELECTOR_TYPES = ['systemd_unit', 'uid', 'gid', 'executable_path', 'executable_digest', 'cgroup', 'vm_id', 'transaction_id', 'skill_bundle_digest'] as const;
export type RootIdentityProviderId = typeof ROOT_IDENTITY_PROVIDERS[number];
export type RootSvidIssuerId = typeof ROOT_SVID_ISSUERS[number];
export type RootSelectorType = typeof ROOT_SELECTOR_TYPES[number];

export interface PcrValue extends JsonObject { index: number; algorithm: 'sha256'; value: string; }
export interface AttestationChallengeRequest extends JsonObject { providerId: RootIdentityProviderId; pcrSelection: number[]; ttlSeconds: number; }
export interface AttestationQuote extends JsonObject {
  providerId: RootIdentityProviderId;
  nonce: string;
  pcrs: PcrValue[];
  eventLogDigest: string | null;
  imaDigest: string | null;
  bootId: string;
  observedAt: string;
  attestationKeyId: string;
  signature: string;
}
export interface AttestationPolicy extends JsonObject {
  expectedPcrs: PcrValue[];
  maxAgeSeconds: number;
  requireMeasuredBoot: boolean;
  requireIma: boolean;
}
export interface AttestationVerifyRequest extends JsonObject { challengeId: string; quote: AttestationQuote; policy: AttestationPolicy; }
export interface AttestationGetRequest extends JsonObject { challengeId?: string; attestationId?: string; }
export interface WorkloadSelector extends JsonObject { type: RootSelectorType; value: string; }
export interface IdentityIssueRequest extends JsonObject {
  attestationId: string;
  transactionId: string;
  skillBundleDigest: string;
  grantDigest: string;
  issuerProviderId: RootSvidIssuerId;
  selectors: WorkloadSelector[];
  ttlSeconds: number;
}
export interface IdentityRevokeRequest extends JsonObject { identityId: string; expectedSequence: number; reasonDigest: string; }
export interface SecretLeaseTarget extends JsonObject { kind: 'SYSTEMD_UNIT' | 'MICROVM' | 'HOST_ENVELOPE' | 'DISPOSABLE_MACHINE'; id: string; }
export interface SecretLeaseRequest extends JsonObject {
  identityId: string;
  attestationId: string;
  transactionId: string;
  skillBundleDigest: string;
  grantDigest: string;
  providerId: 'local-secret-reference';
  secretReference: string;
  target: SecretLeaseTarget;
  ttlSeconds: number;
}
export interface SecretRevokeRequest extends JsonObject { leaseId: string; expectedSequence: number; reasonDigest: string; }

const DIGEST = /^[a-f0-9]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const CHALLENGE_ID = /^atc_[a-f0-9]{32}$/u;
const ATTESTATION_ID = /^atv_[a-f0-9]{32}$/u;
const IDENTITY_ID = /^wid_[a-f0-9]{32}$/u;
const LEASE_ID = /^sls_[a-f0-9]{32}$/u;
const TRANSACTION_ID = /^rtx_[A-Za-z0-9_-]{8,128}$/u;
const PROVIDERS = new Set<string>(ROOT_IDENTITY_PROVIDERS);
const ISSUERS = new Set<string>(ROOT_SVID_ISSUERS);
const SELECTORS = new Set<string>(ROOT_SELECTOR_TYPES);

function invalid(message: string, details: JsonObject = {}): never { throw new RootIdentityError('root_identity_invalid_request', message, details); }
function object(value: unknown, field: string): JsonObject { if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid(`${field} must be an object`); return value as JsonObject; }
function allowed(value: JsonObject, field: string, keys: readonly string[]): void { const permitted = new Set(keys); const unknown = Object.keys(value).filter((key) => !permitted.has(key)); if (unknown.length > 0) invalid(`${field} contains unsupported properties`, { properties: unknown }); }
function text(value: unknown, field: string, maximum = 1_024): string { if (typeof value !== 'string' || value.length < 1 || value.length > maximum || value.includes('\0')) invalid(`${field} must be a bounded non-empty NUL-free string`); return value; }
function id(value: unknown, field: string, expression: RegExp = IDENTIFIER): string { const result = text(value, field, 256); if (!expression.test(result)) invalid(`${field} is invalid`); return result; }
function digest(value: unknown, field: string): string { const result = text(value, field, 64); if (!DIGEST.test(result)) invalid(`${field} must be a lowercase SHA-256 digest`); return result; }
function timestamp(value: unknown, field: string): string { const result = text(value, field, 64); if (!Number.isFinite(Date.parse(result))) invalid(`${field} must be an ISO-8601 timestamp`); return new Date(Date.parse(result)).toISOString(); }
function integer(value: unknown, field: string, minimum: number, maximum: number): number { const result = Number(value); if (!Number.isSafeInteger(result) || result < minimum || result > maximum) invalid(`${field} must be an integer between ${minimum} and ${maximum}`); return result; }

function normalizePcrs(value: unknown, field: string): PcrValue[] {
  if (!Array.isArray(value) || value.length > 24) invalid(`${field} must be a bounded array`);
  const normalized = value.map((entry, index) => {
    const item = object(entry, `${field}[${index}]`); allowed(item, `${field}[${index}]`, ['index', 'algorithm', 'value']);
    if (item.algorithm !== 'sha256') invalid(`${field}[${index}].algorithm must be sha256`);
    return { index: integer(item.index, `${field}[${index}].index`, 0, 23), algorithm: 'sha256' as const, value: digest(item.value, `${field}[${index}].value`) };
  }).sort((left, right) => left.index - right.index);
  if (new Set(normalized.map((entry) => entry.index)).size !== normalized.length) invalid(`${field} contains duplicate PCR indexes`);
  return normalized;
}

export function normalizeAttestationChallenge(value: unknown): AttestationChallengeRequest {
  const payload = object(value, 'attestation challenge payload'); allowed(payload, 'attestation challenge payload', ['providerId', 'pcrSelection', 'ttlSeconds']);
  const providerId = payload.providerId === undefined ? 'hardware-tpm' : text(payload.providerId, 'providerId', 64);
  if (!PROVIDERS.has(providerId)) invalid('providerId is unsupported');
  const selection = payload.pcrSelection === undefined ? [0, 2, 4, 7] : payload.pcrSelection;
  if (!Array.isArray(selection) || selection.length < 1 || selection.length > 24) invalid('pcrSelection must be a bounded non-empty array');
  const pcrSelection = selection.map((entry, index) => integer(entry, `pcrSelection[${index}]`, 0, 23)).sort((left, right) => left - right);
  if (new Set(pcrSelection).size !== pcrSelection.length) invalid('pcrSelection contains duplicates');
  return { providerId: providerId as RootIdentityProviderId, pcrSelection, ttlSeconds: payload.ttlSeconds === undefined ? 300 : integer(payload.ttlSeconds, 'ttlSeconds', 30, 900) };
}

export function normalizeAttestationVerify(value: unknown): AttestationVerifyRequest {
  const payload = object(value, 'attestation verify payload'); allowed(payload, 'attestation verify payload', ['challengeId', 'quote', 'policy']);
  const quoteValue = object(payload.quote, 'quote'); allowed(quoteValue, 'quote', ['providerId', 'nonce', 'pcrs', 'eventLogDigest', 'imaDigest', 'bootId', 'observedAt', 'attestationKeyId', 'signature']);
  const providerId = text(quoteValue.providerId, 'quote.providerId', 64); if (!PROVIDERS.has(providerId)) invalid('quote.providerId is unsupported');
  const quote: AttestationQuote = {
    providerId: providerId as RootIdentityProviderId,
    nonce: digest(quoteValue.nonce, 'quote.nonce'),
    pcrs: normalizePcrs(quoteValue.pcrs, 'quote.pcrs'),
    eventLogDigest: quoteValue.eventLogDigest === null ? null : digest(quoteValue.eventLogDigest, 'quote.eventLogDigest'),
    imaDigest: quoteValue.imaDigest === null ? null : digest(quoteValue.imaDigest, 'quote.imaDigest'),
    bootId: id(quoteValue.bootId, 'quote.bootId'),
    observedAt: timestamp(quoteValue.observedAt, 'quote.observedAt'),
    attestationKeyId: id(quoteValue.attestationKeyId, 'quote.attestationKeyId'),
    signature: digest(quoteValue.signature, 'quote.signature'),
  };
  const policyValue = object(payload.policy, 'policy'); allowed(policyValue, 'policy', ['expectedPcrs', 'maxAgeSeconds', 'requireMeasuredBoot', 'requireIma']);
  const policy: AttestationPolicy = {
    expectedPcrs: normalizePcrs(policyValue.expectedPcrs ?? [], 'policy.expectedPcrs'),
    maxAgeSeconds: policyValue.maxAgeSeconds === undefined ? 300 : integer(policyValue.maxAgeSeconds, 'policy.maxAgeSeconds', 1, 900),
    requireMeasuredBoot: policyValue.requireMeasuredBoot === true,
    requireIma: policyValue.requireIma === true,
  };
  return { challengeId: id(payload.challengeId, 'challengeId', CHALLENGE_ID), quote, policy };
}

export function normalizeAttestationGet(value: unknown): AttestationGetRequest {
  const payload = object(value, 'attestation get payload'); allowed(payload, 'attestation get payload', ['challengeId', 'attestationId']);
  const challengeId = payload.challengeId === undefined ? undefined : id(payload.challengeId, 'challengeId', CHALLENGE_ID);
  const attestationId = payload.attestationId === undefined ? undefined : id(payload.attestationId, 'attestationId', ATTESTATION_ID);
  if ((challengeId === undefined) === (attestationId === undefined)) invalid('exactly one of challengeId or attestationId is required');
  return { ...(challengeId === undefined ? {} : { challengeId }), ...(attestationId === undefined ? {} : { attestationId }) };
}

export function normalizeSelectors(value: unknown): WorkloadSelector[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) invalid('selectors must be a bounded non-empty array');
  const selectors = value.map((entry, index) => {
    const item = object(entry, `selectors[${index}]`); allowed(item, `selectors[${index}]`, ['type', 'value']);
    const type = text(item.type, `selectors[${index}].type`, 64); if (!SELECTORS.has(type)) invalid(`selectors[${index}].type is unsupported`);
    const selectorValue = text(item.value, `selectors[${index}].value`, 1_024);
    if (type === 'executable_digest' || type === 'skill_bundle_digest') digest(selectorValue, `selectors[${index}].value`);
    if ((type === 'uid' || type === 'gid') && !/^(?:0|[1-9][0-9]{0,9})$/u.test(selectorValue)) invalid(`selectors[${index}].value must be a numeric ID`);
    return { type: type as RootSelectorType, value: selectorValue };
  }).sort((left, right) => `${left.type}:${left.value}`.localeCompare(`${right.type}:${right.value}`));
  if (new Set(selectors.map((entry) => `${entry.type}:${entry.value}`)).size !== selectors.length) invalid('selectors contain duplicates');
  return selectors;
}

export function normalizeIdentityIssue(value: unknown): IdentityIssueRequest {
  const payload = object(value, 'identity issue payload'); allowed(payload, 'identity issue payload', ['attestationId', 'transactionId', 'skillBundleDigest', 'grantDigest', 'issuerProviderId', 'selectors', 'ttlSeconds']);
  const issuer = payload.issuerProviderId === undefined ? 'sovereign-x509-svid' : text(payload.issuerProviderId, 'issuerProviderId', 64); if (!ISSUERS.has(issuer)) invalid('issuerProviderId is unsupported');
  const transactionId = id(payload.transactionId, 'transactionId', TRANSACTION_ID);
  const skillBundleDigest = digest(payload.skillBundleDigest, 'skillBundleDigest');
  const selectors = normalizeSelectors(payload.selectors);
  if (!selectors.some((entry) => entry.type === 'transaction_id' && entry.value === transactionId)) invalid('selectors must bind the exact transactionId');
  if (!selectors.some((entry) => entry.type === 'skill_bundle_digest' && entry.value === skillBundleDigest)) invalid('selectors must bind the exact skillBundleDigest');
  return {
    attestationId: id(payload.attestationId, 'attestationId', ATTESTATION_ID), transactionId, skillBundleDigest,
    grantDigest: digest(payload.grantDigest, 'grantDigest'), issuerProviderId: issuer as RootSvidIssuerId, selectors,
    ttlSeconds: payload.ttlSeconds === undefined ? 600 : integer(payload.ttlSeconds, 'ttlSeconds', 60, 3_600),
  };
}

export function normalizeIdentityGet(value: unknown): { identityId: string } { const payload = object(value, 'identity get payload'); allowed(payload, 'identity get payload', ['identityId']); return { identityId: id(payload.identityId, 'identityId', IDENTITY_ID) }; }
export function normalizeIdentityRevoke(value: unknown): IdentityRevokeRequest { const payload = object(value, 'identity revoke payload'); allowed(payload, 'identity revoke payload', ['identityId', 'expectedSequence', 'reasonDigest']); return { identityId: id(payload.identityId, 'identityId', IDENTITY_ID), expectedSequence: integer(payload.expectedSequence, 'expectedSequence', 1, 10_000_000), reasonDigest: digest(payload.reasonDigest, 'reasonDigest') }; }

export function normalizeSecretLease(value: unknown): SecretLeaseRequest {
  const payload = object(value, 'secret lease payload'); allowed(payload, 'secret lease payload', ['identityId', 'attestationId', 'transactionId', 'skillBundleDigest', 'grantDigest', 'providerId', 'secretReference', 'target', 'ttlSeconds']);
  if (payload.providerId !== 'local-secret-reference') invalid('providerId must be local-secret-reference');
  const secretReference = text(payload.secretReference, 'secretReference', 4_096); if (!secretReference.startsWith('/')) invalid('secretReference must be an absolute path');
  const targetValue = object(payload.target, 'target'); allowed(targetValue, 'target', ['kind', 'id']);
  const kinds = new Set(['SYSTEMD_UNIT', 'MICROVM', 'HOST_ENVELOPE', 'DISPOSABLE_MACHINE']); const kind = text(targetValue.kind, 'target.kind', 64); if (!kinds.has(kind)) invalid('target.kind is unsupported');
  return {
    identityId: id(payload.identityId, 'identityId', IDENTITY_ID), attestationId: id(payload.attestationId, 'attestationId', ATTESTATION_ID),
    transactionId: id(payload.transactionId, 'transactionId', TRANSACTION_ID), skillBundleDigest: digest(payload.skillBundleDigest, 'skillBundleDigest'),
    grantDigest: digest(payload.grantDigest, 'grantDigest'), providerId: 'local-secret-reference', secretReference,
    target: { kind: kind as SecretLeaseTarget['kind'], id: id(targetValue.id, 'target.id') },
    ttlSeconds: payload.ttlSeconds === undefined ? 300 : integer(payload.ttlSeconds, 'ttlSeconds', 30, 3_600),
  };
}

export function normalizeSecretRevoke(value: unknown): SecretRevokeRequest { const payload = object(value, 'secret revoke payload'); allowed(payload, 'secret revoke payload', ['leaseId', 'expectedSequence', 'reasonDigest']); return { leaseId: id(payload.leaseId, 'leaseId', LEASE_ID), expectedSequence: integer(payload.expectedSequence, 'expectedSequence', 1, 10_000_000), reasonDigest: digest(payload.reasonDigest, 'reasonDigest') }; }

export function requestDigest(operation: string, ownerPrincipal: string, value: JsonObject): string { return sha256(canonicalize({ operation, ownerPrincipal, value })); }
export function selectorMatches(selectors: readonly WorkloadSelector[], observed: readonly WorkloadSelector[]): boolean {
  const actual = new Set(observed.map((entry) => `${entry.type}:${entry.value}`));
  return selectors.every((entry) => actual.has(`${entry.type}:${entry.value}`));
}
