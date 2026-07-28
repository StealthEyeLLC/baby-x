import { canonicalize, sha256, type JsonObject } from '../core.ts';
import { RootPlatformError } from './errors.ts';

export const ROOT_PLATFORM_SCHEMA_VERSION = '2.0.0' as const;
export const ROOT_PLATFORM_PROVIDER_VERSION = 'sovereign-root-platform@2' as const;
export const PROVIDER_CONTRACT_VERSION = '1.0.0' as const;
export const PROVIDER_SUPPORT_STATES = ['SUPPORTED', 'DEGRADED', 'UNAVAILABLE', 'EXPERIMENTAL', 'DISABLED', 'REVOKED', 'FAILED'] as const;
export type ProviderSupportState = typeof PROVIDER_SUPPORT_STATES[number];

export interface ProviderDefinition extends JsonObject {
  providerId: string;
  family: string;
  implementationVersion: string;
  contractVersion: typeof PROVIDER_CONTRACT_VERSION;
  requiredCapabilities: string[];
  limits: JsonObject;
  restartBehavior: string;
  cancellationBehavior: string;
  cleanupBehavior: string;
  errors: string[];
  configurationDigest: string;
}

export interface ProviderObservation extends JsonObject {
  supportState: ProviderSupportState;
  executableIdentity: string | null;
  health: JsonObject;
  observedCapabilities: string[];
}

export interface ProviderDescriptor extends ProviderDefinition, ProviderObservation {
  descriptorDigest: string;
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const SUPPORT_STATES = new Set<string>(PROVIDER_SUPPORT_STATES);
const DEFINITION_KEYS = new Set([
  'providerId', 'family', 'implementationVersion', 'contractVersion', 'requiredCapabilities', 'limits',
  'restartBehavior', 'cancellationBehavior', 'cleanupBehavior', 'errors', 'configurationDigest',
]);

function boundedText(value: unknown, field: string, maximum = 512): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || value.includes('\0')) throw new RootPlatformError('root_platform_invalid_request', `${field} must be a bounded non-empty NUL-free string`);
  return value;
}

export function providerIdentifier(value: unknown, field = 'providerId'): string {
  const normalized = boundedText(value, field, 256);
  if (!IDENTIFIER.test(normalized)) throw new RootPlatformError('root_platform_invalid_request', `${field} is invalid`);
  return normalized;
}

function stringSet(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length > 128) throw new RootPlatformError('root_platform_invalid_request', `${field} must be a bounded array`);
  const normalized = value.map((entry, index) => providerIdentifier(entry, `${field}[${index}]`));
  if (new Set(normalized).size !== normalized.length) throw new RootPlatformError('root_platform_invalid_request', `${field} must not contain duplicates`);
  return [...normalized].sort();
}

function jsonObject(value: unknown, field: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new RootPlatformError('root_platform_invalid_request', `${field} must be an object`);
  return value as JsonObject;
}

export function supportState(value: unknown): ProviderSupportState {
  if (typeof value !== 'string' || !SUPPORT_STATES.has(value)) throw new RootPlatformError('root_platform_invalid_request', 'provider support state is invalid');
  return value as ProviderSupportState;
}

export function validateProviderDefinition(value: ProviderDefinition): ProviderDefinition {
  const object = jsonObject(value, 'provider definition');
  const unknown = Object.keys(object).filter((key) => !DEFINITION_KEYS.has(key));
  if (unknown.length > 0) throw new RootPlatformError('root_platform_invalid_request', 'provider definition contains unsupported properties', { properties: unknown });
  const normalized: ProviderDefinition = {
    providerId: providerIdentifier(object.providerId),
    family: providerIdentifier(object.family, 'family'),
    implementationVersion: boundedText(object.implementationVersion, 'implementationVersion', 256),
    contractVersion: boundedText(object.contractVersion, 'contractVersion', 32) as typeof PROVIDER_CONTRACT_VERSION,
    requiredCapabilities: stringSet(object.requiredCapabilities, 'requiredCapabilities'),
    limits: structuredClone(jsonObject(object.limits, 'limits')),
    restartBehavior: boundedText(object.restartBehavior, 'restartBehavior', 256),
    cancellationBehavior: boundedText(object.cancellationBehavior, 'cancellationBehavior', 256),
    cleanupBehavior: boundedText(object.cleanupBehavior, 'cleanupBehavior', 256),
    errors: stringSet(object.errors, 'errors'),
    configurationDigest: boundedText(object.configurationDigest, 'configurationDigest', 64),
  };
  if (normalized.contractVersion !== PROVIDER_CONTRACT_VERSION) throw new RootPlatformError('root_platform_invalid_request', 'provider contract version is incompatible');
  if (!DIGEST.test(normalized.configurationDigest)) throw new RootPlatformError('root_platform_invalid_request', 'configurationDigest must be a lowercase SHA-256 digest');
  return normalized;
}

export function validateProviderObservation(value: ProviderObservation): ProviderObservation {
  const object = jsonObject(value, 'provider observation');
  const executableIdentity = object.executableIdentity;
  if (executableIdentity !== null && (typeof executableIdentity !== 'string' || executableIdentity.length > 1024 || executableIdentity.includes('\0'))) throw new RootPlatformError('root_platform_invalid_request', 'executableIdentity must be null or a bounded string');
  return {
    supportState: supportState(object.supportState),
    executableIdentity: executableIdentity as string | null,
    health: structuredClone(jsonObject(object.health, 'health')),
    observedCapabilities: stringSet(object.observedCapabilities, 'observedCapabilities'),
  };
}

export function sealProviderDescriptor(definition: ProviderDefinition, observation: ProviderObservation): ProviderDescriptor {
  const unsigned = { ...validateProviderDefinition(definition), ...validateProviderObservation(observation) };
  return { ...unsigned, descriptorDigest: sha256(canonicalize(unsigned)) };
}

export function strictPayload(value: unknown, field: string, allowed: readonly string[]): JsonObject {
  const object = jsonObject(value, field);
  const permitted = new Set(allowed);
  const unknown = Object.keys(object).filter((key) => !permitted.has(key));
  if (unknown.length > 0) throw new RootPlatformError('root_platform_invalid_request', `${field} contains unsupported properties`, { properties: unknown });
  return object;
}

export function page(value: JsonObject): { offset: number; limit: number } {
  const offset = value.offset === undefined ? 0 : Number(value.offset);
  const limit = value.limit === undefined ? 100 : Number(value.limit);
  if (!Number.isSafeInteger(offset) || offset < 0) throw new RootPlatformError('root_platform_invalid_request', 'offset must be a non-negative safe integer');
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) throw new RootPlatformError('root_platform_invalid_request', 'limit must be between 1 and 1000');
  return { offset, limit };
}
