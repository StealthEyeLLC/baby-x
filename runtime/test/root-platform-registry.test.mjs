import assert from 'node:assert/strict';
import test from 'node:test';
import { ProviderRegistry } from '../../dist/runtime/root-platform/provider-registry.js';
import { PROVIDER_CONTRACT_VERSION } from '../../dist/runtime/root-platform/schemas.js';

const definition = (providerId) => ({ providerId, family: 'fixture', implementationVersion: 'fixture@1', contractVersion: PROVIDER_CONTRACT_VERSION, requiredCapabilities: [], limits: {}, restartBehavior: 'reprobe', cancellationBehavior: 'bounded', cleanupBehavior: 'none', errors: ['fixture_failed'], configurationDigest: 'a'.repeat(64) });
const provider = (providerId, probe = () => ({ supportState: 'SUPPORTED', executableIdentity: null, health: { ok: true }, observedCapabilities: [] })) => ({ definition: definition(providerId), probe });

test('provider registry rejects duplicate, unknown, and incompatible providers', () => {
  assert.throws(() => new ProviderRegistry([provider('fixture'), provider('fixture')]), (error) => error.code === 'root_platform_duplicate_provider');
  const registry = new ProviderRegistry([provider('fixture')]);
  assert.throws(() => registry.get('missing'), (error) => error.code === 'root_platform_provider_not_found');
  const incompatible = provider('incompatible');
  incompatible.definition.contractVersion = '2.0.0';
  assert.throws(() => new ProviderRegistry([incompatible]), /contract version is incompatible/u);
  const extended = provider('extended');
  extended.definition.unexpected = true;
  assert.throws(() => new ProviderRegistry([extended]), /unsupported properties/u);
});

test('provider registry validates support states and bounds probe failure as FAILED', () => {
  assert.throws(() => new ProviderRegistry([provider('bad', () => ({ supportState: 'UNKNOWN', executableIdentity: null, health: {}, observedCapabilities: [] }))]).get('bad'), /support state is invalid/u);
  const registry = new ProviderRegistry([provider('failed', () => { throw new Error('unbounded internal detail'); })]);
  const observed = registry.get('failed');
  assert.equal(observed.supportState, 'FAILED');
  assert.deepEqual(observed.health, { ok: false, error: 'root_platform_provider_failed' });
});

test('provider registry digest and ordering are deterministic', () => {
  const left = new ProviderRegistry([provider('zeta'), provider('alpha')]);
  const right = new ProviderRegistry([provider('alpha'), provider('zeta')]);
  assert.equal(left.registryDigest(), right.registryDigest());
  assert.deepEqual(left.list().map((entry) => entry.providerId), ['alpha', 'zeta']);
});
