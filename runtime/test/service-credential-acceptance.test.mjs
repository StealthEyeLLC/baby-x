import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

test('K.5-A through K.5-D public credential authority remains fully registered and unique', () => {
  const source = readFileSync('runtime/src/operations/definitions.ts', 'utf8');
  const names = source.split(/\r?\n/u).filter((line) => /^babyx\.release\.credential-bootstrap\.[a-z-]+$/u.test(line));
  assert.equal(names.length, 15);
  assert.equal(new Set(names).size, 15);
  for (const required of ['describe','profiles','plan','get','list','events','verify','active','compatibility','ensure','reconcile','rotate','rollback','revoke','clean']) assert.ok(names.includes(`babyx.release.credential-bootstrap.${required}`));
});

test('canonical documentation digest is deterministic and records the legacy discrepancy without claiming a content change', () => {
  const first = spawnSync(process.execPath, ['scripts/documentation-digest.mjs'], { encoding: 'utf8' });
  const second = spawnSync(process.execPath, ['scripts/documentation-digest.mjs'], { encoding: 'utf8' });
  assert.equal(first.status, 0, first.stderr); assert.equal(second.status, 0, second.stderr);
  assert.equal(first.stdout, second.stdout);
  const result = JSON.parse(first.stdout);
  assert.match(result.canonicalSha256, /^[a-f0-9]{64}$/u);
  assert.equal(result.locale, 'C'); assert.equal(result.contentUsedRaw, true); assert.equal(result.pathBytesIncluded, true); assert.equal(result.sizesIncluded, true);
  assert.equal(result.legacyReports.checkpointLPreflight, '1de04475a6a957f66d4ecb6ba1d08f748e0e8f564c2846c4dc8180f392bfbd1e');
  assert.match(result.legacyReports.discrepancyConclusion, /reporting transcription error/u);
  assert.match(result.legacyReports.discrepancyConclusion, /No content change is inferred/u);
});

test('disposable certification harness exposes public fingerprints only and removes all test state', () => {
  const result = spawnSync(process.execPath, ['scripts/k5-service-credential-certification.mjs'], { encoding: 'utf8', timeout: 120_000, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const evidence = JSON.parse(result.stdout);
  assert.equal(evidence.status, 'PASS');
  assert.equal(evidence.serviceIdentity.accountName, 'fix-mcp');
  assert.equal(evidence.serviceIdentity.observedUid, 997);
  assert.equal(evidence.idempotentReplay, true);
  assert.equal(evidence.rotation.independentGeneration, true);
  assert.equal(evidence.rollback.regenerated, false);
  assert.equal(evidence.revocation.evidencePreserved, true);
  assert.equal(evidence.launcherRestartsVerified, 2);
  assert.equal(evidence.cleanup.testRootAbsent, true);
  assert.equal(evidence.rawPrivateMaterialReturned, false);
  assert.equal(result.stdout.includes(['-----BEGIN ', 'PRIVATE KEY-----'].join('')), false);
  assert.doesNotMatch(result.stdout, /\/etc\/stealtheye-quirt\/authority\.key/u);
});

test('repository installer remains fail closed and production paths are absent during K.5 acceptance', () => {
  const installer = readFileSync('scripts/install-local.sh', 'utf8');
  assert.match(installer, /BABY_X_CREDENTIAL_GENERATION_ID/u);
  assert.match(installer, /BABY_X_CREDENTIAL_BINDING_ROOT/u);
  assert.doesNotMatch(installer, /generateKeyPair|openssl gen/u);
  for (const path of ['/etc/baby-x', '/opt/baby-x']) {
    const check = spawnSync('/usr/bin/test', ['!', '-e', path]);
    assert.equal(check.status, 0, `${path} unexpectedly exists`);
  }
});
