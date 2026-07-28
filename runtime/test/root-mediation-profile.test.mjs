import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MediationProfileStore } from '../../dist/runtime/root-platform/mediation/records.js';
import { normalizeMediationProfile } from '../../dist/runtime/root-platform/mediation/schemas.js';

const architecture = process.arch === 'arm64' ? 'aarch64' : 'x86_64';
const context = (idempotencyKey) => ({ subject: 'owner:mediation-test', authorityClass: 'unrestricted-owner', idempotencyKey });

function profile(overrides = {}) {
  return {
    version: '1.0.0',
    skillBundleDigest: 'a'.repeat(64),
    grantDigest: 'b'.repeat(64),
    providerScope: ['LANDLOCK', 'SECCOMP_NOTIFY', 'SECCOMP_FILTER'],
    architecture,
    defaultAction: { kind: 'allow' },
    allowedSyscalls: ['read'],
    deniedSyscalls: [{ syscall: 'mount', action: 'errno', errno: 1 }],
    notifiedSyscalls: [{ syscall: 'getpid', decision: 'allow' }],
    argumentConstraints: [],
    pathConstraints: [{ path: '/tmp', access: 'write' }],
    socketConstraints: [{ protocol: 'tcp', action: 'connect', port: 443 }],
    bpfRules: { mode: 'observe', hooks: [] },
    expiresAt: '2035-01-01T00:00:00.000Z',
    ...overrides,
  };
}

test('mediation profile normalization and digest are deterministic', () => {
  const first = normalizeMediationProfile(profile(), new Date('2026-07-28T00:00:00.000Z'));
  const second = normalizeMediationProfile(profile({ providerScope: ['SECCOMP_FILTER', 'LANDLOCK', 'SECCOMP_NOTIFY'] }), new Date('2026-07-28T00:00:00.000Z'));
  assert.equal(first.profileDigest, second.profileDigest);
  assert.deepEqual(first.providerScope, ['LANDLOCK', 'SECCOMP_FILTER', 'SECCOMP_NOTIFY']);
  assert.equal(first.deniedSyscalls[0].syscallNumber, architecture === 'x86_64' ? 165 : 40);
  assert.equal(first.notifiedSyscalls[0].syscallNumber, architecture === 'x86_64' ? 39 : 172);
});

test('mediation profile schemas reject unsupported, overlapping, and out-of-scope behavior', () => {
  assert.throws(() => normalizeMediationProfile(profile({ unexpected: true })), /unsupported properties/u);
  assert.throws(() => normalizeMediationProfile(profile({ allowedSyscalls: ['getpid'] })), /cannot be allowed, denied, and notified/u);
  assert.throws(() => normalizeMediationProfile(profile({ notifiedSyscalls: [{ syscall: 'not_real', decision: 'allow' }] })), /not in the selected/u);
  assert.throws(() => normalizeMediationProfile(profile({ providerScope: ['LANDLOCK'], allowedSyscalls: [], deniedSyscalls: [], notifiedSyscalls: [{ syscall: 'getpid', decision: 'allow' }] })), /notification rules require/u);
  assert.throws(() => normalizeMediationProfile(profile({ providerScope: ['SECCOMP_FILTER'], notifiedSyscalls: [], pathConstraints: [{ path: '/tmp', access: 'read' }], socketConstraints: [] })), /require LANDLOCK/u);
  assert.throws(() => normalizeMediationProfile(profile({ providerScope: ['SECCOMP_FILTER'], allowedSyscalls: [], deniedSyscalls: [], notifiedSyscalls: [], pathConstraints: [], socketConstraints: [], bpfRules: { mode: 'enforce', hooks: ['bprm_check_security'] } }), new Date('2026-07-28T00:00:00.000Z')), /BPF rules require/u);
  assert.throws(() => normalizeMediationProfile(profile({ expiresAt: '2020-01-01T00:00:00.000Z' }), new Date('2026-07-28T00:00:00.000Z')), /future ISO-8601/u);
});

test('durable profile create and revoke are restart-safe and idempotent', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-mediation-profile-'));
  let now = '2026-07-28T00:00:00.000Z';
  try {
    const first = new MediationProfileStore(root, { now: () => now });
    const created = first.create(profile(), context('mediation-create-0001'));
    const replayed = first.create(profile(), context('mediation-create-0001'));
    assert.equal(created.replayed, false);
    assert.equal(replayed.replayed, true);
    assert.deepEqual(replayed.profile, created.profile);

    const profileId = created.profile.profileId;
    const restarted = new MediationProfileStore(root, { now: () => now });
    assert.equal(restarted.latest(profileId).recordDigest, created.profile.recordDigest);
    const revoked = restarted.revoke(profileId, 1, 'c'.repeat(64), context('mediation-revoke-0001'));
    const revokedReplay = restarted.revoke(profileId, 1, 'c'.repeat(64), context('mediation-revoke-0001'));
    assert.equal(revoked.profile.status, 'REVOKED');
    assert.equal(revoked.profile.sequence, 2);
    assert.equal(revokedReplay.replayed, true);
    assert.deepEqual(revokedReplay.profile, revoked.profile);
    assert.throws(() => restarted.revoke(profileId, 1, 'd'.repeat(64), context('mediation-revoke-0002')), (error) => error.code === 'mediation_sequence_conflict');

    const events = restarted.listEvents(profileId, 0, 100);
    assert.deepEqual(events.events.map((event) => event.operation), ['CREATED', 'REVOKED']);
    assert.equal(events.events[1].priorEventDigest, events.events[0].eventDigest);
    assert.equal(restarted.reconcile().ok, true);

    const second = restarted.create(profile({ version: '1.0.1' }), context('mediation-create-0002'));
    now = '2036-01-01T00:00:00.000Z';
    assert.equal(restarted.effective(restarted.latest(second.profile.profileId)).effectiveStatus, 'EXPIRED');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
