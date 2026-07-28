import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BabyXRuntime } from '../../dist/runtime/core.js';
import { RootMediationService } from '../../dist/runtime/root-platform/mediation/service.js';

const architecture = process.arch === 'arm64' ? 'aarch64' : 'x86_64';
const binary = join(process.cwd(), 'dist/runtime/native/mediation-supervisor/baby-x-mediation-supervisor');
const context = (idempotencyKey) => ({ subject: 'owner:mediation-integration', authorityClass: 'unrestricted-owner', idempotencyKey });

function run(args, expectedStatus = 0) {
  const result = spawnSync(binary, args, { encoding: 'utf8', timeout: 15_000, maxBuffer: 2_097_152 });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, expectedStatus, `${args.join(' ')}\nstdout=${result.stdout}\nstderr=${result.stderr}`);
  return result;
}

function profile(overrides = {}) {
  return {
    version: '1.0.0',
    skillBundleDigest: 'd'.repeat(64),
    grantDigest: 'e'.repeat(64),
    providerScope: ['SECCOMP_FILTER', 'SECCOMP_NOTIFY'],
    architecture,
    defaultAction: { kind: 'allow' },
    allowedSyscalls: [],
    deniedSyscalls: [],
    notifiedSyscalls: [{ syscall: 'getpid', decision: 'allow' }],
    argumentConstraints: [],
    pathConstraints: [],
    socketConstraints: [],
    bpfRules: { mode: 'observe', hooks: [] },
    expiresAt: '2035-01-01T00:00:00.000Z',
    ...overrides,
  };
}

test('native mediation supervisor passes filter, notification, identity, stale, and Landlock cases', () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-native-mediation-'));
  try {
    const allowed = join(root, 'allowed');
    const denied = join(root, 'denied');
    mkdirSync(allowed);
    mkdirSync(denied);
    writeFileSync(join(allowed, 'value'), 'allowed');
    writeFileSync(join(denied, 'value'), 'denied');
    for (const mode of ['allowed', 'errno', 'kill']) assert.match(run(['filter-test', mode]).stdout, /"ok":true/u);
    for (const mode of ['allow', 'deny', 'stale', 'identity-conflict', 'supervisor-death']) {
      const output = run(['notify-test', mode]).stdout;
      assert.match(output, /BABYX_RESULT .*"ok":true/u);
      if (mode === 'stale') assert.match(output, /"staleAfterResponse":true/u);
      if (mode === 'identity-conflict') assert.match(output, /"identity":false/u);
    }
    assert.match(run(['landlock-test', join(allowed, 'value'), join(denied, 'value')]).stdout, /"denied":true/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('public mediation profiles dispatch, execute typed native work, persist events, restart, and revoke', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-mediation-integration-'));
  try {
    const options = { stateRoot: root, sourceCommit: 'a'.repeat(40), sourceTree: 'b'.repeat(40) };
    const runtime = new BabyXRuntime(options);
    const created = await runtime.execute('babyx.root.mediation.profile.create', { profile: profile() }, context('mediation-public-create-0001'));
    const replay = await runtime.execute('babyx.root.mediation.profile.create', { profile: profile() }, context('mediation-public-create-0001'));
    assert.equal(created.replayed, false);
    assert.equal(replay.replayed, true);
    assert.equal(replay.profile.recordDigest, created.profile.recordDigest);

    const profileId = created.profile.profileId;
    const service = new RootMediationService({ stateRoot: root });
    const executed = service.execute(profileId, 'rtx_mediation_integration', ['/usr/bin/python3', '-c', 'import os; assert os.getpid() > 0']);
    assert.equal(executed.result.ok, true);
    assert.ok(executed.decisionEventsPersisted >= 1);

    const events = await runtime.execute('babyx.root.mediation.events', { profileId, offset: 0, limit: 100 });
    assert.equal(events.events[0].operation, 'CREATED');
    assert.ok(events.events.some((event) => event.operation === 'DECISION' && event.transactionId === 'rtx_mediation_integration'));

    const restarted = new BabyXRuntime(options);
    const fetched = await restarted.execute('babyx.root.mediation.profile.get', { profileId });
    const listed = await restarted.execute('babyx.root.mediation.profile.list', { status: 'ACTIVE' });
    assert.equal(fetched.profile.recordDigest, created.profile.recordDigest);
    assert.equal(listed.profiles.length, 1);

    const revoked = await restarted.execute('babyx.root.mediation.profile.revoke', { profileId, expectedSequence: 1, reasonDigest: 'f'.repeat(64) }, context('mediation-public-revoke-0001'));
    const revokedReplay = await restarted.execute('babyx.root.mediation.profile.revoke', { profileId, expectedSequence: 1, reasonDigest: 'f'.repeat(64) }, context('mediation-public-revoke-0001'));
    assert.equal(revoked.profile.status, 'REVOKED');
    assert.equal(revokedReplay.replayed, true);
    assert.throws(() => service.execute(profileId, 'rtx_revoked', ['/bin/true']), (error) => error.code === 'mediation_profile_revoked');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('notification denial, argument mismatch, and unavailable BPF fail closed', async () => {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-mediation-denial-'));
  try {
    const runtime = new BabyXRuntime({ stateRoot: root, sourceCommit: 'a'.repeat(40), sourceTree: 'b'.repeat(40) });
    const denied = await runtime.execute('babyx.root.mediation.profile.create', { profile: profile({ version: '1.0.1', notifiedSyscalls: [{ syscall: 'getpid', decision: 'deny', errno: 1 }] }) }, context('mediation-deny-create-0001'));
    const service = new RootMediationService({ stateRoot: root });
    const deniedResult = service.execute(denied.profile.profileId, 'rtx_denied', [binary, 'raw-syscall', 'getpid']);
    assert.equal(deniedResult.result.ok, false);
    assert.notEqual(deniedResult.result.status, 0);

    const constrained = await runtime.execute('babyx.root.mediation.profile.create', { profile: profile({ version: '1.0.2', argumentConstraints: [{ syscall: 'getpid', index: 0, value: Number.MAX_SAFE_INTEGER }] }) }, context('mediation-constraint-create-0001'));
    const constrainedResult = service.execute(constrained.profile.profileId, 'rtx_constrained', [binary, 'raw-syscall', 'getpid']);
    assert.equal(constrainedResult.result.ok, false);

    const bpf = await runtime.execute('babyx.root.mediation.profile.create', { profile: profile({ version: '1.0.3', providerScope: ['BPF_LSM'], notifiedSyscalls: [], bpfRules: { mode: 'observe', hooks: ['bprm_check_security'] } }) }, context('mediation-bpf-create-0001'));
    assert.throws(() => service.execute(bpf.profile.profileId, 'rtx_bpf_unavailable', ['/bin/true']), (error) => error.code === 'mediation_bpf_unavailable');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
