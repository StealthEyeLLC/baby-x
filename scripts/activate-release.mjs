#!/usr/bin/env node
import {
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import process from 'node:process';
import {
  CANONICAL_UNITS,
  atomicWrite,
  atomicWriteJson,
  canonicalize,
  createFileManifest,
  digestFile,
  fsyncDirectory,
  fsyncTree,
  makeImmutable,
  pathInside,
  sha256,
  verifyRelease,
} from './lib/release-contract.mjs';

const TERMINAL = new Set(['ACTIVE', 'ROLLED_BACK', 'BLOCKED', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS']);
const JOURNAL_FIELDS = [
  'deploymentId',
  'candidateCommit',
  'candidateTree',
  'candidateReleasePath',
  'candidateManifestDigest',
  'desiredState',
  'persistedState',
  'phaseSequence',
  'startedAt',
  'updatedAt',
  'priorCurrentTarget',
  'priorPreviousTarget',
  'priorCommit',
  'priorTree',
  'priorServiceState',
  'priorHealth',
  'pointerSwitchState',
  'systemdReloadState',
  'serviceRestartState',
  'healthReadbackState',
  'runtimeIdentityState',
  'rollbackRequired',
  'rollbackState',
  'error',
  'finalState',
];

export class CrashInjected extends Error {
  constructor(phase) {
    super(`crash injected after ${phase}`);
    this.phase = phase;
  }
}

function parse(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith('--') || value === undefined) throw new Error('activate-release arguments must be --name value pairs');
    result[key.slice(2)] = value;
  }
  return result;
}

function command(executable, argv, options = {}) {
  const result = spawnSync(executable, argv, {
    encoding: 'utf8',
    timeout: options.timeout ?? 30_000,
    env: options.env ?? process.env,
    cwd: options.cwd,
  });
  if (result.status !== 0) throw new Error(`${executable} ${argv.join(' ')} failed: ${result.stderr.trim()}`);
  return result.stdout.trim();
}

function terminalJournal(value) {
  return value && typeof value === 'object' && TERMINAL.has(value.finalState);
}

export function assertActivationJournal(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('activation journal must be an object');
  const missing = JOURNAL_FIELDS.filter((field) => !Object.hasOwn(value, field));
  if (missing.length > 0) throw new Error(`activation journal is missing required fields: ${missing.join(',')}`);
  if (!Number.isSafeInteger(value.phaseSequence) || value.phaseSequence < 0) throw new Error('activation journal phase sequence is invalid');
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(value.deploymentId)) throw new Error('activation journal deployment ID is invalid');
  if (!/^[a-f0-9]{40}$/u.test(value.candidateCommit) || !/^[a-f0-9]{40}$/u.test(value.candidateTree)) {
    throw new Error('activation journal candidate identity is invalid');
  }
  if (value.finalState !== null && !TERMINAL.has(value.finalState)) throw new Error('activation journal final state is invalid');
  return value;
}

export function pointerTarget(link, releaseRoot, required = true) {
  if (!existsSync(link) && !lstatExists(link)) {
    if (required) throw new Error(`${link} is absent`);
    return null;
  }
  const metadata = lstatSync(link);
  if (!metadata.isSymbolicLink()) throw new Error(`${link} is not a symlink`);
  const target = realpathSync(link);
  pathInside(realpathSync(releaseRoot), target, 'release pointer');
  if (!statSync(target).isDirectory()) throw new Error(`${link} does not target a release directory`);
  return target;
}

function lstatExists(path) {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

function targetIdentity(target) {
  const manifestPath = join(target, 'release.json');
  if (existsSync(manifestPath) && existsSync(join(target, 'release.sha256'))) {
    try {
      const verified = verifyRelease(target);
      return { commit: verified.manifest.commit, tree: verified.manifest.tree, canonical: true, manifestSha256: verified.releaseManifestSha256 };
    } catch (error) {
      const value = JSON.parse(readFileSync(manifestPath, 'utf8'));
      if (value.legacyImported === true && /^[a-f0-9]{40}$/u.test(value.commit) && /^[a-f0-9]{40}$/u.test(value.tree)) {
        if (readFileSync(join(target, 'release.sha256'), 'utf8').trim() !== digestFile(manifestPath)) throw new Error('legacy rollback release manifest digest mismatch');
        return { commit: value.commit, tree: value.tree, canonical: false, legacyImported: true, manifestSha256: digestFile(manifestPath) };
      }
      throw error;
    }
  }
  const match = basename(target).match(/^([a-f0-9]{40})-([a-f0-9]{40})(?:$|-)/u);
  if (!match) throw new Error(`legacy release identity cannot be derived from ${target}`);
  return { commit: match[1], tree: match[2], canonical: false, legacyImported: false, manifestSha256: null };
}

export function atomicLink(target, link) {
  const temporary = `${link}.tmp.${process.pid}`;
  if (lstatExists(temporary)) unlinkSync(temporary);
  symlinkSync(target, temporary);
  renameSync(temporary, link);
  fsyncDirectory(dirname(link));
}

function makeWritableForRemoval(root) {
  if (!existsSync(root)) return;
  const visit = (path) => {
    const metadata = lstatSync(path);
    if (metadata.isDirectory()) {
      chmodSync(path, 0o700);
      for (const name of readdirSync(path)) visit(join(path, name));
    } else chmodSync(path, 0o600);
  };
  visit(root);
}

function ensureLegacyRollbackTarget(priorTarget, releaseRoot, identity, deploymentId) {
  if (identity.canonical || identity.legacyImported) return priorTarget;
  const destination = join(releaseRoot, `rollback-${identity.commit}-${identity.tree}`);
  if (existsSync(destination)) {
    const observed = targetIdentity(destination);
    if (observed.commit !== identity.commit || observed.tree !== identity.tree || observed.legacyImported !== true) {
      throw new Error('existing legacy rollback release conflicts with the prior runtime identity');
    }
    return destination;
  }
  const staging = join(releaseRoot, `.rollback-${identity.commit}-${identity.tree}.${process.pid}.staging`);
  if (existsSync(staging)) {
    makeWritableForRemoval(staging);
    rmSync(staging, { recursive: true, force: true });
  }
  const before = createFileManifest(priorTarget, new Set());
  mkdirSync(staging, { mode: 0o700 });
  try {
    cpSync(priorTarget, staging, { recursive: true, dereference: true, errorOnExist: false });
    const copied = createFileManifest(staging, new Set());
    if (canonicalize(before) !== canonicalize(copied)) throw new Error('legacy rollback copy does not match the active release bytes');
    const manifest = {
      schemaVersion: '1.0.0',
      repository: 'StealthEyeLLC/baby-x',
      branch: 'legacy-production-import',
      commit: identity.commit,
      tree: identity.tree,
      parent: '0'.repeat(40),
      releaseIdentity: `${identity.commit}-${identity.tree}`,
      legacyImported: true,
      importedForDeployment: deploymentId,
      contentManifestSha256: sha256(canonicalize(before)),
    };
    atomicWriteJson(join(staging, 'release.json'), manifest, 0o444);
    atomicWrite(join(staging, 'release.sha256'), `${digestFile(join(staging, 'release.json'))}\n`, 0o444);
    fsyncTree(staging);
    makeImmutable(staging);
    renameSync(staging, destination);
    fsyncDirectory(releaseRoot);
    return destination;
  } catch (error) {
    if (existsSync(staging)) {
      makeWritableForRemoval(staging);
      rmSync(staging, { recursive: true, force: true });
    }
    throw error;
  }
}

function backupFiles(paths, backupRoot) {
  mkdirSync(backupRoot, { recursive: true, mode: 0o700 });
  const records = {};
  for (const path of paths) {
    const name = basename(path);
    if (existsSync(path)) {
      const destination = join(backupRoot, name);
      copyFileSync(path, destination);
      chmodSync(destination, 0o600);
      records[path] = { existed: true, backup: destination, sha256: digestFile(path) };
    } else {
      records[path] = { existed: false, backup: null, sha256: null };
    }
  }
  fsyncDirectory(backupRoot);
  return records;
}

function atomicInstall(source, destination, mode = 0o644) {
  const temporary = `${destination}.tmp.${process.pid}`;
  copyFileSync(source, temporary);
  chmodSync(temporary, mode);
  const descriptor = spawnSync('/usr/bin/sync', ['-f', temporary], { encoding: 'utf8' });
  if (descriptor.status !== 0) throw new Error(`could not durably stage ${destination}`);
  renameSync(temporary, destination);
  fsyncDirectory(dirname(destination));
}

function installCanonicalFiles(candidate) {
  for (const unit of CANONICAL_UNITS) atomicInstall(join(candidate, 'ops', 'systemd', unit), join('/etc/systemd/system', unit));
  atomicInstall(join(candidate, 'ops', 'tmpfiles', 'baby-x.conf'), '/etc/tmpfiles.d/baby-x.conf');
}

function restoreFiles(records) {
  for (const [path, record] of Object.entries(records)) {
    if (record.existed) atomicInstall(record.backup, path);
    else if (existsSync(path)) {
      unlinkSync(path);
      fsyncDirectory(dirname(path));
    }
  }
}

function serviceState() {
  return Object.fromEntries(['baby-x.socket', 'baby-x.service', 'baby-x-gateway.service', 'baby-x-root-broker.socket', 'baby-x-root-broker.service'].map((unit) => {
    const result = spawnSync('/usr/bin/systemctl', ['is-active', unit], { encoding: 'utf8', timeout: 5_000 });
    return [unit, result.stdout.trim() || 'inactive'];
  }));
}

async function gatewayHealth() {
  const response = await fetch('http://127.0.0.1:2097/healthz', { signal: AbortSignal.timeout(5_000) });
  if (!response.ok) throw new Error(`gateway health returned HTTP ${response.status}`);
  return response.json();
}

async function verifyPrior(target, identity) {
  if (realpathSync('/opt/baby-x/current') !== realpathSync(target)) throw new Error('rollback current pointer mismatch');
  for (const unit of ['baby-x.socket', 'baby-x.service', 'baby-x-gateway.service']) {
    if (command('/usr/bin/systemctl', ['is-active', unit]) !== 'active') throw new Error(`rollback ${unit} is not active`);
  }
  const gateway = await gatewayHealth();
  if (gateway.ok !== true || gateway.product !== 'baby-x-gateway' || gateway.runtime?.product !== 'baby-x') throw new Error('rollback gateway health mismatch');
  const observed = targetIdentity(target);
  if (observed.commit !== identity.commit || observed.tree !== identity.tree) throw new Error('rollback runtime identity mismatch');
  return { target, commit: identity.commit, tree: identity.tree, gateway };
}

function restartCandidate() {
  command('/usr/bin/systemctl', ['stop', 'baby-x-gateway.service', 'baby-x.service', 'baby-x-root-broker.service'], { timeout: 30_000 });
  command('/usr/bin/systemctl', ['restart', 'baby-x-root-broker.socket', 'baby-x.socket'], { timeout: 30_000 });
  command('/usr/bin/systemctl', ['start', 'baby-x-root-broker.service', 'baby-x.service', 'baby-x-gateway.service'], { timeout: 30_000 });
}

function restartPrior() {
  spawnSync('/usr/bin/systemctl', ['stop', 'baby-x-root-broker.service', 'baby-x-root-broker.socket'], { encoding: 'utf8', timeout: 30_000 });
  command('/usr/bin/systemctl', ['restart', 'baby-x.socket'], { timeout: 30_000 });
  command('/usr/bin/systemctl', ['restart', 'baby-x.service', 'baby-x-gateway.service'], { timeout: 30_000 });
}

function prepareRuntimeAuthority(candidate) {
  command('/bin/bash', [join(candidate, 'scripts', 'provision-local-keys.sh')], { timeout: 30_000 });
  command('/usr/bin/systemd-tmpfiles', ['--create', join(candidate, 'ops', 'tmpfiles', 'baby-x.conf')], { timeout: 30_000 });
  command('/usr/bin/chown', ['-R', 'fix-exec:horsey', '/var/lib/baby-x'], { timeout: 60_000 });
  mkdirSync('/var/lib/baby-x/deployments', { recursive: true, mode: 0o700 });
  command('/usr/bin/chown', ['-R', 'root:root', '/var/lib/baby-x/deployments'], { timeout: 30_000 });
  chmodSync('/var/lib/baby-x/deployments', 0o700);
}

function unresolvedDeployment(stateRoot, deploymentId) {
  const root = join(stateRoot, 'deployments');
  if (!existsSync(root)) return null;
  for (const name of readdirSync(root).filter((value) => value.endsWith('.json'))) {
    const value = JSON.parse(readFileSync(join(root, name), 'utf8'));
    if (value.deploymentId !== deploymentId && !terminalJournal(value)) return value.deploymentId ?? name;
  }
  return null;
}

function phase(journalPath, journal, persistedState, patch = {}) {
  assertActivationJournal(journal);
  const next = {
    ...journal,
    ...patch,
    persistedState,
    phaseSequence: journal.phaseSequence + 1,
    updatedAt: new Date().toISOString(),
  };
  assertActivationJournal(next);
  atomicWriteJson(journalPath, next, 0o600);
  if (process.env.BABY_X_CRASH_AFTER_PHASE === persistedState) throw new CrashInjected(persistedState);
  if (process.env.BABY_X_FAIL_AFTER_PHASE === persistedState) throw new Error(`failure injected after ${persistedState}`);
  return next;
}

export function requestDigest(options) {
  return sha256(canonicalize({
    deploymentId: options.deploymentId,
    candidate: options.candidate,
    commit: options.commit,
    tree: options.tree,
    expectedCurrentCommit: options.expectedCurrentCommit,
    expectedCurrentTree: options.expectedCurrentTree,
    reason: options.reason,
  }));
}

export async function activateRelease(options) {
  const installRoot = resolve(options.installRoot ?? '/opt/baby-x');
  const releaseRoot = realpathSync(join(installRoot, 'releases'));
  const stateRoot = resolve(options.stateRoot ?? '/var/lib/baby-x');
  const deploymentsRoot = join(stateRoot, 'deployments');
  mkdirSync(deploymentsRoot, { recursive: true, mode: 0o700 });
  const deploymentId = options.deploymentId;
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(deploymentId)) throw new Error('deployment ID is invalid');
  const journalPath = join(deploymentsRoot, `${deploymentId}.json`);
  const digest = requestDigest(options);
  let journal;
  if (existsSync(journalPath)) {
    journal = assertActivationJournal(JSON.parse(readFileSync(journalPath, 'utf8')));
    if (journal.creationRequestDigest !== digest) throw new Error('deployment idempotency conflict');
    if (terminalJournal(journal)) return journal;
  } else {
    const conflict = unresolvedDeployment(stateRoot, deploymentId);
    if (conflict !== null) throw new Error(`concurrent deployment ownership conflict: ${conflict}`);
    const candidate = verifyRelease(options.candidate, { repository: 'StealthEyeLLC/baby-x', commit: options.commit, tree: options.tree }, { releaseRoot });
    const currentTarget = pointerTarget(join(installRoot, 'current'), releaseRoot);
    const previousTarget = pointerTarget(join(installRoot, 'previous'), releaseRoot, false);
    const currentIdentity = targetIdentity(currentTarget);
    const priorHealth = await gatewayHealth();
    if (currentIdentity.commit !== options.expectedCurrentCommit || currentIdentity.tree !== options.expectedCurrentTree) {
      journal = {
        schemaVersion: '1.0.0',
        deploymentId,
        repository: 'StealthEyeLLC/baby-x',
        candidateCommit: options.commit,
        candidateTree: options.tree,
        candidateReleasePath: candidate.releasePath,
        candidateManifestDigest: candidate.releaseManifestSha256,
        creationRequestDigest: digest,
        reason: options.reason,
        desiredState: 'ACTIVE',
        persistedState: 'BLOCKED',
        phaseSequence: 0,
        startedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        priorCurrentTarget: currentTarget,
        priorPreviousTarget: previousTarget,
        priorRollbackTarget: null,
        priorCommit: currentIdentity.commit,
        priorTree: currentIdentity.tree,
        priorServiceState: serviceState(),
        priorHealth,
        unitBackups: {},
        pointerSwitchState: 'pending',
        systemdReloadState: 'pending',
        serviceRestartState: 'pending',
        healthReadbackState: 'pending',
        runtimeIdentityState: 'pending',
        rollbackRequired: false,
        rollbackState: 'not-requested',
        error: { code: 'activation_compare_and_swap_conflict', message: 'current release no longer matches the approved prior identity' },
        completedAt: new Date().toISOString(),
        finalState: 'BLOCKED',
      };
      assertActivationJournal(journal);
      atomicWriteJson(journalPath, journal, 0o600);
      return journal;
    }
    const rollbackTarget = ensureLegacyRollbackTarget(currentTarget, releaseRoot, currentIdentity, deploymentId);
    const backupPaths = [
      ...CANONICAL_UNITS.map((unit) => join('/etc/systemd/system', unit)),
      '/etc/tmpfiles.d/baby-x.conf',
    ];
    const backups = backupFiles(backupPaths, join(deploymentsRoot, `${deploymentId}.unit-backup`));
    journal = {
      schemaVersion: '1.0.0',
      deploymentId,
      repository: 'StealthEyeLLC/baby-x',
      candidateCommit: options.commit,
      candidateTree: options.tree,
      candidateReleasePath: candidate.releasePath,
      candidateManifestDigest: candidate.releaseManifestSha256,
      creationRequestDigest: digest,
      reason: options.reason,
      desiredState: 'ACTIVE',
      persistedState: 'REQUESTED',
      phaseSequence: 0,
      startedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      priorCurrentTarget: currentTarget,
      priorPreviousTarget: previousTarget,
      priorRollbackTarget: rollbackTarget,
      priorCommit: currentIdentity.commit,
      priorTree: currentIdentity.tree,
      priorServiceState: serviceState(),
      priorHealth,
      unitBackups: backups,
      pointerSwitchState: 'pending',
      systemdReloadState: 'pending',
      serviceRestartState: 'pending',
      healthReadbackState: 'pending',
      runtimeIdentityState: 'pending',
      rollbackRequired: false,
      rollbackState: 'not-requested',
      error: null,
      finalState: null,
    };
    assertActivationJournal(journal);
    atomicWriteJson(journalPath, journal, 0o600);
  }

  try {
    const currentNow = pointerTarget(join(installRoot, 'current'), releaseRoot);
    if (journal.pointerSwitchState === 'pending') {
      const currentIdentity = targetIdentity(currentNow);
      if (currentIdentity.commit !== options.expectedCurrentCommit || currentIdentity.tree !== options.expectedCurrentTree) {
        throw new Error('activation_compare_and_swap_conflict');
      }
      prepareRuntimeAuthority(journal.candidateReleasePath);
      journal = phase(journalPath, journal, 'PREPARED', { activationCompareAndSwapPassed: true });
      journal = phase(journalPath, journal, 'SWITCHING_POINTERS', { pointerSwitchState: 'started' });
      atomicLink(journal.priorRollbackTarget, join(installRoot, 'previous'));
      atomicLink(journal.candidateReleasePath, join(installRoot, 'current'));
      journal = phase(journalPath, journal, 'POINTERS_SWITCHED', { pointerSwitchState: 'completed' });
    } else if (journal.pointerSwitchState === 'started') {
      const observed = pointerTarget(join(installRoot, 'current'), releaseRoot);
      if (observed === journal.priorCurrentTarget) atomicLink(journal.candidateReleasePath, join(installRoot, 'current'));
      else if (observed !== journal.candidateReleasePath) throw new Error('ambiguous pointer state during activation recovery');
      atomicLink(journal.priorRollbackTarget, join(installRoot, 'previous'));
      journal = phase(journalPath, journal, 'POINTERS_SWITCHED', { pointerSwitchState: 'completed' });
    } else if (currentNow !== journal.candidateReleasePath) {
      throw new Error('candidate pointer was changed after activation');
    }

    if (journal.systemdReloadState !== 'completed') {
      installCanonicalFiles(journal.candidateReleasePath);
      journal = phase(journalPath, journal, 'UNITS_INSTALLED', { systemdReloadState: 'started' });
      command('/usr/bin/systemctl', ['daemon-reload'], { timeout: 30_000 });
      journal = phase(journalPath, journal, 'SYSTEMD_RELOADED', { systemdReloadState: 'completed' });
    }
    if (journal.serviceRestartState !== 'completed') {
      journal = phase(journalPath, journal, 'RESTARTING_SERVICES', { serviceRestartState: 'started' });
      restartCandidate();
      journal = phase(journalPath, journal, 'SERVICES_RESTARTED', { serviceRestartState: 'completed' });
    }
    if (journal.healthReadbackState !== 'completed') {
      journal = phase(journalPath, journal, 'VERIFYING', { healthReadbackState: 'started' });
      const verification = JSON.parse(command('/bin/bash', [join(journal.candidateReleasePath, 'scripts', 'verify-local.sh')], {
        timeout: 60_000,
        env: {
          ...process.env,
          BABY_X_EXPECTED_COMMIT: options.commit,
          BABY_X_EXPECTED_TREE: options.tree,
          BABY_X_DEPLOYMENT_ID: deploymentId,
          BABY_X_INSTALL_UNITS: '1',
          BABY_X_FORBIDDEN_ROOTS: options.forbiddenRoots?.join(':') ?? '',
        },
      }));
      journal = phase(journalPath, journal, 'ACTIVE', {
        healthReadbackState: 'completed',
        runtimeIdentityState: 'completed',
        verification,
        completedAt: new Date().toISOString(),
        finalState: 'ACTIVE',
        rollbackRequired: false,
      });
    }
    return journal;
  } catch (error) {
    if (error instanceof CrashInjected) throw error;
    const message = error instanceof Error ? error.message : String(error);
    const mutated = journal.pointerSwitchState === 'started' || journal.pointerSwitchState === 'completed';
    if (!mutated) {
      journal = phase(journalPath, journal, 'FAILED', { error: { code: 'activation_failed', message }, finalState: 'FAILED', completedAt: new Date().toISOString() });
      return journal;
    }
    try {
      journal = phase(journalPath, journal, 'ROLLBACK_REQUESTED', {
        rollbackRequired: true,
        rollbackState: 'requested',
        error: { code: 'activation_failed', message },
      });
      restoreFiles(journal.unitBackups);
      atomicLink(journal.priorRollbackTarget, join(installRoot, 'current'));
      if (journal.priorPreviousTarget === null) {
        if (lstatExists(join(installRoot, 'previous'))) unlinkSync(join(installRoot, 'previous'));
      } else {
        atomicLink(journal.priorPreviousTarget, join(installRoot, 'previous'));
      }
      command('/usr/bin/systemctl', ['daemon-reload'], { timeout: 30_000 });
      restartPrior();
      const rollbackVerification = await verifyPrior(journal.priorRollbackTarget, { commit: journal.priorCommit, tree: journal.priorTree });
      journal = phase(journalPath, journal, 'ROLLED_BACK', {
        rollbackState: 'completed',
        rollbackVerification,
        completedAt: new Date().toISOString(),
        finalState: 'ROLLED_BACK',
      });
      return journal;
    } catch (rollbackError) {
      journal = phase(journalPath, journal, 'RECOVERY_REQUIRED', {
        rollbackState: 'failed',
        rollbackError: { code: 'rollback_failed', message: rollbackError instanceof Error ? rollbackError.message : String(rollbackError) },
        completedAt: new Date().toISOString(),
        finalState: 'RECOVERY_REQUIRED',
      });
      return journal;
    }
  }
}

export async function rollbackDeployment(options) {
  const installRoot = resolve(options.installRoot ?? '/opt/baby-x');
  const releaseRoot = realpathSync(join(installRoot, 'releases'));
  const stateRoot = resolve(options.stateRoot ?? '/var/lib/baby-x');
  const journalPath = join(stateRoot, 'deployments', `${options.deploymentId}.json`);
  if (!existsSync(journalPath)) throw new Error('deployment journal is absent');
  let journal = JSON.parse(readFileSync(journalPath, 'utf8'));
  if (journal.deploymentId !== options.deploymentId) throw new Error('deployment journal identity mismatch');
  if (journal.finalState === 'ROLLED_BACK') return journal;
  if (journal.finalState !== 'ACTIVE') throw new Error(`deployment is not active: ${journal.finalState ?? journal.persistedState ?? 'unknown'}`);
  const current = pointerTarget(join(installRoot, 'current'), releaseRoot);
  if (current !== journal.candidateReleasePath) throw new Error('manual rollback current pointer does not match the deployed candidate');
  const candidate = verifyRelease(current, {
    repository: 'StealthEyeLLC/baby-x',
    commit: journal.candidateCommit,
    tree: journal.candidateTree,
  }, { releaseRoot });
  const prior = pointerTarget(join(installRoot, 'previous'), releaseRoot);
  if (prior !== journal.priorRollbackTarget) throw new Error('manual rollback previous pointer does not match the preserved prior release');
  const priorIdentity = targetIdentity(prior);
  if (priorIdentity.commit !== journal.priorCommit || priorIdentity.tree !== journal.priorTree) {
    throw new Error('manual rollback prior release identity mismatch');
  }
  journal = phase(journalPath, journal, 'ROLLBACK_REQUESTED', {
    desiredState: 'ROLLED_BACK',
    rollbackRequired: true,
    rollbackState: 'requested',
    rollbackReason: options.reason,
  });
  try {
    restoreFiles(journal.unitBackups);
    atomicLink(prior, join(installRoot, 'current'));
    atomicLink(candidate.releasePath, join(installRoot, 'previous'));
    command('/usr/bin/systemctl', ['daemon-reload'], { timeout: 30_000 });
    restartPrior();
    const rollbackVerification = await verifyPrior(prior, priorIdentity);
    journal = phase(journalPath, journal, 'ROLLED_BACK', {
      rollbackState: 'completed',
      rollbackVerification,
      completedAt: new Date().toISOString(),
      finalState: 'ROLLED_BACK',
    });
    return journal;
  } catch (error) {
    journal = phase(journalPath, journal, 'RECOVERY_REQUIRED', {
      rollbackState: 'failed',
      rollbackError: {
        code: 'rollback_failed',
        message: error instanceof Error ? error.message : String(error),
      },
      completedAt: new Date().toISOString(),
      finalState: 'RECOVERY_REQUIRED',
    });
    return journal;
  }
}

async function main() {
  const args = parse(process.argv.slice(2));
  if (args.mode === 'rollback') {
    for (const name of ['deployment-id', 'reason']) {
      if (!args[name]) throw new Error(`--${name} is required`);
    }
    const journal = await rollbackDeployment({
      deploymentId: args['deployment-id'],
      reason: args.reason,
      installRoot: args['install-root'] ?? '/opt/baby-x',
      stateRoot: args['state-root'] ?? '/var/lib/baby-x',
    });
    process.stdout.write(`${JSON.stringify(journal)}\n`);
    if (journal.finalState !== 'ROLLED_BACK') process.exitCode = 1;
    return;
  }
  for (const name of ['deployment-id', 'candidate', 'commit', 'tree', 'expected-current', 'expected-current-tree', 'reason']) {
    if (!args[name]) throw new Error(`--${name} is required`);
  }
  const journal = await activateRelease({
    deploymentId: args['deployment-id'],
    candidate: args.candidate,
    commit: args.commit,
    tree: args.tree,
    expectedCurrentCommit: args['expected-current'],
    expectedCurrentTree: args['expected-current-tree'],
    reason: args.reason,
    installRoot: args['install-root'] ?? '/opt/baby-x',
    stateRoot: args['state-root'] ?? '/var/lib/baby-x',
    forbiddenRoots: (args['forbidden-roots'] ?? '').split(':').filter(Boolean),
  });
  process.stdout.write(`${JSON.stringify(journal)}\n`);
  if (journal.finalState !== 'ACTIVE') process.exitCode = journal.finalState === 'ROLLED_BACK' ? 2 : 1;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = error instanceof CrashInjected ? 75 : 1;
  });
}
