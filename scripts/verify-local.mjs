#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, readlinkSync, realpathSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import process from 'node:process';
import { verifyRelease } from './lib/release-contract.mjs';

const NODE = '/opt/node-v24.18.0-linux-x64/bin/node';
const REQUIRED_H = ['babyx.root.observation.start', 'babyx.root.observation.get', 'babyx.root.observation.record', 'babyx.root.observation.finalize'];
const REQUIRED_I = ['babyx.root.credential.lease', 'babyx.root.credential.deliver', 'babyx.root.credential.get', 'babyx.root.credential.list', 'babyx.root.credential.revoke', 'babyx.root.credential.clean'];
const REQUIRED_J = ['babyx.root.freeze.get', 'babyx.root.freeze.set', 'babyx.root.kill', 'babyx.root.reconcile'];
const UNITS = ['baby-x-root.slice', 'baby-x-root-broker.socket', 'baby-x-root-broker.service', 'baby-x.socket', 'baby-x.service', 'baby-x-gateway.service'];

function parse(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith('--') || value === undefined) throw new Error('verify-local arguments must be --name value pairs');
    result[key.slice(2)] = value;
  }
  return result;
}

function command(executable, argv, options = {}) {
  const result = spawnSync(executable, argv, { encoding: 'utf8', timeout: options.timeout ?? 10_000, env: options.env ?? process.env });
  if (result.status !== 0) throw new Error(`${executable} ${argv.join(' ')} failed: ${result.stderr.trim()}`);
  return result.stdout.trim();
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function serviceProperties(unit, properties) {
  const output = command('/usr/bin/systemctl', ['show', unit, ...properties.flatMap((property) => ['-p', property])]);
  return Object.fromEntries(output.split('\n').filter(Boolean).map((line) => {
    const split = line.indexOf('=');
    return [line.slice(0, split), line.slice(split + 1)];
  }));
}

function assertActive(unit) {
  const state = command('/usr/bin/systemctl', ['is-active', unit]);
  if (state !== 'active') throw new Error(`${unit} is not active`);
}

function account(name, flag) {
  return Number(command('/usr/bin/id', [flag, name]));
}

function groupId(name) {
  const record = command('/usr/bin/getent', ['group', name]);
  const fields = record.split(':');
  if (fields.length < 3 || !/^[0-9]+$/u.test(fields[2] ?? '')) throw new Error(`group ${name} has no numeric GID`);
  return Number(fields[2]);
}

function socketIdentity(path, expected) {
  const metadata = lstatSync(path);
  if (!metadata.isSocket()) throw new Error(`${path} is not a Unix socket`);
  if (metadata.uid !== expected.uid || metadata.gid !== expected.gid || (metadata.mode & 0o777) !== expected.mode) {
    throw new Error(`${path} ownership or mode mismatch`);
  }
  return { path, uid: metadata.uid, gid: metadata.gid, mode: (metadata.mode & 0o777).toString(8).padStart(4, '0') };
}

function keyIdentity(path, expected) {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error(`${path} is not a regular key file`);
  if (metadata.uid !== expected.uid || metadata.gid !== expected.gid || (metadata.mode & 0o777) !== expected.mode) {
    throw new Error(`${path} key ownership or mode mismatch`);
  }
  return { path, uid: metadata.uid, gid: metadata.gid, mode: (metadata.mode & 0o777).toString(8).padStart(4, '0') };
}

function assertProcess(unit, expectedUid, requiredArgument, forbiddenRoots) {
  const properties = serviceProperties(unit, ['MainPID', 'User', 'Group', 'ExecStart', 'ActiveState']);
  const pid = Number(properties.MainPID);
  if (properties.ActiveState !== 'active' || !Number.isSafeInteger(pid) || pid < 1) throw new Error(`${unit} has no active process`);
  const processOwner = statSync(`/proc/${pid}`).uid;
  if (processOwner !== expectedUid) throw new Error(`${unit} process UID mismatch`);
  const commandLine = readFileSync(`/proc/${pid}/cmdline`).toString('utf8').split('\0').filter(Boolean);
  if (!commandLine.includes(requiredArgument)) throw new Error(`${unit} is not executing the immutable current entrypoint`);
  const cwd = realpathSync(`/proc/${pid}/cwd`);
  for (const root of forbiddenRoots) {
    if (cwd === root || cwd.startsWith(`${root}/`)) throw new Error(`${unit} runs from a forbidden mutable workspace`);
  }
  return { unit, pid, uid: processOwner, commandLine, cwd };
}

async function gatewayHealth(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(5_000) });
  if (!response.ok) throw new Error(`gateway health returned HTTP ${response.status}`);
  return response.json();
}

function unresolvedJournals(stateRoot, ownDeploymentId) {
  const root = join(stateRoot, 'deployments');
  let names;
  try {
    names = readdirSync(root).filter((name) => name.endsWith('.json'));
  } catch {
    return [];
  }
  const terminal = new Set(['ACTIVE', 'ROLLED_BACK', 'BLOCKED', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS']);
  return names.flatMap((name) => {
    const value = JSON.parse(readFileSync(join(root, name), 'utf8'));
    if (value.deploymentId === ownDeploymentId || terminal.has(value.finalState)) return [];
    return [{ deploymentId: value.deploymentId, finalState: value.finalState ?? null, phase: value.persistedState ?? null }];
  });
}

export async function verifyLocal(options) {
  const installRoot = resolve(options.installRoot ?? '/opt/baby-x');
  const stateRoot = resolve(options.stateRoot ?? '/var/lib/baby-x');
  const currentLink = join(installRoot, 'current');
  if (!lstatSync(currentLink).isSymbolicLink()) throw new Error('current release pointer is not a symlink');
  const current = realpathSync(currentLink);
  const releases = realpathSync(join(installRoot, 'releases'));
  if (current !== releases && !current.startsWith(`${releases}/`)) throw new Error('current release pointer escapes the release root');
  const verified = verifyRelease(current, {
    repository: 'StealthEyeLLC/baby-x',
    commit: options.commit,
    tree: options.tree,
  }, { releaseRoot: releases });
  const manifest = verified.manifest;
  const rawTarget = readlinkSync(currentLink);
  const resolvedTarget = resolve(dirname(currentLink), rawTarget);
  if (realpathSync(resolvedTarget) !== current) throw new Error('current pointer target is ambiguous');

  const environment = {
    ...process.env,
    BABY_X_REQUIRE_RELEASE_IDENTITY: '1',
    BABY_X_RELEASE_MANIFEST: join(current, 'release.json'),
  };
  const cli = join(current, 'runtime', 'cli', 'main.js');
  const direct = JSON.parse(command(NODE, [cli, 'describe'], { env: environment }));
  const directHealth = JSON.parse(command(NODE, [cli, 'health'], { env: environment }));
  const registry = JSON.parse(command(NODE, [cli, 'call', 'babyx.root.effect.registry', '{}'], { env: environment }));
  const operations = direct.operations.map((entry) => entry.operation);
  const facts = {
    catalogVersion: direct.operationCatalogVersion,
    catalogSha256: direct.operationCatalogSha256,
    totalOperations: operations.length,
    rootOperations: operations.filter((name) => name.startsWith('babyx.root.')).length,
    rootFabricDispatcherOperations: direct.catalog?.rootFabricDispatcherOperations,
    typedEffects: registry.effects.length,
    duplicateOperations: operations.length - new Set(operations).size,
    hPresent: REQUIRED_H.every((name) => operations.includes(name)),
    iPresent: REQUIRED_I.every((name) => operations.includes(name)),
    jPresent: REQUIRED_J.every((name) => operations.includes(name)),
  };
  for (const [name, expected] of [
    ['catalogVersion', '3.4.0'],
    ['catalogSha256', '87cdc4ab4ab24b193352dab07f9bf92a755bc4e7f2b1f4d8ec88936f47a5f900'],
    ['totalOperations', 230],
    ['rootOperations', 51],
    ['rootFabricDispatcherOperations', 40],
    ['typedEffects', 31],
    ['duplicateOperations', 0],
  ]) if (facts[name] !== expected) throw new Error(`runtime ${name} mismatch`);
  if (!facts.hPresent || !facts.iPresent || !facts.jPresent) throw new Error('runtime is missing an H, I, or J operation');
  if (
    direct.sourceCommit !== manifest.commit
    || direct.sourceTree !== manifest.tree
    || direct.release?.releaseIdentity !== manifest.releaseIdentity
    || direct.release?.manifestSha256 !== verified.releaseManifestSha256
    || directHealth.ready !== true
    || directHealth.commit !== manifest.commit
    || directHealth.tree !== manifest.tree
  ) throw new Error('direct runtime immutable identity mismatch');

  const result = {
    release: verified,
    direct: {
      product: direct.product,
      commit: direct.sourceCommit,
      tree: direct.sourceTree,
      releaseIdentity: direct.release.releaseIdentity,
      manifestSha256: direct.release.manifestSha256,
    },
    catalog: facts,
  };
  if (options.units !== false) {
    for (const unit of UNITS) assertActive(unit);
    const gateway = await gatewayHealth(options.healthUrl ?? 'http://127.0.0.1:2097/healthz');
    if (
      gateway.ok !== true
      || gateway.product !== 'baby-x-gateway'
      || gateway.runtime?.repository !== 'StealthEyeLLC/baby-x'
      || gateway.runtime?.sourceCommit !== manifest.commit
      || gateway.runtime?.sourceTree !== manifest.tree
      || gateway.runtime?.release?.releaseIdentity !== manifest.releaseIdentity
      || gateway.runtime?.operationCatalogVersion !== '3.4.0'
      || gateway.runtime?.operationCount !== 230
      || gateway.runtime?.catalog?.typedEffects !== 31
    ) throw new Error('live gateway-to-runtime health identity mismatch');
    const inventory = JSON.parse(readFileSync(join(current, 'ops', 'service-inventory.json'), 'utf8'));
    for (const unit of UNITS) {
      const expectedDigest = inventory.services?.[unit]?.sha256;
      const installed = join('/etc/systemd/system', unit);
      if (sha256(installed) !== expectedDigest || sha256(join(current, 'ops', 'systemd', unit)) !== expectedDigest) {
        throw new Error(`${unit} installed digest mismatch`);
      }
    }
    const runtimeUid = account('fix-exec', '-u');
    const gatewayUid = account('fix-mcp', '-u');
    const horseyGid = groupId('horsey');
    const processes = [
      assertProcess('baby-x.service', runtimeUid, '/opt/baby-x/current/runtime/cli/main.js', options.forbiddenRoots ?? []),
      assertProcess('baby-x-gateway.service', gatewayUid, '/opt/baby-x/current/gateway/main.js', options.forbiddenRoots ?? []),
      assertProcess('baby-x-root-broker.service', 0, '/opt/baby-x/current/runtime/root-broker-entry.js', options.forbiddenRoots ?? []),
    ];
    const sockets = [
      socketIdentity('/run/horsey/baby-x.sock', { uid: 0, gid: horseyGid, mode: 0o660 }),
      socketIdentity('/run/baby-x/root-broker.sock', { uid: 0, gid: horseyGid, mode: 0o660 }),
    ];
    const keys = [
      keyIdentity('/etc/baby-x/gateway-authority-private.pem', { uid: gatewayUid, gid: horseyGid, mode: 0o600 }),
      keyIdentity('/etc/baby-x/gateway-authority-public.pem', { uid: 0, gid: horseyGid, mode: 0o640 }),
      keyIdentity('/etc/baby-x/proof-private.pem', { uid: runtimeUid, gid: horseyGid, mode: 0o600 }),
      keyIdentity('/etc/baby-x/proof-public.pem', { uid: 0, gid: horseyGid, mode: 0o640 }),
      keyIdentity('/etc/baby-x/root-broker-private.pem', { uid: 0, gid: 0, mode: 0o600 }),
      keyIdentity('/etc/baby-x/root-broker-public.pem', { uid: 0, gid: horseyGid, mode: 0o640 }),
    ];
    const state = statSync(stateRoot);
    const deployments = statSync(join(stateRoot, 'deployments'));
    if (state.uid !== runtimeUid || (state.mode & 0o777) !== 0o750) throw new Error('runtime state root authority mismatch');
    if (deployments.uid !== 0 || (deployments.mode & 0o777) !== 0o700) throw new Error('deployment journal authority mismatch');
    const unresolved = unresolvedJournals(stateRoot, options.deploymentId);
    if (unresolved.length > 0) throw new Error('an unresolved activation journal exists');
    command(NODE, [join(current, 'scripts', 'root-broker-smoke.mjs'), 'wrong-peer', '/run/baby-x/root-broker.sock']);
    command('/usr/sbin/runuser', ['-u', 'fix-exec', '-g', 'horsey', '--', NODE, join(current, 'scripts', 'root-broker-smoke.mjs'), 'allowed', '/run/baby-x/root-broker.sock']);
    result.gateway = gateway;
    result.processes = processes;
    result.sockets = sockets;
    result.keyAuthority = keys;
    result.unresolvedActivations = unresolved;
    result.rootBrokerSmoke = { wrongPeerRejected: true, malformedRejected: true, oversizedRejected: true, unknownRejected: true, arbitraryRootShell: false, tcpListener: false };
  }
  return result;
}

async function main() {
  const args = parse(process.argv.slice(2));
  const result = await verifyLocal({
    installRoot: args['install-root'],
    stateRoot: args['state-root'],
    commit: args.commit,
    tree: args.tree,
    deploymentId: args['deployment-id'],
    units: args.units !== '0',
    healthUrl: args['health-url'],
    forbiddenRoots: (args['forbidden-roots'] ?? '').split(':').filter(Boolean),
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
