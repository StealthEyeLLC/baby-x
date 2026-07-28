import {
  chmodSync, chownSync, closeSync, constants, fchmodSync, fchownSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, readlinkSync, realpathSync, renameSync, rmdirSync, statSync, symlinkSync,
  unlinkSync, writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { randomUUID } from 'node:crypto';
import { canonicalize, sha256, type JsonObject } from '../core.ts';
import { RootFabricError, integer, strictObject, text } from './model.ts';
import type { BrokerEffectAdapter, BrokerEffectResult, RootBrokerRequest } from './broker.ts';

export interface FilesystemArtifactAuthority {
  capture(name: string, bytes: Buffer, metadata: JsonObject): Promise<{ artifactId: string; sha256: string; size: number }>;
  read(artifactId: string): Promise<Buffer>;
}

export const FILESYSTEM_EFFECT_OPERATIONS = Object.freeze([
  'filesystem.file.create',
  'filesystem.file.replace',
  'filesystem.file.remove',
  'filesystem.directory.create',
  'filesystem.directory.remove',
  'filesystem.metadata.update',
  'filesystem.symlink.replace',
  'filesystem.release-pointer.switch',
] as const);

type FilesystemOperation = typeof FILESYSTEM_EFFECT_OPERATIONS[number];
type ParentIdentity = { dev: number; ino: number };
type Confined = { root: string; path: string; parent: string; name: string; parentIdentity: ParentIdentity };

function lexists(path: string): boolean {
  try { lstatSync(path); return true; } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

function sameParent(path: string, expected: ParentIdentity): void {
  const current = lstatSync(path);
  if (!current.isDirectory() || current.dev !== expected.dev || current.ino !== expected.ino) throw new RootFabricError('parent_race', 'filesystem parent identity changed before mutation');
}

function confined(rootValue: unknown, pathValue: unknown, allowLeafSymlink = false): Confined {
  const rootInput = text(rootValue, 'root', 4_096);
  const relativePath = text(pathValue, 'path', 4_096);
  if (!isAbsolute(rootInput)) throw new RootFabricError('path_escape', 'confinement root must be absolute');
  if (isAbsolute(relativePath) || relativePath.includes('\0') || relativePath.split(/[\\/]/u).includes('..')) throw new RootFabricError('path_escape', 'path must be confined and relative');
  const root = realpathSync(rootInput);
  const path = resolve(root, relativePath);
  const rel = relative(root, path);
  if (rel === '' || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new RootFabricError('path_escape', 'path escapes confinement root or targets the root');
  const components = rel.split(sep);
  let cursor = root;
  for (let index = 0; index < components.length - 1; index += 1) {
    cursor = join(cursor, components[index]!);
    const info = lstatSync(cursor);
    if (info.isSymbolicLink()) throw new RootFabricError('symlink_escape', 'path contains an intermediate symlink');
    if (!info.isDirectory()) throw new RootFabricError('precondition_failed', 'path parent is not a directory');
  }
  const parent = dirname(path);
  const parentInfo = lstatSync(parent);
  if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink()) throw new RootFabricError('symlink_escape', 'path parent is not a stable directory');
  if (lexists(path)) {
    const leaf = lstatSync(path);
    if (leaf.isSymbolicLink() && !allowLeafSymlink) throw new RootFabricError('symlink_escape', 'direct symlink target is forbidden');
    if (leaf.isFile() && leaf.nlink > 1) throw new RootFabricError('hardlink_rejected', 'hard-linked file targets are forbidden');
  }
  return { root, path, parent, name: components.at(-1)!, parentIdentity: { dev: parentInfo.dev, ino: parentInfo.ino } };
}

export function filesystemState(path: string): JsonObject {
  if (!lexists(path)) return { exists: false };
  const info = lstatSync(path);
  const base: JsonObject = {
    exists: true, mode: info.mode & 0o7777, uid: info.uid, gid: info.gid, size: info.size,
    dev: info.dev, ino: info.ino, nlink: info.nlink,
    type: info.isFile() ? 'file' : info.isDirectory() ? 'directory' : info.isSymbolicLink() ? 'symlink' : 'unsupported',
  };
  if (info.isFile()) return { ...base, sha256: sha256(readFileSync(path)) };
  if (info.isSymbolicLink()) return { ...base, symlinkTarget: readlinkSync(path) };
  return base;
}

function syncParent(parent: string): void {
  const fd = openSync(parent, constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function atomicFile(path: string, data: Buffer, mode: number, uid: number | undefined, gid: number | undefined): void {
  const temporary = join(dirname(path), `.${randomUUID()}.babyx.tmp`);
  let fd: number | undefined;
  try {
    fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    writeFileSync(fd, data);
    fchmodSync(fd, mode);
    if (uid !== undefined || gid !== undefined) fchownSync(fd, uid ?? -1, gid ?? -1);
    fsyncSync(fd);
    closeSync(fd); fd = undefined;
    renameSync(temporary, path);
    syncParent(dirname(path));
  } catch (error) {
    if (fd !== undefined) try { closeSync(fd); } catch {}
    try { unlinkSync(temporary); } catch {}
    throw error;
  }
}

function atomicSymlink(path: string, target: string): void {
  const temporary = join(dirname(path), `.${randomUUID()}.babyx.link`);
  try {
    symlinkSync(target, temporary);
    renameSync(temporary, path);
    syncParent(dirname(path));
  } catch (error) {
    try { unlinkSync(temporary); } catch {}
    throw error;
  }
}

async function capturePrior(artifacts: FilesystemArtifactAuthority | undefined, transactionId: string, sequence: number, path: string): Promise<JsonObject> {
  const state = filesystemState(path);
  if (state.exists !== true || state.type !== 'file') return state;
  if (artifacts === undefined) throw new RootFabricError('preparation_failed', 'file rollback requires the canonical artifact authority');
  const bytes = readFileSync(path);
  const artifact = await artifacts.capture(`root-prior-${transactionId}-${sequence}`, bytes, { transactionId, path, state });
  if (artifact.sha256 !== state.sha256 || artifact.size !== bytes.length) throw new RootFabricError('preparation_failed', 'prior-state artifact verification failed');
  return { ...state, artifactId: artifact.artifactId, artifactSha256: artifact.sha256 };
}

function verifyExpected(input: JsonObject, current: JsonObject): void {
  if (input.expectedAbsent === true && current.exists === true) throw new RootFabricError('precondition_failed', 'target was expected to be absent');
  if (input.expectedSha256 !== undefined && current.sha256 !== text(input.expectedSha256, 'expectedSha256', 64)) throw new RootFabricError('expected_digest_mismatch', 'existing file digest does not match');
  if (input.expectedTarget !== undefined && current.symlinkTarget !== text(input.expectedTarget, 'expectedTarget', 4_096)) throw new RootFabricError('precondition_failed', 'existing symlink target does not match');
}

export class RootFilesystemEffects {
  constructor(private readonly options: { artifacts?: FilesystemArtifactAuthority; beforeMutation?: (target: JsonObject) => void } = {}) {}

  adapters(): BrokerEffectAdapter[] {
    return FILESYSTEM_EFFECT_OPERATIONS.map((operation) => ({ operation, version: '1.0.0', execute: (input, request) => this.execute(operation, input, request) }));
  }

  async execute(operation: FilesystemOperation, inputValue: JsonObject, request: RootBrokerRequest): Promise<BrokerEffectResult> {
    if (!FILESYSTEM_EFFECT_OPERATIONS.includes(operation)) throw new RootFabricError('unsupported_operation', `unsupported filesystem effect ${operation}`);
    const input = strictObject(inputValue, 'filesystem effect input', ['root', 'path', 'data', 'encoding', 'mode', 'uid', 'gid', 'target', 'expectedSha256', 'expectedAbsent', 'expectedTarget']);
    const allowLeafSymlink = operation === 'filesystem.symlink.replace' || operation === 'filesystem.release-pointer.switch';
    const target = confined(input.root, input.path, allowLeafSymlink);
    const prior = await capturePrior(this.options.artifacts, request.transactionId, request.transactionSequence, target.path);
    verifyExpected(input, prior);
    this.options.beforeMutation?.({ path: target.path, parent: target.parent, parentDev: target.parentIdentity.dev, parentIno: target.parentIdentity.ino });
    sameParent(target.parent, target.parentIdentity);

    if (operation === 'filesystem.file.create' || operation === 'filesystem.file.replace') {
      if (operation === 'filesystem.file.create' && prior.exists === true && input.expectedSha256 === undefined) throw new RootFabricError('precondition_failed', 'file create refuses an existing target without compare-and-swap');
      const encoding = input.encoding === 'base64' ? 'base64' : 'utf8';
      const data = Buffer.from(text(input.data, 'data', 67_108_864), encoding);
      atomicFile(target.path, data, integer(input.mode ?? 0o600, 'mode', 0, 0o7777), input.uid === undefined ? undefined : integer(input.uid, 'uid', 0, 2 ** 31 - 1), input.gid === undefined ? undefined : integer(input.gid, 'gid', 0, 2 ** 31 - 1));
    } else if (operation === 'filesystem.file.remove') {
      const current = lstatSync(target.path);
      if (!current.isFile() || current.nlink > 1) throw new RootFabricError('precondition_failed', 'target is not a single-link regular file');
      unlinkSync(target.path); syncParent(target.parent);
    } else if (operation === 'filesystem.directory.create') {
      if (prior.exists === true) throw new RootFabricError('precondition_failed', 'directory target already exists');
      mkdirSync(target.path, { mode: integer(input.mode ?? 0o700, 'mode', 0, 0o7777) }); syncParent(target.parent);
      if (input.uid !== undefined || input.gid !== undefined) chownSync(target.path, input.uid === undefined ? statSync(target.path).uid : integer(input.uid, 'uid', 0, 2 ** 31 - 1), input.gid === undefined ? statSync(target.path).gid : integer(input.gid, 'gid', 0, 2 ** 31 - 1));
    } else if (operation === 'filesystem.directory.remove') {
      const current = lstatSync(target.path); if (!current.isDirectory() || current.isSymbolicLink()) throw new RootFabricError('precondition_failed', 'target is not a directory');
      rmdirSync(target.path); syncParent(target.parent);
    } else if (operation === 'filesystem.metadata.update') {
      const current = lstatSync(target.path); if (current.isSymbolicLink() || (current.isFile() && current.nlink > 1)) throw new RootFabricError('precondition_failed', 'metadata target is unsafe');
      if (input.mode !== undefined) chmodSync(target.path, integer(input.mode, 'mode', 0, 0o7777));
      if (input.uid !== undefined || input.gid !== undefined) chownSync(target.path, input.uid === undefined ? current.uid : integer(input.uid, 'uid', 0, 2 ** 31 - 1), input.gid === undefined ? current.gid : integer(input.gid, 'gid', 0, 2 ** 31 - 1));
      syncParent(target.parent);
    } else {
      const linkTarget = text(input.target, 'target', 4_096);
      if (operation === 'filesystem.release-pointer.switch' && !linkTarget.startsWith('/opt/baby-x/releases/')) throw new RootFabricError('policy_denied', 'release pointer target must be an immutable Baby-X release');
      atomicSymlink(target.path, linkTarget);
    }
    const observed = filesystemState(target.path);
    return { classification: 'SUCCEEDED', result: { operation, priorState: prior, observedState: observed, targetDigest: sha256(canonicalize(observed)) }, cleanupState: { temporaryAbsent: true, parentIdentityVerified: true }, observationDigest: sha256(canonicalize({ operation, path: target.path, observed })) };
  }

  async restore(inputValue: JsonObject): Promise<JsonObject> {
    const input = strictObject(inputValue, 'filesystem restore input', ['root', 'path', 'priorState']);
    const target = confined(input.root, input.path, true);
    const prior = strictObject(input.priorState, 'priorState', ['exists', 'mode', 'uid', 'gid', 'size', 'dev', 'ino', 'nlink', 'type', 'sha256', 'symlinkTarget', 'artifactId', 'artifactSha256']);
    sameParent(target.parent, target.parentIdentity);
    if (prior.exists !== true) {
      if (lexists(target.path)) {
        const current = lstatSync(target.path);
        if (current.isDirectory() && !current.isSymbolicLink()) rmdirSync(target.path); else unlinkSync(target.path);
        syncParent(target.parent);
      }
    } else if (prior.type === 'file') {
      if (this.options.artifacts === undefined) throw new RootFabricError('rollback_failed', 'file restoration requires the canonical artifact authority');
      const bytes = await this.options.artifacts.read(text(prior.artifactId, 'artifactId', 256));
      if (sha256(bytes) !== text(prior.artifactSha256, 'artifactSha256', 64) || sha256(bytes) !== text(prior.sha256, 'sha256', 64)) throw new RootFabricError('rollback_failed', 'prior artifact digest mismatch');
      atomicFile(target.path, bytes, integer(prior.mode, 'mode', 0, 0o7777), integer(prior.uid, 'uid', 0, 2 ** 31 - 1), integer(prior.gid, 'gid', 0, 2 ** 31 - 1));
    } else if (prior.type === 'symlink') {
      atomicSymlink(target.path, text(prior.symlinkTarget, 'symlinkTarget', 4_096));
    } else if (prior.type === 'directory') {
      if (!lexists(target.path)) mkdirSync(target.path, { mode: integer(prior.mode, 'mode', 0, 0o7777) });
      chmodSync(target.path, integer(prior.mode, 'mode', 0, 0o7777)); chownSync(target.path, integer(prior.uid, 'uid', 0, 2 ** 31 - 1), integer(prior.gid, 'gid', 0, 2 ** 31 - 1)); syncParent(target.parent);
    } else throw new RootFabricError('rollback_failed', 'unsupported prior-state type');
    const observed = filesystemState(target.path);
    const valid = prior.exists !== true ? observed.exists === false : observed.type === prior.type && (prior.type !== 'file' || observed.sha256 === prior.sha256) && (prior.type !== 'symlink' || observed.symlinkTarget === prior.symlinkTarget);
    if (!valid) throw new RootFabricError('rollback_failed', 'rollback readback does not match prior state');
    return { restored: true, observedState: observed, observationDigest: sha256(canonicalize(observed)) };
  }
}
