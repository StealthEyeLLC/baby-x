import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, posix, relative, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { canonicalize, sha256, type JsonObject } from '../core.ts';

export type DeterministicEntryType = 'file' | 'directory' | 'symlink';

export interface DeterministicArchiveEntry extends JsonObject {
  path: string;
  type: DeterministicEntryType;
  mode: number;
  size: number;
  sha256: string;
  linkTarget?: string;
  data?: string;
  dataEncoding?: 'base64';
}

export interface ArchiveLimits extends JsonObject {
  maxEntries: number;
  maxExpandedBytes: number;
  maxPathBytes: number;
  maxSymlinkBytes: number;
}

export const DEFAULT_ARCHIVE_LIMITS: Readonly<ArchiveLimits> = Object.freeze({
  maxEntries: 100_000,
  maxExpandedBytes: 2 * 1024 * 1024 * 1024,
  maxPathBytes: 255,
  maxSymlinkBytes: 4_096,
});

export class ReleaseArchiveError extends Error {
  readonly code: string;
  readonly details: JsonObject;
  constructor(code: string, message: string, details: JsonObject = {}) {
    super(message);
    this.name = 'ReleaseArchiveError';
    this.code = code;
    this.details = details;
  }
}

function octal(value: number, width: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0) throw new ReleaseArchiveError('release_archive_invalid_number', 'tar numeric value is invalid', { value, width });
  const text = value.toString(8);
  if (text.length > width - 1) throw new ReleaseArchiveError('release_archive_numeric_overflow', 'tar numeric value does not fit field', { value, width });
  return Buffer.from(`${text.padStart(width - 1, '0')}\0`, 'ascii');
}

function writeField(header: Buffer, offset: number, length: number, value: Buffer): void {
  if (value.length > length) throw new ReleaseArchiveError('release_archive_field_overflow', 'tar header field is too long', { offset, length, actual: value.length });
  value.copy(header, offset);
}

function splitTarPath(path: string): { name: string; prefix: string } {
  const bytes = Buffer.byteLength(path);
  if (bytes <= 100) return { name: path, prefix: '' };
  const segments = path.split('/');
  for (let index = 1; index < segments.length; index += 1) {
    const prefix = segments.slice(0, index).join('/');
    const name = segments.slice(index).join('/');
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(name) <= 100) return { name, prefix };
  }
  throw new ReleaseArchiveError('release_archive_path_too_long', 'path cannot be represented by ustar', { path, bytes });
}

export function normalizeArchivePath(value: string): string {
  if (value.includes('\0') || value.includes('\\') || isAbsolute(value)) throw new ReleaseArchiveError('release_archive_unsafe_path', 'archive path must be relative POSIX path', { path: value });
  const normalized = posix.normalize(value);
  if (normalized === '.' || normalized === '' || normalized === '..' || normalized.startsWith('../') || normalized.includes('/../') || normalized.startsWith('/')) {
    throw new ReleaseArchiveError('release_archive_unsafe_path', 'archive path escapes root', { path: value });
  }
  return normalized.replace(/^\.\//u, '');
}

export function assertSafeSymlink(path: string, target: string): void {
  if (target.includes('\0') || target.includes('\\') || isAbsolute(target)) {
    throw new ReleaseArchiveError('release_archive_symlink_escape', 'symlink target must be relative', { path, target });
  }
  const parent = posix.dirname(path);
  const resolved = posix.normalize(posix.join(parent, target));
  if (resolved === '..' || resolved.startsWith('../') || resolved.startsWith('/')) {
    throw new ReleaseArchiveError('release_archive_symlink_escape', 'symlink target escapes archive root', { path, target });
  }
}

function entryBytes(entry: DeterministicArchiveEntry): Buffer {
  if (entry.type === 'directory') return Buffer.alloc(0);
  if (entry.type === 'symlink') return Buffer.from(entry.linkTarget ?? '', 'utf8');
  if (entry.dataEncoding !== 'base64' || typeof entry.data !== 'string') throw new ReleaseArchiveError('release_archive_missing_bytes', 'file entry lacks base64 bytes', { path: entry.path });
  return Buffer.from(entry.data, 'base64');
}

export function validateDeterministicEntries(entries: readonly DeterministicArchiveEntry[], limits: ArchiveLimits = DEFAULT_ARCHIVE_LIMITS): DeterministicArchiveEntry[] {
  if (entries.length > limits.maxEntries) throw new ReleaseArchiveError('release_archive_entry_limit', 'archive has too many entries', { count: entries.length, limit: limits.maxEntries });
  const normalized: DeterministicArchiveEntry[] = [];
  const paths = new Set<string>();
  let expanded = 0;
  for (const original of entries) {
    const path = normalizeArchivePath(String(original.path));
    if (Buffer.byteLength(path) > limits.maxPathBytes) throw new ReleaseArchiveError('release_archive_path_too_long', 'archive path exceeds configured limit', { path });
    if (paths.has(path)) throw new ReleaseArchiveError('release_archive_duplicate_path', 'archive contains duplicate path', { path });
    paths.add(path);
    if (!['file', 'directory', 'symlink'].includes(original.type)) throw new ReleaseArchiveError('release_archive_special_file', 'unsupported archive entry type', { path, type: original.type });
    if (!Number.isInteger(original.mode) || original.mode < 0 || original.mode > 0o7777 || (original.mode & 0o6000) !== 0) {
      throw new ReleaseArchiveError('release_archive_unsafe_mode', 'setuid/setgid or invalid mode is forbidden', { path, mode: original.mode });
    }
    const bytes = entryBytes(original);
    if (original.type === 'symlink') {
      const target = original.linkTarget ?? bytes.toString('utf8');
      if (Buffer.byteLength(target) > limits.maxSymlinkBytes) throw new ReleaseArchiveError('release_archive_symlink_too_long', 'symlink target exceeds limit', { path });
      assertSafeSymlink(path, target);
      const digest = sha256(Buffer.from(target, 'utf8'));
      if (original.sha256 !== digest || original.size !== Buffer.byteLength(target)) throw new ReleaseArchiveError('release_archive_manifest_mismatch', 'symlink manifest digest or size mismatch', { path });
      normalized.push({ path, type: 'symlink', mode: original.mode, size: original.size, sha256: digest, linkTarget: target });
      continue;
    }
    if (original.type === 'directory') {
      if (original.size !== 0 || original.sha256 !== sha256(Buffer.alloc(0))) throw new ReleaseArchiveError('release_archive_manifest_mismatch', 'directory manifest must have empty digest', { path });
      normalized.push({ path, type: 'directory', mode: original.mode, size: 0, sha256: original.sha256 });
      continue;
    }
    expanded += bytes.length;
    if (expanded > limits.maxExpandedBytes) throw new ReleaseArchiveError('release_archive_expanded_limit', 'archive expanded bytes exceed limit', { expanded, limit: limits.maxExpandedBytes });
    const digest = sha256(bytes);
    if (original.size !== bytes.length || original.sha256 !== digest) throw new ReleaseArchiveError('release_archive_manifest_mismatch', 'file manifest digest or size mismatch', { path });
    normalized.push({ path, type: 'file', mode: original.mode, size: bytes.length, sha256: digest, data: bytes.toString('base64'), dataEncoding: 'base64' });
  }
  normalized.sort((left, right) => left.path.localeCompare(right.path));
  return normalized;
}

function tarHeader(entry: DeterministicArchiveEntry, epoch: number): Buffer {
  const header = Buffer.alloc(512, 0);
  const path = entry.type === 'directory' && !entry.path.endsWith('/') ? `${entry.path}/` : entry.path;
  const split = splitTarPath(path);
  writeField(header, 0, 100, Buffer.from(split.name, 'utf8'));
  writeField(header, 100, 8, octal(entry.mode & 0o777, 8));
  writeField(header, 108, 8, octal(0, 8));
  writeField(header, 116, 8, octal(0, 8));
  writeField(header, 124, 12, octal(entry.type === 'file' ? entry.size : 0, 12));
  writeField(header, 136, 12, octal(epoch, 12));
  header.fill(0x20, 148, 156);
  header[156] = entry.type === 'file' ? 0x30 : entry.type === 'directory' ? 0x35 : 0x32;
  if (entry.type === 'symlink') writeField(header, 157, 100, Buffer.from(entry.linkTarget ?? '', 'utf8'));
  writeField(header, 257, 6, Buffer.from('ustar\0', 'ascii'));
  writeField(header, 263, 2, Buffer.from('00', 'ascii'));
  writeField(header, 265, 32, Buffer.from('root', 'ascii'));
  writeField(header, 297, 32, Buffer.from('root', 'ascii'));
  writeField(header, 329, 8, octal(0, 8));
  writeField(header, 337, 8, octal(0, 8));
  if (split.prefix !== '') writeField(header, 345, 155, Buffer.from(split.prefix, 'utf8'));
  let checksum = 0;
  for (const byte of header) checksum += byte;
  const checksumText = checksum.toString(8).padStart(6, '0');
  writeField(header, 148, 8, Buffer.from(`${checksumText}\0 `, 'ascii'));
  return header;
}

export function createDeterministicTar(entries: readonly DeterministicArchiveEntry[], epoch: number, limits: ArchiveLimits = DEFAULT_ARCHIVE_LIMITS): Buffer {
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw new ReleaseArchiveError('release_archive_invalid_epoch', 'deterministic epoch must be non-negative integer', { epoch });
  const normalized = validateDeterministicEntries(entries, limits);
  const chunks: Buffer[] = [];
  for (const entry of normalized) {
    chunks.push(tarHeader(entry, epoch));
    if (entry.type === 'file') {
      const bytes = entryBytes(entry);
      chunks.push(bytes);
      const padding = (512 - (bytes.length % 512)) % 512;
      if (padding > 0) chunks.push(Buffer.alloc(padding, 0));
    }
  }
  chunks.push(Buffer.alloc(1024, 0));
  return Buffer.concat(chunks);
}

function parseOctal(field: Buffer, name: string): number {
  const text = field.toString('ascii').replace(/\0.*$/u, '').trim();
  if (text === '') return 0;
  if (!/^[0-7]+$/u.test(text)) throw new ReleaseArchiveError('release_archive_invalid_header', `invalid tar ${name}`, { value: text });
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value)) throw new ReleaseArchiveError('release_archive_invalid_header', `tar ${name} exceeds safe integer`, { value: text });
  return value;
}

function readString(field: Buffer): string {
  const zero = field.indexOf(0);
  return field.subarray(0, zero < 0 ? field.length : zero).toString('utf8');
}

export function parseDeterministicTar(bytes: Buffer, limits: ArchiveLimits = DEFAULT_ARCHIVE_LIMITS): DeterministicArchiveEntry[] {
  const entries: DeterministicArchiveEntry[] = [];
  let offset = 0;
  let expanded = 0;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    offset += 512;
    if (header.every((byte) => byte === 0)) {
      if (offset + 512 > bytes.length || !bytes.subarray(offset, offset + 512).every((byte) => byte === 0)) throw new ReleaseArchiveError('release_archive_invalid_terminator', 'tar archive lacks two zero blocks');
      offset += 512;
      if (!bytes.subarray(offset).every((byte) => byte === 0)) throw new ReleaseArchiveError('release_archive_trailing_bytes', 'tar archive has non-zero trailing bytes');
      return validateDeterministicEntries(entries, limits);
    }
    if (entries.length >= limits.maxEntries) throw new ReleaseArchiveError('release_archive_entry_limit', 'archive has too many entries');
    const storedChecksum = parseOctal(header.subarray(148, 156), 'checksum');
    const copy = Buffer.from(header);
    copy.fill(0x20, 148, 156);
    let checksum = 0;
    for (const byte of copy) checksum += byte;
    if (checksum !== storedChecksum) throw new ReleaseArchiveError('release_archive_checksum', 'tar header checksum mismatch', { offset: offset - 512 });
    const name = readString(header.subarray(0, 100));
    const prefix = readString(header.subarray(345, 500));
    const rawPath = prefix === '' ? name : `${prefix}/${name}`;
    const path = normalizeArchivePath(rawPath.replace(/\/$/u, ''));
    const mode = parseOctal(header.subarray(100, 108), 'mode');
    const size = parseOctal(header.subarray(124, 136), 'size');
    const typeFlag = String.fromCharCode(header[156] ?? 0);
    if ((mode & 0o6000) !== 0) throw new ReleaseArchiveError('release_archive_unsafe_mode', 'setuid/setgid archive entries are forbidden', { path, mode });
    if (typeFlag === '5') {
      if (size !== 0) throw new ReleaseArchiveError('release_archive_invalid_header', 'directory entry has non-zero size', { path });
      entries.push({ path, type: 'directory', mode, size: 0, sha256: sha256(Buffer.alloc(0)) });
      continue;
    }
    if (typeFlag === '2') {
      if (size !== 0) throw new ReleaseArchiveError('release_archive_invalid_header', 'symlink entry has non-zero body size', { path });
      const target = readString(header.subarray(157, 257));
      assertSafeSymlink(path, target);
      entries.push({ path, type: 'symlink', mode, size: Buffer.byteLength(target), sha256: sha256(Buffer.from(target, 'utf8')), linkTarget: target });
      continue;
    }
    if (typeFlag !== '0' && typeFlag !== '\0') throw new ReleaseArchiveError('release_archive_special_file', 'tar contains unsupported special file', { path, typeFlag });
    if (offset + size > bytes.length) throw new ReleaseArchiveError('release_archive_truncated', 'tar file body is truncated', { path, size });
    const data = Buffer.from(bytes.subarray(offset, offset + size));
    offset += size;
    offset += (512 - (size % 512)) % 512;
    expanded += size;
    if (expanded > limits.maxExpandedBytes) throw new ReleaseArchiveError('release_archive_expanded_limit', 'archive expanded bytes exceed limit', { expanded, limit: limits.maxExpandedBytes });
    entries.push({ path, type: 'file', mode, size, sha256: sha256(data), data: data.toString('base64'), dataEncoding: 'base64' });
  }
  throw new ReleaseArchiveError('release_archive_truncated', 'tar archive terminated unexpectedly');
}

export function compressZstd(tar: Buffer, zstdPath = '/usr/bin/zstd', maxOutputBytes = 2 * 1024 * 1024 * 1024): Buffer {
  if (!existsSync(zstdPath)) throw new ReleaseArchiveError('release_zstd_unavailable', 'zstd executable is unavailable', { zstdPath });
  const result = spawnSync(zstdPath, ['-q', '-T1', '-19', '--stdout'], { input: tar, maxBuffer: maxOutputBytes });
  if (result.status !== 0) throw new ReleaseArchiveError('release_zstd_failed', 'zstd compression failed', { status: result.status, stderr: result.stderr.toString('utf8').slice(0, 1024) });
  return result.stdout;
}

export function decompressZstd(archive: Buffer, zstdPath = '/usr/bin/zstd', maxOutputBytes = 2 * 1024 * 1024 * 1024): Buffer {
  if (!existsSync(zstdPath)) throw new ReleaseArchiveError('release_zstd_unavailable', 'zstd executable is unavailable', { zstdPath });
  const result = spawnSync(zstdPath, ['-q', '-d', '--stdout'], { input: archive, maxBuffer: maxOutputBytes });
  if (result.status !== 0) throw new ReleaseArchiveError('release_zstd_failed', 'zstd decompression failed', { status: result.status, stderr: result.stderr.toString('utf8').slice(0, 1024) });
  return result.stdout;
}

function ensureWithinRoot(root: string, path: string): void {
  const rootResolved = resolve(root);
  const target = resolve(path);
  if (target !== rootResolved && !target.startsWith(`${rootResolved}${sep}`)) throw new ReleaseArchiveError('release_archive_unsafe_path', 'extraction path escapes root', { root, path });
}

function fsyncPath(path: string): void {
  const fd = openSync(path, 'r');
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

export function extractValidatedEntries(entriesValue: readonly DeterministicArchiveEntry[], destination: string, limits: ArchiveLimits = DEFAULT_ARCHIVE_LIMITS): JsonObject {
  const entries = validateDeterministicEntries(entriesValue, limits);
  if (existsSync(destination)) throw new ReleaseArchiveError('release_materialization_conflict', 'extraction destination already exists', { destination });
  mkdirSync(destination, { recursive: false, mode: 0o700 });
  try {
    for (const entry of entries.filter((value) => value.type === 'directory')) {
      const target = join(destination, ...entry.path.split('/'));
      ensureWithinRoot(destination, target);
      mkdirSync(target, { recursive: true, mode: entry.mode & 0o777 });
    }
    for (const entry of entries.filter((value) => value.type !== 'directory')) {
      const target = join(destination, ...entry.path.split('/'));
      ensureWithinRoot(destination, target);
      mkdirSync(dirname(target), { recursive: true, mode: 0o755 });
      const parentRelative = relative(destination, dirname(target));
      if (parentRelative.startsWith('..')) throw new ReleaseArchiveError('release_archive_unsafe_path', 'entry parent escapes destination', { path: entry.path });
      if (entry.type === 'symlink') {
        assertSafeSymlink(entry.path, entry.linkTarget ?? '');
        symlinkSync(entry.linkTarget ?? '', target);
      } else {
        const bytes = entryBytes(entry);
        writeFileSync(target, bytes, { flag: 'wx', mode: entry.mode & 0o777 });
        fsyncPath(target);
      }
    }
    const directories = entries.filter((value) => value.type === 'directory').sort((left, right) => right.path.length - left.path.length);
    for (const entry of directories) {
      const target = join(destination, ...entry.path.split('/'));
      chmodSync(target, entry.mode & 0o777);
      fsyncPath(target);
    }
    fsyncPath(destination);
    return { destination, entries: entries.length, expandedBytes: entries.reduce((sum, entry) => sum + (entry.type === 'file' ? entry.size : 0), 0), manifestDigest: sha256(canonicalize(entries.map(({ data, dataEncoding, ...metadata }) => metadata))) };
  } catch (error) {
    rmSync(destination, { recursive: true, force: true });
    throw error;
  }
}

export function scanDirectory(root: string, prefix = '', limits: ArchiveLimits = DEFAULT_ARCHIVE_LIMITS): DeterministicArchiveEntry[] {
  const entries: DeterministicArchiveEntry[] = [];
  if (prefix !== '') {
    const rootInfo = lstatSync(root);
    if (!rootInfo.isDirectory()) throw new ReleaseArchiveError('release_archive_special_file', 'archive root must be a directory', { root, prefix });
    const rootPath = normalizeArchivePath(prefix);
    if ((rootInfo.mode & 0o6000) !== 0) throw new ReleaseArchiveError('release_archive_unsafe_mode', 'setuid/setgid filesystem entry is forbidden', { path: rootPath });
    entries.push({ path: rootPath, type: 'directory', mode: rootInfo.mode & 0o777, size: 0, sha256: sha256(Buffer.alloc(0)) });
  }
  const walk = (absolute: string, relativePath: string): void => {
    const info = lstatSync(absolute);
    const path = normalizeArchivePath(prefix === '' ? relativePath : posix.join(prefix, relativePath));
    if ((info.mode & 0o6000) !== 0) throw new ReleaseArchiveError('release_archive_unsafe_mode', 'setuid/setgid filesystem entry is forbidden', { path });
    if (info.isDirectory()) {
      entries.push({ path, type: 'directory', mode: info.mode & 0o777, size: 0, sha256: sha256(Buffer.alloc(0)) });
      const names = readdirSync(absolute).sort();
      for (const name of names) walk(join(absolute, name), relativePath === '' ? name : posix.join(relativePath, name));
      return;
    }
    if (info.isSymbolicLink()) {
      const target = readlinkSync(absolute);
      assertSafeSymlink(path, target);
      entries.push({ path, type: 'symlink', mode: info.mode & 0o777, size: Buffer.byteLength(target), sha256: sha256(Buffer.from(target, 'utf8')), linkTarget: target });
      return;
    }
    if (!info.isFile()) throw new ReleaseArchiveError('release_archive_special_file', 'special filesystem entry is forbidden', { path });
    const bytes = readFileSync(absolute);
    entries.push({ path, type: 'file', mode: info.mode & 0o777, size: bytes.length, sha256: sha256(bytes), data: bytes.toString('base64'), dataEncoding: 'base64' });
  };
  const names = readdirSync(root).sort();
  for (const name of names) walk(join(root, name), name);
  return validateDeterministicEntries(entries, limits);
}

export function makeImmutableTree(root: string): void {
  const walk = (absolute: string): void => {
    const info = lstatSync(absolute);
    if (info.isSymbolicLink()) return;
    if (info.isDirectory()) {
      const names = readdirSync(absolute).sort();
      for (const name of names) walk(join(absolute, name));
      chmodSync(absolute, 0o555);
      return;
    }
    chmodSync(absolute, (info.mode & 0o111) === 0 ? 0o444 : 0o555);
  };
  walk(root);
}

export function verifyMaterializedTree(root: string, expectedEntries: readonly DeterministicArchiveEntry[], prefixToStrip = ''): JsonObject {
  const observed = scanDirectory(root, '');
  const normalize = (entries: readonly DeterministicArchiveEntry[]): JsonObject[] => entries.map(({ data, dataEncoding, ...entry }) => {
    const path = prefixToStrip !== '' && entry.path.startsWith(`${prefixToStrip}/`) ? entry.path.slice(prefixToStrip.length + 1) : entry.path;
    return { ...entry, path };
  }).filter((entry) => entry.path !== prefixToStrip).sort((a, b) => String(a.path).localeCompare(String(b.path)));
  const expected = normalize(expectedEntries);
  const actual = normalize(observed);
  const valid = canonicalize(expected) === canonicalize(actual);
  return { valid, expectedDigest: sha256(canonicalize(expected)), observedDigest: sha256(canonicalize(actual)), entries: actual.length };
}

export function atomicPromoteDirectory(staging: string, finalPath: string): void {
  if (existsSync(finalPath)) throw new ReleaseArchiveError('release_materialization_conflict', 'final release path already exists', { finalPath });
  mkdirSync(dirname(finalPath), { recursive: true, mode: 0o700 });
  renameSync(staging, finalPath);
  fsyncPath(dirname(finalPath));
}
