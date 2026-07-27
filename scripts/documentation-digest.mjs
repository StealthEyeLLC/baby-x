#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve, relative, sep } from 'node:path';

const root = resolve(process.argv[2] ?? process.cwd());
const git = spawnSync('git', ['-C', root, 'ls-files', '-z', '--', 'docs/*.md', 'docs/**/*.md'], { encoding: null });
if (git.status !== 0) throw new Error(`git ls-files failed: ${Buffer.from(git.stderr ?? []).toString('utf8')}`);
const files = Buffer.from(git.stdout ?? []).toString('utf8').split('\0').filter(Boolean).map((path) => path.split(sep).join('/')).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
if (files.length === 0) throw new Error('no tracked documentation Markdown files found');

const canonical = createHash('sha256');
const legacyLines = createHash('sha256');
let totalBytes = 0;
for (const path of files) {
  if (!path.startsWith('docs/') || path.includes('/../') || path.includes('\0')) throw new Error(`unsafe documentation path: ${path}`);
  const bytes = readFileSync(resolve(root, path));
  const pathBytes = Buffer.from(path, 'utf8');
  const pathLength = Buffer.alloc(8); pathLength.writeBigUInt64BE(BigInt(pathBytes.length));
  const contentLength = Buffer.alloc(8); contentLength.writeBigUInt64BE(BigInt(bytes.length));
  canonical.update(pathLength); canonical.update(pathBytes); canonical.update(contentLength); canonical.update(bytes);
  legacyLines.update(`${createHash('sha256').update(bytes).digest('hex')}  ${path}\n`, 'utf8');
  totalBytes += bytes.length;
}
const result = {
  schemaVersion: 'baby-x-documentation-digest-v1',
  root: '.',
  includedPattern: ['docs/*.md', 'docs/**/*.md'],
  relativePathEncoding: 'UTF-8 POSIX slash',
  sortOrder: 'unsigned bytewise ascending under LC_ALL=C semantics',
  frame: 'uint64be(pathByteLength) || pathBytes || uint64be(contentByteLength) || rawFileBytes',
  delimiters: 'length-prefixed; no implicit newline normalization',
  sizesIncluded: true,
  pathBytesIncluded: true,
  contentUsedRaw: true,
  metadataIncluded: false,
  locale: 'C',
  implementation: 'scripts/documentation-digest.mjs using Node.js crypto SHA-256',
  fileCount: files.length,
  totalBytes,
  canonicalSha256: canonical.digest('hex'),
  currentLegacySha256LinesDigest: legacyLines.digest('hex'),
  legacyReports: {
    earlierAK: '1de04475812712b553ae0d40afac00420aac501cb818256e6e7a1a81137500e0',
    checkpointLPreflight: '1de04475a6a957f66d4ecb6ba1d08f748e0e8f564c2846c4dc8180f392bfbd1e',
    checkpointLProcedure: 'SHA-256 of LC_ALL=C bytewise-sorted sha256sum lines for the 44 tracked Markdown files before K.5',
    discrepancyConclusion: 'The Checkpoint L value is reproducible; the earlier A-K value is a reporting transcription error. No content change is inferred without a Git content diff.',
  },
};
process.stdout.write(`${JSON.stringify(result)}\n`);
