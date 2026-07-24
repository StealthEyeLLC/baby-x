#!/usr/bin/env node
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import process from 'node:process';

const root = process.cwd();
const report = { node: process.version, peerCredentialAddon: 'not-built', seccompSupervisor: 'not-built', copied: [] };
if (process.version !== 'v24.18.0') throw new Error(`Node.js 24.18.0 required, found ${process.version}`);
rmSync(join(root, 'dist'), { recursive: true, force: true });
for (const [source, destination] of [['runtime/src', 'dist/runtime'], ['gateway/src', 'dist/gateway']]) {
  if (existsSync(join(root, source))) { mkdirSync(dirname(join(root, destination)), { recursive: true }); cpSync(join(root, source), join(root, destination), { recursive: true }); report.copied.push(destination); }
}
const compiler = spawnSync('/usr/bin/env', ['bash', '-lc', 'command -v c++'], { encoding: 'utf8' }).stdout.trim();
const includeCandidates = ['/opt/node-v24.18.0-linux-x64/include/node', '/usr/include/node'];
const include = includeCandidates.find((candidate) => existsSync(join(candidate, 'node_api.h')));
if (compiler && include) {
  mkdirSync(join(root, 'runtime/build/Release'), { recursive: true });
  const result = spawnSync(compiler, ['-shared', '-fPIC', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-DNODE_GYP_MODULE_NAME=peer_cred', `-I${include}`, 'runtime/native/peer-cred/peer_cred.cc', '-o', 'runtime/build/Release/peer_cred.node'], { cwd: root, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`peer credential addon build failed: ${result.stderr}`);
  report.peerCredentialAddon = 'built';
}
const cargo = spawnSync('/usr/bin/env', ['bash', '-lc', 'command -v cargo'], { encoding: 'utf8' }).stdout.trim();
if (cargo) {
  const result = spawnSync(cargo, ['build', '--release', '--manifest-path', 'runtime/native/seccomp-supervisor/Cargo.toml'], { cwd: root, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`seccomp supervisor build failed: ${result.stderr}`);
  report.seccompSupervisor = 'built';
}
mkdirSync(join(root, 'dist'), { recursive: true });
writeFileSync(join(root, 'dist/build-report.json'), `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report));
