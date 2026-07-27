#!/usr/bin/env node
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, extname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { stripTypeScriptTypes } from 'node:module';
import process from 'node:process';

const root = process.cwd();
const report = { node: process.version, peerCredentialAddon: 'not-built', seccompSupervisor: 'not-built', transformedTypeScript: 0, copiedJavaScript: 0, copiedDeploymentFiles: 0, copiedNativeArtifacts: 0 };
if (process.version !== 'v24.18.0') throw new Error(`Node.js 24.18.0 required, found ${process.version}`);
rmSync(join(root, 'dist'), { recursive: true, force: true });

function walk(sourceRoot, destinationRoot) {
  for (const name of readdirSync(sourceRoot)) {
    const source = join(sourceRoot, name);
    const destination = join(destinationRoot, name);
    if (statSync(source).isDirectory()) { mkdirSync(destination, { recursive: true }); walk(source, destination); continue; }
    mkdirSync(dirname(destination), { recursive: true });
    if (extname(source) === '.ts') {
      const output = destination.replace(/\.ts$/u, '.js');
      const transformed = stripTypeScriptTypes(readFileSync(source, 'utf8'), { mode: 'transform', sourceMap: false })
        .replaceAll(".ts'", ".js'")
        .replaceAll('.ts"', '.js"');
      writeFileSync(output, transformed, { mode: statSync(source).mode });
      report.transformedTypeScript += 1;
    } else { copyFileSync(source, destination); report.copiedJavaScript += 1; }
  }
}

function copyArtifact(sourcePath, destinationPath, counter) {
  const source = join(root, sourcePath);
  const destination = join(root, 'dist', destinationPath);
  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(source, destination);
  chmodSync(destination, statSync(source).mode & 0o777);
  report[counter] += 1;
}

walk(join(root, 'runtime/src'), join(root, 'dist/runtime'));
walk(join(root, 'gateway/src'), join(root, 'dist/gateway'));
for (const path of [
  'scripts/install-local.sh',
  'scripts/rollback-local.sh',
  'scripts/verify-local.sh',
  'scripts/provision-local-keys.sh',
  'ops/systemd/baby-x.service',
  'ops/systemd/baby-x.socket',
  'ops/systemd/baby-x-gateway.service',
  'ops/tmpfiles/baby-x.conf',
]) copyArtifact(path, path, 'copiedDeploymentFiles');

const compiler = spawnSync('/usr/bin/env', ['bash', '-lc', 'command -v c++'], { encoding: 'utf8' }).stdout.trim();
const includeCandidates = ['/opt/node-v24.18.0-linux-x64/include/node', '/usr/include/node'];
const include = includeCandidates.find((candidate) => existsSync(join(candidate, 'node_api.h')));
if (!compiler || !include) throw new Error('C++ compiler and Node.js headers are required for the peer credential addon');
mkdirSync(join(root, 'runtime/build/Release'), { recursive: true });
const peerResult = spawnSync(compiler, ['-shared', '-fPIC', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-DNODE_GYP_MODULE_NAME=peer_cred', `-I${include}`, 'runtime/native/peer-cred/peer_cred.cc', '-o', 'runtime/build/Release/peer_cred.node'], { cwd: root, encoding: 'utf8' });
if (peerResult.status !== 0) throw new Error(`peer credential addon build failed: ${peerResult.stderr}`);
copyArtifact('runtime/build/Release/peer_cred.node', 'build/Release/peer_cred.node', 'copiedNativeArtifacts');
report.peerCredentialAddon = 'built-and-copied';

const cargo = spawnSync('/usr/bin/env', ['bash', '-lc', 'command -v cargo'], { encoding: 'utf8' }).stdout.trim();
if (cargo) {
  const result = spawnSync(cargo, ['build', '--release', '--manifest-path', 'runtime/native/seccomp-supervisor/Cargo.toml'], { cwd: root, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`seccomp supervisor build failed: ${result.stderr}`);
  const source = 'runtime/native/seccomp-supervisor/target/release/baby-x-seccomp-supervisor';
  if (!existsSync(join(root, source))) throw new Error('seccomp supervisor build succeeded without the expected executable');
  copyArtifact(source, source, 'copiedNativeArtifacts');
  report.seccompSupervisor = 'built-and-copied';
}
mkdirSync(join(root, 'dist'), { recursive: true });
writeFileSync(join(root, 'dist/build-report.json'), `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report));
