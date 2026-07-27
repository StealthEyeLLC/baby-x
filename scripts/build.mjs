#!/usr/bin/env node
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, extname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { stripTypeScriptTypes } from 'node:module';
import process from 'node:process';

const root = process.cwd();
const report = { node: process.version, peerCredentialAddon: 'not-built', seccompSupervisor: 'not-built', transformedTypeScript: 0, copiedJavaScript: 0, copiedDeploymentFiles: 0 };
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

function copyDeploymentFile(path) {
  const source = join(root, path);
  const destination = join(root, 'dist', path);
  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(source, destination);
  chmodSync(destination, statSync(source).mode & 0o777);
  report.copiedDeploymentFiles += 1;
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
]) copyDeploymentFile(path);

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
