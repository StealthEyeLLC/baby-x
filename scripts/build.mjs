#!/usr/bin/env node
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, extname, join } from 'node:path';
import { executableFromPath } from './executable-path.mjs';
import { spawnSync } from 'node:child_process';
import { stripTypeScriptTypes } from 'node:module';
import process from 'node:process';

const root = process.cwd();
const report = {
  node: process.version,
  peerCredentialAddon: 'not-built',
  seccompSupervisor: 'not-built',
  transformedTypeScript: 0,
  copiedJavaScript: 0,
};
if (process.version !== 'v24.18.0') throw new Error(`Node.js 24.18.0 required, found ${process.version}`);
rmSync(join(root, 'dist'), { recursive: true, force: true });

function walk(sourceRoot, destinationRoot) {
  for (const name of readdirSync(sourceRoot)) {
    const source = join(sourceRoot, name);
    const destination = join(destinationRoot, name);
    if (statSync(source).isDirectory()) {
      mkdirSync(destination, { recursive: true });
      walk(source, destination);
      continue;
    }
    mkdirSync(dirname(destination), { recursive: true });
    if (extname(source) === '.ts') {
      const output = destination.replace(/\.ts$/u, '.js');
      const transformed = stripTypeScriptTypes(readFileSync(source, 'utf8'), { mode: 'transform', sourceMap: false })
        .replaceAll(".ts'", ".js'")
        .replaceAll('.ts"', '.js"');
      writeFileSync(output, transformed, { mode: statSync(source).mode });
      report.transformedTypeScript += 1;
    } else {
      copyFileSync(source, destination);
      report.copiedJavaScript += 1;
    }
  }
}

walk(join(root, 'runtime/src'), join(root, 'dist/runtime'));
walk(join(root, 'gateway/src'), join(root, 'dist/gateway'));

const compiler = executableFromPath('c++');
const includeCandidates = ['/opt/node-v24.18.0-linux-x64/include/node', '/usr/include/node'];
const include = includeCandidates.find((candidate) => existsSync(join(candidate, 'node_api.h')));
if (!compiler || !include) throw new Error('the peer credential native build toolchain is unavailable');
mkdirSync(join(root, 'runtime/build/Release'), { recursive: true });
const peerResult = spawnSync(
  compiler,
  [
    '-shared',
    '-fPIC',
    '-std=c++20',
    '-Wall',
    '-Wextra',
    '-Werror',
    '-DNODE_GYP_MODULE_NAME=peer_cred',
    `-I${include}`,
    'runtime/native/peer-cred/peer_cred.cc',
    '-o',
    'runtime/build/Release/peer_cred.node',
  ],
  { cwd: root, encoding: 'utf8' },
);
if (peerResult.status !== 0) throw new Error(`peer credential addon build failed: ${peerResult.stderr}`);
mkdirSync(join(root, 'dist/build/Release'), { recursive: true });
copyFileSync(join(root, 'runtime/build/Release/peer_cred.node'), join(root, 'dist/build/Release/peer_cred.node'));
report.peerCredentialAddon = 'built';

const cargo = executableFromPath('cargo');
if (cargo) {
  const seccompResult = spawnSync(cargo, ['build', '--release', '--manifest-path', 'runtime/native/seccomp-supervisor/Cargo.toml'], {
    cwd: root,
    encoding: 'utf8',
  });
  if (seccompResult.status !== 0) throw new Error(`seccomp supervisor build failed: ${seccompResult.stderr}`);
  const seccompRelative = 'runtime/native/seccomp-supervisor/target/release/baby-x-seccomp-supervisor';
  mkdirSync(dirname(join(root, 'dist', seccompRelative)), { recursive: true });
  copyFileSync(join(root, seccompRelative), join(root, 'dist', seccompRelative));
  report.seccompSupervisor = 'built';
}

mkdirSync(join(root, 'dist'), { recursive: true });
writeFileSync(join(root, 'dist/build-report.json'), `${JSON.stringify(report, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(report)}\n`);
