#!/usr/bin/env node
import { readdirSync, readFileSync, statSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { stripTypeScriptTypes } from 'node:module';
import { spawnSync } from 'node:child_process';

const files = [];
function walk(path) { for (const name of readdirSync(path)) { if (['.git', 'node_modules', 'dist', 'build', 'target'].includes(name)) continue; const item = join(path, name); if (statSync(item).isDirectory()) walk(item); else files.push(item); } }
walk('.');
const forbidden = [/riskScore/u, /confirmationDigest/u, /executableAllowlist/u, /pathAllowlist/u, /mandatoryDryRun/u];
for (const file of files.filter((item) => item.endsWith('.ts'))) {
  const source = readFileSync(file, 'utf8');
  for (const pattern of forbidden) if (pattern.test(source)) throw new Error(`${file}: forbidden ceremony token ${pattern}`);
  const stripped = stripTypeScriptTypes(source, { mode: 'transform', sourceMap: false });
  const temporary = `.baby-x-lint-${process.pid}.mjs`;
  writeFileSync(temporary, stripped);
  const checked = spawnSync(process.execPath, ['--check', temporary], { encoding: 'utf8' });
  rmSync(temporary, { force: true });
  if (checked.status !== 0) throw new Error(`${file}: ${checked.stderr}`);
}
for (const file of files.filter((item) => item.endsWith('.js') || item.endsWith('.mjs'))) { const checked = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' }); if (checked.status !== 0) throw new Error(`${file}: ${checked.stderr}`); }
const tsconfig = JSON.parse(readFileSync('tsconfig.base.json', 'utf8'));
for (const key of ['strict', 'noImplicitAny', 'noUnusedLocals', 'noUnusedParameters', 'noImplicitReturns', 'noFallthroughCasesInSwitch']) if (tsconfig.compilerOptions[key] !== true) throw new Error(`tsconfig ${key} must be true`);
console.log(JSON.stringify({ files: files.length, typescriptSyntaxChecked: files.filter((item) => item.endsWith('.ts')).length, strictCompilerContract: true }));
