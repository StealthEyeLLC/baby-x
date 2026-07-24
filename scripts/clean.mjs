#!/usr/bin/env node
import { rmSync } from 'node:fs';
for (const path of ['dist', 'runtime/build', 'runtime/native/seccomp-supervisor/target', 'release']) rmSync(path, { recursive: true, force: true });
