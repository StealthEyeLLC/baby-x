import { spawnSync } from 'node:child_process';
export function storageCapabilities(path = '/var/lib/machines'): Record<string, unknown> { const reflink = spawnSync('/usr/bin/cp', ['--reflink=always', '--help'], { encoding: 'utf8' }).status === 0; return { path, nativeSnapshot: false, reflink, thinVolumeSnapshot: false, recursiveCopy: true }; }
