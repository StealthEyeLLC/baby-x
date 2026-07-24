import { readFileSync, readlinkSync } from 'node:fs';
import type { ProcessIdentity } from '../core.ts';

export function processIdentity(pid: number): ProcessIdentity {
  const fields = readFileSync(`/proc/${pid}/stat`, 'utf8').trim().split(' ');
  return { pid, processStartTime: fields[21], executablePath: readlinkSync(`/proc/${pid}/exe`), pgid: Number(fields[4]), bootId: readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim() };
}
