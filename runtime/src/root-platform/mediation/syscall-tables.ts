import { MediationError } from './errors.ts';

export type MediationArchitecture = 'x86_64' | 'aarch64';

export const SYSCALL_TABLES: Readonly<Record<MediationArchitecture, Readonly<Record<string, number>>>> = Object.freeze({
  x86_64: Object.freeze({
    read: 0, write: 1, close: 3, getpid: 39, socket: 41, connect: 42, bind: 49, execve: 59, exit: 60,
    getppid: 110, mount: 165, umount2: 166, exit_group: 231, openat: 257, unshare: 272, setns: 308,
    clone3: 435, openat2: 437,
  }),
  aarch64: Object.freeze({
    umount2: 39, mount: 40, openat: 56, close: 57, read: 63, write: 64, exit: 93, exit_group: 94,
    unshare: 97, getpid: 172, getppid: 173, socket: 198, bind: 200, connect: 203, execve: 221,
    setns: 268, clone3: 435, openat2: 437,
  }),
});

export function runtimeArchitecture(value = process.arch): MediationArchitecture {
  if (value === 'x64' || value === 'x86_64') return 'x86_64';
  if (value === 'arm64' || value === 'aarch64') return 'aarch64';
  throw new MediationError('mediation_invalid_request', `unsupported mediation architecture: ${value}`);
}

export function syscallNumber(architecture: MediationArchitecture, syscall: string): number {
  const number = SYSCALL_TABLES[architecture][syscall];
  if (number === undefined) throw new MediationError('mediation_invalid_request', `syscall ${syscall} is not in the selected ${architecture} mediation table`, { architecture, syscall });
  return number;
}

export function syscallNames(architecture: MediationArchitecture): string[] {
  return Object.keys(SYSCALL_TABLES[architecture]).sort();
}
