# God-Mode Providers

Baby-X exposes first-class observation and intervention families:

- bpftrace for kernel and process observation;
- GDB/ptrace for threads, registers, memory, breakpoints, cores, and raw scripts;
- CRIU for compatibility checks, checkpoint, restore, clone, import, and export;
- tcpdump, dumpcap, and tshark for bounded capture and decoding;
- `SECCOMP_RET_USER_NOTIF` for continue, errno, delay, delegation, and FD injection.

Every family provides structured operations plus a raw escape hatch. Availability is reported honestly from the current environment.

Memory dumps, core files, checkpoints, packet captures, and unrestricted traces are sensitive opaque artifacts by default. Only bounded summaries should enter model context.

GDB and CRIU coordinate through a process intervention lease. The lease prevents conflicting controllers; it is not an authorization policy.

Seccomp user notification is used for experimentation, fault injection, compatibility, and delegation, not represented as an infallible security boundary.
