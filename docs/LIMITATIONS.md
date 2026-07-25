# Current Limitations

- The current branch is a source foundation and is not deployed.
- Host validation has Node.js 24.18.0, systemd-nspawn, machinectl, bpftrace, and tcpdump.
- GDB, CRIU, dumpcap, tshark, Rust, and Cargo were not present during the initial host gate; their real acceptance must run in disposable machines or an otherwise authorized environment.
- The seccomp helper source exists, but the host build correctly reported it as not built without Cargo.
- Several subsystem files currently expose catalog or facade definitions while runtime dispatch remains centralized in `core.ts`; they require separation into durable lifecycle managers.
- CRIU restore success is workload- and kernel-dependent and must never be generalized from one passing sample.
- Retro-specification currently provides deterministic statement storage and classification, not complete natural-language requirement recovery.
- CEGIS campaign storage and bounded-loop tests exist; destructive adversaries and full replay reconstruction require further implementation.
- Exact private gateway donor extraction remains to be verified through authenticated materialization.
