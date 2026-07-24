# Baby-X

Baby-X is StealthEye's authenticated unrestricted UID-0 execution and experimentation substrate. It is **nspawn-first, not nspawn-only**: persistent and disposable systemd machines are the default workshop, while raw host root remains the sovereign authority for host, kernel, storage, networking, recovery, and production work.

The private gateway is unprivileged, loopback-only, OAuth-facing, and exposes one public tool: `call_x`. The root runtime accepts signed owner envelopes over `/run/horsey/baby-x.sock`, provides durable operational objects, and returns a compact Ed25519 proof.

Initial provider families include raw execution, jobs, files, PTYs, artifacts, systemd, machines, bpftrace, GDB/ptrace, CRIU, packet capture, seccomp user notification, retroactive specification, and a replayable CEGIS battleground.

This branch is source-only and **not deployed**. Build with Node.js 24.18.0:

```bash
npm ci
npm run build
npm test
npm run lint
```
