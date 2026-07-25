# Baby-X Architecture

Baby-X is an authenticated unrestricted UID-0 execution substrate. Full Quirt owns reasoning; Baby-X owns machine capability.

## Authority flow

Owner -> OAuth gateway -> signed QRT1 request -> private Unix socket -> root runtime -> host, nspawn machine, or provider.

The gateway is unprivileged. The runtime validates peer credentials, signatures, freshness, replay identity, and the unrestricted owner principal. It does not implement operation-specific authorization.

## Execution targets

Every applicable primitive accepts either the host or a named systemd-nspawn machine. Nspawn is the default workshop, not a mandatory prison. Host root remains sovereign for kernel, storage, networking, machine construction, production activation, rollback, and recovery.

## Reliability versus policy

Baby-X preserves exact identity, idempotency, atomic writes, durable jobs, streams, process groups, cleanup, secret non-persistence, and truthful readback. It does not add executable, argument, path, service, syscall, or provider allowlists.

## State ownership

Operational objects persist because they are useful: jobs, streams, artifacts, machines, traces, captures, checkpoints, specifications, campaigns, and counterexamples. Compact signed proofs bind requests to results without creating a second evidence bureaucracy.
