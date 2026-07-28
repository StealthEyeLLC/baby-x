# Baby-X Sovereign Root Platform V2

## Authority boundary

The Prompt-1 transactional root authority remains the sole owner of root transaction truth. The Prompt-2 platform is a sidecar coordination and provider-evidence layer. It does not execute commands, own jobs, own machines, own artifacts, own credentials, own deployment, or rewrite Prompt-1 histories.

## Checkpoint A

Checkpoint A adds a deterministic platform description, a strict provider contract, a duplicate-safe registry, bounded live host-capability probes, durable idempotent provider reconciliation records, and four compact public operations:

- `babyx.root.platform.describe`
- `babyx.root.provider.list`
- `babyx.root.provider.get`
- `babyx.root.provider.reconcile`

Only implemented providers are registered: the Prompt-1 root authority, the sovereign platform core, and the live host-capability probe. Later checkpoint providers are registered only when their vertical slices are complete.

Support states are `SUPPORTED`, `DEGRADED`, `UNAVAILABLE`, `EXPERIMENTAL`, `DISABLED`, `REVOKED`, and `FAILED`. A provider probe exception is bounded and reported as `FAILED`; source presence alone never produces `SUPPORTED`.

Provider reconciliation uses append-only sidecar records beneath the Baby-X state root. Replays require the same owner, idempotency key, provider, and observed descriptor digest. Prompt-1 records remain readable and verifiable without migration or mutation.

## Checkpoint B

Checkpoint B adds architecture-bound mediation profiles and five compact public operations:

- `babyx.root.mediation.profile.create`
- `babyx.root.mediation.profile.get`
- `babyx.root.mediation.profile.list`
- `babyx.root.mediation.profile.revoke`
- `babyx.root.mediation.events`

Profiles are strict, digest-stable, owner-bound, expiring, revocable, sequence-checked, and durably replayable. They bind exact Skill and grant digests to selected syscall tables, seccomp actions, notification decisions, bounded equality constraints, Landlock paths and TCP ports, and BPF-LSM observation intent. A profile cannot silently apply a rule outside its declared provider scope.

The tracked native mediation supervisor uses libseccomp to apply filters and receive user notifications. Notification decisions verify kernel notification validity, PID, process start time, cgroup membership, transaction binding, bounded arguments, and a deadline before allow, deny, or selected value emulation. Supervisor loss fails closed. Decision events are bounded and digest-chained.

The live host reports:

- `seccomp-filter`: `SUPPORTED` after a live errno filter test;
- `seccomp-notify`: `SUPPORTED` after a live notification round trip;
- `landlock`: `SUPPORTED` at ABI 4, including ABI-supported TCP restrictions;
- `bpf-lsm`: `UNAVAILABLE` because `bpf` is not active in the host LSM list.

The BPF-LSM source is tracked and digest-bound. A CO-RE observation-only object is built when clang, libbpf headers, bpftool, and kernel BTF are all available. Fixture tests cover load, health, attach, detach, failure, and reconciliation. Enforcement remains disabled and a profile requesting unavailable BPF-LSM behavior fails closed.
