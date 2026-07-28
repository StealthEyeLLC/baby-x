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

## Checkpoint C

Checkpoint C adds a cold-boot Firecracker microVM provider and six compact public operations:

- `babyx.root.microvm.create`
- `babyx.root.microvm.get`
- `babyx.root.microvm.list`
- `babyx.root.microvm.exec`
- `babyx.root.microvm.stop`
- `babyx.root.microvm.remove`

The provider is an effect sidecar behind the root-only `baby-x-root-provider` Unix socket. The Baby-X runtime remains the public operation authority. Peer credentials are checked with `SO_PEERCRED`, request framing is bounded to one JSON line per connection, and the sidecar accepts typed microVM actions only. It does not expose a shell passthrough.

The compatibility pair is fixed to Firecracker `v1.15.1` and the matching `v1.15` CI kernel `vmlinux-6.1.155`. The official Firecracker archive SHA-256 is `d4a32ab2322d887ca1bc4a4e7afa9cc35393e6362dfc2b3becb389d362e4275a`; the kernel SHA-256 is `e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2`. The release manifest and the resolved local asset manifest bind the Firecracker, jailer, kernel, base root image, and static guest-agent digests. A create request must repeat the exact registered kernel and root-image digests. Network mode is fixed to `NONE`.

MicroVM truth is durable and owner-bound. Records contain the transaction, Skill bundle, grant, policy, provider artifacts, writable layer, systemd unit, cgroup, exact PID/start-time/executable identity, host and guest boot IDs, vsock identity, lifecycle, cleanup observations, and digest chain. Idempotent create replay returns the original VM; a conflicting replay fails closed.

Durable disks and configuration remain beneath the Baby-X state root. Firecracker API and vsock Unix sockets use the bounded runtime root `/run/baby-x/microvm` so a long durable state path cannot violate the kernel Unix-socket path limit. Provider restart adopts a VM only when its exact process identity and authenticated guest boot identity still match. Missing or conflicting process truth transitions a live record to `LOST`; it is never silently replaced. Normal and recovery removal both require positive process, socket, and writable-layer absence before `CLEANED`.

The live x86_64 host reports `firecracker-cold-boot` as `SUPPORTED` only after KVM, vhost-vsock, the exact provider artifacts, cold boot, authenticated guest control, restart adoption, crash classification, and cleanup tests pass. BPF-LSM remains independently `UNAVAILABLE`; its absence does not reduce the microVM provider support state.

The guest is a minimal static PID 1 with no shell. Its authenticated `BABYX-GUEST/1.0.0` protocol supports health, bounded echo, bounded sleep, status, cancellation, and shutdown. The live integration test proves cold boot, authentication failure, typed execution, cancellation, provider restart adoption, forced process crash classification, and complete cleanup.
