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

## Checkpoint D

Checkpoint D extends the Firecracker provider with durable full snapshots, fresh-identity restore, and a bounded warm pool through three additional public operations:

- `babyx.root.microvm.snapshot`
- `babyx.root.microvm.restore`
- `babyx.root.microvm.pool.reconcile`

A snapshot request is owner-bound, strictly shaped, expiring, and idempotent. Only an idle `READY` microVM may become a template. The guest must first acknowledge `PREPARE_SNAPSHOT`, clear all task state, clear its authentication token and workload identity, and report that cleanup. The provider independently verifies that the host token file and copied writable disk no longer contain the token before accepting the snapshot. A busy or otherwise non-`READY` source fails closed.

The provider creates a full Firecracker snapshot containing VM state and memory plus a credential-scrubbed writable disk. Durable snapshot truth binds the source VM and transaction, owner, request digest, Firecracker, kernel, base-image, writable-disk, memory, VM-state, CPU architecture and fingerprint, guest CID, resource shape, policy inputs, credential-absence proof, expiry, and record digest chain. The source VM is stopped and removed through the canonical cleanup path, and `READY` snapshot publication requires positive process, socket, and writable-layer absence. Replaying the same request resolves the durable idempotency claim before inspecting the now-destroyed source; conflicting reuse fails closed.

Restore verifies snapshot ownership, status, expiry, revocation, artifact digests, CPU compatibility, and all snapshot files. It copies the immutable snapshot disk, generates a fresh 256-bit host token, loads the full snapshot through the Firecracker API with VMGenID update handling, and completes an authenticated guest bootstrap that rotates workload identity and random epoch. The restored VM inherits the immutable guest CID but not the prior token, workload identity, random epoch, transaction binding, or task state. Network mode remains fixed to `NONE`.

Warm pools are durable, owner-bound, snapshot-bound, expiring, and capped at one available guest because the full snapshot carries an immutable guest CID. `RECONCILE` creates, replenishes, drains, and verifies that bound pool. `ACQUIRE` atomically leases the available VM and supports replay without duplicate allocation. `RELEASE` always destroys the contaminated leased VM and replenishes from the clean snapshot when the desired count remains one. An empty pool may return an explicitly reported cold fallback; it never silently relabels a cold VM as warm.

Snapshot and pool records use authoritative atomic files, strict schemas, stable serialization, deterministic digests, durable idempotency claims, bounded lists, restart verification, and corruption isolation. Provider reconciliation verifies VM, snapshot, and pool stores together, adopts only exact process and guest identities, stops provider-owned orphan units, and never invents records or replacement identity.

The live certification creates and rejects a contaminated snapshot source, creates a scrubbed full snapshot, replays it after source destruction, restores it with fresh identity, executes authenticated work, creates a one-guest warm pool, replays acquisition, destroys and replenishes a released guest, drains the pool, exercises cold fallback, verifies durable integrity, and proves that no transient Firecracker unit remains.

## Checkpoint D

Checkpoint D adds full Firecracker snapshots, identity-safe restore, and a bounded one-instance warm pool through three catalog operations:

- `babyx.root.microvm.snapshot`
- `babyx.root.microvm.restore`
- `babyx.root.microvm.pool.reconcile`

Snapshot creation is restricted to an idle, authenticated `READY` VM. The guest is quiesced before Firecracker is paused. The provider writes full memory and VM-state artifacts, records their exact digests and compatibility identity, verifies that bootstrap and runtime credentials are absent from the artifacts, resumes only as required for controlled shutdown, then removes the source VM with positive process/socket/writable-layer absence proof. A snapshot is not usable until its durable record and artifact digests are complete.

Restore verifies the snapshot record, all artifact digests, Firecracker/kernel/root-image/guest-protocol compatibility, expiry, and credential-absence evidence. It launches a new VM identity, injects a fresh one-time bootstrap token, establishes a fresh runtime token, and requires new guest boot, workload, nonce, and random-epoch identities. Snapshot credentials and source identity are never reused.

The warm pool is deliberately bounded to one retained snapshot-backed capacity unit. Reconciliation creates or removes that unit to match desired capacity. Acquire binds a fresh restore to a transaction and immediately replenishes capacity; release destroys the leased VM and reconciles the pool. Idempotency, lease state, snapshot state, and events are durable and digest chained. Unknown, expired, contaminated, incompatible, or concurrently leased records fail closed.

Catalog `7.0.0` declares explicit snapshot, restore, and pool postconditions. The combined live certification proves cold boot, snapshot creation, source cleanup, digest readback, identity reseeding, contaminated-snapshot rejection, warm-pool acquire/release/replenishment, provider restart safety, and final zero-resource absence.

## Checkpoint E

Checkpoint E adds an attestation-to-workload-identity chain and eight compact public operations:

- `babyx.root.attestation.challenge`
- `babyx.root.attestation.verify`
- `babyx.root.attestation.get`
- `babyx.root.identity.issue`
- `babyx.root.identity.get`
- `babyx.root.identity.revoke`
- `babyx.root.secret.lease`
- `babyx.root.secret.revoke`

Attestation challenges are owner-bound, nonce-bound, PCR-selection-bound, expiring, and durably idempotent. Verification consumes one challenge, enforces quote freshness, exact provider binding, requested PCR presence, policy PCR equality, optional measured-boot and IMA evidence requirements, and deterministic quote signatures. A consumed nonce cannot authorize a second verification with different evidence. Hardware TPM private keys are never exported.

The live host has no TPM device, TPM2 tools, EFI measured-boot event log, software TPM binary, or SPIRE binary/socket. The registry therefore reports `hardware-tpm`, `measured-boot-evidence`, and `spire-workload-api` as `UNAVAILABLE`; it does not infer trust from source or configuration presence. The bounded software-TPM provider is `EXPERIMENTAL` and test-only. IMA measurement evidence is `SUPPORTED` in observe-only mode and never enables appraisal. The SPIRE contract is pinned to `spire@1.12.4`; it remains unavailable until an enrolled agent and Workload API socket are present and explicitly enabled.

Workload identities use trust domain `babyx.stealtheye.internal`. Identity records bind the owner, fresh attestation, exact transaction, Skill bundle digest, grant digest, issuer provider, deterministic selectors, SPIFFE ID, certificate digest, TTL, revocation state, and private-key reference digest. Supported selectors include systemd unit, UID, GID, executable path and digest, cgroup, VM ID, transaction ID, and Skill bundle digest. The live host's OpenSSL-backed sovereign X.509-SVID issuer is reported `EXPERIMENTAL`; its provider-owned private material is mode-restricted, is never returned through public operations, rotates through new identity issuance, and is deleted on revocation or expiry.

Secret leases require one active identity, one fresh verified attestation, exact transaction/Skill/grant bindings, and a target selector match. The provider reads only a bounded regular-file secret reference, zeroes the read buffer after hashing, and persists and returns metadata and digests only. Secret values and source paths are never stored in lease records or returned by metadata operations. Identity revocation cascades to active leases. Startup reconciliation expires stale challenges, attestations, identities, and leases; removes expired or revoked identity material; and deletes orphan provider-owned material.

Catalog `8.0.0` preserves the original eleven Prompt-1 root operations unchanged. Focused tests cover live support truth, software-TPM quote verification, nonce replay, PCR mismatch, stale quote rejection, unavailable hardware and SPIRE paths, selector matching and mismatch, SVID rotation, lease allow and denial, restart readback, revocation, expiry, credential cleanup, and public runtime dispatch.
