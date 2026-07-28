# Firecracker MicroVM Provider

## Fixed compatibility identity

The provider implementation is `firecracker-v1.15.1+babyx-provider-1.1.0` on `x86_64`.

| Artifact | Fixed identity |
| --- | --- |
| Firecracker release archive | `firecracker-v1.15.1-x86_64.tgz` / `d4a32ab2322d887ca1bc4a4e7afa9cc35393e6362dfc2b3becb389d362e4275a` |
| Firecracker executable | Verified from the release archive and recorded in `resolved-manifest.json` |
| Jailer executable | Verified from the same release archive and recorded in `resolved-manifest.json` |
| Guest kernel | `vmlinux-6.1.155` / `e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2` |
| Guest agent protocol | `BABYX-GUEST/1.1.0` |
| Provider manifest | `runtime/assets/microvm/firecracker-v1.15.1-x86_64.json` |

The provisioner downloads over verified TLS, checks the published Firecracker archive checksum, checks the fixed kernel checksum, builds the static guest agent with warnings as errors, creates the minimal ext4 image, and writes a digest-bound resolved manifest.

```bash
NODE=/opt/node-v24.18.0-linux-x64/bin/node \
  scripts/provision-microvm-assets.sh \
  /var/lib/baby-x/root-platform/microvm/assets
```

No downloaded executable, kernel, or root image is committed to Git.

## Authority boundary

`baby-x-root-provider.socket` is mode `0600` and activates `baby-x-root-provider.service`. The provider validates the connecting UID with the native peer-credential addon before reading a request. Requests are strictly shaped, bounded to 65,536 bytes, and limited to one newline-terminated JSON object per connection. Responses are bounded by the runtime client.

The provider owns only Firecracker effects and their observation. It does not own root transactions, durable jobs, artifacts, receipts, deployment, or public policy. Public calls enter through the existing Baby-X runtime and these nine catalog operations:

- `babyx.root.microvm.create`
- `babyx.root.microvm.get`
- `babyx.root.microvm.list`
- `babyx.root.microvm.exec`
- `babyx.root.microvm.stop`
- `babyx.root.microvm.remove`
- `babyx.root.microvm.snapshot`
- `babyx.root.microvm.restore`
- `babyx.root.microvm.pool.reconcile`

There is no shell passthrough.

## Storage and runtime paths

- Durable VM records: `$BABY_X_STATE_ROOT/root-platform/microvm/vms`
- Durable VM event chain: `$BABY_X_STATE_ROOT/root-platform/microvm/events`
- Durable VM idempotency: `$BABY_X_STATE_ROOT/root-platform/microvm/idempotency`
- Durable instance disks/configuration: `$BABY_X_STATE_ROOT/root-platform/microvm/instances/<vm-id>`
- Durable snapshot records and files: `$BABY_X_STATE_ROOT/root-platform/microvm/snapshots`
- Durable pool records: `$BABY_X_STATE_ROOT/root-platform/microvm/pools`
- Snapshot and pool idempotency claims: `$BABY_X_STATE_ROOT/root-platform/microvm/snapshot-idempotency`, `pool-idempotency`, and `pool-action-idempotency`
- Ephemeral Firecracker API and vsock sockets: `$BABY_X_MICROVM_RUNTIME_ROOT/<hex-id>`
- Default runtime root: `/run/baby-x/microvm`
- Root-provider socket: `/run/baby-x/root-provider.sock`

Separating ephemeral sockets from the durable root prevents long state paths from exceeding the Linux Unix-domain socket path limit.

## VM lifecycle and identity

The lifecycle is:

`REQUESTED -> PREPARING -> STARTING -> BOOTING -> READY <-> RUNNING -> STOPPING -> STOPPED -> CLEANING -> CLEANED`

Failure classifications include `FAILED`, `LOST`, `AMBIGUOUS`, and `RECOVERY_REQUIRED`.

A live VM is bound to:

- owner principal and idempotency-key digest;
- root transaction, Skill bundle, grant, and policy digests;
- exact Firecracker, kernel, root-image, and guest-agent digests;
- systemd unit and cgroup;
- PID, process start time, executable path, and executable digest;
- host boot ID and authenticated guest boot ID;
- vsock CID and socket identity;
- workload identity and random-epoch digests;
- network mode `NONE`.

Provider restart adopts only that exact identity. Process absence, PID reuse, executable mismatch, or failed authenticated guest health transitions the record to `LOST`. The provider never creates a replacement VM under the old identity. A transient systemd pre-exec `MainPID` is tolerated only until the exact Firecracker executable digest appears.

## Guest protocol

The shell-free static PID 1 agent accepts only authenticated typed commands:

- `HEALTH`
- `EXEC ECHO_HEX <task-id> <hex>`
- `EXEC SLEEP_MS <task-id> <milliseconds>`
- `STATUS <task-id>`
- `CANCEL <task-id>`
- `PREPARE_SNAPSHOT`
- `SHUTDOWN`

Inputs, task IDs, durations, and responses are bounded. Bootstrap rotates the workload identity and random epoch and reports their digests. `PREPARE_SNAPSHOT` refuses active work, clears task state, authentication material, and guest identity, and reports the exact cleanup observations required by the host.

## Full snapshot contract

Only an idle `READY` VM may be snapshotted. The provider:

1. Resolves the owner-bound idempotency claim.
2. Requires exact live process identity.
3. Calls authenticated `PREPARE_SNAPSHOT`.
4. Verifies task, token, and identity clearing.
5. Verifies the token is absent from the writable disk.
6. Pauses Firecracker and creates a full memory and VM-state snapshot.
7. Copies and hashes the credential-free writable disk.
8. Removes the host token.
9. Stops and positively cleans the source VM.
10. Publishes the snapshot as `READY` only after all digest and absence proofs succeed.

Snapshot replay is durable even after the source VM is `CLEANED`. A conflicting idempotency reuse fails closed. Snapshot records bind exact provider artifacts, CPU fingerprint, guest CID, resources, policy inputs, credential-absence proof, expiry, revocation, sequence, previous digest, and record digest.

## Restore contract

Restore requires a `READY`, unexpired, unrevoked, owner-matching snapshot with compatible Firecracker, kernel, root image, CPU architecture, CPU fingerprint, and verified snapshot files. The provider copies the snapshot disk, creates a fresh host token, starts Firecracker with the inherited CID, loads memory and VM state with VMGenID update handling, and performs authenticated bootstrap.

The restored guest receives a new VM ID, transaction binding, token, workload identity, random epoch, process identity, host socket identity, and guest boot observation. It inherits only the immutable snapshot state and guest CID. Network remains `NONE`.

## Bounded warm pool

A pool is owner-bound, snapshot-bound, expiring, and capped at one warm guest because the full snapshot contains an immutable guest CID.

- `RECONCILE` creates, replenishes, drains, and verifies the desired count.
- `ACQUIRE` atomically moves one `AVAILABLE` VM to `LEASED`; replay returns the same lease.
- `RELEASE` destroys the leased VM and replenishes from the clean snapshot when desired.
- An empty pool may produce an explicitly marked cold fallback; it is never represented as warm.

A released guest is never returned to the available set. Pool records bind available IDs, leases, failures, health, expiry, sequence, previous digest, and record digest.

## Reconciliation and cleanup

`stop` verifies the Firecracker unit is inactive. `remove` deletes the durable writable layer and bounded runtime socket directory, resets the transient unit, and refuses `CLEANED` unless all three observations are true:

- `processAbsent`
- `socketAbsent`
- `writableLayerAbsent`

Snapshot source cleanup and warm-pool release use the same canonical route. Failure history remains in append-only VM events and durable snapshot/pool records.

Provider reconciliation verifies VM, snapshot, and pool stores, repairs derived indexes from authoritative records, adopts exact live identities, stops provider-owned orphan units, classifies stale truth, and never invents records or success.

## Verification

Focused verification:

```bash
npm run build
node --test \
  runtime/test/root-microvm.test.mjs \
  runtime/test/root-microvm-provider-socket.test.mjs
BABY_X_MICROVM_ASSET_ROOT="$PWD/.baby-x-test-assets" \
  node --test runtime/integration/root-microvm-native.test.mjs
```

The live test requires root, systemd, writable KVM, vhost-vsock, and a resolved exact asset manifest. It skips rather than claiming success when those prerequisites are unavailable. It proves cold boot, typed execution, cancellation, restart adoption, crash classification, complete cleanup, contaminated-source rejection, credential-free full snapshot creation, replay after source destruction, fresh-identity restore, bounded warm acquisition, replay, destruction, replenishment, drain, cold fallback, integrity reconciliation, and absence of transient Firecracker units.

## Snapshot, restore, and warm-pool contract

A snapshot request is accepted only for an owner-bound VM in `READY` with no active guest task. The guest protocol executes `QUIESCE`, Firecracker is paused through its bounded Unix HTTP API, and a full snapshot is written beneath the durable microVM snapshot store. Memory, VM-state, source disk, provider, kernel, root-image, and guest-agent identities are recorded with SHA-256 digests. Credential absence is verified before the record becomes restorable. The source VM is then cleaned through the canonical removal path.

Restore is not process cloning. Before Firecracker loads a snapshot, the provider validates the durable record, expiry, compatibility set, and every artifact digest. The restored guest receives a new bootstrap secret and must report new boot, workload, nonce, and random-epoch identities. The restore record is bound to a new transaction, Skill bundle, grant, policy, VM ID, systemd unit, cgroup, process identity, and vsock identity.

Warm-pool capacity is capped at one. `RECONCILE` converges durable capacity to zero or one; `ACQUIRE` leases a snapshot-backed VM to a transaction and replenishes the pool; `RELEASE` removes the leased VM and reconciles capacity. Pool and snapshot records are authoritative, atomic, digest-bound, and restart-safe. No pooled credential or runtime token is reusable.

Asset provisioning is release-bound: the provisioner computes the current release guest-agent digest before taking its idempotent reuse path. A previously valid asset set is rebuilt when its guest-agent digest does not match the current release. Local deployment verification checks the active root-provider socket and revalidates the complete resolved asset manifest before accepting activation.
