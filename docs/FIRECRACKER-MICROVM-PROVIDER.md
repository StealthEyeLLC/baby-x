# Firecracker Cold-Boot MicroVM Provider

## Fixed compatibility identity

The provider implementation is `firecracker-v1.15.1+babyx-provider-1.0.0` on `x86_64`.

| Artifact | Fixed identity |
| --- | --- |
| Firecracker release archive | `firecracker-v1.15.1-x86_64.tgz` / `d4a32ab2322d887ca1bc4a4e7afa9cc35393e6362dfc2b3becb389d362e4275a` |
| Firecracker executable | Verified from the release archive and recorded in `resolved-manifest.json` |
| Jailer executable | Verified from the same release archive and recorded in `resolved-manifest.json` |
| Guest kernel | `vmlinux-6.1.155` / `e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2` |
| Guest agent protocol | `BABYX-GUEST/1.0.0` |
| Provider manifest | `runtime/assets/microvm/firecracker-v1.15.1-x86_64.json` |

The provisioner downloads over verified TLS, checks the published Firecracker archive checksum, checks the fixed kernel checksum, builds the static guest agent with warnings as errors, creates the minimal ext4 image, and writes a digest-bound resolved manifest.

```bash
NODE=/opt/node-v24.18.0-linux-x64/bin/node \
  scripts/provision-microvm-assets.sh \
  /var/lib/baby-x/root-platform/microvm/assets
```

No downloaded executable or image is committed to Git.

## Authority boundary

`baby-x-root-provider.socket` is mode `0600` and activates `baby-x-root-provider.service`. The provider validates the connecting UID through the native peer-credential addon before reading a request. Requests are strictly shaped, bounded to 65,536 bytes, and limited to one newline-terminated JSON object per connection. Responses are bounded by the runtime client.

The provider owns only Firecracker effects and their observation. It does not own root transactions, durable jobs, artifacts, receipts, deployment, or public policy. Public calls enter through the existing Baby-X runtime and the six catalog operations.

## Storage and runtime paths

- Durable records: `$BABY_X_STATE_ROOT/root-platform/microvm/vms`
- Durable event chain: `$BABY_X_STATE_ROOT/root-platform/microvm/events`
- Durable idempotency claims: `$BABY_X_STATE_ROOT/root-platform/microvm/idempotency`
- Writable guest disks and configuration: `$BABY_X_STATE_ROOT/root-platform/microvm/instances/<vm-id>`
- Ephemeral Firecracker API and vsock sockets: `$BABY_X_MICROVM_RUNTIME_ROOT/<hex-id>`
- Default runtime root: `/run/baby-x/microvm`
- Root-provider socket: `/run/baby-x/root-provider.sock`

Separating the socket root is required because Linux Unix-domain socket paths are length-bounded independently of filesystem path validity.

## Lifecycle and identity

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
- network mode `NONE`.

Provider restart adopts only that exact identity. Process absence, PID reuse, executable mismatch, or failed authenticated guest health transitions the record to `LOST`. The provider never creates a replacement VM under the old identity.

## Guest protocol

The shell-free static guest agent accepts only authenticated typed commands:

- `HEALTH`
- `EXEC ECHO_HEX <task-id> <hex>`
- `EXEC SLEEP_MS <task-id> <milliseconds>`
- `STATUS <task-id>`
- `CANCEL <task-id>`
- `SHUTDOWN`

Inputs, task IDs, durations, and response sizes are bounded. Authentication material is injected into the copied root image and is never returned through public records.

## Cleanup standard

`stop` verifies that the Firecracker unit is inactive. `remove` deletes the durable writable layer and the bounded runtime socket directory, resets the transient unit, and refuses `CLEANED` unless all three observations are true:

- `processAbsent`
- `socketAbsent`
- `writableLayerAbsent`

The same cleanup route applies to `LOST` and failed-boot records. Failure history remains in the append-only event chain.

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

The live test requires root, systemd, writable KVM, vhost-vsock, and a resolved exact asset manifest. It skips rather than claiming success when those prerequisites are unavailable.
