# Transactional Root Authority

The Transactional Root Authority is Baby-X's durable coordination boundary for an exact root mutation. It records authority; it does not execute commands or replace any existing execution provider.

## Exact binding

Every transaction is bound at creation to:

- repository, branch, Git commit, and Git tree;
- mutation, target, and rollback SHA-256 digests;
- the owner principal;
- required execution authorities and verification authorities;
- a caller idempotency key represented only by its digest.

Unknown fields, malformed identities, unbounded values, missing idempotency, conflicting replays, and stale expected sequences fail closed.

## Lifecycle

`REQUESTED -> AUTHORIZED -> EXECUTING -> VERIFYING -> COMMIT_READY -> COMMITTED`

Rollback is explicit and observed:

`{non-terminal or committed state} -> ROLLBACK_REQUESTED -> ROLLED_BACK`

An execution or verification failure reaches `FAILED`. Ambiguous authority observations reach `AMBIGUOUS`. `COMMITTED` requires the exact latest successful verification digest and all declared verification authorities.

## Durable truth

The authoritative record is stored beneath `/var/lib/baby-x/root-authority`. Each transition appends an event containing the prior and next state, sequence, request digest, idempotency-key digest, timestamp, previous-event digest, and event digest. The complete record has a deterministic digest. Reads and mutations verify the chain and record digest before returning or advancing state.

## Authority boundary

This service is coordination-only. It owns no process, job, machine, artifact, release, systemd, Git, or deployment execution path. Those remain with their existing singular authorities. Execution results enter the transaction only as bounded authority references and observation digests.

## Public operations

- `babyx.root.describe`
- `babyx.root.transaction.create`
- `babyx.root.transaction.get`
- `babyx.root.transaction.list`
- `babyx.root.transaction.authorize`
- `babyx.root.transaction.begin`
- `babyx.root.transaction.observe`
- `babyx.root.transaction.commit`
- `babyx.root.transaction.rollback`
- `babyx.root.transaction.events`
- `babyx.root.transaction.verify`

## Local immutable release guarantees

A local release is a complete immutable artifact beneath `/opt/baby-x/releases/<commit>-<tree>`. It contains the compiled runtime and gateway, deployment scripts, systemd units, tmpfiles policy, the peer-credential native addon, and any built native supervisor executable.

Activation and rollback are serialized by `/opt/baby-x/.install.lock`. The `current` pointer changes before verification only inside the locked transition. The `previous` pointer is committed only after the candidate passes the direct runtime check and the live gateway-to-socket-to-runtime health check. A failed activation restores the prior pointer, matching units, and verified service state. A failed rollback restores the former current release.

Local key provisioning is idempotent and fail-closed. It creates distinct Ed25519 gateway-authority and proof key pairs, validates both pairs before service start, preserves existing complete pairs, refuses partial key state, applies strict ownership and modes, and binds the runtime to the exact deployed gateway service UID. Private key material is never embedded in Git or immutable release artifacts.

The socket worker adopts exactly one systemd-provided descriptor and verifies the connecting peer UID before accepting a signed request. Rejected peers are closed without terminating the worker. Deployment verification requires the socket, worker, and gateway to be active and requires the gateway health response to match the direct runtime product and operation count.

## Full `ROOT_EFFECT` fabric

The original `ROOT_MUTATION` service and its eleven public operations remain readable and backward compatible. The complete Prompt 1 authority is implemented as a separate versioned `ROOT_EFFECT` fabric beneath `/var/lib/baby-x/root-fabric`, so existing transaction histories are not rewritten.

The full fabric adds:

- the `REQUESTED` through `COMMITTED`, rollback, compensation, cleanup, recovery, ambiguity, and expiry lifecycle;
- deterministic plans, events, record digests, idempotency claims, controller leases, and fencing tokens;
- exact signed Skill bundles and semantic capability grants;
- a finite root-owned broker on `/run/baby-x/root-broker.sock` with peer-UID checks, bounded QRT frames, signed results, and durable replay protection;
- systemd host envelopes and delegation to the existing Disposable Machine Service;
- typed filesystem, process, service, mount, snapshot, and owned-network effects;
- correlated and bounded observation sessions with explicit completeness and fallback truth;
- transaction-bound just-in-time credential leases with protected delivery and positive cleanup;
- durable scoped freeze, exact-identity reconciliation, and whole-unit or whole-machine emergency termination.

The canonical operation catalog is `3.1.0`. It contains 230 unique operations, including 51 `babyx.root.*` operations: the original eleven compatibility operations and forty full-fabric operations. The typed effect registry contains 31 finite effects and does not expose an arbitrary root shell.

## Authority preservation

The full fabric coordinates existing authorities rather than replacing them:

- durable jobs remain with the existing `JobManager`;
- disposable machines remain with the existing `DisposableMachineService`;
- artifacts remain with the existing `ArtifactManager`;
- systemd actions remain with the existing `SystemdManager`;
- storage effects are restricted to configured Baby-X dataset and mount roots;
- network mutations are restricted to a Baby-X-owned nftables table;
- deployment remains with the existing immutable release authority.

## Checkpoint boundary

Prompt 1 checkpoints A through J are implemented and verified on the implementation branch. Checkpoint K, immutable release construction, service installation, activation, and production deployment are deliberately outside this checkpoint. No live release pointer or production service was changed while completing A through J.
