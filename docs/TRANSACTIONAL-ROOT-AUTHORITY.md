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
