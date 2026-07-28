# Transactional Root Authority Checkpoints A–J

Date: 2026-07-28

## Source

- Repository: `StealthEyeLLC/baby-x`
- Branch: `build/baby-x-transactional-root-authority-foundation-v1`
- Prompt 1 source commit: `f03550add0a76277bf7ac7ca051006eea48a4ead`
- Prompt 1 source tree: `a0bfd76beb54b58bc9546dba166e66cd9584ca39`
- Pre-audit branch commit: `fef1cb3b76a5c6f5beb1ca73499c4d1e5cafe713`
- Pre-audit branch tree: `a98cee4adfed2912bffda2a2fdf5928bcd0b66bf`

## Audit result

The pre-audit branch did not satisfy checkpoints A–G as written in Prompt 1. It contained a healthy, coordination-only `ROOT_MUTATION` service with eleven public operations, but it did not contain the full `ROOT_EFFECT` lifecycle, Skill bundle and grant authority, privileged broker, host envelope, or typed effect registry.

The repair preserved the existing service and durable record format and added the complete full-fabric implementation as a separate backward-compatible authority.

## Remote checkpoints

### Implementation

- Commit: `55b3925a05543e8c1779a03eb3b38a40e924c941`
- Tree: `1b19cad2dee076620b1021984e45780d8f399075`
- Message: `feat(root): complete transactional authority through checkpoint j`

### Proof suite

- Commit: `2aa9c261327472f1c9554e3f22c633b094f7b2b4`
- Tree: `5c2a346a0b07e19fc56b661f3bf24bc7c86b6b17`
- Message: `test(root): verify transactional authority checkpoints a through j`

Both checkpoint commits and trees were read back from GitHub and matched the local repository exactly.

## Checkpoint status

### A — Compatibility and schemas: complete

- deterministic root compatibility manifest;
- strict versioned transaction, event, broker, bundle, grant, observation, credential, and recovery records;
- stable canonical serialization and SHA-256 digests;
- legacy root operation and record compatibility preserved.

### B — Durable transactions: complete

- full `ROOT_EFFECT` lifecycle;
- bounded plans and dependency validation;
- durable records and chained events;
- idempotency conflict detection;
- controller leases, takeover, and monotonic fencing;
- terminal-state and administrative-repair restrictions;
- corruption isolation and bounded listing.

### C — Bundles and grants: complete

- canonical local Skill bundles;
- Ed25519 verification and exact bundle identity;
- signer trust, expiry, and revocation;
- semantic capability grants with operation, provider, effect, resource, and credential constraints;
- traversal, symlink, duplicate-path, and mutable-identity rejection.

### D — Root Broker: complete

- separate root-owned systemd socket/service boundary;
- private Unix socket and peer UID verification;
- bounded one-frame QRT requests;
- exact transaction sequence, fencing, principal, bundle, grant, policy, provider, and step binding;
- durable replay protection and signed results;
- finite adapter registry and no arbitrary root shell.

### E — Host envelope: complete

- systemd transient execution profiles;
- complete cgroup termination semantics;
- CPU, memory, I/O, task, namespace, filesystem, syscall, capability, and address-family controls;
- exact unit identity and bounded credential delivery properties.

### F — Filesystem effects: complete

- create, replace, remove, directory, metadata, symlink, and release-pointer effects;
- explicit confinement roots;
- traversal and symlink rejection;
- compare-and-swap preconditions;
- prior-state artifact capture;
- fsync and atomic rename;
- target-state readback.

### G — Process, service, mount, snapshot, and network effects: complete

- finite typed registry with 31 effects;
- process, service, mount, snapshot, and owned-network providers;
- existing authority delegation;
- configured storage-root restrictions;
- protected golden snapshot denial;
- Baby-X-owned nftables table restriction.

### H — Observability: complete

- durable correlated observation sessions;
- process, filesystem, service, mount, network, accounting, and observer events;
- event, byte, and duration bounds;
- dropped-event truth and overflow classification;
- redaction, source health, fallback classification, deterministic summaries, and artifact spill.

### I — Credentials: complete

- durable credential leases bound to transaction, step, principal, bundle, grant, provider, and unit or machine;
- TTL bounded by transaction, operation, and provider limits;
- protected file delivery under a private runtime root;
- no secret contents in durable records or API results;
- revocation, expiry, cleanup, restart recovery, and secret-redaction tests.

### J — Recovery and emergency control: complete

- durable freeze scopes for global, principal, Skill, bundle, grant, transaction, provider, credential issuance, and new execution;
- exact unit, process, job, and machine readback;
- lost-execution and ambiguity classification;
- credential and observer recovery;
- whole-unit and whole-machine emergency termination;
- finite local `baby-x-rootctl` commands only.

## Verification

The final pre-documentation gate used Node.js `24.18.0` and passed:

- build: pass;
- lint: pass;
- tests: 183 passed;
- failed: 0;
- cancelled: 0;
- skipped: 0;
- todo: 0;
- shell syntax: pass;
- `git diff --check`: pass.

Focused tests cover lifecycle, idempotency, fencing, signatures, grants, replay, path confinement, host envelopes, observation bounds and redaction, credential binding and cleanup, freeze persistence, lost execution, reconciliation, and complete emergency termination.

## Catalog result

- Catalog version: `3.1.0`
- Total operations: 230
- Unique operations: 230
- Root operations: 51
- Preserved legacy root operations: 11 of 11
- New full-fabric root operations: 40
- Typed effects: 31

## Explicit stop boundary

This checkpoint stops after J. It does not perform:

- checkpoint K fast-deployer implementation beyond existing deployment authority integration;
- immutable release construction for this new tree;
- installation of the new broker systemd units;
- live service restart;
- release-pointer mutation;
- runtime activation;
- production deployment.

The existing live Baby-X release and rollback release remain unchanged.
