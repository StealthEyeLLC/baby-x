# Baby-X Transactional Root Authority — Checkpoints H through J

## Scope and status

This checkpoint series extends the independently recovered and verified A–G foundation with exactly:

- H — correlated effect observability;
- I — transaction-bound just-in-time credentials;
- J — durable recovery, freeze, reconciliation, and emergency kill controls.

The series stops after J. It does not implement checkpoint K, construct or activate a release, install units, restart services, deploy, or mutate production state.

## Repository identities

- Repository: `StealthEyeLLC/baby-x`
- Source branch: `build/baby-x-transactional-root-authority-a-g-recovery-v1`
- Source commit: `78440521f887e78f7513e2586ce343b0ad9a0319`
- Source tree: `4251f0c13798681bddadfbe0c8810c1188aca457`
- Target branch: `build/baby-x-transactional-root-authority-h-i-j-v1`
- Workspace: `/var/lib/baby-quirt/workspaces/baby-x-transactional-root-authority-h-i-j-v1/baby-x`
- Selective donor branch: `build/baby-x-transactional-root-authority-foundation-v1`
- Selective donor implementation commit: `55b3925a05543e8c1779a03eb3b38a40e924c941`

The mixed donor branch was not merged or cherry-picked. Only checkpoint-specific source files and narrowly identified integration patterns were reconstructed against the recovered A–G interfaces.

## Toolchain

- Node executable: `/opt/node-v24.18.0-linux-x64/bin/node`
- Node version: `v24.18.0`
- npm executable: `/opt/node-v24.18.0-linux-x64/bin/npm`
- npm version: `11.16.0`

## H — Observability

- Commit: `1f2402d7a3aaf42a1d2094e41e79648fe0e5b2ce`
- Tree: `80187a5d135d8c6ca91c4ecef0ea9cebd871d5d4`
- Parent: `78440521f887e78f7513e2586ce343b0ad9a0319`
- Commit message: `feat(root): add correlated effect observation`
- Full checkpoint test result: 168 passed, 0 failed.

Operations:

- `babyx.root.observation.start`
- `babyx.root.observation.get`
- `babyx.root.observation.record`
- `babyx.root.observation.finalize`

Properties verified include durable and idempotent session creation, transaction and step correlation, bounded event and byte limits, digest-chained events, recursive secret redaction, source-completeness classification, overflow truth, pagination, expiry handling, and optional spill through the existing artifact authority.

## I — Transaction-bound JIT credentials

- Commit: `5f68fa134bbae9cdab5c4ed52c8d3536ba12e11f`
- Tree: `8e3c94dfce03004d06da50614fe64c8820ce7cca`
- Parent: `1f2402d7a3aaf42a1d2094e41e79648fe0e5b2ce`
- Commit message: `feat(root): add transaction-bound JIT credentials`
- Full checkpoint test result: 171 passed, 0 failed.

Operations:

- `babyx.root.credential.lease`
- `babyx.root.credential.deliver`
- `babyx.root.credential.get`
- `babyx.root.credential.list`
- `babyx.root.credential.revoke`
- `babyx.root.credential.clean`

Properties verified include exact principal, transaction, step, bundle, grant, provider, target, purpose, and deadline binding; bounded TTL; private delivery permissions; digest-only durable records; absence of secret material from records and public responses; revocation; cleanup; expiry; and restart recovery. The live runtime delivery root remains `BABYX_ROOT_CREDENTIAL_ROOT` when configured, otherwise `/run/baby-x/root-credentials`.

## J — Recovery, freeze, reconciliation, and emergency kill

- Containing commit message: `feat(root): add reconciliation freeze and kill controls`
- Containing commit and tree: established by the signed post-commit local and remote readback because a commit cannot embed its own identity.
- Parent: `5f68fa134bbae9cdab5c4ed52c8d3536ba12e11f`

Operations:

- `babyx.root.freeze.get`
- `babyx.root.freeze.set`
- `babyx.root.kill`
- `babyx.root.reconcile`

Implemented controls include:

- durable, digest-sealed, idempotent freeze records;
- global, principal, skill, bundle, grant, transaction, provider, credential-issuance, and new-execution freeze scopes;
- freeze enforcement at root-effect creation, authorization, begin, credential lease, and broker execution boundaries;
- reconciliation of nonterminal transactions using exact unit, machine, and job readbacks;
- expiry, resume, validation, rollback, compensation, cleanup, ambiguous, and recovery-required classifications;
- credential cleanup and expired-observation failure during reconciliation;
- emergency kill that freezes first and reuses the existing systemd executor, Disposable Machine Service, and durable JobManager;
- unit process inactivity, machine `DESTROYED` plus observed `ABSENT`, and job terminality readback before completion;
- per-transaction `RECOVERY_REQUIRED` when any terminal or absence verification is incomplete.

The live recovery adapter was compiled and integration-wired but was not exercised against live units, machines, jobs, services, or production state. Emergency mutation proofs used fake authority implementations only.

## Final operation surface

- Operation catalog version: `3.4.0`
- Total catalog definitions: 230
- Total `babyx.root.*` definitions: 51
- Total root-fabric dispatcher operations: 40
- H operations added: 4
- I operations added: 6
- J operations added: 4
- Duplicate operation definitions: 0

All previously verified A–G operations and tests remain present. H and I remain present through J.

## Final validation

The final pre-commit gate used the exact toolchain above and passed:

- `npm run clean`
- `npm run build`
- `npm run lint`
- `npm run test:runtime` — 164 passed, 0 failed
- `npm run test:gateway` — 6 passed, 0 failed
- `npm run test:integration` — 2 passed, 0 failed
- `npm run test:acceptance` — 3 passed, 0 failed
- `npm run test:god-mode` — 1 passed, 0 failed
- `npm run test:battleground` — 1 passed, 0 failed
- `npm test` — 175 passed, 0 failed
- focused H, I, and J proofs — 10 passed, 0 failed
- all tracked shell files parsed with `bash -n`
- `git diff --check` passed

## Explicit stop boundary

Checkpoint K is not implemented. No deployer expansion, release construction, release-pointer change, runtime activation, systemd installation, service restart, production mutation, merge, force-push, or history rewrite is part of this checkpoint.

## Independent audit disposition and forward repair

The original H-I-J tip `0a81c71e00e89e57ca246dea5f65c252442c89d2` passed its existing repository gate and was structurally authentic, but an independent semantic audit found reachable authorization, recovery, replay, identity, redaction, cleanup-classification, and catalog-contract defects. Its correct historical disposition is:

- `STRUCTURALLY_VERIFIED=yes`
- `EXISTING_TEST_GATE_PASSED=yes`
- `SEMANTICALLY_VERIFIED=no`
- `READY_FOR_K=no`
- `DEPLOYABLE=no`
- `REPAIR_REQUIRED=yes`

The defects were repaired only through forward commits on the same branch. No ancestor was amended, replaced, force-pushed, or removed. Checkpoint K remained out of scope throughout the repair.

## Forward hardening addendum

This addendum supersedes the earlier H, I, and J certification counts and implementation qualifications for the final branch tip. The earlier checkpoint identities remain historical ancestors and were not rewritten.

### H repair checkpoints

- Durable exact-result observation replay and interrupted-commit recovery:
  - commit `c274db475fdc4be87d2bde709849552f13494c1a`
  - tree `05b2754121dd4150c655dc1a8dfbf34c68a5a612`
  - parent `0a81c71e00e89e57ca246dea5f65c252442c89d2`
- Read-only observation lookup remains principal-authenticated but does not require a mutation idempotency key:
  - commit `60a798823134bcf035ab4d7c5d3d96f4cc924cd5`
  - tree `6636e81a88efa2ad2ed34ca8d1bd0b057edeab80`
  - parent `c274db475fdc4be87d2bde709849552f13494c1a`

### I repair checkpoint

- Commit: `4b202138a6cc4e0960a31a4011d3f26302edbceb`
- Tree: `36ec11bb1059f75e86c3c7dedf7cf85e43c9eda9`
- Parent: `60a798823134bcf035ab4d7c5d3d96f4cc924cd5`
- Commit message: `fix(root): derive credential authorization`

The public credential lease request no longer accepts caller-asserted authorization, provider, bundle, grant, target, purpose, revocation behavior, or deadlines. Those bindings are derived from the durable transaction, current controller lease and fencing token, declared step, active grant, policy decision, selected provider, and one unambiguous authoritative execution target. Delivery, revocation, cleanup, expiry, and restart recovery use durable mutation claims and preserve digest-only records without secret material.

### J hardening checkpoint

The containing commit and tree are established by signed post-commit local and remote readback because a commit cannot embed its own identity.

The final J implementation adds or verifies:

- fail-closed handling for corrupt records and independently verified freeze event-head digests, including tampering hidden behind a recomputed record digest;
- historical freeze replay that cannot overwrite a newer unfreeze;
- owner-, sequence-, and fencing-token-bound recovery reads and transitions;
- ordinary terminal transaction immutability during recovery;
- a durable, digest-sealed emergency-kill request and per-action state machine persisted before side effects;
- exact idempotent replay that inspects durable action state and does not repeat already verified effects;
- explicit transaction controls that must exactly match the authoritative nonterminal scope;
- unit identity binding across unit name, transaction ID, request digest, PID, `/proc` process start identity, systemd monotonic start timestamp, boot ID, cgroup, invocation ID, and executable path;
- fail-closed refusal to signal a unit with incomplete or mismatched identity;
- positive unit termination proof requiring the original process identity to be absent and the bound cgroup to be empty; systemd unit collection is reported separately and is not substituted for process/cgroup proof;
- disposable-machine destruction through the existing Disposable Machine Service and positive `DESTROYED` plus observed `ABSENT` verification;
- durable-job cancellation through the existing JobManager and terminal readback;
- preservation of the declared truthful terminal result when cleanup has completed;
- removal of the unused unfenced authoritative transaction overwrite API.

The focused J hardening proof contains seven tests and passes `7/7`:

1. historical freeze replay and corrupt-record fail-closed behavior;
2. current sequence/fence enforcement and terminal immutability;
3. durable, exact-replay-safe emergency kill with one dispatch per effect;
4. identity-mismatch refusal and mandatory process/cgroup absence verification;
5. incomplete-unit-identity refusal before dispatch;
6. truthful terminal-result preservation after cleanup;
7. catalog schema and postcondition agreement.

### Final hardening validation

Using Node `v24.18.0` and npm `11.16.0`, the final pre-commit hardening gate passed:

- `npm run clean`
- `npm run build`
- `npm run lint`
- `npm test` — `180` passed, `0` failed
- focused H, I, and J repair tests — `15` passed, `0` failed
- focused J hardening tests — `7` passed, `0` failed
- all tracked shell files parsed with `bash -n`
- `git diff --check`
- no stale `reconcileTransition` or unfenced `replaceRecord` authority remained
- no checkpoint K, deployment, release, service-unit installation, activation, restart, or production-mutation path was changed

Durable final-gate evidence:

- Baby job: `6fc02916-6a92-4c68-9b75-d9aead35f791`
- signed wait receipt: `e9588bf5644f16c634123754ef5a4ce9`
- signed stream-read receipt: `ad2f4bcac6b9b578125aed6484430e44`
- catalog: `3.4.0`; definitions: `230`; root operations: `51`; root dispatcher operations: `40`; duplicates: `0`
- repository tests: `180/180`; focused H-I-J repairs: `15/15`

The live recovery adapter was compiled and integration-wired but was not invoked against production units, machines, jobs, or services. Destructive behavior remains certified through bounded fake-authority tests and existing disposable authority integration contracts; this checkpoint does not claim a production mutation or deployment certification.
