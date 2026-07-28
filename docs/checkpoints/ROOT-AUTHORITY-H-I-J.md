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
