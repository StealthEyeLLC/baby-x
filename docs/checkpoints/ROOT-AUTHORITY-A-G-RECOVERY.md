# Canonical Root Authority A-G Recovery

## Status and scope

This record describes the selective recovery of Prompt-1 checkpoints A through G onto a branch created from the canonical Prompt-1 evidence commit. It is an implementation and evidence ledger, not deployment approval. No H, I, J, K, installation, activation, release switch, or production mutation is part of this checkpoint.

Recovery branch:

`build/baby-x-transactional-root-authority-a-g-recovery-v1`

Recovery workspace:

`/var/lib/baby-quirt/workspaces/baby-x-transactional-root-authority-a-g-recovery-v1/baby-x`

Canonical source identity:

- commit: `f03550add0a76277bf7ac7ca051006eea48a4ead`
- tree: `a0bfd76beb54b58bc9546dba166e66cd9584ca39`
- verified implementation ancestor: `702a6254984775e20d16700fa1e1990f32a24660`
- verified implementation tree: `02fa0ec672efcebf9b7359a23299d49ed1fa59d0`

Mixed donor identity:

- branch: `build/baby-x-transactional-root-authority-foundation-v1`
- mixed implementation commit: `55b3925a05543e8c1779a03eb3b38a40e924c941`
- mixed implementation tree: `1b19cad2dee076620b1021984e45780d8f399075`
- donor remote tip observed for the mission: `ebf8f4725fc645b5f313e0d3ce26fb82f08bc8c7`

The recovery branch was created from the canonical source commit. The mixed donor commit was neither merged nor cherry-picked. A-G files and functions were selectively reconstructed; mixed integration points were reduced to the A-G surface.

## Toolchain

All build, lint, and test commands used the exact installed toolchain:

- Node executable: `/opt/node-v24.18.0-linux-x64/bin/node`
- Node version: `v24.18.0`
- npm executable: `/opt/node-v24.18.0-linux-x64/bin/npm`
- npm version: `11.16.0`

The host-default Node.js executable was not used for certification commands.

## Source and branch verification

Before implementation, the following were verified:

- repository remote identifies `StealthEyeLLC/baby-x` and contains no embedded credential;
- local source commit and tree equal the canonical identities above;
- remote source branch resolves to the same source commit;
- source worktree is clean;
- no tracked private key is present;
- no unrelated active writer was found;
- the empty recovery branch was pushed at the canonical source commit and its remote commit and tree were verified.

The exact-source baseline gate completed successfully with `npm ci`, build, lint, full test, shell syntax validation, `git diff --check`, and a clean tracked worktree.

## Donor classification

Every path changed by `f03550a..55b3925` was classified before selective recovery. `Ported` means the recovery tree contains an A-G-only reconstruction or reduced integration of that donor concept. `Omitted` means no donor content from that path was accepted.

| Donor path | Class | Disposition | Recovery decision |
|---|---:|---|---|
| `docs/ARCHITECTURE.md` | SHARED | Omitted | Mixed future-scope claims were not reused as evidence. |
| `docs/CANONICAL-TRUTH.md` | SHARED | Omitted | Mixed future-scope claims were not reused as evidence. |
| `docs/TRANSACTIONAL-ROOT-AUTHORITY.md` | SHARED | Omitted | Replaced by this A-G-specific evidence ledger. |
| `ops/systemd/baby-x-gateway.service` | UNRELATED | Omitted | Gateway/deployment wiring is outside the recovery checkpoint. |
| `ops/systemd/baby-x-root-broker.service` | D | Ported | Reduced to the finite broker process boundary. |
| `ops/systemd/baby-x-root-broker.socket` | D | Ported | Private socket activation retained. |
| `ops/systemd/baby-x-root.slice` | E | Ported | Dedicated bounded host-envelope slice retained. |
| `ops/systemd/baby-x.service` | UNRELATED | Omitted | Installation and activation wiring is outside scope. |
| `ops/tmpfiles/baby-x.conf` | UNRELATED | Omitted | Host installation/state-directory mutation is outside scope. |
| `runtime/src/core.ts` | SHARED | Ported | Reduced dispatcher integration retains the original root surface and only A-G additions. |
| `runtime/src/index.ts` | SHARED | Omitted | Mixed process/runtime export wiring was unnecessary for the A-G checkpoint. |
| `runtime/src/operations/definitions.ts` | SHARED | Ported | Catalog upgraded only for the finite A-G public surface. |
| `runtime/src/root-authority/service.ts` | SHARED | Ported | Original Prompt-1 root authority remains the sole path for its eleven operations. |
| `runtime/src/root-broker-main.ts` | D | Ported | Reduced broker entrypoint with peer identity, bounded framing, and A-G adapters only. |
| `runtime/src/root-fabric/authorities.ts` | G | Ported | Bounded storage and owned-network authority adapters retained. |
| `runtime/src/root-fabric/broker.ts` | D | Ported | Finite protocol, replay store, deadline checks, exact bindings, and signed results retained. |
| `runtime/src/root-fabric/credentials.ts` | I | Omitted | Later credential runtime service is outside scope. |
| `runtime/src/root-fabric/effects.ts` | G | Ported | Finite 31-effect registry retained without arbitrary shell. |
| `runtime/src/root-fabric/model.ts` | SHARED | Ported | A and B schemas, lifecycle, canonical records, and event-chain types retained; later-service branches removed. |
| `runtime/src/root-fabric/observability.ts` | H | Omitted | Later observation runtime service is outside scope. |
| `runtime/src/root-fabric/recovery.ts` | J | Omitted | Later recovery runtime service is outside scope. |
| `runtime/src/root-fabric/service.ts` | SHARED | Ported | Reduced to 26 A-G operations and A-G service construction only. |
| `runtime/src/root-fabric/transactions.ts` | B | Ported | Durable root-effect transaction coordination retained. |
| `runtime/src/root-fabric/trust.ts` | C | Ported | Signed bundles, trust, revocation, and semantic grants retained. |
| `runtime/src/rootctl.ts` | J | Omitted | Later operator/recovery control surface is outside scope. |
| `runtime/src/server.ts` | SHARED | Omitted | Mixed server construction was unnecessary for the A-G checkpoint. |
| `runtime/src/systemd/manager.ts` | E | Ported | Programmatic transient-unit and process-control support retained. |
| `runtime/test/canonical-repair.test.mjs` | SHARED | Ported | Existing catalog-version assertion updated to measured A-G truth. |
| `runtime/test/core.test.mjs` | SHARED | Ported | Existing catalog count and absence assertions updated to measured A-G truth. |
| `runtime/test/deployment-runtime-path.test.mjs` | UNRELATED | Omitted | Deployment-path certification is outside scope. |
| `runtime/test/local-key-provisioning.test.mjs` | I | Omitted | Credential provisioning is outside scope. |
| `runtime/test/local-release-transaction.test.mjs` | UNRELATED | Omitted | Release installation/activation transaction is outside scope. |
| `runtime/test/native-release-artifacts.test.mjs` | UNRELATED | Omitted | Release artifact packaging is outside scope. |
| `runtime/test/root-authority.test.mjs` | SHARED | Omitted | Mixed A-J test file was replaced by a dedicated A-G suite. |
| `runtime/test/socket-activation.test.mjs` | D | Omitted | Mixed deployment-oriented socket test was replaced by focused broker boundary proofs. |
| `scripts/baby-x-rootctl` | J | Omitted | Later control utility is outside scope. |
| `scripts/build.mjs` | SHARED | Omitted | Existing source build path already compiles the recovered A-G runtime. |
| `scripts/install-local.sh` | UNRELATED | Omitted | Installation is outside scope. |
| `scripts/provision-local-keys.sh` | I | Omitted | Credential provisioning is outside scope. |
| `scripts/rollback-local.sh` | UNRELATED | Omitted | Deployment rollback is outside scope. |
| `scripts/verify-local.sh` | UNRELATED | Omitted | Installed-runtime verification is outside scope. |

## Recovered checkpoint identities

| Checkpoint | Commit | Tree | Parent | Subject |
|---|---|---|---|---|
| A | `fa59c56cac94500905320d7ee75b823d5b470074` | `64a197679c1c3aea0bb37e564b0eb36a809d9c1f` | `f03550add0a76277bf7ac7ca051006eea48a4ead` | `feat(root): recover compatibility and transaction schemas` |
| B | `6e1eef7daa33f4fbf7dc67a061f0bdbede80c63f` | `adf99190234da82be79510c3ce250b86dfe34cd6` | `fa59c56cac94500905320d7ee75b823d5b470074` | `feat(root): recover durable root transactions` |
| C | `2b8f993de2302cb55ba09abb8364bc6886c57f4d` | `9d7037bda00bbcc8909dcb459bde99e593c32458` | `6e1eef7daa33f4fbf7dc67a061f0bdbede80c63f` | `feat(root): recover signed bundles and grants` |
| D | `a3542aba9546392a1d0b157b40cefd85f9ff51e0` | `82e25a095d1359a9cfa8f7b992a084391070bb75` | `2b8f993de2302cb55ba09abb8364bc6886c57f4d` | `feat(root): recover minimal privileged broker` |
| E | `019765cdc1d466eb63cff5c487a57b6463c9a492` | `27588415d6b0d45023b8ba9997f2eb1664645270` | `a3542aba9546392a1d0b157b40cefd85f9ff51e0` | `feat(root): recover systemd host envelopes` |
| F | `29bd274dcce2bae2dc858d97c3b77aa85f2fb3f1` | `067b60ab11805126e6af58167384cf555894aa71` | `019765cdc1d466eb63cff5c487a57b6463c9a492` | `feat(root): recover transactional filesystem effects` |
| G | `04fef54d98a31349629cda3da9b3b18d6515c834` | `bd9266f844774c3ad2a3d2cfdd79be0b3a512e25` | `29bd274dcce2bae2dc858d97c3b77aa85f2fb3f1` | `feat(root): recover process service and storage effects` |
| A-G focused tests | `6133d0ee828784e0d893b1144dbd66d5a8994e94` | `a66ee1a0b3632fa8aa519b886bccd7ecb660d052` | `04fef54d98a31349629cda3da9b3b18d6515c834` | `test(root): verify recovered checkpoints a through g` |
| Catalog assertion alignment | `3db34484bad512aba057766a7e7fcb6017f4459c` | `25c8d64e062eefac7daedcfa9369d6e175145a37` | `6133d0ee828784e0d893b1144dbd66d5a8994e94` | `test(root): align catalog assertions with recovered a through g` |

Every listed checkpoint was pushed fast-forward and its remote commit identity was checked before continuing.

## Measured public surface

Built catalog measurements at the A-G test checkpoint:

- catalog version: `3.1.0`
- total catalog operations: `216`
- root operations: `37`
- original Prompt-1 root operations: `11`
- new A-G root-fabric operations: `26`
- finite typed effects: `31`
- duplicate root operation names: `0`
- arbitrary root shell effects: `0`

The dedicated A-G suite proves the original root operations remain represented, every A-G catalog operation routes through the dispatcher boundary, semantic operation names are unique, later public surfaces are absent, and the effect registry is finite.

## Focused verification

`runtime/test/root-authority-a-g-recovery.test.mjs` contains eight durable groups covering:

- deterministic compatibility and strict versioned records;
- transaction replay, conflict handling, transitions, leases, fencing, terminal immutability, pagination, index reconstruction, corruption isolation, and event-chain verification;
- Ed25519 bundle verification, trust and revocation, normalized path confinement, bundle-to-grant binding, and semantic grant denials;
- finite broker protocol, replay handling, deadlines, release binding, peer-credential enforcement source, bounded framing, and signed responses;
- host-envelope resource controls, exact identity, cancellation, full-cgroup kill, freeze/thaw, and cleanup readback;
- filesystem confinement, compare-and-swap, link and race rejection, fsync, atomic switching, and rollback restoration;
- finite process, service, mount, snapshot, storage, and owned-network authority reuse;
- exact catalog and dispatcher surface measurements.

Focused A-G result at commit `6133d0ee828784e0d893b1144dbd66d5a8994e94`:

- tests: `8`
- passed: `8`
- failed: `0`
- cancelled: `0`
- skipped: `0`
- todo: `0`

The broader catalog-alignment focused run at commit `3db34484bad512aba057766a7e7fcb6017f4459c` passed `28` of `28` tests with zero failures, cancellations, skips, or todos.

## Scope exclusions

The recovery tree intentionally omits the later observation, credential, freeze/kill, and reconciliation runtime services, their constructors, their control utility, and their mixed tests. It also omits deployment, local installation, key provisioning, activation, release-pointer mutation, and production-state changes.

This checkpoint is source-only. `DEPLOYED=no`.
