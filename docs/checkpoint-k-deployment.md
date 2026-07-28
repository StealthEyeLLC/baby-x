# Checkpoint K production release contract

Checkpoint K completes the Baby-X Prompt 2 release boundary on top of repaired checkpoint J:

- repository: `StealthEyeLLC/baby-x`
- branch: `build/baby-x-transactional-root-authority-k-deployment-v1`
- required parent: `09ed66a470d8430fc5a1db118ce24cb4913b5cc6`
- catalog: version `3.4.0`, 230 operations, 51 `babyx.root.*` operations, 40 root-fabric dispatcher operations, 31 typed effects, and zero duplicate operations
- catalog digest: `87cdc4ab4ab24b193352dab07f9bf92a755bc4e7f2b1f4d8ec88936f47a5f900`
- toolchain: Node.js `v24.18.0` and npm `11.16.0`

The exact candidate commit and tree are intentionally not written into a tracked source file. They are bound after commit creation in the immutable `release.json`, its `release.sha256` sidecar, the durable activation journal, and signed deployment receipts. This avoids a circular source identity.

## Release and authority boundary

`scripts/build-release.mjs` is the only release builder. It builds a complete release in a hidden same-filesystem directory, verifies every payload digest and canonical entrypoint, makes all payload paths read-only, atomically exposes the release, and refuses to overwrite a conflicting release identity.

The canonical services are exactly:

- `baby-x.socket`
- `baby-x.service`
- `baby-x-gateway.service`
- `baby-x-root.slice`
- `baby-x-root-broker.socket`
- `baby-x-root-broker.service`

The runtime executes as the existing unprivileged `fix-exec` service account. The gateway remains the existing unprivileged `fix-mcp` service. Only the root broker executes as root, only on its private Unix socket, with exact runtime-UID peer verification and no TCP listener or arbitrary-shell operation.

Runtime and gateway commit/tree readback derives from the verified immutable release manifest. Startup environment variables cannot replace that identity.

## Activation and recovery

`ops/deploy-fast.sh` binds the deployment to the exact remote ref, commit, tree, parent, clean worktree, credential-free origin, lockfile, and exact toolchain. Critical paths still route through `ops/fast-lane-critical-paths.json`; an explicit critical-fast authorization is required to use the compact lane.

`scripts/activate-release.mjs` owns:

- an exclusive deployment lock;
- immutable candidate verification;
- `current`/`previous` confinement;
- expected-current commit/tree compare-and-swap;
- atomic and durable activation journal updates;
- same-filesystem atomic symlink replacement;
- rollback-safe unit backup and installation;
- bounded canonical service restart;
- live manifest, process, socket, catalog, credential-mode, gateway, and root-broker readback;
- automatic rollback after any post-mutation failure;
- deterministic replay and manual rollback through the same journal.

The initial K activation imports the pre-K current release into a separate immutable rollback directory without modifying or rebuilding its bytes. This is required because the legacy production layout predates `release.json`.

## Fast-lane decision

The operator explicitly selected the compact fast deployment lane for this K activation. The disposable-machine deep-certification phase and large certification evidence bundle are therefore not part of this deployment run. Repository gates, K failure-path tests, immutable staging, compare-and-swap, live readback, and automatic rollback remain mandatory.

The authoritative deployment result is the terminal journal state:

- `ACTIVE` only when the exact candidate commit/tree is live and all readback checks pass;
- `ROLLED_BACK` only when prior identity and health are re-established;
- `BLOCKED`, `FAILED`, `AMBIGUOUS`, or `RECOVERY_REQUIRED` otherwise.
