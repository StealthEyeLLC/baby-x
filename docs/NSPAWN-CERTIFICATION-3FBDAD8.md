# Disposable systemd-nspawn Certification

Status: **Passed**

## Certified source

- Branch: `build/baby-x-god-mode-v1`
- Commit: `3fbdad8f3ae028da49ea8764f42c4f6531df6717`
- Tree: `7c06f494c23ebd4c9218b67915a935eb3004206f`
- Base snapshot: `babycert/base/noble@golden-v1`
- Run ID: `baby-x-3fbdad8-cert2`
- Completed: `2026-07-25T06:15:50Z`

## Environment correction

The first disposable certification attempt used Ubuntu's packaged Cargo 1.75, which cannot parse the repository's Rust 2024 edition manifest. The corrected run installed current stable Rust through rustup inside the disposable machine.

Certified toolchain:

- `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- `cargo 1.97.1 (c980f4866 2026-06-30)`

This was an environment/toolchain incompatibility, not a repository defect.

## Passed gates

- Exact commit and tree readback
- Clean repository state before certification
- Node build
- npm test: 38 passed, 0 failed
- npm lint
- Rust release test
- Rust release build
- Native seccomp supervisor `describe`
- Native seccomp supervisor real user-notification `probe`
- TypeScript `SeccompSupervisorManager` integration
- Native artifact SHA-256 capture
- Disposable ZFS dataset destruction
- Bind mount removal
- Disposable machine root removal

## Native truth

The native seccomp supervisor truthfully supports:

- `describe`
- `probe`

Planned response actions are not advertised as implemented operations.

## Artifact digest

`baby-x-seccomp-supervisor` SHA-256:

`49f5a41cd8ee2c87b048bebcfa3b7419181adf1288300cbcf2d0f903dc33a913`

## Cleanup truth

After completion:

- `babycert/runs/baby-x-3fbdad8-cert2` did not exist.
- The machine root was not mounted.
- The remaining empty machine directory was removed during exact cleanup readback.
