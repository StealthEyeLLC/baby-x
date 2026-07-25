# Disposable Machine Service Documentation Set

**Status:** Governing design and implementation guidance. Checkpoints A through G are implemented on the authorized build branch; H remains pending.

**Top-level authority:** [`../DISPOSABLE-MACHINE-SERVICE-BUILD-MANUAL.md`](../DISPOSABLE-MACHINE-SERVICE-BUILD-MANUAL.md)

This directory expands the top-level manual into focused implementation files so a fresh Baby-enabled build tab can execute the work without re-discovering architecture, contracts, testing requirements, or operating procedures. The top-level manual remains controlling when wording differs. These files provide the detailed execution layer beneath it.

## Frozen foundation

- Repository: `StealthEyeLLC/baby-x`
- Branch: `build/baby-x-god-mode-v1`
- Foundation commit: `b849e29f4db3c861f97b9911fe45f5ff1790e76a`
- Foundation tree: `2a30ec92bb2385e6d06ccc28f3d0af5784ba63e3`
- Proven primitive: ZFS snapshot clone → exact `systemd-nspawn` launch → named-machine execution → termination → ZFS destruction → positive absence readback.

Do not redesign or replace that primitive. Build the durable service around it.

## Required reading order

1. [`10-ARCHITECTURE-AND-AUTHORITY.md`](10-ARCHITECTURE-AND-AUTHORITY.md)
2. [`20-DATA-MODEL-AND-STATE-MACHINE.md`](20-DATA-MODEL-AND-STATE-MACHINE.md)
3. [`30-API-AND-OPERATION-CONTRACTS.md`](30-API-AND-OPERATION-CONTRACTS.md)
4. [`40-RECOVERY-CLEANUP-AND-SAFETY.md`](40-RECOVERY-CLEANUP-AND-SAFETY.md)
5. [`50-IMPLEMENTATION-CHECKPOINTS.md`](50-IMPLEMENTATION-CHECKPOINTS.md)
6. [`60-TEST-AND-CERTIFICATION-PLAN.md`](60-TEST-AND-CERTIFICATION-PLAN.md)
7. [`70-OPERATIONS-AND-BABY-EXECUTION.md`](70-OPERATIONS-AND-BABY-EXECUTION.md)
8. [Checkpoint F certification service contract](../DISPOSABLE-MACHINE-CERTIFICATION-SERVICE.md)
9. [Checkpoint G automatic execution policy](../AUTOMATIC-EXECUTION-POLICY.md)

## Controlling constraints

1. Existing durable jobs remain the sole command execution authority.
2. The new Disposable Machine Service becomes the sole generic machine lifecycle authority.
3. Certification, candidate racing, build rehearsal, failure replay, and future skills consume the service.
4. No alternate scheduler, worker, persistence engine, receipt system, artifact authority, or privileged lane may be introduced.
5. Destructive action requires exact resource ownership and positive absence verification.
6. Ambiguous state is preserved as ambiguous; it is never converted into success.
7. Every checkpoint is committed, pushed, remotely verified, and independently buildable.
8. No production deployment or production state mutation belongs to this build.

## Target repository additions

The implementation should converge toward this structure while remaining consistent with the actual codebase:

```text
runtime/src/machines/
  definitions.ts                 # existing definitions; extended carefully
  manager.ts                     # existing generic nspawn/machinectl manager
  disposable.ts                  # existing primitive; decomposed, not replaced
  service.ts                     # canonical lifecycle service
  schemas.ts                     # versioned machine/event/request schemas
  states.ts                      # transition table and terminal classification
  store.ts                       # machine records and event stream
  identity.ts                    # dataset/root/machine/process binding
  observe.ts                     # ZFS, filesystem, machinectl, process readback
  reconcile.ts                   # deterministic recovery classification
  cleanup.ts                     # stop/destroy/GC orchestration
  policy.ts                      # environment selection after service is stable
  errors.ts                      # stable typed error codes

runtime/test/
  machine-schema.test.mjs
  machine-state.test.mjs
  machine-store.test.mjs
  machine-service-create.test.mjs
  machine-service-start.test.mjs
  machine-service-exec.test.mjs
  machine-service-stop.test.mjs
  machine-service-destroy.test.mjs
  machine-reconcile.test.mjs
  machine-gc.test.mjs
  machine-policy.test.mjs

runtime/integration/
  disposable-machine-lifecycle.test.mjs
  disposable-machine-restart.test.mjs
  disposable-machine-certification.test.mjs

runtime/acceptance/
  disposable-machine-service.test.mjs
  candidate-racing.test.mjs       # only in the final checkpoint
```

Names may be adjusted to repository conventions, but responsibilities must remain separated.

## Smooth-build protocol

Each implementation tab must:

1. Read the top-level manual and every file in this directory.
2. Verify branch, commit, tree, remote, and clean status before editing.
3. Inspect the real source files named by the active checkpoint.
4. Implement one checkpoint only.
5. Add tests before or with implementation.
6. Run focused tests first, then the full repository gates.
7. Commit a stable checkpoint.
8. Push through the authorized repository path.
9. Verify exact remote commit and tree.
10. Record results in the top-level manual or an evidence section without rewriting history.

## Completion order

- A: schemas, durable model, state transitions, event stream.
- B: create/get/list/status.
- C: start/ready/exec through durable jobs.
- D: stop/destroy with verified cleanup.
- E: reconcile/recovery/expiration/garbage collection.
- F: certification migration and duplicate lifecycle removal.
- G: automatic execution policy.
- H: minimum candidate racing.

No later checkpoint should compensate for an incomplete earlier checkpoint. Candidate racing is forbidden until the machine service and certification migration are complete and certified.
