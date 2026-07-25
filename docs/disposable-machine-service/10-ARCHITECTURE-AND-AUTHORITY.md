# Disposable Machine Service — Architecture and Authority

## 1. Purpose

This file freezes the architectural boundaries for the Disposable Machine Service. It prevents implementation drift into duplicate schedulers, duplicate persistence, alternate executors, or certification-owned cloning.

## 2. Existing foundation

The repository already contains the major building blocks:

- `runtime/src/core.ts`: operation routing and provider composition.
- `runtime/src/operations/definitions.ts`: operation contracts.
- `runtime/src/operations/registry.ts`: operation discovery and registration.
- `runtime/src/execution/executor.ts`: exact executable and argv execution.
- `runtime/src/execution/target.ts`: host versus named-machine targeting.
- `runtime/src/jobs/manager.ts`: durable job lifecycle.
- `runtime/src/process/identity.ts`: exact process identity and stale-PID protection.
- `runtime/src/state/atomic-store.ts`: durable atomic state.
- `runtime/src/state/replay-store.ts`: replay and idempotency support.
- `runtime/src/artifacts/manager.ts`: artifact authority.
- `runtime/src/proof/*`: proof generation and verification.
- `runtime/src/machines/manager.ts`: generic `systemd-nspawn` and `machinectl` operations.
- `runtime/src/machines/disposable.ts`: ZFS clone and disposable-machine composition.
- `runtime/src/machines/storage.ts`: machine storage operations.
- `runtime/src/machines/networking.ts`: networking operations.
- `gateway/src/*`: OAuth, protocol forwarding, dynamic operation exposure, and proof verification.

The new service composes these pieces. It does not create replacements for them.

## 3. Sole authorities

### 3.1 Durable execution authority

The existing job and execution subsystem owns:

- exact executable and argv;
- process creation;
- process groups;
- stdout and stderr;
- cancellation;
- timeout and termination;
- exit code and signal;
- durable job records;
- job receipts and related artifacts.

The machine service may request a command be executed against a named machine. It must not supervise that command independently or invent a second child-process lifecycle.

### 3.2 Machine lifecycle authority

The Disposable Machine Service owns:

- machine ID allocation;
- machine-name reservation;
- source snapshot binding;
- clone dataset ownership;
- root path ownership;
- launch configuration;
- desired state;
- persisted lifecycle state;
- observed host state;
- machine lifecycle events;
- expiration;
- reconciliation;
- generic stop and destruction;
- cleanup evidence.

No other feature may directly own generic ZFS/nspawn lifecycle once migration is complete.

### 3.3 Storage authority

ZFS remains the storage substrate for this provider. The service owns only datasets it created and durably bound to a machine record. It never assumes ownership from name shape alone.

Source snapshots are immutable inputs. They are protected and never destroyed by machine cleanup.

### 3.4 Certification authority

Certification owns:

- certification profile;
- required tests;
- pass/fail conditions;
- certification evidence index;
- final certification status.

Certification consumes `machine.create`, `machine.start`, `machine.exec`, `machine.stop`, and `machine.destroy`. It must not call raw ZFS clone/destroy or construct generic nspawn lifecycle itself after migration.

### 3.5 Policy authority

Execution policy determines the appropriate environment:

- host;
- persistent workspace;
- one disposable machine;
- multiple disposable machines.

Policy returns a decision and explanation. It does not run commands, mutate machine records, or destroy resources.

### 3.6 Candidate-racing authority

Candidate racing owns:

- candidate strategies;
- identical source baseline;
- common validation profile;
- scoring;
- winner selection;
- preservation policy.

It consumes the machine service and durable jobs. It cannot introduce candidate-specific clone or cleanup code.

### 3.7 Gateway authority

The gateway authenticates and forwards dynamically described operations and verifies proof. It does not become a machine controller. Machine lifecycle state remains in the Baby-X runtime.

## 4. End-state architecture

```text
Owner request
  -> OAuth gateway
  -> signed protocol request
  -> operation registry
  -> execution policy (when needed)
  -> Disposable Machine Service
       -> durable machine store
       -> append-only machine event store
       -> existing ZFS disposable primitive
       -> existing machine manager
       -> existing durable jobs targeted to machine
       -> existing artifacts and proof
       -> observation/reconciliation/cleanup
  -> operation result and signed evidence
```

## 5. Fundamental invariants

1. A machine name is not a complete identity.
2. A PID is not a complete process identity.
3. A ZFS dataset name is not proof of ownership.
4. A root path is not proof of ownership.
5. Desired, persisted, and observed states are distinct.
6. Every accepted state transition increments a sequence number.
7. Mutations require idempotency semantics.
8. Reusing an idempotency key with a different normalized request is an error.
9. Source snapshots are never removed by machine cleanup.
10. `DESTROYED` requires positive absence readback for all owned runtime resources.
11. Unknown observation remains unknown.
12. Ambiguous identity blocks automatic destructive action.
13. Every machine-targeted job references the exact machine ID and observed machine identity.
14. Large evidence is stored as artifacts.
15. No feature may bypass lifecycle APIs after migration.
16. Recovery is a normal lifecycle path, not an ad hoc repair script.
17. Host root remains sovereign for machine construction, storage, networking, production activation, rollback, and recovery.
18. nspawn is the default workshop, not an absolute prison; host execution remains valid when policy selects it.
19. Security derives from exact authority and identity, not from vague container claims.
20. Receipt and proof systems remain shared across all features.

## 6. Provider boundaries

The first provider is `zfs-nspawn-disposable@1`.

Provider responsibilities:

- validate provider-specific source and clone configuration;
- prepare exact clone argv;
- prepare exact nspawn argv;
- observe provider resources;
- return structured provider observations;
- perform provider-specific stop/destroy primitives under service authority.

Provider non-responsibilities:

- allocating global machine IDs;
- owning lifecycle state;
- owning idempotency;
- owning job records;
- deciding certification success;
- deciding candidate winners;
- maintaining a parallel event log.

The service should allow future providers without weakening the canonical lifecycle model. Future providers must fit the same service contract rather than introducing separate top-level APIs.

## 7. Layering rules

Recommended dependency direction:

```text
operations/core
  -> machine service
      -> schemas/states/store/events
      -> identity/observe/reconcile/cleanup
      -> disposable provider
          -> machine manager
          -> executor/jobs
          -> storage/networking
```

Forbidden dependency direction examples:

- `jobs/manager.ts` importing certification code;
- `machines/disposable.ts` deciding candidate winners;
- `gateway` mutating ZFS directly;
- `certification` importing low-level ZFS helpers after migration;
- `policy` calling `machinectl` or `zfs`;
- `machine service` creating its own receipt format.

## 8. Failure truth

Operations return one of:

- successful, with verified resulting state;
- failed, with a specific error and preserved evidence;
- recovery required, where work may have partially succeeded;
- ambiguous, where conflicting identity prevents safe action;
- unknown, where required observation could not be obtained.

No API may return success merely because a command exited zero. Success requires post-action readback appropriate to the operation.

## 9. Concurrency model

A machine has at most one active lifecycle controller lease at a time. Concurrent read operations are permitted. Mutating operations must compare expected sequence and lease ownership.

Rules:

- `create` reserves identity atomically.
- `start`, `stop`, `destroy`, and `reconcile` acquire a per-machine controller lease.
- `exec` may run concurrently when state is compatible and policy permits.
- `destroy` is rejected while protected jobs remain active.
- GC skips leased or protected machines.
- stale leases are reconciled using owner, boot ID, process identity, and expiration—not wall-clock timeout alone.

## 10. Migration rule

During implementation, old direct paths may temporarily remain for compatibility. They must be marked and tested as migration-only. Checkpoint F is not complete until generic consumers use the machine service and duplicate lifecycle code is removed or reduced to private provider primitives.

## 11. Out of scope for this build

- replacing ZFS;
- replacing nspawn;
- production deployment;
- cloud fleet scheduling;
- Kubernetes integration;
- public multi-tenant isolation claims;
- arbitrary user-supplied privileged mounts;
- full autonomous learning and skill promotion;
- general distributed consensus;
- production candidate activation.

## 12. Architecture acceptance checklist

- [ ] Existing jobs remain sole execution authority.
- [ ] Service is sole lifecycle authority.
- [ ] Provider is subordinate to service.
- [ ] Certification uses service APIs.
- [ ] Policy only decides.
- [ ] Candidate racing only consumes.
- [ ] Gateway only authenticates/forwards/verifies.
- [ ] No duplicate state, artifacts, receipts, or scheduling.
- [ ] Unknown and ambiguous states are preserved.
- [ ] Cleanup requires ownership and readback.
