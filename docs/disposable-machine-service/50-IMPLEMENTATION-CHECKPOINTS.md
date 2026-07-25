# Disposable Machine Service — Implementation Checkpoints

## 1. Execution rule

Implement one checkpoint at a time. Each checkpoint must leave the repository clean, buildable, tested, committed, pushed, and remotely verified. Do not start the next checkpoint while the active checkpoint has unresolved failures or uncommitted work.

## 2. Pre-build freeze

Before Checkpoint A:

1. Verify branch `build/baby-x-god-mode-v1`.
2. Record local and remote commit/tree.
3. Confirm clean working tree.
4. Run `npm run build`, `npm run lint`, and `npm test`.
5. Read the top-level manual and all files in this directory.
6. Inspect the actual source files named by Checkpoint A.
7. Confirm no production deployment action is authorized.
8. Create a backup ref if branch history is not already remotely anchored.

Hard stop conditions:

- local/remote tree mismatch without understood cause;
- uncommitted unrelated changes;
- failing baseline gates;
- source file shape materially different from this plan without documented adaptation;
- missing authority to push checkpoints.

## 3. Checkpoint A — Durable model, schemas, states, and store

### Goal

Create the durable machine record, event record, transition validator, store, indexes, and tombstone model without yet moving existing lifecycle execution behind it.

### Expected files

- extend `runtime/src/machines/definitions.ts` only where compatibility is clear;
- add `runtime/src/machines/schemas.ts`;
- add `runtime/src/machines/states.ts`;
- add `runtime/src/machines/store.ts`;
- add `runtime/src/machines/errors.ts`;
- update exports in `runtime/src/index.ts` as appropriate;
- add focused tests.

### Work order

1. Define TypeScript types.
2. Define runtime validation schemas using repository conventions.
3. Define canonical request/event serialization.
4. Define transition table.
5. Define terminal and recoverable classifications.
6. Implement atomic record writes using existing atomic-store patterns.
7. Implement append-only event writes.
8. Implement per-name and per-state indexes as reconstructable data.
9. Implement tombstones.
10. Add store verification and index rebuild helper.

### Tests

- schema validation;
- unknown major version rejection;
- canonical digest stability;
- transition acceptance/rejection;
- expected-sequence conflict;
- event offset monotonicity;
- event digest stability;
- atomic write failure behavior;
- index reconstruction;
- tombstone prevents reuse;
- secret redaction from canonical evidence.

### Completion gate

- no raw ZFS/nspawn behavior changed;
- all baseline tests still pass;
- new model tests pass;
- no operation is publicly exposed prematurely;
- commit message: `feat: add durable disposable machine state model`.

## 4. Checkpoint B — Create, get, list, events, and status

### Goal

Wrap the existing clone primitive with durable creation lifecycle and implement read APIs.

### Expected files

- add `runtime/src/machines/service.ts`;
- add `runtime/src/machines/identity.ts`;
- add `runtime/src/machines/observe.ts`;
- refactor `runtime/src/machines/disposable.ts` into provider-level primitives without replacing it;
- update operation definitions/registry/core;
- add gateway dynamic forwarding tests only if existing coverage is insufficient.

### Work order

1. Implement normalized create request and digest.
2. Atomically reserve machine ID/name.
3. Persist `REQUESTED` and event.
4. Acquire controller lease.
5. Observe source snapshot identity.
6. Transition to `CLONING`.
7. Call existing exact ZFS clone primitive.
8. Apply/read ownership properties.
9. Verify origin/GUID/mountpoint/root.
10. Transition to `CLONED`.
11. Implement `get`, bounded `list`, and `events`.
12. Implement read-only live `status` with discrepancy reporting.
13. Register discovery and operations.

### Tests

- successful create;
- duplicate idempotent create;
- idempotency conflict;
- machine-name conflict;
- missing source;
- source GUID mismatch;
- option injection;
- invalid root;
- existing foreign dataset;
- clone command zero but readback mismatch;
- list filters/pagination;
- status disagreement reporting;
- gateway forwarding.

### Completion gate

- existing disposable tests retained;
- create is durable and restart-safe at each transition boundary;
- commit message: `feat: add durable disposable machine creation and inspection`.

## 5. Checkpoint C — Start, readiness, and machine-targeted execution

### Goal

Provide durable startup and execute through existing jobs.

### Work order

1. Validate state and sequence.
2. Acquire controller lease.
3. Re-observe clone ownership and root.
4. Detect name/process conflicts.
5. Transition to `STARTING`.
6. Build exact launch argv using existing machine manager.
7. Launch through existing durable execution authority.
8. Record process identity.
9. Poll bounded readiness.
10. Verify `machinectl show` identity.
11. Transition to `READY`.
12. Implement `machine.exec` and `machine.shell` as wrappers over existing jobs and execution targeting.
13. Track active job IDs and `READY <-> EXECUTING` transitions.

### Tests

- start from cloned;
- repeated start no-op;
- start from invalid state;
- machine name conflict;
- wrong root conflict;
- process identity mismatch;
- readiness timeout;
- machine exec success;
- machine exec nonzero exit;
- output/artifact behavior;
- concurrent jobs;
- stale PID reuse;
- restart observation of healthy running machine.

### Completion gate

- no second job manager;
- job receipts remain existing format;
- commit message: `feat: add durable disposable machine startup and execution`.

## 6. Checkpoint D — Stop, destroy, and verified cleanup

### Goal

Make teardown safe, durable, and positively verified.

### Work order

1. Implement protected-job checks.
2. Implement stop controller and graceful deadline.
3. Implement bounded escalation.
4. Verify process and machine absence.
5. Persist `STOPPED`.
6. Preserve required evidence before destruction.
7. Verify dataset ownership/source distinction.
8. Transition to `DESTROYING`.
9. Destroy exact owned clone.
10. Verify dataset/root/machine/process absence.
11. Persist `DESTROYED` and tombstone.
12. Make repeated stop/destroy verified no-ops.

### Tests

- graceful stop;
- forced stop under policy;
- protected job blocks stop/destroy;
- wrong ownership blocks destroy;
- source dataset cannot be destroyed;
- recursive child conflict;
- destroy succeeds but response lost;
- dataset absent but root remains;
- cleanup readback failure;
- repeated destroy;
- evidence retained.

### Completion gate

- `DESTROYED` cannot be recorded without positive readback;
- commit message: `feat: add verified disposable machine shutdown and destruction`.

## 7. Checkpoint E — Reconciliation, recovery, expiration, and GC

### Goal

Survive runtime and host interruption and clean expired machines safely.

### Work order

1. Implement provider observation bundle.
2. Implement recovery classification.
3. Implement stale lease handling.
4. Implement exact process adoption.
5. Implement partial-create continuation.
6. Implement partial-destroy continuation.
7. Implement startup bounded reconciliation.
8. Implement explicit `reconcile`.
9. Implement expiration marking.
10. Implement GC dry-run and bounded execution.
11. Implement diagnostic artifact bundle.

### Tests

- restart at every transition boundary;
- host boot ID change;
- stale PID;
- healthy adoption;
- stopped-intact classification;
- orphan clone;
- foreign process conflict;
- partial destruction;
- provider unavailable;
- GC protected exclusions;
- GC dry-run versus apply;
- concurrent explicit operation and GC.

### Completion gate

- restart recovery deterministic;
- ambiguity blocks destruction;
- commit message: `feat: add disposable machine recovery and garbage collection`.

## 8. Checkpoint F — Certification migration

### Goal

Certification consumes the shared service and no longer owns generic lifecycle.

### Work order

1. Inventory all certification clone/start/exec/stop/destroy logic.
2. Define certification consumer adapter.
3. Replace direct lifecycle calls with machine-service operations.
4. Preserve certification-specific test selection and result truth.
5. Preserve existing evidence and improve binding to machine/job IDs.
6. Remove or privatize duplicate lifecycle code.
7. Run disposable certification end to end.
8. Update certification documentation with exact evidence.

### Tests

- certification success;
- test failure with cleanup;
- dependency installation failure;
- runtime interruption and resume;
- cleanup failure produces non-success;
- machine evidence linked to certification result;
- no generic clone code remains in certification layer.

### Completion gate

- commit message: `refactor: route certification through disposable machine service`.

## 9. Checkpoint G — Automatic execution policy

### Goal

Select host, workspace, or disposable execution without user micromanagement.

### Work order

1. Define policy inputs and decision schema.
2. Implement deterministic rule set.
3. Produce explanation and decision digest.
4. Integrate only after explicit-objective entry points are identified.
5. Do not change direct low-level operations.
6. Add safe defaults and overrides.

Policy factors:

- mutation risk;
- dependency uncertainty;
- isolation requirement;
- reproducibility;
- network requirement;
- source sensitivity;
- expected duration;
- resource profile;
- reversibility;
- racing eligibility;
- cost bounds.

### Completion gate

- decisions tested and explainable;
- commit message: `feat: add automatic execution environment policy`.

## 10. Checkpoint H — Minimum candidate racing

### Goal

Run at least two candidates from an identical source baseline, apply identical validation, select deterministically, and clean losers.

### Work order

1. Define candidate and race records.
2. Snapshot identical baseline.
3. Create one machine per candidate through service.
4. Execute candidate plans through durable jobs.
5. Run common validation.
6. Score correctness first.
7. Select winner deterministically.
8. Preserve winner and required evidence.
9. Destroy losers through service.
10. Report cleanup failures separately.

### Completion gate

- no candidate-specific clone lifecycle;
- deterministic tie-break;
- commit message: `feat: add isolated candidate racing foundation`.

## 11. Full gates after every checkpoint

```bash
npm run build
npm run lint
npm test
```

Run focused test commands first when useful, but never substitute them for the full gates.

## 12. Push and verification protocol

After each checkpoint:

1. `git status --short --branch`
2. record commit SHA;
3. record tree SHA;
4. push without force;
5. verify remote branch commit/tree through authorized Baby/GitHub path;
6. confirm ahead/behind zero;
7. preserve test output or evidence artifact;
8. report unresolved limitations honestly.
