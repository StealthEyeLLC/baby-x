# Disposable Machine Service — Test and Certification Plan

## 1. Testing philosophy

The service is not complete because the happy path works. It is complete when identity, interruption, retries, conflicts, cleanup, and evidence are verified under adversarial conditions.

Every test must distinguish:

- command success;
- provider observation;
- durable state transition;
- cleanup truth;
- consumer result.

## 2. Test layers

### 2.1 Pure unit tests

No host mutation. Cover:

- validators;
- canonical serialization;
- request/event digests;
- state transitions;
- terminal/recoverable classification;
- path confinement;
- ZFS name restrictions;
- machine-name restrictions;
- bind and environment normalization;
- resource profile validation;
- recovery classification from synthetic observations;
- GC eligibility;
- policy decisions;
- candidate scoring.

### 2.2 Command-construction tests

Use fake executor and assert exact argv for:

- `zfs list/get/clone/set/destroy`;
- `systemd-nspawn` launch;
- `machinectl show/status/terminate/copy-to/copy-from` where applicable;
- machine-targeted exec;
- systemd resource properties;
- observation commands.

Every external identifier gets injection cases beginning with `-`, containing whitespace, separators, control bytes, excessive length, and traversal-like values.

### 2.3 Store tests

Use disposable temporary state roots. Cover:

- atomic record creation;
- compare-and-swap update;
- stale sequence rejection;
- append-only events;
- partial write simulation;
- event-chain verification;
- index rebuild;
- tombstone retention;
- corruption detection;
- concurrent reader/writer behavior.

### 2.4 Provider integration tests

Use authorized disposable ZFS datasets and nspawn machines. Cover the real environmental bridge:

- clone exact snapshot;
- verify origin/GUID/mountpoint/properties;
- launch exact machine;
- execute a command;
- stop;
- destroy;
- prove absence.

Tests must be self-cleaning but retain evidence when cleanup fails.

### 2.5 Service integration tests

Exercise public machine operations through the runtime registry, not private methods only.

Required flows:

1. create only;
2. create and start;
3. create/start/exec/stop/destroy;
4. start after stop;
5. multiple exec jobs;
6. nonzero command exit without machine failure;
7. command timeout/cancel;
8. repeated idempotent requests;
9. conflicting idempotent requests;
10. expiration and GC;
11. explicit reconcile;
12. restart during each lifecycle phase.

### 2.6 Gateway tests

Prove:

- operations are discovered dynamically;
- schemas are surfaced correctly;
- requests are forwarded unchanged except protocol wrapping;
- proof is verified;
- large evidence is not inlined unsafely;
- OAuth scope/authority is preserved;
- gateway does not implement lifecycle logic.

### 2.7 Acceptance tests

Acceptance runs through the same public interface used by Baby. It verifies outcomes and evidence, not implementation internals.

## 3. Mandatory negative matrix

### Identity

- same machine name, different machine ID;
- same PID, different start time;
- same PID/start time, different boot ID;
- same dataset name, different GUID;
- same dataset, wrong origin snapshot;
- correct origin, wrong ownership property;
- correct machine name, wrong root path;
- stale machinectl entry;
- missing process executable.

### Input safety

- leading-dash machine name;
- leading-dash dataset;
- relative root;
- root outside allowed prefix;
- symlink in protected path;
- bind host root;
- writable credential bind;
- invalid environment name;
- secret value persisted where reference is required;
- overflowed memory/CPU/disk bounds.

### Lifecycle

- start from `DESTROYING`;
- exec from `STOPPED`;
- destroy from `READY` with protected job;
- stale expected sequence;
- concurrent controllers;
- event offset conflict;
- duplicate name reservation;
- destroy already foreign dataset;
- recreate tombstoned machine ID.

### Provider failure

- `zfs clone` nonzero;
- clone zero but dataset absent;
- clone exists but readback mismatches;
- nspawn launch nonzero;
- launch process exists but readiness mismatches;
- machinectl unavailable;
- ZFS unavailable;
- stop nonzero but process absent;
- destroy nonzero but dataset absent;
- destroy zero but dataset present.

### Recovery

- process killed during start;
- runtime killed after clone command before state update;
- runtime killed after state update before command;
- runtime killed during stop;
- runtime killed during destroy;
- host reboot during ready state;
- corrupted last event;
- missing index;
- stale lease from old boot;
- GC races with explicit start.

## 4. Fault injection

Introduce deterministic test hooks at phase boundaries rather than timing-dependent sleeps. Example phases:

- after `REQUESTED` write;
- before clone command;
- after clone command;
- after clone readback;
- before `CLONED` write;
- after `STARTING` write;
- after nspawn launch;
- before readiness write;
- after stop request;
- after process absence;
- after destroy command;
- before absence verification;
- before tombstone write.

Hooks are test-only and must not become public production controls.

## 5. Cleanup verification assertions

A full lifecycle acceptance test must assert:

- clone dataset absent;
- mountpoint/root absent or benign parent state documented;
- machinectl entry absent;
- matching process absent;
- no active related job remains;
- source snapshot still present and unchanged;
- tombstone present;
- final event state `DESTROYED`;
- cleanup evidence references valid;
- no secret leaked in events, artifacts, stdout, or proof.

## 6. Certification migration tests

Certification must use the machine service. Tests should instrument or mock low-level providers to prove no direct generic lifecycle calls remain in certification.

Required scenarios:

- full success;
- test failure;
- dependency/tool installation failure;
- compile failure;
- acceptance failure;
- runtime restart during certification;
- candidate evidence collection failure;
- stop failure;
- destroy failure;
- evidence retention request;
- expired certification cleanup.

Certification success is forbidden when teardown is required but unresolved. The result should distinguish test success from lifecycle cleanup failure.

## 7. Candidate racing tests

Only after Checkpoint H:

- two candidates receive identical source identity;
- candidates cannot see each other’s writable state;
- common validation is identical;
- correctness dominates runtime score;
- deterministic tie-break;
- rejected candidate reason preserved;
- losing machine cleanup verified;
- winner preservation obeys policy;
- race resume after runtime restart;
- one candidate provider failure does not falsify another result.

## 8. Performance checks

Performance is secondary to correctness, but capture:

- clone duration;
- start-to-ready duration;
- exec overhead;
- stop duration;
- destroy duration;
- reconciliation duration;
- state/event write overhead;
- disk usage per clone;
- bounded list/status latency.

No optimization may remove required readback or weaken identity checks.

## 9. Full gate commands

```bash
npm run build
npm run lint
npm test
```

Use focused commands during development, for example:

```bash
npm run build
node --test runtime/test/machine-state.test.mjs
node --test runtime/test/machine-service-create.test.mjs
node --test runtime/integration/disposable-machine-lifecycle.test.mjs
```

Actual filenames must follow the implemented repository layout.

## 10. Disposable certification procedure

1. Verify clean repository and exact commit/tree.
2. Create a protected source snapshot or certified base snapshot.
3. Use the public service to create a new machine.
4. Start and verify readiness.
5. Materialize exact source identity inside the machine.
6. Install only authorized test dependencies inside the disposable machine.
7. Run build, lint, unit, integration, and acceptance gates.
8. Capture bounded output and content-addressed artifacts.
9. Record source commit/tree and machine identity.
10. Stop and destroy through the service.
11. Verify source remains intact and clone resources are absent.
12. Produce a signed certification evidence index.

## 11. Checkpoint acceptance report

Each checkpoint report includes:

- branch;
- parent commit/tree;
- resulting commit/tree;
- changed files;
- focused tests and results;
- full gates and results;
- disposable integration evidence when applicable;
- unresolved limitations;
- remote verification;
- clean working tree status.

## 12. Final definition of certified

- all operation contracts implemented;
- all mandatory negative tests pass;
- restart recovery tested at phase boundaries;
- certification consumes service;
- source protection proven;
- cleanup proven;
- gateway forwarding proven;
- no duplicate lifecycle authority;
- exact remote commit/tree verified;
- public-safe evidence document committed.
