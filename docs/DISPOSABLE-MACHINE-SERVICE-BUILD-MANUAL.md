# Baby-X Disposable Machine Service — Authoritative Build and Operations Manual

**Document status:** Frozen implementation plan; implementation has not started.

**Repository:** `StealthEyeLLC/baby-x`

**Governing branch at freeze:** `build/baby-x-god-mode-v1`

**Foundation commit at freeze:** `b849e29f4db3c861f97b9911fe45f5ff1790e76a`

**Foundation tree at freeze:** `2a30ec92bb2385e6d06ccc28f3d0af5784ba63e3`

**Purpose:** This is the single authoritative build plan for turning Baby-X’s proven ZFS + `systemd-nspawn` disposable-machine primitive into a durable, canonical machine lifecycle service; migrating certification to consume that service; adding automatic execution-environment policy; and establishing the minimum foundation for isolated candidate racing.

This document is intentionally one file. Do not split it into policy documents until the implementation is complete, certified, and the final contracts are stable.

---

## 0. Controlling instructions

1. Treat the existing disposable ZFS/nspawn implementation as a proven foundation. Do not replace it with Docker, Podman, LXC, Kubernetes, cloud VMs, chroot-only execution, a second nspawn wrapper, or an alternate scheduler.
2. Keep the existing Baby-X durable execution kernel as the sole execution authority.
3. Make the Disposable Machine Service the sole generic machine lifecycle authority.
4. Do not create a certification-specific clone manager, candidate-specific clone manager, or provider-specific persistence system.
5. Preserve Baby-X’s existing proof, artifact, process identity, operation registry, gateway, and authority boundaries.
6. Do not deploy, activate, restart production services, change release pointers, change OAuth, mutate DNS/Caddy/firewall/systemd production configuration, or modify production credentials as part of this build.
7. Work only on the designated build branch. Push stable checkpoints early. Never force-push.
8. Every checkpoint must end with exact commit/tree reporting, clean status, passing gates, and remote verification.
9. Unknown or ambiguous state must remain `UNKNOWN`, `AMBIGUOUS`, or `RECOVERY_REQUIRED`; never fabricate success.
10. Destructive cleanup requires exact ownership proof and positive absence readback afterward.

---

# Part I — Existing foundation and authority boundaries

## 1. Existing repository shape

The current implementation surface includes:

- `runtime/src/core.ts` — runtime operation routing and provider integration.
- `runtime/src/operations/definitions.ts` — operation contracts.
- `runtime/src/operations/registry.ts` — registered operation authority.
- `runtime/src/execution/executor.ts` — exact executable/argv execution.
- `runtime/src/execution/target.ts` — host or named-machine execution targeting.
- `runtime/src/execution/command-result.ts` — bounded command results.
- `runtime/src/jobs/manager.ts` — durable jobs.
- `runtime/src/process/identity.ts` — process identity and stale PID protection.
- `runtime/src/process/intervention-lease.ts` — intervention ownership.
- `runtime/src/state/atomic-store.ts` — atomic durable state primitives.
- `runtime/src/state/replay-store.ts` — replay/idempotency support.
- `runtime/src/state/schemas.ts` — shared state schemas.
- `runtime/src/artifacts/manager.ts` — artifact authority.
- `runtime/src/proof/proof.ts` and `verify.ts` — proof creation and verification.
- `runtime/src/machines/definitions.ts` — current machine definition types.
- `runtime/src/machines/manager.ts` — generic nspawn/machinectl manager.
- `runtime/src/machines/disposable.ts` — current ZFS clone + nspawn composition.
- `runtime/src/machines/storage.ts` — machine storage functions.
- `runtime/src/machines/networking.ts` — machine networking.
- `runtime/src/machines/nspawn.ts` — nspawn tool declarations.
- `runtime/test/disposable-machine.test.mjs` — disposable primitive tests.
- `runtime/test/machine-manager.test.mjs` — exact machine command tests.
- `runtime/integration/execution.test.mjs` — execution integration.
- `runtime/acceptance/*.test.mjs` — acceptance and God Mode behavior.
- `gateway/src/*` and `gateway/test/*` — gateway discovery, forwarding, OAuth, and proof handling.
- `docs/ARCHITECTURE.md`, `MACHINE-FABRIC.md`, `OPERATIONS.md`, `BUILDING.md`, `GOD-MODE.md`, and certification evidence documents.

The new service must build on these files and concepts rather than introducing a parallel architecture.

## 2. Proven cloning primitive

At the foundation commit, `runtime/src/machines/disposable.ts` already proves the essential environmental bridge:

1. Validate a source ZFS snapshot.
2. Validate the clone dataset name.
3. Validate an absolute machine root.
4. Execute exact argv for `zfs clone` with the intended mount point.
5. Launch `systemd-nspawn` against the cloned root.
6. Execute inside the named machine through existing execution targeting.
7. Terminate the machine.
8. Destroy the exact clone dataset.
9. Read back dataset absence and machine absence.
10. Reject option-injection identifiers and relative roots.

This primitive is not yet the durable lifecycle service. It is the lower-level mechanism that the service will own and compose.

## 3. Frozen authority model

### 3.1 Durable execution authority

The existing execution/job subsystem owns:

- command/job lifecycle;
- process creation;
- stdout and stderr;
- cancellation;
- process identity;
- exit state;
- durable job receipts;
- job-related artifacts.

The machine service must call this authority. It must not create a second job table or second process supervisor.

### 3.2 Machine lifecycle authority

The new Disposable Machine Service owns:

- machine identity reservation;
- source snapshot binding;
- clone dataset ownership;
- root path ownership;
- nspawn machine identity;
- desired and observed machine state;
- machine lifecycle transitions;
- machine expiration;
- reconciliation;
- generic machine cleanup;
- machine lifecycle events and evidence references.

### 3.3 Certification authority

Certification owns:

- the certification profile;
- test selection;
- expected results;
- acceptance/rejection criteria;
- certification-specific evidence indexing;
- final certification truth.

Certification must not own generic cloning, startup, machine adoption, stop, destroy, expiration, or recovery.

### 3.4 Policy authority

Execution policy decides whether an objective should run:

- on the host;
- in an existing persistent workspace;
- in one disposable machine;
- in multiple disposable machines.

Policy makes a decision. It does not execute commands or own lifecycle state.

### 3.5 Candidate racing authority

Candidate racing owns candidate definitions, common validation, scoring, selection, and preservation rules. It consumes the machine service and durable jobs. It does not implement its own isolation substrate.

---

# Part II — Target architecture

## 4. End-state flow

```text
Owner objective
  -> Baby-X operation registry
  -> objective/planner or direct operation
  -> execution policy decision
  -> Disposable Machine Service
       -> persistent machine record
       -> ZFS clone primitive
       -> systemd-nspawn / machinectl
       -> durable job execution targeted at named machine
       -> artifacts and proofs
       -> stop/destroy/reconcile
  -> consumer result
       -> certification result, candidate result, or direct objective result
```

## 5. Architectural invariants

1. A machine name alone is never sufficient identity.
2. A PID alone is never sufficient process identity.
3. A dataset name alone is never sufficient ownership proof.
4. Persisted desired state and observed host state are separate fields.
5. Every state transition increments a sequence number.
6. Every mutating request is idempotent or explicitly non-idempotent.
7. A repeated idempotency key with a different request digest is rejected.
8. Source snapshots are immutable inputs and are never destroyed by machine cleanup.
9. Machine-owned clone datasets are destroyed only after ownership checks.
10. `DESTROYED` is recorded only after dataset, root, process, and machine readback prove absence.
11. Interrupted work is reconciled from durable records plus host readback.
12. Ambiguity blocks destructive automation.
13. Large output is stored as artifacts, not unbounded inline JSON.
14. The gateway forwards dynamically described Baby-X operations and does not become lifecycle authority.
15. The service remains useful for certification, builds, adversarial arenas, failure replay, and future skills.

---

# Part III — Durable data model

## 6. Machine identifiers

### 6.1 `machineId`

A stable service-generated ID, independent of the nspawn machine name. Recommended format:

```text
mx_<lowercase base32 or uuid without ambiguous punctuation>
```

Requirements:

- immutable;
- globally unique within the installation;
- safe for logs and filenames;
- not user-controlled;
- never reused after destruction.

### 6.2 `machineName`

The validated name passed to `systemd-nspawn --machine=` and `machinectl`.

Requirements:

- strict existing validator;
- does not begin with `-`;
- no whitespace, shell metacharacters, path separators, or control bytes;
- unique among non-destroyed records;
- stored separately from `machineId`.

### 6.3 `requestDigest`

Canonical digest of the normalized creation request. Used with idempotency to distinguish a safe retry from a conflicting request.

## 7. Canonical machine record

Implement a versioned schema, initially `schemaVersion: "1.0.0"`.

Required fields:

```ts
interface DisposableMachineRecordV1 {
  schemaVersion: '1.0.0';
  machineId: string;
  machineName: string;
  ownerPrincipal: string;
  authorityReference?: string;
  parentObjectiveId?: string;
  parentCertificationId?: string;
  parentCandidateId?: string;
  idempotencyKey: string;
  requestDigest: string;

  source: {
    provider: 'zfs-snapshot';
    snapshot: string;
    snapshotGuid?: string;
    snapshotCreationTxg?: string;
    expectedDigest?: string;
  };

  clone: {
    dataset: string;
    datasetGuid?: string;
    mountpoint: string;
    expectedDatasetRoot: string;
    createdByMachineId: string;
  };

  launch: {
    provider: 'systemd-nspawn';
    argvDigest?: string;
    boot: boolean;
    networkMode: 'none' | 'private' | 'host' | 'custom';
    readOnly: boolean;
    binds: MachineBind[];
    environment: MachineEnvironmentEntry[];
    properties: MachineProperty[];
    resourceProfile?: MachineResourceProfile;
  };

  lifecycle: {
    desiredState: MachineDesiredState;
    persistedState: MachineState;
    observedState: MachineObservedState;
    stateSequence: number;
    terminal: boolean;
    createdAt: string;
    updatedAt: string;
    expiresAt?: string;
    destroyedAt?: string;
  };

  hostIdentity: {
    hostname: string;
    machineIdSha256: string;
    bootIdAtCreate: string;
    lastObservedBootId?: string;
  };

  processIdentity?: {
    pid: number;
    processStartTime: string;
    executablePath: string;
    bootId: string;
    cgroupPath?: string;
    systemdUnit?: string;
  };

  observations: {
    dataset: 'present' | 'absent' | 'conflict' | 'unknown';
    mountpoint: 'present' | 'absent' | 'conflict' | 'unknown';
    machinectl: 'running' | 'stopped' | 'absent' | 'conflict' | 'unknown';
    process: 'matching' | 'absent' | 'stale' | 'conflict' | 'unknown';
    lastObservedAt?: string;
  };

  activeJobIds: string[];
  artifactIds: string[];
  proofReferences: string[];
  lastError?: MachineFailure;
  recovery?: MachineRecoveryRecord;
  cleanup: MachineCleanupRecord;
}
```

## 8. Lifecycle states

Use explicit uppercase durable states:

- `REQUESTED`
- `CLONING`
- `CLONED`
- `STARTING`
- `READY`
- `EXECUTING`
- `STOPPING`
- `STOPPED`
- `DESTROYING`
- `DESTROYED`
- `DEGRADED`
- `FAILED`
- `LOST`
- `RECOVERY_REQUIRED`
- `AMBIGUOUS`
- `UNKNOWN`

`DESTROYED` is terminal. `FAILED` is not automatically terminal because recovery or cleanup may still be required.

## 9. Desired versus observed state

Persist both:

- `desiredState`: what the accepted request intends;
- `persistedState`: the last validated service transition;
- `observedState`: the latest host readback classification.

Example: after a host reboot, a record may be:

```text
desiredState=READY
persistedState=READY
observedState=STOPPED
```

Reconciliation must not silently rewrite this to success. It should produce a recovery classification and either restart under policy or require repair.

## 10. Allowed transitions

Minimum transition table:

| From | To | Trigger |
|---|---|---|
| none | REQUESTED | accepted create request |
| REQUESTED | CLONING | controller lease acquired |
| CLONING | CLONED | clone exists and identity verified |
| CLONING | FAILED/RECOVERY_REQUIRED | clone command failure or ambiguous readback |
| CLONED | STARTING | accepted start request |
| STARTING | READY | machine and process identities verified |
| STARTING | DEGRADED/FAILED/RECOVERY_REQUIRED | startup incomplete or conflicting |
| READY | EXECUTING | first active machine-targeted job attached |
| EXECUTING | READY | last active job completes and machine remains healthy |
| READY/EXECUTING/DEGRADED | STOPPING | stop request accepted |
| STOPPING | STOPPED | machine and matching process absent |
| STOPPING | RECOVERY_REQUIRED | termination state ambiguous |
| CLONED/STOPPED/FAILED/DEGRADED | DESTROYING | destroy accepted and ownership proved |
| DESTROYING | DESTROYED | all owned runtime resources verified absent |
| any nonterminal | LOST | owned resource disappeared without authorized transition |
| any nonterminal | AMBIGUOUS | conflicting identity evidence |
| any nonterminal | UNKNOWN | required observation unavailable |
| LOST/AMBIGUOUS/UNKNOWN/FAILED | RECOVERY_REQUIRED | deterministic automatic resolution unavailable |

Transition validation must reject skipped happy-path transitions unless a documented reconciliation transition applies.

## 11. Event record

Every mutation appends an immutable event:

```ts
interface MachineEventV1 {
  schemaVersion: '1.0.0';
  machineId: string;
  offset: number;
  stateSequence: number;
  priorState?: MachineState;
  state: MachineState;
  phase: string;
  kind: string;
  message: string;
  requestDigest?: string;
  jobId?: string;
  artifactId?: string;
  proofReference?: string;
  occurredAt: string;
  eventDigest: string;
}
```

Minimum event kinds:

- `machine.requested`
- `machine.identity_reserved`
- `clone.started`
- `clone.created`
- `clone.verified`
- `start.requested`
- `nspawn.started`
- `machine.ready`
- `job.attached`
- `job.completed`
- `stop.requested`
- `machine.stopped`
- `destroy.requested`
- `dataset.destroyed`
- `cleanup.verified`
- `reconcile.started`
- `reconcile.classified`
- `recovery.required`
- `machine.expired`
- `gc.selected`
- `gc.skipped`
- `gc.completed`

---

# Part IV — Service API

## 12. Operation namespace

Use the existing Baby-X namespace convention. The recommended public operations are:

- `babyx.machine.service.describe`
- `babyx.machine.create`
- `babyx.machine.get`
- `babyx.machine.list`
- `babyx.machine.status`
- `babyx.machine.start`
- `babyx.machine.exec`
- `babyx.machine.shell`
- `babyx.machine.stop`
- `babyx.machine.destroy`
- `babyx.machine.reconcile`
- `babyx.machine.expire`
- `babyx.machine.gc`
- `babyx.machine.events`
- `babyx.machine.diagnostics`

Keep existing lower-level machine operations for compatibility only where needed. Mark raw operations as low-level and do not make them the normal certification path.

## 13. `babyx.machine.service.describe`

Read-only discovery output must include:

- service contract version;
- persistence schema versions;
- supported lifecycle operations;
- available providers (`zfs-snapshot`, `systemd-nspawn`);
- supported network modes;
- supported bind modes;
- resource-limit support;
- configured source allowlists;
- configured clone dataset roots;
- configured machine root;
- expiration defaults and bounds;
- recovery classifications;
- maximum inline result size;
- known limitations.

It must not disclose secrets, raw credential material, or private recovery payloads.

## 14. `babyx.machine.create`

### Input

```json
{
  "machineName": "cert-abc123",
  "class": "clean-build",
  "baseSnapshot": "babycert/base/noble@golden-v1",
  "dataset": "babycert/runs/cert-abc123",
  "root": "/var/lib/baby-x/machines/cert-abc123",
  "networkMode": "private",
  "readOnly": false,
  "binds": [],
  "environment": [],
  "properties": [],
  "resourceProfile": {},
  "expiresAt": "...",
  "parentObjectiveId": "..."
}
```

### Behavior

1. Authenticate and authorize principal.
2. Canonicalize request and calculate digest.
3. Validate all identifiers before any side effect.
4. Enforce source snapshot allowlist.
5. Enforce clone dataset root.
6. Enforce machine root confinement.
7. Reserve `machineId`, `machineName`, dataset, and root atomically.
8. Persist `REQUESTED` before clone side effects.
9. Acquire a machine controller lease.
10. Transition to `CLONING`.
11. execute exact `zfs clone` argv using the existing executor.
12. Read back dataset existence, origin, GUID where available, and mountpoint.
13. Reject any mismatch.
14. Transition to `CLONED`.
15. Return the complete bounded machine view and proof binding.

Creation does not imply startup unless an explicit future `start: true` convenience option is added. The initial contract should keep create and start separate.

### Idempotency

- Same idempotency key + same request digest: return/resume the same machine.
- Same key + different digest: reject with `machine_idempotency_conflict`.
- Same requested name/dataset/root owned by another machine: reject with `machine_resource_conflict`.

## 15. `babyx.machine.get`

Read one persisted machine by `machineId`. Optional strict lookup by `machineName` may be allowed only if exactly one record matches.

Return persisted truth, not an implicit live probe. Include an `observationsStale` indicator.

## 16. `babyx.machine.list`

Bounded pagination and filters:

- owner principal;
- state;
- class;
- parent objective;
- parent certification;
- parent candidate;
- expired/non-expired;
- created time range;
- include/exclude terminal.

Default limit must be bounded. Do not return unbounded events or diagnostics inline.

## 17. `babyx.machine.status`

Perform live readback and return:

- persisted state;
- desired state;
- observed state;
- ZFS dataset identity;
- dataset origin;
- mountpoint readback;
- `machinectl show` fields;
- process identity comparison;
- active jobs;
- expiry and cleanup eligibility;
- conflicts;
- recommended next action.

A status read may append an observation event only if the existing event semantics permit read-generated events. Otherwise return the observation without mutation.

## 18. `babyx.machine.start`

### Preconditions

Allowed from `CLONED` or `STOPPED`. A retry may resume `STARTING` after reconciliation.

### Behavior

1. Verify expected state sequence.
2. Verify dataset identity and mountpoint.
3. Verify machine name is not owned by another process/unit.
4. Construct exact nspawn argv through the existing manager.
5. Persist `STARTING` before launch.
6. Launch through the existing durable executor/job authority.
7. Capture job and process identity.
8. Probe `machinectl show` using stable properties rather than parsing human display text.
9. Confirm root directory, leader PID/process start time, class, service/unit, and machine name as available.
10. Perform readiness probe defined by the machine request or default provider probe.
11. Transition to `READY` only when identity and readiness agree.

Startup timeout is not proof of failure. If the process may survive, classify through reconciliation.

## 19. `babyx.machine.exec`

### Input

- `machineId`;
- exact `argv` array;
- optional absolute `cwd` inside machine;
- bounded environment entries;
- timeout/resource overrides within policy;
- artifact capture declarations.

### Behavior

1. Read machine record.
2. Require `READY` or valid `EXECUTING` state.
3. Perform a lightweight identity readback.
4. Submit execution to the existing job/executor using target `{ kind: 'machine', machine: machineName }`.
5. Attach returned job ID to the machine record.
6. Transition to `EXECUTING` while active jobs exist.
7. Preserve stdout, stderr, exit code, signal, process identity, and artifacts through existing authorities.
8. Remove completed job from active set.
9. Return to `READY` if the machine remains healthy.
10. If the machine vanished or identity changed, transition to an explicit failure/recovery state.

No shell interpolation is allowed in `exec`.

## 20. `babyx.machine.shell`

A convenience wrapper for an explicitly requested shell command. It must lower to the same durable execution path as `exec`, for example exact argv:

```text
/usr/bin/bash -lc <command>
```

Document that shell mode is more injection-sensitive and should not be used for structured internal operations.

## 21. `babyx.machine.stop`

### Behavior

1. Validate ownership and expected sequence.
2. Reject or wait when protected active jobs remain according to policy.
3. Persist `STOPPING`.
4. Request graceful shutdown/termination using exact `machinectl` argv.
5. Wait for bounded absence/readback.
6. Escalate only according to explicit policy.
7. Confirm machinectl absence and matching process absence.
8. Preserve logs/diagnostics before final transition when stop fails.
9. Transition to `STOPPED` only after verified absence.

A stale PID must never be killed solely because it equals the recorded numeric PID.

## 22. `babyx.machine.destroy`

### Preconditions

Normal destroy is allowed from `CLONED`, `STOPPED`, and certain failed states after reconciliation. Destroy from a running state must either stop first under an explicit combined policy or reject.

### Behavior

1. Verify machine record and principal.
2. Verify source snapshot is distinct from clone dataset.
3. Verify clone dataset is beneath the allowed machine dataset root.
4. Verify dataset GUID/origin/ownership properties where supported.
5. Verify no protected active job remains.
6. Persist `DESTROYING`.
7. Ensure the named machine and matching process are absent.
8. Unmount/release owned transient dependencies if necessary.
9. Execute exact `zfs destroy -r <owned-dataset>` only for the validated clone.
10. Read back dataset absence.
11. Read back root absence or an empty/non-mounted expected state according to ZFS behavior.
12. Read back machinectl absence.
13. Read back process absence.
14. Persist cleanup evidence.
15. Transition to `DESTROYED`.

If any identity check is ambiguous, do not destroy; transition to `RECOVERY_REQUIRED` or `AMBIGUOUS`.

## 23. `babyx.machine.reconcile`

Reconcile compares durable truth with host truth.

Classifications:

- `HEALTHY_READY`
- `HEALTHY_STOPPED`
- `RUNNING_ADOPTABLE`
- `STOPPED_INTACT`
- `ORPHANED_CLONE`
- `ORPHANED_MACHINE_PROCESS`
- `PARTIAL_CREATION`
- `PARTIAL_DESTRUCTION`
- `SOURCE_MISSING`
- `DATASET_CONFLICT`
- `MACHINE_NAME_CONFLICT`
- `PROCESS_IDENTITY_CONFLICT`
- `HOST_IDENTITY_MISMATCH`
- `UNKNOWN`

Automatic adoption requires exact process and machine identity proof. Numeric PID/name matches alone are insufficient.

Automatic cleanup is permitted only for resources whose ownership can be proven from record plus host metadata. Otherwise produce a diagnostic artifact and require explicit recovery.

## 24. `babyx.machine.expire`

Marks eligible machines for cleanup according to retention policy. Expiration is a lifecycle intent, not immediate deletion.

Protected exclusions:

- active certification designated for preservation;
- selected candidate winner;
- explicit hold flag;
- active protected job;
- unresolved recovery/forensic hold;
- source/base datasets;
- machines outside the configured managed roots.

## 25. `babyx.machine.gc`

Required input:

```json
{
  "dryRun": true,
  "limit": 25,
  "olderThan": "...",
  "states": ["STOPPED", "FAILED", "LOST"]
}
```

Run order:

1. select bounded candidates;
2. emit exact reason for selection or exclusion;
3. reconcile each candidate;
4. destroy only proven-owned eligible resources;
5. verify absence;
6. preserve final evidence;
7. return selected/skipped/removed/failed lists.

Always implement and test dry-run before destructive GC.

## 26. `babyx.machine.events`

Return bounded append-only events by exact offset. Events must be digest-verifiable and paginated.

## 27. `babyx.machine.diagnostics`

Create an artifact containing:

- redacted machine record;
- recent events;
- relevant job summaries;
- `zfs list/get` readback;
- `machinectl show/status` readback;
- process identity readback;
- mount readback;
- configuration digest;
- last failure/recovery classification.

Never include raw secrets or unbounded journal output.

---

# Part V — Persistence and concurrency

## 28. Storage layout

Use the existing atomic/replay storage primitives. Recommended logical layout:

```text
state/
  machines/
    records/<machineId>.json
    events/<machineId>.jsonl
    indexes/by-name/<machineName>
    indexes/by-dataset/<escaped-dataset>
    indexes/by-root/<digest>
    indexes/by-owner/<owner>/<machineId>
    idempotency/<key-digest>.json
    leases/<machineId>.json
```

Actual physical layout should follow repository conventions. Do not introduce a database unless current atomic stores cannot satisfy the invariants and a design change is explicitly justified.

## 29. Atomic mutation sequence

For each mutation:

1. load and schema-validate record;
2. verify expected sequence;
3. acquire controller lease;
4. verify idempotency/request digest;
5. persist intent transition;
6. perform external side effect through durable execution;
7. perform readback;
8. append event/evidence references;
9. persist resulting state with incremented sequence;
10. release lease.

Crashes between steps must be recoverable by reconciliation.

## 30. Controller lease

Only one mutating controller may own a machine at a time. Lease fields:

- lease ID;
- machine ID;
- owner process identity;
- host boot ID;
- operation;
- acquired/renewed/expires timestamps;
- request digest.

A lease from a prior boot cannot be trusted without recovery. A live matching controller blocks conflicting mutation.

## 31. Index integrity

Indexes are derived helpers, not independent truth. Verification must detect:

- missing index for live record;
- index pointing at missing record;
- duplicate name/dataset/root ownership;
- terminal records holding live ownership reservations unexpectedly.

Provide a bounded repair path that rebuilds indexes from validated records.

---

# Part VI — Safety and security

## 32. ZFS safety

1. Allow only configured source snapshot roots.
2. Allow clone datasets only beneath configured managed roots.
3. Reject names beginning with `-`.
4. Pass dataset and snapshot as exact argv entries.
5. Read back `origin`, `guid`, and `mountpoint` where available.
6. Store source and clone identities separately.
7. Never call recursive destroy on a value derived only from user text.
8. Never destroy a dataset that equals or contains the configured base/source hierarchy.
9. Treat missing ZFS tools or unavailable pool as `resource_unavailable`, not generic success/failure.

## 33. Path safety

- absolute paths only;
- configured confinement root;
- reject `..` traversal after normalization;
- reject symlink components for sensitive replacement/ownership paths;
- reject root `/` and managed-root ancestors;
- explicit bind source/destination validation;
- read-only binds by default;
- no accidental host root, `/proc`, `/sys`, device, credential, or runtime socket exposure without explicit policy.

## 34. Process safety

- exact executable paths;
- exact argv arrays;
- process start time and boot ID binding;
- cgroup/systemd unit binding when available;
- process-group-aware cancellation;
- bounded deadlines;
- no killing by stale PID;
- preserve diagnostics before escalation.

## 35. Network policy

Supported modes:

- `none`: no network namespace connectivity beyond required loopback semantics;
- `private`: private veth/network namespace under configured policy;
- `host`: shared host networking, high risk and policy-gated;
- `custom`: validated future profile.

Default to `private` for ordinary builds requiring package access and `none` for deterministic offline validation where inputs are already present. Host networking must never be selected casually.

## 36. Resource policy

Support bounded optional properties for:

- memory maximum;
- CPU quota/weight;
- tasks maximum;
- file descriptor limit;
- runtime deadline;
- disk quota/reservation where available;
- output byte limit;
- artifact byte/count limit;
- network policy.

Resource-limit implementation should reuse systemd/nspawn properties rather than inventing an alternate supervisor.

## 37. Secret handling

- store credential references, not raw credentials, in records;
- redact environment values marked secret;
- do not include secrets in command argv when a safer reference/file descriptor mechanism exists;
- diagnostics and public evidence must be redacted;
- clone cleanup must include owned transient credential material when applicable.

---

# Part VII — Repository implementation plan

## 38. New and modified files

The exact file split may adjust to repository conventions, but the intended ownership is:

### New runtime files

- `runtime/src/machines/service.ts` — public lifecycle orchestration.
- `runtime/src/machines/record.ts` — record types and validation.
- `runtime/src/machines/states.ts` — states, transition table, helpers.
- `runtime/src/machines/store.ts` — record/event/index persistence.
- `runtime/src/machines/identity.ts` — dataset/machine/process ownership binding.
- `runtime/src/machines/reconcile.ts` — observation and recovery classification.
- `runtime/src/machines/gc.ts` — expiration and bounded garbage collection.
- `runtime/src/machines/diagnostics.ts` — bounded diagnostic artifact assembly.
- `runtime/src/machines/policy.ts` — later execution-environment policy.

### Existing runtime files to modify

- `runtime/src/machines/disposable.ts` — reduce to low-level provider/mechanism or adapt into service internals; preserve proven exact argv behavior.
- `runtime/src/machines/manager.ts` — expose stable probes and exact command builders needed by the service.
- `runtime/src/machines/definitions.ts` — preserve compatibility and add versioned types only where appropriate.
- `runtime/src/machines/storage.ts` and `networking.ts` — integrate ownership/readback contracts.
- `runtime/src/execution/target.ts` — ensure exact machine targeting remains canonical.
- `runtime/src/core.ts` — register service operations and route them.
- `runtime/src/operations/definitions.ts` — define schemas, risk, idempotency, support, and errors.
- `runtime/src/operations/registry.ts` — register operations.
- `runtime/src/state/schemas.ts` — add machine schemas if that is the existing schema authority.
- `runtime/src/index.ts` and server/CLI wiring as required.

### Tests

- `runtime/test/machine-record.test.mjs`
- `runtime/test/machine-states.test.mjs`
- `runtime/test/machine-store.test.mjs`
- `runtime/test/machine-service-create.test.mjs`
- `runtime/test/machine-service-start.test.mjs`
- `runtime/test/machine-service-exec.test.mjs`
- `runtime/test/machine-service-stop-destroy.test.mjs`
- `runtime/test/machine-reconcile.test.mjs`
- `runtime/test/machine-gc.test.mjs`
- extend `runtime/test/disposable-machine.test.mjs`
- extend `runtime/test/machine-manager.test.mjs`
- add integration and acceptance tests.

### Documentation to update after implementation

- this manual with exact final contracts;
- `docs/ARCHITECTURE.md`;
- `docs/MACHINE-FABRIC.md`;
- `docs/OPERATIONS.md`;
- `docs/BUILDING.md`;
- `docs/LIMITATIONS.md`;
- certification evidence document for the completed service.

## 39. Coding rules

1. Full typed objects; avoid unvalidated `Record<string, unknown>` at authority boundaries.
2. Use existing canonical JSON/digest helpers.
3. Use exact argv, never string-built shell for lifecycle internals.
4. Use existing `CommandResult` and executor contracts.
5. Reuse existing process identity logic.
6. Reuse existing atomic/replay stores.
7. Keep command-building tests exact and readable.
8. Make errors stable machine-readable codes with bounded human messages.
9. Avoid hidden retries; retries must be bounded and observable.
10. Do not claim readiness or cleanup based only on exit code.

---

# Part VIII — Checkpoint-by-checkpoint build

## 40. Checkpoint 0 — Freeze and verify foundation

### Actions

1. Verify branch is `build/baby-x-god-mode-v1`.
2. Verify HEAD/tree equal the frozen foundation or document a newer approved docs-only base.
3. Verify clean working tree.
4. Run `npm run build`, `npm run lint`, and `npm test`.
5. Record current disposable and machine-manager tests.
6. Create a safety branch/tag reference if project policy uses one.

### Exit criteria

- exact base commit/tree recorded;
- all existing gates pass;
- no implementation changes;
- remote equals local.

## 41. Checkpoint A — Schema, states, events, store

### Build

1. Add versioned record schema.
2. Add lifecycle state enum and transition table.
3. Add canonical request/event digesting.
4. Add atomic record persistence.
5. Add append-only events.
6. Add indexes and idempotency records.
7. Add controller lease.
8. Add schema migration rejection/handling for unknown versions.

### Tests

- every allowed transition;
- every forbidden transition;
- sequence mismatch;
- duplicate idempotency same digest;
- duplicate idempotency different digest;
- corrupt record;
- corrupt event digest;
- stale lease;
- duplicate name/dataset/root index;
- atomic write interruption simulation where feasible.

### Commit theme

`feat: add durable disposable machine state model`

### Exit criteria

No ZFS/nspawn behavior changes yet. All old and new tests pass.

## 42. Checkpoint B — Create, get, list, status

### Build

1. Add service constructor/dependencies.
2. Implement create validation/reservation.
3. Persist intent before clone.
4. Call existing disposable clone mechanism through exact executor.
5. Add post-clone readback.
6. Persist `CLONED` and evidence.
7. Implement get/list.
8. Implement status observations.

### Tests

- successful clone;
- missing snapshot;
- option injection;
- relative/unsafe root;
- dataset outside root;
- duplicate resources;
- clone command fails before creation;
- clone command fails but dataset exists;
- readback mismatch;
- same idempotent create;
- conflicting idempotent create;
- bounded list/filter/pagination;
- status agreement and disagreement.

### Commit theme

`feat: add durable disposable machine creation and inspection`

## 43. Checkpoint C — Start and execute

### Build

1. Implement start transition and controller lease.
2. Add exact nspawn launch.
3. Capture process/job identity.
4. Add machinectl stable property probes.
5. Add readiness definition.
6. Implement exec and shell through existing durable jobs.
7. Track active jobs and state transitions.

### Tests

- exact nspawn argv;
- successful ready probe;
- startup timeout with surviving process;
- immediate process exit;
- name conflict;
- stale PID conflict;
- machinectl disagreement;
- exec success/nonzero/signal/timeout;
- concurrent jobs;
- machine disappears during job;
- shell lowers to exact Bash argv;
- no alternate job persistence introduced.

### Commit theme

`feat: add durable nspawn machine startup and execution`

## 44. Checkpoint D — Stop and verified destruction

### Build

1. Implement graceful stop.
2. Implement bounded wait/escalation policy.
3. Verify exact process absence.
4. Implement destroy ownership checks.
5. Destroy clone only.
6. Verify dataset, mountpoint, machine, and process absence.
7. Persist terminal cleanup evidence.

### Tests

- normal stop;
- already stopped retry;
- active protected job;
- stale PID reuse;
- wrong machine principal/name;
- graceful timeout/escalation;
- destroy stopped clone;
- reject source dataset destruction;
- reject unknown/conflicting dataset;
- partial destroy;
- absence verification failure;
- idempotent repeated destroy.

### Commit theme

`feat: add verified disposable machine shutdown and destruction`

## 45. Checkpoint E — Reconciliation, recovery, expiration, GC

### Build

1. Implement observation collector.
2. Implement recovery classifier.
3. Reconcile nonterminal records at service startup in bounded batches.
4. Adopt only exact surviving identities.
5. Resume safe incomplete cleanup.
6. Implement expiration.
7. Implement GC dry-run.
8. Implement destructive GC after dry-run tests.
9. Add index verification/repair.

### Tests

- service restart during cloning;
- restart during startup;
- restart while ready;
- restart during stop;
- restart during destroy;
- host boot ID change;
- running adoptable machine;
- orphaned clone;
- orphaned process;
- partial destruction;
- ambiguous ownership;
- protected machine exclusion;
- expiration selection;
- bounded GC;
- GC dry-run has no side effects;
- GC verifies absence.

### Commit theme

`feat: add disposable machine recovery and expiration cleanup`

## 46. Checkpoint F — Certification migration

### Required target flow

```text
certification plan
  -> machine.create
  -> machine.start
  -> machine.exec certification steps
  -> artifact/proof collection
  -> machine.stop
  -> machine.destroy
  -> final certification result
```

### Build

1. Inventory every existing certification clone/start/cleanup call.
2. Replace it with machine service calls.
3. Preserve certification result semantics.
4. Bind machine ID and lifecycle proofs into certification evidence.
5. Remove duplicated generic lifecycle code.
6. Keep failure preservation policy explicit.

### Tests

- successful certification;
- test failure still cleans normally;
- preservation-on-failure when requested;
- interrupted certification resumes/reconciles;
- cleanup failure blocks false success;
- source snapshot preserved;
- certification no longer executes raw ZFS/nspawn lifecycle commands.

### Commit theme

`refactor: route certification through disposable machine service`

## 47. Checkpoint G — Automatic execution policy

### Policy inputs

- mutation risk;
- unknown dependency risk;
- reversibility;
- required tools/packages;
- source sensitivity;
- reproducibility requirement;
- network need;
- runtime and disk estimate;
- explicit user constraint;
- candidate-racing eligibility.

### Policy outputs

```ts
{
  mode: 'host' | 'workspace' | 'disposable' | 'parallel-disposable';
  rationale: string[];
  machineProfile?: ...;
  validationProfile: ...;
  cleanupPolicy: ...;
}
```

### Mandatory rules

- production activation/host recovery remains host-authoritative;
- risky unknown dependency installation defaults to disposable;
- certification defaults to disposable;
- ordinary read-only inspection may remain host/workspace;
- user does not normally need to choose manually;
- policy decision is recorded as evidence.

### Commit theme

`feat: add automatic execution environment policy`

## 48. Checkpoint H — Candidate racing minimum viable capability

### Scope

Implement the smallest useful race:

1. accept one objective and two or more candidate strategies;
2. bind all candidates to the same source commit/tree/snapshot;
3. create one disposable machine per candidate;
4. execute independently;
5. run the same validation profile;
6. score deterministically;
7. select one winner or return no winner;
8. preserve winner evidence and useful failure evidence;
9. destroy losers after evidence preservation;
10. never merge/deploy automatically unless separately authorized.

### Candidate record

- candidate ID;
- objective ID;
- strategy digest;
- source identity;
- machine ID;
- child job IDs;
- validation profile digest;
- result/evidence;
- score components;
- rejection reason;
- selected flag.

### Scoring precedence

1. correctness/required tests;
2. security/policy compliance;
3. reproducibility;
4. regression risk;
5. maintainability/change size;
6. runtime/resource use.

Speed can never outweigh failed correctness gates.

### Tests

- two successful candidates deterministic winner;
- one success/one failure;
- all fail;
- tied scores deterministic tie rule;
- candidate machine crash;
- common baseline mismatch rejected;
- loser cleanup verified;
- winner preservation;
- race restart/reconcile.

### Commit theme

`feat: add isolated candidate racing foundation`

---

# Part IX — Complete validation matrix

## 49. Unit validation

- schema validation;
- canonical digest stability;
- transition table;
- idempotency;
- sequence checks;
- lease checks;
- identifier validation;
- path confinement;
- source/clone distinction;
- event digest chain/index;
- recovery classification;
- GC eligibility;
- policy decisions;
- candidate scoring.

## 50. Exact command validation

Assert full argv arrays for:

- `zfs clone`;
- `zfs list/get`;
- `zfs destroy`;
- `systemd-nspawn`;
- `machinectl show/status/terminate`;
- machine-targeted execution;
- mount/unmount commands if used.

Every externally controlled identifier requires an option-injection test.

## 51. Integration validation

Use actual disposable resources where authorized:

- create only;
- create/start/status;
- exec success/failure;
- stop/restart;
- full create-to-destroy;
- repeated idempotent requests;
- concurrent mutation rejection;
- interrupted lifecycle phases;
- service restart;
- host reboot simulation/readback where practical;
- expiration and GC;
- certification migration;
- two-candidate race.

## 52. Negative validation

Must explicitly test:

- nonexistent source;
- source outside allowlist;
- invalid snapshot/dataset/name;
- `-` option injection;
- traversal/relative root;
- symlink root component;
- root `/`;
- duplicate name/dataset/root;
- unauthorized bind;
- unauthorized host network;
- resource limit outside policy;
- start destroyed machine;
- exec stopped machine;
- destroy running protected machine;
- destroy source dataset;
- stale PID reuse;
- stale boot identity;
- machinectl name collision;
- dataset GUID conflict;
- corrupted record/event/index;
- unavailable ZFS/systemd;
- ambiguous readback;
- cleanup verification failure.

## 53. Stress and boundedness

- many terminal records with paginated list;
- bounded startup reconciliation;
- bounded GC batch;
- large stdout/stderr routed to existing stream/artifact limits;
- event pagination;
- repeated retries;
- concurrent status reads and one mutation;
- no unbounded in-memory accumulation.

## 54. Required repository gates

At each checkpoint run at minimum:

```bash
npm run build
npm run lint
npm test
```

Run focused suites during development, but the full gate is required before each pushed checkpoint.

Also verify:

```bash
git status --short --branch
git rev-parse HEAD
git rev-parse HEAD^{tree}
git log -1 --oneline
```

---

# Part X — How to operate and execute with Baby

## 55. Current Baby Quirt invocation model

The production Baby interface is the single authenticated call surface:

```text
baby.call_quirt(operation, payload, idempotencyKey)
```

The currently deployed Baby Quirt supports durable shell/exec, jobs, streams, files, artifacts, release/delivery operations, GitHub verification, and signed receipts. Baby-X operations are exposed through the installed Baby-X gateway/runtime when that build is running.

Operational rules:

1. Call `baby.describe` first when operation contracts may have changed.
2. Use one unique idempotency key per logical mutation.
3. Reuse a key only for the exact same operation and payload.
4. For long-running work, use detached durable jobs, then `baby.job.wait/get` and stream reads.
5. Preserve returned verified receipt IDs in checkpoint evidence.
6. Do not use ad hoc anonymous Git pushes; use the authorized GitHub connector/delivery authority and remote verification.

## 56. Implementing this build through Baby today

Until the new machine service operations exist, the implementation tab should use Baby’s durable repository workspace and shell/file operations.

Authoritative workspace:

```text
/var/lib/baby-quirt/workspaces/baby-x-god-mode-v1/baby-x
```

### 56.1 Inspect repository

Use `baby.shell` with `/bin/bash`, explicit `cwd`, and an exact script. Example logical payload:

```json
{
  "shell": "/bin/bash",
  "cwd": "/var/lib/baby-quirt/workspaces/baby-x-god-mode-v1/baby-x",
  "script": "set -euo pipefail\ngit status --short --branch\ngit rev-parse HEAD\ngit rev-parse HEAD^{tree}\n"
}
```

### 56.2 Edit files

Preferred order:

1. read/stat exact file;
2. use `baby.file.replace` with `expectedSha256` for atomic compare-and-swap replacement;
3. use `expectedAbsent: true` for new files;
4. preserve mode and create parents intentionally;
5. verify file SHA afterward.

For coordinated multi-file edits, a durable Bash/Python script inside the workspace is acceptable, but it must write complete files atomically and end with repository diff/status output.

### 56.3 Run tests

Submit a detached durable job when the full test suite may exceed one request window:

```text
baby.shell(detached=true, script="npm run build && npm run lint && npm test")
```

Then:

```text
baby.job.wait(jobId, bounded timeout)
baby.job.stream.read(jobId, stdout/stderr, exact offsets)
```

Do not infer success from truncated output; read the terminal job state and exit code.

### 56.4 Commit checkpoint

After review and gates:

```bash
git add <exact files>
git diff --cached --check
git diff --cached --stat
git commit -m "<checkpoint message>"
git status --short --branch
git rev-parse HEAD
git rev-parse HEAD^{tree}
```

Do not stage unrelated files.

### 56.5 Publish

Use the authorized GitHub path. If local HTTPS credentials are unavailable, do not repeatedly retry anonymous push. Publish through the connected GitHub repository authority, preserving a fast-forward history, then verify exact remote commit/tree with Baby’s GitHub verification operation where registered.

### 56.6 Checkpoint report

Every report must include:

- branch;
- base commit/tree;
- resulting commit/tree;
- files changed;
- tests/lint/build results;
- remote verification;
- unresolved limitations;
- next checkpoint.

## 57. Operating the completed machine service

The following examples are target user intents. Exact payload schemas must be taken from runtime discovery after implementation.

### 57.1 Create an isolated machine

User intent:

> Create a disposable machine from the approved Noble base for this build, private network, 8 GB memory, and clean it after two hours.

Baby should:

1. choose disposable policy;
2. resolve approved base snapshot;
3. create a unique machine name/dataset/root;
4. call `babyx.machine.create`;
5. return machine ID and `CLONED` status.

### 57.2 Start and run work

User intent:

> Start that machine and run the repository build and tests.

Baby should:

1. call `babyx.machine.start`;
2. wait for `READY`;
3. call `babyx.machine.exec` with exact argv, not a shell string where avoidable;
4. monitor durable job;
5. return exit state, streams/artifacts, and proof references.

### 57.3 Stop and destroy

User intent:

> Preserve the test evidence, then clean up the machine.

Baby should:

1. finalize requested artifacts;
2. stop machine;
3. destroy clone;
4. verify absence;
5. return cleanup proof.

### 57.4 Reconcile interrupted work

User intent:

> Recover or classify every interrupted disposable machine.

Baby should:

1. list nonterminal/recovery states;
2. reconcile in bounded batches;
3. adopt exact surviving identities;
4. resume safe cleanup;
5. report ambiguous cases without destructive guessing.

### 57.5 Garbage collection

User intent:

> Show what expired disposable machines can be removed.

Baby first runs GC dry-run and reports candidates/exclusions. Only an explicitly authorized follow-up performs destruction.

### 57.6 Certification

User intent:

> Certify this exact commit and tree in a clean disposable machine.

Baby resolves exact source, creates/starts a machine, executes the fixed certification profile, captures evidence, stops/destroys, and returns the certification result plus lifecycle proof.

### 57.7 Candidate race

User intent:

> Try three implementation strategies against the same source, run identical gates, preserve the winner, and clean the losers.

Baby creates three machines from the same source snapshot, binds each candidate, runs identical validation, scores deterministically, preserves winner evidence, and verifies loser cleanup.

---

# Part XI — Certification migration details

## 58. Evidence required from each certification machine

- exact source commit/tree;
- source snapshot/digest;
- machine ID/name;
- clone dataset identity and origin;
- machine root;
- create/start transition events;
- nspawn argv digest;
- readiness evidence;
- each certification job ID and receipt;
- stdout/stderr/artifact digests;
- stop/destroy events;
- dataset/machine/process absence evidence;
- final certification result digest.

## 59. Failure behavior

- Build/test failure: certification may reject while cleanup still succeeds.
- Cleanup failure: certification cannot claim fully successful disposable certification.
- Ambiguous machine identity: preserve diagnostics and require recovery.
- Infrastructure unavailable: classify separately from product failure.
- Evidence missing/corrupt: reject certification integrity.

---

# Part XII — Commit, branch, and delivery discipline

## 60. Branch discipline

Continue on `build/baby-x-god-mode-v1` unless a new explicit branch is approved. Do not rewrite existing published commits.

## 61. Checkpoint commits

Recommended sequence:

1. `docs: add disposable machine service build manual`
2. `feat: add durable disposable machine state model`
3. `feat: add durable disposable machine creation and inspection`
4. `feat: add durable nspawn machine startup and execution`
5. `feat: add verified disposable machine shutdown and destruction`
6. `feat: add disposable machine recovery and expiration cleanup`
7. `refactor: route certification through disposable machine service`
8. `feat: add automatic execution environment policy`
9. `feat: add isolated candidate racing foundation`
10. `docs: record disposable machine service certification`

Implementation and tests may be separate commits when that improves reviewability, but each pushed checkpoint must be internally coherent.

## 62. Fast-forward rule

Before publishing, verify remote head. If it moved, reconcile intentionally. Never force-push. Never manufacture a second parallel lineage for the same checkpoint.

---

# Part XIII — Definition of done

## 63. Machine service completion

The machine-service stage is complete only when:

- one canonical durable record/event implementation exists;
- create/get/list/status/start/exec/stop/destroy/reconcile/expire/gc work;
- process, machine, dataset, source, root, and host identities are bound;
- interruption recovery is deterministic;
- ambiguous ownership blocks destruction;
- cleanup is positively verified;
- source snapshots are protected;
- all operations are discoverable with schemas, risk, idempotency, support, errors, and limits;
- all repository gates pass;
- exact remote commit/tree verification succeeds.

## 64. Certification migration completion

Complete only when certification uses the service exclusively for generic lifecycle and no duplicated ZFS/nspawn cleanup path remains.

## 65. Policy completion

Complete only when policy decisions are deterministic, evidence-backed, tested, and do not override hard authority boundaries.

## 66. Candidate-racing foundation completion

Complete only when at least two identical-baseline isolated candidates can execute, validate, compare, select or reject, preserve evidence, and verify loser cleanup.

## 67. Final acceptance checklist

- [ ] Frozen base verified.
- [ ] Manual present and updated to final contracts.
- [ ] State schema versioned.
- [ ] Transition table exhaustive.
- [ ] Durable records/events/indexes/idempotency implemented.
- [ ] Controller lease implemented.
- [ ] Create and clone readback implemented.
- [ ] Start and readiness implemented.
- [ ] Machine-targeted durable exec implemented.
- [ ] Stop and process absence implemented.
- [ ] Destroy and dataset absence implemented.
- [ ] Reconciliation implemented.
- [ ] Expiration and GC dry-run/destruction implemented.
- [ ] Diagnostics artifact implemented.
- [ ] Certification migrated.
- [ ] Execution policy implemented.
- [ ] Candidate racing MVP implemented.
- [ ] Unit tests pass.
- [ ] Exact argv tests pass.
- [ ] Integration tests pass.
- [ ] Negative tests pass.
- [ ] Restart/recovery tests pass.
- [ ] Build passes.
- [ ] Lint passes.
- [ ] Full test suite passes.
- [ ] Working tree clean.
- [ ] Remote commit/tree match.
- [ ] Public-safe certification evidence written.
- [ ] No production mutation occurred.

---

# Part XIV — Handoff prompt for the implementation tab

Use the following as the controlling opening instruction:

> Implement the Baby-X Disposable Machine Service according to `docs/DISPOSABLE-MACHINE-SERVICE-BUILD-MANUAL.md`. Treat that document as the governing specification and the existing ZFS + systemd-nspawn disposable primitive as the certified environmental foundation. Do not redesign or replace the primitive. Begin by independently verifying the branch, exact base commit/tree, working-tree cleanliness, repository layout, and all current build/lint/test gates. Then execute Checkpoint A only: the versioned durable machine record, lifecycle state/transition validator, append-only events, atomic persistence/indexes, idempotency, and controller lease. Preserve the existing durable job engine as sole execution authority and do not create alternate scheduling, process supervision, artifacts, receipts, or certification-specific lifecycle. Add exhaustive tests, commit a stable checkpoint, publish by fast-forward through the authorized GitHub path, verify exact remote commit/tree, and report evidence. Do not deploy, activate, merge, force-push, or mutate production.

---

# Part XV — Final intent

This build should feel incremental rather than exploratory. The environmental bridge already exists. The work is to turn the proven mechanism into one durable reusable service, migrate consumers onto it, and then exploit it for automatic isolation and candidate racing.

The implementation tab should not spend time re-deciding the architecture. It should verify the frozen assumptions, execute each checkpoint, surface concrete contradictions if found, and keep every step independently testable, recoverable, and remotely anchored.
