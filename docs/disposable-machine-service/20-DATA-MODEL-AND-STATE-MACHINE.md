# Disposable Machine Service — Durable Data Model and State Machine

## 1. Purpose

This file defines the versioned records, lifecycle states, transitions, event model, identity bindings, and persistence requirements for the service.

## 2. Durable record version

The first persisted schema is `1.0.0`. Every stored record includes `schemaVersion`. Readers must reject unknown major versions. Minor additive changes require explicit defaults and migration tests.

## 3. Machine record

```ts
interface DisposableMachineRecordV1 {
  schemaVersion: '1.0.0';
  machineId: string;
  machineName: string;
  providerId: 'zfs-nspawn-disposable@1';
  ownerPrincipal: string;
  authorityReference?: string;
  parentObjectiveId?: string;
  parentCertificationId?: string;
  parentCandidateId?: string;
  creationIdempotencyKey: string;
  creationRequestDigest: string;

  source: {
    kind: 'zfs-snapshot';
    snapshot: string;
    dataset: string;
    snapshotGuid?: string;
    creationTxg?: string;
    observedAt: string;
  };

  clone: {
    dataset: string;
    datasetGuid?: string;
    mountpoint: string;
    expectedRootPrefix: string;
    ownershipMarker: string;
  };

  launch: {
    boot: boolean;
    command?: string[];
    networkMode: 'none' | 'private' | 'host' | 'custom';
    readOnlyRoot: boolean;
    binds: MachineBindV1[];
    environment: MachineEnvironmentV1[];
    properties: MachinePropertyV1[];
    resourceProfile?: MachineResourceProfileV1;
    normalizedDigest: string;
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

  host: {
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
    pgid?: number;
    cgroupPath?: string;
    systemdUnit?: string;
  };

  observations: MachineObservationSetV1;
  activeJobIds: string[];
  protectedJobIds: string[];
  artifactIds: string[];
  proofReferences: string[];
  lastError?: MachineFailureV1;
  recovery?: MachineRecoveryV1;
  cleanup: MachineCleanupV1;
}
```

## 4. Supporting records

### 4.1 Bind

```ts
interface MachineBindV1 {
  source: string;
  destination: string;
  mode: 'ro' | 'rw';
  recursive: boolean;
  sourceIdentity?: {
    device?: number;
    inode?: number;
    sha256?: string;
  };
}
```

Requirements:

- absolute source and destination;
- normalized path with no `..` traversal;
- no symlink component in protected host roots;
- read-only default;
- writable binds explicitly authorized;
- no bind of `/`, `/etc`, `/root`, `/var/lib/baby-x`, credential roots, or runtime sockets unless an explicit internal policy allows it.

### 4.2 Environment

```ts
interface MachineEnvironmentV1 {
  name: string;
  value?: string;
  secretReference?: string;
  redacted: boolean;
}
```

A field has either `value` or `secretReference`, never both. Secret values are not persisted in plaintext evidence.

### 4.3 Resource profile

```ts
interface MachineResourceProfileV1 {
  memoryMaxBytes?: number;
  memoryHighBytes?: number;
  cpuQuotaPercent?: number;
  tasksMax?: number;
  nofileSoft?: number;
  nofileHard?: number;
  runtimeDeadlineMs?: number;
  diskQuotaBytes?: number;
  outputLimitBytes?: number;
  artifactLimitBytes?: number;
}
```

### 4.4 Observation set

```ts
interface MachineObservationSetV1 {
  dataset: 'present-matching' | 'present-conflict' | 'absent' | 'unknown';
  snapshot: 'present-matching' | 'present-conflict' | 'absent' | 'unknown';
  mountpoint: 'present-matching' | 'present-conflict' | 'absent' | 'unknown';
  machinectl: 'running-matching' | 'stopped-matching' | 'present-conflict' | 'absent' | 'unknown';
  process: 'running-matching' | 'stopped' | 'stale-pid' | 'present-conflict' | 'absent' | 'unknown';
  rootPath: 'present-matching' | 'present-conflict' | 'absent' | 'unknown';
  observedAt?: string;
  observationDigest?: string;
}
```

## 5. Stable identifiers

### 5.1 `machineId`

- service generated;
- immutable;
- never reused;
- independent from the human-readable machine name;
- safe for file paths and logs.

### 5.2 `machineName`

- validated by the existing machine-name validator;
- never begins with `-`;
- no path separators or shell syntax;
- unique among non-destroyed records;
- cannot be the sole lookup key for destructive action.

### 5.3 Ownership marker

The service creates a deterministic ownership marker from installation identity, machine ID, provider ID, and creation request digest. Where possible it should be stored in ZFS user properties and in the durable record. Destruction requires both sides to agree.

Recommended ZFS properties:

```text
com.stealtheye.babyx:machine-id=<machineId>
com.stealtheye.babyx:provider=zfs-nspawn-disposable@1
com.stealtheye.babyx:request-digest=<sha256>
com.stealtheye.babyx:owner-principal=<principal>
```

## 6. Lifecycle states

```ts
type MachineState =
  | 'REQUESTED'
  | 'CLONING'
  | 'CLONED'
  | 'STARTING'
  | 'READY'
  | 'EXECUTING'
  | 'STOPPING'
  | 'STOPPED'
  | 'DESTROYING'
  | 'DESTROYED'
  | 'DEGRADED'
  | 'FAILED'
  | 'LOST'
  | 'RECOVERY_REQUIRED'
  | 'AMBIGUOUS'
  | 'UNKNOWN';
```

Only `DESTROYED` is unconditionally terminal. A failed creation may still need cleanup. A failed destroy is nonterminal and requires recovery.

## 7. Desired state

```ts
type MachineDesiredState = 'CLONED' | 'READY' | 'STOPPED' | 'DESTROYED';
```

The service records the accepted goal separately from progress. An interrupted `destroy` may have `desiredState=DESTROYED` and `persistedState=DESTROYING`.

## 8. Observed state

```ts
type MachineObservedState =
  | 'NOT_OBSERVED'
  | 'CLONE_ONLY'
  | 'RUNNING'
  | 'STOPPED_INTACT'
  | 'PARTIALLY_REMOVED'
  | 'ABSENT'
  | 'CONFLICT'
  | 'UNKNOWN';
```

## 9. Transition rules

### 9.1 Normal transitions

```text
none -> REQUESTED
REQUESTED -> CLONING
CLONING -> CLONED
CLONED -> STARTING
STARTING -> READY
READY -> EXECUTING
EXECUTING -> READY
READY -> STOPPING
EXECUTING -> STOPPING (only after protected job policy permits)
STOPPING -> STOPPED
CLONED -> DESTROYING
STOPPED -> DESTROYING
FAILED -> DESTROYING (when ownership is exact)
DEGRADED -> STOPPING or DESTROYING
DESTROYING -> DESTROYED
```

### 9.2 Exceptional transitions

Any nonterminal state may move to:

- `DEGRADED` when service remains usable but an invariant is weakened;
- `FAILED` when a step failed with a known safe resulting state;
- `LOST` when an owned resource disappeared unexpectedly;
- `AMBIGUOUS` when evidence conflicts;
- `UNKNOWN` when required observation cannot be performed;
- `RECOVERY_REQUIRED` when deterministic automatic continuation is unsafe.

### 9.3 Forbidden transitions

Examples:

- `REQUESTED -> READY`;
- `CLONING -> DESTROYED` without cleanup transitions and readback;
- `READY -> DESTROYED` without stop/destroy verification;
- `DESTROYED -> READY`;
- any transition that reduces `stateSequence`;
- any mutation using stale `expectedSequence`;
- adopting a process after boot ID or start time mismatch.

## 10. Transition record

Every accepted transition appends an event before or atomically with durable state replacement.

```ts
interface MachineEventV1 {
  schemaVersion: '1.0.0';
  machineId: string;
  offset: number;
  stateSequence: number;
  priorState?: MachineState;
  nextState: MachineState;
  desiredState: MachineDesiredState;
  operation: string;
  phase: string;
  kind: string;
  message: string;
  requestDigest?: string;
  idempotencyKey?: string;
  controllerLeaseId?: string;
  jobId?: string;
  artifactId?: string;
  proofReference?: string;
  observationDigest?: string;
  occurredAt: string;
  eventDigest: string;
}
```

Event offsets are monotonic per machine. Event digests bind the canonical event content. Events are append-only.

## 11. Idempotency

Each mutating operation normalizes the request and computes a digest.

- Same key + same digest: return or resume the same logical operation.
- Same key + different digest: `machine_idempotency_conflict`.
- New key + equivalent target already satisfied: return a verified no-op result where permitted.
- Non-idempotent operations must be explicitly marked; the initial machine API should avoid them.

## 12. Controller leases

```ts
interface MachineControllerLeaseV1 {
  leaseId: string;
  machineId: string;
  operation: string;
  ownerPrincipal: string;
  requestDigest: string;
  acquiredAt: string;
  expiresAt: string;
  hostBootId: string;
  controllerProcessIdentity?: ProcessIdentity;
}
```

A lease is not considered stale only because time elapsed. Reconciliation checks boot ID and process identity. After restart, old-boot leases may be superseded with an event.

## 13. Cleanup record

```ts
interface MachineCleanupV1 {
  requested: boolean;
  requestedAt?: string;
  stopAttempted: boolean;
  stopVerified: boolean;
  datasetDestroyAttempted: boolean;
  datasetAbsentVerified: boolean;
  rootAbsentVerified: boolean;
  machineAbsentVerified: boolean;
  processAbsentVerified: boolean;
  completed: boolean;
  completedAt?: string;
  retainedEvidence: string[];
}
```

`completed=true` requires every applicable absence check.

## 14. Failure record

```ts
interface MachineFailureV1 {
  code: string;
  message: string;
  phase: string;
  retryable: boolean;
  destructiveRecoveryAllowed: boolean;
  commandExitCode?: number;
  signal?: string;
  observationDigest?: string;
  artifactReferences: string[];
  occurredAt: string;
}
```

## 15. Persistence layout

Recommended durable layout beneath the existing runtime state root:

```text
machines/
  records/<machineId>.json
  events/<machineId>.jsonl
  leases/<machineId>.json
  indexes/by-name/<encoded-name>
  indexes/by-state/<state>/<machineId>
  indexes/by-expiry/<timestamp>/<machineId>
  tombstones/<machineId>.json
```

Use existing atomic-store conventions. Never rewrite event history. Indexes are reconstructable and are not authority over the record.

## 16. Tombstones

Destroyed machine identities remain represented by compact tombstones containing:

- machine ID;
- machine name;
- owner principal;
- source snapshot;
- clone dataset;
- creation digest;
- destruction time;
- final event digest;
- cleanup evidence references.

Tombstones prevent identity reuse and support audits without retaining full mutable state forever.

## 17. Schema acceptance tests

- unknown major version rejected;
- canonical serialization stable;
- request digest stable across key ordering;
- secrets excluded from canonical evidence;
- invalid state rejected;
- invalid transition rejected;
- stale expected sequence rejected;
- duplicate event offset rejected;
- ownership marker mismatch classified as conflict;
- destroyed record cannot transition;
- tombstone prevents ID reuse;
- index reconstruction produces the same lookup results.
