# Disposable Machine Service — API and Operation Contracts

## 1. Operation namespace

Use the existing dynamic Baby-X operation registry. Recommended public operation names:

- `babyx.machine.describe`
- `babyx.machine.create`
- `babyx.machine.get`
- `babyx.machine.list`
- `babyx.machine.events`
- `babyx.machine.status`
- `babyx.machine.start`
- `babyx.machine.exec`
- `babyx.machine.shell`
- `babyx.machine.stop`
- `babyx.machine.destroy`
- `babyx.machine.reconcile`
- `babyx.machine.expire`
- `babyx.machine.gc`

If the repository’s final naming convention differs, preserve the semantic contracts and document the final names.

## 2. Common mutation envelope

Every mutation accepts:

```ts
interface MachineMutationEnvelope {
  machineId?: string;
  expectedSequence?: number;
  authorizationReference?: string;
  deadline?: string;
  reason?: string;
}
```

The protocol-level idempotency key remains outside the payload where the current registry expects it.

Every mutation result includes:

```ts
interface MachineMutationResult {
  operation: string;
  machine: DisposableMachineRecordV1;
  resultDigest: string;
  eventOffset: number;
  proofReference?: string;
  artifactReferences: string[];
  noOp: boolean;
}
```

## 3. Error taxonomy

Stable errors:

- `machine_invalid_request`
- `machine_not_found`
- `machine_name_conflict`
- `machine_idempotency_conflict`
- `machine_sequence_conflict`
- `machine_state_conflict`
- `machine_controller_conflict`
- `machine_source_not_found`
- `machine_source_mismatch`
- `machine_dataset_conflict`
- `machine_root_conflict`
- `machine_process_conflict`
- `machine_identity_ambiguous`
- `machine_provider_unavailable`
- `machine_launch_failed`
- `machine_readiness_failed`
- `machine_job_active`
- `machine_stop_failed`
- `machine_destroy_failed`
- `machine_cleanup_incomplete`
- `machine_recovery_required`
- `machine_unknown`

Errors must be machine-readable and accompanied by bounded human context and evidence references.

## 4. `babyx.machine.describe`

Read-only discovery.

Returns:

- service version;
- provider IDs and versions;
- supported lifecycle operations;
- lifecycle states;
- supported source kinds;
- network modes;
- bind modes;
- resource controls;
- limits;
- idempotency rules;
- recovery behavior;
- cleanup behavior;
- known limitations;
- schema digests.

No host secret, credential value, private key path, or unrestricted environment value may be exposed.

## 5. `babyx.machine.create`

### Input

```ts
interface MachineCreateRequestV1 {
  schemaVersion: '1.0.0';
  machineName: string;
  ownerPrincipal: string;
  authorityReference?: string;
  parentObjectiveId?: string;
  parentCertificationId?: string;
  parentCandidateId?: string;
  source: {
    kind: 'zfs-snapshot';
    snapshot: string;
    expectedGuid?: string;
  };
  clone: {
    dataset: string;
    mountpoint: string;
    expectedRootPrefix: string;
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
  };
  expiresAt?: string;
  startImmediately?: boolean;
}
```

### Behavior

1. Validate request and authorization.
2. Normalize and digest request.
3. Reserve machine ID and name atomically.
4. Persist `REQUESTED`.
5. Acquire controller lease.
6. Observe and bind source snapshot identity.
7. Persist `CLONING`.
8. Execute exact clone argv through existing execution authority.
9. Apply ownership properties.
10. Read back dataset, GUID, origin, mountpoint, and ownership marker.
11. Persist `CLONED`.
12. Optionally call the same internal start path used by `machine.start`.

### Success

Success requires exact clone observation. A zero exit code without readback is insufficient.

### Retry

Same idempotency key and digest resumes or returns the same machine. Different digest conflicts.

## 6. `babyx.machine.get`

Input: `machineId`.

Returns one durable machine record with secrets redacted. It does not perform live observation unless explicitly requested through `status`.

## 7. `babyx.machine.list`

Bounded filters:

- owner principal;
- state;
- provider;
- parent objective;
- parent certification;
- parent candidate;
- created before/after;
- expires before/after;
- terminal/nonterminal.

Pagination must be deterministic. Default and maximum limits are described by `machine.describe`.

## 8. `babyx.machine.events`

Returns a bounded page of append-only events by machine ID and offset. Events are redacted and content-addressed.

## 9. `babyx.machine.status`

Input:

```ts
{
  machineId: string;
  includeJobs?: boolean;
  includeRecentEvents?: boolean;
}
```

Behavior:

- load durable record;
- observe ZFS source and clone;
- observe mountpoint/root;
- observe `machinectl` properties;
- observe exact process identity where available;
- compare desired, persisted, and observed state;
- return discrepancies without mutating the record.

A future option may request persistence of observations, but the initial read-only status operation should not silently transition lifecycle state.

## 10. `babyx.machine.start`

### Preconditions

Permitted from `CLONED`, `STOPPED`, or a recoverable failed state with exact intact resources.

### Behavior

1. Compare expected sequence.
2. Acquire controller lease.
3. Verify clone ownership and root identity.
4. Verify no conflicting machine/process exists.
5. Persist `STARTING`.
6. Build exact nspawn argv using current machine manager conventions.
7. Execute launch through durable jobs or the existing machine launch authority.
8. Capture process identity and host boot ID.
9. Poll bounded readiness signals.
10. Read `machinectl show` properties.
11. Verify name, root, leader PID/start time, and launch digest.
12. Persist `READY`.

### Readiness

Readiness means identity verified and machine operational for intended execution. It must not be inferred from process existence alone.

## 11. `babyx.machine.exec`

### Input

```ts
interface MachineExecRequestV1 {
  machineId: string;
  expectedSequence?: number;
  argv: string[];
  cwd?: string;
  environment?: MachineEnvironmentV1[];
  timeoutMs?: number;
  outputLimitBytes?: number;
  artifactPolicy?: object;
}
```

### Behavior

- require compatible observed state;
- bind request to machine ID and machine name;
- execute through existing durable job manager with target `{ kind: 'machine', machine: machineName }`;
- record job ID in machine record/event stream;
- transition `READY -> EXECUTING` when first active job attaches;
- return to `READY` when last active job completes and observations remain healthy;
- preserve stdout, stderr, exit state, receipt, and artifacts under existing authorities.

The operation may return immediately with a job ID or wait according to the existing job contract. It does not invent a new streaming system.

## 12. `babyx.machine.shell`

Convenience wrapper around `machine.exec` using a fixed shell executable and explicit script/command argument. It must not concatenate untrusted fragments into a host shell command. Prefer exact script content as one argument.

## 13. `babyx.machine.stop`

### Preconditions

Permitted from `READY`, `EXECUTING`, `DEGRADED`, `FAILED`, or an observed-running recoverable state.

### Behavior

1. Compare sequence and acquire lease.
2. Evaluate active/protected job policy.
3. Persist `STOPPING`.
4. Request graceful termination for exact machine.
5. Wait bounded time.
6. Escalate only according to frozen policy.
7. Verify `machinectl` absence/stopped state.
8. Verify matching process identity is absent.
9. Persist `STOPPED`.

Repeated stop on an already verified stopped machine returns a verified no-op.

## 14. `babyx.machine.destroy`

### Preconditions

- exact ownership proven;
- source snapshot distinguished from clone;
- no protected active jobs;
- machine stopped or policy authorizes stop as part of destroy.

### Behavior

1. Compare sequence and acquire lease.
2. Preserve required evidence.
3. Stop exact machine if necessary.
4. Persist `DESTROYING`.
5. Unmount/release owned dependencies.
6. Destroy exact clone dataset.
7. Read back dataset absence.
8. Read back root absence or explain retained empty parent.
9. Read back machine and process absence.
10. Persist `DESTROYED` and tombstone.

Never call recursive ZFS destruction on a value that has not passed ownership and source/clone checks.

## 15. `babyx.machine.reconcile`

Input includes `machineId`, `expectedSequence`, and optionally a recovery policy.

Behavior:

- load record and events;
- observe all resources;
- classify exact state;
- supersede stale controller lease when justified;
- resume idempotent incomplete work where safe;
- adopt a running machine only with exact identity proof;
- continue cleanup only with exact ownership;
- otherwise persist `RECOVERY_REQUIRED`, `AMBIGUOUS`, or `UNKNOWN`.

## 16. `babyx.machine.expire`

Marks a machine’s desired state as `DESTROYED` when retention policy and protections permit. It does not bypass normal stop/destroy operations.

## 17. `babyx.machine.gc`

Input:

```ts
{
  dryRun: boolean;
  limit?: number;
  now?: string;
  retainDestroyedTombstones?: number;
}
```

Dry-run is mandatory in tests and operational previews. Output separates:

- protected;
- eligible;
- skipped with reason;
- reconciled;
- stopped;
- destroyed;
- failed;
- recovery required.

## 18. Operation registration

Each operation definition includes:

- version;
- description;
- mutation flag;
- risk;
- idempotency class;
- input schema;
- output schema;
- error set;
- cancellation behavior;
- restart behavior;
- post-action verification requirement;
- limits;
- provider support state.

Gateway tests must prove dynamically described operations are forwarded without hardcoded per-operation routes.

## 19. API acceptance checklist

- [ ] All public operations registered.
- [ ] Schemas reject unknown properties where appropriate.
- [ ] Stable errors returned.
- [ ] Mutation idempotency tested.
- [ ] Expected sequence enforced.
- [ ] Secrets redacted.
- [ ] Large output artifact-backed.
- [ ] Every success has post-action verification.
- [ ] Gateway forwarding tested.
