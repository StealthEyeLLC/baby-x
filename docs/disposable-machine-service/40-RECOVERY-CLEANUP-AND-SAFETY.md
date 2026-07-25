# Disposable Machine Service — Recovery, Cleanup, and Safety

## 1. Purpose

This file defines how the service survives interruption, classifies partial state, adopts valid resources, refuses unsafe actions, and proves cleanup.

## 2. Recovery principles

1. Durable state is evidence, not unquestionable truth.
2. Host readback is evidence, not sufficient ownership by itself.
3. Recovery combines record, event history, provider observations, host identity, process identity, and ownership markers.
4. No destructive action is permitted when ownership is ambiguous.
5. Reconciliation is idempotent.
6. Recovery events are append-only.
7. Recovery must be bounded; an unavailable provider produces `UNKNOWN`, not an infinite retry loop.
8. A command exit code does not override contradictory readback.
9. Cleanup preserves evidence before deletion.
10. Source snapshots are never cleanup candidates.

## 3. Startup reconciliation

At runtime startup, perform a bounded scan of nonterminal records:

1. Load records and latest events.
2. Validate schema and event-chain integrity.
3. Inspect active controller lease.
4. Compare lease boot ID and process identity with current host.
5. Observe source snapshot, clone dataset, mountpoint, root, machinectl state, and process identity.
6. Classify the machine.
7. Append an observation/reconciliation event.
8. Resume only deterministic safe operations.
9. Queue, but do not silently destroy, ambiguous machines.

The startup scan must have a configurable maximum count and time budget. Remaining machines are reconciled lazily or by explicit operation.

## 4. Recovery classifications

### 4.1 Healthy cloned

Conditions:

- persisted state `CLONED`;
- clone dataset exists with matching ownership properties;
- root/mountpoint matches;
- no machine process exists.

Action: retain `CLONED`; clear stale lease if justified.

### 4.2 Healthy running/adoptable

Conditions:

- persisted state `STARTING`, `READY`, or `EXECUTING`;
- `machinectl` name matches;
- root path matches;
- process executable, start time, boot ID, and cgroup/unit identity match;
- clone ownership matches.

Action: adopt observation, restore service control, rebuild active-job association from durable jobs, transition to `READY` or `EXECUTING` with reconciliation event.

### 4.3 Stopped but intact

Conditions:

- clone and root match;
- no machine/process exists;
- prior desired state was ready or stopped.

Action: classify `STOPPED`. Restart automatically only when an explicit recovery policy authorizes it; otherwise preserve stopped state.

### 4.4 Orphaned clone

Conditions:

- owned clone exists;
- no machine/process exists;
- record is incomplete or prior create failed.

Action: either complete `CLONED` when source and ownership are exact, or continue destruction if desired state is `DESTROYED`.

### 4.5 Orphaned machine process

Conditions:

- process/machine exists;
- clone record missing or ownership cannot be tied exactly.

Action: `AMBIGUOUS` or `RECOVERY_REQUIRED`. Do not terminate automatically solely by name.

### 4.6 Partial destruction

Examples:

- machine absent, dataset present;
- dataset absent, stale root directory remains;
- dataset absent, machinectl entry temporarily present;
- stop verified but destroy command interrupted.

Action: continue only the remaining verified-owned cleanup steps. Record each readback.

### 4.7 Lost resource

Conditions:

- record claims owned clone or running machine;
- resource is absent without authorized transition.

Action: persist `LOST`; preserve evidence; do not claim cleanup success. If all resources are absent and ownership history is intact, explicit reconciliation may later produce a destroyed-equivalent tombstone with a loss reason, not a normal success event.

### 4.8 Identity conflict

Examples:

- dataset exists but ownership property references another machine;
- machine name exists with different root;
- PID reused with different process start time;
- host boot ID changed and old PID metadata is stale;
- mountpoint resolves outside expected root.

Action: `AMBIGUOUS` and block destructive automation.

### 4.9 Provider unavailable

Examples:

- `zfs` unavailable;
- `machinectl` unavailable;
- systemd bus unavailable;
- permission/authority unavailable.

Action: `UNKNOWN` observation; retain durable state; return `machine_provider_unavailable` or `machine_unknown` with evidence.

## 5. Exact process adoption

Adoption requires all applicable fields:

- machine name;
- leader PID;
- process start time from `/proc`;
- executable path;
- current host boot ID;
- cgroup path or systemd unit;
- machine root/directory property;
- clone dataset ownership;
- launch configuration digest where available.

Any mismatch rejects adoption. PID equality alone is never enough.

## 6. Stop policy

Default stop sequence:

1. Reject or wait when protected jobs are active.
2. Send graceful machine termination through exact `machinectl` argv.
3. Wait bounded interval while observing machine/process state.
4. If still running, apply configured escalation to exact process group or systemd unit.
5. Verify process absence using PID/start-time/boot-ID identity.
6. Verify machinectl absence/stopped state.
7. Persist `STOPPED`.

Escalation must be explicit in the operation definition and event stream. The service must not issue broad `pkill`, name-only kills, or unbounded recursive termination.

## 7. Destroy policy

Before ZFS destruction, prove:

- dataset is not the source dataset or source snapshot;
- dataset name passed strict validation;
- dataset GUID matches the recorded clone when available;
- origin equals the recorded source snapshot;
- ownership properties match machine ID/provider/request digest;
- mountpoint equals the recorded path and lies under approved root;
- no conflicting children or holds exist, unless their ownership is separately proven;
- machine and protected jobs are stopped.

Use exact argv and `--` where supported. If ZFS syntax does not support `--` for a subcommand, strict identifier validation remains mandatory.

After destruction, prove:

- `zfs list` reports dataset absent;
- root/mountpoint no longer exposes the cloned filesystem;
- machinectl entry absent;
- matching process absent;
- no owned transient systemd unit remains;
- required evidence was retained.

## 8. Garbage collection

GC is a policy consumer of normal lifecycle operations.

Eligibility requires:

- expiration reached or explicit cleanup requested;
- not protected by certification/candidate preservation;
- no active controller lease;
- no protected jobs;
- exact machine record available;
- ownership observable;
- not already terminal except tombstone retention pruning.

GC phases:

1. bounded candidate selection;
2. dry-run classification;
3. per-machine reconciliation;
4. stop through normal API;
5. destroy through normal API;
6. verify result;
7. report failures and recovery-required cases separately.

GC must never directly execute raw recursive deletion outside the service lifecycle.

## 9. Safety validation

### 9.1 Names

Reject:

- empty identifiers;
- leading `-`;
- NUL/control bytes;
- whitespace where unsupported;
- shell metacharacters;
- `.` and `..` path semantics;
- excessive length;
- names outside configured ZFS dataset roots.

### 9.2 Paths

Require:

- absolute paths;
- normalized path;
- confinement beneath configured roots;
- symlink-component rejection for protected operations;
- no host root or sensitive root bind;
- source/destination separation.

### 9.3 Mounts

- read-only default;
- writable binds allowlisted;
- no Docker socket, Baby private socket, SSH agent, credential store, `/proc/kcore`, host `/dev`, or production release pointer exposure by default;
- record source identity where practical;
- reject destination overlap with critical machine paths.

### 9.4 Network

Modes:

- `none`: no configured external network;
- `private`: private namespace/veth according to existing manager support;
- `host`: explicit high-risk policy only;
- `custom`: validated provider-specific configuration.

Default should be the least permissive mode that satisfies the objective.

### 9.5 Secrets

Persist secret references only. Resolve at execution time through existing secret authority. Redact environment and evidence. Never include secret values in request digests exposed to users, logs, events, or proof bodies.

### 9.6 Resource limits

Apply systemd/nspawn resource properties through exact validated values. Reject negative, overflowing, contradictory, or unbounded values where policy requires bounds.

## 10. Cancellation semantics

- Before resource creation: cancel and persist safe failure/cancel event.
- During clone: observe whether clone exists; destroy only if ownership is exact and policy requests rollback.
- During start: reconcile machine/process state before any cleanup.
- During execution: use existing durable-job cancellation; machine remains unless objective policy requests teardown.
- During stop: continue observation to a stable state.
- During destroy: cancellation does not restore deleted resources; continue readback and classify final truth.

## 11. Evidence preservation

Before destructive cleanup, capture as applicable:

- machine record digest;
- recent event digest chain;
- source and clone ZFS properties;
- machinectl properties;
- process identity;
- launch argv digest;
- related job receipts;
- stdout/stderr artifacts required by consumer;
- cleanup plan and reason.

Evidence must be bounded and redacted.

## 12. Recovery test matrix

- process dies during `STARTING`;
- runtime restarts after clone but before state write;
- runtime restarts after state write but before clone;
- runtime restarts while machine is healthy;
- host reboots while machine was `READY`;
- PID reused after reboot;
- destroy command succeeds but response is lost;
- destroy command fails after unmount;
- clone exists with wrong ownership marker;
- machine name exists with wrong root;
- ZFS unavailable during status;
- machinectl unavailable during stop;
- active protected job during destroy;
- expiration races with explicit start;
- concurrent reconcile and destroy;
- stale controller lease;
- event log tail corruption;
- index missing but record intact;

## 13. Safety acceptance checklist

- [ ] Exact ownership properties implemented.
- [ ] Source protection tested.
- [ ] PID reuse tested.
- [ ] Host boot change tested.
- [ ] Symlink/path escape tested.
- [ ] Option injection tested for every identifier.
- [ ] Protected-job destruction rejected.
- [ ] GC dry-run tested.
- [ ] Positive absence readback required.
- [ ] Ambiguity blocks destructive automation.
- [ ] Secret redaction tested.
