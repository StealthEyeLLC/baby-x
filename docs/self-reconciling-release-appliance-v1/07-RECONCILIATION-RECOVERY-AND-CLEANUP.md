# Reconciliation, Recovery, and Cleanup

## 1. Reconciliation objective

The controller continuously compares durable desired state with observed source, artifact, release path, systemd unit, process, endpoint, Caddy route, jobs, credentials, capacity, and evidence. It repairs only exact owned state. It never converts uncertainty into destructive permission.

## 2. Startup sequence

On process or host startup:

1. open the durable store.
2. recover valid pending mutations.
3. isolate corrupt pending or authoritative records.
4. verify derived indexes.
5. rebuild invalid indexes from readable authoritative records.
6. reconcile recorded-running durable jobs.
7. inspect controller leases.
8. release only leases proven stale by expiry and controller absence.
9. scan nonterminal deployments within record and elapsed-time bounds.
10. reconcile service definitions, releases, slots, routes, and GitHub outbox.
11. publish a startup report with processed, deferred, corrupt, ambiguous, and recovery-required counts.
12. never block the complete runtime indefinitely on one corrupt deployment.

## 3. Observation sources

### 3.1 Jobs

1. durable job record.
2. process existence.
3. PID start time.
4. executable path.
5. boot ID.
6. cgroup/process group.
7. stream paths.
8. terminal exit or signal.

An absent or reused process terminalizes as lost/identity-conflict without fabricated exit code zero.

### 3.2 systemd slot

1. unit load state.
2. active state and substate.
3. main PID.
4. invocation ID when available.
5. control group.
6. result and restart count.
7. unit file/drop-in digest.
8. runtime directory.
9. expected endpoint.

### 3.3 Process

1. PID and parent.
2. process start time.
3. executable path.
4. boot ID.
5. process group.
6. namespace/cgroup identity.
7. open listener/socket ownership when observable.

### 3.4 Endpoint

1. path or address.
2. filesystem type and owner for Unix sockets.
3. listener PID/inode relationship.
4. connection success.
5. protocol response.
6. release identity response when available.

### 3.5 Route

1. Caddy admin endpoint reachability.
2. active configuration bytes and digest.
3. expected route identifier.
4. upstream endpoint.
5. public route probe.
6. Caddy process identity and version.

### 3.6 Artifact and release path

1. object exists.
2. byte digest.
3. manifest digest.
4. expanded file-manifest digest.
5. ownership and permissions.
6. reference set.
7. quarantine state.

## 4. Classification

Every reconciliation result is one of:

1. `CONSISTENT`: durable and observed truth agree.
2. `RECOVERABLE`: a safe exact action can converge state.
3. `DEFERRED`: a live lease, active job, pressure, or bounded time limit prevents action.
4. `UNKNOWN`: observation provider is unavailable or insufficient.
5. `LOST`: an exact expected resource is absent and cannot be recreated without a new decision.
6. `AMBIGUOUS`: a resource exists but ownership or identity conflicts.
7. `CORRUPT`: authoritative or evidence bytes fail schema/digest verification.

Only `RECOVERABLE` permits automatic mutation.

## 5. Phase-specific restart recovery

### 5.1 Source/build/certification

1. Adopt only exact persisted machine and job IDs.
2. Never submit a duplicate build step merely because the response was lost.
3. Inspect artifact finalization before retrying packaging.
4. Incomplete objects remain pending or quarantined.
5. Resume cleanup through machine authority.

### 5.2 Staging

1. Verify the transaction staging directory and expected artifact digest.
2. If final release directory exists, verify it completely before adopting.
3. If a conflicting directory exists, classify ambiguous.
4. If staging is incomplete and exactly owned, remove or resume according to pending intent.
5. Never overwrite an immutable final release directory in place.

### 5.3 Slot start

1. If the unit is running, match unit, release, slot, process, boot, endpoint, and credential-set identities.
2. Adopt only exact identity.
3. If not running and no start job exists, inspect whether start intent was submitted before retrying.
4. A foreign process on the endpoint is ambiguous.
5. A stale PID is ambiguous, not a reason to kill.

### 5.4 Cutover

1. Compare prior config digest, candidate digest, active Caddy readback, and public probe.
2. If candidate is active and healthy, adopt cutover completion.
3. If prior config remains active, safely retry only when the persisted load intent and idempotency identity allow it.
4. If active config matches neither prior nor candidate, enter `AMBIGUOUS` and block automated cleanup.
5. Never infer route state from the last API response alone.

### 5.5 Observation

1. Resume sample sequence without erasing prior samples.
2. Apply the same thresholds and minimum sample counts.
3. Do not reset failure counters on controller restart.
4. A gap is recorded and evaluated according to policy.

### 5.6 Rollback

1. Reconcile which route is active before any additional load.
2. Adopt a completed prior-route restoration only after readback and probe.
3. Never re-promote the failed slot automatically.
4. Resume failed-slot cleanup only after the route is proven safe.

### 5.7 Drain and cleanup

1. Reconcile active connections/jobs where observable.
2. Resume exact stop/destroy operations through the owning authority.
3. Never remove the runtime socket while its exact process may still be alive.
4. Never evict the rollback release while it remains referenced.

## 6. Controller leases

1. Lease is per deployment for general lifecycle work and per service for route mutation.
2. Lease binds owner, controller ID, host boot ID, operation, request digest, acquired time, renewed time, and expiry.
3. Live overlap is rejected.
4. Stale takeover requires expiry plus positive absence of the prior controller identity.
5. A boot-ID change is evidence but not the only takeover condition.
6. Lease release requires exact controller identity.
7. Ambiguous lease state blocks route or cleanup mutation.
8. Reads remain available without a mutation lease.

## 7. Drift repair policy

### 7.1 Safe automatic repairs

1. restart an inactive candidate slot from an exact release before cutover.
2. restart an active service only under its declared restart policy and after route/rollback safety evaluation.
3. restore missing deterministic unit/drop-in bytes when no conflicting local modification exists.
4. restore Caddy desired route when active config matches a known previous or candidate record and policy permits.
5. recreate an absent inactive runtime directory.
6. rebuild derived indexes.
7. retry GitHub outbox delivery.
8. evict unreachable cache entries under capacity policy.

### 7.2 Repairs that require approval or recovery state

1. replacing an unknown Caddy configuration.
2. killing an unowned process.
3. deleting an unowned socket or directory.
4. destroying a dataset with identity mismatch.
5. overwriting a release path with conflicting bytes.
6. restarting a degraded active service when no healthy rollback target exists.
7. applying an irreversible migration.
8. mutating credentials outside the inactive-slot rotation path.

## 8. Cleanup protocol

A slot cleanup executes in this order:

1. confirm the slot is not active in desired or observed route state.
2. confirm it is not the sole rollback target.
3. confirm no protected job or retention hold exists.
4. persist cleanup intent.
5. stop the exact systemd unit through the slot adapter.
6. wait for unit inactive and exact process absence.
7. reconcile all related jobs to terminal truth.
8. verify endpoint listener absence.
9. remove only the exactly owned stale Unix socket after process absence.
10. remove exactly owned runtime files/directories.
11. verify no release-specific transient mount or namespace remains.
12. preserve logs and evidence.
13. update slot to `EMPTY_VERIFIED`.
14. release artifact/release references.
15. invoke separate retention GC for now-unreferenced release bytes.

## 9. Positive-absence fields

Cleanup truth includes:

1. `unitInactiveVerified`.
2. `processAbsenceVerified`.
3. `endpointAbsenceVerified`.
4. `socketPathAbsenceVerified`.
5. `runtimePathAbsenceVerified`.
6. `mountAbsenceVerified` when applicable.
7. `datasetAbsenceVerified` when applicable.
8. `activeJobsAbsentVerified`.
9. `routeReferenceAbsentVerified`.
10. `sourceAndEvidencePreserved`.
11. `completedAt`.

No terminal cleanup state is valid when a required field is false or unknown.

## 10. Garbage collection

1. GC defaults to dry-run.
2. It is owner-scoped unless unrestricted authority explicitly requests global inspection.
3. It is bounded by count, time, and byte budget.
4. Every inclusion and exclusion has a reason.
5. Active, prior, pinned, referenced, ambiguous, corrupt, or protected items are excluded.
6. Global orphan scans classify unknown resources but do not adopt or delete them by name.
7. Live GC delegates to canonical cleanup and artifact authorities.
8. GC never recursively deletes a broad parent directory.
9. GC output records projected and actual reclaimed bytes.

## 11. Response-loss tests

The implementation MUST inject response loss after each persisted intent and after each external effect:

1. source archive creation.
2. cache finalization.
3. build job submission.
4. artifact finalization.
5. machine creation/start/exec.
6. release extraction and rename.
7. unit daemon reload.
8. unit start.
9. readiness completion.
10. Caddy load.
11. public probe.
12. observation decision.
13. rollback load.
14. unit stop.
15. runtime cleanup.
16. evidence finalization.
17. GitHub status delivery.

Recovery must converge without duplicate external effect or fabricated success.

## 12. Corruption handling

1. A corrupt deployment record is isolated and listed in startup diagnostics.
2. Its resources are not automatically deleted.
3. Event-chain discontinuity blocks success claims.
4. A corrupt artifact is quarantined and all dependent releases are blocked.
5. A corrupt derived index is rebuilt.
6. A corrupt prior Caddy configuration blocks automatic rollback unless a separately verified deterministic route can be generated.
7. Evidence corruption is a distinct failure even if the application is healthy.

## 13. Bounded controller behavior

1. Startup reconcile has record and elapsed-time limits.
2. Per-service reconcile has a maximum external-observation budget.
3. Backoff includes jitter for provider/GitHub outages.
4. Persistent failures do not create tight loops.
5. A single service cannot starve all others.
6. Capacity and production health can pause background reconciliation without pausing critical route safety work.
