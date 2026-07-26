# Durable Model and State Machines

## 1. Persistence rules

1. Authoritative records MUST be strict, versioned, canonically serialized, and atomically replaced.
2. Unknown properties MUST be rejected at the write boundary.
3. Unknown newer major schema versions MUST fail closed.
4. Supported older records MAY be read without authoritative rewrite.
5. Migration MUST be an explicit operation with before/after digests and rollback evidence.
6. Every mutation requires `expectedSequence` and the exact owner principal.
7. Every mutation requires an idempotency key and normalized request digest.
8. Reuse of an idempotency key for a different normalized request MUST be rejected.
9. A durable intent record MUST exist before an external side effect begins.
10. Events MUST be append-only and hash-chained.
11. Derived indexes MUST be reproducible from authoritative records.
12. Per-record corruption MUST be isolated so neighboring services remain readable.
13. A pending mutation journal MUST permit recovery after failure between record and event persistence.
14. No record may contain a raw secret.
15. Lists, event pages, error details, and evidence references MUST be bounded.

## 2. Canonical record families

### 2.1 ServiceDefinitionV1

A service definition contains:

1. `schemaVersion`.
2. `serviceId` and display name.
3. owner principal and organization.
4. repository identity and allowed repository IDs.
5. service kind: `WEB`, `API`, `WORKER`, `SCHEDULER`, or `INTERNAL`.
6. deployment group and ordered dependencies.
7. runtime identity and executable contract.
8. working directory.
9. non-secret environment names and values.
10. credential reference names, never values.
11. user, group, and supplementary-group policy.
12. slot model and endpoint preference.
13. Unix-socket path template or loopback port allocation policy.
14. readiness probe definition.
15. liveness and observation probes.
16. smoke-test profile.
17. drain protocol and timeout.
18. termination signal and timeout.
19. restart policy and watchdog policy.
20. resource profile.
21. filesystem write policy.
22. state, cache, log, and runtime directories.
23. Caddy route template identity.
24. public hostnames and path matchers.
25. migration contract.
26. rollback contract.
27. retention policy.
28. approval policy.
29. automation policy.
30. manifest digest and provenance.

### 2.2 SourceIdentityV1

1. repository owner/name and immutable repository ID where available.
2. branch or tag supplied as context only.
3. exact commit SHA.
4. exact tree SHA.
5. source archive artifact ID and SHA-256.
6. source manifest digest.
7. package lockfile path and digest.
8. submodule identities, if any.
9. Git LFS object manifest, if any.
10. resolution time and resolver receipt.
11. signature or verified-commit state when policy requires it.

A mutable ref alone is never a source identity.

### 2.3 BuildRecordV1

1. build ID.
2. owner and idempotency identity.
3. source identity.
4. normalized build profile.
5. toolchain identity.
6. base machine snapshot identity.
7. dependency-cache key and hit/miss result.
8. build-cache key and hit/miss result.
9. machine ID.
10. all child job IDs.
11. build steps and terminal truth.
12. output artifact IDs and digests.
13. SBOM/provenance artifact references when available.
14. resource consumption summary.
15. error classification.
16. cleanup truth.
17. evidence index.

### 2.4 ReleaseArtifactManifestV1

1. schema version.
2. release artifact SHA-256 and size.
3. compression format and parameters.
4. source identity.
5. build record ID.
6. toolchain and dependency identities.
7. service definition digest.
8. release layout version.
9. executable and argument template.
10. runtime requirements.
11. required non-secret configuration names.
12. required credential names.
13. included files manifest with path, mode, type, size, and digest.
14. writable-path declarations.
15. readiness and smoke-test compatibility.
16. database migration metadata.
17. minimum appliance compatibility version.
18. creation timestamp.
19. producer identity.
20. provenance and SBOM references.
21. manifest digest.

The artifact contains no private key, access token, `.env` file, or machine-specific secret.

### 2.5 CertificationRecordV1

1. certification ID.
2. exact artifact and manifest digest.
3. service definition digest.
4. certification profile and digest.
5. base snapshot name, GUID, and creation TXG.
6. machine and durable job IDs.
7. dependency, startup, readiness, smoke, integration, security, and acceptance results.
8. artifact integrity result.
9. cleanup and source-preservation result.
10. evidence index and receipt references.
11. expiration or invalidation conditions.
12. terminal state and failure classification.

Certification reuse requires equality of every identity relevant to behavior.

### 2.6 ReleaseRecordV1

1. `releaseId`, deterministically derived from service and artifact digest.
2. service ID.
3. artifact ID, digest, size, and manifest digest.
4. source commit, tree, and lockfile digest.
5. build and certification IDs.
6. materialization path and method.
7. materialization verification time.
8. installed file-manifest digest.
9. immutable-permission verification.
10. credential-set reference digest.
11. compatible appliance version.
12. retention class and pin status.
13. references from slots and deployments.
14. corruption or quarantine state.

### 2.7 SlotRecordV1

1. service ID.
2. slot ID: `blue` or `green`.
3. bound release ID.
4. desired and persisted slot states.
5. state sequence.
6. systemd unit and drop-in digest.
7. service user/group.
8. runtime directory.
9. endpoint type and identity.
10. expected process identity.
11. observed process identity.
12. active and historical job IDs.
13. readiness and liveness observations.
14. Caddy-route membership.
15. connection/drain observations.
16. credential-set digest.
17. start, ready, exposed, drain, stop, and cleanup times.
18. ambiguity and error fields.

### 2.8 RouteRecordV1

1. route ID and service ID.
2. public hostname/path identity.
3. desired active slot.
4. observed active upstream.
5. prior active slot.
6. candidate Caddy configuration artifact and digest.
7. previous Caddy configuration artifact and digest.
8. validation job and result.
9. load request and response digest.
10. active-config readback digest.
11. internal and public-route probe results.
12. stream-close and transport settings.
13. cutover and rollback timestamps.
14. ambiguity and error fields.

### 2.9 DeploymentRecordV1

The deployment record is the durable parent transaction. It contains:

1. schema version.
2. deployment ID.
3. deployment kind: `APPLICATION_RELEASE`.
4. owner principal.
5. idempotency key and creation request digest.
6. service ID and service-definition digest.
7. trigger source and normalized trigger identity.
8. source, build, artifact, certification, release, slot, and route identities.
9. lifecycle state, desired state, sequence, and timestamps.
10. approval policy and approval evidence.
11. active and all related child job IDs.
12. machine IDs.
13. observation policy and results.
14. prior known-good release and slot.
15. rollback target and status.
16. drain status.
17. cleanup requirements and positive-absence fields.
18. capacity admission snapshot.
19. credential-set digest.
20. GitHub inbox/outbox references.
21. event-tail digest.
22. artifact, receipt, and evidence-index references.
23. structured error with redacted bounded details.

### 2.10 ObservationRecordV1

1. observation ID and deployment ID.
2. sample sequence and timestamp.
3. route and slot identity.
4. probe status and latency.
5. process state and restart count.
6. HTTP status distribution.
7. configured application metrics.
8. memory current/high/max and pressure.
9. CPU usage and pressure.
10. I/O pressure.
11. socket/listener truth.
12. error and timeout counts.
13. sample digest.
14. threshold evaluation.
15. resulting action recommendation.

### 2.11 EvidenceIndexV1

1. parent identity and final state.
2. record digests.
3. ordered event digests.
4. all job IDs and terminal summaries.
5. all machine IDs and cleanup truth.
6. all artifact IDs, byte digests, and verification state.
7. source, build, certification, release, slot, and route bindings.
8. health and observation summaries.
9. cutover and rollback config digests.
10. credential-set digest without values.
11. capacity snapshots.
12. GitHub delivery and reporting references.
13. cleanup and positive-absence proof.
14. signer and signed receipt references.
15. evidence-index digest.

### 2.12 Auxiliary records

1. `CredentialSetReferenceV1`.
2. `CapacitySnapshotV1`.
3. `GitHubInboxRecordV1`.
4. `GitHubOutboxRecordV1`.
5. `ControllerLeaseV1`.
6. `PendingMutationV1`.
7. `RetentionDecisionV1`.
8. `MigrationRunV1`.
9. `MaintenanceRecordV1`, stored by the separate host-maintenance authority.

## 3. Deployment state machine

### 3.1 States

1. `REQUESTED`.
2. `PREFLIGHTING`.
3. `RESOLVING_SOURCE`.
4. `REUSING_ARTIFACT`.
5. `BUILDING`.
6. `CERTIFYING`.
7. `READY_TO_STAGE`.
8. `STAGING`.
9. `STARTING_INACTIVE`.
10. `READINESS_CHECKING`.
11. `READY_TO_PROMOTE`.
12. `AWAITING_APPROVAL`.
13. `CUTOVER_PREPARING`.
14. `CUTTING_OVER`.
15. `OBSERVING`.
16. `DRAINING_PREVIOUS`.
17. `FINALIZING`.
18. `SUCCEEDED`.
19. `ROLLBACK_REQUESTED`.
20. `ROLLING_BACK`.
21. `ROLLED_BACK`.
22. `CLEANUP_PENDING`.
23. `CLEANING`.
24. `FAILED`.
25. `RECOVERY_REQUIRED`.
26. `AMBIGUOUS`.
27. `CANCELLED`.
28. `EXPIRED`.

### 3.2 Terminal states

Terminal states are:

1. `SUCCEEDED`.
2. `ROLLED_BACK` only after route restoration, required evidence, and cleanup/retention truth.
3. `FAILED` only when no unresolved owned resources or active related jobs are hidden.
4. `CANCELLED` only when cancellation and cleanup are complete.
5. `EXPIRED` only when expiration cleanup or explicit retained-resource policy is complete.

`RECOVERY_REQUIRED`, `AMBIGUOUS`, `CLEANUP_PENDING`, and `CLEANING` are nonterminal.

### 3.3 Normal path

```text
REQUESTED
-> PREFLIGHTING
-> RESOLVING_SOURCE
-> REUSING_ARTIFACT | BUILDING
-> CERTIFYING
-> READY_TO_STAGE
-> STAGING
-> STARTING_INACTIVE
-> READINESS_CHECKING
-> READY_TO_PROMOTE
-> AWAITING_APPROVAL | CUTOVER_PREPARING
-> CUTOVER_PREPARING
-> CUTTING_OVER
-> OBSERVING
-> DRAINING_PREVIOUS
-> FINALIZING
-> SUCCEEDED
```

### 3.4 Rollback path

```text
READY_TO_STAGE..FINALIZING
-> ROLLBACK_REQUESTED
-> ROLLING_BACK
-> OBSERVING              # prior route observed after restoration
-> CLEANUP_PENDING
-> CLEANING
-> ROLLED_BACK
```

Before cutover, rollback means stop and clean the inactive slot while leaving the active route unchanged. After cutover, rollback first restores the prior route and verifies it, then handles the failed slot.

### 3.5 Failure and ambiguity

1. A deterministic validation failure may enter `CLEANUP_PENDING` and then terminal `FAILED`.
2. Lost response after a persisted external intent enters `RECOVERY_REQUIRED` until readback resolves it.
3. Conflicting process, unit, socket, artifact, slot, or route ownership enters `AMBIGUOUS`.
4. `AMBIGUOUS` may return only to `RECOVERY_REQUIRED` after exact identity is re-established; it cannot jump directly to success or destructive cleanup.
5. Any cleanup obstruction enters `RECOVERY_REQUIRED` with the intended final state retained.
6. Controller restart resumes only from persisted state and exact child identities.

## 4. Slot state machine

States:

1. `EMPTY`.
2. `STAGING`.
3. `STAGED`.
4. `STARTING`.
5. `RUNNING_NOT_READY`.
6. `READY_PRIVATE`.
7. `ACTIVE`.
8. `DRAINING`.
9. `STOPPING`.
10. `STOPPED`.
11. `CLEANING`.
12. `EMPTY_VERIFIED`.
13. `FAILED`.
14. `RECOVERY_REQUIRED`.
15. `AMBIGUOUS`.

Rules:

1. Only `READY_PRIVATE` may become `ACTIVE`.
2. Only one slot per service may be the desired active slot.
3. The observed route may temporarily disagree during a persisted cutover intent; reconciliation must resolve it.
4. `EMPTY_VERIFIED` requires release-specific process, endpoint, runtime path, and transient-unit absence.
5. The release artifact itself may remain retained after slot cleanup.
6. An active slot cannot be cleaned.
7. A rollback target cannot be evicted or cleaned before policy permits.

## 5. Route state machine

States:

1. `OBSERVED`.
2. `PREPARING`.
3. `VALIDATED`.
4. `LOADING`.
5. `VERIFYING`.
6. `ACTIVE_VERIFIED`.
7. `RESTORE_REQUESTED`.
8. `RESTORING`.
9. `RESTORED_VERIFIED`.
10. `RECOVERY_REQUIRED`.
11. `AMBIGUOUS`.

A route transition requires:

1. previous config artifact and digest.
2. candidate config artifact and digest.
3. installed-Caddy validation result.
4. durable load intent.
5. API response digest.
6. active-config readback.
7. private endpoint probe.
8. public route probe.
9. exact upstream identity.

## 6. Build and certification states

Build states:

`REQUESTED`, `MATERIALIZING`, `RESTORING_CACHE`, `INSTALLING`, `BUILDING`, `PACKAGING`, `VERIFYING`, `SUCCEEDED`, `FAILED`, `RECOVERY_REQUIRED`, `AMBIGUOUS`, `CLEANING`.

Certification states:

`REQUESTED`, `MATERIALIZING`, `STARTING`, `VALIDATING`, `ACCEPTANCE`, `EVIDENCE`, `CLEANING`, `SUCCEEDED`, `FAILED`, `PRESERVED`, `RECOVERY_REQUIRED`, `AMBIGUOUS`.

A successful build or certification requires all related jobs terminal and cleanup truthful.

## 7. Event schema

Every event contains:

1. event schema version.
2. event ID.
3. parent record identity.
4. owner principal.
5. operation.
6. phase.
7. prior and next state.
8. prior and next sequence.
9. request digest.
10. idempotency key when applicable.
11. occurred-at timestamp.
12. previous event digest.
13. event digest.
14. child job IDs.
15. machine, release, slot, and route identities when applicable.
16. observation digest.
17. artifact and receipt references.
18. redacted error classification.

## 8. Success predicates

`SUCCEEDED` requires all of the following:

1. exact source or prebuilt artifact identity resolved.
2. artifact manifest verified.
3. required certification valid.
4. inactive slot staged from immutable bytes.
5. unit and process identity verified.
6. private endpoint ready.
7. candidate Caddy config validated.
8. active route readback points to the intended slot.
9. public route smoke test passed.
10. observation policy passed.
11. all related durable jobs terminal.
12. previous slot drained, or retained under an explicit rollback policy with no hidden cleanup claim.
13. final evidence index complete and verified.
14. GitHub reporting is either delivered or durably queued; reporting outage does not change local success truth.
15. no unresolved ambiguous resource exists.

## 9. Failure codes

Stable families include:

1. `release_invalid_request`.
2. `release_wrong_principal`.
3. `release_stale_sequence`.
4. `release_idempotency_conflict`.
5. `release_capacity_insufficient`.
6. `release_source_unresolved`.
7. `release_source_mismatch`.
8. `release_cache_corrupt`.
9. `release_build_failed`.
10. `release_artifact_invalid`.
11. `release_certification_failed`.
12. `release_certification_stale`.
13. `release_stage_failed`.
14. `release_unit_invalid`.
15. `release_start_failed`.
16. `release_process_ambiguous`.
17. `release_readiness_failed`.
18. `release_route_validation_failed`.
19. `release_cutover_failed`.
20. `release_route_ambiguous`.
21. `release_observation_failed`.
22. `release_rollback_failed`.
23. `release_drain_timeout`.
24. `release_cleanup_failed`.
25. `release_evidence_incomplete`.
26. `release_credential_unavailable`.
27. `release_github_reporting_deferred`.
28. `release_provider_unavailable`.
29. `release_recovery_required`.
