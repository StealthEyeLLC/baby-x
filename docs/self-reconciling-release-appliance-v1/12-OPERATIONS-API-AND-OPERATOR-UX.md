# Operations API and Operator Experience

## 1. API principles

1. Operations are exposed through the existing single dynamic Baby-X catalog.
2. No duplicate gateway catalog is introduced.
3. Input schemas are strict and reject unknown fields.
4. Read operations are explicitly non-mutating.
5. Mutations require idempotency and owner context.
6. Sequence-sensitive mutations require `expectedSequence`.
7. Compact status responses link to bounded detail operations.
8. All operations return signed proof/receipt through the existing boundary.
9. Raw Caddy/systemd commands are not the normal release API.
10. Names are stable and versioned through compatibility metadata.

## 2. Proposed public operations

### 2.1 Discovery and planning

1. `babyx.release.describe` - capability, schema, and authority report.
2. `babyx.release.capabilities` - installed host/provider/service compatibility.
3. `babyx.release.plan` - dry-run normalized deployment plan.
4. `babyx.release.capacity` - live capacity and admission projection.
5. `babyx.release.service.get` - one service definition.
6. `babyx.release.service.list` - bounded owner-scoped service list.

### 2.2 Build and certification

7. `babyx.release.prepare` - resolve/build/reuse/certify without production activation.
8. `babyx.release.build.get` - build record.
9. `babyx.release.build.list` - bounded build list.
10. `babyx.release.certification.get` - certification record.
11. `babyx.release.certification.list` - bounded certification list.
12. `babyx.release.artifact.verify` - verify release artifact and manifest.

### 2.3 Deployment lifecycle

13. `babyx.release.promote` - one-command prepare-and-promote or promote prepared artifact.
14. `babyx.release.approve` - approve one exact request digest.
15. `babyx.release.cancel` - request safe cancellation before terminal state.
16. `babyx.release.rollback` - restore an exact prior known-good release.
17. `babyx.release.reconcile` - reconcile one or bounded deployments.
18. `babyx.release.resume` - owner-requested retry after a resolved obstruction.
19. `babyx.release.expire` - request retention expiration.
20. `babyx.release.gc` - bounded dry-run/live garbage collection.

### 2.4 Status and evidence

21. `babyx.release.live` - authoritative answer to what is live.
22. `babyx.release.status` - one deployment with observed truth.
23. `babyx.release.get` - durable deployment record.
24. `babyx.release.list` - bounded owner-scoped deployments.
25. `babyx.release.events` - bounded hash-chained timeline.
26. `babyx.release.evidence` - final or current evidence index.
27. `babyx.release.slot.get` - slot and process truth.
28. `babyx.release.route.get` - route and Caddy truth.
29. `babyx.release.failures` - bounded unresolved/recovery-required summary.

### 2.5 GitHub and credentials

30. `babyx.release.github.status` - inbox/outbox and installation capability without secrets.
31. `babyx.release.github.reconcile` - bounded inbox/outbox reconciliation.
32. `babyx.release.credentials.describe` - credential names/capabilities only.
33. `babyx.release.credentials.rotate` - stage exact credential-set reference on inactive slot.

### 2.6 Host maintenance namespace

Host maintenance uses separate operations such as:

1. `babyx.maintenance.describe`.
2. `babyx.maintenance.plan`.
3. `babyx.maintenance.apply`.
4. `babyx.maintenance.status`.
5. `babyx.maintenance.reconcile`.
6. `babyx.maintenance.reboot`.

These do not share deployment state transitions.

## 3. `babyx.release.promote` request

A normalized request accepts one of:

1. exact certified artifact ID/digest.
2. exact certification ID.
3. exact source commit plus build/certification profile.

It also includes:

1. service ID.
2. environment, initially `production` or approved preview.
3. approval mode override only when policy allows it.
4. requested observation profile.
5. scheduled promotion time/window when applicable.
6. reason.
7. expected current active release when used as compare-and-swap.
8. optional GitHub trigger reference.

It does not accept arbitrary shell, systemd unit text, Caddy JSON, secret value, mutable branch as final identity, or unbounded timeout.

## 4. `babyx.release.live` response

One compact response answers:

1. service ID.
2. desired active slot.
3. observed routed slot.
4. release ID.
5. artifact digest.
6. repository, commit, tree, and lockfile digest.
7. certification ID and state.
8. systemd unit.
9. process PID/start time/executable/boot ID digest or bounded identity.
10. endpoint type/path or loopback address.
11. Caddy config digest.
12. readiness and liveness.
13. observation status.
14. prior rollback release and slot.
15. active deployment ID and state.
16. drift/ambiguity status.
17. evidence index reference.
18. last reconciliation time.

No secret values are returned.

## 5. Phone-friendly workflow

### Prepare and promote

1. Ask for `babyx.release.plan` by service and commit.
2. Review compact source, cache, capacity, certification, and route summary.
3. Call `babyx.release.promote` once.
4. Poll `babyx.release.status` or receive GitHub status.
5. If approval mode pauses, call `babyx.release.approve` once for the exact digest.
6. Read `babyx.release.live` after completion.

### Rollback

1. Call `babyx.release.rollback` with service or deployment ID and reason.
2. Release Authority selects the recorded prior known-good target unless an exact allowed target is supplied.
3. Observe one durable status.
4. Read `babyx.release.live` for final truth.

No terminal, SSH command, manual Caddy edit, systemctl command, or file copy is required.

## 6. Failure presentation

The top-level status includes:

1. phase.
2. stable failure code.
3. human-readable bounded message.
4. retryable flag.
5. production impact: `NONE`, `CANDIDATE_ONLY`, `ROLLED_BACK`, `ACTIVE_DEGRADED`, or `UNKNOWN`.
6. active route identity.
7. unresolved resources.
8. recommended next authorized operation.
9. evidence reference.

Examples remain distinct:

1. source resolution failure.
2. cache corruption.
3. build failure.
4. certification failure.
5. capacity rejection.
6. stage failure.
7. startup failure.
8. readiness failure.
9. Caddy validation failure.
10. cutover failure.
11. observation degradation.
12. rollback failure.
13. drain timeout.
14. cleanup obstruction.
15. GitHub reporting delay.

## 7. Automation policies

### Low-risk automatic promotion

A change is eligible only when all configured criteria pass, for example:

1. approved repository and branch.
2. exact source identity.
3. valid certification.
4. no dependency or runtime change.
5. no migration or credential change.
6. bounded small artifact/change classification.
7. healthy current production and rollback target.
8. adequate capacity.
9. service-specific automatic-promotion permission.
10. no active incident or maintenance lock.

Failure of any criterion falls back to prepare-and-wait-for-approval; it does not reject preparation.

## 8. Scheduled promotion

1. Preparation and certification may complete early.
2. The record enters `AWAITING_APPROVAL` or scheduled wait.
3. Scheduled time uses an explicit timezone and bounded window.
4. At execution time, capacity, current active release, certification validity, and health are rechecked.
5. A stale plan is recalculated or rejected, never applied blindly.

## 9. Read-only guarantees

The following must not mutate durable or external state:

1. describe.
2. capabilities.
3. plan.
4. capacity.
5. get/list/events.
6. live/status.
7. evidence reads.
8. slot/route reads.
9. GitHub status read.
10. credentials describe.

Tests compare state, filesystem, jobs, units, and Caddy config before and after these calls.

## 10. Compatibility and migration

1. `babyx.release.describe` publishes all schema and provider versions.
2. Existing God Mode operations remain unchanged.
3. Release operations are additive in one catalog.
4. Unknown newer records fail closed.
5. Older supported records are readable without silent rewrite.
6. Service definitions have explicit migration operations.
7. The implementation records its frozen rollback commit and tree.
8. A future V2 branch remains independent.

## 11. Example compact outcomes

Successful promotion:

```json
{
  "operation": "babyx.release.promote",
  "deploymentId": "dep_...",
  "serviceId": "baby-x",
  "state": "SUCCEEDED",
  "activeSlot": "green",
  "releaseId": "rel_...",
  "artifactSha256": "...",
  "priorSlot": "blue",
  "rollbackReady": true,
  "zeroDowntimeVerified": true,
  "evidenceIndex": "artifact_..."
}
```

Prepared, awaiting approval:

```json
{
  "state": "AWAITING_APPROVAL",
  "requestDigest": "...",
  "candidateSlot": "green",
  "readiness": "passed",
  "currentProductionUnchanged": true
}
```

Rollback after degradation:

```json
{
  "state": "ROLLED_BACK",
  "activeSlot": "blue",
  "failedSlot": "green",
  "productionRestored": true,
  "cleanup": "verified-or-retained",
  "evidenceIndex": "artifact_..."
}
```
