# Implementation Plan and Acceptance

## 1. Execution rules

1. Work only on `build/baby-x-self-reconciling-release-appliance-v1`.
2. Verify base commit/tree before implementation.
3. Keep `build/baby-x-god-mode-v1` unchanged.
4. Do not use the V2 branch as implementation base.
5. Push stable fast-forward checkpoints early.
6. Do not force push or rewrite history.
7. Do not mutate production until the controlled migration checkpoint explicitly authorizes it.
8. Build read-only discovery and rehearsal paths before write paths.
9. Use existing job, machine, artifact, proof, and gateway authorities rather than duplicates.
10. Every checkpoint must pass build, lint, tests, shell/native checks, and clean-tree verification.

## 2. Checkpoint A - Compatibility and schemas

Deliver:

1. frozen compatibility manifest.
2. strict service, source, build, artifact, certification, release, slot, route, deployment, observation, evidence, GitHub, capacity, lease, event, and pending-mutation schemas.
3. state transition tables.
4. deterministic canonicalization/digests.
5. redaction and bounded-error utilities.
6. read-only `babyx.release.describe` and capabilities skeleton.

Tests:

1. deterministic serialization/digests.
2. unknown fields and versions fail closed.
3. illegal transitions rejected.
4. terminal success predicates enforced.
5. no raw secret storage.
6. frozen baseline identity immutable.
7. single catalog exposure.

Preferred commit: `feat: define release appliance compatibility and schemas`.

## 3. Checkpoint B - Durable stores and recovery foundation

Deliver:

1. authoritative stores.
2. atomic writes and pending mutation journal.
3. hash-chained events.
4. derived indexes and repair.
5. idempotency indexes.
6. controller and route leases.
7. corruption isolation.
8. startup bounded scan.

Tests:

1. write interruption recovery.
2. index corruption repair without record rewrite.
3. record corruption isolation.
4. event-chain validation.
5. live lease overlap rejection.
6. positive stale-controller absence requirement.
7. bounded startup behavior.

Preferred commit: `feat: add durable release appliance stores and recovery`.

## 4. Checkpoint C - Source, build, cache, and artifact pipeline

Deliver:

1. exact source resolver/archive.
2. source manifest.
3. build-profile normalization.
4. dependency cache.
5. build output cache.
6. deterministic release artifact and manifest.
7. artifact materialization/quarantine.
8. release record.
9. capacity estimation and reservation.

Tests:

1. exact commit/tree/archive binding.
2. cache hit/miss/corruption.
3. archive traversal and symlink escape.
4. deterministic packaging.
5. secret-file rejection.
6. capacity rejection before write.
7. response-loss recovery.
8. no production build path.

Preferred commit: `feat: build immutable content-addressed releases`.

## 5. Checkpoint D - Certification integration

Deliver:

1. release certification profile.
2. exact artifact certification.
3. reusable certification identity.
4. startup/readiness/shutdown/resource/security tests in disposable machines.
5. evidence and cleanup integration.

Tests:

1. valid artifact succeeds.
2. bad manifest, dependency, startup, readiness, or smoke fails distinctly.
3. reuse only for exact identities.
4. active jobs block success.
5. cleanup failure blocks certification success.
6. restart resumes exact jobs.

Preferred commit: `feat: certify immutable releases in disposable machines`.

## 6. Checkpoint E - Slot runtime and systemd adapter

Deliver:

1. service definitions.
2. deterministic unit/drop-in generation.
3. systemd validation.
4. blue/green slot store.
5. Unix-socket and loopback endpoint adapters.
6. native and compatibility readiness.
7. exact unit/process/endpoint adoption.
8. stop and positive absence.
9. systemd slices and resource profiles.

Tests:

1. private inactive start.
2. unit validation failure.
3. process identity/PID reuse.
4. endpoint conflict.
5. readiness failure.
6. restart adoption.
7. cleanup obstruction.
8. active slot cannot be deleted.

Preferred commit: `feat: add durable blue-green slot runtime`.

## 7. Checkpoint F - Caddy route authority

Deliver:

1. trusted route templates.
2. current config capture.
3. installed-version adapt/validate.
4. local admin client.
5. full-config load.
6. active-config readback.
7. private/public probes.
8. saved-config restoration.
9. stream/drain settings.
10. typed canary, shadow, header/identity preview, and expiring preview-route adapters.

Tests:

1. candidate validation.
2. load success and readback.
3. invalid load preserves prior config.
4. response-loss recovery.
5. unknown active config becomes ambiguous.
6. application cannot reach admin endpoint.
7. Unix-socket and loopback upstreams.
8. WebSocket/SSE reload behavior.
9. canary weighting/stickiness and rollback.
10. shadow response isolation and side-effect policy.
11. preview authentication, expiry, and route cleanup.

Preferred commit: `feat: add atomic Caddy route authority`.

## 8. Checkpoint G - Release coordinator

Deliver:

1. full deployment lifecycle.
2. one-command prepare/promote.
3. approval and scheduling.
4. cutover.
5. observation.
6. manual and automatic rollback.
7. drain.
8. final evidence.
9. owner-scoped reads/list/events.
10. live-state projection.

Tests:

1. complete happy path.
2. exact idempotent replay.
3. conflicting idempotency rejection.
4. wrong principal/stale sequence.
5. failure at every phase leaves production safe.
6. restart and response loss at every phase.
7. no direct build/process/route alternate authority.

Preferred commit: `feat: add durable self-reconciling release authority`.

## 9. Checkpoint H - Resource governor and retention

Deliver:

1. ext4 and ZFS capacity snapshots.
2. durable reservations.
3. PSI governor.
4. cgroup priority enforcement.
5. reference-aware retention and GC.
6. bounded logs/evidence.
7. cache eviction.

Tests:

1. concurrent reservation conflict.
2. root/ZFS floors.
3. PSI reduces concurrency.
4. production control remains responsive.
5. active/rollback artifacts never evicted.
6. GC dry-run reasons.
7. restart reconstruction.

Preferred commit: `feat: govern release appliance capacity and retention`.

## 10. Checkpoint I - Credentials and GitHub

Deliver:

1. systemd credential references and encrypted blobs.
2. compatibility launcher.
3. inactive-slot rotation.
4. GitHub App token minting.
5. verified webhook inbox.
6. polling fallback.
7. durable reporting outbox.
8. deployment/check status mapping.

Tests:

1. no raw secret persistence.
2. wrong secret fails only candidate.
3. successful rotation.
4. webhook HMAC and replay.
5. token expiry/format independence.
6. GitHub outage/retry.
7. stale approval rejection.
8. event and manual requests converge.

Preferred commit: `feat: integrate scoped credentials and GitHub delivery`.

## 11. Checkpoint J - Host maintenance authority

Deliver:

1. read-only maintenance capability/inventory.
2. package simulation and classification.
3. separate maintenance records/state machine.
4. disposable verification hooks.
5. reboot-required and Livepatch reporting.
6. soft/full reboot plans without automatic production use.
7. post-update certification.

Tests:

1. root ext4 limitation represented truthfully.
2. unattached Ubuntu Pro represented truthfully.
3. soft reboot never claimed as kernel update.
4. high-impact package requires approval.
5. failure distinct from application deployment.
6. no reboot performed during unit/integration tests.

Preferred commit: `feat: add governed host maintenance authority`.

## 12. Checkpoint K - Full disposable acceptance

Run a disposable integrated topology containing:

1. Caddy.
2. old and new application slots.
3. release controller.
4. durable store.
5. traffic generator.
6. WebSocket/SSE fixtures.
7. GitHub mock or bounded test installation.
8. credential fixtures.
9. pressure and failure injectors.

Required scenarios:

1. first installation.
2. no-op deployment.
3. cache hit deployment.
4. cache miss deployment.
5. blue-to-green and green-to-blue.
6. continuous traffic with zero failed requests under declared envelope.
7. long-lived WebSocket/SSE drain.
8. candidate startup/readiness failure.
9. Caddy validation/load failure.
10. automatic rollback for process, readiness, latency, error, and OOM signal.
11. response loss and restart at each phase.
12. PID and route ambiguity.
13. disk/PSI admission.
14. GitHub outage/redelivery.
15. credential rotation.
16. cleanup obstruction and recovery.
17. final evidence verification.
18. canary, shadow, header/identity preview, and per-commit preview scenarios.
19. complete absence of temporary machines/jobs/resources.

Preferred commit: `test: certify self-reconciling release appliance`.

## 13. Checkpoint L - Controlled production migration

This is the first checkpoint permitted to mutate production deployment state. Before proceeding:

1. owner authorization for production migration must be explicit.
2. all previous checkpoints must be pushed and verified remotely.
3. production inventory and current runbook must be captured.
4. exact current active process, unit, Caddy route, source, and secrets must be understood.
5. rollback release artifact for the currently running version must be constructed and certified.
6. current Caddy config must be preserved.
7. capacity admission must pass.
8. no unresolved host or ZFS warning may exist.
9. provider recovery path must be documented.
10. migration must use a reversible compatibility slot first.

Production acceptance:

1. import current version as blue known-good release.
2. verify blue private/public identity without changing traffic incorrectly.
3. stage a functionally equivalent green release.
4. run continuous traffic.
5. cut over and verify no failed requests.
6. roll back deliberately and verify.
7. promote again.
8. observe through the full window.
9. drain old slot.
10. verify evidence and cleanup.
11. verify `babyx.release.live` answers correctly.
12. preserve old manual path only as documented emergency fallback until owner retires it.

Preferred commit: `docs: record production release appliance acceptance`.

## 14. Final quality gate

1. pinned Node/toolchain used.
2. build passes.
3. strict lint passes.
4. all unit, integration, acceptance, recovery, and adversarial tests pass.
5. shell scripts pass syntax/static checks.
6. native helpers compile and test.
7. no tracked private key, token, credential, `.env`, or production secret.
8. no new public listener.
9. no direct alternate scheduler/job/machine/artifact/route authority.
10. branch clean and synchronized.
11. commit/tree identities recorded.
12. evidence artifacts digest-verified.
13. all related jobs terminal.
14. temporary machines, processes, mounts, paths, sockets, and datasets absent.
15. protected God Mode baseline unchanged.
16. no merge or release activation without explicit owner authorization.

## 15. Required reports

1. compatibility report.
2. authority-boundary audit.
3. test inventory and results.
4. performance/capacity baseline.
5. zero-downtime evidence.
6. rollback evidence.
7. restart/response-loss evidence.
8. security/threat acceptance.
9. cleanup/absence evidence.
10. production-readiness report.
11. unresolved limitations.
12. exact remote branch, commits, trees, and pull request state.
