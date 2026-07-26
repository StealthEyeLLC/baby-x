# Requirements Traceability

## 1. Purpose

This ledger maps every requested outcome to its controlling design and required acceptance evidence. An item is not complete merely because code exists; its verification must pass and be preserved in the final evidence index.

## 2. Requested outcomes 1-95

### R-001 - One-command deployment

- **Design:** Release Authority exposes one typed promote operation that resolves or reuses build and certification, stages, starts, cuts over, observes, drains, and finalizes.
- **Verification:** Complete promote acceptance and exact replay.
- **Controlling documents:** `00, 05, 13`.

### R-002 - Deployments in seconds instead of minutes

- **Design:** Dependency, build-output, source, artifact, and certification reuse remove repeated work; inactive-slot prewarming shortens the critical path.
- **Verification:** Warm-cache deployment timing benchmark and no-op timing benchmark.
- **Controlling documents:** `00, 05, 13`.

### R-003 - No production builds

- **Design:** Production slots consume only immutable verified artifacts; source checkout, install, compile, and packaging are prohibited.
- **Verification:** Source scan plus runtime acceptance proving no build executable runs in production slot.
- **Controlling documents:** `00, 05, 13`.

### R-004 - No manual SSH deployment workflow

- **Design:** All normal deployment actions are Baby release operations or verified GitHub-triggered requests.
- **Verification:** End-to-end promotion and rollback performed only through Baby operations.
- **Controlling documents:** `00, 05, 13`.

### R-005 - Automatic deployment from GitHub

- **Design:** Verified webhook inbox and polling fallback normalize push, tag, release, deployment, and approval events.
- **Verification:** Signed webhook, redelivery, polling, and GitHub-outage tests.
- **Controlling documents:** `00, 05, 13`.

### R-006 - Idempotent deployment requests

- **Design:** Owner, idempotency key, request digest, and sequence bind every mutation.
- **Verification:** Exact replay returns one deployment; conflicting reuse is rejected.
- **Controlling documents:** `00, 05, 13`.

### R-007 - Parallel preparation

- **Design:** Build/certification and inactive-slot preparation can proceed while the active slot serves traffic, subject to the governor.
- **Verification:** Continuous traffic during preparation with production health preserved.
- **Controlling documents:** `00, 05, 13`.

### R-008 - Pre-warmed inactive release slot

- **Design:** Blue/green slots allow private startup and readiness before route exposure.
- **Verification:** Inactive endpoint passes readiness while public route remains on old slot.
- **Controlling documents:** `00, 05, 13`.

### R-009 - Fast dependency restoration

- **Design:** Complete lockfile/runtime/base-snapshot cache key restores verified dependency objects.
- **Verification:** Cache hit, miss, corruption, and identity-mismatch tests.
- **Controlling documents:** `00, 05, 13`.

### R-010 - Content-addressed release reuse

- **Design:** One canonical object exists per digest and repeated releases reference it.
- **Verification:** Repeated request creates no duplicate artifact bytes.
- **Controlling documents:** `00, 05, 13`.

### R-011 - Blue/green deployments

- **Design:** Every routable service receives stable blue and green slots bound to immutable releases.
- **Verification:** Blue-to-green and green-to-blue acceptance.
- **Controlling documents:** `06, 13`.

### R-012 - Atomic traffic switching

- **Design:** Validated full Caddy config is loaded through the local admin API and read back.
- **Verification:** Single route transition under continuous traffic.
- **Controlling documents:** `06, 13`.

### R-013 - No broken intermediate state

- **Design:** Artifact extraction finalizes by atomic rename; route changes only after private readiness.
- **Verification:** Crash injection during extraction and cutover.
- **Controlling documents:** `06, 13`.

### R-014 - Graceful connection draining

- **Design:** Route removal, stream-close delay, application/worker quiesce, and bounded stop preserve existing work.
- **Verification:** Keep-alive, WebSocket, SSE, and worker-drain tests.
- **Controlling documents:** `06, 13`.

### R-015 - Readiness-gated exposure

- **Design:** Unit activity, exact process identity, endpoint ownership, protocol probe, and consecutive success are required.
- **Verification:** Alive-but-not-ready candidate never receives traffic.
- **Controlling documents:** `06, 13`.

### R-016 - Health-gated promotion

- **Design:** Dependency, schema, startup, file, credential, migration, readiness, and smoke checks can block promotion.
- **Verification:** Distinct failure injection for every gate.
- **Controlling documents:** `06, 13`.

### R-017 - Near-instant rollback

- **Design:** Prior immutable release and saved route remain ready through the observation window.
- **Verification:** Measured route restoration without rebuild.
- **Controlling documents:** `06, 13`.

### R-018 - Automatic rollback

- **Design:** Hard and threshold triggers request one bounded rollback with hysteresis.
- **Verification:** Process, readiness, error-rate, latency, memory, and OOM trigger tests.
- **Controlling documents:** `06, 13`.

### R-019 - No rollback through source mutation

- **Design:** Rollback selects a recorded release and route; Git reset/checkout/rebuild is absent.
- **Verification:** Source remains unchanged during rollback acceptance.
- **Controlling documents:** `06, 13`.

### R-020 - Release observation windows

- **Design:** Provisional releases are sampled for declared duration and minimum count before final success.
- **Verification:** Restart-resilient observation and threshold tests.
- **Controlling documents:** `06, 13`.

### R-021 - Crash-safe deployment state

- **Design:** Atomic records, pending mutations, event chain, and fsync boundaries preserve intent and truth.
- **Verification:** Crash after every persistence boundary.
- **Controlling documents:** `04, 07, 13`.

### R-022 - Response-loss recovery

- **Design:** External-effect intent is persisted first; recovery reads back exact state before retry.
- **Verification:** Response loss after every side effect.
- **Controlling documents:** `04, 07, 13`.

### R-023 - Restart recovery

- **Design:** Startup repairs indexes, reconciles jobs, leases, deployments, slots, routes, and outbox within bounds.
- **Verification:** Controller and host-process restart suite.
- **Controlling documents:** `04, 07, 13`.

### R-024 - Exact child-job adoption

- **Design:** Only persisted job IDs and exact process identities are adopted.
- **Verification:** Foreign, reused-PID, and missing-job tests.
- **Controlling documents:** `04, 07, 13`.

### R-025 - No fabricated success

- **Design:** Unknown process, exit, route, provider, or cleanup truth remains unknown/lost/recovery-required.
- **Verification:** Lost job and zero-exit-without-readback tests.
- **Controlling documents:** `04, 07, 13`.

### R-026 - Desired-state reconciliation

- **Design:** Controller continuously compares durable desired release/slot/route with observed systemd, process, socket, artifact, and Caddy truth.
- **Verification:** Drift matrix acceptance.
- **Controlling documents:** `04, 07, 13`.

### R-027 - Automatic repair of drift

- **Design:** Exact owned units, inactive slots, known routes, indexes, and GitHub outbox can be repaired automatically.
- **Verification:** Safe-repair tests and conflict exclusions.
- **Controlling documents:** `04, 07, 13`.

### R-028 - Safe ambiguous-state handling

- **Design:** Identity conflict enters AMBIGUOUS and blocks destructive action.
- **Verification:** Foreign unit/process/socket/config tests prove no cleanup.
- **Controlling documents:** `04, 07, 13`.

### R-029 - Verified cleanup

- **Design:** Unit, process, endpoint, runtime path, jobs, route references, mounts, and datasets require positive absence.
- **Verification:** Cleanup obstruction and eventual recovery tests.
- **Controlling documents:** `04, 07, 13`.

### R-030 - Previous-release preservation

- **Design:** Active and prior known-good releases are protected references until a newer release survives policy.
- **Verification:** Retention/GC cannot remove rollback target.
- **Controlling documents:** `04, 07, 13`.

### R-031 - Full use of all six vCores

- **Design:** Governor can raise bounded build/test/compression concurrency to four workers while leaving production headroom.
- **Verification:** Idle-host scaling benchmark and pressure reduction test.
- **Controlling documents:** `02, 08, 13`.

### R-032 - Production-first CPU scheduling

- **Design:** Dedicated cgroup slices give production the highest CPU weight.
- **Verification:** cgroup readback and load-under-build latency test.
- **Controlling documents:** `02, 08, 13`.

### R-033 - Production-first disk scheduling

- **Design:** Production receives the highest I/O weight; extraction/compression run in background slices.
- **Verification:** I/O pressure acceptance with live traffic.
- **Controlling documents:** `02, 08, 13`.

### R-034 - Memory pressure protection

- **Design:** MemoryHigh, MemoryMax, available-memory floors, and PSI pause background work.
- **Verification:** Synthetic pressure test without production OOM.
- **Controlling documents:** `02, 08, 13`.

### R-035 - Pressure-aware concurrency

- **Design:** CPU, memory, I/O PSI, capacity, and service health choose concurrency dynamically.
- **Verification:** Governor decision and transition tests.
- **Controlling documents:** `02, 08, 13`.

### R-036 - Bounded deployment workloads

- **Design:** Every build/test/archive/extract/probe has time, memory, CPU, tasks, output, artifact, and disk bounds.
- **Verification:** Boundary and cancellation tests.
- **Controlling documents:** `02, 08, 13`.

### R-037 - Faster release staging through ZFS

- **Design:** Disposable build/certification uses fast ZFS clones; release materialization may use clone/reflink only when supported and verified.
- **Verification:** Clone identity, quota, speed, and fallback tests.
- **Controlling documents:** `02, 08, 13`.

### R-038 - Efficient compression and deduplication by identity

- **Design:** Deterministic compressed artifacts and canonical digest objects avoid repeated logical copies without ZFS block dedup.
- **Verification:** One-object-per-digest and compression benchmark.
- **Controlling documents:** `02, 08, 13`.

### R-039 - Controlled retention

- **Design:** Separate policies cover active, rollback, successful, failed, preview, cache, logs, records, and evidence.
- **Verification:** Reference-aware GC decision suite.
- **Controlling documents:** `02, 08, 13`.

### R-040 - Predictable disk headroom

- **Design:** Independent ext4 and ZFS projections plus durable reservations reject unsafe work before staging.
- **Verification:** 12 GiB root-floor and 2 GiB ZFS-floor rejection tests.
- **Controlling documents:** `02, 08, 13`.

### R-041 - Rebootless kernel security fixes where supported

- **Design:** Maintenance capability reports and integrates Canonical Livepatch only when the host is attached and entitled.
- **Verification:** Attached/unattached capability fixtures; no false coverage claim.
- **Controlling documents:** `10, 13`.

### R-042 - Controlled package updates

- **Design:** Separate Maintenance Authority classifies packages, simulates changes, verifies risky updates, and gates high-impact packages.
- **Verification:** Low/medium/high risk policy tests.
- **Controlling documents:** `10, 13`.

### R-043 - Reboot-required awareness

- **Design:** Kernel, package, running-state, and reboot-required files are reported explicitly.
- **Verification:** Fixture and live read-only capability tests.
- **Controlling documents:** `10, 13`.

### R-044 - Fast userspace restart path

- **Design:** systemd soft reboot is available as a separately approved, rehearsed userspace operation and never represented as a kernel reboot.
- **Verification:** Disposable/rehearsal and semantic truth tests.
- **Controlling documents:** `10, 13`.

### R-045 - Pre-update snapshots

- **Design:** Applicable ZFS datasets and optional provider snapshots are checkpointed through explicit provider capability; ext4 limitations are truthful.
- **Verification:** Snapshot identity/readback and unavailable-provider tests.
- **Controlling documents:** `10, 13`.

### R-046 - Post-update health certification

- **Design:** Maintenance completion requires systemd, Caddy, ZFS, Baby/operator, release, listener, and application checks.
- **Verification:** Maintenance certification fixture.
- **Controlling documents:** `10, 13`.

### R-047 - Scheduled maintenance orchestration

- **Design:** Maintenance plans can schedule drain, update, reboot path, verification, and return-to-service.
- **Verification:** Scheduled-plan revalidation and stale-plan tests.
- **Controlling documents:** `10, 13`.

### R-048 - No .env files in release artifacts

- **Design:** Manifest and archive scanners reject .env and secret-bearing paths.
- **Verification:** Malicious artifact rejection.
- **Controlling documents:** `09, 11, 13`.

### R-049 - Per-service encrypted credentials

- **Design:** systemd encrypted credentials or a protected compatibility source are scoped to one service/slot.
- **Verification:** Credential visibility and unit-boundary tests.
- **Controlling documents:** `09, 11, 13`.

### R-050 - Safe secret rotation

- **Design:** New credential set is tested on inactive slot before route cutover; prior set remains per rollback policy.
- **Verification:** Successful and failed rotation acceptance.
- **Controlling documents:** `09, 11, 13`.

### R-051 - Reduced environment-variable leakage

- **Design:** Credential files are preferred; legacy launcher injects only immediately before exec without persistence.
- **Verification:** Process arguments, records, logs, and exported evidence secret scan.
- **Controlling documents:** `09, 11, 13`.

### R-052 - Short-lived GitHub credentials

- **Design:** GitHub App installation tokens are minted on demand and treated as format-variable and expiring.
- **Verification:** Expiry, refresh, and token-format tests.
- **Controlling documents:** `09, 11, 13`.

### R-053 - No public deployment control port

- **Design:** Baby/operator remains the control plane; webhook uses an existing Caddy path and only writes inbox state.
- **Verification:** Public-listener inventory before/after.
- **Controlling documents:** `09, 11, 13`.

### R-054 - Smaller public attack surface

- **Design:** Only Caddy fronts applications; services use Unix sockets or loopback.
- **Verification:** Wildcard-listener and admin-endpoint isolation tests.
- **Controlling documents:** `09, 11, 13`.

### R-055 - Exact commit-to-production binding

- **Design:** Live state binds repository, commit, tree, lockfile, build profile, certification, and artifact digest.
- **Verification:** Evidence and live projection recomputation.
- **Controlling documents:** `04, 06, 07, 09, 13`.

### R-056 - Exact artifact-to-process binding

- **Design:** Slot record binds artifact/release to unit, cgroup, invocation, process identity, and endpoint.
- **Verification:** Process identity readback test.
- **Controlling documents:** `04, 06, 07, 09, 13`.

### R-057 - Signed deployment receipts

- **Design:** Every mutation crosses the existing signed proof/receipt boundary and final evidence references receipts.
- **Verification:** Signature and mutation-detection tests.
- **Controlling documents:** `04, 06, 07, 09, 13`.

### R-058 - Complete deployment timeline

- **Design:** Hash-chained events record request, build, certify, stage, start, cutover, observe, drain, rollback, and cleanup.
- **Verification:** Sequence/digest continuity test.
- **Controlling documents:** `04, 06, 07, 09, 13`.

### R-059 - Provable zero-downtime acceptance

- **Design:** Traffic harness records every request across promotion and verifies no cutover-attributable failures under the declared envelope.
- **Verification:** Integrated continuous-traffic certification.
- **Controlling documents:** `04, 06, 07, 09, 13`.

### R-060 - Provable rollback acceptance

- **Design:** A deliberately defective candidate triggers or requests rollback and verifies restored service identity.
- **Verification:** Defective-release acceptance artifact.
- **Controlling documents:** `04, 06, 07, 09, 13`.

### R-061 - Provable process absence

- **Design:** Cleanup evidence proves unit, exact process, endpoint, socket, runtime path, jobs, mount, and dataset absence where applicable.
- **Verification:** Positive-absence certification.
- **Controlling documents:** `04, 06, 07, 09, 13`.

### R-062 - Auditable operator actions

- **Design:** Manual, scheduled, automatic, and GitHub requests normalize into the same owner-bound durable authority.
- **Verification:** Equivalent-request provenance tests.
- **Controlling documents:** `04, 06, 07, 09, 13`.

### R-063 - No uncertainty about what is running

- **Design:** babyx.release.live projects exact route, slot, release, artifact, source, process, endpoint, health, and rollback target.
- **Verification:** Read-only live-state acceptance.
- **Controlling documents:** `04, 06, 07, 09, 13`.

### R-064 - GitHub-visible deployment history

- **Design:** Durable outbox maps local states to GitHub deployment/check statuses.
- **Verification:** Queued through inactive/success/failure/rollback reporting tests.
- **Controlling documents:** `04, 06, 07, 09, 13`.

### R-065 - A single promotion action

- **Design:** babyx.release.promote owns the normal end-to-end request.
- **Verification:** One API call starts the durable workflow.
- **Controlling documents:** `07, 12, 13`.

### R-066 - Phone-friendly deployment control

- **Design:** Compact plan, approve, promote, rollback, status, and live operations require no terminal.
- **Verification:** Operator UX acceptance through Baby only.
- **Controlling documents:** `07, 12, 13`.

### R-067 - Clear failure classification

- **Design:** Stable codes distinguish source, cache, build, certification, capacity, stage, start, readiness, route, observation, rollback, drain, cleanup, and reporting.
- **Verification:** Failure-code matrix.
- **Controlling documents:** `07, 12, 13`.

### R-068 - Automatic evidence collection

- **Design:** Jobs, logs, probes, configs, identities, metrics, artifacts, receipts, and cleanup are automatically indexed.
- **Verification:** Evidence completeness validator.
- **Controlling documents:** `07, 12, 13`.

### R-069 - No dependency on one long-running chat or shell

- **Design:** Durable state and reconciliation survive loss of initiating interface and controller process.
- **Verification:** Interface-disconnect and restart tests.
- **Controlling documents:** `07, 12, 13`.

### R-070 - No detached mystery processes

- **Design:** Every child process is a durable job or systemd-owned slot process with exact identity.
- **Verification:** Process census and authority scan.
- **Controlling documents:** `07, 12, 13`.

### R-071 - Safe experimentation

- **Design:** Candidates and previews start privately or in disposable machines without touching the active route.
- **Verification:** Failed experiment leaves production unchanged.
- **Controlling documents:** `07, 12, 13`.

### R-072 - Repeatable incident reproduction

- **Design:** Exact artifact, service definition, credential-name contract, base snapshot, profile, and evidence can reconstruct a failed environment.
- **Verification:** Replay a preserved failure in disposable machine.
- **Controlling documents:** `07, 12, 13`.

### R-073 - Simple status answer

- **Design:** One authoritative read operation provides compact live truth.
- **Verification:** babyx.release.live read-only test.
- **Controlling documents:** `07, 12, 13`.

### R-074 - Simple rollback answer

- **Design:** One durable rollback operation selects and verifies the recorded known-good target.
- **Verification:** Phone-only rollback acceptance.
- **Controlling documents:** `07, 12, 13`.

### R-075 - Independent worker deployment

- **Design:** Service definitions and drain modes support web, API, worker, scheduler, and internal process slots independently.
- **Verification:** Worker intake/quiesce fixture.
- **Controlling documents:** `06, 12, 13`.

### R-076 - Ordered multi-service deployment

- **Design:** Deployment groups declare dependencies, compatibility, stage-all, ordered cutover, and rollback strategy.
- **Verification:** Two-service compatibility and failure fixture.
- **Controlling documents:** `06, 12, 13`.

### R-077 - Backward-compatible database migration workflows

- **Design:** Typed expand/migrate/contract steps bind evidence and protect rollback semantics.
- **Verification:** Expand/migrate/contract fixture with irreversible-change gate.
- **Controlling documents:** `06, 12, 13`.

### R-078 - Canary operation on one VPS

- **Design:** Typed route policy supports bounded percentage or matcher-based canary with sticky behavior and observation.
- **Verification:** Policy-gated canary fixture and full-promotion/rollback tests.
- **Controlling documents:** `06, 12, 13`.

### R-079 - Shadow traffic validation

- **Design:** Typed shadow policy mirrors only service-approved safe requests and discards candidate responses.
- **Verification:** Side-effect-safe shadow fixture and privacy checks.
- **Controlling documents:** `06, 12, 13`.

### R-080 - Header- or identity-based preview releases

- **Design:** Trusted Caddy matchers route approved identities/headers to a private candidate without general exposure.
- **Verification:** Authorized and unauthorized preview routing tests.
- **Controlling documents:** `06, 12, 13`.

### R-081 - Per-commit preview environments

- **Design:** Exact commits can create expiring disposable preview machines/endpoints with retention and capacity limits.
- **Verification:** Preview create, access, expiry, and absence tests.
- **Controlling documents:** `06, 12, 13`.

### R-082 - Scheduled promotion

- **Design:** Prepared deployment waits for a timezone-bound window and rechecks all stale facts before cutover.
- **Verification:** Scheduled execution and stale-plan tests.
- **Controlling documents:** `06, 12, 13`.

### R-083 - Approval-gated promotion

- **Design:** One approval binds exact request/source/artifact/certification and expires.
- **Verification:** Wrong, stale, reused, and valid approval tests.
- **Controlling documents:** `06, 12, 13`.

### R-084 - Automatic promotion for low-risk changes

- **Design:** Strict service policy auto-promotes only exact low-risk candidates; all uncertainty falls back to approval.
- **Verification:** Eligibility matrix and fallback tests.
- **Controlling documents:** `06, 12, 13`.

### R-085 - Reusable release platform for every StealthEye service

- **Design:** Typed service definitions, artifact manifests, slot and route adapters are service-agnostic.
- **Verification:** At least web, worker, and internal-service fixtures.
- **Controlling documents:** `03, 05, 13`.

### R-086 - Separation of build authority from release authority

- **Design:** Build and certification cannot invoke systemd/Caddy production activation; Release Authority cannot compile.
- **Verification:** Static authority-boundary audit and runtime mocks.
- **Controlling documents:** `03, 05, 13`.

### R-087 - Deployment as a durable transaction

- **Design:** Deployment has strict lifecycle, sequence, idempotency, events, leases, recovery, evidence, and ambiguity.
- **Verification:** Full restart/adversarial transaction suite.
- **Controlling documents:** `03, 05, 13`.

### R-088 - Immutable infrastructure behavior without replacing Ubuntu

- **Design:** Digest-addressed read-only releases and slot selection run on current Ubuntu/systemd/Caddy.
- **Verification:** Installed-host compatibility certification.
- **Controlling documents:** `03, 05, 13`.

### R-089 - Future Portable Service or mkosi releases

- **Design:** Artifact/provider interfaces and release manifest are transport-neutral enough to add signed service images later.
- **Verification:** Compatibility extension point documented and tested against unknown-provider rejection.
- **Controlling documents:** `03, 05, 13`.

### R-090 - Future Nix-backed deterministic toolchains

- **Design:** Build profile/toolchain identity can add Nix without changing Release Authority.
- **Verification:** Provider contract and schema compatibility test.
- **Controlling documents:** `03, 05, 13`.

### R-091 - Future second-node failover

- **Design:** Release, artifact, desired-state, and evidence identities contain no single-path semantic dependency.
- **Verification:** Architecture audit and host-scoped observation fields.
- **Controlling documents:** `03, 05, 13`.

### R-092 - Future active/passive high availability

- **Design:** Route and host-scoped deployment records allow a later standby host while v1 remains truthfully single-node.
- **Verification:** No false HA claim; extension contract documented.
- **Controlling documents:** `03, 05, 13`.

### R-093 - Future geographic deployment

- **Design:** Content-addressed artifacts and per-host desired state are portable to later region adapters.
- **Verification:** Provider/host identity separation audit.
- **Controlling documents:** `03, 05, 13`.

### R-094 - Future fleet reconciliation

- **Design:** Service desired release is separable from host-specific slot/process observations.
- **Verification:** Schema supports bounded per-host outcomes without weakening local truth.
- **Controlling documents:** `03, 05, 13`.

### R-095 - Foundation for self-hosting upgrades

- **Design:** Baby-X may build/certify its successor while independent Release Authority controls activation and retains rollback.
- **Verification:** Self-upgrade rehearsal with controller survival and rollback.
- **Controlling documents:** `03, 05, 13`.

## 3. Completion accounting

1. The implementation report MUST list R-001 through R-095 with status `PASS`, `PARTIAL`, `BLOCKED`, or `NOT_STARTED`.
2. `PARTIAL` requires exact missing behavior and evidence.
3. `BLOCKED` requires the external dependency, why safe fallback is insufficient, and the next action.
4. Future-leverage items R-089 through R-094 are complete in v1 only when the extension contract and authority separation are proven; they MUST NOT be reported as deployed multi-node capability.
5. Livepatch R-041 is capability-gated and may truthfully pass as `supported-but-not-enabled` when Ubuntu Pro is not attached; the appliance itself must still implement detection and integration.
6. Provider snapshot portions of R-045 are capability-gated; local ZFS checkpointing and truthful provider-unavailable reporting remain mandatory.
7. Canary, shadow, controlled preview, and per-commit preview R-078 through R-081 are real v1 typed capabilities and require acceptance fixtures, even when a production service policy leaves them disabled.
8. No requirement may be silently dropped because the host is small; resource policy must bound it or report a hard limitation.
