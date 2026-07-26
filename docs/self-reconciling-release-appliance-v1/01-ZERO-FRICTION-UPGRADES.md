# Zero-Friction Upgrades

## 1. Admission rule

An item is classified as zero-friction only when all of the following are true:

1. It adds no normal-path operator step.
2. It requires no application rewrite for the baseline path.
3. It introduces no new public listening port.
4. It requires no paid external service.
5. It causes no planned production outage.
6. It is reversible through configuration or selection of the prior release.
7. It can be capability-detected.
8. Unsupported capability degrades to a safe existing path.
9. It does not reduce evidence quality.
10. It does not grant new authority to GitHub, the builder, or the candidate artifact.

The following upgrades meet that rule and SHOULD be part of v1.

## 2. Source, build, and artifact upgrades

### ZF-001 - Exact source archive materialization

Resolve an exact commit and tree, create or retrieve a digest-bound source archive, and build from that archive. This removes production Git working-tree state without changing developer workflow.

### ZF-002 - Content-addressed release identity

Use the artifact digest as the canonical release identity. Repeated requests for the same bytes converge automatically.

### ZF-003 - Automatic manifest synthesis

If a repository does not yet contain a service-release manifest, infer a conservative manifest from package metadata and current unit configuration, persist the generated candidate as evidence, and require explicit approval only when inference is ambiguous. Existing services do not need an immediate source change.

### ZF-004 - Lockfile-keyed dependency cache

Cache dependencies by OS snapshot, architecture, runtime digest, package-manager version, lockfile digest, and install flags. Reuse is automatic and denied on any identity mismatch.

### ZF-005 - Build-output cache

Cache deterministic build output by source tree, dependency cache, toolchain, and build profile. This changes no source behavior.

### ZF-006 - Certification-result reuse

Reuse a successful certification only when artifact digest, test profile, base snapshot, service contract, and dependency identities match exactly and the evidence index verifies.

### ZF-007 - One physical copy per digest

Store one canonical artifact object and reference it from releases, certifications, and deployments. This supplies deduplication-by-identity without enabling memory-expensive ZFS block deduplication.

### ZF-008 - Automatic compression

Compress source archives, release bundles, logs, and evidence with a bounded profile. Decompression is transparent to deployment.

### ZF-009 - No-op promotion detection

If the requested artifact is already active with the same service contract and route digest, return a verified no-op rather than restarting it.

### ZF-010 - Preflight size prediction

Estimate source, cache, extraction, evidence, and rollback-space needs before staging. Reject safely before partial allocation.

## 3. Process and slot upgrades

### ZF-011 - Stable blue/green slot names

Use stable `blue` and `green` slot identities while release digests remain immutable. Operators never manage slot names manually.

### ZF-012 - Private inactive endpoint

Start the inactive release on a private Unix socket when supported, with loopback TCP fallback when the application cannot use Unix sockets. The choice is automatic and recorded.

### ZF-013 - Readiness adapter

Use native `sd_notify` when available. Otherwise use a small supervisor that combines process identity and the declared readiness probe before reporting ready. Applications do not need to be rewritten for baseline adoption.

### ZF-014 - Service watchdog adapter

Use a native systemd watchdog when supported; otherwise use bounded external health observation. Native support is discovered rather than required.

### ZF-015 - Per-slot runtime directories

Create runtime directories through systemd and remove them only after verified stop. Applications receive a stable path without manually creating it.

### ZF-016 - Automatic unit generation

Generate deterministic systemd unit/drop-in content from the service manifest and release identity. The generated unit is validated before daemon reload.

### ZF-017 - Immutable release directory permissions

After staging, make release content non-writable to the service identity. Writable state is redirected to declared state/cache/runtime directories.

### ZF-018 - Compatibility launch wrapper

Provide a minimal launcher that maps release paths, non-secret configuration, and systemd credential files into the existing application invocation. This removes the need for immediate application changes.

## 4. Routing and availability upgrades

### ZF-019 - Caddy configuration pre-validation

Adapt and validate the candidate Caddy configuration before calling the live API.

### ZF-020 - API-based zero-downtime reload

Apply the complete intended Caddy configuration through its blocking `/load` API. On load failure Caddy retains the prior configuration.

### ZF-021 - Local-only Caddy administration

Use a permissioned Unix admin socket where supported; otherwise retain a loopback-only endpoint with process isolation. No internet-facing admin listener is introduced.

### ZF-022 - Caddy configuration autosave and resume

Retain the last working live configuration so Caddy can resume it after restart. This is automatic and does not alter application code.

### ZF-023 - Stream-aware reload settings

Set a bounded `stream_close_delay` and low-latency SSE behavior so a config reload does not immediately terminate WebSockets or event streams.

### ZF-024 - Bounded application drain

After cutover, stop new routing to the prior slot, request application drain when a drain endpoint exists, and otherwise wait for observed connection/process quiescence up to a policy limit.

### ZF-025 - Readback after route change

Query Caddy's active configuration and issue an internal probe through the public route after cutover. API success without readback is insufficient.

### ZF-026 - Automatic prior-route restoration

If cutover validation fails, load the previously recorded configuration digest immediately and verify it.

### ZF-027 - Observation-window rollback guard

Keep the old slot installed and startable until the new release survives a configured observation window.

### ZF-028 - Rollback hysteresis

Use minimum sample counts, consecutive failures, cooldowns, and a one-way transaction latch to prevent route flapping.

## 5. Durable recovery upgrades

### ZF-029 - Idempotency keys on every mutation

Every create, build, stage, start, cutover, rollback, drain, and cleanup action has a stable idempotency identity.

### ZF-030 - Exact child-job adoption

Restart recovery reconnects only to persisted durable job IDs and exact process identities.

### ZF-031 - Durable intent before side effect

Persist operation, sequence, request digest, desired state, and child identity before starting the external action.

### ZF-032 - Pending-mutation recovery

Use atomic records plus recoverable pending intent so a crash between event and record writes can be reconciled.

### ZF-033 - Hash-chained event timeline

Every lifecycle event links to the previous event digest, making missing or reordered evidence detectable.

### ZF-034 - Derived-index rebuild

Owner, state, service, release, slot, and idempotency indexes can be rebuilt from authoritative records without rewriting them.

### ZF-035 - Read-only live-state projection

Provide one operation that reports repository, commit, artifact, slot, unit, process, socket, route, health, and rollback target without mutating state.

### ZF-036 - Automatic drift reconciliation

Compare desired and observed unit, process, endpoint, route, release, and artifact truth. Repair only exact owned state; defer ambiguity.

### ZF-037 - Positive cleanup verification

Verify unit inactive/absent, process absent, socket absent, runtime path absent, and transient resources absent before terminal cleanup success.

### ZF-038 - Evidence-preserving failure retention

When cleanup cannot be proven, preserve the failed slot and evidence under bounded retention rather than deleting uncertain state.

## 6. Resource and storage upgrades

### ZF-039 - Production-priority systemd slices

Place active production, release control, and background build/certification into separate cgroup v2 slices with production-favoring CPU and I/O weights.

### ZF-040 - Pressure-aware concurrency

Read Linux PSI, available memory, load, and I/O pressure before admitting or expanding background work. Concurrency changes automatically.

### ZF-041 - Memory high-water throttling

Use `MemoryHigh` for background slices and a hard `MemoryMax` as the final boundary. This protects production without application changes.

### ZF-042 - Bounded job outputs

Cap time, tasks, memory, CPU, output, artifact, and disk growth for every build, test, extraction, and validation job.

### ZF-043 - Root and ZFS watermarks

Admission control accounts for the ext4 root and `babycert` pool independently. Crossing a hard watermark blocks new staging before service impact.

### ZF-044 - Automatic cache eviction by reachability

Evict only unreferenced cache entries in least-recently-used order, never active, prior, pinned, or evidence-referenced objects.

### ZF-045 - Separate retention classes

Apply distinct policies to active releases, rollback releases, failed releases, previews, source archives, caches, logs, and evidence.

### ZF-046 - Clone-or-extract selection

Use ZFS clones when the source and target layout support them; otherwise extract the immutable artifact to an ordinary release directory. Selection is automatic.

## 7. Credentials and GitHub upgrades

### ZF-047 - Systemd credential delivery

Keep secrets outside artifacts and load them into a service-scoped credential directory. A compatibility launcher can map credentials to legacy environment names only inside the target process.

### ZF-048 - Slot-scoped secret rotation

Stage new credentials with the inactive slot, validate them privately, and cut them over with the release.

### ZF-049 - Short-lived GitHub App tokens

Mint installation tokens only when an API call is needed and never treat token length or format as fixed.

### ZF-050 - Webhook delivery de-duplication

Persist GitHub delivery GUID, event type, repository, installation, payload digest, and processing result. Redelivery becomes a no-op.

### ZF-051 - Constant-time webhook signature verification

Verify the raw request body with `X-Hub-Signature-256` before parsing or enqueueing.

### ZF-052 - GitHub outbox

Persist outbound deployment/check status updates locally and retry them independently. GitHub unavailability never corrupts local deployment truth.

### ZF-053 - Polling fallback

If webhooks are unavailable, poll configured repositories with the same event-normalization and idempotency path. No public endpoint is required for fallback operation.

### ZF-054 - Automatic GitHub deployment timeline

Map local durable states to GitHub deployment statuses and evidence URLs without requiring a workflow file.

## 8. Operability upgrades

### ZF-055 - One-command promotion

Expose a single promotion operation that computes or reuses every intermediate stage.

### ZF-056 - Phone-friendly status and approval

Keep request and status payloads compact enough for the Baby tool surface. No terminal is needed.

### ZF-057 - Automatic failure classification

Return stable codes for source, build, certification, staging, startup, readiness, cutover, observation, drain, rollback, cleanup, capacity, credential, and provider failures.

### ZF-058 - Automatic evidence bundle

Produce a final evidence index with all records, job IDs, artifact digests, route digests, probes, process identities, and cleanup proof.

### ZF-059 - Capability report

Expose a read-only report for systemd, Caddy, ZFS, GitHub, credential, provider-backup, Livepatch, soft-reboot, and application-contract capabilities.

### ZF-060 - Dry-run plan

Produce the exact normalized release plan, expected cache hits, slot choice, resource estimate, route change, and retention effects without side effects.

## 9. Deliberately excluded from the zero-friction list

The following may be valuable but are not zero-friction on this host and MUST remain separately approved or capability-gated:

1. Attaching an Ubuntu Pro subscription.
2. Enabling Canonical Livepatch when not already entitled and attached.
3. A full host reboot or kexec.
4. Repartitioning or converting the ext4 root to ZFS.
5. Enabling ZFS block deduplication.
6. Adding a second VPS.
7. Requiring every application to implement `sd_notify` immediately.
8. Mandatory database down-migrations.
9. Opening a new public webhook or control port outside Caddy.
10. Replacing Caddy, systemd, Ubuntu, or Baby-X.
11. Requiring GitHub Actions.
12. Enabling automatic high-impact package upgrades.
13. Adding unbounded swap or changing kernel memory policy.
14. Canary or shadow routing before service-specific data and privacy rules exist.
15. Provider snapshots until a supported authenticated provider API and retention contract are configured.
