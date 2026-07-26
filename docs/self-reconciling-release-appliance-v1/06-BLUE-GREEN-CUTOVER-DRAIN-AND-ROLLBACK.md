# Blue/Green Cutover, Drain, and Rollback

## 1. Slot model

1. Every routable service has stable `blue` and `green` slot identities.
2. A slot identity is not a release identity.
3. Each slot binds to one exact immutable release at a time.
4. At most one slot is desired active for a given route.
5. The inactive slot can be staged, started, tested, and stopped without changing public traffic.
6. A release may be installed without being bound to a slot.
7. The previous known-good release remains installed through the observation window.

## 2. Endpoint model

### 2.1 Preferred Unix socket

1. Path template: `/run/stealtheye/releases/<service>/<slot>/app.sock`.
2. Parent runtime directory is systemd-managed.
3. Socket permissions grant access only to the service and Caddy identities.
4. The path is slot-specific and cannot collide with the other slot.
5. Stale socket removal requires process and unit absence proof.
6. Caddy upstream uses `unix//absolute/path` syntax supported by the installed version after a compatibility test.

### 2.2 Loopback fallback

1. Bind only `127.0.0.1` or `::1`.
2. Allocate from a service-specific, persisted port range.
3. Verify the listener belongs to the expected unit and process.
4. A port conflict is `AMBIGUOUS`; it is never killed by name alone.
5. No wildcard bind is allowed without an explicit service exception.

## 3. systemd slot unit

A deterministic template or generated drop-in binds:

1. service and slot identity.
2. exact release path.
3. executable and argv.
4. working directory.
5. service user/group.
6. endpoint identity.
7. non-secret environment.
8. credential references.
9. runtime/state/cache/log directories.
10. resource limits and slice.
11. restart policy.
12. readiness mode.
13. watchdog mode.
14. stop signal and timeout.
15. security hardening compatible with the service.
16. release, artifact, and deployment IDs as non-secret unit metadata.

Candidate units MUST pass `systemd-analyze verify` or equivalent installed-version verification before daemon reload.

## 4. Start protocol

1. Persist `STARTING_INACTIVE` intent.
2. Verify the slot is inactive or exactly adoptable.
3. verify release path and manifest digest.
4. verify credential-set availability.
5. verify endpoint path/port is absent or exactly owned.
6. start the exact unit.
7. persist the start job/process reference.
8. read back unit load state, active state, substate, main PID, cgroup, and invocation ID where available.
9. read `/proc` process identity: PID, start time, executable, boot ID, and process group.
10. verify the endpoint belongs to that process/unit.
11. run readiness probes until success or bounded timeout.
12. persist `READY_PRIVATE` only after all checks pass.

A unit being `active` is not readiness.

## 5. Readiness protocol

Readiness combines:

1. exact unit identity.
2. exact process identity.
3. no restart loop.
4. expected endpoint listening.
5. native `sd_notify` readiness when available.
6. declared HTTP, Unix-socket, command, or protocol probe.
7. dependency compatibility checks.
8. release identity response when the service exposes it.
9. required files and credentials present.
10. optional migration preflight.
11. bounded consecutive successes.

Readiness failure never changes the public route.

## 6. Caddy configuration model

1. The full intended application configuration is rendered deterministically from trusted templates and route records.
2. The current live configuration is captured and stored as the rollback configuration artifact.
3. The candidate config is adapted and validated using the installed Caddy binary.
4. The Caddy admin endpoint remains local; a permissioned Unix socket is preferred when verified on installed Caddy, otherwise loopback-only administration remains.
5. Public requests cannot reach the admin endpoint.
6. Configuration changes are loaded through the blocking admin API.
7. A failed load must leave the prior configuration active.
8. Active config is read back and canonically digested after load.
9. A route probe must verify the expected release/slot through the real public route.
10. Route records preserve previous and candidate config artifacts.

## 7. Cutover protocol

1. Acquire the per-service route lease.
2. Reconcile both slots and the current Caddy route.
3. confirm the candidate slot is `READY_PRIVATE`.
4. confirm the prior route is healthy or explicitly record its degraded state.
5. capture current Caddy config and digest.
6. render candidate config pointing new traffic to the candidate endpoint.
7. validate candidate config with installed Caddy.
8. persist `CUTOVER_PREPARING`, all config digests, and rollback target.
9. persist `CUTTING_OVER` before calling Caddy.
10. load candidate config through the local API.
11. persist API response digest.
12. read back active config.
13. verify route points to the intended slot only, except during an explicit canary policy.
14. issue private and public probes.
15. persist cutover observation digest.
16. mark the new slot `ACTIVE` and previous slot `DRAINING` only after route readback.
17. enter the observation window.

## 8. Continuous traffic acceptance

The acceptance harness MUST:

1. send requests before, during, and after cutover.
2. include HTTP keep-alive.
3. include concurrent requests.
4. include WebSocket sessions if the service supports them.
5. include SSE or streaming responses if supported.
6. record every status, connection error, latency, response release identity, and timestamp.
7. verify no response came from a half-staged release.
8. verify no failed request attributable to cutover under the declared load envelope.
9. verify the route changed exactly once.
10. preserve the complete request timeline as an artifact.

## 9. WebSocket and stream behavior

Caddy reloads can terminate WebSocket connections unless stream handling is configured. Therefore:

1. Set a bounded Caddy `stream_close_delay` after installed-version verification.
2. Select the delay from service drain policy rather than an unbounded value.
3. Disable response buffering for SSE where required.
4. After cutover, new connections go to the new slot.
5. Existing old-slot connections may remain until completion or the drain deadline.
6. The old process is not stopped while owned active connections are still observed unless the hard deadline or emergency policy applies.
7. Forced termination is recorded separately from graceful drain.

## 10. Observation window

The new route remains provisional for a configured duration and sample count. Observation includes:

1. readiness continuity.
2. liveness.
3. process restarts.
4. HTTP failures and timeouts.
5. latency thresholds.
6. application-specific metrics when available.
7. memory current, `MemoryHigh` events, and OOM events.
8. CPU and I/O pressure.
9. socket continuity.
10. error-log classifiers.
11. public route identity.

Initial policy should be conservative and service-specific. A short smoke window may be followed by a longer rollback-preservation window.

## 11. Automatic rollback triggers

Hard triggers:

1. candidate process exits or enters a restart loop.
2. endpoint disappears.
3. readiness fails for the required consecutive samples.
4. public route returns a configured fatal response.
5. route readback disagrees with desired state.
6. release identity probe returns the wrong artifact.
7. OOM kill or hard memory limit breach.
8. fatal migration or compatibility signal.

Threshold triggers:

1. error-rate threshold with minimum sample count.
2. latency percentile threshold over a window.
3. consecutive timeout threshold.
4. sustained memory or I/O pressure.
5. service-specific metric regression.

Anti-flap controls:

1. minimum sample count.
2. consecutive breach requirement.
3. cooldown.
4. one rollback decision latch per deployment.
5. no automatic re-promotion of the failed release.
6. bounded rollback attempts.
7. owner-visible reason and evidence.

## 12. Rollback protocol

1. Persist `ROLLBACK_REQUESTED` with reason and target.
2. acquire the route lease.
3. verify the prior release and slot record.
4. start or verify the prior slot privately if it was stopped.
5. pass prior-slot readiness.
6. render the prior Caddy route from the saved config or deterministic route record.
7. validate it.
8. persist `ROLLING_BACK` before the load.
9. load prior config.
10. read back active config.
11. run public-route probes and verify prior release identity.
12. mark prior slot active and failed slot inactive/draining.
13. observe the restored route.
14. preserve failed-slot evidence.
15. stop and clean the failed slot only after exact ownership and policy gates.
16. terminalize as `ROLLED_BACK` only after evidence and required cleanup/retention truth.

Rollback never invokes Git reset, branch rewrite, source checkout, or rebuild.

## 13. Drain protocol

Drain modes, selected by service capability:

1. `APPLICATION_ENDPOINT`: call a private authenticated drain endpoint, then observe.
2. `SYSTEMD_SIGNAL`: send a declared signal causing the service to stop accepting new work.
3. `ROUTE_ONLY`: remove from route and wait for observed connections to close.
4. `WORKER_QUIESCE`: stop intake, finish or hand off in-flight work, then stop.
5. `BOUNDED_STOP`: use systemd stop after the configured grace interval.

Drain evidence includes:

1. initiation method and time.
2. route-removal readback.
3. active connection/job count observations where available.
4. process state.
5. completion or timeout.
6. graceful or forced classification.
7. logs and job receipts.

## 14. Database migrations

v1 supports declared expand/migrate/contract workflows:

1. `expand` must be backward-compatible with the old and new release.
2. `migrate` runs as a durable, separately identified job before or after cutover according to contract.
3. `contract` runs only after the rollback window closes and explicit policy permits it.
4. destructive or irreversible migrations require owner approval.
5. automatic rollback may restore application traffic but cannot claim database rollback unless a proven database rollback operation exists.
6. migration identity and evidence bind to the deployment.
7. a service without a declared migration contract cannot request one implicitly.

## 15. Multi-service groups

1. Services may belong to an ordered deployment group.
2. Each service has its own slots and release record.
3. A group plan declares dependency order and compatibility matrix.
4. All candidates may be staged before any route changes.
5. Cutover order is durable and explicit.
6. Failure invokes the declared group rollback strategy.
7. A group cannot claim atomicity beyond what the route and data contracts actually provide.

## 16. Canary, shadow, and preview capabilities

These are real v1 typed capabilities, disabled per service until its policy and safety contract permit them:

1. Canary routing requires an explicit percentage or trusted matcher, bounded duration, maximum request count, rollback threshold, and exact candidate slot.
2. Sticky/session behavior must be declared and tested; a canary cannot silently split a stateful session across incompatible releases.
3. Shadow traffic uses a trusted route adapter that mirrors only service-approved methods, paths, body sizes, and identities; candidate responses are never returned to production clients.
4. Shadow requests must not execute unsafe side effects unless the service implements and certifies a safe shadow mode.
5. Privacy, credentials, data residency, log handling, and replay semantics must be approved in the service definition.
6. Header- or identity-based previews use trusted Caddy matchers, authenticated identities or unforgeable operator headers, and a private candidate endpoint.
7. Per-commit previews run in disposable nspawn machines, bind exact source/artifact identity, use expiring private routes, and clean through canonical machine and route authorities.
8. Preview and canary routes cannot weaken the public Caddy admin boundary or expose a wildcard application listener.
9. v1 acceptance MUST include safe fixture services for canary, shadow, identity-gated preview, and per-commit preview creation, use, expiry, rollback, and positive cleanup.
10. A production service that lacks a safe contract reports the capability as implemented-but-disabled rather than silently attempting it.
