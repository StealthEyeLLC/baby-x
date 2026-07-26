# Authorized Implementation Prompt

Copy the text below into the implementation session as the controlling mission.

---

## 1. AUTHORIZATION AND EXECUTION MODE

You are fully authorized by the owner of StealthEye LLC to implement, verify, certify, checkpoint, and—only after every pre-production gate passes—perform the controlled production migration of the Baby-X Self-Reconciling Release Appliance v1 on the existing authorized VPS.

This is an execution mission, not a planning exercise. Continue autonomously through the complete sequence. Do not stop for ordinary design choices, intermediate confirmations, or routine permission. Make conservative evidence-backed decisions from the controlling documents and preserve remote checkpoints continuously.

This prompt is the owner's explicit authorization for Checkpoint L production migration once every prerequisite and hard gate in the controlling package has passed. It is not authorization to bypass a failed gate, destroy ambiguous resources, weaken authority boundaries, or fabricate success.

If a true hard stop occurs, preserve all work, push the latest safe checkpoint, record exact evidence, and report the blocker. Hard stops are limited to matters such as a frozen-base mismatch, inaccessible authoritative repository, unresolved production identity conflict, missing healthy rollback target, capacity below the mandatory floor, unverified Caddy/systemd behavior that would make cutover unsafe, secret exposure risk, or an external dependency that has no safe fallback.

## 2. CONTROLLING REPOSITORY AND BRANCH

1. Repository: `StealthEyeLLC/baby-x`.
2. Implementation branch: `build/baby-x-self-reconciling-release-appliance-v1`.
3. Expected ancestry base: `b8dcc150ddc175b2ad00099df405b8a3bf0e843a`.
4. Expected base tree: `2045a746e0c6d928cf3354fd0ef9544918fbf514`.
5. Base branch: `build/baby-x-god-mode-v1`.
6. Isolated workspace: `/var/lib/baby-quirt/workspaces/baby-x-self-reconciling-release-appliance-v1/baby-x`.
7. The V2 transactional-tool-fabric branch is not an implementation dependency and must not be used as the base.
8. Do not merge, cherry-pick the V2 line wholesale, rewrite history, force push, or replace the branch.
9. Preserve the frozen God Mode v1 branch and evidence unchanged.
10. Verify local and remote branch, HEAD, tree, ancestry, upstream, ahead/behind state, and clean worktree before editing.

## 3. CONTROLLING DOCUMENTS

Read every file under:

`docs/self-reconciling-release-appliance-v1/`

Read them completely before implementation. Treat them as one normative package in this order:

1. `README.md`.
2. `00-FROZEN-BASELINE-AND-MISSION.md`.
3. `01-ZERO-FRICTION-UPGRADES.md`.
4. `02-TARGET-HOST-AND-CONSTRAINTS.md`.
5. `03-AUTHORITY-ARCHITECTURE.md`.
6. `04-DURABLE-MODEL-AND-STATE-MACHINES.md`.
7. `05-BUILD-ARTIFACT-CACHE-AND-CERTIFICATION.md`.
8. `06-BLUE-GREEN-CUTOVER-DRAIN-AND-ROLLBACK.md`.
9. `07-RECONCILIATION-RECOVERY-AND-CLEANUP.md`.
10. `08-RESOURCE-STORAGE-AND-RETENTION.md`.
11. `09-GITHUB-SECRETS-AND-ACCESS.md`.
12. `10-HOST-MAINTENANCE.md`.
13. `11-SECURITY-THREAT-MODEL.md`.
14. `12-OPERATIONS-API-AND-OPERATOR-UX.md`.
15. `13-IMPLEMENTATION-PLAN-AND-ACCEPTANCE.md`.
16. `14-REQUIREMENTS-TRACEABILITY.md`.
17. `15-POST-UPGRADE-CAPABILITIES.md`.
18. `17-RESEARCH-SOURCES.md`.

When documents appear to conflict, apply this priority:

1. Frozen identities and absolute prohibitions.
2. Safety, authority, truth, and cleanup invariants.
3. Requirements traceability R-001 through R-095.
4. Detailed subsystem specifications.
5. Suggested implementation details and default thresholds.

Do not silently weaken a requirement. Record and justify any necessary compatibility adjustment while preserving the intended invariant.

## 4. TARGET HOST

The exact target is the existing authorized single VPS, not a new machine:

1. 6 vCores.
2. approximately 12 GB plan memory and approximately 11 GiB live usable memory.
3. 100 GB NVMe-class disk.
4. Ubuntu 24.04 LTS.
5. systemd 255.
6. Caddy 2.6.2 at design time; re-observe before implementation and cutover.
7. OpenZFS 2.2.2 with the `babycert` pool at design time; re-observe before work.
8. ext4 root filesystem.
9. no swap at design time.
10. provider plan advertises daily backup, unlimited traffic, and 2 Gbps public bandwidth; treat these as configured owner facts until provider API proof exists.

Re-inventory all versions, capacity, pressure, listeners, active services, Caddy config, ZFS health, protected snapshot identity, Livepatch state, reboot requirement, and production process identity before depending on them.

## 5. TOOLING AND ACCESS RULES

1. Use Baby for host and repository work.
2. Use the GitHub connector for remote verification, branch/PR state, and repository metadata when useful.
3. Do not use Termius.
4. Do not request manual SSH.
5. Do not use a browser terminal.
6. Do not use Codex as an alternate executor.
7. Do not use GitHub Actions as the implementation or deployment authority.
8. Do not create or rent another VPS.
9. Do not ask the owner to download, upload, or manually move build artifacts.
10. Use durable Baby jobs for execution and retain their terminal truth.
11. Use the repository-pinned Node runtime. At design time the required binary root is `/opt/node-v24.18.0-linux-x64/bin`; verify the build's pin before every gate.
12. Never expose a private key, token, credential value, webhook secret, or production `.env` content in chat, logs, records, commits, artifacts, or receipts.

## 6. ABSOLUTE ARCHITECTURAL REQUIREMENTS

1. Production must receive completed immutable artifacts; it must not build from source.
2. Release activation authority must remain separate from build and certification authority.
3. The existing Baby-X durable job authority remains the sole child-process authority.
4. The existing disposable-machine authority remains the sole ZFS/nspawn lifecycle authority for disposable work.
5. The artifact/proof/gateway authorities must be reused or compatibly extended, not duplicated.
6. Caddy remains the only internet-facing application ingress.
7. Application slots bind private Unix sockets where compatible, with loopback-only fallback.
8. No public deployment-control port may be introduced.
9. Every mutation is strict, owner-bound, idempotent, request-digest-bound, and sequence-checked.
10. Durable intent must precede every external side effect.
11. Exit code zero is never sufficient proof of source, artifact, start, readiness, cutover, rollback, drain, or cleanup success.
12. Exact unit, process, endpoint, route, artifact, job, and credential-set identities must be read back.
13. Unknown or conflicting identity becomes `UNKNOWN`, `RECOVERY_REQUIRED`, or `AMBIGUOUS`, never guessed success.
14. Destructive cleanup is prohibited while ownership is ambiguous.
15. Terminal cleanup requires positive absence of every required resource.
16. Rollback selects a prior immutable release and route; it never rewrites source history.
17. The previous known-good release remains available through the observation/rollback window.
18. GitHub is an event/reporting surface, not local deployment truth or production authority.
19. Secrets remain outside source and immutable artifacts.
20. Host maintenance is a separate authority and state machine from application release deployment.
21. Root ext4 and `babycert` ZFS capacity are separate admission budgets.
22. ZFS block deduplication must not be enabled.
23. Canary, shadow, header/identity preview, and per-commit preview are typed v1 capabilities, disabled per service until a safe policy contract exists.
24. Single-node limits must remain explicit; do not claim host high availability or zero-downtime kernel reboot.
25. All R-001 through R-095 must be accounted for in the final report.

## 7. FROZEN PRE-IMPLEMENTATION VERIFICATION

Before changing code:

1. Call Baby describe and inspect the available operation catalog.
2. Verify repository remote URL.
3. Verify current branch is exactly the implementation branch.
4. Verify HEAD/tree and ancestry from the frozen v1 base.
5. Verify upstream and ahead/behind state.
6. Verify clean worktree.
7. Verify no tracked private keys, tokens, `.env` secrets, or production credentials.
8. Verify required Node/npm and all build tools.
9. Run the complete baseline build, lint, test, shell, and native-helper gates.
10. Record baseline operation count and test count.
11. Re-inventory host compute, memory, PSI, filesystems, inodes, ZFS pool, versions, listeners, Caddy admin exposure, active units, sockets, production process identity, and reboot/Livepatch state.
12. Verify the protected God Mode source snapshot and absence of unintended disposable resources.
13. Push a documentation/baseline checkpoint if the branch head is not already remote.
14. Stop immediately on any frozen identity mismatch.

## 8. IMPLEMENTATION SEQUENCE

Implement the checkpoints in `13-IMPLEMENTATION-PLAN-AND-ACCEPTANCE.md` in order. Do not skip foundational durability to reach cutover faster.

### Checkpoint A - Compatibility and strict schemas

Implement frozen compatibility metadata; strict schemas for services, source, builds, artifacts, certification, releases, slots, routes, deployments, observations, evidence, GitHub inbox/outbox, capacity, leases, events, pending mutations, and maintenance; deterministic canonicalization; redaction; transitions; terminal predicates; read-only describe/capabilities operations.

### Checkpoint B - Durable stores and recovery

Implement atomic authoritative records, pending mutation recovery, hash-chained events, derived indexes, idempotency indexes, per-deployment and per-route leases, corruption isolation, bounded startup repair, and exact sequence enforcement.

### Checkpoint C - Source, cache, build, artifact, and capacity pipeline

Implement exact source resolution/archive, source manifest, normalized build profiles, dependency/build caches, deterministic compressed release artifact, manifest verification, safe extraction, immutable materialization, quarantine, byte estimation, durable reservations, and no-op/content-reuse paths.

### Checkpoint D - Release certification

Integrate exact artifact certification in disposable machines, including startup, readiness, smoke, migration preflight, worker behavior, security, resources, streams, cleanup, source preservation, evidence, reuse identity, and invalidation.

### Checkpoint E - Durable blue/green slot runtime

Implement service definitions, deterministic systemd units/drop-ins, installed-version verification, service users, private endpoints, readiness adapters, native notify/watchdog support where available, compatibility launcher, cgroup slices, exact process/endpoint adoption, drain/stop, and positive absence.

### Checkpoint F - Caddy route authority

Implement trusted route generation, current-config capture, installed-Caddy adapt/validate, local admin client, full-config load, active-config readback, route probes, prior-config restoration, WebSocket/SSE stream policy, canary, shadow, header/identity preview, and expiring preview routes.

### Checkpoint G - Release coordinator

Implement prepare, promote, approve, schedule, cancel, rollback, reconcile, resume, expire, GC, status, live-state projection, events, evidence, cutover, observation, rollback hysteresis, drain, cleanup, grouped services, migrations, previews, and failure classification.

### Checkpoint H - Resource governor and retention

Implement cgroup priorities, PSI decisions, dynamic concurrency, ext4/ZFS admission, reservations, cache/reference accounting, retention classes, LRU eviction, journal/evidence bounds, and dry-run-first GC.

### Checkpoint I - Credentials and GitHub

Implement systemd credential references/encrypted credential support, legacy compatibility launcher, inactive-slot rotation, GitHub App token minting, raw-body webhook HMAC verification, delivery de-duplication, polling fallback, approval normalization, durable outbox, deployment/check status reporting, and outage recovery.

### Checkpoint J - Separate host maintenance authority

Implement read-only inventory, package simulation/classification, maintenance records, disposable verification, snapshot/provider capability, controlled package updates, reboot-required/Livepatch/soft-reboot truth, scheduled maintenance, post-update certification, and recovery-required behavior. Do not perform an actual reboot in ordinary tests.

### Checkpoint K - Full disposable integrated certification

Certify the entire topology with Caddy, old/new slots, controller, durable state, traffic generator, WebSocket/SSE, worker, multi-service group, migration fixture, canary, shadow, preview, GitHub mock/test integration, credentials, pressure, failures, restart, response loss, rollback, and cleanup.

### Checkpoint L - Controlled production migration

This prompt authorizes Checkpoint L only after all earlier checkpoints pass and are remotely preserved. Perform the exact migration protocol in the controlling document:

1. Capture current production truth and manual runbook.
2. Construct and certify an immutable rollback release for what is currently live.
3. Preserve current Caddy configuration.
4. Verify capacity floors and provider recovery path.
5. Import current production as the initial known-good blue slot without changing its behavior unexpectedly.
6. Stage an equivalent green release privately.
7. Run continuous traffic and stream fixtures.
8. Cut over atomically and verify no failed requests under the declared envelope.
9. Deliberately roll back and prove restoration.
10. Promote again and complete observation.
11. Drain and clean the old slot with positive absence.
12. Verify `babyx.release.live`, GitHub status, receipts, evidence, and rollback readiness.
13. Preserve an emergency fallback until final owner-visible acceptance evidence is complete.
14. Never proceed with cutover if the active service or rollback identity is ambiguous.

## 9. ZERO-FRICTION UPGRADES

Implement all ZF-001 through ZF-060 from `01-ZERO-FRICTION-UPGRADES.md`. They are part of the build, not optional suggestions. Preserve their admission rule:

1. no additional normal operator step.
2. no baseline application rewrite.
3. no new public port.
4. no new paid dependency.
5. no planned production outage.
6. reversible selection/configuration.
7. capability detection.
8. safe fallback.
9. no evidence reduction.
10. no authority leakage.

Do not quietly include excluded non-zero-friction changes such as attaching Ubuntu Pro, enabling Livepatch without entitlement, converting the root filesystem, enabling ZFS dedup, adding a second VPS, or automatically applying a full reboot.

## 10. TEST AND ADVERSARIAL REQUIREMENTS

At minimum, test:

1. deterministic schemas, manifests, plans, events, and digests.
2. unknown fields and newer schema rejection.
3. exact idempotent replay and conflicting reuse.
4. wrong owner and stale sequence.
5. atomic-write interruption and pending recovery.
6. corrupt record isolation and index repair.
7. live lease overlap and proven stale takeover.
8. cache hit, miss, corruption, poisoning, and identity mismatch.
9. archive traversal, symlink escape, special files, expansion bombs, and secret paths.
10. build/certification failure separation.
11. private inactive slot and no premature exposure.
12. process PID/start-time/executable/boot/cgroup/unit conflicts.
13. endpoint/socket conflicts.
14. alive-but-not-ready candidates.
15. Caddy validation/load/readback and unknown-config ambiguity.
16. HTTP keep-alive, WebSocket, SSE, worker, and scheduler drain.
17. continuous traffic across both direction cutovers.
18. defective release and every automatic rollback trigger.
19. rollback hysteresis and no route flapping.
20. response loss after every external side effect.
21. controller restart in every lifecycle phase.
22. active related jobs blocking terminal success.
23. positive cleanup and obstruction recovery.
24. root/ZFS capacity floors, reservations, inode limits, and overcommit prevention.
25. production CPU/I/O/memory priority under background load.
26. PSI-based concurrency reduction and emergency rollback admission.
27. GitHub signature, delivery replay/conflict, polling convergence, token expiry/format, outage, and outbox retry.
28. credential absence from records/artifacts/logs/arguments and successful/failed rotation.
29. no public deployment listener and no application access to Caddy admin.
30. canary stickiness/threshold rollback.
31. shadow response isolation and side-effect policy.
32. preview authentication, expiration, route removal, machine cleanup, and absence.
33. ordered multi-service deployment and rollback.
34. expand/migrate/contract and irreversible migration gating.
35. self-hosting upgrade rehearsal.
36. signed final evidence mutation detection.
37. all R-001 through R-095 traceability outcomes.

## 11. RESOURCE AND CAPACITY DEFAULTS

Use the controlling defaults unless measurement justifies a safer stricter value:

1. Root warning below 20 GiB or 20 percent free.
2. Root background throttle below 15 GiB free.
3. Reject staging when projected root free falls below 12 GiB.
4. Emergency root floor at 8 GiB.
5. ZFS warning below 3 GiB or 25 percent free.
6. Reject disposable clone when projected ZFS free falls below 2 GiB.
7. Preserve at least 2 GiB available memory before heavyweight admission.
8. Default to one heavyweight build/certification.
9. Allow up to four background workers only when health and PSI are green.
10. Keep production at the highest cgroup CPU/I/O weight.
11. Never evict active, rollback, pinned, nonterminal-referenced, evidence-required, ambiguous, or corrupt objects automatically.

Recompute capacity immediately before every materialization and use durable reservations.

## 12. GIT AND CHECKPOINT DISCIPLINE

1. Keep the worktree clean between checkpoints.
2. Make coherent full-file edits.
3. Run checkpoint-specific tests before commit.
4. Run the complete gate before major milestones.
5. Commit with clear messages recommended by the implementation plan.
6. Push each stable checkpoint fast-forward to the implementation branch.
7. Verify remote commit and tree after every push.
8. Never force push.
9. Never merge without an explicit separate merge instruction.
10. Create or update a draft pull request only after the branch has a reviewable stable implementation; do not mark ready or merge unless explicitly instructed.
11. Record exact commit/tree identities and test results in evidence documents.
12. Do not leave untracked host scripts as implementation authority; place durable code in the repository.

## 13. QUALITY GATE

For every final or production-relevant checkpoint:

1. Use the pinned Node/toolchain.
2. Build passes.
3. Strict lint passes.
4. Unit, integration, acceptance, recovery, adversarial, traffic, and security tests pass.
5. Shell scripts pass syntax and static checks.
6. Native helpers compile and test.
7. Git diff check passes.
8. No tracked secret/private key/token/credential/production `.env` exists.
9. No duplicate scheduler, job, machine, artifact, route, proof, or release authority exists.
10. All related durable jobs are terminal.
11. Temporary machines, processes, sockets, paths, mounts, and datasets are positively absent.
12. Protected God Mode baseline is unchanged.
13. Branch is clean, synchronized, and remotely verified.
14. Evidence artifacts and signed receipts verify.
15. Final live route, slot, release, artifact, source, process, endpoint, health, and rollback target agree.

## 14. FINAL DELIVERABLES

Produce and push:

1. complete implementation.
2. strict schemas and compatibility manifest.
3. service/release examples and safe fixtures.
4. unit, integration, recovery, adversarial, traffic, pressure, security, and production acceptance tests.
5. operational systemd/Caddy templates and compatibility adapters.
6. migration and rollback runbook generated from durable operations, not manual commands.
7. capability and host inventory report.
8. authority-boundary audit.
9. performance/cache/capacity results.
10. zero-downtime acceptance evidence.
11. rollback acceptance evidence.
12. restart/response-loss evidence.
13. GitHub and credential security evidence.
14. cleanup/positive-absence evidence.
15. R-001 through R-095 completion ledger.
16. final production-readiness and residual-limit report.
17. exact branch, commits, trees, remote verification, and draft PR state.

## 15. FINAL RESPONSE

When the mission is complete, report:

1. exact final branch, HEAD, tree, parent, upstream, and ahead/behind state.
2. all checkpoint commits/trees.
3. tests and counts.
4. exact production live release, commit, tree, artifact, slot, unit, process, endpoint, Caddy config digest, health, and rollback target.
5. zero-downtime and rollback acceptance results.
6. GitHub reporting state.
7. capacity and retention state.
8. every unresolved limitation or disabled capability.
9. R-001 through R-095 status.
10. confirmation that God Mode v1 remained unchanged and V2 was not used.

Do the work. Do not merely describe how it could be done.

---
