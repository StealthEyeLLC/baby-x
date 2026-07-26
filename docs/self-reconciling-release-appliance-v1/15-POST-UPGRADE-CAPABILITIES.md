# Post-Upgrade Capabilities

## 1. Completion boundary

The following inventory describes what is available **after implementation, disposable certification, controlled production migration, and final acceptance pass**. This documentation checkpoint alone does not claim that these runtime capabilities are already installed.

## 2. Delivered capabilities

1. One durable promotion operation from exact source or certified artifact to final evidence.
2. Warm-path deployments that reuse exact verified dependencies, build output, artifacts, and certifications.
3. Production release slots that never run source checkout, dependency installation, compilation, or packaging.
4. Normal deployment and rollback without SSH, terminal commands, Caddy edits, or manual file copying.
5. GitHub push, tag, release, deployment, and approval event ingestion through verified durable inbox records.
6. Exact idempotent convergence for repeated deployment requests.
7. Build and certification preparation while the current production slot continues serving.
8. Private prewarming and readiness of the inactive slot.
9. Lockfile/runtime/base-snapshot dependency-cache restoration.
10. Content-addressed artifact and source reuse with one canonical object per digest.
11. Stable blue and green slots for every routable service.
12. Validated atomic Caddy route switching with active-config readback.
13. Atomic release materialization with no half-written production tree.
14. Graceful draining for HTTP keep-alive, WebSockets, SSE, workers, and schedulers.
15. Exposure only after exact unit, process, endpoint, and readiness proof.
16. Promotion blocked by dependency, schema, credential, startup, migration, readiness, or smoke-test failure.
17. Rollback by selecting a prior immutable release rather than rebuilding.
18. Automatic rollback from hard failures and bounded threshold policies.
19. No Git history mutation as a rollback mechanism.
20. Provisional observation windows with persistent samples and minimum evidence.
21. Crash-safe durable deployment records and pending mutation recovery.
22. Response-loss recovery by readback instead of blind replay.
23. Restart recovery for controller, jobs, slots, routes, and GitHub reporting.
24. Adoption of only exact persisted child jobs and process identities.
25. Unknown and lost truth that can never be relabeled successful.
26. Continuous desired-versus-observed reconciliation.
27. Automatic repair of exact owned drift.
28. Non-destructive AMBIGUOUS handling for conflicting ownership.
29. Positive cleanup proof for units, processes, endpoints, paths, jobs, mounts, and datasets.
30. Protected previous known-good rollback release.
31. Pressure-safe use of all six CPUs when idle.
32. Production-first CPU weighting.
33. Production-first NVMe I/O weighting.
34. MemoryHigh, MemoryMax, available-memory floors, and PSI backpressure.
35. Dynamic concurrency that shrinks during traffic or pressure.
36. Hard resource and output bounds on every background step.
37. Fast ZFS disposable build and certification environments.
38. Deterministic compression and logical deduplication without ZFS block dedup.
39. Independent retention classes for releases, previews, caches, logs, records, and evidence.
40. Preflight ext4 and ZFS capacity admission with durable reservations.
41. Livepatch capability reporting and integration when Ubuntu Pro is enabled.
42. Governed low-, medium-, and high-impact package update paths.
43. Explicit reboot-required and running-kernel truth.
44. Rehearsable systemd userspace soft-reboot path with truthful limitations.
45. Applicable ZFS and provider checkpoint integration before risky maintenance.
46. Full post-maintenance platform and application certification.
47. Scheduled maintenance plans with drain, update, restart/reboot, and verification.
48. Artifact rejection for .env and secret-bearing files.
49. Encrypted, service-scoped systemd credentials.
50. Inactive-slot credential rotation and private validation.
51. Less secret exposure in process environments and no secret persistence in deployment records.
52. On-demand, one-hour-class GitHub App installation credentials without fixed-format assumptions.
53. No new public deployment control listener.
54. Caddy-only public application ingress with private service endpoints.
55. Exact repository/commit/tree/lockfile/build/artifact binding to production.
56. Exact artifact/release/unit/cgroup/process/endpoint binding.
57. Signed receipts for all mutations.
58. Hash-chained complete deployment timelines.
59. Continuous-traffic zero-downtime acceptance evidence.
60. Defective-release rollback acceptance evidence.
61. Provable process and runtime-resource absence.
62. One audit trail for manual, automatic, scheduled, and GitHub actions.
63. One authoritative answer to what is live.
64. GitHub-visible deployment state and history.
65. One normal promotion action.
66. Phone-friendly plan, approve, promote, rollback, status, and live operations.
67. Stable and distinct failure classifications.
68. Automatic collection of logs, probes, identities, configs, metrics, and cleanup proof.
69. Durable progress independent of a chat, shell, or UI lifetime.
70. No unowned deployment-related mystery process.
71. Safe private and disposable experimentation.
72. Exact failed-environment reproduction.
73. One compact status answer.
74. One durable rollback answer.
75. Independent release slots for web, API, worker, scheduler, and internal services.
76. Ordered multi-service staging and cutover groups.
77. Typed expand/migrate/contract database workflows.
78. Bounded policy-gated canary routing on one VPS.
79. Service-approved side-effect-safe shadow traffic.
80. Header- and identity-gated preview routing.
81. Expiring per-commit disposable preview environments.
82. Scheduled promotion after early preparation.
83. Exact approval-gated promotion.
84. Strict low-risk automatic promotion with safe fallback to approval.
85. A reusable release platform across StealthEye services.
86. Hard separation between build/certification and production release authority.
87. Deployment as a durable transaction with sequence, lease, events, recovery, and evidence.
88. Immutable release behavior on the existing Ubuntu host.
89. A provider contract for future Portable Service or mkosi images.
90. A toolchain contract for future Nix-backed builds.
91. Host-scoped records ready for a future second node.
92. An honest foundation for future active/passive availability.
93. Artifact and desired-state identities ready for future regions.
94. Host-separated state ready for bounded future fleet reconciliation.
95. A safe self-hosting upgrade path in which Baby-X certifies but independent Release Authority activates.
96. An exact read-only dry-run showing source, cache hits, capacity, slot, route, observation, and retention effects.
97. Live capability discovery for systemd, Caddy, ZFS, credentials, GitHub, backups, Livepatch, and reboot paths.
98. Automatic no-op detection when the requested digest and service contract are already live.
99. Byte reservations that prevent concurrent deployments from overcommitting disk.
100. Quarantine of corrupt caches, artifacts, releases, or conflicting digest paths.
101. A durable GitHub outbox that never makes GitHub availability part of local deployment truth.
102. Webhook GUID de-duplication and conflict detection.
103. GitHub polling fallback that converges with webhook events.
104. Credential-only blue/green promotion without changing application bytes.
105. Deterministic systemd unit/drop-in generation and installed-version validation.
106. A local-only Caddy admin boundary with a Unix-socket option when installed-version support is proven.
107. Caddy autosave/resume plus saved previous-config artifacts.
108. Rollback hysteresis, minimum samples, cooldowns, and one-way failure latches.
109. Hash-chained release events whose missing or reordered history is detectable.
110. Derived-index verification and repair without rewriting authoritative records.
111. Bounded, dry-run-first, reference-aware garbage collection.
112. Immutable artifact and release-path collision detection.
113. Separate systemd slices for production, control, builds, certification, previews, and audit.
114. A PSI-based governor that prioritizes rollback and route safety over optional work.
115. Readiness tied to exact release and endpoint identity rather than generic HTTP success.
116. Route readback and public release-identity probing after every Caddy change.
117. Separate ext4-root and ZFS-pool capacity budgets.
118. Host-maintenance reports that state ext4, single-node reboot, Livepatch, and provider limits honestly.
119. Clear separation between owner-supplied VPS-plan facts and host-observed runtime facts.
120. A frozen compatibility report with explicit supported schema/provider versions.
121. Reproducibility classifications that distinguish byte-identical, manifest-equivalent, and not-proven builds.
122. Optional artifact-bound SBOM and provenance records without granting release authority.
123. Installed-version gates so online documentation cannot silently authorize unsupported Caddy/systemd/ZFS behavior.
124. Emergency route and rollback work that remains admitted even when optional builds are pressure-paused.
125. Final evidence indexes that are independently digest-verifiable.

## 3. Truthful limits that remain

1. This is still one physical VPS; blue/green deployment does not eliminate host, network, or kernel-reboot downtime.
2. Canonical Livepatch remains disabled until the owner attaches an entitled Ubuntu Pro subscription.
3. The ext4 root cannot receive native ZFS snapshots; only the separate ZFS pool can.
4. Provider daily backup is disaster recovery, not live failover, and remains an owner-supplied fact until an API proves it.
5. Database rollback is only as strong as each declared migration contract.
6. Canary and shadow traffic are disabled by default for a service until its data, side-effect, privacy, and session policies permit them.
7. Future multi-node, regional, and fleet capabilities are architectural foundations, not falsely claimed deployed infrastructure.
8. Disk headroom remains finite; the appliance rejects work rather than consuming the final safety reserve.
9. A full kernel reboot still causes an outage until a second serving node exists.
10. Unknown or ambiguous truth may require owner review; the appliance chooses safety over destructive guessing.
