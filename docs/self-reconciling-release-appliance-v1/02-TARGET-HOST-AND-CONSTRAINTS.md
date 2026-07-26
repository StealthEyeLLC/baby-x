# Target Host and Constraints

## 1. Live inventory observed on 2026-07-26

### 1.1 Compute

1. Architecture: x86_64.
2. Hypervisor: KVM/QEMU.
3. CPU model exposed to the guest: Intel Haswell class.
4. Online CPUs: 6, numbered 0 through 5.
5. Threads per core exposed: 1.
6. Usable memory: approximately 11 GiB.
7. Swap: none.

### 1.2 Root storage

1. Device: 100 GB virtual disk.
2. Root partition: approximately 99 GB.
3. Root filesystem: ext4.
4. Mounted root size: approximately 96 GiB.
5. Used at observation: approximately 79 GiB.
6. Free at observation: approximately 17 GiB.
7. Utilization at observation: 83 percent.
8. The root filesystem is not ZFS and cannot receive native ZFS snapshots.

### 1.3 ZFS

1. OpenZFS userland and module: 2.2.2 Ubuntu package level.
2. Pool: `babycert`.
3. Pool size: approximately 11.5 GiB.
4. Allocated at observation: approximately 369 MiB.
5. Free at observation: approximately 11.1 GiB.
6. Health: online.
7. Existing hierarchy includes `babycert/base/noble` and `babycert/runs`.
8. Protected source snapshot identity from the certified baseline remains outside this design's mutation authority.

### 1.4 Operating system and platform

1. Ubuntu 24.04 LTS.
2. Running kernel at observation: `6.8.0-136-generic`.
3. systemd: 255.4 Ubuntu build.
4. `systemctl soft-reboot` is available.
5. `systemctl kexec` is available.
6. `systemd-creds` is available.
7. Caddy: 2.6.2.
8. Ubuntu Pro client is installed but the machine is not attached to a subscription.
9. Livepatch is therefore available as an entitlement capability but not active.
10. No reboot was required at observation.
11. Linux PSI interfaces for CPU, memory, and I/O are present.

### 1.5 Commercial-plan facts supplied by the owner

1. 6 vCores.
2. 12 GB RAM.
3. 100 GB SSD NVMe.
4. Daily backup of the previous 24 hours.
5. Unlimited traffic.
6. 2 Gbps public bandwidth.
7. Listed starting price: $12.32 per month.

These plan claims are recorded as owner-supplied facts. The release appliance MUST distinguish them from host-observed facts unless a provider API later confirms them.

## 2. Capacity consequences

### 2.1 Root disk is the immediate limiting resource

The current root has approximately 17 GiB free. The appliance MUST NOT assume that a nominal 100 GB plan means 100 GB is available for releases. Every promotion must account for:

1. Compressed artifact bytes.
2. Temporary download bytes.
3. Extraction amplification.
4. Inactive slot bytes.
5. Prior rollback slot bytes.
6. Build or dependency cache growth.
7. Logs and evidence.
8. Journal growth.
9. Package-manager temporary files.
10. Safety reserve for the operating system.

Initial root policy:

1. Warning watermark: free space below 20 GiB or 20 percent, whichever is stricter.
2. New-build throttle watermark: free space below 15 GiB.
3. New-stage hard stop: projected post-stage free space below 12 GiB.
4. Emergency hard stop: actual free space below 8 GiB.
5. The active and prior known-good releases are never evicted to satisfy a new request.
6. Evidence referenced by a non-expired record is never evicted.
7. The exact thresholds are configuration and must be reported by `babyx.release.capacity`.

At the observed 17 GiB free state, staging remains possible only for artifacts whose projected footprint preserves the 12 GiB hard floor. The first implementation acceptance must exercise rejection before the floor is crossed.

### 2.2 ZFS pool is a separate budget

Initial `babycert` policy:

1. Warning when free space is below 25 percent or 3 GiB.
2. Hard stop for new disposable clones when projected free space is below 2 GiB.
3. Per-clone quota or refquota must be set.
4. Dataset and snapshot count limits should be configured where supported.
5. Clone cleanup requires dataset absence readback.
6. The protected base snapshot is never included in recursive destroy commands.
7. ZFS block deduplication remains disabled.
8. Compression may be enabled on release-specific datasets after a capability and performance check.

### 2.3 Memory has no swap safety net

Initial policy for an approximately 11 GiB usable-memory host:

1. Preserve at least 2 GiB available memory before starting a new heavyweight background job.
2. Pause new background admission when memory PSI `full` is nonzero over a sustained window.
3. Throttle when memory PSI `some` crosses the configured warning threshold.
4. Use `MemoryHigh` before `MemoryMax` for background slices.
5. Never rely on OOM kill as a normal backpressure mechanism.
6. One active build or certification machine is the default.
7. A second concurrent heavyweight job is allowed only after pressure and headroom checks.
8. Swap or zram is not introduced by v1 without a separate host-maintenance decision.

### 2.4 Six CPUs must remain production-first

Initial scheduling model:

1. Active production services receive the highest CPU and I/O weights.
2. Release control receives middle priority and remains responsive.
3. Build, compression, testing, preview, and audit work receive lower weights.
4. Default build parallelism is at most four workers, leaving two logical CPUs uncommitted to background work.
5. Pressure-aware control may reduce parallelism to one or pause admission.
6. The system may expand to four workers only while production health, load, memory, and I/O remain green.
7. A single build job may not set an unbounded task count.

## 3. Network consequences

1. Caddy remains the only internet-facing application ingress.
2. Release slots bind Unix sockets where compatible.
3. Loopback TCP is the compatibility fallback.
4. No release service binds a wildcard address by default.
5. The Caddy admin endpoint must remain local and non-public.
6. GitHub webhook ingestion, when enabled, is a path behind Caddy rather than a new port.
7. Webhook ingestion can only persist a verified event; it cannot directly perform cutover.
8. Outbound GitHub API access uses short-lived installation tokens.

## 4. Single-node availability consequences

1. Blue/green prevents application deployment downtime, not physical host failure.
2. A kernel reboot still interrupts service because there is no second node.
3. Soft reboot is userspace-only and does not apply a new kernel.
4. Daily provider backup is disaster recovery, not live failover.
5. Automatic rollback can restore an application route but cannot recover a failed host.
6. The design must never claim high availability beyond the single host.
7. Future second-node support must reuse release and artifact identities without changing the single-host record schema.

## 5. Version-compatibility consequences

1. Caddy features must be tested against installed version 2.6.2 rather than current online documentation alone.
2. Candidate configuration must pass the installed `caddy adapt --validate` or equivalent validation.
3. systemd unit directives must be supported by systemd 255.
4. OpenZFS commands must be supported by 2.2.2.
5. Node builds in this repository use the repository-pinned Node version, not the host default.
6. Unsupported newer schema versions fail closed.
7. Capability reports must include exact binary paths and versions.

## 6. Required host preflight report

Before any implementation-phase production activation, the appliance must produce a signed report containing:

1. Hostname and machine-id digest.
2. Boot ID.
3. OS, kernel, systemd, Caddy, ZFS, Git, Node, npm, and compression-tool versions.
4. CPU count and architecture.
5. Memory total, available, and PSI.
6. Root filesystem size, free bytes, inode headroom, and mount type.
7. ZFS pool health, free bytes, fragmentation, and protected snapshot identity.
8. Caddy active configuration digest and admin endpoint exposure.
9. Active services, units, PIDs, sockets, and public listeners.
10. Existing deployment/release directories.
11. GitHub App capability without emitting secret values.
12. systemd credential capability.
13. Ubuntu Pro and Livepatch state.
14. Reboot-required state.
15. Provider snapshot capability state: configured, unavailable, or unknown.
16. Admission decision and reasons.
