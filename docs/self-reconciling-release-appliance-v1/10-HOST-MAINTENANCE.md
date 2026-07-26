# Host Maintenance

## 1. Separate authority

Host maintenance is not an application release transaction. It has a separate schema, controller lease, approval policy, evidence index, and operation namespace. It may consume Release Authority operations to drain or verify services but cannot impersonate an application deployment.

## 2. Host facts and limitations

1. The target root filesystem is ext4, not ZFS.
2. Host-wide ZFS snapshots are therefore impossible for the root filesystem.
3. The `babycert` ZFS pool can protect only datasets it actually contains.
4. The commercial plan's daily backup is owner-supplied disaster-recovery capability, not an atomic application rollback primitive.
5. Canonical Livepatch is not active because the machine is not currently attached to Ubuntu Pro.
6. `systemctl soft-reboot` is available but restarts userspace only; it does not load a new kernel.
7. A full reboot interrupts service on this single-node VPS.
8. No maintenance workflow may claim zero downtime for a kernel reboot without a second serving node.

## 3. Maintenance record

`MaintenanceRecordV1` includes:

1. maintenance ID and owner.
2. request digest and idempotency key.
3. kind: `PACKAGE_UPDATE`, `SERVICE_RUNTIME_UPDATE`, `SOFT_REBOOT`, `FULL_REBOOT`, `KEXEC`, `LIVEPATCH`, `FILESYSTEM`, or `OTHER_APPROVED`.
4. target packages/components and versions.
5. preflight inventory and capacity.
6. risk class.
7. disposable-verification record.
8. provider-backup capability and optional snapshot reference.
9. ZFS snapshot references for applicable datasets.
10. active services and rollback releases.
11. drain plan.
12. package-manager job IDs.
13. reboot requirement before/after.
14. boot ID before/after.
15. post-update health and release checks.
16. rollback or recovery plan.
17. evidence index.
18. state, sequence, timestamps, and error.

## 4. Package risk classes

### 4.1 Low impact

Potentially automatic only after dry-run and policy:

1. data-only packages.
2. leaf utilities not used by active services.
3. security updates with no service restart and no critical dependency impact.

### 4.2 Medium impact

Require disposable verification and scheduled application health checks:

1. language runtimes used by noncritical build work.
2. libraries used by inactive tooling.
3. package-manager updates.
4. observability tooling.

### 4.3 High impact

Require explicit owner approval, disposable rehearsal where possible, backup/snapshot assessment, maintenance window, and post-update certification:

1. kernel and kernel modules.
2. libc.
3. systemd.
4. Caddy.
5. OpenZFS packages or modules.
6. OpenSSH.
7. firewall/network stack.
8. bootloader.
9. storage and filesystem utilities.
10. cryptographic libraries used by the operator or ingress.
11. Baby/Baby-X release authority itself.
12. database engines.

## 5. Controlled update workflow

1. resolve exact candidate package versions and repositories.
2. capture package-state manifest and configuration digests.
3. run package-manager simulation/dry-run.
4. classify affected services, libraries, kernel, and reboot requirement.
5. verify disk and memory headroom.
6. run disposable or isolated compatibility tests where meaningful.
7. verify active release and rollback readiness.
8. obtain approval required by risk class.
9. optionally request provider snapshot through a separately configured authenticated provider adapter.
10. create ZFS snapshots only for applicable owned datasets.
11. drain or quiesce services only when required.
12. persist update intent.
13. run exact package operation through durable jobs.
14. reconcile terminal package truth.
15. restart only affected services through their authorities.
16. run post-update application, systemd, Caddy, ZFS, operator, and release health checks.
17. report reboot-required truth.
18. finalize evidence or enter recovery-required.

## 6. Automatic security updates

1. Preserve Ubuntu's security-update mechanism but govern it with explicit package classes.
2. Low-risk security updates may be automated after simulation and exclusion checks.
3. High-impact packages are blacklisted from unattended application and enter the Host Maintenance queue.
4. Automatic reboot remains disabled by default.
5. Every unattended run is imported into a maintenance observation/evidence record.
6. Failure cannot be hidden as a successful maintenance run.
7. Repository source and package signature verification remain mandatory.
8. Phased updates and pinning state are recorded.

## 7. Livepatch

1. Expose capability state: client installed, subscription attached, service entitled, patches applied, and kernel coverage.
2. Do not attach or purchase Ubuntu Pro automatically.
3. If the owner later enables Livepatch, integrate status and patch evidence.
4. Livepatch reduces some kernel-reboot needs but does not eliminate all reboot requirements.
5. The appliance must still report a true reboot requirement when running state cannot be corrected live.
6. Livepatch failure cannot be represented as host compliance.

## 8. Soft reboot

1. Use only for approved userspace refresh cases.
2. It does not replace a kernel reboot.
3. Record boot ID and kernel identity before and after.
4. Preserve release and route records on persistent storage.
5. Ensure services and Release Authority restart in a declared order.
6. Reconcile Caddy route, active slots, jobs, and endpoints after return.
7. A soft reboot is not zero downtime on one node; it is only potentially faster than a full firmware/kernel reboot.
8. Require a successful rehearsal before production use.

## 9. Full reboot or kexec

1. Requires explicit owner approval.
2. Requires maintenance window.
3. Requires all durable records flushed and evidence checkpointed.
4. Requires active release and rollback artifact verification.
5. Requires service drain/stop plan.
6. Requires provider console/recovery path verification.
7. Requires post-boot reconciliation.
8. Requires public-route acceptance after boot.
9. Must report actual downtime.
10. kexec is not used automatically merely because the command is available.

## 10. Backup and snapshots

1. Provider daily backup is recorded as configured capability, not assumed atomic or immediately restorable.
2. If a provider API is added, snapshot creation and restoration are separate durable provider operations.
3. Provider credentials use references and least privilege.
4. Snapshot completion must be read back from the provider.
5. Application-consistent snapshots require service-specific quiesce contracts.
6. ZFS snapshots cover only exact datasets and preserve GUID/TXG identity.
7. No snapshot replaces immutable release rollback.
8. Restore is never performed automatically during ordinary application deployment.

## 11. Configuration protection

Before high-impact maintenance, preserve:

1. package manifest and apt sources.
2. relevant `/etc` file digests and bounded archives.
3. systemd unit/drop-in bytes.
4. Caddy active config and source config.
5. Release Authority records and indexes.
6. credential-object metadata without plaintext.
7. firewall/nftables ruleset.
8. ZFS pool and dataset metadata.
9. operator/Baby manifests.
10. boot and kernel state.

## 12. Post-maintenance certification

1. package versions match plan.
2. no unexpected package removal.
3. systemd manager healthy.
4. Caddy config active and public route healthy.
5. ZFS pool online and protected snapshots unchanged.
6. Baby and operator proof paths work.
7. release live-state report is consistent.
8. all active services have exact process/endpoint identity.
9. background resource policy is active.
10. no new public listener exists.
11. reboot-required state is explicit.
12. evidence index verifies.

## 13. Recovery

1. Package failure remains a maintenance failure, not application deployment failure.
2. Restore individual configuration only from verified pre-update artifacts.
3. Roll back a package only when repository availability and compatibility are proven.
4. Restore application traffic through immutable release rollback where relevant.
5. Do not attempt automatic kernel or ZFS rollback without a separately certified path.
6. Preserve provider-console instructions as offline operational documentation, not automated credentials.
7. Enter `RECOVERY_REQUIRED` when automated truth cannot be established.
