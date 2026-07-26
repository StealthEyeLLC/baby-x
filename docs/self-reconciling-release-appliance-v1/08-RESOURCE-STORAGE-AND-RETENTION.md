# Resource, Storage, and Retention

## 1. Objectives

1. Preserve production responsiveness.
2. reject work before exhausting disk or memory.
3. use all six CPUs when safe without reserving them permanently for background work.
4. retain active and rollback releases.
5. maximize cache reuse within bounded storage.
6. prevent logs and evidence from growing without policy.
7. make every admission and eviction decision inspectable.

## 2. systemd slice hierarchy

Recommended hierarchy:

```text
stealtheye.slice
  stealtheye-production.slice
  stealtheye-release-control.slice
  stealtheye-background.slice
    stealtheye-build.slice
    stealtheye-certification.slice
    stealtheye-preview.slice
    stealtheye-audit.slice
```

Initial relative priorities, subject to host testing:

1. Production: `CPUWeight=1000`, `IOWeight=1000`.
2. Release control: `CPUWeight=500`, `IOWeight=500`.
3. Build/certification: `CPUWeight=100`, `IOWeight=100`.
4. Preview/audit: `CPUWeight=50`, `IOWeight=50`.

Weights are relative, not hard reservations. Exact values must be certified on systemd 255 and the host's cgroup v2 controllers.

## 3. Memory policy

For the observed approximately 11 GiB usable memory and no swap:

1. Production service limits are service-specific and based on observed peaks.
2. Background aggregate `MemoryHigh` initially targets 4 GiB.
3. Background aggregate `MemoryMax` initially targets 6 GiB.
4. Individual disposable builds default lower unless profile requires more.
5. Start no heavyweight work when available memory is below 2 GiB.
6. Throttle when available memory is below 3 GiB or memory PSI warning persists.
7. Pause new admission when memory PSI full pressure is observed over the policy window.
8. OOM kill is a hard failure and automatic rollback trigger when it affects the candidate.
9. Memory limits and events are included in evidence.
10. v1 does not add swap or zram automatically.

## 4. CPU policy

1. Background default maximum parallel build workers: 4.
2. Leave at least two logical CPUs outside explicit background saturation assumptions.
3. Reduce to 2 workers on moderate CPU or I/O pressure.
4. Reduce to 1 on sustained pressure or elevated production latency.
5. Pause optional work on severe production health degradation.
6. Release-control and rollback operations remain admitted even when background builds pause.
7. Compression threads are included in concurrency accounting.
8. Candidate racing is sequential by default on this host unless the governor proves capacity.

## 5. I/O policy

1. Production slice receives the highest I/O weight.
2. Artifact extraction and compression run in the background slice.
3. Use bounded temporary directories on the intended filesystem.
4. Avoid copying the same artifact through multiple root-filesystem staging paths.
5. fsync only required durability boundaries, not every intermediate byte.
6. Monitor I/O PSI and production latency.
7. Suspend cache compaction and optional evidence compression during high I/O pressure.
8. Never use lazy unmount as proof of cleanup.

## 6. Capacity admission

Every request produces `CapacitySnapshotV1` with:

1. root filesystem total/free/available bytes and inodes.
2. ZFS pool total/free/health/fragmentation.
3. artifact compressed and expanded bytes.
4. current installed release bytes.
5. expected temporary amplification.
6. cache growth estimate.
7. evidence/log reserve.
8. active and rollback retention reserve.
9. expected post-operation free bytes.
10. admission result and reasons.

### 6.1 Root defaults

1. warning: free below 20 GiB or 20 percent.
2. throttle: free below 15 GiB.
3. stage rejection: projected free below 12 GiB.
4. emergency: actual free below 8 GiB.
5. inode warning and hard thresholds are separately configured.

### 6.2 ZFS defaults

1. warning: free below 3 GiB or 25 percent.
2. clone rejection: projected free below 2 GiB.
3. per-clone quota/refquota required.
4. protected base snapshot is never a GC candidate.

### 6.3 Reservation protocol

1. Calculate estimate.
2. create durable byte reservation with expiry.
3. verify current free space again immediately before materialization.
4. account actual bytes as work progresses.
5. fail before exceeding reservation plus bounded tolerance.
6. release reservation on terminal cleanup.
7. controller restart reconstructs reservations from active records.

## 7. Storage classes

1. `ACTIVE_RELEASE`: never evicted.
2. `ROLLBACK_RELEASE`: never evicted during rollback window.
3. `PINNED_RELEASE`: owner-pinned.
4. `CANDIDATE_RELEASE`: staged/inactive.
5. `FAILED_RELEASE`: evidence-retained, bounded.
6. `SOURCE_ARCHIVE`: content-addressed and reusable.
7. `DEPENDENCY_CACHE`: reconstructable.
8. `BUILD_CACHE`: reconstructable.
9. `CERTIFICATION_EVIDENCE`: authoritative.
10. `DEPLOYMENT_EVIDENCE`: authoritative.
11. `PREVIEW`: short-lived.
12. `TEMPORARY`: transaction-owned.
13. `QUARANTINE`: corrupt or ambiguous; not auto-reused.

## 8. Logical deduplication

1. One artifact object per SHA-256.
2. One source archive per source-identity digest.
3. One dependency cache per complete cache key.
4. One build output per build key.
5. Reference records point to canonical objects.
6. Hard links or reflinks may be used only after filesystem and immutability verification.
7. Ordinary copy fallback remains correct.
8. ZFS block deduplication MUST remain disabled because its memory and operational cost is not justified on this host.
9. ZFS compression MAY be enabled per new dataset after benchmark and compatibility proof.

## 9. Retention defaults

Initial defaults, configurable per service:

1. Active release: indefinite while active.
2. Immediate prior known-good release: indefinite until replaced by a newer proven rollback target.
3. Additional successful releases: retain 3 or 14 days, whichever policy chooses, subject to capacity.
4. Failed release bytes: 72 hours unless pinned or needed for incident investigation.
5. Failed evidence: 30 days minimum.
6. Deployment records and signed receipts: 90 days minimum; longer if inexpensive.
7. Source archives: retain while referenced plus an LRU cache allowance.
8. Dependency/build caches: LRU, reconstructable, no fixed guarantee.
9. Preview environments: default 24 hours.
10. Temporary transaction directories: remove after terminal verification.
11. GitHub inbox/outbox: retain enough for de-duplication and audit, initially 30 days.
12. Quarantine: owner-reviewed; never silently reused.

Retention must be tuned after real artifact-size measurement. It may not promise a number of releases that the observed 17 GiB headroom cannot support.

## 10. Eviction order

When capacity is needed:

1. expired transaction temporaries.
2. expired previews.
3. unreferenced build cache.
4. unreferenced dependency cache.
5. unreferenced source archives.
6. expired failed release bytes after evidence preservation.
7. older successful releases beyond active, rollback, and pin requirements.

Never automatically evict:

1. active release.
2. current rollback release.
3. owner-pinned release.
4. artifact referenced by nonterminal work.
5. artifact whose evidence retention requires bytes.
6. ambiguous or corrupt resource before review.

## 11. Logs and journal

1. Service logs remain in journald or declared log sinks.
2. Per-deployment log extracts are bounded artifacts.
3. Journald retention must be configured to preserve OS headroom.
4. The appliance records cursor/time ranges instead of copying unlimited logs.
5. Secret patterns are redacted in exported evidence.
6. Truncation is explicit with byte counts and digests.
7. Log retention is separate from release retention.

## 12. Pressure governor

Inputs:

1. CPU PSI.
2. memory PSI.
3. I/O PSI.
4. available memory.
5. load average and runnable tasks.
6. root/ZFS capacity.
7. active-service latency and error health.
8. current background resource usage.
9. pending critical rollback/control work.

Outputs:

1. `ADMIT`.
2. `ADMIT_THROTTLED` with concurrency.
3. `PAUSE_OPTIONAL`.
4. `REJECT_CAPACITY`.
5. `REJECT_PRODUCTION_HEALTH`.
6. `OVERRIDE_FOR_ROLLBACK` for bounded critical recovery work.

Every decision is stored with input digest and expires quickly so stale capacity observations cannot authorize new work.

## 13. ZFS safety

1. All dataset identities are normalized and root-bounded.
2. Ownership properties bind machine, parent, owner, and request digest.
3. Create and destroy commands use exact argv.
4. Recursive destroy is prohibited for transaction clones unless a separately reviewed contract requires it.
5. Descendants and snapshots are enumerated before destroy.
6. Source snapshots are never destroyed by build cleanup.
7. Dataset absence is read back after destroy.
8. Provider unavailable means unknown, not absent.
9. Capacity and quota settings are read back after create.

## 14. Capacity acceptance tests

1. stage at adequate capacity succeeds.
2. projected breach of 12 GiB root floor rejects before extraction.
3. projected breach of 2 GiB ZFS floor rejects before clone.
4. reservation conflict prevents overcommit.
5. controller restart reconstructs active reservations.
6. concurrent requests cannot both consume the same headroom.
7. cache eviction preserves active and rollback objects.
8. interrupted eviction cannot delete a newly referenced object.
9. inode exhaustion is handled separately from byte availability.
10. PSI throttle reduces concurrency while production traffic remains healthy.
