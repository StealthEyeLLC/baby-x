# Authority Architecture

## 1. Architectural objective

The appliance must automate aggressively without concentrating unrelated powers in one process. Automation is not permission collapse. Each authority owns one durable truth domain and other components consume it through explicit contracts.

## 2. Authority map

### 2.1 Release Authority

The Release Authority is the sole authority allowed to:

1. Create a deployment transaction.
2. Select the inactive slot.
3. Bind a certified artifact to a slot.
4. Request slot start and readiness validation.
5. Request Caddy cutover.
6. Mark a release provisional or active.
7. Request rollback.
8. Request prior-slot drain.
9. Request cleanup after retention gates.
10. Finalize deployment evidence.

It MUST NOT compile source, directly spawn unmanaged processes, directly mutate ZFS, mint broad GitHub credentials, or perform package updates.

### 2.2 Durable Job Authority

The existing Baby-X job authority remains the sole child-process authority. It owns:

1. Job identity.
2. Process identity.
3. stdout and stderr streams.
4. Timeouts and cancellation.
5. Terminal status.
6. Restart reconciliation.
7. Output bounds.
8. Metadata binding to parent release, slot, service, and phase.

No release component may use an alternate detached-process mechanism.

### 2.3 Artifact Authority

The artifact authority owns immutable byte objects and metadata. It must support:

1. Content digest verification.
2. Atomic finalization.
3. Reference tracking.
4. Bounded reads.
5. Retention classification.
6. Evidence index storage.
7. Import from source archive, build output, logs, and reports.
8. Corruption detection.

The Release Authority references artifact IDs and digests; it does not own arbitrary artifact bytes.

### 2.4 Disposable Machine Authority

The existing disposable-machine authority owns:

1. ZFS clone creation.
2. nspawn machine start.
3. machine execution through durable jobs.
4. process identity.
5. stop, destroy, and positive absence.
6. recovery and ambiguity classification.

Build and certification request machines through this authority. Release slots on the production host are not disposable machines and are managed through the Slot Runtime Adapter under Release Authority.

### 2.5 Build Authority

The Build Authority may:

1. Resolve an exact source input.
2. Materialize it in an isolated build environment.
3. restore verified caches.
4. run declared dependency and build steps.
5. create an immutable release artifact.
6. emit build evidence.

It cannot stage, start, route, promote, rollback, or clean production slots.

### 2.6 Certification Authority

The Certification Authority may:

1. Materialize the exact artifact in a disposable environment.
2. run declared validation and acceptance profiles.
3. verify release-manifest compatibility.
4. produce a signed certification record.

It cannot activate production. A successful certification is necessary but not sufficient for promotion.

### 2.7 Slot Runtime Adapter

This adapter is a narrow systemd integration used only by Release Authority. It may:

1. Write deterministic non-secret slot metadata under the release-state root.
2. write or select a validated unit/drop-in.
3. daemon-reload when unit bytes change.
4. start, stop, restart, and query the exact slot unit.
5. query the exact cgroup and main process identity.
6. query the expected Unix socket or loopback endpoint.
7. collect journal evidence.

It must not accept arbitrary unit names or arbitrary command lines from the public API.

### 2.8 Route Adapter

This is a narrow Caddy integration used only by Release Authority. It may:

1. Read the current active Caddy configuration.
2. generate the complete intended configuration from trusted templates and release state.
3. validate candidate config with the installed Caddy binary.
4. load configuration through the local admin API.
5. read back the active config.
6. execute route probes.
7. restore a previously recorded config.

It must not expose the raw Caddy admin API publicly or accept arbitrary untrusted JSON as a public Baby operation.

### 2.9 Credential Authority

The Credential Authority owns credential references and encrypted service-scoped material. It may:

1. resolve a reference for a specific service and slot.
2. create or select encrypted systemd credential blobs.
3. bind credential-set digest to deployment evidence.
4. rotate inactive-slot credentials.
5. revoke retired credential sets after policy gates.

It must not place secret values in release records, events, logs, Git history, artifacts, Caddy config, command arguments, or public responses.

### 2.10 GitHub Integration Adapter

The GitHub adapter owns no local deployment truth. It may:

1. verify and normalize webhook events.
2. poll configured repository state.
3. mint short-lived installation tokens.
4. create or update deployment/check status.
5. persist inbound de-duplication and outbound retry state.

GitHub is an event and reporting surface. Local authoritative records remain the source of truth.

### 2.11 Resource Governor

The Resource Governor is decision-only plus narrowly-scoped cgroup configuration. It may:

1. observe PSI, load, memory, disk, and service health.
2. admit, throttle, pause, or resume background release work.
3. calculate concurrency.
4. apply declared slice properties.

It cannot route traffic or delete releases.

### 2.12 Host Maintenance Authority

Host maintenance is a separate root authority for package and reboot operations. It consumes release health and drain capabilities but does not share deployment state transitions. It is specified in `10-HOST-MAINTENANCE.md`.

## 3. Trust boundaries

```text
GitHub event / owner request
        |
        v
verified request normalization
        |
        v
Release Authority durable transaction
   |         |          |          |
   v         v          v          v
Build     Certify    Slot       Route
Authority Authority  Adapter    Adapter
   |         |          |          |
   v         v          v          v
Machines   Machines   systemd    Caddy
   \___________|__________|__________/
               |
               v
        Durable Job Authority
               |
               v
        Artifact / Evidence Authority
```

No arrow grants the caller the callee's authority. Each call is normalized, owner-bound, sequence-bound, idempotent, and evidence-producing.

## 4. Durable storage layout

Recommended paths, subject to implementation-time compatibility verification:

```text
/var/lib/baby-x/release-authority/
  services/
  releases/
  deployments/
  events/
  indexes/
  leases/
  pending/
  routes/
  slots/
  observations/
  github-inbox/
  github-outbox/
  capacity/

/var/lib/baby-x/artifacts/
  objects/<sha256-prefix>/<sha256>
  metadata/
  references/

/opt/stealtheye/releases/<service>/<artifact-sha256>/
  release-manifest.json
  app/
  runtime/
  provenance/

/run/stealtheye/releases/<service>/<slot>/
  app.sock
  pid/
  readiness/
  credentials/   # systemd-managed mount or directory, not artifact content

/etc/systemd/system/stealtheye-release@.service
/etc/systemd/system/stealtheye-release@<service>-<slot>.service.d/
/etc/stealtheye-release/services/<service>.json
```

The implementation may adjust paths only if it records a migration plan and preserves the same ownership boundaries.

## 5. Process topology

1. Baby gateway exposes the single authenticated dynamic tool.
2. Baby-X runtime routes `babyx.release.*` operations.
3. Release Authority maintains durable records and a bounded reconcile loop.
4. Existing JobManager owns external commands.
5. systemd owns production service process lifetime.
6. Caddy owns public ingress and TLS.
7. GitHub adapter has no root process-control path.
8. No deployment daemon listens on a public port.
9. A local webhook receiver, if enabled, is reachable only through a specific Caddy route and can only write a verified inbox record.
10. The release controller may be socket-activated or periodically triggered, but durable state cannot depend on one long-running process.

## 6. Ownership identities

Every mutable resource must carry enough identity to prevent mistaken adoption or deletion:

1. `serviceId`.
2. `releaseId`.
3. `artifactDigest`.
4. `deploymentId`.
5. `slotId`.
6. `ownerPrincipal`.
7. `requestDigest`.
8. `idempotencyKey`.
9. `unitName`.
10. `machineId` where applicable.
11. `jobIds`.
12. `processIdentity` including PID, start time, executable, boot ID, cgroup, and unit.
13. `socketPath` or loopback address.
14. `routeConfigDigest`.
15. `credentialSetDigest`.
16. timestamps and state sequence.

## 7. Public-operation boundary

The public operation catalog exposes typed release operations, not raw route or unit mutation. Raw God Mode operations remain available under their existing authority model, but the release appliance must never use a raw operation as an undocumented alternate deployment path.

## 8. Failure containment

1. Build failure cannot change production.
2. Certification failure cannot change production.
3. Slot start failure cannot change the route.
4. Route load failure retains the prior Caddy config.
5. Observation failure requests rollback while retaining both slot records.
6. Rollback failure retains exact state as recovery-required and blocks cleanup.
7. GitHub API failure delays reporting only.
8. Evidence finalization failure prevents terminal success but does not undo a healthy route blindly.
9. Cleanup failure preserves the old slot and reports residual resources.
10. Host-maintenance failure cannot be mislabeled as application-release failure.
