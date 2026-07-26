# Security and Threat Model

## 1. Protected assets

1. production traffic continuity.
2. active and rollback release identity.
3. Caddy route integrity.
4. systemd unit and process integrity.
5. Release Authority records.
6. artifact bytes and manifests.
7. GitHub App private key and tokens.
8. service credentials.
9. signing keys and receipts.
10. protected ZFS snapshots and datasets.
11. deployment evidence.
12. owner authorization.
13. host storage and capacity headroom.

## 2. Trust assumptions

1. The host kernel and root authority are trusted for v1.
2. The existing Baby/operator authentication and peer-identity boundary is trusted after its own certification.
3. GitHub is trusted to provide repository data through authenticated APIs, but events and artifacts are still verified.
4. Candidate source and release artifacts are untrusted until validation and certification.
5. Application processes are not trusted with Release Authority or GitHub credentials.
6. Caddy is trusted only within its narrow ingress role.
7. systemd is trusted as process and resource supervisor.
8. Provider backup claims are not treated as live observed truth without an API.

## 3. Threat actors

1. attacker controlling a candidate repository commit.
2. attacker replaying or forging GitHub webhooks.
3. compromised build dependency.
4. compromised application process.
5. accidental operator error.
6. stale controller process.
7. PID reuse or unit-name collision.
8. filesystem corruption or capacity exhaustion.
9. malicious archive path/symlink.
10. compromised or misconfigured Caddy route.
11. leaked service or GitHub credential.
12. partial host failure or process crash.
13. neighboring unowned process/resource.
14. logic bug causing duplicate requests.

## 4. Primary threats and controls

### T-001 - Candidate gains production activation authority

Controls:

1. build/certification separated from Release Authority.
2. no candidate-provided arbitrary systemd or Caddy config.
3. typed trusted templates.
4. exact manifest schema.
5. owner/automation policy gate.

### T-002 - Webhook forgery or replay

Controls:

1. raw-body HMAC-SHA256 verification.
2. constant-time comparison.
3. delivery-GUID de-duplication.
4. repository and installation allowlists.
5. event/action allowlists.
6. body size/rate limits.

### T-003 - Mutable ref substitution

Controls:

1. exact commit/tree resolution.
2. source archive digest.
3. re-read remote identity.
4. approvals bind request digest and artifact.

### T-004 - Build artifact substitution

Controls:

1. content-addressed object.
2. manifest digest.
3. certification binds exact digest.
4. materialization re-verification.
5. immutable final path.

### T-005 - Archive traversal or symlink escape

Controls:

1. pre-scan entries.
2. relative normalized paths.
3. no `..` or absolute paths.
4. symlink-parent checks.
5. expanded-size and entry bounds.
6. post-extraction manifest verification.

### T-006 - Secret leakage

Controls:

1. secret-free artifact schema.
2. systemd credentials.
3. redaction at error/evidence boundaries.
4. no token arguments or URLs.
5. secret-scanning tests.
6. service-specific credential names.

### T-007 - PID reuse causes wrong process adoption or kill

Controls:

1. PID start time.
2. executable path.
3. boot ID.
4. cgroup and unit identity.
5. process group.
6. endpoint ownership.
7. ambiguity blocks kill.

### T-008 - Route changes to wrong upstream

Controls:

1. trusted route templates.
2. installed-Caddy validation.
3. prior/candidate config digests.
4. local admin endpoint.
5. active-config readback.
6. public-route release-identity probe.

### T-009 - Cutover response loss causes double action

Controls:

1. durable intent before load.
2. exact candidate and previous config digests.
3. active-config readback on recovery.
4. route lease.
5. idempotency.

### T-010 - Cleanup deletes active or foreign resource

Controls:

1. route-reference check.
2. exact unit/process/slot ownership.
3. rollback-reference check.
4. positive absence before path removal.
5. no broad recursive delete.
6. ambiguous exclusion.

### T-011 - Resource exhaustion harms production

Controls:

1. ext4 and ZFS admission floors.
2. durable reservations.
3. cgroup weights and limits.
4. PSI governor.
5. output and runtime bounds.
6. reference-aware eviction.

### T-012 - Dependency-cache poisoning

Controls:

1. complete cache key.
2. immutable cache object.
3. manifest and byte verification.
4. isolation.
5. quarantine on corruption.

### T-013 - GitHub compromise activates unauthorized code

Controls:

1. repo allowlist.
2. exact source and certification.
3. owner or strict low-risk policy.
4. local Release Authority remains final activation authority.
5. production credentials unavailable to build.

### T-014 - Application compromises Caddy or Release Authority

Controls:

1. separate service user.
2. private endpoint only.
3. no admin-socket access.
4. systemd filesystem and capability hardening.
5. no shared writable release tree.
6. credential isolation.

### T-015 - Corrupt durable state fabricates success

Controls:

1. strict schemas.
2. canonical digests.
3. hash-chained events.
4. evidence verification.
5. per-record isolation.
6. terminal success predicates.

## 5. systemd hardening baseline

Subject to service compatibility testing:

1. dedicated unprivileged user/group.
2. `NoNewPrivileges=yes`.
3. `PrivateTmp=yes`.
4. `ProtectSystem=strict` or strongest compatible setting.
5. `ProtectHome=yes`.
6. `PrivateDevices=yes` unless required.
7. `ProtectKernelTunables=yes`.
8. `ProtectKernelModules=yes`.
9. `ProtectControlGroups=yes`.
10. restricted address families.
11. bounded capability set, preferably empty.
12. `RestrictSUIDSGID=yes`.
13. `LockPersonality=yes`.
14. `MemoryDenyWriteExecute=yes` when compatible.
15. explicit writable paths.
16. private runtime and credentials.
17. production slice and resource bounds.

Hardening is capability-tested. An incompatible directive is not silently ignored; it is recorded and the approved strongest compatible profile is used.

## 6. Caddy boundary

1. public listeners are only declared HTTP/HTTPS endpoints.
2. admin endpoint is local.
3. application services cannot access the admin endpoint.
4. candidate artifacts cannot supply arbitrary global Caddy JSON.
5. route templates escape and validate all service-derived values.
6. Caddy config and logs contain no credentials.
7. TLS material remains under Caddy's existing protected storage authority.
8. Caddy upgrade is a host-maintenance action.

## 7. Filesystem boundary

1. release directories are root-owned and service-read-only.
2. writable state is outside release directories.
3. staging paths are transaction-specific and root-bounded.
4. finalization uses atomic rename.
5. file modes are declared and verified.
6. special files are rejected.
7. content-addressed paths cannot be overwritten.
8. quarantine is not executable or routable.
9. runtime sockets live under `/run` and are ephemeral.
10. cleanup checks exact ownership before deletion.

## 8. Audit and detection

1. signed receipts for every mutation.
2. hash-chained lifecycle events.
3. GitHub delivery audit.
4. route-config before/after artifacts.
5. process and unit identities.
6. denied/ambiguous cleanup events.
7. capacity decisions.
8. credential-set digest changes.
9. approval records.
10. unexpected public listener scan.
11. artifact corruption/quarantine alerts.
12. repeated rollback or restart-loop alerts.

## 9. Security acceptance

1. malicious archive tests.
2. symlink-parent traversal tests.
3. unit/route injection tests.
4. webhook forgery/replay tests.
5. token/credential redaction tests.
6. PID reuse and foreign socket tests.
7. conflicting Caddy config recovery test.
8. active-release eviction prevention test.
9. dependency-cache poisoning test.
10. untrusted artifact cannot reach route test.
11. application user cannot modify release bytes test.
12. application user cannot reach Caddy admin socket test.
13. no new public listener test.
14. unknown schema fails closed test.
15. final evidence mutation detection test.
