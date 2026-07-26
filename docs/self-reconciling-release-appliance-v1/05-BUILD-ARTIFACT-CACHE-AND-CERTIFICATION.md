# Build, Artifact, Cache, and Certification

## 1. Production-build prohibition

Production release slots MUST NOT run:

1. `git pull`, `git checkout`, or mutable repository synchronization.
2. package-manager install commands.
3. compiler or bundler commands.
4. source-code generation.
5. release archive construction.
6. tests that mutate the production release tree.

Production receives one complete, immutable, verified release artifact and non-secret slot metadata.

## 2. Source resolution

A source request may begin with a commit SHA, tag, release, or approved branch event. Resolution must end with:

1. exact repository identity.
2. exact commit SHA.
3. exact tree SHA.
4. exact submodule/LFS identities where applicable.
5. source archive bytes.
6. source archive SHA-256.
7. source manifest digest.
8. lockfile digest.
9. resolver receipt.

Resolution rules:

1. Branch and tag names are not authoritative after resolution.
2. The remote commit must be independently read back.
3. The archive must be generated from the resolved tree, not an arbitrary working directory.
4. Source archives must exclude `.git`, transient build output, and secret files.
5. The source manifest lists every included path, type, mode, size, and digest.
6. Any mismatch aborts before build.

## 3. Build environment

1. Builds execute in a disposable machine or an equivalent approved isolated profile.
2. The environment is bound to an exact base snapshot identity.
3. Network is disabled after dependency materialization unless the normalized build profile declares a bounded dependency-fetch phase.
4. Credential references are allowed only for the minimum fetch operation and are never included in artifacts.
5. Build steps use exact argv, cwd, environment, timeout, memory, CPU, tasks, output, and disk bounds.
6. Every step is a durable job.
7. Concurrent build steps are allowed only when the dependency graph and resource governor permit them.
8. A build machine cannot become a production slot.
9. Cleanup uses the existing disposable-machine authority.

## 4. Build profile

A normalized build profile includes:

1. profile ID and version.
2. source working directory.
3. runtime and toolchain identities.
4. dependency install steps.
5. code-generation steps.
6. compile/bundle steps.
7. unit and static-analysis steps.
8. packaging steps.
9. included/excluded output paths.
10. expected artifact layout.
11. environment allowlist.
12. credential-reference allowlist.
13. network phases.
14. resource bounds.
15. reproducibility requirements.
16. expected manifest schema.
17. cache policy.
18. certification profile reference.

Unknown step kinds fail closed.

## 5. Dependency cache

### 5.1 Cache key

The dependency cache key MUST include:

1. architecture.
2. operating-system/base-snapshot name.
3. snapshot GUID and creation TXG.
4. runtime path, version, and binary digest.
5. package-manager path, version, and binary digest.
6. lockfile path and digest.
7. package-manager configuration digest.
8. install flags.
9. production/development dependency mode.
10. relevant environment names and non-secret values.
11. native-addon ABI identity.
12. dependency-fetch policy version.

### 5.2 Cache creation

1. Populate in a disposable environment.
2. Finalize only after install success and manifest verification.
3. Store a path/type/mode/size/digest manifest.
4. Record native binaries and architecture.
5. Mark incomplete caches quarantined.
6. Never mutate a finalized cache object.

### 5.3 Cache restore

1. Verify metadata and object digest before use.
2. Restore to a fresh destination.
3. Reject ownership, path, mode, or manifest mismatch.
4. A cache miss is normal and not a failure.
5. A corrupt hit is a distinct failure and must not silently fall back without recording the corruption.

## 6. Build-output cache

The build-output key includes:

1. source tree SHA.
2. source manifest digest.
3. dependency-cache key.
4. toolchain identity.
5. normalized build profile digest.
6. non-secret build configuration digest.
7. target platform.
8. release-layout schema.

A hit is accepted only after artifact and manifest verification.

## 7. Release artifact format

The default artifact is a deterministic compressed archive, preferably `tar.zst` when available and verified. It contains:

```text
release-manifest.json
app/
runtime/
provenance/
  source.json
  build.json
  certification-policy.json
  sbom.*              # optional when generated
```

Rules:

1. Entry order is deterministic.
2. Ownership is normalized.
3. timestamps are normalized to the source epoch or declared deterministic epoch.
4. absolute paths and traversal entries are forbidden.
5. devices, FIFOs, and unsafe special files are forbidden unless explicitly supported by a future schema.
6. symlink targets are validated and cannot escape the release root.
7. setuid/setgid bits are forbidden by default.
8. a maximum expanded size and entry count are enforced before extraction.
9. the archive digest is calculated over final bytes.
10. the manifest digest is independently calculated.
11. secret-looking paths and configured secret names cause rejection.

## 8. Artifact materialization

1. Reserve capacity before download or extraction.
2. Write into a transaction-specific staging directory.
3. verify artifact SHA-256 before extraction.
4. extract with traversal and symlink protections.
5. verify the installed file manifest.
6. fsync files and directories required for crash safety.
7. atomically rename the completed release directory into its digest-addressed final path.
8. make the release tree non-writable to the service identity.
9. create no `current` symlink that acts as hidden activation authority.
10. slot bindings refer to exact release paths and digests.
11. replay of an existing verified release is a no-op.
12. conflicting bytes at a digest path cause quarantine and `AMBIGUOUS` state.

## 9. Certification profile

A complete certification profile can include:

1. artifact integrity verification.
2. manifest schema validation.
3. dependency/runtime availability.
4. startup in a disposable machine.
5. native readiness protocol.
6. compatibility readiness probe.
7. health endpoint behavior.
8. smoke tests.
9. unit tests not already proven by build.
10. integration tests.
11. migration preflight.
12. backward-compatibility checks.
13. credential-name contract without production secret values.
14. Unix-socket or loopback endpoint contract.
15. graceful shutdown behavior.
16. WebSocket/SSE behavior when applicable.
17. resource-bound tests.
18. filesystem write-boundary tests.
19. no-public-listener checks.
20. log redaction checks.
21. startup/restart stability.
22. cleanup and positive absence.

## 10. Certification reuse

A prior successful certification may be reused only when all are identical:

1. artifact SHA-256.
2. manifest digest.
3. certification profile ID, version, and digest.
4. service definition digest.
5. base snapshot identity, GUID, and creation TXG.
6. runtime/toolchain identity.
7. dependency identity.
8. appliance compatibility version.
9. required external contract identities.
10. security policy version.

Reuse is blocked if:

1. evidence cannot be verified.
2. the certification expired.
3. a vulnerability or policy invalidation references the artifact or dependency.
4. the service definition changed in a behavior-relevant way.
5. the target host lacks a capability tested by the certification.

## 11. Reproducibility

v1 supports three truthful classifications:

1. `BIT_REPRODUCIBLE`: two independent builds produce identical artifact bytes.
2. `MANIFEST_REPRODUCIBLE`: file manifest and behavior identities match but archive bytes differ for a declared benign reason.
3. `NOT_PROVEN_REPRODUCIBLE`: build may still be certifiable but no reproducibility claim is made.

The platform never labels a single successful build reproducible without comparison evidence.

## 12. SBOM and provenance

1. Generate an SBOM when an approved tool is available.
2. Bind the SBOM to artifact digest.
3. Record builder identity, source, toolchain, dependencies, commands, and environment digest.
4. Keep provenance separate from owner approval.
5. No provenance statement can grant production activation.
6. Missing optional SBOM tooling is reported, not silently represented as complete coverage.

## 13. Build failure behavior

1. Production route is unchanged.
2. Existing active and rollback releases are untouched.
3. failed machine and jobs are reconciled.
4. logs and partial evidence are preserved according to policy.
5. incomplete caches and artifacts are quarantined or removed only after ownership proof.
6. GitHub receives failure status through the outbox.
7. a retry with the same normalized request reuses durable progress and never duplicates completed work blindly.

## 14. Performance strategy on this VPS

1. Default to one heavyweight build or certification at a time.
2. Use up to four build workers only with green production health and low PSI.
3. Prefer cache restore over dependency installation.
4. Prefer content-addressed hard-link/reflink/copy-on-write methods only after filesystem capability checks.
5. Compress at a moderate bounded level; do not consume all CPUs for marginal ratio gains.
6. Avoid holding both uncompressed source and artifact copies longer than necessary.
7. Reserve root and ZFS bytes before work.
8. Evict only unreachable cache objects.
9. Never enable ZFS deduplication for this workload.
