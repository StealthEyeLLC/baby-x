# Frozen Baseline and Mission

## 1. Frozen repository baseline

1. The implementation MUST begin from commit `b8dcc150ddc175b2ad00099df405b8a3bf0e843a`.
2. The expected Git tree is `2045a746e0c6d928cf3354fd0ef9544918fbf514`.
3. The base branch is `build/baby-x-god-mode-v1`.
4. The implementation branch is `build/baby-x-self-reconciling-release-appliance-v1`.
5. The V2 branch MUST NOT be merged, cherry-picked wholesale, or treated as an implementation dependency.
6. Concepts may be independently re-derived, but every line on this branch must have its own review and test provenance.
7. The certified God Mode v1 branch and evidence commit MUST remain unchanged.
8. No force push, history rewrite, reset-based rollback, or branch replacement is permitted.

## 2. Exact target host

The target is one VPS with the following commercial specification supplied by the owner and verified against the live host where possible:

1. 6 vCores.
2. 12 GB RAM class; live usable memory is approximately 11 GiB.
3. 100 GB SSD NVMe class storage; live root filesystem is approximately 96 GiB.
4. Daily provider backup of the previous 24 hours according to the plan description.
5. Unlimited traffic according to the plan description.
6. 2 Gbps public bandwidth according to the plan description.
7. Ubuntu 24.04 LTS.
8. systemd 255.
9. Caddy 2.6.2 at design time.
10. OpenZFS 2.2.2 with the `babycert` pool.
11. One public host; no second-node availability assumption.

Provider backup, traffic, and bandwidth claims are commercial-plan facts supplied by the owner and are not treated as runtime API proof. The appliance must report them as configured expectations unless a provider API later proves them.

## 3. Mission

Build a durable Release Authority and supporting adapters that transform deployment from a sequence of shell commands into a recoverable state transition.

A complete promotion MUST bind:

1. Repository identity.
2. Exact source commit and tree.
3. Source archive digest.
4. Lockfile digest.
5. Runtime and toolchain identities.
6. Build profile and normalized build inputs.
7. Dependency-cache identity.
8. Release-artifact digest and manifest.
9. Certification profile and result.
10. Service definition version.
11. Slot identity.
12. systemd unit identity and process identity.
13. Private socket or loopback endpoint identity.
14. Caddy configuration digest before and after cutover.
15. Readiness, smoke-test, and observation evidence.
16. Prior known-good rollback release.
17. All child durable job IDs.
18. All artifacts and signed receipts.
19. Drain status.
20. Cleanup and positive-absence evidence.

## 4. Required end state

After implementation and production acceptance:

1. `babyx.release.promote` can request promotion of an exact certified release.
2. Repeating the same normalized request returns the same durable transaction.
3. Production does not run `git pull`, dependency installation, compilation, or packaging.
4. The inactive slot can be prepared while the active slot serves traffic.
5. The inactive slot starts on a private endpoint and cannot receive public traffic before promotion.
6. Readiness is based on real probes and declared compatibility checks, not process existence alone.
7. Caddy cutover is validated before application and applied through its graceful configuration API.
8. Existing long-lived streams are protected by bounded drain behavior.
9. The previous slot remains available until the new release passes its observation window.
10. Hard health failure or threshold breach can automatically restore the previous route.
11. A coordinator restart resumes from durable state and exact child identities.
12. Ambiguous ownership prevents cleanup and is surfaced as `AMBIGUOUS` or `RECOVERY_REQUIRED`.
13. Cleanup is complete only after process, unit, socket, runtime path, and release-specific transient resources are absent.
14. `babyx.release.live` authoritatively answers what is serving production.
15. GitHub can show queued, running, successful, failed, rolled-back, and inactive deployment states.
16. No public deployment-control port exists.
17. Secrets are supplied outside the artifact through systemd credentials or a compatibility adapter.
18. Resource pressure throttles background work before it harms production.
19. Disk admission control rejects work that cannot safely fit.
20. Every action has a signed receipt and an evidence timeline.

## 5. Invariants

### 5.1 Authority invariants

1. Build authority cannot activate production.
2. Certification authority cannot activate production.
3. GitHub event ingestion cannot activate production by itself.
4. Caddy and systemd adapters execute only under a durable Release Authority transaction.
5. Child execution uses the existing Baby-X durable job authority.
6. Disposable validation uses the existing machine authority.
7. Artifact bytes use the existing artifact authority or a single compatible extension of it.
8. There is one active route authority per service.
9. Host maintenance has a separate authority and schema.

### 5.2 Truth invariants

1. Exit code zero is never sufficient evidence of activation, health, cutover, drain, or cleanup.
2. Missing process truth never becomes exit code zero.
3. A lost response never causes blind duplicate execution.
4. A PID is valid only with process start time, executable identity, boot ID, unit/cgroup ownership, and expected slot binding.
5. A Caddy reload is successful only after API success and route readback.
6. A systemd start is successful only after unit, main PID, process identity, endpoint, and readiness readback.
7. Rollback is successful only after route readback confirms the prior endpoint.
8. Cleanup is successful only after positive absence.
9. Unknown provider state remains unknown.
10. Corrupt authoritative records are isolated, not silently rewritten.

### 5.3 Availability invariants

1. The active healthy release remains routed while the inactive release is prepared.
2. A failed candidate cannot replace the active route.
3. The prior release remains installed and restartable through the observation window.
4. Caddy configuration failure leaves the old configuration active.
5. Automatic rollback is bounded and cannot oscillate indefinitely.
6. Cleanup never removes the sole known-good release.

## 6. Non-goals for v1

1. Multi-host quorum or consensus.
2. Active/active cross-region service.
3. Kubernetes orchestration.
4. General-purpose package manager replacement.
5. Whole-host immutable image conversion.
6. Automatic database down-migration.
7. Automatic handling of application-incompatible schema changes without a declared migration contract.
8. Automatic provider restore when no provider API is configured.
9. Automatic Ubuntu Pro subscription enrollment.
10. Automatic full reboot without a declared maintenance policy.
11. Unbounded canary experimentation.
12. ZFS deduplication property enablement.
13. Public unauthenticated release controls.
14. Release from an unverified branch name without exact commit resolution.
15. Treating GitHub status as authoritative local state.

## 7. Definition of done

The build is done only when all implementation checkpoints, restart tests, response-loss tests, ambiguity tests, disk-pressure tests, blue/green tests, sustained-traffic tests, long-lived-stream tests, defective-release rollback tests, cleanup tests, evidence verification, and a controlled production acceptance have passed. A documentation-complete branch is not an implementation-complete appliance.
