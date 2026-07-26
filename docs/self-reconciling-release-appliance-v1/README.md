# Baby-X Self-Reconciling Release Appliance v1

## Status

This directory is the controlling design package for the Baby-X Self-Reconciling Release Appliance v1.

- Repository: `StealthEyeLLC/baby-x`
- Branch: `build/baby-x-self-reconciling-release-appliance-v1`
- Frozen base commit: `b8dcc150ddc175b2ad00099df405b8a3bf0e843a`
- Frozen base tree: `2045a746e0c6d928cf3354fd0ef9544918fbf514`
- Base branch: `build/baby-x-god-mode-v1`
- Isolated workspace: `/var/lib/baby-quirt/workspaces/baby-x-self-reconciling-release-appliance-v1/baby-x`
- V2 dependency: none
- Production mutation performed by this documentation checkpoint: none

The V2 transactional-tool-fabric branch is intentionally not used. Any future V2 work remains a separate fresh branch. This release-appliance line starts from the certified God Mode v1 evidence commit and must remain independently buildable, reviewable, certifiable, and rollback-capable.

## Mission

Turn the current single Ubuntu VPS into a self-reconciling deployment appliance in which an exact certified release can be promoted through one durable operation. The platform must perform source resolution, artifact reuse or build, certification, private staging, readiness validation, atomic traffic cutover, observation, rollback, connection drain, evidence finalization, and cleanup without a manual SSH runbook.

The normal operator experience becomes:

```text
select exact certified release
-> promote
-> stage inactive slot
-> start privately
-> pass readiness and smoke tests
-> atomically switch traffic
-> observe
-> drain prior slot
-> finalize evidence
```

Failure becomes:

```text
new release fails or degrades
-> keep or restore prior healthy route
-> isolate failed slot
-> preserve logs and evidence
-> verify cleanup or retain recovery-required state
-> require no emergency shell session
```

## Normative language

- **MUST**: required for correctness or safety.
- **MUST NOT**: prohibited.
- **SHOULD**: expected unless evidence justifies an exception.
- **MAY**: optional and capability-gated.
- **Observed truth**: state established by direct readback, not inferred from an attempted command.
- **Positive absence**: explicit verification that a process, socket, unit, runtime path, mount, or dataset is absent.
- **Zero friction**: no additional normal-path operator step, no new paid dependency, no new public control port, no required application rewrite, no production downtime, and automatic fallback when unsupported.

## Reading order

1. [00-FROZEN-BASELINE-AND-MISSION.md](00-FROZEN-BASELINE-AND-MISSION.md)
2. [01-ZERO-FRICTION-UPGRADES.md](01-ZERO-FRICTION-UPGRADES.md)
3. [02-TARGET-HOST-AND-CONSTRAINTS.md](02-TARGET-HOST-AND-CONSTRAINTS.md)
4. [03-AUTHORITY-ARCHITECTURE.md](03-AUTHORITY-ARCHITECTURE.md)
5. [04-DURABLE-MODEL-AND-STATE-MACHINES.md](04-DURABLE-MODEL-AND-STATE-MACHINES.md)
6. [05-BUILD-ARTIFACT-CACHE-AND-CERTIFICATION.md](05-BUILD-ARTIFACT-CACHE-AND-CERTIFICATION.md)
7. [06-BLUE-GREEN-CUTOVER-DRAIN-AND-ROLLBACK.md](06-BLUE-GREEN-CUTOVER-DRAIN-AND-ROLLBACK.md)
8. [07-RECONCILIATION-RECOVERY-AND-CLEANUP.md](07-RECONCILIATION-RECOVERY-AND-CLEANUP.md)
9. [08-RESOURCE-STORAGE-AND-RETENTION.md](08-RESOURCE-STORAGE-AND-RETENTION.md)
10. [09-GITHUB-SECRETS-AND-ACCESS.md](09-GITHUB-SECRETS-AND-ACCESS.md)
11. [10-HOST-MAINTENANCE.md](10-HOST-MAINTENANCE.md)
12. [11-SECURITY-THREAT-MODEL.md](11-SECURITY-THREAT-MODEL.md)
13. [12-OPERATIONS-API-AND-OPERATOR-UX.md](12-OPERATIONS-API-AND-OPERATOR-UX.md)
14. [13-IMPLEMENTATION-PLAN-AND-ACCEPTANCE.md](13-IMPLEMENTATION-PLAN-AND-ACCEPTANCE.md)
15. [14-REQUIREMENTS-TRACEABILITY.md](14-REQUIREMENTS-TRACEABILITY.md)
16. [15-POST-UPGRADE-CAPABILITIES.md](15-POST-UPGRADE-CAPABILITIES.md)
17. [16-AUTHORIZED-IMPLEMENTATION-PROMPT.md](16-AUTHORIZED-IMPLEMENTATION-PROMPT.md)
18. [17-RESEARCH-SOURCES.md](17-RESEARCH-SOURCES.md)

## Controlling principles

1. Production never builds from source.
2. A release is immutable and content-addressed.
3. A deployment request is durable and idempotent.
4. Release activation is a distinct authority from build and certification.
5. Caddy is the only internet-facing application ingress.
6. New releases start privately and receive traffic only after readiness proof.
7. Rollback selects a prior immutable release; it never rewrites source history.
8. Existing traffic drains before the prior slot is removed.
9. Unknown or ambiguous identity blocks destructive cleanup.
10. A successful command is not proof that the desired state exists.
11. Every child process is owned by the existing durable job authority.
12. Every production process is tied to a release, slot, unit, socket, artifact digest, and owner.
13. The previous known-good release remains available through the observation window.
14. Root and ZFS capacity are admission gates, not afterthoughts.
15. GitHub events request work but never directly possess production activation authority.
16. Secrets never enter source archives or release artifacts.
17. Host maintenance is separate from application release promotion.
18. All normal operations must be phone-friendly through Baby.

## Scope boundary

This design includes application and worker releases, blue/green slots, immutable artifacts, Caddy cutover, systemd process control, resource governance, GitHub integration, credential delivery, durable recovery, evidence, and a separate host-maintenance authority.

It does not require Kubernetes, Docker, GitHub Actions, NixOS, a second VPS, a new public control port, or replacement of Ubuntu. It deliberately avoids ZFS block-level deduplication on a 12 GB RAM host; content-addressed logical reuse provides the required deduplication-by-identity without the memory cost.
