# Baby-X Canonical Truth

This document defines where truth lives. It does not duplicate operation tables, schemas, or state-machine definitions.

## Truth precedence

When two artifacts disagree, use this order:

1. **Runtime source and strict validators** — executable authority.
2. **Persisted authoritative records and digest-chained events** — durable operational truth.
3. **Fresh test and certification evidence** — evidence for the exact tested subject.
4. **Normative architecture documents** — design constraints, subordinate to executable truth.
5. **Historical certification documents** — immutable evidence for their recorded commit and tree only.
6. **Held-branch documents** — noncanonical until deliberately adopted and recertified.

## Generated facts

The following facts must be read or generated from source rather than maintained manually:

- public operation names and count;
- operation schemas and metadata;
- catalog version and digest;
- lifecycle state enumerations;
- schema versions;
- test counts; and
- exact commit and tree identities.

`babyx.describe` is the public read-only source for the active operation catalog. Git is the source for commit and tree identity.

## Authority ownership

Each durable concern has one authority:

- `JobManager`: durable jobs and process identity;
- `DisposableMachineService`: disposable machine lifecycle and positive absence;
- `ArtifactManager`: artifact content and metadata;
- `CertificationService`: certification coordination only;
- `CandidateRaceService`: deterministic candidate comparison only;
- gateway: authentication, audit envelope, and forwarding only.

Generic provider execution must not bypass these authorities.

## Historical evidence

`docs/FINAL-DISPOSABLE-CERTIFICATION.md` is certified evidence for its exact historical commit, tree, snapshot, jobs, artifacts, and cleanup observations. It is not a claim that later commits are certified.

## Held branches

Work on held branches is `HELD_BRANCH_ONLY`. It may be inspected and individual concepts may be reimplemented, but it is not canonical merely because it exists or passes its own tests.
