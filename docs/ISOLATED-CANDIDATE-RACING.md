# Isolated Candidate Racing Foundation

**Status:** Checkpoint H public contract.

Candidate racing owns durable objective, race, candidate, validation, score, selection, and evidence truth. It does not own cloning, machine startup, command supervision, jobs, receipts, artifacts, generic recovery, or cleanup.

Each candidate is executed through the Checkpoint F certification consumer. Certification in turn consumes the shared Disposable Machine Service and existing durable-job and artifact authorities.

## Public operations

- `babyx.race.describe`
- `babyx.race.run`
- `babyx.race.resume`
- `babyx.race.get`
- `babyx.race.list`

No race operation merges, deploys, activates a release, or mutates production.

## Common baseline and isolation

Every candidate binds the same exact:

- source commit;
- source tree;
- protected source snapshot;
- optional source snapshot GUID;
- common validation profile digest.

Each candidate must provide a distinct machine name, clone dataset, and mountpoint. Writable candidate state cannot be shared. Strategy steps and their normalized strategy digest are candidate-specific; validation steps are appended identically to every candidate certification profile.

## Durable records

A race record binds:

- race and objective IDs;
- objective digest;
- exact source identity;
- automatic execution-policy decision and digest;
- common validation profile and digest;
- candidate records;
- winner or no-winner truth;
- cleanup failures;
- bounded evidence artifact and digest.

Each candidate record binds:

- candidate ID;
- objective and strategy identity through its parent race;
- strategy digest;
- source identity;
- machine-template digest;
- certification and machine IDs;
- durable child-job IDs;
- validation profile digest;
- artifact and proof references;
- score components;
- rejection reason;
- selected flag;
- verified cleanup truth.

Restart or retry uses the same deterministic per-candidate certification idempotency key. Existing certification, machine, and job identities are adopted rather than duplicated.

## Acceptance and scoring

A candidate is eligible only when common validation passed, evidence is complete, destruction succeeded, final absence is positively verified, and the source remained protected.

Accepted candidates are ordered lexicographically:

1. correctness, higher first;
2. security and policy compliance, higher first;
3. reproducibility, higher first;
4. regression risk, lower first;
5. maintainability, higher first;
6. change size, lower first;
7. resource cost, lower first;
8. candidate ID, ascending, as the final deterministic tie-breaker.

A race may produce exactly one winner or no winner. A passing candidate with unresolved cleanup is rejected. One provider or candidate failure cannot falsify another candidate's result.

## Preservation and cleanup

Certification captures candidate evidence and performs stop and destruction through the shared machine service. The race evidence index preserves selected, rejected, and failed candidate references according to the request's preservation policy. Cleanup failures are reported independently and never converted into success.

The evidence index is bounded to one MiB, canonically redacted, content-addressed through the existing artifact authority, and explicitly records that no merge or deployment was performed.
