# Baby-X Canonical Repair Evidence

Status: **implementation verified; source-only; not deployed**

## Exact subject

- Repository: `StealthEyeLLC/baby-x`
- Branch: `build/baby-x-canonical-repair-v1`
- Audited base commit: `b8dcc150ddc175b2ad00099df405b8a3bf0e843a`
- Audited base tree: `2045a746e0c6d928cf3354fd0ef9544918fbf514`
- Verified implementation commit: `1b68ca6808716385141537296a8a204486d3d54a`
- Verified implementation tree: `0b76bb4767817769a27c6a38863cd51874229892`
- Repair commits above audited base: `6`
- Changed tracked paths relative to audited base: `24`

This document is evidence for the exact implementation identity above. The commit adding this document must differ from the implementation commit by this file only.

## Verified checkpoints

| Checkpoint | Commit | Tree | Purpose |
|---|---|---|---|
| 1 | `7df9ce6824a75942f4586b5dc722430feff80e30` | `fa949ce238e71376588445d7ceee1c53a76f7af9` | Repair false contracts, durable job safety, file CAS, catalog/dispatcher mismatch, and machine-authority bypasses. |
| 2 | `be340900242367d64a1483d3da6d92f682b67a0a` | `d942bb440c59035439088cf116da26239908bf76` | Bound gateway HTTP bodies and QRT1 frame accumulation before concatenation. |
| 3 | `6e174b376d1537755d666337b940c806ccad8fe1` | `374697e9d81ad2009581979d6dbf0c47d7b8ef21` | Publish finite operation schemas and execution metadata with a deterministic catalog digest. |
| 4 | `a74d0621d027383b2605beca068105ecc18fa4d7` | `86981606832a4f5f56cb691be76512bd4f7250bf` | Isolate artifact, certification, and racing records; add bounded evidence reads and corruption isolation. |
| 5 | `1b68ca6808716385141537296a8a204486d3d54a` | `0b76bb4767817769a27c6a38863cd51874229892` | Consolidate canonical truth and remove unused duplicate facades. |

## Audit findings closed

- `babyx.spec.validate` performs structural validation instead of unconditional success.
- `babyx.job.wait` waits or polls until terminal state or bounded timeout.
- Catalog and dispatcher agree; artifact verification is reachable; unavailable operations are not advertised.
- Disposable machine lifecycle has one public authority: `DisposableMachineService`.
- Durable job identity is reserved before spawn and failed spawn state is persisted.
- Cancellation re-observes process identity and preserves terminal immutability.
- Atomic core persistence fsyncs files and parent directories.
- Gateway request bodies and gateway/runtime frames are rejected before unbounded concatenation.
- Public operation contracts include finite schemas, risk, idempotency, errors, cancellation, restart, limits, authority, and postconditions.
- Artifact, certification, and race metadata use per-record durable storage with corruption isolation and legacy import.
- Job, file, artifact, specification, generic object, certification, and race reads are bounded or paginated.
- File patching is compare-and-swap and atomic at exact offsets.
- Canonical documentation defers generated facts to source, and unused duplicate facades are removed.

## Verification

The implementation gate used exactly Node.js `24.18.0` and produced:

- tests: `155 passed, 0 failed, 0 cancelled, 0 skipped, 0 todo`;
- lint: passed;
- shell syntax: passed;
- `git diff --check`: passed;
- test-log SHA-256: `d8be74bbb2c060078b63d7da258e64b027a27b8a0613741694f53cd8ee2b0b00`;
- lint-log SHA-256: `7dcca0967482356ad6bc8abb34386632e68f0057b72b8400c118b4ce37c61cd9`.

Negative and recovery coverage includes malformed specifications, real job waiting, failed spawn reservation, terminal cancellation replay, PID identity conflict, compare-and-swap patch conflict, unknown/removed operations, oversized HTTP bodies and QRT1 frames, bounded reads, paginated listings, and isolated corrupt records.

## Non-mutation statement

No merge, deployment, release activation, service restart, production configuration change, OAuth change, DNS change, firewall change, systemd change, snapshot mutation, or protected-source mutation was performed. The audited base and historical certification evidence remain unchanged.
