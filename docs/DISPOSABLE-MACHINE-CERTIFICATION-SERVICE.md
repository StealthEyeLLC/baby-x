# Disposable Machine Certification Service

**Status:** Checkpoint F public contract. The certification authority is implemented as a consumer of the shared Disposable Machine Service.

## Authority boundary

Certification owns certification profiles, acceptance truth, evidence indexing, retention policy, and final certification status. It does not clone datasets, launch machines, supervise commands, stop processes, or destroy resources directly.

Generic lifecycle is delegated exclusively to:

- `babyx.machine.create`
- `babyx.machine.start`
- `babyx.machine.exec`
- `babyx.machine.reconcile`
- `babyx.machine.diagnostics`
- `babyx.machine.stop`
- `babyx.machine.destroy`
- `babyx.machine.expire`

Command execution remains under the existing durable-job authority. Evidence remains under the existing artifact authority.

## Public operations

- `babyx.certification.describe`
- `babyx.certification.run`
- `babyx.certification.resume`
- `babyx.certification.get`
- `babyx.certification.list`
- `babyx.certification.cleanup`

`run` is idempotent by normalized request digest. `resume` adopts persisted machine and durable-job identities instead of submitting duplicate work. Read operations preserve owner visibility boundaries.

## Certification request

Checkpoint G additionally binds the deterministic automatic execution-policy decision and digest to every certification record and evidence index. Certification remains disposable by mandatory policy.

A request binds:

- exact source commit;
- exact source tree;
- protected source snapshot and optional expected GUID;
- a machine template accepted by the public machine-create contract;
- a versioned certification profile;
- ordered dependency, build, lint, unit, integration, and acceptance steps;
- preservation and expiration policy.

Machine templates cannot provide their own source, owner, certification parent, expiration, or start-immediately fields. Certification binds those fields deterministically.

## Truth model

Certification state is distinct from test and cleanup truth.

A certification succeeds only when all of the following are true:

1. every required profile step passed;
2. bounded diagnostic evidence was captured through the machine artifact authority;
3. a bounded redacted certification evidence index was stored through the artifact authority;
4. stop succeeded through the machine service;
5. destroy succeeded through the machine service;
6. final machine status positively reported `ABSENT`;
7. the protected source remained verified by the destruction authority.

A passing test result never overrides failed evidence collection, stop failure, destroy failure, or contradictory cleanup readback. Unresolved cleanup produces `RECOVERY_REQUIRED`, not success.

## Retention and recovery

Failure evidence may be preserved explicitly. Preserved certifications retain their machine through the normal machine-service lifecycle and may later be expired and cleaned by `babyx.certification.cleanup`. Cleanup never bypasses sequence checks, leases, ownership proofs, stop, destruction, or positive absence verification.

Persisted running steps retain their durable job IDs. After a runtime restart, `resume` reads the existing job and machine records and continues without duplicate execution.

## Evidence index

The public-safe evidence index is bounded to one MiB and uses canonical redaction. It binds:

- source commit, tree, snapshot, and expected GUID;
- certification ID and profile digest;
- machine ID and lifecycle sequence;
- durable child-job IDs and step results;
- diagnostic, stream, cleanup, and proof references;
- bounded machine events;
- test truth and cleanup truth.

Raw secrets are rejected from certification machine templates. Secret-bearing machine environment entries must use redacted secret references.

## Historical primitive evidence

[`NSPAWN-CERTIFICATION-3FBDAD8.md`](NSPAWN-CERTIFICATION-3FBDAD8.md) records the earlier low-level disposable primitive certification. It is historical evidence, not the post-F generic service certification. Final service certification must use the public certification and machine operations documented here.
