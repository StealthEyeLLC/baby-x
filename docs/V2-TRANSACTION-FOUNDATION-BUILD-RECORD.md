# Baby-X V2 Transaction Foundation Build Record

## Baseline and workspace

- Repository: `StealthEyeLLC/baby-x`
- Frozen rollback branch: `build/baby-x-god-mode-v1`
- Frozen rollback commit/tree: `b8dcc150ddc175b2ad00099df405b8a3bf0e843a` / `2045a746e0c6d928cf3354fd0ef9544918fbf514`
- Certified v1 implementation commit/tree: `ec6a955983753e30e4ed35bd3cceae348737bd6a` / `d56f37dffcfb079151258aa47a7c9d19294d3ba0`
- V2 branch: `build/baby-x-transactional-tool-fabric-v2`
- Isolated workspace: `/var/lib/baby-quirt/workspaces/baby-x-transactional-tool-fabric-v2/baby-x`
- Protected snapshot: `babycert/base/noble@golden-v1`, GUID `9351137475418520293`, creation TXG `53`
- Phase-0 gate: Node `v24.18.0`, npm `11.16.0`, 139/139 tests passed, build/lint/shell syntax/diff check passed.
- Baby Quirt discovery: `baby-quirt` `0.1.0`, protocol `QRT1/1.0.0`, 54 operations; durable shell/exec, job, file, artifact, release/delivery, and Git verification families are available.

## Existing authority map

| Authority | Exact implementation | V2 integration rule |
| --- | --- | --- |
| Canonical serialization and atomic state | `runtime/src/core.ts` (`canonicalize`, `sha256`, `AtomicStore`) | Reuse canonical serialization and atomic per-record writes; derived transaction indexes remain reconstructable. |
| Durable execution and reconciliation | `runtime/src/core.ts` (`JobManager`, `JobRecord`, `reconcile`, `reconcileRunning`, `cancel`, stream reads) | Transaction execution submits only through this job authority. Process absence becomes `lost`, never fabricated exit zero. |
| Machine durable model and events | `runtime/src/machines/schemas.ts`, `states.ts`, `store.ts` | Reuse strict normalization, expected-sequence transitions, append-only digest-chained events, leases, bounded scans, and index repair patterns. |
| Machine identity and policy confinement | `runtime/src/machines/identity.ts` | Reuse provider ID, source/clone roots, exact owner binding, option-injection rejection, path confinement, and redacted environment conventions. |
| Machine lifecycle | `runtime/src/machines/service.ts`, `execution.ts`, `destruction.ts`, `recovery.ts` | Transactions coordinate `create/start/exec/stop/destroy/reconcile`; no direct ZFS, nspawn, PID, mount, or cleanup authority. |
| Machine provider/readback | `runtime/src/machines/disposable.ts`, `manager.ts`, `observe.ts` | Remain private beneath the machine service; transaction code must not import them. |
| Artifact authority | `runtime/src/artifacts/manager.ts` | Candidate patches, archives, manifests, and evidence are registered and content-addressed through `ArtifactManager`. |
| Receipt/proof authority | `runtime/src/core.ts` (`BabyXProof`, `createProof`) and `runtime/src/proof/*` | Transaction evidence references existing proofs; no new proof or receipt format. |
| Certification authority | `runtime/src/certification/service.ts` | Certification remains the sole pass/fail certification authority and consumes machine/jobs/artifacts. |
| Execution policy | `runtime/src/policy/execution.ts` | `decideExecutionPolicy` is the sole environment-class decision and is evidence-digested; it does not execute. |
| Candidate racing | `runtime/src/racing/service.ts` | Existing `CANDIDATE_RACE_SCHEMA_VERSION` and deterministic scoring remain compatible and otherwise unchanged. |
| Public runtime registry | `runtime/src/operations/definitions.ts`, `runtime/src/core.ts` | Add operations to the one catalog and route them through one lazily initialized transaction-service promise. |
| Gateway | `gateway/src/catalog.js`, `client.js`, `server.js`, `tool.js` | Gateway continues dynamic forwarding through the single `call_x` tool; no duplicate operation catalog or transaction controller. |
| Build and strict lint | `scripts/build.mjs`, `scripts/lint.mjs`, `tsconfig.base.json`, `package.json` | Node 24.18.0 transform build, strict syntax checks, and current full-suite glob remain controlling. |
| Tests | `runtime/test/*.test.mjs`, `runtime/integration/*.test.mjs`, `runtime/acceptance/*.test.mjs`, `gateway/test/gateway.test.mjs` | Add focused transaction unit/integration/recovery/acceptance files without skipping existing suites. |

## Frozen integration decisions

1. V2 adds one `TransactionService`; it owns transaction truth and coordination only.
2. The transaction store uses authoritative per-record files, per-transaction event logs, controller leases, and reconstructable bounded indexes.
3. Code mutation is submitted as machine-targeted durable jobs. Transaction code never spawns processes.
4. Candidate production uses deterministic Git plumbing inside the disposable machine and registers every durable output through the artifact authority.
5. `COMMITTED` means candidate durability plus complete verified cleanup; it never means merge, deployment, release activation, or Git-ref update.
6. Startup recovery is bounded, idempotent, and child-truth-driven. Insufficient identity becomes `AMBIGUOUS` or `RECOVERY_REQUIRED`.
7. Unknown newer schemas and provider contracts fail closed; v1 durable records are read-only compatible and are never silently rewritten.
8. The frozen rollback identities and protected snapshot identity are compile-time manifest constants, never runtime inputs.

## Phase-0 evidence

- Frozen local/upstream comparison: `0/0`, clean.
- Frozen remote branch independently resolved to the exact evidence commit and tree.
- Evidence commit has the certified implementation as direct parent and changes only `docs/FINAL-DISPOSABLE-CERTIFICATION.md`.
- Checkpoints E through final form the expected linear ancestry and every listed tree matches.
- Prior disposable certification resources are positively absent; the protected snapshot remains exact.
- No tracked private-key block or credential-path candidate was detected.
- New V2 branch was created and normally pushed from the exact frozen evidence commit; independent remote comparison is identical.

## Prohibited implementation boundaries

No transaction source may import provider, ZFS, nspawn, direct child-process, merge, deployment, release, or production-mutation authority. No second scheduler, worker, artifact store, proof store, cleanup mechanism, or operation catalog is permitted.
