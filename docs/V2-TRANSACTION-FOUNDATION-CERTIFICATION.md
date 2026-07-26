# Baby-X V2 Transaction Foundation Certification

## Result

**PASS — BABY-X V2-C COMPLETE AND CERTIFIED**

The certified implementation is commit `6e268c39f689b3c2c36ebcd2c3d40d4136e4e313`, tree `3ef05a48141b9ac8ba0efe058ea9dd6bac687911`, on `build/baby-x-transactional-tool-fabric-v2`. The certification record is `cert_17728207eb6e45c482abfee375bdb54a`, state `SUCCEEDED`, success `true`. This document is a later evidence artifact and is not the certified source subject. The exact evidence commit and tree are resolved after this document is committed and pushed in the byte-identical host audit ledgers and the final independent report; this avoids an impossible self-reference inside the commit that contains the document.

## Identity reconciliation

Two values in the corrective mission text did not resolve to the authoritative repository:

- Supplied V2-A commit `3ca3f2da978ea4b16de5eddc1512baf8210f168d` is absent locally and GitHub reports no such commit. V2-B's actual direct parent is `b36050849f33380326a6c8de62694869a759a418`, tree `39e475f6bd05c99352ee4a799f787dada90ec936`, with the required message.
- Supplied tree `9e996f9c3eb39222d5a41919635def3c89604c0a` for commit `037672fc...` differs from the authoritative Git tree `8e996f9c3eb39222d5a41919635def3c89604c0a`.

The current branch ancestry and independently fetched GitHub objects control. No history was rewritten.

## Certified and evidence identities

- Repository: `StealthEyeLLC/baby-x`
- Branch: `build/baby-x-transactional-tool-fabric-v2`
- Certified implementation commit: `6e268c39f689b3c2c36ebcd2c3d40d4136e4e313`
- Certified implementation tree: `3ef05a48141b9ac8ba0efe058ea9dd6bac687911`
- Certified implementation parent: `d927d538b4e6827dac9f7440f0423ab1eaa98f24`
- Evidence commit: the later documentation commit containing this file; exact commit/tree resolved post-push in `/var/lib/baby-x/v2-transaction-foundation-ledger.json` and `/var/lib/baby-x/v2-transaction-foundation-summary.json`.
- Node: `v24.18.0`
- npm: `11.16.0`

| Checkpoint | Commit | Tree | Parent | Message |
| --- | --- | --- | --- | --- |
| frozenV1Evidence | `b8dcc150ddc175b2ad00099df405b8a3bf0e843a` | `2045a746e0c6d928cf3354fd0ef9544918fbf514` | `ec6a955983753e30e4ed35bd3cceae348737bd6a` | docs: record final disposable certification evidence |
| frozenV1Implementation | `ec6a955983753e30e4ed35bd3cceae348737bd6a` | `d56f37dffcfb079151258aa47a7c9d19294d3ba0` | `1ce31d84bda0c2f632a41592cfb05d6275d6fde4` | fix: settle launch jobs after certification teardown |
| v2a | `b36050849f33380326a6c8de62694869a759a418` | `39e475f6bd05c99352ee4a799f787dada90ec936` | `b8dcc150ddc175b2ad00099df405b8a3bf0e843a` | feat: define Baby-X core compatibility manifest |
| v2b | `80d9c7b68f1bc32960cd0041c746379ce67e8eca` | `a03c5fac6f569fa8eca8193970cc8b61e12bce50` | `b36050849f33380326a6c8de62694869a759a418` | feat: add durable transaction service |
| v2cInitial | `8a4403bd38d1fbadaa0a69a8856b2b5271bae7a3` | `823ba8f143ad346d03ec3fbe4c0323eb44f4d735` | `80d9c7b68f1bc32960cd0041c746379ce67e8eca` | feat: add disposable code transactions |
| durableJobCorrection | `037672fcfb4ae5c6ca518ef3dc3137cd6e8eef19` | `8e996f9c3eb39222d5a41919635def3c89604c0a` | `8a4403bd38d1fbadaa0a69a8856b2b5271bae7a3` | fix: wire code transactions to durable jobs |
| rollbackExecutionCorrection | `fcb60bd22bee81c63fe7f28082d837efae07ea79` | `6deaafe431e01a9f6e31d3d817325aa1a1fea9a5` | `037672fcfb4ae5c6ca518ef3dc3137cd6e8eef19` | fix: restore transactional rollback and execution contracts |
| exactChildAdoptionCorrection | `d927d538b4e6827dac9f7440f0423ab1eaa98f24` | `3682b001491ed739b45a6e6d7fcb3a814d262fc3` | `fcb60bd22bee81c63fe7f28082d837efae07ea79` | fix: adopt strict machine jobs in code transactions |
| uniqueArgvCorrection | `6e268c39f689b3c2c36ebcd2c3d40d4136e4e313` | `3ef05a48141b9ac8ba0efe058ea9dd6bac687911` | `d927d538b4e6827dac9f7440f0423ab1eaa98f24` | fix: preserve unique transaction execution argv |

## Corrected defects

### Transaction-to-Machine execution contract

The transaction driver sent unsupported top-level `transactionBinding`. The strict Machine Service validator correctly rejected it. The correction removes that field, keeps unknown-property rejection strict, and retains provenance in the transaction record, event/request digests, exact machine/job bindings, idempotency identities, safe reasons, artifacts, and receipts. No alternate execution path or direct process launch was added.

Real-authority acceptance further proved that exact child adoption must use supported generic Machine Service evidence. The final implementation adopts a child only when owner, machine, and transaction idempotency identity match; conflicting bindings remain ambiguous. Internal bounded helpers use the protected base image's Python interpreter, and generated argv preserve strict uniqueness. These are additive completion of the same execution-contract repair, not feature expansion.

### Rollback routing

Public rollback attempted `RECOVERY_REQUIRED -> ROLLBACK_REQUESTED`, but the strict transition table omitted that one route. The correction adds only that transition and then uses the existing `ROLLBACK_REQUESTED -> ROLLING_BACK -> ROLLED_BACK` path. Expected sequence, owner authority, idempotency, event-chain continuity, lease safety, job reconciliation, cleanup truth, and terminal-state rules remain intact.

## Historical stranded recovery

Transaction `tx_74cffafeca7048939f22b27209972b71` began at `RECOVERY_REQUIRED` sequence 9 with desired state `COMMITTED`; machine `mx_f9c8d7c3ae8f45e0b5e472313bab99eb` was `DEGRADED/CLONE_ONLY` sequence 7. The original error was `machine_invalid_request` for unsupported `transactionBinding`.

Using the remotely anchored corrected runtime, public rollback set desired state `ROLLED_BACK` and requested cleanup. Machine Service initially retained an unmount obstruction caused by exact Baby audit jobs holding the clone console. Those jobs exited or were reconciled through Baby; Machine Service then destroyed the clone and positive absence was verified. Final truth:

- Transaction: `ROLLED_BACK`, sequence `23`, terminal `true`.
- Machine: `DESTROYED/ABSENT`, sequence `11`.
- Dataset, mount, root, machinectl identity, and exact nspawn process: absent.
- Same rollback idempotency replay: existing result; no duplicate destruction.
- Protected snapshot: unchanged.

## Exact source input

- Source artifact: `c17391f6-cd8f-4307-b0aa-93d15bf85630`
- Archive SHA-256: `0e8fc907ea11a25aae7673c38b999223ce56a74cf2eef6e71182f14a36ad7cf4`
- Manifest SHA-256: `f12b47c4cffd020470e01df9809aa2d51399f5fc22745d7ab55c7f9c43a81ad5`
- `package-lock.json` SHA-256: `b18a36dd0bfe0a6c7543e6b7532ebdefe556dc1b40f26ca39be1613b5c307c54`
- Reproduced Git tree: `3ef05a48141b9ac8ba0efe058ea9dd6bac687911`
- Git metadata, credentials, deploy keys, and raw secrets: absent.

## Regression coverage and final repository gate

The regression suite proves public rollback from `RECOVERY_REQUIRED`, exact sequence and owner enforcement, replay/conflict behavior, error preservation, event continuity, obstruction recovery, exact child-job adoption, strict request acceptance, `transactionBinding` absence, unknown-field rejection, response-loss adoption, and strict argv uniqueness.

Final pinned gate:

- Build: passed
- Strict lint: passed
- Tests: `213/213` passed; `0` failed; `0` cancelled; `0` skipped; `0` todo
- Test duration: `2387.89012` ms
- Shell syntax: `6` tracked scripts passed
- `git diff --check`: passed
- Tracked-secret scan: passed
- Authority-boundary scan: passed
- Worktree: clean; local/upstream `0/0`

## Five real-authority acceptance scenarios

| Scenario | Transaction | Final transaction | Machine | Candidate tree | Special proof |
| --- | --- | --- | --- | --- | --- |
| 1 — no-op | `tx_c5c7648e191740848b57300012e44302` | `COMMITTED` | `mx_4c581806684840d38a797feb80d7d7c4` / `DESTROYED` | `3ef05a48141b9ac8ba0efe058ea9dd6bac687911` | none |
| 2 — changed candidate | `tx_730ad1ac1d9345708662ca656ec32fb0` | `COMMITTED` | `mx_fc979e5d27fa4943b98e12c3fd255b64` / `DESTROYED` | `d2b517c29fce1bb5b361e2ecf4164b1d6eb5692e` | `docs/V2C-ACCEPTANCE-FIXTURE.md` |
| 3 — validation failure | `tx_267175d427f24d16924d0aedc0e5f95a` | `ROLLED_BACK` | `mx_6368b616c80b4735b99f318c2cab83c6` / `DESTROYED` | none | controlled exit 1 |
| 4 — restart recovery | `tx_8f6f938a18ba42018692e403778299db` | `COMMITTED` | `mx_4d963cf79e504a2c91f4409f88bc9c99` / `DESTROYED` | `3ef05a48141b9ac8ba0efe058ea9dd6bac687911` | exact child IDs reused |
| 5 — cleanup obstruction | `tx_4e460f1c1322473c904cfa932b199cad` | `ROLLED_BACK` | `mx_34d8adb0a8d949f5b37327f6dc2db6b6` / `DESTROYED` | none | mount-busy RECOVERY_REQUIRED, then canonical recovery |

All scenarios used the real Transaction Service, strict Machine Service, Durable Job Authority, Artifact Authority, durable records, disposable machines, canonical cleanup, network-none policy, no credentials, bounded resources, terminal jobs, and positive absence.

Acceptance-wide audit: `20` transactions, `19` machines, `75` related jobs, and `94` artifacts. Missing artifacts: `0`; bad digests: `0`; unresolved resources: `0`.

## Certification

- Certification ID: `cert_17728207eb6e45c482abfee375bdb54a`
- Profile: `baby-x-v2-transaction-foundation-certification` version `1`
- Profile digest: `482a7d26d5876f82e3b4195f995a193201bc1e88fa6c320744651faa11baaec8`
- State: `SUCCEEDED`
- Success: `true`
- Machine: `mx_ea6a723f42fc4f07a79fc8091898dbaf` / `baby-x-v2c-cert-6e268c39c`
- Evidence-index artifact: `7caae68a-a1f5-436e-957f-7b8b2837900b`
- Evidence-index digest: `f965783b148f3b5a8ac33f214425b895620d8532325292c07dbc995217ba0495`
- Diagnostic artifact: `7a811ad7-e14b-4bd7-b8cf-04eeb4930de9`
- Artifact audit: `39` checked, `0` missing, `0` bad digest
- Cleanup: stop `succeeded`, destroy `succeeded`, absence verified `true`, source preserved `true`

| Required stage | Durable job | State | Exit |
| --- | --- | --- | --- |
| `exact-source-materialization` | `08fbe051-3461-4653-b29d-18594f7e14b6` | `passed` | `0` |
| `exact-dependency-materialization` | `0ea546fa-6232-47e1-b5cb-407f98bcba71` | `passed` | `0` |
| `source-digest-verification` | `30da860e-29ec-48d8-93bb-4ab9d442aa64` | `passed` | `0` |
| `build` | `1ac20231-0e33-45d7-ace4-86444b1dc6d3` | `passed` | `0` |
| `strict-lint` | `b01a9517-38b2-4e05-8fab-14f6af8cdd88` | `passed` | `0` |
| `transaction-unit-tests` | `51b2c3fd-b4a6-4dcf-8dc4-c8155fc0fe24` | `passed` | `0` |
| `transaction-integration-tests` | `e7cd4750-c92d-48ca-a2c6-916592eecff3` | `passed` | `0` |
| `transaction-recovery-tests` | `940b0392-46bd-4790-9c61-d8dac128306e` | `passed` | `0` |
| `machine-execution-contract-regressions` | `7b39bf2e-bb5e-49b9-9462-7fe7aa50ceda` | `passed` | `0` |
| `rollback-from-recovery-required-regressions` | `959ecb75-e2ad-4774-99be-23a6d92054f9` | `passed` | `0` |
| `real-authority-noop-acceptance` | `30c3bddd-ce0f-4859-82cd-496122e56670` | `passed` | `0` |
| `real-authority-changed-candidate-acceptance` | `770b7ea1-b312-41e0-8bab-ea8e2c3cda6f` | `passed` | `0` |
| `real-authority-validation-failure-rollback` | `1603950d-c4d0-42d3-9f20-02527281f689` | `passed` | `0` |
| `real-authority-restart-recovery` | `8dfc82d9-1005-4487-a4d8-a417cf1d0075` | `passed` | `0` |
| `real-authority-cleanup-obstruction-recovery` | `463e0525-8344-42e1-ade3-7bcae5f90d54` | `passed` | `0` |
| `complete-repository-test-suite` | `84bf8546-2b06-4f74-b08a-98cd8197242c` | `passed` | `0` |
| `authority-boundary-scan` | `e1bc93ae-a963-41c7-b588-451641bf7062` | `passed` | `0` |
| `candidate-tree-determinism-and-evidence-audit` | `12f96733-968d-43e5-98e5-5324034a4582` | `passed` | `0` |

All 18 required stages passed. All 19 certification jobs are terminal. The launch job truthfully ended `lost/process-absent` after destruction and was not relabeled successful. The certification machine is `DESTROYED/ABSENT`; dataset, mount, root, machinectl identity, and exact nspawn process are absent.

## Protected baseline and authority boundaries

- Frozen v1 evidence: `b8dcc150ddc175b2ad00099df405b8a3bf0e843a` / `2045a746e0c6d928cf3354fd0ef9544918fbf514`
- Frozen v1 certified implementation: `ec6a955983753e30e4ed35bd3cceae348737bd6a` / `d56f37dffcfb079151258aa47a7c9d19294d3ba0`
- Protected snapshot: `babycert/base/noble@golden-v1`, GUID `9351137475418520293`, TXG `53`
- Frozen branch, workspace, base dataset, and snapshot: unchanged

Transaction Service owns transaction truth and coordination only. Machine lifecycle remains under Machine Service; command execution remains under Durable Job Authority; artifacts remain under Artifact Authority; certification remains under Certification Service. Transaction code contains no direct ZFS, nspawn, mount, PID, child-process, merge, deployment, release, or Git-ref authority.

## Deployment boundary and remaining scope

- Merged: false
- Deployed: false
- Release activated: false
- Production mutated: false

Later transaction kinds, later tool/skill fabric layers, candidate publication or merge authority, deployment, and release activation remain outside V2-C.

## Machine-readable evidence

The public-safe canonical ledger is written byte-identically to:

- `/var/lib/baby-x/v2-transaction-foundation-summary.json`
- `/var/lib/baby-x/v2-transaction-foundation-ledger.json`

Pre-commit canonical ledger digest: `2da6a3985888d4306eaa3f3ae3387b404fc882cd1f64e1d73b2b48009e3feea9`. After this documentation commit is pushed, the two mirrors are regenerated with the exact evidence commit/tree and a final canonical digest.
