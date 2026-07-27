# Service Credential Bootstrap Certification — Checkpoint K.5

## Certification decision

Checkpoint K.5 is certified for repository implementation and disposable-machine execution at the exact source identity below. This certification does not deploy Baby-X, create production credentials, install production paths, restart production services, change Caddy, stage a release, arm rollback, or cut over traffic.

The certification result is `SUCCEEDED`. The disposable machine, its ZFS clone, its root path, and its process were positively verified absent after evidence capture.

## Certified source identity

- Repository: `StealthEyeLLC/baby-x`
- Branch: `build/baby-x-self-reconciling-release-appliance-v1`
- Commit: `8e1b33bb2c84a1e1680b918b137847e4a0fcbb25`
- Tree: `17552e2a42a6bf5c04b289a759071712ac681afb`
- Commit subject: `test: certify service credential bootstrap authority`
- Protected source snapshot: `babycert/base/noble@golden-v1`
- Snapshot GUID: `9351137475418520293`
- Snapshot creation TXG: `53`
- Canonical source-documentation digest: `86b963a38c3e96b618031f70c4e532c52896bf09d9f9320ad8b8c69a76d1bc6f`
- Canonical source-documentation file count: `45`

The documentation digest above is the digest of the certified source commit before this evidence-only document was added. It is intentionally not a digest of the later evidence checkpoint, avoiding a self-referential documentation hash.

## Pre-certification quality gate

The exact certified source passed:

- pinned Node.js `v24.18.0` build and lint;
- focused service-credential contract, bootstrap, issuer, activation, and acceptance tests;
- release-focused tests;
- Checkpoint K acceptance;
- the complete repository suite: `695/695` passing;
- shell syntax checks for all eight tracked shell scripts;
- operation catalog count `267` with zero duplicates;
- canonical documentation-digest verification;
- packaged launcher byte comparison and executable-mode verification;
- current-tree and Git-history secret scans, with zero complete private-key blocks in Git history;
- linear-history verification with zero merge commits in the implementation range and no V2 transactional-fabric ancestry;
- production non-interference checks; and
- protected-snapshot identity readback.

## Disposable certification record

- Certification ID: `cert_8b3adbb8d90d48e08d1ac2e5e4ee3447`
- Certification state: `SUCCEEDED`
- Certification revision: `21`
- Owner principal: `stealtheye-owner`
- Request digest: `c437763a079a7ffba621f1a7b436bbdfe1659e05c663a493403461ee3e3fa696`
- Created: `2026-07-27T08:48:00.948Z`
- Completed: `2026-07-27T08:48:04.934Z`
- Certification profile: `baby-x-k5-service-credential-bootstrap-final-certified@1.0.0`
- Result-file SHA-256: `ffc2b3bcde10e029df5c9b38be003df1793e3da3440d52ced0550cdb49ca699c`
- Evidence status: `complete`
- Evidence index digest: `cad013789c2afac3714a174d512c6c00f19d14540b6192423aa8f7ec249756aa`
- Diagnostic artifact reference: `df79f6bb-009d-4ac3-9dd3-0289c6d5e76a`
- Evidence-index artifact reference: `ebf8e0d9-9279-4cb9-876c-0af81c9f528b`
- Proof references:
  - `926631798ada018fd208c23197e955f643a5f84e017e6983a96f332e8fff59a3`
  - `cad013789c2afac3714a174d512c6c00f19d14540b6192423aa8f7ec249756aa`

## Disposable machine identity and cleanup

- Machine ID: `mx_979d70b0dfe947bfa031db0392c998d6`
- Machine name: `baby-x-k5e-finalcert-8e1b33bb`
- Clone dataset: `babycert/runs/k5e-finalcert-8e1b33bb`
- Clone dataset GUID: `5011933695473172058`
- Clone mountpoint: `/var/lib/machines/baby-x-k5e-finalcert-8e1b33bb`
- Final machine sequence: `19`
- Final persisted state: `DESTROYED`
- Final observed state: `ABSENT`
- Final observation digest: `e7fd1221c93bb4ccbe3becb58ae43191bd5533866475c5a7041d0e008f262ca2`
- Retained cleanup-evidence artifact: `2476e8e7-0f95-42a0-a213-47439910a353`

Positive cleanup predicates were all true:

- machine registration absent;
- exact machine process absent;
- clone dataset absent;
- clone root path absent;
- cleanup completed;
- source snapshot preserved; and
- retained evidence remained readable after destruction.

## Durable certification steps

All required steps completed with exit code zero:

1. `account-uid-binding`
   - phase: `startup`
   - durable job: `10fbd3ac-0081-42f1-9953-316f1b12cc17`
2. `runtime-contract-bootstrap-issuer`
   - phase: `unit`
   - durable job: `45e0b01f-4d93-46d9-9674-00a73272c3dc`
   - result: `61/61` disposable runtime tests passing
3. `real-credential-lifecycle`
   - phase: `acceptance`
   - durable job: `2f53b22c-6bb3-4b1b-a22b-99184070ae40`
4. `secret-and-temporary-cleanup`
   - phase: `security`
   - durable job: `acc2e43f-2cd0-43c1-9b79-538e583c6001`

The disposable runtime test count comprised:

- contract tests: `19`;
- durable bootstrap transaction tests: `18`; and
- issuer/filesystem/identity adversarial tests: `24`.

The host pre-certification gate separately retained the complete activation, acceptance, documentation, installer, packaging, history, and full-suite coverage at the exact source identity.

## Certified credential lifecycle

The public certification result reported:

- schema: `baby-x-k5-disposable-certification-v1`;
- status: `PASS`;
- service profile: `baby-x.production-controller.v1`;
- algorithm: `ED25519`;
- private encoding: `PKCS8_PEM`;
- public encoding: `SPKI_PEM`;
- first generation: `scg-290057aab93fa83351b9c7e8064a4304`;
- second generation: `scg-5b0789ca797d54f2e833e64d474f899f`;
- idempotent replay: verified;
- independent rotation: verified;
- prior generation remained active until successor verification: verified;
- rollback without regeneration: verified;
- revocation state `REVOKED`: verified;
- revocation evidence preservation: verified;
- launcher restarts: `2` verified;
- dry-run materialization with no effects: verified;
- materialization readback: verified;
- private-material exclusion from public materialization: verified;
- temporary credential material absent after the run: verified;
- disposable test root absent after the run: verified; and
- raw private material returned: `false`.

## Service identity binding

The disposable machine established and read back the exact service identity through the durable Job Authority:

- account: `fix-mcp`;
- observed UID: `997`;
- observed GID: `997`;
- reverse UID account: `fix-mcp`; and
- lookup source: `DURABLE_JOB_AUTHORITY_GETENT`.

Forward-name, UID, and reverse-name agreement was required before credential issuance.

## Public fingerprints

Only public-key fingerprints were retained:

- `gateway-authority-public` — `57c9dcb149ddf0fad4f4a069a4f63eae51208e3191f1add148827151f0977935`
- `proof-public` — `4099b64d0e849fee3163a97f2e7a549829b87e9477b9d43275a898525c1642ca`

No private key bytes, private-key environment values, production credential values, or unrelated Quirt authority material entered the certification result, evidence index, Git history, or this document.

## Production non-interference

Certification did not mutate production. The final source and disposable gates verified continued absence of:

- `/etc/baby-x`;
- `/opt/baby-x`;
- `/run/horsey/baby-x.sock`;
- `/etc/systemd/system/baby-x.service`;
- `/etc/systemd/system/baby-x.socket`; and
- `/etc/systemd/system/baby-x-gateway.service`.

The installed Baby Quirt and Baby Quirt MCP release pointers remained unchanged, `baby-quirt.service`, `baby-quirt-mcp.service`, and `caddy.service` remained active, the active Caddy configuration digest remained unchanged, and the protected snapshot retained its exact GUID and creation TXG.

## Certification boundary

This evidence certifies Checkpoint K.5 implementation and disposable execution only. Controlled production migration remains a separate Checkpoint L authority and requires its own current-state preflight, rollback identity, capacity admission, production credential bootstrap, staged release, cutover, observation, and final acceptance evidence.
