# Final Disposable Machine Certification

## Result

Baby X God Mode v1 passed the final disposable-machine certification on 2026-07-25.

- Certification state: `SUCCEEDED`
- Certification success: `true`
- Certification revision: `31`
- Certification ID: `cert_2c7f028ff3a94ff0ba5843a18e1c9659`
- Certified commit: `ec6a955983753e30e4ed35bd3cceae348737bd6a`
- Certified tree: `d56f37dffcfb079151258aa47a7c9d19294d3ba0`
- Certified parent: `1ce31d84bda0c2f632a41592cfb05d6275d6fde4`
- Branch: `build/baby-x-god-mode-v1`
- Repository: `StealthEyeLLC/baby-x`
- Node: `v24.18.0`
- npm: `11.16.0`

The certified subject includes the bounded launch-job settlement correction required to distinguish a transient nspawn teardown race from a genuinely active durable job. It does not weaken the requirement that every related job be terminal before certification success.

## Certification Profile

- Profile ID: `baby-x-corrective-final-disposable-certification`
- Profile version: `7`
- Profile digest: `629cbd209ea736f3c18c3ccd3ebad5b0cfe0b80daa3b91de9e40b16201e5edd0`
- Network mode: `none`
- Machine init: `/usr/lib/systemd/systemd --unit=basic.target`
- Root mode: writable disposable clone
- Source and Node inputs: read-only binds
- Dependency materialization: offline `npm ci`

## Immutable Certification Input

| Identity | SHA-256 |
| --- | --- |
| Source archive | `210073989a868d587c4ac9a36779369111966eddcc8cf114fe041ca7e3daccdc` |
| Dependency input | `2707d9aa3429a5b0c5c9079e97f2d5ced29ef474dc6157f9e2455185263cf4cd` |
| `package-lock.json` | `b18a36dd0bfe0a6c7543e6b7532ebdefe556dc1b40f26ca39be1613b5c307c54` |
| Source manifest | `ceb5eb821f45feaaff18a4b8b2713f22be490f688d0d659a9689e14f6cc328b3` |

The archive was produced from the exact certified commit with `git archive`. The machine received no Git metadata and no network access.

## Protected Source Snapshot

- Snapshot: `babycert/base/noble@golden-v1`
- GUID: `9351137475418520293`
- Creation epoch: `1784751695`
- Creation TXG: `53`
- Final observation: `present-matching`

The protected source snapshot remained unchanged and was not destroyed, replaced, mounted for mutation, or promoted.

## Disposable Machine

- Machine ID: `mx_ccd9437f264c4d8fa70c1e8b03207908`
- Machine name: `baby-x-final-cert-ec6a9559`
- Clone dataset: `babycert/runs/baby-x-final-cert-ec6a9559`
- Root path: `/var/lib/baby-x/machines/baby-x-final-cert-ec6a9559`
- Terminal lifecycle state: `DESTROYED`
- Terminal lifecycle sequence: `29`
- Terminal event time: `2026-07-25T21:29:27.701Z`
- Terminal event digest: `235fdd88a69827b955370bd54b34ebd7fd74965978de2528b6554744bc4e7b55`

The terminal event digest is included in the certification proof references.

## Required Stage Results

All required stages passed in the frozen order with exit code zero.

| Stage | Durable job | Result |
| --- | --- | --- |
| Source and dependency materialization | `1bff66c6-4a99-4ed3-91f0-99a73d08d2e7` | `passed`, exit `0` |
| Build | `58cfd9d6-2d77-4a49-9d9c-ff7f745385e6` | `passed`, exit `0` |
| Lint | `f8b473ae-8d0a-4cba-82f6-63e485a617bb` | `passed`, exit `0` |
| Runtime unit | `f505f1a4-5e08-4d01-b9bd-ec428110f1d7` | `passed`, exit `0` |
| Gateway integration | `b8cbfe03-4f15-4f16-a440-cf9c47d66cd7` | `passed`, exit `0` |
| Runtime integration | `eb0bd14b-7ff0-47ce-9f8f-33c46a02ec86` | `passed`, exit `0` |
| Acceptance | `9c9bf8dd-ebdd-408b-9830-afdc0c7459b8` | `passed`, exit `0` |
| God-mode acceptance | `89935f41-904b-45b5-979e-1e7fc49b81c9` | `passed`, exit `0` |
| Battleground acceptance | `72e6afeb-3259-4641-a286-3a0fad57d5fb` | `passed`, exit `0` |

## Durable Job Terminality

Exactly ten related durable jobs were bound to the certification.

- Nine machine execution jobs completed with exit code zero.
- Launch job `d18dccee-27d3-49b8-9a3e-60984e7f192a` terminalized as `lost` with reconciliation classification `process-absent` at `2026-07-25T21:29:27.714Z` after the machine was destroyed.
- No related job remained `running`.
- No job was relabeled from failure to success.
- The terminal launch classification represents positive post-teardown process absence, not a successful command result.

## Evidence Authority

- Evidence status: `complete`
- Diagnostic artifact: `5ffb900d-26f0-4109-a018-43f7a7723b86`
- Evidence-index artifact: `0de77a7a-55c9-4f3b-9933-dfc99fa8dcf5`
- Evidence-index digest: `9d72402b79d369fdb238469c4e711ac685776cfac63610454017128e2edac64a`
- Artifact references retained: `21`

Proof references:

1. `235fdd88a69827b955370bd54b34ebd7fd74965978de2528b6554744bc4e7b55` — terminal `machine.destroyed` event digest.
2. `9d72402b79d369fdb238469c4e711ac685776cfac63610454017128e2edac64a` — canonical certification evidence-index digest.

## Cleanup and Positive Absence

The certification record reports:

- Stop status: `succeeded`
- Destroy status: `succeeded`
- Absence verified: `true`
- Source preserved: `true`
- Active jobs after teardown: none

Independent post-certification checks verified all of the following:

- `machinectl` entry absent
- owned nspawn process absent
- root mount absent
- root path absent
- clone dataset absent
- protected source snapshot still present with GUID `9351137475418520293`

Final independent result: `POSITIVE_ABSENCE=verified`.

The final observation digest was `2528f016d73810a43a59345480fb202e32d8fed952ad4b8ad6a1d18361f2c86c`.

## Repository Gate

Before the certified run, the exact implementation subject passed:

- Build
- Strict lint
- Shell syntax validation
- `git diff --check`
- Full repository test suite: `139` passed, `0` failed, `0` cancelled, `0` skipped, `0` todo
- Clean local worktree
- Local/upstream branch comparison: `0/0`

A final repository gate is required again after this evidence document is committed.

## Authority and Deployment Boundary

This work used the existing Baby X durable job, disposable machine, artifact, certification, and proof authorities. It did not introduce an alternate scheduler, worker, persistence store, recovery path, artifact authority, or privileged execution lane.

No branch was merged. No release pointer was changed. No production service, package, listener, OAuth configuration, DNS, Caddy configuration, systemd unit, firewall rule, broker policy, or deployment state was changed.
