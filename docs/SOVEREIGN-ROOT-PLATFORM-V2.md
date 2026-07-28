# Baby-X Sovereign Root Platform V2

## Authority boundary

The Prompt-1 transactional root authority remains the sole owner of root transaction truth. The Prompt-2 platform is a sidecar coordination and provider-evidence layer. It does not execute commands, own jobs, own machines, own artifacts, own credentials, own deployment, or rewrite Prompt-1 histories.

## Checkpoint A

Checkpoint A adds a deterministic platform description, a strict provider contract, a duplicate-safe registry, bounded live host-capability probes, durable idempotent provider reconciliation records, and four compact public operations:

- `babyx.root.platform.describe`
- `babyx.root.provider.list`
- `babyx.root.provider.get`
- `babyx.root.provider.reconcile`

Only implemented providers are registered: the Prompt-1 root authority, the sovereign platform core, and the live host-capability probe. Later checkpoint providers are registered only when their vertical slices are complete.

Support states are `SUPPORTED`, `DEGRADED`, `UNAVAILABLE`, `EXPERIMENTAL`, `DISABLED`, `REVOKED`, and `FAILED`. A provider probe exception is bounded and reported as `FAILED`; source presence alone never produces `SUPPORTED`.

Provider reconciliation uses append-only sidecar records beneath the Baby-X state root. Replays require the same owner, idempotency key, provider, and observed descriptor digest. Prompt-1 records remain readable and verifiable without migration or mutation.
