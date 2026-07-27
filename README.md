# Baby-X

Baby-X is StealthEye's authenticated owner-authorized execution and experimentation substrate. This repository contains the source runtime and private gateway; this repair branch is **not deployed**.

The private gateway exposes one public MCP tool, `call_x`. The gateway authenticates and forwards signed QRT1 envelopes. It does not schedule, execute, persist, reconcile, or own provider lifecycle.

The runtime provides bounded host execution, durable jobs and streams, compare-and-swap file operations, durable artifacts, systemd and diagnostic providers, retroactive specification, disposable machine lifecycle, certification, and deterministic candidate racing.

Disposable machine lifecycle is owned exclusively by `DisposableMachineService`. Legacy direct `machinectl` catalog routes, `babyx.machine.raw`, unsupported PTY entries, and incomplete artifact-upload lifecycle entries are not public operations.

## Sources of truth

- `runtime/src/operations/definitions.ts` — executable public operation catalog.
- `babyx.describe` — catalog version, digest, limits, and runtime identity.
- `docs/CANONICAL-TRUTH.md` — truth precedence and authority ownership.
- `docs/BABY-X-CONSTITUTION.md` — architectural direction.
- `docs/FINAL-DISPOSABLE-CERTIFICATION.md` — immutable evidence for its exact historical subject only.

## Build and test

Use exactly Node.js 24.18.0:

```bash
npm ci
npm run build
npm test
npm run lint
```

Large output belongs in bounded durable streams or artifacts rather than inline model context.
