# Baby-X Operation Contract

Status: **generated-source governed**

The public gateway exposes exactly one MCP tool: `call_x`. `call_x` forwards only operations present in the runtime catalog exported from:

- `runtime/src/operations/definitions.ts`
- `OPERATION_DEFINITIONS`
- `OPERATION_NAMES`
- `OPERATION_CATALOG_VERSION`

The runtime catalog, not this prose document, is the executable source of truth. `babyx.describe` returns the current catalog, its version, and a deterministic SHA-256 digest.

## Contract requirements

Every public operation definition includes:

- operation name, family, and version;
- mutation truth;
- risk classification;
- idempotency behavior;
- a closed top-level input schema;
- bounded transport and inline-result limits;
- documented errors;
- cancellation and restart behavior;
- authority provider;
- post-action verification truth;
- required postconditions; and
- receipt version.

Unknown operations fail before dispatch. The catalog must contain no duplicate names and may not advertise an unavailable handler.

## Authority boundaries

The catalog does not create a second authority merely by exposing a name.

- Disposable machine lifecycle operations route through `DisposableMachineService`.
- Certification delegates machine lifecycle, durable jobs, and artifacts to their existing authorities.
- Candidate racing delegates candidate execution to certification.
- Artifacts are owned by `ArtifactManager`.
- Durable jobs are owned by `JobManager`.
- The gateway authenticates and forwards; it does not schedule, execute, persist, or reconcile work.

Legacy direct `machinectl` catalog entries and the unrestricted `babyx.machine.raw` route are not public operations. Unsupported PTY and incomplete artifact-upload lifecycle entries are not advertised.

## Raw operations

Raw operations remain available only for provider families whose raw path is intentionally implemented. They still pass through authenticated QRT1 transport, finite input schemas, bounded frames, and the runtime executor. Raw operations do not bypass a specialized durable authority.

## Bounded results

Inline frame and result sizes are bounded. Large output belongs in durable job streams or artifacts. List operations are paginated and bounded. Artifact downloads and job stream reads require an offset and bounded limit.

## Change procedure

A catalog change is complete only when:

1. the handler exists;
2. the operation definition is finite and truthful;
3. authority ownership remains singular;
4. negative tests cover malformed, unknown, unavailable, and oversized requests;
5. the full repository gate passes; and
6. the catalog digest changes deterministically.
