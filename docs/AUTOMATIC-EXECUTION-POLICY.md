# Automatic Execution Environment Policy

**Status:** Checkpoint G public contract.

The execution policy is a deterministic decision authority. It selects an environment but never executes commands, creates machines, schedules jobs, persists lifecycle state, or creates artifacts.

## Public operations

- `babyx.execution.policy.describe`
- `babyx.execution.policy.decide`

## Decision modes

- `host`
- `workspace`
- `disposable`
- `parallel-disposable`

Every decision returns normalized inputs, ordered rationale, validation policy, cleanup policy, any applicable machine profile, and a stable SHA-256 decision digest.

## Inputs

The policy binds:

- objective type;
- mutation risk;
- dependency uncertainty;
- isolation requirement;
- reversibility;
- required tools and packages;
- source sensitivity;
- reproducibility requirement;
- network requirement;
- expected duration;
- CPU, memory, and disk profile;
- explicit environment constraint;
- candidate-racing eligibility and count;
- absolute machine, duration, and disk bounds.

Unknown properties and overflowing values fail closed.

## Mandatory rules

1. Production activation and host recovery remain host-authoritative.
2. Certification defaults to disposable execution.
3. High or unknown mutation risk defaults to disposable execution.
4. Unknown dependencies or package installation default to disposable execution.
5. Required isolation, required reproducibility, or sensitive source material defaults to disposable execution.
6. Ordinary low-risk, read-only inspection may use a persistent workspace.
7. Parallel disposable execution requires an eligible race, at least two candidates, and aggregate cost compliance.
8. Explicit host or workspace overrides are accepted only when the normalized objective is safe for that mode.
9. Cost bounds are absolute; the policy never silently exceeds them.

## Integration boundary

Checkpoint G integrates policy at the existing certification objective entry point. Each certification record and evidence index binds the exact policy decision and digest. Certification still consumes the Disposable Machine Service and existing durable jobs; the policy does not gain execution authority.

Checkpoint H candidate racing consumes the same pure decision function and binds the decision to each durable race and evidence index. Future objective entry points must do the same. Direct low-level job, machine, artifact, and provider operations remain unchanged.

## Evidence and determinism

Input arrays are deduplicated and sorted before hashing. Equivalent normalized inputs produce the same decision digest. The digest covers the selected mode, rationale, machine profile, validation profile, cleanup policy, and normalized inputs.
