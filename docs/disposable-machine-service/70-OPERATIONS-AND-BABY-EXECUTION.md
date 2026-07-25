# Disposable Machine Service — Operations and Baby Execution Guide

## 1. Purpose

This file explains how an implementation tab operates the repository with Baby today and how users and higher-level Baby features will operate the completed service.

It distinguishes:

- current build-time Baby Quirt operations;
- future Baby-X machine service operations being implemented;
- internal service flow;
- troubleshooting and recovery commands.

## 2. Current authorized build environment

The known repository workspace is:

```text
/var/lib/baby-quirt/workspaces/baby-x-god-mode-v1/baby-x
```

The current branch is:

```text
build/baby-x-god-mode-v1
```

The foundation before documentation expansion was:

```text
commit b849e29f4db3c861f97b9911fe45f5ff1790e76a
tree   2a30ec92bb2385e6d06ccc28f3d0af5784ba63e3
```

The Baby Quirt interface exposes durable execution, jobs, files, PTY, artifacts, proof-backed receipts, self-host/release operations, and repository verification. Build tabs must use the single authenticated Baby interface and authorized GitHub path rather than manual SSH or anonymous HTTPS credentials.

## 3. Build-tab opening procedure

A fresh implementation tab should first run Baby discovery, then execute a read-only repository gate.

Conceptual Baby calls:

```text
baby.describe {}
```

Then:

```text
baby.shell {
  shell: "/bin/bash",
  cwd: "/var/lib/baby-quirt/workspaces/baby-x-god-mode-v1/baby-x",
  script: "set -euo pipefail; git branch --show-current; git rev-parse HEAD; git rev-parse HEAD^{tree}; git status --short --branch"
}
```

Use a new idempotency key for each changed script or payload. Reuse a key only for the exact same logical request.

## 4. Required repository inspection

Before editing an active checkpoint, inspect:

```bash
find runtime/src/machines runtime/test runtime/integration runtime/acceptance -type f | sort
sed -n '1,260p' runtime/src/machines/disposable.ts
sed -n '1,260p' runtime/src/machines/manager.ts
sed -n '1,260p' runtime/src/machines/definitions.ts
sed -n '1,260p' runtime/src/execution/executor.ts
sed -n '1,260p' runtime/src/execution/target.ts
sed -n '1,260p' runtime/src/jobs/manager.ts
sed -n '1,260p' runtime/src/state/atomic-store.ts
sed -n '1,260p' runtime/src/state/replay-store.ts
sed -n '1,320p' runtime/src/core.ts
sed -n '1,320p' runtime/src/operations/definitions.ts
sed -n '1,320p' runtime/src/operations/registry.ts
```

Do not assume the plan’s suggested file boundaries already exist. Adapt the implementation to the real tree while preserving responsibilities.

## 5. Editing through Baby

Preferred editing approaches:

1. Use an exact script to create full files or perform deterministic transformations.
2. Use atomic file replacement with expected SHA when the direct file operation is available.
3. Avoid ad hoc partial edits that cannot be verified.
4. Immediately read back changed files and run formatting/type checks.

For large new files, write complete contents to a temporary file and atomically move them into place. Preserve existing mode and directory conventions.

## 6. Running focused tests

Conceptual call:

```text
baby.shell {
  shell: "/bin/bash",
  cwd: "/var/lib/baby-quirt/workspaces/baby-x-god-mode-v1/baby-x",
  script: "set -euo pipefail; npm run build; node --test runtime/test/machine-state.test.mjs"
}
```

For longer tests, use detached execution:

```text
baby.shell {
  shell: "/bin/bash",
  cwd: ".../baby-x",
  detached: true,
  script: "set -euo pipefail; npm test"
}
```

Then:

```text
baby.job.wait { jobId, timeoutMs }
baby.job.stream.read { jobId, stream: "stdout", offset, limit }
baby.job.stream.read { jobId, stream: "stderr", offset, limit }
```

Always inspect stderr even when the job status is failed before diagnosing the repository.

## 7. Full checkpoint gate

Every checkpoint ends with:

```bash
set -euo pipefail
npm run build
npm run lint
npm test
git status --short --branch
git diff --check
git rev-parse HEAD
git rev-parse HEAD^{tree}
```

Capture output as an artifact when it exceeds inline limits.

## 8. Commit protocol

Before commit:

```bash
git diff --stat
git diff --check
git status --short
```

Commit one coherent checkpoint. Do not mix unrelated cleanup or broad formatting changes.

Suggested checkpoint messages are listed in `50-IMPLEMENTATION-CHECKPOINTS.md`.

After commit:

```bash
git rev-parse HEAD
git rev-parse HEAD^{tree}
git status --short --branch
```

## 9. Push and remote verification

Use the authorized GitHub connector or Baby’s registered repository authority. Do not fall back to unauthenticated HTTPS prompts.

Remote verification must compare:

- branch;
- expected commit;
- expected tree;
- expected base branch where applicable.

The build report is incomplete until local and remote commit/tree match and ahead/behind is zero.

## 10. Current direct Baby execution patterns

### 10.1 Run an exact executable

```text
baby.exec {
  argv: ["/usr/bin/git", "status", "--short", "--branch"],
  cwd: "/var/lib/baby-quirt/workspaces/baby-x-god-mode-v1/baby-x"
}
```

### 10.2 Run a Bash script

```text
baby.shell {
  shell: "/bin/bash",
  cwd: "/var/lib/baby-quirt/workspaces/baby-x-god-mode-v1/baby-x",
  script: "set -euo pipefail; npm run build"
}
```

Use `/bin/bash` explicitly for `pipefail`; `/bin/sh` may reject it.

### 10.3 Read/write files

Use `baby.file.stat` to capture SHA, `baby.file.read` for bounded content, and atomic replacement with expected SHA when changing an existing file. For generated build output, prefer artifacts rather than copying large content into chat.

### 10.4 Preserve artifacts

```text
baby.artifact.create {
  name: "checkpoint-a-test-output.txt",
  sourcePath: "/absolute/path/to/output.txt",
  metadata: { checkpoint: "A", commit: "..." }
}
```

## 11. Completed-service user experience

After implementation, users should not need to know ZFS or nspawn commands.

Natural request:

```text
Run this build and test suite in a disposable machine, preserve the failure evidence if it fails, and clean up when done.
```

Baby’s internal flow:

```text
policy decision
-> babyx.machine.create
-> babyx.machine.start
-> babyx.machine.exec
-> collect jobs/artifacts/proof
-> babyx.machine.stop
-> babyx.machine.destroy
-> verify cleanup
-> return result
```

## 12. Direct completed-service operation examples

The exact connector call shape depends on the final exposed Baby-X tool, but operation and payload semantics should match these examples.

### Create

```json
{
  "operation": "babyx.machine.create",
  "payload": {
    "schemaVersion": "1.0.0",
    "machineName": "build-checkpoint-a-001",
    "ownerPrincipal": "stealtheye-owner",
    "source": {
      "kind": "zfs-snapshot",
      "snapshot": "babycert/base/noble@golden-v1"
    },
    "clone": {
      "dataset": "babycert/runs/build-checkpoint-a-001",
      "mountpoint": "/var/lib/baby-x/machines/build-checkpoint-a-001",
      "expectedRootPrefix": "/var/lib/baby-x/machines"
    },
    "launch": {
      "boot": true,
      "networkMode": "private",
      "readOnlyRoot": false,
      "binds": [],
      "environment": [],
      "properties": [],
      "resourceProfile": {
        "memoryMaxBytes": 4294967296,
        "tasksMax": 1024,
        "runtimeDeadlineMs": 3600000
      }
    },
    "startImmediately": false
  },
  "idempotencyKey": "checkpoint-a-create-001"
}
```

### Start

```json
{
  "operation": "babyx.machine.start",
  "payload": {
    "machineId": "mx_example",
    "expectedSequence": 2
  },
  "idempotencyKey": "checkpoint-a-start-001"
}
```

### Execute

```json
{
  "operation": "babyx.machine.exec",
  "payload": {
    "machineId": "mx_example",
    "argv": ["/usr/bin/npm", "test"],
    "cwd": "/work/baby-x",
    "timeoutMs": 3600000
  },
  "idempotencyKey": "checkpoint-a-test-001"
}
```

### Status

```json
{
  "operation": "babyx.machine.status",
  "payload": {
    "machineId": "mx_example",
    "includeJobs": true,
    "includeRecentEvents": true
  }
}
```

### Stop and destroy

```json
{
  "operation": "babyx.machine.stop",
  "payload": {
    "machineId": "mx_example",
    "expectedSequence": 7,
    "reason": "objective complete"
  },
  "idempotencyKey": "checkpoint-a-stop-001"
}
```

```json
{
  "operation": "babyx.machine.destroy",
  "payload": {
    "machineId": "mx_example",
    "expectedSequence": 9,
    "reason": "objective complete and evidence retained"
  },
  "idempotencyKey": "checkpoint-a-destroy-001"
}
```

## 13. Certification operation

Natural request:

```text
Certify this exact commit in a fresh disposable machine. Run build, lint, unit, integration, and acceptance gates; retain signed evidence; then verify cleanup.
```

Certification owns the profile and final pass/fail result. The machine service owns every generic lifecycle action.

A certification result must report separately:

- test result;
- evidence completeness;
- stop result;
- destroy result;
- cleanup verification;
- source commit/tree;
- machine ID;
- related job and artifact references.

## 14. Recovery operation

Natural request:

```text
Reconcile interrupted disposable machines and report anything that cannot be safely recovered or cleaned.
```

Internal flow:

1. list nonterminal machines;
2. status/observe each;
3. reconcile with bounded concurrency;
4. adopt exact healthy machines;
5. continue exact owned cleanup;
6. leave ambiguity untouched;
7. return machine-by-machine classification.

## 15. Garbage collection operation

Always preview first:

```text
Run disposable-machine garbage collection in dry-run mode and show protected, eligible, and ambiguous machines.
```

Only then apply under the user’s authority:

```text
Clean eligible expired disposable machines, preserve required evidence, and do not touch ambiguous or protected machines.
```

## 16. Candidate racing operation

After Checkpoint H:

```text
Create three isolated candidates from the same source commit. Try the proposed strategies, run identical validation, keep the strongest correct result, preserve evidence, and destroy losing machines.
```

The final report includes:

- identical baseline proof;
- candidate IDs and machine IDs;
- strategies;
- validation results;
- scoring explanation;
- winner;
- loser cleanup verification;
- unresolved ambiguity.

## 17. Troubleshooting

### Job failed immediately with `pipefail`

Cause: script executed with `/bin/sh`. Use `shell: "/bin/bash"` or exact `/bin/bash -c`.

### Git push asks for username

Cause: anonymous HTTPS path. Use authorized GitHub connector or registered Baby repository authority.

### Machine status disagrees with record

Do not edit record manually. Run `machine.reconcile` and inspect observations/events.

### Destroy blocked by identity conflict

Do not force deletion. Preserve evidence and classify `AMBIGUOUS`. Resolve dataset/machine ownership independently.

### Tests pass but cleanup failed

Do not report complete certification success. Report test success plus cleanup failure/recovery required.

### Output too large

Redirect to a file, capture as artifact, and read bounded sections.

## 18. Final operator checklist

- [ ] Correct branch and repository.
- [ ] Exact base commit/tree recorded.
- [ ] All governing docs read.
- [ ] One checkpoint active.
- [ ] Existing authorities reused.
- [ ] Focused tests pass.
- [ ] Full gates pass.
- [ ] Commit and tree recorded.
- [ ] Push uses authorized path.
- [ ] Remote commit/tree verified.
- [ ] Working tree clean.
- [ ] No production mutation.
