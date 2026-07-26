import { existsSync, lstatSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, normalize, relative, sep } from 'node:path';
import { canonicalize, sha256, type JobRecord, type JsonObject, type RuntimeExecutionContext } from '../core.ts';
import type { ArtifactManager } from '../artifacts/manager.ts';
import { decideExecutionPolicy, type ExecutionPolicyDecision } from '../policy/execution.ts';
import {
  assertChangedPathsAllowed,
  assertPatchTextSafe,
  codeMutationPlanDigest,
  deterministicCandidateId,
  parseRawGitDiff,
  validationExecutionDigest,
  type CodeAssertionV1,
  type CodeExecutionActionV1,
  type CodeMutationPlanV1,
  type CodeValidationExecutionV1,
  type CodeValidationStepV1,
} from './code-schemas.ts';
import {
  type DurableTransactionRecordV1,
} from './schemas.ts';
import type {
  TransactionCandidateResult,
  TransactionCheckpointResult,
  TransactionCodeDriver,
  TransactionEvidenceResult,
  TransactionExecutionResult,
  TransactionOperationContext,
  TransactionValidationResult,
} from './service.ts';

const SOURCE_INPUT = '/run/babyx-input/source.tar';
const WORKSPACE_ROOT = '/workspace';
const SOURCE_ROOT = '/workspace/source';
const OUTPUT_ROOT = '/workspace/.babyx-output';

const MATERIALIZE_SCRIPT = `set -euo pipefail
archive="$1"
workspace="$2"
expected_tree="$3"
expected_manifest="$4"
parent="$(dirname "$workspace")"
test ! -e "$workspace"
install -d -m 0755 "$parent"
tar --extract --file "$archive" --directory "$parent" --no-same-owner
test -f "$parent/manifest.json"
actual_manifest="$(sha256sum "$parent/manifest.json" | cut -d ' ' -f 1)"
test "$actual_manifest" = "$expected_manifest"
cd "$workspace"
test ! -e .git
git init -q
git config user.name baby-x-transaction
git config user.email transaction@invalid
git config commit.gpgSign false
git add -A
actual_tree="$(git write-tree)"
test "$actual_tree" = "$expected_tree"
GIT_AUTHOR_DATE='2000-01-01T00:00:00Z' GIT_COMMITTER_DATE='2000-01-01T00:00:00Z' git commit -q --no-gpg-sign -m 'immutable transaction baseline'
test "$(git rev-parse HEAD^{tree})" = "$expected_tree"`;

const ACTION_SCRIPT = `'use strict';
const fs = require('node:fs');
const path = require('node:path');
const [root, kind, relativePath, operand] = process.argv.slice(1);
const absoluteRoot = fs.realpathSync(root);
function target(value) {
  const candidate = path.resolve(absoluteRoot, value);
  const relation = path.relative(absoluteRoot, candidate);
  if (!relation || relation === '..' || relation.startsWith('..' + path.sep) || path.isAbsolute(relation)) throw new Error('mutation target escapes transaction root');
  let current = absoluteRoot;
  for (const part of path.dirname(relation).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) throw new Error('mutation parent is a symbolic link');
  }
  return candidate;
}
if (kind === 'NO_OP') process.exit(0);
const destination = target(relativePath);
if (kind === 'WRITE_FILE') {
  fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o755 });
  const source = fs.realpathSync(operand);
  fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
  fs.chmodSync(destination, 0o644);
} else if (kind === 'DELETE_PATH') {
  const stat = fs.lstatSync(destination);
  if (stat.isDirectory()) throw new Error('directory deletion is not supported');
  fs.unlinkSync(destination);
} else if (kind === 'SET_MODE') {
  const stat = fs.lstatSync(destination);
  if (!stat.isFile()) throw new Error('mode changes require a regular file');
  fs.chmodSync(destination, operand === '0755' ? 0o755 : 0o644);
} else if (kind === 'CREATE_SYMLINK') {
  fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o755 });
  fs.symlinkSync(operand, destination);
} else {
  throw new Error('unsupported declared mutation action');
}`;

const CANDIDATE_SCRIPT = `set -euo pipefail
source_root="$1"
output_root="$2"
expected_base_tree="$3"
artifact_limit="$4"
cd "$source_root"
test "$(git rev-parse HEAD^{tree})" = "$expected_base_tree"
git add -A
candidate_tree="$(git write-tree)"
install -d -m 0700 "$output_root"
printf '%s\\n' "$candidate_tree" > "$output_root/candidate-tree.txt"
git diff --cached --binary --full-index --no-ext-diff --src-prefix=a/ --dst-prefix=b/ HEAD > "$output_root/candidate.patch"
git diff --cached --name-only --no-renames -z HEAD > "$output_root/changed-paths.z"
git diff --cached --raw --no-renames -z HEAD > "$output_root/raw-diff.z"
stage="$(mktemp -d /workspace/.babyx-candidate.XXXXXX)"
trap 'rm -rf -- "$stage"' EXIT
install -d -m 0755 "$stage/source"
git checkout-index --prefix="$stage/source/" -a
git ls-files -s -z > "$stage/manifest.index"
TZ=UTC tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=posix --pax-option=delete=atime,delete=ctime -C "$stage" -cf "$output_root/candidate.tar" source manifest.index
size="$(stat -c %s "$output_root/candidate.tar")"
test "$size" -le "$artifact_limit"`;

const ASSERTION_SCRIPT = `'use strict';
const fs = require('node:fs');
const path = require('node:path');
const [root, kind, relativePath, expected, baseTree] = process.argv.slice(1);
const resolve = (value) => {
  const candidate = path.resolve(root, value);
  const relation = path.relative(root, candidate);
  if (!relation || relation === '..' || relation.startsWith('..' + path.sep) || path.isAbsolute(relation)) throw new Error('assertion path escapes transaction root');
  return candidate;
};
if (kind === 'PATH_EXISTS') {
  fs.lstatSync(resolve(relativePath));
} else if (kind === 'FILE_CONTAINS') {
  if (!fs.readFileSync(resolve(relativePath), 'utf8').includes(expected)) throw new Error('file assertion failed');
} else if (kind === 'CREDENTIALS_ABSENT') {
  const sensitive = /(^|_)(SECRET|TOKEN|PASSWORD|PRIVATE_KEY|API_KEY|ACCESS_KEY|CREDENTIAL)(_|$)/i;
  if (Object.keys(process.env).some((name) => sensitive.test(name))) throw new Error('secret-bearing environment name is present');
  if (fs.existsSync('/root/.ssh') || fs.existsSync('/root/.git-credentials')) throw new Error('credential path is present');
} else if (kind === 'NETWORK_DISABLED') {
  const interfaces = fs.readdirSync('/sys/class/net').filter((name) => name !== 'lo');
  if (interfaces.length !== 0) throw new Error('non-loopback network interface is present');
} else if (kind === 'TREE_EQUALS_BASE') {
  const child = require('node:child_process').spawnSync('/usr/bin/git', ['write-tree'], { cwd: root, encoding: 'utf8' });
  if (child.status !== 0 || child.stdout.trim() !== baseTree) throw new Error('working tree does not equal base tree');
} else {
  throw new Error('unsupported assertion');
}`;

export interface CodeTransactionMachineAuthority {
  create(payload: unknown, context: RuntimeExecutionContext): Promise<JsonObject>;
  get(payload: JsonObject, context: RuntimeExecutionContext): JsonObject;
  list(payload: JsonObject | undefined, context: RuntimeExecutionContext): JsonObject;
  start(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  exec(payload: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
}

export interface CodeTransactionJobAuthority {
  get(id: string): JobRecord;
  reconcile(id: string): JobRecord;
}

export interface DisposableCodeTransactionDriverOptions {
  machine: CodeTransactionMachineAuthority;
  jobs: CodeTransactionJobAuthority;
  artifacts: ArtifactManager;
  now?: () => string;
  sleep?: (milliseconds: number) => Promise<void>;
  jobPollIntervalMs?: number;
  settleTimeoutMs?: number;
}

function json(value: unknown, field: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${field} must be an object`);
  return value as JsonObject;
}

function machineFrom(value: JsonObject): JsonObject {
  return json(value.machine, 'machine response');
}

function lifecycle(machine: JsonObject): { state: string; sequence: number } {
  const value = json(machine.lifecycle, 'machine lifecycle');
  const sequence = Number(value.stateSequence);
  if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Error('machine sequence is invalid');
  return { state: String(value.persistedState), sequence };
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string') : [];
}

function contextFor(record: DurableTransactionRecordV1, suffix: string): RuntimeExecutionContext {
  return { subject: record.ownerPrincipal, authorityClass: 'unrestricted-owner', idempotencyKey: `transaction:${record.transactionId}:${suffix}` };
}

export function codeTransactionMachineExecutionRequest(
  record: DurableTransactionRecordV1,
  machine: JsonObject,
  phase: 'materialization' | 'mutation' | 'validation' | 'candidate',
  stepId: string,
  argv: string[],
  cwd: string,
  timeoutMs: number,
): JsonObject {
  return {
    machineId: machine.machineId,
    expectedSequence: lifecycle(machine).sequence,
    argv,
    cwd,
    env: {},
    timeoutMs,
    outputLimitBytes: record.code.mutationPlan.resourceBounds.outputLimitBytes,
    artifactPolicy: { captureStreams: true },
    reason: `code transaction ${record.transactionId} ${phase} ${stepId}`,
  };
}

function artifactMetadata(record: DurableTransactionRecordV1, role: string): JsonObject {
  return { transactionId: record.transactionId, ownerPrincipal: record.ownerPrincipal, role, baseCommit: record.source.commit, baseTree: record.source.tree, mutationPlanDigest: record.code.mutationPlanDigest };
}

function artifactPath(record: JsonObject): string {
  if (record.state !== 'finalized' || typeof record.path !== 'string' || !isAbsolute(record.path) || normalize(record.path) !== record.path || !existsSync(record.path) || !lstatSync(record.path).isFile()) throw new Error('bound artifact is not a finalized regular file');
  return realpathSync(record.path);
}

function metadata(record: JsonObject): JsonObject {
  return json(record.metadata, 'artifact metadata');
}

function safeHostOutput(mountpoint: string, relativePath: string): string {
  const root = realpathSync(mountpoint);
  const candidate = join(root, relativePath);
  const actual = realpathSync(candidate);
  const relation = relative(root, actual);
  if (!relation || relation === '..' || relation.startsWith(`..${sep}`) || isAbsolute(relation) || !lstatSync(actual).isFile()) throw new Error('candidate output escapes exact machine root');
  return actual;
}

export function codeTransactionPolicyDecision(plan: CodeMutationPlanV1, mode: 'disposable' | 'parallel-disposable' = 'disposable'): ExecutionPolicyDecision {
  const tools = [
    ...plan.validationSteps.map((step) => step.argv[0]),
    ...(plan.mutationMode === 'PATCH_ARTIFACT' ? ['/usr/bin/git'] : ['/usr/bin/node']),
  ];
  return decideExecutionPolicy({
    schemaVersion: '1.0.0', objectiveType: 'development', mutationRisk: 'high', dependencyUncertainty: 'known',
    isolationRequirement: 'required', reversibility: 'reversible', requiredTools: tools, requiredPackages: [],
    sourceSensitivity: 'internal', reproducibilityRequirement: 'required', networkRequirement: 'none',
    expectedDurationMs: plan.resourceBounds.timeoutMs,
    resourceProfile: {
      cpuUnits: Math.max(1, Math.ceil(plan.resourceBounds.cpuQuotaPercent / 100)),
      memoryMb: Math.max(64, Math.ceil(plan.resourceBounds.memoryMaxBytes / 1_048_576)),
      diskMb: Math.max(1, Math.ceil(plan.resourceBounds.diskQuotaBytes / 1_048_576)),
    },
    explicitConstraint: mode, racingEligibility: false, candidateCount: mode === 'parallel-disposable' ? 2 : 1,
    costBounds: {
      maxMachines: mode === 'parallel-disposable' ? 2 : 1,
      maxDurationMs: plan.resourceBounds.timeoutMs,
      maxDiskMb: Math.max(1, Math.ceil(plan.resourceBounds.diskQuotaBytes / 1_048_576)),
    },
  });
}

export class DisposableCodeTransactionDriver implements TransactionCodeDriver {
  private readonly now: () => string;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly jobPollIntervalMs: number;
  private readonly settleTimeoutMs: number;

  constructor(private readonly options: DisposableCodeTransactionDriverOptions) {
    this.now = options.now ?? (() => new Date().toISOString());
    this.sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    this.jobPollIntervalMs = options.jobPollIntervalMs ?? 100;
    this.settleTimeoutMs = options.settleTimeoutMs ?? 60_000;
  }

  private verifiedArtifact(id: string): JsonObject {
    return this.options.artifacts.verify(id);
  }

  private sourceArtifact(record: DurableTransactionRecordV1): JsonObject {
    if (record.source.sourceArchiveArtifactId === null) throw new Error('code transaction requires an immutable source archive artifact');
    const artifact = this.verifiedArtifact(record.source.sourceArchiveArtifactId);
    const meta = metadata(artifact);
    const required = {
      kind: 'babyx.exact-source-tree-v1', repository: record.source.repository, commit: record.source.commit, tree: record.source.tree,
      sourceManifestDigest: record.source.sourceManifestDigest, containsGitMetadata: false, containsCredentials: false,
    };
    for (const [key, value] of Object.entries(required)) if (meta[key] !== value) throw new Error(`source artifact metadata mismatch: ${key}`);
    if (record.source.packageLockDigest !== null && meta.packageLockDigest !== record.source.packageLockDigest) throw new Error('source artifact package-lock digest mismatch');
    const expectedReference = `artifact:${artifact.id}:sha256:${artifact.sha256}`;
    if (record.source.immutableSourceReference !== expectedReference) throw new Error('immutable source reference does not bind the verified source artifact digest');
    return artifact;
  }

  private mutationArtifacts(record: DurableTransactionRecordV1): Map<string, JsonObject> {
    const result = new Map<string, JsonObject>();
    for (const id of record.code.mutationPlan.mutationInputArtifactIds) {
      const artifact = this.verifiedArtifact(id);
      const meta = metadata(artifact);
      if (meta.transactionId !== record.transactionId && meta.transactionId !== null && meta.transactionId !== undefined) throw new Error('mutation input artifact is bound to another transaction');
      if (record.code.mutationPlan.mutationMode === 'PATCH_ARTIFACT' && id === record.code.mutationPlan.patchArtifactId) {
        if (meta.kind !== 'babyx.code-patch-v1' || meta.baseCommit !== record.source.commit || meta.baseTree !== record.source.tree) throw new Error('patch artifact metadata does not match immutable source');
        assertPatchTextSafe(readFileSync(artifactPath(artifact), 'utf8'));
      }
      result.set(id, artifact);
    }
    return result;
  }

  private machineList(record: DurableTransactionRecordV1): JsonObject[] {
    const listed = this.options.machine.list({ parentObjectiveId: record.transactionId, offset: 0, limit: 2 }, { subject: record.ownerPrincipal, authorityClass: 'unrestricted-owner' });
    return Array.isArray(listed.machines) ? listed.machines.map((entry) => json(entry, 'listed machine')) : [];
  }

  private exactMachine(record: DurableTransactionRecordV1): JsonObject {
    const ids = record.execution.machineIds;
    if (ids.length !== 1) throw new Error('transaction must bind exactly one disposable machine');
    const machine = machineFrom(this.options.machine.get({ machineId: ids[0] }, { subject: record.ownerPrincipal, authorityClass: 'unrestricted-owner' }));
    if (machine.machineId !== ids[0] || machine.ownerPrincipal !== record.ownerPrincipal || machine.parentObjectiveId !== record.transactionId || machine.authorityReference !== record.transactionId) throw new Error('machine identity does not match exact transaction ownership');
    return machine;
  }

  private async waitJob(id: string, timeoutMs: number): Promise<JobRecord> {
    const started = Date.now();
    for (;;) {
      const job = this.options.jobs.reconcile(id);
      if (job.status !== 'running') return job;
      if (Date.now() - started > timeoutMs + this.settleTimeoutMs) throw new Error(`durable job ${id} did not terminalize within bound`);
      await this.sleep(this.jobPollIntervalMs);
    }
  }

  private async waitMachineSettled(record: DurableTransactionRecordV1, jobId: string): Promise<JsonObject> {
    const started = Date.now();
    for (;;) {
      const machine = this.exactMachine(record);
      if (!stringArray(machine.activeJobIds).includes(jobId)) return machine;
      if (Date.now() - started > this.settleTimeoutMs) throw new Error(`machine did not durably reconcile terminal job ${jobId}`);
      await this.sleep(this.jobPollIntervalMs);
    }
  }

  private async submit(record: DurableTransactionRecordV1, machine: JsonObject, phase: 'materialization' | 'mutation' | 'validation' | 'candidate', stepId: string, argv: string[], cwd: string, timeoutMs: number): Promise<{ machine: JsonObject; job: JobRecord }> {
    const response = await this.options.machine.exec(
      codeTransactionMachineExecutionRequest(record, machine, phase, stepId, argv, cwd, timeoutMs),
      contextFor(record, `${phase}:${stepId}`),
    );
    const jobId = String(response.jobId);
    const job = await this.waitJob(jobId, timeoutMs);
    const settled = await this.waitMachineSettled(record, jobId);
    return { machine: settled, job };
  }

  async checkpoint(record: DurableTransactionRecordV1, _context: TransactionOperationContext): Promise<TransactionCheckpointResult> {
    if (record.environment.credentialPresence || record.environment.credentialReferenceIds.length > 0) throw new Error('code transactions cannot inherit credentials');
    const source = this.sourceArtifact(record);
    const inputs = this.mutationArtifacts(record);
    const decision = codeTransactionPolicyDecision(record.code.mutationPlan, record.policy.selectedEnvironmentClass);
    if (decision.mode !== record.policy.selectedEnvironmentClass || decision.decisionDigest !== record.policy.policyDecisionDigest) throw new Error('execution policy decision does not match exact transaction binding');
    let machines = this.machineList(record);
    if (machines.length > 1) throw new Error('transaction machine ownership is ambiguous');
    if (machines.length === 0) {
      const binds: JsonObject[] = [{ source: artifactPath(source), destination: SOURCE_INPUT, mode: 'ro', recursive: false }];
      let index = 0;
      for (const [id, artifact] of [...inputs.entries()].sort(([left], [right]) => left.localeCompare(right))) {
        binds.push({ source: artifactPath(artifact), destination: `/run/babyx-input/mutation-${index}`, mode: 'ro', recursive: false });
        index += 1;
      }
      const created = await this.options.machine.create({
        schemaVersion: '1.0.0', machineName: record.policy.resourceBoundIdentity.machineName, ownerPrincipal: record.ownerPrincipal,
        authorityReference: record.transactionId, parentObjectiveId: record.transactionId,
        source: { kind: 'zfs-snapshot', snapshot: record.source.protectedSnapshot, expectedGuid: record.source.expectedSnapshotGuid },
        clone: {
          dataset: record.policy.resourceBoundIdentity.cloneDataset, mountpoint: record.policy.resourceBoundIdentity.mountpoint,
          expectedRootPrefix: record.policy.resourceBoundIdentity.expectedRootPrefix,
        },
        launch: {
          boot: true, networkMode: 'none', readOnlyRoot: false, binds, environment: [], properties: [],
          resourceProfile: {
            memoryMaxBytes: record.code.mutationPlan.resourceBounds.memoryMaxBytes,
            cpuQuotaPercent: record.code.mutationPlan.resourceBounds.cpuQuotaPercent,
            tasksMax: record.code.mutationPlan.resourceBounds.tasksMax,
            runtimeDeadlineMs: record.code.mutationPlan.resourceBounds.timeoutMs,
            diskQuotaBytes: record.code.mutationPlan.resourceBounds.diskQuotaBytes,
            outputLimitBytes: record.code.mutationPlan.resourceBounds.outputLimitBytes,
            artifactLimitBytes: record.code.mutationPlan.resourceBounds.artifactLimitBytes,
          },
        },
        startImmediately: false,
      }, contextFor(record, 'machine-create'));
      machines = [machineFrom(created)];
    }
    const machine = machines[0];
    if (machine.ownerPrincipal !== record.ownerPrincipal || machine.parentObjectiveId !== record.transactionId || machine.authorityReference !== record.transactionId) throw new Error('created machine ownership is ambiguous');
    const sourceTruth = json(machine.source, 'machine source');
    const observations = json(machine.observations, 'machine observations');
    if (sourceTruth.snapshot !== record.source.protectedSnapshot || sourceTruth.snapshotGuid !== record.source.expectedSnapshotGuid || sourceTruth.creationTxg !== record.source.snapshotCreationTxg) throw new Error('machine source snapshot readback mismatches transaction baseline');
    return {
      observedSnapshotGuid: String(sourceTruth.snapshotGuid), snapshotCreationTxg: String(sourceTruth.creationTxg),
      sourceVerifiedAt: String(sourceTruth.observedAt ?? this.now()), observationDigest: String(observations.observationDigest),
      machineIds: [String(machine.machineId)],
    };
  }

  private inputPath(record: DurableTransactionRecordV1, artifactId: string): string {
    const ids = [...record.code.mutationPlan.mutationInputArtifactIds].sort();
    const index = ids.indexOf(artifactId);
    if (index < 0) throw new Error('mutation artifact is not bound');
    return `/run/babyx-input/mutation-${index}`;
  }

  private actionArgv(record: DurableTransactionRecordV1, action: CodeExecutionActionV1): string[] {
    if (action.kind === 'NO_OP') return ['/usr/bin/node', '-e', ACTION_SCRIPT, SOURCE_ROOT, 'NO_OP', 'unused', 'unused'];
    const operand = action.kind === 'WRITE_FILE' ? this.inputPath(record, action.contentArtifactId as string)
      : action.kind === 'SET_MODE' ? action.mode as string
      : action.kind === 'CREATE_SYMLINK' ? action.symlinkTarget as string
      : 'unused';
    return ['/usr/bin/node', '-e', ACTION_SCRIPT, SOURCE_ROOT, action.kind, action.path as string, operand];
  }

  async execute(record: DurableTransactionRecordV1, _context: TransactionOperationContext): Promise<TransactionExecutionResult> {
    let machine = this.exactMachine(record);
    const related = new Set<string>(stringArray(machine.protectedJobIds));
    if (!['READY', 'EXECUTING'].includes(lifecycle(machine).state)) {
      const started = await this.options.machine.start({ machineId: machine.machineId, expectedSequence: lifecycle(machine).sequence, readinessTimeoutMs: 60_000, reason: `code transaction ${record.transactionId} start` }, contextFor(record, 'machine-start'));
      machine = machineFrom(started);
      if (typeof started.jobId === 'string') related.add(started.jobId);
    }
    for (const id of stringArray(machine.protectedJobIds)) related.add(id);
    const materialized = await this.submit(record, machine, 'materialization', 'exact-source', ['/usr/bin/bash', '-c', MATERIALIZE_SCRIPT, '--', SOURCE_INPUT, SOURCE_ROOT, record.source.tree, record.source.sourceManifestDigest], '/', record.code.mutationPlan.resourceBounds.timeoutMs);
    machine = materialized.machine;
    related.add(materialized.job.id);
    const mutationJobs = [materialized.job.id];
    if (materialized.job.status === 'completed' && materialized.job.exitCode === 0) {
      if (record.code.mutationPlan.mutationMode === 'PATCH_ARTIFACT') {
        const applied = await this.submit(record, machine, 'mutation', 'apply-patch', ['/usr/bin/git', 'apply', '--index', '--whitespace=error-all', this.inputPath(record, record.code.mutationPlan.patchArtifactId as string)], SOURCE_ROOT, record.code.mutationPlan.resourceBounds.timeoutMs);
        machine = applied.machine; related.add(applied.job.id); mutationJobs.push(applied.job.id);
      } else {
        for (const action of record.code.mutationPlan.executionActions) {
          const executed = await this.submit(record, machine, 'mutation', action.stepId, this.actionArgv(record, action), SOURCE_ROOT, record.code.mutationPlan.resourceBounds.timeoutMs);
          machine = executed.machine; related.add(executed.job.id); mutationJobs.push(executed.job.id);
          if (executed.job.status !== 'completed' || executed.job.exitCode !== 0) break;
        }
      }
    }
    const active = [...related].filter((id) => {
      try { return this.options.jobs.get(id).status === 'running'; } catch { return true; }
    }).sort();
    return { machineIds: [String(machine.machineId)], allRelatedJobIds: [...related].sort(), mutationJobIds: mutationJobs, activeJobIds: active, materializationJobId: materialized.job.id };
  }

  private assertionStep(assertion: CodeAssertionV1, index: number): CodeValidationStepV1 {
    return {
      stepId: `assertion-${index}-${assertion.assertionId}`, phase: 'assertion',
      argv: ['/usr/bin/node', '-e', ASSERTION_SCRIPT, SOURCE_ROOT, assertion.kind, assertion.path ?? 'unused', assertion.expected ?? 'unused', assertion.kind === 'TREE_EQUALS_BASE' ? 'BASE_TREE' : 'unused'],
      cwd: '.', timeoutMs: 30_000, required: true,
    };
  }

  private execution(record: DurableTransactionRecordV1, step: CodeValidationStepV1, job: JobRecord, artifactIds: string[]): CodeValidationExecutionV1 {
    const status: CodeValidationExecutionV1['status'] = job.status === 'completed' && job.exitCode === 0 ? 'passed'
      : job.status === 'lost' ? 'lost' : job.status === 'running' ? 'ambiguous' : 'failed';
    return {
      stepId: step.stepId, phase: step.phase, jobId: job.id, executionPlanDigest: validationExecutionDigest(step),
      argv: [...step.argv], startedAt: job.startedAt ?? job.createdAt, completedAt: job.completedAt ?? this.now(), status,
      exitCode: job.exitCode ?? null, signal: job.signal ?? null, artifactIds, receiptReferences: [],
    };
  }

  private artifactsForJob(jobId: string): string[] {
    return this.options.artifacts.list().filter((record) => {
      const meta = record.metadata;
      return meta !== null && typeof meta === 'object' && !Array.isArray(meta) && (meta as JsonObject).jobId === jobId;
    }).map((record) => String(record.id)).sort();
  }

  async validate(record: DurableTransactionRecordV1, _context: TransactionOperationContext): Promise<TransactionValidationResult> {
    let machine = this.exactMachine(record);
    const jobIds: string[] = [];
    const executions: CodeValidationExecutionV1[] = [];
    const steps = [
      ...record.code.mutationPlan.validationSteps,
      ...record.code.mutationPlan.assertions.map((assertion, index) => this.assertionStep(assertion, index)),
    ];
    for (const sourceStep of steps) {
      const step = sourceStep.argv.includes('BASE_TREE') ? { ...sourceStep, argv: sourceStep.argv.map((entry) => entry === 'BASE_TREE' ? record.source.tree : entry) } : sourceStep;
      const cwd = step.cwd === '.' ? SOURCE_ROOT : join(SOURCE_ROOT, step.cwd);
      const submitted = await this.submit(record, machine, 'validation', step.stepId, step.argv, cwd, step.timeoutMs);
      machine = submitted.machine; jobIds.push(submitted.job.id);
      const artifacts = this.artifactsForJob(submitted.job.id);
      executions.push(this.execution(record, step, submitted.job, artifacts));
      if (submitted.job.status !== 'completed' || submitted.job.exitCode !== 0) break;
    }
    const protectedJobs = stringArray(machine.protectedJobIds);
    const active = protectedJobs.filter((id) => {
      try { return this.options.jobs.get(id).status === 'running'; } catch { return true; }
    }).sort();
    return { allRelatedJobIds: [...new Set([...jobIds, ...protectedJobs])].sort(), validationJobIds: jobIds, activeJobIds: active, validationExecutions: executions };
  }

  private validationResults(record: DurableTransactionRecordV1): CodeValidationExecutionV1[] {
    return record.code.validationExecutions.map((execution) => {
      const job = this.options.jobs.reconcile(execution.jobId);
      return this.execution(record, {
        stepId: execution.stepId, phase: execution.phase, argv: execution.argv, cwd: '.',
        timeoutMs: record.code.mutationPlan.resourceBounds.timeoutMs, required: true,
      }, job, this.artifactsForJob(job.id));
    });
  }

  async finalize(record: DurableTransactionRecordV1, _context: TransactionOperationContext): Promise<TransactionCandidateResult> {
    let machine = this.exactMachine(record);
    const prepared = await this.submit(record, machine, 'candidate', 'prepare-candidate', ['/usr/bin/bash', '-c', CANDIDATE_SCRIPT, '--', SOURCE_ROOT, OUTPUT_ROOT, record.source.tree, String(record.code.mutationPlan.resourceBounds.artifactLimitBytes)], SOURCE_ROOT, record.code.mutationPlan.resourceBounds.timeoutMs);
    machine = prepared.machine;
    if (prepared.job.status !== 'completed' || prepared.job.exitCode !== 0) throw new Error('candidate preparation job failed');
    const mountpoint = record.policy.resourceBoundIdentity.mountpoint;
    const treePath = safeHostOutput(mountpoint, 'workspace/.babyx-output/candidate-tree.txt');
    const patchPath = safeHostOutput(mountpoint, 'workspace/.babyx-output/candidate.patch');
    const archivePath = safeHostOutput(mountpoint, 'workspace/.babyx-output/candidate.tar');
    const changedPath = safeHostOutput(mountpoint, 'workspace/.babyx-output/changed-paths.z');
    const rawPath = safeHostOutput(mountpoint, 'workspace/.babyx-output/raw-diff.z');
    const candidateTree = readFileSync(treePath, 'utf8').trim();
    if (!/^[a-f0-9]{40,64}$/u.test(candidateTree)) throw new Error('candidate tree is invalid');
    const changedPaths = assertChangedPathsAllowed(readFileSync(changedPath).toString('utf8').split('\0').filter(Boolean), record.code.mutationPlan.changedPathAllowlist);
    const pathChanges = parseRawGitDiff(readFileSync(rawPath));
    if (canonicalize(changedPaths) !== canonicalize(pathChanges.map((change) => change.path))) throw new Error('candidate changed-path observations conflict');
    if (changedPaths.length === 0 && candidateTree !== record.source.tree) throw new Error('zero-mutation candidate does not reproduce exact base tree');
    if (changedPaths.length > 0 && candidateTree === record.source.tree) throw new Error('modified candidate unexpectedly equals base tree');
    const patchArtifact = this.options.artifacts.createOnce(`transaction:${record.transactionId}:candidate-patch`, `transaction-${record.transactionId}-candidate-patch`, patchPath, artifactMetadata(record, 'candidate-patch'));
    const archiveArtifact = this.options.artifacts.createOnce(`transaction:${record.transactionId}:candidate-archive`, `transaction-${record.transactionId}-candidate-archive`, archivePath, artifactMetadata(record, 'candidate-archive'));
    this.options.artifacts.verify(String(patchArtifact.id)); this.options.artifacts.verify(String(archiveArtifact.id));
    const validationResults = this.validationResults(record);
    const validationDigest = sha256(canonicalize(validationResults));
    const candidateCore: JsonObject = {
      schemaVersion: '1.0.0', transactionId: record.transactionId, ownerPrincipal: record.ownerPrincipal,
      baseRepository: record.source.repository, baseCommit: record.source.commit, baseTree: record.source.tree, candidateTree,
      pathChanges, changedFiles: changedPaths, addedFiles: pathChanges.filter((change) => change.status === 'added').map((change) => change.path),
      deletedFiles: pathChanges.filter((change) => change.status === 'deleted').map((change) => change.path),
      modifiedFiles: pathChanges.filter((change) => change.status === 'modified' || change.status === 'type-changed').map((change) => change.path),
      fileModeChanges: pathChanges.filter((change) => change.oldMode !== change.newMode).map((change) => change.path),
      symlinkChanges: pathChanges.filter((change) => change.symlinkChanged).map((change) => change.path),
      patchArtifact: { id: patchArtifact.id, sha256: patchArtifact.sha256, size: patchArtifact.size },
      candidateArchiveArtifact: { id: archiveArtifact.id, sha256: archiveArtifact.sha256, size: archiveArtifact.size },
      validationDigest, validationResults, mutationPlanDigest: record.code.mutationPlanDigest, policyDecisionDigest: record.policy.policyDecisionDigest,
      machineId: machine.machineId, relatedJobIds: [...new Set([...record.execution.allRelatedJobIds, prepared.job.id])].sort(),
    };
    const candidateId = deterministicCandidateId(candidateCore);
    const manifest = Buffer.from(`${canonicalize({ ...candidateCore, candidateId, createdAt: this.now() })}\n`);
    const manifestArtifact = this.options.artifacts.createBytesOnce(`transaction:${record.transactionId}:candidate-manifest`, `transaction-${record.transactionId}-candidate-manifest`, manifest, artifactMetadata(record, 'candidate-manifest'));
    this.options.artifacts.verify(String(manifestArtifact.id));
    const machineArtifacts = stringArray(machine.artifactIds);
    const artifactIds = [...new Set([...machineArtifacts, String(patchArtifact.id), String(archiveArtifact.id), String(manifestArtifact.id)])].sort();
    return {
      candidateId, candidateTree, changedPaths, pathChanges,
      addedFiles: pathChanges.filter((change) => change.status === 'added').map((change) => change.path),
      deletedFiles: pathChanges.filter((change) => change.status === 'deleted').map((change) => change.path),
      modifiedFiles: pathChanges.filter((change) => change.status === 'modified' || change.status === 'type-changed').map((change) => change.path),
      fileModeChanges: pathChanges.filter((change) => change.oldMode !== change.newMode).map((change) => change.path),
      symlinkChanges: pathChanges.filter((change) => change.symlinkChanged).map((change) => change.path),
      patchArtifactId: String(patchArtifact.id), candidateArchiveArtifactId: String(archiveArtifact.id),
      candidateManifestArtifactId: String(manifestArtifact.id), validationDigest, validationPassed: true,
      artifactIds, receiptReferences: [], candidateJobIds: [prepared.job.id], validationExecutions: validationResults,
    };
  }

  async completeEvidence(record: DurableTransactionRecordV1, _context: TransactionOperationContext): Promise<TransactionEvidenceResult> {
    const evidence = {
      schemaVersion: '1.0.0', transactionId: record.transactionId, ownerPrincipal: record.ownerPrincipal,
      source: record.source, policy: record.policy, execution: record.execution, code: record.code, candidate: record.candidate,
      cleanup: record.cleanup, eventTailDigest: record.evidence.eventTailDigest,
      artifactIds: record.evidence.artifactIds, receiptReferences: record.evidence.receiptReferences, capturedAt: this.now(),
      boundaries: { authoritativeRefUpdated: false, merge: false, deployment: false, releaseActivation: false },
    };
    const canonical = Buffer.from(`${canonicalize(evidence)}\n`);
    const digest = sha256(canonical);
    const artifact = this.options.artifacts.createBytesOnce(`transaction:${record.transactionId}:evidence-index`, `transaction-${record.transactionId}-evidence-index`, canonical, { ...artifactMetadata(record, 'evidence-index'), evidenceIndexDigest: digest });
    this.options.artifacts.verify(String(artifact.id));
    return { finalEvidenceIndexArtifactId: String(artifact.id), finalEvidenceIndexDigest: digest, artifactIds: [String(artifact.id)], receiptReferences: [] };
  }
}
