import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  initialTransactionRecord,
  normalizeTransactionCreateRequest,
} from '../../dist/runtime/transactions/schemas.js';
import { DurableTransactionStore } from '../../dist/runtime/transactions/store.js';
import { TransactionService } from '../../dist/runtime/transactions/service.js';

const DIGESTS = Object.freeze({
  source: '1'.repeat(64),
  lock: '2'.repeat(64),
  policy: '3'.repeat(64),
});

export function createRequest(overrides = {}) {
  return {
    schemaVersion: '1.0.0',
    transactionKind: 'CODE_MUTATION',
    repository: 'StealthEyeLLC/baby-x',
    branch: 'build/baby-x-transactional-tool-fabric-v2',
    commit: 'a'.repeat(40),
    tree: 'b'.repeat(40),
    sourceArchiveArtifactId: 'artifact-source-1',
    immutableSourceReference: 'artifact:artifact-source-1',
    sourceManifestDigest: DIGESTS.source,
    packageLockDigest: DIGESTS.lock,
    protectedSnapshot: 'babycert/base/noble@golden-v1',
    expectedSnapshotGuid: '9351137475418520293',
    snapshotCreationTxg: '53',
    policyDecisionDigest: DIGESTS.policy,
    selectedEnvironmentClass: 'disposable',
    providerId: 'zfs-nspawn-disposable@1',
    providerVersion: '1.0.0',
    networkMode: 'none',
    resourceBoundIdentity: {
      machineName: 'bxt-test0001',
      cloneDataset: 'babycert/certifications/tx-test0001',
      mountpoint: '/var/lib/baby-machines/tx-test0001',
      expectedRootPrefix: '/var/lib/baby-machines',
    },
    normalizedEnvironment: [{ name: 'CI', value: 'true' }],
    credentialReferenceIds: [],
    credentialPresence: false,
    ...overrides,
  };
}

export function makeRecord({
  ownerPrincipal = 'owner-a',
  idempotencyKey = 'create-key-0001',
  transactionId = `tx_${'1'.repeat(32)}`,
  occurredAt = '2026-07-25T12:00:00.000Z',
  request = createRequest(),
} = {}) {
  const normalized = normalizeTransactionCreateRequest(request, ownerPrincipal, idempotencyKey);
  return initialTransactionRecord(normalized, ownerPrincipal, idempotencyKey, transactionId, occurredAt);
}

export function mutationDetails(overrides = {}) {
  return {
    operation: 'babyx.transaction.reconcile',
    phase: 'test',
    requestDigest: '4'.repeat(64),
    idempotencyKey: 'mutation-key-0001',
    occurredAt: '2026-07-25T12:00:01.000Z',
    ...overrides,
  };
}

export function context(subject = 'owner-a', idempotencyKey = 'mutation-key-0001', authorityClass = 'owner') {
  return { subject, idempotencyKey, authorityClass };
}

export function tempRoot(t, prefix = 'baby-x-transaction-') {
  const root = mkdtempSync(join(tmpdir(), prefix));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

export class FakeJobs {
  constructor(records = []) {
    this.records = new Map(records.map((record) => [record.id, structuredClone(record)]));
    this.getCalls = [];
    this.reconcileCalls = [];
    this.cancelCalls = [];
  }

  set(record) { this.records.set(record.id, structuredClone(record)); }

  get(id) {
    this.getCalls.push(id);
    const record = this.records.get(id);
    if (!record) throw new Error(`job ${id} not found`);
    return structuredClone(record);
  }

  reconcile(id) {
    this.reconcileCalls.push(id);
    return this.get(id);
  }

  cancel(id, signal = 'SIGTERM') {
    this.cancelCalls.push({ id, signal });
    const current = this.get(id);
    const next = { ...current, status: 'failed', exitCode: null, signal, completedAt: '2026-07-25T12:00:02.000Z' };
    this.set(next);
    return structuredClone(next);
  }
}

export function jobRecord(id, transactionId, ownerPrincipal = 'owner-a', overrides = {}) {
  return {
    id,
    status: 'completed',
    exitCode: 0,
    signal: null,
    metadata: { transactionId, ownerPrincipal },
    ...overrides,
  };
}

export class FakeMachine {
  constructor(records = []) {
    this.records = new Map(records.map((record) => [record.machineId, structuredClone(record)]));
    this.getCalls = [];
    this.statusCalls = [];
    this.stopCalls = [];
    this.destroyCalls = [];
    this.reconcileCalls = [];
    this.destroyFailure = null;
  }

  set(record) { this.records.set(record.machineId, structuredClone(record)); }

  get(payload) {
    this.getCalls.push(structuredClone(payload));
    const record = this.records.get(payload.machineId);
    if (!record) throw new Error(`machine ${payload.machineId} not found`);
    return { operation: 'babyx.machine.get', machine: structuredClone(record) };
  }

  async status(payload) {
    this.statusCalls.push(structuredClone(payload));
    return this.get(payload);
  }

  async stop(payload) {
    this.stopCalls.push(structuredClone(payload));
    return this.get(payload);
  }

  async destroy(payload) {
    this.destroyCalls.push(structuredClone(payload));
    if (this.destroyFailure) throw this.destroyFailure;
    const current = this.records.get(payload.machineId);
    if (!current) throw new Error(`machine ${payload.machineId} not found`);
    const next = destroyedMachine({ ...current, lifecycle: { ...current.lifecycle, stateSequence: current.lifecycle.stateSequence + 1 } });
    this.set(next);
    return { operation: 'babyx.machine.destroy', machine: structuredClone(next) };
  }

  async reconcile(payload) {
    this.reconcileCalls.push(structuredClone(payload));
    return this.get(payload);
  }
}

export function activeMachine({ machineId = 'machine-0001', ownerPrincipal = 'owner-a', expectedSnapshotGuid = '9351137475418520293' } = {}) {
  return {
    machineId,
    ownerPrincipal,
    lifecycle: { persistedState: 'RUNNING', stateSequence: 7, terminal: false },
    source: { expectedSnapshotGuid, snapshotGuid: expectedSnapshotGuid },
    cleanup: {
      completed: false,
      machineAbsentVerified: false,
      processAbsentVerified: false,
      rootAbsentVerified: false,
      datasetAbsentVerified: false,
    },
    observations: { mountpoint: 'present' },
  };
}

export function destroyedMachine(record = activeMachine()) {
  return {
    ...record,
    lifecycle: { ...record.lifecycle, persistedState: 'DESTROYED', terminal: true },
    cleanup: {
      completed: true,
      machineAbsentVerified: true,
      processAbsentVerified: true,
      rootAbsentVerified: true,
      datasetAbsentVerified: true,
    },
    observations: { ...record.observations, mountpoint: 'absent' },
  };
}

export class FakeArtifacts {
  constructor(records = []) { this.records = new Map(records.map((record) => [record.id, structuredClone(record)])); }
  set(record) { this.records.set(record.id, structuredClone(record)); }
  get(id) {
    const record = this.records.get(id);
    if (!record) throw new Error(`artifact ${id} not found`);
    return structuredClone(record);
  }
}

export function finalizedArtifact(id, sha256 = '5'.repeat(64)) {
  return { id, state: 'finalized', sha256 };
}

export class FakeCodeDriver {
  constructor({ jobs, machine, artifacts } = {}) {
    this.jobs = jobs;
    this.machine = machine;
    this.artifacts = artifacts;
    this.calls = { checkpoint: 0, execute: 0, validate: 0, finalize: 0, completeEvidence: 0 };
    this.fail = {};
  }

  async checkpoint(record) {
    this.calls.checkpoint += 1;
    if (this.fail.checkpoint) throw this.fail.checkpoint;
    return {
      observedSnapshotGuid: record.source.expectedSnapshotGuid,
      snapshotCreationTxg: record.source.snapshotCreationTxg,
      sourceVerifiedAt: '2026-07-25T12:01:00.000Z',
      observationDigest: '6'.repeat(64),
    };
  }

  async execute(record) {
    this.calls.execute += 1;
    if (this.fail.execute) throw this.fail.execute;
    const machineId = `machine-${record.transactionId.slice(-8)}`;
    const jobId = `job-mutation-${record.transactionId.slice(-8)}`;
    this.machine?.set(activeMachine({ machineId, ownerPrincipal: record.ownerPrincipal, expectedSnapshotGuid: record.source.expectedSnapshotGuid }));
    this.jobs?.set(jobRecord(jobId, record.transactionId, record.ownerPrincipal));
    return { machineIds: [machineId], allRelatedJobIds: [jobId], mutationJobIds: [jobId], activeJobIds: [] };
  }

  async validate(record) {
    this.calls.validate += 1;
    if (this.fail.validate) throw this.fail.validate;
    const jobId = `job-validation-${record.transactionId.slice(-8)}`;
    this.jobs?.set(jobRecord(jobId, record.transactionId, record.ownerPrincipal));
    return { allRelatedJobIds: [jobId], validationJobIds: [jobId], activeJobIds: [] };
  }

  async finalize(record) {
    this.calls.finalize += 1;
    if (this.fail.finalize) throw this.fail.finalize;
    const suffix = record.transactionId.slice(-8);
    const ids = [`patch-${suffix}`, `archive-${suffix}`, `manifest-${suffix}`];
    for (const id of ids) this.artifacts?.set(finalizedArtifact(id));
    return {
      candidateId: `candidate-${suffix}`,
      candidateTree: 'c'.repeat(40),
      changedPaths: ['docs/fixture.md'],
      patchArtifactId: ids[0],
      candidateArchiveArtifactId: ids[1],
      candidateManifestArtifactId: ids[2],
      validationDigest: '7'.repeat(64),
      validationPassed: true,
      artifactIds: ids,
      receiptReferences: [`receipt-${suffix}`],
    };
  }

  async completeEvidence(record) {
    this.calls.completeEvidence += 1;
    if (this.fail.completeEvidence) throw this.fail.completeEvidence;
    const id = `evidence-${record.transactionId.slice(-8)}`;
    this.artifacts?.set(finalizedArtifact(id, '8'.repeat(64)));
    return {
      finalEvidenceIndexArtifactId: id,
      finalEvidenceIndexDigest: '8'.repeat(64),
      artifactIds: [id],
      receiptReferences: [`receipt-evidence-${record.transactionId.slice(-8)}`],
    };
  }
}

export function makeHarness(t, options = {}) {
  const stateRoot = options.stateRoot ?? tempRoot(t);
  mkdirSync(stateRoot, { recursive: true });
  const jobs = options.jobs ?? new FakeJobs();
  const machine = options.machine ?? new FakeMachine();
  const artifacts = options.artifacts ?? new FakeArtifacts();
  const codeDriver = options.codeDriver ?? new FakeCodeDriver({ jobs, machine, artifacts });
  let tick = 0;
  let id = 0;
  const service = new TransactionService({
    stateRoot,
    jobs,
    machine,
    artifacts,
    codeDriver,
    now: options.now ?? (() => new Date(Date.parse('2026-07-25T12:00:00.000Z') + tick++ * 1000).toISOString()),
    transactionIdFactory: options.transactionIdFactory ?? (() => `tx_${(++id).toString(16).padStart(32, '0')}`),
    controllerId: options.controllerId ?? 'controller-a',
    hostBootId: options.hostBootId ?? 'boot-a',
    controllerAbsent: options.controllerAbsent ?? (() => false),
    maximumListLimit: options.maximumListLimit ?? 10,
    maximumEventLimit: options.maximumEventLimit ?? 10,
    startupReconcileLimit: options.startupReconcileLimit ?? 10,
    store: options.store,
  });
  return { stateRoot, service, jobs, machine, artifacts, codeDriver };
}

export function createVia(service, { owner = 'owner-a', key = 'create-key-0001', request = createRequest() } = {}) {
  return service.create(request, context(owner, key));
}

export function createStore(t, options = {}) {
  return new DurableTransactionStore(tempRoot(t, 'baby-x-transaction-store-'), options);
}
