import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assertTransactionRecord,
  assertTransactionTransition,
  createTransactionEvent,
  normalizeTransactionCreateRequest,
  redactTransactionDetails,
  transactionRecordDigest,
} from '../../dist/runtime/transactions/schemas.js';
import { createRequest, makeRecord } from './_transaction-fixture.mjs';

function committedRecord() {
  const base = makeRecord();
  return {
    ...base,
    lifecycle: {
      ...base.lifecycle,
      persistedState: 'COMMITTED',
      desiredState: 'COMMITTED',
      stateSequence: 20,
      terminal: true,
      updatedAt: '2026-07-25T12:20:00.000Z',
      completedAt: '2026-07-25T12:20:00.000Z',
    },
    source: {
      ...base.source,
      observedSnapshotGuid: base.source.expectedSnapshotGuid,
      sourceVerifiedAt: '2026-07-25T12:01:00.000Z',
    },
    execution: {
      ...base.execution,
      allRelatedJobIds: ['job-1'],
      mutationJobIds: ['job-1'],
      jobTerminalityStatus: 'all-terminal',
      mutationSubmitted: true,
      validationSubmitted: true,
    },
    candidate: {
      ...base.candidate,
      candidateId: 'candidate-1',
      candidateTree: 'c'.repeat(40),
      changedPaths: ['docs/fixture.md'],
      modifiedFiles: ['docs/fixture.md'],
      pathChanges: [{ path: 'docs/fixture.md', status: 'modified', oldMode: '100644', newMode: '100644', oldObject: 'a'.repeat(40), newObject: 'b'.repeat(40), symlinkChanged: false }],
      patchArtifactId: 'patch-1',
      candidateArchiveArtifactId: 'archive-1',
      candidateManifestArtifactId: 'manifest-1',
      validationDigest: '7'.repeat(64),
      validationPassed: true,
    },
    evidence: {
      artifactIds: ['archive-1', 'evidence-1', 'manifest-1', 'patch-1'],
      receiptReferences: ['receipt-1'],
      proofReferences: ['proof-1'],
      certificationReferences: ['certification-1'],
      eventTailDigest: '8'.repeat(64),
      finalEvidenceIndexArtifactId: 'evidence-1',
      finalEvidenceIndexDigest: '9'.repeat(64),
    },
    cleanup: {
      required: true,
      requested: true,
      completed: true,
      machineAbsenceVerified: true,
      processAbsenceVerified: true,
      mountAbsenceVerified: true,
      rootPathAbsenceVerified: true,
      datasetAbsenceVerified: true,
      socketAbsenceVerified: true,
      controllerLeaseAbsenceVerified: true,
      temporaryPathAbsenceVerified: true,
      sourcePreserved: true,
      completedAt: '2026-07-25T12:19:00.000Z',
    },
  };
}

test('transaction record schema is strict and rejects unknown fields', () => {
  const record = makeRecord();
  assert.deepEqual(assertTransactionRecord(record), record);
  assert.throws(() => assertTransactionRecord({ ...record, unknown: true }), /incompatible schema/u);
  assert.throws(() => assertTransactionRecord({ ...record, schemaVersion: '2.0.0' }), /schema version is unsupported/u);
});

test('unknown transaction kinds fail closed at request and durable-record boundaries', () => {
  assert.throws(() => normalizeTransactionCreateRequest(createRequest({ transactionKind: 'BROWSER_TRANSACTION' }), 'owner-a', 'create-key-0001'), /unknown transaction kind/u);
  assert.throws(() => assertTransactionRecord({ ...makeRecord(), transactionKind: 'DEPLOYMENT' }), /transaction kind is unsupported/u);
});

test('raw secret-bearing environment values are rejected and only references are retained', () => {
  assert.throws(() => normalizeTransactionCreateRequest(createRequest({ normalizedEnvironment: [{ name: 'API_TOKEN', value: 'raw-secret' }] }), 'owner-a', 'create-key-0001'), /secret-bearing environment/u);
  const request = normalizeTransactionCreateRequest(createRequest({ credentialReferenceIds: ['credential-ref-1'], credentialPresence: true }), 'owner-a', 'create-key-0001');
  const record = makeRecord({ request });
  assert.deepEqual(record.environment.credentialReferenceIds, ['credential-ref-1']);
  assert.equal(record.environment.credentialPresence, true);
  assert.doesNotMatch(JSON.stringify(record), /raw-secret/u);
});

test('illegal state transitions and direct EXECUTING-to-COMMITTED transitions are rejected', () => {
  assert.throws(() => assertTransactionTransition('REQUESTED', 'VALIDATING'), /illegal transaction transition/u);
  assert.throws(() => assertTransactionTransition('EXECUTING', 'COMMITTED'), /illegal transaction transition/u);
  assert.doesNotThrow(() => assertTransactionTransition('REQUESTED', 'CHECKPOINTING'));
});

test('RECOVERY_REQUIRED has one public rollback entry without enabling unrelated transitions', () => {
  assert.doesNotThrow(() => assertTransactionTransition('RECOVERY_REQUIRED', 'ROLLBACK_REQUESTED'));
  assert.doesNotThrow(() => assertTransactionTransition('RECOVERY_REQUIRED', 'ROLLING_BACK'));
  assert.throws(() => assertTransactionTransition('RECOVERY_REQUIRED', 'COMMITTED'), /illegal transaction transition/u);
  assert.throws(() => assertTransactionTransition('RECOVERY_REQUIRED', 'VALIDATING'), /illegal transaction transition/u);
});

test('COMMITTED requires candidate tree, validation, terminal jobs, cleanup, and complete evidence', () => {
  const valid = committedRecord();
  assert.doesNotThrow(() => assertTransactionRecord(valid));
  assert.throws(() => assertTransactionRecord({ ...valid, candidate: { ...valid.candidate, candidateTree: null } }), /durable validated candidate/u);
  assert.throws(() => assertTransactionRecord({ ...valid, execution: { ...valid.execution, activeJobIds: ['job-1'], jobTerminalityStatus: 'active' } }), /all related jobs terminal/u);
  assert.throws(() => assertTransactionRecord({ ...valid, cleanup: { ...valid.cleanup, completed: false, completedAt: null } }), /completed positive cleanup/u);
  assert.throws(() => assertTransactionRecord({ ...valid, cleanup: { ...valid.cleanup, controllerLeaseAbsenceVerified: false } }), /full positive absence|completed cleanup/u);
  assert.throws(() => assertTransactionRecord({ ...valid, cleanup: { ...valid.cleanup, socketAbsenceVerified: false } }), /full positive absence|completed cleanup/u);
  assert.throws(() => assertTransactionRecord({ ...valid, cleanup: { ...valid.cleanup, temporaryPathAbsenceVerified: false } }), /full positive absence|completed cleanup/u);
  assert.throws(() => assertTransactionRecord({ ...valid, evidence: { ...valid.evidence, finalEvidenceIndexArtifactId: null } }), /complete evidence/u);
  assert.deepEqual(valid.authorityReferences, { rootTransactionReferences: [], rootEffectPlanReferences: [], deploymentRecordReferences: [] });
});

test('FAILED, ROLLED_BACK, and EXPIRED cannot hide unresolved cleanup', () => {
  for (const state of ['FAILED', 'ROLLED_BACK', 'EXPIRED']) {
    const base = makeRecord();
    const value = {
      ...base,
      lifecycle: { ...base.lifecycle, persistedState: state, desiredState: state, terminal: true, completedAt: '2026-07-25T12:02:00.000Z' },
      cleanup: { ...base.cleanup, required: true },
    };
    assert.throws(() => assertTransactionRecord(value), /cannot hide|cannot bypass/u);
  }
});

test('transaction record digest is stable across equivalent canonical values', () => {
  const first = makeRecord();
  const second = JSON.parse(JSON.stringify(first));
  assert.equal(transactionRecordDigest(first), transactionRecordDigest(second));
  assert.match(transactionRecordDigest(first), /^[a-f0-9]{64}$/u);
});

test('transaction event digest is deterministic across equivalent drafts', () => {
  const draft = {
    transactionId: `tx_${'1'.repeat(32)}`,
    ownerPrincipal: 'owner-a',
    operation: 'babyx.transaction.create',
    phase: 'request',
    priorState: null,
    nextState: 'REQUESTED',
    priorSequence: 0,
    nextSequence: 1,
    requestDigest: '4'.repeat(64),
    idempotencyKey: 'create-key-0001',
    occurredAt: '2026-07-25T12:00:00.000Z',
    previousEventDigest: null,
  };
  const first = createTransactionEvent(draft);
  const second = createTransactionEvent({ ...draft });
  assert.equal(first.eventDigest, second.eventDigest);
  assert.equal(first.eventId, second.eventId);
});

test('event sequence discontinuity is rejected', () => {
  assert.throws(() => createTransactionEvent({
    transactionId: `tx_${'1'.repeat(32)}`,
    ownerPrincipal: 'owner-a',
    operation: 'babyx.transaction.reconcile',
    phase: 'test',
    priorState: 'REQUESTED',
    nextState: 'CHECKPOINTING',
    priorSequence: 1,
    nextSequence: 3,
    requestDigest: '4'.repeat(64),
    occurredAt: '2026-07-25T12:00:00.000Z',
  }), /sequence is discontinuous/u);
});

test('structured error details are bounded and redact secret-bearing keys', () => {
  const redacted = redactTransactionDetails({ token: 'secret', nested: { password: 'secret', safe: 'value' } });
  assert.deepEqual(redacted, { token: '[REDACTED]', nested: { password: '[REDACTED]', safe: 'value' } });
});


test('existing strict V2-B and V2-C records remain readable without durable rewrite', () => {
  const current = makeRecord();
  const {
    code,
    authorityReferences: _authorityReferences,
    candidate,
    evidence,
    cleanup,
    ...rest
  } = current;
  const {
    proofReferences: _proofReferences,
    certificationReferences: _certificationReferences,
    ...priorEvidence
  } = evidence;
  const {
    socketAbsenceVerified: _socketAbsenceVerified,
    controllerLeaseAbsenceVerified: _controllerLeaseAbsenceVerified,
    temporaryPathAbsenceVerified: _temporaryPathAbsenceVerified,
    ...priorCleanup
  } = cleanup;

  const legacy = {
    ...rest,
    schemaVersion: '1.0.0',
    candidate: {
      candidateId: candidate.candidateId,
      baseCommit: candidate.baseCommit,
      baseTree: candidate.baseTree,
      candidateTree: candidate.candidateTree,
      changedPaths: candidate.changedPaths,
      patchArtifactId: candidate.patchArtifactId,
      candidateArchiveArtifactId: candidate.candidateArchiveArtifactId,
      candidateManifestArtifactId: candidate.candidateManifestArtifactId,
      validationDigest: candidate.validationDigest,
      validationPassed: candidate.validationPassed,
    },
    evidence: priorEvidence,
    cleanup: priorCleanup,
  };
  const legacyBefore = JSON.stringify(legacy);
  const readableLegacy = assertTransactionRecord(legacy);
  assert.equal(readableLegacy.schemaVersion, '1.0.0');
  assert.equal(readableLegacy.code, null);
  assert.deepEqual(readableLegacy.authorityReferences, { rootTransactionReferences: [], rootEffectPlanReferences: [], deploymentRecordReferences: [] });
  assert.deepEqual(readableLegacy.evidence.proofReferences, []);
  assert.deepEqual(readableLegacy.evidence.certificationReferences, []);
  assert.equal(JSON.stringify(legacy), legacyBefore);
  assert.match(transactionRecordDigest(readableLegacy), /^[a-f0-9]{64}$/u);
  assert.throws(() => assertTransactionRecord({ ...legacy, code: null }), /incompatible schema/u);

  const intermediate = {
    ...rest,
    schemaVersion: '1.1.0',
    candidate,
    evidence: priorEvidence,
    cleanup: priorCleanup,
    code,
  };
  const intermediateBefore = JSON.stringify(intermediate);
  const readableIntermediate = assertTransactionRecord(intermediate);
  assert.equal(readableIntermediate.schemaVersion, '1.1.0');
  assert.deepEqual(readableIntermediate.authorityReferences, { rootTransactionReferences: [], rootEffectPlanReferences: [], deploymentRecordReferences: [] });
  assert.deepEqual(readableIntermediate.evidence.proofReferences, []);
  assert.deepEqual(readableIntermediate.evidence.certificationReferences, []);
  assert.equal(JSON.stringify(intermediate), intermediateBefore);
  assert.match(transactionRecordDigest(readableIntermediate), /^[a-f0-9]{64}$/u);
  assert.throws(() => assertTransactionRecord({ ...intermediate, authorityReferences: current.authorityReferences }), /incompatible schema/u);
});
