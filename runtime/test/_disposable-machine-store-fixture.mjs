import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MachineServiceError } from '../../dist/runtime/machines/errors.js';
import {
  MACHINE_SCHEMA_VERSION,
  assertDisposableMachineRecord,
  canonicalMachineEvidence,
  canonicalMachineRequestDigest,
  createMachineEvent,
} from '../../dist/runtime/machines/schemas.js';
import {
  assertMachineTransition,
  canTransitionMachineState,
} from '../../dist/runtime/machines/states.js';
import { DisposableMachineStore } from '../../dist/runtime/machines/store.js';

export const NOW = '2026-07-25T10:00:00.000Z';
export const LATER = '2026-07-25T10:01:00.000Z';
export const MUCH_LATER = '2026-07-25T11:00:00.000Z';
export const HOST_SHA = '1'.repeat(64);

export function makeRecord(overrides = {}) {
  const machineId = overrides.machineId ?? 'mx_machine0001';
  const machineName = overrides.machineName ?? 'machine-1';
  const cloneDataset = overrides.cloneDataset ?? `pool/runs/${machineName}`;
  const mountpoint = overrides.mountpoint ?? `/var/lib/baby-x/machines/${machineName}`;
  const idempotencyKey = overrides.idempotencyKey ?? 'create-machine-1';
  const requestDigest = overrides.requestDigest ?? canonicalMachineRequestDigest({
    sourceSnapshot: 'pool/base@golden-v1',
    machineName,
    cloneDataset,
    mountpoint,
    launch: { boot: true, networkMode: 'none' },
  });
  return {
    schemaVersion: MACHINE_SCHEMA_VERSION,
    machineId,
    machineName,
    providerId: 'zfs-nspawn-disposable@1',
    ownerPrincipal: 'owner:test',
    creationIdempotencyKey: idempotencyKey,
    creationRequestDigest: requestDigest,
    source: {
      kind: 'zfs-snapshot',
      snapshot: 'pool/base@golden-v1',
      dataset: 'pool/base',
      snapshotGuid: '111222333',
      creationTxg: '444555',
      observedAt: NOW,
    },
    clone: {
      dataset: cloneDataset,
      mountpoint,
      expectedRootPrefix: '/var/lib/baby-x/machines',
      ownershipMarker: `baby-x:${machineId}`,
    },
    launch: {
      boot: true,
      networkMode: 'none',
      readOnlyRoot: false,
      binds: [],
      environment: [
        { name: 'VISIBLE', value: 'safe', redacted: false },
        { name: 'TOKEN', value: 'do-not-persist-in-evidence', redacted: true },
      ],
      properties: [],
      normalizedDigest: canonicalMachineRequestDigest({ boot: true, networkMode: 'none' }),
    },
    lifecycle: {
      desiredState: 'READY',
      persistedState: 'REQUESTED',
      observedState: 'NOT_OBSERVED',
      stateSequence: 1,
      terminal: false,
      createdAt: NOW,
      updatedAt: NOW,
    },
    host: {
      hostname: 'test-host',
      machineIdSha256: HOST_SHA,
      bootIdAtCreate: 'boot-1',
    },
    observations: {
      dataset: 'unknown',
      snapshot: 'unknown',
      mountpoint: 'unknown',
      machinectl: 'unknown',
      process: 'unknown',
      rootPath: 'unknown',
    },
    activeJobIds: [],
    protectedJobIds: [],
    artifactIds: [],
    proofReferences: [],
    cleanup: {
      requested: false,
      stopAttempted: false,
      stopVerified: false,
      datasetDestroyAttempted: false,
      datasetAbsentVerified: false,
      rootAbsentVerified: false,
      machineAbsentVerified: false,
      processAbsentVerified: false,
      completed: false,
      retainedEvidence: [],
    },
  };
}

export function temporaryStore(t) {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-machine-store-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { root, store: new DisposableMachineStore(root) };
}

export function creationEvent(record) {
  return {
    operation: 'babyx.machine.create',
    phase: 'request',
    kind: 'machine.requested',
    message: 'machine request persisted',
    requestDigest: record.creationRequestDigest,
    idempotencyKey: record.creationIdempotencyKey,
    occurredAt: NOW,
  };
}

export function transitionEvent(operation, phase, kind, message, occurredAt = LATER) {
  return { operation, phase, kind, message, occurredAt };
}

export function assertMachineError(code) {
  return (error) => error instanceof MachineServiceError && error.code === code;
}


export {
  test,
  assert,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
  tmpdir,
  join,
  MachineServiceError,
  MACHINE_SCHEMA_VERSION,
  assertDisposableMachineRecord,
  canonicalMachineEvidence,
  canonicalMachineRequestDigest,
  createMachineEvent,
  assertMachineTransition,
  canTransitionMachineState,
  DisposableMachineStore,
};
