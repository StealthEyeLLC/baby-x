import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BoundedDrainAuthority,
  canonicalize,
  normalizeDrainPolicy,
  sha256,
} from '../../dist/runtime/index.js';

const START = '2026-07-27T04:00:00.000Z';
const DEADLINE = '2026-07-27T04:01:00.000Z';
const CONTEXT = { subject:'owner-release', idempotencyKey:'drain-test', authorityClass:'owner' };
const TARGET = {
  serviceId:'notes-api',
  slotId:'blue',
  releaseId:'release-old',
  unitIdentity:'babyx-release-notes-api-blue.service',
  processIdentityDigest:'a'.repeat(64),
  routeGeneration:'b'.repeat(64),
};

function policy(overrides = {}) {
  return normalizeDrainPolicy({
    schemaVersion:'1.0.0',
    timeoutMs:60_000,
    intervalMs:1_000,
    maximumSamples:8,
    keepAlive:true,
    websocket:true,
    sse:true,
    worker:true,
    scheduler:true,
    keepAliveTimeoutMs:5_000,
    websocketMaximumLifetimeMs:30_000,
    sseMaximumLifetimeMs:30_000,
    workerGracePeriodMs:20_000,
    schedulerHandoffRequired:true,
    forceTerminationAfterDeadline:false,
    rollbackBehavior:'RESTORE_AND_CANCEL_DRAIN',
    ...overrides,
  });
}

function record(drainPolicy, overrides = {}) {
  return {
    priorKnownGoodSlotId:'blue',
    drainStatus:{
      schemaVersion:'1.0.0',
      classification:'DRAINING',
      drained:false,
      startedAt:START,
      deadline:DEADLINE,
      nextObservationAt:START,
      policyDigest:sha256(canonicalize(drainPolicy)),
      target:structuredClone(TARGET),
      observations:[],
      observationCount:0,
      ...overrides,
    },
  };
}

function observation(overrides = {}) {
  return {
    schemaVersion:'1.0.0',
    observationSequence:1,
    observedAt:START,
    ...structuredClone(TARGET),
    providerStatus:'AVAILABLE',
    activeKeepAliveConnections:0,
    activeWebSockets:0,
    activeSseStreams:0,
    activeLongRunningRequests:0,
    activeWorkerTasks:0,
    queuedWorkerTasks:0,
    activeSchedulerWork:0,
    queuedSchedulerWork:0,
    applicationStatus:'DRAINED',
    ...overrides,
  };
}

function provider(result) {
  return {
    authority:'release-drain-observation',
    async observe() {
      if (result instanceof Error) throw result;
      return structuredClone(result);
    },
  };
}

async function execute(observationValue, options = {}) {
  const drainPolicy = options.policy ?? policy();
  const authority = new BoundedDrainAuthority({
    ...(observationValue === undefined ? {} : { provider:provider(observationValue) }),
    now:options.now ?? (() => START),
  });
  return authority.drain(options.record ?? record(drainPolicy), { drainPolicy }, CONTEXT);
}

test('R4-01 zero observed connections and work produces DRAINED evidence', async () => {
  const result = await execute(observation());
  assert.equal(result.classification, 'DRAINED');
  assert.equal(result.drained, true);
  assert.equal(result.observationCount, 1);
  assert.equal(result.observations.length, 1);
  assert.equal(result.finalObservationDigest.length, 64);
  assert.deepEqual(result.remainingWork, {
    keepAliveConnections:0, webSockets:0, sseStreams:0, longRunningRequests:0,
    activeWorkerTasks:0, queuedWorkerTasks:0, activeSchedulerWork:0, queuedSchedulerWork:0,
  });
});

test('R4-02 active keep-alive connection remains DRAINING', async () => {
  const result = await execute(observation({ activeKeepAliveConnections:1, applicationStatus:'DRAINING' }));
  assert.equal(result.classification, 'DRAINING');
  assert.equal(result.drained, false);
  assert.equal(result.remainingWork.keepAliveConnections, 1);
});

test('R4-03 active WebSocket remains DRAINING', async () => {
  const result = await execute(observation({ activeWebSockets:1, applicationStatus:'DRAINING' }));
  assert.equal(result.classification, 'DRAINING');
  assert.equal(result.remainingWork.webSockets, 1);
});

test('R4-04 active SSE stream remains DRAINING', async () => {
  const result = await execute(observation({ activeSseStreams:1, applicationStatus:'DRAINING' }));
  assert.equal(result.classification, 'DRAINING');
  assert.equal(result.remainingWork.sseStreams, 1);
});

test('R4-05 long-running request remains DRAINING', async () => {
  const result = await execute(observation({ activeLongRunningRequests:1, applicationStatus:'DRAINING' }));
  assert.equal(result.classification, 'DRAINING');
  assert.equal(result.remainingWork.longRunningRequests, 1);
});

test('R4-06 worker and queued work remain DRAINING', async () => {
  const result = await execute(observation({ activeWorkerTasks:1, queuedWorkerTasks:2, applicationStatus:'DRAINING' }));
  assert.equal(result.classification, 'DRAINING');
  assert.equal(result.remainingWork.activeWorkerTasks, 1);
  assert.equal(result.remainingWork.queuedWorkerTasks, 2);
});

test('R4-07 scheduler work and handoff remain DRAINING', async () => {
  const result = await execute(observation({ activeSchedulerWork:1, queuedSchedulerWork:1, applicationStatus:'DRAINING' }));
  assert.equal(result.classification, 'DRAINING');
  assert.equal(result.remainingWork.activeSchedulerWork, 1);
  assert.equal(result.remainingWork.queuedSchedulerWork, 1);
});

test('R4-08 deadline expiry is TIMED_OUT without provider invocation', async () => {
  let calls = 0;
  const drainPolicy = policy();
  const authority = new BoundedDrainAuthority({
    provider:{ authority:'release-drain-observation', async observe() { calls += 1; return observation(); } },
    now:() => DEADLINE,
  });
  const result = await authority.drain(record(drainPolicy), { drainPolicy }, CONTEXT);
  assert.equal(result.classification, 'TIMED_OUT');
  assert.equal(result.drained, false);
  assert.equal(calls, 0);
});

test('R4-09 forced-termination policy classifies deadline truth explicitly', async () => {
  const drainPolicy = policy({ forceTerminationAfterDeadline:true });
  const result = await execute(observation(), { policy:drainPolicy, now:() => DEADLINE });
  assert.equal(result.classification, 'FORCED_TERMINATION_REQUIRED');
  assert.equal(result.drained, false);
});

test('R4-10 unconfigured provider is UNSUPPORTED and never drained', async () => {
  const result = await execute(undefined);
  assert.equal(result.classification, 'UNSUPPORTED');
  assert.equal(result.drained, false);
  assert.equal(result.providerConfigured, false);
});

test('R4-11 provider exception is PROVIDER_FAILED and redacted', async () => {
  const result = await execute(new Error('provider failed with token=synthetic-secret'));
  assert.equal(result.classification, 'PROVIDER_FAILED');
  assert.equal(result.drained, false);
  assert.equal(result.error.code, 'release_provider_failed');
  assert.doesNotMatch(JSON.stringify(result), /synthetic-secret/u);
});

test('R4-12 provider UNKNOWN remains UNKNOWN', async () => {
  const result = await execute(observation({ providerStatus:'UNKNOWN', applicationStatus:'UNKNOWN' }));
  assert.equal(result.classification, 'UNKNOWN');
  assert.equal(result.drained, false);
});

test('R4-13 provider unavailable cannot report no-op success', async () => {
  const result = await execute(observation({ providerStatus:'UNAVAILABLE', applicationStatus:'UNKNOWN' }));
  assert.equal(result.classification, 'PROVIDER_FAILED');
  assert.equal(result.drained, false);
});

test('R4-14 wrong process identity is IDENTITY_MISMATCH', async () => {
  const result = await execute(observation({ processIdentityDigest:'c'.repeat(64) }));
  assert.equal(result.classification, 'IDENTITY_MISMATCH');
  assert.equal(result.drained, false);
});

test('R4-15 wrong unit identity is IDENTITY_MISMATCH', async () => {
  const result = await execute(observation({ unitIdentity:'babyx-release-foreign.service' }));
  assert.equal(result.classification, 'IDENTITY_MISMATCH');
});

test('R4-16 route rollback or generation change during drain is IDENTITY_MISMATCH', async () => {
  const result = await execute(observation({ routeGeneration:'d'.repeat(64) }));
  assert.equal(result.classification, 'IDENTITY_MISMATCH');
  assert.equal(result.drained, false);
});

test('R4-17 malformed provider output fails closed', async () => {
  const result = await execute({ ...observation(), unknownAuthorityField:true });
  assert.equal(result.classification, 'PROVIDER_FAILED');
  assert.equal(result.drained, false);
});

test('R4-18 orchestrator restart resumes bounded observations without losing prior truth', async () => {
  const drainPolicy = policy();
  const first = await execute(observation({ activeWebSockets:1, applicationStatus:'DRAINING' }), { policy:drainPolicy });
  assert.equal(first.classification, 'DRAINING');
  assert.equal(first.observationCount, 1);
  const secondObservation = observation({ observationSequence:2, observedAt:'2026-07-27T04:00:02.000Z' });
  const second = await execute(secondObservation, {
    policy:drainPolicy,
    now:() => '2026-07-27T04:00:02.000Z',
    record:{ priorKnownGoodSlotId:'blue', drainStatus:first },
  });
  assert.equal(second.classification, 'DRAINED');
  assert.equal(second.drained, true);
  assert.equal(second.observationCount, 2);
  assert.equal(second.observations.length, 2);
  assert.equal(second.observations[0].activeWebSockets, 1);
  assert.equal(second.observations[1].activeWebSockets, 0);
});

test('R4-19 observation tail remains bounded at 256 entries', async () => {
  const drainPolicy = policy({ maximumSamples:1_000 });
  const prior = Array.from({ length:256 }, (_, index) => ({ observationSequence:index + 1, observationDigest:sha256(String(index)) }));
  const current = record(drainPolicy, { observations:prior, observationCount:256, nextObservationAt:START });
  const result = await execute(observation({ observationSequence:257 }), { policy:drainPolicy, record:current });
  assert.equal(result.classification, 'DRAINED');
  assert.equal(result.observationCount, 257);
  assert.equal(result.observations.length, 256);
  assert.equal(result.observations.at(-1).observationSequence, 257);
});


test('R4-20 application-defined FAILED drain status fails closed', async () => {
  const result = await execute(observation({ applicationStatus:'FAILED' }));
  assert.equal(result.classification, 'PROVIDER_FAILED');
  assert.equal(result.drained, false);
});

test('R4-21 application-defined UNKNOWN drain status remains UNKNOWN', async () => {
  const result = await execute(observation({ applicationStatus:'UNKNOWN' }));
  assert.equal(result.classification, 'UNKNOWN');
  assert.equal(result.drained, false);
});
