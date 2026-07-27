import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { CALL_X_DESCRIPTION, CALL_X_TOOL, callX } from '../src/tool.js';
import { canonicalize } from '../src/canonical.js';
import { encodeFrame, decodeFrame } from '../src/protocol.js';
import { appendBoundedFrameChunk } from '../src/client.js';
import { readJsonBody } from '../src/server.js';
import { verifyProof, sha256 } from '../src/proof.js';

test('gateway exposes exactly call_x without a duplicate operation catalog', () => { assert.equal(CALL_X_TOOL.name, 'call_x'); assert.match(CALL_X_DESCRIPTION, /single unrestricted Baby-X interface/u); assert.equal(Object.keys(CALL_X_TOOL.inputSchema.properties).length, 3); });
test('QRT1 gateway frames are binary safe', () => { const value = { operation: 'babyx.exec', payload: { data: Buffer.from([0, 255]).toString('base64') } }; assert.deepEqual(decodeFrame(encodeFrame(value)), value); });
test('compact proof verification detects mutation', () => { const { privateKey, publicKey } = generateKeyPairSync('ed25519'); const result = { value: 1 }; const unsigned = { version: '1', requestId: 'r', operation: 'babyx.health', ok: true, startedAt: 'a', completedAt: 'b', hostname: 'h', machineIdSha256: 'm', resultSha256: sha256(canonicalize(result)), keyId: 'k' }; const proof = { ...unsigned, signature: sign(null, Buffer.from(canonicalize(unsigned)), privateKey).toString('base64') }; assert.equal(verifyProof(publicKey, proof, result), true); assert.equal(verifyProof(publicKey, proof, { value: 2 }), false); });
test('call_x forwards any dynamically described babyx operation', async () => { const client = { call: async (operation, payload, key) => ({ result: { operation, payload, key }, proof: { verified: true } }) }; const result = await callX(client, { operation: 'babyx.machine.raw', payload: { tool: 'machinectl', argv: ['list'] }, idempotencyKey: 'machine-list-1' }); assert.equal(result.structuredContent.result.operation, 'babyx.machine.raw'); });


test('gateway frame accumulation rejects oversized chunks and declared frames before concatenation', () => {
  assert.throws(() => appendBoundedFrameChunk(Buffer.alloc(0), Buffer.alloc(33), 24), /exceeds configured maximum/u);
  const header = Buffer.alloc(8);
  header.write('QRT1', 0);
  header.writeUInt32BE(25, 4);
  assert.throws(() => appendBoundedFrameChunk(Buffer.alloc(0), header, 24), /exceeds configured maximum/u);
  const accepted = appendBoundedFrameChunk(Buffer.alloc(0), encodeFrame({ ok: true }), 1024);
  assert.deepEqual(decodeFrame(accepted), { ok: true });
});

test('gateway JSON body reader enforces declared and streamed size bounds', async () => {
  const declared = { headers: { 'content-length': '9' }, async *[Symbol.asyncIterator]() { yield Buffer.from('{}'); } };
  await assert.rejects(() => readJsonBody(declared, 8), /body too large/u);
  const streamed = { headers: {}, resume() {}, async *[Symbol.asyncIterator]() { yield Buffer.from('{"a":'); yield Buffer.from('12345}'); } };
  await assert.rejects(() => readJsonBody(streamed, 8), /body too large/u);
  const valid = { headers: {}, async *[Symbol.asyncIterator]() { yield Buffer.from('{"a":1}'); } };
  assert.deepEqual(await readJsonBody(valid, 8), { a: 1 });
});
