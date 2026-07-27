import { connect } from 'node:net';
import { randomUUID, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalize } from './canonical.js';
import { decodeFrame, encodeFrame } from './protocol.js';
import { verifyProof } from './proof.js';

export function appendBoundedFrameChunk(pending, chunk, maximum) {
  if (!Buffer.isBuffer(pending) || !Buffer.isBuffer(chunk)) throw new Error('frame chunks must be buffers');
  if (!Number.isSafeInteger(maximum) || maximum < 1) throw new Error('maximum frame size must be a positive safe integer');
  if (chunk.length > maximum + 8 - pending.length) throw new Error('Baby-X response frame exceeds configured maximum');
  const next = Buffer.concat([pending, chunk], pending.length + chunk.length);
  if (next.length >= 8 && next.readUInt32BE(4) > maximum) throw new Error('Baby-X response frame exceeds configured maximum');
  return next;
}

export class BabyXClient {
  constructor(config) {
    this.config = config;
    this.privateKey = readFileSync(config.authorityPrivateKey);
    this.proofPublicKey = readFileSync(config.proofPublicKey);
  }

  async call(operation, payload = {}, idempotencyKey = randomUUID()) {
    const requestId = randomUUID();
    const unsigned = { requestId, operation, payload, idempotencyKey, timestamp: new Date().toISOString(), nonce: randomUUID(), subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner' };
    const envelope = { ...unsigned, signature: sign(null, Buffer.from(canonicalize(unsigned)), this.privateKey).toString('base64') };
    const response = await new Promise((resolve, reject) => {
      const socket = connect(this.config.socketPath);
      const maximum = this.config.maxFrameSize ?? 16_777_216;
      let pending = Buffer.alloc(0);
      let settled = false;
      const fail = (error) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        reject(error);
      };
      socket.once('error', fail);
      socket.once('connect', () => socket.write(encodeFrame(envelope)));
      socket.on('data', (chunk) => {
        if (settled) return;
        try {
          pending = appendBoundedFrameChunk(pending, chunk, maximum);
          if (pending.length < 8) return;
          const length = pending.readUInt32BE(4);
          if (pending.length < length + 8) return;
          if (pending.length !== length + 8) throw new Error('Baby-X response must contain exactly one frame');
          settled = true;
          resolve(decodeFrame(pending, maximum));
          socket.end();
        } catch (error) { fail(error); }
      });
    });
    if (!response || typeof response !== 'object' || response.requestId !== requestId || response.ok !== true) throw new Error(response?.error ?? 'Baby-X request failed');
    if (!response.proof || !verifyProof(this.proofPublicKey, response.proof, response.result)) throw new Error('Baby-X proof verification failed');
    return { result: response.result, proof: response.proof };
  }
}
