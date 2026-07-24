import { connect } from 'node:net';
import { randomUUID, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalize } from './canonical.js';
import { decodeFrame, encodeFrame } from './protocol.js';
import { verifyProof } from './proof.js';

export class BabyXClient {
  constructor(config) { this.config = config; this.privateKey = readFileSync(config.authorityPrivateKey); this.proofPublicKey = readFileSync(config.proofPublicKey); }
  async call(operation, payload = {}, idempotencyKey = randomUUID()) {
    const requestId = randomUUID();
    const unsigned = { requestId, operation, payload, idempotencyKey, timestamp: new Date().toISOString(), nonce: randomUUID(), subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner' };
    const envelope = { ...unsigned, signature: sign(null, Buffer.from(canonicalize(unsigned)), this.privateKey).toString('base64') };
    const response = await new Promise((resolve, reject) => {
      const socket = connect(this.config.socketPath); let pending = Buffer.alloc(0);
      socket.once('error', reject); socket.once('connect', () => socket.write(encodeFrame(envelope)));
      socket.on('data', (chunk) => { pending = Buffer.concat([pending, chunk]); if (pending.length < 8) return; const length = pending.readUInt32BE(4); if (pending.length < length + 8) return; try { resolve(decodeFrame(pending.subarray(0, length + 8))); } catch (error) { reject(error); } finally { socket.end(); } });
    });
    if (!response || typeof response !== 'object' || response.requestId !== requestId || response.ok !== true) throw new Error(response?.error ?? 'Baby-X request failed');
    if (!response.proof || !verifyProof(this.proofPublicKey, response.proof, response.result)) throw new Error('Baby-X proof verification failed');
    return { result: response.result, proof: response.proof };
  }
}
