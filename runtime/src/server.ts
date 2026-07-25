import { createServer, type Socket } from 'node:net';
import { readFileSync } from 'node:fs';
import { BabyXRuntime, canonicalize, decodeFrame, encodeFrame, verifyCanonical, type JsonObject } from './core.ts';
import { loadConfig } from './config.ts';

interface Envelope extends JsonObject {
  requestId: string;
  operation: string;
  payload: JsonObject;
  idempotencyKey: string;
  timestamp: string;
  nonce: string;
  subject: 'stealtheye-owner';
  authorityClass: 'unrestricted-owner';
  signature: string;
}

function unsigned(envelope: Envelope): JsonObject {
  const { signature: _signature, ...value } = envelope;
  return value;
}

function peerUid(socket: Socket): number {
  const fd = (socket as unknown as { _handle?: { fd?: number } })._handle?.fd;
  if (typeof fd !== 'number') throw new Error('socket file descriptor unavailable');
  try {
    const addon = process.getBuiltinModule('module').createRequire(import.meta.url)('../build/Release/peer_cred.node') as { getPeerCredentials(value: number): { uid: number } };
    return addon.getPeerCredentials(fd).uid;
  } catch (error) {
    if (process.env.BABY_X_ALLOW_TEST_PEER_CRED === '1') return Number(process.env.BABY_X_GATEWAY_UID ?? process.getuid?.() ?? -1);
    throw error;
  }
}

export function startRuntimeServer(runtime = new BabyXRuntime()): ReturnType<typeof createServer> {
  const config = loadConfig();
  const publicKeyPath = process.env.BABY_X_GATEWAY_PUBLIC_KEY;
  if (!publicKeyPath) throw new Error('BABY_X_GATEWAY_PUBLIC_KEY is required');
  const publicKey = readFileSync(publicKeyPath);
  const nonces = new Map<string, number>();
  const server = createServer((socket) => {
    if (peerUid(socket) !== config.gatewayUid) { socket.destroy(new Error('peer uid mismatch')); return; }
    let pending = Buffer.alloc(0);
    socket.on('data', async (chunk) => {
      pending = Buffer.concat([pending, chunk]);
      while (pending.length >= 8) {
        const length = pending.readUInt32BE(4);
        if (pending.length < length + 8) return;
        const frame = pending.subarray(0, length + 8); pending = pending.subarray(length + 8);
        const startedAt = new Date().toISOString();
        try {
          const envelope = decodeFrame(frame) as Envelope;
          if (envelope.subject !== config.ownerSubject || envelope.authorityClass !== config.authorityClass) throw new Error('owner identity mismatch');
          const age = Math.abs(Date.now() - Date.parse(envelope.timestamp)); if (!Number.isFinite(age) || age > config.requestMaxAgeMs) throw new Error('stale request');
          const seen = nonces.get(envelope.nonce); if (seen && Date.now() - seen < config.nonceRetentionMs) throw new Error('nonce replay'); nonces.set(envelope.nonce, Date.now());
          if (!verifyCanonical(publicKey, unsigned(envelope), envelope.signature)) throw new Error('invalid signature');
          const result = await runtime.execute(envelope.operation, envelope.payload ?? {}, { idempotencyKey: envelope.idempotencyKey, subject: envelope.subject, authorityClass: envelope.authorityClass });
          const proof = runtime.createProof(envelope.requestId, envelope.operation, true, startedAt, result);
          socket.write(encodeFrame({ requestId: envelope.requestId, ok: true, result, proof }));
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          socket.write(encodeFrame({ ok: false, error: message, digest: canonicalize(message) }));
        }
      }
    });
  });
  server.listen({ path: config.socketPath });
  return server;
}
