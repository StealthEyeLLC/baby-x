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

export function appendBoundedRuntimeFrameChunk(pending: Buffer, chunk: Buffer, maximum: number): Buffer {
  if (!Number.isSafeInteger(maximum) || maximum < 1) throw new Error('maximum frame size must be a positive safe integer');
  if (chunk.length > maximum + 8 - pending.length) throw new Error('request frame exceeds configured maximum');
  const next = Buffer.concat([pending, chunk], pending.length + chunk.length);
  if (next.length >= 8 && next.readUInt32BE(4) > maximum) throw new Error('request frame exceeds configured maximum');
  return next;
}

export function resolveRuntimeListenOptions(
  socketPath: string,
  environment: NodeJS.ProcessEnv = process.env,
  pid = process.pid,
): { path: string } | { fd: number } {
  const provided = ['LISTEN_PID', 'LISTEN_FDS', 'LISTEN_FDNAMES'].filter((name) => environment[name] !== undefined);
  if (provided.length === 0) return { path: socketPath };
  if (environment.LISTEN_PID === undefined || environment.LISTEN_FDS === undefined) {
    throw new Error('incomplete systemd socket activation environment');
  }
  const listenPid = Number(environment.LISTEN_PID);
  const listenFds = Number(environment.LISTEN_FDS);
  if (!Number.isSafeInteger(listenPid) || listenPid < 1 || !Number.isSafeInteger(listenFds) || listenFds < 0) {
    throw new Error('invalid systemd socket activation environment');
  }
  if (listenPid !== pid) throw new Error('systemd socket activation pid mismatch');
  if (listenFds !== 1) throw new Error('exactly one systemd socket is required');
  if (environment.LISTEN_FDNAMES !== undefined && environment.LISTEN_FDNAMES !== '' && environment.LISTEN_FDNAMES !== 'baby-x') {
    throw new Error('systemd socket activation descriptor name mismatch');
  }
  return { fd: 3 };
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
    let processing = false;
    socket.on('data', async (chunk) => {
      if (processing) { socket.destroy(new Error('multiple concurrent request frames are not supported')); return; }
      try { pending = appendBoundedRuntimeFrameChunk(pending, chunk, config.maxFrameSize); }
      catch (error) { socket.destroy(error instanceof Error ? error : new Error(String(error))); return; }
      if (pending.length < 8) return;
      const length = pending.readUInt32BE(4);
      if (pending.length < length + 8) return;
      if (pending.length !== length + 8) { socket.destroy(new Error('exactly one request frame is required')); return; }
      processing = true;
      const frame = pending;
      pending = Buffer.alloc(0);
      const startedAt = new Date().toISOString();
      try {
        const envelope = decodeFrame(frame, config.maxFrameSize) as Envelope;
        if (envelope.subject !== config.ownerSubject || envelope.authorityClass !== config.authorityClass) throw new Error('owner identity mismatch');
        const age = Math.abs(Date.now() - Date.parse(envelope.timestamp));
        if (!Number.isFinite(age) || age > config.requestMaxAgeMs) throw new Error('stale request');
        const seen = nonces.get(envelope.nonce);
        if (seen && Date.now() - seen < config.nonceRetentionMs) throw new Error('nonce replay');
        nonces.set(envelope.nonce, Date.now());
        if (!verifyCanonical(publicKey, unsigned(envelope), envelope.signature)) throw new Error('invalid signature');
        const result = await runtime.execute(envelope.operation, envelope.payload ?? {}, { idempotencyKey: envelope.idempotencyKey, subject: envelope.subject, authorityClass: envelope.authorityClass });
        const proof = runtime.createProof(envelope.requestId, envelope.operation, true, startedAt, result);
        socket.end(encodeFrame({ requestId: envelope.requestId, ok: true, result, proof }));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        socket.end(encodeFrame({ ok: false, error: message, digest: canonicalize(message) }));
      }
    });
  });
  server.listen(resolveRuntimeListenOptions(config.socketPath));
  return server;
}
