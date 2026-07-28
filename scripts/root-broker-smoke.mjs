#!/usr/bin/env node
import { connect } from 'node:net';
import { lstatSync } from 'node:fs';
import process from 'node:process';

function frame(body) {
  const bytes = Buffer.from(body);
  const result = Buffer.alloc(8 + bytes.length);
  Buffer.from('QRT1').copy(result, 0);
  result.writeUInt32BE(bytes.length, 4);
  bytes.copy(result, 8);
  return result;
}

function exchange(socketPath, bytes, timeoutMs = 3_000) {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    const chunks = [];
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error('root broker smoke timed out'));
    }, timeoutMs);
    socket.on('connect', () => socket.end(bytes));
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    socket.on('close', () => {
      clearTimeout(timeout);
      resolve(Buffer.concat(chunks));
    });
  });
}

function decodedResponse(bytes) {
  if (bytes.length < 8 || bytes.subarray(0, 4).toString() !== 'QRT1') throw new Error('root broker returned no canonical frame');
  const size = bytes.readUInt32BE(4);
  if (size !== bytes.length - 8) throw new Error('root broker returned an invalid frame length');
  return JSON.parse(bytes.subarray(8).toString('utf8'));
}

export async function allowedPeerSmoke(socketPath) {
  const malformed = decodedResponse(await exchange(socketPath, frame('{')));
  if (malformed.ok !== false) throw new Error('root broker accepted a malformed frame');
  const oversizedHeader = Buffer.alloc(8);
  Buffer.from('QRT1').copy(oversizedHeader, 0);
  oversizedHeader.writeUInt32BE(1_048_577, 4);
  const oversized = decodedResponse(await exchange(socketPath, oversizedHeader));
  if (oversized.ok !== false) throw new Error('root broker accepted an oversized frame');
  const zero = '0'.repeat(64);
  const unknown = decodedResponse(await exchange(socketPath, frame(JSON.stringify({
    protocolVersion: '1.0.0',
    requestId: 'production-smoke-unknown',
    transactionId: 'production-smoke-absent',
    transactionSequence: 1,
    fencingToken: 1,
    ownerPrincipalDigest: zero,
    skillBundleDigest: zero,
    grantDigest: zero,
    policyDecisionDigest: zero,
    operation: 'babyx.root.smoke.unknown',
    operationVersion: '1.0.0',
    operationInput: {},
    inputDigest: '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
    deadline: new Date(Date.now() + 30_000).toISOString(),
    nonce: 'production-smoke-unknown',
    selectedProvider: 'HOST_ENVELOPE',
    credentialReferences: [],
  }))));
  if (unknown.ok !== false) throw new Error('root broker accepted an unknown smoke operation');
  return { malformedRejected: true, oversizedRejected: true, unknownRejected: true };
}

export async function wrongPeerSmoke(socketPath) {
  let bytes;
  try {
    bytes = await exchange(socketPath, frame('{}'));
  } catch (error) {
    if (['ECONNRESET', 'EPIPE'].includes(error?.code)) return { wrongPeerRejected: true };
    throw error;
  }
  if (bytes.length !== 0) throw new Error('wrong peer received a root broker response');
  return { wrongPeerRejected: true };
}

async function main() {
  const mode = process.argv[2];
  const socketPath = process.argv[3] ?? '/run/baby-x/root-broker.sock';
  const metadata = lstatSync(socketPath);
  if (!metadata.isSocket()) throw new Error('root broker path is not a Unix socket');
  const result = mode === 'allowed'
    ? await allowedPeerSmoke(socketPath)
    : mode === 'wrong-peer'
      ? await wrongPeerSmoke(socketPath)
      : (() => { throw new Error('mode must be allowed or wrong-peer'); })();
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
