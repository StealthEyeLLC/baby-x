import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createServer, type Socket } from 'node:net';
import { canonicalize, decodeFrame, encodeFrame, type JsonObject } from './core.ts';
import { activatedSocketFd } from './net/socket-activation.ts';
import { getPeerCredentials } from './net/peer-cred.ts';
import { RootBrokerService, type RootBrokerRequest } from './root-fabric/broker.ts';
import { RootTrustService } from './root-fabric/trust.ts';
import { RootEffectTransactionService } from './root-fabric/transactions.ts';
import { RootFabricError, type RootExecutionProvider } from './root-fabric/model.ts';

const maximumFrame = 1_048_576;
const stateRoot = process.env.BABYX_STATE_ROOT ?? '/var/lib/baby-x';
const allowedUid = Number(process.env.BABYX_RUNTIME_UID ?? '-1');
if (!Number.isSafeInteger(allowedUid) || allowedUid < 0) throw new Error('BABYX_RUNTIME_UID must name the exact unprivileged runtime UID');
const signingKeyPath = process.env.BABYX_ROOT_BROKER_SIGNING_KEY;
if (!signingKeyPath) throw new Error('BABYX_ROOT_BROKER_SIGNING_KEY is required');
const trustDirectory = process.env.BABYX_ROOT_TRUST_DIRECTORY ?? '/etc/baby-x/root-trust';
const transactions = new RootEffectTransactionService(stateRoot);
const trust = new RootTrustService(stateRoot, (keyId) => {
  const path = join(trustDirectory, `${keyId}.pub`);
  return existsSync(path) ? readFileSync(path) : undefined;
});

function verifyBinding(request: RootBrokerRequest): void {
  const transaction = transactions.record(request.transactionId);
  if (transaction.lifecycle.persistedState !== 'EXECUTING' || transaction.lifecycle.sequence !== request.transactionSequence || transaction.lease.fencingToken !== request.fencingToken) throw new RootFabricError('fencing_token_stale', 'broker transaction sequence or fencing token mismatch');
  if (transaction.ownerPrincipal.principalDigest !== request.ownerPrincipalDigest || transaction.skill.bundleDigest !== request.skillBundleDigest || transaction.skill.capabilityGrantDigest !== request.grantDigest || transaction.policy.decisionDigest !== request.policyDecisionDigest || transaction.routing.executionProvider !== request.selectedProvider) throw new RootFabricError('principal_mismatch', 'broker request is not bound to the authorized transaction');
  const step = transaction.plan.steps.find((candidate) => candidate.operation === request.operation && candidate.operationVersion === request.operationVersion && candidate.inputDigest === request.inputDigest);
  if (step === undefined) throw new RootFabricError('unsupported_operation', 'broker request does not match a declared transaction step');
  trust.authorize({ grantId: transaction.skill.capabilityGrantId, bundleDigest: transaction.skill.bundleDigest, ownerPrincipal: transaction.ownerPrincipal.principalId, operation: step.operation, provider: request.selectedProvider as RootExecutionProvider, effectClass: step.effectClass, resources: step.resourceSelectors, credentialReferences: request.credentialReferences });
}

const broker = new RootBrokerService({
  stateRoot,
  brokerIdentity: process.env.BABYX_ROOT_BROKER_ID ?? 'baby-x-root-broker',
  releaseCommit: process.env.BABYX_RELEASE_COMMIT ?? 'development',
  releaseTree: process.env.BABYX_RELEASE_TREE ?? 'development',
  signingKey: readFileSync(signingKeyPath),
  verifyBinding,
  receipt: (request, resultDigest) => `broker:${request.requestId}:${resultDigest}`,
});

function closeWithError(socket: Socket, message: string): void {
  socket.end(encodeFrame({ ok: false, error: { code: 'invalid_request', message } }));
}
const server = createServer(async (socket) => {
  try {
    const credentials = await getPeerCredentials((socket as unknown as { _handle?: { fd?: number } })._handle?.fd ?? -1);
    if (credentials.uid !== allowedUid) { socket.destroy(); return; }
  } catch { socket.destroy(); return; }
  let buffer = Buffer.alloc(0);
  let handled = false;
  socket.on('data', async (chunk: Buffer) => {
    if (handled) { socket.destroy(); return; }
    buffer = Buffer.concat([buffer, chunk]);
    if (buffer.length > maximumFrame + 8) { handled = true; closeWithError(socket, 'root broker frame exceeds limit'); return; }
    if (buffer.length < 8) return;
    const bodyLength = buffer.readUInt32BE(4);
    if (bodyLength > maximumFrame) { handled = true; closeWithError(socket, 'root broker frame exceeds limit'); return; }
    if (buffer.length < bodyLength + 8) return;
    if (buffer.length !== bodyLength + 8) { handled = true; closeWithError(socket, 'root broker accepts exactly one canonical frame per connection'); return; }
    handled = true;
    try { socket.end(encodeFrame({ ok: true, result: await broker.handle(decodeFrame(buffer, maximumFrame)) })); }
    catch (error) {
      const value: JsonObject = error instanceof RootFabricError ? { code: error.code, message: error.message, details: error.details } : { code: 'internal_error', message: error instanceof Error ? error.message : 'unknown error' };
      socket.end(encodeFrame({ ok: false, error: value }));
    }
  });
});
const fd = activatedSocketFd();
if (fd === null) throw new Error('root broker requires one systemd-activated Unix socket');
server.listen({ fd });
process.stdout.write(`${canonicalize({ ready: true, broker: broker.describe() })}\n`);
