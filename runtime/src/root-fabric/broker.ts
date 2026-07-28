import { join } from 'node:path';
import { canonicalize, sha256, signCanonical, type JsonObject } from '../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../storage/record-store.ts';
import { ROOT_BROKER_PROTOCOL_VERSION, RootFabricError, digest, identifier, integer, object, strictObject, text, timestamp, type RootExecutionProvider } from './model.ts';

export interface RootBrokerRequest extends JsonObject {
  protocolVersion: typeof ROOT_BROKER_PROTOCOL_VERSION;
  requestId: string;
  transactionId: string;
  transactionSequence: number;
  fencingToken: number;
  ownerPrincipalDigest: string;
  skillBundleDigest: string;
  grantDigest: string;
  policyDecisionDigest: string;
  operation: string;
  operationVersion: string;
  operationInput: JsonObject;
  inputDigest: string;
  deadline: string;
  nonce: string;
  selectedProvider: RootExecutionProvider;
  credentialReferences: string[];
}

export interface RootBrokerResponse extends JsonObject {
  protocolVersion: typeof ROOT_BROKER_PROTOCOL_VERSION;
  requestId: string;
  transactionId: string;
  brokerIdentity: string;
  brokerReleaseCommit: string;
  brokerReleaseTree: string;
  accepted: boolean;
  provider: RootExecutionProvider;
  executionIdentity: JsonObject;
  jobIds: string[];
  resultClassification: 'SUCCEEDED' | 'FAILED' | 'AMBIGUOUS' | 'REJECTED';
  resultDigest: string;
  observationDigest: string | null;
  cleanupState: JsonObject;
  receiptReference: string;
  error: JsonObject | null;
  completedAt: string;
  signature: string;
}

export interface BrokerEffectResult {
  executionIdentity?: JsonObject;
  jobIds?: string[];
  classification: 'SUCCEEDED' | 'FAILED' | 'AMBIGUOUS';
  result: JsonObject;
  observationDigest?: string | null;
  cleanupState?: JsonObject;
}

export interface BrokerEffectAdapter {
  readonly operation: string;
  readonly version: string;
  execute(input: JsonObject, request: RootBrokerRequest): Promise<BrokerEffectResult>;
}

interface BrokerReplayRecord extends JsonObject {
  requestId: string;
  requestDigest: string;
  transactionId: string;
  transactionSequence: number;
  fencingToken: number;
  nonce: string;
  response: RootBrokerResponse;
  recordDigest: string;
}

function unsigned(record: BrokerReplayRecord): JsonObject {
  const { recordDigest: _recordDigest, ...rest } = record;
  return rest;
}

function seal(record: Omit<BrokerReplayRecord, 'recordDigest'>): BrokerReplayRecord {
  return { ...record, recordDigest: sha256(canonicalize(record)) };
}

function normalizeRequest(value: unknown, now: string, maximumBytes = 1_048_576): RootBrokerRequest {
  const raw = strictObject(value, 'root broker request', ['protocolVersion', 'requestId', 'transactionId', 'transactionSequence', 'fencingToken', 'ownerPrincipalDigest', 'skillBundleDigest', 'grantDigest', 'policyDecisionDigest', 'operation', 'operationVersion', 'operationInput', 'inputDigest', 'deadline', 'nonce', 'selectedProvider', 'credentialReferences']);
  if (Buffer.byteLength(canonicalize(raw)) > maximumBytes) throw new RootFabricError('invalid_request', 'root broker request exceeds the bounded request size');
  if (raw.protocolVersion !== ROOT_BROKER_PROTOCOL_VERSION) throw new RootFabricError('broker_protocol_mismatch', 'root broker protocol version mismatch');
  const selectedProvider = text(raw.selectedProvider, 'selectedProvider', 32);
  if (selectedProvider !== 'HOST_ENVELOPE' && selectedProvider !== 'DISPOSABLE_MACHINE') throw new RootFabricError('unsupported_provider', 'root broker provider is unsupported');
  const operationInput = object(raw.operationInput, 'operationInput');
  const inputDigest = digest(raw.inputDigest, 'inputDigest');
  if (inputDigest !== sha256(canonicalize(operationInput))) throw new RootFabricError('expected_digest_mismatch', 'root broker input digest mismatch');
  const deadline = timestamp(raw.deadline, 'deadline');
  if (Date.parse(deadline) <= Date.parse(now)) throw new RootFabricError('deadline_exceeded', 'root broker request is expired');
  if (!Array.isArray(raw.credentialReferences) || raw.credentialReferences.length > 64) throw new RootFabricError('invalid_request', 'credentialReferences must be a bounded array');
  return {
    protocolVersion: ROOT_BROKER_PROTOCOL_VERSION,
    requestId: identifier(raw.requestId, 'requestId'), transactionId: identifier(raw.transactionId, 'transactionId'),
    transactionSequence: integer(raw.transactionSequence, 'transactionSequence', 1, 10_000_000), fencingToken: integer(raw.fencingToken, 'fencingToken', 1, Number.MAX_SAFE_INTEGER),
    ownerPrincipalDigest: digest(raw.ownerPrincipalDigest, 'ownerPrincipalDigest'), skillBundleDigest: digest(raw.skillBundleDigest, 'skillBundleDigest'),
    grantDigest: digest(raw.grantDigest, 'grantDigest'), policyDecisionDigest: digest(raw.policyDecisionDigest, 'policyDecisionDigest'),
    operation: identifier(raw.operation, 'operation'), operationVersion: text(raw.operationVersion, 'operationVersion', 64), operationInput, inputDigest, deadline,
    nonce: identifier(raw.nonce, 'nonce'), selectedProvider: selectedProvider as RootExecutionProvider,
    credentialReferences: raw.credentialReferences.map((entry, index) => identifier(entry, `credentialReferences[${index}]`)),
  };
}

function redactedError(error: unknown): JsonObject {
  if (error instanceof RootFabricError) return { code: error.code, message: error.message, details: error.details };
  if (error instanceof Error) return { code: 'execution_failed', message: error.message };
  return { code: 'internal_error', message: 'unknown root broker failure' };
}

export class RootBrokerService {
  private readonly adapters = new Map<string, BrokerEffectAdapter>();
  private readonly replay: DurableRecordStore<BrokerReplayRecord>;
  private readonly claims: DurableClaimStore<BrokerReplayRecord>;
  private readonly now: () => string;

  constructor(private readonly options: {
    stateRoot: string;
    brokerIdentity: string;
    releaseCommit: string;
    releaseTree: string;
    signingKey: string | Buffer;
    verifyBinding: (request: RootBrokerRequest) => void | Promise<void>;
    receipt: (request: RootBrokerRequest, resultDigest: string) => string;
    now?: () => string;
  }) {
    const root = join(options.stateRoot, 'root-fabric', 'broker');
    this.replay = new DurableRecordStore(join(root, 'replay'));
    this.claims = new DurableClaimStore(join(root, 'claims'));
    this.now = options.now ?? (() => new Date().toISOString());
  }

  register(adapter: BrokerEffectAdapter): void {
    const key = `${identifier(adapter.operation, 'adapter.operation')}@${text(adapter.version, 'adapter.version', 64)}`;
    if (this.adapters.has(key)) throw new RootFabricError('resource_conflict', `duplicate root broker adapter ${key}`);
    this.adapters.set(key, adapter);
  }

  describe(): JsonObject {
    return {
      brokerProtocolVersion: ROOT_BROKER_PROTOCOL_VERSION,
      brokerIdentity: this.options.brokerIdentity,
      releaseCommit: this.options.releaseCommit,
      releaseTree: this.options.releaseTree,
      operations: [...this.adapters.values()].map((adapter) => ({ operation: adapter.operation, version: adapter.version })).sort((left, right) => `${left.operation}@${left.version}`.localeCompare(`${right.operation}@${right.version}`)),
      arbitraryShell: false,
      tcpListener: false,
      maximumRequestBytes: 1_048_576,
      maximumInlineResponseBytes: 65_536,
    };
  }

  async handle(value: unknown): Promise<RootBrokerResponse> {
    const completedAt = this.now();
    const request = normalizeRequest(value, completedAt);
    const requestDigest = sha256(canonicalize(request));
    const existing = this.replay.has(request.requestId) ? this.replay.get(request.requestId) : undefined;
    if (existing !== undefined) {
      if (existing.requestDigest !== requestDigest || existing.transactionId !== request.transactionId || existing.transactionSequence !== request.transactionSequence || existing.fencingToken !== request.fencingToken || existing.nonce !== request.nonce) throw new RootFabricError('broker_replay_detected', 'root broker request ID or nonce was replayed with conflicting identity');
      if (existing.recordDigest !== sha256(canonicalize(unsigned(existing)))) throw new RootFabricError('corrupt_record', 'root broker replay record integrity failed');
      return existing.response;
    }
    await this.options.verifyBinding(request);
    const key = `${request.operation}@${request.operationVersion}`;
    const adapter = this.adapters.get(key);
    if (adapter === undefined) throw new RootFabricError('unsupported_operation', `root broker operation ${key} is not registered`);
    let accepted = true;
    let classification: RootBrokerResponse['resultClassification'];
    let executionIdentity: JsonObject = {};
    let jobIds: string[] = [];
    let result: JsonObject = {};
    let observationDigest: string | null = null;
    let cleanupState: JsonObject = {};
    let errorValue: JsonObject | null = null;
    try {
      const effect = await adapter.execute(request.operationInput, request);
      classification = effect.classification;
      executionIdentity = effect.executionIdentity ?? {};
      jobIds = effect.jobIds ?? [];
      result = effect.result;
      observationDigest = effect.observationDigest ?? null;
      cleanupState = effect.cleanupState ?? {};
    } catch (error) {
      accepted = false;
      classification = error instanceof RootFabricError && ['grant_denied', 'policy_denied', 'frozen', 'unsupported_operation', 'unsupported_provider'].includes(error.code) ? 'REJECTED' : 'FAILED';
      errorValue = redactedError(error);
      result = { error: errorValue };
    }
    const resultDigest = sha256(canonicalize({ classification, result, executionIdentity, jobIds, observationDigest, cleanupState }));
    const receiptReference = this.options.receipt(request, resultDigest);
    const unsignedResponse = {
      protocolVersion: ROOT_BROKER_PROTOCOL_VERSION, requestId: request.requestId, transactionId: request.transactionId,
      brokerIdentity: this.options.brokerIdentity, brokerReleaseCommit: this.options.releaseCommit, brokerReleaseTree: this.options.releaseTree,
      accepted, provider: request.selectedProvider, executionIdentity, jobIds, resultClassification: classification,
      resultDigest, observationDigest, cleanupState, receiptReference, error: errorValue, completedAt,
    };
    const response: RootBrokerResponse = { ...unsignedResponse, signature: signCanonical(this.options.signingKey, unsignedResponse) };
    if (Buffer.byteLength(canonicalize(response)) > 65_536) throw new RootFabricError('internal_error', 'root broker response exceeds the bounded inline response size');
    const record = seal({ requestId: request.requestId, requestDigest, transactionId: request.transactionId, transactionSequence: request.transactionSequence, fencingToken: request.fencingToken, nonce: request.nonce, response });
    const claim = this.claims.claim(request.requestId, requestDigest, request.requestId, record);
    if (claim.requestDigest !== requestDigest) throw new RootFabricError('broker_replay_detected', 'root broker replay claim conflicts with the request');
    if (!this.replay.has(request.requestId)) this.replay.create(request.requestId, claim.record);
    return this.replay.get(request.requestId).response;
  }
}
