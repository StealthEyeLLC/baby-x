import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import { DurableClaimStore, DurableRecordStore } from '../../storage/record-store.ts';
import { MicrovmError } from './errors.ts';
import { MICROVM_LIFECYCLES, type MicrovmCreateRequest, type MicrovmLifecycle } from './schemas.ts';

export const MICROVM_RECORD_SCHEMA_VERSION = '1.0.0' as const;
export const MICROVM_EVENT_SCHEMA_VERSION = '1.0.0' as const;

export interface MicrovmProcessIdentity extends JsonObject {
  pid: number;
  processStartTime: string;
  executablePath: string;
  executableDigest: string;
}

export interface MicrovmRecord extends JsonObject {
  schemaVersion: typeof MICROVM_RECORD_SCHEMA_VERSION;
  vmId: string;
  transactionId: string;
  ownerPrincipal: string;
  sequence: number;
  lifecycle: MicrovmLifecycle;
  requestDigest: string;
  idempotencyKeyDigest: string;
  skillBundleDigest: string;
  grantDigest: string;
  policyDigest: string;
  firecrackerVersion: string;
  firecrackerDigest: string;
  kernelDigest: string;
  rootImageDigest: string;
  guestAgentDigest: string;
  guestAgentProtocol: string;
  writableLayerIdentity: string;
  writableLayerDigest: string;
  vcpuCount: number;
  memoryMiB: number;
  cgroup: string;
  systemdUnit: string;
  processIdentity: MicrovmProcessIdentity | null;
  hostBootId: string;
  guestBootId: string | null;
  vsockCid: number;
  vsockSocketIdentity: string;
  tapIdentity: null;
  networkMode: 'NONE';
  guestAgentState: 'UNKNOWN' | 'READY' | 'FAILED' | 'STOPPED';
  sourceSnapshotId: string | null;
  poolId: string | null;
  leaseState: 'NONE' | 'AVAILABLE' | 'LEASED';
  workloadIdentityDigest: string | null;
  randomEpochDigest: string | null;
  inheritedGuestCid: boolean;
  cleanup: { requested: boolean; completed: boolean; processAbsent: boolean; socketAbsent: boolean; writableLayerAbsent: boolean; completedAt: string | null };
  error: { code: string; message: string; phase: string } | null;
  createdAt: string;
  updatedAt: string;
  priorRecordDigest: string | null;
  recordDigest: string;
}

export interface MicrovmEventRecord extends JsonObject {
  schemaVersion: typeof MICROVM_EVENT_SCHEMA_VERSION;
  eventId: string;
  vmId: string;
  sequence: number;
  priorLifecycle: MicrovmLifecycle | null;
  nextLifecycle: MicrovmLifecycle;
  operation: string;
  details: JsonObject;
  occurredAt: string;
  priorEventDigest: string | null;
  eventDigest: string;
}

interface MicrovmClaimRecord extends JsonObject { vmId: string }

function unsignedRecord(record: MicrovmRecord): JsonObject { const { recordDigest: _digest, ...unsigned }=record; return unsigned; }
function unsignedEvent(event: MicrovmEventRecord): JsonObject { const { eventDigest: _digest, ...unsigned }=event; return unsigned; }

export function verifyMicrovmRecord(record: MicrovmRecord): { valid: boolean; errors: string[] } {
  const errors: string[]=[];
  if(record.schemaVersion!==MICROVM_RECORD_SCHEMA_VERSION) errors.push('schema version mismatch');
  if(!/^mvm_[a-f0-9]{32}$/u.test(record.vmId)) errors.push('vm identifier mismatch');
  if(!MICROVM_LIFECYCLES.includes(record.lifecycle)) errors.push('lifecycle mismatch');
  if(!Number.isSafeInteger(record.sequence)||record.sequence<1) errors.push('sequence mismatch');
  if(record.recordDigest!==sha256(canonicalize(unsignedRecord(record)))) errors.push('record digest mismatch');
  return {valid:errors.length===0,errors};
}
export function verifyMicrovmEvent(event: MicrovmEventRecord): { valid: boolean; errors: string[] } {
  const errors:string[]=[];
  if(event.schemaVersion!==MICROVM_EVENT_SCHEMA_VERSION) errors.push('schema version mismatch');
  if(!/^mve_[a-f0-9]{32}$/u.test(event.eventId)) errors.push('event identifier mismatch');
  if(event.eventDigest!==sha256(canonicalize(unsignedEvent(event)))) errors.push('event digest mismatch');
  return {valid:errors.length===0,errors};
}

export class MicrovmRecordStore {
  private readonly records: DurableRecordStore<MicrovmRecord>;
  private readonly events: DurableRecordStore<MicrovmEventRecord>;
  private readonly claims: DurableClaimStore<MicrovmClaimRecord>;
  private readonly now: () => string;
  constructor(stateRoot:string, options:{now?:()=>string}={}) {
    const root=join(stateRoot,'root-platform','microvm');
    this.records=new DurableRecordStore<MicrovmRecord>(join(root,'vms'));
    this.events=new DurableRecordStore<MicrovmEventRecord>(join(root,'events'));
    this.claims=new DurableClaimStore<MicrovmClaimRecord>(join(root,'idempotency'));
    this.now=options.now??(()=>new Date().toISOString());
  }
  claim(ownerPrincipal:string,idempotencyKey:string,requestDigest:string):{vmId:string;replayed:boolean} {
    if(idempotencyKey.length<8||idempotencyKey.length>256||idempotencyKey.includes('\0')) throw new MicrovmError('microvm_invalid_request','a bounded idempotency key is required');
    const key=`${ownerPrincipal}:${idempotencyKey}`;
    const existing=this.claims.get(key);
    if(existing!==undefined){ if(existing.requestDigest!==requestDigest) throw new MicrovmError('microvm_idempotency_conflict','idempotency key belongs to a different microVM request'); return {vmId:existing.record.vmId,replayed:true}; }
    const vmId=`mvm_${randomUUID().replaceAll('-','')}`;
    const claim=this.claims.claim(key,requestDigest,vmId,{vmId});
    if(claim.requestDigest!==requestDigest) throw new MicrovmError('microvm_idempotency_conflict','idempotency key belongs to a different microVM request');
    return {vmId:claim.record.vmId,replayed:false};
  }
  create(record:MicrovmRecord):void {
    const verified=verifyMicrovmRecord(record); if(!verified.valid) throw new MicrovmError('microvm_ambiguous','initial microVM record is invalid',{errors:verified.errors});
    if(!this.records.create(record.vmId,record)) throw new MicrovmError('microvm_state_conflict','microVM record already exists');
    this.appendEvent(record.vmId,null,record.lifecycle,'CREATE',{requestDigest:record.requestDigest});
  }
  get(vmId:string):MicrovmRecord {
    let record:MicrovmRecord; try{record=this.records.get(vmId);}catch{throw new MicrovmError('microvm_not_found',`microVM not found: ${vmId}`);}
    const verified=verifyMicrovmRecord(record); if(!verified.valid) throw new MicrovmError('microvm_ambiguous','microVM record integrity failed',{vmId,errors:verified.errors});
    return structuredClone(record);
  }
  transition(vmId:string,nextLifecycle:MicrovmLifecycle,operation:string,patch:Partial<MicrovmRecord>,details:JsonObject={}):MicrovmRecord {
    const prior=this.get(vmId);
    const base={...prior,...structuredClone(patch),sequence:prior.sequence+1,lifecycle:nextLifecycle,updatedAt:this.now(),priorRecordDigest:prior.recordDigest};
    const {recordDigest:_old,...unsigned}=base;
    const next={...unsigned,recordDigest:sha256(canonicalize(unsigned as JsonObject))} as MicrovmRecord;
    const verified=verifyMicrovmRecord(next); if(!verified.valid) throw new MicrovmError('microvm_ambiguous','transition produced an invalid microVM record',{errors:verified.errors});
    this.records.put(vmId,next);
    this.appendEvent(vmId,prior.lifecycle,nextLifecycle,operation,details);
    return structuredClone(next);
  }
  list(filters:{ownerPrincipal?:string;lifecycle?:MicrovmLifecycle;offset:number;limit:number}):JsonObject {
    const scan=this.records.scan((record)=>(filters.ownerPrincipal===undefined||record.ownerPrincipal===filters.ownerPrincipal)&&(filters.lifecycle===undefined||record.lifecycle===filters.lifecycle),0,10_000);
    const all=scan.records.sort((a,b)=>a.vmId.localeCompare(b.vmId));
    const records=all.slice(filters.offset,filters.offset+filters.limit).map((record)=>{const verified=verifyMicrovmRecord(record);if(!verified.valid)throw new MicrovmError('microvm_ambiguous','microVM record integrity failed',{vmId:record.vmId,errors:verified.errors});return record;});
    return {microvms:records,offset:filters.offset,limit:filters.limit,total:all.length,nextOffset:filters.offset+records.length<all.length?filters.offset+records.length:null,corruptRecordIds:scan.corruptRecordIds};
  }
  all():MicrovmRecord[]{return this.records.scan(()=>true,0,10_000).records.map((record)=>this.get(record.vmId));}
  eventsFor(vmId:string):MicrovmEventRecord[]{return this.events.scan((event)=>event.vmId===vmId,0,10_000).records.sort((a,b)=>a.sequence-b.sequence);}
  reconcileIntegrity():JsonObject {
    const recordScan=this.records.scan(()=>true,0,10_000); const eventScan=this.events.scan(()=>true,0,10_000);
    const invalidRecords=recordScan.records.filter((record)=>!verifyMicrovmRecord(record).valid).map((record)=>record.vmId);
    const invalidEvents=eventScan.records.filter((event)=>!verifyMicrovmEvent(event).valid).map((event)=>event.eventId);
    return {ok:recordScan.corruptRecordIds.length===0&&eventScan.corruptRecordIds.length===0&&invalidRecords.length===0&&invalidEvents.length===0,records:recordScan.records.length,events:eventScan.records.length,corruptRecordIds:recordScan.corruptRecordIds,corruptEventIds:eventScan.corruptRecordIds,invalidRecords,invalidEvents};
  }
  private appendEvent(vmId:string,priorLifecycle:MicrovmLifecycle|null,nextLifecycle:MicrovmLifecycle,operation:string,details:JsonObject):void {
    const prior=this.eventsFor(vmId).at(-1); const sequence=(prior?.sequence??0)+1;
    const base={schemaVersion:MICROVM_EVENT_SCHEMA_VERSION,eventId:`mve_${randomUUID().replaceAll('-','')}`,vmId,sequence,priorLifecycle,nextLifecycle,operation,details:structuredClone(details),occurredAt:this.now(),priorEventDigest:prior?.eventDigest??null};
    const event={...base,eventDigest:sha256(canonicalize(base))} as MicrovmEventRecord;
    if(!this.events.create(`${vmId}:${String(sequence).padStart(12,'0')}:${event.eventId}`,event)) throw new MicrovmError('microvm_ambiguous','microVM event could not be persisted');
  }
}

export function initialMicrovmRecord(input:{vmId:string;ownerPrincipal:string;request:MicrovmCreateRequest;requestDigest:string;idempotencyKey:string;artifacts:{firecrackerDigest:string;kernelDigest:string;rootImageDigest:string;guestAgentDigest:string;guestAgentProtocol:string};writableLayerIdentity:string;writableLayerDigest:string;systemdUnit:string;vsockCid:number;vsockSocketIdentity:string;hostBootId:string;now:string}):MicrovmRecord {
  const base={schemaVersion:MICROVM_RECORD_SCHEMA_VERSION,vmId:input.vmId,transactionId:input.request.transactionId,ownerPrincipal:input.ownerPrincipal,sequence:1,lifecycle:'REQUESTED' as const,requestDigest:input.requestDigest,idempotencyKeyDigest:sha256(input.idempotencyKey),skillBundleDigest:input.request.skillBundleDigest,grantDigest:input.request.grantDigest,policyDigest:input.request.policyDigest,firecrackerVersion:input.request.firecrackerVersion,firecrackerDigest:input.artifacts.firecrackerDigest,kernelDigest:input.artifacts.kernelDigest,rootImageDigest:input.artifacts.rootImageDigest,guestAgentDigest:input.artifacts.guestAgentDigest,guestAgentProtocol:input.artifacts.guestAgentProtocol,writableLayerIdentity:input.writableLayerIdentity,writableLayerDigest:input.writableLayerDigest,vcpuCount:input.request.vcpuCount,memoryMiB:input.request.memoryMiB,cgroup:'',systemdUnit:input.systemdUnit,processIdentity:null,hostBootId:input.hostBootId,guestBootId:null,vsockCid:input.vsockCid,vsockSocketIdentity:input.vsockSocketIdentity,tapIdentity:null,networkMode:'NONE' as const,guestAgentState:'UNKNOWN' as const,sourceSnapshotId:null,poolId:null,leaseState:'NONE' as const,workloadIdentityDigest:null,randomEpochDigest:null,inheritedGuestCid:false,cleanup:{requested:false,completed:false,processAbsent:false,socketAbsent:false,writableLayerAbsent:false,completedAt:null},error:null,createdAt:input.now,updatedAt:input.now,priorRecordDigest:null};
  return {...base,recordDigest:sha256(canonicalize(base))} as MicrovmRecord;
}
