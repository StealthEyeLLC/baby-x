import { randomBytes } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, readlinkSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import { MicrovmArtifactRegistry } from './artifacts.ts';
import { MicrovmError } from './errors.ts';
import { initialMicrovmRecord, MicrovmRecordStore, type MicrovmProcessIdentity, type MicrovmRecord } from './records.ts';
import { createRequestDigest, normalizeCreateRequest, normalizeExecRequest, normalizeListRequest, normalizeVmSelector, type MicrovmExecAction } from './schemas.ts';
import { guestCall, type GuestResponse } from './vsock.ts';

interface ProviderContext extends JsonObject { ownerPrincipal: string; idempotencyKey: string }
interface CommandResult { status:number|null;stdout:string;stderr:string }
type CommandRunner=(command:string,args:string[],timeoutMs?:number)=>CommandResult;

function defaultRun(command:string,args:string[],timeoutMs=30_000):CommandResult { const result=spawnSync(command,args,{encoding:'utf8',timeout:timeoutMs,maxBuffer:4_194_304}); return {status:result.status,stdout:String(result.stdout??''),stderr:String(result.stderr??result.error?.message??'')}; }
function requireSuccess(result:CommandResult,code:'microvm_provider_unavailable'|'microvm_cleanup_failed',message:string):void { if(result.status!==0) throw new MicrovmError(code,message,{status:result.status,stderrDigest:sha256(result.stderr.slice(0,4096))}); }
function readHostBootId():string { return readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim(); }
function processStartTime(pid:number):string { const stat=readFileSync(`/proc/${pid}/stat`,'utf8'); const rest=stat.slice(stat.lastIndexOf(')')+2).split(' '); return rest[19]??''; }
function processCgroup(pid:number):string { return readFileSync(`/proc/${pid}/cgroup`,'utf8').trim().slice(0,4096); }
function executableDigest(path:string):string { return sha256(readFileSync(path)); }
function sleep(ms:number):Promise<void>{return new Promise((resolve)=>setTimeout(resolve,ms));}
function owner(context:ProviderContext):string { if(typeof context.ownerPrincipal!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(context.ownerPrincipal)) throw new MicrovmError('microvm_invalid_request','owner principal is invalid'); return context.ownerPrincipal; }
function tokenPath(vmRoot:string):string{return join(vmRoot,'guest.token');}

export class FirecrackerMicrovmProvider {
  readonly store:MicrovmRecordStore;
  readonly artifacts:MicrovmArtifactRegistry;
  private readonly root:string;
  private readonly runtimeRoot:string;
  private readonly run:CommandRunner;
  private readonly now:()=>string;
  constructor(options:{stateRoot:string;assetRoot?:string;runtimeRoot?:string;run?:CommandRunner;now?:()=>string}) {
    this.root=join(options.stateRoot,'root-platform','microvm','instances'); mkdirSync(this.root,{recursive:true,mode:0o700});
    this.runtimeRoot=options.runtimeRoot??process.env.BABY_X_MICROVM_RUNTIME_ROOT??'/run/baby-x/microvm'; mkdirSync(this.runtimeRoot,{recursive:true,mode:0o700});
    this.store=new MicrovmRecordStore(options.stateRoot,{now:options.now}); this.artifacts=new MicrovmArtifactRegistry(options.assetRoot); this.run=options.run??defaultRun; this.now=options.now??(()=>new Date().toISOString());
  }
  describe():JsonObject{return {providerId:'firecracker-cold-boot',implementationVersion:'1.0.0',contractVersion:'microvm-provider@1',artifact:this.artifacts.probe(),networkDefault:'NONE',guestProtocol:'BABYX-GUEST/1.0.0',operations:['create','get','list','exec','stop','remove','reconcile']};}
  async create(payload:unknown,context:ProviderContext):Promise<JsonObject>{
    const ownerPrincipal=owner(context); if(typeof context.idempotencyKey!=='string') throw new MicrovmError('microvm_invalid_request','idempotency key is required');
    const request=normalizeCreateRequest(payload); const artifacts=this.artifacts.load();
    if(request.kernelDigest!==artifacts.kernelDigest) throw new MicrovmError('microvm_asset_integrity_failure','requested kernel digest does not match the provider registry');
    if(request.rootImageDigest!==artifacts.baseRootImageDigest) throw new MicrovmError('microvm_asset_integrity_failure','requested root image digest does not match the provider registry');
    if(!existsSync('/dev/kvm')||!existsSync('/dev/vhost-vsock')) throw new MicrovmError('microvm_provider_unavailable','KVM and vhost-vsock are required');
    const requestDigest=createRequestDigest(ownerPrincipal,request); const claim=this.store.claim(ownerPrincipal,context.idempotencyKey,requestDigest);
    if(claim.replayed){const existing=this.store.get(claim.vmId);return {microvm:existing,replayed:true};}
    const vmId=claim.vmId; const vmRoot=join(this.root,vmId); const vmRuntimeRoot=join(this.runtimeRoot,vmId.slice(4)); mkdirSync(vmRoot,{recursive:true,mode:0o700}); mkdirSync(vmRuntimeRoot,{recursive:true,mode:0o700});
    const writable=join(vmRoot,'rootfs.ext4'); copyFileSync(artifacts.baseRootImagePath,writable); const token=randomBytes(32).toString('hex'); const tokenSource=join(vmRoot,'token.source'); writeFileSync(tokenSource,token,{mode:0o600});
    const debugfs=this.run('/usr/sbin/debugfs',['-w','-R',`write ${tokenSource} /etc/babyx-auth-token`,writable]); rmSync(tokenSource,{force:true}); requireSuccess(debugfs,'microvm_provider_unavailable','guest authentication injection failed');
    writeFileSync(tokenPath(vmRoot),token,{mode:0o600}); const writableDigest=sha256(readFileSync(writable)); const systemdUnit=`baby-x-microvm-${vmId.slice(4)}.service`; const vsockPath=join(vmRuntimeRoot,'vsock.sock'); const vsockCid=this.allocateVsockCid();
    const record=initialMicrovmRecord({vmId,ownerPrincipal,request,requestDigest,idempotencyKey:context.idempotencyKey,artifacts:{firecrackerDigest:artifacts.firecrackerDigest,kernelDigest:artifacts.kernelDigest,rootImageDigest:artifacts.baseRootImageDigest,guestAgentDigest:artifacts.guestAgentDigest,guestAgentProtocol:artifacts.guestAgentProtocol},writableLayerIdentity:writable,writableLayerDigest:writableDigest,systemdUnit,vsockCid,vsockSocketIdentity:vsockPath,hostBootId:readHostBootId(),now:this.now()});
    this.store.create(record);
    try {
      this.store.transition(vmId,'PREPARING','PREPARE',{},{vmRootDigest:sha256(vmRoot)});
      const configPath=join(vmRoot,'firecracker.json'); const apiPath=join(vmRuntimeRoot,'api.sock'); const logPath=join(vmRoot,'firecracker.log');
      const config={'boot-source':{kernel_image_path:artifacts.kernelPath,boot_args:'console=ttyS0 reboot=k panic=1 pci=off nomodules random.trust_cpu=on root=/dev/vda rw init=/sbin/init'},drives:[{drive_id:'rootfs',path_on_host:writable,is_root_device:true,is_read_only:false,cache_type:'Unsafe'}],'machine-config':{vcpu_count:request.vcpuCount,mem_size_mib:request.memoryMiB,smt:false},vsock:{guest_cid:vsockCid,uds_path:vsockPath}};
      writeFileSync(configPath,`${canonicalize(config as JsonObject)}\n`,{mode:0o600}); writeFileSync(logPath,'',{mode:0o600});
      this.store.transition(vmId,'STARTING','START',{},{configDigest:sha256(canonicalize(config as JsonObject))});
      const start=this.run('/usr/bin/systemd-run',['--quiet',`--unit=${systemdUnit}`,'--property=Type=simple','--property=KillMode=mixed','--property=TimeoutStopSec=10s','--property=PrivateNetwork=yes','--property=NoNewPrivileges=no',`--property=WorkingDirectory=${vmRoot}`,artifacts.firecrackerPath,'--id',vmId.slice(4),'--api-sock',apiPath,'--config-file',configPath,'--log-path',logPath,'--level','Info'],30_000);
      requireSuccess(start,'microvm_provider_unavailable','Firecracker process could not be started');
      const identity=await this.waitForProcess(systemdUnit,artifacts.firecrackerDigest);
      this.store.transition(vmId,'BOOTING','PROCESS_READY',{processIdentity:identity,cgroup:processCgroup(identity.pid)},{pid:identity.pid,processStartTime:identity.processStartTime});
      const health=await this.waitForGuest(vsockPath,token,10_000); const guestBootId=typeof health.bootId==='string'?health.bootId:null;
      const ready=this.store.transition(vmId,'READY','GUEST_READY',{guestAgentState:'READY',guestBootId},{healthDigest:sha256(canonicalize(health as JsonObject))});
      return {microvm:ready,replayed:false};
    } catch(error) {
      const code=error instanceof MicrovmError?error.code:'microvm_provider_unavailable'; const message=error instanceof Error?error.message:String(error);
      try{this.store.transition(vmId,'FAILED','CREATE_FAILED',{guestAgentState:'FAILED',error:{code,message,phase:'create'},cleanup:{requested:true,completed:false,processAbsent:false,socketAbsent:false,writableLayerAbsent:false,completedAt:null}},{code});}catch{}
      await this.cleanupEffects(record,true);
      try{const failed=this.store.get(vmId);this.store.transition(vmId,'FAILED','CREATE_FAILURE_CLEANED',{cleanup:{requested:true,completed:true,processAbsent:!this.unitActive(record.systemdUnit),socketAbsent:!existsSync(record.vsockSocketIdentity),writableLayerAbsent:!existsSync(record.writableLayerIdentity),completedAt:this.now()}},{code});}catch{}
      throw error;
    }
  }
  get(payload:unknown,context:ProviderContext):JsonObject { const {vmId}=normalizeVmSelector(payload); return {microvm:this.owned(vmId,owner(context))}; }
  list(payload:unknown,context:ProviderContext):JsonObject { const filters=normalizeListRequest(payload); const ownerPrincipal=owner(context); return this.store.list({...filters,ownerPrincipal:filters.ownerPrincipal??ownerPrincipal}); }
  async exec(payload:unknown,context:ProviderContext):Promise<JsonObject>{
    const {vmId,request}=normalizeExecRequest(payload); let record=this.owned(vmId,owner(context)); if(record.lifecycle!=='READY'&&record.lifecycle!=='RUNNING') throw new MicrovmError('microvm_state_conflict','microVM is not ready for execution',{lifecycle:record.lifecycle});
    this.assertProcess(record); const token=readFileSync(tokenPath(join(this.root,vmId)),'utf8').trim(); const command=this.guestCommand(request); const response=await guestCall(record.vsockSocketIdentity,token,command,request.action==='SLEEP'?5_000:10_000);
    if(request.action==='SLEEP'&&response.ok===true&&response.state==='RUNNING') record=this.store.transition(vmId,'RUNNING','TASK_STARTED',{}, {taskId:request.taskId});
    if(request.action==='STATUS'&&(response.state==='COMPLETED'||response.state==='CANCELLED'||response.state==='FAILED')&&record.lifecycle==='RUNNING') record=this.store.transition(vmId,'READY','TASK_TERMINAL',{}, {taskId:request.taskId,state:String(response.state)});
    const publicResponse={...response}; if(typeof publicResponse.resultHex==='string'){publicResponse.output=Buffer.from(publicResponse.resultHex,'hex').toString('utf8');delete publicResponse.resultHex;}
    return {vmId,task:publicResponse,microvmSequence:record.sequence};
  }
  async stop(payload:unknown,context:ProviderContext):Promise<JsonObject>{
    const {vmId}=normalizeVmSelector(payload); let record=this.owned(vmId,owner(context)); if(record.lifecycle==='STOPPED'||record.lifecycle==='CLEANED') return {microvm:record,replayed:true};
    record=this.store.transition(vmId,'STOPPING','STOP_REQUESTED',{},{}); const tokenFile=tokenPath(join(this.root,vmId));
    if(existsSync(tokenFile)&&existsSync(record.vsockSocketIdentity)){try{await guestCall(record.vsockSocketIdentity,readFileSync(tokenFile,'utf8').trim(),'SHUTDOWN',3_000);}catch{}}
    await this.stopUnit(record.systemdUnit); const absent=!this.unitActive(record.systemdUnit);
    if(!absent) throw new MicrovmError('microvm_cleanup_failed','Firecracker process did not stop');
    const stopped=this.store.transition(vmId,'STOPPED','STOPPED',{guestAgentState:'STOPPED',processIdentity:null,cgroup:'',cleanup:{...record.cleanup,processAbsent:true}},{processAbsent:true});
    return {microvm:stopped,replayed:false};
  }
  async remove(payload:unknown,context:ProviderContext):Promise<JsonObject>{
    const {vmId}=normalizeVmSelector(payload); let record=this.owned(vmId,owner(context)); if(record.lifecycle==='CLEANED') return {microvm:record,replayed:true};
    if(record.lifecycle!=='STOPPED') await this.stop({vmId},context); record=this.store.get(vmId); record=this.store.transition(vmId,'CLEANING','REMOVE_REQUESTED',{cleanup:{...record.cleanup,requested:true}},{ });
    const vmRoot=join(this.root,vmId); const vmRuntimeRoot=join(this.runtimeRoot,vmId.slice(4)); rmSync(vmRoot,{recursive:true,force:true}); rmSync(vmRuntimeRoot,{recursive:true,force:true}); this.run('/usr/bin/systemctl',['reset-failed',record.systemdUnit],10_000);
    const processAbsent=!this.unitActive(record.systemdUnit); const socketAbsent=!existsSync(record.vsockSocketIdentity); const writableLayerAbsent=!existsSync(record.writableLayerIdentity);
    if(!processAbsent||!socketAbsent||!writableLayerAbsent) throw new MicrovmError('microvm_cleanup_failed','microVM resource cleanup could not be verified',{processAbsent,socketAbsent,writableLayerAbsent});
    const cleaned=this.store.transition(vmId,'CLEANED','CLEANED',{cleanup:{requested:true,completed:true,processAbsent,socketAbsent,writableLayerAbsent,completedAt:this.now()}},{processAbsent,socketAbsent,writableLayerAbsent});
    return {microvm:cleaned,replayed:false};
  }
  async reconcile():Promise<JsonObject>{
    const updated:string[]=[]; const healthy:string[]=[]; const lost:string[]=[];
    for(const record of this.store.all()){
      if(!['STARTING','BOOTING','READY','RUNNING','STOPPING'].includes(record.lifecycle)) continue;
      try{this.assertProcess(record); if(record.lifecycle==='READY'||record.lifecycle==='RUNNING'){const token=readFileSync(tokenPath(join(this.root,record.vmId)),'utf8').trim();await guestCall(record.vsockSocketIdentity,token,'HEALTH',2_000);} healthy.push(record.vmId);}
      catch(error){const code=error instanceof MicrovmError?error.code:'microvm_process_identity_conflict';const message=(error instanceof Error?error.message:String(error)).slice(0,512);this.store.transition(record.vmId,'LOST','RECONCILE_LOST',{guestAgentState:'FAILED',error:{code,message,phase:'reconcile'}},{code,messageDigest:sha256(message)});updated.push(record.vmId);lost.push(record.vmId);}
    }
    const orphans=this.findOrphanUnits(); for(const unit of orphans) await this.stopUnit(unit);
    return {ok:orphans.every((unit)=>!this.unitActive(unit)),healthy,lost,updated,orphanUnits:orphans,integrity:this.store.reconcileIntegrity()};
  }
  private owned(vmId:string,ownerPrincipal:string):MicrovmRecord { const record=this.store.get(vmId); if(record.ownerPrincipal!==ownerPrincipal) throw new MicrovmError('microvm_not_found','microVM was not found for this owner'); return record; }
  private guestCommand(request:MicrovmExecAction):string { if(request.action==='ECHO') return `EXEC ECHO_HEX ${request.taskId} ${Buffer.from(request.input,'utf8').toString('hex')}`; if(request.action==='SLEEP')return `EXEC SLEEP_MS ${request.taskId} ${request.durationMs}`;return `${request.action} ${request.taskId}`; }
  private allocateVsockCid():number { const used=new Set(this.store.all().filter((record)=>!['CLEANED','FAILED','LOST'].includes(record.lifecycle)).map((record)=>record.vsockCid)); for(let cid=10_000;cid<65_535;cid++)if(!used.has(cid))return cid; throw new MicrovmError('microvm_provider_unavailable','no vsock CID is available'); }
  private async waitForProcess(unit:string,expectedDigest:string):Promise<MicrovmProcessIdentity>{for(let i=0;i<200;i++){const show=this.run('/usr/bin/systemctl',['show','--value','-p','MainPID',unit],5_000);const pid=Number(show.stdout.trim());if(Number.isSafeInteger(pid)&&pid>1&&existsSync(`/proc/${pid}`)){const executablePath=readlinkSync(`/proc/${pid}/exe`);const identity={pid,processStartTime:processStartTime(pid),executablePath,executableDigest:executableDigest(executablePath)};if(identity.executableDigest!==expectedDigest)throw new MicrovmError('microvm_process_identity_conflict','Firecracker executable digest mismatch');return identity;}await sleep(50);}throw new MicrovmError('microvm_provider_unavailable','Firecracker process readiness deadline exceeded');}
  private async waitForGuest(vsockPath:string,token:string,timeoutMs:number):Promise<GuestResponse>{const deadline=Date.now()+timeoutMs;let last:unknown;while(Date.now()<deadline){try{const response=await guestCall(vsockPath,token,'HEALTH',1_000);if(response.ok===true)return response;last=response;}catch(error){last=error;}await sleep(50);}throw new MicrovmError('microvm_guest_protocol_failed','guest readiness deadline exceeded',{lastError:last instanceof Error?last.message:String(last)});}
  private unitActive(unit:string):boolean{return this.run('/usr/bin/systemctl',['is-active','--quiet',unit],5_000).status===0;}
  private assertProcess(record:MicrovmRecord):void { if(record.processIdentity===null||!existsSync(`/proc/${record.processIdentity.pid}`))throw new MicrovmError('microvm_process_identity_conflict','Firecracker process is absent');const observedStart=processStartTime(record.processIdentity.pid);const observedExe=readlinkSync(`/proc/${record.processIdentity.pid}/exe`);if(observedStart!==record.processIdentity.processStartTime||observedExe!==record.processIdentity.executablePath||executableDigest(observedExe)!==record.processIdentity.executableDigest)throw new MicrovmError('microvm_process_identity_conflict','Firecracker process identity conflict');}
  private async stopUnit(unit:string):Promise<void>{this.run('/usr/bin/systemctl',['stop',unit],15_000);for(let i=0;i<100;i++){if(!this.unitActive(unit))return;await sleep(50);}this.run('/usr/bin/systemctl',['kill','--signal=SIGKILL',unit],5_000);for(let i=0;i<100;i++){if(!this.unitActive(unit))return;await sleep(50);}}
  private async cleanupEffects(record:MicrovmRecord,removeFiles:boolean):Promise<void>{await this.stopUnit(record.systemdUnit);this.run('/usr/bin/systemctl',['reset-failed',record.systemdUnit],10_000);if(removeFiles){rmSync(join(this.root,record.vmId),{recursive:true,force:true});rmSync(join(this.runtimeRoot,record.vmId.slice(4)),{recursive:true,force:true});}}
  private findOrphanUnits():string[]{const result=this.run('/usr/bin/systemctl',['list-units','--all','--plain','--no-legend','baby-x-microvm-*.service'],10_000);if(result.status!==0)return[];const known=new Set(this.store.all().filter((record)=>['STARTING','BOOTING','READY','RUNNING','STOPPING'].includes(record.lifecycle)).map((record)=>record.systemdUnit));return result.stdout.split('\n').map((line)=>line.trim().split(/\s+/u)[0]).filter((unit)=>unit&&unit.endsWith('.service')&&!known.has(unit));}
}
