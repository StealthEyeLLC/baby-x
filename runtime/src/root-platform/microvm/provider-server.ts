import { createServer, type Server, type Socket } from 'node:net';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname } from 'node:path';
import { getPeerCredentials } from '../../net/peer-cred.ts';
import type { JsonObject } from '../../core.ts';
import { MicrovmError } from './errors.ts';
import { FirecrackerMicrovmProvider } from './provider.ts';

interface ProviderRequest { requestId:string; operation:string; payload:JsonObject; context:{ownerPrincipal:string;idempotencyKey:string} }
interface ProviderResponse extends JsonObject { requestId:string; ok:boolean; result?:JsonObject; error?:{code:string;message:string;details:JsonObject} }
export type ProviderListenOptions={path:string}|{fd:number};

function socketFd(socket:Socket):number { const fd=(socket as unknown as {_handle?:{fd?:number}})._handle?.fd; if(typeof fd!=='number')throw new Error('provider socket descriptor unavailable'); return fd; }
export function resolveProviderListenOptions(socketPath:string,environment:Record<string,string|undefined>=process.env,processId=process.pid):ProviderListenOptions {
  const pid=environment.LISTEN_PID; const fds=environment.LISTEN_FDS;
  if(pid===undefined&&fds===undefined)return {path:socketPath};
  if(pid===undefined||fds===undefined||!/^\d+$/u.test(pid)||!/^\d+$/u.test(fds)||Number(pid)!==processId||Number(fds)!==1)throw new Error('invalid root provider socket activation environment');
  return {fd:3};
}
function responseError(requestId:string,error:unknown):ProviderResponse { return {requestId,ok:false,error:{code:error instanceof MicrovmError?error.code:'microvm_provider_unavailable',message:error instanceof Error?error.message:String(error),details:error instanceof MicrovmError?error.details:{}}}; }
function validRequest(value:unknown):ProviderRequest {
  if(value===null||typeof value!=='object'||Array.isArray(value))throw new MicrovmError('microvm_invalid_request','provider request must be an object');
  const input=value as Record<string,unknown>; const extras=Object.keys(input).filter((key)=>!['requestId','operation','payload','context'].includes(key)); if(extras.length)throw new MicrovmError('microvm_invalid_request','provider request has unsupported properties',{properties:extras});
  if(typeof input.requestId!=='string'||!/^[A-Za-z0-9_-]{8,128}$/u.test(input.requestId))throw new MicrovmError('microvm_invalid_request','provider requestId is invalid');
  if(typeof input.operation!=='string'||!['describe','create','get','list','exec','stop','remove','reconcile'].includes(input.operation))throw new MicrovmError('microvm_invalid_request','provider operation is invalid');
  if(input.payload===null||typeof input.payload!=='object'||Array.isArray(input.payload))throw new MicrovmError('microvm_invalid_request','provider payload must be an object');
  if(input.context===null||typeof input.context!=='object'||Array.isArray(input.context))throw new MicrovmError('microvm_invalid_request','provider context must be an object');
  const context=input.context as Record<string,unknown>; if(typeof context.ownerPrincipal!=='string'||typeof context.idempotencyKey!=='string')throw new MicrovmError('microvm_invalid_request','provider context is invalid');
  return input as unknown as ProviderRequest;
}
async function dispatch(provider:FirecrackerMicrovmProvider,request:ProviderRequest):Promise<JsonObject>{
  if(request.operation==='describe')return provider.describe(); if(request.operation==='create')return provider.create(request.payload,request.context); if(request.operation==='get')return provider.get(request.payload,request.context); if(request.operation==='list')return provider.list(request.payload,request.context); if(request.operation==='exec')return provider.exec(request.payload,request.context); if(request.operation==='stop')return provider.stop(request.payload,request.context); if(request.operation==='remove')return provider.remove(request.payload,request.context); return provider.reconcile();
}
export function startRootProviderServer(provider:FirecrackerMicrovmProvider,options:{socketPath:string;allowedUid:number;listen?:ProviderListenOptions}):Server {
  const server=createServer({ allowHalfOpen: true },(socket)=>{
    let pending=Buffer.alloc(0); let processing=false; let authorized=false;
    socket.pause();
    void getPeerCredentials(socketFd(socket)).then((credentials)=>{if(credentials.uid!==options.allowedUid){socket.destroy();return;}authorized=true;socket.resume();}).catch(()=>socket.destroy());
    socket.on('data',(chunk:Buffer)=>{
      if(!authorized)return socket.destroy(new Error('provider peer is not authorized'));
      if(processing)return socket.destroy(new Error('only one provider request is allowed per connection'));
      if(pending.length+chunk.length>65_536)return socket.destroy(new Error('provider request exceeds the configured bound'));
      pending=Buffer.concat([pending,chunk]); const newline=pending.indexOf(0x0a); if(newline<0)return; if(newline!==pending.length-1)return socket.destroy(new Error('exactly one provider request line is required'));
      processing=true; let requestId='unknown';
      void (async()=>{try{const request=validRequest(JSON.parse(pending.subarray(0,newline).toString('utf8')));requestId=request.requestId;const result=await dispatch(provider,request);socket.end(`${JSON.stringify({requestId,ok:true,result} satisfies ProviderResponse)}\n`);}catch(error){socket.end(`${JSON.stringify(responseError(requestId,error))}\n`);}})();
    });
  });
  const listen=options.listen??resolveProviderListenOptions(options.socketPath);
  if('path'in listen){mkdirSync(dirname(listen.path),{recursive:true,mode:0o750});rmSync(listen.path,{force:true});server.listen(listen.path);}else server.listen({fd:listen.fd});
  return server;
}
