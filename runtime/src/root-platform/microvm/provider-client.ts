import { randomUUID } from 'node:crypto';
import { createConnection } from 'node:net';
import type { JsonObject, RuntimeExecutionContext } from '../../core.ts';
import { MicrovmError, type MicrovmErrorCode } from './errors.ts';

interface ProviderResponse {requestId:string;ok:boolean;result?:JsonObject;error?:{code:string;message:string;details:JsonObject}}
export class RootProviderClient {
  constructor(readonly socketPath=process.env.BABY_X_ROOT_PROVIDER_SOCKET??'/run/baby-x/root-provider.sock'){}
  call(operation:string,payload:JsonObject,context:RuntimeExecutionContext,timeoutMs=120_000):Promise<JsonObject>{
    const requestId=`rpr_${randomUUID().replaceAll('-','')}`; const ownerPrincipal=context.subject??'stealtheye-owner'; const idempotencyKey=context.idempotencyKey??`read-${requestId}`;
    const request={requestId,operation,payload,context:{ownerPrincipal,idempotencyKey}};
    return new Promise((resolve,reject)=>{const socket=createConnection({path:this.socketPath});let pending=Buffer.alloc(0);let complete=false;
      const finish=(error?:Error,result?:JsonObject)=>{if(complete)return;complete=true;clearTimeout(timer);socket.destroy();if(error)reject(error);else resolve(result??{});};
      const timer=setTimeout(()=>finish(new MicrovmError('microvm_provider_unavailable','root provider deadline exceeded')),timeoutMs);
      socket.on('connect',()=>socket.write(`${JSON.stringify(request)}\n`));
      socket.on('data',(chunk:Buffer)=>{if(pending.length+chunk.length>1_048_576)return finish(new MicrovmError('microvm_provider_unavailable','root provider response exceeds the configured bound'));pending=Buffer.concat([pending,chunk]);});
      socket.on('end',()=>{if(complete)return;try{const line=pending.toString('utf8').trim();const response=JSON.parse(line) as ProviderResponse;if(response.requestId!==requestId)throw new Error('request identity mismatch');if(!response.ok){const code=(response.error?.code??'microvm_provider_unavailable') as MicrovmErrorCode;return finish(new MicrovmError(code,response.error?.message??'root provider request failed',response.error?.details??{}));}finish(undefined,response.result??{});}catch(error){finish(error instanceof MicrovmError?error:new MicrovmError('microvm_provider_unavailable','root provider returned an invalid response',{cause:error instanceof Error?error.message:String(error)}));}});
      socket.on('error',(error)=>finish(new MicrovmError('microvm_provider_unavailable','root provider connection failed',{cause:error.message})));
    });
  }
}
