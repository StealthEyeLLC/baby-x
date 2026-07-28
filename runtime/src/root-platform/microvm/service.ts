import type { JsonObject, RuntimeExecutionContext } from '../../core.ts';
import { RootProviderClient } from './provider-client.ts';
export class RootMicrovmService {
  constructor(private readonly client=new RootProviderClient()){}
  create(payload:JsonObject,context:RuntimeExecutionContext):Promise<JsonObject>{return this.client.call('create',payload,context);}
  get(payload:JsonObject,context:RuntimeExecutionContext):Promise<JsonObject>{return this.client.call('get',payload,context,15_000);}
  list(payload:JsonObject,context:RuntimeExecutionContext):Promise<JsonObject>{return this.client.call('list',payload,context,15_000);}
  exec(payload:JsonObject,context:RuntimeExecutionContext):Promise<JsonObject>{return this.client.call('exec',payload,context,75_000);}
  stop(payload:JsonObject,context:RuntimeExecutionContext):Promise<JsonObject>{return this.client.call('stop',payload,context,30_000);}
  remove(payload:JsonObject,context:RuntimeExecutionContext):Promise<JsonObject>{return this.client.call('remove',payload,context,30_000);}
  snapshot(payload:JsonObject,context:RuntimeExecutionContext):Promise<JsonObject>{return this.client.call('snapshot',payload,context,120_000);}
  restore(payload:JsonObject,context:RuntimeExecutionContext):Promise<JsonObject>{return this.client.call('restore',payload,context,120_000);}
  poolReconcile(payload:JsonObject,context:RuntimeExecutionContext):Promise<JsonObject>{return this.client.call('poolReconcile',payload,context,180_000);}
}
