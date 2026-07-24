import { Executor, type JsonObject } from '../core.ts';

export class SystemdManager {
  constructor(private readonly executor = new Executor()) {}
  raw(tool: string, argv: string[], payload: JsonObject = {}): Promise<JsonObject> { return this.executor.run({ ...payload, argv: [tool, ...argv] }) as unknown as Promise<JsonObject>; }
}
