import { Executor, type JsonObject } from '../core.ts';

export const MACHINE_CLASSES = ['persistent-workspace', 'clean-build', 'disposable-experiment', 'adversarial-arena', 'failure-replay', 'production-rehearsal', 'custom'] as const;
export class MachineManager { constructor(private readonly executor = new Executor()) {} raw(tool: string, argv: string[], payload: JsonObject = {}): Promise<JsonObject> { return this.executor.run({ ...payload, argv: [tool, ...argv] }) as unknown as Promise<JsonObject>; } }
