import test from 'node:test';
import assert from 'node:assert/strict';
import { GdbManager } from '../../dist/runtime/debug/gdb.js';
class Recorder { calls=[]; async run(p){this.calls.push(p); return { ...p, exitCode:0, signal:null, stdout:'', stderr:'', cwd:'/', startedAt:'', completedAt:'', durationMs:0, stdoutSha256:'', stderrSha256:'' };} }
test('gdb backtrace uses exact batch argv',async()=>{const e=new Recorder(); await new GdbManager(e).backtrace({pid:42,target:{kind:'machine',machine:'arena-1'}}); assert.deepEqual(e.calls[0].argv,['/usr/bin/gdb','--quiet','--batch','--ex','set pagination off','--ex','thread apply all bt full','--pid','42']); assert.deepEqual(e.calls[0].target,{kind:'machine',machine:'arena-1'});});
test('gdb validates selector combinations and paths',async()=>{const m=new GdbManager(new Recorder()); await assert.rejects(()=>m.run({}),/provide/); await assert.rejects(()=>m.run({coreFile:'/tmp/core'}),/requires executable/); await assert.rejects(()=>m.run({executable:'relative'}),/absolute/); await assert.rejects(()=>m.run({pid:0}),/positive/);});
