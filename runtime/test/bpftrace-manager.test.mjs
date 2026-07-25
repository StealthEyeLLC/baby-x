import test from 'node:test';
import assert from 'node:assert/strict';
import { BpftraceManager } from '../../dist/runtime/trace/bpftrace.js';
class Recorder { calls=[]; async run(p){this.calls.push(p); return { ...p, exitCode:0, signal:null, stdout:'', stderr:'', cwd:'/', startedAt:'', completedAt:'', durationMs:0, stdoutSha256:'', stderrSha256:'' };} }
test('bpftrace constructs exact argv and machine target', async()=>{ const e=new Recorder(); const m=new BpftraceManager(e); await m.run({program:'BEGIN { printf("x"); }', output:'json', definitions:{PID:42}, target:{kind:'machine',machine:'arena-1'}}); assert.deepEqual(e.calls[0].argv,['/usr/bin/bpftrace','--output','json','--define','PID=42','-e','BEGIN { printf("x"); }']); assert.deepEqual(e.calls[0].target,{kind:'machine',machine:'arena-1'}); });
test('bpftrace validates mutually exclusive source and paths', async()=>{ const m=new BpftraceManager(new Recorder()); await assert.rejects(()=>m.run({program:'BEGIN{}',file:'/tmp/x'}),/exactly one/); await assert.rejects(()=>m.run({file:'relative'}),/absolute/); });
test('recipes are concrete programs',()=>{ const m=new BpftraceManager(new Recorder()); assert.match(m.recipe('process-exec'),/sched_process_exec/); assert.throws(()=>m.recipe('nope'),/unknown/); });
