import test from 'node:test';
import assert from 'node:assert/strict';
import { SeccompSupervisorManager, SECCOMP_SUPERVISOR_ACTIONS } from '../../dist/runtime/syscall/supervisor.js';
class Recorder { calls=[]; async run(p){ this.calls.push(p); return { ...p, exitCode:0, signal:null, stdout:'', stderr:'', cwd:'/', startedAt:'', completedAt:'', durationMs:0, stdoutSha256:'', stderrSha256:'' }; } }
test('seccomp supervisor probe uses exact argv and target', async()=>{
  const e=new Recorder();
  await new SeccompSupervisorManager(e,'/opt/baby-x-seccomp-supervisor').probe({target:{kind:'machine',machine:'arena-1'},timeoutMs:1234});
  assert.deepEqual(e.calls[0],{argv:['/opt/baby-x-seccomp-supervisor','probe'],target:{kind:'machine',machine:'arena-1'},timeoutMs:1234});
});
test('seccomp supervisor describes supported truth',()=>{
  const d=new SeccompSupervisorManager(new Recorder(),'/x').describe();
  assert.deepEqual(d.supportedActions,['describe','probe']);
  assert.deepEqual(d.plannedResponseActions,[...SECCOMP_SUPERVISOR_ACTIONS]);
  assert.match(d.limitations[0],/currently implements/);
});
test('seccomp supervisor validates executable and actions',async()=>{
  const m=new SeccompSupervisorManager(new Recorder(),'relative');
  await assert.rejects(()=>m.probe(),/absolute/);
  assert.throws(()=>m.assertResponseAction('explode'),/unsupported/);
  assert.doesNotThrow(()=>m.assertResponseAction('errno'));
});
