import { createConnection } from 'node:net';
import { MicrovmError } from './errors.ts';

export interface GuestResponse { ok: boolean; [key: string]: unknown }

export function guestCall(socketPath: string, token: string, command: string, timeoutMs = 5_000): Promise<GuestResponse> {
  if (!/^[a-f0-9]{64}$/u.test(token)) return Promise.reject(new MicrovmError('microvm_guest_authentication_failed','guest token is invalid'));
  if (Buffer.byteLength(command,'utf8') > 4096 || command.includes('\n')) return Promise.reject(new MicrovmError('microvm_invalid_request','guest command is invalid'));
  return new Promise((resolve,reject) => {
    const socket=createConnection({path:socketPath});
    let pending=Buffer.alloc(0); let connected=false; let complete=false;
    const finish=(error?:Error,response?:GuestResponse) => { if(complete)return; complete=true; clearTimeout(timer); socket.destroy(); if(error)reject(error); else resolve(response as GuestResponse); };
    const timer=setTimeout(()=>finish(new MicrovmError('microvm_guest_protocol_failed','guest response deadline exceeded')),timeoutMs);
    socket.on('connect',()=>socket.write('CONNECT 5000\n'));
    socket.on('data',(chunk:Buffer)=>{
      if (pending.length + chunk.length > 16_384) { finish(new MicrovmError('microvm_guest_protocol_failed','guest response exceeded the configured bound')); return; }
      pending=Buffer.concat([pending,chunk]);
      while(true){ const newline=pending.indexOf(0x0a); if(newline<0)return; const line=pending.subarray(0,newline).toString('utf8'); pending=pending.subarray(newline+1);
        if(!connected){ if(!/^OK [0-9]+$/u.test(line)){finish(new MicrovmError('microvm_guest_protocol_failed','vsock handshake failed'));return;} connected=true; socket.write(`${token}\n${command}\n`); continue; }
        try { const response=JSON.parse(line) as GuestResponse; if(response.error==='AUTHENTICATION_FAILED'){finish(new MicrovmError('microvm_guest_authentication_failed','guest authentication failed'));return;} finish(undefined,response); }
        catch { finish(new MicrovmError('microvm_guest_protocol_failed','guest returned invalid JSON')); }
        return;
      }
    });
    socket.on('error',(error)=>finish(new MicrovmError('microvm_guest_protocol_failed','guest transport failed',{ cause: error.message })));
    socket.on('end',()=>{ if(!complete)finish(new MicrovmError('microvm_guest_protocol_failed','guest closed the connection without a response')); });
  });
}
