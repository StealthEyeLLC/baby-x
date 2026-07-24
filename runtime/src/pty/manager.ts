import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export class PtyManager {
  constructor(private readonly root: string, private readonly socket = '/run/horsey/baby-x-tmux.sock') { mkdirSync(root, { recursive: true, mode: 0o700 }); }
  create(shell = '/usr/bin/bash', cwd = '/'): Record<string, unknown> { const sessionId = randomUUID(); const result = spawnSync('/usr/bin/tmux', ['-S', this.socket, 'new-session', '-d', '-s', sessionId, '-c', cwd, shell], { encoding: 'utf8' }); if (result.status !== 0) throw new Error(result.stderr); writeFileSync(join(this.root, `${sessionId}.offset`), '0'); return { sessionId, socket: this.socket, shell, cwd }; }
  input(sessionId: string, data: Buffer): void { const result = spawnSync('/usr/bin/tmux', ['-S', this.socket, 'load-buffer', '-'], { input: data }); if (result.status !== 0) throw new Error('tmux load-buffer failed'); spawnSync('/usr/bin/tmux', ['-S', this.socket, 'paste-buffer', '-t', sessionId]); }
  read(sessionId: string): Record<string, unknown> { const result = spawnSync('/usr/bin/tmux', ['-S', this.socket, 'capture-pane', '-p', '-e', '-t', sessionId], { encoding: 'utf8' }); return { data: Buffer.from(result.stdout).toString('base64'), encoding: 'base64', offset: Buffer.byteLength(result.stdout) }; }
  resize(sessionId: string, cols: number, rows: number): void { spawnSync('/usr/bin/tmux', ['-S', this.socket, 'resize-window', '-t', sessionId, '-x', String(cols), '-y', String(rows)]); }
  close(sessionId: string): void { spawnSync('/usr/bin/tmux', ['-S', this.socket, 'kill-session', '-t', sessionId]); }
}
