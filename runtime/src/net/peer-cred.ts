export interface PeerCredentials { pid: number; uid: number; gid: number }

export async function getPeerCredentials(fd: number): Promise<PeerCredentials> {
  const require = process.getBuiltinModule('module').createRequire(import.meta.url);
  const addon = require('../../build/Release/peer_cred.node') as { getPeerCredentials(value: number): PeerCredentials };
  return addon.getPeerCredentials(fd);
}
