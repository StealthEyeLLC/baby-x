export interface RuntimeConfig {
  socketPath: string;
  stateRoot: string;
  gatewayUid: number;
  requestMaxAgeMs: number;
  nonceRetentionMs: number;
  ownerSubject: 'stealtheye-owner';
  authorityClass: 'unrestricted-owner';
}

export function loadConfig(): RuntimeConfig {
  return {
    socketPath: process.env.BABY_X_SOCKET_PATH ?? '/run/horsey/baby-x.sock',
    stateRoot: process.env.BABY_X_STATE_ROOT ?? '/var/lib/baby-x',
    gatewayUid: Number(process.env.BABY_X_GATEWAY_UID ?? '-1'),
    requestMaxAgeMs: Number(process.env.BABY_X_REQUEST_MAX_AGE_MS ?? '300000'),
    nonceRetentionMs: Number(process.env.BABY_X_NONCE_RETENTION_MS ?? '86400000'),
    ownerSubject: 'stealtheye-owner',
    authorityClass: 'unrestricted-owner',
  };
}
