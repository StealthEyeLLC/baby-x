export interface RuntimeConfig {
  socketPath: string;
  stateRoot: string;
  gatewayUid: number;
  requestMaxAgeMs: number;
  nonceRetentionMs: number;
  maxFrameSize: number;
  ownerSubject: 'stealtheye-owner';
  authorityClass: 'unrestricted-owner';
}

function boundedInteger(value: string | undefined, fallback: number, minimum: number, maximum: number, name: string): number {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  return parsed;
}

export function loadConfig(): RuntimeConfig {
  return {
    socketPath: process.env.BABY_X_SOCKET_PATH ?? '/run/horsey/baby-x.sock',
    stateRoot: process.env.BABY_X_STATE_ROOT ?? '/var/lib/baby-x',
    gatewayUid: Number(process.env.BABY_X_GATEWAY_UID ?? '-1'),
    requestMaxAgeMs: Number(process.env.BABY_X_REQUEST_MAX_AGE_MS ?? '300000'),
    nonceRetentionMs: Number(process.env.BABY_X_NONCE_RETENTION_MS ?? '86400000'),
    maxFrameSize: boundedInteger(process.env.BABY_X_MAX_FRAME_SIZE, 16_777_216, 1_024, 67_108_864, 'BABY_X_MAX_FRAME_SIZE'),
    ownerSubject: 'stealtheye-owner',
    authorityClass: 'unrestricted-owner',
  };
}
