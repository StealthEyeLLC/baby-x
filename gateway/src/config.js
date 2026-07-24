export function loadConfig() {
  return {
    host: process.env.BABY_X_GATEWAY_HOST ?? '127.0.0.1',
    port: Number(process.env.BABY_X_GATEWAY_PORT ?? '2097'),
    socketPath: process.env.BABY_X_SOCKET_PATH ?? '/run/horsey/baby-x.sock',
    authorityPrivateKey: process.env.BABY_X_GATEWAY_PRIVATE_KEY ?? '/etc/baby-x/gateway-authority-private.pem',
    proofPublicKey: process.env.BABY_X_PROOF_PUBLIC_KEY ?? '/etc/baby-x/proof-public.pem',
    issuer: process.env.BABY_X_OAUTH_ISSUER ?? 'http://127.0.0.1:2097',
    resource: process.env.BABY_X_OAUTH_RESOURCE ?? 'http://127.0.0.1:2097/mcp',
    ownerId: Number(process.env.BABY_X_OWNER_GITHUB_ID ?? '247854506'),
    statePath: process.env.BABY_X_OAUTH_STATE_PATH ?? '/var/lib/baby-x-gateway/oauth-state.json',
  };
}
