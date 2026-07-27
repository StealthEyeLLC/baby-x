#!/usr/bin/env bash
set -euo pipefail

config_root=${BABY_X_CONFIG_ROOT:-/etc/baby-x}
node_bin=${BABY_X_NODE_BIN:-/opt/node-v24.18.0-linux-x64/bin/node}
gateway_private="$config_root/gateway-authority-private.pem"
gateway_public="$config_root/gateway-authority-public.pem"
proof_private="$config_root/proof-private.pem"
proof_public="$config_root/proof-public.pem"
runtime_environment="$config_root/runtime-key-environment"
gateway_environment="$config_root/gateway-key-environment"

[[ $(id -u) == 0 ]] || { echo 'root authority is required to provision Baby-X keys' >&2; exit 1; }
getent passwd fix-mcp >/dev/null
getent group horsey >/dev/null
[[ -x "$node_bin" ]]
install -d -o root -g horsey -m 0750 "$config_root"
exec 9>"$config_root/.keys.lock"
flock -x 9

files=("$gateway_private" "$gateway_public" "$proof_private" "$proof_public")
present=0
for path in "${files[@]}"; do [[ -e "$path" ]] && present=$((present + 1)); done
if (( present != 0 && present != ${#files[@]} )); then
  echo 'partial Baby-X key material exists; refusing automatic replacement' >&2
  exit 1
fi

if (( present == 0 )); then
  temporary=$(mktemp -d "$config_root/.keys.XXXXXX")
  cleanup() { rm -rf "$temporary"; }
  trap cleanup EXIT
  "$node_bin" --input-type=module - "$temporary" <<'NODE'
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

const directory = process.argv[2];
for (const prefix of ['gateway-authority', 'proof']) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  writeFileSync(join(directory, `${prefix}-private.pem`), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
  writeFileSync(join(directory, `${prefix}-public.pem`), publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600, flag: 'wx' });
}
NODE
  install -o fix-mcp -g horsey -m 0600 "$temporary/gateway-authority-private.pem" "$gateway_private"
  install -o root -g horsey -m 0640 "$temporary/gateway-authority-public.pem" "$gateway_public"
  install -o root -g root -m 0600 "$temporary/proof-private.pem" "$proof_private"
  install -o root -g horsey -m 0640 "$temporary/proof-public.pem" "$proof_public"
  trap - EXIT
  cleanup
else
  chown fix-mcp:horsey "$gateway_private"
  chmod 0600 "$gateway_private"
  chown root:horsey "$gateway_public" "$proof_public"
  chmod 0640 "$gateway_public" "$proof_public"
  chown root:root "$proof_private"
  chmod 0600 "$proof_private"
fi

"$node_bin" --input-type=module - "$gateway_private" "$gateway_public" "$proof_private" "$proof_public" <<'NODE'
import { createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const paths = process.argv.slice(2);
for (let index = 0; index < paths.length; index += 2) {
  const privateKey = createPrivateKey(readFileSync(paths[index]));
  const publicKey = createPublicKey(readFileSync(paths[index + 1]));
  if (privateKey.asymmetricKeyType !== 'ed25519' || publicKey.asymmetricKeyType !== 'ed25519') throw new Error('Baby-X keys must be Ed25519');
  const challenge = randomBytes(32);
  const signature = sign(null, challenge, privateKey);
  if (!verify(null, challenge, publicKey, signature)) throw new Error('Baby-X key pair verification failed');
}
NODE

write_environment() {
  local destination=$1
  local temporary
  temporary=$(mktemp "$config_root/.environment.XXXXXX")
  cat > "$temporary"
  chown root:horsey "$temporary"
  chmod 0640 "$temporary"
  mv -f "$temporary" "$destination"
}

write_environment "$runtime_environment" <<EOF_RUNTIME
BABY_X_GATEWAY_PUBLIC_KEY=$gateway_public
BABY_X_PROOF_PRIVATE_KEY=$proof_private
BABY_X_PROOF_KEY_ID=baby-x-proof-v1
EOF_RUNTIME

write_environment "$gateway_environment" <<EOF_GATEWAY
BABY_X_GATEWAY_PRIVATE_KEY=$gateway_private
BABY_X_PROOF_PUBLIC_KEY=$proof_public
EOF_GATEWAY

printf 'gateway_public_sha256=%s\n' "$(sha256sum "$gateway_public" | awk '{print $1}')"
printf 'proof_public_sha256=%s\n' "$(sha256sum "$proof_public" | awk '{print $1}')"
