#!/usr/bin/env bash
set -euo pipefail

config_root=${BABY_X_CONFIG_ROOT:-/etc/baby-x}
node_bin=${BABY_X_NODE_BIN:-/opt/node-v24.18.0-linux-x64/bin/node}
gateway_private="$config_root/gateway-authority-private.pem"
gateway_public="$config_root/gateway-authority-public.pem"
proof_private="$config_root/proof-private.pem"
proof_public="$config_root/proof-public.pem"
broker_private="$config_root/root-broker-private.pem"
broker_public="$config_root/root-broker-public.pem"
runtime_environment="$config_root/runtime-key-environment"
gateway_environment="$config_root/gateway-key-environment"
broker_environment="$config_root/root-broker-environment"

[[ $(id -u) == 0 ]] || { echo 'root authority is required to provision Baby-X keys' >&2; exit 1; }
getent passwd fix-exec >/dev/null
getent passwd fix-mcp >/dev/null
getent group horsey >/dev/null
runtime_uid=$(id -u fix-exec)
gateway_uid=$(id -u fix-mcp)
[[ "$runtime_uid" =~ ^[0-9]+$ ]] && (( runtime_uid > 0 ))
[[ -x "$node_bin" ]]
install -d -o root -g horsey -m 0750 "$config_root"
exec 9>"$config_root/.keys.lock"
flock -x 9

assert_pair_state() {
  local private=$1
  local public=$2
  if [[ -e "$private" && ! -e "$public" ]] || [[ ! -e "$private" && -e "$public" ]]; then
    echo "partial Baby-X key material exists for $(basename "$private"); refusing automatic replacement" >&2
    exit 1
  fi
}

generate_pair() {
  local private=$1
  local public=$2
  [[ ! -e "$private" && ! -e "$public" ]] || return 0
  local temporary
  temporary=$(mktemp -d "$config_root/.keys.XXXXXX")
  trap 'rm -rf "$temporary"' RETURN
  "$node_bin" --input-type=module - "$temporary/private.pem" "$temporary/public.pem" <<'NODE'
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const [privatePath, publicPath] = process.argv.slice(2);
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
writeFileSync(privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
writeFileSync(publicPath, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600, flag: 'wx' });
NODE
  install -o root -g root -m 0600 "$temporary/private.pem" "$private"
  install -o root -g horsey -m 0640 "$temporary/public.pem" "$public"
  rm -rf "$temporary"
  trap - RETURN
}

assert_pair_state "$gateway_private" "$gateway_public"
assert_pair_state "$proof_private" "$proof_public"
assert_pair_state "$broker_private" "$broker_public"
generate_pair "$gateway_private" "$gateway_public"
generate_pair "$proof_private" "$proof_public"
generate_pair "$broker_private" "$broker_public"

chown fix-mcp:horsey "$gateway_private"
chown fix-exec:horsey "$proof_private"
chmod 0600 "$gateway_private" "$proof_private"
chown root:horsey "$gateway_public" "$proof_public" "$broker_public"
chmod 0640 "$gateway_public" "$proof_public" "$broker_public"
chown root:root "$broker_private"
chmod 0600 "$broker_private"

"$node_bin" --input-type=module - \
  "$gateway_private" "$gateway_public" \
  "$proof_private" "$proof_public" \
  "$broker_private" "$broker_public" <<'NODE'
import { createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
const paths = process.argv.slice(2);
for (let index = 0; index < paths.length; index += 2) {
  const privateKey = createPrivateKey(readFileSync(paths[index]));
  const publicKey = createPublicKey(readFileSync(paths[index + 1]));
  if (privateKey.asymmetricKeyType !== 'ed25519' || publicKey.asymmetricKeyType !== 'ed25519') throw new Error('Baby-X keys must be Ed25519');
  const challenge = randomBytes(32);
  if (!verify(null, challenge, publicKey, sign(null, challenge, privateKey))) throw new Error('Baby-X key pair verification failed');
}
NODE

write_environment() {
  local destination=$1
  local mode=$2
  local group=$3
  local temporary
  temporary=$(mktemp "$config_root/.environment.XXXXXX")
  /bin/cp /dev/stdin "$temporary"
  chown root:"$group" "$temporary"
  chmod "$mode" "$temporary"
  mv -f "$temporary" "$destination"
}

write_environment "$runtime_environment" 0640 horsey <<EOF_RUNTIME
BABY_X_GATEWAY_UID=$gateway_uid
BABY_X_GATEWAY_PUBLIC_KEY=$gateway_public
BABY_X_PROOF_PRIVATE_KEY=$proof_private
BABY_X_PROOF_KEY_ID=baby-x-proof-v1
BABYX_ROOT_BROKER_PUBLIC_KEY=$broker_public
EOF_RUNTIME

write_environment "$gateway_environment" 0640 horsey <<EOF_GATEWAY
BABY_X_GATEWAY_PRIVATE_KEY=$gateway_private
BABY_X_PROOF_PUBLIC_KEY=$proof_public
EOF_GATEWAY

write_environment "$broker_environment" 0600 root <<EOF_BROKER
BABYX_ROOT_BROKER_SIGNING_KEY=$broker_private
BABYX_RUNTIME_UID=$runtime_uid
EOF_BROKER

printf 'runtime_uid=%s\n' "$runtime_uid"
printf 'gateway_public_sha256=%s\n' "$(sha256sum "$gateway_public" | awk '{print $1}')"
printf 'proof_public_sha256=%s\n' "$(sha256sum "$proof_public" | awk '{print $1}')"
printf 'broker_public_sha256=%s\n' "$(sha256sum "$broker_public" | awk '{print $1}')"
