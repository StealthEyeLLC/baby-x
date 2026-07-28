#!/usr/bin/env bash
set -euo pipefail

node_bin=${BABY_X_NODE_BIN:-/opt/node-v24.18.0-linux-x64/bin/node}
root=${BABY_X_INSTALL_ROOT:-/opt/baby-x}
current=$(readlink -f "$root/current" 2>/dev/null || true)
[[ -n "$current" && -d "$current" ]] || { echo 'current immutable release is absent' >&2; exit 1; }

args=(
  --install-root "$root"
  --state-root "${BABY_X_STATE_ROOT:-/var/lib/baby-x}"
  --commit "${BABY_X_EXPECTED_COMMIT:?BABY_X_EXPECTED_COMMIT is required}"
  --tree "${BABY_X_EXPECTED_TREE:?BABY_X_EXPECTED_TREE is required}"
  --deployment-id "${BABY_X_DEPLOYMENT_ID:-read-only-verification}"
  --units "${BABY_X_INSTALL_UNITS:-1}"
  --health-url "${BABY_X_GATEWAY_HEALTH_URL:-http://127.0.0.1:2097/healthz}"
  --forbidden-roots "${BABY_X_FORBIDDEN_ROOTS:-}"
)

exec "$node_bin" "$current/scripts/verify-local.mjs" "${args[@]}"
