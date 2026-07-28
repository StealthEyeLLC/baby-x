#!/usr/bin/env bash
set -euo pipefail

node_bin=${BABY_X_NODE_BIN:-/opt/node-v24.18.0-linux-x64/bin/node}
root=${BABY_X_INSTALL_ROOT:-/opt/baby-x}
deployment_id=${BABY_X_DEPLOYMENT_ID:?BABY_X_DEPLOYMENT_ID is required}
reason=${BABY_X_ROLLBACK_REASON:?BABY_X_ROLLBACK_REASON is required}
current=$(readlink -f "$root/current" 2>/dev/null || true)

[[ $(id -u) == 0 ]] || { echo 'root authority is required for rollback' >&2; exit 1; }
[[ -n "$current" && -d "$current" ]] || { echo 'current immutable release is absent' >&2; exit 1; }
exec 9>/run/lock/baby-x-deploy.lock
flock -x 9

exec "$node_bin" "$current/scripts/activate-release.mjs" \
  --mode rollback \
  --deployment-id "$deployment_id" \
  --reason "$reason" \
  --install-root "$root" \
  --state-root "${BABY_X_STATE_ROOT:-/var/lib/baby-x}"
