#!/usr/bin/env bash
set -euo pipefail
root=${BABY_X_INSTALL_ROOT:-/opt/baby-x}
current=$(readlink -f "$root/current")
previous=$(readlink -f "$root/previous")
[[ -n "$current" && -n "$previous" && "$current" != "$previous" ]] || { echo 'distinct current and previous releases required' >&2; exit 1; }
ln -sfn "$previous" "$root/current.tmp"; mv -Tf "$root/current.tmp" "$root/current"
ln -sfn "$current" "$root/previous.tmp"; mv -Tf "$root/previous.tmp" "$root/previous"
if [[ ${BABY_X_INSTALL_UNITS:-0} == 1 ]]; then systemctl restart baby-x.socket baby-x-gateway.service; fi
scripts/verify-local.sh
