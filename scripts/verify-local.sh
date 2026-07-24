#!/usr/bin/env bash
set -euo pipefail
root=${BABY_X_INSTALL_ROOT:-/opt/baby-x}
printf 'current=%s\n' "$(readlink -f "$root/current" 2>/dev/null || true)"
if [[ ${BABY_X_INSTALL_UNITS:-0} == 1 ]]; then systemctl is-active baby-x.socket baby-x.service baby-x-gateway.service; fi
