#!/usr/bin/env bash
set -euo pipefail

root=${BABY_X_INSTALL_ROOT:-/opt/baby-x}
mkdir -p "$root"
exec 9>"$root/.install.lock"
flock -x 9

atomic_link() {
  local target=$1
  local link=$2
  ln -sfn "$target" "$link.tmp" || return
  mv -Tf "$link.tmp" "$link" || return
}

install_units_from() {
  local source=$1
  [[ ${BABY_X_INSTALL_UNITS:-0} == 1 ]] || return 0
  "$source/scripts/provision-local-keys.sh" || return
  cp "$source/ops/systemd/baby-x.service" "$source/ops/systemd/baby-x.socket" "$source/ops/systemd/baby-x-gateway.service" /etc/systemd/system/ || return
  if [[ -f "$source/ops/systemd/baby-x-root-provider.service" && -f "$source/ops/systemd/baby-x-root-provider.socket" && -x "$source/scripts/provision-microvm-assets.sh" ]]; then
    BABY_X_MICROVM_ASSET_ROOT=${BABY_X_MICROVM_ASSET_ROOT:-/var/lib/baby-x/root-platform/microvm/assets}       NODE=${BABY_X_NODE_BIN:-/opt/node-v24.18.0-linux-x64/bin/node}       "$source/scripts/provision-microvm-assets.sh" "${BABY_X_MICROVM_ASSET_ROOT:-/var/lib/baby-x/root-platform/microvm/assets}" || return
    cp "$source/ops/systemd/baby-x-root-provider.service" "$source/ops/systemd/baby-x-root-provider.socket" /etc/systemd/system/ || return
  else
    systemctl stop baby-x-root-provider.service baby-x-root-provider.socket 2>/dev/null || true
    systemctl disable baby-x-root-provider.socket 2>/dev/null || true
    rm -f /etc/systemd/system/baby-x-root-provider.service /etc/systemd/system/baby-x-root-provider.socket
  fi
  cp "$source/ops/tmpfiles/baby-x.conf" /etc/tmpfiles.d/ || return
  systemd-tmpfiles --create /etc/tmpfiles.d/baby-x.conf || return
  systemctl daemon-reload || return
}

restart_units() {
  [[ ${BABY_X_INSTALL_UNITS:-0} == 1 ]] || return 0
  systemctl stop baby-x.service baby-x-root-provider.service 2>/dev/null || true
  systemctl reset-failed baby-x.service baby-x-gateway.service baby-x-root-provider.service 2>/dev/null || true
  systemctl enable baby-x.socket baby-x-gateway.service >/dev/null || return
  systemctl restart baby-x.socket baby-x-gateway.service || return
  if [[ -f /etc/systemd/system/baby-x-root-provider.socket ]]; then
    systemctl enable baby-x-root-provider.socket >/dev/null || return
    systemctl restart baby-x-root-provider.socket || return
  fi
}

activate_and_verify() {
  local target=$1
  atomic_link "$target" "$root/current" || return
  install_units_from "$target" || return
  restart_units || return
  BABY_X_INSTALL_UNITS=${BABY_X_INSTALL_UNITS:-0} "$target/scripts/verify-local.sh" || return
}

current=$(readlink -f "$root/current")
previous=$(readlink -f "$root/previous")
[[ -n "$current" && -n "$previous" && "$current" != "$previous" ]] || { echo 'distinct current and previous releases required' >&2; exit 1; }
[[ -d "$current" && -d "$previous" ]] || { echo 'current and previous release directories must exist' >&2; exit 1; }

if activate_and_verify "$previous"; then
  rollback_status=0
else
  rollback_status=$?
fi

if (( rollback_status == 0 )); then
  if atomic_link "$current" "$root/previous"; then
    exit 0
  fi
  rollback_status=1
  echo 'rollback target verified but recording the former current release failed; restoring it' >&2
else
  echo "rollback activation failed for $previous; restoring $current" >&2
fi

if activate_and_verify "$current"; then
  atomic_link "$previous" "$root/previous" || true
  echo "rollback attempt failed safely; restored $current" >&2
  exit "$rollback_status"
fi

echo "rollback attempt failed and restoration verification also failed for $current" >&2
exit 2
