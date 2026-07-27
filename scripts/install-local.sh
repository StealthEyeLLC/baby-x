#!/usr/bin/env bash
set -euo pipefail

: "${BABY_X_RELEASE_ID:?BABY_X_RELEASE_ID is required}"
root=${BABY_X_INSTALL_ROOT:-/opt/baby-x}
release="$root/releases/$BABY_X_RELEASE_ID"
[[ ! -e "$release" ]] || { echo "release already exists: $release" >&2; exit 1; }
mkdir -p "$root/releases"
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
  cp "$source/ops/tmpfiles/baby-x.conf" /etc/tmpfiles.d/ || return
  systemd-tmpfiles --create /etc/tmpfiles.d/baby-x.conf || return
  systemctl daemon-reload || return
}

restart_units() {
  [[ ${BABY_X_INSTALL_UNITS:-0} == 1 ]] || return 0
  systemctl stop baby-x.service 2>/dev/null || true
  systemctl reset-failed baby-x.service baby-x-gateway.service 2>/dev/null || true
  systemctl restart baby-x.socket baby-x-gateway.service || return
}

activate_and_verify() {
  local target=$1
  atomic_link "$target" "$root/current" || return
  install_units_from "$target" || return
  restart_units || return
  BABY_X_INSTALL_UNITS=${BABY_X_INSTALL_UNITS:-0} "$target/scripts/verify-local.sh" || return
}

old_current=$(readlink -f "$root/current" 2>/dev/null || true)
old_previous=$(readlink -f "$root/previous" 2>/dev/null || true)
cp -a dist "$release"

if activate_and_verify "$release"; then
  activation_status=0
else
  activation_status=$?
fi

if (( activation_status == 0 )); then
  if [[ -n "$old_current" ]]; then
    if atomic_link "$old_current" "$root/previous"; then
      exit 0
    fi
    activation_status=1
    echo 'activation verified but recording the rollback target failed; restoring prior release' >&2
  else
    rm -f "$root/previous" "$root/previous.tmp"
    exit 0
  fi
else
  echo "activation failed for $release; restoring prior release" >&2
fi

if [[ -n "$old_current" && -d "$old_current" ]]; then
  if activate_and_verify "$old_current"; then
    if [[ -n "$old_previous" ]]; then
      atomic_link "$old_previous" "$root/previous" || true
    else
      rm -f "$root/previous" "$root/previous.tmp"
    fi
    echo "automatic rollback restored $old_current" >&2
    exit "$activation_status"
  fi
  echo "activation failed and automatic rollback verification also failed for $old_current" >&2
  exit 2
fi

rm -f "$root/current" "$root/current.tmp"
echo 'activation failed and no prior release existed; current pointer was removed' >&2
exit "$activation_status"
