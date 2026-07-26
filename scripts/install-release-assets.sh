#!/usr/bin/env bash
set -euo pipefail

: "${BABY_X_RELEASE_PATH:?BABY_X_RELEASE_PATH is required}"
libexec_root=${BABY_X_LIBEXEC_ROOT:-/usr/libexec}
install_owner=${BABY_X_INSTALL_OWNER:-root}
install_group=${BABY_X_INSTALL_GROUP:-root}
source_launcher="$BABY_X_RELEASE_PATH/libexec/babyx-credential-launcher"
target_launcher="$libexec_root/babyx-credential-launcher"

[[ -f "$source_launcher" && ! -L "$source_launcher" ]] || {
  echo "credential launcher is missing or not a regular packaged file: $source_launcher" >&2
  exit 1
}
[[ $(stat -c '%a' "$source_launcher") == 755 ]] || {
  echo "credential launcher packaged mode must be 0755" >&2
  exit 1
}
install -d -o "$install_owner" -g "$install_group" -m 0755 "$libexec_root"
install -o "$install_owner" -g "$install_group" -m 0755 "$source_launcher" "$target_launcher"
[[ -f "$target_launcher" && ! -L "$target_launcher" ]]
[[ $(stat -c '%a' "$target_launcher") == 755 ]]
