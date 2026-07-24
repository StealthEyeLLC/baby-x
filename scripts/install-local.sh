#!/usr/bin/env bash
set -euo pipefail
: "${BABY_X_RELEASE_ID:?BABY_X_RELEASE_ID is required}"
root=${BABY_X_INSTALL_ROOT:-/opt/baby-x}
release="$root/releases/$BABY_X_RELEASE_ID"
[[ ! -e "$release" ]] || { echo "release already exists: $release" >&2; exit 1; }
mkdir -p "$root/releases"
cp -a dist "$release"
ln -sfn "$(readlink -f "$root/current" 2>/dev/null || true)" "$root/previous.tmp"
[[ ! -L "$root/previous.tmp" || -n "$(readlink "$root/previous.tmp")" ]] || rm -f "$root/previous.tmp"
mv -Tf "$root/previous.tmp" "$root/previous" 2>/dev/null || true
ln -sfn "$release" "$root/current.tmp"
mv -Tf "$root/current.tmp" "$root/current"
if [[ ${BABY_X_INSTALL_UNITS:-0} == 1 ]]; then cp ops/systemd/baby-x.service ops/systemd/baby-x.socket ops/systemd/baby-x-gateway.service /etc/systemd/system/; cp ops/tmpfiles/baby-x.conf /etc/tmpfiles.d/; systemd-tmpfiles --create /etc/tmpfiles.d/baby-x.conf; systemctl daemon-reload; systemctl restart baby-x.socket baby-x-gateway.service; fi
scripts/verify-local.sh
