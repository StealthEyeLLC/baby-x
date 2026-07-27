#!/usr/bin/env bash
set -euo pipefail
root=${BABY_X_INSTALL_ROOT:-/opt/baby-x}
printf 'current=%s\n' "$(readlink -f "$root/current" 2>/dev/null || true)"
if [[ ${BABY_X_INSTALL_UNITS:-0} == 1 ]]; then
  config_root=${BABY_X_CONFIG_ROOT:-/etc/baby-x}
  systemd_root=${BABY_X_SYSTEMD_ROOT:-/etc/systemd/system}
  : "${BABY_X_CREDENTIAL_GENERATION_ID:?BABY_X_CREDENTIAL_GENERATION_ID is required when verifying units}"
  [[ -f "$config_root/credential-generation.json" && ! -L "$config_root/credential-generation.json" ]]
  [[ -f "$config_root/proof-public.pem" && ! -L "$config_root/proof-public.pem" ]]
  [[ -f "$systemd_root/baby-x.service.d/20-service-credentials.conf" && ! -L "$systemd_root/baby-x.service.d/20-service-credentials.conf" ]]
  [[ -f "$systemd_root/baby-x-gateway.service.d/20-service-credentials.conf" && ! -L "$systemd_root/baby-x-gateway.service.d/20-service-credentials.conf" ]]
  node - "$config_root/credential-generation.json" "$BABY_X_CREDENTIAL_GENERATION_ID" <<'NODE'
const fs = require('node:fs');
const [path, expected] = process.argv.slice(2);
const value = JSON.parse(fs.readFileSync(path, 'utf8'));
if (value.generationId !== expected || value.rawPrivateMaterialIncluded !== false) throw new Error('installed credential generation readback mismatch');
NODE
  if [[ ${BABY_X_SKIP_SYSTEMD:-0} != 1 ]]; then systemctl is-active baby-x.socket baby-x.service baby-x-gateway.service; fi
fi
