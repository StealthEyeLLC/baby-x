#!/usr/bin/env bash
set -euo pipefail
: "${BABY_X_RELEASE_ID:?BABY_X_RELEASE_ID is required}"
root=${BABY_X_INSTALL_ROOT:-/opt/baby-x}
release="$root/releases/$BABY_X_RELEASE_ID"
install_units=${BABY_X_INSTALL_UNITS:-0}

if [[ $install_units == 1 ]]; then
  : "${BABY_X_CREDENTIAL_GENERATION_ID:?BABY_X_CREDENTIAL_GENERATION_ID is required when installing units}"
  : "${BABY_X_CREDENTIAL_BINDING_ROOT:?BABY_X_CREDENTIAL_BINDING_ROOT is required when installing units}"
  binding_root=$(readlink -f -- "$BABY_X_CREDENTIAL_BINDING_ROOT")
  metadata_source="$binding_root/etc/baby-x/credential-generation.json"
  proof_public_source="$binding_root/etc/baby-x/proof-public.pem"
  controller_binding_source="$binding_root/etc/systemd/system/baby-x.service.d/20-service-credentials.conf"
  gateway_binding_source="$binding_root/etc/systemd/system/baby-x-gateway.service.d/20-service-credentials.conf"
  for source in "$metadata_source" "$proof_public_source" "$controller_binding_source" "$gateway_binding_source"; do
    [[ -f "$source" && ! -L "$source" ]] || { echo "verified credential binding asset is missing or unsafe: $source" >&2; exit 1; }
  done
  [[ $(stat -c '%a' "$metadata_source") == 640 ]]
  [[ $(stat -c '%a' "$proof_public_source") == 640 ]]
  [[ $(stat -c '%a' "$controller_binding_source") == 644 ]]
  [[ $(stat -c '%a' "$gateway_binding_source") == 644 ]]
  node - "$metadata_source" "$BABY_X_CREDENTIAL_GENERATION_ID" <<'NODE'
const fs = require('node:fs');
const [path, expectedGenerationId] = process.argv.slice(2);
const value = JSON.parse(fs.readFileSync(path, 'utf8'));
const digest = /^[a-f0-9]{64}$/u;
if (value.schemaVersion !== '1.0.0') throw new Error('unsupported credential generation metadata schema');
if (value.profileId !== 'baby-x.production-controller.v1') throw new Error('unsupported service credential profile');
if (value.generationId !== expectedGenerationId) throw new Error('credential generation identity mismatch');
if (!digest.test(String(value.compatibilityDigest)) || !digest.test(String(value.verificationDigest))) throw new Error('credential generation compatibility or verification digest is invalid');
if (value.rawPrivateMaterialIncluded !== false) throw new Error('credential generation metadata must exclude private material');
if (!Array.isArray(value.privateReferences) || value.privateReferences.length !== 2) throw new Error('credential generation must contain exactly two opaque private references');
if (Number(value.serviceIdentity?.observedUid) !== 997 || value.serviceIdentity?.accountName !== 'fix-mcp' || value.serviceIdentity?.reverseUidAccountName !== 'fix-mcp') throw new Error('fix-mcp UID 997 binding is not verified');
NODE
  grep -Fq 'LoadCredential=baby-x-proof-private:' "$controller_binding_source"
  grep -Fq 'BABY_X_PROOF_PRIVATE_KEY=%d/baby-x-proof-private' "$controller_binding_source"
  grep -Fq 'LoadCredential=baby-x-gateway-authority-private:' "$gateway_binding_source"
  grep -Fq 'BABY_X_GATEWAY_PRIVATE_KEY=%d/baby-x-gateway-authority-private' "$gateway_binding_source"
  grep -Fq 'BABY_X_PROOF_PUBLIC_KEY=/etc/baby-x/proof-public.pem' "$gateway_binding_source"
  grep -Fq 'BABY_X_GATEWAY_UID=997' "$gateway_binding_source"
  if grep -aEq -- '-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----' "$metadata_source" "$proof_public_source" "$controller_binding_source" "$gateway_binding_source"; then
    echo 'private credential bytes are forbidden in installation assets' >&2
    exit 1
  fi
fi

[[ ! -e "$release" ]] || { echo "release already exists: $release" >&2; exit 1; }
mkdir -p "$root/releases"
cp -a dist "$release"
ln -sfn "$(readlink -f "$root/current" 2>/dev/null || true)" "$root/previous.tmp"
[[ ! -L "$root/previous.tmp" || -n "$(readlink "$root/previous.tmp")" ]] || rm -f "$root/previous.tmp"
mv -Tf "$root/previous.tmp" "$root/previous" 2>/dev/null || true
ln -sfn "$release" "$root/current.tmp"
mv -Tf "$root/current.tmp" "$root/current"

if [[ $install_units == 1 ]]; then
  systemd_root=${BABY_X_SYSTEMD_ROOT:-/etc/systemd/system}
  config_root=${BABY_X_CONFIG_ROOT:-/etc/baby-x}
  tmpfiles_root=${BABY_X_TMPFILES_ROOT:-/etc/tmpfiles.d}
  libexec_root=${BABY_X_LIBEXEC_ROOT:-/usr/libexec}
  install_owner=${BABY_X_INSTALL_OWNER:-root}
  install_group=${BABY_X_INSTALL_GROUP:-root}
  BABY_X_RELEASE_PATH="$release" BABY_X_LIBEXEC_ROOT="$libexec_root" BABY_X_INSTALL_OWNER="$install_owner" BABY_X_INSTALL_GROUP="$install_group" scripts/install-release-assets.sh
  install -d -o "$install_owner" -g "$install_group" -m 0755 "$systemd_root" "$tmpfiles_root"
  install -d -o "$install_owner" -g "$install_group" -m 0750 "$config_root"
  install -o "$install_owner" -g "$install_group" -m 0644 ops/systemd/baby-x.service ops/systemd/baby-x.socket ops/systemd/baby-x-gateway.service "$systemd_root/"
  install -d -o "$install_owner" -g "$install_group" -m 0755 "$systemd_root/baby-x.service.d" "$systemd_root/baby-x-gateway.service.d"
  install -o "$install_owner" -g "$install_group" -m 0644 "$controller_binding_source" "$systemd_root/baby-x.service.d/20-service-credentials.conf"
  install -o "$install_owner" -g "$install_group" -m 0644 "$gateway_binding_source" "$systemd_root/baby-x-gateway.service.d/20-service-credentials.conf"
  install -o "$install_owner" -g "$install_group" -m 0640 "$metadata_source" "$config_root/credential-generation.json"
  install -o "$install_owner" -g "$install_group" -m 0640 "$proof_public_source" "$config_root/proof-public.pem"
  install -o "$install_owner" -g "$install_group" -m 0644 ops/tmpfiles/baby-x.conf "$tmpfiles_root/baby-x.conf"
  cmp -s "$metadata_source" "$config_root/credential-generation.json"
  cmp -s "$proof_public_source" "$config_root/proof-public.pem"
  cmp -s "$controller_binding_source" "$systemd_root/baby-x.service.d/20-service-credentials.conf"
  cmp -s "$gateway_binding_source" "$systemd_root/baby-x-gateway.service.d/20-service-credentials.conf"
  if [[ ${BABY_X_SKIP_SYSTEMD:-0} != 1 ]]; then
    systemd-tmpfiles --create "$tmpfiles_root/baby-x.conf"
    systemctl daemon-reload
    systemctl restart baby-x.socket baby-x-gateway.service
  fi
fi
scripts/verify-local.sh
