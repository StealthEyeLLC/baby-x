#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ASSET_ROOT=${1:-${BABY_X_MICROVM_ASSET_ROOT:-$ROOT/.baby-x-test-assets}}
NODE=${NODE:-/opt/node-v24.18.0-linux-x64/bin/node}
FC_VERSION=v1.15.1
FC_ARCHIVE=firecracker-v1.15.1-x86_64.tgz
FC_SHA=d4a32ab2322d887ca1bc4a4e7afa9cc35393e6362dfc2b3becb389d362e4275a
KERNEL_NAME=vmlinux-6.1.155
KERNEL_SHA=e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2
FC_URL=https://github.com/firecracker-microvm/firecracker/releases/download/v1.15.1/firecracker-v1.15.1-x86_64.tgz
FC_SUM_URL=https://github.com/firecracker-microvm/firecracker/releases/download/v1.15.1/firecracker-v1.15.1-x86_64.tgz.sha256.txt
KERNEL_URL=https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155
[[ $(uname -m) == x86_64 ]] || { echo 'x86_64 is required' >&2; exit 1; }
for tool in curl tar sha256sum gcc strip mkfs.ext4; do command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }; done
[[ -x $NODE ]] || { echo 'Node.js 24.18.0 is required' >&2; exit 1; }
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/download" "$TMP/rootfs"/{sbin,etc,dev,proc,sys,run,tmp} "$ASSET_ROOT/bin" "$ASSET_ROOT/images"
rm -f "$ASSET_ROOT/resolved-manifest.json"
curl -fsSL --proto '=https' --tlsv1.2 --max-time 180 -o "$TMP/download/$FC_ARCHIVE" "$FC_URL"
curl -fsSL --proto '=https' --tlsv1.2 --max-time 60 -o "$TMP/download/$FC_ARCHIVE.sha256.txt" "$FC_SUM_URL"
[[ $(sha256sum "$TMP/download/$FC_ARCHIVE" | awk '{print $1}') == "$FC_SHA" ]] || { echo 'Firecracker archive digest mismatch' >&2; exit 1; }
[[ $(awk '{print $1}' "$TMP/download/$FC_ARCHIVE.sha256.txt") == "$FC_SHA" ]] || { echo 'official Firecracker checksum mismatch' >&2; exit 1; }
tar -xzf "$TMP/download/$FC_ARCHIVE" -C "$TMP"
FC_SOURCE="$TMP/release-v1.15.1-x86_64/firecracker-v1.15.1-x86_64"
JAILER_SOURCE="$TMP/release-v1.15.1-x86_64/jailer-v1.15.1-x86_64"
[[ -x $FC_SOURCE && -x $JAILER_SOURCE ]] || { echo 'Firecracker release archive is incomplete' >&2; exit 1; }
install -m 0555 "$FC_SOURCE" "$ASSET_ROOT/bin/firecracker-v1.15.1-x86_64"
install -m 0555 "$JAILER_SOURCE" "$ASSET_ROOT/bin/jailer-v1.15.1-x86_64"
curl -fsSL --proto '=https' --tlsv1.2 --max-time 180 -o "$ASSET_ROOT/images/$KERNEL_NAME" "$KERNEL_URL"
[[ $(sha256sum "$ASSET_ROOT/images/$KERNEL_NAME" | awk '{print $1}') == "$KERNEL_SHA" ]] || { echo 'kernel digest mismatch' >&2; exit 1; }
chmod 0444 "$ASSET_ROOT/images/$KERNEL_NAME"
AGENT_BUILD="$ROOT/runtime/native/microvm-guest-agent/build/baby-x-microvm-guest-agent"
mkdir -p "$(dirname "$AGENT_BUILD")"
gcc -static -O2 -pthread -Wall -Wextra -Werror -o "$AGENT_BUILD" "$ROOT/runtime/native/microvm-guest-agent/guest_agent.c"
strip "$AGENT_BUILD"
install -m 0555 "$AGENT_BUILD" "$ASSET_ROOT/bin/baby-x-microvm-guest-agent"
install -m 0555 "$AGENT_BUILD" "$TMP/rootfs/sbin/init"
truncate -s 64M "$ASSET_ROOT/images/baby-x-rootfs-v1.ext4"
mkfs.ext4 -q -F -d "$TMP/rootfs" -U 8b3baf52-4fcb-4c47-9cd1-c0e528d98301 -E lazy_itable_init=0,lazy_journal_init=0 "$ASSET_ROOT/images/baby-x-rootfs-v1.ext4"
chmod 0444 "$ASSET_ROOT/images/baby-x-rootfs-v1.ext4"
PROVIDER_MANIFEST="$ROOT/runtime/assets/microvm/firecracker-v1.15.1-x86_64.json"
ASSET_ROOT="$ASSET_ROOT" PROVIDER_MANIFEST="$PROVIDER_MANIFEST" "$NODE" --input-type=module <<'NODE'
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
const root=resolve(process.env.ASSET_ROOT);
const digest=(path)=>createHash('sha256').update(readFileSync(path)).digest('hex');
const canonicalize=(value)=>{ if(value===null||typeof value!=='object') return JSON.stringify(value); if(Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`; return `{${Object.keys(value).sort().map((key)=>`${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`; };
const providerManifest=resolve(process.env.PROVIDER_MANIFEST);
const unsigned={
  schemaVersion:'1.0.0',providerManifestDigest:digest(providerManifest),firecrackerVersion:'v1.15.1',
  firecrackerPath:join(root,'bin/firecracker-v1.15.1-x86_64'),firecrackerDigest:digest(join(root,'bin/firecracker-v1.15.1-x86_64')),
  jailerPath:join(root,'bin/jailer-v1.15.1-x86_64'),jailerDigest:digest(join(root,'bin/jailer-v1.15.1-x86_64')),
  kernelPath:join(root,'images/vmlinux-6.1.155'),kernelDigest:digest(join(root,'images/vmlinux-6.1.155')),kernelVersion:'6.1.155',
  baseRootImagePath:join(root,'images/baby-x-rootfs-v1.ext4'),baseRootImageDigest:digest(join(root,'images/baby-x-rootfs-v1.ext4')),
  guestAgentPath:join(root,'bin/baby-x-microvm-guest-agent'),guestAgentDigest:digest(join(root,'bin/baby-x-microvm-guest-agent')),
  guestAgentProtocol:'BABYX-GUEST/1.0.0',architecture:'x86_64',resolvedAt:new Date().toISOString(),
};
const resolvedManifestDigest=createHash('sha256').update(canonicalize(unsigned)).digest('hex');
writeFileSync(join(root,'resolved-manifest.json'),`${canonicalize({...unsigned,resolvedManifestDigest})}\n`,{mode:0o444});
console.log(JSON.stringify({...unsigned,resolvedManifestDigest}));
NODE
printf 'microVM assets provisioned at %s\n' "$ASSET_ROOT"
