#!/usr/bin/env bash
set -euo pipefail

root=${BABY_X_INSTALL_ROOT:-/opt/baby-x}
node_bin=${BABY_X_NODE_BIN:-/opt/node-v24.18.0-linux-x64/bin/node}
health_url=${BABY_X_GATEWAY_HEALTH_URL:-http://127.0.0.1:2097/healthz}
asset_root=${BABY_X_MICROVM_ASSET_ROOT:-/var/lib/baby-x/root-platform/microvm/assets}
current=$(readlink -f "$root/current" 2>/dev/null || true)
printf 'current=%s\n' "$current"
[[ -n "$current" && -d "$current" ]]
cli="$current/runtime/cli/main.js"
[[ -x "$node_bin" && -f "$cli" ]]

if [[ ${BABY_X_INSTALL_UNITS:-0} == 1 ]]; then
  systemctl is-active --quiet baby-x.socket
  systemctl is-active --quiet baby-x-gateway.service
  if [[ -f /etc/systemd/system/baby-x-root-provider.socket ]]; then
    systemctl is-enabled --quiet baby-x-root-provider.socket
    systemctl is-active --quiet baby-x-root-provider.socket
    "$node_bin" --input-type=module - "$current" "$asset_root" <<'NODE'
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
const [current, assetRoot] = process.argv.slice(2);
const { MicrovmArtifactRegistry } = await import(pathToFileURL(join(current, 'runtime/root-platform/microvm/artifacts.js')).href);
const artifacts = new MicrovmArtifactRegistry(assetRoot).load();
process.stdout.write(`${JSON.stringify({ microvmAssets: { firecrackerVersion: artifacts.firecrackerVersion, firecrackerDigest: artifacts.firecrackerDigest, kernelDigest: artifacts.kernelDigest, rootImageDigest: artifacts.baseRootImageDigest, guestAgentDigest: artifacts.guestAgentDigest, resolvedManifestDigest: artifacts.resolvedManifestDigest } })}
`);
NODE
  fi
  "$node_bin" --input-type=module - "$cli" "$health_url" <<'NODE'
import { execFileSync } from 'node:child_process';

const [cli, healthUrl] = process.argv.slice(2);
const direct = JSON.parse(execFileSync(process.execPath, [cli, 'describe'], { encoding: 'utf8', timeout: 10_000 }));
let response;
let lastError;
for (let attempt = 0; attempt < 20; attempt += 1) {
  try {
    response = await fetch(healthUrl, { signal: AbortSignal.timeout(5_000) });
    if (response.ok) break;
    lastError = new Error(`gateway health returned HTTP ${response.status}`);
  } catch (error) {
    lastError = error;
  }
  await new Promise((resolve) => setTimeout(resolve, 250));
}
if (!response?.ok) throw lastError ?? new Error('gateway health did not become ready');
const gateway = await response.json();
if (gateway.ok !== true || gateway.product !== 'baby-x-gateway' || gateway.publicTool !== 'call_x') {
  throw new Error('gateway health identity mismatch');
}
if (gateway.runtime?.product !== direct.product) throw new Error('gateway runtime product mismatch');
if (gateway.runtime?.operationCount !== direct.operations?.length) throw new Error('gateway runtime operation count mismatch');
process.stdout.write(`${JSON.stringify({ gateway, direct: { product: direct.product, operationCatalogVersion: direct.operationCatalogVersion, operationCount: direct.operations.length } })}\n`);
NODE
  worker_state=$(systemctl is-active baby-x.service || true)
  [[ "$worker_state" == active ]]
  printf 'worker=%s\n' "$worker_state"
else
  "$node_bin" "$cli" health >/dev/null
fi
