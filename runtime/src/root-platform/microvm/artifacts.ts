import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import { MicrovmError } from './errors.ts';

export interface ResolvedMicrovmArtifacts extends JsonObject {
  schemaVersion: '1.0.0';
  providerManifestDigest: string;
  firecrackerVersion: 'v1.15.1';
  firecrackerPath: string;
  firecrackerDigest: string;
  jailerPath: string;
  jailerDigest: string;
  kernelPath: string;
  kernelDigest: string;
  kernelVersion: '6.1.155';
  baseRootImagePath: string;
  baseRootImageDigest: string;
  guestAgentPath: string;
  guestAgentDigest: string;
  guestAgentProtocol: 'BABYX-GUEST/1.0.0';
  architecture: 'x86_64';
  resolvedAt: string;
  resolvedManifestDigest: string;
}

const PINNED_ARCHIVE = 'd4a32ab2322d887ca1bc4a4e7afa9cc35393e6362dfc2b3becb389d362e4275a';
const PINNED_KERNEL = 'e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2';

function digestFile(path: string): string { return sha256(readFileSync(path)); }
function checkedPath(root: string, value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new MicrovmError('microvm_asset_integrity_failure', `${name} path is invalid`);
  const path = resolve(value);
  const normalizedRoot = `${realpathSync(resolve(root))}/`;
  if (!existsSync(path)) throw new MicrovmError('microvm_asset_unavailable', `${name} is unavailable`);
  const realPath = realpathSync(path);
  if (!realPath.startsWith(normalizedRoot)) throw new MicrovmError('microvm_asset_integrity_failure', `${name} escapes the provider asset root`);
  if (!statSync(realPath).isFile()) throw new MicrovmError('microvm_asset_unavailable', `${name} is unavailable`);
  return realPath;
}

export class MicrovmArtifactRegistry {
  readonly assetRoot: string;
  readonly providerManifestPath: string;
  readonly resolvedManifestPath: string;
  constructor(assetRoot = process.env.BABY_X_MICROVM_ASSET_ROOT ?? join(process.env.BABY_X_STATE_ROOT ?? '/var/lib/baby-x', 'root-platform', 'microvm', 'assets')) {
    this.assetRoot = resolve(assetRoot);
    this.providerManifestPath = join(process.cwd(), 'runtime', 'assets', 'microvm', 'firecracker-v1.15.1-x86_64.json');
    this.resolvedManifestPath = join(this.assetRoot, 'resolved-manifest.json');
  }
  load(): ResolvedMicrovmArtifacts {
    if (!existsSync(this.providerManifestPath) || !existsSync(this.resolvedManifestPath)) throw new MicrovmError('microvm_asset_unavailable', 'microVM provider assets have not been provisioned');
    const provider = JSON.parse(readFileSync(this.providerManifestPath,'utf8')) as Record<string,unknown>;
    if (provider.archiveSha256 !== PINNED_ARCHIVE || provider.kernelSha256 !== PINNED_KERNEL || provider.firecrackerVersion !== 'v1.15.1') throw new MicrovmError('microvm_asset_integrity_failure', 'pinned provider manifest identity mismatch');
    const resolved = JSON.parse(readFileSync(this.resolvedManifestPath,'utf8')) as unknown as ResolvedMicrovmArtifacts;
    const unsigned = { ...resolved } as Record<string,unknown>;
    delete unsigned.resolvedManifestDigest;
    if (resolved.resolvedManifestDigest !== sha256(canonicalize(unsigned as JsonObject))) throw new MicrovmError('microvm_asset_integrity_failure', 'resolved asset manifest digest mismatch');
    if (resolved.providerManifestDigest !== sha256(readFileSync(this.providerManifestPath))) throw new MicrovmError('microvm_asset_integrity_failure', 'provider manifest digest mismatch');
    if (resolved.firecrackerVersion !== 'v1.15.1' || resolved.kernelVersion !== '6.1.155' || resolved.architecture !== 'x86_64' || resolved.guestAgentProtocol !== 'BABYX-GUEST/1.0.0') throw new MicrovmError('microvm_asset_integrity_failure', 'resolved asset compatibility mismatch');
    const files: Array<[keyof ResolvedMicrovmArtifacts,keyof ResolvedMicrovmArtifacts,string]> = [
      ['firecrackerPath','firecrackerDigest','Firecracker binary'], ['jailerPath','jailerDigest','jailer binary'], ['kernelPath','kernelDigest','kernel image'], ['baseRootImagePath','baseRootImageDigest','base root image'], ['guestAgentPath','guestAgentDigest','guest agent'],
    ];
    for (const [pathKey,digestKey,name] of files) {
      const path = checkedPath(this.assetRoot,resolved[pathKey],name);
      if (digestFile(path) !== resolved[digestKey]) throw new MicrovmError('microvm_asset_integrity_failure', `${name} digest mismatch`);
    }
    if (resolved.kernelDigest !== PINNED_KERNEL) throw new MicrovmError('microvm_asset_integrity_failure', 'kernel does not match the pinned digest');
    return structuredClone(resolved);
  }
  probe(): JsonObject {
    try { const artifacts=this.load(); const kvm=existsSync('/dev/kvm'); const vsock=existsSync('/dev/vhost-vsock'); return { supportState: kvm && vsock ? 'SUPPORTED' : 'UNAVAILABLE', health: { ok: kvm && vsock, kvm, vsock, firecrackerVersion: artifacts.firecrackerVersion, firecrackerDigest: artifacts.firecrackerDigest, kernelDigest: artifacts.kernelDigest, rootImageDigest: artifacts.baseRootImageDigest, guestAgentDigest: artifacts.guestAgentDigest } }; }
    catch (error) { return { supportState: 'UNAVAILABLE', health: { ok: false, code: error instanceof MicrovmError ? error.code : 'microvm_asset_unavailable', message: error instanceof Error ? error.message : String(error) } }; }
  }
}
