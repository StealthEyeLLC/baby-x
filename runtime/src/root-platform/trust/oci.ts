import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { canonicalize, sha256, type JsonObject } from '../../core.ts';
import { RootTrustError } from './errors.ts';
import {
  OCI_INDEX_MEDIA_TYPE,
  OCI_MANIFEST_MEDIA_TYPE,
  SKILL_CONFIG_MEDIA_TYPE,
  SKILL_LAYER_MEDIA_TYPES,
  manifestHex,
  type BundleResolveRequest,
} from './schemas.ts';

interface OciDescriptor extends JsonObject {
  mediaType: string;
  digest: string;
  size: number;
  annotations?: JsonObject;
}
interface OciManifest extends JsonObject {
  schemaVersion: number;
  mediaType: string;
  config: OciDescriptor;
  layers: OciDescriptor[];
}
interface OciIndex extends JsonObject {
  schemaVersion: number;
  mediaType?: string;
  manifests: OciDescriptor[];
}

export interface ResolvedOciBundle extends JsonObject {
  sourceKind: 'LOCAL_OCI_LAYOUT' | 'REMOTE_REGISTRY';
  registry: string;
  repository: string;
  discoveryReferenceDigest: string;
  resolvedReference: string;
  manifestDigest: string;
  manifestMediaType: typeof OCI_MANIFEST_MEDIA_TYPE;
  configDigest: string;
  configMediaType: typeof SKILL_CONFIG_MEDIA_TYPE;
  layerDigests: string[];
  layerMediaTypes: string[];
  size: number;
  contentVerified: boolean;
  executionEligible: boolean;
  layoutPath: string | null;
  manifest: OciManifest;
}

function fail(code: string, message: string, details: JsonObject = {}): never { throw new RootTrustError(code, message, details); }
function parseObject(data: Buffer, field: string): Record<string, unknown> {
  try {
    const value = JSON.parse(data.toString('utf8')) as unknown;
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('not object');
    return value as Record<string, unknown>;
  } catch { fail('root_bundle_invalid_json', `${field} is not valid JSON`); }
}
function descriptor(value: unknown, field: string): OciDescriptor {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail('root_bundle_manifest_invalid', `${field} must be an object`);
  const input = value as Record<string, unknown>;
  const mediaType = String(input.mediaType ?? '');
  const digest = String(input.digest ?? '');
  const size = Number(input.size);
  if (!mediaType || !/^sha256:[a-f0-9]{64}$/u.test(digest) || !Number.isSafeInteger(size) || size < 0 || size > 1024 * 1024 * 1024) fail('root_bundle_manifest_invalid', `${field} descriptor is invalid`);
  const annotations = input.annotations;
  return { mediaType, digest, size, ...(annotations !== null && typeof annotations === 'object' && !Array.isArray(annotations) ? { annotations: annotations as JsonObject } : {}) };
}
function manifest(raw: Buffer): OciManifest {
  const input = parseObject(raw, 'OCI manifest');
  if (input.schemaVersion !== 2 || input.mediaType !== OCI_MANIFEST_MEDIA_TYPE) fail('root_bundle_media_type_rejected', 'OCI manifest media type or schema version is unsupported');
  const config = descriptor(input.config, 'manifest.config');
  if (config.mediaType !== SKILL_CONFIG_MEDIA_TYPE) fail('root_bundle_media_type_rejected', 'Skill config media type is unsupported');
  if (!Array.isArray(input.layers) || input.layers.length < 1 || input.layers.length > 128) fail('root_bundle_manifest_invalid', 'OCI manifest must contain a bounded non-empty layer array');
  const layers = input.layers.map((entry, index) => descriptor(entry, `manifest.layers[${index}]`));
  const supportedLayers = new Set<string>(SKILL_LAYER_MEDIA_TYPES);
  if (layers.some((entry) => !supportedLayers.has(entry.mediaType))) fail('root_bundle_media_type_rejected', 'one or more Skill layer media types are unsupported');
  return { schemaVersion: 2, mediaType: OCI_MANIFEST_MEDIA_TYPE, config, layers };
}
function index(raw: Buffer): OciIndex {
  const input = parseObject(raw, 'OCI index');
  if (input.schemaVersion !== 2) fail('root_bundle_manifest_invalid', 'OCI index schema version is unsupported');
  if (input.mediaType !== undefined && input.mediaType !== OCI_INDEX_MEDIA_TYPE) fail('root_bundle_media_type_rejected', 'OCI index media type is unsupported');
  if (!Array.isArray(input.manifests) || input.manifests.length > 256) fail('root_bundle_manifest_invalid', 'OCI index manifests must be a bounded array');
  return { schemaVersion: 2, ...(input.mediaType === undefined ? {} : { mediaType: OCI_INDEX_MEDIA_TYPE }), manifests: input.manifests.map((entry, entryIndex) => descriptor(entry, `index.manifests[${entryIndex}]`)) };
}
function blobPath(layoutPath: string, digest: string): string { return join(layoutPath, 'blobs', 'sha256', manifestHex(digest)); }
function verifiedRead(path: string, digest: string, size: number, maximum = 1024 * 1024 * 1024): Buffer {
  if (!existsSync(path)) fail('root_bundle_blob_missing', 'OCI blob is missing', { digest });
  const stat = statSync(path);
  if (!stat.isFile() || stat.size !== size || stat.size > maximum) fail('root_bundle_blob_size_mismatch', 'OCI blob size is invalid', { digest, declaredSize: size, observedSize: stat.size });
  const data = readFileSync(path);
  if (`sha256:${sha256(data)}` !== digest) fail('root_bundle_blob_digest_mismatch', 'OCI blob digest verification failed', { digest });
  return data;
}
function parseLocalReference(reference: string): { layoutPath: string; exactDigest: string | null; tag: string | null } {
  const raw = reference.slice('oci-layout:'.length);
  const exact = /^(.*)@sha256:([a-f0-9]{64})$/u.exec(raw);
  if (exact !== null) return { layoutPath: resolve(exact[1] as string), exactDigest: `sha256:${exact[2]}`, tag: null };
  const separator = raw.lastIndexOf(':');
  if (separator < 1) fail('root_bundle_reference_invalid', 'local OCI discovery reference must include a tag');
  return { layoutPath: resolve(raw.slice(0, separator)), exactDigest: null, tag: raw.slice(separator + 1) };
}
function parseRemoteReference(reference: string): { repository: string; exactDigest: string | null } {
  const raw = reference.slice('docker://'.length);
  const exact = /^(.*)@sha256:([a-f0-9]{64})$/u.exec(raw);
  if (exact !== null) return { repository: exact[1] as string, exactDigest: `sha256:${exact[2]}` };
  return { repository: raw, exactDigest: null };
}
function boundedSkopeo(args: string[]): string {
  const result = spawnSync('/usr/bin/skopeo', args, { encoding: 'utf8', timeout: 30_000, maxBuffer: 16 * 1024 * 1024 });
  if (result.status !== 0) fail('root_bundle_registry_failure', 'skopeo registry operation failed', { status: result.status, stderrDigest: sha256(result.stderr ?? '') });
  return result.stdout;
}
function repositoryParts(repository: string): { registry: string; repository: string } {
  const slash = repository.indexOf('/');
  if (slash < 1) return { registry: 'docker.io', repository };
  return { registry: repository.slice(0, slash), repository: repository.slice(slash + 1) };
}

export class OciSkillResolver {
  constructor(private readonly cacheRoot: string) { mkdirSync(cacheRoot, { recursive: true, mode: 0o700 }); }

  resolve(request: BundleResolveRequest): ResolvedOciBundle {
    return request.reference.startsWith('oci-layout:') ? this.resolveLocal(request) : this.resolveRemote(request);
  }

  cache(bundle: ResolvedOciBundle): { cachePath: string; cacheDigest: string; contentVerified: true } {
    if (!bundle.executionEligible) fail('root_bundle_mutable_reference_rejected', 'discovery-only bundles cannot become execution cache identities');
    const destination = join(this.cacheRoot, manifestHex(bundle.manifestDigest));
    if (existsSync(destination)) {
      const resolved = this.resolve({ reference: `oci-layout:${destination}@${bundle.manifestDigest}`, expectedManifestDigest: bundle.manifestDigest, discoveryOnly: false });
      return { cachePath: destination, cacheDigest: sha256(canonicalize(resolved)), contentVerified: true };
    }
    const temporary = `${destination}.tmp-${randomUUID()}`;
    rmSync(temporary, { recursive: true, force: true });
    try {
      if (bundle.sourceKind === 'LOCAL_OCI_LAYOUT') {
        if (bundle.layoutPath === null) fail('root_bundle_cache_failure', 'local OCI bundle has no layout path');
        cpSync(bundle.layoutPath, temporary, { recursive: true, force: false, errorOnExist: true });
      } else {
        mkdirSync(dirname(temporary), { recursive: true, mode: 0o700 });
        boundedSkopeo(['copy', '--all=false', bundle.resolvedReference, `oci:${temporary}:bundle`]);
      }
      const verified = this.resolve({ reference: `oci-layout:${temporary}@${bundle.manifestDigest}`, expectedManifestDigest: bundle.manifestDigest, discoveryOnly: false });
      if (!verified.contentVerified) fail('root_bundle_cache_failure', 'cached OCI content was not fully verified');
      renameSync(temporary, destination);
      return { cachePath: destination, cacheDigest: sha256(canonicalize(verified)), contentVerified: true };
    } catch (error) {
      rmSync(temporary, { recursive: true, force: true });
      throw error;
    }
  }

  private resolveLocal(request: BundleResolveRequest): ResolvedOciBundle {
    const parsed = parseLocalReference(request.reference);
    const layoutMarker = join(parsed.layoutPath, 'oci-layout');
    const indexPath = join(parsed.layoutPath, 'index.json');
    if (!existsSync(layoutMarker) || !existsSync(indexPath)) fail('root_bundle_layout_invalid', 'OCI layout marker or index is missing');
    const layout = parseObject(readFileSync(layoutMarker), 'oci-layout marker');
    if (layout.imageLayoutVersion !== '1.0.0') fail('root_bundle_layout_invalid', 'OCI layout version is unsupported');
    const parsedIndex = index(readFileSync(indexPath));
    let selected: OciDescriptor | undefined;
    if (parsed.exactDigest !== null) selected = parsedIndex.manifests.find((entry) => entry.digest === parsed.exactDigest);
    else selected = parsedIndex.manifests.find((entry) => entry.annotations?.['org.opencontainers.image.ref.name'] === parsed.tag);
    if (selected === undefined) fail('root_bundle_not_found', 'OCI manifest descriptor was not found in the layout index');
    if (request.expectedManifestDigest !== null && selected.digest !== request.expectedManifestDigest) fail('root_bundle_digest_mismatch', 'resolved OCI manifest does not match expectedManifestDigest');
    const rawManifest = verifiedRead(blobPath(parsed.layoutPath, selected.digest), selected.digest, selected.size, 16 * 1024 * 1024);
    const parsedManifest = manifest(rawManifest);
    verifiedRead(blobPath(parsed.layoutPath, parsedManifest.config.digest), parsedManifest.config.digest, parsedManifest.config.size, 16 * 1024 * 1024);
    for (const layer of parsedManifest.layers) verifiedRead(blobPath(parsed.layoutPath, layer.digest), layer.digest, layer.size);
    const exact = parsed.exactDigest !== null;
    return {
      sourceKind: 'LOCAL_OCI_LAYOUT',
      registry: 'local',
      repository: basename(parsed.layoutPath),
      discoveryReferenceDigest: sha256(request.reference),
      resolvedReference: `oci-layout:${parsed.layoutPath}@${selected.digest}`,
      manifestDigest: selected.digest,
      manifestMediaType: OCI_MANIFEST_MEDIA_TYPE,
      configDigest: parsedManifest.config.digest,
      configMediaType: SKILL_CONFIG_MEDIA_TYPE,
      layerDigests: parsedManifest.layers.map((entry) => entry.digest),
      layerMediaTypes: parsedManifest.layers.map((entry) => entry.mediaType),
      size: selected.size + parsedManifest.config.size + parsedManifest.layers.reduce((sum, layer) => sum + layer.size, 0),
      contentVerified: true,
      executionEligible: exact && !request.discoveryOnly,
      layoutPath: parsed.layoutPath,
      manifest: parsedManifest,
    };
  }

  private resolveRemote(request: BundleResolveRequest): ResolvedOciBundle {
    if (!existsSync('/usr/bin/skopeo')) fail('root_bundle_provider_unavailable', 'skopeo is unavailable');
    const parsed = parseRemoteReference(request.reference);
    let digest = parsed.exactDigest;
    if (digest === null) {
      const output = boundedSkopeo(['inspect', '--format', '{{.Digest}}', request.reference]).trim();
      if (!/^sha256:[a-f0-9]{64}$/u.test(output)) fail('root_bundle_registry_failure', 'registry did not return a valid immutable digest');
      digest = output;
    }
    if (request.expectedManifestDigest !== null && digest !== request.expectedManifestDigest) fail('root_bundle_digest_mismatch', 'resolved registry digest does not match expectedManifestDigest');
    const exactReference = `docker://${parsed.repository}@${digest}`;
    const raw = Buffer.from(boundedSkopeo(['inspect', '--raw', exactReference]), 'utf8');
    if (`sha256:${sha256(raw)}` !== digest) fail('root_bundle_digest_mismatch', 'registry manifest bytes do not match the resolved digest');
    const parsedManifest = manifest(raw);
    const parts = repositoryParts(parsed.repository);
    return {
      sourceKind: 'REMOTE_REGISTRY',
      registry: parts.registry,
      repository: parts.repository,
      discoveryReferenceDigest: sha256(request.reference),
      resolvedReference: exactReference,
      manifestDigest: digest,
      manifestMediaType: OCI_MANIFEST_MEDIA_TYPE,
      configDigest: parsedManifest.config.digest,
      configMediaType: SKILL_CONFIG_MEDIA_TYPE,
      layerDigests: parsedManifest.layers.map((entry) => entry.digest),
      layerMediaTypes: parsedManifest.layers.map((entry) => entry.mediaType),
      size: raw.length + parsedManifest.config.size + parsedManifest.layers.reduce((sum, layer) => sum + layer.size, 0),
      contentVerified: false,
      executionEligible: parsed.exactDigest !== null && !request.discoveryOnly,
      layoutPath: null,
      manifest: parsedManifest,
    };
  }
}

export function writeOciLayoutIndex(layoutPath: string, descriptorValue: OciDescriptor, tag = 'bundle'): void {
  mkdirSync(join(layoutPath, 'blobs', 'sha256'), { recursive: true, mode: 0o700 });
  writeFileSync(join(layoutPath, 'oci-layout'), `${JSON.stringify({ imageLayoutVersion: '1.0.0' })}\n`, { mode: 0o600 });
  writeFileSync(join(layoutPath, 'index.json'), `${JSON.stringify({ schemaVersion: 2, mediaType: OCI_INDEX_MEDIA_TYPE, manifests: [{ ...descriptorValue, annotations: { 'org.opencontainers.image.ref.name': tag } }] })}\n`, { mode: 0o600 });
}
