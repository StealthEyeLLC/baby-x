import { OPERATION_CATALOG_VERSION, OPERATION_DEFINITIONS } from './operations/definitions.ts';
import { BabyXRuntime, canonicalize, sha256, type JsonObject, type RuntimeOptions } from './core.ts';
import { ROOT_FABRIC_OPERATION_NAMES } from './root-fabric/service.ts';
import { loadVerifiedReleaseIdentity, releaseBoundRuntimeOptions, type VerifiedReleaseIdentity } from './release-identity.ts';

const REQUIRED_H = ['babyx.root.observation.start', 'babyx.root.observation.get', 'babyx.root.observation.record', 'babyx.root.observation.finalize'];
const REQUIRED_I = ['babyx.root.credential.lease', 'babyx.root.credential.deliver', 'babyx.root.credential.get', 'babyx.root.credential.list', 'babyx.root.credential.revoke', 'babyx.root.credential.clean'];
const REQUIRED_J = ['babyx.root.freeze.get', 'babyx.root.freeze.set', 'babyx.root.kill', 'babyx.root.reconcile'];

function catalogReadback(identity: VerifiedReleaseIdentity): JsonObject {
  const names = OPERATION_DEFINITIONS.map((entry) => entry.operation);
  const readback = {
    catalogVersion: OPERATION_CATALOG_VERSION,
    catalogSha256: sha256(canonicalize(OPERATION_DEFINITIONS)),
    totalOperations: names.length,
    rootOperations: names.filter((name) => name.startsWith('babyx.root.')).length,
    rootFabricDispatcherOperations: ROOT_FABRIC_OPERATION_NAMES.length,
    typedEffects: identity.typedEffects,
    duplicateOperations: names.length - new Set(names).size,
    hPresent: REQUIRED_H.every((name) => names.includes(name)),
    iPresent: REQUIRED_I.every((name) => names.includes(name)),
    jPresent: REQUIRED_J.every((name) => names.includes(name)),
  };
  if (
    readback.catalogVersion !== identity.catalogVersion
    || readback.catalogSha256 !== identity.catalogSha256
    || readback.totalOperations !== identity.totalOperations
    || readback.rootOperations !== identity.rootOperations
    || readback.rootFabricDispatcherOperations !== identity.rootFabricDispatcherOperations
    || readback.typedEffects !== identity.typedEffects
    || readback.duplicateOperations !== identity.duplicateOperations
    || !readback.hPresent
    || !readback.iPresent
    || !readback.jPresent
  ) throw new Error('runtime catalog does not match the immutable release contract');
  return readback;
}

export class ReleaseBoundBabyXRuntime extends BabyXRuntime {
  readonly releaseIdentity: VerifiedReleaseIdentity;

  constructor(options: RuntimeOptions = {}) {
    const identity = loadVerifiedReleaseIdentity({ required: true });
    if (identity === null) throw new Error('canonical release identity is required');
    super(releaseBoundRuntimeOptions(options));
    this.releaseIdentity = identity;
  }

  override describe(): JsonObject {
    const catalog = catalogReadback(this.releaseIdentity);
    return {
      ...super.describe(),
      repository: this.releaseIdentity.repository,
      sourceCommit: this.releaseIdentity.commit,
      sourceTree: this.releaseIdentity.tree,
      release: {
        releaseIdentity: this.releaseIdentity.releaseIdentity,
        branch: this.releaseIdentity.branch,
        commit: this.releaseIdentity.commit,
        tree: this.releaseIdentity.tree,
        parent: this.releaseIdentity.parent,
        manifestPath: this.releaseIdentity.releaseManifestPath,
        manifestSha256: this.releaseIdentity.releaseManifestSha256,
      },
      catalog,
    };
  }

  override health(): JsonObject {
    const catalog = catalogReadback(this.releaseIdentity);
    return {
      ...super.health(),
      ready: true,
      repository: this.releaseIdentity.repository,
      releaseIdentity: this.releaseIdentity.releaseIdentity,
      commit: this.releaseIdentity.commit,
      tree: this.releaseIdentity.tree,
      releaseManifestSha256: this.releaseIdentity.releaseManifestSha256,
      ...catalog,
    };
  }
}

export function createCanonicalRuntime(options: RuntimeOptions = {}): BabyXRuntime {
  return process.env.BABY_X_REQUIRE_RELEASE_IDENTITY === '1'
    ? new ReleaseBoundBabyXRuntime(options)
    : new BabyXRuntime(options);
}
