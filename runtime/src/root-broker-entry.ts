import { loadVerifiedReleaseIdentity } from './release-identity.ts';

const identity = loadVerifiedReleaseIdentity({ required: true });
if (identity === null) throw new Error('root broker release identity is required');

if (process.env.BABYX_RELEASE_COMMIT !== undefined || process.env.BABYX_RELEASE_TREE !== undefined) {
  throw new Error('root broker release identity must not be supplied by the startup environment');
}

process.env.BABYX_RELEASE_COMMIT = identity.commit;
process.env.BABYX_RELEASE_TREE = identity.tree;
process.env.BABYX_ROOT_BROKER_ID = `baby-x-root-broker:${identity.releaseIdentity}`;

await import('./root-broker-main.ts');
