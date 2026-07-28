export async function dynamicCatalog(client) {
  const { result } = await client.call('babyx.describe', {}, 'gateway-describe-catalog');
  const operations = Array.isArray(result.operations) ? result.operations : [];
  return {
    product: result.product,
    protocol: result.protocol,
    repository: result.repository ?? null,
    sourceCommit: result.sourceCommit ?? null,
    sourceTree: result.sourceTree ?? null,
    release: result.release ?? null,
    catalog: result.catalog ?? null,
    operationCatalogVersion: result.operationCatalogVersion ?? null,
    operationCatalogSha256: result.operationCatalogSha256 ?? null,
    operations,
  };
}
