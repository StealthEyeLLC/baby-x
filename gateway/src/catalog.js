export async function dynamicCatalog(client) {
  const { result } = await client.call('babyx.describe', {}, 'gateway-describe-catalog');
  const operations = Array.isArray(result.operations) ? result.operations : [];
  return { product: result.product, protocol: result.protocol, operations };
}
