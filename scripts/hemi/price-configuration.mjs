import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import {
  Contract, Interface, JsonRpcProvider, getBytes, getCreateAddress,
  id, keccak256, solidityPacked, verifyMessage, formatEther, Transaction,
} from 'ethers';

const root = fileURLToPath(new URL('../..', import.meta.url));
const network = JSON.parse(await readFile(resolve(root, 'config/hemi-sepolia/network.json')));
const output = resolve(root, 'scratchpad/hemi-prices');
const provider = new JsonRpcProvider(network.rpc_urls[0], network.chain_id, {
  staticNetwork: true, batchMaxCount: 1, cacheTimeout: -1,
});
const registryAbi = [
  'function owner() view returns(address)',
  'function registeredAssetIds() view returns(bytes32[])',
  'function assetParams(bytes32) view returns(uint8,uint16,uint16)',
  'function latestPrices(bytes32) view returns(uint256,uint256,uint256,uint8,bytes32,uint80)',
  'function isValidSigner(address) view returns(bool)',
  'function registerAssets((bytes32 id,uint8 minSources,uint16 maxChangeBps,uint16 maxResumeChangeBps)[])',
  'function updatePrice(bytes32,uint256,uint256,uint8,bytes32,bytes)',
];
const registry = new Contract(network.oracle_registry, registryAbi, provider);
const aave = new Contract(network.aave_oracle, [
  'function getSourceOfAsset(address) view returns(address)',
  'function setAssetSources(address[],address[])',
], provider);
const pool = new Contract(network.pool, [
  'function getReservesList() view returns(address[])',
  'function getConfiguration(address) view returns(uint256)',
], provider);
const encodeJson = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2) + '\n';
const same = (a, b) => a.toLowerCase() === b.toLowerCase();
const checkedFetch = async path => {
  const response = await fetch(network.price_api + path, { signal: AbortSignal.timeout(15000) });
  assert(response.ok, `Price API returned HTTP ${response.status}`);
  return response.json();
};

try {
  assert.equal(Number(BigInt(await provider.send('eth_chainId', []))), 743111);
  const [snapshot, health, block, owner, registered, reserves] = await Promise.all([
    checkedFetch('/prices'), checkedFetch('/health'), provider.getBlock('latest'),
    registry.owner(), registry.registeredAssetIds(), pool.getReservesList(),
  ]);
  assert(same(owner, network.admin), 'Unexpected registry owner');
  assert(health.attestation_healthy === true, 'Price signer attestation is unavailable');
  assert(same(snapshot.signer, health.signer), 'Price API signer mismatch');
  assert(await registry.isValidSigner(snapshot.signer), 'API signer is not registered on Hemi');
  const configs = new Map();
  for (const assetId of registered) {
    const params = await registry.assetParams(assetId);
    configs.set(assetId.toLowerCase(), [assetId, ...params]);
  }
  const observations = [];
  const updates = [];
  for (const feed of network.feeds) {
    const assetId = id(feed.symbol);
    if (!configs.has(assetId)) configs.set(assetId, [assetId, feed.min_sources, feed.max_change_bps, feed.max_resume_change_bps]);
    const matches = snapshot.prices.filter(p => p.asset_symbol === feed.symbol);
    assert(matches.length <= 1, `Duplicate signed feed ${feed.symbol}`);
    const price = matches[0];
    const current = await registry.latestPrices(assetId);
    const observation = {
      symbol: feed.symbol, assetId, available: !!price,
      registered: registered.some(value => same(value, assetId)),
      lastPublishedAt: current[1],
    };
    if (price) {
      assert.equal(price.asset_id, assetId, 'Asset identifier mismatch');
      assert(BigInt(price.price) > 0n && price.num_sources >= feed.min_sources, 'Invalid price or source quorum');
      const now = Math.floor(Date.now() / 1000);
      assert(Number.isSafeInteger(price.timestamp) && price.timestamp >= now - 120 && price.timestamp <= now + 30, 'Stale or future observation');
      const digest = keccak256(solidityPacked(
        ['bytes32', 'uint256', 'uint256', 'uint8', 'bytes32'],
        [price.asset_id, price.price, price.timestamp, price.num_sources, price.sources_hash],
      ));
      assert(same(verifyMessage(getBytes(digest), price.signature), snapshot.signer), 'Invalid price signature');
      assert(same(price.signer, snapshot.signer), 'Signed price signer mismatch');
      Object.assign(observation, { price: price.price_human, sources: price.num_sources, signedAt: price.timestamp });
      updates.push(price);
    }
    observations.push(observation);
  }
  const tokens = [];
  for (const [symbol, token] of Object.entries(network.testnet_tokens)) {
    assert(reserves.some(asset => same(asset, token.address)), `${symbol} is not a listed reserve`);
    const erc20 = new Contract(token.address, ['function decimals() view returns(uint8)'], provider);
    const [decimals, source, configuration] = await Promise.all([
      erc20.decimals(), aave.getSourceOfAsset(token.address), pool.getConfiguration(token.address),
    ]);
    assert.equal(Number(decimals), token.decimals, `${symbol} decimals mismatch`);
    tokens.push({ symbol, ...token, source, configuration, paused: !!((configuration >> 60n) & 1n) });
  }
  const completeConfigs = [...configs.values()].sort((a, b) => a[0].localeCompare(b[0]));
  await mkdir(output, { recursive: true });
  await writeFile(resolve(output, 'signed-prices.json'), encodeJson({ capturedAt: new Date().toISOString(), signer: snapshot.signer, updates }));
  const result = {
    checkedAt: new Date().toISOString(), chainId: 743111, block: block.number,
    priceApi: network.price_api, signer: snapshot.signer,
    delivery: network.price_delivery, observations, tokens,
    registeredBefore: registered, completeConfigs,
    readyForAllTokens: observations.every(feed => feed.available),
    publicTransactionsSignedOrBroadcast: 0,
  };
  if (process.argv.includes('--prepare')) {
    const artifact = JSON.parse(await readFile(resolve(root, 'contracts/out/HemiPriceSources.sol/HemiPriceSources.json')));
    const nonce = await provider.getTransactionCount(owner, 'latest');
    assert.equal(nonce, await provider.getTransactionCount(owner, 'pending'), 'Owner has pending transactions');
    const bundle = getCreateAddress({ from: owner, nonce });
    const predicted = {
      btcAggregator: getCreateAddress({ from: bundle, nonce: 1 }),
      usdcAggregator: getCreateAddress({ from: bundle, nonce: 2 }),
      hbtcSource: getCreateAddress({ from: bundle, nonce: 3 }),
      hemiSource: getCreateAddress({ from: bundle, nonce: 4 }),
      usdcSource: getCreateAddress({ from: bundle, nonce: 5 }),
    };
    const constructorArgs = new Interface(artifact.abi).encodeDeploy([network.oracle_registry, network.existing_hemi_aggregator]);
    const selected = ['hBTC', 'HEMI', 'USDC.e'].map(symbol => tokens.find(token => token.symbol === symbol));
    assert(selected.every(token => token.source === '0x0000000000000000000000000000000000000000'), 'New reserve sources are already configured; inspect before preparing another deployment');
    const transactions = [
      { step: 1, action: 'Deploy two aggregators and three freshness adapters', nonce, data: artifact.bytecode.object + constructorArgs.slice(2), value: '0' },
      { step: 2, action: 'Register complete feed set and preserve existing parameters', nonce: nonce + 1, to: network.oracle_registry, data: registry.interface.encodeFunctionData('registerAssets', [completeConfigs]), value: '0' },
      { step: 3, action: 'Connect three paused reserves to Aave price sources', nonce: nonce + 2, to: network.aave_oracle, data: aave.interface.encodeFunctionData('setAssetSources', [selected.map(token => token.address), [predicted.hbtcSource, predicted.hemiSource, predicted.usdcSource]]), value: '0' },
    ];
    let totalGas = 0n;
    let totalL1Fee = 0n;
    const gasOracle = new Contract('0x420000000000000000000000000000000000000F', [
      'function getL1FeeUpperBound(uint256) view returns(uint256)',
    ], provider);
    for (const transaction of transactions) {
      const estimate = await provider.estimateGas({ from: owner, ...(transaction.to ? { to: transaction.to } : {}), data: transaction.data, value: 0n });
      transaction.estimatedGas = estimate;
      transaction.gasLimit = estimate * 12n / 10n + 10000n;
      const serialized = Transaction.from({
        chainId: 743111, type: 2, nonce: transaction.nonce,
        ...(transaction.to ? { to: transaction.to } : {}), data: transaction.data,
        value: 0n, gasLimit: transaction.gasLimit,
        maxFeePerGas: 3000000n, maxPriorityFeePerGas: 2500000n,
      }).unsignedSerialized;
      transaction.l1FeeUpperBoundWei = await gasOracle.getL1FeeUpperBound((serialized.length - 2) / 2 + 65);
      totalL1Fee += transaction.l1FeeUpperBoundWei;
      totalGas += transaction.gasLimit;
    }
    Object.assign(result, {
      status: 'prepared-not-signed', owner, bundle, predicted, transactions,
      maximumFeePerGasWei: '3000000', maximumExecutionFeeEth: formatEther(totalGas * 3000000n),
      maximumTotalFeeEth: formatEther(totalGas * 3000000n + totalL1Fee),
      publicTransactionFeeBudgetEth: '0.00005',
      unpauseIncluded: false, reserveRiskParametersChanged: false,
      sourceSha256: createHash('sha256').update(await readFile(resolve(root, 'contracts/src/HemiPriceSources.sol'))).digest('hex'),
      adapterSha256: createHash('sha256').update(await readFile(resolve(root, 'contracts/src/HemiNuntiusPriceAdapter.sol'))).digest('hex'),
      artifactSha256: createHash('sha256').update(await readFile(resolve(root, 'contracts/out/HemiPriceSources.sol/HemiPriceSources.json'))).digest('hex'),
    });
  }
  await writeFile(resolve(output, process.argv.includes('--prepare') ? 'configuration-plan.json' : 'inspection.json'), encodeJson(result));
  console.log(encodeJson({
    ...result, transactions: result.transactions?.map(({ data, ...transaction }) => ({ ...transaction, calldataBytes: (data.length - 2) / 2 })),
  }));
} finally {
  provider.destroy();
}
