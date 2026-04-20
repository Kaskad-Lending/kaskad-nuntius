/**
 * RelayLoop — FSM per asset. Reads cached signed prices, verifies
 * signatures locally, compares with on-chain state, and submits
 * via TxQueue when fresh.
 */

import { ethers } from "ethers";
import { KaskadPriceOracle } from "./types/contracts/KaskadPriceOracle.js";
import { TxQueue, TxResult, TxIntent } from "./tx-queue.js";
import { PricePoller } from "./poll.js";
import {
  AssetRelay,
  AssetState,
  SignedPriceUpdate,
} from "./types.js";

/** Minimum gap (seconds) between relay attempts for one asset.
 *  Must exceed contract's MIN_UPDATE_DELAY (5s). */
const MIN_RELAY_GAP = 8;

/** Minimum number of sources required (matches enclave Data Quorum). */
const MIN_SOURCES = 3;

export class Relayer {
  private assets: Map<string, AssetRelay> = new Map();
  private oracle: KaskadPriceOracle;
  private txQueue: TxQueue;
  private poller: PricePoller;
  /** Grow-only cache of valid signer addresses (lowercase). Bootstrapped
   *  from past `EnclaveRegistered` events and kept current via a live
   *  subscription. The on-chain set is also grow-only so we only ever
   *  `add` — never remove. A cache miss falls back to a direct
   *  `validSigner(addr)` RPC call. */
  private validSigners: Set<string> = new Set();
  private signerSubscribed = false;

  constructor(
    oracle: KaskadPriceOracle,
    txQueue: TxQueue,
    poller: PricePoller,
  ) {
    this.oracle = oracle;
    this.txQueue = txQueue;
    this.poller = poller;

    this.txQueue.setCallback(this.onTxComplete.bind(this));
  }

  /** Run one poll + relay cycle. Called from the main loop. */
  async tick() {
    await this.ensureSignerSubscription();

    // 1. Poll fresh prices
    const prices = await this.poller.fetchPrices();

    // 2. Upsert into local cache
    for (const p of prices) {
      this.upsertPrice(p);
    }

    // 3. For each tracked asset, try to relay
    for (const [, asset] of this.assets) {
      await this.tryRelay(asset);
    }
  }

  private upsertPrice(p: SignedPriceUpdate) {
    const existing = this.assets.get(p.asset_symbol);
    if (existing) {
      if (p.timestamp > (existing.latest?.timestamp ?? 0)) {
        existing.latest = p;
        existing.assetId = p.asset_id;
        if (existing.state === AssetState.IDLE) {
          existing.state = AssetState.FRESH;
        }
      }
    } else {
      this.assets.set(p.asset_symbol, {
        symbol: p.asset_symbol,
        assetId: p.asset_id,
        state: AssetState.FRESH,
        latest: p,
        onchainTimestamp: 0n,
        lastRelayedAt: 0,
      });
    }
  }

  private async tryRelay(asset: AssetRelay) {
    // Don't submit if already in flight
    if (asset.state === AssetState.SUBMITTING) return;
    if (!asset.latest) return;

    // Rate limit ourselves
    const now = Math.floor(Date.now() / 1000);
    if (now - asset.lastRelayedAt < MIN_RELAY_GAP) return;

    // M-4: Enforce Data Quorum locally (save gas on revert)
    if (asset.latest.num_sources < MIN_SOURCES) {
      console.warn(
        `[Relay] ${asset.symbol}: num_sources=${asset.latest.num_sources} < ${MIN_SOURCES}, skipping`
      );
      asset.state = AssetState.IDLE;
      return;
    }

    // Read on-chain state
    try {
      const [, onchainTs] = await this.oracle.getLatestPrice(asset.assetId);
      asset.onchainTimestamp = onchainTs;
    } catch {
      // First price for this asset — no on-chain data yet
      asset.onchainTimestamp = 0n;
    }

    const signedTs = BigInt(asset.latest.timestamp);

    // Skip if on-chain is already at or ahead of signed timestamp
    if (signedTs <= asset.onchainTimestamp) {
      asset.state = AssetState.IDLE;
      return;
    }

    // H-2: Verify EIP-191 signature locally before paying gas
    if (!(await this.verifySignature(asset.latest))) {
      console.error(
        `[Relay] ${asset.symbol}: local signature verification failed, skipping`
      );
      asset.state = AssetState.IDLE;
      return;
    }

    // M-3: Set SUBMITTING *and keep it* until TX callback fires
    asset.state = AssetState.SUBMITTING;

    const calldata = this.oracle.interface.encodeFunctionData("updatePrice", [
      asset.latest.asset_id,
      BigInt(asset.latest.price),
      signedTs,
      asset.latest.num_sources,
      asset.latest.sources_hash,
      asset.latest.signature,
    ]);

    const label = `updatePrice(${asset.symbol} ts=${asset.latest.timestamp})`;

    this.txQueue.push(
      await this.oracle.getAddress(),
      calldata,
      label
    );

    asset.lastRelayedAt = now;

    console.log(
      `[Relay] Queued ${asset.symbol}: price=${asset.latest.price_human} sources=${asset.latest.num_sources} ts=${asset.latest.timestamp}`
    );
  }

  /** H-2: Verify EIP-191 signature against the valid-signer set. Checks
   *  the local cache first; on miss, falls back to `validSigner(addr)`
   *  on-chain and admits the result into the cache. */
  private async verifySignature(update: SignedPriceUpdate): Promise<boolean> {
    try {
      // Reconstruct payload: abi.encodePacked(assetId, price, timestamp, numSources, sourcesHash)
      const payload = ethers.solidityPacked(
        ["bytes32", "uint256", "uint256", "uint8", "bytes32"],
        [
          update.asset_id,
          BigInt(update.price),
          BigInt(update.timestamp),
          update.num_sources,
          update.sources_hash,
        ]
      );

      const messageHash = ethers.keccak256(payload);

      // EIP-191: "\x19Ethereum Signed Message:\n32" + hash
      const ethHash = ethers.hashMessage(ethers.getBytes(messageHash));

      const recovered = ethers.recoverAddress(ethHash, update.signature).toLowerCase();

      if (this.validSigners.has(recovered)) return true;

      // Cache miss — confirm against chain. Either our event feed missed
      // a registration, or this is a forged signature.
      const ok = await this.oracle.validSigner(recovered);
      if (ok) {
        this.validSigners.add(recovered);
        console.log(`[Relay] Admitted signer ${recovered} via RPC fallback`);
        return true;
      }

      console.warn(`[Relay] Unknown signer recovered: ${recovered}`);
      return false;
    } catch (err: any) {
      console.error(`[Relay] Signature verification error: ${err.message}`);
      return false;
    }
  }

  /** Bootstrap the signer cache from past `EnclaveRegistered` events and
   *  subscribe to live ones. The on-chain signer set is grow-only, so we
   *  only ever add — an RPC outage that drops a future event is covered
   *  by the cache-miss fallback in `verifySignature`. */
  private async ensureSignerSubscription() {
    if (this.signerSubscribed) return;
    try {
      const filter = this.oracle.filters.EnclaveRegistered();

      // Replay all past events so we don't start with an empty cache.
      const past = await this.oracle.queryFilter(filter);
      for (const ev of past) {
        // ethers v6: typed event log; first arg is the `signer` address.
        const who = String(ev.args[0]).toLowerCase();
        this.validSigners.add(who);
      }
      console.log(
        `[Relay] Bootstrapped signer cache: ${this.validSigners.size} entry(ies)`
      );

      // Subscribe to future events.
      await this.oracle.on(filter, (signer: string) => {
        const lc = signer.toLowerCase();
        if (!this.validSigners.has(lc)) {
          this.validSigners.add(lc);
          console.log(`[Relay] EnclaveRegistered: added signer ${lc}`);
        }
      });
      this.signerSubscribed = true;
    } catch (err: any) {
      // Some RPCs (or ethers providers without log-subscription support)
      // throw here. The per-verify RPC fallback in `verifySignature`
      // keeps us correct, just less efficient.
      console.warn(
        `[Relay] EnclaveRegistered subscribe failed (${err?.message ?? err}); falling back to per-verify RPC check`
      );
      this.signerSubscribed = true; // don't spam retry
    }
  }

  /** M-3: Callback from TxQueue — transition asset back to IDLE. */
  private onTxComplete(intent: TxIntent, result: TxResult) {
    // Extract symbol from label: "updatePrice(ETH/USD ts=...)"
    const match = intent.label.match(/updatePrice\((\S+)/);
    if (!match) return;

    const symbol = match[1];
    const asset = this.assets.get(symbol);
    if (!asset) return;

    asset.state = AssetState.IDLE;

    if (result.status === "confirmed") {
      console.log(`[Relay] ${symbol}: TX confirmed (${result.hash})`);
    } else {
      console.warn(`[Relay] ${symbol}: TX ${result.status} — ${result.reason}`);
    }
  }
}
