/**
 * TEE Oracle Relayer — permissionless price relay service.
 *
 * Polls the TEE oracle pull API for signed prices, compares with
 * on-chain state, and submits updatePrice() transactions for any
 * asset whose signed timestamp is newer than on-chain.
 */

import { ethers } from "ethers";
import { KaskadPriceOracle__factory } from "./types/contracts/factories/KaskadPriceOracle__factory.js";
import { loadConfig } from "./config.js";
import { TxQueue } from "./tx-queue.js";
import { PricePoller } from "./poll.js";
import { Relayer } from "./relay.js";

async function main() {
  const config = loadConfig();

  console.log("[Relayer] Starting TEE Oracle Relayer...");
  console.log(`[Relayer] Oracle API: ${config.oracleApiUrl}`);
  console.log(`[Relayer] RPC:        ${config.rpcUrl}`);
  console.log(`[Relayer] Contract:   ${config.oracleAddress}`);
  console.log(
    `[Relayer] Poll=${config.pollInterval}s  Relay=${config.relayInterval}s`
  );

  // Provider + wallet
  const provider = new ethers.JsonRpcProvider(config.rpcUrl);
  const wallet = new ethers.Wallet(config.privateKey, provider);

  console.log(`[Relayer] Gas-payer:  ${wallet.address}`);

  // Check balance
  const balance = await provider.getBalance(wallet.address);
  console.log(
    `[Relayer] Balance:    ${ethers.formatEther(balance)} ETH`
  );
  if (balance === 0n) {
    console.warn("[Relayer] WARNING: Gas-payer wallet has zero balance!");
  }

  // Contract instance (read-only for getLatestPrice calls)
  const oracle = KaskadPriceOracle__factory.connect(
    config.oracleAddress,
    provider
  );

  // Verify contract is reachable and log bootstrap state.
  try {
    const count = await oracle.signerCount();
    console.log(`[Relayer] Registered enclave signer count: ${count}`);
    if (count === 0n) {
      console.warn(
        "[Relayer] WARNING: no enclave signer registered yet — updatePrice will revert until registerEnclave() is called."
      );
    }
  } catch (err: any) {
    console.error(`[Relayer] Cannot reach oracle contract: ${err.message}`);
    process.exit(1);
  }

  // Components
  const txQueue = new TxQueue(wallet);
  const poller = new PricePoller(config.oracleApiUrl);
  const relayer = new Relayer(oracle, txQueue, poller);

  // Health check
  const healthy = await poller.healthy();
  console.log(`[Relayer] Oracle API health: ${healthy ? "OK" : "UNREACHABLE"}`);

  // Main loop
  console.log("[Relayer] Entering main loop...");

  while (true) {
    try {
      await relayer.tick();
    } catch (err: any) {
      console.error(`[Relayer] Tick error: ${err.message}`);
    }

    await sleep(config.pollInterval * 1000);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

main().catch((err) => {
  console.error("[Relayer] Fatal:", err);
  process.exit(1);
});
