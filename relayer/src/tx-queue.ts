/**
 * Serial transaction queue with retry logic and proper nonce tracking.
 */

import { ethers } from "ethers";

const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 10_000;

export interface TxIntent {
  to: string;
  data: string;
  label: string;
  retries: number;
}

export type TxResult = { status: "confirmed"; hash: string } | { status: "reverted"; reason: string } | { status: "failed"; reason: string };
export type TxCallback = (intent: TxIntent, result: TxResult) => void;

export class TxQueue {
  private queue: TxIntent[] = [];
  private processing = false;
  private wallet: ethers.Wallet;
  private nonce: number | null = null;
  private onComplete: TxCallback | null = null;

  constructor(wallet: ethers.Wallet) {
    this.wallet = wallet;
  }

  /** Register a callback for TX completion (confirmed, reverted, or failed). */
  setCallback(cb: TxCallback) {
    this.onComplete = cb;
  }

  push(to: string, data: string, label: string) {
    this.queue.push({ to, data, label, retries: 0 });
    if (!this.processing) this.drain();
  }

  get pending(): number {
    return this.queue.length;
  }

  private async drain() {
    this.processing = true;

    while (this.queue.length > 0) {
      const intent = this.queue.shift()!;
      await this.send(intent);
    }

    this.processing = false;
  }

  /** Sync nonce from chain if we don't have one or after errors. */
  private async syncNonce(): Promise<number> {
    this.nonce = await this.wallet.getNonce("pending");
    return this.nonce;
  }

  private async send(intent: TxIntent) {
    try {
      // Use tracked nonce, sync from chain on first TX or after reset
      if (this.nonce === null) {
        await this.syncNonce();
      }

      const tx = await this.wallet.sendTransaction({
        to: intent.to,
        data: intent.data,
        nonce: this.nonce!,
        type: 0,
      });

      // Increment local nonce optimistically
      this.nonce!++;

      const receipt = await tx.wait();

      if (!receipt) {
        throw new Error("Receipt is null — TX dropped");
      }

      // ethers v6 receipts carry status: 0 on revert, 1 on success. The
      // old code treated any non-null receipt as confirmed, so a reverted
      // submission looked successful to the FSM and the stale on-chain
      // price persisted silently (audit M-3).
      if (receipt.status !== 1) {
        console.error(
          `[TxQueue] Reverted on-chain: ${receipt.hash} block=${receipt.blockNumber} [${intent.label}]`
        );
        this.onComplete?.(intent, {
          status: "reverted",
          reason: `on-chain revert in tx ${receipt.hash}`,
        });
        return;
      }

      console.log(
        `[TxQueue] Confirmed: ${receipt.hash} block=${receipt.blockNumber} [${intent.label}]`
      );

      this.onComplete?.(intent, { status: "confirmed", hash: receipt.hash });
    } catch (err: any) {
      const errMsg = err?.shortMessage || err?.message || String(err);

      // Don't retry known contract reverts — they will fail again
      if (this.isContractRevert(errMsg)) {
        console.error(
          `[TxQueue] Reverted [${intent.label}]: ${errMsg} — dropping`
        );
        this.onComplete?.(intent, { status: "reverted", reason: errMsg });
        return;
      }

      // Nonce error — resync from chain
      if (errMsg.includes("nonce") || errMsg.includes("replacement")) {
        console.warn(`[TxQueue] Nonce issue, resyncing: ${errMsg}`);
        this.nonce = null;
      }

      const attempt = intent.retries + 1;
      console.error(
        `[TxQueue] Failed [${intent.label}] attempt ${attempt}/${MAX_RETRIES}: ${errMsg}`
      );

      if (intent.retries < MAX_RETRIES - 1) {
        intent.retries++;
        await sleep(RETRY_DELAY_MS);
        this.queue.unshift(intent);
      } else {
        console.error(
          `[TxQueue] Permanently failed after ${MAX_RETRIES} attempts [${intent.label}]`
        );
        this.onComplete?.(intent, { status: "failed", reason: errMsg });
      }
    }
  }

  private isContractRevert(msg: string): boolean {
    return (
      msg.includes("StalePrice") ||
      msg.includes("UpdateTooFrequent") ||
      msg.includes("PriceChangeExceedsLimit") ||
      msg.includes("InvalidSignature") ||
      msg.includes("NoEnclaveRegistered") ||
      msg.includes("revert") ||
      msg.includes("CALL_EXCEPTION")
    );
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
