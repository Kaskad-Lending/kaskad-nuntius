/**
 * PollLoop — fetches signed prices from the TEE oracle pull API.
 *
 * The pull API uses a length-prefixed JSON protocol over TCP/VSOCK.
 * Behind the ALB we talk plain HTTP (the ALB proxies to the enclave's
 * price_server via the host-side pull_api.py bridge).
 *
 * If the ALB exposes a REST wrapper, we use that. Otherwise we fall
 * back to raw TCP with the length-prefix protocol.
 */

import { SignedPriceUpdate, GetPricesResponse } from "./types.js";

export class PricePoller {
  private apiUrl: string;

  constructor(apiUrl: string) {
    // Normalize: strip trailing slash
    this.apiUrl = apiUrl.replace(/\/+$/, "");
  }

  /**
   * Fetch all signed prices from the oracle pull API.
   * Returns an empty array on transient errors (logged, not thrown).
   */
  async fetchPrices(): Promise<SignedPriceUpdate[]> {
    try {
      const resp = await fetch(`${this.apiUrl}/prices`, {
        signal: AbortSignal.timeout(10_000),
      });

      if (!resp.ok) {
        console.warn(`[Poll] HTTP ${resp.status} from oracle API`);
        return [];
      }

      const body: GetPricesResponse = await resp.json();

      if (body.error) {
        console.warn(`[Poll] API error: ${body.error}`);
        return [];
      }

      return body.prices ?? [];
    } catch (err: any) {
      console.warn(`[Poll] Fetch failed: ${err.message}`);
      return [];
    }
  }

  /** Health check. */
  async healthy(): Promise<boolean> {
    try {
      const resp = await fetch(`${this.apiUrl}/health`, {
        signal: AbortSignal.timeout(5_000),
      });
      return resp.ok;
    } catch {
      return false;
    }
  }
}
