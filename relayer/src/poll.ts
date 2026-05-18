/**
 * PollLoop — fetches signed prices from the TEE oracle pull API.
 *
 * Polls every configured regional endpoint and merges the results.
 * A region that errors contributes nothing; the others still return,
 * so a single-region outage never interrupts relaying. The relayer's
 * upsert keeps the freshest valid signature per asset.
 */

import { SignedPriceUpdate, GetPricesResponse } from "./types.js";

export class PricePoller {
  private apiUrls: string[];

  constructor(apiUrls: string[]) {
    // Normalize: strip trailing slashes.
    this.apiUrls = apiUrls.map((u) => u.replace(/\/+$/, ""));
  }

  /**
   * Fetch and merge all signed prices from every endpoint.
   * Returns an empty array if every endpoint fails (logged, not thrown).
   */
  async fetchPrices(): Promise<SignedPriceUpdate[]> {
    const perEndpoint = await Promise.all(
      this.apiUrls.map((url) => this.fetchFrom(url)),
    );
    return perEndpoint.flat();
  }

  private async fetchFrom(apiUrl: string): Promise<SignedPriceUpdate[]> {
    try {
      const resp = await fetch(`${apiUrl}/prices`, {
        signal: AbortSignal.timeout(10_000),
      });

      if (!resp.ok) {
        console.warn(`[Poll] HTTP ${resp.status} from ${apiUrl}`);
        return [];
      }

      const body: GetPricesResponse = await resp.json();

      if (body.error) {
        console.warn(`[Poll] API error from ${apiUrl}: ${body.error}`);
        return [];
      }

      return body.prices ?? [];
    } catch (err: any) {
      console.warn(`[Poll] Fetch failed from ${apiUrl}: ${err.message}`);
      return [];
    }
  }

  /** Healthy if at least one endpoint responds. */
  async healthy(): Promise<boolean> {
    const checks = await Promise.all(
      this.apiUrls.map((url) => this.healthyOne(url)),
    );
    return checks.some((ok) => ok);
  }

  private async healthyOne(apiUrl: string): Promise<boolean> {
    try {
      const resp = await fetch(`${apiUrl}/health`, {
        signal: AbortSignal.timeout(5_000),
      });
      return resp.ok;
    } catch {
      return false;
    }
  }
}
