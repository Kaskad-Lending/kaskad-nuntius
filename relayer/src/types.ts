/** Types matching the TEE oracle pull API responses. */

/** Single signed price update from the enclave pull API. */
export interface SignedPriceUpdate {
  asset_id: string;
  asset_symbol: string;
  price: string;
  price_human: string;
  timestamp: number;
  num_sources: number;
  sources_hash: string;
  signature: string;
  signer: string;
}

/** Pull API response for get_prices. */
export interface GetPricesResponse {
  prices: SignedPriceUpdate[] | null;
  error?: string;
  signer?: string;
  num_assets?: number;
}

/** Pull API response for health. */
export interface HealthResponse {
  status?: string;
  signer?: string;
  num_assets?: number;
  error?: string;
}

/** FSM state for a single asset relay. */
export enum AssetState {
  /** Waiting for next poll cycle */
  IDLE = "IDLE",
  /** Fresh signed price available, timestamp > on-chain */
  FRESH = "FRESH",
  /** TX submitted, waiting for confirmation */
  SUBMITTING = "SUBMITTING",
}

/** Per-asset relay state tracked in memory. */
export interface AssetRelay {
  symbol: string;
  assetId: string;
  state: AssetState;
  /** Latest signed update from pull API */
  latest: SignedPriceUpdate | null;
  /** Last on-chain timestamp we observed */
  onchainTimestamp: bigint;
  /** Last successful relay timestamp */
  lastRelayedAt: number;
}
