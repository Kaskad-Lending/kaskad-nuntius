/** Environment-based configuration. */

function mustEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required env var: ${name}`);
  return value;
}

function optionalEnv(name: string, fallback: string): string {
  return process.env[name] || fallback;
}

export interface Config {
  /** TEE pull-API endpoints, one per region. Prices from all are merged;
   *  the freshest valid signature per asset wins. */
  oracleApiUrls: string[];
  /** RPC endpoint for the target chain. */
  rpcUrl: string;
  /** KaskadPriceOracle contract address. */
  oracleAddress: string;
  /** Private key for the gas-payer wallet (NOT the enclave signer). */
  privateKey: string;
  /** Seconds between pull-API polls. */
  pollInterval: number;
  /** Seconds between relay attempts per asset. */
  relayInterval: number;
}

/** Parse ORACLE_API_URLS (comma-separated). Falls back to the legacy
 *  single-endpoint ORACLE_API_URL var. */
function loadOracleApiUrls(): string[] {
  const raw = process.env.ORACLE_API_URLS ?? process.env.ORACLE_API_URL;
  if (!raw) {
    throw new Error("Missing required env var: ORACLE_API_URLS");
  }
  const urls = raw
    .split(",")
    .map((u) => u.trim())
    .filter((u) => u.length > 0);
  if (urls.length === 0) {
    throw new Error("ORACLE_API_URLS must list at least one endpoint");
  }
  return urls;
}

export function loadConfig(): Config {
  return {
    oracleApiUrls: loadOracleApiUrls(),
    rpcUrl: mustEnv("RPC_URL"),
    oracleAddress: mustEnv("ORACLE_ADDRESS"),
    privateKey: mustEnv("PRIVATE_KEY"),
    pollInterval: Number(optionalEnv("POLL_INTERVAL", "10")),
    relayInterval: Number(optionalEnv("RELAY_INTERVAL", "15")),
  };
}
