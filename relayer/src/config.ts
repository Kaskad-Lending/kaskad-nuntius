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
  /** Public HTTPS endpoint serving the TEE pull API (https://oracle.kaskad.live) */
  oracleApiUrl: string;
  /** RPC endpoint for Galleon / target chain */
  rpcUrl: string;
  /** KaskadPriceOracle contract address */
  oracleAddress: string;
  /** Private key for gas-payer wallet (NOT the enclave signer) */
  privateKey: string;
  /** Seconds between pull API polls */
  pollInterval: number;
  /** Seconds between relay attempts per asset */
  relayInterval: number;
}

export function loadConfig(): Config {
  return {
    oracleApiUrl: mustEnv("ORACLE_API_URL"),
    rpcUrl: mustEnv("RPC_URL"),
    oracleAddress: mustEnv("ORACLE_ADDRESS"),
    privateKey: mustEnv("PRIVATE_KEY"),
    pollInterval: Number(optionalEnv("POLL_INTERVAL", "10")),
    relayInterval: Number(optionalEnv("RELAY_INTERVAL", "15")),
  };
}
