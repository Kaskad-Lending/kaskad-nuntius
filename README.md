# Kaskad TEE Oracle

Trustless price oracle for the Kaskad lending protocol. Fetches prices from multiple CEX/DEX sources, aggregates them using a volume-weighted median with statistical outlier rejection, signs the result with an enclave-bound key, and pushes updates on-chain via deviation/heartbeat triggers.

Designed to run inside a Trusted Execution Environment (AWS Nitro Enclave or Intel TDX), providing cryptographic guarantees that the oracle software hasn't been tampered with and the signing key never leaves the enclave.

## Architecture

```
                                ┌─────────────────────┐
                                │   Kaskad Oracle      │
                                │   (Rust binary)      │
                                │                      │
   ┌──────────┐  HTTP/REST      │  ┌───────────────┐   │
   │ Binance  │◄────────────────┤  │   Sources     │   │
   │ OKX      │                 │  │   (5 CEX APIs)│   │
   │ Bybit    │                 │  └───────┬───────┘   │
   │ Coinbase │                 │          │           │
   │ CoinGecko│                 │          ▼           │
   └──────────┘                 │  ┌───────────────┐   │
                                │  │  Aggregator   │   │
                                │  │  - outliers   │   │
                                │  │  - w. median  │   │
                                │  └───────┬───────┘   │
                                │          │           │
                                │          ▼           │
                                │  ┌───────────────┐   │
                                │  │    Signer     │   │
                                │  │  (EIP-191)    │   │
   ┌──────────────────┐         │  └───────┬───────┘   │
   │  Galleon Testnet  │  TX    │          │           │
   │  ┌──────────────┐│◄───────┤  ┌───────▼───────┐   │
   │  │ KaskadPrice  ││        │  │  Publisher    │   │
   │  │ Oracle.sol   ││        │  │  (TODO)       │   │
   │  └──────────────┘│        │  └───────────────┘   │
   └──────────────────┘        └─────────────────────┘
```

In TEE mode the binary runs inside a Nitro Enclave. The enclave has no network — all I/O goes through a VSOCK proxy on the parent EC2 instance:

```
┌───── EC2 Instance ───────────────────────────┐
│                                               │
│  ┌───── Nitro Enclave ──────────────────┐    │
│  │                                       │    │
│  │  kaskad-oracle binary                 │    │
│  │  (no network, no disk, no SSH)        │    │
│  │                                       │    │
│  │  Key generated inside enclave         │    │
│  │  Attestation doc = PCR0..PCR8 hashes  │    │
│  │                                       │    │
│  └──────────┬────────────────────────────┘    │
│             │ VSOCK                           │
│  ┌──────────▼────────────────────────────┐    │
│  │  Proxy Service                         │    │
│  │  - forwards HTTP to CEX APIs           │    │
│  │  - forwards RPC to Galleon node        │    │
│  │  - submits signed TXs                  │    │
│  └────────────────────────────────────────┘    │
└───────────────────────────────────────────────┘
```

## Modules

### Sources (`src/sources/`)

Each source implements the `PriceSource` trait:

```rust
#[async_trait]
pub trait PriceSource: Send + Sync {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>>;
    fn name(&self) -> &'static str;
}
```

| Source | API | Assets |
|--------|-----|--------|
| Binance | `/api/v3/ticker/price` | ETH, BTC, KAS, USDC |
| OKX | `/api/v5/market/ticker` | ETH, BTC, KAS, USDC |
| Bybit | `/v5/market/tickers` | ETH, BTC, KAS |
| Coinbase | `/v2/prices/.../spot` | ETH, BTC |
| CoinGecko | `/api/v3/simple/price` | ETH, BTC, KAS, USDC |
| Ethereum JSON-RPC (`ethrpc_*`, 8 operators) | `eth_call` to Multicall3 (POST) | VUSD |

The `ethrpc_*` sources read the VUSD backing ratio `min(reserve / (totalSupply − amoSupply), 1)` from one Multicall3 `eth_call`. Addresses and calldata are compiled in; the only pair is `VUSD_NAV`. The eight operators share one poller: the first source asked each cycle starts one parallel round, and every result is handed out once.

All sources are fetched sequentially per asset. On error, the source is skipped and a warning is logged. Minimum 2 sources required to proceed.

### HTTP failures (`src/http_client.rs`)

Every failed request has one class, logged with its HTTP status, attempt count and duration:

| Class | Cause |
|-------|-------|
| `rate_limited` | HTTP 429 or 418 |
| `blocked` | HTTP 403 or 451 |
| `client_error` | any other 4xx |
| `server_error` | 5xx |
| `timeout` | the call deadline expired, or a connect attempt timed out |
| `network` | connect, TLS or proxy refusal; connection cut mid-response |
| `bad_response` | unexpected status, redirect loop, missing or bad `Date`, oversized or non-JSON body |
| `config` | invalid URL or host outside the allowlist; nothing sent |
| `cooling_down` | host paused; nothing sent |

The body preview in a non-2xx error (its first 200 bytes) keeps only printable ASCII and space, and so does the logged `error` field; every other char becomes `?`.

**Retry.** At most 2 attempts inside one deadline (GET 10 s; the VUSD JSON-RPC POST 4 s, shared by both attempts). Only `network`, HTTP 408/425/500/502/503/504 and a 429 whose `Retry-After` is ≤ 1 s are retried. The retry waits 250 ms (a 429 waits its `Retry-After`) and runs only if at least that wait plus 1 s is left before the deadline. A retry also needs the host's retry right: the first call to a host has it, and so does every call after one that ended in a 2xx the client accepted (`Date` present, body within the cap and JSON, a JSON-RPC `error` included). After any other outcome that reached the network, including an unaccepted 2xx, the next call gets one attempt. A `config` or `cooling_down` refusal sends nothing and leaves the right as it was.

**Host pauses.** After 451 a host gets no requests for 600 s, after 403 for 60 s, after 429/418 for its `Retry-After` capped at 120 s (30 s without one). Pauses use the monotonic clock and are per host; requests to a paused host fail at once as `cooling_down`, and the first success on the host ends its pause. CoinGecko keeps serving its last snapshot (at most 120 s old) while its refresh fails, so its pairs stay `ok` through a short pause.

### Diagnostics (`src/diagnostics.rs`, `host/oracle_diag.py`)

The enclave keeps bounded, in-memory diagnostics: per asset and source the last outcome, consecutive failures, success age and samples dropped as outliers; per asset the last skip reason, skip counts by reason, responders and outliers with their deviation; host pauses; the VUSD NAV operator outcomes; cycle durations; and the newest 256 events. They hold request outcomes and public prices only, never URLs past the host, keys, credentials or attestation bodies. The reply to the `get_diagnostics` VSOCK method is at most 256 KiB (oldest events are left out first).

Events mark changes of state, not repeats. `source_failed` is added when the pair's previous outcome was not a failure of the same class and HTTP status, and `source_recovered` on its first success after failures. `outlier_dropped` is added when the source was not an outlier the cycle before. `asset_skipped` is added when the previous cycle was not skipped for the same reason, and `asset_resumed` on the first sign after skips. The counters still count every repeat. A failure detail is cut to 120 chars, URLs keep only their host, and every char outside printable ASCII and space becomes `?`.

`get_diagnostics` is for operators on the host only: the public pull API (`host/pull_api.py`) never routes it, and `/diagnostics` is a 404. Read it with `python3 host/oracle_diag.py` (VSOCK) or `--tcp 127.0.0.1:5001` for a local run; `--json` prints the raw reply.

### Aggregator (`src/aggregator/`)

Pipeline: **outlier rejection → weighted median → fixed-point conversion**

**Outlier rejection** — Modified Z-score using MAD (Median Absolute Deviation):
1. Compute median of all prices
2. Compute MAD = median(|price - median|)
3. Reject any price where |price - median| > σ × 1.4826 × MAD
4. Default σ = 3.0

**Weighted median** — prices are weighted by 24h trading volume. If volume data is unavailable, all sources are weighted equally. This makes high-liquidity exchanges (Binance, OKX) have more influence than aggregators (CoinGecko).

**Fixed-point** — prices are converted to `uint256` with 8 decimals for on-chain storage: `$1234.56 → 123456000000`.

### Signer (`src/signer.rs`)

The `OracleSigner` trait abstracts signing:

```rust
pub trait OracleSigner: Send + Sync {
    fn sign_price_update(&self, asset_id, price, timestamp, num_sources, sources_hash)
        -> Result<(Vec<u8>, [u8; 20])>;
    fn address(&self) -> [u8; 20];
}
```

| Implementation | Key source | Use case |
|----------------|-----------|----------|
| `MockSigner` | env var or random | Local dev, tests |
| `EnclaveSigner` (planned) | TEE key manager | Production |

Signature payload matches what Solidity `ecrecover` expects:

```
payload = abi.encodePacked(assetId, price, timestamp, numSources, sourcesHash)
hash    = keccak256(payload)
signed  = sign(keccak256("\x19Ethereum Signed Message:\n32" + hash))
```

### Update Triggers (`src/main.rs`)

Price updates are pushed on-chain only when:

| Condition | ETH/BTC | KAS | USDC | IGRA |
|-----------|---------|-----|------|------|
| **Deviation** exceeds | 0.5% | 2.0% | 0.1% | always |
| **Heartbeat** (max silence) | 1 hour | 30 min | 24 hours | 24 hours |

This minimizes gas cost while keeping prices fresh — same model as Chainlink.

## Supported Assets

| Asset | Type | Sources | Notes |
|-------|------|---------|-------|
| ETH/USD | Major | 5 | High liquidity on all exchanges |
| BTC/USD | Major | 5 | — |
| KAS/USD | Exotic L1 | 2-3 | Bybit, CoinGecko; limited exchange support |
| USDC/USD | Stablecoin | 2-3 | Depeg detection via multi-source |
| IGRA/USD | Presale | — | Governance-set price (planned) |
| VUSD/USD | Backed stablecoin | 8 | On-chain backing ratio via Ethereum RPC, capped at 1.00; `min_sources` 3 |

## Quick Start

```bash
# Run oracle with test key (auto-generated)
cargo run

# Run with specific key
ORACLE_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 cargo run

# Run tests
cargo test                              # Rust unit tests
cd contracts && forge test -vvv         # Solidity tests (45 tests incl. E2E)

# Run relayer
cd relayer && cp .env.example .env      # fill in values
npm run dev

# E2E integration test (Anvil + real CEX APIs + relayer)
bash scripts/e2e_relayer.sh

# Verbose logging
RUST_LOG=debug cargo run
```

## Contracts

| Contract | Purpose |
|----------|---------|
| `KaskadPriceOracle` | Permissionless oracle. OZ ECDSA verification, circuit breaker (15% + 4h staleness bypass), rate limiter (5s), future timestamp cap (5 min) |
| `KaskadAggregatorV3` | Chainlink `IAggregatorV3` wrapper (one per asset) |
| `KaskadRouter` | Atomic price-update + Aave action. `borrowWithPrices`, `withdrawWithPrices`, `liquidateWithPrices`. Validates MAX_PRICE_AGE=60s |
| `NitroAttestationVerifier` | On-chain AWS Nitro attestation verification (Marlin NitroProver) |

## Relayer

Permissionless TypeScript service (`relayer/`). Polls oracle pull API, verifies EIP-191 signatures locally, submits `updatePrice()` via ethers.js. Anyone can run a relayer — contract verifies only the enclave signature.

Users can also push prices directly via `KaskadRouter` (pull oracle pattern) — frontend fetches signed price from enclave, bundles with Aave action in one TX.

## Deployments

### Galleon Testnet (Chain ID: 38836)

Full addresses in [`contracts/deployments/galleon.json`](contracts/deployments/galleon.json).

| Contract | Address |
|----------|---------|
| KaskadPriceOracle | `0x876a9d20eC033AA3b3DA43b742079eC16fB0C989` |
| ETH/USD Aggregator | `0xee25D927c926BcA73912f0B3b88B7274Df42ffd8` |
| BTC/USD Aggregator | `0x3A0d0e305f5cE7FE541A56f88c433DBABD2E8aB0` |
| USDC/USD Aggregator | `0xB7836b00Cb8a452b47315D720f16fEf4f6D25Ae8` |
| KAS/USD Aggregator | `0xc578C1E1CE67D5782e0D27C8b268bD1FBd4707f3` |
| KaskadRouter | `0xdA23732c1Ac6Ea18EE5Bc04A629b8CD1E9fEDe9C` |

Integrates with Kaskad lending protocol (`lending-onchain`). IGRA and KSKD stay on MockPriceOracle (governance/computed prices).

## Configuration

Environment variables (`.env` file supported):

| Variable | Default | Description |
|----------|---------|-------------|
| `ORACLE_PRIVATE_KEY` | random | Hex-encoded secp256k1 private key |
| `ENCLAVE_MODE` | unset | Enable EnclaveSigner + VSOCK bridge |
| `SINGLE_RUN` | unset | Exit after one oracle loop |
| `VSOCK_PORT` | 5001 | Pull API server port |
| `IGRA_PRICE` | 0.10 | Governance-set IGRA price |
| `RUST_LOG` | info | Tracing filter level |

## Roadmap

- [x] Multi-source price fetcher (8 CEX/DEX APIs)
- [x] Weighted median aggregation + MAD outlier rejection
- [x] EIP-191 compatible signer (MockSigner + EnclaveSigner)
- [x] Deviation/heartbeat update triggers
- [x] Smart contracts (KaskadPriceOracle, AggregatorV3, Router)
- [x] Permissionless relayer (TypeScript)
- [x] Pull API (VSOCK/TCP price server)
- [x] Security audit + fixes (OZ ECDSA, circuit breaker staleness, symbol validation)
- [x] Galleon testnet deployment
- [x] Aave V3 integration (KaskadRouter — atomic price+action)
- [x] Nitro Enclave attestation on-chain (real AWS Nitro COSE_Sign1 verification)
- [ ] ZKP aggregation proofs (Phase 3)

## License

Private. Kaskad project.
