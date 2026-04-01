# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kaskad TEE Oracle — a trustless price oracle for the Kaskad lending protocol. Fetches prices from 8 CEX/DEX sources, aggregates via volume-weighted median with MAD outlier rejection, signs with an enclave-bound ECDSA key (EIP-191), and exposes signed prices via a VSOCK pull API. Runs inside AWS Nitro Enclaves in production; uses a MockSigner locally.

## Build & Test Commands

```bash
# Rust
cargo build                  # build (dev)
cargo build --release        # build (release)
cargo test                   # run all unit tests
cargo test aggregator        # run tests in aggregator module
cargo fmt --check            # format check (CI enforces this)
cargo clippy -- -D warnings  # lint (CI runs this, currently warn-only)
RUST_LOG=debug cargo run     # run oracle with verbose logging
SINGLE_RUN=1 cargo run       # run one oracle loop iteration then exit

# Solidity (from contracts/)
cd contracts && forge build --sizes   # build contracts
cd contracts && forge test -vvv       # run contract tests
cd contracts && forge fmt --check     # format check

# Integration
bash scripts/full_flow_test.sh        # end-to-end test (needs Foundry + Rust)
bash scripts/test_pull_api.sh         # test the VSOCK pull API
```

## Architecture

### Oracle Loop (30-second cycle in `src/main.rs`)

Fetch prices from all sources → Data Quorum check (min 3 sources) → MAD outlier rejection (σ=3.0) → Volume-weighted median → Deviation/heartbeat trigger check → EIP-191 sign → Store in `PriceStore` (shared `Arc<RwLock<HashMap>>`)

### Key Modules

- **`src/sources/`** — Each file implements `PriceSource` trait (`fetch_price(Asset) -> Result<Option<PricePoint>>`). Sources: Binance, OKX, Bybit, Coinbase, CoinGecko, MEXC, KuCoin, GateIo, GovernancePrice (IGRA). All use the shared `HttpClient`.
- **`src/aggregator/mod.rs`** — `reject_outliers()` (MAD-based), `weighted_median()`, `to_fixed_point()` (f64 → U256 with 8 decimals), `sources_hash()`.
- **`src/signer.rs`** — `OracleSigner` trait with two impls: `MockSigner` (local dev, key from env or random) and `EnclaveSigner` (Linux-only, uses `aws-nitro-enclaves-nsm-api` for attestation). Signature payload: `keccak256(abi.encodePacked(assetId, price, timestamp, numSources, sourcesHash))` wrapped with EIP-191 prefix.
- **`src/price_server.rs`** — Length-prefixed JSON over VSOCK (production) or TCP (dev fallback on non-Linux). Methods: `get_prices`, `get_price`, `get_attestation`, `health`.
- **`src/http_client.rs`** — Wraps reqwest. In enclave mode, routes through `http://127.0.0.1:5000` VSOCK→TCP bridge to the host proxy.
- **`src/types.rs`** — `Asset` enum (EthUsd, BtcUsd, KasUsd, UsdcUsd, IgraUsd) with per-asset deviation thresholds and heartbeat intervals. `PricePoint`, `SignedPriceUpdate`.

### Solidity Contracts (`contracts/`)

- **`KaskadPriceOracle.sol`** — On-chain oracle with OZ ECDSA signature verification, circuit breaker (15% + staleness bypass at 4h), rate limiter (5s), future timestamp cap (5 min)
- **`KaskadAggregatorV3.sol`** — Chainlink `IAggregatorV3` compatibility wrapper (per-asset deploy)
- **`KaskadRouter.sol`** — Atomic price-update + Aave action. Methods: `borrowWithPrices`, `withdrawWithPrices`, `liquidateWithPrices`. Validates `MAX_PRICE_AGE=60s`, selective catch (only StalePrice/UpdateTooFrequent), nonReentrant
- **`NitroAttestationVerifier.sol`** — Marlin NitroProver-based PCR0 attestation verification
- Uses Foundry with OpenZeppelin + Marlin `nitro-prover` as git submodules (`contracts/lib/`)

### Relayer (`relayer/`)

TypeScript/Node.js permissionless relay service. Polls pull API → verifies EIP-191 signature locally → submits `updatePrice()` via ethers.js. FSM per asset (IDLE/FRESH/SUBMITTING). Serial TxQueue with nonce tracking and selective retry.

### Infrastructure (`infra/`)

Terraform configs for AWS: EC2, ALB, S3 (EIF storage), IAM, monitoring. Two user-data scripts: `user-data-builder.sh` (EIF build instance) and `user-data-prod.sh` (Nitro enclave host).

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ORACLE_PRIVATE_KEY` | random | Hex secp256k1 key for MockSigner |
| `ENCLAVE_MODE` | unset | Set to enable EnclaveSigner + VSOCK bridge |
| `SINGLE_RUN` | unset | Exit after one oracle loop |
| `VSOCK_PORT` | 5001 | Pull API server port |
| `IGRA_PRICE` | 0.10 | Governance-set IGRA price |
| `RUST_LOG` | info | Tracing filter level |

## Key Design Decisions

- **Pull-based architecture**: The oracle does NOT push prices on-chain. It signs and stores them in memory; consumers pull via the VSOCK API. On-chain publishing is deferred (publisher module exists but is not wired in).
- **Platform-conditional compilation**: `EnclaveSigner`, VSOCK listener, and TCP bridge are behind `#[cfg(target_os = "linux")]`. On macOS/other, the price server falls back to TCP on localhost.
- **Timestamp encoding**: Timestamps are `u64` in Rust but encoded as `uint256` (32 bytes big-endian) in the signing payload to match Solidity's `abi.encodePacked`.
- **Data Quorum**: Minimum 3 sources required per asset before signing. This prevents "Liquidity Eclipse" attacks.
- **Submodules**: The `contracts/lib/nitro-prover` and `contracts/lib/openzeppelin-contracts` are git submodules. Clone with `--recursive` or run `git submodule update --init --recursive`.

## Galleon Testnet Integration

Deployment addresses in `contracts/deployments/galleon.json`. Integration with lending-onchain:
1. Deploy via `forge script script/DeployGalleon.s.sol` (needs `ORACLE_SIGNER` env)
2. Swap oracle sources: `AaveOracle.setAssetSources([WETH,WBTC,USDC,WIKAS], [aggregators...])`
3. IGRA and KSKD stay on MockPriceOracle (governance/computed prices)
