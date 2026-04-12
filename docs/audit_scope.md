# Kaskad TEE Oracle - Audit Scope

## Overview

Trustless price oracle for the Kaskad lending protocol. Fetches prices from 14 CEX/DEX sources inside an AWS Nitro Enclave, aggregates via volume-weighted median with MAD outlier rejection, signs with an enclave-bound ECDSA key (EIP-191), and exposes signed prices via a pull API. On-chain contracts are fully permissionless -- no owner, no admin, no upgradeability.

## Trust Model

```
                 TRUST BOUNDARY (Nitro Enclave)
                +---------------------------------+
 CEX APIs ─TLS─>| Fetch -> Aggregate -> Sign      |
                | Private key NEVER leaves enclave |
                +---------------------------------+
                          |  VSOCK (no TCP/IP)
                          v
                    Host EC2 proxy
                          |
                          v
                Anyone submits updatePrice() TX
                          |
                          v
                  On-chain Oracle Contract
                    (signature verified)
```

Key security properties:

- Enclave has NO network access -- all HTTP goes through host VSOCK proxy
- Signing key generated inside enclave, never exported
- On-chain registration requires valid AWS Nitro attestation (P-384 cert chain verification)
- PCR0 (enclave image hash) is immutable in contract -- only code with matching image can sign
- All price updates verified via ECDSA.recover -- no trust in submitter

---

## In Scope

### 1. Smart Contracts (`contracts/src/`)

| Contract                       | Lines | Focus                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------------------ | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `KaskadPriceOracle.sol`        | 252   | Core oracle. Constructor `(bytes32 pcr0, address verifier)`. Signature verification via OZ `ECDSA.recover`. Replay prevention via strict `signedTimestamp` ordering. Circuit breaker (15% max change, 4h staleness bypass). Dual timestamp model: `block.timestamp` stored for consumers, `signedTimestamp` for ordering. No rate limiter, no future timestamp cap (see "Removed parameters" below) |
| `KaskadRouter.sol`             | 212   | Aave integration wrapper (synced from lending-onchain). `borrowWithPrices`, `withdrawWithPrices`, `liquidateWithPrices`. `nonReentrant` + transient storage `withSender` modifier for caller tracking. Selective catch -- only `StalePrice` skipped. Freshness validation delegated to oracle. Delegation model (`onBehalfOf = msg.sender` always)                                                  |
| `KaskadAggregatorV3.sol`       | 99    | Chainlink `IAggregatorV3` compatibility wrapper. Per-asset deploy (each aggregator bound to a single `assetId = keccak256(symbol)`). Reads from `KaskadPriceOracle.latestPrices`                                                                                                                                                                                                                    |
| `NitroAttestationVerifier.sol` | 137   | Wraps Marlin NitroProver. Direct call (no `try/catch`). Extracts PCR0/PCR1/PCR2 from CBOR attestation, derives Ethereum address from enclave public key (keccak256 of uncompressed secp256k1 point), validates PCR-1/PCR-2 if set (`bytes32(0)` to skip)                                                                                                                                            |

### 2. Rust Oracle Binary (`src/`)

| Module              | Lines                              | Focus                                                                                                                                                                          |
| ------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `main.rs`           | 415                                | Oracle loop, asset configuration, VSOCK bridge setup, on-demand signing flow                                                                                                   |
| `signer.rs`         | 230                                | `OracleSigner` trait. MockSigner (dev) and EnclaveSigner (prod, aws-nitro-enclaves-nsm-api). Key generation, attestation doc request, EIP-191 message construction and signing |
| `aggregator/mod.rs` | 163                                | `reject_outliers()` (MAD, sigma=3.0), `weighted_median()` (volume-weighted or equal-weight fallback), `to_fixed_point()` (f64 to U256 8 decimals), `sources_hash()`            |
| `price_server.rs`   | 366                                | Length-prefixed JSON over VSOCK (prod) or TCP (dev). On-demand signing: fresh timestamp on every pull request. Read/write timeouts, connection limits                          |
| `types.rs`          | 108                                | Asset enum with per-asset config: `min_sources()` (data quorum), `deviation_threshold_bps()`, `heartbeat_seconds()`. Exchange server timestamp for enclave clock trust         |
| `http_client.rs`    | 54                                 | HTTP via VSOCK proxy in enclave mode. TLS termination inside enclave                                                                                                           |
| `sources/*.rs`      | 14 CEX + 1 governance, ~1240 total | Per-exchange price fetchers. Symbol validation, server_time parsing, volume extraction                                                                                         |

**Source coverage** (14 CEX/DEX + 1 governance):

| Asset    | Sources | Notes                                                                 |
| -------- | ------- | --------------------------------------------------------------------- |
| ETH/USD  | 14      | All CEX sources                                                       |
| BTC/USD  | 14      | All CEX sources                                                       |
| KAS/USD  | 7       | Not on Binance, OKX, Coinbase, Bitfinex, Bitstamp, Kraken, Crypto.com |
| USDC/USD | 8       | Not on Bybit, Coinbase, MEXC, KuCoin, GateIo, Crypto.com              |
| IGRA/USD | 1       | Governance-set price (no CEX listings)                                |

### 3. Enclave Build & Deployment

| File                      | Focus                                                                                              |
| ------------------------- | -------------------------------------------------------------------------------------------------- |
| `Dockerfile`              | Multi-stage build. Static musl binary. nsm-hwrng validation gate. Loopback interface setup         |
| `enclave/pull_api.py`     | Host-side VSOCK-to-HTTP proxy. Rate limiting (60 req/min/IP)                                       |
| `infra/user-data-prod.sh` | Production EC2 setup. EIF download from S3, enclave launch (no --debug-mode), VSOCK proxy services |

### 4. Data Pipeline (end-to-end)

```
Exchange API (HTTPS)
  -> Host VSOCK proxy (socat VSOCK:5000 -> TCP:8888)
  -> Enclave HTTP client (TLS inside enclave)
  -> PriceSource::fetch_price() [symbol validation, server_time extraction]
  -> Data Quorum check (min 2-3 sources per asset)
  -> reject_outliers() MAD sigma=3.0
  -> weighted_median() (volume-weighted or equal-weight)
  -> to_fixed_point() f64 -> U256 (8 decimals)
  -> On-demand EIP-191 signing (secp256k1, k256 crate)
  -> Pull API response (length-prefixed JSON over VSOCK)
  -> Anyone calls updatePrice() with signed payload
  -> KaskadPriceOracle verifies ECDSA signature on-chain
  -> Stores price with block.timestamp (consumer-facing)
  -> AggregatorV3 wrapper exposes to Aave
```

---

## Out of Scope

### Third-party Submodules

- `contracts/lib/openzeppelin-contracts/` -- OpenZeppelin (ECDSA, SafeERC20, ReentrancyGuard)
- `contracts/lib/nitro-prover/` -- Marlin NitroProver (P-384 cert chain verification, CBOR parsing)
- `contracts/lib/forge-std/` -- Foundry test framework

### TypeScript Relayer (`relayer/`)

Permissionless relay service. A compromised relayer can only affect liveness (delay price updates), not integrity (cannot forge signatures). Anyone can run their own relayer or submit `updatePrice()` directly.

### External Dependencies

- CEX/DEX API availability, correctness, and uptime
- AWS Nitro Enclave hardware security (assumed secure per AWS model)
- Igra L1 consensus and block production
- Aave V3 pool contract behavior (audited separately as part of lending-onchain)

### Infrastructure (operational)

- AWS IAM policies, KMS configuration, Terraform, CI/CD, DNS, TLS certificates

### Test Code

- `contracts/test/`, `contracts/test/mocks/`, `scripts/`

---

## Deployment Configuration

Same parameters for testnet and mainnet. No per-chain tuning.

| Parameter                   | Value                                | Rationale                                                                                                                  |
| --------------------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `MAX_PRICE_CHANGE_BPS`      | 1500 (15%)                           | Circuit breaker -- rejects single-update swings larger than 15% when last update is fresh                                  |
| `CIRCUIT_BREAKER_STALENESS` | 4 hours                              | Bypass circuit breaker when `block.timestamp - last_update > 4h`. Prevents permanent asset lockout after extended downtime |
| Data Quorum (Rust)          | ETH/BTC: 3, KAS: 3, USDC: 2, IGRA: 1 | Per-asset minimum source count before the enclave signs                                                                    |
| Outlier rejection (Rust)    | MAD σ=3.0                            | Per-cycle outlier filter before weighted median                                                                            |
| Oracle decimals             | 8                                    | Chainlink compatibility                                                                                                    |

### Removed parameters (design decisions)

| Parameter                         | Rationale                                                                                                                                                                                                                                            |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MIN_UPDATE_DELAY` (rate limiter) | No security value -- caller pays gas (self-limiting), enclave signature required (no fakes), replay prevented by `signedTimestamp` ordering. Blocked concurrent Router users                                                                         |
| `MAX_FUTURE_TIMESTAMP`            | Attack it mitigated (host manipulates clock → future timestamp locks asset) is impossible because enclave uses TLS-verified exchange server timestamps. Check conflicted with chains where `block.timestamp` drifts from real time (Igra DAA scores) |
| `MAX_PRICE_AGE` (Router)          | Freshness validation delegated to oracle. Router no longer checks `block.timestamp - price.timestamp` -- was incompatible with chains where `block.timestamp` diverges from real time                                                                |

---

## Known Issues / Design Tradeoffs

1. **Attestation cert chain expiry** -- AWS Nitro leaf certs live ~3 hours. Re-registering an enclave on-chain requires `verifyCerts` (~60M gas) + `registerEnclave` (~24M gas) within the cert validity window. On chains where `block.timestamp` drifts ahead of UTC, the effective window shrinks.

2. **Enclave restart = new key** -- Every enclave restart generates a new signing key. Re-registration is permissionless (anyone can call with a valid attestation matching the immutable `expectedPCR0`). No governance, no operator keys needed.

3. **Host proxy trust** -- The host proxies all enclave HTTP traffic. A compromised host can selectively drop, delay, or replay API responses. Mitigated by: TLS inside enclave (host sees ciphertext), data quorum, MAD outlier rejection, 15% circuit breaker. Host cannot forge prices (signing key is in enclave memory).

4. **Dual timestamp model** -- `block.timestamp` stored for consumers (Aave staleness), `signedTimestamp` (exchange server time) for replay ordering. On chains where `block.timestamp` diverges from UTC, consumers see "on-chain freshness" not "real-world freshness".

5. **No rate limiter, no future timestamp cap** -- Intentionally removed. Security relies on enclave signature (unforgeable), `signedTimestamp` ordering (replay prevention), circuit breaker (price manipulation bounds), data quorum (multi-source requirement).

---

## Focus Areas

- Smart contract security
- Cryptographic correctness (EIP-191, ECDSA, CBOR/PCR extraction)
- Data pipeline integrity (CEX API → on-chain storage)
- Trust boundaries (enclave vs host vs submitter)
- Economic attacks (flash-loan + oracle manipulation, Router edge cases)
- Permissionless verification (no hidden privilege paths)
