# Kaskad TEE Oracle - Audit Scope

## Overview

Trustless price oracle for the Kaskad lending protocol. Fetches prices from 14 CEX/DEX sources inside an AWS Nitro Enclave, aggregates via volume-weighted median with MAD outlier rejection, signs with an enclave-bound ECDSA key (EIP-191), and exposes signed prices via a pull API. Permissionless relayer pushes prices on-chain. Fully permissionless contracts -- no owner, no admin, no upgradeability.

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
                  Permissionless Relayer
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
- All price updates verified via ECDSA.recover -- no trust in relayer or submitter

---

## In Scope

### 1. Smart Contracts (`contracts/src/`)

| Contract | Lines | Focus |
|----------|-------|-------|
| `KaskadPriceOracle.sol` | 276 | Core oracle. Signature verification, replay prevention (signedTimestamp ordering), circuit breaker (15% max change / 4h staleness bypass), no rate limiter (caller pays gas, enclave signature prevents spam), future timestamp cap (configurable per chain). Dual timestamp model: `block.timestamp` for consumers, `signedTimestamp` for ordering |
| `KaskadRouter.sol` | 161 | Aave integration wrapper. `borrowWithPrices`, `withdrawWithPrices`, `liquidateWithPrices`. Selective try/catch (only `StalePrice` + `UpdateTooFrequent`). `MAX_PRICE_AGE=60s`. Delegation model (user approves once, Router acts on behalf) |
| `KaskadAggregatorV3.sol` | 99 | Chainlink IAggregatorV3 compatibility wrapper. Per-asset deploy, reads from KaskadPriceOracle, uint80 roundId bounds check |
| `NitroAttestationVerifier.sol` | 137 | Wraps Marlin NitroProver. Extracts PCR0/PCR1/PCR2 from CBOR attestation, derives Ethereum address from enclave public key, validates PCR-1/PCR-2 (optional) |

**Security questions for auditors:**
- Can a valid signature from a previous enclave instance be replayed after key rotation?
- Is the circuit breaker bypassable? Can an attacker lock an asset permanently?
- Can the dual timestamp model (signedTimestamp vs block.timestamp) be exploited?
- Is the EIP-191 signing payload collision-resistant across assets?
- Can Router be used to extract value via selective price staleness?

### 2. Rust Oracle Binary (`src/`)

| Module | Lines | Focus |
|--------|-------|-------|
| `main.rs` | 415 | Oracle loop, asset configuration, VSOCK bridge setup, on-demand signing flow |
| `signer.rs` | 230 | `OracleSigner` trait. MockSigner (dev) and EnclaveSigner (prod, aws-nitro-enclaves-nsm-api). Key generation, attestation doc request, EIP-191 message construction and signing |
| `aggregator/mod.rs` | ~120 | `reject_outliers()` (MAD, sigma=3.0), `weighted_median()` (volume-weighted or equal-weight fallback), `to_fixed_point()` (f64 to U256 8 decimals), `sources_hash()` |
| `price_server.rs` | 366 | Length-prefixed JSON over VSOCK (prod) or TCP (dev). On-demand signing: fresh timestamp on every pull request. Read/write timeouts, connection limits |
| `types.rs` | 108 | Asset enum with per-asset config: `min_sources()` (data quorum), `deviation_threshold_bps()`, `heartbeat_seconds()`. Exchange server timestamp for enclave clock trust |
| `http_client.rs` | 54 | HTTP via VSOCK proxy in enclave mode. TLS termination inside enclave |
| `sources/*.rs` | 14 files, ~1100 total | Per-exchange price fetchers. Symbol validation, server_time parsing, volume extraction |

**Security questions for auditors:**
- Can the host manipulate prices by selectively blocking/replaying CEX API responses through the VSOCK proxy?
- Is MAD outlier rejection sufficient against a coordinated multi-exchange manipulation?
- Can f64 to U256 conversion produce incorrect fixed-point values (rounding, overflow)?
- Is the data quorum (min_sources per asset) sufficient to prevent single-source manipulation?
- Can the VSOCK bridge be used to exfiltrate the signing key?
- Is on-demand signing safe? Can a consumer cause the oracle to sign a stale price?

### 3. TypeScript Relayer (`relayer/src/`)

| Module | Lines | Focus |
|--------|-------|-------|
| `relay.ts` | 217 | FSM per asset (IDLE/FRESH/SUBMITTING). Local EIP-191 signature verification before submitting. numSources check |
| `tx-queue.ts` | 141 | Serial TX queue with nonce tracking. Selective retry on revert |
| `poll.ts` | 62 | HTTP polling of pull API |
| `index.ts` | 89 | Main loop, config loading |

**Security questions for auditors:**
- Can a compromised relayer cause harm beyond liveness (it's permissionless, anyone can relay)?
- Is the local signature verification sufficient to prevent submitting invalid prices?
- Can nonce management issues cause stuck or double-submitted prices?

### 4. Enclave Build & Deployment

| File | Focus |
|------|-------|
| `Dockerfile` | Multi-stage build. Static musl binary. nsm-hwrng validation gate. Loopback interface setup |
| `enclave/pull_api.py` | Host-side VSOCK-to-HTTP proxy. Rate limiting (60 req/min/IP) |
| `infra/user-data-prod.sh` | Production EC2 setup. EIF download from S3, enclave launch (no --debug-mode), VSOCK proxy services |

**Security questions for auditors:**
- Is the Dockerfile deterministic? Can the same source produce different PCR0 hashes?
- Is nsm-hwrng validation sufficient to ensure cryptographic-quality randomness?
- Can the host-side pull_api.py be exploited to inject data into the enclave?
- Is the VSOCK proxy configuration secure (no port forwarding, no data injection)?

### 5. Data Pipeline (end-to-end)

The full path a price takes from exchange API to on-chain consumer:

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
  -> Relayer polls, verifies signature locally
  -> cast/ethers.js submits updatePrice() TX
  -> KaskadPriceOracle verifies ECDSA signature on-chain
  -> Stores price with block.timestamp (consumer-facing)
  -> AggregatorV3 wrapper exposes to Aave
```

**Critical audit focus:** every transformation and trust boundary in this pipeline.

---

## Out of Scope

### Third-party Submodules (audited separately)
- `contracts/lib/openzeppelin-contracts/` -- OpenZeppelin ECDSA, well-audited
- `contracts/lib/nitro-prover/` -- Marlin NitroProver (P-384 cert chain verification, CBOR parsing)
- `contracts/lib/forge-std/` -- Foundry test framework

### External Dependencies
- CEX/DEX API availability, correctness, and uptime
- AWS Nitro Enclave hardware security (assumed secure per AWS model)
- Galleon/Igra L1 consensus and block production
- Aave V3 pool contract behavior

### Infrastructure (operational, not code audit)
- AWS IAM policies, KMS configuration
- Terraform resource provisioning
- CI/CD pipeline (GitHub Actions)
- DNS, TLS certificates, ALB configuration

### Test Code
- `contracts/test/` -- Foundry test suites
- `contracts/test/mocks/` -- MockAttestationVerifier, FailingAttestationVerifier
- `scripts/` -- E2E test scripts, deployment helpers

---

## Deployment Configuration

### Galleon Testnet (current)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `MAX_FUTURE_TIMESTAMP` | 3 hours | Galleon block.timestamp derived from DAA scores, drifts ~100min from UTC |
| `MAX_PRICE_CHANGE_BPS` | 1500 (15%) | Circuit breaker |
| `CIRCUIT_BREAKER_STALENESS` | 4 hours | Bypass after extended downtime |
| `MAX_PRICE_AGE` (Router) | 60 seconds | Uses block.timestamp (not exchange time) |
| Data Quorum | ETH/BTC/KAS: 3, USDC: 2, IGRA: 1 | Per-asset minimum sources |

### Mainnet (planned)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `MAX_FUTURE_TIMESTAMP` | 5 minutes | Normal chain with accurate timestamps |
| Other parameters | Same | No change expected |

---

## Known Issues / Design Tradeoffs

1. **CertManager constructor gas** -- Marlin's CertManager runs P-384 root cert verification in constructor. On some chains this exceeds deploy gas limits. Workaround: deploy CertManager separately with high gas, or use pre-deployed instance. Not a security issue -- operational constraint.

2. **Attestation cert chain expiry** -- AWS Nitro leaf certs live ~3 hours. On chains with timestamp drift (Galleon), the effective window shrinks. Re-registration requires fresh attestation + verifyCerts (60M gas) + registerEnclave within the cert validity window.

3. **Enclave restart = new key** -- Every enclave restart generates a new signing key. Requires on-chain re-registration via attestation. Old prices remain valid (signed by previous key, already stored on-chain). New prices require the new key to be registered.

4. **Host proxy trust** -- The host EC2 instance proxies all HTTP traffic for the enclave. A compromised host could selectively block or delay API responses. Mitigated by: data quorum (min 3 sources), MAD outlier rejection, TLS inside enclave (host sees ciphertext). Cannot forge prices because signing key is in enclave.

5. **Dual timestamp model** -- `block.timestamp` stored for consumers (Aave staleness), `signedTimestamp` (exchange server time) for replay prevention. Designed for chains where block.timestamp diverges from real time. Tradeoff: consumers see "on-chain freshness" not "real-world freshness".

---

## Requested Audit Deliverables

1. **Smart contract security audit** -- focus on signature verification, access control (should be none), economic attacks (circuit breaker bypass, price manipulation via Router)
2. **Cryptographic review** -- EIP-191 message construction, signing payload uniqueness, key derivation from enclave attestation
3. **Data pipeline integrity** -- can prices be manipulated at any stage between exchange API and on-chain storage?
4. **Trust boundary analysis** -- what can a compromised host do? What can a compromised relayer do? What are the enclave's actual guarantees?
5. **Economic attack vectors** -- flash loan + oracle manipulation scenarios, Router arbitrage, selective staleness attacks
