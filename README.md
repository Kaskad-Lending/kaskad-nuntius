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

All sources are fetched sequentially per asset. On error, the source is skipped and a warning is logged. Minimum 2 sources required to proceed.

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

## Quick Start

```bash
# Run with test key (auto-generated)
cargo run

# Run with specific key
ORACLE_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 cargo run

# Run tests
cargo test

# Verbose logging
RUST_LOG=debug cargo run
```

## Configuration

Environment variables (`.env` file supported):

| Variable | Default | Description |
|----------|---------|-------------|
| `ORACLE_PRIVATE_KEY` | random | Hex-encoded secp256k1 private key |
| `RUST_LOG` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `RPC_URL` | — | Galleon testnet RPC endpoint (planned) |

## TEE Development

For local testing without real TEE hardware:

| Approach | Command | What it tests |
|----------|---------|---------------|
| **Mock signer** | `cargo run` | Full flow with local key |
| **QEMU Nitro** | `qemu-system-x86_64 -machine nitro-enclave ...` | EIF boot, VSOCK, attestation format |
| **Foundry/Anvil** | `forge test` / `anvil` | On-chain signature verification |

The oracle uses a trait-based signer — `MockSigner` runs locally, `EnclaveSigner` (planned) reads the key from TEE key management (Nitro KMS or TDX HKDF-derived key via quex-vault pattern).

## Roadmap

- [x] Multi-source price fetcher (5 CEX APIs)
- [x] Weighted median aggregation + MAD outlier rejection
- [x] EIP-191 compatible signer
- [x] Deviation/heartbeat update triggers
- [ ] Smart contracts (`KaskadPriceOracle.sol`, `IAggregatorV3` wrapper)
- [ ] On-chain publisher (Galleon testnet)
- [ ] IGRA governance-set price module
- [ ] Nitro Enclave build (Docker → EIF)
- [ ] VSOCK proxy service
- [ ] Attestation integration (on-chain enclave registration)
- [ ] ZKP aggregation proofs (circom circuits, Phase 3)

## License

Private. Kaskad project.
