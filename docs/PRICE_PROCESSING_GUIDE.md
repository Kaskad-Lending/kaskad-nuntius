# Price Processing Developer Guide

> How to work with, extend, and test the oracle's price aggregation pipeline.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Module Map](#module-map)
- [Data Flow](#data-flow)
- [Key Extension Points](#key-extension-points)
  - [1. Outlier Rejection](#1-outlier-rejection-aggregatormodrs)
  - [2. Aggregation Strategy](#2-aggregation-strategy-aggregatormodrs)
  - [3. Adding a New Data Source](#3-adding-a-new-data-source-sourcesrs)
  - [4. Per-Asset Configuration](#4-per-asset-configuration-typesrs)
- [CI/CD Pipeline](#cicd-pipeline)
- [Testing](#testing)
  - [Unit Tests](#unit-tests)
  - [Local Integration Test](#local-integration-test)
  - [Verifying a Production Deployment](#verifying-a-production-deployment)
- [Security Constraints](#security-constraints)

---

## Architecture Overview

The oracle runs inside an **AWS Nitro Enclave** (TEE). It has no direct network access — all HTTP traffic is tunneled through VSOCK to the Host OS, which forwards it via an HTTP CONNECT proxy. TLS termination happens **inside** the enclave, so the Host cannot read or tamper with exchange data.

```
┌─────────────── Nitro Enclave ────────────────┐
│                                               │
│  reqwest (TLS) ──► 127.0.0.1:5000             │
│       │                                       │
│  VSOCK→TCP Bridge (Rust, AF_VSOCK)            │
│       │                                       │
└───────┼───────────────────────────────────────┘
        │ VSOCK CID:3 port:5000
┌───────┼──────── Host OS (EC2) ────────────────┐
│       │                                       │
│  socat VSOCK-LISTEN:5000 ──► 127.0.0.1:8888   │
│       │                                       │
│  Python HTTP CONNECT proxy ──► Internet       │
└───────────────────────────────────────────────┘
```

## Module Map

| Module | File | Responsibility |
|--------|------|----------------|
| **Aggregator** | [`src/aggregator/mod.rs`](https://github.com/Kaskad-Lending/kaskad-nuntius/blob/main/src/aggregator/mod.rs) | Outlier rejection, weighted median, fixed-point conversion |
| **Sources** | [`src/sources/mod.rs`](https://github.com/Kaskad-Lending/kaskad-nuntius/blob/main/src/sources/mod.rs) | `PriceSource` trait, `fetch_all()` orchestrator |
| **Source impls** | [`src/sources/{binance,okx,bybit,...}.rs`](https://github.com/Kaskad-Lending/kaskad-nuntius/tree/main/src/sources) | Per-exchange HTTP parsers |
| **Types** | [`src/types.rs`](https://github.com/Kaskad-Lending/kaskad-nuntius/blob/main/src/types.rs) | `PricePoint`, `Asset`, per-asset thresholds |
| **Orchestrator** | [`src/main.rs`](https://github.com/Kaskad-Lending/kaskad-nuntius/blob/main/src/main.rs) (L173-280) | Main loop: fetch → reject → median → sign → store |
| **HTTP Client** | [`src/http_client.rs`](https://github.com/Kaskad-Lending/kaskad-nuntius/blob/main/src/http_client.rs) | Unified reqwest client with VSOCK proxy support |

## Data Flow

The main loop in [`src/main.rs`](https://github.com/Kaskad-Lending/kaskad-nuntius/blob/main/src/main.rs) runs every 30 seconds:

```
for each Asset:
    1. Fetch          ──  sources::fetch_all()       →  Vec<PricePoint>
    2. Quorum check   ──  prices.len() >= 3          →  skip if insufficient
    3. Reject outliers──  aggregator::reject_outliers →  Vec<PricePoint> (filtered)
    4. Aggregate      ──  aggregator::weighted_median →  f64
    5. Deviation check──  state.should_update()      →  skip if within threshold
    6. Sign           ──  signer.sign_price_update() →  ECDSA signature
    7. Store          ──  price_store.insert()       →  available via Pull API
```

The core data structure flowing through the pipeline:

```rust
// src/types.rs
pub struct PricePoint {
    pub price: f64,      // USD price from the source
    pub volume: f64,     // 24h volume (used as weight in median)
    pub timestamp: u64,  // When this observation was made
    pub source: String,  // e.g. "binance", "okx"
}
```

---

## Key Extension Points

### 1. Outlier Rejection (`aggregator/mod.rs`)

**Current implementation:** [MAD (Median Absolute Deviation)](https://github.com/Kaskad-Lending/kaskad-nuntius/blob/main/src/aggregator/mod.rs#L41-L67) with σ=3.

```rust
// src/aggregator/mod.rs — current implementation
pub fn reject_outliers(prices: &mut Vec<PricePoint>, sigma: f64) {
    if prices.len() < 3 { return; }

    let median = /* sorted median of prices */;
    let mad = /* median of |price - median| */;
    let threshold = sigma * 1.4826 * mad;

    prices.retain(|p| (p.price - median).abs() <= threshold);
}
```

**To replace/extend**, edit this function directly. The contract is simple:
- **Input**: `&mut Vec<PricePoint>` — mutate in place, removing outliers
- **Input**: `sigma: f64` — the sensitivity parameter (called from `main.rs` with `3.0`)
- **Postcondition**: surviving points must be "trustworthy" observations

**Example: adding IQR-based filtering as an alternative:**

```rust
pub fn reject_outliers_iqr(prices: &mut Vec<PricePoint>, k: f64) {
    if prices.len() < 4 { return; }

    let mut sorted: Vec<f64> = prices.iter().map(|p| p.price).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let q1 = sorted[sorted.len() / 4];
    let q3 = sorted[3 * sorted.len() / 4];
    let iqr = q3 - q1;

    let lower = q1 - k * iqr;
    let upper = q3 + k * iqr;

    prices.retain(|p| p.price >= lower && p.price <= upper);
}
```

Then update `main.rs` L196 to call your new function:

```rust
// src/main.rs — change the call site
aggregator::reject_outliers_iqr(&mut prices, 1.5);
```

### 2. Aggregation Strategy (`aggregator/mod.rs`)

**Current implementation:** [Weighted median](https://github.com/Kaskad-Lending/kaskad-nuntius/blob/main/src/aggregator/mod.rs#L6-L39) using `volume` as weight.

```rust
pub fn weighted_median(prices: &[PricePoint]) -> Option<f64> {
    // Sort by price, walk cumulative weight until 50%
    // Falls back to equal weights if volume = 0
}
```

**To replace**, create a new function with the same signature `(&[PricePoint]) -> Option<f64>` and update the call in `main.rs` L206:

```rust
let median = match aggregator::your_new_aggregation(&prices) {
    Some(m) => m,
    None => { /* ... */ continue; }
};
```

**Example ideas:**
- TWAP (Time-Weighted Average Price) — use `timestamp` field
- VWAP (Volume-Weighted Average) — use `volume` field
- Trimmed mean — discard top/bottom 10% then average
- Huber estimator — robust location estimator

### 3. Adding a New Data Source (`sources/*.rs`)

Every exchange is a separate file implementing the [`PriceSource`](https://github.com/Kaskad-Lending/kaskad-nuntius/blob/main/src/sources/mod.rs#L17-L24) trait:

```rust
#[async_trait]
pub trait PriceSource: Send + Sync {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>>;
    fn name(&self) -> &'static str;
}
```

**Step-by-step: Adding a new exchange (e.g. Kraken)**

1. **Create** `src/sources/kraken.rs`:

```rust
use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;
use crate::types::{Asset, PricePoint, now_secs};
use super::PriceSource;

pub struct Kraken {
    client: crate::http_client::HttpClient,
}

impl Kraken {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }

    fn pair_for(asset: Asset) -> Option<&'static str> {
        match asset {
            Asset::EthUsd => Some("XETHZUSD"),
            Asset::BtcUsd => Some("XXBTZUSD"),
            _ => None,  // return None for unsupported assets
        }
    }
}

#[derive(Deserialize)]
struct KrakenResponse {
    result: std::collections::HashMap<String, KrakenPair>,
}

#[derive(Deserialize)]
struct KrakenPair {
    c: Vec<String>,  // c[0] = last trade price
    v: Vec<String>,  // v[1] = 24h volume
}

#[async_trait]
impl PriceSource for Kraken {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        let pair = match Self::pair_for(asset) {
            Some(p) => p,
            None => return Ok(None),
        };

        let url = format!("https://api.kraken.com/0/public/Ticker?pair={}", pair);
        let resp: KrakenResponse = self.client.get_json(&url).await?;

        let ticker = resp.result.values().next()
            .ok_or_else(|| eyre::eyre!("empty Kraken response"))?;

        let price: f64 = ticker.c[0].parse()?;
        let volume: f64 = ticker.v.get(1).and_then(|v| v.parse().ok()).unwrap_or(0.0);

        Ok(Some(PricePoint {
            price,
            volume,
            timestamp: now_secs(),
            source: "kraken".into(),
        }))
    }

    fn name(&self) -> &'static str { "kraken" }
}
```

2. **Register** in `src/sources/mod.rs`:

```rust
pub mod kraken;  // add this line at the top
```

3. **Wire up** in `src/main.rs` (search for `price_sources`):

```rust
price_sources.push(Box::new(sources::kraken::Kraken::new(client.clone())));
```

That's it — `fetch_all()` will automatically include the new source.

### 4. Per-Asset Configuration (`types.rs`)

Each asset has tunable parameters in [`src/types.rs`](https://github.com/Kaskad-Lending/kaskad-nuntius/blob/main/src/types.rs):

```rust
impl Asset {
    /// Deviation threshold before pushing on-chain
    pub fn deviation_threshold_bps(&self) -> u16 {
        match self {
            Asset::EthUsd | Asset::BtcUsd => 50,  // 0.5%
            Asset::KasUsd => 200,                   // 2%
            Asset::UsdcUsd => 10,                   // 0.1%
            Asset::IgraUsd => 0,                    // always push
        }
    }

    /// Max time between updates
    pub fn heartbeat_seconds(&self) -> u64 {
        match self {
            Asset::EthUsd | Asset::BtcUsd => 3600,
            Asset::KasUsd => 1800,
            Asset::UsdcUsd | Asset::IgraUsd => 86400,
        }
    }
}
```

To add per-asset outlier rejection parameters, add a new method:

```rust
pub fn outlier_sigma(&self) -> f64 {
    match self {
        Asset::KasUsd => 2.5,   // tighter for volatile assets
        _ => 3.0,
    }
}
```

Then use it in `main.rs`:

```rust
aggregator::reject_outliers(&mut prices, asset.outlier_sigma());
```

---

## CI/CD Pipeline

### Production Deploy ([`deploy.yml`](https://github.com/Kaskad-Lending/kaskad-nuntius/blob/main/.github/workflows/deploy.yml))

Triggered **automatically** on push to `main` when files under `src/`, `Cargo.*`, `Dockerfile`, or `enclave/` change.

```
Push to main
    │
    ├── 1. Start EC2 Builder instance (c5.xlarge with Nitro CLI)
    ├── 2. Upload source.zip to S3
    ├── 3. SSM → Builder: docker build + nitro-cli build-enclave → oracle.eif
    ├── 4. Upload oracle.eif to S3 (kaskad-oracle-eif/latest.eif)
    ├── 5. Stop Builder instance (cost saving)
    └── 6. Trigger ASG Instance Refresh (rolling replacement)
              │
              └── New EC2 spot instance boots with latest user-data
                  → Downloads oracle.eif from S3
                  → Launches enclave with nitro-cli run-enclave
                  → Starts pull_api.py + HTTP CONNECT proxy + socat bridge
```

**Timeline:** Push → Prices live ≈ **15-20 minutes**

> [!IMPORTANT]
> The CI rebuilds only the **EIF image** (enclave binary). Changes to `infra/user-data-prod.sh` require a separate `terraform apply` from a machine with AWS credentials (no SSH access to prod instances).

### What triggers a deploy

| Path changed | Triggers deploy? |
|---|---|
| `src/**` | ✅ Yes |
| `Cargo.toml` / `Cargo.lock` | ✅ Yes |
| `Dockerfile` | ✅ Yes |
| `enclave/**` | ✅ Yes |
| `contracts/**` | ❌ No |
| `infra/**` | ❌ No (requires `terraform apply`) |
| `docs/**` | ❌ No |

---

## Testing

### Unit Tests

The aggregator module has existing tests in [`src/aggregator/mod.rs`](https://github.com/Kaskad-Lending/kaskad-nuntius/blob/main/src/aggregator/mod.rs#L89-L153).

**Run tests:**

```bash
cargo test
```

**Add a test for your new algorithm:**

```rust
// src/aggregator/mod.rs — add in the #[cfg(test)] mod tests block

#[test]
fn test_my_new_outlier_rejection() {
    // Helper creates PricePoints from f64 values
    let mut prices = make_prices(&[100.0, 101.0, 99.5, 100.5, 999.0]);
    
    reject_outliers_iqr(&mut prices, 1.5);
    
    // The outlier (999.0) should be removed
    assert_eq!(prices.len(), 4);
    assert!(prices.iter().all(|p| p.price < 200.0));
}

#[test]
fn test_edge_case_all_same_price() {
    let mut prices = make_prices(&[100.0, 100.0, 100.0, 100.0]);
    reject_outliers_iqr(&mut prices, 1.5);
    assert_eq!(prices.len(), 4); // nothing removed
}

#[test]
fn test_edge_case_two_sources() {
    let mut prices = make_prices(&[100.0, 200.0]);
    reject_outliers_iqr(&mut prices, 1.5);
    assert_eq!(prices.len(), 2); // not enough to filter
}
```

**Use the helper function to create test PricePoints:**

```rust
fn make_prices(values: &[f64]) -> Vec<PricePoint> {
    values.iter().enumerate().map(|(i, &price)| PricePoint {
        price,
        volume: 0.0,
        timestamp: 1000 + i as u64,
        source: format!("source_{}", i),
    }).collect()
}
```

**With volume weights:**

```rust
fn make_weighted_prices(data: &[(f64, f64)]) -> Vec<PricePoint> {
    data.iter().enumerate().map(|(i, &(price, volume))| PricePoint {
        price,
        volume,
        timestamp: 1000 + i as u64,
        source: format!("source_{}", i),
    }).collect()
}

#[test]
fn test_weighted_median_high_volume_dominates() {
    let prices = make_weighted_prices(&[
        (100.0, 1_000_000.0),   // Binance: huge volume
        (105.0, 100.0),          // small exchange
        (110.0, 50.0),           // tiny exchange
    ]);
    let median = weighted_median(&prices).unwrap();
    assert_eq!(median, 100.0); // high-volume source dominates
}
```

### Local Integration Test

Run the full oracle locally to verify your changes against real exchange APIs:

```bash
# 1. Build and run with a random test key
SINGLE_RUN=1 cargo run

# This will:
#   - Generate a random signer key
#   - Fetch from all 8 exchanges
#   - Apply outlier rejection + aggregation
#   - Print signed price updates
#   - Exit after one cycle
```

**Expected output (healthy run):**

```
INFO kaskad_oracle: 🚀 Kaskad TEE Oracle starting...
INFO kaskad_oracle: Using private key from ORACLE_PRIVATE_KEY env
INFO kaskad_oracle: fetched BTC/USD, source: binance, price: 67000.0
INFO kaskad_oracle: fetched BTC/USD, source: okx,     price: 67010.5
INFO kaskad_oracle: fetched BTC/USD, source: bybit,   price: 66995.0
...
INFO kaskad_oracle: fetched prices, asset: BTC/USD, num_sources: 7
INFO kaskad_oracle: rejected outliers, asset: BTC/USD, removed: 0
INFO kaskad_oracle: ✅ signed price update, asset: BTC/USD, price: 67002.50000000
```

**If you see `Data Quorum (3) not met` — one of two things:**
1. Your local IP is geo-blocked by some exchanges (use a VPN)
2. The asset is governance-priced (IGRA/USD) — that's expected, it uses a hardcoded price

### Verifying a Production Deployment

After your changes are merged to `main` and CI completes (~15 min):

```bash
# 1. Check health
curl http://kaskad-oracle-alb-670133639.us-east-1.elb.amazonaws.com/health
# → {"status":"ok","signer":"0x...","num_assets":5}

# 2. Check all prices
curl http://kaskad-oracle-alb-670133639.us-east-1.elb.amazonaws.com/prices | python3 -m json.tool
# → should have non-empty "prices" array with all 5 assets

# 3. Check a specific asset
curl http://kaskad-oracle-alb-670133639.us-east-1.elb.amazonaws.com/price/BTC/USD
# → single price entry with signature

# 4. Check CloudWatch logs for warnings/errors
aws logs filter-log-events \
  --log-group-name /kaskad/oracle \
  --filter-pattern "WARN" \
  --start-time $(python3 -c "import time; print(int((time.time()-3600)*1000))") \
  --query 'events[*].message' --output text
```

> [!WARNING]
> The oracle runs inside a Nitro Enclave with **no SSH access**. If your code panics, the enclave crashes silently (E44 in console logs). Always test with `SINGLE_RUN=1 cargo run` locally before pushing.

**CloudWatch log streams** (per instance):

| Stream | Contents |
|--------|----------|
| `{instance-id}/init` | Boot script output, package install, EIF launch |
| `{instance-id}/enclave` | `nitro-cli console` output (usually E44 — that's normal) |
| `{instance-id}/vsock-proxy` | HTTP CONNECT proxy logs |
| `{instance-id}/pull-api` | Pull API request logs |

---

## Security Constraints

When modifying the price pipeline, keep these invariants:

1. **Data Quorum**: At least 3 sources must agree before signing (`main.rs` L179). Do not lower this — it prevents [Liquidity Eclipse attacks](https://en.wikipedia.org/wiki/Eclipse_attack).

2. **No network calls outside `HttpClient`**: All HTTP goes through `http_client.rs` which tunnels via VSOCK. Never use `reqwest::get()` directly.

3. **Deterministic output**: Given the same `PricePoint[]` input, your aggregation must produce the exact same `f64` output. Non-deterministic oracles cause signature mismatches.

4. **No panics**: A panic inside the enclave kills it silently. Use `Result<>` and `?` propagation. The main loop catches errors and continues.

5. **Timestamp source**: `now_secs()` in `types.rs` uses the Host OS clock. This is a known trust boundary — don't add extra reliance on it. The smart contract already validates `timestamp <= block.timestamp + 1 hour`.
