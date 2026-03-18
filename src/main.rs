mod types;
mod sources;
mod aggregator;
mod signer;
mod publisher;
mod vsock_client;

use std::collections::HashMap;

use eyre::Result;
use tracing::{info, warn, error};

use types::{Asset, PricePoint, now_secs};
use sources::PriceSource;
use signer::{OracleSigner, MockSigner};

const ORACLE_DECIMALS: u8 = 8;
const FETCH_INTERVAL_SECS: u64 = 30;

/// Tracks the last pushed price and timestamp per asset.
struct OracleState {
    last_prices: HashMap<Asset, (f64, u64)>, // (price, timestamp)
}

impl OracleState {
    fn new() -> Self {
        Self {
            last_prices: HashMap::new(),
        }
    }

    /// Returns true if we should push a new price update.
    fn should_update(&self, asset: Asset, new_price: f64) -> bool {
        match self.last_prices.get(&asset) {
            None => true, // First update
            Some((last_price, last_ts)) => {
                let now = now_secs();

                // Heartbeat check
                if now - last_ts >= asset.heartbeat_seconds() {
                    return true;
                }

                // Deviation check
                let deviation_bps = ((new_price - last_price) / last_price * 10000.0).abs() as u16;
                if deviation_bps >= asset.deviation_threshold_bps() {
                    return true;
                }

                false
            }
        }
    }

    fn record_update(&mut self, asset: Asset, price: f64) {
        self.last_prices.insert(asset, (price, now_secs()));
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Init logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Load config
    let _ = dotenvy::dotenv();

    info!("🚀 Kaskad TEE Oracle starting...");

    // Init signer
    let signer = match std::env::var("ORACLE_PRIVATE_KEY") {
        Ok(key) => {
            info!("Using private key from ORACLE_PRIVATE_KEY env");
            MockSigner::new(&key)?
        }
        Err(_) => {
            info!("No ORACLE_PRIVATE_KEY found, generating random key for testing");
            MockSigner::random()
        }
    };
    info!(
        address = format!("0x{}", hex::encode(signer.address())),
        "Oracle signer initialized"
    );

    // Init HTTP client
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("KaskadOracle/0.1")
        .build()?;

    // Init publisher (optional — if env vars set, push on-chain; otherwise log-only)
    let maybe_publisher = match (
        std::env::var("RPC_URL"),
        std::env::var("ORACLE_CONTRACT"),
        std::env::var("TX_SIGNER_KEY"),
    ) {
        (Ok(rpc), Ok(contract), Ok(tx_key)) => {
            let chain_id: u64 = std::env::var("CHAIN_ID")
                .unwrap_or_else(|_| "31337".into())
                .parse()
                .unwrap_or(31337);

            let contract_addr: alloy_primitives::Address = contract.parse()
                .map_err(|e| eyre::eyre!("invalid ORACLE_CONTRACT: {}", e))?;

            info!(
                rpc_url = %rpc,
                contract = %contract_addr,
                chain_id = chain_id,
                "Publisher initialized — prices will be pushed on-chain"
            );

            Some(publisher::Publisher::new(rpc, contract_addr, tx_key, chain_id))
        }
        _ => {
            warn!("Missing RPC_URL/ORACLE_CONTRACT/TX_SIGNER_KEY — running in log-only mode (no on-chain publishing)");
            None
        }
    };

    // Init sources (9 total: 5 major CEX + 3 additional for KAS + governance for IGRA)
    let igra_price = std::env::var("IGRA_PRICE")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.10); // default: $0.10 presale price

    let price_sources: Vec<Box<dyn PriceSource>> = vec![
        Box::new(sources::binance::Binance::new(client.clone())),
        Box::new(sources::okx::Okx::new(client.clone())),
        Box::new(sources::bybit::Bybit::new(client.clone())),
        Box::new(sources::coinbase::Coinbase::new(client.clone())),
        Box::new(sources::coingecko::CoinGecko::new(client.clone())),
        Box::new(sources::mexc::Mexc::new(client.clone())),
        Box::new(sources::kucoin::Kucoin::new(client.clone())),
        Box::new(sources::gateio::GateIo::new(client.clone())),
        Box::new(sources::governance::GovernancePrice::new(igra_price)),
    ];

    info!(igra_price = igra_price, "IGRA governance price set");

    // Assets to track
    let assets = vec![
        Asset::EthUsd,
        Asset::BtcUsd,
        Asset::KasUsd,
        Asset::UsdcUsd,
        Asset::IgraUsd,
    ];

    // Single-run mode: run once and exit (for testing)
    let single_run = std::env::var("SINGLE_RUN").is_ok();

    let mut state = OracleState::new();

    info!(
        assets = ?assets.iter().map(|a| a.symbol()).collect::<Vec<_>>(),
        single_run = single_run,
        "Starting oracle loop"
    );

    // Main oracle loop
    loop {
        for &asset in &assets {
            // 1. Fetch from all sources
            let mut prices = sources::fetch_all(&price_sources, asset).await;

            if prices.is_empty() {
                warn!(asset = asset.symbol(), "no prices fetched, skipping");
                continue;
            }

            info!(
                asset = asset.symbol(),
                num_sources = prices.len(),
                "fetched prices"
            );

            // 2. Outlier rejection
            let before = prices.len();
            aggregator::reject_outliers(&mut prices, 3.0);
            if prices.len() < before {
                info!(
                    asset = asset.symbol(),
                    removed = before - prices.len(),
                    "rejected outliers"
                );
            }

            // 3. Compute weighted median
            let median = match aggregator::weighted_median(&prices) {
                Some(m) => m,
                None => {
                    warn!(asset = asset.symbol(), "no prices after filtering");
                    continue;
                }
            };

            // 4. Check if we should push
            if !state.should_update(asset, median) {
                info!(
                    asset = asset.symbol(),
                    price = format!("{:.6}", median),
                    "price within threshold, skipping"
                );
                continue;
            }

            // 5. Convert to fixed point
            let timestamp = now_secs();
            let price_fixed = aggregator::to_fixed_point(median, ORACLE_DECIMALS);
            let sources_hash = aggregator::sources_hash(&prices);

            // 6. Sign
            let (signature, _signer_addr) = signer.sign_price_update(
                asset.id(),
                price_fixed,
                timestamp,
                prices.len() as u8,
                sources_hash,
            )?;

            info!(
                asset = asset.symbol(),
                price = format!("{:.6}", median),
                price_fixed = %price_fixed,
                num_sources = prices.len(),
                "✅ signed price update"
            );

            // 7. Push to chain (if publisher available)
            if let Some(ref pub_) = maybe_publisher {
                match pub_.submit_price(
                    asset.id(),
                    price_fixed,
                    timestamp,
                    prices.len() as u8,
                    sources_hash,
                    signature,
                ).await {
                    Ok(tx_hash) => {
                        info!(
                            asset = asset.symbol(),
                            tx_hash = %tx_hash,
                            "📤 submitted to chain"
                        );
                    }
                    Err(e) => {
                        error!(
                            asset = asset.symbol(),
                            error = %e,
                            "❌ failed to submit to chain"
                        );
                    }
                }
            }

            // 8. Record update
            state.record_update(asset, median);
        }

        if single_run {
            info!("✅ Single run complete, exiting");
            break;
        }

        info!(
            "💤 sleeping {} seconds...",
            FETCH_INTERVAL_SECS
        );
        tokio::time::sleep(std::time::Duration::from_secs(FETCH_INTERVAL_SECS)).await;
    }

    Ok(())
}

