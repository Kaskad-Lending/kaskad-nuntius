mod types;
mod sources;
mod aggregator;
mod signer;
mod price_server;
mod http_client;
pub mod vsock_client;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use eyre::Result;
use tracing::{info, warn, error};

use types::{Asset, PricePoint, SignedPriceUpdate, now_secs};
use sources::PriceSource;
use signer::{OracleSigner, MockSigner};

const ORACLE_DECIMALS: u8 = 8;
const FETCH_INTERVAL_SECS: u64 = 30;

/// Shared state: latest signed prices, accessible by the VSOCK server.
pub type PriceStore = Arc<RwLock<HashMap<String, SignedPriceUpdate>>>;

/// Tracks the last pushed price and timestamp per asset (for deviation/heartbeat logic).
struct OracleState {
    last_prices: HashMap<Asset, (f64, u64)>,
}

impl OracleState {
    fn new() -> Self {
        Self {
            last_prices: HashMap::new(),
        }
    }

    fn should_update(&self, asset: Asset, new_price: f64) -> bool {
        match self.last_prices.get(&asset) {
            None => true,
            Some((last_price, last_ts)) => {
                let now = now_secs();
                if now - last_ts >= asset.heartbeat_seconds() {
                    return true;
                }
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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let _ = dotenvy::dotenv();

    info!("🚀 Kaskad TEE Oracle starting...");

    // Init signer
    let enclave_mode = std::env::var("ENCLAVE_MODE").is_ok();
    
    let signer: Box<dyn OracleSigner> = if enclave_mode {
        #[cfg(target_os = "linux")]
        {
            info!("Running in ENCLAVE mode — Initializing EnclaveSigner via NSM");
            Box::new(signer::EnclaveSigner::new().expect("Failed to init EnclaveSigner"))
        }
        #[cfg(not(target_os = "linux"))]
        {
            panic!("Enclave mode requested but target is not Linux/Nitro compatible");
        }
    } else {
        match std::env::var("ORACLE_PRIVATE_KEY") {
            Ok(key) => {
                info!("Using private key from ORACLE_PRIVATE_KEY env");
                Box::new(MockSigner::new(&key)?)
            }
            Err(_) => {
                info!("No ORACLE_PRIVATE_KEY found, generating random key for testing");
                Box::new(MockSigner::random())
            }
        }
    };
    
    let signer_address = format!("0x{}", hex::encode(signer.address()));
    info!(address = %signer_address, "Oracle signer initialized");

    // Shared price store
    let price_store: PriceStore = Arc::new(RwLock::new(HashMap::new()));

    // Start VSOCK price server (pull API)
    let vsock_port: u32 = std::env::var("VSOCK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5001);

    let server_store = price_store.clone();
    let server_signer_address = signer_address.clone();
    let attestation_doc = signer.attestation_doc();
    tokio::spawn(async move {
        if let Err(e) = price_server::run_price_server(vsock_port, server_store, server_signer_address, attestation_doc).await {
            error!(error = %e, "Price server failed");
        }
    });

    // Init HTTP client — auto-detect enclave mode
    let enclave_mode = std::env::var("ENCLAVE_MODE").is_ok();
    if enclave_mode {
        info!("Running in ENCLAVE mode — HTTP routed through VSOCK proxy");
    } else {
        info!("Running in HOST mode — HTTP via direct connection");
    }
    let client = http_client::HttpClient::new(enclave_mode);

    // Init sources
    let igra_price = std::env::var("IGRA_PRICE")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.10);

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

    let assets = vec![
        Asset::EthUsd,
        Asset::BtcUsd,
        Asset::KasUsd,
        Asset::UsdcUsd,
        Asset::IgraUsd,
    ];

    let single_run = std::env::var("SINGLE_RUN").is_ok();
    let mut state = OracleState::new();

    info!(
        assets = ?assets.iter().map(|a| a.symbol()).collect::<Vec<_>>(),
        single_run = single_run,
        "Starting oracle loop"
    );

    // Main oracle loop: fetch → aggregate → sign → store
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

            // 4. Check if we should update
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

            // 7. Store signed update (instead of pushing on-chain)
            let update = SignedPriceUpdate {
                asset_id: format!("0x{}", hex::encode(asset.id().as_slice())),
                asset_symbol: asset.symbol().to_string(),
                price: format!("{}", price_fixed),
                price_human: format!("{:.8}", median),
                timestamp,
                num_sources: prices.len() as u8,
                sources_hash: format!("0x{}", hex::encode(sources_hash.as_slice())),
                signature: format!("0x{}", hex::encode(&signature)),
                signer: signer_address.clone(),
            };

            {
                let mut store = price_store.write().await;
                store.insert(asset.symbol().to_string(), update);
            }

            info!(asset = asset.symbol(), "📦 stored signed update for pull API");

            // 8. Record update locally
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
