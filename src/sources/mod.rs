pub mod binance;
pub mod bitfinex;
pub mod bitget;
pub mod bitstamp;
pub mod bybit;
pub mod coinbase;
pub mod coingecko;
pub mod crypto_com;
pub mod ethrpc;
pub mod gateio;
pub mod htx;
pub mod igralabs;
pub mod kraken;
pub mod kucoin;
pub mod mexc;
pub mod okx;
pub mod robinhood;

use async_trait::async_trait;
use eyre::Result;
use tokio::time::Instant;

use crate::http_client::{ErrorClass, RequestError};
use crate::types::{AssetConfig, PricePoint};

/// Trait for all price data sources. The source looks up its specific
/// symbol for `asset` via `asset.pair(self.name())` — when the
/// key is absent, the source MUST return `Ok(None)` to be transparent
/// about lack of coverage.
#[async_trait]
pub trait PriceSource: Send + Sync {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>>;

    /// Stable identifier used as the key in `AssetConfig.sources`.
    fn name(&self) -> &'static str;
}

/// Fetch prices from all sources concurrently. Sources that don't support
/// the asset return None and are skipped. Errors are logged and their
/// source omitted from this cycle's sample.
pub async fn fetch_all(sources: &[Box<dyn PriceSource>], asset: &AssetConfig) -> Vec<PricePoint> {
    let mut handles = Vec::new();

    for source in sources {
        let name = source.name();
        let fut = source.fetch_price(asset);
        handles.push((name, fut));
    }

    let mut results = Vec::new();
    for (name, fut) in handles {
        let started = Instant::now();
        let outcome = fut.await;
        let duration_ms = started.elapsed().as_millis() as u64;
        match outcome {
            Ok(Some(pp)) => {
                tracing::info!(source = name, price = pp.price, "fetched {}", asset.symbol);
                results.push(pp);
            }
            Ok(None) => {
                tracing::debug!(source = name, "doesn't support {}", asset.symbol);
            }
            Err(e) => {
                let request = e.downcast_ref::<RequestError>();
                tracing::warn!(
                    source = name,
                    error = %e,
                    class = %request.map_or(ErrorClass::BadResponse, RequestError::class),
                    http_status = request.and_then(RequestError::http_status),
                    attempts = request.map(|r| r.attempts),
                    duration_ms,
                    "failed to fetch {}",
                    asset.symbol
                );
            }
        }
    }

    results
}
