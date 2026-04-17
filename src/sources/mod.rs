pub mod binance;
pub mod bitfinex;
pub mod bitget;
pub mod bitstamp;
pub mod bybit;
pub mod coinbase;
pub mod coingecko;
pub mod crypto_com;
pub mod gateio;
pub mod htx;
pub mod igralabs;
pub mod kraken;
pub mod kucoin;
pub mod mexc;
pub mod okx;

use async_trait::async_trait;
use eyre::Result;

use crate::types::{AssetConfig, PricePoint};

/// Trait for all price data sources. The source looks up its specific
/// symbol for `asset` via `asset.sources.get(self.name())` — when the
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
        match fut.await {
            Ok(Some(pp)) => {
                tracing::info!(
                    source = name,
                    price = pp.price,
                    "fetched {}",
                    asset.symbol
                );
                results.push(pp);
            }
            Ok(None) => {
                tracing::debug!(source = name, "doesn't support {}", asset.symbol);
            }
            Err(e) => {
                tracing::warn!(source = name, error = %e, "failed to fetch {}", asset.symbol);
            }
        }
    }

    results
}
