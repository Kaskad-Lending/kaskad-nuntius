pub mod binance;
pub mod okx;
pub mod bybit;
pub mod coinbase;
pub mod coingecko;
pub mod mexc;
pub mod kucoin;
pub mod gateio;
pub mod governance;

use async_trait::async_trait;
use eyre::Result;

use crate::types::{Asset, PricePoint};

/// Trait for all price data sources.
#[async_trait]
pub trait PriceSource: Send + Sync {
    /// Fetch the current price for the given asset.
    /// Returns None if this source doesn't support the asset.
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>>;

    /// Human-readable name of this source.
    fn name(&self) -> &'static str;
}

/// Fetch prices from all sources concurrently. Skips sources that
/// don't support the asset or return errors (logged).
pub async fn fetch_all(sources: &[Box<dyn PriceSource>], asset: Asset) -> Vec<PricePoint> {
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
                    asset.symbol()
                );
                results.push(pp);
            }
            Ok(None) => {
                tracing::debug!(source = name, "doesn't support {}", asset.symbol());
            }
            Err(e) => {
                tracing::warn!(source = name, error = %e, "failed to fetch {}", asset.symbol());
            }
        }
    }

    results
}
