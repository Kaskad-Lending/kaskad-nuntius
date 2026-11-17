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

use crate::diagnostics::{Diagnostics, Spent};
use crate::http_client::{classify, tallied};
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
/// source omitted from this cycle's sample; every answer or failure is
/// recorded in `diag`.
pub async fn fetch_all(
    sources: &[Box<dyn PriceSource>],
    asset: &AssetConfig,
    diag: &Diagnostics,
) -> Vec<PricePoint> {
    let mut handles = Vec::new();

    for source in sources {
        let name = source.name();
        let fut = source.fetch_price(asset);
        handles.push((name, fut));
    }

    let mut results = Vec::new();
    for (name, fut) in handles {
        let started = Instant::now();
        let (outcome, tally) = tallied(fut).await;
        let spent = Spent {
            duration: if tally.calls > 0 {
                tally.elapsed
            } else {
                started.elapsed()
            },
            attempts: tally.attempts,
        };
        match outcome {
            Ok(Some(pp)) => {
                tracing::info!(source = name, price = pp.price, "fetched {}", asset.symbol);
                diag.source_ok(&asset.symbol, name, spent);
                results.push(pp);
            }
            Ok(None) => {
                tracing::debug!(source = name, "doesn't support {}", asset.symbol);
            }
            Err(e) => {
                let (class, http_status) = classify(&e);
                tracing::warn!(
                    source = name,
                    error = %e,
                    %class,
                    http_status,
                    attempts = spent.attempts,
                    duration_ms = spent.duration.as_millis() as u64,
                    "failed to fetch {}",
                    asset.symbol
                );
                diag.source_failed(&asset.symbol, name, &e, spent);
            }
        }
    }

    results
}
