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
use crate::http_client::{classify, printable_ascii, tallied};
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
                    error = %printable_ascii(&e.to_string()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};

    /// Fails with an error whose text carries a newline, ESC and U+202E.
    struct Foreign;

    #[async_trait]
    impl PriceSource for Foreign {
        async fn fetch_price(&self, _: &AssetConfig) -> Result<Option<PricePoint>> {
            Err(eyre::eyre!(
                "upstream: busy\nlevel=INFO \u{1b}[2J\u{202e}fdp.exe"
            ))
        }

        fn name(&self) -> &'static str {
            "binance"
        }
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A failed fetch logs one line, its error text as printable ASCII only.
    #[tokio::test]
    async fn a_failure_is_logged_on_one_line_of_printable_ascii() {
        let asset: AssetConfig = serde_json::from_value(serde_json::json!({
            "symbol": "BTC/USD", "min_sources": 1, "deviation_threshold_bps": 50,
            "heartbeat_seconds": 60,
            "sources": { "binance": { "pair": "BTCUSDT", "quote": "USDT" } }
        }))
        .unwrap();
        let diag = Diagnostics::new(std::slice::from_ref(&asset), &[]);
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let sources: Vec<Box<dyn PriceSource>> = vec![Box::new(Foreign)];
        let points = {
            let _log = tracing::subscriber::set_default(subscriber);
            fetch_all(&sources, &asset, &diag).await
        };
        assert!(points.is_empty());
        let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert_eq!(log.lines().count(), 1, "{log:?}");
        assert!(!log.contains(['\u{1b}', '\u{202e}']), "{log:?}");
        assert!(
            log.contains("error=upstream: busy?level=INFO ?[2J?fdp.exe"),
            "{log:?}"
        );
    }
}
