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
use futures::future::join_all;
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

/// Fetch prices from all sources at once, in one task: the first poll of
/// each source runs in list order and none is cancelled. Sources that don't
/// support the asset return None and are skipped. Errors are logged and
/// their source omitted from this cycle's sample; every answer or failure
/// is recorded in `diag`, in list order.
pub async fn fetch_all(
    sources: &[Box<dyn PriceSource>],
    asset: &AssetConfig,
    diag: &Diagnostics,
) -> Vec<PricePoint> {
    let answers = join_all(sources.iter().map(|source| async move {
        let started = Instant::now();
        let (outcome, tally) = tallied(source.fetch_price(asset)).await;
        (source.name(), outcome, tally, started.elapsed())
    }))
    .await;

    let mut results = Vec::new();
    for (name, outcome, tally, waited) in answers {
        let spent = Spent {
            duration: if tally.calls > 0 {
                tally.elapsed
            } else {
                waited
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

/// Log capture for tests that pin what reaches a log line.
#[cfg(test)]
pub(crate) mod log_capture {
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    pub(crate) struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        pub(crate) fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A buffer and a plain-text subscriber writing events up to `level` into it.
    pub(crate) fn capture(
        level: tracing::Level,
    ) -> (Captured, impl tracing::Subscriber + Send + Sync) {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(level)
            .with_writer(move || writer.clone())
            .finish();
        (captured, subscriber)
    }
}

#[cfg(test)]
mod tests {
    use super::log_capture::capture;
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

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
        let (captured, subscriber) = capture(tracing::Level::INFO);
        let sources: Vec<Box<dyn PriceSource>> = vec![Box::new(Foreign)];
        let points = {
            let _log = tracing::subscriber::set_default(subscriber);
            fetch_all(&sources, &asset, &diag).await
        };
        assert!(points.is_empty());
        let log = captured.text();
        assert_eq!(log.lines().count(), 1, "{log:?}");
        assert!(!log.contains(['\u{1b}', '\u{202e}']), "{log:?}");
        assert!(
            log.contains("error=upstream: busy?level=INFO ?[2J?fdp.exe"),
            "{log:?}"
        );
    }

    /// Answers after `delay`, noting its name when first polled.
    struct Slow {
        name: &'static str,
        delay: Duration,
        polled: Arc<Mutex<Vec<&'static str>>>,
    }

    #[async_trait]
    impl PriceSource for Slow {
        async fn fetch_price(&self, _: &AssetConfig) -> Result<Option<PricePoint>> {
            self.polled.lock().unwrap().push(self.name);
            tokio::time::sleep(self.delay).await;
            Ok(Some(PricePoint {
                price: 1.0,
                volume: 0.0,
                source: self.name.into(),
                server_time: 0,
            }))
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }

    fn hemi_usd() -> AssetConfig {
        serde_json::from_value(serde_json::json!({
            "symbol": "HEMI/USD", "min_sources": 3, "deviation_threshold_bps": 1500,
            "heartbeat_seconds": 3600,
            "sources": {
                "binance": { "pair": "HEMIUSDT", "quote": "USDT" },
                "gateio": { "pair": "HEMI_USDT", "quote": "USDT" },
                "mexc": { "pair": "HEMIUSDT", "quote": "USDT" }
            }
        }))
        .unwrap()
    }

    fn slow(
        polled: &Arc<Mutex<Vec<&'static str>>>,
        named: impl IntoIterator<Item = (&'static str, u64)>,
    ) -> Vec<Box<dyn PriceSource>> {
        named
            .into_iter()
            .map(|(name, secs)| {
                Box::new(Slow {
                    name,
                    delay: Duration::from_secs(secs),
                    polled: Arc::clone(polled),
                }) as Box<dyn PriceSource>
            })
            .collect()
    }

    /// Sources wait together: the call lasts as long as the slowest one, each
    /// is first polled and answered in list order, and each is charged its own wait.
    #[tokio::test(start_paused = true)]
    async fn sources_are_polled_at_once_in_list_order() {
        let asset = hemi_usd();
        let diag = Diagnostics::new(std::slice::from_ref(&asset), &[]);
        let polled = Arc::new(Mutex::new(Vec::new()));
        let sources = slow(&polled, [("binance", 3), ("gateio", 1), ("mexc", 2)]);
        let started = Instant::now();
        let points = fetch_all(&sources, &asset, &diag).await;
        assert_eq!(started.elapsed(), Duration::from_secs(3));
        let order = ["binance", "gateio", "mexc"];
        assert_eq!(*polled.lock().unwrap(), order);
        let answered: Vec<&str> = points.iter().map(|p| p.source.as_str()).collect();
        assert_eq!(answered, order);
        let reply: serde_json::Value = serde_json::from_slice(&diag.response()).unwrap();
        let sources = &reply["diagnostics"]["assets"]["HEMI/USD"]["sources"];
        let waits = order.map(|name| sources[name]["last_duration_ms"].as_u64());
        assert_eq!(waits, [Some(3000), Some(1000), Some(2000)]);
    }

    /// `join_all` drives more than 30 futures another way; the order holds.
    #[tokio::test(start_paused = true)]
    async fn a_long_source_list_keeps_list_order() {
        let asset = hemi_usd();
        let diag = Diagnostics::new(std::slice::from_ref(&asset), &[]);
        let polled = Arc::new(Mutex::new(Vec::new()));
        let names: Vec<&'static str> = (0..40)
            .map(|i| &*Box::leak(format!("source{i}").into_boxed_str()))
            .collect();
        let sources = slow(&polled, names.iter().map(|name| (*name, 1)));
        let started = Instant::now();
        let points = fetch_all(&sources, &asset, &diag).await;
        assert_eq!(started.elapsed(), Duration::from_secs(1));
        assert_eq!(*polled.lock().unwrap(), names);
        let answered: Vec<&str> = points.iter().map(|p| p.source.as_str()).collect();
        assert_eq!(answered, names);
    }
}
