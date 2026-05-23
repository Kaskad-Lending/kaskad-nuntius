//! Collector trait — one impl per exchange.
//!
//! Each impl owns its full lifecycle for all configured pairs:
//! connect → bootstrap (REST snapshot if needed) → maintain a `LocalBook`
//! per pair via WS deltas → emit `OrderBookData` snapshots on `sink`.
//!
//! When `run` returns Err, the manager applies a 5s backoff and re-spawns.
//! When it returns Ok, the manager treats it as voluntary shutdown.

use crate::cob_common::ExchangeConfig;
use crate::collectors::sink::BookSink;
use async_trait::async_trait;
use eyre::Result;

#[async_trait]
pub trait Collector: Send + Sync + 'static {
    fn id(&self) -> &str;

    /// Run forever until cancelled or until an unrecoverable error occurs.
    /// Implementations should handle their own reconnection (transient
    /// network errors should NOT bubble up).
    async fn run(&self, sink: BookSink) -> Result<()>;
}

/// Boxed collector type used by the manager.
pub type CollectorBox = std::sync::Arc<dyn Collector>;

/// Factory: build a collector by name.
pub fn create_collector(name: &str, config: &ExchangeConfig) -> Option<CollectorBox> {
    crate::collectors::impls::create_collector(name, config)
}
