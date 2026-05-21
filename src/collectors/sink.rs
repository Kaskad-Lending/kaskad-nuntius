//! Sink that collectors push their book snapshots into.
//!
//! Wraps the `CollectorMessage` mpsc channel + a per-(exchange,symbol)
//! throttle so we don't flood downstream with thousands of msg/s/symbol.

use crate::cob_common::{CollectorMessage, OrderBookData, ServiceStatus};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;

/// Default minimum interval between two book emissions for the same
/// (exchange, symbol). Override via `COLLECTOR_EMIT_INTERVAL_MS` env var
/// (`0` to disable throttling).
const DEFAULT_EMIT_INTERVAL_MS: u64 = 50;

#[derive(Clone)]
pub struct BookSink {
    tx: Option<UnboundedSender<CollectorMessage>>,
    throttle: Option<std::sync::Arc<Mutex<HashMap<String, Instant>>>>,
    interval: Duration,
}

impl BookSink {
    pub fn new(tx: Option<UnboundedSender<CollectorMessage>>) -> Self {
        let interval_ms = std::env::var("COLLECTOR_EMIT_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_EMIT_INTERVAL_MS);
        let throttle = if interval_ms > 0 {
            Some(std::sync::Arc::new(Mutex::new(HashMap::new())))
        } else {
            None
        };
        Self {
            tx,
            throttle,
            interval: Duration::from_millis(interval_ms),
        }
    }

    /// Disabled sink (used in tests).
    pub fn disabled() -> Self {
        Self {
            tx: None,
            throttle: None,
            interval: Duration::ZERO,
        }
    }

    /// Send an order book snapshot. Drops the message silently if the throttle
    /// window for `(exchange_id, symbol)` hasn't elapsed yet, or if the receiver
    /// is gone.
    pub fn emit(&self, book: OrderBookData) {
        if !book.is_valid() {
            return;
        }
        if let Some(map) = &self.throttle {
            let key = format!("{}:{}", book.exchange_id, book.symbol);
            let now = Instant::now();
            let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(last) = guard.get(&key) {
                if now.duration_since(*last) < self.interval {
                    return;
                }
            }
            guard.insert(key, now);
        }
        if let Some(tx) = &self.tx {
            let _ = tx.send(CollectorMessage::Data(book));
        }
    }

    pub fn status(&self, name: &str, status: ServiceStatus) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(CollectorMessage::Status {
                name: name.to_string(),
                status,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cob_common::PriceLevel;
    use tokio::sync::mpsc::unbounded_channel;

    fn book(ex: &str, sym: &str) -> OrderBookData {
        OrderBookData {
            exchange_id: ex.into(),
            symbol: sym.into(),
            exchange_timestamp: 0,
            received_timestamp: 0,
            latency: 0,
            bids: vec![PriceLevel {
                price: 100.0,
                quantity: 1.0,
            }],
            asks: vec![PriceLevel {
                price: 101.0,
                quantity: 1.0,
            }],
            node_id: None,
        }
    }

    #[test]
    fn invalid_books_dropped() {
        let (tx, mut rx) = unbounded_channel();
        let sink = BookSink {
            tx: Some(tx),
            throttle: None,
            interval: Duration::ZERO,
        };
        let mut bad = book("ex", "S");
        bad.bids = vec![];
        bad.asks = vec![]; // empty book → invalid
        sink.emit(bad);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn valid_books_pass_when_no_throttle() {
        let (tx, mut rx) = unbounded_channel();
        let sink = BookSink {
            tx: Some(tx),
            throttle: None,
            interval: Duration::ZERO,
        };
        sink.emit(book("ex", "S"));
        sink.emit(book("ex", "S"));
        assert!(matches!(rx.try_recv(), Ok(CollectorMessage::Data(_))));
        assert!(matches!(rx.try_recv(), Ok(CollectorMessage::Data(_))));
    }
}
