//! Latest OrderBookData per (exchange_id, symbol). Written by the
//! collector fan-in task in main.rs, read by `cob::read_books_from_state`.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::cob_common::OrderBookData;

pub type SharedBookState = Arc<RwLock<HashMap<String, OrderBookData>>>;

/// One stale-entry prune sweep per `PRUNE_EVERY_N` inserts -- cheap, amortised.
const PRUNE_EVERY_N: u64 = 1000;
/// Books older than this are considered abandoned and evicted.
const DEFAULT_MAX_AGE_MS: i64 = 60_000;

pub fn new_shared() -> SharedBookState {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Insert counter for amortised pruning.
static INSERT_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Insert/replace the book for (exchange_id, symbol). Keyed on
/// "{exchange_id}:{symbol}" for cheap HashMap lookup. Every
/// `PRUNE_EVERY_N` inserts the map is swept for stale entries (any
/// book whose received_timestamp is older than `DEFAULT_MAX_AGE_MS`)
/// so an exchange that disconnects permanently doesn't leak forever.
pub async fn insert(state: &SharedBookState, book: OrderBookData) {
    let key = format!("{}:{}", book.exchange_id, book.symbol);
    let mut guard = state.write().await;
    guard.insert(key, book);

    let n = INSERT_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if n > 0 && n.is_multiple_of(PRUNE_EVERY_N) {
        let now_ms = chrono::Utc::now().timestamp_millis();
        prune_in_place(&mut guard, now_ms, DEFAULT_MAX_AGE_MS);
    }
}

/// Evict any entry whose `received_timestamp` is older than `max_age_ms`
/// at `now_ms`. Pure helper -- testable without a tokio runtime.
pub fn prune_in_place(
    state: &mut HashMap<String, OrderBookData>,
    now_ms: i64,
    max_age_ms: i64,
) -> usize {
    let before = state.len();
    state.retain(|_, book| {
        let age = now_ms - book.received_timestamp;
        age >= 0 && age <= max_age_ms
    });
    before - state.len()
}

/// External hook so tests / future operators can prune on demand.
pub async fn prune(state: &SharedBookState, max_age_ms: i64) -> usize {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let mut guard = state.write().await;
    prune_in_place(&mut guard, now_ms, max_age_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cob_common::PriceLevel;

    fn book(ex: &str, sym: &str, ts_ms: i64) -> OrderBookData {
        OrderBookData {
            exchange_id: ex.into(),
            symbol: sym.into(),
            exchange_timestamp: ts_ms,
            received_timestamp: ts_ms,
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
    fn prune_evicts_stale_entries() {
        let mut m: HashMap<String, OrderBookData> = HashMap::new();
        let now = 1_700_000_000_000_i64;
        m.insert("ex:S1".into(), book("ex", "S1", now)); // fresh
        m.insert("ex:S2".into(), book("ex", "S2", now - 30_000)); // fresh
        m.insert("ex:S3".into(), book("ex", "S3", now - 120_000)); // stale
        let removed = prune_in_place(&mut m, now, 60_000);
        assert_eq!(removed, 1);
        assert!(m.contains_key("ex:S1"));
        assert!(m.contains_key("ex:S2"));
        assert!(!m.contains_key("ex:S3"));
    }

    #[test]
    fn prune_rejects_future_timestamps() {
        // A future-dated book has negative age; treat as stale.
        let mut m: HashMap<String, OrderBookData> = HashMap::new();
        let now = 1_700_000_000_000_i64;
        m.insert("ex:S".into(), book("ex", "S", now + 1_000));
        let removed = prune_in_place(&mut m, now, 60_000);
        assert_eq!(removed, 1);
        assert!(m.is_empty());
    }

    #[test]
    fn prune_empty_is_noop() {
        let mut m: HashMap<String, OrderBookData> = HashMap::new();
        let removed = prune_in_place(&mut m, 1_700_000_000_000, 60_000);
        assert_eq!(removed, 0);
    }
}
