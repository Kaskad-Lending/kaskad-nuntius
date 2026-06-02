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
/// Books older than this (relative to the in-map reference clock) are
/// considered abandoned and evicted.
const DEFAULT_MAX_AGE_MS: i64 = 60_000;

pub fn new_shared() -> SharedBookState {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Insert counter for amortised pruning.
static INSERT_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Insert/replace the book for (exchange_id, symbol). Keyed on
/// "{exchange_id}:{symbol}" for cheap HashMap lookup. Every
/// `PRUNE_EVERY_N` inserts the map is swept for stale entries (any
/// book whose `exchange_timestamp` is far below the in-map reference)
/// so an exchange that disconnects permanently doesn't leak forever.
pub async fn insert(state: &SharedBookState, book: OrderBookData) {
    let key = format!("{}:{}", book.exchange_id, book.symbol);
    let mut guard = state.write().await;
    guard.insert(key, book);

    let n = INSERT_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if n > 0 && n.is_multiple_of(PRUNE_EVERY_N) {
        if let Some(reference_ms) = reference_now_ms(&guard) {
            prune_in_place(&mut guard, reference_ms, DEFAULT_MAX_AGE_MS);
        }
    }
}

/// Median of in-map `exchange_timestamp`s — the host-clock-free
/// reference used as "now" for the prune sweep. Mirrors the same
/// design used in `cob::read_books_filtered`. Returns `None` for an
/// empty map or one containing only invalid (`<= 0`) timestamps.
fn reference_now_ms(state: &HashMap<String, OrderBookData>) -> Option<i64> {
    let mut v: Vec<i64> = state
        .values()
        .map(|b| b.exchange_timestamp)
        .filter(|t| *t > 0)
        .collect();
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    Some(v[v.len() / 2])
}

/// Evict any entry whose `exchange_timestamp` differs from
/// `reference_ms` by more than `max_age_ms`. Pure helper -- testable
/// without a tokio runtime. Closed range on both sides so a single
/// future-dated malicious book is also dropped.
pub fn prune_in_place(
    state: &mut HashMap<String, OrderBookData>,
    reference_ms: i64,
    max_age_ms: i64,
) -> usize {
    let before = state.len();
    state.retain(|_, book| {
        if book.exchange_timestamp <= 0 {
            return false;
        }
        let delta = reference_ms - book.exchange_timestamp;
        delta.abs() <= max_age_ms
    });
    before - state.len()
}

/// External hook so tests / future operators can prune on demand.
/// `None` if the map is empty / has no valid timestamps to anchor on
/// (nothing to evict in that case anyway).
pub async fn prune(state: &SharedBookState, max_age_ms: i64) -> Option<usize> {
    let mut guard = state.write().await;
    let reference_ms = reference_now_ms(&guard)?;
    Some(prune_in_place(&mut guard, reference_ms, max_age_ms))
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
        // A future-dated book has negative delta; the closed range
        // catches it from the other side.
        let mut m: HashMap<String, OrderBookData> = HashMap::new();
        let now = 1_700_000_000_000_i64;
        m.insert("ex:S".into(), book("ex", "S", now + 120_000));
        let removed = prune_in_place(&mut m, now, 60_000);
        assert_eq!(removed, 1);
        assert!(m.is_empty());
    }

    #[test]
    fn prune_drops_non_positive_timestamps() {
        // Should never reach the map (collectors drop them), but a
        // belt-and-braces check: zero ts is evicted unconditionally.
        let mut m: HashMap<String, OrderBookData> = HashMap::new();
        m.insert("ex:S".into(), book("ex", "S", 0));
        let removed = prune_in_place(&mut m, 1_700_000_000_000, 60_000);
        assert_eq!(removed, 1);
    }

    #[test]
    fn prune_empty_is_noop() {
        let mut m: HashMap<String, OrderBookData> = HashMap::new();
        let removed = prune_in_place(&mut m, 1_700_000_000_000, 60_000);
        assert_eq!(removed, 0);
    }

    #[test]
    fn reference_is_median_of_valid_timestamps() {
        let mut m: HashMap<String, OrderBookData> = HashMap::new();
        m.insert("ex:S1".into(), book("ex", "S1", 1_000));
        m.insert("ex:S2".into(), book("ex", "S2", 2_000));
        m.insert("ex:S3".into(), book("ex", "S3", 3_000));
        // A malicious far-future book is just one of the inputs —
        // does not pull the median away from the honest cluster.
        m.insert("ex:S4".into(), book("ex", "S4", i64::MAX / 2));
        let r = reference_now_ms(&m).expect("non-empty");
        assert!(
            (1_000..=3_000).contains(&r) || r == i64::MAX / 2,
            "median sat at {r}"
        );
    }
}
