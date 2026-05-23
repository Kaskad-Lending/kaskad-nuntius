//! Local L2 order book maintained by each collector.
//!
//! Each (exchange, symbol) owns one `LocalBook`. Collectors apply WebSocket
//! deltas + (optionally) REST snapshots to it, then call `to_orderbook_data`
//! to emit a top-N snapshot to the data bus.

use crate::cob_common::{LatencyTracker, OrderBookData, PriceLevel};
use ordered_float::OrderedFloat;
use std::collections::BTreeMap;

/// How many price levels we publish per side. The merger only consumes top-N,
/// so emitting more is wasted bandwidth.
pub const TOP_N: usize = 25;

/// Local L2 book backed by `BTreeMap<OrderedFloat<f64>, f64>` for O(log n)
/// insert/delete and ordered iteration.
///
/// `seq` is the last applied sequence/update id (semantics depend on the
/// exchange — Binance `u`, OKX `seqId`, HTX `seqNum`, ...). `None` means
/// the book has not yet been bootstrapped.
pub struct LocalBook {
    pub exchange_id: String,
    pub symbol: String,
    pub bids: BTreeMap<OrderedFloat<f64>, f64>,
    pub asks: BTreeMap<OrderedFloat<f64>, f64>,
    pub seq: Option<u64>,
    pub latency: LatencyTracker,
}

impl LocalBook {
    pub fn new(exchange_id: impl Into<String>, symbol: impl Into<String>) -> Self {
        Self {
            exchange_id: exchange_id.into(),
            symbol: symbol.into(),
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            seq: None,
            latency: LatencyTracker::new(0),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.seq.is_some() && (!self.bids.is_empty() || !self.asks.is_empty())
    }

    pub fn clear(&mut self) {
        self.bids.clear();
        self.asks.clear();
        self.seq = None;
    }

    /// Replace the book with a new snapshot. Used after REST snapshot or after
    /// an exchange-pushed snapshot event (Coinbase, OKX `snapshot`).
    pub fn apply_snapshot<I, J>(&mut self, bids: I, asks: J, seq: Option<u64>)
    where
        I: IntoIterator<Item = (f64, f64)>,
        J: IntoIterator<Item = (f64, f64)>,
    {
        self.bids.clear();
        self.asks.clear();
        for (p, q) in bids {
            if p > 0.0 && q > 0.0 && p.is_finite() && q.is_finite() {
                self.bids.insert(OrderedFloat(p), q);
            }
        }
        for (p, q) in asks {
            if p > 0.0 && q > 0.0 && p.is_finite() && q.is_finite() {
                self.asks.insert(OrderedFloat(p), q);
            }
        }
        self.seq = seq;
    }

    /// Apply incremental updates. `qty == 0.0` deletes the level.
    pub fn apply_deltas<I, J>(&mut self, bids: I, asks: J, new_seq: Option<u64>)
    where
        I: IntoIterator<Item = (f64, f64)>,
        J: IntoIterator<Item = (f64, f64)>,
    {
        for (p, q) in bids {
            if !p.is_finite() || !q.is_finite() || p <= 0.0 {
                continue;
            }
            if q < 0.0 {
                continue;
            }
            let key = OrderedFloat(p);
            if q == 0.0 {
                self.bids.remove(&key);
            } else {
                self.bids.insert(key, q);
            }
        }
        for (p, q) in asks {
            if !p.is_finite() || !q.is_finite() || p <= 0.0 {
                continue;
            }
            if q < 0.0 {
                continue;
            }
            let key = OrderedFloat(p);
            if q == 0.0 {
                self.asks.remove(&key);
            } else {
                self.asks.insert(key, q);
            }
        }
        if let Some(s) = new_seq {
            self.seq = Some(s);
        }
    }

    /// True when best bid >= best ask (book crossed — usually a sign of stale data).
    pub fn is_crossed(&self) -> bool {
        match (self.bids.keys().next_back(), self.asks.keys().next()) {
            (Some(b), Some(a)) => b.0 >= a.0,
            _ => false,
        }
    }

    /// Top N levels per side as `Vec<PriceLevel>` (bids high→low, asks low→high).
    pub fn top_n(&self, n: usize) -> (Vec<PriceLevel>, Vec<PriceLevel>) {
        let bids = self
            .bids
            .iter()
            .rev()
            .take(n)
            .map(|(p, q)| PriceLevel {
                price: p.0,
                quantity: *q,
            })
            .collect();
        let asks = self
            .asks
            .iter()
            .take(n)
            .map(|(p, q)| PriceLevel {
                price: p.0,
                quantity: *q,
            })
            .collect();
        (bids, asks)
    }

    /// Build a snapshot suitable for the data bus.
    /// `exchange_ts_ms` is the exchange-side timestamp for this update (or 0 if absent),
    /// `received_at_ms` is local wall clock.
    pub fn to_orderbook_data(&self, exchange_ts_ms: i64, received_at_ms: i64) -> OrderBookData {
        let (bids, asks) = self.top_n(TOP_N);
        let (norm_ts, latency) = self.latency.process(exchange_ts_ms, received_at_ms);
        OrderBookData {
            exchange_id: self.exchange_id.clone(),
            symbol: self.symbol.clone(),
            exchange_timestamp: norm_ts,
            received_timestamp: received_at_ms,
            latency,
            bids,
            asks,
            node_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lb() -> LocalBook {
        LocalBook::new("test", "BTC/USDT")
    }

    #[test]
    fn snapshot_replaces_book() {
        let mut b = lb();
        b.apply_snapshot(
            [(100.0, 1.0), (99.0, 2.0)],
            [(101.0, 3.0), (102.0, 4.0)],
            Some(1),
        );
        let (bids, asks) = b.top_n(10);
        assert_eq!(bids.len(), 2);
        assert_eq!(asks.len(), 2);
        assert_eq!(bids[0].price, 100.0);
        assert_eq!(bids[0].quantity, 1.0);
        assert_eq!(asks[0].price, 101.0);
        assert_eq!(b.seq, Some(1));

        // New snapshot wipes prior state
        b.apply_snapshot([(200.0, 5.0)], [(201.0, 6.0)], Some(2));
        let (bids, asks) = b.top_n(10);
        assert_eq!(bids[0].price, 200.0);
        assert_eq!(asks[0].price, 201.0);
    }

    #[test]
    fn delta_zero_qty_removes_level() {
        let mut b = lb();
        b.apply_snapshot([(100.0, 1.0)], [(101.0, 2.0)], Some(1));
        b.apply_deltas([(100.0, 0.0)], [(101.0, 0.0)], Some(2));
        let (bids, asks) = b.top_n(10);
        assert!(bids.is_empty());
        assert!(asks.is_empty());
        assert_eq!(b.seq, Some(2));
    }

    #[test]
    fn delta_updates_qty() {
        let mut b = lb();
        b.apply_snapshot([(100.0, 1.0)], [(101.0, 2.0)], Some(1));
        b.apply_deltas([(100.0, 5.0)], [(101.0, 6.0)], Some(2));
        let (bids, asks) = b.top_n(10);
        assert_eq!(bids[0].quantity, 5.0);
        assert_eq!(asks[0].quantity, 6.0);
    }

    #[test]
    fn invalid_prices_rejected() {
        let mut b = lb();
        b.apply_snapshot(
            [(0.0, 1.0), (-1.0, 1.0), (f64::NAN, 1.0), (100.0, 1.0)],
            [(101.0, 1.0)],
            Some(1),
        );
        let (bids, _) = b.top_n(10);
        assert_eq!(bids.len(), 1);
        assert_eq!(bids[0].price, 100.0);
    }

    #[test]
    fn top_n_ordering() {
        let mut b = lb();
        b.apply_snapshot(
            [(100.0, 1.0), (99.0, 2.0), (101.0, 3.0)],
            [(105.0, 1.0), (103.0, 2.0), (104.0, 3.0)],
            Some(1),
        );
        let (bids, asks) = b.top_n(10);
        // bids: high to low
        assert_eq!(
            bids.iter().map(|l| l.price).collect::<Vec<_>>(),
            vec![101.0, 100.0, 99.0]
        );
        // asks: low to high
        assert_eq!(
            asks.iter().map(|l| l.price).collect::<Vec<_>>(),
            vec![103.0, 104.0, 105.0]
        );
    }

    #[test]
    fn crossed_detection() {
        let mut b = lb();
        b.apply_snapshot([(100.0, 1.0)], [(99.0, 1.0)], Some(1));
        assert!(b.is_crossed());

        let mut b = lb();
        b.apply_snapshot([(99.0, 1.0)], [(100.0, 1.0)], Some(1));
        assert!(!b.is_crossed());
    }

    #[test]
    fn delta_rejects_negative_qty() {
        let mut b = lb();
        b.apply_snapshot([(100.0, 1.0)], [(101.0, 2.0)], Some(1));
        // Negative quantity must be ignored — neither remove nor insert.
        b.apply_deltas([(100.0, -5.0)], [(101.0, -1.0)], Some(2));
        let (bids, asks) = b.top_n(10);
        assert_eq!(bids.len(), 1);
        assert_eq!(asks.len(), 1);
        assert_eq!(bids[0].quantity, 1.0);
        assert_eq!(asks[0].quantity, 2.0);
        // Sequence still advances since the call carried a new seq.
        assert_eq!(b.seq, Some(2));
    }

    #[test]
    fn ready_state() {
        let mut b = lb();
        assert!(!b.is_ready());
        b.apply_snapshot([(100.0, 1.0)], [(101.0, 1.0)], Some(1));
        assert!(b.is_ready());
        b.clear();
        assert!(!b.is_ready());
    }
}
