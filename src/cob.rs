//! Consolidated Order Book (COB) for KAS/USDT across 7 centralized exchanges.
//!
//! Implements Algorithm 1 from "A Mathematical Model for Cross-Exchange Price Discovery"
//! (Eliott Mea, KEF). Aggregates order book snapshots into a single consolidated book,
//! simulates cross-venue arbitrage clearing, and returns the fair mid-price.
//!
//! Designed to run inside an AWS Nitro Enclave: pure computation, no filesystem,
//! no WebSocket, no persistent storage. All HTTP goes through an injected client.
//!
//! Scope: KAS/USDT only. Other assets use the legacy aggregator path in `main.rs`.

use std::collections::BTreeMap;

use crate::http_client::HttpClient;
use eyre::Result;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Level {
    pub price: f64,
    pub quantity: f64,
}

#[derive(Debug, Clone)]
pub struct OrderBookSnapshot {
    pub source: String,
    pub bids: Vec<Level>,
    pub asks: Vec<Level>,
    pub tick_size: f64,
}

#[derive(Debug, Clone)]
pub struct FairValue {
    pub price: f64,
    pub best_bid: f64,
    pub best_ask: f64,
    pub spread_bps: f64,
    pub num_sources: usize,
}

// ---------------------------------------------------------------------------
// Per-exchange tick sizes (KASUSDT)
// ---------------------------------------------------------------------------

fn tick_size_for(source: &str) -> f64 {
    match source {
        "bybit" | "okx" | "bitget" | "kucoin" => 0.00001,
        "gateio" | "mexc" | "htx" => 0.000001,
        _ => 0.000001,
    }
}

// ---------------------------------------------------------------------------
// Grid computation (GCD of tick sizes)
// ---------------------------------------------------------------------------

fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

fn gcd_f64(a: f64, b: f64) -> f64 {
    // Work in integer mantissas (1e10 scale) to avoid floating-point drift.
    let scale = 1e10;
    let ia = (a * scale).round() as u64;
    let ib = (b * scale).round() as u64;
    gcd_u64(ia, ib) as f64 / scale
}

fn compute_common_grid(books: &[OrderBookSnapshot]) -> f64 {
    let mut g: f64 = 0.0;
    for book in books {
        let tick = book.tick_size;
        if tick <= 0.0 {
            continue;
        }
        if g == 0.0 {
            g = tick;
        } else {
            g = gcd_f64(g, tick);
        }
    }
    if g <= 0.0 {
        0.0001
    } else {
        g
    }
}

// ---------------------------------------------------------------------------
// COB Algorithm 1
// ---------------------------------------------------------------------------

/// Run the Consolidated Order Book algorithm on a set of order book snapshots.
///
/// 1. Compute common grid = GCD of all tick sizes.
/// 2. Project all bids/asks onto the grid, summing quantities per level.
/// 3. Clear crossing volume until no overlap remains (arbitrage simulation).
/// 4. Return fair mid-price = (best_bid + best_ask) / 2.
pub fn consolidated_order_book(books: &[OrderBookSnapshot]) -> Option<FairValue> {
    if books.is_empty() {
        return None;
    }

    let grid = compute_common_grid(books);
    if grid <= 0.0 {
        return None;
    }
    let inv_grid = 1.0 / grid;

    let mut global_bids: BTreeMap<i64, f64> = BTreeMap::new();
    let mut global_asks: BTreeMap<i64, f64> = BTreeMap::new();

    for book in books {
        for level in &book.bids {
            if level.price <= 0.0 || level.quantity <= 0.0 || level.price.is_nan() {
                continue;
            }
            let key = (level.price * inv_grid).round() as i64;
            *global_bids.entry(key).or_insert(0.0) += level.quantity;
        }
        for level in &book.asks {
            if level.price <= 0.0 || level.quantity <= 0.0 || level.price.is_nan() {
                continue;
            }
            let key = (level.price * inv_grid).round() as i64;
            *global_asks.entry(key).or_insert(0.0) += level.quantity;
        }
    }

    // Arbitrage clearing.
    loop {
        let best_bid_key = global_bids.keys().next_back().copied();
        let best_ask_key = global_asks.keys().next().copied();
        match (best_bid_key, best_ask_key) {
            (Some(kb), Some(ka)) if kb >= ka => {
                let vb = *global_bids.get(&kb).unwrap();
                let va = *global_asks.get(&ka).unwrap();
                let v = vb.min(va);
                if (vb - v).abs() < 1e-15 {
                    global_bids.remove(&kb);
                } else {
                    *global_bids.get_mut(&kb).unwrap() -= v;
                }
                if (va - v).abs() < 1e-15 {
                    global_asks.remove(&ka);
                } else {
                    *global_asks.get_mut(&ka).unwrap() -= v;
                }
            }
            _ => break,
        }
    }

    let best_bid_key = global_bids.keys().next_back().copied()?;
    let best_ask_key = global_asks.keys().next().copied()?;

    let best_bid = best_bid_key as f64 * grid;
    let best_ask = best_ask_key as f64 * grid;
    let mid = (best_bid + best_ask) / 2.0;
    let spread_bps = if mid > 0.0 {
        (best_ask - best_bid) / mid * 10_000.0
    } else {
        0.0
    };

    Some(FairValue {
        price: mid,
        best_bid,
        best_ask,
        spread_bps,
        num_sources: books.len(),
    })
}

// ---------------------------------------------------------------------------
// Order book source trait + concurrent fetcher
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
pub trait OrderBookSource: Send + Sync {
    /// Fetch the KAS/USDT order book. Returns `Ok(None)` if this source is
    /// temporarily unavailable for KAS (e.g. delisting).
    async fn fetch_orderbook(&self) -> Result<Option<OrderBookSnapshot>>;
    fn name(&self) -> &'static str;
}

/// Minimum levels per side required for a book to be considered usable.
const MIN_BOOK_DEPTH: usize = 3;

/// Maximum per-source spread (bps). Above this, the venue is too illiquid to be
/// trusted; its best quotes would pollute the consolidated mid.
const MAX_SPREAD_BPS: f64 = 500.0;

/// Returns true if the book is clean enough to enter the COB aggregation.
///
/// Filters out:
/// - crossed or touching books (best_bid ≥ best_ask) — feed error
/// - shallow books (< MIN_BOOK_DEPTH levels on either side)
/// - excessively wide books (spread > MAX_SPREAD_BPS)
fn is_book_usable(book: &OrderBookSnapshot) -> bool {
    if book.bids.len() < MIN_BOOK_DEPTH || book.asks.len() < MIN_BOOK_DEPTH {
        warn!(
            source = book.source.as_str(),
            bids = book.bids.len(),
            asks = book.asks.len(),
            "rejected: book too shallow"
        );
        return false;
    }
    let best_bid = book.bids[0].price;
    let best_ask = book.asks[0].price;
    if !(best_bid > 0.0 && best_ask > 0.0) {
        warn!(
            source = book.source.as_str(),
            "rejected: non-positive top of book"
        );
        return false;
    }
    if best_bid >= best_ask {
        warn!(
            source = book.source.as_str(),
            best_bid, best_ask, "rejected: crossed or touching book"
        );
        return false;
    }
    let mid = (best_bid + best_ask) / 2.0;
    let spread_bps = (best_ask - best_bid) / mid * 10_000.0;
    if spread_bps > MAX_SPREAD_BPS {
        warn!(
            source = book.source.as_str(),
            spread_bps, "rejected: spread too wide"
        );
        return false;
    }
    true
}

/// Fetch order books from all sources. Per-source errors and bad books are
/// logged and skipped. Surviving books are guaranteed to pass [`is_book_usable`].
pub async fn fetch_all_books(sources: &[Box<dyn OrderBookSource>]) -> Vec<OrderBookSnapshot> {
    let mut results = Vec::new();
    for source in sources {
        match source.fetch_orderbook().await {
            Ok(Some(book)) => {
                if !is_book_usable(&book) {
                    continue;
                }
                info!(
                    source = source.name(),
                    bids = book.bids.len(),
                    asks = book.asks.len(),
                    "fetched KAS/USDT orderbook"
                );
                results.push(book);
            }
            Ok(None) => {}
            Err(e) => {
                warn!(
                    source = source.name(),
                    error = %e,
                    "failed to fetch KAS/USDT orderbook"
                );
            }
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Exchange implementations (7 venues, all KASUSDT)
//
// Binance is intentionally NOT included: KAS/USDT is not listed on
// api.binance.com spot (`{"code":-1121,"msg":"Invalid symbol."}`). Adding it
// would only produce noise in the warn logs without contributing to quorum.
// ---------------------------------------------------------------------------

pub struct BybitBook {
    client: HttpClient,
}
impl BybitBook {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }
}
#[async_trait::async_trait]
impl OrderBookSource for BybitBook {
    async fn fetch_orderbook(&self) -> Result<Option<OrderBookSnapshot>> {
        let url = "https://api.bybit.com/v5/market/orderbook?category=spot&symbol=KASUSDT&limit=20";
        #[derive(serde::Deserialize)]
        struct Resp {
            result: RespResult,
        }
        #[derive(serde::Deserialize)]
        struct RespResult {
            #[serde(default)]
            b: Vec<Vec<String>>,
            #[serde(default)]
            a: Vec<Vec<String>>,
        }
        let resp: Resp = self.client.get_json(url).await?;
        Ok(Some(OrderBookSnapshot {
            source: "bybit".to_string(),
            bids: parse_string_levels(&resp.result.b),
            asks: parse_string_levels(&resp.result.a),
            tick_size: tick_size_for("bybit"),
        }))
    }
    fn name(&self) -> &'static str {
        "bybit"
    }
}

pub struct OkxBook {
    client: HttpClient,
}
impl OkxBook {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }
}
#[async_trait::async_trait]
impl OrderBookSource for OkxBook {
    async fn fetch_orderbook(&self) -> Result<Option<OrderBookSnapshot>> {
        let url = "https://www.okx.com/api/v5/market/books?instId=KAS-USDT&sz=20";
        #[derive(serde::Deserialize)]
        struct Resp {
            #[serde(default)]
            data: Vec<BookData>,
        }
        #[derive(serde::Deserialize)]
        struct BookData {
            #[serde(default)]
            bids: Vec<Vec<String>>,
            #[serde(default)]
            asks: Vec<Vec<String>>,
        }
        let resp: Resp = self.client.get_json(url).await?;
        let data = resp
            .data
            .first()
            .ok_or_else(|| eyre::eyre!("okx: empty data"))?;
        Ok(Some(OrderBookSnapshot {
            source: "okx".to_string(),
            bids: parse_string_levels(&data.bids),
            asks: parse_string_levels(&data.asks),
            tick_size: tick_size_for("okx"),
        }))
    }
    fn name(&self) -> &'static str {
        "okx"
    }
}

pub struct BitgetBook {
    client: HttpClient,
}
impl BitgetBook {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }
}
#[async_trait::async_trait]
impl OrderBookSource for BitgetBook {
    async fn fetch_orderbook(&self) -> Result<Option<OrderBookSnapshot>> {
        let url = "https://api.bitget.com/api/v2/spot/market/orderbook?symbol=KASUSDT&limit=20";
        #[derive(serde::Deserialize)]
        struct Resp {
            #[serde(default)]
            data: Option<BookData>,
        }
        #[derive(serde::Deserialize)]
        struct BookData {
            #[serde(default)]
            bids: Vec<Vec<String>>,
            #[serde(default)]
            asks: Vec<Vec<String>>,
        }
        let resp: Resp = self.client.get_json(url).await?;
        let data = resp.data.ok_or_else(|| eyre::eyre!("bitget: empty data"))?;
        Ok(Some(OrderBookSnapshot {
            source: "bitget".to_string(),
            bids: parse_string_levels(&data.bids),
            asks: parse_string_levels(&data.asks),
            tick_size: tick_size_for("bitget"),
        }))
    }
    fn name(&self) -> &'static str {
        "bitget"
    }
}

pub struct GateioBook {
    client: HttpClient,
}
impl GateioBook {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }
}
#[async_trait::async_trait]
impl OrderBookSource for GateioBook {
    async fn fetch_orderbook(&self) -> Result<Option<OrderBookSnapshot>> {
        let url = "https://api.gateio.ws/api/v4/spot/order_book?currency_pair=KAS_USDT&limit=20";
        let resp: serde_json::Value = self.client.get_json(url).await?;
        Ok(Some(OrderBookSnapshot {
            source: "gateio".to_string(),
            bids: parse_levels(resp.get("bids"))?,
            asks: parse_levels(resp.get("asks"))?,
            tick_size: tick_size_for("gateio"),
        }))
    }
    fn name(&self) -> &'static str {
        "gateio"
    }
}

pub struct MexcBook {
    client: HttpClient,
}
impl MexcBook {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }
}
#[async_trait::async_trait]
impl OrderBookSource for MexcBook {
    async fn fetch_orderbook(&self) -> Result<Option<OrderBookSnapshot>> {
        let url = "https://api.mexc.com/api/v3/depth?symbol=KASUSDT&limit=20";
        let resp: serde_json::Value = self.client.get_json(url).await?;
        Ok(Some(OrderBookSnapshot {
            source: "mexc".to_string(),
            bids: parse_levels(resp.get("bids"))?,
            asks: parse_levels(resp.get("asks"))?,
            tick_size: tick_size_for("mexc"),
        }))
    }
    fn name(&self) -> &'static str {
        "mexc"
    }
}

pub struct KucoinBook {
    client: HttpClient,
}
impl KucoinBook {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }
}
#[async_trait::async_trait]
impl OrderBookSource for KucoinBook {
    async fn fetch_orderbook(&self) -> Result<Option<OrderBookSnapshot>> {
        let url = "https://api.kucoin.com/api/v1/market/orderbook/level2_20?symbol=KAS-USDT";
        #[derive(serde::Deserialize)]
        struct Resp {
            #[serde(default)]
            data: Option<BookData>,
        }
        #[derive(serde::Deserialize)]
        struct BookData {
            #[serde(default)]
            bids: Vec<Vec<String>>,
            #[serde(default)]
            asks: Vec<Vec<String>>,
        }
        let resp: Resp = self.client.get_json(url).await?;
        let data = resp.data.ok_or_else(|| eyre::eyre!("kucoin: empty data"))?;
        Ok(Some(OrderBookSnapshot {
            source: "kucoin".to_string(),
            bids: parse_string_levels(&data.bids),
            asks: parse_string_levels(&data.asks),
            tick_size: tick_size_for("kucoin"),
        }))
    }
    fn name(&self) -> &'static str {
        "kucoin"
    }
}

pub struct HtxBook {
    client: HttpClient,
}
impl HtxBook {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }
}
#[async_trait::async_trait]
impl OrderBookSource for HtxBook {
    async fn fetch_orderbook(&self) -> Result<Option<OrderBookSnapshot>> {
        let url = "https://api.huobi.pro/market/depth?symbol=kasusdt&type=step0&depth=20";
        #[derive(serde::Deserialize)]
        struct Resp {
            #[serde(default)]
            tick: Option<HtxTick>,
        }
        #[derive(serde::Deserialize)]
        struct HtxTick {
            #[serde(default)]
            bids: Vec<Vec<f64>>,
            #[serde(default)]
            asks: Vec<Vec<f64>>,
        }
        let resp: Resp = self.client.get_json(url).await?;
        let tick = resp.tick.ok_or_else(|| eyre::eyre!("htx: no tick"))?;
        let bids = tick
            .bids
            .iter()
            .filter(|v| v.len() >= 2 && v[0] > 0.0 && v[1] > 0.0)
            .map(|v| Level {
                price: v[0],
                quantity: v[1],
            })
            .collect();
        let asks = tick
            .asks
            .iter()
            .filter(|v| v.len() >= 2 && v[0] > 0.0 && v[1] > 0.0)
            .map(|v| Level {
                price: v[0],
                quantity: v[1],
            })
            .collect();
        Ok(Some(OrderBookSnapshot {
            source: "htx".to_string(),
            bids,
            asks,
            tick_size: tick_size_for("htx"),
        }))
    }
    fn name(&self) -> &'static str {
        "htx"
    }
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

fn parse_levels(val: Option<&serde_json::Value>) -> Result<Vec<Level>> {
    let arr = match val {
        Some(serde_json::Value::Array(a)) => a,
        _ => return Ok(vec![]),
    };
    let mut levels = Vec::with_capacity(arr.len());
    for entry in arr {
        if let serde_json::Value::Array(pair) = entry {
            if pair.len() >= 2 {
                let p = parse_json_f64(&pair[0]);
                let q = parse_json_f64(&pair[1]);
                if let (Some(p), Some(q)) = (p, q) {
                    if p > 0.0 && q > 0.0 {
                        levels.push(Level {
                            price: p,
                            quantity: q,
                        });
                    }
                }
            }
        }
    }
    Ok(levels)
}

fn parse_json_f64(v: &serde_json::Value) -> Option<f64> {
    match v {
        serde_json::Value::String(s) => s.parse().ok(),
        serde_json::Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

fn parse_string_levels(data: &[Vec<String>]) -> Vec<Level> {
    data.iter()
        .filter(|v| v.len() >= 2)
        .filter_map(|v| {
            let price: f64 = v[0].parse().ok()?;
            let qty: f64 = v[1].parse().ok()?;
            if price > 0.0 && qty > 0.0 {
                Some(Level {
                    price,
                    quantity: qty,
                })
            } else {
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_book(source: &str, bids: &[(f64, f64)], asks: &[(f64, f64)]) -> OrderBookSnapshot {
        OrderBookSnapshot {
            source: source.to_string(),
            bids: bids
                .iter()
                .map(|&(p, q)| Level {
                    price: p,
                    quantity: q,
                })
                .collect(),
            asks: asks
                .iter()
                .map(|&(p, q)| Level {
                    price: p,
                    quantity: q,
                })
                .collect(),
            tick_size: 0.00001,
        }
    }

    #[test]
    fn test_no_overlap() {
        let books = vec![
            make_book("binance", &[(0.03100, 1000.0)], &[(0.03102, 1000.0)]),
            make_book("bybit", &[(0.03099, 500.0)], &[(0.03103, 500.0)]),
        ];
        let fv = consolidated_order_book(&books).unwrap();
        assert!((fv.best_bid - 0.03100).abs() < 0.0001);
        assert!((fv.best_ask - 0.03102).abs() < 0.0001);
        assert!((fv.price - 0.03101).abs() < 0.0001);
        assert_eq!(fv.num_sources, 2);
    }

    #[test]
    fn test_arbitrage_clearing() {
        // Venue A: bid 0.03101. Venue B: ask 0.03100. Overlap → clear.
        let books = vec![
            make_book("a", &[(0.03101, 500.0)], &[(0.03103, 1000.0)]),
            make_book("b", &[(0.03099, 1000.0)], &[(0.03100, 500.0)]),
        ];
        let fv = consolidated_order_book(&books).unwrap();
        assert!(fv.best_bid < 0.03100);
        assert!(fv.best_ask > 0.03102);
    }

    #[test]
    fn test_grid_gcd() {
        let books = vec![
            OrderBookSnapshot {
                source: "a".to_string(),
                bids: vec![],
                asks: vec![],
                tick_size: 0.0001,
            },
            OrderBookSnapshot {
                source: "b".to_string(),
                bids: vec![],
                asks: vec![],
                tick_size: 0.00005,
            },
        ];
        let grid = compute_common_grid(&books);
        assert!(
            (grid - 0.00005).abs() < 1e-10,
            "grid {} should be 0.00005",
            grid
        );
    }

    #[test]
    fn test_empty_books() {
        let books: Vec<OrderBookSnapshot> = vec![];
        assert!(consolidated_order_book(&books).is_none());
    }

    fn book_with_depth(source: &str, levels: usize) -> OrderBookSnapshot {
        let bids: Vec<(f64, f64)> = (0..levels)
            .map(|i| (0.03100 - (i as f64) * 0.00001, 1000.0))
            .collect();
        let asks: Vec<(f64, f64)> = (0..levels)
            .map(|i| (0.03102 + (i as f64) * 0.00001, 1000.0))
            .collect();
        make_book(source, &bids, &asks)
    }

    #[test]
    fn test_reject_crossed_book() {
        let mut b = book_with_depth("bad", 5);
        b.bids[0].price = 0.03110;
        b.asks[0].price = 0.03100;
        assert!(!is_book_usable(&b));
    }

    #[test]
    fn test_reject_touching_book() {
        let mut b = book_with_depth("bad", 5);
        b.bids[0].price = 0.03101;
        b.asks[0].price = 0.03101;
        assert!(!is_book_usable(&b));
    }

    #[test]
    fn test_reject_shallow_book() {
        let b = book_with_depth("thin", 2);
        assert!(!is_book_usable(&b));
    }

    #[test]
    fn test_reject_wide_spread() {
        // 0.03000 bid / 0.03500 ask → spread ≈ 1538 bps > 500 bps cap
        let b = make_book(
            "wide",
            &[(0.03000, 100.0), (0.02999, 100.0), (0.02998, 100.0)],
            &[(0.03500, 100.0), (0.03501, 100.0), (0.03502, 100.0)],
        );
        assert!(!is_book_usable(&b));
    }

    #[test]
    fn test_accept_healthy_book() {
        let b = book_with_depth("good", 5);
        assert!(is_book_usable(&b));
    }

    #[test]
    fn test_determinism() {
        // Same input → identical output (critical for TEE signature determinism).
        let books = vec![
            make_book("binance", &[(0.03100, 1000.0)], &[(0.03102, 1000.0)]),
            make_book("okx", &[(0.03099, 500.0)], &[(0.03103, 500.0)]),
            make_book("bybit", &[(0.03101, 200.0)], &[(0.03104, 200.0)]),
        ];
        let fv1 = consolidated_order_book(&books).unwrap();
        let fv2 = consolidated_order_book(&books).unwrap();
        assert_eq!(fv1.price.to_bits(), fv2.price.to_bits());
        assert_eq!(fv1.best_bid.to_bits(), fv2.best_bid.to_bits());
        assert_eq!(fv1.best_ask.to_bits(), fv2.best_ask.to_bits());
    }
}
