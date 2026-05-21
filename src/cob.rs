//! Consolidated Order Book (Algorithm 1, Mea/KEF): GCD-grid projection,
//! cross-venue arbitrage clearing, fair mid-price. Pure compute, no I/O.
//! Inputs come from `cob_state`, populated by the WS collector layer.

use std::collections::BTreeMap;

use tracing::warn;

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
#[allow(dead_code)] // best_bid / best_ask kept for downstream introspection.
pub struct FairValue {
    pub price: f64,
    pub best_bid: f64,
    pub best_ask: f64,
    pub spread_bps: f64,
    pub num_sources: usize,
}

// ---------------------------------------------------------------------------
// Per-exchange / per-asset tick sizes
// ---------------------------------------------------------------------------

/// Per-(exchange, base) price-tick used to build the consolidated grid.
/// Fallback returns the per-base default when the venue is not listed.
fn tick_size_for(source: &str, base_asset: &str) -> f64 {
    // BTC: 0.01 USD on almost every major CEX; bitget uses 0.1 USD; a
    // handful of small venues use 1e-6 as a generic.
    let btc = matches!(
        source,
        "binance"
            | "bybit"
            | "okx"
            | "kucoin"
            | "mexc"
            | "kraken"
            | "coinbase"
            | "cryptocom"
            | "htx"
            | "gate"
            | "gateio"
            | "bingx"
            | "bitmart"
            | "whitebit"
            | "poloniex"
            | "ascendex"
            | "xt"
            | "phemex"
            | "lbank"
            | "weex"
            | "orangex"
            | "bitfinex"
            | "biconomy"
            | "coinstore"
    );

    match base_asset {
        "BTC" if btc => 0.01,
        "BTC" if source == "bitget" => 0.1,
        "ETH" => match source {
            "bitget" => 0.01,
            _ => 0.01,
        },
        "KAS" => match source {
            "binance" | "bybit" | "kucoin" | "mexc" | "gate" | "gateio" | "bitget" | "htx"
            | "kraken" | "bingx" | "bitmart" | "whitebit" | "poloniex" | "ascendex" | "xt"
            | "phemex" | "lbank" | "weex" | "orangex" => 0.00001,
            _ => 0.00001,
        },
        "USDC" => match source {
            "binance" | "bybit" | "okx" | "kucoin" | "gate" | "gateio" | "mexc" | "kraken"
            | "cryptocom" => 0.0001,
            _ => 0.0001,
        },
        _ => {
            // Last-resort fallback: prefer 1e-5 for any unknown base on a
            // venue we know prices in fine increments; otherwise 1e-6.
            match source {
                "bybit" | "okx" | "bitget" | "kucoin" => 0.00001,
                _ => 0.000001,
            }
        }
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
// Per-book sanity filter
// ---------------------------------------------------------------------------

const MIN_BOOK_DEPTH: usize = 3;
const MAX_SPREAD_BPS: f64 = 500.0;

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

// ---------------------------------------------------------------------------
// State-backed source reader
// ---------------------------------------------------------------------------

use crate::cob_common::{extract_base_asset, OrderBookData};
use crate::cob_state::SharedBookState;
use crate::types::AssetConfig;

/// Max age (ms) for a book to count toward COB quorum.
const MAX_BOOK_AGE_MS: i64 = 5_000;

/// Closed range `[0, MAX_BOOK_AGE_MS]` so clock-skewed future timestamps
/// don't pass a naive `now - ts <= max` check.
fn fresh_book_age_ms(now_ms: i64, received_ts_ms: i64) -> bool {
    let age = now_ms - received_ts_ms;
    (0..=MAX_BOOK_AGE_MS).contains(&age)
}

/// Read all currently-fresh OrderBookData for `asset` from the shared
/// WS state, drop books that don't pass is_book_usable, sort by source
/// name for deterministic source_hash, and return.
pub async fn read_books_from_state(
    asset: &AssetConfig,
    state: &SharedBookState,
) -> Vec<OrderBookSnapshot> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let symbol_filter = asset_to_collector_symbol(asset);
    if symbol_filter.is_empty() {
        return Vec::new();
    }

    let guard = state.read().await;
    let mut snapshots: Vec<OrderBookSnapshot> = guard
        .values()
        .filter(|book: &&OrderBookData| {
            extract_base_asset(&book.symbol) == symbol_filter
                && fresh_book_age_ms(now_ms, book.received_timestamp)
                && !book.bids.is_empty()
                && !book.asks.is_empty()
        })
        .map(|book| OrderBookSnapshot {
            source: book.exchange_id.clone(),
            bids: book
                .bids
                .iter()
                .map(|l| Level {
                    price: l.price,
                    quantity: l.quantity,
                })
                .collect(),
            asks: book
                .asks
                .iter()
                .map(|l| Level {
                    price: l.price,
                    quantity: l.quantity,
                })
                .collect(),
            tick_size: tick_size_for(&book.exchange_id, &extract_base_asset(&book.symbol)),
        })
        .filter(is_book_usable)
        .collect();

    snapshots.sort_by(|a, b| a.source.cmp(&b.source));
    snapshots
}

/// Canonical asset symbol → base ticker. `""` for non-COB assets;
/// callers must check before using it as a filter.
pub fn asset_to_collector_symbol(asset: &AssetConfig) -> &'static str {
    match asset.symbol.as_str() {
        "BTC/USD" => "BTC",
        "ETH/USD" => "ETH",
        "KAS/USD" => "KAS",
        "USDC/USD" => "USDC",
        _ => "",
    }
}

/// True for BTC/ETH/KAS/USDC; everything else falls through to the
/// legacy REST aggregator in main.rs.
pub fn is_cob_asset(asset: &AssetConfig) -> bool {
    !asset_to_collector_symbol(asset).is_empty()
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
    fn symbol_filter_btc_matches_btc_usdt() {
        assert_eq!(extract_base_asset("BTC/USDT"), "BTC");
    }

    #[test]
    fn symbol_filter_btc_rejects_wbtc_usdt() {
        // WBTC should not slip through when the filter is "BTC".
        assert_ne!(extract_base_asset("WBTC/USDT"), "BTC");
    }

    #[test]
    fn symbol_filter_btc_rejects_ethbtc() {
        // ETHBTC has BTC as quote, not base; filter "BTC" must NOT match.
        assert_ne!(extract_base_asset("ETHBTC"), "BTC");
    }

    #[test]
    fn symbol_filter_btc_matches_bitfinex_tbtcusd() {
        // Bitfinex prefixes pairs with `t` (e.g. tBTCUSD); extract_base_asset
        // strips the leading lowercase t before normalising.
        assert_eq!(extract_base_asset("tBTCUSD"), "BTC");
    }

    #[test]
    fn fresh_book_age_accepts_recent_past() {
        let now = 1_700_000_000_000_i64;
        assert!(fresh_book_age_ms(now, now - 1_000));
    }

    #[test]
    fn fresh_book_age_accepts_now() {
        let now = 1_700_000_000_000_i64;
        assert!(fresh_book_age_ms(now, now));
    }

    #[test]
    fn fresh_book_age_rejects_future_timestamp() {
        let now = 1_700_000_000_000_i64;
        // received 1s in the future -> delta is negative -> reject.
        assert!(!fresh_book_age_ms(now, now + 1_000));
    }

    #[test]
    fn fresh_book_age_rejects_stale() {
        let now = 1_700_000_000_000_i64;
        assert!(!fresh_book_age_ms(now, now - (MAX_BOOK_AGE_MS + 1)));
    }

    #[test]
    fn test_determinism() {
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

    #[test]
    fn tick_btc_is_cent_on_major_cex() {
        for ex in [
            "binance",
            "bybit",
            "okx",
            "kucoin",
            "mexc",
            "kraken",
            "coinbase",
            "biconomy",
            "coinstore",
        ] {
            let t = tick_size_for(ex, "BTC");
            assert!(
                (t - 0.01).abs() < 1e-12,
                "BTC tick on {ex} should be 0.01, got {t}"
            );
        }
    }

    #[test]
    fn tick_kas_is_fine() {
        assert!((tick_size_for("binance", "KAS") - 0.00001).abs() < 1e-12);
        assert!((tick_size_for("mexc", "KAS") - 0.00001).abs() < 1e-12);
    }

    #[test]
    fn tick_usdc_is_basis_point() {
        for ex in ["binance", "okx", "kucoin", "kraken"] {
            let t = tick_size_for(ex, "USDC");
            assert!(
                (t - 0.0001).abs() < 1e-12,
                "USDC tick on {ex} should be 0.0001, got {t}"
            );
        }
    }

    #[test]
    fn tick_unknown_base_uses_fallback() {
        // unknown base, but a known venue with a fine tick -> 1e-5
        assert!((tick_size_for("bybit", "XYZ") - 0.00001).abs() < 1e-12);
        // truly unknown venue + unknown base -> 1e-6
        assert!((tick_size_for("noname", "XYZ") - 0.000001).abs() < 1e-12);
    }
}
