//! Consolidated Order Book (Algorithm 1, Mea/KEF): GCD-grid projection,
//! cross-venue arbitrage clearing, fair mid-price. Pure compute, no I/O.
//! Inputs come from `cob_state`, populated by the WS collector layer.
//!
//! USD pricing assumption (audit C-2).
//! ---
//! Every feed in `config/exchanges.json` is USDT-quoted (`BTC/USDT`, `ETH/USDT`,
//! `USDC/USDT`, `KAS/USDT`). The oracle publishes them under USD names
//! (`BTC/USD`, ...). This rebroadcast is honest *only as long as USDT ≈ USD*.
//! If USDT depegs (Mar-2023 USDC, May-2022 UST are precedents), an
//! unguarded oracle would silently lie. To detect that, the consumer
//! must read `probe_usdc_mid` before publishing USD-named prices: USDC
//! is itself USDT-quoted, so its consolidated mid is a direct USDT/USD
//! proxy. If it strays from 1.0 beyond a tolerance, fail closed.

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
    /// Normalised base ticker (`BTC`, `ETH`, ...). Filled in by
    /// `read_books_from_state`; tests build it directly. Used by the
    /// per-book spread gate to pick the right tolerance (audit M-4).
    pub base_asset: String,
    pub bids: Vec<Level>,
    pub asks: Vec<Level>,
    pub tick_size: f64,
    /// Best-effort exchange-side timestamp in unix-ms, or the local
    /// receive time if the venue's payload had no usable timestamp
    /// (audit C-3 / M-1: the main loop signs with the median of these,
    /// never the host wall clock).
    pub exchange_timestamp_ms: i64,
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
/// Fallback spread cap for bases not enumerated below. Anything wider than
/// 5 % is almost certainly stale or manipulated — keep it as a generous
/// last-resort gate, not a regular operating point. Audit M-4.
const MAX_SPREAD_BPS_DEFAULT: f64 = 500.0;

/// Per-base spread cap. Honest top-of-book on major-CEX BTC/ETH/USDC stays
/// well under 10 bps; a compromised venue can otherwise pad the spread
/// up to MAX_SPREAD_BPS_DEFAULT and still pass sanity. These tighter caps
/// reject manipulation early — at the per-book gate — instead of letting
/// it land in the consolidated grid.
fn max_spread_bps_for(base: &str) -> f64 {
    match base {
        "BTC" | "ETH" => 30.0,
        "USDC" => 20.0,
        "KAS" => 100.0,
        _ => MAX_SPREAD_BPS_DEFAULT,
    }
}

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
    let max_spread_bps = max_spread_bps_for(&book.base_asset);
    if spread_bps > max_spread_bps {
        warn!(
            source = book.source.as_str(),
            base = book.base_asset.as_str(),
            spread_bps,
            max_spread_bps,
            "rejected: spread too wide"
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
    let symbol_filter = asset_to_collector_symbol(asset);
    if symbol_filter.is_empty() {
        return Vec::new();
    }
    read_books_filtered(symbol_filter, state).await
}

/// Lower-level reader used by both `read_books_from_state` and the
/// USDT-peg gate. Takes the base ticker filter directly (`"USDC"`,
/// `"BTC"`, ...) so we don't need a synthetic `AssetConfig`.
async fn read_books_filtered(
    symbol_filter: &str,
    state: &SharedBookState,
) -> Vec<OrderBookSnapshot> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let guard = state.read().await;
    let mut snapshots: Vec<OrderBookSnapshot> = guard
        .values()
        .filter(|book: &&OrderBookData| {
            extract_base_asset(&book.symbol) == symbol_filter
                && fresh_book_age_ms(now_ms, book.received_timestamp)
                && !book.bids.is_empty()
                && !book.asks.is_empty()
        })
        .map(|book| {
            let base = extract_base_asset(&book.symbol);
            // Prefer the exchange's own timestamp; fall back to the local
            // receive time only when the venue didn't give us one. NEVER
            // host wall clock — audit C-3.
            let ts_ms = if book.exchange_timestamp > 0 {
                book.exchange_timestamp
            } else {
                book.received_timestamp
            };
            OrderBookSnapshot {
                source: book.exchange_id.clone(),
                tick_size: tick_size_for(&book.exchange_id, &base),
                base_asset: base,
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
                exchange_timestamp_ms: ts_ms,
            }
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
// USDT-peg gate (audit C-2)
// ---------------------------------------------------------------------------

/// Tolerance for the USDC/USDT proxy used as a USDT-peg sentinel.
/// 50 bps = 0.50 % drift from $1.00 is the line at which we refuse to
/// publish USD-named prices that are actually USDT-quoted.
pub const MAX_USDT_DEPEG_BPS: f64 = 50.0;

/// Run a COB pass on USDC books (which are USDT-quoted) and return the
/// consolidated mid. Returns `None` when fewer than `min_sources` books
/// are usable — the caller decides whether that means "wait and retry"
/// or "fail closed".
pub async fn probe_usdc_mid(state: &SharedBookState, min_sources: usize) -> Option<f64> {
    let books = read_books_filtered("USDC", state).await;
    if books.len() < min_sources {
        return None;
    }
    consolidated_order_book(&books).map(|fv| fv.price)
}

/// `Ok(mid)` if the USDT peg holds within `MAX_USDT_DEPEG_BPS`; otherwise
/// `Err(observed_mid)` so the caller can log what it saw. `None` propagates
/// when there aren't enough USDC sources yet — fail-closed at the caller.
pub async fn usdt_peg_ok(state: &SharedBookState, min_sources: usize) -> Option<Result<f64, f64>> {
    let mid = probe_usdc_mid(state, min_sources).await?;
    let drift_bps = (mid - 1.0).abs() * 10_000.0;
    if drift_bps <= MAX_USDT_DEPEG_BPS {
        Some(Ok(mid))
    } else {
        Some(Err(mid))
    }
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
            base_asset: "KAS".to_string(),
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
            exchange_timestamp_ms: 0,
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
                base_asset: "KAS".into(),
                bids: vec![],
                asks: vec![],
                tick_size: 0.0001,
                exchange_timestamp_ms: 0,
            },
            OrderBookSnapshot {
                source: "b".to_string(),
                base_asset: "KAS".into(),
                bids: vec![],
                asks: vec![],
                tick_size: 0.00005,
                exchange_timestamp_ms: 0,
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
    fn btc_book_rejected_at_40bps_spread() {
        // Audit M-4: BTC tolerance is 30 bps; 40 bps must be rejected.
        // Builds a BTC book directly (cap-per-base lookup goes via
        // `base_asset` on the snapshot).
        let mut b = make_book(
            "spoofer",
            &[(50_000.0, 1.0), (49_999.0, 1.0), (49_998.0, 1.0)],
            &[(50_200.0, 1.0), (50_201.0, 1.0), (50_202.0, 1.0)],
        );
        b.base_asset = "BTC".to_string();
        // (50200-50000)/50100 ≈ 40 bps.
        assert!(!is_book_usable(&b));
    }

    #[test]
    fn btc_book_accepted_at_20bps_spread() {
        let mut b = make_book(
            "honest",
            &[(50_000.0, 1.0), (49_999.0, 1.0), (49_998.0, 1.0)],
            &[(50_100.0, 1.0), (50_101.0, 1.0), (50_102.0, 1.0)],
        );
        b.base_asset = "BTC".to_string();
        // (50100-50000)/50050 ≈ 20 bps — under the 30 bps cap.
        assert!(is_book_usable(&b));
    }

    #[test]
    fn unknown_base_falls_back_to_500bps_default() {
        // 200 bps would be rejected for BTC but accepted for an unknown base.
        let mut b = make_book(
            "wat",
            &[(100.0, 1.0), (99.5, 1.0), (99.0, 1.0)],
            &[(102.0, 1.0), (102.5, 1.0), (103.0, 1.0)],
        );
        b.base_asset = "ZZZZ".to_string();
        // (102-100)/101 ≈ 198 bps.
        assert!(is_book_usable(&b));
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
    fn symbol_filter_does_not_t_strip_uppercase_tokens() {
        // Audit C-1: tokens that legitimately begin with `T` MUST NOT
        // collapse into their would-be base. Bitfinex's `tBTCUSD`-style
        // pairs are normalised inside the bitfinex collector before
        // reaching this function — see `strip_bitfinex_t_prefix`.
        assert_ne!(extract_base_asset("TBTC/USDT"), "BTC");
        assert_ne!(extract_base_asset("TBTCUSDT"), "BTC");
        assert_ne!(extract_base_asset("TUSDC/USDT"), "USDC");
        assert_ne!(extract_base_asset("TUSDCUSDT"), "USDC");
        assert_ne!(extract_base_asset("TUSDUSDT"), "USD");
    }

    #[test]
    fn symbol_filter_normalised_bitfinex_pair_matches_base() {
        // After bitfinex collector strips the lowercase `t`, the symbol
        // that lands in cob_state is `BTCUSD` — and that DOES resolve.
        assert_eq!(extract_base_asset("BTCUSD"), "BTC");
        assert_eq!(extract_base_asset("ETHUSD"), "ETH");
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

    use crate::cob_common::{OrderBookData, PriceLevel};
    use crate::cob_state::{insert, new_shared};

    fn usdc_book(ex: &str, mid: f64) -> OrderBookData {
        let now = chrono::Utc::now().timestamp_millis();
        // Five levels deep on each side, 1 bp spread either way around `mid`.
        let bid_base = mid * 0.99995;
        let ask_base = mid * 1.00005;
        let bids = (0..5)
            .map(|i| PriceLevel {
                price: bid_base - (i as f64) * 1e-4,
                quantity: 1000.0,
            })
            .collect();
        let asks = (0..5)
            .map(|i| PriceLevel {
                price: ask_base + (i as f64) * 1e-4,
                quantity: 1000.0,
            })
            .collect();
        OrderBookData {
            exchange_id: ex.into(),
            symbol: "USDCUSDT".into(),
            exchange_timestamp: now,
            received_timestamp: now,
            latency: 0,
            bids,
            asks,
            node_id: None,
        }
    }

    #[tokio::test]
    async fn usdt_peg_ok_when_usdc_pegs() {
        let state = new_shared();
        for ex in ["binance", "okx", "bybit"] {
            insert(&state, usdc_book(ex, 1.0001)).await;
        }
        match usdt_peg_ok(&state, 3).await {
            Some(Ok(mid)) => assert!((mid - 1.0001).abs() < 0.001, "got {mid}"),
            other => panic!("expected Ok(~1.0001), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn usdt_peg_breaks_when_usdc_depegs_down() {
        // USDT pumps → USDC priced cheap against it. 200 bps drift > 50 bps cap.
        let state = new_shared();
        for ex in ["binance", "okx", "bybit"] {
            insert(&state, usdc_book(ex, 0.98)).await;
        }
        match usdt_peg_ok(&state, 3).await {
            Some(Err(mid)) => assert!((mid - 0.98).abs() < 0.001, "got {mid}"),
            other => panic!("expected Err(~0.98), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn usdt_peg_returns_none_below_min_sources() {
        let state = new_shared();
        insert(&state, usdc_book("binance", 1.0)).await;
        // Only 1 source — below the min of 3.
        assert!(usdt_peg_ok(&state, 3).await.is_none());
    }
}
