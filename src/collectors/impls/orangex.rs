//! OrangeX spot collector — `cex_data/orangex/ob.py` reference.
//!
//! Channel: `book.{instrument}.raw` on `wss://api.orangex.com/ws/api/v1`.
//! JSON-RPC 2.0 transport. **REST snapshot bootstrap is mandatory** —
//! the WS does not push an initial snapshot, only deltas. The REST `version`
//! and the WS `change_id` share a sequence space.
//!
//! Each delta entry is `[action, price, size]` where action ∈ `{new, change, delete}`.
//! `delete` (or size==0) removes the level.
//!
//! Live continuity: `change_id == local + 1` ⇒ apply, else gap ⇒ reconnect.
//! Ping `{"jsonrpc":"2.0","method":"/public/ping"}` every 5s.
//!
//! Symbol naming quirk: REST + book WS take `BTC-USDT`, NOT `BTC-USDT-SPOT`.

use crate::cob_common::ExchangeConfig;
use crate::collectors::book::LocalBook;
use crate::collectors::collector::Collector;
use crate::collectors::rest::HTTP;
use crate::collectors::sink::BookSink;
use crate::collectors::util::{now_ms, parse_f64, parse_u64, ws_connect};
use async_trait::async_trait;
use eyre::{eyre, Result, WrapErr};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

const REST_BASE: &str = "https://api.orangex.com";
const PING_INTERVAL: Duration = Duration::from_secs(5);
const PRELUDE_BUFFER_TIMEOUT: Duration = Duration::from_secs(3);
const PRELUDE_BUFFER_MIN: usize = 3;

pub struct Orangex {
    config: ExchangeConfig,
}

impl Orangex {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn fetch_snapshot(&self, symbol: &str) -> Result<RestSnapshot> {
        let url =
            format!("{REST_BASE}/api/v1/public/get_order_book?instrument_name={symbol}&depth=100");
        let v: Value = HTTP
            .get(&url)
            .send()
            .await
            .wrap_err_with(|| format!("orangex REST {symbol}"))?
            .error_for_status()?
            .json()
            .await?;
        let result = v.get("result").ok_or_else(|| eyre!("missing result"))?;
        let version = result
            .get("version")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| eyre!("missing version"))?;
        let bids = parse_simple(result.get("bids"));
        let asks = parse_simple(result.get("asks"));
        Ok(RestSnapshot {
            version,
            bids,
            asks,
        })
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[orangex] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        let channels: Vec<String> = self
            .config
            .pairs
            .iter()
            .map(|p| format!("book.{}.raw", p.to_uppercase()))
            .collect();
        ws.send(Message::Text(
            json!({
                "jsonrpc":"2.0","id":1,
                "method":"/public/subscribe",
                "params":{"channels": channels},
            })
            .to_string(),
        ))
        .await?;

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| {
                let key = p.to_uppercase();
                (key.clone(), LocalBook::new("orangex", key))
            })
            .collect();
        let mut prelude: HashMap<String, VecDeque<OrangeDelta>> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.to_uppercase(), VecDeque::new()))
            .collect();

        let (mut write, mut read) = ws.split();

        // Phase 1: buffer prelude.
        let deadline = tokio::time::Instant::now() + PRELUDE_BUFFER_TIMEOUT;
        loop {
            if prelude.values().all(|q| q.len() >= PRELUDE_BUFFER_MIN) {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                debug!("[orangex] prelude deadline");
                break;
            }
            let to = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(to, read.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    if let Some((sym, d)) = parse_book_event(&text) {
                        prelude.entry(sym).or_default().push_back(d);
                    }
                }
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(e))) => return Err(eyre!("WS error: {e}")),
                Ok(None) => return Err(eyre!("WS closed")),
                Err(_) => break,
            }
        }

        // Phase 2: REST snapshot per pair, then reconcile prelude. On a
        // bootstrap-gap we refetch the snapshot once; persistent gap aborts
        // the session so the manager re-spawns after backoff. Mirrors the
        // Binance pattern (see binance.rs). OrangeX deltas carry a single
        // `change_id` (not a U/u range), so the first applied event must be
        // exactly `snap.version + 1`.
        for pair in self.config.pairs.iter().map(|p| p.to_uppercase()) {
            let book = books.get_mut(&pair).expect("book");
            for attempt in 0..2 {
                let snap = self.fetch_snapshot(&pair).await.wrap_err_with(|| {
                    format!("orangex bootstrap {pair} (attempt {})", attempt + 1)
                })?;
                book.apply_snapshot(snap.bids, snap.asks, Some(snap.version));
                let buf = prelude.get_mut(&pair).expect("buf");
                let drained = std::mem::take(buf);
                match reconcile_prelude(book, snap.version, drained) {
                    Ok(applied) => {
                        info!(
                            "[orangex/{pair}] bootstrapped (version={}, applied {applied})",
                            snap.version
                        );
                        break;
                    }
                    Err(BootstrapGap { first_seen }) => {
                        warn!(
                            "[orangex/{pair}] bootstrap gap (change_id={} > snap+1={}) attempt {}",
                            first_seen,
                            snap.version + 1,
                            attempt + 1
                        );
                        if attempt == 1 {
                            return Err(eyre!("[orangex/{pair}] persistent bootstrap gap"));
                        }
                    }
                }
            }
        }

        // Phase 3: live + ping.
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.tick().await;
        loop {
            tokio::select! {
                msg = read.next() => {
                    let received_at = now_ms();
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            let Some((sym, d)) = parse_book_event(&text) else { continue };
                            let Some(book) = books.get_mut(&sym) else { continue };
                            let Some(local) = book.seq else { continue };
                            if d.change_id <= local { continue; }
                            if d.change_id != local + 1 {
                                warn!("[orangex/{sym}] gap (change_id={}, expected {}), reconnecting",
                                      d.change_id, local + 1);
                                return Err(eyre!("orangex gap"));
                            }
                            book.apply_deltas(d.bids, d.asks, Some(d.change_id));
                            if !book.is_crossed() {
                                if let Some(d) = book.to_orderbook_data(d.timestamp, received_at) {
                                    sink.emit(d);
                                }
                            }
                        }
                        Some(Ok(Message::Ping(p))) => { let _ = write.send(Message::Pong(p)).await; }
                        Some(Ok(Message::Close(_))) | None => return Err(eyre!("WS closed")),
                        Some(Err(e)) => return Err(eyre!("WS error: {e}")),
                        _ => {}
                    }
                }
                _ = ping.tick() => {
                    if write.send(Message::Text(json!({
                        "jsonrpc":"2.0","id":0,"method":"/public/ping","params":{}
                    }).to_string())).await.is_err() {
                        return Err(eyre!("ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Orangex {
    fn id(&self) -> &str {
        "orangex"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[orangex] no pairs"));
        }
        sink.status("orangex", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

struct RestSnapshot {
    version: u64,
    bids: Vec<(f64, f64)>,
    asks: Vec<(f64, f64)>,
}

#[derive(Debug)]
struct OrangeDelta {
    change_id: u64,
    timestamp: i64,
    bids: Vec<(f64, f64)>,
    asks: Vec<(f64, f64)>,
}

/// Pure reconciliation step extracted for testability. Drains `prelude` into
/// `book`. OrangeX deltas carry a single `change_id`, so the first applied
/// event MUST equal `snap_anchor + 1`. Stale events (`change_id <= snap_anchor`)
/// are dropped silently; any larger jump on the first applied event is a gap
/// and clears the book so the caller can re-snapshot.
#[derive(Debug)]
struct BootstrapGap {
    first_seen: u64,
}

fn reconcile_prelude(
    book: &mut LocalBook,
    snap_anchor: u64,
    mut prelude: VecDeque<OrangeDelta>,
) -> std::result::Result<usize, BootstrapGap> {
    let mut applied = 0usize;
    while let Some(d) = prelude.pop_front() {
        if d.change_id <= snap_anchor {
            continue;
        }
        if applied == 0 && d.change_id > snap_anchor + 1 {
            book.clear();
            return Err(BootstrapGap {
                first_seen: d.change_id,
            });
        }
        book.apply_deltas(d.bids, d.asks, Some(d.change_id));
        applied += 1;
    }
    Ok(applied)
}

fn parse_book_event(text: &str) -> Option<(String, OrangeDelta)> {
    let v: Value = serde_json::from_str(text).ok()?;
    if v.get("method")?.as_str()? != "subscription" {
        return None;
    }
    let params = v.get("params")?;
    let data = params.get("data")?;
    let symbol = data.get("instrument_name")?.as_str()?.to_uppercase();
    let change_id = parse_u64(data.get("change_id")?)?;
    let timestamp = data.get("timestamp").and_then(|x| x.as_i64()).unwrap_or(0);
    let bids = parse_action_levels(data.get("bids"));
    let asks = parse_action_levels(data.get("asks"));
    Some((
        symbol,
        OrangeDelta {
            change_id,
            timestamp,
            bids,
            asks,
        },
    ))
}

/// Action-prefixed levels: `[action, price, size]`. `delete`/size=0 ⇒ qty 0.
fn parse_action_levels(v: Option<&Value>) -> Vec<(f64, f64)> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|row| {
            let r = row.as_array()?;
            let action = r.first()?.as_str()?;
            let price = parse_f64(r.get(1)?)?;
            let size = parse_f64(r.get(2)?)?;
            if action == "delete" {
                Some((price, 0.0))
            } else {
                Some((price, size))
            }
        })
        .collect()
}

fn parse_simple(v: Option<&Value>) -> Vec<(f64, f64)> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|row| {
            let r = row.as_array()?;
            Some((parse_f64(r.first()?)?, parse_f64(r.get(1)?)?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_action_levels_handles_delete() {
        let raw = r#"[["new","100","1.5"],["delete","99","0"],["change","101","2.0"]]"#;
        let v: Value = serde_json::from_str(raw).unwrap();
        let lv = parse_action_levels(Some(&v));
        assert_eq!(lv, vec![(100.0, 1.5), (99.0, 0.0), (101.0, 2.0)]);
    }

    #[test]
    fn parse_subscription_event() {
        let s = r#"{"jsonrpc":"2.0","method":"subscription","params":{"channel":"book.BTC-USDT.raw","data":{"timestamp":1,"change_id":42,"instrument_name":"BTC-USDT","bids":[["new","100","1"]],"asks":[]}}}"#;
        let (sym, d) = parse_book_event(s).unwrap();
        assert_eq!(sym, "BTC-USDT");
        assert_eq!(d.change_id, 42);
        assert_eq!(d.bids, vec![(100.0, 1.0)]);
    }

    fn test_delta(change_id: u64) -> OrangeDelta {
        OrangeDelta {
            change_id,
            timestamp: 0,
            bids: vec![(100.0, 1.0)],
            asks: vec![(101.0, 1.0)],
        }
    }

    #[test]
    fn reconcile_filters_stale_first_event_below_snap() {
        let mut book = LocalBook::new("orangex", "BTC-USDT");
        book.apply_snapshot([(100.0, 5.0)], [(101.0, 5.0)], Some(100));
        // Stale events (<=100) must be filtered, then 101 (snap+1) applies.
        let mut q = VecDeque::new();
        q.push_back(test_delta(99));
        q.push_back(test_delta(100));
        q.push_back(test_delta(101));
        q.push_back(test_delta(102));
        let applied = reconcile_prelude(&mut book, 100, q).expect("no gap");
        assert_eq!(applied, 2);
        assert_eq!(book.seq, Some(102));
    }

    #[test]
    fn reconcile_detects_gap_when_first_event_above_snap_plus_one() {
        let mut book = LocalBook::new("orangex", "BTC-USDT");
        book.apply_snapshot([(100.0, 5.0)], [(101.0, 5.0)], Some(100));
        // First applied event jumps to change_id=103 (>= snap+2): gap.
        let mut q = VecDeque::new();
        q.push_back(test_delta(103));
        let err = reconcile_prelude(&mut book, 100, q).unwrap_err();
        assert_eq!(err.first_seen, 103);
        // Book is cleared so the caller can re-snapshot.
        assert!(book.seq.is_none());
        assert!(book.bids.is_empty() && book.asks.is_empty());
    }
}
