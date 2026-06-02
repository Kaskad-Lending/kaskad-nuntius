//! Binance spot collector.
//!
//! Protocol (mirrors the Python reference in `cex_data/binance/ob.py`):
//!   1. Open combined-stream WebSocket for all configured pairs:
//!      `wss://stream.binance.com:9443/stream?streams=btcusdt@depth@100ms/...`
//!   2. Buffer the first few diff-depth events.
//!   3. Per pair, fetch `GET /api/v3/depth?symbol=...&limit=5000` REST snapshot.
//!   4. Drop buffered events with `u <= lastUpdateId`.
//!   5. The first remaining event must satisfy `U <= lastUpdateId+1 <= u`,
//!      otherwise a gap occurred → re-fetch snapshot.
//!   6. Apply remaining buffered events, then live events from the WS.
//!   7. On any future gap (`U > last_u + 1`) → re-fetch the REST snapshot.
//!
//! All pairs share one TCP connection; per-pair state lives in `LocalBook`.

use crate::cob_common::ExchangeConfig;
use crate::collectors::book::LocalBook;
use crate::collectors::collector::Collector;
use crate::collectors::rest::HTTP;
use crate::collectors::sink::BookSink;
use crate::collectors::util::{
    now_ms, parse_f64, parse_u64, symbol_from_binance_stream, ws_connect,
};
use async_trait::async_trait;
use eyre::{eyre, Result, WrapErr};
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

const REST_BASE: &str = "https://api.binance.com";
const REST_DEPTH_LIMIT: u32 = 5000;
const PING_INTERVAL: Duration = Duration::from_secs(180);
const PRELUDE_BUFFER_MIN: usize = 5;
const PRELUDE_BUFFER_TIMEOUT: Duration = Duration::from_secs(3);

pub struct Binance {
    config: ExchangeConfig,
}

impl Binance {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    /// Combined-stream URL for all configured pairs.
    fn ws_url(&self) -> String {
        let streams: Vec<String> = self
            .config
            .pairs
            .iter()
            .map(|p| format!("{}@depth@100ms", p.to_lowercase()))
            .collect();
        format!(
            "{}/stream?streams={}",
            self.config.ws_url.trim_end_matches('/'),
            streams.join("/")
        )
    }

    async fn fetch_snapshot(&self, pair: &str) -> Result<RestSnapshot> {
        let url = format!(
            "{REST_BASE}/api/v3/depth?symbol={}&limit={REST_DEPTH_LIMIT}",
            pair.to_uppercase()
        );
        let v: Value = HTTP
            .get(&url)
            .send()
            .await
            .wrap_err_with(|| format!("REST snapshot {pair}"))?
            .error_for_status()?
            .json()
            .await?;

        let last_update_id = v
            .get("lastUpdateId")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| eyre!("snapshot {pair}: missing lastUpdateId"))?;

        let bids = parse_levels(v.get("bids"));
        let asks = parse_levels(v.get("asks"));
        Ok(RestSnapshot {
            last_update_id,
            bids,
            asks,
        })
    }

    /// One full session: connect, buffer prelude, snapshot per pair, stream.
    /// Returns `Err` on transient errors (caller will retry).
    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.ws_url();
        info!(
            "[binance] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // Per-pair state map. Books start un-bootstrapped; we fill them after REST fetch.
        let mut books: HashMap<String, LocalBook> = HashMap::new();
        for p in &self.config.pairs {
            let key = p.to_uppercase();
            books.insert(key.clone(), LocalBook::new("binance", key));
        }

        // Per-pair prelude buffer (events received before REST snapshot lands).
        let mut prelude: HashMap<String, VecDeque<DepthEvent>> = HashMap::new();
        for p in &self.config.pairs {
            prelude.insert(p.to_uppercase(), VecDeque::new());
        }

        // 1. Buffer prelude events. We aim for at least PRELUDE_BUFFER_MIN
        //    events per pair, but cap on a 3s deadline so a quiet pair doesn't
        //    block bootstrap of the others.
        let deadline = tokio::time::Instant::now() + PRELUDE_BUFFER_TIMEOUT;
        loop {
            if prelude.values().all(|q| q.len() >= PRELUDE_BUFFER_MIN) {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                debug!("[binance] prelude deadline reached, proceeding to snapshot");
                break;
            }
            let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(timeout, ws.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    if let Some((sym, ev)) = parse_combined_event(&text) {
                        prelude.entry(sym).or_default().push_back(ev);
                    }
                }
                Ok(Some(Ok(Message::Ping(p)))) => {
                    let _ = ws.send(Message::Pong(p)).await;
                }
                Ok(Some(Ok(_))) => {} // ignore other frames
                Ok(Some(Err(e))) => return Err(eyre!("WS error during prelude: {e}")),
                Ok(None) => return Err(eyre!("WS closed during prelude")),
                Err(_) => break, // timeout fired
            }
        }

        // 2. REST snapshot per pair, then reconcile with prelude. Any failure
        //    here aborts the whole session — we don't want to silently leave
        //    a pair un-bootstrapped (its live events would all be dropped at
        //    line `let Some(seq) = book.seq` below). The caller will retry
        //    after RECONNECT_DELAY.
        for pair in self.config.pairs.iter().map(|p| p.to_uppercase()) {
            let book = books.get_mut(&pair).expect("book for pair");
            // Try once; on bootstrap-gap (rare), refetch once more before giving up.
            for attempt in 0..2 {
                let snap = self
                    .fetch_snapshot(&pair)
                    .await
                    .wrap_err_with(|| format!("bootstrap {pair} (attempt {})", attempt + 1))?;
                book.apply_snapshot(snap.bids, snap.asks, Some(snap.last_update_id));
                let buf = prelude.get_mut(&pair).expect("buffer");
                let mut gapped = false;
                let mut applied = 0usize;
                let mut still_to_drain = std::mem::take(buf);
                while let Some(ev) = still_to_drain.pop_front() {
                    if ev.final_id <= snap.last_update_id {
                        continue; // stale
                    }
                    if applied == 0 && ev.first_id > snap.last_update_id + 1 {
                        warn!(
                            "[binance/{pair}] bootstrap gap (U={} > snap+1={}) attempt {}",
                            ev.first_id,
                            snap.last_update_id + 1,
                            attempt + 1
                        );
                        book.clear();
                        gapped = true;
                        break;
                    }
                    book.apply_deltas(ev.bids, ev.asks, Some(ev.final_id));
                    applied += 1;
                }
                if !gapped {
                    info!(
                        "[binance/{pair}] bootstrapped (snap.lastUpdateId={}, applied {applied} prelude events)",
                        snap.last_update_id
                    );
                    break;
                }
                if attempt == 1 {
                    return Err(eyre!("[binance/{pair}] persistent bootstrap gap"));
                }
            }
        }

        // 3. Live stream loop.
        let last_ping = Mutex::new(tokio::time::Instant::now());
        let (mut write, mut read) = ws.split();
        let mut ping_ticker = tokio::time::interval(PING_INTERVAL);
        ping_ticker.tick().await; // skip first immediate fire

        loop {
            tokio::select! {
                msg = read.next() => {
                    let received_at = now_ms();
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            let Some((sym, ev)) = parse_combined_event(&text) else {
                                continue;
                            };
                            let Some(book) = books.get_mut(&sym) else {
                                continue;
                            };
                            // Drop messages until we're bootstrapped.
                            let Some(seq) = book.seq else { continue };
                            // Stale event
                            if ev.final_id <= seq { continue; }
                            // Gap → re-snapshot
                            if ev.first_id > seq + 1 {
                                warn!(
                                    "[binance/{sym}] gap detected (U={} > last_u+1={}), re-snapshotting",
                                    ev.first_id, seq + 1
                                );
                                book.clear();
                                match self.fetch_snapshot(&sym).await {
                                    Ok(snap) => {
                                        book.apply_snapshot(snap.bids, snap.asks, Some(snap.last_update_id));
                                    }
                                    Err(e) => {
                                        error!("[binance/{sym}] re-snapshot failed: {e:#}");
                                    }
                                }
                                continue;
                            }
                            book.apply_deltas(ev.bids, ev.asks, Some(ev.final_id));
                            if !book.is_crossed() {
                                let exch_ts = ev.event_time.unwrap_or(0);
                                if let Some(d) = book.to_orderbook_data(exch_ts, received_at) {
                                    sink.emit(d);
                                }
                            }
                        }
                        Some(Ok(Message::Binary(_))) => {} // unused on binance
                        Some(Ok(Message::Ping(p))) => {
                            let _ = write.send(Message::Pong(p)).await;
                        }
                        Some(Ok(Message::Pong(_))) => {
                            *last_ping.lock().unwrap_or_else(|e| e.into_inner()) =
                                tokio::time::Instant::now();
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            return Err(eyre!("WS closed by peer"));
                        }
                        Some(Err(e)) => return Err(eyre!("WS read error: {e}")),
                        _ => {}
                    }
                }
                _ = ping_ticker.tick() => {
                    if write.send(Message::Ping(vec![])).await.is_err() {
                        return Err(eyre!("WS ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Binance {
    fn id(&self) -> &str {
        "binance"
    }

    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[binance] no pairs configured"));
        }
        sink.status("binance", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

// ─── helpers ───────────────────────────────────────────────────────────────

struct RestSnapshot {
    last_update_id: u64,
    bids: Vec<(f64, f64)>,
    asks: Vec<(f64, f64)>,
}

#[derive(Debug)]
struct DepthEvent {
    first_id: u64,
    final_id: u64,
    event_time: Option<i64>,
    bids: Vec<(f64, f64)>,
    asks: Vec<(f64, f64)>,
}

fn parse_levels(v: Option<&Value>) -> Vec<(f64, f64)> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|level| {
            let row = level.as_array()?;
            let p = parse_f64(row.first()?)?;
            let q = parse_f64(row.get(1)?)?;
            Some((p, q))
        })
        .collect()
}

/// Parse a combined-stream message: `{"stream":"btcusdt@depth@100ms","data":{...}}`
/// or a plain depth event without the wrapper.
fn parse_combined_event(text: &str) -> Option<(String, DepthEvent)> {
    let v: Value = serde_json::from_str(text).ok()?;
    let (stream_key, data) = if let Some(s) = v.get("stream").and_then(|x| x.as_str()) {
        (s.to_string(), v.get("data")?)
    } else {
        let s = v.get("s").and_then(|x| x.as_str())?;
        (format!("{}@depth", s.to_lowercase()), &v)
    };
    let symbol = symbol_from_binance_stream(&stream_key)?;
    let first_id = parse_u64(data.get("U")?)?;
    let final_id = parse_u64(data.get("u")?)?;
    let event_time = data.get("E").and_then(parse_u64).map(|x| x as i64);
    let bids = parse_levels(data.get("b"));
    let asks = parse_levels(data.get("a"));
    Some((
        symbol,
        DepthEvent {
            first_id,
            final_id,
            event_time,
            bids,
            asks,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_combined_event_works() {
        let text = r#"{"stream":"btcusdt@depth@100ms","data":{"e":"depthUpdate","E":1672515782136,"s":"BTCUSDT","U":157,"u":160,"b":[["42000.50","1.5"]],"a":[["42001.00","0.5"]]}}"#;
        let (sym, ev) = parse_combined_event(text).expect("parse");
        assert_eq!(sym, "BTCUSDT");
        assert_eq!(ev.first_id, 157);
        assert_eq!(ev.final_id, 160);
        assert_eq!(ev.event_time, Some(1672515782136));
        assert_eq!(ev.bids, vec![(42000.50, 1.5)]);
        assert_eq!(ev.asks, vec![(42001.00, 0.5)]);
    }

    #[test]
    fn parse_plain_event_works() {
        let text = r#"{"e":"depthUpdate","E":1,"s":"ETHUSDT","U":1,"u":2,"b":[["1","1"]],"a":[]}"#;
        let (sym, ev) = parse_combined_event(text).expect("parse");
        assert_eq!(sym, "ETHUSDT");
        assert_eq!(ev.first_id, 1);
        assert_eq!(ev.final_id, 2);
    }

    #[test]
    fn parse_garbage_returns_none() {
        assert!(parse_combined_event("not json").is_none());
        assert!(parse_combined_event(r#"{"result":null,"id":1}"#).is_none());
    }

    #[test]
    fn ws_url_combines_streams() {
        let cfg = ExchangeConfig {
            name: "binance".into(),
            enabled: true,
            ws_url: "wss://stream.binance.com:9443".into(),
            pairs: vec!["BTCUSDT".into(), "ETHUSDT".into()],
            extra_params: Default::default(),
        };
        let b = Binance::new(cfg);
        let url = b.ws_url();
        assert!(url.starts_with("wss://stream.binance.com:9443/stream?streams="));
        assert!(url.contains("btcusdt@depth@100ms"));
        assert!(url.contains("ethusdt@depth@100ms"));
        assert!(url.contains("/"));
    }

    /// Reproduce the bootstrap reconciliation from the Python reference:
    /// stale events (u <= lastUpdateId) discarded, first valid event must
    /// straddle lastUpdateId+1.
    #[test]
    fn book_apply_after_snapshot_handles_prelude() {
        let mut book = LocalBook::new("binance", "BTCUSDT");
        // REST snapshot: lastUpdateId=100
        book.apply_snapshot([(100.0, 1.0)], [(101.0, 1.0)], Some(100));

        // Stale prelude event should not bump seq.
        let stale = DepthEvent {
            first_id: 90,
            final_id: 99,
            event_time: None,
            bids: vec![(99.0, 1.0)],
            asks: vec![],
        };
        assert!(stale.final_id <= book.seq.unwrap()); // collector would skip

        // Valid first event: U=101, u=110 → covers lastUpdateId+1=101.
        let valid = DepthEvent {
            first_id: 101,
            final_id: 110,
            event_time: None,
            bids: vec![(99.0, 1.0)],
            asks: vec![],
        };
        book.apply_deltas(valid.bids, valid.asks, Some(valid.final_id));
        assert_eq!(book.seq, Some(110));
        let (bids, _) = book.top_n(10);
        assert_eq!(
            bids.iter().map(|l| l.price).collect::<Vec<_>>(),
            vec![100.0, 99.0]
        );
    }
}
