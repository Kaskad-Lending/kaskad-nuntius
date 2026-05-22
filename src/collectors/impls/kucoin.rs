//! KuCoin spot collector — `cex_data/kucoin/ob.py` reference.
//!
//! Connection bootstrap is unusual:
//!   1. POST `https://api.kucoin.com/api/v1/bullet-public` (no body) →
//!      returns a temporary `token`, a WS `endpoint`, and `pingInterval` ms.
//!   2. Open `{endpoint}?token=...&connectId={uuid}`.
//!   3. Receive a "welcome" message before subscribing.
//!
//! Channel: `/market/level2:{SYMBOL}`. Each delta exposes
//! `(sequenceStart, sequenceEnd)`; `sequenceStart != local_seq + 1` ⇒ gap ⇒
//! reconnect. REST snapshot from `/api/v1/market/orderbook/level2_100`.
//!
//! Application ping required at `pingInterval` (~18s); 3 missed pings drop us.

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

const REST_BASE: &str = "https://api.kucoin.com";
const PRELUDE_BUFFER_TIMEOUT: Duration = Duration::from_secs(3);
const PRELUDE_BUFFER_MIN: usize = 5;

pub struct Kucoin {
    config: ExchangeConfig,
}

impl Kucoin {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn fetch_token(&self) -> Result<(String, Duration)> {
        let v: Value = HTTP
            .post(format!("{REST_BASE}/api/v1/bullet-public"))
            .send()
            .await
            .wrap_err("kucoin bullet-public")?
            .error_for_status()?
            .json()
            .await?;
        let data = v.get("data").ok_or_else(|| eyre!("missing data"))?;
        let token = data
            .get("token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| eyre!("missing token"))?;
        let server = data
            .get("instanceServers")
            .and_then(|s| s.as_array())
            .and_then(|a| a.first())
            .ok_or_else(|| eyre!("missing instanceServers"))?;
        let endpoint = server
            .get("endpoint")
            .and_then(|e| e.as_str())
            .ok_or_else(|| eyre!("missing endpoint"))?;
        let ping_ms = server
            .get("pingInterval")
            .and_then(|p| p.as_u64())
            .unwrap_or(18_000);
        let connect_id = format!(
            "{:x}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default() as u128
        );
        let url = format!("{endpoint}?token={token}&connectId={connect_id}");
        Ok((url, Duration::from_millis(ping_ms)))
    }

    async fn fetch_snapshot(&self, symbol: &str) -> Result<RestSnapshot> {
        let url = format!("{REST_BASE}/api/v1/market/orderbook/level2_100?symbol={symbol}");
        let v: Value = HTTP
            .get(&url)
            .send()
            .await
            .wrap_err_with(|| format!("kucoin snapshot {symbol}"))?
            .error_for_status()?
            .json()
            .await?;
        let data = v.get("data").ok_or_else(|| eyre!("missing data"))?;
        let sequence = parse_u64(data.get("sequence").unwrap_or(&Value::Null))
            .ok_or_else(|| eyre!("missing sequence"))?;
        let bids = parse_simple_levels(data.get("bids"));
        let asks = parse_simple_levels(data.get("asks"));
        Ok(RestSnapshot {
            sequence,
            bids,
            asks,
        })
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let (url, ping_iv) = self.fetch_token().await?;
        info!(
            "[kucoin] Connecting (ping={:?}, {} pairs)",
            ping_iv,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // Drain the welcome frame.
        match ws.next().await {
            Some(Ok(Message::Text(_))) => {}
            Some(Ok(_)) => {}
            other => return Err(eyre!("kucoin: missing welcome ({other:?})")),
        }

        // Subscribe per-pair.
        for (i, pair) in self.config.pairs.iter().enumerate() {
            ws.send(Message::Text(
                json!({
                    "id": format!("sub{i}"),
                    "type": "subscribe",
                    "topic": format!("/market/level2:{pair}"),
                    "privateChannel": false,
                    "response": true,
                })
                .to_string(),
            ))
            .await?;
        }

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.clone(), LocalBook::new("kucoin", p.clone())))
            .collect();
        let mut prelude: HashMap<String, VecDeque<KucoinUpdate>> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.clone(), VecDeque::new()))
            .collect();

        let (mut write, mut read) = ws.split();

        // Phase 1: buffer a few deltas per pair.
        let deadline = tokio::time::Instant::now() + PRELUDE_BUFFER_TIMEOUT;
        loop {
            if prelude.values().all(|q| q.len() >= PRELUDE_BUFFER_MIN) {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                debug!("[kucoin] prelude deadline");
                break;
            }
            let to = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(to, read.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    if let Some((sym, upd)) = parse_l2_message(&text) {
                        prelude.entry(sym).or_default().push_back(upd);
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
        // Binance pattern (see binance.rs).
        for pair in self.config.pairs.iter() {
            let book = books.get_mut(pair).expect("book");
            for attempt in 0..2 {
                let snap = self.fetch_snapshot(pair).await.wrap_err_with(|| {
                    format!("kucoin bootstrap {pair} (attempt {})", attempt + 1)
                })?;
                book.apply_snapshot(snap.bids, snap.asks, Some(snap.sequence));
                let buf = prelude.get_mut(pair).expect("buf");
                let drained = std::mem::take(buf);
                match reconcile_prelude(book, snap.sequence, drained) {
                    Ok(applied) => {
                        info!(
                            "[kucoin/{pair}] bootstrapped (seq={}, applied {applied})",
                            snap.sequence
                        );
                        break;
                    }
                    Err(BootstrapGap { first_seen }) => {
                        warn!(
                            "[kucoin/{pair}] bootstrap gap (start={} > snap+1={}) attempt {}",
                            first_seen,
                            snap.sequence + 1,
                            attempt + 1
                        );
                        if attempt == 1 {
                            return Err(eyre!("[kucoin/{pair}] persistent bootstrap gap"));
                        }
                    }
                }
            }
        }

        // Phase 3: live + ping.
        let mut ping = tokio::time::interval(ping_iv);
        ping.tick().await;
        loop {
            tokio::select! {
                msg = read.next() => {
                    let received_at = now_ms();
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            let Some((sym, upd)) = parse_l2_message(&text) else { continue };
                            let Some(book) = books.get_mut(&sym) else { continue };
                            let Some(local) = book.seq else { continue };
                            if upd.sequence_end <= local { continue; }
                            if upd.sequence_start != local + 1 {
                                warn!("[kucoin/{sym}] gap (start={}, local={local}), reconnecting",
                                      upd.sequence_start);
                                return Err(eyre!("kucoin gap"));
                            }
                            let exch_ts_ms = upd.time_ms;
                            book.apply_deltas(upd.bids, upd.asks, Some(upd.sequence_end));
                            if !book.is_crossed() {
                                sink.emit(book.to_orderbook_data(exch_ts_ms, received_at));
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => return Err(eyre!("WS closed")),
                        Some(Err(e)) => return Err(eyre!("WS error: {e}")),
                        _ => {}
                    }
                }
                _ = ping.tick() => {
                    if write.send(Message::Text(json!({"id":"p","type":"ping"}).to_string())).await.is_err() {
                        return Err(eyre!("ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Kucoin {
    fn id(&self) -> &str {
        "kucoin"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[kucoin] no pairs"));
        }
        sink.status("kucoin", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

struct RestSnapshot {
    sequence: u64,
    bids: Vec<(f64, f64)>,
    asks: Vec<(f64, f64)>,
}

#[derive(Debug)]
struct KucoinUpdate {
    sequence_start: u64,
    sequence_end: u64,
    /// Exchange-side ms timestamp (Kucoin `data.time`). `0` if the
    /// message omits it; the caller treats that as "no exchange ts"
    /// and falls back to host receive-time. Audit M-3.
    time_ms: i64,
    bids: Vec<(f64, f64)>,
    asks: Vec<(f64, f64)>,
}

/// Pure reconciliation step extracted for testability. Drains `prelude` into
/// `book`, enforcing that the FIRST applied event covers `snap_anchor + 1`
/// (i.e. `sequence_start <= snap_anchor + 1 <= sequence_end`). Stale events
/// (`sequence_end <= snap_anchor`) are dropped silently. On gap the book is
/// cleared so the caller can re-snapshot.
#[derive(Debug)]
struct BootstrapGap {
    first_seen: u64,
}

fn reconcile_prelude(
    book: &mut LocalBook,
    snap_anchor: u64,
    mut prelude: VecDeque<KucoinUpdate>,
) -> std::result::Result<usize, BootstrapGap> {
    let mut applied = 0usize;
    while let Some(u) = prelude.pop_front() {
        if u.sequence_end <= snap_anchor {
            continue;
        }
        if applied == 0 && u.sequence_start > snap_anchor + 1 {
            book.clear();
            return Err(BootstrapGap {
                first_seen: u.sequence_start,
            });
        }
        book.apply_deltas(u.bids, u.asks, Some(u.sequence_end));
        applied += 1;
    }
    Ok(applied)
}

/// Parse a `[price, size]` array (REST snapshot).
fn parse_simple_levels(v: Option<&Value>) -> Vec<(f64, f64)> {
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

/// Parse a `[price, size, sequence]` change entry (WS delta).
fn parse_change_entries(v: Option<&Value>) -> Vec<(f64, f64)> {
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

fn parse_l2_message(text: &str) -> Option<(String, KucoinUpdate)> {
    let v: Value = serde_json::from_str(text).ok()?;
    if v.get("type").and_then(|t| t.as_str()) != Some("message") {
        return None;
    }
    let topic = v.get("topic").and_then(|t| t.as_str())?;
    // topic = "/market/level2:BTC-USDT"
    let symbol = topic.strip_prefix("/market/level2:")?.to_string();
    let data = v.get("data")?;
    let sequence_start = parse_u64(data.get("sequenceStart")?)?;
    let sequence_end = parse_u64(data.get("sequenceEnd")?)?;
    // `time` is exchange-side, millis since epoch (Kucoin doc).
    let time_ms = data
        .get("time")
        .and_then(|t| {
            t.as_i64()
                .or_else(|| t.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0);
    let changes = data.get("changes")?;
    let bids = parse_change_entries(changes.get("bids"));
    let asks = parse_change_entries(changes.get("asks"));
    Some((
        symbol,
        KucoinUpdate {
            sequence_start,
            sequence_end,
            time_ms,
            bids,
            asks,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_l2() {
        let s = r#"{"type":"message","topic":"/market/level2:BTC-USDT","subject":"trade.l2update","data":{"sequenceStart":10,"sequenceEnd":12,"time":1704164645123,"changes":{"asks":[["100","1","11"]],"bids":[["99","2","12"]]}}}"#;
        let (sym, upd) = parse_l2_message(s).unwrap();
        assert_eq!(sym, "BTC-USDT");
        assert_eq!(upd.sequence_start, 10);
        assert_eq!(upd.sequence_end, 12);
        assert_eq!(upd.time_ms, 1704164645123);
        assert_eq!(upd.asks, vec![(100.0, 1.0)]);
        assert_eq!(upd.bids, vec![(99.0, 2.0)]);
    }

    #[test]
    fn parse_l2_time_optional() {
        // `time` absent — `time_ms` defaults to 0 (caller treats it as
        // "no exchange ts" and falls back to host receive-time).
        let s = r#"{"type":"message","topic":"/market/level2:BTC-USDT","subject":"trade.l2update","data":{"sequenceStart":10,"sequenceEnd":12,"changes":{"asks":[],"bids":[]}}}"#;
        let (_, upd) = parse_l2_message(s).unwrap();
        assert_eq!(upd.time_ms, 0);
    }

    #[test]
    fn ignore_non_message_types() {
        let s = r#"{"type":"welcome"}"#;
        assert!(parse_l2_message(s).is_none());
    }

    fn upd(start: u64, end: u64) -> KucoinUpdate {
        KucoinUpdate {
            sequence_start: start,
            sequence_end: end,
            time_ms: 0,
            bids: vec![(100.0, 1.0)],
            asks: vec![(101.0, 1.0)],
        }
    }

    #[test]
    fn reconcile_filters_stale_first_event_below_snap() {
        let mut book = LocalBook::new("kucoin", "BTC-USDT");
        book.apply_snapshot([(100.0, 5.0)], [(101.0, 5.0)], Some(100));
        let mut q = VecDeque::new();
        q.push_back(upd(80, 99)); // stale, end <= snap
        q.push_back(upd(95, 105)); // straddle
        let applied = reconcile_prelude(&mut book, 100, q).expect("no gap");
        assert_eq!(applied, 1);
        assert_eq!(book.seq, Some(105));
    }

    #[test]
    fn reconcile_detects_gap_when_first_event_above_snap_plus_one() {
        let mut book = LocalBook::new("kucoin", "BTC-USDT");
        book.apply_snapshot([(100.0, 5.0)], [(101.0, 5.0)], Some(100));
        let mut q = VecDeque::new();
        q.push_back(upd(103, 110));
        let err = reconcile_prelude(&mut book, 100, q).unwrap_err();
        assert_eq!(err.first_seen, 103);
        assert!(book.seq.is_none());
        assert!(book.bids.is_empty() && book.asks.is_empty());
    }
}
