//! XT.com spot collector — `cex_data/xt/ob.py` reference.
//!
//! Channel: `depth_update@{symbol}` (incremental, up to 500 levels) on
//! `wss://stream.xt.com/public`. Bootstrap mirrors Binance:
//!   1. Subscribe → buffer prelude events
//!   2. REST `https://sapi.xt.com/v4/public/depth?symbol={s}&limit=500` →
//!      `result.lastUpdateId` is the seq anchor.
//!   3. Drop buffered events with `i <= lastUpdateId`.
//!   4. First valid event must satisfy `fi <= last+1 <= i`.
//!   5. Live: `fi == local + 1`; otherwise gap ⇒ reconnect.

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

const REST_BASE: &str = "https://sapi.xt.com";
const PRELUDE_BUFFER_TIMEOUT: Duration = Duration::from_secs(3);
const PRELUDE_BUFFER_MIN: usize = 5;

pub struct Xt {
    config: ExchangeConfig,
}

impl Xt {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn fetch_snapshot(&self, symbol: &str) -> Result<RestSnapshot> {
        let url = format!(
            "{REST_BASE}/v4/public/depth?symbol={}&limit=500",
            symbol.to_lowercase()
        );
        let v: Value = HTTP
            .get(&url)
            .send()
            .await
            .wrap_err_with(|| format!("xt REST {symbol}"))?
            .error_for_status()?
            .json()
            .await?;
        let result = v.get("result").ok_or_else(|| eyre!("missing result"))?;
        let last = result
            .get("lastUpdateId")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| eyre!("missing lastUpdateId"))?;
        let bids = parse_levels(result.get("bids"));
        let asks = parse_levels(result.get("asks"));
        Ok(RestSnapshot {
            last_update_id: last,
            bids,
            asks,
        })
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[xt] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // XT subscribes one channel per param array entry; one message can hold many.
        let params: Vec<String> = self
            .config
            .pairs
            .iter()
            .map(|p| format!("depth_update@{}", p.to_lowercase()))
            .collect();
        ws.send(Message::Text(
            json!({"method": "subscribe", "params": params, "id": 1}).to_string(),
        ))
        .await?;

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| {
                let key = p.to_lowercase();
                (key.clone(), LocalBook::new("xt", key))
            })
            .collect();
        let mut prelude: HashMap<String, VecDeque<XtDelta>> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.to_lowercase(), VecDeque::new()))
            .collect();

        let (mut write, mut read) = ws.split();

        // Phase 1: buffer prelude.
        let deadline = tokio::time::Instant::now() + PRELUDE_BUFFER_TIMEOUT;
        loop {
            if prelude.values().all(|q| q.len() >= PRELUDE_BUFFER_MIN) {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                debug!("[xt] prelude deadline");
                break;
            }
            let to = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(to, read.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    if let Some((sym, d)) = parse_delta(&text) {
                        prelude.entry(sym).or_default().push_back(d);
                    }
                }
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(e))) => return Err(eyre!("WS error: {e}")),
                Ok(None) => return Err(eyre!("WS closed")),
                Err(_) => break,
            }
        }

        // Phase 2: REST snapshot per pair.
        for pair in self.config.pairs.iter().map(|p| p.to_lowercase()) {
            let book = books.get_mut(&pair).expect("book");
            let snap = self
                .fetch_snapshot(&pair)
                .await
                .wrap_err_with(|| format!("xt bootstrap {pair}"))?;
            book.apply_snapshot(snap.bids, snap.asks, Some(snap.last_update_id));
            let buf = prelude.get_mut(&pair).expect("buf");
            let mut applied = 0;
            while let Some(d) = buf.pop_front() {
                if d.last_id <= snap.last_update_id {
                    continue;
                }
                if applied == 0 && d.first_id > snap.last_update_id + 1 {
                    return Err(eyre!("[xt/{pair}] bootstrap gap"));
                }
                book.apply_deltas(d.bids, d.asks, Some(d.last_id));
                applied += 1;
            }
            info!(
                "[xt/{pair}] bootstrapped (lastUpdateId={}, applied {applied})",
                snap.last_update_id
            );
        }

        // Phase 3: live.
        loop {
            match read.next().await {
                Some(Ok(Message::Text(text))) => {
                    let received_at = now_ms();
                    let Some((sym, d)) = parse_delta(&text) else {
                        continue;
                    };
                    let Some(book) = books.get_mut(&sym) else {
                        continue;
                    };
                    let Some(local) = book.seq else { continue };
                    if d.last_id <= local {
                        continue;
                    }
                    if d.first_id != local + 1 {
                        warn!(
                            "[xt/{sym}] gap (fi={}, expected {}), reconnecting",
                            d.first_id,
                            local + 1
                        );
                        return Err(eyre!("xt gap"));
                    }
                    let exch_ts_ms = d.time_ms;
                    book.apply_deltas(d.bids, d.asks, Some(d.last_id));
                    if !book.is_crossed() {
                        sink.emit(book.to_orderbook_data(exch_ts_ms, received_at));
                    }
                }
                Some(Ok(Message::Ping(p))) => {
                    let _ = write.send(Message::Pong(p)).await;
                }
                Some(Ok(Message::Close(_))) | None => return Err(eyre!("WS closed")),
                Some(Err(e)) => return Err(eyre!("WS error: {e}")),
                _ => {}
            }
        }
    }
}

#[async_trait]
impl Collector for Xt {
    fn id(&self) -> &str {
        "xt"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[xt] no pairs"));
        }
        sink.status("xt", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

struct RestSnapshot {
    last_update_id: u64,
    bids: Vec<(f64, f64)>,
    asks: Vec<(f64, f64)>,
}

#[derive(Debug)]
struct XtDelta {
    first_id: u64,
    last_id: u64,
    /// Exchange `t` field — usually unix ms, but `LatencyTracker::process`
    /// will up-scale a seconds-resolution value if XT ever ships one (audit M-3).
    time_ms: i64,
    bids: Vec<(f64, f64)>,
    asks: Vec<(f64, f64)>,
}

fn parse_delta(text: &str) -> Option<(String, XtDelta)> {
    let v: Value = serde_json::from_str(text).ok()?;
    if v.get("topic")?.as_str()? != "depth_update" {
        return None;
    }
    let data = v.get("data")?;
    let symbol = data.get("s")?.as_str()?.to_lowercase();
    let first_id = parse_u64(data.get("fi")?)?;
    let last_id = parse_u64(data.get("i")?)?;
    let time_ms = data
        .get("t")
        .and_then(|t| {
            t.as_i64()
                .or_else(|| t.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0);
    let bids = parse_levels(data.get("b"));
    let asks = parse_levels(data.get("a"));
    Some((
        symbol,
        XtDelta {
            first_id,
            last_id,
            time_ms,
            bids,
            asks,
        },
    ))
}

fn parse_levels(v: Option<&Value>) -> Vec<(f64, f64)> {
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
    fn parse_delta_works() {
        let s = r#"{"topic":"depth_update","event":"depth_update@btc_usdt","data":{"s":"btc_usdt","fi":12346,"i":12350,"t":1704164645123,"a":[["76865","0"]],"b":[["76860","5.12"]]}}"#;
        let (sym, d) = parse_delta(s).unwrap();
        assert_eq!(sym, "btc_usdt");
        assert_eq!(d.first_id, 12346);
        assert_eq!(d.last_id, 12350);
        assert_eq!(d.time_ms, 1704164645123);
        assert_eq!(d.bids, vec![(76860.0, 5.12)]);
        assert_eq!(d.asks, vec![(76865.0, 0.0)]);
    }

    #[test]
    fn parse_delta_time_optional() {
        let s = r#"{"topic":"depth_update","event":"depth_update@btc_usdt","data":{"s":"btc_usdt","fi":1,"i":2,"a":[],"b":[]}}"#;
        let (_, d) = parse_delta(s).unwrap();
        assert_eq!(d.time_ms, 0);
    }
}
