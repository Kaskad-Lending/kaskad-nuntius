//! Gate.io spot collector — `cex_data/gate/ob.py` reference.
//!
//! Channel: `spot.obu` with payload `ob.{SYMBOL}.400` (400 levels @ 100ms) on
//! `wss://api.gateio.ws/ws/v4/`. Server pushes a `result.full=true` snapshot
//! first, then incremental deltas. Each carries `(U, u)`; `U == local_u + 1`
//! ⇒ continuous, otherwise gap ⇒ reconnect.
//!
//! Ping (required every 30s):
//!   {"time": <unix>, "channel": "spot.ping", "event": "ping"}

use crate::cob_common::ExchangeConfig;
use crate::collectors::book::LocalBook;
use crate::collectors::collector::Collector;
use crate::collectors::sink::BookSink;
use crate::collectors::util::{now_ms, parse_f64, parse_u64, ws_connect};
use async_trait::async_trait;
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

const PING_INTERVAL: Duration = Duration::from_secs(30);
const DEPTH: u32 = 400;

pub struct Gate {
    config: ExchangeConfig,
}

impl Gate {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[gate] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // Subscribe per-pair (gate accepts only one ob channel per subscribe message).
        for pair in &self.config.pairs {
            ws.send(Message::Text(
                json!({
                    "time": chrono::Utc::now().timestamp(),
                    "channel": "spot.obu",
                    "event": "subscribe",
                    "payload": [format!("ob.{}.{DEPTH}", pair.to_uppercase())],
                })
                .to_string(),
            ))
            .await?;
        }

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| {
                let key = p.to_uppercase();
                (key.clone(), LocalBook::new("gate", key))
            })
            .collect();

        let (mut write, mut read) = ws.split();
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.tick().await;

        loop {
            tokio::select! {
                msg = read.next() => {
                    let received_at = now_ms();
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            let v: Value = match serde_json::from_str(&text) {
                                Ok(v) => v, Err(_) => continue,
                            };
                            let result = match v.get("result") { Some(r) if !r.is_null() => r, _ => continue };
                            let symbol = match result.get("s").and_then(|s| s.as_str()) {
                                Some(s) => s.to_uppercase(), None => continue,
                            };
                            let Some(book) = books.get_mut(&symbol) else { continue };

                            let is_full = result.get("full").and_then(|f| f.as_bool()).unwrap_or(false);
                            let big_u = result.get("U").and_then(parse_u64);
                            let lit_u = result.get("u").and_then(parse_u64);
                            let exch_ts = result.get("t").and_then(parse_u64).map(|x| x as i64).unwrap_or(0);
                            let bids = parse_levels(result.get("b"));
                            let asks = parse_levels(result.get("a"));

                            if is_full {
                                book.apply_snapshot(bids, asks, lit_u);
                            } else {
                                let Some(local) = book.seq else { continue };
                                let Some(u) = lit_u else { continue };
                                if u <= local { continue; }
                                if let Some(big_u) = big_u {
                                    if big_u != local + 1 {
                                        warn!("[gate/{symbol}] gap (U={big_u}, expected {}), reconnecting", local + 1);
                                        return Err(eyre!("gate gap"));
                                    }
                                }
                                book.apply_deltas(bids, asks, Some(u));
                            }
                            if !book.is_crossed() {
                                if let Some(d) = book.to_orderbook_data(exch_ts, received_at) {
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
                    let p = json!({
                        "time": chrono::Utc::now().timestamp(),
                        "channel": "spot.ping",
                        "event": "ping",
                    });
                    if write.send(Message::Text(p.to_string())).await.is_err() {
                        return Err(eyre!("ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Gate {
    fn id(&self) -> &str {
        "gate"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[gate] no pairs"));
        }
        sink.status("gate", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
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
    fn parse_snapshot_message() {
        let s = r#"{"channel":"spot.obu","event":"update","result":{"t":1,"s":"BTC_USDT","U":1,"u":1,"full":true,"b":[["100","1"]],"a":[["101","2"]]}}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let r = v.get("result").unwrap();
        assert_eq!(r.get("s").unwrap().as_str().unwrap(), "BTC_USDT");
        assert_eq!(r.get("full").unwrap().as_bool(), Some(true));
        assert_eq!(parse_levels(r.get("b")), vec![(100.0, 1.0)]);
    }

    #[test]
    fn parse_delta_message() {
        let s = r#"{"result":{"t":1,"s":"BTC_USDT","U":2,"u":3,"b":[["100","0"]],"a":[]}}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let r = v.get("result").unwrap();
        assert_eq!(parse_u64(r.get("U").unwrap()), Some(2));
        assert_eq!(parse_u64(r.get("u").unwrap()), Some(3));
        assert!(!r.get("full").and_then(|f| f.as_bool()).unwrap_or(false));
    }
}
