//! Bybit spot collector — `cex_data/bybit/ob.py` reference.
//!
//! Channel: `orderbook.{depth}.{symbol}` on `wss://stream.bybit.com/v5/public/spot`.
//! No REST snapshot — Bybit pushes a `type=snapshot` message immediately on
//! subscribe, followed by `type=delta` increments with strictly monotonic
//! `data.u` (`u != last_u + 1` ⇒ gap ⇒ reconnect for fresh snapshot).
//!
//! Application ping required: `{"op":"ping"}` every 20s or the server drops us.

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

const PING_INTERVAL: Duration = Duration::from_secs(20);
const DEPTH: u32 = 200; // 200 levels @ 100ms — best depth/latency tradeoff for KAS-class symbols

pub struct Bybit {
    config: ExchangeConfig,
}

impl Bybit {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[bybit] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // Subscribe to all pairs in one message.
        let args: Vec<String> = self
            .config
            .pairs
            .iter()
            .map(|p| format!("orderbook.{DEPTH}.{}", p.to_uppercase()))
            .collect();
        let sub = json!({"op": "subscribe", "args": args});
        ws.send(Message::Text(sub.to_string())).await?;

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| {
                let key = p.to_uppercase();
                (key.clone(), LocalBook::new("bybit", key))
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
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            // Subscription ack / pong
                            if v.get("op").is_some() && v.get("data").is_none() { continue; }

                            let topic = match v.get("topic").and_then(|t| t.as_str()) {
                                Some(t) => t,
                                None => continue,
                            };
                            // topic = "orderbook.{depth}.{SYMBOL}"
                            let symbol = match topic.split('.').nth(2) {
                                Some(s) => s.to_uppercase(),
                                None => continue,
                            };
                            let Some(book) = books.get_mut(&symbol) else { continue };

                            let mtype = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
                            let Some(data) = v.get("data") else { continue };
                            let new_u = match data.get("u").and_then(parse_u64) {
                                Some(u) => u,
                                None => continue,
                            };
                            let exch_ts = v.get("ts").and_then(parse_u64).map(|x| x as i64).unwrap_or(received_at);

                            let bids = parse_pairs(data.get("b"));
                            let asks = parse_pairs(data.get("a"));

                            match mtype {
                                "snapshot" => {
                                    book.apply_snapshot(bids, asks, Some(new_u));
                                }
                                "delta" => {
                                    let Some(last) = book.seq else { continue };
                                    if new_u != last + 1 {
                                        warn!("[bybit/{symbol}] gap (u={new_u} expected {}), reconnecting", last + 1);
                                        return Err(eyre!("bybit gap"));
                                    }
                                    book.apply_deltas(bids, asks, Some(new_u));
                                }
                                _ => continue,
                            }
                            if !book.is_crossed() {
                                sink.emit(book.to_orderbook_data(exch_ts, received_at));
                            }
                        }
                        Some(Ok(Message::Ping(p))) => { let _ = write.send(Message::Pong(p)).await; }
                        Some(Ok(Message::Close(_))) | None => return Err(eyre!("WS closed")),
                        Some(Err(e)) => return Err(eyre!("WS error: {e}")),
                        _ => {}
                    }
                }
                _ = ping.tick() => {
                    if write.send(Message::Text(r#"{"op":"ping"}"#.into())).await.is_err() {
                        return Err(eyre!("ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Bybit {
    fn id(&self) -> &str {
        "bybit"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[bybit] no pairs"));
        }
        sink.status("bybit", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

fn parse_pairs(v: Option<&Value>) -> Vec<(f64, f64)> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|row| {
            let r = row.as_array()?;
            let p = parse_f64(r.first()?)?;
            let q = parse_f64(r.get(1)?)?;
            Some((p, q))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_snapshot_then_delta() {
        let snap = r#"{"topic":"orderbook.200.BTCUSDT","type":"snapshot","ts":1,"data":{"b":[["100","1"]],"a":[["101","1"]],"u":42,"seq":1}}"#;
        let v: Value = serde_json::from_str(snap).unwrap();
        let topic = v.get("topic").unwrap().as_str().unwrap();
        let sym = topic.split('.').nth(2).unwrap();
        assert_eq!(sym, "BTCUSDT");
        let data = v.get("data").unwrap();
        let bids = parse_pairs(data.get("b"));
        let asks = parse_pairs(data.get("a"));
        assert_eq!(bids, vec![(100.0, 1.0)]);
        assert_eq!(asks, vec![(101.0, 1.0)]);
        let u = data.get("u").unwrap().as_u64().unwrap();
        assert_eq!(u, 42);
    }

    #[test]
    fn delta_zero_size_means_delete() {
        let pairs = parse_pairs(Some(&serde_json::from_str(r#"[["100","0"]]"#).unwrap()));
        assert_eq!(pairs, vec![(100.0, 0.0)]);
        // and book.apply_deltas treats q==0 as delete (covered in book.rs tests)
    }
}
