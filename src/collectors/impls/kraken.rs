//! Kraken spot collector — `cex_data/kraken/ob.py` reference.
//!
//! Channel: `book` on `wss://ws.kraken.com/v2`. Server-pushed snapshot+delta;
//! Kraken does NOT expose a sequence number on the order-book channel — gaps
//! manifest as TCP/WS errors which trigger our reconnect loop. Heartbeat
//! frames `{"channel":"heartbeat"}` arrive periodically; respond with
//! `{"method":"pong"}` (JSON, NOT a raw "pong" string).
//!
//! Symbol format: `BTC/USD` (with slash; Kraken trades USD natively but
//! some pairs are listed as `BTC/USDT`).
//!
//! Levels in messages are `{"price":..., "qty":...}` dicts, not arrays.

use crate::cob_common::ExchangeConfig;
use crate::collectors::book::LocalBook;
use crate::collectors::collector::Collector;
use crate::collectors::sink::BookSink;
use crate::collectors::util::{now_ms, parse_f64, ws_connect};
use async_trait::async_trait;
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio_tungstenite::tungstenite::Message;
use tracing::info;

const DEPTH: u32 = 1000;

pub struct Kraken {
    config: ExchangeConfig,
}

impl Kraken {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[kraken] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // Subscribe — Kraken accepts an array of symbols in a single subscribe.
        ws.send(Message::Text(
            json!({
                "method": "subscribe",
                "params": {"channel": "book", "symbol": self.config.pairs, "depth": DEPTH},
            })
            .to_string(),
        ))
        .await?;

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.clone(), LocalBook::new("kraken", p.clone())))
            .collect();

        let (mut write, mut read) = ws.split();
        // Synthetic seq counter — Kraken has no native one but `is_ready()` requires
        // `Some(seq)` so we increment per message to gate the dispatch.
        let mut tick: u64 = 0;

        loop {
            match read.next().await {
                Some(Ok(Message::Text(text))) => {
                    let received_at = now_ms();
                    let v: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let channel = v.get("channel").and_then(|c| c.as_str()).unwrap_or("");
                    if channel == "heartbeat" {
                        let _ = write
                            .send(Message::Text(json!({"method":"pong"}).to_string()))
                            .await;
                        continue;
                    }
                    if channel != "book" {
                        continue;
                    }
                    let mtype = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    let Some(data) = v
                        .get("data")
                        .and_then(|d| d.as_array())
                        .and_then(|a| a.first())
                    else {
                        continue;
                    };
                    let symbol = match data.get("symbol").and_then(|s| s.as_str()) {
                        Some(s) => s.to_string(),
                        None => continue,
                    };
                    let Some(book) = books.get_mut(&symbol) else {
                        continue;
                    };

                    let bids = parse_dict_levels(data.get("bids"));
                    let asks = parse_dict_levels(data.get("asks"));

                    tick = tick.wrapping_add(1);
                    match mtype {
                        "snapshot" => {
                            book.apply_snapshot(bids, asks, Some(tick));
                        }
                        "update" => {
                            if !book.is_ready() {
                                continue;
                            }
                            book.apply_deltas(bids, asks, Some(tick));
                        }
                        _ => continue,
                    }
                    if !book.is_crossed() {
                        sink.emit(book.to_orderbook_data(0, received_at));
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
impl Collector for Kraken {
    fn id(&self) -> &str {
        "kraken"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[kraken] no pairs"));
        }
        sink.status("kraken", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

/// Parse `[{"price":N,"qty":N}, ...]` (Kraken-specific dict shape).
fn parse_dict_levels(v: Option<&Value>) -> Vec<(f64, f64)> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|item| {
            let p = parse_f64(item.get("price")?)?;
            let q = parse_f64(item.get("qty")?)?;
            Some((p, q))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kraken_dict_levels() {
        let s = r#"[{"price":100.0,"qty":1.0},{"price":99.5,"qty":2.0}]"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let lv = parse_dict_levels(Some(&v));
        assert_eq!(lv, vec![(100.0, 1.0), (99.5, 2.0)]);
    }

    #[test]
    fn snapshot_message_has_symbol() {
        let s = r#"{"channel":"book","type":"snapshot","data":[{"symbol":"BTC/USD","bids":[{"price":1.0,"qty":1.0}],"asks":[{"price":2.0,"qty":1.0}],"checksum":0}]}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let data = v.get("data").unwrap().as_array().unwrap().first().unwrap();
        assert_eq!(data.get("symbol").unwrap().as_str().unwrap(), "BTC/USD");
    }
}
