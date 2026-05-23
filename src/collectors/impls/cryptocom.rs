//! Crypto.com Exchange spot collector — `cex_data/cryptocom/ob.py` reference.
//!
//! Channel: `book.{SYMBOL}.{depth}` on
//! `wss://stream.crypto.com/exchange/v1/market`. The first push has
//! `result.channel == "book"` (snapshot), subsequent ones
//! `result.channel == "book.update"` (delta) with a `pu` (previous u) link.
//! `pu != local_u` ⇒ gap ⇒ reconnect.
//!
//! Heartbeat: server sends `{"method":"public/heartbeat","id":N}`; we must
//! reply with `{"id":N,"method":"public/respond-heartbeat"}` (echo the id).
//!
//! Subscribe needs a `nonce` (current ms). Available depth tiers: 10, 50.

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
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

const DEPTH: u32 = 50;

pub struct CryptoCom {
    config: ExchangeConfig,
}

impl CryptoCom {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[cryptocom] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        let channels: Vec<String> = self
            .config
            .pairs
            .iter()
            .map(|p| format!("book.{}.{DEPTH}", p.to_uppercase()))
            .collect();
        ws.send(Message::Text(
            json!({
                "id": 1,
                "method": "subscribe",
                "params": {
                    "channels": channels,
                    "book_subscription_type": "SNAPSHOT_AND_UPDATE",
                    "book_update_frequency": 10,
                },
                "nonce": now_ms(),
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
                (key.clone(), LocalBook::new("cryptocom", key))
            })
            .collect();

        let (mut write, mut read) = ws.split();

        loop {
            match read.next().await {
                Some(Ok(Message::Text(text))) => {
                    let received_at = now_ms();
                    let v: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if v.get("method").and_then(|m| m.as_str()) == Some("public/heartbeat") {
                        if let Some(id) = v.get("id") {
                            let _ = write
                                .send(Message::Text(
                                    json!({
                                        "id": id, "method": "public/respond-heartbeat",
                                    })
                                    .to_string(),
                                ))
                                .await;
                        }
                        continue;
                    }
                    let Some(result) = v.get("result") else {
                        continue;
                    };
                    let channel = result.get("channel").and_then(|c| c.as_str()).unwrap_or("");
                    let symbol = match result.get("instrument_name").and_then(|s| s.as_str()) {
                        Some(s) => s.to_uppercase(),
                        None => continue,
                    };
                    let Some(book) = books.get_mut(&symbol) else {
                        continue;
                    };
                    let Some(items) = result.get("data").and_then(|d| d.as_array()) else {
                        continue;
                    };

                    match channel {
                        "book" => {
                            for item in items {
                                let bids = parse_triple_levels(item.get("bids"));
                                let asks = parse_triple_levels(item.get("asks"));
                                let u = item.get("u").and_then(parse_u64);
                                book.apply_snapshot(bids, asks, u);
                                let ts = item
                                    .get("t")
                                    .and_then(parse_u64)
                                    .map(|x| x as i64)
                                    .unwrap_or(received_at);
                                if !book.is_crossed() {
                                    sink.emit(book.to_orderbook_data(ts, received_at));
                                }
                            }
                        }
                        "book.update" => {
                            let Some(local) = book.seq else { continue };
                            for item in items {
                                let Some(pu) = item.get("pu").and_then(parse_u64) else {
                                    continue;
                                };
                                if pu != local {
                                    warn!("[cryptocom/{symbol}] gap (pu={pu}, local={local}), reconnecting");
                                    return Err(eyre!("cryptocom gap"));
                                }
                                let Some(u) = item.get("u").and_then(parse_u64) else {
                                    continue;
                                };
                                let upd = item.get("update").unwrap_or(item);
                                let bids = parse_triple_levels(upd.get("bids"));
                                let asks = parse_triple_levels(upd.get("asks"));
                                book.apply_deltas(bids, asks, Some(u));
                                let ts = item
                                    .get("t")
                                    .and_then(parse_u64)
                                    .map(|x| x as i64)
                                    .unwrap_or(received_at);
                                if !book.is_crossed() {
                                    sink.emit(book.to_orderbook_data(ts, received_at));
                                }
                            }
                        }
                        _ => {}
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
impl Collector for CryptoCom {
    fn id(&self) -> &str {
        "cryptocom"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[cryptocom] no pairs"));
        }
        sink.status("cryptocom", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

/// Crypto.com level rows are `[price, qty, n_orders]`; we only need the first two.
fn parse_triple_levels(v: Option<&Value>) -> Vec<(f64, f64)> {
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
    fn snapshot_dispatch() {
        let s = r#"{"result":{"channel":"book","instrument_name":"BTC_USDT","data":[{"asks":[["50130","1.279","3"]],"bids":[["50113.5","0.4","3"]],"u":1,"t":1647917463000}]}}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let r = v.get("result").unwrap();
        assert_eq!(r.get("channel").unwrap().as_str().unwrap(), "book");
        let item = r.get("data").unwrap().as_array().unwrap().first().unwrap();
        let bids = parse_triple_levels(item.get("bids"));
        assert_eq!(bids, vec![(50113.5, 0.4)]);
    }

    #[test]
    fn update_has_pu() {
        let s = r#"{"result":{"channel":"book.update","instrument_name":"BTC_USDT","data":[{"update":{"asks":[["50180","3.279","10"]],"bids":[]},"u":2,"pu":1,"t":1}]}}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let item = v
            .get("result")
            .unwrap()
            .get("data")
            .unwrap()
            .as_array()
            .unwrap()
            .first()
            .unwrap();
        assert_eq!(parse_u64(item.get("pu").unwrap()), Some(1));
        assert_eq!(parse_u64(item.get("u").unwrap()), Some(2));
    }
}
