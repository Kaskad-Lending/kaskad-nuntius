//! Poloniex spot collector — `cex_data/poloniex/ob.py` reference.
//!
//! Channel: `book_lv2` on `wss://ws.poloniex.com/ws/public`. Subscription
//! confirmations have `event` field and no `data`. Snapshot messages have
//! `action="snapshot"` (or sometimes absent — treat both as snapshot).
//! Delta messages have `action="update"` with a `lastId` that must equal
//! the previous `id`; otherwise reconnect.
//!
//! Application keepalive: `{"event":"ping"}` every 30s.

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
pub struct Poloniex {
    config: ExchangeConfig,
}

impl Poloniex {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[poloniex] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        ws.send(Message::Text(
            json!({
                "event": "subscribe",
                "channel": ["book_lv2"],
                "symbols": self.config.pairs,
            })
            .to_string(),
        ))
        .await?;

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.clone(), LocalBook::new("poloniex", p.clone())))
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
                            // Skip subscribe acks (have `event`, no `data`)
                            if v.get("event").is_some() && v.get("data").is_none() { continue; }
                            if v.get("channel").and_then(|c| c.as_str()) != Some("book_lv2") { continue; }
                            let Some(items) = v.get("data").and_then(|d| d.as_array()) else { continue };
                            let action = v.get("action").and_then(|a| a.as_str()).unwrap_or("snapshot");
                            for d in items {
                                let symbol = match d.get("symbol").and_then(|s| s.as_str()) {
                                    Some(s) => s.to_string(), None => continue,
                                };
                                let Some(book) = books.get_mut(&symbol) else { continue };
                                let new_id = d.get("id").and_then(parse_u64);
                                let bids = parse_levels(d.get("bids"));
                                let asks = parse_levels(d.get("asks"));
                                let ts = d.get("ts").and_then(parse_u64).map(|x| x as i64).unwrap_or(0);

                                match action {
                                    "snapshot" => {
                                        book.apply_snapshot(bids, asks, new_id);
                                    }
                                    "update" => {
                                        let Some(local) = book.seq else { continue };
                                        let last_id = d.get("lastId").and_then(parse_u64).unwrap_or(local);
                                        if last_id != local {
                                            warn!("[poloniex/{symbol}] gap (lastId={last_id}, local={local}), reconnecting");
                                            return Err(eyre!("poloniex gap"));
                                        }
                                        book.apply_deltas(bids, asks, new_id);
                                    }
                                    _ => continue,
                                }
                                if !book.is_crossed() && book.is_ready() {
                                    if let Some(d) = book.to_orderbook_data(ts, received_at) {
                                        sink.emit(d);
                                    }
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
                    if write.send(Message::Text(json!({"event": "ping"}).to_string())).await.is_err() {
                        return Err(eyre!("ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Poloniex {
    fn id(&self) -> &str {
        "poloniex"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[poloniex] no pairs"));
        }
        sink.status("poloniex", crate::cob_common::ServiceStatus::Connected);
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
        let s = r#"{"channel":"book_lv2","action":"snapshot","data":[{"symbol":"BTC_USDT","id":1,"lastId":0,"asks":[["100","1"]],"bids":[["99","2"]]}]}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let item = v.get("data").unwrap().as_array().unwrap().first().unwrap();
        assert_eq!(item.get("symbol").unwrap().as_str().unwrap(), "BTC_USDT");
        assert_eq!(parse_u64(item.get("id").unwrap()), Some(1));
    }

    #[test]
    fn parse_update_with_last_id() {
        let s = r#"{"channel":"book_lv2","action":"update","data":[{"symbol":"BTC_USDT","id":2,"lastId":1,"asks":[["100","0"]],"bids":[]}]}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let item = v.get("data").unwrap().as_array().unwrap().first().unwrap();
        assert_eq!(parse_u64(item.get("lastId").unwrap()), Some(1));
    }
}
