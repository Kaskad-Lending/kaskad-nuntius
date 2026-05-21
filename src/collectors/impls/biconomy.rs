//! Biconomy spot collector — `cex_data/biconomy/ob.py` reference.
//!
//! Channel: `depth.subscribe` with params `[symbol, depth, precision]` on
//! `wss://bei.biconomy.com/ws`. First push has `is_full=true`, subsequent
//! pushes are deltas (`is_full=false`). No sequence number — gaps are
//! recovered by reconnecting (which triggers a fresh full snapshot).
//!
//! Ping: `{"method":"server.ping","params":[],"id":0}` every 3 minutes.

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
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tracing::info;

const PING_INTERVAL: Duration = Duration::from_secs(180);
const DEPTH: u32 = 50;
const PRECISION: &str = "0.01";

pub struct Biconomy {
    config: ExchangeConfig,
}

impl Biconomy {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[biconomy] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        for (i, pair) in self.config.pairs.iter().enumerate() {
            ws.send(Message::Text(
                json!({
                    "method": "depth.subscribe",
                    "params": [pair, DEPTH, PRECISION],
                    "id": i as u64 + 1,
                })
                .to_string(),
            ))
            .await?;
        }

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.clone(), LocalBook::new("biconomy", p.clone())))
            .collect();
        let mut tick: u64 = 0;

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
                            if v.get("method").and_then(|m| m.as_str()) != Some("depth.update") { continue; }
                            let Some(params) = v.get("params").and_then(|p| p.as_array()) else { continue };
                            if params.len() < 3 { continue; }
                            let is_full = params[0].as_bool().unwrap_or(false);
                            let data = &params[1];
                            let symbol = params[2].as_str().unwrap_or("").to_string();
                            let Some(book) = books.get_mut(&symbol) else { continue };
                            let bids = parse_levels(data.get("bids"));
                            let asks = parse_levels(data.get("asks"));
                            tick = tick.wrapping_add(1);
                            if is_full {
                                book.apply_snapshot(bids, asks, Some(tick));
                            } else if book.is_ready() {
                                book.apply_deltas(bids, asks, Some(tick));
                            }
                            if !book.is_crossed() && book.is_ready() {
                                sink.emit(book.to_orderbook_data(0, received_at));
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
                        "method": "server.ping", "params": [], "id": 0
                    }).to_string())).await.is_err() {
                        return Err(eyre!("ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Biconomy {
    fn id(&self) -> &str {
        "biconomy"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[biconomy] no pairs"));
        }
        sink.status("biconomy", crate::cob_common::ServiceStatus::Connected);
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
    fn parse_full_snapshot_message() {
        let s = r#"{"method":"depth.update","params":[true,{"asks":[["100","1"]],"bids":[["99","2"]]},"BTC_USDT"]}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let p = v.get("params").unwrap().as_array().unwrap();
        assert_eq!(p[0].as_bool(), Some(true));
        assert_eq!(p[2].as_str(), Some("BTC_USDT"));
    }
}
