//! WhiteBIT spot collector — `cex_data/whitebit/ob.py` reference.
//!
//! Channel: `depth_subscribe` on `wss://api.whitebit.com/ws`. Subscribe
//! arguments: `[symbol, depth, "0", true]`. First push has `is_full=true`
//! (full top-N book), subsequent pushes have `is_full=false` deltas with
//! a `past_update_id` field that must equal the previous `update_id`;
//! otherwise reconnect.
//!
//! Application keepalive: `{"id":0,"method":"ping","params":[]}` every 50s.

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

const PING_INTERVAL: Duration = Duration::from_secs(50);
const DEPTH: u32 = 100;

pub struct Whitebit {
    config: ExchangeConfig,
}

impl Whitebit {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[whitebit] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        for (i, pair) in self.config.pairs.iter().enumerate() {
            ws.send(Message::Text(
                json!({
                    "id": i as u64 + 1,
                    "method": "depth_subscribe",
                    "params": [pair, DEPTH, "0", true],
                })
                .to_string(),
            ))
            .await?;
        }

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.clone(), LocalBook::new("whitebit", p.clone())))
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
                            if v.get("method").and_then(|m| m.as_str()) != Some("depth_update") { continue; }
                            let Some(params) = v.get("params").and_then(|p| p.as_array()) else { continue };
                            if params.len() < 3 { continue; }
                            let is_full = params[0].as_bool().unwrap_or(false);
                            let data = &params[1];
                            let symbol = params[2].as_str().unwrap_or("").to_string();
                            let Some(book) = books.get_mut(&symbol) else { continue };

                            let bids = parse_levels(data.get("bids"));
                            let asks = parse_levels(data.get("asks"));
                            let new_id = data.get("update_id").and_then(parse_u64);

                            if is_full {
                                book.apply_snapshot(bids, asks, new_id);
                            } else {
                                let Some(local) = book.seq else { continue };
                                let past = data.get("past_update_id").and_then(parse_u64).unwrap_or(local);
                                if past != local {
                                    warn!("[whitebit/{symbol}] gap (past_update_id={past}, local={local}), reconnecting");
                                    return Err(eyre!("whitebit gap"));
                                }
                                book.apply_deltas(bids, asks, new_id);
                            }
                            let ts = data.get("timestamp")
                                .and_then(|x| x.as_f64())
                                .map(|s| (s * 1000.0) as i64)
                                .unwrap_or(0);
                            if !book.is_crossed() {
                                if let Some(d) = book.to_orderbook_data(ts, received_at) {
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
                        "id": 0, "method": "ping", "params": []
                    }).to_string())).await.is_err() {
                        return Err(eyre!("ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Whitebit {
    fn id(&self) -> &str {
        "whitebit"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[whitebit] no pairs"));
        }
        sink.status("whitebit", crate::cob_common::ServiceStatus::Connected);
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
    fn parse_full_snapshot() {
        let s = r#"{"id":null,"method":"depth_update","params":[true,{"update_id":12500630137,"timestamp":1689600180.516,"asks":[["76353.78","1.2"]],"bids":[["76344.46","0.5"]]},"BTC_USDT"]}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let p = v.get("params").unwrap().as_array().unwrap();
        assert!(p[0].as_bool().unwrap());
        assert_eq!(p[2].as_str().unwrap(), "BTC_USDT");
        assert_eq!(parse_u64(p[1].get("update_id").unwrap()), Some(12500630137));
    }

    #[test]
    fn parse_delta_with_past_update_id() {
        let s = r#"{"params":[false,{"update_id":2,"past_update_id":1,"asks":[["100","0"]],"bids":[]},"BTC_USDT"]}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let data = v.get("params").unwrap().as_array().unwrap().get(1).unwrap();
        assert_eq!(parse_u64(data.get("past_update_id").unwrap()), Some(1));
    }
}
