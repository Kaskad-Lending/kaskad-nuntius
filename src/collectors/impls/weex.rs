//! WEEX spot collector — `cex_data/weex/ob.py` reference.
//!
//! Channel: `{symbol}@depth{level}` on `wss://ws-spot.weex.com/v3/ws/public`.
//! WS pushes the snapshot first (`d="SNAPSHOT"`, event `e="depthSnapshot"`);
//! subsequent deltas are `d="CHANGED"` (event `e="depth"`). Continuity is
//! `U == last_u` (overlap by 1, NOT +1 like Binance/Gate).
//!
//! Server pings: `{"event":"ping","time":...}` arrive periodically; reply
//! with `{"method":"PONG","id":1}`. Connection drops after 10 missed pings.

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

const DEPTH: u32 = 200;

pub struct Weex {
    config: ExchangeConfig,
}

impl Weex {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[weex] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        let params: Vec<String> = self
            .config
            .pairs
            .iter()
            .map(|p| format!("{}@depth{DEPTH}", p.to_uppercase()))
            .collect();
        ws.send(Message::Text(
            json!({
                "method": "SUBSCRIBE", "params": params, "id": 1,
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
                (key.clone(), LocalBook::new("weex", key))
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
                    if v.get("event").and_then(|e| e.as_str()) == Some("ping") {
                        let _ = write
                            .send(Message::Text(
                                json!({
                                    "method": "PONG", "id": 1,
                                })
                                .to_string(),
                            ))
                            .await;
                        continue;
                    }
                    let e_type = v.get("e").and_then(|x| x.as_str()).unwrap_or("");
                    if e_type != "depth" && e_type != "depthSnapshot" {
                        continue;
                    }
                    let symbol = match v.get("s").and_then(|s| s.as_str()) {
                        Some(s) => s.to_uppercase(),
                        None => continue,
                    };
                    let Some(book) = books.get_mut(&symbol) else {
                        continue;
                    };
                    let big_u = v.get("U").and_then(parse_u64);
                    let lit_u = v.get("u").and_then(parse_u64);
                    let exch_ts = v
                        .get("E")
                        .and_then(parse_u64)
                        .map(|x| x as i64)
                        .unwrap_or(received_at);
                    let bids = parse_levels(v.get("b"));
                    let asks = parse_levels(v.get("a"));

                    let kind = v.get("d").and_then(|d| d.as_str()).unwrap_or("");
                    match kind {
                        "SNAPSHOT" => {
                            book.apply_snapshot(bids, asks, lit_u);
                        }
                        "CHANGED" => {
                            let Some(local) = book.seq else { continue };
                            // WEEX overlaps: each CHANGED message has U == previous u.
                            if let Some(big_u) = big_u {
                                if big_u != local {
                                    warn!("[weex/{symbol}] gap (U={}, expected {local}), reconnecting", big_u);
                                    return Err(eyre!("weex gap"));
                                }
                            }
                            book.apply_deltas(bids, asks, lit_u);
                        }
                        _ => continue,
                    }
                    if !book.is_crossed() && book.is_ready() {
                        sink.emit(book.to_orderbook_data(exch_ts, received_at));
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
impl Collector for Weex {
    fn id(&self) -> &str {
        "weex"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[weex] no pairs"));
        }
        sink.status("weex", crate::cob_common::ServiceStatus::Connected);
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
        let s = r#"{"e":"depth","E":1,"s":"BTCUSDT","U":1,"u":1,"l":200,"d":"SNAPSHOT","b":[["100","1"]],"a":[["101","2"]]}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        assert_eq!(v.get("e").unwrap().as_str().unwrap(), "depth");
        assert_eq!(v.get("d").unwrap().as_str().unwrap(), "SNAPSHOT");
        assert_eq!(parse_u64(v.get("U").unwrap()), Some(1));
    }

    #[test]
    fn parse_changed_overlap() {
        let s = r#"{"e":"depth","E":1,"s":"BTCUSDT","U":1,"u":3,"d":"CHANGED","b":[["100","0"]],"a":[]}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        assert_eq!(v.get("d").unwrap().as_str().unwrap(), "CHANGED");
        assert_eq!(parse_u64(v.get("U").unwrap()), Some(1));
    }
}
