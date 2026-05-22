//! Phemex spot collector — `cex_data/phemex/ob.py` reference.
//!
//! Channel: `orderbook.subscribe` on `wss://ws.phemex.com`. Spot symbols
//! prefix `s` (e.g. `sBTCUSDT`).
//!
//! Phemex uses **scaled integers**: `priceEp / 1e8` and `qty / 1e8`.
//!
//! First message is the snapshot (no `type`, or `type:"snapshot"`); subsequent
//! messages have `type:"incremental"`. The `sequence` is global across all
//! instruments — gaps between messages are normal, no gap detection needed.
//!
//! Application keepalive: `{"id":0,"method":"server.ping","params":[]}` 20s.

use crate::cob_common::ExchangeConfig;
use crate::collectors::book::LocalBook;
use crate::collectors::collector::Collector;
use crate::collectors::sink::BookSink;
use crate::collectors::util::{now_ms, parse_i64, ws_connect};
use async_trait::async_trait;
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tracing::info;

const PING_INTERVAL: Duration = Duration::from_secs(20);
const SCALE: f64 = 1e8;

pub struct Phemex {
    config: ExchangeConfig,
}

impl Phemex {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[phemex] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // Subscribe to all spot symbols (Phemex accepts an array).
        let params: Vec<String> = self.config.pairs.to_vec();
        ws.send(Message::Text(
            json!({
                "id": 1, "method": "orderbook.subscribe", "params": params,
            })
            .to_string(),
        ))
        .await?;

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.clone(), LocalBook::new("phemex", p.clone())))
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
                            let Some(data) = v.get("book") else { continue };
                            let symbol = match v.get("symbol").and_then(|s| s.as_str()) {
                                Some(s) => s.to_string(), None => continue,
                            };
                            let Some(book) = books.get_mut(&symbol) else { continue };

                            let mtype = v.get("type").and_then(|t| t.as_str()).unwrap_or("snapshot");
                            let bids = parse_scaled(data.get("bids"));
                            let asks = parse_scaled(data.get("asks"));
                            // Audit M-3: Phemex emits `timestamp` in nanoseconds.
                            // Convert to ms here; LatencyTracker is happy with
                            // ms-scale values via `normalize_timestamp_ms`.
                            let exch_ts_ms = v
                                .get("timestamp")
                                .and_then(parse_i64)
                                .map(|ns| ns / 1_000_000)
                                .unwrap_or(0);

                            tick = tick.wrapping_add(1);
                            if mtype != "incremental" {
                                // snapshot: anchor on per-symbol synthetic counter (sequence
                                // is global on Phemex so we don't use it for gap detection)
                                book.apply_snapshot(bids, asks, Some(tick));
                            } else if book.is_ready() {
                                book.apply_deltas(bids, asks, Some(tick));
                            }

                            if !book.is_crossed() && book.is_ready() {
                                sink.emit(book.to_orderbook_data(exch_ts_ms, received_at));
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
                        "id": 0, "method": "server.ping", "params": []
                    }).to_string())).await.is_err() {
                        return Err(eyre!("ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Phemex {
    fn id(&self) -> &str {
        "phemex"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[phemex] no pairs"));
        }
        sink.status("phemex", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

/// Phemex levels: `[priceEp:int, qty:int]` scaled by 1e8.
fn parse_scaled(v: Option<&Value>) -> Vec<(f64, f64)> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|row| {
            let r = row.as_array()?;
            let p_ep = r.first()?.as_f64()?;
            let q_e = r.get(1)?.as_f64()?;
            Some((p_ep / SCALE, q_e / SCALE))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scaled_levels() {
        let raw = r#"[[7639352000000, 3850000], [7639351000000, 1000000]]"#;
        let v: Value = serde_json::from_str(raw).unwrap();
        let lv = parse_scaled(Some(&v));
        assert_eq!(lv, vec![(76393.52, 0.0385), (76393.51, 0.01)]);
    }

    #[test]
    fn snapshot_message_shape() {
        let s = r#"{"book":{"asks":[[7639778000000,6885000]],"bids":[[7639352000000,3850000]]},"depth":30,"sequence":123,"symbol":"sBTCUSDT","type":"snapshot"}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        assert_eq!(v.get("symbol").unwrap().as_str().unwrap(), "sBTCUSDT");
        assert_eq!(v.get("type").unwrap().as_str().unwrap(), "snapshot");
    }

    #[test]
    fn timestamp_field_is_nanoseconds() {
        // Phemex emits unix ns. Confirm the JSON parses as i64 and the
        // /1_000_000 reduction lands in ms range.
        let s = r#"{"timestamp":1704164645123000000}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let ns = v.get("timestamp").and_then(parse_i64).unwrap();
        assert_eq!(ns / 1_000_000, 1704164645123);
    }
}
