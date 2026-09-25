//! WhiteBIT spot collector — `cex_data/whitebit/ob.py` reference.
//!
//! Channel: `depth_subscribe` on `wss://api.whitebit.com/ws`. Subscribe
//! arguments: `[symbol, depth, "0", true]` — the trailing `true` is
//! `multipleSub`, which ADDS a subscription instead of replacing the
//! channel's market set (confirmed live 2026-07-16). First push has
//! `is_full=true` (full top-N book), subsequent pushes have
//! `is_full=false` deltas with a `past_update_id` field that must equal
//! the previous `update_id`; otherwise reconnect. `update_id` values are
//! non-contiguous, so only the `past_update_id` chain is checked.
//! Unprompted keepalive full snapshots (~10s cadence) restart the chain.
//! Deltas omit an entire side (`asks`/`bids` key absent) when unchanged.
//! `timestamp` is float epoch SECONDS and reflects the last book change,
//! not send time.
//!
//! Application keepalive: `{"id":0,"method":"ping","params":[]}` every 50s
//! (server closes idle connections after 60s).

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
                    "params": [pair.to_uppercase(), DEPTH, "0", true],
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
                (key.clone(), LocalBook::new("whitebit", key))
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
                            // Subscribe acks / RPC replies carry a non-null
                            // `error` on rejection (e.g. unknown market).
                            // Silently dropping them would leave a session
                            // that pings forever with zero data.
                            if is_error_frame(&v) {
                                warn!("[whitebit] server error frame: {text}");
                                return Err(eyre!("whitebit error frame"));
                            }
                            if v.get("method").and_then(|m| m.as_str()) != Some("depth_update") { continue; }
                            let Some(params) = v.get("params").and_then(|p| p.as_array()) else { continue };
                            if params.len() < 3 { continue; }
                            let is_full = params[0].as_bool().unwrap_or(false);
                            let data = &params[1];
                            let symbol = params[2].as_str().unwrap_or("").to_uppercase();
                            let Some(book) = books.get_mut(&symbol) else { continue };

                            let bids = parse_levels(data.get("bids"));
                            let asks = parse_levels(data.get("asks"));
                            let new_id = data.get("update_id").and_then(parse_u64);

                            if is_full {
                                book.apply_snapshot(bids, asks, new_id);
                            } else {
                                let Some(local) = book.seq else { continue };
                                // A delta without past_update_id means the
                                // continuity chain can't be verified —
                                // treat as a gap rather than assuming it.
                                let Some(past) = data.get("past_update_id").and_then(parse_u64) else {
                                    warn!("[whitebit/{symbol}] delta without past_update_id, reconnecting");
                                    return Err(eyre!("whitebit delta missing past_update_id"));
                                };
                                if past != local {
                                    warn!("[whitebit/{symbol}] gap (past_update_id={past}, local={local}), reconnecting");
                                    return Err(eyre!("whitebit gap"));
                                }
                                book.apply_deltas(bids, asks, new_id);
                            }
                            let ts = ts_ms_from_seconds(data);
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

/// True for RPC frames carrying a non-null `error` (rejected subscribe,
/// malformed request). Push messages and successful acks have `error: null`.
fn is_error_frame(v: &Value) -> bool {
    v.get("error").is_some_and(|e| !e.is_null())
}

/// WhiteBIT's `timestamp` is float epoch SECONDS with a microsecond
/// fraction (e.g. `1784196710.043553`, verified live 2026-07-16); the
/// pipeline wants unix ms. `0` when missing/unparseable — LocalBook then
/// drops the book instead of substituting host time (audit C-3).
fn ts_ms_from_seconds(data: &Value) -> i64 {
    data.get("timestamp")
        .and_then(parse_f64)
        .map(|s| (s * 1000.0) as i64)
        .unwrap_or(0)
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

    #[test]
    fn ts_converts_float_seconds_to_ms() {
        // Exactly representable fraction.
        let v: Value = serde_json::from_str(r#"{"timestamp":1689600180.5}"#).unwrap();
        assert_eq!(ts_ms_from_seconds(&v), 1689600180500);
        // Live-captured value with microsecond fraction (f64 rounding may
        // shave 1 ms via truncation — accept ±1).
        let v: Value = serde_json::from_str(r#"{"timestamp":1784196710.043553}"#).unwrap();
        assert!((ts_ms_from_seconds(&v) - 1784196710043).abs() <= 1);
        // Missing timestamp -> 0 -> book dropped downstream.
        let v: Value = serde_json::from_str(r#"{"update_id":1}"#).unwrap();
        assert_eq!(ts_ms_from_seconds(&v), 0);
    }

    #[test]
    fn delta_with_absent_side_parses_as_empty() {
        // Live deltas omit the unchanged side entirely (no "asks" key).
        let s = r#"{"params":[false,{"update_id":2,"past_update_id":1,"bids":[["192.7","98.1484"]]},"TAO_USDT"]}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let data = v.get("params").unwrap().as_array().unwrap().get(1).unwrap();
        assert_eq!(parse_levels(data.get("asks")), Vec::<(f64, f64)>::new());
        assert_eq!(parse_levels(data.get("bids")), vec![(192.7, 98.1484)]);
    }

    #[test]
    fn zero_amount_is_removal_sentinel() {
        // Live-observed level deletion: ["198","0"].
        let v: Value = serde_json::from_str(r#"{"asks":[["198","0"]]}"#).unwrap();
        assert_eq!(parse_levels(v.get("asks")), vec![(198.0, 0.0)]);
    }

    #[test]
    fn error_frames_detected_acks_and_pushes_pass() {
        // Live-captured successful ack and pong: error is null -> not an error.
        let ack: Value =
            serde_json::from_str(r#"{"error":null,"result":{"status":"success"},"id":1}"#).unwrap();
        assert!(!is_error_frame(&ack));
        let pong: Value = serde_json::from_str(r#"{"error":null,"result":"pong","id":0}"#).unwrap();
        assert!(!is_error_frame(&pong));
        // Push frames have no error key at all.
        let push: Value =
            serde_json::from_str(r#"{"method":"depth_update","params":[],"id":null}"#).unwrap();
        assert!(!is_error_frame(&push));
        // Rejected subscribe carries a non-null error object.
        let err: Value = serde_json::from_str(
            r#"{"error":{"code":2,"message":"unknown market"},"result":null,"id":1}"#,
        )
        .unwrap();
        assert!(is_error_frame(&err));
    }
}
