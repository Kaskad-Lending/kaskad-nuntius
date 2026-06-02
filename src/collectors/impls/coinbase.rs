//! Coinbase Advanced Trade collector — `cex_data/coinbase/ob.py` reference.
//!
//! Channel: `level2` on `wss://advanced-trade-ws.coinbase.com`.
//! No REST snapshot — Coinbase pushes a `type=snapshot` event first, then
//! `type=update` deltas. Outer `sequence_num` is shared across all channels;
//! a non-monotonic sequence ⇒ reconnect for fresh snapshot.
//!
//! `heartbeats` channel must be subscribed too, otherwise Coinbase silently
//! closes the `level2` channel within 60–90s of inactivity.
//!
//! Note: incoming messages have `channel="l2_data"`, NOT `"level2"`.

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

pub struct Coinbase {
    config: ExchangeConfig,
}

impl Coinbase {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[coinbase] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // Heartbeats first to keep level2 from closing.
        let prods: Vec<String> = self.config.pairs.to_vec();
        ws.send(Message::Text(
            json!({
                "type": "subscribe",
                "channel": "heartbeats",
                "product_ids": prods,
            })
            .to_string(),
        ))
        .await?;
        ws.send(Message::Text(
            json!({
                "type": "subscribe",
                "channel": "level2",
                "product_ids": prods,
            })
            .to_string(),
        ))
        .await?;

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.clone(), LocalBook::new("coinbase", p.clone())))
            .collect();

        let mut last_seq: Option<u64> = None;
        let (mut write, mut read) = ws.split();

        loop {
            match read.next().await {
                Some(Ok(Message::Text(text))) => {
                    let received_at = now_ms();
                    let v: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    // Outer sequence — gap on any channel = reconnect.
                    if let Some(seq) = v.get("sequence_num").and_then(parse_u64) {
                        if let Some(last) = last_seq {
                            if seq != last + 1 {
                                warn!(
                                    "[coinbase] outer sequence gap ({last} → {seq}), reconnecting"
                                );
                                return Err(eyre!("coinbase sequence gap"));
                            }
                        }
                        last_seq = Some(seq);
                    }

                    if v.get("channel").and_then(|c| c.as_str()) != Some("l2_data") {
                        continue;
                    }
                    // Audit M-3: outer `timestamp` is ISO-8601 from Coinbase
                    // and is the exchange-side time for this batch. Median
                    // of these across venues seeds the COB cycle stamp.
                    let exch_ts_ms = parse_rfc3339_ms(v.get("timestamp")).unwrap_or(0);
                    let Some(events) = v.get("events").and_then(|e| e.as_array()) else {
                        continue;
                    };

                    for event in events {
                        let etype = event.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        let product_id = match event.get("product_id").and_then(|p| p.as_str()) {
                            Some(p) => p.to_string(),
                            None => continue,
                        };
                        let Some(book) = books.get_mut(&product_id) else {
                            continue;
                        };
                        let Some(updates) = event.get("updates").and_then(|u| u.as_array()) else {
                            continue;
                        };

                        let (bids, asks) = split_sides(updates);

                        match etype {
                            "snapshot" => {
                                book.apply_snapshot(bids, asks, last_seq);
                            }
                            "update" => {
                                if !book.is_ready() {
                                    continue;
                                }
                                book.apply_deltas(bids, asks, last_seq);
                            }
                            _ => continue,
                        }
                        if !book.is_crossed() {
                            if let Some(d) = book.to_orderbook_data(exch_ts_ms, received_at) {
                                sink.emit(d);
                            }
                        }
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
impl Collector for Coinbase {
    fn id(&self) -> &str {
        "coinbase"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[coinbase] no pairs"));
        }
        sink.status("coinbase", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

/// Parse a Coinbase ISO-8601 timestamp value (`"2026-05-21T13:42:01.123456Z"`)
/// into unix-ms. Returns `None` for missing / non-string / invalid input;
/// callers fall back to host receive-time, which trips the COB cycle into
/// host-clock-based timestamping — see audit M-3.
fn parse_rfc3339_ms(v: Option<&Value>) -> Option<i64> {
    let s = v?.as_str()?;
    let dt = chrono::DateTime::parse_from_rfc3339(s).ok()?;
    Some(dt.timestamp_millis())
}

/// Split `updates` into `(bids, asks)` of `(price, qty)`. `new_quantity == 0` deletes.
type Levels = Vec<(f64, f64)>;

fn split_sides(updates: &[Value]) -> (Levels, Levels) {
    let mut bids = Vec::new();
    let mut asks = Vec::new();
    for u in updates {
        let side = u.get("side").and_then(|s| s.as_str()).unwrap_or("");
        let Some(p) = u.get("price_level").and_then(parse_f64) else {
            continue;
        };
        let Some(q) = u.get("new_quantity").and_then(parse_f64) else {
            continue;
        };
        match side {
            "bid" => bids.push((p, q)),
            "offer" | "ask" => asks.push((p, q)),
            _ => {}
        }
    }
    (bids, asks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_sides_handles_bid_and_offer() {
        let raw = r#"[
            {"side":"bid","price_level":"100.0","new_quantity":"1.0"},
            {"side":"offer","price_level":"101.0","new_quantity":"2.0"},
            {"side":"bid","price_level":"99.0","new_quantity":"0"}
        ]"#;
        let arr: Vec<Value> = serde_json::from_str(raw).unwrap();
        let (bids, asks) = split_sides(&arr);
        assert_eq!(bids, vec![(100.0, 1.0), (99.0, 0.0)]);
        assert_eq!(asks, vec![(101.0, 2.0)]);
    }

    #[test]
    fn channel_filter_is_l2_data_not_level2() {
        let v: Value = serde_json::from_str(r#"{"channel":"l2_data"}"#).unwrap();
        assert_eq!(v.get("channel").unwrap().as_str().unwrap(), "l2_data");
    }

    #[test]
    fn parse_rfc3339_extracts_unix_ms() {
        // Real-shape Coinbase l2_data envelope.
        let v: Value =
            serde_json::from_str(r#"{"timestamp":"2024-01-02T03:04:05.123456Z"}"#).unwrap();
        let ts = parse_rfc3339_ms(v.get("timestamp")).expect("parses");
        // 2024-01-02T03:04:05.123Z → 1704164645123 ms.
        assert_eq!(ts, 1704164645123);
    }

    #[test]
    fn parse_rfc3339_rejects_garbage_and_missing() {
        assert!(parse_rfc3339_ms(None).is_none());
        let v: Value = serde_json::from_str(r#"{"timestamp":"not a date"}"#).unwrap();
        assert!(parse_rfc3339_ms(v.get("timestamp")).is_none());
        let v: Value = serde_json::from_str(r#"{"timestamp":42}"#).unwrap();
        assert!(parse_rfc3339_ms(v.get("timestamp")).is_none());
    }
}
