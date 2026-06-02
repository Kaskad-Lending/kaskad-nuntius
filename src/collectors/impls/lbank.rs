//! LBank spot collector — `cex_data/lbank/ob.py` reference.
//!
//! Channel: `depth` on `wss://api.lbkex.com/ws/V2/`. Server pushes a full
//! top-N snapshot on every message; no incremental deltas.
//! Subscribe via `{"action":"subscribe","subscribe":"depth","depth":"100","pair":<sym>}`.
//! Application keepalive `{"action":"ping"}` every 30s.
//!
//! NOTE: the `cex_data/lbank/README.md` warns to use `api.lbkex.com`, not the
//! `www.lbkex.net` host (that one redirects and tungstenite rejects redirects).

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

const PING_INTERVAL: Duration = Duration::from_secs(30);
const DEPTH: &str = "100";

pub struct Lbank {
    config: ExchangeConfig,
}

impl Lbank {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[lbank] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        for pair in &self.config.pairs {
            ws.send(Message::Text(
                json!({
                    "action": "subscribe",
                    "subscribe": "depth",
                    "depth": DEPTH,
                    "pair": pair.to_lowercase(),
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
                let key = p.to_lowercase();
                (key.clone(), LocalBook::new("lbank", key))
            })
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
                            // server-side ping (very rare on LBank but handle defensively)
                            if v.get("action").and_then(|a| a.as_str()) == Some("ping") {
                                let _ = write.send(Message::Text(json!({"action":"pong"}).to_string())).await;
                                continue;
                            }
                            let Some(d) = v.get("depth") else { continue };
                            let Some(pair) = v.get("pair").and_then(|p| p.as_str()) else { continue };
                            let pair = pair.to_lowercase();
                            let Some(book) = books.get_mut(&pair) else { continue };
                            let bids = parse_levels(d.get("bids"));
                            let asks = parse_levels(d.get("asks"));
                            // Audit M-3: LBank includes a `TS` field
                            // (naive UTC ISO-ish), e.g. "2019-06-28T17:49:22.722".
                            let exch_ts_ms = parse_lbank_ts_ms(v.get("TS")).unwrap_or(0);
                            tick = tick.wrapping_add(1);
                            book.apply_snapshot(bids, asks, Some(tick));
                            if !book.is_crossed() {
                                if let Some(d) = book.to_orderbook_data(exch_ts_ms, received_at) {
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
                    if write.send(Message::Text(json!({"action":"ping"}).to_string())).await.is_err() {
                        return Err(eyre!("ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Lbank {
    fn id(&self) -> &str {
        "lbank"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[lbank] no pairs"));
        }
        sink.status("lbank", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

/// LBank ships server time as a TZ-less ISO-like string in `TS`, e.g.
/// `"2019-06-28T17:49:22.722"`. Parse it as naive UTC. Returns `None` for
/// missing / non-string / unparseable input — caller falls back to host
/// receive-time (audit M-3).
fn parse_lbank_ts_ms(v: Option<&Value>) -> Option<i64> {
    let s = v?.as_str()?;
    let dt = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f").ok()?;
    Some(dt.and_utc().timestamp_millis())
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
    fn parse_depth_message() {
        let s = r#"{"depth":{"bids":[["76810","2.5"]],"asks":[["76822","6.3"]]},"pair":"btc_usdt","SERVER":"V2","type":"depth"}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        assert_eq!(v.get("pair").unwrap().as_str().unwrap(), "btc_usdt");
        let d = v.get("depth").unwrap();
        assert_eq!(parse_levels(d.get("bids")), vec![(76810.0, 2.5)]);
    }

    #[test]
    fn parse_ts_field_handles_naive_utc() {
        let v: Value = serde_json::from_str(r#"{"TS":"2024-01-02T03:04:05.123"}"#).unwrap();
        assert_eq!(parse_lbank_ts_ms(v.get("TS")), Some(1704164645123));
    }

    #[test]
    fn parse_ts_field_rejects_garbage() {
        assert!(parse_lbank_ts_ms(None).is_none());
        let v: Value = serde_json::from_str(r#"{"TS":"junk"}"#).unwrap();
        assert!(parse_lbank_ts_ms(v.get("TS")).is_none());
    }
}
