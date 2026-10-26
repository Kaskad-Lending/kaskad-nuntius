//! CoinW spot collector.
//!
//! Raw public WS at `wss://ws.futurescw.com` (no auth/token). The WAF
//! rejects handshakes without a browser `Origin` header (403, verified
//! live 2026-07-19), so we send `Origin: https://www.coinw.com`.
//!
//! Subscription is by NUMERIC pairCode, not symbol:
//! `{"event":"sub","params":{"biz":"exchange","type":"depth_snapshot","pairCode":"2109"}}`.
//! The pairCode mapping comes from REST `returnTicker` (each pair's `id`
//! field), resolved once per session like coinstore. The server pushes
//! full snapshots (~6.6/s per pair, 20 levels per side, verified live);
//! no deltas. Application keepalive `{"event":"ping"}` every 30s is
//! REQUIRED: the server drops the connection after ~200-230s without it
//! even while snapshots are flowing (observed live 2026-07-19; the
//! server replies `{"event":"pong"}`).
//!
//! Format quirks (all verified live):
//! - Push frames DOUBLE-ENCODE `data`: it is a JSON *string* that must
//!   be parsed again. Subscribe acks carry `data` as an object
//!   (`{"result":true}`) — both shapes must be handled.
//! - The outer `time` is an internal counter (17 digits, not epoch);
//!   the usable timestamp is the inner `data.time` (epoch ms).
//! - The inner `seq` is monotonic per pair; used as the book sequence.

use crate::cob_common::ExchangeConfig;
use crate::collectors::book::LocalBook;
use crate::collectors::collector::Collector;
use crate::collectors::rest::HTTP;
use crate::collectors::sink::BookSink;
use crate::collectors::util::{now_ms, parse_f64, parse_i64, parse_u64, ws_connect_with_origin};
use async_trait::async_trait;
use eyre::{eyre, Result, WrapErr};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

const REST_BASE: &str = "https://api.coinw.com";
const WS_ORIGIN: &str = "https://www.coinw.com";
const PING_INTERVAL: Duration = Duration::from_secs(30);

pub struct Coinw {
    config: ExchangeConfig,
}

impl Coinw {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    /// GET /api/v1/public?command=returnTicker → pairCode (as string, the
    /// wire format of the WS `pairCode` field) → config pair (uppercase).
    /// Fails if ANY configured pair is missing so a typo'd pair surfaces
    /// as a boot error instead of a silent no-data subscription.
    async fn resolve_pair_codes(&self) -> Result<HashMap<String, String>> {
        let v: Value = HTTP
            .get(format!("{REST_BASE}/api/v1/public?command=returnTicker"))
            .send()
            .await
            .wrap_err("coinw returnTicker lookup")?
            .error_for_status()?
            .json()
            .await?;
        let data = v
            .get("data")
            .and_then(|d| d.as_object())
            .ok_or_else(|| eyre!("coinw returnTicker: missing data object"))?;
        let mut out = HashMap::new();
        for pair in &self.config.pairs {
            let key = pair.to_uppercase();
            let id = data
                .get(&key)
                .and_then(|t| t.get("id"))
                .and_then(parse_u64)
                .ok_or_else(|| eyre!("coinw: no pairCode for {key} in returnTicker"))?;
            out.insert(id.to_string(), key);
        }
        Ok(out)
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let code_to_sym = self.resolve_pair_codes().await?;
        let url = self.config.ws_url.clone();
        info!("[coinw] Connecting {} ({} pairs)", url, code_to_sym.len());
        let mut ws = ws_connect_with_origin(&url, Some(WS_ORIGIN)).await?;

        for code in code_to_sym.keys() {
            ws.send(Message::Text(
                json!({
                    "event": "sub",
                    "params": {"biz": "exchange", "type": "depth_snapshot", "pairCode": code},
                })
                .to_string(),
            ))
            .await?;
        }

        let mut books: HashMap<String, LocalBook> = code_to_sym
            .values()
            .map(|sym| (sym.clone(), LocalBook::new("coinw", sym.clone())))
            .collect();

        let (mut write, mut read) = ws.split();
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.tick().await;

        loop {
            tokio::select! {
                msg = read.next() => {
                    match msg {
                Some(Ok(Message::Text(text))) => {
                    let received_at = now_ms();
                    let v: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if v.get("type").and_then(|t| t.as_str()) != Some("depth_snapshot") {
                        continue;
                    }
                    let Some(code) = v.get("pairCode").and_then(|c| c.as_str()) else {
                        continue;
                    };
                    let Some(symbol) = code_to_sym.get(code) else {
                        continue;
                    };
                    // Acks carry `data` as an object; pushes double-encode
                    // it as a JSON string.
                    let data: Value = match v.get("data") {
                        Some(Value::String(s)) => match serde_json::from_str(s) {
                            Ok(d) => d,
                            Err(_) => continue,
                        },
                        Some(Value::Object(o)) => {
                            if o.get("result").and_then(|r| r.as_bool()) == Some(false) {
                                warn!("[coinw/{symbol}] subscription rejected, reconnecting");
                                return Err(eyre!("coinw subscription rejected for {symbol}"));
                            }
                            continue;
                        }
                        _ => continue,
                    };
                    let Some(book) = books.get_mut(symbol) else {
                        continue;
                    };

                    let bids = parse_levels(data.get("bids"));
                    let asks = parse_levels(data.get("asks"));
                    let seq = data.get("seq").and_then(parse_u64);
                    book.apply_snapshot(bids, asks, seq);
                    // Inner data.time is epoch ms; the OUTER time field is
                    // an internal counter and must not be used.
                    let ts = data.get("time").and_then(parse_i64).unwrap_or(0);
                    if !book.is_crossed() {
                        if let Some(d) = book.to_orderbook_data(ts, received_at) {
                            sink.emit(d);
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
                _ = ping.tick() => {
                    if write
                        .send(Message::Text(json!({"event": "ping"}).to_string()))
                        .await
                        .is_err()
                    {
                        return Err(eyre!("ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Coinw {
    fn id(&self) -> &str {
        "coinw"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[coinw] no pairs"));
        }
        sink.status("coinw", crate::cob_common::ServiceStatus::Connected);
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
    fn ack_frame_carries_data_as_object() {
        // Live-captured subscription ack (2026-07-19).
        let s = r#"{"biz":"exchange","pairCode":"2109","data":{"result":true},"channel":"subscribe","type":"depth_snapshot"}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let d = v.get("data").unwrap();
        assert!(d.is_object());
        assert_eq!(d.get("result").and_then(|r| r.as_bool()), Some(true));
    }

    #[test]
    fn push_frame_double_encodes_data() {
        // Live-captured push shape: `data` is a JSON STRING to re-parse;
        // outer `time` is a 17-digit internal counter, NOT epoch.
        let s = r#"{"biz":"exchange","pairCode":"2109","time":65069397089101600,"data":"{\"asks\":[[\"198.8\",\"95.993\"]],\"bids\":[[\"198.5\",\"112.520\"]],\"time\":1784457169976,\"seq\":806602804}","type":"depth_snapshot"}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let raw = v.get("data").unwrap().as_str().unwrap();
        let data: Value = serde_json::from_str(raw).unwrap();
        assert_eq!(parse_levels(data.get("asks")), vec![(198.8, 95.993)]);
        assert_eq!(parse_levels(data.get("bids")), vec![(198.5, 112.520)]);
        // Inner time is epoch ms (13 digits) — inside LatencyTracker's
        // [1e12, 1e15] pass-through band.
        assert_eq!(data.get("time").and_then(parse_i64), Some(1784457169976));
        assert_eq!(data.get("seq").and_then(parse_u64), Some(806602804));
    }

    #[test]
    fn rejected_subscription_detected() {
        let s = r#"{"biz":"exchange","pairCode":"9999","data":{"result":false},"channel":"subscribe","type":"depth_snapshot"}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let d = v.get("data").unwrap();
        assert_eq!(d.get("result").and_then(|r| r.as_bool()), Some(false));
    }

    #[test]
    fn return_ticker_id_is_paircode() {
        // returnTicker maps symbol -> ticker; `id` is the WS pairCode
        // (verified live: BTC_USDT=78, TAO_USDT=2109).
        let s = r#"{"data":{"TAO_USDT":{"id":2109,"last":"198.7","isFrozen":0}}}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let id = v
            .get("data")
            .and_then(|d| d.get("TAO_USDT"))
            .and_then(|t| t.get("id"))
            .and_then(parse_u64);
        assert_eq!(id, Some(2109));
    }
}
