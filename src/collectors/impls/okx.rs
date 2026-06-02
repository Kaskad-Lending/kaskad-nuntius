//! OKX spot collector — `cex_data/okx/ob.py` reference.
//!
//! Channel: `books` (400 levels, 100ms) on `wss://ws.okx.com:8443/ws/v5/public`.
//! No REST snapshot — OKX pushes `action=snapshot` first, then `action=update`
//! deltas with `(seqId, prevSeqId)` continuity. Mismatch ⇒ wait for next snapshot.
//!
//! Ping is the literal **text** string `ping` (not JSON).

use crate::cob_common::ExchangeConfig;
use crate::collectors::book::LocalBook;
use crate::collectors::collector::Collector;
use crate::collectors::sink::BookSink;
use crate::collectors::util::{now_ms, parse_f64, parse_i64, parse_u64, ws_connect};
use async_trait::async_trait;
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

const PING_INTERVAL: Duration = Duration::from_secs(25);
pub struct Okx {
    config: ExchangeConfig,
}

impl Okx {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[okx] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // Subscribe to all instruments at once.
        let args: Vec<Value> = self
            .config
            .pairs
            .iter()
            .map(|p| json!({"channel": "books", "instId": p}))
            .collect();
        ws.send(Message::Text(
            json!({"op": "subscribe", "args": args}).to_string(),
        ))
        .await?;

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.clone(), LocalBook::new("okx", p.clone())))
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
                            // Plain "pong" replies
                            if text == "pong" { continue; }
                            let v: Value = match serde_json::from_str(&text) {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            // Subscription ack
                            if v.get("event").is_some() { continue; }

                            let action = match v.get("action").and_then(|x| x.as_str()) {
                                Some(a) => a,
                                None => continue,
                            };
                            let inst_id = match v.get("arg").and_then(|a| a.get("instId")).and_then(|x| x.as_str()) {
                                Some(s) => s.to_string(),
                                None => continue,
                            };
                            let Some(book) = books.get_mut(&inst_id) else { continue };
                            let Some(data) = v.get("data").and_then(|d| d.as_array()).and_then(|a| a.first()) else { continue };

                            let seq_id = match data.get("seqId").and_then(parse_u64) {
                                Some(s) => s,
                                None => continue,
                            };
                            let exch_ts = data.get("ts").and_then(parse_u64).map(|x| x as i64).unwrap_or(0);
                            let bids = parse_levels(data.get("bids"));
                            let asks = parse_levels(data.get("asks"));

                            match action {
                                "snapshot" => {
                                    book.apply_snapshot(bids, asks, Some(seq_id));
                                }
                                "update" => {
                                    // OKX uses `prevSeqId == -1` as a sentinel meaning
                                    // "this message is itself a (re)snapshot anchor — no
                                    // continuity with prior local seq required". Treat
                                    // missing prevSeqId or any other negative value as a
                                    // protocol violation and fail the session so the
                                    // supervisor reconnects (vs silently desyncing).
                                    match classify_prev_seq(data.get("prevSeqId")) {
                                        PrevSeq::SnapshotAnchor => {
                                            // Re-snapshot framed as update. Anchor afresh.
                                            book.apply_snapshot(bids, asks, Some(seq_id));
                                        }
                                        PrevSeq::Continuity(prev) => {
                                            let Some(local) = book.seq else { continue };
                                            if seq_id <= local { continue; } // stale
                                            if prev != local {
                                                warn!("[okx/{inst_id}] gap (prevSeqId={prev} vs local={local}), waiting for snapshot");
                                                book.clear();
                                                continue;
                                            }
                                            book.apply_deltas(bids, asks, Some(seq_id));
                                        }
                                        PrevSeq::Invalid(reason) => {
                                            return Err(eyre!(
                                                "[okx/{inst_id}] {reason}"
                                            ));
                                        }
                                    }
                                }
                                _ => continue,
                            }
                            if !book.is_crossed() {
                                if let Some(d) = book.to_orderbook_data(exch_ts, received_at) {
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
                    if write.send(Message::Text("ping".into())).await.is_err() {
                        return Err(eyre!("ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Okx {
    fn id(&self) -> &str {
        "okx"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[okx] no pairs"));
        }
        sink.status("okx", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

/// Classification of OKX `prevSeqId` on an `update` message.
#[derive(Debug, PartialEq, Eq)]
enum PrevSeq {
    /// `prevSeqId == -1` — sentinel meaning this update is itself a
    /// (re)snapshot anchor; no continuity with prior local seq required.
    SnapshotAnchor,
    /// Normal positive value — must equal local `seqId` for the delta to be
    /// continuous.
    Continuity(u64),
    /// Missing field or any negative value other than `-1`. Caller should
    /// fail the session so the supervisor reconnects rather than silently
    /// desyncing.
    Invalid(&'static str),
}

fn classify_prev_seq(v: Option<&Value>) -> PrevSeq {
    let Some(raw) = v.and_then(parse_i64) else {
        return PrevSeq::Invalid("update missing prevSeqId; protocol violation");
    };
    if raw == -1 {
        PrevSeq::SnapshotAnchor
    } else if raw < 0 {
        PrevSeq::Invalid("invalid negative prevSeqId")
    } else {
        PrevSeq::Continuity(raw as u64)
    }
}

/// OKX entries: `[price, size, deprecated, order_count]`.
fn parse_levels(v: Option<&Value>) -> Vec<(f64, f64)> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|row| {
            let r = row.as_array()?;
            let p = parse_f64(r.first()?)?;
            let q = parse_f64(r.get(1)?)?;
            Some((p, q))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_okx_levels_with_extra_fields() {
        let raw = r#"[["77831.4","0.3","0","5"],["77820.0","1.2","0","3"]]"#;
        let v: Value = serde_json::from_str(raw).unwrap();
        let lv = parse_levels(Some(&v));
        assert_eq!(lv, vec![(77831.4, 0.3), (77820.0, 1.2)]);
    }

    #[test]
    fn snapshot_message_shape() {
        let raw = r#"{"arg":{"channel":"books","instId":"BTC-USDT"},"action":"snapshot","data":[{"asks":[["77831","0.3","0","5"]],"bids":[["77820","1.2","0","3"]],"ts":"1695716059516","seqId":1,"prevSeqId":-1}]}"#;
        let v: Value = serde_json::from_str(raw).unwrap();
        assert_eq!(v.get("action").unwrap().as_str().unwrap(), "snapshot");
        assert_eq!(
            v.get("arg")
                .unwrap()
                .get("instId")
                .unwrap()
                .as_str()
                .unwrap(),
            "BTC-USDT"
        );
        let data = v.get("data").unwrap().as_array().unwrap().first().unwrap();
        assert_eq!(parse_u64(data.get("seqId").unwrap()), Some(1));
    }

    /// `prevSeqId == -1` on an update is the documented OKX sentinel for a
    /// re-snapshot anchor. It MUST NOT silently fall through to the
    /// continuity check (the previous bug used `parse_u64(...).unwrap_or(local)`
    /// which made a re-snapshot look like a normal contiguous delta).
    #[test]
    fn prev_seq_id_minus_one_is_snapshot_sentinel() {
        let raw = r#"{"arg":{"channel":"books","instId":"BTC-USDT"},"action":"update","data":[{"asks":[["77831","0.3","0","5"]],"bids":[["77820","1.2","0","3"]],"ts":"1695716059516","seqId":42,"prevSeqId":-1}]}"#;
        let v: Value = serde_json::from_str(raw).unwrap();
        let data = v.get("data").unwrap().as_array().unwrap().first().unwrap();
        // parse_u64 cannot represent -1 (returns None) — this is exactly why
        // the old `.unwrap_or(local)` path was wrong.
        assert_eq!(parse_u64(data.get("prevSeqId").unwrap()), None);
        // parse_i64 must surface the sentinel value.
        assert_eq!(parse_i64(data.get("prevSeqId").unwrap()), Some(-1));
        // And the classifier must route it as a snapshot anchor.
        assert_eq!(
            classify_prev_seq(data.get("prevSeqId")),
            PrevSeq::SnapshotAnchor
        );
    }

    /// Normal positive `prevSeqId` must classify as a continuity check value.
    #[test]
    fn prev_seq_id_positive_is_continuity() {
        let raw = r#"{"arg":{"channel":"books","instId":"BTC-USDT"},"action":"update","data":[{"asks":[],"bids":[],"ts":"1695716059516","seqId":12346,"prevSeqId":12345}]}"#;
        let v: Value = serde_json::from_str(raw).unwrap();
        let data = v.get("data").unwrap().as_array().unwrap().first().unwrap();
        assert_eq!(parse_i64(data.get("prevSeqId").unwrap()), Some(12345));
        assert_eq!(
            classify_prev_seq(data.get("prevSeqId")),
            PrevSeq::Continuity(12345)
        );
    }

    /// Strings are also accepted (some OKX payloads stringify integers).
    #[test]
    fn prev_seq_id_positive_string_is_continuity() {
        let v: Value = serde_json::from_str(r#"{"prevSeqId":"99"}"#).unwrap();
        assert_eq!(
            classify_prev_seq(v.get("prevSeqId")),
            PrevSeq::Continuity(99)
        );
    }

    /// Missing or non-`-1` negative values must be rejected so the session
    /// fails closed instead of silently desyncing.
    #[test]
    fn prev_seq_id_invalid_cases() {
        let v: Value = serde_json::from_str(r#"{}"#).unwrap();
        assert!(matches!(
            classify_prev_seq(v.get("prevSeqId")),
            PrevSeq::Invalid(_)
        ));
        let v: Value = serde_json::from_str(r#"{"prevSeqId":-7}"#).unwrap();
        assert!(matches!(
            classify_prev_seq(v.get("prevSeqId")),
            PrevSeq::Invalid(_)
        ));
    }
}
