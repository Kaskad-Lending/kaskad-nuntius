//! WhiteBIT trade stream — same endpoint as the collector
//! (`wss://api.whitebit.com/ws`). One subscribe covers all markets:
//! `{"id":1,"method":"trades_subscribe","params":["BTC_USDT","TAO_USDT"]}`
//! — a repeat call replaces the market set, so the full list goes in one
//! message. Application-level JSON ping `{"id":0,"method":"ping",
//! "params":[]}` every 40s; the server does not answer client
//! protocol-level pings.
//!
//! The first `trades_update` per market replays the ~100 most recent
//! trades, newest first, with stale timestamps (verified live 2026-07-19
//! and 2026-07-27). Trade ids are strictly increasing per market, so the
//! highest seen id is kept per market across sessions: the first frame on
//! a cold market seeds the watermark and is not counted; afterwards only
//! `id > max_id` rows are counted, which lets the replay backfill trades
//! missed during a reconnect gap instead of double-counting them.
//! `time` is float epoch seconds; `amount` is BASE quantity.

use crate::types::{EventTx, VenueCfg};
use crate::util::{parse_f64, ws_connect, IDLE_TIMEOUT};
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

/// market → highest trade id seen. Static so the watermark survives
/// session reconnects (one whitebit task per process).
static MAX_ID: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);

/// Market name if `v` is a `trades_update` push.
fn trades_update_market(v: &Value) -> Option<&str> {
    if v.get("method").and_then(|m| m.as_str()) != Some("trades_update") {
        return None;
    }
    v.get("params")?.get(0)?.as_str()
}

/// Countable `(price, qty_base, ts_ms)` rows from a `trades_update` trade
/// array given the market's current watermark, plus the new watermark.
/// A `None` watermark marks a cold market: the frame is the snapshot
/// replay, so nothing is counted and the frame's highest id seeds the
/// watermark. Otherwise only `id > watermark` rows are counted.
fn parse_trades(trades: &[Value], watermark: Option<u64>) -> (Vec<(f64, f64, i64)>, Option<u64>) {
    let frame_max = trades
        .iter()
        .filter_map(|t| t.get("id").and_then(|i| i.as_u64()))
        .max();
    let new_watermark = match (watermark, frame_max) {
        (Some(w), Some(f)) => Some(w.max(f)),
        (w, f) => w.or(f),
    };
    let Some(max_id) = watermark else {
        return (Vec::new(), new_watermark);
    };
    let mut rows = Vec::new();
    for t in trades {
        let Some(id) = t.get("id").and_then(|i| i.as_u64()) else {
            continue;
        };
        if id <= max_id {
            continue;
        }
        let (Some(price), Some(qty)) = (
            t.get("price").and_then(parse_f64),
            t.get("amount").and_then(parse_f64),
        ) else {
            continue;
        };
        let ts = t
            .get("time")
            .and_then(parse_f64)
            .map(|s| (s * 1000.0) as i64)
            .unwrap_or(0);
        rows.push((price, qty, ts));
    }
    (rows, new_watermark)
}

pub async fn run(cfg: &VenueCfg, tx: &EventTx) -> Result<()> {
    let mut ws = ws_connect(&cfg.ws_url).await?;
    let markets: Vec<String> = cfg.pairs.iter().map(|p| p.to_uppercase()).collect();
    ws.send(Message::Text(
        json!({"id": 1, "method": "trades_subscribe", "params": markets}).to_string(),
    ))
    .await?;
    cfg.send_connected(tx);
    let (mut write, mut read) = ws.split();
    let mut ping = tokio::time::interval(Duration::from_secs(40));
    ping.tick().await;

    loop {
        tokio::select! {
            _ = ping.tick() => {
                let m = json!({"id": 0, "method": "ping", "params": []}).to_string();
                if write.send(Message::Text(m)).await.is_err() {
                    return Err(eyre!("ping send failed"));
                }
            }
            msg = tokio::time::timeout(IDLE_TIMEOUT, read.next()) => match msg
                .map_err(|_| eyre!("idle: no frames for {IDLE_TIMEOUT:?}"))?
            {
                Some(Ok(Message::Text(text))) => {
                    let v: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if v.get("error").is_some_and(|e| !e.is_null()) {
                        return Err(eyre!("whitebit error frame: {text}"));
                    }
                    let Some(pair) = trades_update_market(&v)
                        .and_then(|m| cfg.pairs.iter().find(|p| p.eq_ignore_ascii_case(m)))
                    else {
                        continue;
                    };
                    let Some(trades) = v
                        .get("params")
                        .and_then(|p| p.get(1))
                        .and_then(|t| t.as_array())
                    else {
                        continue;
                    };
                    let watermark = {
                        let mut guard = MAX_ID.lock().unwrap_or_else(|e| e.into_inner());
                        guard
                            .get_or_insert_with(HashMap::new)
                            .get(pair.as_str())
                            .copied()
                    };
                    let (rows, new_watermark) = parse_trades(trades, watermark);
                    for (price, qty, ts) in rows {
                        cfg.send_trade(tx, pair, price, qty, ts);
                    }
                    if let Some(wm) = new_watermark {
                        let mut guard = MAX_ID.lock().unwrap_or_else(|e| e.into_inner());
                        let map = guard.get_or_insert_with(HashMap::new);
                        let e = map.entry(pair.clone()).or_insert(0);
                        if wm > *e {
                            *e = wm;
                        }
                    }
                }
                Some(Ok(Message::Ping(p))) => {
                    let _ = write.send(Message::Pong(p)).await;
                }
                Some(Ok(Message::Close(_))) | None => return Err(eyre!("WS closed")),
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(eyre!("WS error: {e}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Live captures, wss://api.whitebit.com/ws, 2026-07-27 probe session.
    const ACK: &str = r#"{"error": null, "result": {"status": "success"}, "id": 1}"#;
    const LIVE_PUSH: &str = r#"{"method": "trades_update", "params": ["BTC_USDT", [{"id": 22516225781, "time": 1785141195.516568, "price": "65210.54", "amount": "0.000061", "type": "sell", "rpi": false}]], "id": null}"#;
    // Endpoints of the captured 100-trade snapshot replay (ids descending,
    // trade times up to ~12.7 min older than receipt); array truncated to
    // its captured first and last elements.
    const SNAPSHOT: &str = r#"{"method": "trades_update", "params": ["BTC_USDT", [{"id": 22516208448, "time": 1785141132.676807, "price": "65240.83", "amount": "0.000055", "type": "sell", "rpi": false}, {"id": 22516021419, "time": 1785140429.594488, "price": "65222.72", "amount": "0.00015", "type": "sell", "rpi": false}]], "id": null}"#;

    fn trades(s: &str) -> Vec<Value> {
        let v: Value = serde_json::from_str(s).unwrap();
        v["params"][1].as_array().unwrap().clone()
    }

    #[test]
    fn ack_is_not_a_trades_update() {
        let v: Value = serde_json::from_str(ACK).unwrap();
        assert_eq!(trades_update_market(&v), None);
        let v: Value = serde_json::from_str(LIVE_PUSH).unwrap();
        assert_eq!(trades_update_market(&v), Some("BTC_USDT"));
    }

    #[test]
    fn cold_market_snapshot_seeds_watermark_counts_nothing() {
        let (rows, wm) = parse_trades(&trades(SNAPSHOT), None);
        assert!(rows.is_empty());
        assert_eq!(wm, Some(22516208448));
    }

    #[test]
    fn warm_market_counts_ids_above_watermark() {
        let (rows, wm) = parse_trades(&trades(LIVE_PUSH), Some(22516208448));
        // time is float epoch seconds → epoch ms.
        assert_eq!(rows, vec![(65210.54, 0.000061, 1785141195516)]);
        assert_eq!(wm, Some(22516225781));
    }

    #[test]
    fn replay_backfills_only_above_watermark() {
        // Watermark sits between the snapshot's two ids: the older trade
        // is a duplicate, the newer one is backfill.
        let (rows, wm) = parse_trades(&trades(SNAPSHOT), Some(22516021419));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, 65240.83);
        assert_eq!(wm, Some(22516208448));
    }

    #[test]
    fn watermark_never_regresses() {
        let (rows, wm) = parse_trades(&trades(SNAPSHOT), Some(99_999_999_999));
        assert!(rows.is_empty());
        assert_eq!(wm, Some(99_999_999_999));
    }
}
