//! LBank trade stream — same endpoint as the collector
//! (`wss://api.lbkex.com/ws/V2/`). Subscribe one frame per pair:
//! `{"action":"subscribe","subscribe":"trade","pair":"tao_usdt"}` — there
//! is NO ack; silence = wrong symbol. Server sends an application ping
//! `{"action":"ping","ping":"<id>"}` ~every 60s that MUST be echoed as
//! `{"action":"pong","pong":"<id>"}` (id echo verified live; a bare pong
//! was not tested).
//!
//! Trade push: `type=="trade"`, symbol at top-level `pair`, one trade per
//! frame. `trade.volume` = BASE qty (JSON number, sometimes scientific
//! notation), `trade.price` = quote price, `trade.amount` = quote notional.
//! `trade.TS` is a NAIVE ISO string in BEIJING TIME (UTC+8) — the trade
//! channel has NO epoch field (unlike the book channel's `ds`), so the
//! -8h correction is mandatory. Live-verified 2026-07-19.

use crate::types::{EventTx, VenueCfg};
use crate::util::{parse_f64, ws_connect, IDLE_TIMEOUT};
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

const BEIJING_OFFSET_MS: i64 = 8 * 3600 * 1000;

/// `"2026-07-19T21:04:33.597"` (UTC+8, naive) → epoch ms UTC.
fn parse_beijing_ts(s: &str) -> Option<i64> {
    let naive = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f").ok()?;
    Some(naive.and_utc().timestamp_millis() - BEIJING_OFFSET_MS)
}

/// Trades in one decoded frame: (`pair` as sent, price, BASE qty, epoch ms
/// UTC). LBank sends one trade per frame; non-trade frames (pings, depth
/// pushes) yield nothing. `ts` is 0 when `trade.TS` is missing or
/// unparseable.
fn parse_trades(v: &Value) -> Vec<(String, f64, f64, i64)> {
    if v.get("type").and_then(|t| t.as_str()) != Some("trade") {
        return Vec::new();
    }
    let Some(pair) = v.get("pair").and_then(|p| p.as_str()) else {
        return Vec::new();
    };
    let Some(t) = v.get("trade") else {
        return Vec::new();
    };
    let (Some(price), Some(qty)) = (
        t.get("price").and_then(parse_f64),
        t.get("volume").and_then(parse_f64),
    ) else {
        return Vec::new();
    };
    let ts = t
        .get("TS")
        .and_then(|s| s.as_str())
        .and_then(parse_beijing_ts)
        .unwrap_or(0);
    vec![(pair.to_string(), price, qty, ts)]
}

pub async fn run(cfg: &VenueCfg, tx: &EventTx) -> Result<()> {
    let mut ws = ws_connect(&cfg.ws_url).await?;
    for pair in &cfg.pairs {
        ws.send(Message::Text(
            json!({
                "action": "subscribe",
                "subscribe": "trade",
                "pair": pair.to_lowercase(),
            })
            .to_string(),
        ))
        .await?;
    }
    cfg.send_connected(tx);
    let (mut write, mut read) = ws.split();
    // Client-initiated liveness ping (the collector does the same every 30s).
    let mut ping = tokio::time::interval(Duration::from_secs(30));
    ping.tick().await;
    let mut ping_seq: u64 = 0;

    loop {
        tokio::select! {
            _ = ping.tick() => {
                ping_seq += 1;
                let m = json!({"action": "ping", "ping": format!("volmon-{ping_seq}")}).to_string();
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
                    // Server keepalive: echo the id back or get dropped ~1min later.
                    if v.get("action").and_then(|a| a.as_str()) == Some("ping") {
                        if let Some(id) = v.get("ping") {
                            let reply = json!({"action": "pong", "pong": id}).to_string();
                            if write.send(Message::Text(reply)).await.is_err() {
                                return Err(eyre!("pong send failed"));
                            }
                        }
                        continue;
                    }
                    for (sym, price, qty, ts) in parse_trades(&v) {
                        let Some(pair) =
                            cfg.pairs.iter().find(|p| p.eq_ignore_ascii_case(&sym))
                        else {
                            continue;
                        };
                        cfg.send_trade(tx, pair, price, qty, ts);
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

    /// Trade push, 2026-07-19 live session: `TS` and the scientific-notation
    /// `volume` are the captured values; `price`/`amount`/`direction` filled
    /// in per the channel schema (`amount` = price × volume, quote notional).
    const TRADE_FRAME: &str = r#"{"trade":{"volume":1.4E-4,"amount":0.06031729,"price":430.8378,"direction":"buy","TS":"2026-07-19T21:04:33.597"},"SERVER":"V2","type":"trade","pair":"tao_usdt","TS":"2026-07-19T21:04:33.602"}"#;

    #[test]
    fn trade_push_parses_price_qty_ts() {
        let v: Value = serde_json::from_str(TRADE_FRAME).unwrap();
        let rows = parse_trades(&v);
        assert_eq!(rows.len(), 1);
        let (sym, price, qty, ts) = &rows[0];
        assert_eq!(sym, "tao_usdt");
        assert_eq!(*price, 430.8378);
        // `trade.volume` is BASE qty; 1.4E-4 must survive as 0.00014.
        assert_eq!(*qty, 0.00014);
        // Naive Beijing TS 21:04:33.597 → 13:04:33.597Z, epoch ms.
        assert_eq!(*ts, 1784466273597);
        let utc = chrono::DateTime::from_timestamp_millis(*ts).unwrap();
        assert_eq!(utc.to_rfc3339(), "2026-07-19T13:04:33.597+00:00");
    }

    #[test]
    fn server_ping_yields_no_trades() {
        // Application ping, ~every 60s; the read loop echoes it before parsing.
        let v: Value = serde_json::from_str(
            r#"{"action":"ping","ping":"0f508b28-7f79-4b7a-a0f4-1cf75a972ac8"}"#,
        )
        .unwrap();
        assert!(parse_trades(&v).is_empty());
    }

    #[test]
    fn depth_push_yields_no_trades() {
        // Same endpoint carries the depth channel; `type` gates it out.
        let v: Value = serde_json::from_str(
            r#"{"depth":{"bids":[["430.82","2.5"]],"asks":[["430.85","6.3"]]},"pair":"tao_usdt","SERVER":"V2","type":"depth","TS":"2026-07-19T21:04:33.6"}"#,
        )
        .unwrap();
        assert!(parse_trades(&v).is_empty());
    }

    #[test]
    fn missing_ts_yields_zero() {
        let v: Value = serde_json::from_str(
            r#"{"trade":{"volume":2.0,"price":430.0},"type":"trade","pair":"tao_usdt"}"#,
        )
        .unwrap();
        assert_eq!(
            parse_trades(&v),
            vec![("tao_usdt".to_string(), 430.0, 2.0, 0)]
        );
    }

    #[test]
    fn beijing_ts_shifted_to_utc() {
        // Live capture: TS "2026-07-19T21:04:33.597" arrived at 13:04:33.666Z.
        let ms = parse_beijing_ts("2026-07-19T21:04:33.597").unwrap();
        let utc = chrono::DateTime::from_timestamp_millis(ms).unwrap();
        assert_eq!(utc.to_rfc3339(), "2026-07-19T13:04:33.597+00:00");
    }

    #[test]
    fn scientific_notation_volume_parses() {
        let v: Value = serde_json::from_str(r#"{"volume":1.4E-4}"#).unwrap();
        assert_eq!(v.get("volume").and_then(parse_f64), Some(0.00014));
    }
}
