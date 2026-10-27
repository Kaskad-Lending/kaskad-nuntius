//! CoinW trade stream — same endpoint + quirks as the collector's book
//! channel (`wss://ws.futurescw.com`, Origin header required, numeric
//! pairCode bootstrap via REST `returnTicker`, `{"event":"ping"}` app
//! keepalive every 30s), channel type `fills` instead of `depth_snapshot`.
//! Push frames DOUBLE-ENCODE `data` as a JSON string containing an ARRAY
//! of trades (all string values): price, size (base), time (epoch ms),
//! seq. The outer `time` is an internal counter (17 digits, not epoch);
//! the usable timestamp is the per-trade `time`. Acks carry `data` as an
//! object with `result`. Live-verified 2026-07-19; re-verified 2026-07-27.

use crate::types::{EventTx, VenueCfg};
use crate::util::{parse_f64, parse_i64, parse_u64, ws_connect_with_origin, IDLE_TIMEOUT};
use eyre::{eyre, Result, WrapErr};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

const REST_BASE: &str = "https://api.coinw.com";
const WS_ORIGIN: &str = "https://www.coinw.com";
const PING_INTERVAL: Duration = Duration::from_secs(30);

async fn resolve_pair_codes(pairs: &[String]) -> Result<HashMap<String, String>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let v: Value = client
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
    for pair in pairs {
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

/// Trades in a `fills` push frame as (pairCode, price, qty base, ts epoch
/// ms) rows. The `data` string is re-parsed (double-encoded); ts is the
/// per-trade `time`, never the outer counter, 0 when absent. Non-fills
/// frames, acks (`data` object), and malformed payloads yield no rows.
fn parse_trades(v: &Value) -> Vec<(String, f64, f64, i64)> {
    if v.get("type").and_then(|t| t.as_str()) != Some("fills") {
        return Vec::new();
    }
    let Some(code) = v.get("pairCode").and_then(|c| c.as_str()) else {
        return Vec::new();
    };
    let Some(Value::String(inner)) = v.get("data") else {
        return Vec::new();
    };
    let Ok(trades) = serde_json::from_str::<Value>(inner) else {
        return Vec::new();
    };
    let Some(arr) = trades.as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for t in arr {
        let (Some(price), Some(qty)) = (
            t.get("price").and_then(parse_f64),
            t.get("size").and_then(parse_f64),
        ) else {
            continue;
        };
        let ts = t.get("time").and_then(parse_i64).unwrap_or(0);
        out.push((code.to_string(), price, qty, ts));
    }
    out
}

pub async fn run(cfg: &VenueCfg, tx: &EventTx) -> Result<()> {
    let code_to_sym = resolve_pair_codes(&cfg.pairs).await?;
    let mut ws = ws_connect_with_origin(&cfg.ws_url, Some(WS_ORIGIN)).await?;
    for code in code_to_sym.keys() {
        ws.send(Message::Text(
            json!({
                "event": "sub",
                "params": {"biz": "exchange", "type": "fills", "pairCode": code},
            })
            .to_string(),
        ))
        .await?;
    }
    cfg.send_connected(tx);
    let (mut write, mut read) = ws.split();
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await;

    loop {
        tokio::select! {
            _ = ping.tick() => {
                if write
                    .send(Message::Text(json!({"event": "ping"}).to_string()))
                    .await
                    .is_err()
                {
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
                    if v.get("event").and_then(|e| e.as_str()) == Some("pong") {
                        continue;
                    }
                    if v.get("type").and_then(|t| t.as_str()) != Some("fills") {
                        continue;
                    }
                    // Subscribe ack: data is an object with `result`.
                    if let Some(o) = v.get("data").and_then(|d| d.as_object()) {
                        if o.get("result").and_then(|r| r.as_bool()) == Some(false) {
                            return Err(eyre!("coinw subscription rejected: {text}"));
                        }
                        continue;
                    }
                    for (code, price, qty, ts) in parse_trades(&v) {
                        if let Some(pair) = code_to_sym.get(&code) {
                            cfg.send_trade(tx, pair, price, qty, ts);
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

    // Live captures from wss://ws.futurescw.com, 2026-07-27, pairCode 78
    // (BTC_USDT per returnTicker).
    const ACK: &str = r#"{"biz":"exchange","pairCode":"78","data":{"result":true},"channel":"subscribe","type":"fills"}"#;
    const PUSH: &str = r#"{"biz":"exchange","pairCode":"78","data":"[{\"price\":\"65223.48\",\"seq\":\"162916055\",\"side\":\"BUY\",\"size\":\"0.0003\",\"symbol\":\"78\",\"time\":\"1785141193898\"}]","time":43178593844614700,"type":"fills"}"#;

    #[test]
    fn push_parses_through_double_encoded_data() {
        let v: Value = serde_json::from_str(PUSH).unwrap();
        // `data` arrives as a JSON string, not an array — the trades only
        // exist after a second parse.
        assert!(v.get("data").unwrap().is_string());
        let rows = parse_trades(&v);
        assert_eq!(
            rows,
            vec![("78".to_string(), 65223.48, 0.0003, 1785141193898)]
        );
        // ts is the inner per-trade `time` (epoch ms; capture received at
        // 1785141194153 ms wall clock), not the outer 17-digit counter.
        assert_ne!(rows[0].3, 43178593844614700);
        // qty is BASE (BTC): 0.0003 * 65223.48 ≈ 19.57 USDT notional.
        assert!((rows[0].1 * rows[0].2 - 19.567).abs() < 0.01);
    }

    #[test]
    fn ack_frame_yields_no_trades() {
        let v: Value = serde_json::from_str(ACK).unwrap();
        assert!(parse_trades(&v).is_empty());
        // Ack carries `data` as an object — the shape the read loop keys
        // its accept/reject handling on.
        assert_eq!(
            v.get("data")
                .and_then(|d| d.get("result"))
                .and_then(|r| r.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn pong_and_reject_frames_yield_no_trades() {
        // Server app-level pong (shape per 2026-07-19 session).
        let pong: Value = serde_json::from_str(r#"{"event":"pong"}"#).unwrap();
        assert!(parse_trades(&pong).is_empty());
        // Rejected subscription: `result: false` in the ack object.
        let rej: Value = serde_json::from_str(
            r#"{"biz":"exchange","pairCode":"9999","data":{"result":false},"channel":"subscribe","type":"fills"}"#,
        )
        .unwrap();
        assert!(parse_trades(&rej).is_empty());
        assert_eq!(
            rej.get("data")
                .and_then(|d| d.get("result"))
                .and_then(|r| r.as_bool()),
            Some(false)
        );
    }
}
