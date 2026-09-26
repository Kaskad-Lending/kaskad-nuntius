//! XT trade stream — same endpoint + envelope as the collector
//! (`wss://stream.xt.com/public`): one subscribe with all channels
//! `{"method":"subscribe","params":["trade@tao_usdt",...],"id":1}`.
//! Keepalive is the literal text frame `ping` every 20s answered by the
//! literal `pong` (not JSON — skipped before parsing). Trade push:
//! `topic=="trade"`, `data` is a SINGLE object: s (symbol, lowercase),
//! p (price str), q (BASE qty str), t (epoch ms int), i (trade id str),
//! b (buyer-is-maker bool). No replay on subscribe. Live-verified
//! 2026-07-19.

use crate::types::{EventTx, VenueCfg};
use crate::util::{parse_f64, parse_i64, ws_connect, IDLE_TIMEOUT};
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

/// Extracts (venue symbol, price, qty_base, ts_ms) rows from a parsed
/// frame. A trade push carries a single `data` object, so at most one row
/// comes back; `i` (trade id, string) and `b` (buyer-is-maker) are not
/// used. Non-trade topics and acks yield no rows.
fn parse_trades(v: &Value) -> Vec<(String, f64, f64, i64)> {
    if v.get("topic").and_then(|t| t.as_str()) != Some("trade") {
        return Vec::new();
    }
    let Some(data) = v.get("data") else {
        return Vec::new();
    };
    let Some(sym) = data.get("s").and_then(|s| s.as_str()) else {
        return Vec::new();
    };
    let (Some(price), Some(qty)) = (
        data.get("p").and_then(parse_f64),
        data.get("q").and_then(parse_f64),
    ) else {
        return Vec::new();
    };
    let ts = data.get("t").and_then(parse_i64).unwrap_or(0);
    vec![(sym.to_string(), price, qty, ts)]
}

pub async fn run(cfg: &VenueCfg, tx: &EventTx) -> Result<()> {
    let mut ws = ws_connect(&cfg.ws_url).await?;
    let params: Vec<String> = cfg
        .pairs
        .iter()
        .map(|p| format!("trade@{}", p.to_lowercase()))
        .collect();
    ws.send(Message::Text(
        json!({"method": "subscribe", "params": params, "id": 1}).to_string(),
    ))
    .await?;
    cfg.send_connected(tx);
    let (mut write, mut read) = ws.split();
    let mut ping = tokio::time::interval(Duration::from_secs(20));
    ping.tick().await;

    loop {
        tokio::select! {
            _ = ping.tick() => {
                if write.send(Message::Text("ping".into())).await.is_err() {
                    return Err(eyre!("ping send failed"));
                }
            }
            msg = tokio::time::timeout(IDLE_TIMEOUT, read.next()) => match msg
                .map_err(|_| eyre!("idle: no frames for {IDLE_TIMEOUT:?}"))?
            {
                Some(Ok(Message::Text(text))) => {
                    if text == "pong" {
                        continue;
                    }
                    let v: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if v.get("method").and_then(|m| m.as_str()) == Some("subscribe")
                        && v.get("code").and_then(|c| c.as_i64()) != Some(0)
                    {
                        return Err(eyre!("xt subscription rejected: {text}"));
                    }
                    for (sym, price, qty, ts) in parse_trades(&v) {
                        if let Some(pair) =
                            cfg.pairs.iter().find(|p| p.eq_ignore_ascii_case(&sym))
                        {
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

    /// Trade push per the live-verified 2026-07-19 shape: `t` is already
    /// epoch ms, `i` is a string trade id, `b` a bool — the last two carry
    /// no volume information.
    #[test]
    fn trade_push_parses() {
        let s = r#"{"topic":"trade","event":"trade@tao_usdt","data":{"s":"tao_usdt","i":"373668026467356160","t":1784466125031,"p":"432.86","q":"0.245","b":true}}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let rows = parse_trades(&v);
        assert_eq!(rows.len(), 1);
        let (sym, price, qty, ts) = &rows[0];
        assert_eq!(sym, "tao_usdt");
        assert_eq!(*price, 432.86);
        assert_eq!(*qty, 0.245);
        assert_eq!(*ts, 1784466125031);
    }

    #[test]
    fn subscribe_ack_yields_no_trades() {
        let s = r#"{"id":"1","code":0,"msg":"SUCCESS","method":"subscribe"}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        assert!(parse_trades(&v).is_empty());
    }

    /// `i` stays a string even for numeric-looking ids and `b` flips per
    /// side; neither field affects the extracted row.
    #[test]
    fn string_trade_id_and_bool_b_ignored() {
        let maker = r#"{"topic":"trade","event":"trade@btc_usdt","data":{"s":"btc_usdt","i":"6316559590087222000","t":1784466125999,"p":"118432.1","q":"0.0021","b":true}}"#;
        let taker = r#"{"topic":"trade","event":"trade@btc_usdt","data":{"s":"btc_usdt","i":"6316559590087222001","t":1784466125999,"p":"118432.1","q":"0.0021","b":false}}"#;
        for s in [maker, taker] {
            let v: Value = serde_json::from_str(s).unwrap();
            let rows = parse_trades(&v);
            assert_eq!(
                rows,
                vec![("btc_usdt".to_string(), 118432.1, 0.0021, 1784466125999)]
            );
        }
    }

    #[test]
    fn non_trade_topic_yields_no_trades() {
        let s = r#"{"topic":"depth_update","event":"depth_update@tao_usdt","data":{"s":"tao_usdt","fi":12346,"i":12350,"t":1784466125031,"a":[],"b":[]}}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        assert!(parse_trades(&v).is_empty());
    }

    #[test]
    fn missing_t_defaults_to_zero() {
        let s = r#"{"topic":"trade","event":"trade@tao_usdt","data":{"s":"tao_usdt","i":"373668026467356161","p":"432.9","q":"1.5","b":false}}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        assert_eq!(
            parse_trades(&v),
            vec![("tao_usdt".to_string(), 432.9, 1.5, 0)]
        );
    }
}
