//! KuCoin trade stream — same bootstrap as the collector's book channel:
//! POST `bullet-public` → token + endpoint + pingInterval, connect
//! `{endpoint}?token=...&connectId=...`, wait for the `welcome` frame,
//! then subscribe topics `/market/match:{SYMBOL}` (one per pair, distinct
//! ids). App-level `{"id":"p","type":"ping"}` at pingInterval. Trade push:
//! `type=="message"`, `data.price`/`data.size` (base) strings, `data.time`
//! is NANOSECONDS as a string (book channel uses ms — do not reuse that
//! parse). One fill per frame, no replay. Live-verified 2026-07-19.

use crate::types::{EventTx, VenueCfg};
use crate::util::{now_ms, parse_f64, parse_i64, ws_connect, IDLE_TIMEOUT};
use eyre::{eyre, Result, WrapErr};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

const REST_BASE: &str = "https://api.kucoin.com";

async fn fetch_token() -> Result<(String, Duration)> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let v: Value = client
        .post(format!("{REST_BASE}/api/v1/bullet-public"))
        .send()
        .await
        .wrap_err("kucoin bullet-public")?
        .error_for_status()?
        .json()
        .await?;
    let data = v.get("data").ok_or_else(|| eyre!("missing data"))?;
    let token = data
        .get("token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| eyre!("missing token"))?;
    let server = data
        .get("instanceServers")
        .and_then(|s| s.as_array())
        .and_then(|a| a.first())
        .ok_or_else(|| eyre!("missing instanceServers"))?;
    let endpoint = server
        .get("endpoint")
        .and_then(|e| e.as_str())
        .ok_or_else(|| eyre!("missing endpoint"))?;
    let ping_ms = server
        .get("pingInterval")
        .and_then(|p| p.as_u64())
        .unwrap_or(18_000);
    let url = format!("{endpoint}?token={token}&connectId=volmon{:x}", now_ms());
    Ok((url, Duration::from_millis(ping_ms)))
}

/// First post-connect frame; the server sends `{"id":...,"type":"welcome"}`
/// before it accepts subscribes (live: `{"id":"probe...","type":"welcome"}`).
fn is_welcome(text: &str) -> bool {
    serde_json::from_str::<Value>(text)
        .map(|v| v.get("type").and_then(|t| t.as_str()) == Some("welcome"))
        .unwrap_or(false)
}

/// Fills from one decoded frame: `(symbol, price, qty_base, ts_ms)` — at
/// most one row, KuCoin sends one fill per frame. `data.time` is
/// nanoseconds-as-string; converted to epoch ms here (missing → 0).
/// Control frames (`welcome`/`ack`/`pong`/`error`) yield no rows; the
/// caller handles `error` frames as fatal before calling this.
fn parse_trades(v: &Value) -> Vec<(String, f64, f64, i64)> {
    if v.get("type").and_then(|t| t.as_str()) != Some("message") {
        return Vec::new();
    }
    let Some(data) = v.get("data") else {
        return Vec::new();
    };
    let Some(sym) = data.get("symbol").and_then(|s| s.as_str()) else {
        return Vec::new();
    };
    let (Some(price), Some(qty)) = (
        data.get("price").and_then(parse_f64),
        data.get("size").and_then(parse_f64),
    ) else {
        return Vec::new();
    };
    let ts = data
        .get("time")
        .and_then(parse_i64)
        .map(|ns| ns / 1_000_000)
        .unwrap_or(0);
    vec![(sym.to_string(), price, qty, ts)]
}

pub async fn run(cfg: &VenueCfg, tx: &EventTx) -> Result<()> {
    let (url, ping_iv) = fetch_token().await?;
    let mut ws = ws_connect(&url).await?;

    match ws.next().await {
        Some(Ok(Message::Text(text))) if is_welcome(&text) => {}
        other => return Err(eyre!("kucoin: missing welcome ({other:?})")),
    }

    for (i, pair) in cfg.pairs.iter().enumerate() {
        ws.send(Message::Text(
            json!({
                "id": format!("sub{i}"),
                "type": "subscribe",
                "topic": format!("/market/match:{pair}"),
                "privateChannel": false,
                "response": true,
            })
            .to_string(),
        ))
        .await?;
    }
    cfg.send_connected(tx);
    let (mut write, mut read) = ws.split();
    let mut ping = tokio::time::interval(ping_iv);
    ping.tick().await;

    loop {
        tokio::select! {
            _ = ping.tick() => {
                let m = json!({"id": "p", "type": "ping"}).to_string();
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
                    if v.get("type").and_then(|t| t.as_str()) == Some("error") {
                        return Err(eyre!("kucoin error frame: {text}"));
                    }
                    for (sym, price, qty, ts) in parse_trades(&v) {
                        if let Some(pair) = cfg
                            .pairs
                            .iter()
                            .find(|p| p.eq_ignore_ascii_case(&sym))
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

    // Verbatim captures, wss://ws-api-spot.kucoin.com `/market/match:BTC-USDT`,
    // 2026-07-27 probe session.
    const WELCOME: &str = r#"{"id":"probe19fa2b4de6c","type":"welcome"}"#;
    const ACK: &str = r#"{"id":"sub0","type":"ack"}"#;
    const MATCH: &str = r#"{"topic":"/market/match:BTC-USDT","type":"message","subject":"trade.l3match","data":{"makerOrderId":"6a6717c36bce220007404013","price":"65215.6","sequence":"23715934308417536","side":"sell","size":"0.04915634","symbol":"BTC-USDT","takerOrderId":"6a6717cb536fcb0007901fdd","time":"1785141195448000000","tradeId":"23715934308417536","type":"match"}}"#;

    fn frame(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn match_push_parses_one_fill() {
        assert_eq!(
            parse_trades(&frame(MATCH)),
            vec![("BTC-USDT".to_string(), 65215.6, 0.04915634, 1785141195448)]
        );
    }

    #[test]
    fn time_nanoseconds_to_ms() {
        // "time":"1785141195449000000" — ns; ms result matches the probe's
        // recv_ms (1785141195674) to within transit delay.
        let f = frame(
            r#"{"topic":"/market/match:BTC-USDT","type":"message","subject":"trade.l3match","data":{"makerOrderId":"6a6717c8970a070007f5c7ea","price":"65214.7","sequence":"23715934311563264","side":"sell","size":"0.05901673","symbol":"BTC-USDT","takerOrderId":"471137752230928384","time":"1785141195449000000","tradeId":"23715934311563264","type":"match"}}"#,
        );
        let rows = parse_trades(&f);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].3, 1785141195449);
    }

    #[test]
    fn missing_time_yields_zero_ts() {
        let f = frame(
            r#"{"type":"message","data":{"symbol":"BTC-USDT","price":"65215.6","size":"0.005"}}"#,
        );
        assert_eq!(parse_trades(&f)[0].3, 0);
    }

    #[test]
    fn control_frames_yield_no_trades() {
        assert!(parse_trades(&frame(WELCOME)).is_empty());
        assert!(parse_trades(&frame(ACK)).is_empty());
        assert!(parse_trades(&frame(r#"{"id":"p","type":"pong"}"#)).is_empty());
        assert!(parse_trades(&frame(
            r#"{"id":"x","type":"error","code":401,"data":"token expired"}"#
        ))
        .is_empty());
    }

    #[test]
    fn welcome_gate_accepts_only_welcome() {
        assert!(is_welcome(WELCOME));
        assert!(!is_welcome(ACK));
        assert!(!is_welcome(
            r#"{"id":"x","type":"error","code":401,"data":"token expired"}"#
        ));
        assert!(!is_welcome("not json"));
    }
}
