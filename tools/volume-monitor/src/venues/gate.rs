//! Gate spot trade stream — same endpoint as the collector
//! (`wss://api.gateio.ws/ws/v4/`), channel `spot.trades`.
//! Subscribe: `{"time":<s>,"channel":"spot.trades","event":"subscribe",
//! "payload":["TAO_USDT","BTC_USDT",...]}`. Update pushes carry one trade:
//! `result: {currency_pair, price, amount (base), create_time_ms, side}`.
//! App-level `spot.ping` sent every 15s; protocol pings answered too.

use crate::types::{EventTx, VenueCfg};
use crate::util::{now_ms, parse_f64, ws_connect, IDLE_TIMEOUT};
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

/// Extracts (currency_pair, price, qty_base, ts_ms) rows from a decoded
/// frame. Non-update frames yield nothing; update pushes carry one trade.
/// `create_time_ms` is a decimal string like "1785141195444.991000" —
/// truncated (not rounded) to whole milliseconds.
fn parse_trades(v: &Value) -> Vec<(String, f64, f64, i64)> {
    if v.get("channel").and_then(|c| c.as_str()) != Some("spot.trades")
        || v.get("event").and_then(|e| e.as_str()) != Some("update")
    {
        return Vec::new();
    }
    let Some(r) = v.get("result") else {
        return Vec::new();
    };
    let Some(pair) = r.get("currency_pair").and_then(|s| s.as_str()) else {
        return Vec::new();
    };
    let (Some(price), Some(qty)) = (
        r.get("price").and_then(parse_f64),
        r.get("amount").and_then(parse_f64),
    ) else {
        return Vec::new();
    };
    let ts = r
        .get("create_time_ms")
        .and_then(parse_f64)
        .map(|f| f as i64)
        .unwrap_or(0);
    vec![(pair.to_string(), price, qty, ts)]
}

pub async fn run(cfg: &VenueCfg, tx: &EventTx) -> Result<()> {
    let mut ws = ws_connect(&cfg.ws_url).await?;
    ws.send(Message::Text(
        json!({
            "time": now_ms() / 1000,
            "channel": "spot.trades",
            "event": "subscribe",
            "payload": cfg.pairs,
        })
        .to_string(),
    ))
    .await?;
    cfg.send_connected(tx);
    let (mut write, mut read) = ws.split();
    let mut ping = tokio::time::interval(Duration::from_secs(15));
    ping.tick().await;

    loop {
        tokio::select! {
            _ = ping.tick() => {
                let m = json!({"time": now_ms() / 1000, "channel": "spot.ping", "event": "ping"})
                    .to_string();
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
                    if v.get("event").and_then(|e| e.as_str()) == Some("subscribe")
                        && v.get("error").is_some_and(|e| !e.is_null())
                    {
                        return Err(eyre!("gate subscription rejected: {text}"));
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

    // Frames below are verbatim live captures from wss://api.gateio.ws/ws/v4/
    // (2026-07-27).

    #[test]
    fn trade_update_parses() {
        let v: Value = serde_json::from_str(
            r#"{"time":1785141195,"time_ms":1785141195445,"channel":"spot.trades","event":"update","result":{"id":213746270,"id_market":213746270,"create_time":1785141195,"create_time_ms":"1785141195444.991000","side":"sell","currency_pair":"BTC_USDT","amount":"0.000047","price":"65222.1","range":"213746270-213746270"}}"#,
        )
        .unwrap();
        assert_eq!(
            parse_trades(&v),
            vec![("BTC_USDT".to_string(), 65222.1, 0.000047, 1785141195444)]
        );
    }

    #[test]
    fn subscribe_ack_yields_no_trades() {
        let v: Value = serde_json::from_str(
            r#"{"time":1785141191,"time_ms":1785141191994,"conn_id":"3583e88ea576bd16","trace_id":"8a37f7004b1e54b1fb2acb7e0fdbdd91","channel":"spot.trades","event":"subscribe","payload":["BTC_USDT"],"result":{"status":"success"},"requestId":"8a37f7004b1e54b1fb2acb7e0fdbdd91"}"#,
        )
        .unwrap();
        assert!(parse_trades(&v).is_empty());
    }

    #[test]
    fn fractional_create_time_ms_truncates() {
        // ".999000" truncates to ...444; rounding would give ...445.
        let v: Value = serde_json::from_str(
            r#"{"time":1785141195,"time_ms":1785141195445,"channel":"spot.trades","event":"update","result":{"id":213746271,"id_market":213746271,"create_time":1785141195,"create_time_ms":"1785141195444.999000","side":"sell","currency_pair":"BTC_USDT","amount":"0.000494","price":"65222.1","range":"213746271-213746271"}}"#,
        )
        .unwrap();
        assert_eq!(parse_trades(&v)[0].3, 1785141195444);
    }
}
