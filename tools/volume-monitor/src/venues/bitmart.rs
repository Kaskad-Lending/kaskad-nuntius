//! BitMart trade stream — same endpoint as the collector
//! (`wss://ws-manager-compress.bitmart.com/api?protocol=1.1`), channel
//! `spot/trade:{SYMBOL}`, all pairs in one subscribe. Frames arrive as
//! plain text (permessage-deflate handled below the app layer). Keepalive
//! is a literal `ping` text frame every 10s answered by literal `pong`.
//! Trade push: `{"table":"spot/trade","data":[{symbol, price, size (base),
//! side, ms_t (ms)}]}` — data is an array; no trade id, no replay.
//! Live-verified 2026-07-19.

use crate::types::{EventTx, VenueCfg};
use crate::util::{parse_f64, parse_i64, ws_connect, IDLE_TIMEOUT};
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

/// Rows from a `spot/trade` push frame: (symbol, price, qty_base, ts_ms).
/// Non-trade tables and frames without a `data` array yield no rows.
fn parse_trades(v: &Value) -> Vec<(String, f64, f64, i64)> {
    let mut out = Vec::new();
    if v.get("table").and_then(|t| t.as_str()) != Some("spot/trade") {
        return out;
    }
    let Some(data) = v.get("data").and_then(|d| d.as_array()) else {
        return out;
    };
    for t in data {
        let Some(sym) = t.get("symbol").and_then(|s| s.as_str()) else {
            continue;
        };
        let (Some(price), Some(qty)) = (
            t.get("price").and_then(parse_f64),
            t.get("size").and_then(parse_f64),
        ) else {
            continue;
        };
        let ts = t.get("ms_t").and_then(parse_i64).unwrap_or(0);
        out.push((sym.to_string(), price, qty, ts));
    }
    out
}

pub async fn run(cfg: &VenueCfg, tx: &EventTx) -> Result<()> {
    let mut ws = ws_connect(&cfg.ws_url).await?;
    let args: Vec<String> = cfg
        .pairs
        .iter()
        .map(|p| format!("spot/trade:{}", p.to_uppercase()))
        .collect();
    ws.send(Message::Text(
        json!({"op": "subscribe", "args": args}).to_string(),
    ))
    .await?;
    cfg.send_connected(tx);
    let (mut write, mut read) = ws.split();
    let mut ping = tokio::time::interval(Duration::from_secs(10));
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
                    if v.get("event").and_then(|e| e.as_str()) == Some("error") {
                        return Err(eyre!("bitmart error frame: {text}"));
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

    // Frame shapes per the 2026-07-19 live verification: price/size are
    // strings, ms_t is a JSON number in epoch ms, data batches multiple
    // trades per frame.
    #[test]
    fn trade_push_rows() {
        let v: Value = serde_json::from_str(
            r#"{"table":"spot/trade","data":[{"symbol":"TAO_USDT","price":"197.54","side":"sell","size":"0.35","ms_t":1784466123456},{"symbol":"BTC_USDT","price":"64230.11","side":"buy","size":"0.00500","ms_t":1784466123999}]}"#,
        )
        .unwrap();
        let rows = parse_trades(&v);
        assert_eq!(
            rows,
            vec![
                ("TAO_USDT".to_string(), 197.54, 0.35, 1784466123456),
                ("BTC_USDT".to_string(), 64230.11, 0.005, 1784466123999),
            ]
        );
    }

    #[test]
    fn subscribe_ack_yields_no_trades() {
        let v: Value =
            serde_json::from_str(r#"{"event":"subscribe","topic":"spot/trade:TAO_USDT"}"#).unwrap();
        assert!(parse_trades(&v).is_empty());
    }

    #[test]
    fn other_table_yields_no_trades() {
        let v: Value = serde_json::from_str(
            r#"{"table":"spot/depth/increase100","data":[{"symbol":"TAO_USDT","version":7}]}"#,
        )
        .unwrap();
        assert!(parse_trades(&v).is_empty());
    }
}
