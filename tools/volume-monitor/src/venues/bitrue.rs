//! Bitrue trade stream. Trades are served from
//! `wss://ws.bitrue.com/kline-api/ws`, not the collector's `/market/ws`
//! book endpoint — that endpoint rejects `_trade_ticker` channels with
//! `{"status":"error"}` and a TCP drop (verified live 2026-07-19).
//!
//! Same mechanics as the book channel otherwise: every server frame is a
//! gzip binary; server-initiated `{"ping":<ms>}` must be answered with a
//! text `{"pong":<ms>}`; subscribe per pair with channel
//! `market_{sym}_trade_ticker`. Trade push: `tick.data` = array of trades
//! (newest first), fields price/vol (base)/amount (quote)/ts (ms)/id —
//! JSON numbers, sometimes scientific notation. A frame without
//! `tick.data` but with `tick.vol`/`tick.amount` is a one-shot 24h ticker
//! summary sent right after the ack; counting it as a trade would inflate
//! volume, so trades are only read from `tick.data`.

use crate::types::{EventTx, VenueCfg};
use crate::util::{gunzip, parse_f64, parse_i64, ws_connect, IDLE_TIMEOUT};
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

fn trade_ws_url(cfg_url: &str) -> String {
    if let Some(base) = cfg_url.strip_suffix("/market/ws") {
        format!("{base}/kline-api/ws")
    } else {
        cfg_url.to_string()
    }
}

/// `market_taousdt_trade_ticker` → `taousdt`.
fn symbol_from_channel(channel: &str) -> Option<&str> {
    channel
        .strip_prefix("market_")?
        .strip_suffix("_trade_ticker")
}

/// Extracts (channel symbol, price, qty_base, ts_ms) rows from one decoded
/// frame. Control frames (ping, subscribe ack) are handled by the caller.
fn parse_trades(v: &Value) -> Vec<(String, f64, f64, i64)> {
    let Some(sym) = v
        .get("channel")
        .and_then(|c| c.as_str())
        .and_then(symbol_from_channel)
    else {
        return Vec::new();
    };
    // A frame without tick.data is the 24h ticker summary — skip.
    let Some(data) = v
        .get("tick")
        .and_then(|t| t.get("data"))
        .and_then(|d| d.as_array())
    else {
        return Vec::new();
    };
    data.iter()
        .filter_map(|t| {
            Some((
                sym.to_string(),
                t.get("price").and_then(parse_f64)?,
                t.get("vol").and_then(parse_f64)?,
                t.get("ts").and_then(parse_i64).unwrap_or(0),
            ))
        })
        .collect()
}

pub async fn run(cfg: &VenueCfg, tx: &EventTx) -> Result<()> {
    let url = trade_ws_url(&cfg.ws_url);
    let mut ws = ws_connect(&url).await?;
    for pair in &cfg.pairs {
        let sym = pair.to_lowercase();
        ws.send(Message::Text(
            json!({
                "event": "sub",
                "params": {"cb_id": sym, "channel": format!("market_{sym}_trade_ticker")},
            })
            .to_string(),
        ))
        .await?;
    }
    cfg.send_connected(tx);
    let (mut write, mut read) = ws.split();

    loop {
        let next = match tokio::time::timeout(IDLE_TIMEOUT, read.next()).await {
            Ok(m) => m,
            Err(_) => return Err(eyre!("idle: no frames for {IDLE_TIMEOUT:?}")),
        };
        match next {
            Some(Ok(msg)) => {
                let text = match &msg {
                    Message::Text(t) => t.clone(),
                    Message::Binary(bin) => match gunzip(bin) {
                        Some(t) => t,
                        None => continue,
                    },
                    Message::Ping(p) => {
                        let _ = write.send(Message::Pong(p.clone())).await;
                        continue;
                    }
                    Message::Close(_) => return Err(eyre!("WS closed")),
                    _ => continue,
                };
                let v: Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let Some(ping) = v.get("ping") {
                    let reply = json!({ "pong": ping }).to_string();
                    if write.send(Message::Text(reply)).await.is_err() {
                        return Err(eyre!("pong send failed"));
                    }
                    continue;
                }
                if v.get("event_rep").is_some() {
                    let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
                    if status != "ok" {
                        return Err(eyre!("bitrue subscription rejected: {text}"));
                    }
                    continue;
                }
                for (sym, price, qty, ts) in parse_trades(&v) {
                    let Some(pair) = cfg
                        .pairs
                        .iter()
                        .find(|p| p.eq_ignore_ascii_case(sym.as_str()))
                    else {
                        continue;
                    };
                    cfg.send_trade(tx, pair, price, qty, ts);
                }
            }
            Some(Err(e)) => return Err(eyre!("WS error: {e}")),
            None => return Err(eyre!("WS closed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trade_url_swaps_path() {
        assert_eq!(
            trade_ws_url("wss://ws.bitrue.com/market/ws"),
            "wss://ws.bitrue.com/kline-api/ws"
        );
        assert_eq!(
            trade_ws_url("wss://ws.bitrue.com/kline-api/ws"),
            "wss://ws.bitrue.com/kline-api/ws"
        );
    }

    #[test]
    fn trade_push_parses_price_qty_ts() {
        // Trade push shape per the 2026-07-19 live capture: tick.data newest
        // first, JSON numbers, vol sometimes in scientific notation, ts in
        // epoch ms. `amount` (quote) and `id` are present but unused.
        let v: Value = serde_json::from_str(
            r#"{"channel":"market_taousdt_trade_ticker","ts":1784466123999,"tick":{"data":[{"id":170526836,"side":"BUY","price":197.54,"vol":2.51,"amount":495.8254,"ts":1784466123456},{"id":170526835,"side":"SELL","price":197.42,"vol":6.6E-4,"amount":0.1302972,"ts":1784466122980}]}}"#,
        )
        .unwrap();
        assert_eq!(
            parse_trades(&v),
            vec![
                ("taousdt".to_string(), 197.54, 2.51, 1784466123456),
                ("taousdt".to_string(), 197.42, 6.6e-4, 1784466122980),
            ]
        );
    }

    #[test]
    fn ack_frame_yields_no_trades() {
        // Subscribe ack shape per the 2026-07-19 live capture (the read loop
        // consumes it before parsing, but the parser must also reject it).
        let ack: Value = serde_json::from_str(
            r#"{"channel":"market_taousdt_trade_ticker","cb_id":"taousdt","event_rep":"subed","status":"ok","ts":1784466000000}"#,
        )
        .unwrap();
        assert!(parse_trades(&ack).is_empty());
        // Server keepalive has no channel at all.
        let ping: Value = serde_json::from_str(r#"{"ping":1784461537875}"#).unwrap();
        assert!(parse_trades(&ping).is_empty());
    }

    #[test]
    fn ticker_summary_yields_no_trades() {
        // Live-captured 24h summary sent right after the ack: tick has
        // vol/amount but no data array — must produce zero trades.
        let v: Value = serde_json::from_str(
            r#"{"tick":{"amount":1083659.0,"rose":0.0269,"close":197.54,"vol":5508.8,"high":199.96,"low":191.54,"open":192.36},"channel":"market_taousdt_trade_ticker","ts":1784466000000}"#,
        )
        .unwrap();
        assert!(v.get("tick").and_then(|t| t.get("data")).is_none());
        assert!(parse_trades(&v).is_empty());
    }

    #[test]
    fn trade_row_missing_price_is_dropped() {
        // Rows lacking price or vol are skipped; ts defaults to 0.
        let v: Value = serde_json::from_str(
            r#"{"channel":"market_taousdt_trade_ticker","tick":{"data":[{"vol":1.0,"ts":1784466123456},{"price":"197.60","vol":"3.5"}]}}"#,
        )
        .unwrap();
        assert_eq!(
            parse_trades(&v),
            vec![("taousdt".to_string(), 197.60, 3.5, 0)]
        );
    }
}
