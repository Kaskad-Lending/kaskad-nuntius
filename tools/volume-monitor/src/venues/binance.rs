//! Binance trade stream — same host as the collector (`stream.binance.com`),
//! combined streams: `/stream?streams=btcusdt@trade/taousdt@trade`.
//! Each push: `{"stream":"taousdt@trade","data":{"e":"trade","s":"TAOUSDT",
//! "p":"197.5","q":"1.2","T":<ms>,...}}` — one trade per message, `q` in
//! base units, `T` (trade time, ms) is the tape timestamp — `E` (event
//! time) can lag it by a few ms. Server sends protocol-level pings only
//! every ~3 min (documented cadence for stream.binance.com); reply with
//! pong. That interval exceeds util.rs's 120s IDLE_TIMEOUT when no trades
//! flow (a manual `--venues binance --bases TAO` run), so a client ping
//! goes out every 60s. Live-verified 2026-07-19, frames re-captured
//! 2026-07-27.

use crate::types::{EventTx, VenueCfg};
use crate::util::{parse_f64, parse_i64, ws_connect, IDLE_TIMEOUT};
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

/// Rows from a combined-stream push: (symbol, price, qty_base, ts_ms).
/// Frames without a `data.e == "trade"` payload (subscribe acks
/// `{"result":null,"id":N}`, other event types) yield no rows.
fn parse_trades(v: &Value) -> Vec<(String, f64, f64, i64)> {
    let Some(data) = v.get("data") else {
        return Vec::new();
    };
    if data.get("e").and_then(|e| e.as_str()) != Some("trade") {
        return Vec::new();
    }
    let Some(sym) = data.get("s").and_then(|s| s.as_str()) else {
        return Vec::new();
    };
    let (Some(price), Some(qty)) = (
        data.get("p").and_then(parse_f64),
        data.get("q").and_then(parse_f64),
    ) else {
        return Vec::new();
    };
    let ts = data.get("T").and_then(parse_i64).unwrap_or(0);
    vec![(sym.to_string(), price, qty, ts)]
}

pub async fn run(cfg: &VenueCfg, tx: &EventTx) -> Result<()> {
    let streams: Vec<String> = cfg
        .pairs
        .iter()
        .map(|p| format!("{}@trade", p.to_lowercase()))
        .collect();
    let url = format!(
        "{}/stream?streams={}",
        cfg.ws_url.trim_end_matches('/'),
        streams.join("/")
    );
    let ws = ws_connect(&url).await?;
    cfg.send_connected(tx);
    let (mut write, mut read) = ws.split();
    let mut ping = tokio::time::interval(Duration::from_secs(60));
    ping.tick().await;

    loop {
        tokio::select! {
            _ = ping.tick() => {
                if write.send(Message::Ping(Vec::new())).await.is_err() {
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

    /// Combined-stream trade push captured live 2026-07-27.
    #[test]
    fn trade_push_rows() {
        let v: Value = serde_json::from_str(
            r#"{"stream":"btcusdt@trade","data":{"e":"trade","E":1785141192057,"s":"BTCUSDT","t":6535802407,"p":"65218.14000000","q":"0.00039000","T":1785141192057,"m":false,"M":true}}"#,
        )
        .unwrap();
        let rows = parse_trades(&v);
        assert_eq!(
            rows,
            vec![("BTCUSDT".to_string(), 65218.14, 0.00039, 1785141192057)]
        );
    }

    /// Captured frame where `E` (1785141194963) and `T` (1785141194962)
    /// differ: the row timestamp is `T`, epoch ms.
    #[test]
    fn ts_is_trade_time_not_event_time() {
        let v: Value = serde_json::from_str(
            r#"{"stream":"btcusdt@trade","data":{"e":"trade","E":1785141194963,"s":"BTCUSDT","t":6535802412,"p":"65218.13000000","q":"0.00148000","T":1785141194962,"m":true,"M":true}}"#,
        )
        .unwrap();
        let rows = parse_trades(&v);
        assert_eq!(
            rows,
            vec![("BTCUSDT".to_string(), 65218.13, 0.00148, 1785141194962)]
        );
    }

    /// Subscribe/LIST_SUBSCRIPTIONS responses have no `data` wrapper.
    #[test]
    fn subscribe_ack_yields_no_trades() {
        let v: Value = serde_json::from_str(r#"{"result":null,"id":1}"#).unwrap();
        assert!(parse_trades(&v).is_empty());
    }

    /// Wrapped non-trade event (`data.e != "trade"`) yields no rows.
    #[test]
    fn non_trade_event_yields_no_trades() {
        let v: Value = serde_json::from_str(
            r#"{"stream":"btcusdt@depth@100ms","data":{"e":"depthUpdate","E":1785141192057,"s":"BTCUSDT","U":157,"u":160,"b":[["65218.13","1.5"]],"a":[]}}"#,
        )
        .unwrap();
        assert!(parse_trades(&v).is_empty());
    }
}
