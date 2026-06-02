//! Coinstore spot collector — `cex_data/coinstore/ob.py` reference.
//!
//! Channel: `{symbolId}@depth@{depth}` on `wss://ws.coinstore.com/s/ws`.
//! Coinstore identifies symbols by a numeric `symbolId` (looked up via
//! `POST /api/v2/public/config/spot/symbols`), not the symbol string.
//! Order book messages are full snapshots on every push (no deltas).
//! WS-protocol ping handled by tungstenite.
//!
//! Multi-pair: we resolve all symbol→symbolId mappings up-front via REST.

use crate::cob_common::ExchangeConfig;
use crate::collectors::book::LocalBook;
use crate::collectors::collector::Collector;
use crate::collectors::rest::HTTP;
use crate::collectors::sink::BookSink;
use crate::collectors::util::{now_ms, parse_f64, ws_connect};
use async_trait::async_trait;
use eyre::{eyre, Result, WrapErr};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio_tungstenite::tungstenite::Message;
use tracing::info;

const REST_BASE: &str = "https://api.coinstore.com";
const DEPTH: u32 = 100;

pub struct Coinstore {
    config: ExchangeConfig,
}

impl Coinstore {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    /// POST /api/v2/public/config/spot/symbols with the full symbol list.
    /// Returns symbolId → symbol_uppercase.
    async fn resolve_symbol_ids(&self) -> Result<HashMap<i64, String>> {
        let codes: Vec<String> = self.config.pairs.iter().map(|p| p.to_uppercase()).collect();
        let v: Value = HTTP
            .post(format!("{REST_BASE}/api/v2/public/config/spot/symbols"))
            .json(&json!({"symbolCodes": codes}))
            .send()
            .await
            .wrap_err("coinstore symbols lookup")?
            .error_for_status()?
            .json()
            .await?;
        let arr = v
            .get("data")
            .and_then(|d| d.as_array())
            .ok_or_else(|| eyre!("missing data array"))?;
        let mut out = HashMap::new();
        for item in arr {
            if let (Some(id), Some(code)) = (
                item.get("symbolId").and_then(|x| x.as_i64()),
                item.get("symbolCode").and_then(|x| x.as_str()),
            ) {
                out.insert(id, code.to_uppercase());
            }
        }
        if out.is_empty() {
            return Err(eyre!(
                "coinstore: resolved 0 symbols (requested {:?})",
                self.config.pairs
            ));
        }
        Ok(out)
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let id_to_sym = self.resolve_symbol_ids().await?;
        let url = self.config.ws_url.clone();
        info!("[coinstore] Connecting {} ({} pairs)", url, id_to_sym.len());
        let mut ws = ws_connect(&url).await?;

        let channels: Vec<String> = id_to_sym
            .keys()
            .map(|id| format!("{id}@depth@{DEPTH}"))
            .collect();
        ws.send(Message::Text(
            json!({"op":"SUB","channel":channels,"id":1}).to_string(),
        ))
        .await?;

        let mut books: HashMap<String, LocalBook> = id_to_sym
            .values()
            .map(|sym| (sym.clone(), LocalBook::new("coinstore", sym.clone())))
            .collect();
        let mut tick: u64 = 0;

        // Coinstore sends WS-protocol Ping frames every ~3 minutes. tungstenite
        // 0.20 does NOT auto-pong, so we keep the writer alive to reply.
        // Missing pongs ⇒ server drops the connection within one window.
        let (mut write, mut read) = ws.split();

        loop {
            match read.next().await {
                Some(Ok(Message::Text(text))) => {
                    let received_at = now_ms();
                    let v: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if v.get("T").and_then(|t| t.as_str()) != Some("depth") {
                        continue;
                    }
                    // Channel format `{id}@depth@N`
                    let Some(channel) = v.get("channel").and_then(|c| c.as_str()) else {
                        continue;
                    };
                    let id_str = match channel.split('@').next() {
                        Some(s) => s,
                        None => continue,
                    };
                    let Some(id) = id_str.parse::<i64>().ok() else {
                        continue;
                    };
                    let Some(symbol) = id_to_sym.get(&id) else {
                        continue;
                    };
                    let Some(book) = books.get_mut(symbol) else {
                        continue;
                    };
                    let bids = parse_triple(v.get("b"));
                    let asks = parse_triple(v.get("a"));
                    tick = tick.wrapping_add(1);
                    book.apply_snapshot(bids, asks, Some(tick));
                    if !book.is_crossed() {
                        if let Some(d) = book.to_orderbook_data(0, received_at) {
                            sink.emit(d);
                        }
                    }
                }
                Some(Ok(Message::Ping(p))) => {
                    let _ = write.send(Message::Pong(p)).await;
                }
                Some(Ok(Message::Close(_))) | None => return Err(eyre!("WS closed")),
                Some(Err(e)) => return Err(eyre!("WS error: {e}")),
                _ => {}
            }
        }
    }
}

#[async_trait]
impl Collector for Coinstore {
    fn id(&self) -> &str {
        "coinstore"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[coinstore] no pairs"));
        }
        sink.status("coinstore", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

/// Coinstore book entries are `[price, qty, flag]`; the third element (1 / -1)
/// is informational and ignored.
fn parse_triple(v: Option<&Value>) -> Vec<(f64, f64)> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|row| {
            let r = row.as_array()?;
            Some((parse_f64(r.first()?)?, parse_f64(r.get(1)?)?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_depth_levels_ignores_third_field() {
        let raw = r#"[["76072.65","0.066",1],["76070.0","1.0",-1]]"#;
        let v: Value = serde_json::from_str(raw).unwrap();
        assert_eq!(
            parse_triple(Some(&v)),
            vec![(76072.65, 0.066), (76070.0, 1.0)]
        );
    }

    #[test]
    fn channel_id_extraction() {
        let channel = "4@depth@100";
        assert_eq!(channel.split('@').next(), Some("4"));
    }
}
