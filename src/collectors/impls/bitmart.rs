//! BitMart spot collector — `cex_data/bitmart/ob.py` reference.
//!
//! Channel: `spot/depth/increase100:{SYMBOL}` on
//! `wss://ws-manager-compress.bitmart.com/api?protocol=1.1`. Server pushes a
//! `type=snapshot` first, then `type=update` deltas with strictly monotonic
//! `version`. `version != local + 1` ⇒ reconnect. Updates can arrive before
//! the snapshot in rare cases — buffer them and reconcile.
//!
//! Permessage-deflate compression is handled transparently by tungstenite,
//! so messages arrive as plain text strings.
//!
//! Ping is the literal text frame `ping`; server replies `pong`. 10s interval.

use crate::cob_common::ExchangeConfig;
use crate::collectors::book::LocalBook;
use crate::collectors::collector::Collector;
use crate::collectors::sink::BookSink;
use crate::collectors::util::{now_ms, parse_f64, parse_u64, ws_connect};
use async_trait::async_trait;
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

const PING_INTERVAL: Duration = Duration::from_secs(10);
pub struct Bitmart {
    config: ExchangeConfig,
}

impl Bitmart {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[bitmart] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        let args: Vec<String> = self
            .config
            .pairs
            .iter()
            .map(|p| format!("spot/depth/increase100:{}", p.to_uppercase()))
            .collect();
        ws.send(Message::Text(
            json!({"op": "subscribe", "args": args}).to_string(),
        ))
        .await?;

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| {
                let key = p.to_uppercase();
                (key.clone(), LocalBook::new("bitmart", key))
            })
            .collect();
        let mut buf: HashMap<String, VecDeque<BitmartUpdate>> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.to_uppercase(), VecDeque::new()))
            .collect();

        let (mut write, mut read) = ws.split();
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.tick().await;

        loop {
            tokio::select! {
                msg = read.next() => {
                    let received_at = now_ms();
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            if text == "pong" { continue; }
                            let v: Value = match serde_json::from_str(&text) {
                                Ok(v) => v, Err(_) => continue,
                            };
                            if v.get("table").and_then(|t| t.as_str()) != Some("spot/depth/increase100") {
                                continue;
                            }
                            let Some(items) = v.get("data").and_then(|d| d.as_array()) else { continue };
                            for d in items {
                                let symbol = match d.get("symbol").and_then(|s| s.as_str()) {
                                    Some(s) => s.to_uppercase(), None => continue,
                                };
                                let Some(book) = books.get_mut(&symbol) else { continue };
                                let typ = d.get("type").and_then(|t| t.as_str()).unwrap_or("");
                                let Some(version) = d.get("version").and_then(parse_u64) else { continue };
                                let ts = d.get("ms_t").and_then(parse_u64).map(|x| x as i64).unwrap_or(0);
                                let bids = parse_levels(d.get("bids"));
                                let asks = parse_levels(d.get("asks"));

                                match typ {
                                    "snapshot" => {
                                        book.apply_snapshot(bids, asks, Some(version));
                                        // Drain any update we buffered before the snapshot.
                                        let pending = buf.entry(symbol.clone()).or_default();
                                        while let Some(u) = pending.pop_front() {
                                            if u.version <= version { continue; }
                                            if u.version != book.seq.unwrap() + 1 {
                                                warn!("[bitmart/{symbol}] post-snap gap (v={}, expected {})",
                                                      u.version, book.seq.unwrap() + 1);
                                                return Err(eyre!("bitmart bootstrap gap"));
                                            }
                                            book.apply_deltas(u.bids, u.asks, Some(u.version));
                                        }
                                    }
                                    "update" => {
                                        match book.seq {
                                            None => {
                                                buf.entry(symbol.clone()).or_default().push_back(
                                                    BitmartUpdate { version, bids, asks }
                                                );
                                                continue;
                                            }
                                            Some(local) => {
                                                if version <= local { continue; }
                                                if version != local + 1 {
                                                    warn!("[bitmart/{symbol}] gap (v={version}, local={local})");
                                                    return Err(eyre!("bitmart gap"));
                                                }
                                                book.apply_deltas(bids, asks, Some(version));
                                            }
                                        }
                                    }
                                    _ => continue,
                                }
                                if !book.is_crossed() && book.is_ready() {
                                    if let Some(d) = book.to_orderbook_data(ts, received_at) {
                                        sink.emit(d);
                                    }
                                }
                            }
                        }
                        Some(Ok(Message::Ping(p))) => { let _ = write.send(Message::Pong(p)).await; }
                        Some(Ok(Message::Close(_))) | None => return Err(eyre!("WS closed")),
                        Some(Err(e)) => return Err(eyre!("WS error: {e}")),
                        _ => {}
                    }
                }
                _ = ping.tick() => {
                    if write.send(Message::Text("ping".into())).await.is_err() {
                        return Err(eyre!("ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Bitmart {
    fn id(&self) -> &str {
        "bitmart"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[bitmart] no pairs"));
        }
        sink.status("bitmart", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

struct BitmartUpdate {
    version: u64,
    bids: Vec<(f64, f64)>,
    asks: Vec<(f64, f64)>,
}

fn parse_levels(v: Option<&Value>) -> Vec<(f64, f64)> {
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
    fn snapshot_parsing() {
        let s = r#"{"table":"spot/depth/increase100","data":[{"symbol":"BTC_USDT","type":"snapshot","version":12,"ms_t":1,"bids":[["100","1"]],"asks":[["101","2"]]}]}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let item = v.get("data").unwrap().as_array().unwrap().first().unwrap();
        assert_eq!(item.get("symbol").unwrap().as_str().unwrap(), "BTC_USDT");
        assert_eq!(item.get("type").unwrap().as_str().unwrap(), "snapshot");
        assert_eq!(parse_u64(item.get("version").unwrap()), Some(12));
        assert_eq!(parse_levels(item.get("bids")), vec![(100.0, 1.0)]);
    }
}
