//! AscendEX (ex-BitMax) spot collector — `cex_data/ascendex/ob.py` reference.
//!
//! Channel: `depth:{symbol}` on `wss://ascendex.com/api/pro/v2/stream`.
//! After subscribe we explicitly request `{"op":"req","action":"depth-snapshot"}`
//! to seed the book; deltas received before the snapshot are buffered and
//! reconciled. Each message carries `data.seqnum` (monotonically increasing
//! per symbol). Stale `seqnum <= local` ⇒ skip; no hard-gap reconnect per
//! the upstream README (depth messages carry full changed levels per push).
//!
//! Symbol format: `BTC/USDT` (slash). Ping `{"op":"ping"}` every 50s.

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
use tracing::info;

const PING_INTERVAL: Duration = Duration::from_secs(50);
pub struct Ascendex {
    config: ExchangeConfig,
}

impl Ascendex {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[ascendex] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // Subscribe + request snapshot per pair.
        for pair in &self.config.pairs {
            ws.send(Message::Text(
                json!({"op":"sub","ch":format!("depth:{pair}")}).to_string(),
            ))
            .await?;
            ws.send(Message::Text(
                json!({
                    "op":"req","action":"depth-snapshot","args":{"symbol":pair}
                })
                .to_string(),
            ))
            .await?;
        }

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.clone(), LocalBook::new("ascendex", p.clone())))
            .collect();
        let mut buf: HashMap<String, VecDeque<AscendexDelta>> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.clone(), VecDeque::new()))
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
                            let v: Value = match serde_json::from_str(&text) {
                                Ok(v) => v, Err(_) => continue,
                            };
                            let m = v.get("m").and_then(|x| x.as_str()).unwrap_or("");
                            let symbol = match v.get("symbol").and_then(|s| s.as_str()) {
                                Some(s) => s.to_string(), None => continue,
                            };
                            let Some(book) = books.get_mut(&symbol) else { continue };
                            let Some(data) = v.get("data") else { continue };
                            let Some(seqnum) = data.get("seqnum").and_then(parse_u64) else { continue };
                            let ts = data.get("ts").and_then(parse_u64).map(|x| x as i64).unwrap_or(0);
                            let bids = parse_levels(data.get("bids"));
                            let asks = parse_levels(data.get("asks"));

                            match m {
                                "depth-snapshot" => {
                                    book.apply_snapshot(bids, asks, Some(seqnum));
                                    // drain buffer
                                    let pending = buf.entry(symbol.clone()).or_default();
                                    while let Some(d) = pending.pop_front() {
                                        if d.seqnum <= seqnum { continue; }
                                        book.apply_deltas(d.bids, d.asks, Some(d.seqnum));
                                    }
                                }
                                "depth" => {
                                    if !book.is_ready() {
                                        buf.entry(symbol.clone()).or_default().push_back(
                                            AscendexDelta { seqnum, bids, asks }
                                        );
                                        continue;
                                    }
                                    if seqnum <= book.seq.unwrap() { continue; }
                                    book.apply_deltas(bids, asks, Some(seqnum));
                                }
                                _ => continue,
                            }
                            if !book.is_crossed() && book.is_ready() {
                                if let Some(d) = book.to_orderbook_data(ts, received_at) {
                                    sink.emit(d);
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
                    if write.send(Message::Text(json!({"op":"ping"}).to_string())).await.is_err() {
                        return Err(eyre!("ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Ascendex {
    fn id(&self) -> &str {
        "ascendex"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[ascendex] no pairs"));
        }
        sink.status("ascendex", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

struct AscendexDelta {
    seqnum: u64,
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
    fn parse_snapshot_message() {
        let s = r#"{"m":"depth-snapshot","symbol":"BTC/USDT","data":{"ts":1,"seqnum":42,"asks":[["100","0.1"]],"bids":[["99","0.2"]]}}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        assert_eq!(v.get("m").unwrap().as_str().unwrap(), "depth-snapshot");
        assert_eq!(v.get("symbol").unwrap().as_str().unwrap(), "BTC/USDT");
        let data = v.get("data").unwrap();
        assert_eq!(parse_u64(data.get("seqnum").unwrap()), Some(42));
    }
}
