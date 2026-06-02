//! BingX spot collector — `cex_data/bingx/ob.py` reference.
//!
//! Channel: `{SYMBOL}@depth100` on `wss://open-api-ws.bingx.com/market`.
//! gzip-compressed JSON. Server pushes a full top-100 snapshot every 100ms;
//! there are NO incremental deltas, so we replace the book wholesale.
//! Library handles WS-protocol pings automatically.

use crate::cob_common::ExchangeConfig;
use crate::collectors::book::LocalBook;
use crate::collectors::collector::Collector;
use crate::collectors::sink::BookSink;
use crate::collectors::util::{now_ms, parse_f64, ws_connect};
use async_trait::async_trait;
use eyre::{eyre, Result};
use flate2::read::GzDecoder;
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

pub struct Bingx {
    config: ExchangeConfig,
}

impl Bingx {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[bingx] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // BingX subscribes one channel per message.
        for (i, pair) in self.config.pairs.iter().enumerate() {
            ws.send(Message::Text(
                json!({
                    "id": format!("ob{i}"),
                    "reqType": "sub",
                    "dataType": format!("{}@depth100", pair.to_uppercase()),
                })
                .to_string(),
            ))
            .await?;
        }

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| {
                let key = p.to_uppercase();
                (key.clone(), LocalBook::new("bingx", key))
            })
            .collect();
        let mut tick: u64 = 0;

        let (mut write, mut read) = ws.split();

        loop {
            match read.next().await {
                Some(Ok(Message::Binary(bin))) => {
                    let received_at = now_ms();
                    let Some(text) = decompress(&bin) else {
                        continue;
                    };
                    if let Some((sym, bids, asks, ts)) = parse_depth(&text) {
                        let Some(book) = books.get_mut(&sym) else {
                            continue;
                        };
                        tick = tick.wrapping_add(1);
                        book.apply_snapshot(bids, asks, Some(tick));
                        if !book.is_crossed() {
                            if let Some(d) = book.to_orderbook_data(ts, received_at) {
                                sink.emit(d);
                            }
                        }
                    }
                }
                // BingX may ping at the protocol level (handled by tungstenite),
                // but also occasionally sends literal "Ping" text frames.
                Some(Ok(Message::Text(text))) => {
                    if text == "Ping" || text == "ping" {
                        let _ = write.send(Message::Text("Pong".into())).await;
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
impl Collector for Bingx {
    fn id(&self) -> &str {
        "bingx"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[bingx] no pairs"));
        }
        sink.status("bingx", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

/// Decompression bomb cap: refuse to inflate past this size. A 4 MiB
/// envelope is far above any legitimate top-100 snapshot but well below
/// the per-message WS cap (1 MiB pre-decompression × ~10x typical ratio
/// would be 10 MiB; we lock to 4 MiB to make the bomb path obvious).
/// Audit 10 P2 — flate2 has no built-in cap.
const MAX_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024;

fn decompress(bin: &[u8]) -> Option<String> {
    let raw = GzDecoder::new(bin);
    // .take(N+1) so we can detect overrun rather than silently truncate.
    let mut limited = raw.take(MAX_DECOMPRESSED_BYTES + 1);
    let mut buf = Vec::with_capacity(64 * 1024);
    limited.read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > MAX_DECOMPRESSED_BYTES {
        warn!(
            "[bingx] decompressed payload exceeds {} bytes — dropping (possible decompression bomb)",
            MAX_DECOMPRESSED_BYTES
        );
        return None;
    }
    String::from_utf8(buf).ok()
}

type Levels = Vec<(f64, f64)>;
type ParsedDepth = (String, Levels, Levels, i64);

fn parse_depth(text: &str) -> Option<ParsedDepth> {
    let v: Value = serde_json::from_str(text).ok()?;
    let dt = v.get("dataType")?.as_str()?; // e.g. "BTC-USDT@depth100"
    let symbol = dt.split('@').next()?.to_uppercase();
    let data = v.get("data")?;
    let bids = parse_levels(data.get("bids"));
    let asks = parse_levels(data.get("asks"));
    let ts = v.get("ts").and_then(|x| x.as_i64()).unwrap_or(0);
    Some((symbol, bids, asks, ts))
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
    fn parse_depth_extracts_symbol() {
        let s = r#"{"dataType":"BTC-USDT@depth100","ts":1,"data":{"bids":[["100","1"]],"asks":[["101","2"]]}}"#;
        let (sym, bids, asks, _) = parse_depth(s).unwrap();
        assert_eq!(sym, "BTC-USDT");
        assert_eq!(bids, vec![(100.0, 1.0)]);
        assert_eq!(asks, vec![(101.0, 2.0)]);
    }
}
