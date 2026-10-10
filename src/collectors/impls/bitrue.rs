//! Bitrue spot collector.
//!
//! Channel: `market_{symbol_lower}_simple_depth_step0` on
//! `wss://ws.bitrue.com/market/ws`. Subscribe:
//! `{"event":"sub","params":{"cb_id":"taousdt","channel":"market_taousdt_simple_depth_step0"}}`.
//! Every frame — acks, pings and data — is a GZIP-compressed binary
//! frame (verified live 2026-07-19: 243/243 frames gzip); gunzip before
//! JSON parsing, falling back to plain text for safety.
//!
//! Pushes are full snapshots keyed by channel name, with the bid side
//! called `buys` (not `bids`): `{"channel":..,"tick":{"buys":[[p,q]..],
//! "asks":[[p,q]..]},"ts":<epoch_ms>}`. No sequence field — a synthetic
//! tick counter is used (lbank pattern). Pushes fire on book CHANGE only:
//! quiet markets (TAO ~1 push/18s observed) go silent between changes,
//! so their books drop out of the ±5s freshness gate downstream between
//! pushes — intermittent contribution is expected and correct.
//!
//! Keepalive is SERVER-initiated: `{"ping":<ts>}` every ~15s; reply
//! `{"pong":<ts>}` within 1 minute or the server disconnects.
//! Subscribe acks carry `{"event_rep":"subed","status":"ok"}`; any
//! non-ok status is fatal (reconnect via manager backoff).

use crate::cob_common::ExchangeConfig;
use crate::collectors::book::LocalBook;
use crate::collectors::collector::Collector;
use crate::collectors::sink::BookSink;
use crate::collectors::util::{now_ms, parse_f64, parse_i64, ws_connect};
use async_trait::async_trait;
use eyre::{eyre, Result};
use flate2::read::GzDecoder;
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

pub struct Bitrue {
    config: ExchangeConfig,
}

impl Bitrue {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[bitrue] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // Channel symbol is lowercase concatenated ("taousdt"); books are
        // keyed by the lowercase symbol so pushes map back via channel name.
        for pair in &self.config.pairs {
            let sym = pair.to_lowercase();
            ws.send(Message::Text(
                json!({
                    "event": "sub",
                    "params": {
                        "cb_id": sym,
                        "channel": format!("market_{sym}_simple_depth_step0"),
                    },
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
                let key = p.to_lowercase();
                (key.clone(), LocalBook::new("bitrue", key))
            })
            .collect();
        let mut tick_counter: u64 = 0;

        let (mut write, mut read) = ws.split();

        loop {
            match read.next().await {
                Some(Ok(msg)) => {
                    let received_at = now_ms();
                    let text = match &msg {
                        Message::Text(t) => t.clone(),
                        Message::Binary(bin) => match decompress(bin) {
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

                    // Server-initiated keepalive: {"ping":<ts>} -> {"pong":<ts>}.
                    if let Some(ping) = v.get("ping") {
                        let reply = json!({ "pong": ping }).to_string();
                        if write.send(Message::Text(reply)).await.is_err() {
                            return Err(eyre!("pong send failed"));
                        }
                        continue;
                    }

                    // Subscribe ack: fatal on any non-ok status.
                    if v.get("event_rep").is_some() {
                        let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
                        if status != "ok" {
                            warn!("[bitrue] subscription failed: {text}");
                            return Err(eyre!("bitrue subscription rejected"));
                        }
                        continue;
                    }

                    let Some(channel) = v.get("channel").and_then(|c| c.as_str()) else {
                        continue;
                    };
                    let Some(sym) = symbol_from_channel(channel) else {
                        continue;
                    };
                    let Some(book) = books.get_mut(sym) else {
                        continue;
                    };
                    let Some(t) = v.get("tick") else { continue };

                    // Bitrue calls the bid side "buys".
                    let bids = parse_levels(t.get("buys"));
                    let asks = parse_levels(t.get("asks"));
                    tick_counter = tick_counter.wrapping_add(1);
                    book.apply_snapshot(bids, asks, Some(tick_counter));
                    // Outer `ts` is epoch ms (verified live 2026-07-19).
                    let ts = v.get("ts").and_then(parse_i64).unwrap_or(0);
                    if !book.is_crossed() {
                        if let Some(d) = book.to_orderbook_data(ts, received_at) {
                            sink.emit(d);
                        }
                    }
                }
                Some(Err(e)) => return Err(eyre!("WS error: {e}")),
                None => return Err(eyre!("WS closed")),
            }
        }
    }
}

#[async_trait]
impl Collector for Bitrue {
    fn id(&self) -> &str {
        "bitrue"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[bitrue] no pairs"));
        }
        sink.status("bitrue", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

/// Cap on decompressed size of a single gzip frame — bounds a decompression
/// bomb far below the 512 MiB enclave. The compressed side is capped at
/// MAX_MESSAGE_SIZE (1 MiB) but gzip expands ~1000:1, so the output needs
/// its own limit. Mirrors the bingx.rs / htx.rs idiom (audit 10 P2 / H-8).
const MAX_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024;

fn decompress(bin: &[u8]) -> Option<String> {
    // .take(N+1) so overrun is detected and the frame dropped, rather than
    // handing a silently-truncated payload to the JSON parser.
    let mut limited = GzDecoder::new(bin).take(MAX_DECOMPRESSED_BYTES + 1);
    let mut buf = Vec::with_capacity(64 * 1024);
    limited.read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > MAX_DECOMPRESSED_BYTES {
        warn!(
            "[bitrue] decompressed payload exceeds {MAX_DECOMPRESSED_BYTES} bytes — dropping (possible decompression bomb)"
        );
        return None;
    }
    String::from_utf8(buf).ok()
}

/// `market_taousdt_simple_depth_step0` → `taousdt`.
fn symbol_from_channel(channel: &str) -> Option<&str> {
    channel
        .strip_prefix("market_")?
        .strip_suffix("_simple_depth_step0")
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
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn gzip(s: &str) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(s.as_bytes()).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn gzip_roundtrip_decompresses() {
        let raw = r#"{"ping":1784461537875}"#;
        assert_eq!(decompress(&gzip(raw)).as_deref(), Some(raw));
        // Garbage is None, not a panic.
        assert!(decompress(&[0x1f, 0x8b, 0x00]).is_none());
    }

    #[test]
    fn decompress_drops_bomb_over_limit() {
        // 8 MiB of zeros compresses to a few KiB; decompression must be
        // bounded and the over-limit frame dropped (None), never a 8 MiB
        // allocation nor a truncated payload handed downstream.
        let raw = "\0".repeat(8 * 1024 * 1024);
        assert!(decompress(&gzip(&raw)).is_none());
        // A frame exactly at the cap still decodes.
        let ok = "a".repeat(MAX_DECOMPRESSED_BYTES as usize);
        assert_eq!(decompress(&gzip(&ok)).as_deref(), Some(ok.as_str()));
    }

    #[test]
    fn parse_push_with_buys_side() {
        // Live-captured push shape (2026-07-19): bid side is "buys",
        // outer ts is epoch ms.
        let s = r#"{"channel":"market_taousdt_simple_depth_step0","tick":{"buys":[["198.29","20.245"]],"asks":[["198.41","22.277"]]},"ts":1784461537828}"#;
        let v: Value = serde_json::from_str(s).unwrap();
        let t = v.get("tick").unwrap();
        assert_eq!(parse_levels(t.get("buys")), vec![(198.29, 20.245)]);
        assert_eq!(parse_levels(t.get("asks")), vec![(198.41, 22.277)]);
        assert_eq!(v.get("ts").and_then(parse_i64), Some(1784461537828));
    }

    #[test]
    fn channel_symbol_extraction() {
        assert_eq!(
            symbol_from_channel("market_taousdt_simple_depth_step0"),
            Some("taousdt")
        );
        assert_eq!(
            symbol_from_channel("market_btcusdt_simple_depth_step0"),
            Some("btcusdt")
        );
        assert_eq!(symbol_from_channel("market_btcusdt_trade_ticker"), None);
    }

    #[test]
    fn ack_and_ping_frames_recognized() {
        // Live-captured ack and ping (both arrive gzip-compressed on the wire).
        let ack: Value = serde_json::from_str(
            r#"{"channel":"market_taousdt_simple_depth_step0","cb_id":"taousdt","event_rep":"subed","status":"ok","ts":1784461537828}"#,
        )
        .unwrap();
        assert!(ack.get("event_rep").is_some());
        assert_eq!(ack.get("status").and_then(|s| s.as_str()), Some("ok"));
        let ping: Value = serde_json::from_str(r#"{"ping":1784461537875}"#).unwrap();
        assert!(ping.get("ping").is_some());
    }
}
