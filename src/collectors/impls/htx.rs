//! HTX (ex-Huobi) spot collector — `cex_data/htx/ob.py` reference.
//!
//! Channel: `market.{symbol}.mbp.400` (incremental, 100ms) on
//! `wss://api.huobi.pro/feed`. All frames are **gzip-compressed JSON**,
//! including pings.
//!
//! Bootstrap: subscribe → buffer N deltas → REST `GET /market/depth?depth=20`
//! (REST max depth = 20 only; WS will refill the deeper book). REST returns
//! `tick.version` which is our initial seqNum anchor.
//!
//! Live: each delta has `seqNum` and `prevSeqNum`. On mismatch, refetch REST.
//! HTX's MBP also produces the occasional crossed book under fast moves —
//! we re-snapshot when `bid >= ask`.
//!
//! Application ping: server sends `{"ping": <ts>}`, we reply `{"pong": <ts>}`.

use crate::cob_common::ExchangeConfig;
use crate::collectors::book::LocalBook;
use crate::collectors::collector::Collector;
use crate::collectors::rest::HTTP;
use crate::collectors::sink::BookSink;
use crate::collectors::util::{now_ms, parse_f64, parse_u64, ws_connect};
use async_trait::async_trait;
use eyre::{eyre, Result, WrapErr};
use flate2::read::GzDecoder;
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

const REST_BASE: &str = "https://api.huobi.pro";
const MBP_LEVELS: u32 = 400;
const REST_DEPTH: u32 = 20; // HTX REST max depth — WS will fill the rest
const PRELUDE_BUFFER_TIMEOUT: Duration = Duration::from_secs(3);
const PRELUDE_BUFFER_MIN: usize = 5;
pub struct Htx {
    config: ExchangeConfig,
}

impl Htx {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    fn channel(symbol: &str) -> String {
        format!("market.{}.mbp.{MBP_LEVELS}", symbol.to_lowercase())
    }

    async fn fetch_snapshot(&self, symbol: &str) -> Result<RestSnapshot> {
        let url = format!(
            "{REST_BASE}/market/depth?symbol={}&depth={REST_DEPTH}&type=step0",
            symbol.to_lowercase()
        );
        let v: Value = HTTP
            .get(&url)
            .send()
            .await
            .wrap_err_with(|| format!("HTX REST {symbol}"))?
            .error_for_status()?
            .json()
            .await?;
        let tick = v
            .get("tick")
            .ok_or_else(|| eyre!("htx snapshot {symbol}: missing tick"))?;
        let version = tick
            .get("version")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| eyre!("htx snapshot {symbol}: missing version"))?;
        let bids = parse_levels(tick.get("bids"));
        let asks = parse_levels(tick.get("asks"));
        Ok(RestSnapshot {
            version,
            bids,
            asks,
        })
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[htx] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // Subscribe per-pair (HTX requires one sub message per channel).
        for (i, pair) in self.config.pairs.iter().enumerate() {
            let sub = json!({"sub": Self::channel(pair), "id": format!("ob{i}")});
            ws.send(Message::Text(sub.to_string())).await?;
        }

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| {
                let key = p.to_lowercase();
                (key.clone(), LocalBook::new("htx", key))
            })
            .collect();
        let mut prelude: HashMap<String, VecDeque<HtxDelta>> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.to_lowercase(), VecDeque::new()))
            .collect();

        let (mut write, mut read) = ws.split();

        // Phase 1: buffer prelude up to deadline / per-pair min count.
        let deadline = tokio::time::Instant::now() + PRELUDE_BUFFER_TIMEOUT;
        loop {
            if prelude.values().all(|q| q.len() >= PRELUDE_BUFFER_MIN) {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                debug!("[htx] prelude deadline");
                break;
            }
            let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(timeout, read.next()).await {
                Ok(Some(Ok(Message::Binary(bin)))) => {
                    let Some(text) = decompress(&bin) else {
                        continue;
                    };
                    if let Some(ts) = ping_ts(&text) {
                        write
                            .send(Message::Text(json!({"pong": ts}).to_string()))
                            .await?;
                        continue;
                    }
                    if let Some((sym, delta)) = parse_mbp(&text) {
                        prelude.entry(sym).or_default().push_back(delta);
                    }
                }
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(e))) => return Err(eyre!("WS error during prelude: {e}")),
                Ok(None) => return Err(eyre!("WS closed during prelude")),
                Err(_) => break,
            }
        }

        // Phase 2: REST snapshot per pair.
        for pair in self.config.pairs.iter().map(|p| p.to_lowercase()) {
            let book = books.get_mut(&pair).expect("book");
            let snap = self
                .fetch_snapshot(&pair)
                .await
                .wrap_err_with(|| format!("htx bootstrap {pair}"))?;
            book.apply_snapshot(snap.bids, snap.asks, Some(snap.version));
            let buf = prelude.get_mut(&pair).expect("buf");
            let mut applied = 0;
            while let Some(d) = buf.pop_front() {
                if d.seq_num <= snap.version {
                    continue;
                }
                book.apply_deltas(d.bids, d.asks, Some(d.seq_num));
                applied += 1;
            }
            if book.is_crossed() {
                warn!("[htx/{pair}] crossed after bootstrap, reseed");
                let snap2 = self.fetch_snapshot(&pair).await?;
                book.apply_snapshot(snap2.bids, snap2.asks, Some(snap2.version));
            }
            info!(
                "[htx/{pair}] bootstrapped (version={}, applied {applied})",
                snap.version
            );
        }

        // Phase 3: live deltas.
        loop {
            match read.next().await {
                Some(Ok(Message::Binary(bin))) => {
                    let received_at = now_ms();
                    let Some(text) = decompress(&bin) else {
                        continue;
                    };
                    if let Some(ts) = ping_ts(&text) {
                        write
                            .send(Message::Text(json!({"pong": ts}).to_string()))
                            .await?;
                        continue;
                    }
                    let Some((sym, delta)) = parse_mbp(&text) else {
                        continue;
                    };
                    let Some(book) = books.get_mut(&sym) else {
                        continue;
                    };
                    let Some(local) = book.seq else { continue };

                    if delta.seq_num <= local {
                        continue;
                    }
                    if delta.prev_seq_num != local {
                        warn!(
                            "[htx/{sym}] gap (prev={} vs local={}), re-snapshot",
                            delta.prev_seq_num, local
                        );
                        let snap = self.fetch_snapshot(&sym).await?;
                        book.apply_snapshot(snap.bids, snap.asks, Some(snap.version));
                        continue;
                    }
                    book.apply_deltas(delta.bids, delta.asks, Some(delta.seq_num));
                    if book.is_crossed() {
                        warn!("[htx/{sym}] crossed book, re-snapshot");
                        let snap = self.fetch_snapshot(&sym).await?;
                        book.apply_snapshot(snap.bids, snap.asks, Some(snap.version));
                        continue;
                    }
                    sink.emit(book.to_orderbook_data(delta.ts, received_at));
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
impl Collector for Htx {
    fn id(&self) -> &str {
        "htx"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[htx] no pairs"));
        }
        sink.status("htx", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

// ─── helpers ───────────────────────────────────────────────────────────────

struct RestSnapshot {
    version: u64,
    bids: Vec<(f64, f64)>,
    asks: Vec<(f64, f64)>,
}

#[derive(Debug)]
struct HtxDelta {
    seq_num: u64,
    prev_seq_num: u64,
    ts: i64,
    bids: Vec<(f64, f64)>,
    asks: Vec<(f64, f64)>,
}

fn decompress(bin: &[u8]) -> Option<String> {
    let mut d = GzDecoder::new(bin);
    let mut s = String::new();
    d.read_to_string(&mut s).ok()?;
    Some(s)
}

fn ping_ts(text: &str) -> Option<u64> {
    let v: Value = serde_json::from_str(text).ok()?;
    v.get("ping").and_then(|p| p.as_u64())
}

fn parse_levels(v: Option<&Value>) -> Vec<(f64, f64)> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|row| {
            let r = row.as_array()?;
            let p = parse_f64(r.first()?)?;
            let q = parse_f64(r.get(1)?)?;
            Some((p, q))
        })
        .collect()
}

fn parse_mbp(text: &str) -> Option<(String, HtxDelta)> {
    let v: Value = serde_json::from_str(text).ok()?;
    let ch = v.get("ch")?.as_str()?;
    // ch = "market.{symbol}.mbp.{N}" — extract symbol slot
    let sym = ch.split('.').nth(1)?.to_string();
    let tick = v.get("tick")?;
    let seq_num = parse_u64(tick.get("seqNum")?)?;
    let prev_seq_num = parse_u64(tick.get("prevSeqNum")?)?;
    let ts = v
        .get("ts")
        .and_then(parse_u64)
        .map(|x| x as i64)
        .unwrap_or(0);
    let bids = parse_levels(tick.get("bids"));
    let asks = parse_levels(tick.get("asks"));
    Some((
        sym,
        HtxDelta {
            seq_num,
            prev_seq_num,
            ts,
            bids,
            asks,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ping() {
        assert_eq!(ping_ts(r#"{"ping":1562979600}"#), Some(1562979600));
        assert_eq!(ping_ts(r#"{"sub":"x"}"#), None);
    }

    #[test]
    fn parse_mbp_extracts_symbol_and_seq() {
        let s = r#"{"ch":"market.btcusdt.mbp.400","ts":1,"tick":{"seqNum":2,"prevSeqNum":1,"bids":[[100.0,1.0]],"asks":[[101.0,2.0]]}}"#;
        let (sym, d) = parse_mbp(s).unwrap();
        assert_eq!(sym, "btcusdt");
        assert_eq!(d.seq_num, 2);
        assert_eq!(d.prev_seq_num, 1);
        assert_eq!(d.bids, vec![(100.0, 1.0)]);
        assert_eq!(d.asks, vec![(101.0, 2.0)]);
    }

    #[test]
    fn channel_format() {
        assert_eq!(Htx::channel("BTCUSDT"), "market.btcusdt.mbp.400");
        assert_eq!(Htx::channel("kasusdt"), "market.kasusdt.mbp.400");
    }
}
