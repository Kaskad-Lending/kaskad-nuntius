//! MEXC spot collector — `cex_data/mexc/ob.py` reference.
//!
//! Channel: `spot@public.aggre.depth.v3.api.pb@10ms@{SYMBOL}` on
//! `wss://wbs-api.mexc.com/ws`. Frames are **binary protobuf**
//! (`PushDataV3ApiWrapper` → `publicAggreDepths`). String frames are
//! subscription acks/pongs and are skipped.
//!
//! Bootstrap: subscribe → buffer protobuf deltas → REST snapshot
//! `https://api.mexc.com/api/v3/depth?symbol={S}&limit=5000` (returns
//! `lastUpdateId` as the seqNum anchor).
//!
//! Continuity: each delta carries `(fromVersion, toVersion)` strings.
//! `fromVersion <= local` ⇒ stale (skip); `fromVersion > local + 1` ⇒
//! gap ⇒ reconnect.
//!
//! Application keepalive: send `{"method":"PING"}` every 45s.

use crate::cob_common::ExchangeConfig;
use crate::collectors::book::LocalBook;
use crate::collectors::collector::Collector;
use crate::collectors::rest::HTTP;
use crate::collectors::sink::BookSink;
use crate::collectors::util::{now_ms, ws_connect};
use async_trait::async_trait;
use eyre::{eyre, Result, WrapErr};
use futures::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

mod proto {
    include!(concat!(env!("OUT_DIR"), "/mexc.rs"));
}

const REST_BASE: &str = "https://api.mexc.com";
const PING_INTERVAL: Duration = Duration::from_secs(45);
const PRELUDE_BUFFER_TIMEOUT: Duration = Duration::from_secs(3);
const PRELUDE_BUFFER_MIN: usize = 5;

pub struct Mexc {
    config: ExchangeConfig,
}

impl Mexc {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    fn channel(symbol: &str) -> String {
        format!(
            "spot@public.aggre.depth.v3.api.pb@10ms@{}",
            symbol.to_uppercase()
        )
    }

    async fn fetch_snapshot(&self, symbol: &str) -> Result<RestSnapshot> {
        let url = format!(
            "{REST_BASE}/api/v3/depth?symbol={}&limit=5000",
            symbol.to_uppercase()
        );
        let v: Value = HTTP
            .get(&url)
            .send()
            .await
            .wrap_err_with(|| format!("MEXC REST {symbol}"))?
            .error_for_status()?
            .json()
            .await?;
        let last = v
            .get("lastUpdateId")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| eyre!("missing lastUpdateId"))?;
        let bids = parse_rest_levels(v.get("bids"));
        let asks = parse_rest_levels(v.get("asks"));
        Ok(RestSnapshot {
            last_update_id: last,
            bids,
            asks,
        })
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[mexc] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // Subscribe — MEXC accepts an array of channels.
        let params: Vec<String> = self.config.pairs.iter().map(|p| Self::channel(p)).collect();
        ws.send(Message::Text(
            json!({"method": "SUBSCRIPTION", "params": params}).to_string(),
        ))
        .await?;

        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| {
                let key = p.to_uppercase();
                (key.clone(), LocalBook::new("mexc", key))
            })
            .collect();
        let mut prelude: HashMap<String, VecDeque<MexcDelta>> = self
            .config
            .pairs
            .iter()
            .map(|p| (p.to_uppercase(), VecDeque::new()))
            .collect();

        let (mut write, mut read) = ws.split();

        // Phase 1: buffer prelude.
        let deadline = tokio::time::Instant::now() + PRELUDE_BUFFER_TIMEOUT;
        loop {
            if prelude.values().all(|q| q.len() >= PRELUDE_BUFFER_MIN) {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                debug!("[mexc] prelude deadline");
                break;
            }
            let to = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(to, read.next()).await {
                Ok(Some(Ok(Message::Binary(bin)))) => {
                    if let Some((sym, d)) = decode_wrapper(&bin) {
                        prelude.entry(sym).or_default().push_back(d);
                    }
                }
                Ok(Some(Ok(_))) => {} // text ack, ignore
                Ok(Some(Err(e))) => return Err(eyre!("WS error during prelude: {e}")),
                Ok(None) => return Err(eyre!("WS closed during prelude")),
                Err(_) => break,
            }
        }

        // Phase 2: REST snapshot per pair, then reconcile prelude. On a
        // bootstrap-gap we refetch the snapshot once; persistent gap aborts
        // the session so the manager re-spawns after backoff. Mirrors the
        // Binance pattern (see binance.rs).
        for pair in self.config.pairs.iter().map(|p| p.to_uppercase()) {
            let book = books.get_mut(&pair).expect("book");
            for attempt in 0..2 {
                let snap = self
                    .fetch_snapshot(&pair)
                    .await
                    .wrap_err_with(|| format!("mexc bootstrap {pair} (attempt {})", attempt + 1))?;
                book.apply_snapshot(snap.bids, snap.asks, Some(snap.last_update_id));
                let buf = prelude.get_mut(&pair).expect("buf");
                let drained = std::mem::take(buf);
                match reconcile_prelude(book, snap.last_update_id, drained) {
                    Ok(applied) => {
                        info!(
                            "[mexc/{pair}] bootstrapped (lastUpdateId={}, applied {applied})",
                            snap.last_update_id
                        );
                        break;
                    }
                    Err(BootstrapGap { first_seen }) => {
                        warn!(
                            "[mexc/{pair}] bootstrap gap (from={} > snap+1={}) attempt {}",
                            first_seen,
                            snap.last_update_id + 1,
                            attempt + 1
                        );
                        if attempt == 1 {
                            return Err(eyre!("[mexc/{pair}] persistent bootstrap gap"));
                        }
                    }
                }
            }
        }

        // Phase 3: live + ping.
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.tick().await;
        loop {
            tokio::select! {
                msg = read.next() => {
                    let received_at = now_ms();
                    match msg {
                        Some(Ok(Message::Binary(bin))) => {
                            let Some((sym, d)) = decode_wrapper(&bin) else { continue };
                            let Some(book) = books.get_mut(&sym) else { continue };
                            let Some(local) = book.seq else { continue };
                            if d.from_version <= local { continue; }
                            if d.from_version > local + 1 {
                                warn!("[mexc/{sym}] gap (from={}, local={local}), reconnecting", d.from_version);
                                return Err(eyre!("mexc gap"));
                            }
                            book.apply_deltas(d.bids, d.asks, Some(d.to_version));
                            if !book.is_crossed() {
                                if let Some(d) = book.to_orderbook_data(d.send_time, received_at) {
                                    sink.emit(d);
                                }
                            }
                        }
                        Some(Ok(Message::Text(_))) => {} // PONG / acks
                        Some(Ok(Message::Ping(p))) => { let _ = write.send(Message::Pong(p)).await; }
                        Some(Ok(Message::Close(_))) | None => return Err(eyre!("WS closed")),
                        Some(Err(e)) => return Err(eyre!("WS error: {e}")),
                        _ => {}
                    }
                }
                _ = ping.tick() => {
                    if write.send(Message::Text(r#"{"method":"PING"}"#.into())).await.is_err() {
                        return Err(eyre!("ping send failed"));
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Collector for Mexc {
    fn id(&self) -> &str {
        "mexc"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[mexc] no pairs"));
        }
        sink.status("mexc", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

// ─── decoding ──────────────────────────────────────────────────────────────

struct RestSnapshot {
    last_update_id: u64,
    bids: Vec<(f64, f64)>,
    asks: Vec<(f64, f64)>,
}

#[derive(Debug)]
struct MexcDelta {
    from_version: u64,
    to_version: u64,
    send_time: i64,
    bids: Vec<(f64, f64)>,
    asks: Vec<(f64, f64)>,
}

fn decode_wrapper(bytes: &[u8]) -> Option<(String, MexcDelta)> {
    let w = proto::PushDataV3ApiWrapper::decode(bytes).ok()?;
    let depths = w.public_aggre_depths.as_ref()?;
    let from_version: u64 = depths.from_version.parse().ok()?;
    let to_version: u64 = depths.to_version.parse().ok()?;
    let bids = depths
        .bids
        .iter()
        .filter_map(|i| Some((i.price.parse().ok()?, i.quantity.parse().ok()?)))
        .collect();
    let asks = depths
        .asks
        .iter()
        .filter_map(|i| Some((i.price.parse().ok()?, i.quantity.parse().ok()?)))
        .collect();
    let symbol = w.symbol.unwrap_or_default().to_uppercase();
    let send_time = w.send_time.unwrap_or(0);
    if symbol.is_empty() {
        // Some MEXC channels embed the symbol in the channel name only. Recover:
        let ch = w.channel; // "spot@public.aggre.depth.v3.api.pb@10ms@BTCUSDT"
        let symbol = ch.rsplit('@').next()?.to_uppercase();
        return Some((
            symbol,
            MexcDelta {
                from_version,
                to_version,
                send_time,
                bids,
                asks,
            },
        ));
    }
    Some((
        symbol,
        MexcDelta {
            from_version,
            to_version,
            send_time,
            bids,
            asks,
        },
    ))
}

/// Pure reconciliation step extracted for testability. Drains `prelude` into
/// `book`, enforcing that the FIRST applied event covers `snap_anchor + 1`
/// (i.e. `from_version <= snap_anchor + 1 <= to_version`). Stale events
/// (`to_version <= snap_anchor`) are dropped silently. On gap the book is
/// cleared so the caller can re-snapshot.
#[derive(Debug)]
struct BootstrapGap {
    first_seen: u64,
}

fn reconcile_prelude(
    book: &mut LocalBook,
    snap_anchor: u64,
    mut prelude: VecDeque<MexcDelta>,
) -> std::result::Result<usize, BootstrapGap> {
    let mut applied = 0usize;
    while let Some(d) = prelude.pop_front() {
        if d.to_version <= snap_anchor {
            continue;
        }
        if applied == 0 && d.from_version > snap_anchor + 1 {
            book.clear();
            return Err(BootstrapGap {
                first_seen: d.from_version,
            });
        }
        book.apply_deltas(d.bids, d.asks, Some(d.to_version));
        applied += 1;
    }
    Ok(applied)
}

fn parse_rest_levels(v: Option<&Value>) -> Vec<(f64, f64)> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|row| {
            let r = row.as_array()?;
            let p = r.first()?.as_str()?.parse::<f64>().ok()?;
            let q = r.get(1)?.as_str()?.parse::<f64>().ok()?;
            Some((p, q))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_format() {
        assert_eq!(
            Mexc::channel("BTCUSDT"),
            "spot@public.aggre.depth.v3.api.pb@10ms@BTCUSDT"
        );
        assert_eq!(
            Mexc::channel("kasusdt"),
            "spot@public.aggre.depth.v3.api.pb@10ms@KASUSDT"
        );
    }

    fn delta(from: u64, to: u64) -> MexcDelta {
        MexcDelta {
            from_version: from,
            to_version: to,
            send_time: 0,
            bids: vec![(100.0, 1.0)],
            asks: vec![(101.0, 1.0)],
        }
    }

    #[test]
    fn reconcile_filters_stale_first_event_below_snap() {
        let mut book = LocalBook::new("mexc", "BTCUSDT");
        book.apply_snapshot([(100.0, 5.0)], [(101.0, 5.0)], Some(100));
        // Stale event (to_version=99 <= snap=100) is filtered, then the
        // straddling event applies cleanly.
        let mut q = VecDeque::new();
        q.push_back(delta(80, 99)); // stale
        q.push_back(delta(95, 105)); // straddle: from<=101<=to → applies
        let applied = reconcile_prelude(&mut book, 100, q).expect("no gap");
        assert_eq!(applied, 1);
        assert_eq!(book.seq, Some(105));
    }

    #[test]
    fn reconcile_detects_gap_when_first_event_above_snap_plus_one() {
        let mut book = LocalBook::new("mexc", "BTCUSDT");
        book.apply_snapshot([(100.0, 5.0)], [(101.0, 5.0)], Some(100));
        // First event jumps from=103 (>= snap+2): gap.
        let mut q = VecDeque::new();
        q.push_back(delta(103, 110));
        let err = reconcile_prelude(&mut book, 100, q).unwrap_err();
        assert_eq!(err.first_seen, 103);
        // Book is cleared so caller can re-snapshot.
        assert!(book.seq.is_none());
        assert!(book.bids.is_empty() && book.asks.is_empty());
    }

    #[test]
    fn decode_synthetic_wrapper() {
        // Build a tiny wrapper using prost itself, then round-trip through decoder.
        use proto::*;
        let w = PushDataV3ApiWrapper {
            channel: "spot@public.aggre.depth.v3.api.pb@10ms@BTCUSDT".into(),
            public_aggre_depths: Some(PublicAggreDepthsV3Api {
                asks: vec![PublicAggreDepthV3ApiItem {
                    price: "101.0".into(),
                    quantity: "0.5".into(),
                }],
                bids: vec![PublicAggreDepthV3ApiItem {
                    price: "100.0".into(),
                    quantity: "1.0".into(),
                }],
                event_type: "diff".into(),
                from_version: "10".into(),
                to_version: "12".into(),
            }),
            symbol: Some("BTCUSDT".into()),
            symbol_id: None,
            create_time: None,
            send_time: Some(1700000000000),
        };
        let mut buf = Vec::new();
        w.encode(&mut buf).unwrap();
        let (sym, d) = decode_wrapper(&buf).expect("decode");
        assert_eq!(sym, "BTCUSDT");
        assert_eq!(d.from_version, 10);
        assert_eq!(d.to_version, 12);
        assert_eq!(d.bids, vec![(100.0, 1.0)]);
        assert_eq!(d.asks, vec![(101.0, 0.5)]);
        assert_eq!(d.send_time, 1700000000000);
    }
}
