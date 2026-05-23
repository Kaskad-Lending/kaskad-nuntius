//! Bitfinex spot collector — `cex_data/bitfinex/ob.py` reference.
//!
//! Bitfinex's protocol is array-based, not object-based. Subscribe replies
//! and other "events" are JSON objects (`{"event": "subscribed", "chanId":N}`),
//! but every subsequent payload for that channel is a JSON array
//! `[chanId, payload]`. We track `chanId → symbol` to route across pairs.
//!
//! Order book messages encode side via the sign of `AMOUNT`:
//!   `[PRICE, COUNT, AMOUNT]`
//!     COUNT == 0           ⇒ remove PRICE from both sides
//!     COUNT  > 0, AMOUNT>0 ⇒ bid PRICE size = AMOUNT
//!     COUNT  > 0, AMOUNT<0 ⇒ ask PRICE size = abs(AMOUNT)
//!
//! Initial message after a `subscribed` event is the snapshot — a nested
//! array of triples. Following messages are single deltas.
//! Heartbeat messages are `[chanId, "hb"]`; just skip them.

use crate::cob_common::ExchangeConfig;
use crate::collectors::book::LocalBook;
use crate::collectors::collector::Collector;
use crate::collectors::sink::BookSink;
use crate::collectors::util::{now_ms, parse_f64, ws_connect};
use async_trait::async_trait;
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio_tungstenite::tungstenite::Message;
use tracing::info;

const LEN: u32 = 250;

pub struct Bitfinex {
    config: ExchangeConfig,
}

impl Bitfinex {
    pub fn new(config: ExchangeConfig) -> Self {
        Self { config }
    }

    async fn run_session(&self, sink: &BookSink) -> Result<()> {
        let url = self.config.ws_url.clone();
        info!(
            "[bitfinex] Connecting {} ({} pairs)",
            url,
            self.config.pairs.len()
        );
        let mut ws = ws_connect(&url).await?;

        // Subscribe to each symbol.
        for symbol in &self.config.pairs {
            ws.send(Message::Text(
                json!({
                    "event": "subscribe",
                    "channel": "book",
                    "symbol": symbol,
                    "prec": "P0",
                    "freq": "F0",
                    "len": LEN.to_string(),
                })
                .to_string(),
            ))
            .await?;
        }

        // chan_id ↔ subscribed-form symbol routing built up from `subscribed`
        // events. LocalBook is keyed by subscribed-form (what Bitfinex echoes)
        // but the OrderBookData it emits carries the normalized form
        // (`tBTCUSD` → `BTCUSD`) so downstream `extract_base_asset` resolves
        // to `BTC` without the generic T-strip hack (audit C-1).
        let mut chan_to_symbol: HashMap<i64, String> = HashMap::new();
        let mut books: HashMap<String, LocalBook> = self
            .config
            .pairs
            .iter()
            .map(|p| {
                (
                    p.clone(),
                    LocalBook::new("bitfinex", strip_bitfinex_t_prefix(p)),
                )
            })
            .collect();
        let mut tick: u64 = 0;

        let (mut write, mut read) = ws.split();

        loop {
            match read.next().await {
                Some(Ok(Message::Text(text))) => {
                    let received_at = now_ms();
                    let v: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    // Event objects (subscribe ack, info, error)
                    if v.is_object() {
                        if v.get("event").and_then(|e| e.as_str()) == Some("subscribed") {
                            let chan = v.get("chanId").and_then(|x| x.as_i64());
                            let sym = v.get("symbol").and_then(|x| x.as_str());
                            if let (Some(c), Some(s)) = (chan, sym) {
                                chan_to_symbol.insert(c, s.to_string());
                            }
                        }
                        continue;
                    }
                    // Data arrays: [chanId, payload]
                    let arr = match v.as_array() {
                        Some(a) if a.len() >= 2 => a,
                        _ => continue,
                    };
                    let chan = match arr.first().and_then(|x| x.as_i64()) {
                        Some(c) => c,
                        None => continue,
                    };
                    let sym = match chan_to_symbol.get(&chan) {
                        Some(s) => s.clone(),
                        None => continue,
                    };
                    let Some(book) = books.get_mut(&sym) else {
                        continue;
                    };
                    let payload = &arr[1];

                    // Heartbeat
                    if payload.as_str() == Some("hb") {
                        continue;
                    }

                    let Some(p_arr) = payload.as_array() else {
                        continue;
                    };
                    if p_arr.is_empty() {
                        continue;
                    }

                    if p_arr[0].is_array() {
                        // Snapshot — nested array of [price, count, amount]
                        let (bids, asks) = split_levels(p_arr);
                        tick = tick.wrapping_add(1);
                        book.apply_snapshot(bids, asks, Some(tick));
                    } else if p_arr.len() == 3 {
                        // Single delta
                        let (bids, asks, removed) = single_delta(p_arr);
                        tick = tick.wrapping_add(1);
                        if !removed.is_empty() {
                            // count==0: delete price from BOTH sides
                            let zeros: Vec<(f64, f64)> =
                                removed.iter().map(|p| (*p, 0.0)).collect();
                            book.apply_deltas(zeros.clone(), zeros, Some(tick));
                        }
                        book.apply_deltas(bids, asks, Some(tick));
                    }
                    if !book.is_crossed() && book.is_ready() {
                        sink.emit(book.to_orderbook_data(0, received_at));
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
impl Collector for Bitfinex {
    fn id(&self) -> &str {
        "bitfinex"
    }
    async fn run(&self, sink: BookSink) -> Result<()> {
        if self.config.pairs.is_empty() {
            return Err(eyre!("[bitfinex] no pairs"));
        }
        sink.status("bitfinex", crate::cob_common::ServiceStatus::Connected);
        self.run_session(&sink).await
    }
}

type Levels = Vec<(f64, f64)>;

/// `tBTCUSD` → `BTCUSD`; anything not starting with lowercase `t` + an
/// uppercase letter passes through unchanged. Used only inside this
/// collector — `cob_common::extract_base_asset` no longer does it
/// generically (that produced collisions for tokens that legitimately
/// begin with `T`, e.g. TBTC / TUSDC / TUSD).
fn strip_bitfinex_t_prefix(symbol: &str) -> String {
    let bytes = symbol.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b't' && bytes[1].is_ascii_uppercase() {
        symbol[1..].to_string()
    } else {
        symbol.to_string()
    }
}

fn split_levels(arr: &[Value]) -> (Levels, Levels) {
    let mut bids = Vec::new();
    let mut asks = Vec::new();
    for entry in arr {
        let Some(triple) = entry.as_array() else {
            continue;
        };
        if triple.len() < 3 {
            continue;
        }
        let Some(price) = parse_f64(&triple[0]) else {
            continue;
        };
        let count = triple[1].as_i64().unwrap_or(0);
        let Some(amount) = parse_f64(&triple[2]) else {
            continue;
        };
        if count <= 0 {
            continue;
        } // snapshots only contain count>0
        if amount > 0.0 {
            bids.push((price, amount));
        } else if amount < 0.0 {
            asks.push((price, amount.abs()));
        }
    }
    (bids, asks)
}

fn single_delta(triple: &[Value]) -> (Levels, Levels, Vec<f64>) {
    let mut bids = Vec::new();
    let mut asks = Vec::new();
    let mut removed = Vec::new();
    let Some(price) = parse_f64(&triple[0]) else {
        return (bids, asks, removed);
    };
    let count = triple[1].as_i64().unwrap_or(0);
    let Some(amount) = parse_f64(&triple[2]) else {
        return (bids, asks, removed);
    };
    if count == 0 {
        removed.push(price);
    } else if amount > 0.0 {
        bids.push((price, amount));
    } else if amount < 0.0 {
        asks.push((price, amount.abs()));
    }
    (bids, asks, removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_split_by_amount_sign() {
        let raw = r#"[[100.0,3,1.5],[101.0,2,-2.0],[99.0,5,0.0]]"#;
        let v: Vec<Value> = serde_json::from_str(raw).unwrap();
        let (bids, asks) = split_levels(&v);
        assert_eq!(bids, vec![(100.0, 1.5)]);
        assert_eq!(asks, vec![(101.0, 2.0)]);
        // amount=0 with count>0 is filtered (Bitfinex shouldn't send this)
    }

    #[test]
    fn delta_count_zero_removes() {
        let triple = vec![Value::from(100.0), Value::from(0), Value::from(1.0)];
        let (b, a, removed) = single_delta(&triple);
        assert!(b.is_empty());
        assert!(a.is_empty());
        assert_eq!(removed, vec![100.0]);
    }

    #[test]
    fn delta_negative_amount_is_ask() {
        let triple = vec![Value::from(100.0), Value::from(2), Value::from(-1.5)];
        let (b, a, removed) = single_delta(&triple);
        assert!(b.is_empty());
        assert_eq!(a, vec![(100.0, 1.5)]);
        assert!(removed.is_empty());
    }

    #[test]
    fn strip_t_prefix_normalises_bitfinex_pairs() {
        assert_eq!(strip_bitfinex_t_prefix("tBTCUSD"), "BTCUSD");
        assert_eq!(strip_bitfinex_t_prefix("tETHUSD"), "ETHUSD");
    }

    #[test]
    fn strip_t_prefix_leaves_other_symbols_alone() {
        // Tokens that legitimately begin with uppercase T must be
        // preserved — the audit C-1 collision case.
        assert_eq!(strip_bitfinex_t_prefix("TBTCUSD"), "TBTCUSD");
        assert_eq!(strip_bitfinex_t_prefix("TUSDCUSDT"), "TUSDCUSDT");
        assert_eq!(strip_bitfinex_t_prefix("TRUMPUSDT"), "TRUMPUSDT");
        // Bitfinex funding/derivative prefixes other than `t` pass through.
        assert_eq!(strip_bitfinex_t_prefix("fUSD"), "fUSD");
    }
}
