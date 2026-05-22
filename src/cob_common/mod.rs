//! Types shared by `src/collectors/**` and `src/cob.rs`. Slim subset of
//! oracle-light's `common` crate. `#![allow(dead_code)]` covers the
//! variants/fields the collector layer uses internally but the signer
//! never reads (CollectorCommand, ExchangeStats, CollectorMessage::Stats).
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};

/// Feed latency tracker using min-delta calibration.
pub struct LatencyTracker {
    min_delta: AtomicI64,
    base_rtt_ms: i64,
    sample_count: AtomicI64,
    recalibrate_every: i64,
}

const DEFAULT_RECALIBRATE_EVERY: i64 = 3000;

impl LatencyTracker {
    pub fn new(base_rtt_ms: i64) -> Self {
        Self {
            min_delta: AtomicI64::new(i64::MAX),
            base_rtt_ms,
            sample_count: AtomicI64::new(0),
            recalibrate_every: DEFAULT_RECALIBRATE_EVERY,
        }
    }

    pub fn normalize_timestamp_ms(ts: i64) -> Option<i64> {
        if ts <= 0 {
            return None;
        }
        if ts < 1_000_000_000_000 {
            Some(ts * 1000)
        } else if ts > 1_000_000_000_000_000 {
            Some(ts / 1000)
        } else {
            Some(ts)
        }
    }

    pub fn calculate(&self, exchange_ts_ms: i64, received_at_ms: i64) -> i64 {
        if exchange_ts_ms <= 0 {
            return -1;
        }
        let current_delta = received_at_ms - exchange_ts_ms;

        let count = self.sample_count.fetch_add(1, Ordering::Relaxed);
        if count > 0 && count % self.recalibrate_every == 0 {
            self.min_delta.store(i64::MAX, Ordering::Relaxed);
        }

        let mut min = self.min_delta.load(Ordering::Relaxed);
        loop {
            if current_delta >= min {
                break;
            }
            match self.min_delta.compare_exchange_weak(
                min,
                current_delta,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    min = current_delta;
                    break;
                }
                Err(actual) => min = actual,
            }
        }

        if min == i64::MAX {
            return self.base_rtt_ms;
        }

        let relative = current_delta - min;
        if relative < 0 {
            self.base_rtt_ms
        } else {
            relative + self.base_rtt_ms
        }
    }

    pub fn process(&self, raw_ts: i64, received_at_ms: i64) -> (i64, i64) {
        match Self::normalize_timestamp_ms(raw_ts) {
            Some(ts_ms) => (ts_ms, self.calculate(ts_ms, received_at_ms)),
            None => (received_at_ms, -1),
        }
    }
}

/// Exchange config. Tick sizes are owned by `cob::tick_size_for` (a
/// hardcoded matrix per (venue, base)); adding a new venue means a code
/// change there, not a JSON edit. Older revisions of this file carried
/// `tick_size` + `tick_overrides` fields, but they were never read by
/// the COB layer — kept-but-unused config is worse than no config
/// (operator thinks they can change behaviour from JSON, can't). Audit M-2.
///
/// `#[serde(default)]` + `#[serde(deny_unknown_fields)]` is intentionally
/// NOT set: legacy `exchanges.json` blobs with `tick_size` / `tick_overrides`
/// fields still parse — those fields are silently ignored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExchangeConfig {
    pub name: String,
    pub enabled: bool,
    #[serde(default)]
    pub ws_url: String,
    #[serde(default)]
    pub pairs: Vec<String>,
    #[serde(default)]
    pub extra_params: HashMap<String, String>,
}

impl ExchangeConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Exchange config has empty name".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum CollectorCommand {
    Enable(String),
    Disable(String),
    Status,
    Reload,
    Stop,
}

#[derive(Debug, Clone)]
pub struct ExchangeStats {
    pub name: String,
    pub bids_count: usize,
    pub asks_count: usize,
    pub timestamp: i64,
    pub latency_ms: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ServiceStatus {
    Starting,
    Connected,
    Reconnecting,
    Error(String),
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceLevel {
    pub price: f64,
    pub quantity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBookData {
    pub exchange_id: String,
    pub symbol: String,
    pub exchange_timestamp: i64,
    pub received_timestamp: i64,
    pub latency: i64,
    pub bids: Vec<PriceLevel>,
    pub asks: Vec<PriceLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

impl OrderBookData {
    pub fn best_bid(&self) -> Option<&PriceLevel> {
        self.bids.first()
    }
    pub fn best_ask(&self) -> Option<&PriceLevel> {
        self.asks.first()
    }
    pub fn mid_price(&self) -> Option<f64> {
        let bb = self.best_bid()?.price;
        let ba = self.best_ask()?.price;
        Some((bb + ba) / 2.0)
    }
    pub fn is_valid(&self) -> bool {
        match (self.best_bid(), self.best_ask()) {
            (Some(bid), Some(ask)) => bid.price > 0.0 && ask.price > 0.0 && bid.price < ask.price,
            (None, None) => false,
            (Some(bid), None) => bid.price > 0.0,
            (None, Some(ask)) => ask.price > 0.0,
        }
    }
}

/// Pushed from collectors to the main loop. The kaskad-nuntius overlay
/// only cares about the `Data` variant; Stats/Status are kept for
/// wire-compatibility with the manager but dropped at the fan-in.
#[derive(Debug, Clone)]
pub enum CollectorMessage {
    Stats(ExchangeStats),
    Data(OrderBookData),
    Status { name: String, status: ServiceStatus },
}

/// Extract the base asset from any exchange symbol format.
/// "BTC/USD" -> "BTC", "KAS_USDT" -> "KAS", "ETHUSDT" -> "ETH".
///
/// NB: bitfinex prefixes spot pairs with lowercase `t` (e.g. `tBTCUSD`).
/// Strip that in the bitfinex collector before forwarding the symbol —
/// do NOT do it here, otherwise tokens that legitimately begin with `T`
/// collide with their base (TBTC = Threshold-BTC mutates to BTC, TUSDC
/// collapses into USDC, TUSD into USD). Audit C-1.
pub fn extract_base_asset(symbol: &str) -> String {
    let s = symbol.to_uppercase();
    for sep in ['/', '_', '-', ':'] {
        if let Some(pos) = s.find(sep) {
            return s[..pos].to_string();
        }
    }
    for quote in &["USDT", "USDC", "BUSD", "TUSD", "UST", "USD"] {
        if let Some(base) = s.strip_suffix(quote) {
            if !base.is_empty() {
                return base.to_string();
            }
        }
    }
    s
}
