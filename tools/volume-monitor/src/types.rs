//! Shared types between the venue sessions and the accumulator.

use tokio::sync::mpsc::UnboundedSender;

/// One executed trade observed on a venue's public trade stream.
#[derive(Debug, Clone)]
pub struct Trade {
    pub venue: String,
    /// Venue-native pair string as configured in exchanges.json.
    pub pair: String,
    pub price: f64,
    /// Quantity in BASE asset units.
    pub qty_base: f64,
    /// Exchange trade timestamp, unix ms (0 if the venue doesn't send one).
    pub ts_ms: i64,
}

#[derive(Debug)]
pub enum Event {
    Trade(Trade),
    /// Session established (post-handshake, post-subscribe-send).
    Connected {
        venue: String,
    },
    /// Session ended with an error; the wrapper will reconnect after backoff.
    SessionEnd {
        venue: String,
        error: String,
    },
}

pub type EventTx = UnboundedSender<Event>;

/// Venue entry parsed from config/exchanges.json (same shape as the
/// oracle's `ExchangeConfig`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct VenueCfg {
    pub name: String,
    pub enabled: bool,
    #[serde(default)]
    pub ws_url: String,
    #[serde(default)]
    pub pairs: Vec<String>,
}

impl VenueCfg {
    pub fn send_trade(&self, tx: &EventTx, pair: &str, price: f64, qty_base: f64, ts_ms: i64) {
        // NaN/zero guard: a malformed frame must never poison the totals.
        if !(price.is_finite() && qty_base.is_finite()) || price <= 0.0 || qty_base <= 0.0 {
            return;
        }
        let _ = tx.send(Event::Trade(Trade {
            venue: self.name.clone(),
            pair: pair.to_string(),
            price,
            qty_base,
            ts_ms,
        }));
    }

    pub fn send_connected(&self, tx: &EventTx) {
        let _ = tx.send(Event::Connected {
            venue: self.name.clone(),
        });
    }
}
