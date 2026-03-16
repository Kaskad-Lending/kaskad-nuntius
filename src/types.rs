use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{B256, FixedBytes};
use serde::Deserialize;

/// A single price observation from a data source.
#[derive(Debug, Clone)]
pub struct PricePoint {
    pub price: f64,
    pub volume: f64,
    pub timestamp: u64,
    pub source: String,
}

/// Supported assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Asset {
    EthUsd,
    BtcUsd,
    KasUsd,
    UsdcUsd,
    IgraUsd,
}

impl Asset {
    /// Return the on-chain asset ID (keccak256 of the symbol string).
    pub fn id(&self) -> B256 {
        use sha3::{Digest, Keccak256};
        let symbol = self.symbol();
        let hash = Keccak256::digest(symbol.as_bytes());
        B256::from_slice(&hash)
    }

    pub fn symbol(&self) -> &'static str {
        match self {
            Asset::EthUsd => "ETH/USD",
            Asset::BtcUsd => "BTC/USD",
            Asset::KasUsd => "KAS/USD",
            Asset::UsdcUsd => "USDC/USD",
            Asset::IgraUsd => "IGRA/USD",
        }
    }

    /// Deviation threshold in basis points before pushing on-chain.
    pub fn deviation_threshold_bps(&self) -> u16 {
        match self {
            Asset::EthUsd | Asset::BtcUsd => 50,   // 0.5%
            Asset::KasUsd => 200,                    // 2% (exotic, volatile)
            Asset::UsdcUsd => 10,                    // 0.1% (stablecoin)
            Asset::IgraUsd => 0,                     // governance-set, always push
        }
    }

    /// Heartbeat interval in seconds (max time between updates).
    pub fn heartbeat_seconds(&self) -> u64 {
        match self {
            Asset::EthUsd | Asset::BtcUsd => 3600,  // 1 hour
            Asset::KasUsd => 1800,                    // 30 min
            Asset::UsdcUsd => 86400,                  // 24 hours
            Asset::IgraUsd => 86400,                  // 24 hours
        }
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}
