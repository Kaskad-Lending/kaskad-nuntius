use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{FixedBytes, B256};
use serde::{Deserialize, Serialize};

/// A single price observation from a data source.
#[derive(Debug, Clone)]
pub struct PricePoint {
    pub price: f64,
    pub volume: f64,
    pub timestamp: u64,
    pub source: String,
    /// Server-reported unix timestamp (seconds). Used as trusted clock source
    /// inside the enclave since the host controls the system clock.
    pub server_time: Option<u64>,
}

/// Cached aggregated price — unsigned, stored in PriceStore.
/// Signature is created on-demand when a client requests it.
#[derive(Debug, Clone)]
pub struct CachedPrice {
    pub asset: Asset,
    pub price_fixed: alloy_primitives::U256,
    pub price_human: f64,
    pub num_sources: u8,
    pub sources_hash: alloy_primitives::B256,
}

/// A signed price update ready for external consumption (pull API).
#[derive(Debug, Clone, Serialize)]
pub struct SignedPriceUpdate {
    pub asset_id: String,
    pub asset_symbol: String,
    pub price: String,
    pub price_human: String,
    pub timestamp: u64,
    pub num_sources: u8,
    pub sources_hash: String,
    pub signature: String,
    pub signer: String,
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
            Asset::EthUsd | Asset::BtcUsd => 50, // 0.5%
            Asset::KasUsd => 200,                // 2% (exotic, volatile)
            Asset::UsdcUsd => 10,                // 0.1% (stablecoin)
            Asset::IgraUsd => 0,                 // governance-set, always push
        }
    }

    /// Minimum number of sources required to sign a price (Data Quorum).
    pub fn min_sources(&self) -> usize {
        match self {
            Asset::EthUsd | Asset::BtcUsd => 3,
            Asset::KasUsd => 3,
            Asset::UsdcUsd => 2,  // only 3 exchanges carry USDC/USDT
            Asset::IgraUsd => 1,  // governance-set, single source
        }
    }

    /// Heartbeat interval in seconds (max time between updates).
    pub fn heartbeat_seconds(&self) -> u64 {
        match self {
            Asset::EthUsd | Asset::BtcUsd => 3600, // 1 hour
            Asset::KasUsd => 1800,                 // 30 min
            Asset::UsdcUsd => 86400,               // 24 hours
            Asset::IgraUsd => 86400,               // 24 hours
        }
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}
