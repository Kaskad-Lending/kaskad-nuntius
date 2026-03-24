use async_trait::async_trait;
use eyre::Result;

use super::PriceSource;
use crate::types::{now_secs, Asset, PricePoint};

/// Governance-set price source for IGRA (presale token).
///
/// During presale, IGRA has no exchange listings, so the price is set by
/// governance (multisig). The oracle reads this fixed price and pushes it
/// on-chain with the oracle's attestation signature, proving that the
/// governance-set value was faithfully relayed.
///
/// Once IGRA is listed on a DEX, this source will be replaced with a
/// standard TWAP source.
pub struct GovernancePrice {
    /// Fixed price per token in USD.
    price: f64,
}

impl GovernancePrice {
    pub fn new(price: f64) -> Self {
        Self { price }
    }

    /// Update the governance-set price (e.g. after a governance vote).
    pub fn set_price(&mut self, price: f64) {
        self.price = price;
    }
}

#[async_trait]
impl PriceSource for GovernancePrice {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        match asset {
            Asset::IgraUsd => Ok(Some(PricePoint {
                price: self.price,
                volume: 0.0,
                timestamp: now_secs(),
                source: "governance".into(),
            })),
            _ => Ok(None),
        }
    }

    fn name(&self) -> &'static str {
        "governance"
    }
}
