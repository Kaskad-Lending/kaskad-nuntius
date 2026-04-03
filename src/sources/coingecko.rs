use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;
use std::collections::HashMap;

use super::PriceSource;
use crate::types::{now_secs, Asset, PricePoint};

pub struct CoinGecko {
    client: crate::http_client::HttpClient,
}

impl CoinGecko {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }

    fn coin_id_for(asset: Asset) -> Option<&'static str> {
        match asset {
            Asset::EthUsd => Some("ethereum"),
            Asset::BtcUsd => Some("bitcoin"),
            Asset::KasUsd => Some("kaspa"),
            Asset::UsdcUsd => Some("usd-coin"),
            _ => None,
        }
    }
}

// CoinGecko returns: { "bitcoin": { "usd": 12345.67 } }
type CoinGeckoResponse = HashMap<String, HashMap<String, f64>>;

#[async_trait]
impl PriceSource for CoinGecko {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        let coin_id = match Self::coin_id_for(asset) {
            Some(s) => s,
            None => return Ok(None),
        };

        let url = format!(
            "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd",
            coin_id
        );
        let resp: CoinGeckoResponse = self.client.get_json(&url).await?;

        let price = resp
            .get(coin_id)
            .and_then(|m| m.get("usd"))
            .copied()
            .ok_or_else(|| eyre::eyre!("no price from CoinGecko for {}", coin_id))?;

        Ok(Some(PricePoint {
            price,
            volume: 0.0,
            timestamp: now_secs(),
            source: "coingecko".into(),
            server_time: None,
        }))
    }

    fn name(&self) -> &'static str {
        "coingecko"
    }
}
