use async_trait::async_trait;
use eyre::Result;
use std::collections::HashMap;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

pub struct CoinGecko {
    client: crate::http_client::HttpClient,
}

impl CoinGecko {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

// CoinGecko returns: { "bitcoin": { "usd": 12345.67 } }
type CoinGeckoResponse = HashMap<String, HashMap<String, f64>>;

#[async_trait]
impl PriceSource for CoinGecko {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let coin_id = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!(
            "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd",
            coin_id
        );
        let (resp, server_time): (CoinGeckoResponse, u64) =
            self.client.get_json_with_time(&url).await?;

        let price = resp
            .get(coin_id)
            .and_then(|m| m.get("usd"))
            .copied()
            .ok_or_else(|| eyre::eyre!("no price from CoinGecko for {}", coin_id))?;

        Ok(Some(PricePoint {
            price,
            volume: 0.0,
            source: "coingecko".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "coingecko"
    }
}
