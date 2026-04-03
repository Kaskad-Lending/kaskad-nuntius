use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{now_secs, Asset, PricePoint};

pub struct Coinbase {
    client: crate::http_client::HttpClient,
}

impl Coinbase {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }

    fn pair_for(asset: Asset) -> Option<&'static str> {
        match asset {
            Asset::EthUsd => Some("ETH-USD"),
            Asset::BtcUsd => Some("BTC-USD"),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct CoinbaseResponse {
    data: CoinbasePrice,
}

#[derive(Deserialize)]
struct CoinbasePrice {
    amount: String,
    base: String,
    currency: String,
}

#[async_trait]
impl PriceSource for Coinbase {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        let pair = match Self::pair_for(asset) {
            Some(s) => s,
            None => return Ok(None),
        };

        let url = format!("https://api.coinbase.com/v2/prices/{}/spot", pair);
        let resp: CoinbaseResponse = self.client.get_json(&url).await?;
        let expected_base = pair.split('-').next().unwrap_or("");
        if resp.data.base != expected_base {
            return Err(eyre::eyre!("coinbase base mismatch: expected {}, got {}", expected_base, resp.data.base));
        }
        let price: f64 = resp.data.amount.parse()?;

        Ok(Some(PricePoint {
            price,
            volume: 0.0,
            timestamp: now_secs(),
            source: "coinbase".into(),
            server_time: None,
        }))
    }

    fn name(&self) -> &'static str {
        "coinbase"
    }
}
