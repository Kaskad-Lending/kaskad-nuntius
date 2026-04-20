use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

pub struct Coinbase {
    client: crate::http_client::HttpClient,
}

impl Coinbase {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
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
    #[allow(dead_code)]
    currency: String,
}

#[async_trait]
impl PriceSource for Coinbase {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let pair = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!("https://api.coinbase.com/v2/prices/{}/spot", pair);
        let (resp, server_time): (CoinbaseResponse, u64) =
            self.client.get_json_with_time(&url).await?;
        let expected_base = pair.split('-').next().unwrap_or("");
        if resp.data.base != expected_base {
            return Err(eyre::eyre!(
                "coinbase base mismatch: expected {}, got {}",
                expected_base,
                resp.data.base
            ));
        }
        let price: f64 = resp.data.amount.parse()?;

        Ok(Some(PricePoint {
            price,
            volume: 0.0,
            source: "coinbase".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "coinbase"
    }
}
