use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

pub struct Mexc {
    client: crate::http_client::HttpClient,
}

impl Mexc {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[derive(Deserialize)]
struct MexcTicker {
    symbol: String,
    price: String,
}

#[async_trait]
impl PriceSource for Mexc {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let symbol = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!("https://api.mexc.com/api/v3/ticker/price?symbol={}", symbol);
        let (resp, server_time): (MexcTicker, u64) = self.client.get_json_with_time(&url).await?;
        if resp.symbol != symbol {
            return Err(eyre::eyre!(
                "mexc symbol mismatch: expected {}, got {}",
                symbol,
                resp.symbol
            ));
        }
        let price: f64 = resp.price.parse()?;

        Ok(Some(PricePoint {
            price,
            volume: 0.0,
            source: "mexc".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "mexc"
    }
}
