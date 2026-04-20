use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

pub struct Binance {
    client: crate::http_client::HttpClient,
}

impl Binance {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[derive(Deserialize)]
struct BinanceTicker {
    symbol: String,
    price: String,
}

#[async_trait]
impl PriceSource for Binance {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let symbol = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!(
            "https://api.binance.com/api/v3/ticker/price?symbol={}",
            symbol
        );
        let (resp, server_time): (BinanceTicker, u64) =
            self.client.get_json_with_time(&url).await?;
        if resp.symbol != symbol {
            return Err(eyre::eyre!(
                "binance symbol mismatch: expected {}, got {}",
                symbol,
                resp.symbol
            ));
        }
        let price: f64 = resp.price.parse()?;

        Ok(Some(PricePoint {
            price,
            volume: 0.0,
            source: "binance".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "binance"
    }
}
