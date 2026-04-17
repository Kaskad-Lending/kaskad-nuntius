use async_trait::async_trait;
use eyre::Result;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

pub struct Bitfinex {
    client: crate::http_client::HttpClient,
}

impl Bitfinex {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl PriceSource for Bitfinex {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let pair = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!("https://api-pub.bitfinex.com/v2/ticker/{}", pair);
        let (arr, server_time): (Vec<f64>, u64) =
            self.client.get_json_with_time(&url).await?;

        if arr.len() < 8 {
            return Err(eyre::eyre!(
                "bitfinex unexpected ticker length: {} for {}",
                arr.len(),
                pair
            ));
        }

        let price = arr[6];
        let volume = arr[7];

        if !price.is_finite() || price <= 0.0 {
            return Err(eyre::eyre!(
                "bitfinex returned invalid price {} for {}",
                price,
                pair
            ));
        }

        Ok(Some(PricePoint {
            price,
            volume,
            source: "bitfinex".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "bitfinex"
    }
}
