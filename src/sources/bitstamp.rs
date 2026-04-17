use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

pub struct Bitstamp {
    client: crate::http_client::HttpClient,
}

impl Bitstamp {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[derive(Deserialize)]
struct BitstampTicker {
    last: String,
    volume: String,
}

#[async_trait]
impl PriceSource for Bitstamp {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let pair = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!("https://www.bitstamp.net/api/v2/ticker/{}/", pair);
        // Bitstamp response has no pair identifier — binding is URL-only.
        let (resp, server_time): (BitstampTicker, u64) =
            self.client.get_json_with_time(&url).await?;

        let price: f64 = resp.last.parse()?;
        let volume: f64 = resp.volume.parse().unwrap_or(0.0);

        Ok(Some(PricePoint {
            price,
            volume,
            source: "bitstamp".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "bitstamp"
    }
}
