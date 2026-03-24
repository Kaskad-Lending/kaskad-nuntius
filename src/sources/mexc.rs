use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{now_secs, Asset, PricePoint};

pub struct Mexc {
    client: crate::http_client::HttpClient,
}

impl Mexc {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }

    fn symbol_for(asset: Asset) -> Option<&'static str> {
        match asset {
            Asset::EthUsd => Some("ETHUSDT"),
            Asset::BtcUsd => Some("BTCUSDT"),
            Asset::KasUsd => Some("KASUSDT"),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct MexcTicker {
    symbol: String,
    price: String,
}

#[async_trait]
impl PriceSource for Mexc {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        let symbol = match Self::symbol_for(asset) {
            Some(s) => s,
            None => return Ok(None),
        };

        let url = format!("https://api.mexc.com/api/v3/ticker/price?symbol={}", symbol);
        let resp: MexcTicker = self.client.get_json(&url).await?;
        let price: f64 = resp.price.parse()?;

        Ok(Some(PricePoint {
            price,
            volume: 0.0,
            timestamp: now_secs(),
            source: "mexc".into(),
        }))
    }

    fn name(&self) -> &'static str {
        "mexc"
    }
}
