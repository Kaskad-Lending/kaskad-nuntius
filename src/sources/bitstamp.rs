use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{now_secs, Asset, PricePoint};

pub struct Bitstamp {
    client: crate::http_client::HttpClient,
}

impl Bitstamp {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }

    fn pair_for(asset: Asset) -> Option<&'static str> {
        match asset {
            Asset::EthUsd => Some("ethusd"),
            Asset::BtcUsd => Some("btcusd"),
            Asset::UsdcUsd => Some("usdcusd"),
            // Bitstamp does not list KAS spot.
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct BitstampTicker {
    last: String,
    volume: String,
    #[serde(default)]
    timestamp: String,
}

#[async_trait]
impl PriceSource for Bitstamp {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        let pair = match Self::pair_for(asset) {
            Some(p) => p,
            None => return Ok(None),
        };

        let url = format!("https://www.bitstamp.net/api/v2/ticker/{}/", pair);
        // Bitstamp response has no pair identifier — binding is URL-only.
        // TLS ensures we hit the correct endpoint for the requested pair.
        let resp: BitstampTicker = self.client.get_json(&url).await?;

        let price: f64 = resp.last.parse()?;
        let volume: f64 = resp.volume.parse().unwrap_or(0.0);
        let server_time = resp.timestamp.parse::<u64>().ok();

        Ok(Some(PricePoint {
            price,
            volume,
            timestamp: now_secs(),
            source: "bitstamp".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "bitstamp"
    }
}
