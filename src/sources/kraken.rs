use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;
use std::collections::HashMap;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

pub struct Kraken {
    client: crate::http_client::HttpClient,
}

impl Kraken {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[derive(Deserialize)]
struct KrakenResponse {
    #[serde(default)]
    error: Vec<String>,
    #[serde(default)]
    result: HashMap<String, KrakenPair>,
}

#[derive(Deserialize)]
struct KrakenPair {
    c: Vec<String>,
    v: Vec<String>,
}

#[async_trait]
impl PriceSource for Kraken {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let pair = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!("https://api.kraken.com/0/public/Ticker?pair={}", pair);
        let (resp, server_time): (KrakenResponse, u64) =
            self.client.get_json_with_time(&url).await?;

        if !resp.error.is_empty() {
            return Err(eyre::eyre!("kraken error: {:?}", resp.error));
        }

        let ticker = resp
            .result
            .get(pair)
            .ok_or_else(|| eyre::eyre!("pair {} not found in Kraken result", pair))?;

        let price: f64 = ticker
            .c
            .first()
            .ok_or_else(|| eyre::eyre!("kraken: missing last price"))?
            .parse()?;
        // Strict parse: see audit R-9. `unwrap_or(0.0)` previously let a
        // missing or malformed v[1] silently become zero-volume.
        let volume: f64 = ticker
            .v
            .get(1)
            .ok_or_else(|| eyre::eyre!("kraken: v[1] missing (24h volume)"))?
            .parse()
            .map_err(|e| eyre::eyre!("kraken volume parse failed: {}", e))?;

        Ok(Some(PricePoint {
            price,
            volume,
            source: "kraken".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "kraken"
    }
}
