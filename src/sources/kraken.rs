use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;
use std::collections::HashMap;

use super::PriceSource;
use crate::types::{now_secs, Asset, PricePoint};

pub struct Kraken {
    client: crate::http_client::HttpClient,
}

impl Kraken {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }

    /// Kraken uses legacy 4-letter prefixes for some assets (X for crypto, Z for fiat).
    fn pair_for(asset: Asset) -> Option<&'static str> {
        match asset {
            Asset::EthUsd => Some("XETHZUSD"),
            Asset::BtcUsd => Some("XXBTZUSD"),
            Asset::UsdcUsd => Some("USDCUSD"),
            // KAS is not listed on Kraken at the time of writing.
            _ => None,
        }
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
    /// c[0] = last trade price, c[1] = last trade lot volume
    c: Vec<String>,
    /// v[0] = today's volume, v[1] = 24h volume
    v: Vec<String>,
}

#[async_trait]
impl PriceSource for Kraken {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        let pair = match Self::pair_for(asset) {
            Some(p) => p,
            None => return Ok(None),
        };

        let url = format!("https://api.kraken.com/0/public/Ticker?pair={}", pair);
        let resp: KrakenResponse = self.client.get_json(&url).await?;

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
        let volume: f64 = ticker.v.get(1).and_then(|v| v.parse().ok()).unwrap_or(0.0);

        // Kraken returns server time in "result" but not per-ticker.
        // Use the dedicated /0/public/Time endpoint is wasteful, so we
        // rely on the response arriving within seconds of the server clock.
        Ok(Some(PricePoint {
            price,
            volume,
            timestamp: now_secs(),
            source: "kraken".into(),
            server_time: None,
        }))
    }

    fn name(&self) -> &'static str {
        "kraken"
    }
}
