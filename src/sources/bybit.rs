use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

pub struct Bybit {
    client: crate::http_client::HttpClient,
}

impl Bybit {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[derive(Deserialize)]
struct BybitResponse {
    result: BybitResult,
}

#[derive(Deserialize)]
struct BybitResult {
    list: Vec<BybitTicker>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BybitTicker {
    symbol: String,
    last_price: String,
    volume24h: String,
}

#[async_trait]
impl PriceSource for Bybit {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let symbol = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!(
            "https://api.bybit.com/v5/market/tickers?category=spot&symbol={}",
            symbol
        );
        let (resp, server_time): (BybitResponse, u64) =
            self.client.get_json_with_time(&url).await?;
        let ticker = resp
            .result
            .list
            .first()
            .ok_or_else(|| eyre::eyre!("no ticker data from Bybit"))?;

        if ticker.symbol != symbol {
            return Err(eyre::eyre!(
                "bybit symbol mismatch: expected {}, got {}",
                symbol,
                ticker.symbol
            ));
        }
        let price: f64 = ticker.last_price.parse()?;
        let volume: f64 = ticker.volume24h.parse().unwrap_or(0.0);

        Ok(Some(PricePoint {
            price,
            volume,
            source: "bybit".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "bybit"
    }
}
