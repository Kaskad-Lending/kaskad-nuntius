use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

pub struct Kucoin {
    client: crate::http_client::HttpClient,
}

impl Kucoin {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[derive(Deserialize)]
struct KucoinResponse {
    data: KucoinTickerData,
}

#[derive(Deserialize)]
struct KucoinTickerData {
    #[serde(default)]
    symbol: String,
    price: String,
    #[serde(default)]
    vol: String,
}

#[async_trait]
impl PriceSource for Kucoin {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let symbol = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!(
            "https://api.kucoin.com/api/v1/market/orderbook/level1?symbol={}",
            symbol
        );
        let (resp, server_time): (KucoinResponse, u64) =
            self.client.get_json_with_time(&url).await?;
        if !resp.data.symbol.is_empty() && resp.data.symbol != symbol {
            return Err(eyre::eyre!(
                "kucoin symbol mismatch: expected {}, got {}",
                symbol,
                resp.data.symbol
            ));
        }
        let price: f64 = resp.data.price.parse()?;
        // Strict parse: see audit R-9. `unwrap_or(0.0)` previously let a
        // malformed vol silently become zero-volume.
        let volume: f64 = resp
            .data
            .vol
            .parse()
            .map_err(|e| eyre::eyre!("kucoin volume parse failed: {}", e))?;

        Ok(Some(PricePoint {
            price,
            volume,
            source: "kucoin".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "kucoin"
    }
}
