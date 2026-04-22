use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

pub struct Bitget {
    client: crate::http_client::HttpClient,
}

impl Bitget {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[derive(Deserialize)]
struct BitgetResponse {
    code: String,
    #[serde(default)]
    data: Vec<BitgetTicker>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitgetTicker {
    symbol: String,
    last_pr: String,
    base_volume: String,
}

#[async_trait]
impl PriceSource for Bitget {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let symbol = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!(
            "https://api.bitget.com/api/v2/spot/market/tickers?symbol={}",
            symbol
        );
        let (resp, server_time): (BitgetResponse, u64) =
            self.client.get_json_with_time(&url).await?;

        if resp.code != "00000" {
            return Err(eyre::eyre!("bitget non-OK code: {}", resp.code));
        }

        let ticker = resp
            .data
            .first()
            .ok_or_else(|| eyre::eyre!("no ticker data from Bitget"))?;

        if ticker.symbol != symbol {
            return Err(eyre::eyre!(
                "bitget symbol mismatch: expected {}, got {}",
                symbol,
                ticker.symbol
            ));
        }

        let price: f64 = ticker.last_pr.parse()?;
        // Strict parse: see audit R-9. `unwrap_or(0.0)` previously let a
        // malformed base_volume silently become zero-volume.
        let volume: f64 = ticker
            .base_volume
            .parse()
            .map_err(|e| eyre::eyre!("bitget volume parse failed: {}", e))?;

        Ok(Some(PricePoint {
            price,
            volume,
            source: "bitget".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "bitget"
    }
}
