use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{now_secs, Asset, PricePoint};

pub struct Bitget {
    client: crate::http_client::HttpClient,
}

impl Bitget {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }

    fn symbol_for(asset: Asset) -> Option<&'static str> {
        match asset {
            Asset::EthUsd => Some("ETHUSDT"),
            Asset::BtcUsd => Some("BTCUSDT"),
            Asset::KasUsd => Some("KASUSDT"),
            Asset::UsdcUsd => Some("USDCUSDT"),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct BitgetResponse {
    code: String,
    #[serde(default)]
    data: Vec<BitgetTicker>,
    /// Server timestamp in milliseconds
    #[serde(default, rename = "requestTime")]
    request_time: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitgetTicker {
    symbol: String,
    /// Last traded price
    last_pr: String,
    /// 24h base-asset volume
    base_volume: String,
}

#[async_trait]
impl PriceSource for Bitget {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        let symbol = match Self::symbol_for(asset) {
            Some(s) => s,
            None => return Ok(None),
        };

        let url = format!(
            "https://api.bitget.com/api/v2/spot/market/tickers?symbol={}",
            symbol
        );
        let resp: BitgetResponse = self.client.get_json(&url).await?;

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
        let volume: f64 = ticker.base_volume.parse().unwrap_or(0.0);

        let server_time = resp.request_time.map(|ms| ms / 1000);

        Ok(Some(PricePoint {
            price,
            volume,
            timestamp: now_secs(),
            source: "bitget".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "bitget"
    }
}
