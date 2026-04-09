use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{now_secs, Asset, PricePoint};

pub struct Binance {
    client: crate::http_client::HttpClient,
}

impl Binance {
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
struct BinanceTicker {
    symbol: String,
    price: String,
}

#[async_trait]
impl PriceSource for Binance {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        let symbol = match Self::symbol_for(asset) {
            Some(s) => s,
            None => return Ok(None),
        };

        let url = format!(
            "https://api.binance.com/api/v3/ticker/price?symbol={}",
            symbol
        );
        let resp: BinanceTicker = self.client.get_json(&url).await?;
        if resp.symbol != symbol {
            return Err(eyre::eyre!(
                "binance symbol mismatch: expected {}, got {}",
                symbol,
                resp.symbol
            ));
        }
        let price: f64 = resp.price.parse()?;

        Ok(Some(PricePoint {
            price,
            volume: 0.0,
            timestamp: now_secs(),
            source: "binance".into(),
            server_time: None, // ticker/price endpoint has no server timestamp
        }))
    }

    fn name(&self) -> &'static str {
        "binance"
    }
}
