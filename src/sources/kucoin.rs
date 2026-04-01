use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{now_secs, Asset, PricePoint};

pub struct Kucoin {
    client: crate::http_client::HttpClient,
}

impl Kucoin {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }

    fn symbol_for(asset: Asset) -> Option<&'static str> {
        match asset {
            Asset::EthUsd => Some("ETH-USDT"),
            Asset::BtcUsd => Some("BTC-USDT"),
            Asset::KasUsd => Some("KAS-USDT"),
            _ => None,
        }
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
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        let symbol = match Self::symbol_for(asset) {
            Some(s) => s,
            None => return Ok(None),
        };

        let url = format!(
            "https://api.kucoin.com/api/v1/market/orderbook/level1?symbol={}",
            symbol
        );
        let resp: KucoinResponse = self.client.get_json(&url).await?;
        if !resp.data.symbol.is_empty() && resp.data.symbol != symbol {
            return Err(eyre::eyre!("kucoin symbol mismatch: expected {}, got {}", symbol, resp.data.symbol));
        }
        let price: f64 = resp.data.price.parse()?;
        let volume: f64 = resp.data.vol.parse().unwrap_or(0.0);

        Ok(Some(PricePoint {
            price,
            volume,
            timestamp: now_secs(),
            source: "kucoin".into(),
        }))
    }

    fn name(&self) -> &'static str {
        "kucoin"
    }
}
