use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{now_secs, Asset, PricePoint};

pub struct GateIo {
    client: crate::http_client::HttpClient,
}

impl GateIo {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }

    fn pair_for(asset: Asset) -> Option<&'static str> {
        match asset {
            Asset::EthUsd => Some("ETH_USDT"),
            Asset::BtcUsd => Some("BTC_USDT"),
            Asset::KasUsd => Some("KAS_USDT"),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct GateIoTicker {
    currency_pair: String,
    last: String,
    base_volume: String,
}

// Gate.io returns an array of tickers
type GateIoResponse = Vec<GateIoTicker>;

#[async_trait]
impl PriceSource for GateIo {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        let pair = match Self::pair_for(asset) {
            Some(s) => s,
            None => return Ok(None),
        };

        let url = format!(
            "https://api.gateio.ws/api/v4/spot/tickers?currency_pair={}",
            pair
        );
        let resp: GateIoResponse = self.client.get_json(&url).await?;
        let ticker = resp
            .first()
            .ok_or_else(|| eyre::eyre!("no ticker data from Gate.io"))?;

        if ticker.currency_pair != pair {
            return Err(eyre::eyre!(
                "gateio pair mismatch: expected {}, got {}",
                pair,
                ticker.currency_pair
            ));
        }
        let price: f64 = ticker.last.parse()?;
        let volume: f64 = ticker.base_volume.parse().unwrap_or(0.0);

        Ok(Some(PricePoint {
            price,
            volume,
            timestamp: now_secs(),
            source: "gateio".into(),
            server_time: None,
        }))
    }

    fn name(&self) -> &'static str {
        "gateio"
    }
}
