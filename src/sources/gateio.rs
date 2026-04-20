use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

pub struct GateIo {
    client: crate::http_client::HttpClient,
}

impl GateIo {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[derive(Deserialize)]
struct GateIoTicker {
    currency_pair: String,
    last: String,
    base_volume: String,
}

type GateIoResponse = Vec<GateIoTicker>;

#[async_trait]
impl PriceSource for GateIo {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let pair = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!(
            "https://api.gateio.ws/api/v4/spot/tickers?currency_pair={}",
            pair
        );
        let (resp, server_time): (GateIoResponse, u64) =
            self.client.get_json_with_time(&url).await?;
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
            source: "gateio".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "gateio"
    }
}
