use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

/// HTX (formerly Huobi Global). API host is still api.huobi.pro.
pub struct Htx {
    client: crate::http_client::HttpClient,
}

impl Htx {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[derive(Deserialize)]
struct HtxResponse {
    status: String,
    tick: Option<HtxTick>,
}

#[derive(Deserialize)]
struct HtxTick {
    close: f64,
    amount: f64,
}

#[async_trait]
impl PriceSource for Htx {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let symbol = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!(
            "https://api.huobi.pro/market/detail/merged?symbol={}",
            symbol
        );
        let (resp, server_time): (HtxResponse, u64) = self.client.get_json_with_time(&url).await?;

        if resp.status != "ok" {
            return Err(eyre::eyre!("htx non-ok status: {}", resp.status));
        }

        let tick = resp
            .tick
            .ok_or_else(|| eyre::eyre!("htx: missing tick for {}", symbol))?;

        Ok(Some(PricePoint {
            price: tick.close,
            volume: tick.amount,
            source: "htx".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "htx"
    }
}
