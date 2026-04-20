use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

pub struct Okx {
    client: crate::http_client::HttpClient,
}

impl Okx {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[derive(Deserialize)]
struct OkxResponse {
    data: Vec<OkxTicker>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OkxTicker {
    #[serde(rename = "instId")]
    inst_id: String,
    last: String,
    vol24h: String,
}

#[async_trait]
impl PriceSource for Okx {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let inst_id = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!(
            "https://www.okx.com/api/v5/market/ticker?instId={}",
            inst_id
        );
        let (resp, server_time): (OkxResponse, u64) = self.client.get_json_with_time(&url).await?;
        let ticker = resp
            .data
            .first()
            .ok_or_else(|| eyre::eyre!("no ticker data from OKX"))?;

        if ticker.inst_id != inst_id {
            return Err(eyre::eyre!(
                "okx instId mismatch: expected {}, got {}",
                inst_id,
                ticker.inst_id
            ));
        }
        let price: f64 = ticker.last.parse()?;
        let volume: f64 = ticker.vol24h.parse().unwrap_or(0.0);

        Ok(Some(PricePoint {
            price,
            volume,
            source: "okx".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "okx"
    }
}
