use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{now_secs, Asset, PricePoint};

pub struct Okx {
    client: crate::http_client::HttpClient,
}

impl Okx {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }

    fn inst_id_for(asset: Asset) -> Option<&'static str> {
        match asset {
            Asset::EthUsd => Some("ETH-USDT"),
            Asset::BtcUsd => Some("BTC-USDT"),
            // OKX does not list KAS-USDT (as of 2026-04)
            Asset::UsdcUsd => Some("USDC-USDT"),
            _ => None,
        }
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
    /// Server timestamp in milliseconds
    ts: String,
}

#[async_trait]
impl PriceSource for Okx {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        let inst_id = match Self::inst_id_for(asset) {
            Some(s) => s,
            None => return Ok(None),
        };

        let url = format!(
            "https://www.okx.com/api/v5/market/ticker?instId={}",
            inst_id
        );
        let resp: OkxResponse = self.client.get_json(&url).await?;
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

        let server_time = ticker.ts.parse::<u64>().ok().map(|ms| ms / 1000);

        Ok(Some(PricePoint {
            price,
            volume,
            timestamp: now_secs(),
            source: "okx".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "okx"
    }
}
