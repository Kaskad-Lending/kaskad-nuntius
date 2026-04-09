use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{now_secs, Asset, PricePoint};

/// HTX (formerly Huobi Global). API host is still api.huobi.pro.
pub struct Htx {
    client: crate::http_client::HttpClient,
}

impl Htx {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }

    fn symbol_for(asset: Asset) -> Option<&'static str> {
        match asset {
            Asset::EthUsd => Some("ethusdt"),
            Asset::BtcUsd => Some("btcusdt"),
            Asset::KasUsd => Some("kasusdt"),
            Asset::UsdcUsd => Some("usdcusdt"),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct HtxResponse {
    status: String,
    #[serde(default)]
    ts: u64,
    tick: Option<HtxTick>,
}

#[derive(Deserialize)]
struct HtxTick {
    /// Last close price
    close: f64,
    /// 24h traded volume in base asset
    amount: f64,
}

#[async_trait]
impl PriceSource for Htx {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        let symbol = match Self::symbol_for(asset) {
            Some(s) => s,
            None => return Ok(None),
        };

        let url = format!(
            "https://api.huobi.pro/market/detail/merged?symbol={}",
            symbol
        );
        let resp: HtxResponse = self.client.get_json(&url).await?;

        if resp.status != "ok" {
            return Err(eyre::eyre!("htx non-ok status: {}", resp.status));
        }

        let tick = resp
            .tick
            .ok_or_else(|| eyre::eyre!("htx: missing tick for {}", symbol))?;

        let server_time = if resp.ts > 0 {
            Some(resp.ts / 1000)
        } else {
            None
        };

        Ok(Some(PricePoint {
            price: tick.close,
            volume: tick.amount,
            timestamp: now_secs(),
            source: "htx".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "htx"
    }
}
