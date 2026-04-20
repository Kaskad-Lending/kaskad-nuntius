use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

pub struct CryptoCom {
    client: crate::http_client::HttpClient,
}

impl CryptoCom {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[derive(Deserialize)]
struct CryptoComResponse {
    code: i64,
    #[serde(default)]
    result: Option<CryptoComResult>,
}

#[derive(Deserialize)]
struct CryptoComResult {
    #[serde(default)]
    data: Vec<CryptoComTicker>,
}

#[derive(Deserialize)]
struct CryptoComTicker {
    i: String,
    a: Option<String>,
    v: Option<String>,
}

#[async_trait]
impl PriceSource for CryptoCom {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let instrument = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!(
            "https://api.crypto.com/exchange/v1/public/get-tickers?instrument_name={}",
            instrument
        );
        let (resp, server_time): (CryptoComResponse, u64) =
            self.client.get_json_with_time(&url).await?;

        if resp.code != 0 {
            return Err(eyre::eyre!("crypto.com non-OK code: {}", resp.code));
        }

        let ticker = resp
            .result
            .as_ref()
            .and_then(|r| r.data.first())
            .ok_or_else(|| eyre::eyre!("crypto.com: empty data for {}", instrument))?;

        if ticker.i != instrument {
            return Err(eyre::eyre!(
                "crypto.com instrument mismatch: expected {}, got {}",
                instrument,
                ticker.i
            ));
        }

        let price: f64 = ticker
            .a
            .as_deref()
            .ok_or_else(|| eyre::eyre!("crypto.com: missing last price"))?
            .parse()?;
        let volume: f64 = ticker
            .v
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);

        Ok(Some(PricePoint {
            price,
            volume,
            source: "crypto_com".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "crypto_com"
    }
}
