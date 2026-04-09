use async_trait::async_trait;
use eyre::Result;
use serde::Deserialize;

use super::PriceSource;
use crate::types::{now_secs, Asset, PricePoint};

pub struct CryptoCom {
    client: crate::http_client::HttpClient,
}

impl CryptoCom {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }

    fn instrument_for(asset: Asset) -> Option<&'static str> {
        match asset {
            Asset::EthUsd => Some("ETH_USDT"),
            Asset::BtcUsd => Some("BTC_USDT"),
            // Crypto.com Exchange does not list USDC_USDT (HTTP 400) and has
            // no spot KAS pair at the time of writing.
            _ => None,
        }
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
    /// Instrument name (e.g. "BTC_USDT")
    i: String,
    /// Latest trade price (string-encoded decimal)
    a: Option<String>,
    /// 24h traded volume in base asset
    v: Option<String>,
}

#[async_trait]
impl PriceSource for CryptoCom {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        let instrument = match Self::instrument_for(asset) {
            Some(i) => i,
            None => return Ok(None),
        };

        let url = format!(
            "https://api.crypto.com/exchange/v1/public/get-tickers?instrument_name={}",
            instrument
        );
        let resp: CryptoComResponse = self.client.get_json(&url).await?;

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
            timestamp: now_secs(),
            source: "crypto_com".into(),
            server_time: None,
        }))
    }

    fn name(&self) -> &'static str {
        "crypto_com"
    }
}
