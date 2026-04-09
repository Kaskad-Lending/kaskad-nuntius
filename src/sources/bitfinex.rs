use async_trait::async_trait;
use eyre::Result;

use super::PriceSource;
use crate::types::{now_secs, Asset, PricePoint};

pub struct Bitfinex {
    client: crate::http_client::HttpClient,
}

impl Bitfinex {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }

    fn pair_for(asset: Asset) -> Option<&'static str> {
        match asset {
            Asset::EthUsd => Some("tETHUSD"),
            Asset::BtcUsd => Some("tBTCUSD"),
            // Bitfinex lists UDC/USD (their USDC ticker) and no spot KAS pair.
            Asset::UsdcUsd => Some("tUDCUSD"),
            _ => None,
        }
    }
}

#[async_trait]
impl PriceSource for Bitfinex {
    async fn fetch_price(&self, asset: Asset) -> Result<Option<PricePoint>> {
        let pair = match Self::pair_for(asset) {
            Some(p) => p,
            None => return Ok(None),
        };

        // Bitfinex public v2 ticker returns a flat array:
        // [ BID, BID_SIZE, ASK, ASK_SIZE, DAILY_CHANGE, DAILY_CHANGE_RELATIVE,
        //   LAST_PRICE, VOLUME, HIGH, LOW ]
        let url = format!("https://api-pub.bitfinex.com/v2/ticker/{}", pair);
        let arr: Vec<f64> = self.client.get_json(&url).await?;

        if arr.len() < 8 {
            return Err(eyre::eyre!(
                "bitfinex unexpected ticker length: {} for {}",
                arr.len(),
                pair
            ));
        }

        let price = arr[6];
        let volume = arr[7];

        // Bitfinex array format has no pair identifier — the URL path is the
        // only binding.  Sanity-check that price is positive and finite.
        if !price.is_finite() || price <= 0.0 {
            return Err(eyre::eyre!(
                "bitfinex returned invalid price {} for {}",
                price,
                pair
            ));
        }

        Ok(Some(PricePoint {
            price,
            volume,
            timestamp: now_secs(),
            source: "bitfinex".into(),
            server_time: None,
        }))
    }

    fn name(&self) -> &'static str {
        "bitfinex"
    }
}
