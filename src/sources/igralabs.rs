use async_trait::async_trait;
use chrono::DateTime;
use eyre::{eyre, Result};
use serde::Deserialize;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

/// Igra Labs TWAP aggregator — `apis.igralabs.com/twap/prices`.
///
/// Returns per-token prices in USD and iKAS for ~18 tokens on Igra Network.
/// Sources are either "coingecko" (majors) or "zealousswap" (DEX TWAPs).
///
/// Security model: single-party feed (Igra Labs host). TLS is the only
/// authenticity barrier; if apis.igralabs.com is compromised the IGRA
/// price can be forged. The asset config should keep min_sources = 1 for
/// IGRA until a second independent source is wired in.
pub struct IgraLabs {
    client: crate::http_client::HttpClient,
}

impl IgraLabs {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[derive(Deserialize)]
struct IgraLabsTicker {
    symbol: String,
    /// TWAP price in USD.
    price_usd: f64,
    /// Per-token freshness marker, ISO 8601 in UTC.
    updated_at: String,
    /// "coingecko" or "zealousswap" — logged for observability.
    source: String,
}

type IgraLabsResponse = Vec<IgraLabsTicker>;

#[async_trait]
impl PriceSource for IgraLabs {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let wanted = match asset.sources.get(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = "https://apis.igralabs.com/twap/prices";
        let (resp, http_server_time): (IgraLabsResponse, u64) =
            self.client.get_json_with_time(url).await?;

        let ticker = resp
            .into_iter()
            .find(|t| t.symbol == wanted)
            .ok_or_else(|| eyre!("igralabs: symbol {} not in basket", wanted))?;

        // Prefer per-token `updated_at` — millisecond-precise and reflects
        // when the ZealousSwap TWAP was last sampled, not when the API
        // served this request.
        let server_time = match DateTime::parse_from_rfc3339(&ticker.updated_at) {
            Ok(dt) => dt.timestamp() as u64,
            Err(e) => {
                tracing::warn!(
                    updated_at = %ticker.updated_at,
                    error = %e,
                    "igralabs: failed to parse updated_at, using HTTP Date"
                );
                http_server_time
            }
        };

        if !ticker.price_usd.is_finite() || ticker.price_usd <= 0.0 {
            return Err(eyre!(
                "igralabs: invalid price_usd {} for {}",
                ticker.price_usd,
                wanted
            ));
        }

        tracing::debug!(
            symbol = %ticker.symbol,
            source = %ticker.source,
            price_usd = ticker.price_usd,
            "igralabs ticker"
        );

        Ok(Some(PricePoint {
            price: ticker.price_usd,
            volume: 0.0,
            source: "igralabs".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "igralabs"
    }
}
