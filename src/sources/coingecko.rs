use async_trait::async_trait;
use eyre::Result;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

/// One batched request per TTL serves every coingecko-backed asset. Per-asset
/// requests at FETCH_INTERVAL_SECS exceed the free tier and 429, which silently
/// strips the sample from whichever assets are polled last.
const SNAPSHOT_TTL: Duration = Duration::from_secs(30);
/// Refuse a snapshot this old: a refresh has been failing and the quote is no
/// longer representative. Dropping the source is safer than aging it.
const MAX_SNAPSHOT_AGE: Duration = Duration::from_secs(120);

// CoinGecko returns: { "bitcoin": { "usd": 12345.67 } }
type CoinGeckoResponse = HashMap<String, HashMap<String, f64>>;

struct Snapshot {
    taken_at: Instant,
    server_time: u64,
    prices: CoinGeckoResponse,
}

#[derive(Default)]
struct Cache {
    snapshot: Option<Snapshot>,
    last_attempt: Option<Instant>,
}

pub struct CoinGecko {
    client: crate::http_client::HttpClient,
    ids: Vec<String>,
    cache: Mutex<Cache>,
}

impl CoinGecko {
    /// `ids` are every coingecko id in the asset config, fetched in one call.
    pub fn new(client: crate::http_client::HttpClient, ids: Vec<String>) -> Self {
        Self {
            client,
            ids,
            cache: Mutex::new(Cache::default()),
        }
    }

    async fn quote(&self, coin_id: &str) -> Result<(f64, u64)> {
        let mut cache = self.cache.lock().await;

        let due = cache
            .last_attempt
            .is_none_or(|t| t.elapsed() >= SNAPSHOT_TTL);
        if due {
            cache.last_attempt = Some(Instant::now());
            let url = format!(
                "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd",
                self.ids.join(",")
            );
            // A failed refresh keeps the previous snapshot until MAX_SNAPSHOT_AGE
            // so one 429 does not blank every coingecko-backed asset at once.
            match self
                .client
                .get_json_with_time::<CoinGeckoResponse>(&url)
                .await
            {
                Ok((prices, server_time)) => {
                    cache.snapshot = Some(Snapshot {
                        taken_at: Instant::now(),
                        server_time,
                        prices,
                    });
                }
                Err(e) if cache.snapshot.is_some() => {
                    tracing::warn!(error = %e, "coingecko batch refresh failed; serving snapshot")
                }
                Err(e) => return Err(e),
            }
        }

        let snap = cache
            .snapshot
            .as_ref()
            .ok_or_else(|| eyre::eyre!("no CoinGecko snapshot yet"))?;
        if snap.taken_at.elapsed() >= MAX_SNAPSHOT_AGE {
            return Err(eyre::eyre!(
                "CoinGecko snapshot older than {}s",
                MAX_SNAPSHOT_AGE.as_secs()
            ));
        }
        let price = snap
            .prices
            .get(coin_id)
            .and_then(|m| m.get("usd"))
            .copied()
            .ok_or_else(|| eyre::eyre!("no price from CoinGecko for {}", coin_id))?;
        Ok((price, snap.server_time))
    }
}

#[async_trait]
impl PriceSource for CoinGecko {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let coin_id = match asset.pair(self.name()) {
            Some(s) => s.clone(),
            None => return Ok(None),
        };

        let (price, server_time) = self.quote(&coin_id).await?;

        Ok(Some(PricePoint {
            price,
            volume: 0.0,
            source: "coingecko".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "coingecko"
    }
}
