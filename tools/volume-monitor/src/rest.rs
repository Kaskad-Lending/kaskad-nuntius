//! Per-venue REST 24h ticker fetchers — used only to compare the venue's
//! *reported* 24h volume against volume observed on the WS trade stream.
//! Endpoints verified live 2026-07-19.

use eyre::{eyre, Result};
use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::OnceCell;

use crate::util::parse_f64;

#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct Reported {
    /// 24h volume in base asset units, if the venue reports it.
    pub base: Option<f64>,
    /// 24h volume in quote (USDT) units, if the venue reports it.
    pub quote: Option<f64>,
}

/// Shared client: report time fires ~40 requests concurrently, so one
/// client keeps connection reuse instead of a TLS handshake per request.
fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("volume-monitor/0.1")
            .build()
            .expect("reqwest client")
    })
}

async fn get_json(url: &str) -> Result<Value> {
    Ok(client()
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

/// Fetch-once cache for venues that only expose an all-markets ticker map
/// (whitebit, coinw): with join_all's unbounded concurrency a per-pair
/// fetch would download the identical full map once per pair. Concurrent
/// callers share one in-flight request; a failed fetch is not cached.
async fn cached_map(cell: &'static OnceCell<Value>, url: &str) -> Result<&'static Value> {
    cell.get_or_try_init(|| get_json(url)).await
}

/// Reported 24h volume for `(venue, venue-native pair)`.
pub async fn reported(venue: &str, pair: &str) -> Result<Reported> {
    match venue {
        "binance" => {
            let v = get_json(&format!(
                "https://api.binance.com/api/v3/ticker/24hr?symbol={pair}"
            ))
            .await?;
            Ok(Reported {
                base: v.get("volume").and_then(parse_f64),
                quote: v.get("quoteVolume").and_then(parse_f64),
            })
        }
        "bitmart" => {
            let v = get_json(&format!(
                "https://api-cloud.bitmart.com/spot/quotation/v3/ticker?symbol={pair}"
            ))
            .await?;
            let d = v.get("data").ok_or_else(|| eyre!("no data"))?;
            Ok(Reported {
                base: d.get("v_24h").and_then(parse_f64),
                quote: d.get("qv_24h").and_then(parse_f64),
            })
        }
        "bitrue" => {
            let v = get_json(&format!(
                "https://openapi.bitrue.com/api/v1/ticker/24hr?symbol={pair}"
            ))
            .await?;
            let d = v.get(0).ok_or_else(|| eyre!("empty array"))?;
            Ok(Reported {
                base: d.get("volume").and_then(parse_f64),
                quote: d.get("quoteVolume").and_then(parse_f64),
            })
        }
        "coinw" => {
            static MAP: OnceCell<Value> = OnceCell::const_new();
            let v = cached_map(
                &MAP,
                "https://api.coinw.com/api/v1/public?command=returnTicker",
            )
            .await?;
            let d = v
                .get("data")
                .and_then(|d| d.get(pair.to_uppercase()))
                .ok_or_else(|| eyre!("pair not in returnTicker"))?;
            // CoinW's `baseVolume` is denominated in the QUOTE currency
            // (USDT) despite the name — verified by comparing magnitudes
            // across pairs.
            Ok(Reported {
                base: None,
                quote: d.get("baseVolume").and_then(parse_f64),
            })
        }
        "gate" => {
            let v = get_json(&format!(
                "https://api.gateio.ws/api/v4/spot/tickers?currency_pair={pair}"
            ))
            .await?;
            let d = v.get(0).ok_or_else(|| eyre!("empty array"))?;
            Ok(Reported {
                base: d.get("base_volume").and_then(parse_f64),
                quote: d.get("quote_volume").and_then(parse_f64),
            })
        }
        "kucoin" => {
            let v = get_json(&format!(
                "https://api.kucoin.com/api/v1/market/stats?symbol={pair}"
            ))
            .await?;
            let d = v.get("data").ok_or_else(|| eyre!("no data"))?;
            Ok(Reported {
                base: d.get("vol").and_then(parse_f64),
                quote: d.get("volValue").and_then(parse_f64),
            })
        }
        "lbank" => {
            let v = get_json(&format!(
                "https://api.lbkex.com/v2/ticker/24hr.do?symbol={}",
                pair.to_lowercase()
            ))
            .await?;
            let t = v
                .get("data")
                .and_then(|d| d.get(0))
                .and_then(|d| d.get("ticker"))
                .ok_or_else(|| eyre!("no ticker"))?;
            Ok(Reported {
                base: t.get("vol").and_then(parse_f64),
                quote: t.get("turnover").and_then(parse_f64),
            })
        }
        "mexc" => {
            let v = get_json(&format!(
                "https://api.mexc.com/api/v3/ticker/24hr?symbol={pair}"
            ))
            .await?;
            Ok(Reported {
                base: v.get("volume").and_then(parse_f64),
                quote: v.get("quoteVolume").and_then(parse_f64),
            })
        }
        "whitebit" => {
            static MAP: OnceCell<Value> = OnceCell::const_new();
            let v = cached_map(&MAP, "https://whitebit.com/api/v4/public/ticker").await?;
            let d = v
                .get(pair.to_uppercase())
                .ok_or_else(|| eyre!("pair not in ticker map"))?;
            Ok(Reported {
                base: d.get("base_volume").and_then(parse_f64),
                quote: d.get("quote_volume").and_then(parse_f64),
            })
        }
        "xt" => {
            let v = get_json(&format!(
                "https://sapi.xt.com/v4/public/ticker/24h?symbol={}",
                pair.to_lowercase()
            ))
            .await?;
            let d = v
                .get("result")
                .and_then(|r| r.get(0))
                .ok_or_else(|| eyre!("empty result"))?;
            // XT: `q` = 24h quantity (base), `v` = 24h volume (quote).
            Ok(Reported {
                base: d.get("q").and_then(parse_f64),
                quote: d.get("v").and_then(parse_f64),
            })
        }
        other => Err(eyre!("no REST ticker fetcher for {other}")),
    }
}
