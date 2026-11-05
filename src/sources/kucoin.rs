use async_trait::async_trait;
use eyre::{eyre, Result};
use serde::Deserialize;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

const SUCCESS_CODE: &str = "200000";

pub struct Kucoin {
    client: crate::http_client::HttpClient,
}

impl Kucoin {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[derive(Deserialize)]
struct KucoinResponse {
    code: String,
    data: Option<KucoinStats>,
}

/// `/api/v1/market/stats` payload. Every field is null for an unknown pair.
#[derive(Deserialize)]
struct KucoinStats {
    symbol: Option<String>,
    last: Option<String>,
    vol: Option<String>,
}

fn parse_positive(field: &str, raw: Option<&str>) -> Result<f64> {
    let raw = raw.ok_or_else(|| eyre!("kucoin {field} missing"))?;
    let v: f64 = raw
        .parse()
        .map_err(|e| eyre!("kucoin {field} parse failed: {e}"))?;
    if !v.is_finite() || v <= 0.0 {
        return Err(eyre!("kucoin {field} not a positive number: {raw}"));
    }
    Ok(v)
}

/// Validates a stats response for `symbol` and returns `(last price, 24h base volume)`.
fn extract_price_volume(resp: KucoinResponse, symbol: &str) -> Result<(f64, f64)> {
    if resp.code != SUCCESS_CODE {
        return Err(eyre!("kucoin error code {}", resp.code));
    }
    let data = resp.data.ok_or_else(|| eyre!("kucoin data missing"))?;
    match data.symbol.as_deref() {
        Some(s) if s == symbol => {}
        Some(s) => {
            return Err(eyre!(
                "kucoin symbol mismatch: expected {}, got {}",
                symbol,
                s
            ))
        }
        None => return Err(eyre!("kucoin symbol missing")),
    }
    let price = parse_positive("last", data.last.as_deref())?;
    let volume = parse_positive("vol", data.vol.as_deref())?;
    Ok((price, volume))
}

#[async_trait]
impl PriceSource for Kucoin {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let symbol = match asset.pair(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!(
            "https://api.kucoin.com/api/v1/market/stats?symbol={}",
            symbol
        );
        let (resp, server_time): (KucoinResponse, u64) =
            self.client.get_json_with_time(&url).await?;
        let (price, volume) = extract_price_volume(resp, symbol)?;

        Ok(Some(PricePoint {
            price,
            volume,
            source: "kucoin".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "kucoin"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Responses recorded from api.kucoin.com on 2026-11-05.
    const HOODX_STATS: &str = r#"{"code":"200000","data":{"time":1793888933221,"symbol":"HOODX-USDT","buy":"85.87","sell":"85.91","changeRate":"0.0193","changePrice":"1.63","high":"88.83","low":"83.73","vol":"6402.408","volValue":"558025.49242","last":"85.88","averagePrice":"84.97248947","takerFeeRate":"0.001","makerFeeRate":"0.001","takerCoefficient":"2","makerCoefficient":"2"}}"#;
    const TSLAX_STATS: &str = r#"{"code":"200000","data":{"time":1793888934017,"symbol":"TSLAX-USDT","buy":"373.39","sell":"373.6","changeRate":"-0.017","changePrice":"-6.48","high":"392.17","low":"372.68","vol":"1838.592","volValue":"701964.18972","last":"373.49","averagePrice":"387.7658831","takerFeeRate":"0.001","makerFeeRate":"0.001","takerCoefficient":"2","makerCoefficient":"2"}}"#;
    const BTC_STATS: &str = r#"{"code":"200000","data":{"time":1793888934071,"symbol":"BTC-USDT","buy":"79489.9","sell":"79490","changeRate":"0.0147","changePrice":"1154.8","high":"81199.2","low":"78318.7","vol":"5667.96129840135441166284","volValue":"454981711.47016570053742154564","last":"79489.7","averagePrice":"78244.60572138","takerFeeRate":"0.001","makerFeeRate":"0.001","takerCoefficient":"1","makerCoefficient":"1"}}"#;
    // Unknown pair: HTTP 200 with every field null.
    const UNKNOWN_STATS: &str = r#"{"code":"200000","data":{"time":1793888936513,"symbol":"NOPE-USDT","buy":null,"sell":null,"changeRate":null,"changePrice":null,"high":null,"low":null,"vol":null,"volValue":null,"last":null,"averagePrice":null,"takerFeeRate":null,"makerFeeRate":null,"takerCoefficient":null,"makerCoefficient":null}}"#;
    // Previous endpoint: carries neither `symbol`, `last` nor `vol`.
    const LEVEL1: &str = r#"{"code":"200000","data":{"time":1793888929058,"sequence":"82564310","price":"373.49","size":"0.135","bestBid":"373.39","bestBidSize":"0.022","bestAsk":"373.6","bestAskSize":"0.016"}}"#;

    fn parse(body: &str, symbol: &str) -> Result<(f64, f64)> {
        extract_price_volume(serde_json::from_str(body)?, symbol)
    }

    fn stats(symbol: &str, last: &str, vol: &str) -> String {
        format!(r#"{{"code":"200000","data":{{"symbol":"{symbol}","last":{last},"vol":{vol}}}}}"#)
    }

    #[test]
    fn parses_recorded_stats() {
        assert_eq!(parse(HOODX_STATS, "HOODX-USDT").unwrap(), (85.88, 6402.408));
        assert_eq!(
            parse(TSLAX_STATS, "TSLAX-USDT").unwrap(),
            (373.49, 1838.592)
        );
        let (price, volume) = parse(BTC_STATS, "BTC-USDT").unwrap();
        assert_eq!(price, 79489.7);
        assert!((volume - 5667.961298401354).abs() < 1e-9);
    }

    #[test]
    fn rejects_unknown_pair_with_null_fields() {
        let err = parse(UNKNOWN_STATS, "NOPE-USDT").unwrap_err();
        assert!(err.to_string().contains("last missing"), "{err}");
    }

    #[test]
    fn rejects_level1_shape() {
        assert!(parse(LEVEL1, "TSLAX-USDT").is_err());
    }

    #[test]
    fn rejects_symbol_mismatch() {
        let err = parse(TSLAX_STATS, "HOODX-USDT").unwrap_err();
        assert!(err.to_string().contains("symbol mismatch"), "{err}");
    }

    #[test]
    fn rejects_missing_symbol() {
        let body = r#"{"code":"200000","data":{"last":"1.5","vol":"10"}}"#;
        assert!(parse(body, "X-USDT").is_err());
    }

    #[test]
    fn rejects_error_code_and_null_data() {
        let err = parse(r#"{"code":"400100","data":null}"#, "X-USDT").unwrap_err();
        assert!(err.to_string().contains("error code"), "{err}");
        let err = parse(r#"{"code":"200000","data":null}"#, "X-USDT").unwrap_err();
        assert!(err.to_string().contains("data missing"), "{err}");
        assert!(parse(r#"{"data":{}}"#, "X-USDT").is_err());
    }

    #[test]
    fn rejects_missing_or_garbage_vol() {
        let missing = r#"{"code":"200000","data":{"symbol":"X-USDT","last":"1.5"}}"#;
        assert!(parse(missing, "X-USDT").is_err());
        for vol in [r#""""#, r#""abc""#, "null", "12", r#""1,5""#] {
            let body = stats("X-USDT", r#""1.5""#, vol);
            assert!(parse(&body, "X-USDT").is_err(), "vol {vol} accepted");
        }
    }

    #[test]
    fn rejects_missing_or_garbage_last() {
        for last in [r#""""#, r#""abc""#, "null", "1.5"] {
            let body = stats("X-USDT", last, r#""10""#);
            assert!(parse(&body, "X-USDT").is_err(), "last {last} accepted");
        }
    }

    #[test]
    fn rejects_non_positive_and_non_finite() {
        for bad in ["0", "0.0", "-1", "-0.5", "NaN", "inf", "-inf"] {
            let q = format!(r#""{bad}""#);
            assert!(
                parse(&stats("X-USDT", &q, r#""10""#), "X-USDT").is_err(),
                "last {bad} accepted"
            );
            assert!(
                parse(&stats("X-USDT", r#""1.5""#, &q), "X-USDT").is_err(),
                "vol {bad} accepted"
            );
        }
    }
}
