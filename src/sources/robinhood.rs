use async_trait::async_trait;
use eyre::{eyre, Result};
use serde::Deserialize;

use super::PriceSource;
use crate::types::{AssetConfig, PricePoint};

/// Widest bid/ask spread, in bps of the mid, at which the mid still stands
/// for the share price. A one-sided or empty book fails here instead of
/// reaching the median.
const MAX_SPREAD_BPS: f64 = 100.0;

/// Robinhood Chain token quotes. `bid`/`ask` quote the underlying share in
/// USD; `tokenBid`/`tokenAsk` carry the token's dividend multiplier and are
/// not read.
pub struct Robinhood {
    client: crate::http_client::HttpClient,
}

impl Robinhood {
    pub fn new(client: crate::http_client::HttpClient) -> Self {
        Self { client }
    }
}

#[derive(Deserialize)]
struct RobinhoodResponse {
    quotes: Vec<RobinhoodQuote>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RobinhoodQuote {
    token_symbol: String,
    bid: String,
    ask: String,
    currency: String,
    is_trading_halt: bool,
}

fn parse_positive(field: &str, raw: &str) -> Result<f64> {
    let v: f64 = raw
        .parse()
        .map_err(|e| eyre!("robinhood {field} parse failed: {e}"))?;
    if !v.is_finite() || v <= 0.0 {
        return Err(eyre!("robinhood {field} not a positive number: {raw}"));
    }
    Ok(v)
}

/// Validates a quote response for `symbol` and returns the share mid in USD.
fn extract_mid(resp: RobinhoodResponse, symbol: &str) -> Result<f64> {
    let [quote] = resp.quotes.as_slice() else {
        return Err(eyre!(
            "robinhood: expected one quote, got {}",
            resp.quotes.len()
        ));
    };
    if quote.token_symbol != symbol {
        return Err(eyre!(
            "robinhood symbol mismatch: expected {}, got {}",
            symbol,
            quote.token_symbol
        ));
    }
    if quote.currency != "USD" {
        return Err(eyre!("robinhood quote currency is {}", quote.currency));
    }
    if quote.is_trading_halt {
        return Err(eyre!("robinhood: {} is halted", symbol));
    }
    let bid = parse_positive("bid", &quote.bid)?;
    let ask = parse_positive("ask", &quote.ask)?;
    if ask < bid {
        return Err(eyre!("robinhood crossed quote: bid {bid}, ask {ask}"));
    }
    let mid = (bid + ask) / 2.0;
    let spread_bps = (ask - bid) / mid * 10_000.0;
    if spread_bps > MAX_SPREAD_BPS {
        return Err(eyre!(
            "robinhood spread {spread_bps:.0} bps exceeds {MAX_SPREAD_BPS} bps: bid {bid}, ask {ask}"
        ));
    }
    Ok(mid)
}

#[async_trait]
impl PriceSource for Robinhood {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let symbol = match asset.pair(self.name()) {
            Some(s) => s.as_str(),
            None => return Ok(None),
        };

        let url = format!("https://api.robinhood.com/rhj/prices/{}", symbol);
        let (resp, server_time): (RobinhoodResponse, u64) =
            self.client.get_json_with_time(&url).await?;
        let price = extract_mid(resp, symbol)?;

        // `dailyTradingVolume` is the underlying's session volume and resets
        // every day, so it is not a weight for this venue.
        Ok(Some(PricePoint {
            price,
            volume: 0.0,
            source: "robinhood".into(),
            server_time,
        }))
    }

    fn name(&self) -> &'static str {
        "robinhood"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Responses recorded from api.robinhood.com on 2026-11-11.
    const SGOV: &str = r#"{"quotes":[{"tokenSymbol":"SGOV","deployments":[{"contractAddress":"0x92FD66527192E3e61d4DDd13322Aa222DE86F9B5","chainId":4663,"networkName":"Robinhood Chain","transporterEnabled":false,"replicatorEnabled":true}],"bid":"100.52","ask":"100.53","currency":"USD","dailyTradingVolume":"674887","isTradingHalt":false,"generatedAt":"2026-11-11T13:28:15.404524173Z","dailyHigh":"100.53","dailyLow":"100.52","mintBurnTokenVolume":"0","mintBurnUsdVolume":"0","tokenBid":"101.471965781096888373","tokenAsk":"101.482060485213591207"}]}"#;
    const SPY: &str = r#"{"quotes":[{"tokenSymbol":"SPY","deployments":[{"contractAddress":"0x117cc2133c37B721F49dE2A7a74833232B3B4C0C","chainId":4663,"networkName":"Robinhood Chain","transporterEnabled":false,"replicatorEnabled":false}],"bid":"757.25","ask":"757.29","currency":"USD","dailyTradingVolume":"721332","isTradingHalt":false,"generatedAt":"2026-11-11T13:28:11.791185186Z","dailyHigh":"757.4","dailyLow":"751.34","mintBurnTokenVolume":"2489.22387534","mintBurnUsdVolume":"1885014.5640787218","tokenBid":"758.550948826713174272","tokenAsk":"758.591017546360673152"}]}"#;
    // Unknown symbol: HTTP 404 with this body.
    const UNKNOWN: &str =
        r#"{"code":5,"message":"no whitelisted asset with symbol \"SPYM\"","details":[]}"#;

    fn parse(body: &str, symbol: &str) -> Result<f64> {
        extract_mid(serde_json::from_str(body)?, symbol)
    }

    fn quote(symbol: &str, bid: &str, ask: &str, currency: &str, halt: bool) -> String {
        format!(
            r#"{{"quotes":[{{"tokenSymbol":"{symbol}","bid":{bid},"ask":{ask},"currency":"{currency}","isTradingHalt":{halt}}}]}}"#
        )
    }

    #[test]
    fn parses_recorded_quotes_as_share_mid() {
        assert!((parse(SGOV, "SGOV").unwrap() - 100.525).abs() < 1e-9);
        assert!((parse(SPY, "SPY").unwrap() - 757.27).abs() < 1e-9);
    }

    #[test]
    fn rejects_unknown_symbol_body() {
        assert!(parse(UNKNOWN, "SPYM").is_err());
    }

    #[test]
    fn rejects_symbol_mismatch() {
        let err = parse(SPY, "SGOV").unwrap_err();
        assert!(err.to_string().contains("symbol mismatch"), "{err}");
    }

    #[test]
    fn rejects_empty_and_multiple_quotes() {
        let err = parse(r#"{"quotes":[]}"#, "SGOV").unwrap_err();
        assert!(err.to_string().contains("expected one quote"), "{err}");
        let one = r#"{"tokenSymbol":"SGOV","bid":"100.52","ask":"100.53","currency":"USD","isTradingHalt":false}"#;
        let two = format!(r#"{{"quotes":[{one},{one}]}}"#);
        assert!(parse(&two, "SGOV").is_err());
    }

    #[test]
    fn rejects_non_usd_quote() {
        let body = quote("SGOV", r#""100.52""#, r#""100.53""#, "EUR", false);
        let err = parse(&body, "SGOV").unwrap_err();
        assert!(err.to_string().contains("currency"), "{err}");
    }

    #[test]
    fn rejects_trading_halt() {
        let body = quote("SGOV", r#""100.52""#, r#""100.53""#, "USD", true);
        let err = parse(&body, "SGOV").unwrap_err();
        assert!(err.to_string().contains("halted"), "{err}");
    }

    #[test]
    fn rejects_missing_fields() {
        for body in [
            r#"{"quotes":[{"tokenSymbol":"SGOV","ask":"100.53","currency":"USD","isTradingHalt":false}]}"#,
            r#"{"quotes":[{"tokenSymbol":"SGOV","bid":"100.52","currency":"USD","isTradingHalt":false}]}"#,
            r#"{"quotes":[{"tokenSymbol":"SGOV","bid":"100.52","ask":"100.53","isTradingHalt":false}]}"#,
            r#"{"quotes":[{"tokenSymbol":"SGOV","bid":"100.52","ask":"100.53","currency":"USD"}]}"#,
            r#"{}"#,
        ] {
            assert!(parse(body, "SGOV").is_err(), "accepted {body}");
        }
    }

    #[test]
    fn rejects_garbage_non_positive_and_non_finite_sides() {
        for bad in [
            r#""""#, r#""abc""#, "null", "100.52", r#""0""#, r#""-1""#, r#""NaN""#, r#""inf""#,
        ] {
            let as_bid = quote("SGOV", bad, r#""100.53""#, "USD", false);
            assert!(parse(&as_bid, "SGOV").is_err(), "bid {bad} accepted");
            let as_ask = quote("SGOV", r#""100.52""#, bad, "USD", false);
            assert!(parse(&as_ask, "SGOV").is_err(), "ask {bad} accepted");
        }
    }

    #[test]
    fn rejects_crossed_quote() {
        let body = quote("SGOV", r#""100.54""#, r#""100.53""#, "USD", false);
        let err = parse(&body, "SGOV").unwrap_err();
        assert!(err.to_string().contains("crossed"), "{err}");
    }

    #[test]
    fn spread_guard_boundary() {
        // 100 bps of the mid: accepted at the limit, rejected just above it.
        let at_limit = quote("X", r#""99.5""#, r#""100.5""#, "USD", false);
        assert!((parse(&at_limit, "X").unwrap() - 100.0).abs() < 1e-9);
        let above = quote("X", r#""99.49""#, r#""100.5""#, "USD", false);
        let err = parse(&above, "X").unwrap_err();
        assert!(err.to_string().contains("spread"), "{err}");
        let locked = quote("X", r#""100.5""#, r#""100.5""#, "USD", false);
        assert_eq!(parse(&locked, "X").unwrap(), 100.5);
    }
}
