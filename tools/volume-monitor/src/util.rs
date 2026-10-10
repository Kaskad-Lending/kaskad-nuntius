//! WS connect helpers — trimmed copy of the oracle's `collectors/util.rs`
//! (no SOCKS proxy: this tool runs outside the enclave) so the tool dials
//! venues exactly the way the collectors do: same timeout, same size caps,
//! same optional Origin header.

use eyre::{Result, WrapErr};
use std::time::Duration;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use url::Url;

pub type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MiB
const MAX_FRAME_SIZE: usize = 256 * 1024; //   256 KiB

/// Max silence on a venue socket before the session is declared half-dead
/// and reconnected. Every venue emits SOMETHING at least every ~60s
/// (server pings, pong replies, trade flow), so 120s of nothing means
/// a dead TCP path that would otherwise undercount silently forever.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

pub async fn ws_connect(url_str: &str) -> Result<WsStream> {
    ws_connect_with_origin(url_str, None).await
}

/// Some venues (CoinW) sit behind a WAF that 403s handshakes without a
/// browser `Origin` — same workaround as the collector layer.
pub async fn ws_connect_with_origin(url_str: &str, origin: Option<&str>) -> Result<WsStream> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http;

    let url = Url::parse(url_str).wrap_err_with(|| format!("parse URL {url_str}"))?;
    let mut request = url
        .as_str()
        .into_client_request()
        .wrap_err_with(|| format!("build WS request {url_str}"))?;
    if let Some(o) = origin {
        request.headers_mut().insert(
            http::header::ORIGIN,
            http::HeaderValue::from_str(o).wrap_err("invalid Origin header value")?,
        );
    }
    let config = WebSocketConfig {
        max_message_size: Some(MAX_MESSAGE_SIZE),
        max_frame_size: Some(MAX_FRAME_SIZE),
        accept_unmasked_frames: false,
        ..Default::default()
    };
    let fut = tokio_tungstenite::connect_async_with_config(request, Some(config), false);
    let (ws, _) = tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .wrap_err_with(|| format!("WS connect timeout: {url_str}"))?
        .wrap_err_with(|| format!("WS connect failed: {url_str}"))?;
    Ok(ws)
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn parse_f64(v: &serde_json::Value) -> Option<f64> {
    if let Some(n) = v.as_f64() {
        return Some(n);
    }
    v.as_str().and_then(|s| s.parse().ok())
}

pub fn parse_i64(v: &serde_json::Value) -> Option<i64> {
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    v.as_str().and_then(|s| s.parse().ok())
}

pub fn parse_u64(v: &serde_json::Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    v.as_str().and_then(|s| s.parse().ok())
}

/// Gunzip a binary frame to text (Bitrue-style venues gzip every frame).
pub fn gunzip(bin: &[u8]) -> Option<String> {
    use std::io::Read;
    let mut d = flate2::read::GzDecoder::new(bin);
    let mut s = String::new();
    d.read_to_string(&mut s).ok()?;
    Some(s)
}

/// `"TAO_USDT"` / `"TAO-USDT"` / `"tao_usdt"` / `"TAOUSDT"` → `("TAO", "USDT")`.
pub fn canon_pair(pair: &str) -> (String, String) {
    let flat: String = pair
        .to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    for quote in ["USDT", "USDC", "USD"] {
        if flat.len() > quote.len() {
            if let Some(base) = flat.strip_suffix(quote) {
                return (base.to_string(), quote.to_string());
            }
        }
    }
    (flat, String::new())
}

#[cfg(test)]
mod tests {
    use super::canon_pair;

    fn assert_pair(pair: &str, base: &str, quote: &str) {
        let (b, q) = canon_pair(pair);
        assert_eq!((b.as_str(), q.as_str()), (base, quote), "pair {pair}");
    }

    #[test]
    fn canon_pair_separator_and_case_variants() {
        assert_pair("TAOUSDT", "TAO", "USDT");
        assert_pair("TAO-USDT", "TAO", "USDT");
        assert_pair("TAO_USDT", "TAO", "USDT");
        assert_pair("tao_usdt", "TAO", "USDT");
        assert_pair("KAS_USDT", "KAS", "USDT");
        assert_pair("kasusdt", "KAS", "USDT");
        assert_pair("KAS-USDT", "KAS", "USDT");
    }

    #[test]
    fn canon_pair_quote_suffix_priority() {
        // Longest suffix wins: USDCUSDT is USDC-based, USDT-quoted.
        assert_pair("USDCUSDT", "USDC", "USDT");
        assert_pair("USDC-USDT", "USDC", "USDT");
        assert_pair("TAO_USDC", "TAO", "USDC");
        assert_pair("TAOUSD", "TAO", "USD");
    }

    #[test]
    fn canon_pair_no_recognized_quote() {
        // No quote suffix: the whole flattened symbol is the base.
        assert_pair("KAS", "KAS", "");
        assert_pair("TAOBTC", "TAOBTC", "");
        // A symbol equal to a quote is kept whole — the split requires
        // flat.len() > quote.len().
        assert_pair("USDT", "USDT", "");
        assert_pair("usdc", "USDC", "");
    }
}
