//! WS connect helpers. When `WS_PROXY` is set we dial the SOCKS5 proxy
//! first (Nitro Enclave has no routable network); otherwise behave like
//! the upstream oracle-light helpers.

use eyre::{eyre, Result, WrapErr};
use futures::SinkExt;
use std::time::Duration;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use url::Url;

pub type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

// Tight caps vs the tungstenite defaults (64 MiB/16 MiB).
const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MiB
const MAX_FRAME_SIZE: usize = 256 * 1024; //   256 KiB

fn default_port_for_scheme(scheme: &str) -> Option<u16> {
    match scheme {
        "wss" => Some(443),
        "ws" => Some(80),
        _ => None,
    }
}

/// `host:port` from a WS URL.
pub fn ws_endpoint(url: &Url) -> Result<(String, u16)> {
    let host = url
        .host_str()
        .ok_or_else(|| eyre!("WS URL has no host: {url}"))?
        .to_string();
    let port = url
        .port()
        .or_else(|| default_port_for_scheme(url.scheme()))
        .ok_or_else(|| eyre!("WS URL has no port and unknown scheme: {url}"))?;
    Ok((host, port))
}

/// Optional SOCKS5 proxy address for the WS TCP handshake. Reads `WS_PROXY`.
/// Accepts either `socks5://host:port`, `host:port`, or empty/unset.
/// Returns `None` if unset -> caller should fall back to direct connect.
fn ws_proxy_target() -> Option<String> {
    let raw = std::env::var("WS_PROXY").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Strip optional socks5:// scheme prefix.
    let stripped = trimmed
        .strip_prefix("socks5h://")
        .or_else(|| trimmed.strip_prefix("socks5://"))
        .unwrap_or(trimmed);
    Some(stripped.to_string())
}

/// Connect to a WebSocket URL with a 10s timeout and conservative size caps.
///
/// If `WS_PROXY` is set, the TCP leg is dialled through that SOCKS5 proxy
/// (the only outbound path available inside an AWS Nitro Enclave) and the
/// TLS handshake is layered on top via `client_async_tls`.
pub async fn ws_connect(url_str: &str) -> Result<WsStream> {
    let url = Url::parse(url_str).wrap_err_with(|| format!("parse URL {url_str}"))?;
    let config = WebSocketConfig {
        max_message_size: Some(MAX_MESSAGE_SIZE),
        max_frame_size: Some(MAX_FRAME_SIZE),
        accept_unmasked_frames: false,
        ..Default::default()
    };

    if let Some(proxy) = ws_proxy_target() {
        let (host, port) = ws_endpoint(&url)?;
        let target = format!("{host}:{port}");
        let proxy_for_connect = proxy.clone();
        let target_for_connect = target.clone();
        let config_for_connect = config;
        let connect = async move {
            let tcp = tokio_socks::tcp::Socks5Stream::connect(
                proxy_for_connect.as_str(),
                target_for_connect.as_str(),
            )
            .await
            .wrap_err_with(|| {
                format!("SOCKS5 connect {proxy_for_connect} -> {target_for_connect}")
            })?;
            let tcp_inner: tokio::net::TcpStream = tcp.into_inner();
            // Use client_async_tls_with_config so the proxied path inherits the
            // same 1 MiB message / 256 KiB frame caps as the direct path.
            let (ws, _) = tokio_tungstenite::client_async_tls_with_config(
                url.as_str(),
                tcp_inner,
                Some(config_for_connect),
                None,
            )
            .await
            .wrap_err_with(|| format!("WS TLS handshake via proxy {proxy_for_connect}"))?;
            Ok::<WsStream, eyre::Report>(ws)
        };
        let ws = tokio::time::timeout(Duration::from_secs(10), connect)
            .await
            .wrap_err_with(|| format!("WS connect timeout (proxy): {url_str}"))??;
        return Ok(ws);
    }

    let fut = tokio_tungstenite::connect_async_with_config(url.as_str(), Some(config), false);
    let (ws, _) = tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .wrap_err_with(|| format!("WS connect timeout: {url_str}"))?
        .wrap_err_with(|| format!("WS connect failed: {url_str}"))?;
    Ok(ws)
}

/// Send a JSON text frame.
pub async fn send_json<T: serde::Serialize>(ws: &mut WsStream, value: &T) -> Result<()> {
    let s = serde_json::to_string(value)?;
    ws.send(Message::Text(s)).await?;
    Ok(())
}

/// Current wall clock in unix milliseconds.
pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Parse a `f64` from either a JSON number or string.
pub fn parse_f64(v: &serde_json::Value) -> Option<f64> {
    if let Some(n) = v.as_f64() {
        return Some(n);
    }
    v.as_str().and_then(|s| s.parse().ok())
}

/// Parse an integer (u64) from either a JSON number or string.
pub fn parse_u64(v: &serde_json::Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    v.as_str().and_then(|s| s.parse().ok())
}

/// Parse a signed integer (i64) from either a JSON number or string.
/// Used for fields that may carry sentinel negatives (e.g. OKX `prevSeqId == -1`
/// to denote the snapshot anchor).
pub fn parse_i64(v: &serde_json::Value) -> Option<i64> {
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    v.as_str().and_then(|s| s.parse().ok())
}

/// Extract the symbol part of a Binance combined-stream key:
/// `"btcusdt@depth@100ms"` -> `"BTCUSDT"`.
pub fn symbol_from_binance_stream(stream: &str) -> Option<String> {
    Some(stream.split('@').next()?.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialise all tests that touch WS_PROXY -- cargo runs them in
    // parallel by default, which races on the shared process env.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_ws_proxy<T>(value: Option<&str>, body: impl FnOnce() -> T) -> T {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("WS_PROXY").ok();
        match value {
            Some(v) => std::env::set_var("WS_PROXY", v),
            None => std::env::remove_var("WS_PROXY"),
        }
        let out = body();
        match prev {
            Some(v) => std::env::set_var("WS_PROXY", v),
            None => std::env::remove_var("WS_PROXY"),
        }
        out
    }

    #[test]
    fn endpoint_wss_default_port() {
        let url = Url::parse("wss://stream.binance.com/ws").unwrap();
        let (h, p) = ws_endpoint(&url).unwrap();
        assert_eq!(h, "stream.binance.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn endpoint_wss_explicit_port() {
        let url = Url::parse("wss://ws.kraken.com:8443/v2").unwrap();
        let (h, p) = ws_endpoint(&url).unwrap();
        assert_eq!(h, "ws.kraken.com");
        assert_eq!(p, 8443);
    }

    #[test]
    fn endpoint_ws_default_port() {
        let url = Url::parse("ws://example.com/path").unwrap();
        let (_h, p) = ws_endpoint(&url).unwrap();
        assert_eq!(p, 80);
    }

    #[test]
    fn proxy_target_unset_is_none() {
        with_ws_proxy(None, || {
            assert!(ws_proxy_target().is_none());
        });
    }

    #[test]
    fn proxy_target_strips_socks5_scheme() {
        with_ws_proxy(Some("socks5://127.0.0.1:5000"), || {
            assert_eq!(ws_proxy_target().as_deref(), Some("127.0.0.1:5000"));
        });
    }

    #[test]
    fn proxy_target_strips_socks5h_scheme() {
        with_ws_proxy(Some("socks5h://127.0.0.1:5000"), || {
            assert_eq!(ws_proxy_target().as_deref(), Some("127.0.0.1:5000"));
        });
    }

    #[test]
    fn proxy_target_accepts_bare_host_port() {
        with_ws_proxy(Some("127.0.0.1:5000"), || {
            assert_eq!(ws_proxy_target().as_deref(), Some("127.0.0.1:5000"));
        });
    }

    #[test]
    fn proxy_target_empty_is_none() {
        with_ws_proxy(Some(""), || {
            assert!(ws_proxy_target().is_none());
        });
        with_ws_proxy(Some("   "), || {
            assert!(ws_proxy_target().is_none());
        });
    }
}
