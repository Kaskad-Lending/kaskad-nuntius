//! Unified HTTP client — auto-detects enclave vs. host environment.
//!
//! Outside enclave: uses reqwest (direct HTTPS).
//! Inside enclave: routes reqwest traffic through a local socat TCP socket
//! (port 5000) which tunnels via VSOCK to the Host OS, which then forwards
//! the encrypted TLS stream via an HTTP CONNECT proxy. TLS termination
//! happens explicitly *inside* the enclave boundary.
//!
//! Security rule: the enclave NEVER reads its own system clock for signing
//! timestamps (audit C-3/H-9). Every HTTP fetch returns the server-reported
//! unix time from the TLS-authenticated `Date` response header. Each source
//! MAY override this with a more precise field from the JSON body. There is
//! NO fallback to the host clock — if a server fails to supply a Date header,
//! the request is rejected.

use chrono::{DateTime, Utc};
use eyre::{eyre, Result};
use reqwest::header::DATE;

const MAX_RESPONSE_BYTES: u64 = 1 << 20; // 1 MiB — CEX ticker responses are typically <5 KB.

/// HTTP client that works both inside and outside the enclave.
#[derive(Clone)]
pub struct HttpClient {
    reqwest_client: reqwest::Client,
}

impl HttpClient {
    pub fn new(enclave_mode: bool) -> Self {
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::limited(2))
            .user_agent("KaskadOracle/0.1");

        if enclave_mode {
            // Tunnel through local socat bridge at 127.0.0.1:5000
            // This natively prevents Host OS MITM interception!
            let proxy = reqwest::Proxy::all("http://127.0.0.1:5000")
                .expect("Failed to configure enclave VSOCK proxy tunnel");
            builder = builder.proxy(proxy);
        }

        Self {
            reqwest_client: builder.build().expect("failed to create reqwest client"),
        }
    }

    /// Perform an HTTPS GET request using native TLS. Returns the parsed
    /// body AND the server's unix timestamp extracted from the `Date`
    /// header (RFC 2822). Caller can override with a more precise JSON
    /// field if the source provides one.
    pub async fn get_json_with_time<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<(T, u64)> {
        let resp = self.reqwest_client.get(url).send().await?;
        let status = resp.status();

        // Extract Date before consuming the body.
        let date_hdr = resp
            .headers()
            .get(DATE)
            .ok_or_else(|| eyre!("missing Date header from {}", url))?
            .to_str()
            .map_err(|e| eyre!("non-ascii Date header from {}: {}", url, e))?
            .to_string();

        // Bound the body size to avoid OOM via a malicious/compromised CEX
        // (audit H-8 — cap the response body).
        let content_length = resp.content_length().unwrap_or(0);
        if content_length > MAX_RESPONSE_BYTES {
            return Err(eyre!(
                "response body too large from {}: {} > {}",
                url,
                content_length,
                MAX_RESPONSE_BYTES
            ));
        }
        let body_bytes = resp.bytes().await?;
        if body_bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(eyre!(
                "streamed body exceeded cap for {}: {} bytes",
                url,
                body_bytes.len()
            ));
        }

        if !status.is_success() {
            let preview = String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(200)]);
            return Err(eyre!("HTTP {} from {}: {}", status, url, preview));
        }

        let parsed: T = serde_json::from_slice(&body_bytes)?;

        let server_unix = DateTime::parse_from_rfc2822(&date_hdr)
            .map_err(|e| eyre!("bad Date header '{}' from {}: {}", date_hdr, url, e))?
            .with_timezone(&Utc)
            .timestamp();
        if server_unix <= 0 {
            return Err(eyre!(
                "non-positive server time {} from {}",
                server_unix,
                url
            ));
        }

        Ok((parsed, server_unix as u64))
    }
}
