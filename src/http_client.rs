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

use std::time::Duration;

use chrono::{DateTime, Utc};
use eyre::{eyre, Result};
use reqwest::header::{CONTENT_TYPE, DATE};

const MAX_RESPONSE_BYTES: u64 = 1 << 20; // 1 MiB — CEX ticker responses are typically <5 KB.

/// HTTP client that works both inside and outside the enclave.
#[derive(Clone)]
pub struct HttpClient {
    reqwest_client: reqwest::Client,
    /// Same settings as `reqwest_client` but never follows a redirect:
    /// the allowlist only vets the URL a request starts from.
    post_client: reqwest::Client,
    /// Allowlist of hostnames the client will issue requests to. Set at
    /// construction from `config/assets.json → exchange_hostnames` so
    /// the allowlist is measured in PCR0 alongside the source code that
    /// uses it. Any request to a hostname not in this list returns an
    /// error without opening a connection — a
    /// defence-in-depth layer against enclave-side code paths that
    /// might otherwise be tricked into fetching an attacker-controlled
    /// URL (audit EXPLOIT-class CONNECT destination-allowlist).
    allowed_hosts: Vec<String>,
}

fn build_client(enclave_mode: bool, redirect: reqwest::redirect::Policy) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .redirect(redirect)
        .user_agent("KaskadOracle/0.1");

    if enclave_mode {
        // Tunnel through local socat bridge at 127.0.0.1:5000
        // This natively prevents Host OS MITM interception!
        let proxy = reqwest::Proxy::all("http://127.0.0.1:5000")
            .expect("Failed to configure enclave VSOCK proxy tunnel");
        builder = builder.proxy(proxy);
    }

    builder.build().expect("failed to create reqwest client")
}

impl HttpClient {
    pub fn new(enclave_mode: bool, allowed_hosts: Vec<String>) -> Self {
        Self {
            reqwest_client: build_client(enclave_mode, reqwest::redirect::Policy::limited(2)),
            post_client: build_client(enclave_mode, reqwest::redirect::Policy::none()),
            allowed_hosts,
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
        self.check_host(url)?;
        let resp = self.reqwest_client.get(url).send().await?;
        read_json_with_time(resp, url).await
    }

    /// POST a JSON `body` without following redirects. Same allowlist, body
    /// cap and `Date` rules as GET; `timeout` bounds connect through the
    /// last body byte.
    pub async fn post_json_with_time<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &'static [u8],
        timeout: Duration,
    ) -> Result<(T, u64)> {
        self.check_host(url)?;
        let resp = self
            .post_client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .timeout(timeout)
            .send()
            .await?;
        read_json_with_time(resp, url).await
    }

    /// Hostname allowlist gate, checked before any network call.
    fn check_host(&self, url: &str) -> Result<()> {
        let parsed = reqwest::Url::parse(url).map_err(|e| eyre!("invalid url {}: {}", url, e))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| eyre!("url missing host: {}", url))?;
        if !self.allowed_hosts.iter().any(|h| h == host) {
            return Err(eyre!(
                "disallowed host {} (not in exchange_hostnames allowlist)",
                host
            ));
        }
        Ok(())
    }
}

/// Shared response rules: `Date` required, body capped, 2xx required, JSON
/// body. Returns the parsed body and the server's unix time.
async fn read_json_with_time<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
    url: &str,
) -> Result<(T, u64)> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const SERVER_DATE: &str = "Tue, 17 Nov 2026 12:00:00 GMT";
    const SERVER_UNIX: u64 = 1_794_916_800;
    const REDIRECT_PATH: &str = "/start";
    const TARGET_BODY: &str = r#"{"ok":true}"#;

    /// One request as the test server received it.
    #[derive(Debug, Clone)]
    struct Seen {
        method: String,
        path: String,
        content_type: Option<String>,
        body: Vec<u8>,
    }

    type Log = Arc<Mutex<Vec<Seen>>>;

    /// Serves `REDIRECT_PATH` with `redirect_status` pointing at `/next`, and
    /// any other path with 200 `TARGET_BODY`. Returns the base URL and the log.
    async fn serve(redirect_status: &'static str) -> (String, Log) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let log: Log = Arc::default();
        let server_log = Arc::clone(&log);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(answer(stream, redirect_status, Arc::clone(&server_log)));
            }
        });
        (base, log)
    }

    async fn answer(mut stream: TcpStream, redirect_status: &'static str, log: Log) {
        let mut buf = Vec::new();
        let head_end = loop {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before the request head");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8(buf[..head_end].to_vec()).unwrap();
        let mut lines = head.split("\r\n");
        let mut request_line = lines.next().unwrap().split(' ');
        let method = request_line.next().unwrap().to_string();
        let path = request_line.next().unwrap().to_string();
        let header = |name: &str| {
            head.split("\r\n").find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
            })
        };
        let content_length: usize = header("content-length").map_or(0, |v| v.parse().unwrap());
        let mut body = buf[head_end..].to_vec();
        while body.len() < content_length {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before the request body");
            body.extend_from_slice(&chunk[..n]);
        }
        log.lock().unwrap().push(Seen {
            method,
            path: path.clone(),
            content_type: header("content-type"),
            body,
        });

        let (status, location) = if path == REDIRECT_PATH {
            (redirect_status, "Location: /next\r\n")
        } else {
            ("200 OK", "")
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nDate: {SERVER_DATE}\r\nContent-Type: application/json\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n{TARGET_BODY}",
            TARGET_BODY.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    }

    fn local_client() -> HttpClient {
        HttpClient::new(false, vec!["127.0.0.1".into()])
    }

    #[tokio::test]
    async fn post_never_follows_a_redirect() {
        for status in [
            "301 Moved Permanently",
            "302 Found",
            "303 See Other",
            "307 Temporary Redirect",
            "308 Permanent Redirect",
        ] {
            let (base, log) = serve(status).await;
            let err = local_client()
                .post_json_with_time::<serde_json::Value>(
                    &format!("{base}{REDIRECT_PATH}"),
                    b"{}",
                    Duration::from_secs(4),
                )
                .await
                .expect_err("a redirect must not be followed");
            assert!(err.to_string().contains(status), "{status}: {err}");
            let paths: Vec<String> = log.lock().unwrap().iter().map(|s| s.path.clone()).collect();
            assert_eq!(paths, [REDIRECT_PATH], "{status}");
        }
    }

    #[tokio::test]
    async fn get_still_follows_a_redirect() {
        let (base, log) = serve("302 Found").await;
        let (body, server_time) = local_client()
            .get_json_with_time::<serde_json::Value>(&format!("{base}{REDIRECT_PATH}"))
            .await
            .unwrap();
        assert_eq!(body, serde_json::json!({"ok": true}));
        assert_eq!(server_time, SERVER_UNIX);
        let paths: Vec<String> = log.lock().unwrap().iter().map(|s| s.path.clone()).collect();
        assert_eq!(paths, [REDIRECT_PATH, "/next"]);
    }

    #[tokio::test]
    async fn post_sends_the_json_body_and_returns_the_date() {
        const SENT: &[u8] = br#"{"jsonrpc":"2.0","id":1}"#;
        let (base, log) = serve("307 Temporary Redirect").await;
        let (body, server_time) = local_client()
            .post_json_with_time::<serde_json::Value>(
                &format!("{base}/rpc"),
                SENT,
                Duration::from_secs(4),
            )
            .await
            .unwrap();
        assert_eq!(body, serde_json::json!({"ok": true}));
        assert_eq!(server_time, SERVER_UNIX);
        let seen = log.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].content_type.as_deref(), Some("application/json"));
        assert_eq!(seen[0].body, SENT);
    }

    #[tokio::test]
    async fn allowlist_vets_the_host_and_post_keeps_the_path() {
        let bundled = crate::types::load_assets().unwrap().exchange_hostnames;
        HttpClient::new(false, bundled)
            .check_host("https://0xrpc.io/eth")
            .expect("0xrpc.io is allowlisted by host");
        let (base, log) = serve("307 Temporary Redirect").await;
        local_client()
            .post_json_with_time::<serde_json::Value>(
                &format!("{base}/eth"),
                b"{}",
                Duration::from_secs(4),
            )
            .await
            .unwrap();
        let paths: Vec<String> = log.lock().unwrap().iter().map(|s| s.path.clone()).collect();
        assert_eq!(paths, ["/eth"]);
    }

    #[tokio::test]
    async fn post_rejects_a_host_outside_the_allowlist() {
        let client = HttpClient::new(false, vec!["example.com".into()]);
        let err = client
            .post_json_with_time::<serde_json::Value>(
                "http://127.0.0.1:9/rpc",
                b"{}",
                Duration::from_secs(4),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("disallowed host"), "{err}");
    }

    #[tokio::test]
    async fn post_honours_the_caller_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/rpc", listener.local_addr().unwrap());
        let (held_tx, held_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // Keep the connection open without answering.
            let _ = held_tx.send(stream);
        });
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            local_client().post_json_with_time::<serde_json::Value>(
                &url,
                b"{}",
                Duration::from_millis(300),
            ),
        )
        .await
        .expect("the request timeout must fire before the guard");
        assert!(outcome.is_err());
        assert!(started.elapsed() < Duration::from_secs(4));
        drop(held_rx);
    }
}
