/// Unified HTTP client — auto-detects enclave vs. host environment.
///
/// Outside enclave: uses reqwest (direct HTTPS).
/// Inside enclave: routes reqwest traffic through a local `socat` TCP socket (port 5000),
/// which tunnels via VSOCK to the Untrusted Host OS, which then forwards the encrypted
/// TLS stream via an HTTP CONNECT proxy.
/// Native TLS termination happens explicitly *inside* the enclave boundary!
use eyre::Result;

/// HTTP client that works both inside and outside the enclave.
#[derive(Clone)]
pub struct HttpClient {
    reqwest_client: reqwest::Client,
}

impl HttpClient {
    pub fn new(enclave_mode: bool) -> Self {
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
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

    /// Perform an HTTPS GET request using native TLS.
    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T> {
        let resp = self.reqwest_client.get(url).send().await?;

        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            return Err(eyre::eyre!(
                "HTTP {} from {}: {}",
                status,
                url,
                &body[..body.len().min(200)]
            ));
        }

        let parsed: T = serde_json::from_str(&body)?;
        Ok(parsed)
    }
}
