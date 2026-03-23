/// Unified HTTP client — auto-detects enclave vs. host environment.
///
/// Outside enclave: uses reqwest (direct HTTPS).
/// Inside enclave: routes all HTTP through VSOCK proxy (port 5000).
///
/// All price source modules use this client, so networking is transparent.

use eyre::Result;

/// HTTP client that works both inside and outside the enclave.
#[derive(Clone)]
pub struct HttpClient {
    /// Standard reqwest client (used outside enclave)
    reqwest_client: reqwest::Client,
    /// Whether we're running inside an enclave
    enclave_mode: bool,
}

impl HttpClient {
    pub fn new(enclave_mode: bool) -> Self {
        let reqwest_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("KaskadOracle/0.1")
            .build()
            .expect("failed to create reqwest client");

        Self {
            reqwest_client,
            enclave_mode,
        }
    }

    /// Perform a GET request. Transparently routes through VSOCK in enclave mode.
    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T> {
        if self.enclave_mode {
            self.vsock_get_json(url).await
        } else {
            let resp = self.reqwest_client.get(url).send().await?;
            let body = resp.text().await?;
            let parsed: T = serde_json::from_str(&body)?;
            Ok(parsed)
        }
    }

    /// VSOCK-based GET: send request through the VSOCK proxy on the host.
    async fn vsock_get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T> {
        // Run blocking VSOCK I/O in a separate thread
        let url = url.to_string();
        let body = tokio::task::spawn_blocking(move || -> Result<String> {
            vsock_get(&url)
        })
        .await??;

        let parsed: T = serde_json::from_str(&body)?;
        Ok(parsed)
    }
}

/// Perform a synchronous VSOCK GET request through the host proxy (port 5000).
fn vsock_get(url: &str) -> Result<String> {
    use std::io::{Read, Write};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize)]
    struct VsockRequest {
        method: String,
        url: String,
        headers: std::collections::HashMap<String, String>,
        body: Option<String>,
        http_method: String,
    }

    #[derive(Deserialize)]
    struct VsockResponse {
        #[serde(default)]
        status: u16,
        #[serde(default)]
        body: String,
        #[serde(default)]
        error: Option<String>,
    }

    let request = VsockRequest {
        method: "http".into(),
        url: url.into(),
        headers: {
            let mut h = std::collections::HashMap::new();
            h.insert("User-Agent".into(), "KaskadOracle/0.1".into());
            h
        },
        body: None,
        http_method: "GET".into(),
    };

    let request_bytes = serde_json::to_vec(&request)?;

    let mut stream = connect_vsock_proxy()?;

    // Send: [4 bytes length][payload]
    let len = request_bytes.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&request_bytes)?;
    stream.flush()?;

    // Receive: [4 bytes length][payload]
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf)?;

    let response: VsockResponse = serde_json::from_slice(&resp_buf)?;

    if let Some(error) = response.error {
        return Err(eyre::eyre!("VSOCK proxy error: {}", error));
    }

    if response.status >= 400 {
        return Err(eyre::eyre!(
            "HTTP {} from {}: {}",
            response.status,
            url,
            &response.body[..response.body.len().min(200)]
        ));
    }

    Ok(response.body)
}

/// Connect to the VSOCK proxy on the host (CID 3, port 5000).
#[cfg(target_os = "linux")]
fn connect_vsock_proxy() -> Result<std::net::TcpStream> {
    use std::mem;
    use std::os::unix::io::FromRawFd;

    const AF_VSOCK: i32 = 40;
    const PARENT_CID: u32 = 3;
    const VSOCK_PORT: u32 = 5000;

    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(eyre::eyre!("failed to create VSOCK socket"));
    }

    #[repr(C)]
    struct SockaddrVm {
        svm_family: u16,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }

    let addr = SockaddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: VSOCK_PORT,
        svm_cid: PARENT_CID,
        svm_zero: [0; 4],
    };

    let ret = unsafe {
        libc::connect(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            mem::size_of::<SockaddrVm>() as u32,
        )
    };

    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(eyre::eyre!("failed to connect VSOCK to CID {} port {}", PARENT_CID, VSOCK_PORT));
    }

    let stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
fn connect_vsock_proxy() -> Result<std::net::TcpStream> {
    let stream = std::net::TcpStream::connect("127.0.0.1:5000")?;
    Ok(stream)
}
