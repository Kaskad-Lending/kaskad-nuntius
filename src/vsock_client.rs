/// VSOCK HTTP client for use inside Nitro Enclave.
///
/// The enclave has no network. All HTTP requests are forwarded through
/// a VSOCK proxy running on the host EC2 instance. This module provides
/// a reqwest-like interface that transparently routes through VSOCK.
///
/// Protocol: length-prefixed JSON over VSOCK (AF_VSOCK).
///
///   Request:  [4 bytes: length BE][JSON request]
///   Response: [4 bytes: length BE][JSON response]

use eyre::Result;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[cfg(target_os = "linux")]
use std::os::unix::io::FromRawFd;

/// VSOCK CID for the parent instance (always 3 for Nitro Enclaves).
const PARENT_CID: u32 = 3;

/// Default VSOCK port for the proxy.
const DEFAULT_VSOCK_PORT: u32 = 5000;

#[derive(Serialize)]
struct VsockRequest {
    method: String,
    url: String,
    headers: std::collections::HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
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

/// HTTP client that routes requests through the VSOCK proxy.
pub struct VsockHttpClient {
    cid: u32,
    port: u32,
}

impl VsockHttpClient {
    pub fn new() -> Self {
        Self {
            cid: PARENT_CID,
            port: DEFAULT_VSOCK_PORT,
        }
    }

    pub fn with_port(port: u32) -> Self {
        Self {
            cid: PARENT_CID,
            port,
        }
    }

    /// Send a GET request through the VSOCK proxy.
    pub fn get(&self, url: &str) -> Result<String> {
        self.request("GET", url, None)
    }

    /// Send a POST request through the VSOCK proxy.
    pub fn post(&self, url: &str, body: &str) -> Result<String> {
        self.request("POST", url, Some(body.to_string()))
    }

    fn request(&self, method: &str, url: &str, body: Option<String>) -> Result<String> {
        let req = VsockRequest {
            method: "http".into(),
            url: url.into(),
            headers: {
                let mut h = std::collections::HashMap::new();
                h.insert("User-Agent".into(), "KaskadOracle/0.1".into());
                if method == "POST" {
                    h.insert("Content-Type".into(), "application/json".into());
                }
                h
            },
            body,
            http_method: method.into(),
        };

        let request_bytes = serde_json::to_vec(&req)?;

        // Connect to VSOCK
        let mut stream = self.connect_vsock()?;

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

    /// Connect to the parent instance via VSOCK.
    #[cfg(target_os = "linux")]
    fn connect_vsock(&self) -> Result<std::net::TcpStream> {
        use std::mem;

        // AF_VSOCK = 40
        const AF_VSOCK: i32 = 40;

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
            svm_port: self.port,
            svm_cid: self.cid,
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
            return Err(eyre::eyre!(
                "failed to connect VSOCK to CID {} port {}",
                self.cid,
                self.port
            ));
        }

        // SAFETY: fd is a valid socket file descriptor we just created
        let stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        Ok(stream)
    }

    /// Fallback for non-Linux (development): use localhost TCP instead of VSOCK.
    #[cfg(not(target_os = "linux"))]
    fn connect_vsock(&self) -> Result<std::net::TcpStream> {
        // For local development: connect to TCP localhost instead
        let stream = std::net::TcpStream::connect(format!("127.0.0.1:{}", self.port))?;
        Ok(stream)
    }
}
