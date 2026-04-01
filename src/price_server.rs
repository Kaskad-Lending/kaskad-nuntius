/// VSOCK-based price server — listens for queries from the host.
///
/// The host-side `pull_api.py` connects to this server via VSOCK and
/// requests the latest signed prices.  The enclave responds with JSON.
///
/// Protocol: length-prefixed JSON (same as vsock_client.rs).
///   Request:  [4 bytes: length BE][JSON request]
///   Response: [4 bytes: length BE][JSON response]
///
/// Supported methods:
///   {"method": "get_prices"}                     → all prices
///   {"method": "get_price", "asset": "ETH/USD"}  → single asset
///   {"method": "health"}                         → server status
use crate::PriceStore;
use eyre::Result;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

#[cfg(target_os = "linux")]
use std::os::unix::io::FromRawFd;

/// VSOCK CID — accept from any CID.
#[cfg(target_os = "linux")]
const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;

#[derive(Deserialize)]
struct PriceRequest {
    method: String,
    #[serde(default)]
    asset: Option<String>,
}

#[derive(Serialize)]
struct PriceResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    prices: Option<Vec<crate::types::SignedPriceUpdate>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    price: Option<crate::types::SignedPriceUpdate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_assets: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation_doc: Option<String>,
}

pub async fn run_price_server(
    port: u32,
    store: PriceStore,
    signer_address: String,
    attestation_doc_bytes: Option<Vec<u8>>,
) -> Result<()> {
    info!(port = port, "Starting VSOCK price server");

    let listener = create_listener(port)?;
    info!(port = port, "VSOCK price server listening");

    loop {
        let (stream, _addr) = accept_connection(&listener)?;
        let store = store.clone();
        let signer = signer_address.clone();
        let attestation = attestation_doc_bytes.clone();

        tokio::task::spawn_blocking(move || {
            if let Err(e) = handle_connection(stream, &store, &signer, &attestation) {
                warn!(error = %e, "price server connection error");
            }
        });
    }
}

fn handle_connection(
    mut stream: std::net::TcpStream,
    store: &PriceStore,
    signer_address: &str,
    attestation_doc: &Option<Vec<u8>>,
) -> Result<()> {
    use std::io::{Read, Write};

    // Read request
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let req_len = u32::from_be_bytes(len_buf) as usize;

    if req_len > 1024 * 64 {
        return Err(eyre::eyre!("request too large: {} bytes", req_len));
    }

    let mut req_buf = vec![0u8; req_len];
    stream.read_exact(&mut req_buf)?;

    let request: PriceRequest = serde_json::from_slice(&req_buf)?;
    let response = process_request(&request, store, signer_address, attestation_doc);

    // Write response
    let resp_bytes = serde_json::to_vec(&response)?;
    stream.write_all(&(resp_bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&resp_bytes)?;
    stream.flush()?;

    Ok(())
}

fn process_request(
    request: &PriceRequest,
    store: &PriceStore,
    signer_address: &str,
    attestation_doc: &Option<Vec<u8>>,
) -> PriceResponse {
    match request.method.as_str() {
        "get_prices" => {
            let store = store.blocking_read();
            let prices: Vec<_> = store.values().cloned().collect();
            PriceResponse {
                prices: Some(prices),
                price: None,
                error: None,
                status: None,
                signer: Some(signer_address.to_string()),
                num_assets: Some(store.len()),
                attestation_doc: None,
            }
        }
        "get_price" => {
            let asset = match &request.asset {
                Some(a) => a.clone(),
                None => {
                    return PriceResponse {
                        prices: None,
                        price: None,
                        error: Some("missing 'asset' field".to_string()),
                        status: None,
                        signer: None,
                        num_assets: None,
                        attestation_doc: None,
                    }
                }
            };
            let store = store.blocking_read();
            match store.get(&asset) {
                Some(update) => PriceResponse {
                    prices: None,
                    price: Some(update.clone()),
                    error: None,
                    status: None,
                    signer: Some(signer_address.to_string()),
                    num_assets: None,
                    attestation_doc: None,
                },
                None => PriceResponse {
                    prices: None,
                    price: None,
                    error: Some(format!("asset '{}' not found", asset)),
                    status: None,
                    signer: None,
                    num_assets: None,
                    attestation_doc: None,
                },
            }
        }
        "get_attestation" => {
            PriceResponse {
                prices: None,
                price: None,
                error: if attestation_doc.is_none() {
                    Some("Attestation document missing".into())
                } else {
                    None
                },
                status: None,
                signer: Some(signer_address.to_string()),
                num_assets: None,
                attestation_doc: attestation_doc.as_ref().map(|doc| hex::encode(doc)), // encode bytes as hex string
            }
        }
        "health" => {
            let store = store.blocking_read();
            PriceResponse {
                prices: None,
                price: None,
                error: None,
                status: Some("ok".to_string()),
                signer: Some(signer_address.to_string()),
                num_assets: Some(store.len()),
                attestation_doc: None,
            }
        }
        _ => PriceResponse {
            prices: None,
            price: None,
            error: Some(format!("unknown method: {}", request.method)),
            status: None,
            signer: None,
            num_assets: None,
            attestation_doc: None,
        },
    }
}

// ─── Platform-specific listener creation ──────────────────────────

#[cfg(target_os = "linux")]
fn create_listener(port: u32) -> Result<std::net::TcpListener> {
    // In enclave mode, use VSOCK. Otherwise, fall back to TCP for local development.
    if std::env::var("ENCLAVE_MODE").is_ok() {
        create_vsock_listener(port)
    } else {
        info!(port = port, "Using TCP fallback for development (no ENCLAVE_MODE)");
        let listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", port))?;
        Ok(listener)
    }
}

#[cfg(target_os = "linux")]
fn create_vsock_listener(port: u32) -> Result<std::net::TcpListener> {
    use std::mem;

    const AF_VSOCK: i32 = 40;

    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(eyre::eyre!("failed to create VSOCK socket"));
    }

    let optval: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &optval as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as u32,
        );
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
        svm_port: port,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };

    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            mem::size_of::<SockaddrVm>() as u32,
        )
    };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(eyre::eyre!("failed to bind VSOCK on port {}", port));
    }

    let ret = unsafe { libc::listen(fd, 5) };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(eyre::eyre!("failed to listen on VSOCK port {}", port));
    }

    let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    Ok(listener)
}

#[cfg(not(target_os = "linux"))]
fn create_listener(port: u32) -> Result<std::net::TcpListener> {
    let listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", port))?;
    info!(port = port, "Using TCP fallback for development");
    Ok(listener)
}

fn accept_connection(listener: &std::net::TcpListener) -> Result<(std::net::TcpStream, ())> {
    let (stream, _) = listener.accept()?;
    Ok((stream, ()))
}
