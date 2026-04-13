/// VSOCK-based price server — listens for queries from the host.
///
/// Prices are cached unsigned in PriceStore. On each request, the server
/// signs with the current timestamp — so signatures are always fresh.
///
/// Protocol: length-prefixed JSON.
///   Request:  [4 bytes: length BE][JSON request]
///   Response: [4 bytes: length BE][JSON response]
///
/// Supported methods:
///   {"method": "get_prices"}                     → all prices (freshly signed)
///   {"method": "get_price", "asset": "ETH/USD"}  → single asset (freshly signed)
///   {"method": "get_attestation"}                → attestation doc
///   {"method": "health"}                         → server status
use crate::aggregator;
use crate::signer::OracleSigner;
use crate::types::{now_secs, SignedPriceUpdate};
use crate::{PriceStore, SharedSigner};
use eyre::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use std::os::unix::io::FromRawFd;

#[cfg(target_os = "linux")]
const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;

const ORACLE_DECIMALS: u8 = 8;

#[derive(Deserialize)]
struct PriceRequest {
    method: String,
    #[serde(default)]
    asset: Option<String>,
}

#[derive(Serialize)]
struct PriceResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    prices: Option<Vec<SignedPriceUpdate>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    price: Option<SignedPriceUpdate>,
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
    signer: SharedSigner,
    signer_address: String,
) -> Result<()> {
    info!(port = port, "Starting VSOCK price server");

    let listener = create_listener(port)?;
    info!(port = port, "VSOCK price server listening");

    loop {
        let (stream, _addr) = accept_connection(&listener)?;
        let store = store.clone();
        let signer = signer.clone();
        let signer_addr = signer_address.clone();

        tokio::task::spawn_blocking(move || {
            if let Err(e) = handle_connection(stream, &store, &signer, &signer_addr) {
                warn!(error = %e, "price server connection error");
            }
        });
    }
}

fn handle_connection(
    mut stream: std::net::TcpStream,
    store: &PriceStore,
    signer: &SharedSigner,
    signer_address: &str,
) -> Result<()> {
    use std::io::{Read, Write};

    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let req_len = u32::from_be_bytes(len_buf) as usize;

    if req_len > 1024 * 64 {
        return Err(eyre::eyre!("request too large: {} bytes", req_len));
    }

    let mut req_buf = vec![0u8; req_len];
    stream.read_exact(&mut req_buf)?;

    let request: PriceRequest = serde_json::from_slice(&req_buf)?;
    let response = process_request(&request, store, signer, signer_address);

    let resp_bytes = serde_json::to_vec(&response)?;
    stream.write_all(&(resp_bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&resp_bytes)?;
    stream.flush()?;

    Ok(())
}

/// Sign a cached price with the current timestamp.
fn sign_cached(
    cached: &crate::types::CachedPrice,
    signer: &dyn OracleSigner,
) -> Result<SignedPriceUpdate> {
    // Use median exchange server time if we had it during aggregation.
    // For on-demand signing, use system clock (best we can do at request time).
    let timestamp = now_secs();

    let (signature, _) = signer.sign_price_update(
        cached.asset.id(),
        cached.price_fixed,
        timestamp,
        cached.num_sources,
        cached.sources_hash,
    )?;

    Ok(SignedPriceUpdate {
        asset_id: format!("0x{}", hex::encode(cached.asset.id().as_slice())),
        asset_symbol: cached.asset.symbol().to_string(),
        price: format!("{}", cached.price_fixed),
        price_human: format!("{:.8}", cached.price_human),
        timestamp,
        num_sources: cached.num_sources,
        sources_hash: format!("0x{}", hex::encode(cached.sources_hash.as_slice())),
        signature: format!("0x{}", hex::encode(&signature)),
        signer: format!("0x{}", hex::encode(signer.address())),
    })
}

fn process_request(
    request: &PriceRequest,
    store: &PriceStore,
    signer: &SharedSigner,
    signer_address: &str,
) -> PriceResponse {
    match request.method.as_str() {
        "get_prices" => {
            let store = store.blocking_read();
            let mut signed = Vec::new();
            for cached in store.values() {
                match sign_cached(cached, signer.as_ref()) {
                    Ok(update) => signed.push(update),
                    Err(e) => {
                        warn!(error = %e, asset = cached.asset.symbol(), "failed to sign on-demand");
                    }
                }
            }
            let count = signed.len();
            PriceResponse {
                prices: Some(signed),
                price: None,
                error: None,
                status: None,
                signer: Some(signer_address.to_string()),
                num_assets: Some(count),
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
                Some(cached) => match sign_cached(cached, signer.as_ref()) {
                    Ok(update) => PriceResponse {
                        prices: None,
                        price: Some(update),
                        error: None,
                        status: None,
                        signer: Some(signer_address.to_string()),
                        num_assets: None,
                        attestation_doc: None,
                    },
                    Err(e) => PriceResponse {
                        prices: None,
                        price: None,
                        error: Some(format!("signing failed: {}", e)),
                        status: None,
                        signer: None,
                        num_assets: None,
                        attestation_doc: None,
                    },
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
            // Regenerate fresh on every request — AWS Nitro leaf certs live ~3h,
            // caching would serve expired docs and break registerEnclave on-chain.
            let fresh = signer.attestation_doc();
            PriceResponse {
                prices: None,
                price: None,
                error: if fresh.is_none() {
                    Some("Attestation document unavailable".into())
                } else {
                    None
                },
                status: None,
                signer: Some(signer_address.to_string()),
                num_assets: None,
                attestation_doc: fresh.as_ref().map(hex::encode),
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
    if std::env::var("ENCLAVE_MODE").is_ok() {
        create_vsock_listener(port)
    } else {
        info!(
            port = port,
            "Using TCP fallback for development (no ENCLAVE_MODE)"
        );
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

    Ok(unsafe { std::net::TcpListener::from_raw_fd(fd) })
}

#[cfg(not(target_os = "linux"))]
fn create_listener(port: u32) -> Result<std::net::TcpListener> {
    let listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", port))?;
    info!(port = port, "Using TCP fallback for development");
    Ok(listener)
}

#[cfg(target_os = "linux")]
fn accept_connection(listener: &std::net::TcpListener) -> Result<(std::net::TcpStream, ())> {
    if std::env::var("ENCLAVE_MODE").is_ok() {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let fd = listener.as_raw_fd();
        let mut addr: libc::sockaddr = unsafe { std::mem::zeroed() };
        let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr>() as libc::socklen_t;
        let client_fd = unsafe { libc::accept(fd, &mut addr as *mut _, &mut len) };
        if client_fd < 0 {
            return Err(eyre::eyre!("libc::accept failed on VSOCK"));
        }
        Ok((unsafe { std::net::TcpStream::from_raw_fd(client_fd) }, ()))
    } else {
        let (stream, _) = listener.accept()?;
        Ok((stream, ()))
    }
}

#[cfg(not(target_os = "linux"))]
fn accept_connection(listener: &std::net::TcpListener) -> Result<(std::net::TcpStream, ())> {
    let (stream, _) = listener.accept()?;
    Ok((stream, ()))
}
