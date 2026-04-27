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
use crate::signer::OracleSigner;
use crate::types::SignedPriceUpdate;
use crate::{PriceStore, SharedSigner};
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use std::os::unix::io::FromRawFd;

#[cfg(target_os = "linux")]
const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;

/// Hard cap on concurrent connection handlers (audit R-1). Without this,
/// a host-local attacker can open thousands of slowloris VSOCK
/// connections and exhaust the Tokio blocking pool / FDs. Overflow
/// connections are dropped at accept time.
const MAX_INFLIGHT: usize = 64;

/// Total per-connection wall-clock budget from accept to last byte
/// (audit R-4). The previous `set_read_timeout(10s)` only enforced an
/// idle timeout — a drip-feeder writing 1 byte every 9 s could hold a
/// connection for days. This deadline is checked between every read
/// and shrinks `set_read_timeout` accordingly.
const REQUEST_DEADLINE: Duration = Duration::from_secs(15);

/// Cache TTL for the attestation doc (audit R-2). NSM signs each
/// `Request::Attestation` synchronously and is a serial device; spam
/// at `get_attestation` previously starved real signing path
/// indirectly. AWS Nitro leaf certs live ~3 h, so caching for 5 min
/// is well inside the validity window and removes the DoS primitive.
const ATTESTATION_CACHE_TTL: Duration = Duration::from_secs(300);

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
    /// Monotonic counter of aggregator equal-weight fallback events since
    /// process start (audit EXPLOIT-3). Off-chain monitors poll the
    /// `health` endpoint; a sudden jump means volume reporting collapsed
    /// on ≥50 % of sources — treat as a security event.
    #[serde(skip_serializing_if = "Option::is_none")]
    equal_weight_fallbacks: Option<u64>,
}

pub async fn run_price_server(
    port: u32,
    store: PriceStore,
    signer: SharedSigner,
    signer_address: String,
) -> Result<()> {
    info!(port = port, "Starting VSOCK price server");

    let listener = create_listener(port)?;
    info!(
        port = port,
        max_inflight = MAX_INFLIGHT,
        "VSOCK price server listening"
    );

    let semaphore = Arc::new(Semaphore::new(MAX_INFLIGHT));

    loop {
        let (stream, _addr) = accept_connection(&listener)?;

        // Non-blocking acquire — if MAX_INFLIGHT handlers are already
        // in flight, drop this connection at accept time rather than
        // grow the blocking pool unbounded (audit R-1).
        let permit = match Arc::clone(&semaphore).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                drop(stream); // closes immediately
                warn!("price server overload — dropping connection");
                continue;
            }
        };

        let store = store.clone();
        let signer = signer.clone();
        let signer_addr = signer_address.clone();

        tokio::task::spawn_blocking(move || {
            // `_permit` is dropped (released) when the closure returns,
            // so the semaphore count tracks live handlers exactly.
            let _permit = permit;
            if handle_connection(stream, &store, &signer, &signer_addr).is_err() {
                // Audit R-8: do NOT include the raw error message — a
                // serde_json parse error on attacker-controlled bytes
                // would otherwise echo those bytes into host-readable
                // enclave logs. The fact of a failed connection is
                // observable via this warn line; deeper debugging
                // happens via tcpdump on the VSOCK port, not log
                // messages.
                warn!("price server connection error");
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
    use std::io::Write;

    let deadline = Instant::now() + REQUEST_DEADLINE;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let mut len_buf = [0u8; 4];
    read_exact_with_deadline(&mut stream, &mut len_buf, deadline)?;
    let req_len = u32::from_be_bytes(len_buf) as usize;

    if req_len > 1024 * 64 {
        return Err(eyre::eyre!("request too large: {} bytes", req_len));
    }

    let mut req_buf = vec![0u8; req_len];
    read_exact_with_deadline(&mut stream, &mut req_buf, deadline)?;

    let request: PriceRequest = serde_json::from_slice(&req_buf)?;
    let response = process_request(&request, store, signer, signer_address);

    let resp_bytes = serde_json::to_vec(&response)?;
    stream.write_all(&(resp_bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&resp_bytes)?;
    stream.flush()?;

    Ok(())
}

/// Read `buf.len()` bytes from `stream`, but bail if total elapsed time
/// exceeds the `deadline` regardless of per-byte progress (audit R-4).
/// Sets the OS-level `read_timeout` to the remaining budget on each
/// iteration, so a drip-feeder making 1-byte progress per second still
/// hits the wall.
fn read_exact_with_deadline(
    stream: &mut std::net::TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<()> {
    use std::io::Read;

    let mut filled = 0;
    while filled < buf.len() {
        let now = Instant::now();
        if now >= deadline {
            return Err(eyre::eyre!("request read deadline exceeded"));
        }
        // Shrink the per-read timeout to the remaining budget so the
        // syscall returns control even mid-read.
        stream.set_read_timeout(Some(deadline - now))?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(eyre::eyre!("connection closed mid-read")),
            Ok(n) => filled += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(eyre::eyre!("request read timed out"));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Cached attestation doc + when it was fetched. The Mutex is held only
/// for the hash-map lookups + a clone of ~9 KiB bytes, which is far
/// cheaper than the NSM round-trip the cache replaces.
static ATTESTATION_CACHE: Mutex<Option<(Vec<u8>, Instant)>> = Mutex::new(None);

/// Return the attestation doc, serving from cache if it's < TTL old.
/// Falls back to `signer.attestation_doc()` on miss / stale, and
/// updates the cache if the fetch succeeds (audit R-2).
fn cached_attestation(signer: &dyn OracleSigner) -> Option<Vec<u8>> {
    if let Ok(guard) = ATTESTATION_CACHE.lock() {
        if let Some((doc, fetched)) = &*guard {
            if fetched.elapsed() < ATTESTATION_CACHE_TTL {
                return Some(doc.clone());
            }
        }
    }
    let fresh = signer.attestation_doc()?;
    if let Ok(mut guard) = ATTESTATION_CACHE.lock() {
        *guard = Some((fresh.clone(), Instant::now()));
    }
    Some(fresh)
}

/// Sign a cached price with the enclave-authoritative timestamp computed
/// at aggregation (median of per-source server_time). The host clock is
/// NEVER read here (audit C-3/H-9): if we signed with SystemTime::now()
/// the host could replay-walk the timestamp forward or manipulate the
/// kernel clock.
fn sign_cached(
    cached: &crate::types::CachedPrice,
    signer: &dyn OracleSigner,
) -> Result<SignedPriceUpdate> {
    let timestamp = cached.signed_timestamp;

    let (signature, _) = signer.sign_price_update(
        cached.asset_id,
        cached.price_fixed,
        timestamp,
        cached.num_sources,
        cached.sources_hash,
    )?;

    Ok(SignedPriceUpdate {
        asset_id: format!("0x{}", hex::encode(cached.asset_id.as_slice())),
        asset_symbol: cached.asset_symbol.clone(),
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
                        warn!(error = %e, asset = %cached.asset_symbol, "failed to sign on-demand");
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
                equal_weight_fallbacks: None,
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
                        equal_weight_fallbacks: None,
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
                        equal_weight_fallbacks: None,
                    },
                    Err(e) => PriceResponse {
                        prices: None,
                        price: None,
                        error: Some(format!("signing failed: {}", e)),
                        status: None,
                        signer: None,
                        num_assets: None,
                        attestation_doc: None,
                        equal_weight_fallbacks: None,
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
                    equal_weight_fallbacks: None,
                },
            }
        }
        "get_attestation" => {
            // 5-minute cache (audit R-2): NSM is a serial device; spam
            // here used to indirectly starve other request paths.
            // Leaf certs live ~3 h so a 5-min TTL is well inside the
            // validity window.
            let doc = cached_attestation(signer.as_ref());
            PriceResponse {
                prices: None,
                price: None,
                error: if doc.is_none() {
                    Some("Attestation document unavailable".into())
                } else {
                    None
                },
                status: None,
                signer: Some(signer_address.to_string()),
                num_assets: None,
                attestation_doc: doc.as_ref().map(hex::encode),
                equal_weight_fallbacks: None,
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
                // Expose the equal-weight fallback counter on health
                // so off-chain monitors can alert on a climb without
                // parsing enclave console logs (audit EXPLOIT-3).
                equal_weight_fallbacks: Some(crate::aggregator::equal_weight_fallback_count()),
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
            equal_weight_fallbacks: None,
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
