//! VSOCK serve loop for the bridge (CID 17, port 5004), modelled on the oracle
//! price server: a bounded in-flight count, a per-connection deadline, and the
//! R-8 rule of never echoing attacker bytes into host-readable logs. Each request
//! is stamped with the enclave's current wall clock, which feeds the claim's soft
//! deadline (the mint amount is anchored to the baked-Igra burn read, not the
//! clock).

use std::net::{TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eyre::{eyre, Result};
use keyex::api::BridgeRequest;
use nitro_common::vsock::{read_frame_deadline, write_frame, MAX_FRAME};
use tokio::runtime::Handle;
use tokio::sync::{Mutex, Semaphore};
use tracing::{info, warn};

use crate::config::BakedIdentity;
use crate::handler::{handle, Attestor, HandlerCtx};
use crate::state::BridgeState;

/// Concurrent-handler ceiling; overflow connections are dropped at accept.
const MAX_INFLIGHT: usize = 64;
/// Per-connection wall-clock budget from accept to last byte read.
const REQUEST_DEADLINE: Duration = Duration::from_secs(15);
/// Write-side timeout, matching the price server.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-request handler budget for chain reads. Independent of the frame-read
/// deadline: a hung handler must release the state lock, never wedge the server.
const HANDLER_DEADLINE: Duration = Duration::from_secs(20);
/// Pause after a resource-exhaustion accept fault before retrying.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// Bind to any CID (the enclave's own).
const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;

/// Everything a serve loop needs. The attestor is startup-built and holds no key;
/// it binds the signer pubkey read from `state` per request, so it is valid both
/// before and after boot.
pub struct Serve<A: Attestor> {
    pub state: Arc<Mutex<BridgeState>>,
    pub client: reqwest::Client,
    pub igra_url: String,
    pub baked: BakedIdentity,
    pub attestor: Arc<A>,
}

/// Accept connections forever, dispatching each through [`handle`] on the blocking
/// pool. Returns only on a fatal accept fault.
pub async fn serve_loop<A: Attestor + Send + Sync + 'static>(
    listener: TcpListener,
    serve: Arc<Serve<A>>,
) -> Result<()> {
    let semaphore = Arc::new(Semaphore::new(MAX_INFLIGHT));
    loop {
        let stream = match accept_connection(&listener)? {
            Accepted::Conn(s) => s,
            Accepted::RetryNow => continue,
            Accepted::Backoff => {
                warn!("bridge accept: resource exhaustion — backing off");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let permit = match Arc::clone(&semaphore).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                drop(stream);
                warn!("bridge server overload — dropping connection");
                continue;
            }
        };
        let serve = Arc::clone(&serve);
        let rt = Handle::current();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if handle_connection(&rt, stream, &serve).is_err() {
                // R-8: never echo attacker-controlled bytes into enclave logs.
                warn!("bridge server connection error");
            }
        });
    }
}

fn handle_connection<A: Attestor + Send + Sync + 'static>(
    rt: &Handle,
    mut stream: TcpStream,
    serve: &Serve<A>,
) -> Result<()> {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;

    let req_buf = read_frame_deadline(&mut stream, MAX_FRAME, deadline)?;

    // A parse failure on host bytes must not echo them back (R-8): reply a generic
    // coded error and close.
    let req: BridgeRequest = match serde_json::from_slice(&req_buf) {
        Ok(r) => r,
        Err(_) => {
            write_frame(&mut stream, br#"{"error":"bad_request"}"#, MAX_FRAME)?;
            return Ok(());
        }
    };

    // Enclave wall clock, stamped per request; feeds the claim's soft deadline.
    let enclave_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let resp = rt.block_on(async {
        let fut = async {
            let mut guard = serve.state.lock().await;
            let ctx = HandlerCtx {
                client: &serve.client,
                igra_url: &serve.igra_url,
                baked: &serve.baked,
                enclave_now,
            };
            handle(req, &mut guard, &ctx, serve.attestor.as_ref()).await
        };
        // On timeout the future is dropped, releasing the state lock — a hung
        // chain read can never permanently wedge the single handler slot.
        match tokio::time::timeout(HANDLER_DEADLINE, fut).await {
            Ok(resp) => resp,
            Err(_) => br#"{"error":"timeout"}"#.to_vec(),
        }
    });

    write_frame(&mut stream, &resp, MAX_FRAME)?;
    Ok(())
}

// ─── Listener creation (VSOCK in-enclave, TCP for dev) ──────────────

/// VSOCK listener when `ENCLAVE_MODE` is set, else a localhost TCP fallback.
pub fn create_listener(port: u32) -> Result<TcpListener> {
    if std::env::var("ENCLAVE_MODE").is_ok() {
        create_vsock_listener(port)
    } else {
        info!(port, "bridge server: TCP fallback (no ENCLAVE_MODE)");
        Ok(TcpListener::bind(format!("127.0.0.1:{port}"))?)
    }
}

fn create_vsock_listener(port: u32) -> Result<TcpListener> {
    use std::mem;
    const AF_VSOCK: i32 = 40;

    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(eyre!("failed to create VSOCK socket"));
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
        return Err(eyre!("failed to bind VSOCK on port {port}"));
    }

    let ret = unsafe { libc::listen(fd, 5) };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(eyre!("failed to listen on VSOCK port {port}"));
    }

    Ok(unsafe { TcpListener::from_raw_fd(fd) })
}

/// Outcome of one accept attempt: a connection, a transient fault to retry at
/// once, or a resource-exhaustion fault to retry after a short pause.
enum Accepted {
    Conn(TcpStream),
    RetryNow,
    Backoff,
}

/// Map an accept errno to an action. Transient faults (a signal, a peer gone
/// mid-handshake) retry; resource exhaustion backs off; anything else means the
/// listener itself is broken and the serve loop must exit.
fn classify_accept(errno: Option<i32>) -> Result<Accepted> {
    match errno {
        Some(libc::EINTR) | Some(libc::ECONNABORTED) => Ok(Accepted::RetryNow),
        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOBUFS) | Some(libc::ENOMEM) => {
            Ok(Accepted::Backoff)
        }
        other => Err(eyre!(
            "VSOCK accept failed (errno {other:?}) — listener unrecoverable"
        )),
    }
}

fn accept_connection(listener: &TcpListener) -> Result<Accepted> {
    if std::env::var("ENCLAVE_MODE").is_ok() {
        let fd = listener.as_raw_fd();
        let mut addr: libc::sockaddr = unsafe { std::mem::zeroed() };
        let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr>() as libc::socklen_t;
        let client_fd = unsafe { libc::accept(fd, &mut addr as *mut _, &mut len) };
        if client_fd < 0 {
            return classify_accept(std::io::Error::last_os_error().raw_os_error());
        }
        Ok(Accepted::Conn(unsafe { TcpStream::from_raw_fd(client_fd) }))
    } else {
        match listener.accept() {
            Ok((stream, _)) => Ok(Accepted::Conn(stream)),
            Err(e) => classify_accept(e.raw_os_error()),
        }
    }
}
