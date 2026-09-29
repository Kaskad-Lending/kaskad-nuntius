//! RA-TLS key handover server (VSOCK/TCP port 5002), async. A verified successor
//! enclave connects, both sides attest, and `run_server_handshake` decides — under
//! the pure boot rules — whether to hand this enclave's own root key or a derived
//! child. The transferable key is zeroized on every path.
//!
//! Tokio has no VSOCK type, so [`VsockAsyncStream`] wraps a raw fd (vsock or tcp)
//! in an [`AsyncFd`]. Each connection is driven on its own current-thread runtime
//! inside `spawn_blocking`: this both registers the `AsyncFd` with the reactor that
//! drives it and sidesteps a `Send` bound on the per-connection NSM handle.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eyre::{eyre, Result};
use keyex::policy::{EnclaveRole, ImageIdentity};
use keyex::ratls::{
    crypto_provider, fresh_nonce, generate_ephemeral_cert, run_server_handshake, server_config,
    HandoverInputs, Handshake, NsmPeerVerifier, ServerExchange, NONCE_LEN,
};
use nitro_common::nsm::Nsm;
use nitro_common::rng::NsmRng;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Handle;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use zeroize::Zeroize;

use super::state::OracleKeyexState;
use super::{bound_vsock_listen_fd, classify_accept, enclave_mode, AcceptFault, RootKeyBytes};

/// RA-TLS handover VSOCK port.
const HANDOVER_PORT: u32 = 5002;
/// Concurrent in-flight handovers. Each one holds the root key in memory, so keep
/// this small — a successor rollout needs one at a time, not a fleet.
const MAX_HANDOVER_INFLIGHT: usize = 8;
/// Pause after a resource-exhaustion accept fault.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// Wall-clock bound on one handshake. A hung or stalling peer must not pin an
/// in-flight slot — or hold the root key snapshot in memory — indefinitely.
const HANDOVER_TIMEOUT: Duration = Duration::from_secs(30);

/// Spawn the handover server as a detached background task. VSOCK in the enclave,
/// localhost TCP otherwise. Called after the key is installed.
pub fn spawn_handover_server(
    state: Arc<Mutex<OracleKeyexState>>,
    pcr0: [u8; 48],
    version: u64,
) -> Result<()> {
    let handle = Handle::current();
    if enclave_mode() {
        let listen_fd = bound_vsock_listen_fd(HANDOVER_PORT)?;
        let inner = handle.clone();
        handle.spawn_blocking(move || accept_loop_vsock(inner, listen_fd, state, pcr0, version));
    } else {
        let inner = handle.clone();
        handle.spawn(async move {
            if let Err(e) = accept_loop_tcp(inner, state, pcr0, version).await {
                warn!(error = %e, "handover tcp accept loop exited");
            }
        });
    }
    Ok(())
}

/// Blocking VSOCK accept loop (Tokio has no vsock listener). Each accepted fd is
/// handed to its own per-connection runtime.
fn accept_loop_vsock(
    handle: Handle,
    listen_fd: RawFd,
    state: Arc<Mutex<OracleKeyexState>>,
    pcr0: [u8; 48],
    version: u64,
) {
    // SAFETY: `listen_fd` is a freshly bound+listening fd we own; wrapping it in an
    // OwnedFd closes it if the loop ever returns.
    let _listener = unsafe { OwnedFd::from_raw_fd(listen_fd) };
    let inflight = Arc::new(AtomicUsize::new(0));
    info!(
        port = HANDOVER_PORT,
        "keyex handover channel listening (vsock)"
    );
    loop {
        let mut addr: libc::sockaddr = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr>() as libc::socklen_t;
        let client_fd = unsafe { libc::accept(listen_fd, &mut addr as *mut _, &mut len) };
        if client_fd < 0 {
            match classify_accept(io::Error::last_os_error().raw_os_error()) {
                Ok(AcceptFault::RetryNow) => continue,
                Ok(AcceptFault::Backoff) => {
                    std::thread::sleep(ACCEPT_BACKOFF);
                    continue;
                }
                Err(e) => {
                    warn!(error = %e, "handover vsock accept fatal — listener exiting");
                    return;
                }
            }
        }
        // SAFETY: `client_fd` is a fresh owned fd returned by accept.
        let owned = unsafe { OwnedFd::from_raw_fd(client_fd) };
        spawn_handover_conn(
            &handle,
            owned,
            Arc::clone(&inflight),
            Arc::clone(&state),
            pcr0,
            version,
        );
    }
}

/// Localhost TCP accept loop for dev/CI (no ENCLAVE_MODE).
async fn accept_loop_tcp(
    handle: Handle,
    state: Arc<Mutex<OracleKeyexState>>,
    pcr0: [u8; 48],
    version: u64,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{HANDOVER_PORT}")).await?;
    info!(
        port = HANDOVER_PORT,
        "keyex handover channel listening (tcp fallback)"
    );
    let inflight = Arc::new(AtomicUsize::new(0));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => match classify_accept(e.raw_os_error()) {
                Ok(AcceptFault::RetryNow) => continue,
                Ok(AcceptFault::Backoff) => {
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
                Err(fatal) => return Err(fatal),
            },
        };
        let owned: OwnedFd = stream.into_std()?.into();
        spawn_handover_conn(
            &handle,
            owned,
            Arc::clone(&inflight),
            Arc::clone(&state),
            pcr0,
            version,
        );
    }
}

/// Drive one handover connection on a dedicated current-thread runtime. Building
/// the runtime here means the `VsockAsyncStream` (and its `AsyncFd`) registers with
/// the reactor that actually polls it, and the non-`Send` NSM handle never crosses
/// a task boundary.
fn spawn_handover_conn(
    handle: &Handle,
    owned: OwnedFd,
    inflight: Arc<AtomicUsize>,
    state: Arc<Mutex<OracleKeyexState>>,
    pcr0: [u8; 48],
    version: u64,
) {
    if inflight.fetch_add(1, Ordering::SeqCst) >= MAX_HANDOVER_INFLIGHT {
        inflight.fetch_sub(1, Ordering::SeqCst);
        warn!("keyex handover overload — dropping connection");
        return; // `owned` drops here → fd closed.
    }
    let guard = InflightGuard { inflight };
    handle.spawn_blocking(move || {
        let _guard = guard;
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                warn!(error = %e, "handover: failed to build connection runtime");
                return;
            }
        };
        rt.block_on(async move {
            let stream = match VsockAsyncStream::from_owned(owned) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "handover: stream setup failed");
                    return;
                }
            };
            if let Err(e) = handle_handover_conn(stream, &state, pcr0, version).await {
                warn!(error = %e, "keyex handover connection error");
            }
        });
    });
}

/// Decrements the in-flight counter when a handover connection ends.
struct InflightGuard {
    inflight: Arc<AtomicUsize>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serve the RA-TLS handshake to one connected peer. Snapshots the installed key
/// and approvals under the lock, then runs the pure handover decision. The
/// transferable key copy is zeroized on every return path.
async fn handle_handover_conn<S>(
    stream: S,
    state: &Arc<Mutex<OracleKeyexState>>,
    pcr0: [u8; 48],
    version: u64,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut root_opt, approvals) = {
        let st = state
            .lock()
            .map_err(|_| eyre!("handover: state mutex poisoned"))?;
        (st.root_key(), st.approvals())
    };
    let mut root_bytes = match root_opt {
        Some(rb) => rb,
        None => {
            warn!("handover requested before key install — refusing");
            return Ok(());
        }
    };

    let provider = crypto_provider();
    let cert = generate_ephemeral_cert()?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config(provider, &cert)?));

    let mut rng = NsmRng::new()?;
    let my_nonce = fresh_nonce(&mut rng);
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let verifier = NsmPeerVerifier { now_unix_secs };
    let nsm = Nsm::new()?;
    let attest = |peer_nonce: &[u8; NONCE_LEN], my_point: &[u8]| -> Vec<u8> {
        nsm.attestation(None, Some(peer_nonce.to_vec()), Some(my_point.to_vec()))
            .unwrap_or_default()
    };

    let own = ImageIdentity { pcr0, version };
    let hs = Handshake {
        my_cert: &cert,
        my_nonce: &my_nonce,
        verifier: &verifier,
        attest_fn: &attest,
    };
    let inputs = HandoverInputs {
        own: &own,
        role: EnclaveRole::Oracle,
        own_key_is_candidate: false,
        approvals: &approvals,
    };

    let handshake = run_server_handshake(&acceptor, stream, hs, inputs, RootKeyBytes(root_bytes));
    let outcome = tokio::time::timeout(HANDOVER_TIMEOUT, handshake).await;
    // Scrub every local copy of the transferable key on BOTH paths — the handshake's
    // own `RootKeyBytes` copy self-zeroizes on drop (including timeout cancellation),
    // but these two locals must be scrubbed here before any return.
    root_bytes.zeroize();
    if let Some(b) = root_opt.as_mut() {
        b.zeroize();
    }
    let outcome = match outcome {
        Ok(o) => o,
        Err(_elapsed) => {
            warn!(
                timeout_secs = HANDOVER_TIMEOUT.as_secs(),
                "handover handshake timed out"
            );
            return Ok(());
        }
    };

    match outcome? {
        ServerExchange::HandedOwnKey => {
            info!("handover: served own root key to a verified successor")
        }
        ServerExchange::HandedChild => {
            info!("handover: served a derived child key to a verified peer")
        }
        ServerExchange::Refused(r) => warn!(?r, "handover refused by boot policy"),
    }
    Ok(())
}

/// An async stream over a raw fd (vsock or tcp) via [`AsyncFd`]. Reads and writes
/// go through `libc::{read,write}` guarded by Tokio readiness, so it works for any
/// fd Tokio has no native type for. Must be constructed inside the runtime that
/// drives it.
struct VsockAsyncStream {
    inner: AsyncFd<OwnedFd>,
}

impl VsockAsyncStream {
    fn from_owned(fd: OwnedFd) -> Result<Self> {
        set_nonblocking(&fd)?;
        Ok(Self {
            inner: AsyncFd::new(fd)?,
        })
    }
}

/// Put the fd into non-blocking mode; `AsyncFd` requires it.
fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    let raw = fd.as_raw_fd();
    // SAFETY: fcntl on a fd we own.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 {
        return Err(eyre!(
            "fcntl(F_GETFL) failed: {}",
            io::Error::last_os_error()
        ));
    }
    let rc = unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(eyre!(
            "fcntl(F_SETFL, O_NONBLOCK) failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

impl AsyncRead for VsockAsyncStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.inner.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let (ptr, len) = {
                let unfilled = buf.initialize_unfilled();
                (unfilled.as_mut_ptr(), unfilled.len())
            };
            let res = guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // SAFETY: `ptr`/`len` describe `buf`'s initialized-unfilled region.
                let n = unsafe { libc::read(fd, ptr as *mut libc::c_void, len) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for VsockAsyncStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.inner.poll_write_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let ptr = buf.as_ptr();
            let len = buf.len();
            let res = guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // SAFETY: `ptr`/`len` describe the caller's `buf`.
                let n = unsafe { libc::write(fd, ptr as *const libc::c_void, len) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(r) => return Poll::Ready(r),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let fd = self.inner.get_ref().as_raw_fd();
        // SAFETY: half-close the write side of a fd we own; errors are non-fatal.
        unsafe {
            libc::shutdown(fd, libc::SHUT_WR);
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn vsock_async_stream_roundtrips_over_socketpair() {
        let mut fds = [0i32; 2];
        // SAFETY: socketpair fills `fds` with two connected AF_UNIX stream fds.
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair failed: {}", io::Error::last_os_error());
        // SAFETY: fresh owned fds from socketpair.
        let a = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let b = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        let mut sa = VsockAsyncStream::from_owned(a).unwrap();
        let mut sb = VsockAsyncStream::from_owned(b).unwrap();

        sa.write_all(b"ping-1234").await.unwrap();
        sa.flush().await.unwrap();

        let mut buf = [0u8; 9];
        sb.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-1234");
    }
}
