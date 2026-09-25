//! In-enclave egress forwarder. Binds `127.0.0.1:5000` and relays each accepted
//! connection to the host over VSOCK (CID 3, port 5000), so the reqwest proxy and
//! the RA-TLS peer client can reach the host's CONNECT proxy. Mirrors the oracle's
//! `src/main.rs` forwarder; kept crate-local because nitro-common carries no
//! tokio/libc and `src/main.rs` is a binary, not a library.

use std::os::unix::io::FromRawFd;

use eyre::{eyre, Result};
use tracing::{error, info, warn};

/// Host CID as seen from inside the enclave.
const HOST_CID: u32 = 3;
/// Loopback port the enclave's reqwest proxy and RA-TLS client dial.
const EGRESS_PORT: u32 = 5000;

/// Bind the loopback egress port and relay every connection to the host proxy over
/// VSOCK. No-op outside `ENCLAVE_MODE` (dev egress is direct). Fails loud if the
/// port cannot be bound — nothing can egress without it.
pub async fn spawn_forwarder() -> Result<()> {
    if std::env::var("ENCLAVE_MODE").is_err() {
        info!("not ENCLAVE_MODE — skipping VSOCK egress forwarder (direct egress)");
        return Ok(());
    }
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", EGRESS_PORT as u16)).await {
        Ok(l) => {
            info!(port = EGRESS_PORT, "VSOCK egress forwarder bound on 127.0.0.1");
            l
        }
        Err(e) => {
            error!(error = %e, port = EGRESS_PORT, "failed to bind VSOCK egress forwarder");
            return Err(e.into());
        }
    };
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp_stream, _)) => {
                    tokio::spawn(async move {
                        if let Err(e) = bridge_connection(tcp_stream, HOST_CID, EGRESS_PORT).await {
                            warn!(error = %e, "egress forward connection failed");
                        }
                    });
                }
                Err(e) => warn!(error = %e, "egress forwarder accept failed"),
            }
        }
    });
    Ok(())
}

/// Relay one accepted TCP connection to `remote_cid:remote_port` over VSOCK.
async fn bridge_connection(
    tcp_stream: tokio::net::TcpStream,
    remote_cid: u32,
    remote_port: u32,
) -> Result<()> {
    let vsock_stream = tokio::task::spawn_blocking(move || -> Result<std::net::TcpStream> {
        const AF_VSOCK: i32 = 40;

        let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(eyre!("failed to create VSOCK socket"));
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
            svm_port: remote_port,
            svm_cid: remote_cid,
            svm_zero: [0; 4],
        };

        let ret = unsafe {
            libc::connect(
                fd,
                &addr as *const SockaddrVm as *const libc::sockaddr,
                std::mem::size_of::<SockaddrVm>() as u32,
            )
        };

        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(eyre!("VSOCK connect to CID {remote_cid} port {remote_port} failed"));
        }

        // SAFETY: `fd` is a fresh owned socket we just connected.
        Ok(unsafe { std::net::TcpStream::from_raw_fd(fd) })
    })
    .await??;

    vsock_stream.set_nonblocking(true)?;
    let vsock_stream = tokio::net::TcpStream::from_std(vsock_stream)?;

    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_stream);
    let (mut vsock_read, mut vsock_write) = tokio::io::split(vsock_stream);

    let t1 = tokio::io::copy(&mut tcp_read, &mut vsock_write);
    let t2 = tokio::io::copy(&mut vsock_read, &mut tcp_write);

    tokio::select! {
        _ = t1 => {},
        _ = t2 => {},
    }

    Ok(())
}
