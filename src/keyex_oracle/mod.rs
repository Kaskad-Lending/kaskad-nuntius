//! Genesis-root RA-TLS oracle boot (feature `keyex_oracle`, Robinhood
//! `kaskad-nitro-us` image only). Mints an NSM-rooted signing key in-enclave,
//! publishes it as a candidate for on-chain registration on the RH
//! KaskadPriceOracle, installs it once registered, then serves the key to verified
//! successor enclaves over RA-TLS. New PCRs by design — the default oracle binary
//! compiles none of this (`option_env!`-baked config, optional deps off).
//!
//! Layout: [`config`] baked trust anchors, [`state`] the guarded boot/key state,
//! [`signer`] the installed key as an `OracleSigner`, [`transport`] enclave→RH
//! JSON-RPC over the host proxy, [`control`] the operator channel (5005), and
//! [`handover`] the successor key-transfer server (5002). This file owns the
//! shared VSOCK primitives and the [`boot_and_serve`] orchestration.

#[cfg(not(target_os = "linux"))]
compile_error!(
    "feature `keyex_oracle` targets the Nitro enclave and requires target_os = \"linux\""
);

mod config;
mod control;
mod handover;
mod signer;
mod state;
mod transport;

use std::future::Future;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eyre::{eyre, Result};
use k256::ecdsa::SigningKey;
use keyex::api::KeySource;
use keyex::boot::Role;
use keyex::chain::{Finality, Registry, RpcChainView};
use keyex::driver::{run_boot, Backoff, BootDeps, Genesis, Installed};
use keyex::peer::RatlsPeerSource;
use keyex::policy::FetchKind;
use nitro_common::nsm::Nsm;
use nitro_common::rng::NsmRng;
use rand::RngCore;
use tracing::{error, info};
use zeroize::Zeroize;

use self::config::BakedOracleConfig;
use self::state::OracleKeyexState;

/// AF_VSOCK address family (absent from libc's constants).
const AF_VSOCK: libc::c_int = 40;
/// Bind to any CID — the enclave accepts from the host regardless of its CID.
const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;
/// Default egress proxy the enclave tunnels JSON-RPC through.
const DEFAULT_PROXY: &str = "http://127.0.0.1:5000";
/// Poll cadence between boot ticks while awaiting on-chain registration.
const BOOT_POLL: Duration = Duration::from_secs(3);

/// Whether this process runs inside the enclave (VSOCK) or on a dev host (TCP).
fn enclave_mode() -> bool {
    std::env::var("ENCLAVE_MODE").is_ok()
}

/// Bind and listen a VSOCK socket on `port`, returning the raw fd. Mirrors the
/// bridge's `create_vsock_listener` but hands back the fd so both a `TcpListener`
/// wrapper (control) and a raw `accept` loop (handover) can consume it. The fd is
/// closed on every error path.
fn bound_vsock_listen_fd(port: u32) -> Result<RawFd> {
    #[repr(C)]
    struct SockaddrVm {
        svm_family: u16,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }
    // SAFETY: raw socket syscalls; the fd is closed on each error path below.
    unsafe {
        let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(eyre!(
                "vsock socket() failed: {}",
                io::Error::last_os_error()
            ));
        }
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let addr = SockaddrVm {
            svm_family: AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: VMADDR_CID_ANY,
            svm_zero: [0; 4],
        };
        let rc = libc::bind(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
        );
        if rc < 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(eyre!("vsock bind(port={port}) failed: {e}"));
        }
        if libc::listen(fd, 5) < 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(eyre!("vsock listen(port={port}) failed: {e}"));
        }
        Ok(fd)
    }
}

/// How an `accept()` fault should be handled: retry now, or back off first.
enum AcceptFault {
    RetryNow,
    Backoff,
}

/// Classify an `accept()` errno into a recoverable fault or a fatal error.
fn classify_accept(errno: Option<i32>) -> Result<AcceptFault> {
    match errno {
        Some(libc::EINTR) | Some(libc::ECONNABORTED) => Ok(AcceptFault::RetryNow),
        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOBUFS) | Some(libc::ENOMEM) => {
            Ok(AcceptFault::Backoff)
        }
        other => Err(eyre!("accept() failed: errno={other:?}")),
    }
}

/// The transferable root key, wrapped so RA-TLS handover can move it under the
/// `Zeroize + AsRef<[u8; 32]>` bound and it scrubs itself on drop.
struct RootKeyBytes([u8; 32]);

impl Zeroize for RootKeyBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl AsRef<[u8; 32]> for RootKeyBytes {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for RootKeyBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Real back-off between unproductive boot ticks.
struct SleepBackoff;

impl Backoff for SleepBackoff {
    fn wait(&self) -> impl Future<Output = ()> {
        tokio::time::sleep(BOOT_POLL)
    }
}

/// NSM-rooted candidate generation. Draws entropy from the Nitro Security Module
/// (never the host-seeded guest CSPRNG), mints a secp256k1 key, and publishes its
/// address + public point into shared state so the control channel can attest it
/// and the operator can register it on the RH KaskadPriceOracle.
struct NsmGenesis {
    state: Arc<Mutex<OracleKeyexState>>,
}

impl Genesis for NsmGenesis {
    fn generate(&self) -> Result<SigningKey> {
        let mut rng = NsmRng::new()?;
        let mut seed = [0u8; 32];
        let mut minted = None;
        // A random scalar is valid with overwhelming probability; redraw on the
        // vanishingly rare rejection rather than loop unboundedly.
        for _ in 0..64 {
            rng.fill_bytes(&mut seed);
            if let Ok(k) = SigningKey::from_bytes((&seed).into()) {
                minted = Some(k);
                break;
            }
        }
        seed.zeroize();
        let key = minted.ok_or_else(|| eyre!("failed to mint a valid key from NSM entropy"))?;

        let vk = key.verifying_key();
        let pubkey = vk.to_encoded_point(false).as_bytes().to_vec();
        let addr = keyex::sig::address_from_key(vk);
        self.state
            .lock()
            .map_err(|_| eyre!("state mutex poisoned"))?
            .publish_candidate(addr, pubkey);
        info!(signer = %addr, "genesis candidate minted; awaiting on-chain registration");
        Ok(key)
    }
}

/// This image's measured PCR0 (48 bytes). A signer with an unknown identity must
/// not boot.
fn own_pcr0(nsm: &Nsm) -> Result<[u8; 48]> {
    nsm.describe_pcr(0)?
        .data
        .try_into()
        .map_err(|_| eyre!("PCR0 is not 48 bytes"))
}

/// Boot the keyex oracle and return the installed key as an [`OracleSigner`].
///
/// Serves the control channel first (so the operator can register the genesis
/// candidate while boot blocks), runs the pure boot state machine against the RH
/// KaskadPriceOracle registry until a key is installed, then starts the RA-TLS
/// handover server for future successors.
pub async fn boot_and_serve() -> Result<Box<dyn crate::signer::OracleSigner>> {
    let cfg = BakedOracleConfig::from_baked()?;
    let pcr0 = own_pcr0(&Nsm::new()?)?;
    let state = Arc::new(Mutex::new(OracleKeyexState::new()));
    state
        .lock()
        .map_err(|_| eyre!("state mutex poisoned"))?
        .set_config(cfg.rh_rpcs.clone(), cfg.peers.clone());

    // Serve the operator control channel before boot: the genesis candidate is
    // attested and registered over it while `run_boot` awaits registration.
    let ctrl = control::ControlCtx {
        state: Arc::clone(&state),
        pcr0,
        version: cfg.version,
        owners: cfg.owners.clone(),
        threshold: cfg.threshold,
        chain_id: cfg.chain_id,
        registry: cfg.registry,
    };
    tokio::spawn(async move {
        if let Err(e) = control::serve_control(ctrl).await {
            error!(error = %e, "keyex control channel exited");
        }
    });

    // Enclave JSON-RPC egress tunnels through the untrusted host proxy; timeouts
    // stop a hung proxy from wedging a boot read forever.
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(
            std::env::var("PONTIFEX_PROXY").unwrap_or_else(|_| DEFAULT_PROXY.to_owned()),
        )?)
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(4))
        .build()?;
    let rh_url = cfg
        .rh_rpcs
        .first()
        .cloned()
        .ok_or_else(|| eyre!("no baked RH RPC"))?;
    let rh = transport::ProxyTransport::new(client, rh_url);
    let view = RpcChainView {
        transport: &rh,
        registry: cfg.registry,
        kind: Registry::Oracle,
        finality: Finality::Tag,
    };

    // Genesis launch has no siblings; a later image sweeps registered oracle peers
    // for the already-installed root (root→root RA-TLS).
    let mut peers: Vec<(String, FetchKind)> = Vec::new();
    for p in &cfg.peers {
        peers.push((p.clone(), FetchKind::RootFromRoot));
    }
    let deps = BootDeps {
        role: Role::Oracle,
        peers: &peers,
        fresh_approved: false,
    };
    let source = RatlsPeerSource::new(Nsm::new()?, pcr0, cfg.ancestors.clone());
    let genesis = NsmGenesis {
        state: Arc::clone(&state),
    };

    let (key, source_kind) = match run_boot(&deps, &source, &view, &genesis, &SleepBackoff).await {
        Installed::Candidate(key) => (key, KeySource::Genesis),
        Installed::Peer { key, .. } => (key, KeySource::Peer),
    };

    // Extract the transferable bytes and the identity before the key is moved into
    // the signer; scrub the local copy once installed.
    let mut root_bytes = [0u8; 32];
    root_bytes.copy_from_slice(&key.to_bytes());
    let addr = keyex::sig::address_from_key(key.verifying_key());
    let installed = signer::KeyexSigner::from_key(key);
    let pubkey = installed.pubkey_bytes().to_vec();
    state
        .lock()
        .map_err(|_| eyre!("state mutex poisoned"))?
        .install_key(root_bytes, addr, pubkey, source_kind);
    root_bytes.zeroize();
    info!(signer = %addr, source = ?source_kind, "keyex oracle key installed; oracle ready");

    handover::spawn_handover_server(Arc::clone(&state), pcr0, cfg.version)?;
    Ok(Box::new(installed))
}
