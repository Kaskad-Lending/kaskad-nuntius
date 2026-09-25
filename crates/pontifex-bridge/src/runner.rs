//! Enclave boot orchestration (Linux only): start the egress forwarder and VSOCK
//! server, wait for the host `configure`, fetch the claim key from the local oracle
//! via RA-TLS (the bridge never generates one), install it, then serve forever.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use eyre::{eyre, Result};
use k256::ecdsa::SigningKey;
use keyex::boot::Role;
use keyex::chain::{Finality, Registry, RpcChainView};
use keyex::policy::FetchKind;
use nitro_common::nsm::Nsm;
use tokio::sync::Mutex;
use tracing::info;

use crate::config::{baked_ancestor_pcrs, baked_igra_rpcs, BakedIdentity};
use crate::nitro::{own_pcr0, NsmAttestor};
use crate::serve::{create_listener, serve_loop, Serve};
use crate::state::BridgeState;
use crate::transport::ProxyTransport;
use keyex::driver::{run_boot, Backoff, BootDeps, Genesis, Installed};
use keyex::peer::RatlsPeerSource;

/// Bridge VSOCK port (CID 17).
const SERVE_PORT: u32 = 5004;
/// Default egress proxy the enclave tunnels JSON-RPC through.
const DEFAULT_PROXY: &str = "http://127.0.0.1:5000";
/// Poll cadence while awaiting host `configure` and between boot ticks.
const BOOT_POLL: Duration = Duration::from_secs(3);

/// A [`Genesis`] that always refuses: the bridge holds only a fetched child key
/// and must never mint one of its own.
struct RefusingGenesis;
impl Genesis for RefusingGenesis {
    fn generate(&self) -> Result<SigningKey> {
        Err(eyre!(
            "bridge never generates a key; it fetches from the oracle"
        ))
    }
}

/// Real back-off between unproductive boot ticks.
struct SleepBackoff;
impl Backoff for SleepBackoff {
    fn wait(&self) -> impl Future<Output = ()> {
        tokio::time::sleep(BOOT_POLL)
    }
}

/// Enclave entry point.
pub async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Egress forwarder first: the reqwest proxy and the RA-TLS peer client both
    // tunnel through 127.0.0.1:5000, so it must be listening before either runs.
    crate::egress::spawn_forwarder().await?;

    // Trust-critical identity + endpoints are baked (fail-loud), never host-supplied.
    let baked = BakedIdentity::from_baked()?;
    let igra_url = baked_igra_rpcs()?
        .into_iter()
        .next()
        .ok_or_else(|| eyre!("no baked Igra RPC"))?;
    let ancestors = baked_ancestor_pcrs()?;
    // The bridge only ever fetches BridgeFromParent, which now accepts a parent
    // solely by baked PCR0. An empty allowlist would reject every oracle and spin
    // forever, so an empty one is a misbuild — refuse to boot, loud.
    if ancestors.is_empty() {
        return Err(eyre!(
            "bridge built with no parent-oracle PCR0 allowlist (PONTIFEX_ANCESTOR_PCRS empty); \
             refusing to boot — it would otherwise accept a child key from any genuine enclave"
        ));
    }

    // One NSM handle per consumer (Nsm is not Clone).
    let pcr0 = own_pcr0(&Nsm::new()?)?;
    let attestor = Arc::new(NsmAttestor::new(Nsm::new()?));

    let version: u64 = option_env!("PONTIFEX_VERSION")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(
            std::env::var("PONTIFEX_PROXY").unwrap_or_else(|_| DEFAULT_PROXY.to_owned()),
        )?)
        // A hung host proxy must never wedge a boot fetch or a claim read forever.
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(4))
        .build()?;

    let state = Arc::new(Mutex::new(BridgeState::new(pcr0, version)));

    // Serve BEFORE boot: the host delivers `configure` (entry, RH RPCs, peers)
    // over this same API, and boot needs it.
    let listener = create_listener(SERVE_PORT)?;
    let serve = Arc::new(Serve {
        state: Arc::clone(&state),
        client: client.clone(),
        igra_url,
        baked,
        attestor,
    });
    let serve_task = tokio::spawn(serve_loop(listener, Arc::clone(&serve)));
    info!(port = SERVE_PORT, "bridge serving; awaiting configure");

    // Wait for the host configuration to land.
    let cfg = loop {
        if let Some(c) = state.lock().await.config().cloned() {
            break c;
        }
        tokio::time::sleep(BOOT_POLL).await;
    };
    info!(entry = %cfg.entry, "configure received; fetching claim key");

    // Fetch the claim key: a child derived by the local oracle from the genesis
    // root. Membership is read at RH finality.
    let rh_url = cfg
        .rh_rpcs
        .first()
        .cloned()
        .ok_or_else(|| eyre!("configure had no RH RPC"))?;
    let rh = ProxyTransport::new(client.clone(), rh_url);
    let view = RpcChainView {
        transport: &rh,
        registry: cfg.entry,
        kind: Registry::Bridge,
        finality: Finality::Tag,
    };

    let peers: Vec<(String, FetchKind)> = cfg
        .oracle_peers
        .iter()
        .map(|o| (o.clone(), FetchKind::BridgeFromParent))
        .collect();
    let deps = BootDeps {
        role: Role::Bridge,
        peers: &peers,
        fresh_approved: false,
    };

    let source = RatlsPeerSource::new(Nsm::new()?, pcr0, ancestors);

    let (key, addr) = match run_boot(&deps, &source, &view, &RefusingGenesis, &SleepBackoff).await {
        Installed::Peer { address, key } => (key, address),
        Installed::Candidate(_) => {
            return Err(eyre!(
                "bridge boot produced a candidate; a fetch-only role must never generate a key"
            ))
        }
    };
    state.lock().await.install_key(key, addr);
    info!(signer = %addr, "claim key installed; bridge ready");

    serve_task
        .await
        .map_err(|e| eyre!("serve task ended: {e}"))?
}
