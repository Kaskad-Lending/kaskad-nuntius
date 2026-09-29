//! Enclave boot orchestration (Linux only): start the egress forwarder and VSOCK
//! server, wait for the host `configure`, fetch the claim key from the local oracle
//! via RA-TLS (the bridge never generates one), install it, then serve forever.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use eyre::{eyre, Result};
use k256::ecdsa::SigningKey;
use keyex::boot::Role;
use keyex::chain::{EthTransport, Finality, Registry, RpcChainView};
use keyex::policy::FetchKind;
use nitro_common::nsm::Nsm;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::config::{baked_ancestor_pcrs, baked_igra_rpcs, BakedIdentity};
use crate::nitro::{own_pcr0, NsmAttestor};
use crate::serve::{create_listener, serve_loop, Serve};
use crate::state::BridgeState;
use crate::transport::ProxyTransport;
use keyex::driver::{step, Backoff, BootDeps, BootLoopState, Genesis, Installed, StepOutcome};
use keyex::peer::{PeerSource, RatlsPeerSource};

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

/// Refresh accepted endpoint hints each tick; freeze them with the installed key.
async fn boot_with_config<P, T, F, B>(
    state: &Mutex<BridgeState>,
    key_installed: &AtomicBool,
    loop_state: &mut BootLoopState,
    source: &P,
    transport: F,
    backoff: &B,
) -> Result<()>
where
    P: PeerSource,
    T: EthTransport,
    F: Fn(&str) -> T,
    B: Backoff,
{
    loop {
        let cfg = state.lock().await.config().cloned();
        let cfg = match cfg {
            Some(cfg) if !cfg.rh_rpcs.is_empty() => cfg,
            _ => {
                backoff.wait().await;
                continue;
            }
        };
        let rh = transport(&cfg.rh_rpcs[0]);
        let view = RpcChainView {
            transport: &rh,
            registry: cfg.entry,
            kind: Registry::Bridge,
            finality: Finality::Tag,
        };
        let peers: Vec<_> = cfg
            .oracle_peers
            .iter()
            .map(|o| (o.clone(), FetchKind::BridgeFromParent))
            .collect();
        let deps = BootDeps {
            role: Role::Bridge,
            peers: &peers,
            fresh_approved: false,
        };

        match step(loop_state, &deps, source, &view, &RefusingGenesis).await {
            Ok(StepOutcome::Done(Installed::Peer { address, key })) => {
                let mut state = state.lock().await;
                // A Configure accepted during this tick must be tried before install.
                if state.config().is_some_and(|current| {
                    current.rh_rpcs == cfg.rh_rpcs && current.oracle_peers == cfg.oracle_peers
                }) {
                    state.install_key(key, address);
                    key_installed.store(true, Ordering::Release);
                    info!(signer = %address, "claim key installed; bridge ready");
                    return Ok(());
                }
            }
            Ok(StepOutcome::Done(Installed::Candidate(_))) => {
                return Err(eyre!(
                    "bridge boot produced a candidate; a fetch-only role must never generate a key"
                ));
            }
            Ok(StepOutcome::Continue) => {}
            Err(e) => warn!(error = %e, "boot tick failed; backing off"),
        }
        backoff.wait().await;
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
        key_installed: AtomicBool::new(false),
        client: client.clone(),
        igra_url,
        baked,
        attestor,
    });
    let serve_task = tokio::spawn(serve_loop(listener, Arc::clone(&serve)));
    info!(port = SERVE_PORT, "bridge serving; awaiting configure");

    let source = RatlsPeerSource::new(Nsm::new()?, pcr0, ancestors);
    let mut loop_state = BootLoopState::default();
    boot_with_config(
        &state,
        &serve.key_installed,
        &mut loop_state,
        &source,
        |url| ProxyTransport::new(client.clone(), url),
        &SleepBackoff,
    )
    .await?;

    serve_task
        .await
        .map_err(|e| eyre!("serve task ended: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use alloy_primitives::{hex, Address, U256};
    use keyex::api::{Ack, BootState, BridgeRequest};
    use keyex::chain::{ChainError, ChainView};
    use keyex::peer::FetchedKey;
    use serde_json::{json, Value};

    use crate::handler::{handle, Attestor, HandlerCtx};

    const GOOD_RPC: &str = "https://available.invalid";
    const BAD_RPC: &str = "https://unavailable.invalid";
    const LOCAL_PARENT: &str = "127.0.0.1:8443";
    const ABSENT_PARENT: &str = "absent.invalid:8443";
    const CHILD_SEED: [u8; 32] = [0x42; 32];

    fn baked() -> BakedIdentity {
        BakedIdentity {
            exit: Address::from([0xee; 20]),
            kskd: Address::from([0xdd; 20]),
            entry: Address::from([0x11; 20]),
            chain_id: 46630,
        }
    }

    fn state() -> Mutex<BridgeState> {
        Mutex::new(BridgeState::new([0xab; 48], 7))
    }

    fn child_address() -> Address {
        FetchedKey::from_bytes(&CHILD_SEED).unwrap().address
    }

    struct NoAttestation;
    impl Attestor for NoAttestation {
        fn attest(&self, _: Option<Vec<u8>>, _: Vec<u8>) -> Option<Vec<u8>> {
            panic!("configure must not attest");
        }
    }

    async fn configure(state: &Mutex<BridgeState>, rpcs: &[&str], peers: &[&str]) -> bool {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let baked = baked();
        let ctx = HandlerCtx {
            client: &client,
            igra_url: "https://igra.invalid",
            baked: &baked,
            enclave_now: 0,
        };
        let mut state = state.lock().await;
        let reply = handle(
            BridgeRequest::Configure {
                entry: baked.entry.to_string(),
                rh_rpcs: rpcs.iter().map(|s| (*s).to_owned()).collect(),
                oracle_peers: peers.iter().map(|s| (*s).to_owned()).collect(),
            },
            &mut state,
            &ctx,
            &NoAttestation,
        )
        .await;
        serde_json::from_slice::<Ack>(&reply).unwrap().ok
    }

    #[derive(Clone, Copy)]
    enum ParentState {
        Offline,
        AwaitingChildApproval,
        Ready,
    }

    struct LocalParent {
        state: Cell<ParentState>,
        calls: RefCell<Vec<String>>,
    }

    impl LocalParent {
        fn new(state: ParentState) -> Self {
            Self {
                state: Cell::new(state),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl PeerSource for LocalParent {
        async fn fetch(&self, endpoint: &str, kind: FetchKind) -> Result<Option<FetchedKey>> {
            assert_eq!(kind, FetchKind::BridgeFromParent);
            self.calls.borrow_mut().push(endpoint.to_owned());
            if endpoint != LOCAL_PARENT {
                return Err(eyre!("parent unavailable"));
            }
            match self.state.get() {
                ParentState::Offline => Err(eyre!("local oracle not ready")),
                ParentState::AwaitingChildApproval => Ok(None),
                ParentState::Ready => FetchedKey::from_bytes(&CHILD_SEED).map(Some),
            }
        }
    }

    #[derive(Default)]
    struct LocalChain {
        endpoints: RefCell<Vec<String>>,
        reads: Cell<usize>,
    }

    impl LocalChain {
        fn transport(&self, url: &str) -> LocalRpc<'_> {
            self.endpoints.borrow_mut().push(url.to_owned());
            LocalRpc {
                chain: self,
                available: url == GOOD_RPC,
            }
        }
    }

    struct LocalRpc<'a> {
        chain: &'a LocalChain,
        available: bool,
    }

    impl EthTransport for LocalRpc<'_> {
        async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
            self.chain.reads.set(self.chain.reads.get() + 1);
            if !self.available {
                return Err(eyre!("RPC unavailable"));
            }
            match method {
                "eth_getBlockByNumber" => {
                    assert_eq!(params, json!(["finalized", false]));
                    Ok(json!({
                        "number": "0x2a",
                        "hash": hex::encode_prefixed([0x55; 32]),
                        "timestamp": "0x1",
                    }))
                }
                "eth_call" => {
                    let mut data = vec![0xba, 0x6f, 0x8b, 0x0e];
                    data.extend_from_slice(&[0; 12]);
                    data.extend_from_slice(child_address().as_slice());
                    assert_eq!(
                        params,
                        json!([
                            {"to": baked().entry.to_string(), "data": hex::encode_prefixed(data)},
                            "0x2a"
                        ])
                    );
                    // The pinned child may install before its on-chain enrollment.
                    Ok(json!(hex::encode_prefixed([0; 32])))
                }
                _ => panic!("unexpected boot RPC method"),
            }
        }
    }

    enum Change {
        Keep,
        Configure {
            rpc: &'static str,
            peers: &'static [&'static str],
        },
        Parent(ParentState),
    }

    struct ScriptedBackoff<'a> {
        state: &'a Mutex<BridgeState>,
        key_installed: &'a AtomicBool,
        parent: &'a LocalParent,
        changes: RefCell<VecDeque<Change>>,
        waits: Cell<usize>,
    }

    impl<'a> ScriptedBackoff<'a> {
        fn new(
            state: &'a Mutex<BridgeState>,
            key_installed: &'a AtomicBool,
            parent: &'a LocalParent,
            changes: impl IntoIterator<Item = Change>,
        ) -> Self {
            Self {
                state,
                key_installed,
                parent,
                changes: RefCell::new(changes.into_iter().collect()),
                waits: Cell::new(0),
            }
        }

        fn assert_waits(&self, expected: usize) {
            assert_eq!(self.waits.get(), expected);
            assert!(self.changes.borrow().is_empty());
        }
    }

    impl Backoff for ScriptedBackoff<'_> {
        async fn wait(&self) {
            assert!(!self.key_installed.load(Ordering::Acquire));
            {
                let state = self
                    .state
                    .try_lock()
                    .expect("backoff must release the state lock");
                assert_eq!(state.boot(), BootState::Fetching);
                assert!(state.key().is_none());
            }
            self.waits.set(self.waits.get() + 1);
            let change = self
                .changes
                .borrow_mut()
                .pop_front()
                .expect("unexpected retry");
            match change {
                Change::Keep => {}
                Change::Configure { rpc, peers } => {
                    assert!(configure(self.state, &[rpc], peers).await);
                }
                Change::Parent(next) => self.parent.state.set(next),
            }
        }
    }

    fn assert_ready(state: &Mutex<BridgeState>, key_installed: &AtomicBool) {
        assert!(key_installed.load(Ordering::Acquire));
        let state = state.try_lock().unwrap();
        assert_eq!(state.boot(), BootState::Ready);
        assert_eq!(state.signer(), Some(child_address()));
        assert_eq!(
            keyex::sig::address_from_key(state.key().unwrap().verifying_key()),
            child_address()
        );
        let cfg = state.config().unwrap();
        assert_eq!(cfg.entry, baked().entry);
        assert_eq!(cfg.exit, baked().exit);
        assert_eq!(cfg.kskd, baked().kskd);
        assert_eq!(cfg.chain_id, baked().chain_id);
        assert_eq!(state.pcr0(), &[0xab; 48]);
        assert_eq!(state.version(), 7);
    }

    #[tokio::test]
    async fn unavailable_initial_rpc_can_be_corrected_before_install() {
        let state = state();
        let key_installed = AtomicBool::new(false);
        assert!(configure(&state, &[BAD_RPC], &[LOCAL_PARENT]).await);
        let parent = LocalParent::new(ParentState::Ready);
        let chain = LocalChain::default();
        let backoff = ScriptedBackoff::new(
            &state,
            &key_installed,
            &parent,
            [Change::Configure {
                rpc: GOOD_RPC,
                peers: &[LOCAL_PARENT],
            }],
        );
        boot_with_config(
            &state,
            &key_installed,
            &mut BootLoopState::default(),
            &parent,
            |url| chain.transport(url),
            &backoff,
        )
        .await
        .unwrap();

        backoff.assert_waits(1);
        assert_eq!(*chain.endpoints.borrow(), [BAD_RPC, GOOD_RPC]);
        assert_eq!(*parent.calls.borrow(), [LOCAL_PARENT, LOCAL_PARENT]);
        assert_ready(&state, &key_installed);
    }

    #[tokio::test]
    async fn newly_configured_parent_is_swept_on_the_next_retry() {
        let state = state();
        let key_installed = AtomicBool::new(false);
        assert!(configure(&state, &[GOOD_RPC], &[ABSENT_PARENT]).await);
        let parent = LocalParent::new(ParentState::Ready);
        let chain = LocalChain::default();
        let backoff = ScriptedBackoff::new(
            &state,
            &key_installed,
            &parent,
            [Change::Configure {
                rpc: GOOD_RPC,
                peers: &[ABSENT_PARENT, LOCAL_PARENT],
            }],
        );
        boot_with_config(
            &state,
            &key_installed,
            &mut BootLoopState::default(),
            &parent,
            |url| chain.transport(url),
            &backoff,
        )
        .await
        .unwrap();

        backoff.assert_waits(1);
        assert_eq!(
            *parent.calls.borrow(),
            [ABSENT_PARENT, ABSENT_PARENT, LOCAL_PARENT]
        );
        assert_eq!(*chain.endpoints.borrow(), [GOOD_RPC, GOOD_RPC]);
        assert_ready(&state, &key_installed);
    }

    #[tokio::test]
    async fn loopback_parent_can_start_and_receive_child_approval_later() {
        let state = state();
        let key_installed = AtomicBool::new(false);
        assert!(configure(&state, &[GOOD_RPC], &[LOCAL_PARENT]).await);
        let parent = LocalParent::new(ParentState::Offline);
        let chain = LocalChain::default();
        let backoff = ScriptedBackoff::new(
            &state,
            &key_installed,
            &parent,
            [
                Change::Parent(ParentState::AwaitingChildApproval),
                Change::Keep,
                Change::Parent(ParentState::Ready),
            ],
        );
        boot_with_config(
            &state,
            &key_installed,
            &mut BootLoopState::default(),
            &parent,
            |url| chain.transport(url),
            &backoff,
        )
        .await
        .unwrap();

        backoff.assert_waits(3);
        assert_eq!(*parent.calls.borrow(), [LOCAL_PARENT; 4]);
        assert_eq!(chain.reads.get(), 2);
        assert_ready(&state, &key_installed);
    }

    #[tokio::test]
    async fn missing_config_and_empty_peer_updates_back_off_until_usable() {
        let state = state();
        let key_installed = AtomicBool::new(false);
        assert!(!configure(&state, &[], &[LOCAL_PARENT]).await);
        assert!(state.lock().await.config().is_none());
        let parent = LocalParent::new(ParentState::Ready);
        let chain = LocalChain::default();
        let backoff = ScriptedBackoff::new(
            &state,
            &key_installed,
            &parent,
            [
                Change::Keep,
                Change::Configure {
                    rpc: GOOD_RPC,
                    peers: &[],
                },
                Change::Keep,
                Change::Configure {
                    rpc: GOOD_RPC,
                    peers: &[LOCAL_PARENT],
                },
            ],
        );
        boot_with_config(
            &state,
            &key_installed,
            &mut BootLoopState::default(),
            &parent,
            |url| chain.transport(url),
            &backoff,
        )
        .await
        .unwrap();

        backoff.assert_waits(4);
        assert_eq!(*chain.endpoints.borrow(), [GOOD_RPC; 3]);
        assert_eq!(*parent.calls.borrow(), [LOCAL_PARENT]);
        assert_eq!(chain.reads.get(), 2);
        assert_ready(&state, &key_installed);
    }

    #[tokio::test]
    async fn retries_preserve_the_existing_boot_loop_state() {
        struct SentinelGenesis(Cell<usize>);
        impl Genesis for SentinelGenesis {
            fn generate(&self) -> Result<SigningKey> {
                self.0.set(self.0.get() + 1);
                Ok(SigningKey::from_bytes((&[0x31; 32]).into())?)
            }
        }
        struct SentinelView;
        impl ChainView for SentinelView {
            async fn registered(&self, _: Address) -> Result<bool, ChainError> {
                Ok(true)
            }
            async fn signer_count(&self) -> Result<U256, ChainError> {
                panic!("sentinel uses explicit local approval");
            }
        }

        // A local sentinel candidate makes a reset observable; the bridge cannot install it.
        let parent = LocalParent::new(ParentState::Ready);
        let genesis = SentinelGenesis(Cell::new(0));
        let sentinel_deps = BootDeps {
            role: Role::Oracle,
            peers: &[],
            fresh_approved: true,
        };
        let mut loop_state = BootLoopState::default();
        assert!(matches!(
            step(
                &mut loop_state,
                &sentinel_deps,
                &parent,
                &SentinelView,
                &genesis
            )
            .await
            .unwrap(),
            StepOutcome::Continue
        ));
        let state = state();
        let key_installed = AtomicBool::new(false);
        let chain = LocalChain::default();
        let backoff = ScriptedBackoff::new(
            &state,
            &key_installed,
            &parent,
            [
                Change::Configure {
                    rpc: BAD_RPC,
                    peers: &[LOCAL_PARENT],
                },
                Change::Configure {
                    rpc: GOOD_RPC,
                    peers: &[LOCAL_PARENT],
                },
            ],
        );
        boot_with_config(
            &state,
            &key_installed,
            &mut loop_state,
            &parent,
            |url| chain.transport(url),
            &backoff,
        )
        .await
        .unwrap();
        backoff.assert_waits(2);
        assert_ready(&state, &key_installed);

        let outcome = step(
            &mut loop_state,
            &sentinel_deps,
            &parent,
            &SentinelView,
            &genesis,
        )
        .await
        .unwrap();
        let StepOutcome::Done(Installed::Candidate(key)) = outcome else {
            panic!("retry replaced the supplied boot loop state");
        };
        let expected = SigningKey::from_bytes((&[0x31; 32]).into()).unwrap();
        assert_eq!(key.verifying_key(), expected.verifying_key());
        assert_eq!(genesis.0.get(), 1);
        assert!(RefusingGenesis.generate().is_err());
    }

    #[tokio::test]
    async fn configure_accepted_during_a_tick_is_tried_before_install() {
        struct ReconfiguringParent<'a> {
            state: &'a Mutex<BridgeState>,
            parent: &'a LocalParent,
            changed: Cell<bool>,
        }
        impl PeerSource for ReconfiguringParent<'_> {
            async fn fetch(&self, endpoint: &str, kind: FetchKind) -> Result<Option<FetchedKey>> {
                if !self.changed.replace(true) {
                    assert!(configure(self.state, &[BAD_RPC], &[LOCAL_PARENT]).await);
                }
                self.parent.fetch(endpoint, kind).await
            }
        }

        let state = state();
        let key_installed = AtomicBool::new(false);
        assert!(configure(&state, &[GOOD_RPC], &[LOCAL_PARENT]).await);
        let parent = LocalParent::new(ParentState::Ready);
        let source = ReconfiguringParent {
            state: &state,
            parent: &parent,
            changed: Cell::new(false),
        };
        let chain = LocalChain::default();
        let backoff = ScriptedBackoff::new(
            &state,
            &key_installed,
            &parent,
            [
                Change::Keep,
                Change::Configure {
                    rpc: GOOD_RPC,
                    peers: &[LOCAL_PARENT],
                },
            ],
        );
        boot_with_config(
            &state,
            &key_installed,
            &mut BootLoopState::default(),
            &source,
            |url| chain.transport(url),
            &backoff,
        )
        .await
        .unwrap();

        backoff.assert_waits(2);
        assert_eq!(*chain.endpoints.borrow(), [GOOD_RPC, BAD_RPC, GOOD_RPC]);
        assert_ready(&state, &key_installed);
    }

    #[tokio::test]
    async fn configure_is_rejected_after_the_loop_installs_the_key() {
        let state = state();
        let key_installed = AtomicBool::new(false);
        assert!(configure(&state, &[GOOD_RPC], &[LOCAL_PARENT]).await);
        let parent = LocalParent::new(ParentState::Ready);
        let chain = LocalChain::default();
        let backoff = ScriptedBackoff::new(&state, &key_installed, &parent, []);
        boot_with_config(
            &state,
            &key_installed,
            &mut BootLoopState::default(),
            &parent,
            |url| chain.transport(url),
            &backoff,
        )
        .await
        .unwrap();

        backoff.assert_waits(0);
        assert!(!configure(&state, &[BAD_RPC], &[ABSENT_PARENT]).await);
        assert_ready(&state, &key_installed);
        let state = state.lock().await;
        let cfg = state.config().unwrap();
        assert_eq!(cfg.rh_rpcs, [GOOD_RPC]);
        assert_eq!(cfg.oracle_peers, [LOCAL_PARENT]);
    }
}
