//! Boot driver: fetch peer keys, ask the pure [`crate::boot::tick`] rules what to
//! do, and act on the answer (install a peer key, hold an NSM-generated
//! candidate, or back off). [`step`] is one iteration and carries all the logic;
//! [`run_boot`] is the thin retry loop an enclave runs until it has a key.

use std::future::Future;

use crate::boot::{self, BootAction, Role, Tick};
use crate::chain::ChainView;
use crate::policy::FetchKind;
use alloy_primitives::Address;
use eyre::{eyre, Result};
use k256::ecdsa::SigningKey;

use crate::peer::PeerSource;

/// NSM candidate-key generation (oracle only). Sync — a single hardware draw.
pub trait Genesis {
    fn generate(&self) -> Result<SigningKey>;
}

/// Back-off between unproductive boot ticks.
pub trait Backoff {
    fn wait(&self) -> impl Future<Output = ()>;
}

/// The endpoints to sweep each tick, each with the fetch kind it answers.
pub struct BootDeps<'a> {
    pub role: Role,
    pub peers: &'a [(String, FetchKind)],
    pub fresh_approved: bool,
}

/// Carried across ticks: an oracle candidate already generated and published,
/// awaiting registration.
#[derive(Default)]
pub struct BootLoopState {
    candidate: Option<(Address, SigningKey)>,
}

/// The resolved boot key and how it was obtained.
pub enum Installed {
    Peer { address: Address, key: SigningKey },
    Candidate(SigningKey),
}

/// One tick's outcome.
pub enum StepOutcome {
    Continue,
    Done(Installed),
}

/// Run one boot iteration: sweep peers, consult the rules, act. A per-peer fetch
/// fault is logged and treated as "no key" (try the rest / retry); a registry
/// read fault propagates so [`run_boot`] backs off and retries.
pub async fn step<P: PeerSource, V: ChainView, G: Genesis>(
    loop_state: &mut BootLoopState,
    deps: &BootDeps<'_>,
    source: &P,
    view: &V,
    genesis: &G,
) -> Result<StepOutcome> {
    let mut fetched = Vec::new();
    // Log by peer index only: the endpoint and the fetch error are host/peer-
    // supplied and must never be echoed into host-readable enclave logs (R-8).
    for (idx, (endpoint, kind)) in deps.peers.iter().enumerate() {
        match source.fetch(endpoint, *kind).await {
            Ok(Some(fk)) => fetched.push(fk),
            Ok(None) => {}
            Err(_) => tracing::warn!(peer = idx, "boot peer fetch failed"),
        }
    }
    let sweep: Vec<Address> = fetched.iter().map(|f| f.address).collect();
    let candidate = loop_state.candidate.as_ref().map(|(a, _)| *a);

    let t = Tick {
        role: deps.role,
        sweep: &sweep,
        fresh_approved: deps.fresh_approved,
        candidate,
    };
    // ChainError carries no std::error::Error impl; map it into the eyre channel
    // so run_boot backs off and retries on a registry read fault.
    let action = boot::tick(&t, view)
        .await
        .map_err(|e| eyre!("registry read during boot: {e:?}"))?;
    match action {
        BootAction::InstallPeerKey(addr) => {
            let fk = fetched
                .into_iter()
                .find(|f| f.address == addr)
                .ok_or_else(|| eyre!("boot chose an address absent from the sweep"))?;
            Ok(StepOutcome::Done(Installed::Peer {
                address: fk.address,
                key: fk.key,
            }))
        }
        BootAction::GenerateCandidate => {
            let key = genesis.generate()?;
            let addr = crate::sig::address_from_key(key.verifying_key());
            loop_state.candidate = Some((addr, key));
            Ok(StepOutcome::Continue)
        }
        BootAction::InstallCandidate => {
            let (_, key) = loop_state
                .candidate
                .take()
                .ok_or_else(|| eyre!("install-candidate with no held candidate"))?;
            Ok(StepOutcome::Done(Installed::Candidate(key)))
        }
        BootAction::Wait => Ok(StepOutcome::Continue),
    }
}

/// Drive [`step`] until it installs a key, backing off between unproductive
/// ticks and after transient faults. Never gives up — the enclave has no key
/// until the registry lists one.
pub async fn run_boot<P: PeerSource, V: ChainView, G: Genesis, B: Backoff>(
    deps: &BootDeps<'_>,
    source: &P,
    view: &V,
    genesis: &G,
    backoff: &B,
) -> Installed {
    let mut loop_state = BootLoopState::default();
    loop {
        match step(&mut loop_state, deps, source, view, genesis).await {
            Ok(StepOutcome::Done(installed)) => return installed,
            Ok(StepOutcome::Continue) => backoff.wait().await,
            Err(e) => {
                tracing::warn!(error = %e, "boot tick failed; backing off");
                backoff.wait().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};

    use alloy_primitives::U256;

    use crate::peer::FetchedKey;

    // ---- mock ChainView (mirror of crate::boot's test view) ----
    struct MockView {
        registered: HashMap<Address, bool>,
        count: U256,
    }
    impl MockView {
        fn new(count: u64) -> Self {
            Self {
                registered: HashMap::new(),
                count: U256::from(count),
            }
        }
        fn with(mut self, who: Address, ok: bool) -> Self {
            self.registered.insert(who, ok);
            self
        }
    }
    impl ChainView for MockView {
        fn registered(
            &self,
            who: Address,
        ) -> impl Future<Output = Result<bool, crate::chain::ChainError>> {
            let out = Ok(self.registered.get(&who).copied().unwrap_or(false));
            async move { out }
        }
        fn signer_count(&self) -> impl Future<Output = Result<U256, crate::chain::ChainError>> {
            let out = Ok(self.count);
            async move { out }
        }
    }

    // ---- mock PeerSource: endpoint -> raw key seed ----
    struct MockPeer {
        keys: HashMap<String, [u8; 32]>,
    }
    impl MockPeer {
        fn none() -> Self {
            Self {
                keys: HashMap::new(),
            }
        }
        fn with(mut self, endpoint: &str, seed: [u8; 32]) -> Self {
            self.keys.insert(endpoint.to_owned(), seed);
            self
        }
    }
    impl PeerSource for MockPeer {
        fn fetch(
            &self,
            endpoint: &str,
            _kind: FetchKind,
        ) -> impl Future<Output = Result<Option<FetchedKey>>> {
            let out = match self.keys.get(endpoint) {
                Some(seed) => FetchedKey::from_bytes(seed).map(Some),
                None => Ok(None),
            };
            async move { out }
        }
    }

    // ---- mock Genesis ----
    struct CountingGenesis {
        seed: [u8; 32],
        calls: AtomicU32,
    }
    impl CountingGenesis {
        fn new(seed: [u8; 32]) -> Self {
            Self {
                seed,
                calls: AtomicU32::new(0),
            }
        }
    }
    impl Genesis for CountingGenesis {
        fn generate(&self) -> Result<SigningKey> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(SigningKey::from_bytes((&self.seed).into())?)
        }
    }
    struct PanicGenesis;
    impl Genesis for PanicGenesis {
        fn generate(&self) -> Result<SigningKey> {
            panic!("genesis must never be called for this role");
        }
    }
    struct NoBackoff;
    impl Backoff for NoBackoff {
        async fn wait(&self) {}
    }

    fn addr_of(seed: [u8; 32]) -> Address {
        crate::sig::address_from_key(
            SigningKey::from_bytes((&seed).into())
                .unwrap()
                .verifying_key(),
        )
    }

    fn deps<'a>(role: Role, peers: &'a [(String, FetchKind)], fresh: bool) -> BootDeps<'a> {
        BootDeps {
            role,
            peers,
            fresh_approved: fresh,
        }
    }

    #[tokio::test]
    async fn bridge_installs_registered_peer_and_never_generates() {
        let seed = [0xB0; 32];
        let addr = addr_of(seed);
        let source = MockPeer::none().with("sib", seed);
        let view = MockView::new(1).with(addr, true);
        let peers = [("sib".to_owned(), FetchKind::BridgeFromBridge)];
        let mut st = BootLoopState::default();
        let out = step(
            &mut st,
            &deps(Role::Bridge, &peers, false),
            &source,
            &view,
            &PanicGenesis,
        )
        .await
        .unwrap();
        match out {
            StepOutcome::Done(Installed::Peer { address, .. }) => assert_eq!(address, addr),
            _ => panic!("expected a peer install"),
        }
    }

    #[tokio::test]
    async fn bridge_installs_unregistered_child_and_never_generates() {
        // A fetched-but-unregistered RA-TLS child installs to break the genesis
        // deadlock; PanicGenesis proves the bridge still never generates a root.
        let seed = [0xB1; 32];
        let addr = addr_of(seed);
        let source = MockPeer::none().with("parent", seed);
        let view = MockView::new(1).with(addr, false); // fetched, not yet registered
        let peers = [("parent".to_owned(), FetchKind::BridgeFromParent)];
        let mut st = BootLoopState::default();
        let out = step(
            &mut st,
            &deps(Role::Bridge, &peers, false),
            &source,
            &view,
            &PanicGenesis,
        )
        .await
        .unwrap();
        match out {
            StepOutcome::Done(Installed::Peer { address, .. }) => assert_eq!(address, addr),
            _ => panic!("expected a peer install"),
        }
    }

    #[tokio::test]
    async fn oracle_generates_then_installs_candidate() {
        let cand_seed = [0xC0; 32];
        let cand_addr = addr_of(cand_seed);
        let genesis = CountingGenesis::new(cand_seed);
        let source = MockPeer::none();
        let peers: [(String, FetchKind); 0] = [];

        // Tick 1: empty registry → generate + hold the candidate.
        let mut st = BootLoopState::default();
        let view0 = MockView::new(0);
        let out = step(
            &mut st,
            &deps(Role::Oracle, &peers, false),
            &source,
            &view0,
            &genesis,
        )
        .await
        .unwrap();
        assert!(matches!(out, StepOutcome::Continue));
        assert_eq!(genesis.calls.load(Ordering::SeqCst), 1);
        assert!(st.candidate.is_some());

        // Tick 2: the candidate is now registered → install it, no re-generation.
        let view1 = MockView::new(1).with(cand_addr, true);
        let out = step(
            &mut st,
            &deps(Role::Oracle, &peers, false),
            &source,
            &view1,
            &genesis,
        )
        .await
        .unwrap();
        match out {
            StepOutcome::Done(Installed::Candidate(key)) => {
                assert_eq!(crate::sig::address_from_key(key.verifying_key()), cand_addr);
            }
            _ => panic!("expected candidate install"),
        }
        assert_eq!(
            genesis.calls.load(Ordering::SeqCst),
            1,
            "candidate not regenerated"
        );
    }

    #[tokio::test]
    async fn oracle_registered_peer_beats_pending_candidate() {
        let cand_seed = [0xC1; 32];
        let cand_addr = addr_of(cand_seed);
        let mate_seed = [0xC2; 32];
        let mate_addr = addr_of(mate_seed);
        let genesis = CountingGenesis::new(cand_seed);

        // Pre-load a held candidate.
        let mut st = BootLoopState {
            candidate: Some((
                cand_addr,
                SigningKey::from_bytes((&cand_seed).into()).unwrap(),
            )),
        };
        // A registered mate appears in the sweep; candidate is not registered.
        let source = MockPeer::none().with("mate", mate_seed);
        let view = MockView::new(1)
            .with(mate_addr, true)
            .with(cand_addr, false);
        let peers = [("mate".to_owned(), FetchKind::BridgeFromBridge)];
        let out = step(
            &mut st,
            &deps(Role::Oracle, &peers, false),
            &source,
            &view,
            &genesis,
        )
        .await
        .unwrap();
        match out {
            StepOutcome::Done(Installed::Peer { address, .. }) => assert_eq!(address, mate_addr),
            _ => panic!("registered peer must beat the pending candidate"),
        }
        assert_eq!(genesis.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn run_boot_loops_until_candidate_registers() {
        // A view that reports the candidate registered only on its 2nd read,
        // proving run_boot backs off and re-ticks to a terminal install.
        struct FlipView {
            reads: AtomicU32,
            cand: Address,
        }
        impl ChainView for FlipView {
            fn registered(
                &self,
                who: Address,
            ) -> impl Future<Output = Result<bool, crate::chain::ChainError>> {
                let n = self.reads.fetch_add(1, Ordering::SeqCst);
                let out = Ok(who == self.cand && n >= 1);
                async move { out }
            }
            async fn signer_count(&self) -> Result<U256, crate::chain::ChainError> {
                Ok(U256::ZERO)
            }
        }
        let cand_seed = [0xD0; 32];
        let cand_addr = addr_of(cand_seed);
        let genesis = CountingGenesis::new(cand_seed);
        let source = MockPeer::none();
        let peers: [(String, FetchKind); 0] = [];
        let view = FlipView {
            reads: AtomicU32::new(0),
            cand: cand_addr,
        };

        let installed = run_boot(
            &deps(Role::Oracle, &peers, false),
            &source,
            &view,
            &genesis,
            &NoBackoff,
        )
        .await;
        match installed {
            Installed::Candidate(key) => {
                assert_eq!(crate::sig::address_from_key(key.verifying_key()), cand_addr);
            }
            _ => panic!("expected candidate install"),
        }
    }
}
