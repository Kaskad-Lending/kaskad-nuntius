//! Pure boot state machine shared by both images: peers are hints, the registry
//! is the arbiter. One [`tick`] decides the next action from the peer-sweep
//! outcome and the registry answers ([`ChainView`], the only seam). The oracle
//! may genesis a candidate; the bridge never generates and holds no root.

use alloy_primitives::Address;

use crate::chain::{ChainError, ChainView};

/// Which image is booting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Oracle,
    Bridge,
}

/// What the driver must do after a tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootAction {
    /// Install the fetched peer/parent key with this address; boot is done.
    InstallPeerKey(Address),
    /// Oracle only: NSM-generate a candidate, publish it via attestation, then
    /// poll the registry on later ticks (feed its address back as `candidate`).
    GenerateCandidate,
    /// Oracle only: the held candidate is now registered — install it; done.
    InstallCandidate,
    /// Nothing installable yet; back off and tick again.
    Wait,
}

/// One boot iteration's observable inputs. The driver performed the RA-TLS
/// fetches and any NSM candidate generation; boot sees only addresses.
pub struct Tick<'a> {
    pub role: Role,
    /// Addresses of keys fetched this tick, in priority order (peers, then
    /// parents for the bridge).
    pub sweep: &'a [Address],
    /// Oracle: an `(own_pcr0, own_version, FRESH)` approval verified this boot.
    pub fresh_approved: bool,
    /// Oracle: address of a candidate already generated and published, else None.
    pub candidate: Option<Address>,
}

/// Decide the next boot action. Peers first for both roles: a registered fetched
/// key always wins, so an RPC lying `signerCount == 0` — or a replayed FRESH —
/// cannot make a replacement ignore a live mate, and a registered peer key
/// replaces a pending candidate.
pub async fn tick<V: ChainView>(t: &Tick<'_>, view: &V) -> Result<BootAction, ChainError> {
    for &addr in t.sweep {
        if view.registered(addr).await? {
            return Ok(BootAction::InstallPeerKey(addr));
        }
    }
    match t.role {
        Role::Bridge => {
            // Install the first fetched child even if unregistered: it is an RA-TLS
            // + PCR-pinned deterministic HKDF child (trust anchor), and gating on
            // `registered` here deadlocks boot — no install -> no attestation ->
            // operator can never registerEnclave. claim() rejects an unregistered
            // signer on-chain (KskdEntry:180), so pre-registration install is safe.
            // Never generates and holds no root.
            Ok(match t.sweep.first() {
                Some(&addr) => BootAction::InstallPeerKey(addr),
                None => BootAction::Wait,
            })
        }
        Role::Oracle => {
            if let Some(candidate) = t.candidate {
                if view.registered(candidate).await? {
                    return Ok(BootAction::InstallCandidate);
                }
                return Ok(BootAction::Wait); // keep the candidate, back off
            }
            let eligible = t.fresh_approved || view.signer_count().await?.is_zero();
            Ok(if eligible {
                BootAction::GenerateCandidate
            } else {
                BootAction::Wait
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::future::Future;

    use alloy_primitives::U256;

    struct MockView {
        registered: HashMap<Address, bool>,
        count: U256,
        err: bool,
    }

    impl MockView {
        fn new(count: u64) -> Self {
            Self {
                registered: HashMap::new(),
                count: U256::from(count),
                err: false,
            }
        }
        fn with(mut self, who: Address, ok: bool) -> Self {
            self.registered.insert(who, ok);
            self
        }
        fn failing() -> Self {
            Self {
                registered: HashMap::new(),
                count: U256::ZERO,
                err: true,
            }
        }
    }

    impl ChainView for MockView {
        fn registered(&self, who: Address) -> impl Future<Output = Result<bool, ChainError>> {
            let out = if self.err {
                Err(ChainError::Rpc)
            } else {
                Ok(self.registered.get(&who).copied().unwrap_or(false))
            };
            async move { out }
        }
        fn signer_count(&self) -> impl Future<Output = Result<U256, ChainError>> {
            let out = if self.err {
                Err(ChainError::Rpc)
            } else {
                Ok(self.count)
            };
            async move { out }
        }
    }

    fn addr(b: u8) -> Address {
        Address::from([b; 20])
    }

    fn oracle<'a>(
        sweep: &'a [Address],
        fresh_approved: bool,
        candidate: Option<Address>,
    ) -> Tick<'a> {
        Tick {
            role: Role::Oracle,
            sweep,
            fresh_approved,
            candidate,
        }
    }
    fn bridge(sweep: &[Address]) -> Tick<'_> {
        Tick {
            role: Role::Bridge,
            sweep,
            fresh_approved: false,
            candidate: None,
        }
    }

    #[tokio::test]
    async fn peer_beats_genesis() {
        // Empty registry (would trigger genesis) but a peer hands a registered key.
        let mate = addr(0xAA);
        let view = MockView::new(0).with(mate, true);
        let sweep = [mate];
        let t = oracle(&sweep, false, None);
        assert_eq!(
            tick(&t, &view).await.unwrap(),
            BootAction::InstallPeerKey(mate)
        );
    }

    #[tokio::test]
    async fn rpc_lie_signer_count_zero_cannot_ignore_live_mate() {
        // signerCount==0 is never consulted when a registered mate is present.
        let mate = addr(0xAB);
        let view = MockView::new(0).with(mate, true);
        let sweep = [mate];
        let t = oracle(&sweep, false, None);
        assert_eq!(
            tick(&t, &view).await.unwrap(),
            BootAction::InstallPeerKey(mate)
        );
    }

    #[tokio::test]
    async fn fresh_replay_cannot_ignore_live_mate() {
        let mate = addr(0xAC);
        let view = MockView::new(5).with(mate, true);
        let sweep = [mate];
        let t = oracle(&sweep, true, None); // replayed FRESH present
        assert_eq!(
            tick(&t, &view).await.unwrap(),
            BootAction::InstallPeerKey(mate)
        );
    }

    #[tokio::test]
    async fn oracle_genesis_on_empty_registry() {
        let view = MockView::new(0);
        let t = oracle(&[], false, None);
        assert_eq!(
            tick(&t, &view).await.unwrap(),
            BootAction::GenerateCandidate
        );
    }

    #[tokio::test]
    async fn oracle_genesis_on_fresh_approval_even_if_populated() {
        let view = MockView::new(5); // nonzero, but FRESH is the other trigger
        let t = oracle(&[], true, None);
        assert_eq!(
            tick(&t, &view).await.unwrap(),
            BootAction::GenerateCandidate
        );
    }

    #[tokio::test]
    async fn oracle_waits_when_not_eligible() {
        let view = MockView::new(5);
        let t = oracle(&[], false, None);
        assert_eq!(tick(&t, &view).await.unwrap(), BootAction::Wait);
    }

    #[tokio::test]
    async fn oracle_installs_candidate_once_registered() {
        let cand = addr(0xC0);
        let view = MockView::new(1).with(cand, true);
        let t = oracle(&[], false, Some(cand));
        assert_eq!(tick(&t, &view).await.unwrap(), BootAction::InstallCandidate);
    }

    #[tokio::test]
    async fn oracle_candidate_signs_nothing_until_registered() {
        let cand = addr(0xC1);
        let view = MockView::new(1).with(cand, false); // not yet listed
        let t = oracle(&[], false, Some(cand));
        assert_eq!(tick(&t, &view).await.unwrap(), BootAction::Wait);
    }

    #[tokio::test]
    async fn registered_peer_replaces_pending_candidate() {
        let cand = addr(0xC2);
        let mate = addr(0xC3);
        let view = MockView::new(1).with(cand, false).with(mate, true);
        let sweep = [mate];
        let t = oracle(&sweep, false, Some(cand));
        assert_eq!(
            tick(&t, &view).await.unwrap(),
            BootAction::InstallPeerKey(mate)
        );
    }

    #[tokio::test]
    async fn bridge_never_generates() {
        let view = MockView::new(0); // empty registry does NOT trigger genesis for the bridge
        let t = bridge(&[]);
        assert_eq!(tick(&t, &view).await.unwrap(), BootAction::Wait);
    }

    #[tokio::test]
    async fn bridge_installs_registered_key() {
        let child = addr(0xB0);
        let view = MockView::new(1).with(child, true);
        let sweep = [child];
        let t = bridge(&sweep);
        assert_eq!(
            tick(&t, &view).await.unwrap(),
            BootAction::InstallPeerKey(child)
        );
    }

    #[tokio::test]
    async fn bridge_installs_unregistered_child_to_break_deadlock() {
        // The RA-TLS-verified deterministic child installs pre-registration so
        // get_attestation can bind it; claim() gates it on-chain until registered.
        let child = addr(0xB1);
        let view = MockView::new(1).with(child, false);
        let sweep = [child];
        let t = bridge(&sweep);
        assert_eq!(
            tick(&t, &view).await.unwrap(),
            BootAction::InstallPeerKey(child)
        );
    }

    #[tokio::test]
    async fn first_registered_in_sweep_order_wins() {
        let unreg = addr(0xD0);
        let reg = addr(0xD1);
        let view = MockView::new(1).with(unreg, false).with(reg, true);
        let sweep = [unreg, reg];
        let t = bridge(&sweep);
        assert_eq!(
            tick(&t, &view).await.unwrap(),
            BootAction::InstallPeerKey(reg)
        );
    }

    #[tokio::test]
    async fn chain_error_propagates() {
        let view = MockView::failing();
        let sweep = [addr(0xEE)];
        let t = oracle(&sweep, false, None);
        assert_eq!(tick(&t, &view).await, Err(ChainError::Rpc));
    }
}
