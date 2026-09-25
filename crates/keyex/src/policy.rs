//! Handover policy for the Pontifex keyex: who an attested enclave hands its
//! key to, and whose attestation a fetching enclave accepts. Pure and
//! deterministic — no NSM, no network, no signature recovery. The caller
//! validates approvals with [`crate::approval::verify_approvals`] first and
//! passes the result in as [`VerifiedApproval`]; PCR0s arrive from an already
//! cryptographically-verified attestation (`nitro_common::verify`).
//!
//! Fail closed: any case not explicitly authorized is a [`KeyDecision::Refuse`].

use crate::approval::{ApprovalMode, ApprovalRequest};

/// Which image is asking. Oracle holds `K_root` and can derive child keys;
/// bridge holds only a child key and never derives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnclaveRole {
    Oracle,
    Bridge,
}

/// Every reason a server refuses to hand its key over. Closed set → real enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffRefusal {
    /// Peer PCR0 differs and no owner approval authorizes it.
    PcrMismatchNoApproval,
    /// A FRESH approval exists but FRESH never hands a live key over.
    FreshNeverHandsOff,
    /// A CHILD approval hit the bridge image, which holds no root to derive from.
    ChildRequestedByBridge,
    /// A CARRY approval exists but its version is not strictly greater than ours.
    VersionNotNewer,
    /// This enclave holds only an unregistered genesis candidate key.
    CandidateKeyNoHandoff,
}

/// The server's decision about its own key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyDecision {
    /// Hand over this enclave's own key (root→root, bridge→bridge, or CARRY upgrade).
    OwnKey,
    /// Derive and hand over `HKDF(K_root, label)` for the given label (oracle only).
    Child([u8; 32]),
    /// Refuse; the payload names the reason.
    Refuse(HandoffRefusal),
}

/// A booting/running image's identity: its measured PCR0 and its baked version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageIdentity {
    pub pcr0: [u8; 48],
    pub version: u64,
}

/// An approval whose owner-quorum signatures the caller has ALREADY checked via
/// [`crate::approval::verify_approvals`]. Construct one ONLY after that returns
/// `Ok`; policy here re-runs no signature recovery. The seam keeps this module
/// pure and free of k256.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedApproval {
    pub pcr0: [u8; 48],
    pub version: u64,
    pub mode: ApprovalMode,
    pub label: [u8; 32],
}

impl VerifiedApproval {
    /// Lift a request into a verified approval. Caller contract: only after
    /// `verify_approvals(req, ..)` returned `Ok` for this exact request.
    pub fn from_request(req: &ApprovalRequest) -> Self {
        VerifiedApproval {
            pcr0: req.pcr0,
            version: req.version,
            mode: req.mode,
            label: req.label,
        }
    }
}

/// Server-side handover decision, run after the client's attestation verified.
///
/// `peer_pcr0` is the client's VERIFIED PCR0. `own_key_is_candidate` is true
/// while this enclave holds only an unregistered genesis key — ENCLAVE.md:
/// "A candidate (genesis) key is handed to nobody and signs nothing until the
/// registry lists it", so it overrides every other branch (checked first).
/// `approvals` are pre-verified owner approvals available to this enclave.
///
/// Matrix (ENCLAVE.md "Handover policy"):
/// - `peer.pcr0 == own.pcr0` → OwnKey;
/// - CARRY approval for peer.pcr0 with `version > own` → OwnKey; not newer → VersionNotNewer;
/// - CHILD approval for peer.pcr0 → Child(label) if Oracle, else ChildRequestedByBridge;
/// - FRESH → FreshNeverHandsOff; otherwise PcrMismatchNoApproval.
pub fn decide_handover(
    own: &ImageIdentity,
    role: EnclaveRole,
    peer_pcr0: &[u8; 48],
    own_key_is_candidate: bool,
    approvals: &[VerifiedApproval],
) -> KeyDecision {
    // Fail closed first: an unregistered candidate key is handed to nobody, not
    // even a same-PCR0 mate, until the registry lists it.
    if own_key_is_candidate {
        return KeyDecision::Refuse(HandoffRefusal::CandidateKeyNoHandoff);
    }

    // Same image inherits the key directly.
    if peer_pcr0 == &own.pcr0 {
        return KeyDecision::OwnKey;
    }

    // Different image: only an owner approval naming this peer.pcr0 authorizes it.
    let mut saw_carry_not_newer = false;
    let mut saw_fresh = false;
    for a in approvals {
        if &a.pcr0 != peer_pcr0 {
            continue;
        }
        match a.mode {
            // Incumbent hands over only to a strictly-newer version (anti-rollback).
            ApprovalMode::Carry => {
                if a.version > own.version {
                    return KeyDecision::OwnKey;
                }
                saw_carry_not_newer = true;
            }
            // Oracle derives the child; the bridge holds no root to derive from.
            ApprovalMode::Child => {
                return match role {
                    EnclaveRole::Oracle => KeyDecision::Child(a.label),
                    EnclaveRole::Bridge => {
                        KeyDecision::Refuse(HandoffRefusal::ChildRequestedByBridge)
                    }
                };
            }
            ApprovalMode::Fresh => saw_fresh = true,
        }
    }

    // Most specific refusal first: rollback beats a bare FRESH beats no approval.
    if saw_carry_not_newer {
        return KeyDecision::Refuse(HandoffRefusal::VersionNotNewer);
    }
    if saw_fresh {
        return KeyDecision::Refuse(HandoffRefusal::FreshNeverHandsOff);
    }
    KeyDecision::Refuse(HandoffRefusal::PcrMismatchNoApproval)
}

/// Anti-rollback dual of [`decide_handover`]. ENCLAVE.md: "an incumbent hands
/// over to `version > own`; a new image requires `version == own`." The
/// incumbent's `>` lives in `decide_handover`; a NEW image validating its own
/// CARRY/CHILD approval uses this `==` so an approval minted for another
/// version cannot be replayed under a different claimed version.
pub fn approval_version_matches_new_image(approval_version: u64, own_version: u64) -> bool {
    approval_version == own_version
}

/// What the fetching (client) side is doing, per ENCLAVE.md boot rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchKind {
    /// Oracle fetching `K_root` from an oracle peer.
    RootFromRoot,
    /// Bridge fetching `k_bridge` from a bridge peer (same image only).
    BridgeFromBridge,
    /// Bridge fetching `k_bridge` from its parent oracle.
    BridgeFromParent,
}

/// Why a client rejects a server's attestation before installing its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientRefusal {
    /// Server PCR0 is neither our own nor a baked ancestor (root→root).
    ServerPcrNotSelfOrAncestor,
    /// Server PCR0 is not our own image (bridge→bridge, same PCR0 only).
    ServerPcrNotSelf,
    /// Server PCR0 is not a baked parent-oracle measurement (bridge→parent).
    ServerPcrNotParentOracle,
}

/// The client's decision about a server's attested identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientDecision {
    Accept,
    Reject(ClientRefusal),
}

/// Client-side acceptance of a server's VERIFIED PCR0 (ENCLAVE.md "Client side").
///
/// - root→root: accept iff `server_pcr0 ∈ {own} ∪ baked_ancestors`;
/// - bridge→bridge: accept iff `server_pcr0 == own` (peers are same-image only);
/// - bridge→parent: accept iff `server_pcr0 ∈ baked_ancestors` — the parent
///   oracle's PCR0 is baked, so a lying host cannot reroute the fetch to a
///   genuine but attacker-controlled enclave whose child key it would then get
///   registered under the bridge's own (correct) PCR0. An empty allowlist
///   accepts no parent (fail-closed): the bridge runner refuses to boot.
///
/// `baked_ancestors` is an input (the image's baked ancestor-PCR0 set); the fn
/// judges identity only, never key freshness — the registry does that at boot.
pub fn client_accepts_server(
    kind: FetchKind,
    own_pcr0: &[u8; 48],
    server_pcr0: &[u8; 48],
    baked_ancestors: &[[u8; 48]],
) -> ClientDecision {
    match kind {
        FetchKind::RootFromRoot => {
            if server_pcr0 == own_pcr0 || baked_ancestors.iter().any(|a| a == server_pcr0) {
                ClientDecision::Accept
            } else {
                ClientDecision::Reject(ClientRefusal::ServerPcrNotSelfOrAncestor)
            }
        }
        FetchKind::BridgeFromBridge => {
            if server_pcr0 == own_pcr0 {
                ClientDecision::Accept
            } else {
                ClientDecision::Reject(ClientRefusal::ServerPcrNotSelf)
            }
        }
        // A lying host can route this fetch to ANY genuine enclave, so pin the
        // parent by its baked PCR0. The registry does NOT gate it: the bridge
        // re-attests whatever child it installs under its own correct PCR0, so
        // registerEnclave would then admit an attacker's key → unbacked mint.
        FetchKind::BridgeFromParent => {
            if baked_ancestors.iter().any(|a| a == server_pcr0) {
                ClientDecision::Accept
            } else {
                ClientDecision::Reject(ClientRefusal::ServerPcrNotParentOracle)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{approval_digest, verify_approvals};
    use alloy_primitives::Address;
    use k256::ecdsa::{
        signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey, VerifyingKey,
    };
    use sha3::{Digest, Keccak256};

    fn v1_label() -> [u8; 32] {
        Keccak256::digest(b"kaskad/pontifex/v1").into()
    }

    fn pcr(fill: u8) -> [u8; 48] {
        [fill; 48]
    }

    fn own(version: u64) -> ImageIdentity {
        ImageIdentity {
            pcr0: pcr(0xAA),
            version,
        }
    }

    fn appr(pcr0: [u8; 48], version: u64, mode: ApprovalMode, label: [u8; 32]) -> VerifiedApproval {
        VerifiedApproval {
            pcr0,
            version,
            mode,
            label,
        }
    }

    // ---- server-side matrix ----

    #[test]
    fn same_pcr0_gets_own_key_both_roles() {
        // peer.pcr0 == own.pcr0 → OwnKey (root→root and bridge→bridge).
        let me = own(5);
        assert_eq!(
            decide_handover(&me, EnclaveRole::Oracle, &me.pcr0, false, &[]),
            KeyDecision::OwnKey
        );
        assert_eq!(
            decide_handover(&me, EnclaveRole::Bridge, &me.pcr0, false, &[]),
            KeyDecision::OwnKey
        );
    }

    #[test]
    fn carry_newer_version_gets_own_key() {
        // CARRY (peer.pcr0, version > own) → OwnKey (image upgrade).
        let me = own(5);
        let peer = pcr(0xBB);
        let a = appr(peer, 6, ApprovalMode::Carry, [0u8; 32]);
        assert_eq!(
            decide_handover(&me, EnclaveRole::Oracle, &peer, false, &[a]),
            KeyDecision::OwnKey
        );
        assert_eq!(
            decide_handover(&me, EnclaveRole::Bridge, &peer, false, &[a]),
            KeyDecision::OwnKey
        );
    }

    #[test]
    fn carry_not_newer_is_version_rollback_refusal() {
        // CARRY at == or < own version → refuse for BOTH roles (anti-rollback:
        // incumbent hands to strictly greater only; the check is role-agnostic).
        let me = own(5);
        let peer = pcr(0xBB);
        for ver in [5u64, 4, 0] {
            let a = appr(peer, ver, ApprovalMode::Carry, [0u8; 32]);
            for role in [EnclaveRole::Oracle, EnclaveRole::Bridge] {
                assert_eq!(
                    decide_handover(&me, role, &peer, false, &[a]),
                    KeyDecision::Refuse(HandoffRefusal::VersionNotNewer),
                    "version {ver} role {role:?} must not carry"
                );
            }
        }
    }

    #[test]
    fn child_derives_for_oracle_refuses_for_bridge() {
        // CHILD → Child(label) on oracle; the bridge holds no root → refuse.
        let me = own(5);
        let peer = pcr(0xCC);
        let label = v1_label();
        let a = appr(peer, 5, ApprovalMode::Child, label);
        assert_eq!(
            decide_handover(&me, EnclaveRole::Oracle, &peer, false, &[a]),
            KeyDecision::Child(label)
        );
        assert_eq!(
            decide_handover(&me, EnclaveRole::Bridge, &peer, false, &[a]),
            KeyDecision::Refuse(HandoffRefusal::ChildRequestedByBridge)
        );
    }

    #[test]
    fn fresh_never_hands_off_either_role() {
        // FRESH approvals never hand a live key over.
        let me = own(5);
        let peer = pcr(0xDD);
        let a = appr(peer, 9, ApprovalMode::Fresh, [0u8; 32]);
        for role in [EnclaveRole::Oracle, EnclaveRole::Bridge] {
            assert_eq!(
                decide_handover(&me, role, &peer, false, &[a]),
                KeyDecision::Refuse(HandoffRefusal::FreshNeverHandsOff)
            );
        }
    }

    #[test]
    fn candidate_key_handed_to_nobody() {
        // A candidate (genesis) key is handed to nobody — overrides same-PCR0,
        // CARRY, and CHILD alike.
        let me = own(5);
        let carry = appr(pcr(0xBB), 6, ApprovalMode::Carry, [0u8; 32]);
        let child = appr(pcr(0xCC), 5, ApprovalMode::Child, v1_label());
        // same-pcr0 peer
        assert_eq!(
            decide_handover(&me, EnclaveRole::Oracle, &me.pcr0, true, &[]),
            KeyDecision::Refuse(HandoffRefusal::CandidateKeyNoHandoff)
        );
        // otherwise-valid CARRY
        assert_eq!(
            decide_handover(&me, EnclaveRole::Oracle, &pcr(0xBB), true, &[carry]),
            KeyDecision::Refuse(HandoffRefusal::CandidateKeyNoHandoff)
        );
        // otherwise-valid CHILD
        assert_eq!(
            decide_handover(&me, EnclaveRole::Oracle, &pcr(0xCC), true, &[child]),
            KeyDecision::Refuse(HandoffRefusal::CandidateKeyNoHandoff)
        );
    }

    #[test]
    fn unknown_peer_no_approval_refuses() {
        let me = own(5);
        assert_eq!(
            decide_handover(&me, EnclaveRole::Oracle, &pcr(0xEE), false, &[]),
            KeyDecision::Refuse(HandoffRefusal::PcrMismatchNoApproval)
        );
    }

    #[test]
    fn approval_for_other_pcr0_ignored() {
        // A valid CARRY for a different image does not authorize this peer.
        let me = own(5);
        let peer = pcr(0xEE);
        let a = appr(pcr(0xBB), 6, ApprovalMode::Carry, [0u8; 32]);
        assert_eq!(
            decide_handover(&me, EnclaveRole::Oracle, &peer, false, &[a]),
            KeyDecision::Refuse(HandoffRefusal::PcrMismatchNoApproval)
        );
    }

    #[test]
    fn anti_rollback_new_image_requires_equal_version() {
        assert!(approval_version_matches_new_image(7, 7));
        assert!(!approval_version_matches_new_image(8, 7));
        assert!(!approval_version_matches_new_image(6, 7));
    }

    // ---- client-side acceptance ----

    #[test]
    fn client_root_accepts_self_and_ancestors_only() {
        let me = pcr(0x11);
        let ancestor = pcr(0x22);
        let stranger = pcr(0x33);
        let ancestors = [ancestor];
        assert_eq!(
            client_accepts_server(FetchKind::RootFromRoot, &me, &me, &ancestors),
            ClientDecision::Accept
        );
        assert_eq!(
            client_accepts_server(FetchKind::RootFromRoot, &me, &ancestor, &ancestors),
            ClientDecision::Accept
        );
        assert_eq!(
            client_accepts_server(FetchKind::RootFromRoot, &me, &stranger, &ancestors),
            ClientDecision::Reject(ClientRefusal::ServerPcrNotSelfOrAncestor)
        );
        // Empty ancestor set: only self accepted.
        assert_eq!(
            client_accepts_server(FetchKind::RootFromRoot, &me, &ancestor, &[]),
            ClientDecision::Reject(ClientRefusal::ServerPcrNotSelfOrAncestor)
        );
    }

    #[test]
    fn client_bridge_peer_same_image_only() {
        let me = pcr(0x11);
        let other = pcr(0x22);
        assert_eq!(
            client_accepts_server(FetchKind::BridgeFromBridge, &me, &me, &[]),
            ClientDecision::Accept
        );
        assert_eq!(
            client_accepts_server(FetchKind::BridgeFromBridge, &me, &other, &[pcr(0x22)]),
            ClientDecision::Reject(ClientRefusal::ServerPcrNotSelf)
        );
    }

    #[test]
    fn client_bridge_parent_accepts_only_baked_oracle_pcr0() {
        // bridge→parent accepts iff the server is a baked parent-oracle image; a
        // genuine but unlisted enclave (host reroute) is rejected, and an empty
        // allowlist accepts no parent — closing the accept-any hole that let an
        // attacker's child key be registered under the bridge's own PCR0.
        let me = pcr(0x11);
        let oracle = pcr(0x22);
        let stranger = pcr(0x99);
        assert_eq!(
            client_accepts_server(FetchKind::BridgeFromParent, &me, &oracle, &[oracle]),
            ClientDecision::Accept
        );
        assert_eq!(
            client_accepts_server(FetchKind::BridgeFromParent, &me, &stranger, &[oracle]),
            ClientDecision::Reject(ClientRefusal::ServerPcrNotParentOracle)
        );
        assert_eq!(
            client_accepts_server(FetchKind::BridgeFromParent, &me, &oracle, &[]),
            ClientDecision::Reject(ClientRefusal::ServerPcrNotParentOracle)
        );
    }

    // ---- seam: real approval verification feeds policy ----

    fn key(seed: u8) -> SigningKey {
        let mut s = [0u8; 32];
        s[31] = seed;
        SigningKey::from_bytes((&s).into()).expect("nonzero seed")
    }

    fn addr(sk: &SigningKey) -> Address {
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        Address::from_slice(&hash[12..])
    }

    fn sign(sk: &SigningKey, req: &ApprovalRequest) -> [u8; 65] {
        let digest = approval_digest(req);
        let (sig, _): (Signature, RecoveryId) = sk.sign_prehash(digest.as_slice()).expect("sign");
        let sig = sig.normalize_s().unwrap_or(sig);
        let vk = sk.verifying_key();
        let mut rec = RecoveryId::from_byte(0).unwrap();
        for cand in [
            RecoveryId::from_byte(0).unwrap(),
            RecoveryId::from_byte(1).unwrap(),
        ] {
            if let Ok(rk) = VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, cand) {
                if &rk == vk {
                    rec = cand;
                    break;
                }
            }
        }
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = 27 + rec.to_byte();
        out
    }

    #[test]
    fn verified_carry_seam_hands_own_key() {
        // Owners sign a CARRY for a newer image; verify_approvals gates it; the
        // lifted VerifiedApproval drives decide_handover to OwnKey.
        let me = own(5);
        let peer = pcr(0xBB);
        let (o1, o2, o3) = (key(1), key(2), key(3));
        let owners = vec![addr(&o1), addr(&o2), addr(&o3)];
        let req = ApprovalRequest {
            pcr0: peer,
            version: 6,
            mode: ApprovalMode::Carry,
            label: [0u8; 32],
            chain_id: 46630,
        };
        let sigs = vec![sign(&o1, &req), sign(&o2, &req), sign(&o3, &req)];
        verify_approvals(&req, &sigs, &owners, 3).expect("quorum verifies");
        let va = VerifiedApproval::from_request(&req);
        assert_eq!(
            decide_handover(&me, EnclaveRole::Oracle, &peer, false, &[va]),
            KeyDecision::OwnKey
        );
    }
}
