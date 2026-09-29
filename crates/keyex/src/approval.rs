//! EIP-712 owner-quorum approval verification for keyex image transitions.
//! Domain = { name: "Kaskad Keyex", version: "1", chainId }, no verifyingContract, no salt.

use std::borrow::Cow;

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{sol, Eip712Domain, SolStruct};
use eyre::{bail, Result};

use crate::sig::recover;

sol! {
    struct Approval {
        bytes pcr0;
        uint64 version;
        uint8 mode;
        bytes32 label;
    }
}

/// Image-transition approval kind. Closed set → real enum.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalMode {
    Carry = 1,
    Fresh = 2,
    Child = 3,
}

impl TryFrom<u8> for ApprovalMode {
    type Error = eyre::Report;

    fn try_from(v: u8) -> Result<Self> {
        match v {
            1 => Ok(ApprovalMode::Carry),
            2 => Ok(ApprovalMode::Fresh),
            3 => Ok(ApprovalMode::Child),
            other => bail!("invalid ApprovalMode: {other}"),
        }
    }
}

/// The image transition an owner quorum is approving: which PCR0, at which
/// version, in which mode, for which label, on which chain.
#[derive(Clone, Copy, Debug)]
pub struct ApprovalRequest {
    pub pcr0: [u8; 48],
    pub version: u64,
    pub mode: ApprovalMode,
    pub label: [u8; 32],
    pub chain_id: u64,
}

/// EIP-712 domain with only name/version/chainId — verifyingContract and salt stay None so the
/// separator uses "EIP712Domain(string name,string version,uint256 chainId)".
fn domain(chain_id: u64) -> Eip712Domain {
    Eip712Domain::new(
        Some(Cow::Borrowed("Kaskad Keyex")),
        Some(Cow::Borrowed("1")),
        Some(U256::from(chain_id)),
        None,
        None,
    )
}

/// EIP-712 signing hash of an Approval over the keyex domain.
pub fn approval_digest(req: &ApprovalRequest) -> B256 {
    let approval = Approval {
        pcr0: req.pcr0.to_vec().into(),
        version: req.version,
        mode: req.mode as u8,
        label: B256::from(req.label),
    };
    approval.eip712_signing_hash(&domain(req.chain_id))
}

/// Verify an owner quorum signed the Approval digest. Duplicate owner sigs count once;
/// non-owner sigs are ignored. Ok iff distinct owners ≥ threshold.
pub fn verify_approvals(
    req: &ApprovalRequest,
    sigs: &[[u8; 65]],
    owners: &[Address],
    threshold: usize,
) -> Result<()> {
    // Fail closed on a degenerate quorum config: 0 would authorize with no
    // sigs; a threshold above the owner count can never be met.
    if threshold == 0 {
        bail!("threshold must be >= 1");
    }
    if threshold > owners.len() {
        bail!(
            "threshold {} exceeds owner count {}",
            threshold,
            owners.len()
        );
    }

    let digest = approval_digest(req);

    let mut distinct_owners: Vec<Address> = Vec::new();
    for sig in sigs {
        // A malformed / high-s / non-owner sig is ignored, not fatal.
        let addr = match recover(&digest, sig) {
            Ok(a) => a,
            Err(_) => continue,
        };
        if owners.contains(&addr) && !distinct_owners.contains(&addr) {
            distinct_owners.push(addr);
        }
    }

    if distinct_owners.len() < threshold {
        bail!(
            "insufficient approvals: {} distinct owner(s) {:?}, need {}",
            distinct_owners.len(),
            distinct_owners,
            threshold
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::{address_from_key, sign_recoverable};
    use k256::ecdsa::{Signature, SigningKey};
    use sha3::{Digest, Keccak256};

    // keccak256("kaskad/pontifex/v1")
    fn v1_label() -> [u8; 32] {
        Keccak256::digest(b"kaskad/pontifex/v1").into()
    }

    fn canonical_pcr0() -> [u8; 48] {
        let mut p = [0u8; 48];
        for (i, b) in p.iter_mut().enumerate() {
            *b = i as u8;
        }
        p
    }

    fn req(
        pcr0: [u8; 48],
        version: u64,
        mode: ApprovalMode,
        label: [u8; 32],
        chain_id: u64,
    ) -> ApprovalRequest {
        ApprovalRequest {
            pcr0,
            version,
            mode,
            label,
            chain_id,
        }
    }

    fn key(seed: u8) -> SigningKey {
        let mut s = [0u8; 32];
        s[31] = seed;
        SigningKey::from_bytes((&s).into()).expect("nonzero seed")
    }

    fn addr(sk: &SigningKey) -> Address {
        address_from_key(sk.verifying_key())
    }

    /// Sign `digest` via the shared recoverable signer (low-s, v=27/28).
    fn sign(sk: &SigningKey, digest: &B256) -> [u8; 65] {
        sign_recoverable(sk, digest).expect("sign")
    }

    fn sign_at(
        sk: &SigningKey,
        pcr0: &[u8; 48],
        version: u64,
        mode: ApprovalMode,
        label: [u8; 32],
        chain_id: u64,
    ) -> [u8; 65] {
        sign(
            sk,
            &approval_digest(&req(*pcr0, version, mode, label, chain_id)),
        )
    }

    #[test]
    fn parity_with_forge() {
        // Expected digest printed by
        // kaskad-oracle-contracts/script/KeyexApprovalDigest.s.sol for the canonical vector.
        let expected =
            hex::decode("cb8a371abea52badb34086be1ed4d34b1af468a4804f61754fb89188c441a7fc")
                .unwrap();
        let got = approval_digest(&req(
            canonical_pcr0(),
            1,
            ApprovalMode::Carry,
            v1_label(),
            46630,
        ));
        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "Rust↔Solidity EIP-712 parity"
        );
    }

    #[test]
    fn mode_tryfrom() {
        assert_eq!(ApprovalMode::try_from(1).unwrap(), ApprovalMode::Carry);
        assert_eq!(ApprovalMode::try_from(2).unwrap(), ApprovalMode::Fresh);
        assert_eq!(ApprovalMode::try_from(3).unwrap(), ApprovalMode::Child);
        assert!(ApprovalMode::try_from(0).is_err());
        assert!(ApprovalMode::try_from(4).is_err());
    }

    #[test]
    fn k_of_n_boundary() {
        let pcr0 = canonical_pcr0();
        let label = v1_label();
        let (o1, o2, o3) = (key(1), key(2), key(3));
        let owners = vec![addr(&o1), addr(&o2), addr(&o3)];

        let two = vec![
            sign_at(&o1, &pcr0, 1, ApprovalMode::Carry, label, 46630),
            sign_at(&o2, &pcr0, 1, ApprovalMode::Carry, label, 46630),
        ];
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Carry, label, 46630),
            &two,
            &owners,
            2
        )
        .is_ok());

        let one = vec![sign_at(&o1, &pcr0, 1, ApprovalMode::Carry, label, 46630)];
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Carry, label, 46630),
            &one,
            &owners,
            2
        )
        .is_err());
    }

    #[test]
    fn duplicate_signer_counts_once() {
        let pcr0 = canonical_pcr0();
        let label = v1_label();
        let (o1, o2) = (key(1), key(2));
        let owners = vec![addr(&o1), addr(&o2)];

        let s = sign_at(&o1, &pcr0, 1, ApprovalMode::Carry, label, 46630);
        let dup = vec![s, s];
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Carry, label, 46630),
            &dup,
            &owners,
            2
        )
        .is_err());
    }

    #[test]
    fn foreign_signer_ignored() {
        let pcr0 = canonical_pcr0();
        let label = v1_label();
        let (o1, o2, o3, foreign) = (key(1), key(2), key(3), key(99));
        let owners = vec![addr(&o1), addr(&o2), addr(&o3)];

        let sigs = vec![
            sign_at(&o1, &pcr0, 1, ApprovalMode::Carry, label, 46630),
            sign_at(&o2, &pcr0, 1, ApprovalMode::Carry, label, 46630),
            sign_at(&foreign, &pcr0, 1, ApprovalMode::Carry, label, 46630),
        ];
        // threshold 3 (== owner count, so not the >owners guard): only 2 owners
        // signed, foreigner ignored → 2 < 3 fails.
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Carry, label, 46630),
            &sigs,
            &owners,
            3
        )
        .is_err());
        // threshold 2: the two owner sigs meet it, foreigner ignored.
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Carry, label, 46630),
            &sigs,
            &owners,
            2
        )
        .is_ok());
    }

    #[test]
    fn wrong_chain_id_fails() {
        let pcr0 = canonical_pcr0();
        let label = v1_label();
        let (o1, o2) = (key(1), key(2));
        let owners = vec![addr(&o1), addr(&o2)];

        // Sigs made over chainId=1, verified at 46630 → recover to non-owners.
        let sigs = vec![
            sign_at(&o1, &pcr0, 1, ApprovalMode::Carry, label, 1),
            sign_at(&o2, &pcr0, 1, ApprovalMode::Carry, label, 1),
        ];
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Carry, label, 46630),
            &sigs,
            &owners,
            2
        )
        .is_err());
    }

    #[test]
    fn wrong_mode_fails() {
        let pcr0 = canonical_pcr0();
        let label = v1_label();
        let (o1, o2) = (key(1), key(2));
        let owners = vec![addr(&o1), addr(&o2)];
        let sigs = vec![
            sign_at(&o1, &pcr0, 1, ApprovalMode::Carry, label, 46630),
            sign_at(&o2, &pcr0, 1, ApprovalMode::Carry, label, 46630),
        ];
        // verify under Fresh — digest differs → owner sigs no longer count
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Fresh, label, 46630),
            &sigs,
            &owners,
            2
        )
        .is_err());
    }

    #[test]
    fn wrong_label_fails() {
        let pcr0 = canonical_pcr0();
        let label = v1_label();
        let other: [u8; 32] = Keccak256::digest(b"kaskad/pontifex/v2").into();
        let (o1, o2) = (key(1), key(2));
        let owners = vec![addr(&o1), addr(&o2)];
        let sigs = vec![
            sign_at(&o1, &pcr0, 1, ApprovalMode::Child, label, 46630),
            sign_at(&o2, &pcr0, 1, ApprovalMode::Child, label, 46630),
        ];
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Child, other, 46630),
            &sigs,
            &owners,
            2
        )
        .is_err());
    }

    #[test]
    fn wrong_version_fails() {
        let pcr0 = canonical_pcr0();
        let label = v1_label();
        let (o1, o2) = (key(1), key(2));
        let owners = vec![addr(&o1), addr(&o2)];
        let sigs = vec![
            sign_at(&o1, &pcr0, 1, ApprovalMode::Carry, label, 46630),
            sign_at(&o2, &pcr0, 1, ApprovalMode::Carry, label, 46630),
        ];
        assert!(verify_approvals(
            &req(pcr0, 2, ApprovalMode::Carry, label, 46630),
            &sigs,
            &owners,
            2
        )
        .is_err());
    }

    #[test]
    fn wrong_pcr0_fails() {
        // Approval for pcr0=X must not verify against pcr0=Y.
        let label = v1_label();
        let x = canonical_pcr0();
        let mut y = canonical_pcr0();
        y[47] ^= 0x01; // single-bit flip
        let (o1, o2) = (key(1), key(2));
        let owners = vec![addr(&o1), addr(&o2)];
        let sigs = vec![
            sign_at(&o1, &x, 1, ApprovalMode::Carry, label, 46630),
            sign_at(&o2, &x, 1, ApprovalMode::Carry, label, 46630),
        ];
        // digest for x != digest for y → owner sigs recover to strangers.
        assert_ne!(
            approval_digest(&req(x, 1, ApprovalMode::Carry, label, 46630)),
            approval_digest(&req(y, 1, ApprovalMode::Carry, label, 46630)),
        );
        assert!(verify_approvals(
            &req(y, 1, ApprovalMode::Carry, label, 46630),
            &sigs,
            &owners,
            2
        )
        .is_err());
        // control: same pcr0 still passes
        assert!(verify_approvals(
            &req(x, 1, ApprovalMode::Carry, label, 46630),
            &sigs,
            &owners,
            2
        )
        .is_ok());
    }

    #[test]
    fn testnet_approval_not_replayable_on_mainnet() {
        // Robinhood testnet 46630 approval must not carry to Igra mainnet 4663.
        let pcr0 = canonical_pcr0();
        let label = v1_label();
        let (o1, o2) = (key(1), key(2));
        let owners = vec![addr(&o1), addr(&o2)];
        let sigs = vec![
            sign_at(&o1, &pcr0, 1, ApprovalMode::Carry, label, 46630),
            sign_at(&o2, &pcr0, 1, ApprovalMode::Carry, label, 46630),
        ];
        assert_ne!(
            approval_digest(&req(pcr0, 1, ApprovalMode::Carry, label, 46630)),
            approval_digest(&req(pcr0, 1, ApprovalMode::Carry, label, 4663)),
        );
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Carry, label, 4663),
            &sigs,
            &owners,
            2
        )
        .is_err());
    }

    #[test]
    fn carry_not_accepted_as_child() {
        // Cover the mode direction wrong_mode_fails omits: a Carry quorum must not
        // satisfy a Child requirement.
        let pcr0 = canonical_pcr0();
        let label = v1_label();
        let (o1, o2) = (key(1), key(2));
        let owners = vec![addr(&o1), addr(&o2)];
        let sigs = vec![
            sign_at(&o1, &pcr0, 1, ApprovalMode::Carry, label, 46630),
            sign_at(&o2, &pcr0, 1, ApprovalMode::Carry, label, 46630),
        ];
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Child, label, 46630),
            &sigs,
            &owners,
            2
        )
        .is_err());
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Fresh, label, 46630),
            &sigs,
            &owners,
            2
        )
        .is_err());
    }

    #[test]
    fn rejects_zero_threshold() {
        let pcr0 = canonical_pcr0();
        let label = v1_label();
        let o1 = key(1);
        let owners = vec![addr(&o1)];
        let good = sign_at(&o1, &pcr0, 1, ApprovalMode::Carry, label, 46630);
        // threshold 0 fails closed: valid sig, empty sigs, and empty owners alike.
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Carry, label, 46630),
            &[good],
            &owners,
            0
        )
        .is_err());
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Carry, label, 46630),
            &[],
            &owners,
            0
        )
        .is_err());
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Carry, label, 46630),
            &[],
            &[],
            0
        )
        .is_err());
    }

    #[test]
    fn rejects_threshold_exceeding_owners() {
        let pcr0 = canonical_pcr0();
        let label = v1_label();
        let (o1, o2) = (key(1), key(2));
        let owners = vec![addr(&o1), addr(&o2)];
        let sigs = vec![
            sign_at(&o1, &pcr0, 1, ApprovalMode::Carry, label, 46630),
            sign_at(&o2, &pcr0, 1, ApprovalMode::Carry, label, 46630),
        ];
        // 3-of-2 is unsatisfiable → explicit fail even with both owners signing.
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Carry, label, 46630),
            &sigs,
            &owners,
            3
        )
        .is_err());
    }

    #[test]
    fn rejects_non_canonical_v() {
        let pcr0 = canonical_pcr0();
        let label = v1_label();
        let o1 = key(1);
        let owners = vec![addr(&o1)];
        let mut sig = sign_at(&o1, &pcr0, 1, ApprovalMode::Carry, label, 46630);
        let d = approval_digest(&req(pcr0, 1, ApprovalMode::Carry, label, 46630));
        assert!(recover(&d, &sig).is_ok()); // canonical v accepted
                                            // v ∉ {27,28} rejected before any recovery math.
        sig[64] = 29;
        assert!(recover(&d, &sig).is_err());
        sig[64] = 30;
        assert!(recover(&d, &sig).is_err());
        // and such a sig never counts toward a quorum.
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Carry, label, 46630),
            &[sig],
            &owners,
            1
        )
        .is_err());
    }

    #[test]
    fn high_s_rejected() {
        let pcr0 = canonical_pcr0();
        let label = v1_label();
        let (o1, o2) = (key(1), key(2));
        let owners = vec![addr(&o1), addr(&o2)];

        let good1 = sign_at(&o1, &pcr0, 1, ApprovalMode::Carry, label, 46630);
        let good2 = sign_at(&o2, &pcr0, 1, ApprovalMode::Carry, label, 46630);
        // Malleate o2's sig into high-s form: s' = n - s, flip v.
        let high2 = to_high_s(&good2);

        // Sanity: recover() rejects the high-s one outright.
        let d = approval_digest(&req(pcr0, 1, ApprovalMode::Carry, label, 46630));
        assert!(recover(&d, &high2).is_err());

        // With only o1 good + o2 high-s, threshold 2 fails (high-s ignored).
        let sigs = vec![good1, high2];
        assert!(verify_approvals(
            &req(pcr0, 1, ApprovalMode::Carry, label, 46630),
            &sigs,
            &owners,
            2
        )
        .is_err());
    }

    /// Produce a high-s variant of a valid low-s 65-byte sig (s' = n - s, v flipped).
    fn to_high_s(sig: &[u8; 65]) -> [u8; 65] {
        let parsed = Signature::from_slice(&sig[..64]).unwrap();
        let s: k256::Scalar = *parsed.s();
        let high_s = s.negate();
        let mut out = *sig;
        out[32..64].copy_from_slice(&high_s.to_bytes());
        out[64] = if sig[64] == 27 { 28 } else { 27 };
        out
    }
}
