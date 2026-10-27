//! EIP-712 claim signing for the bridge image. Domain = { name: "Pontifex",
//! version: "1", chainId, verifyingContract: KskdEntry } — distinct from the
//! keyex approval domain (which has no verifyingContract). The digest matches
//! `KskdEntry._hashTypedDataV4(keccak256(abi.encode(CLAIM_TYPEHASH, recipient,
//! cumulativeBurned, deadline)))`; signatures are EIP-2 low-s, v ∈ {27, 28} for
//! `ECDSA.recoverCalldata`.

use std::borrow::Cow;

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{sol, Eip712Domain, SolStruct};
use eyre::Result;
use k256::ecdsa::SigningKey;

sol! {
    struct Claim {
        address recipient;
        uint256 cumulativeBurned;
        uint256 deadline;
    }
}

/// A claim to sign: mint up to `cumulative_burned` to `recipient` on `entry`
/// (chain `chain_id`), valid until `deadline`.
#[derive(Clone, Copy, Debug)]
pub struct ClaimRequest {
    pub recipient: Address,
    pub cumulative_burned: U256,
    pub deadline: U256,
    pub chain_id: u64,
    pub entry: Address,
}

/// Every refusal path `sign_claim` can hit. One code per path; the wire form is
/// the snake_case rename, matching ENCLAVE.md's `sign_claim` error set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimError {
    NotReady,
    RecipientForbidden,
    NothingBurned,
    ReadMismatch,
    DecreasingBurned,
    RpcError,
    ClockSkew,
}

/// Claim validity window and the clock-skew ceiling between the enclave and the
/// Robinhood block clock.
pub const CLAIM_TTL_SECS: u64 = 3600;
pub const MAX_CLOCK_SKEW_SECS: u64 = 600;

/// EIP-712 domain with verifyingContract = the KskdEntry address, so a signature
/// is bound to one contract on one chain.
fn domain(chain_id: u64, entry: Address) -> Eip712Domain {
    Eip712Domain::new(
        Some(Cow::Borrowed("Pontifex")),
        Some(Cow::Borrowed("1")),
        Some(U256::from(chain_id)),
        Some(entry),
        None,
    )
}

/// EIP-712 signing hash of the Claim over the Pontifex domain.
pub fn claim_digest(req: &ClaimRequest) -> B256 {
    let claim = Claim {
        recipient: req.recipient,
        cumulativeBurned: req.cumulative_burned,
        deadline: req.deadline,
    };
    claim.eip712_signing_hash(&domain(req.chain_id, req.entry))
}

/// Sign a fully-formed claim with the bridge key. The shared signer self-checks
/// the recovery, so a signer fault fails closed. Does NOT enforce the
/// recipient/amount policy — the caller runs [`check_claimable`] first.
pub fn sign_claim(key: &SigningKey, req: &ClaimRequest) -> Result<[u8; 65]> {
    crate::sig::sign_recoverable(key, &claim_digest(req))
}

/// Recipient/amount preconditions independent of any chain read. Per ENCLAVE.md:
/// recipient ∉ {0, KskdExit, KSKD} (the `forbidden` set is configured), and
/// `cumulative_burned > 0`.
pub fn check_claimable(
    recipient: Address,
    cumulative_burned: U256,
    forbidden: &[Address],
) -> Result<(), ClaimError> {
    if recipient.is_zero() || forbidden.contains(&recipient) {
        return Err(ClaimError::RecipientForbidden);
    }
    if cumulative_burned.is_zero() {
        return Err(ClaimError::NothingBurned);
    }
    Ok(())
}

/// `deadline = min(enclave_clock, rh_block_ts) + 3600`, refusing `clock_skew`
/// when the two clocks disagree by more than 600 s.
pub fn compute_deadline(enclave_now: u64, rh_block_ts: u64) -> Result<u64, ClaimError> {
    if enclave_now.abs_diff(rh_block_ts) > MAX_CLOCK_SKEW_SECS {
        return Err(ClaimError::ClockSkew);
    }
    Ok(enclave_now.min(rh_block_ts) + CLAIM_TTL_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        let mut s = [0u8; 32];
        s[31] = seed;
        SigningKey::from_bytes((&s).into()).expect("nonzero seed")
    }

    fn canonical() -> ClaimRequest {
        ClaimRequest {
            recipient: Address::from([0x22u8; 20]),
            cumulative_burned: U256::from(1_000_000_000_000_000_000u64),
            deadline: U256::from(1_789_682_698u64),
            chain_id: 46630,
            entry: Address::from([0x11u8; 20]),
        }
    }

    #[test]
    fn parity_with_forge() {
        // Ground truth from `cast` over KskdEntry's EIP-712 (CLAIM_TYPEHASH
        // 0x9b616237…0661, domain EIP712("Pontifex","1")) for the canonical vector.
        let expected =
            hex::decode("5d9069c7695343cd934c9b809a094758b59c5320f023a7bada0872c89552e76c")
                .unwrap();
        assert_eq!(
            claim_digest(&canonical()).as_slice(),
            expected.as_slice(),
            "Rust↔Solidity Claim EIP-712 parity"
        );
    }

    #[test]
    fn sign_claim_recovers_to_signer() {
        let sk = key(9);
        let sig = sign_claim(&sk, &canonical()).unwrap();
        assert_eq!(
            crate::sig::recover(&claim_digest(&canonical()), &sig).unwrap(),
            crate::sig::address_from_key(sk.verifying_key()),
        );
    }

    #[test]
    fn digest_binds_chain_and_contract() {
        let base = canonical();
        // A claim signed for 46630 must not verify on Igra mainnet 4663.
        assert_ne!(
            claim_digest(&base),
            claim_digest(&ClaimRequest {
                chain_id: 4663,
                ..base
            })
        );
        // Nor against a different KskdEntry deployment.
        assert_ne!(
            claim_digest(&base),
            claim_digest(&ClaimRequest {
                entry: Address::from([0x99u8; 20]),
                ..base
            }),
        );
        // Nor for a different recipient / amount / deadline.
        assert_ne!(
            claim_digest(&base),
            claim_digest(&ClaimRequest {
                recipient: Address::from([0x23u8; 20]),
                ..base
            }),
        );
        assert_ne!(
            claim_digest(&base),
            claim_digest(&ClaimRequest {
                cumulative_burned: U256::from(2u64),
                ..base
            }),
        );
        assert_ne!(
            claim_digest(&base),
            claim_digest(&ClaimRequest {
                deadline: U256::from(1u64),
                ..base
            }),
        );
    }

    #[test]
    fn refuses_forbidden_recipients() {
        let kskd_exit = Address::from([0xEEu8; 20]);
        let kskd = Address::from([0xDDu8; 20]);
        let forbidden = [kskd_exit, kskd];
        let one = U256::from(1u64);
        assert_eq!(
            check_claimable(Address::ZERO, one, &forbidden),
            Err(ClaimError::RecipientForbidden)
        );
        assert_eq!(
            check_claimable(kskd_exit, one, &forbidden),
            Err(ClaimError::RecipientForbidden)
        );
        assert_eq!(
            check_claimable(kskd, one, &forbidden),
            Err(ClaimError::RecipientForbidden)
        );
        let ok_recipient = Address::from([0x22u8; 20]);
        assert_eq!(
            check_claimable(ok_recipient, U256::ZERO, &forbidden),
            Err(ClaimError::NothingBurned)
        );
        assert!(check_claimable(ok_recipient, one, &forbidden).is_ok());
    }

    #[test]
    fn deadline_and_clock_skew() {
        // Within skew: deadline = min(clocks) + TTL.
        assert_eq!(compute_deadline(1000, 900).unwrap(), 900 + CLAIM_TTL_SECS);
        assert_eq!(compute_deadline(900, 1000).unwrap(), 900 + CLAIM_TTL_SECS);
        // Exactly at the ceiling is allowed; one past it refuses.
        assert!(compute_deadline(1000, 1000 - MAX_CLOCK_SKEW_SECS).is_ok());
        assert_eq!(
            compute_deadline(1000, 1000 - MAX_CLOCK_SKEW_SECS - 1),
            Err(ClaimError::ClockSkew),
        );
        assert_eq!(
            compute_deadline(1000, 1000 + MAX_CLOCK_SKEW_SECS + 1),
            Err(ClaimError::ClockSkew),
        );
    }

    #[test]
    fn error_wire_codes() {
        // The JSON form must match ENCLAVE.md's exact strings.
        let cases = [
            (ClaimError::NotReady, "\"not_ready\""),
            (ClaimError::RecipientForbidden, "\"recipient_forbidden\""),
            (ClaimError::NothingBurned, "\"nothing_burned\""),
            (ClaimError::ReadMismatch, "\"read_mismatch\""),
            (ClaimError::DecreasingBurned, "\"decreasing_burned\""),
            (ClaimError::RpcError, "\"rpc_error\""),
            (ClaimError::ClockSkew, "\"clock_skew\""),
        ];
        for (e, want) in cases {
            assert_eq!(serde_json::to_string(&e).unwrap(), want);
        }
    }
}
