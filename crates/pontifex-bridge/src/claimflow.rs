//! The bridge's money path: read the Igra burn ledger at finality, enforce the
//! recipient/amount/monotonicity policy, then sign an EIP-712 claim. Pure over
//! two injected [`EthTransport`]s (Igra + Robinhood) so every branch is tested
//! without a chain. Every refusal returns a coded [`SignClaimResponse::Err`];
//! the deadline clock is read from the RH LATEST block (not finalized), so RH
//! finality lag can never trip the clock-skew ceiling.

use alloy_primitives::{Address, U256};
use k256::ecdsa::SigningKey;
use keyex::api::{ClaimGrant, SignClaimResponse};
use keyex::chain::{self, EthTransport, Finality};
use keyex::claim::{self, ClaimError, ClaimRequest};

/// Everything a single `sign_claim` needs beyond the two transports and the key.
pub struct ClaimInputs<'a> {
    pub recipient: Address,
    /// Highest burned total already signed for this recipient this session.
    pub high_water: U256,
    /// The enclave's current wall-clock time (unix seconds).
    pub enclave_now: u64,
    /// Recipients a claim must never mint to (KskdExit, KSKD).
    pub forbidden: &'a [Address],
    /// KskdExit on Igra.
    pub exit: Address,
    /// KskdEntry on Robinhood — the claim's verifyingContract.
    pub entry: Address,
    /// Robinhood chain id.
    pub chain_id: u64,
    /// How to pin the Igra burn read.
    pub igra_finality: Finality,
}

/// Read burned at finality, apply policy, and sign the claim. Returns the grant
/// or a coded refusal — never panics, never signs a claim it did not fully
/// validate.
pub async fn build_grant<I: EthTransport, R: EthTransport>(
    key: &SigningKey,
    igra: &I,
    rh: &R,
    inp: &ClaimInputs<'_>,
) -> SignClaimResponse {
    // 1. Burn ledger at Igra finality, pinned to the exact height read.
    let (burned, igra_block) =
        match chain::burned_finalized(igra, inp.exit, inp.recipient, inp.igra_finality).await {
            Ok(x) => x,
            Err(e) => return ClaimError::from(e).into(),
        };

    // 2. Never sign a total below one already signed this session.
    if let Err(e) = chain::ensure_not_decreasing(burned, inp.high_water) {
        return ClaimError::from(e).into();
    }

    // 3. Recipient/amount policy, independent of any chain read.
    if let Err(e) = claim::check_claimable(inp.recipient, burned, inp.forbidden) {
        return e.into();
    }

    // 4. Deadline clock from the RH LATEST block (HeadMinus(0)), not finalized.
    let rh_block = match chain::finalized_block(rh, Finality::HeadMinus(0)).await {
        Ok(b) => b,
        Err(e) => return ClaimError::from(e).into(),
    };
    let deadline = match claim::compute_deadline(inp.enclave_now, rh_block.timestamp) {
        Ok(d) => d,
        Err(e) => return e.into(),
    };

    // 5. Sign. A signer fault (self-check fails) is catastrophic — fail closed.
    let req = ClaimRequest {
        recipient: inp.recipient,
        cumulative_burned: burned,
        deadline: U256::from(deadline),
        chain_id: inp.chain_id,
        entry: inp.entry,
    };
    let signature = match claim::sign_claim(key, &req) {
        Ok(s) => s,
        Err(_) => return ClaimError::NotReady.into(),
    };

    let signer = keyex::sig::address_from_key(key.verifying_key());
    SignClaimResponse::Ok(ClaimGrant::new(
        signature, burned, deadline, signer, igra_block,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::sync::Mutex;

    use alloy_primitives::hex;
    use keyex::api::SignClaimError;
    use serde_json::{json, Value};

    enum Resp {
        Ok(Value),
        Fail,
    }

    /// Scripted JSON-RPC transport: replays responses in order, records calls.
    struct Scripted {
        responses: Mutex<VecDeque<Resp>>,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl Scripted {
        fn new(responses: Vec<Resp>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                calls: Mutex::new(Vec::new()),
            }
        }
        fn empty() -> Self {
            Self::new(vec![])
        }
        fn calls(&self) -> Vec<(String, Value)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl EthTransport for Scripted {
        fn rpc(&self, method: &str, params: Value) -> impl Future<Output = eyre::Result<Value>> {
            self.calls.lock().unwrap().push((method.to_owned(), params));
            let next = self.responses.lock().unwrap().pop_front();
            async move {
                match next {
                    Some(Resp::Ok(v)) => Ok(v),
                    Some(Resp::Fail) => eyre::bail!("scripted rpc failure"),
                    None => eyre::bail!("unexpected rpc call"),
                }
            }
        }
    }

    fn block(number: u64, hash: u8, ts: u64) -> Value {
        json!({
            "number": format!("0x{number:x}"),
            "hash": hex::encode_prefixed([hash; 32]),
            "timestamp": format!("0x{ts:x}"),
        })
    }
    fn word(v: U256) -> Value {
        Value::String(hex::encode_prefixed(v.to_be_bytes::<32>()))
    }
    fn quantity(v: u64) -> Value {
        Value::String(format!("0x{v:x}"))
    }

    const EXIT: Address = Address::new([0xEE; 20]);
    const KSKD: Address = Address::new([0xDD; 20]);
    const ENTRY: Address = Address::new([0x11; 20]);
    const RECIPIENT: Address = Address::new([0x22; 20]);
    const CHAIN_ID: u64 = 46630;
    const ONE_KSKD: u64 = 1_000_000_000_000_000_000;

    fn key() -> SigningKey {
        SigningKey::from_bytes((&[9u8; 32]).into()).unwrap()
    }

    fn forbidden() -> [Address; 2] {
        [EXIT, KSKD]
    }

    fn inputs<'a>(
        recipient: Address,
        high_water: U256,
        enclave_now: u64,
        forbidden: &'a [Address],
    ) -> ClaimInputs<'a> {
        ClaimInputs {
            recipient,
            high_water,
            enclave_now,
            forbidden,
            exit: EXIT,
            entry: ENTRY,
            chain_id: CHAIN_ID,
            igra_finality: Finality::HeadMinus(769),
        }
    }

    /// The full Igra burn double-read for latest=2000 → target 1231 (0x4cf).
    fn igra_burned(burned: u64) -> Scripted {
        Scripted::new(vec![
            Resp::Ok(quantity(2000)),
            Resp::Ok(block(1231, 0xAB, 1)),
            Resp::Ok(word(U256::from(burned))),
            Resp::Ok(block(1231, 0xAB, 1)),
            Resp::Ok(word(U256::from(burned))),
        ])
    }
    /// The RH latest-block read for latest=5000 (0x1388) at timestamp `ts`.
    fn rh_latest(ts: u64) -> Scripted {
        Scripted::new(vec![
            Resp::Ok(quantity(5000)),
            Resp::Ok(block(5000, 0xCD, ts)),
        ])
    }

    #[tokio::test]
    async fn happy_path_signs_pins_block_and_deadline() {
        let igra = igra_burned(ONE_KSKD);
        let rh = rh_latest(1_789_000_000);
        let f = forbidden();
        let resp = build_grant(
            &key(),
            &igra,
            &rh,
            &inputs(RECIPIENT, U256::ZERO, 1_789_000_050, &f),
        )
        .await;

        let grant = match resp {
            SignClaimResponse::Ok(g) => g,
            SignClaimResponse::Err(e) => panic!("expected grant, got {e:?}"),
        };
        assert_eq!(
            grant.igra_block, 1231,
            "igra_block pinned to the read height"
        );
        assert_eq!(grant.cumulative_burned, "1000000000000000000");
        // deadline = min(enclave_now, rh_ts) + 3600.
        assert_eq!(grant.deadline, 1_789_000_000 + 3600);

        // The signature recovers to the signer over the exact claim digest.
        let req = ClaimRequest {
            recipient: RECIPIENT,
            cumulative_burned: U256::from(ONE_KSKD),
            deadline: U256::from(grant.deadline),
            chain_id: CHAIN_ID,
            entry: ENTRY,
        };
        let sig_bytes: [u8; 65] = hex::decode(grant.signature.strip_prefix("0x").unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let recovered = keyex::sig::recover(&claim::claim_digest(&req), &sig_bytes).unwrap();
        assert_eq!(
            recovered,
            keyex::sig::address_from_key(key().verifying_key())
        );
        assert_eq!(grant.signer, recovered.to_string());
    }

    #[tokio::test]
    async fn deadline_uses_rh_latest_not_finalized() {
        // Locks finding #2: the RH leg resolves latest (eth_blockNumber →
        // getBlockByNumber(hex(latest))), never the "finalized" tag.
        let igra = igra_burned(ONE_KSKD);
        let rh = rh_latest(1_789_000_000);
        let f = forbidden();
        let _ = build_grant(
            &key(),
            &igra,
            &rh,
            &inputs(RECIPIENT, U256::ZERO, 1_789_000_050, &f),
        )
        .await;
        let calls = rh.calls();
        assert_eq!(calls[0].0, "eth_blockNumber");
        assert_eq!(calls[1].0, "eth_getBlockByNumber");
        assert_eq!(calls[1].1[0], "0x1388"); // block 5000, the latest — not "finalized"
        assert!(calls
            .iter()
            .all(|c| c.1.get(0).is_none_or(|p| p != "finalized")));
    }

    #[tokio::test]
    async fn forbidden_recipient_refuses_after_burn_read_without_touching_rh() {
        let igra = igra_burned(ONE_KSKD);
        let rh = Scripted::empty();
        let f = forbidden();
        // KSKD token as recipient — burned is read, then policy refuses.
        let resp = build_grant(
            &key(),
            &igra,
            &rh,
            &inputs(KSKD, U256::ZERO, 1_789_000_050, &f),
        )
        .await;
        assert_eq!(resp, ClaimError::RecipientForbidden.into());
        assert!(
            rh.calls().is_empty(),
            "RH must not be read on a policy refusal"
        );
    }

    #[tokio::test]
    async fn zero_recipient_is_forbidden() {
        let igra = igra_burned(ONE_KSKD);
        let rh = Scripted::empty();
        let f = forbidden();
        let resp = build_grant(
            &key(),
            &igra,
            &rh,
            &inputs(Address::ZERO, U256::ZERO, 1_789_000_050, &f),
        )
        .await;
        assert_eq!(resp, ClaimError::RecipientForbidden.into());
    }

    #[tokio::test]
    async fn nothing_burned_refuses() {
        let igra = igra_burned(0);
        let rh = Scripted::empty();
        let f = forbidden();
        let resp = build_grant(
            &key(),
            &igra,
            &rh,
            &inputs(RECIPIENT, U256::ZERO, 1_789_000_050, &f),
        )
        .await;
        assert_eq!(resp, ClaimError::NothingBurned.into());
        assert!(rh.calls().is_empty());
    }

    #[tokio::test]
    async fn decreasing_below_high_water_refuses() {
        let igra = igra_burned(500);
        let rh = Scripted::empty();
        let f = forbidden();
        // Already signed 1000 for this recipient; a fresh 500 is a decrease.
        let resp = build_grant(
            &key(),
            &igra,
            &rh,
            &inputs(RECIPIENT, U256::from(1000), 1_789_000_050, &f),
        )
        .await;
        assert_eq!(resp, ClaimError::DecreasingBurned.into());
        assert!(rh.calls().is_empty());
    }

    #[tokio::test]
    async fn burn_read_mismatch_refuses() {
        // Second burned read disagrees → ReadMismatch → read_mismatch code.
        let igra = Scripted::new(vec![
            Resp::Ok(quantity(2000)),
            Resp::Ok(block(1231, 0xAB, 1)),
            Resp::Ok(word(U256::from(ONE_KSKD))),
            Resp::Ok(block(1231, 0xAB, 1)),
            Resp::Ok(word(U256::from(ONE_KSKD + 1))),
        ]);
        let rh = Scripted::empty();
        let f = forbidden();
        let resp = build_grant(
            &key(),
            &igra,
            &rh,
            &inputs(RECIPIENT, U256::ZERO, 1_789_000_050, &f),
        )
        .await;
        assert_eq!(resp, ClaimError::ReadMismatch.into());
    }

    #[tokio::test]
    async fn clock_skew_refuses() {
        // enclave_now is 700s past the RH block clock — beyond the 600s ceiling.
        let igra = igra_burned(ONE_KSKD);
        let rh = rh_latest(1_789_000_000);
        let f = forbidden();
        let resp = build_grant(
            &key(),
            &igra,
            &rh,
            &inputs(RECIPIENT, U256::ZERO, 1_789_000_700, &f),
        )
        .await;
        assert_eq!(resp, ClaimError::ClockSkew.into());
    }

    #[tokio::test]
    async fn igra_rpc_failure_is_rpc_error() {
        let igra = Scripted::new(vec![Resp::Fail]);
        let rh = Scripted::empty();
        let f = forbidden();
        let resp = build_grant(
            &key(),
            &igra,
            &rh,
            &inputs(RECIPIENT, U256::ZERO, 1_789_000_050, &f),
        )
        .await;
        assert_eq!(resp, ClaimError::RpcError.into());
        assert!(rh.calls().is_empty());
    }

    #[tokio::test]
    async fn high_water_equal_is_allowed() {
        // Re-signing the exact same burned total (relayer retry) is not a decrease.
        let igra = igra_burned(ONE_KSKD);
        let rh = rh_latest(1_789_000_000);
        let f = forbidden();
        let resp = build_grant(
            &key(),
            &igra,
            &rh,
            &inputs(RECIPIENT, U256::from(ONE_KSKD), 1_789_000_050, &f),
        )
        .await;
        assert!(matches!(resp, SignClaimResponse::Ok(_)));
    }

    #[test]
    fn sign_claim_error_helper_is_unused_marker() {
        // Keep the SignClaimError import meaningful: the Err arm carries it.
        let e: SignClaimResponse = ClaimError::NotReady.into();
        assert_eq!(
            e,
            SignClaimResponse::Err(SignClaimError {
                error: ClaimError::NotReady
            })
        );
    }
}
