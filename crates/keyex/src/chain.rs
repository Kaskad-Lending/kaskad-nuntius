//! Typed, seam-injected chain reads for the bridge/oracle boot rules: `burned`
//! on KskdExit (Igra, double-read at finality) and the signer registries
//! (`isValidSigner` on KaskadPriceOracle, `validSigner` on KskdEntry). Pure over
//! an injected [`EthTransport`]; every refusal is a coded [`ChainError`].

use std::future::Future;

use alloy_primitives::{hex, Address, B256, U256};
use serde_json::{json, Value};

// Verified 4-byte selectors (`cast sig`). The two registries expose the
// signer check under DIFFERENT names, so the selector is chosen per registry.
const SEL_BURNED: [u8; 4] = [0xa7, 0x50, 0x9b, 0x83]; // burned(address)
const SEL_IS_VALID_SIGNER: [u8; 4] = [0xd5, 0xf5, 0x05, 0x82]; // isValidSigner(address) — oracle
const SEL_VALID_SIGNER: [u8; 4] = [0xba, 0x6f, 0x8b, 0x0e]; // validSigner(address) — bridge
const SEL_SIGNER_COUNT: [u8; 4] = [0x7c, 0xa5, 0x48, 0xc6]; // signerCount()

/// JSON-RPC transport seam. `rpc` returns the already-unwrapped `result` value,
/// or `Err` when the transport failed or the response carried a JSON-RPC error.
pub trait EthTransport {
    fn rpc(&self, method: &str, params: Value) -> impl Future<Output = eyre::Result<Value>>;
}

/// Which registry's `validSigner`/`isValidSigner` ABI to call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Registry {
    /// KaskadPriceOracle: `isValidSigner(address)`.
    Oracle,
    /// KskdEntry: `validSigner(address)` (public mapping getter).
    Bridge,
}

impl Registry {
    fn valid_signer_selector(self) -> [u8; 4] {
        match self {
            Registry::Oracle => SEL_IS_VALID_SIGNER,
            Registry::Bridge => SEL_VALID_SIGNER,
        }
    }
}

/// How to pin the block a read observes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finality {
    /// The RPC `finalized` block tag (Robinhood).
    Tag,
    /// `latest - depth`, saturating at genesis.
    HeadMinus(u64),
    /// The older of `finalized` and `latest - depth`; insufficient history fails closed.
    FinalizedWithDepth(u64),
}

/// Every coded refusal a chain read can produce. Maps into [`crate::claim::ClaimError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainError {
    /// The two independent reads disagreed on block hash or value.
    ReadMismatch,
    /// The fresh burned total is below the last one signed for this recipient.
    DecreasingBurned,
    /// Transport failure, JSON-RPC error, or an undecodable response.
    Rpc,
}

impl From<ChainError> for crate::claim::ClaimError {
    fn from(e: ChainError) -> Self {
        match e {
            ChainError::ReadMismatch => Self::ReadMismatch,
            ChainError::DecreasingBurned => Self::DecreasingBurned,
            ChainError::Rpc => Self::RpcError,
        }
    }
}

/// A pinned block: number, hash, and timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRef {
    pub number: u64,
    pub hash: B256,
    pub timestamp: u64,
}

/// Resolve the block a read pins to under the selected finality policy.
/// Its timestamp feeds the claim deadline's clock cross-check.
pub async fn finalized_block<T: EthTransport>(
    t: &T,
    finality: Finality,
) -> Result<BlockRef, ChainError> {
    let number = match finality {
        Finality::Tag => None,
        Finality::HeadMinus(depth) => Some(eth_block_number(t).await?.saturating_sub(depth)),
        Finality::FinalizedWithDepth(depth) => {
            let finalized = read_block(t, None).await?;
            let ceiling = eth_block_number(t)
                .await?
                .checked_sub(depth)
                .ok_or(ChainError::Rpc)?;
            if finalized.number <= ceiling {
                return Ok(finalized);
            }
            Some(ceiling)
        }
    };
    read_block(t, number).await
}

/// Read `finalized` or an explicit height, rejecting a substituted block number.
async fn read_block<T: EthTransport>(
    t: &T,
    requested_number: Option<u64>,
) -> Result<BlockRef, ChainError> {
    let tag = requested_number
        .map(|number| format!("0x{number:x}"))
        .unwrap_or_else(|| "finalized".to_owned());
    let resp = t
        .rpc("eth_getBlockByNumber", json!([tag, false]))
        .await
        .map_err(|_| ChainError::Rpc)?;
    let number =
        parse_quantity(resp.get("number").ok_or(ChainError::Rpc)?).ok_or(ChainError::Rpc)?;
    if requested_number.is_some_and(|expected| expected != number) {
        return Err(ChainError::ReadMismatch);
    }
    let hash = parse_b256(resp.get("hash").ok_or(ChainError::Rpc)?).ok_or(ChainError::Rpc)?;
    let timestamp =
        parse_quantity(resp.get("timestamp").ok_or(ChainError::Rpc)?).ok_or(ChainError::Rpc)?;
    Ok(BlockRef {
        number,
        hash,
        timestamp,
    })
}

/// Read `KskdExit.burned(recipient)` twice at the selected canonical block hash.
/// Both values and the reread header hash must agree; return the total and height.
/// The caller enforces [`ensure_not_decreasing`] across signed claims.
pub async fn burned_finalized<T: EthTransport>(
    t: &T,
    exit: Address,
    recipient: Address,
    finality: Finality,
) -> Result<(U256, u64), ChainError> {
    let block = finalized_block(t, finality).await?;
    let data = encode_call(SEL_BURNED, recipient);
    let v1 = eth_call_word(t, exit, &data, CallBlock::CanonicalHash(block.hash)).await?;
    let hash2 = read_block_hash(t, block.number).await?;
    let v2 = eth_call_word(t, exit, &data, CallBlock::CanonicalHash(block.hash)).await?;
    if block.hash != hash2 || v1 != v2 {
        return Err(ChainError::ReadMismatch);
    }
    Ok((U256::from_be_bytes(v1), block.number))
}

/// Block hash at an explicit height, for the burned double-read's second pass.
async fn read_block_hash<T: EthTransport>(t: &T, number: u64) -> Result<B256, ChainError> {
    let resp = t
        .rpc(
            "eth_getBlockByNumber",
            json!([format!("0x{number:x}"), false]),
        )
        .await
        .map_err(|_| ChainError::Rpc)?;
    let observed =
        parse_quantity(resp.get("number").ok_or(ChainError::Rpc)?).ok_or(ChainError::Rpc)?;
    if observed != number {
        return Err(ChainError::ReadMismatch);
    }
    parse_b256(resp.get("hash").ok_or(ChainError::Rpc)?).ok_or(ChainError::Rpc)
}

/// Refuse a burned total below the last one signed for this recipient.
pub fn ensure_not_decreasing(fresh: U256, last_signed: U256) -> Result<(), ChainError> {
    if fresh < last_signed {
        return Err(ChainError::DecreasingBurned);
    }
    Ok(())
}

/// Registry membership of `who`, using the correct per-registry selector.
pub async fn is_valid_signer<T: EthTransport>(
    t: &T,
    registry: Address,
    kind: Registry,
    who: Address,
    finality: Finality,
) -> Result<bool, ChainError> {
    let block = finalized_block(t, finality).await?;
    let data = encode_call(kind.valid_signer_selector(), who);
    let w = eth_call_word(t, registry, &data, CallBlock::Number(block.number)).await?;
    Ok(w != [0u8; 32])
}

/// `signerCount()` on either registry (same selector).
pub async fn signer_count<T: EthTransport>(
    t: &T,
    registry: Address,
    finality: Finality,
) -> Result<U256, ChainError> {
    let block = finalized_block(t, finality).await?;
    let w = eth_call_word(
        t,
        registry,
        &SEL_SIGNER_COUNT,
        CallBlock::Number(block.number),
    )
    .await?;
    Ok(U256::from_be_bytes(w))
}

/// The registry as the boot state machine sees it: membership + population,
/// abstracted over which registry (oracle `isValidSigner` vs bridge
/// `validSigner`) and finality. The only seam the boot rules are tested against.
pub trait ChainView {
    fn registered(&self, who: Address) -> impl Future<Output = Result<bool, ChainError>>;
    fn signer_count(&self) -> impl Future<Output = Result<U256, ChainError>>;
}

/// A [`ChainView`] backed by a live [`EthTransport`], bound to one registry.
pub struct RpcChainView<'a, T> {
    pub transport: &'a T,
    pub registry: Address,
    pub kind: Registry,
    pub finality: Finality,
}

impl<T: EthTransport> ChainView for RpcChainView<'_, T> {
    fn registered(&self, who: Address) -> impl Future<Output = Result<bool, ChainError>> {
        // Bare path-call resolves to the free fn; the trait method needs a receiver.
        is_valid_signer(self.transport, self.registry, self.kind, who, self.finality)
    }
    fn signer_count(&self) -> impl Future<Output = Result<U256, ChainError>> {
        signer_count(self.transport, self.registry, self.finality)
    }
}

async fn eth_block_number<T: EthTransport>(t: &T) -> Result<u64, ChainError> {
    let resp = t
        .rpc("eth_blockNumber", json!([]))
        .await
        .map_err(|_| ChainError::Rpc)?;
    parse_quantity(&resp).ok_or(ChainError::Rpc)
}

enum CallBlock {
    Number(u64),
    CanonicalHash(B256),
}

/// `eth_call` returning one 32-byte ABI word, pinned to `block`.
async fn eth_call_word<T: EthTransport>(
    t: &T,
    to: Address,
    data: &[u8],
    block: CallBlock,
) -> Result<[u8; 32], ChainError> {
    let block_id = match block {
        CallBlock::Number(number) => json!(format!("0x{number:x}")),
        CallBlock::CanonicalHash(hash) => json!({
            "blockHash": hex::encode_prefixed(hash),
            "requireCanonical": true,
        }),
    };
    let params = json!([
        { "to": to.to_string(), "data": hex::encode_prefixed(data) },
        block_id,
    ]);
    let resp = t
        .rpc("eth_call", params)
        .await
        .map_err(|_| ChainError::Rpc)?;
    let s = resp.as_str().ok_or(ChainError::Rpc)?;
    let bytes = decode_hex(s).ok_or(ChainError::Rpc)?;
    if bytes.len() < 32 {
        return Err(ChainError::Rpc);
    }
    let mut w = [0u8; 32];
    w.copy_from_slice(&bytes[..32]);
    Ok(w)
}

/// `selector ‖ left-padded(address)` — a single-address ABI calldata.
fn encode_call(selector: [u8; 4], arg: Address) -> Vec<u8> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&selector);
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(arg.as_slice());
    data
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).ok()
}

fn parse_quantity(v: &Value) -> Option<u64> {
    let s = v.as_str()?.strip_prefix("0x")?;
    if s.is_empty()
        || (s.len() > 1 && s.starts_with('0'))
        || !s.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    u64::from_str_radix(s, 16).ok()
}

fn parse_b256(v: &Value) -> Option<B256> {
    let bytes = decode_hex(v.as_str()?)?;
    if bytes.len() != 32 {
        return None;
    }
    Some(B256::from_slice(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    enum Resp {
        Ok(Value),
        Fail,
        UnsupportedBlockIdentifier,
    }

    /// Transport that replays scripted responses in order and records every call,
    /// so a test asserts both the outcome and the exact RPC sequence.
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
                    Some(Resp::UnsupportedBlockIdentifier) => {
                        eyre::bail!("-32602: block parameter must be a string")
                    }
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
    fn word_u64(v: u64) -> Value {
        Value::String(hex::encode_prefixed(U256::from(v).to_be_bytes::<32>()))
    }
    fn quantity(v: u64) -> Value {
        Value::String(format!("0x{v:x}"))
    }
    fn malformed_quantities() -> Vec<Value> {
        vec![
            Value::Null,
            json!(1000),
            json!(true),
            json!([]),
            json!({}),
            json!(""),
            json!("0x"),
            json!("1000"),
            json!("+1000"),
            json!("+0x1000"),
            json!("0x+1000"),
            json!("-1000"),
            json!("0x-1000"),
            json!("0x00"),
            json!("0x01000"),
            json!("0x03e8"),
            json!("0X1000"),
            json!(" 0x1000"),
            json!("0x1000 "),
            json!("0x1000\n"),
            json!("0x 1000"),
            json!("0x1_000"),
            json!("0xgg"),
            json!("0x１２"),
            json!("0x10000000000000000"),
        ]
    }
    fn burned_call_params(exit: Address, recipient: Address, hash: u8) -> Value {
        json!([
            {
                "to": exit.to_string(),
                "data": hex::encode_prefixed(encode_call(SEL_BURNED, recipient)),
            },
            { "blockHash": hex::encode_prefixed([hash; 32]), "requireCanonical": true },
        ])
    }

    #[test]
    fn quantity_accepts_canonical_unsigned_u64() {
        for (input, expected) in [
            ("0x0", 0),
            ("0x1", 1),
            ("0xa", 10),
            ("0xA", 10),
            ("0x3e8", 1000),
            ("0xffffffffffffffff", u64::MAX),
            ("0xFFFFFFFFFFFFFFFF", u64::MAX),
        ] {
            assert_eq!(parse_quantity(&json!(input)), Some(expected), "{input}");
        }
    }

    #[test]
    fn quantity_rejects_noncanonical_or_overflowing_values() {
        for malformed in malformed_quantities() {
            assert_eq!(parse_quantity(&malformed), None, "{malformed}");
        }
    }

    #[tokio::test]
    async fn finalized_with_depth_rejects_noncanonical_head_without_fallback() {
        for malformed in malformed_quantities() {
            let t = Scripted::new(vec![
                Resp::Ok(block(900, 0xAB, 1000)),
                Resp::Ok(malformed.clone()),
            ]);
            assert_eq!(
                finalized_block(&t, Finality::FinalizedWithDepth(800)).await,
                Err(ChainError::Rpc),
                "{malformed}",
            );
            assert_eq!(
                t.calls(),
                vec![
                    ("eth_getBlockByNumber".into(), json!(["finalized", false])),
                    ("eth_blockNumber".into(), json!([])),
                ],
                "{malformed}",
            );
        }
    }

    #[tokio::test]
    async fn finalized_with_depth_rejects_noncanonical_finalized_quantities() {
        for field in ["number", "timestamp"] {
            for malformed in malformed_quantities() {
                let mut response = block(900, 0xAB, 1000);
                response[field] = malformed.clone();
                let t = Scripted::new(vec![Resp::Ok(response)]);
                assert_eq!(
                    finalized_block(&t, Finality::FinalizedWithDepth(800)).await,
                    Err(ChainError::Rpc),
                    "{field}: {malformed}",
                );
                assert_eq!(
                    t.calls(),
                    vec![("eth_getBlockByNumber".into(), json!(["finalized", false]))],
                    "{field}: {malformed}",
                );
            }
        }
    }

    #[tokio::test]
    async fn burned_returns_consistent_double_read() {
        let t = Scripted::new(vec![
            Resp::Ok(block(100, 0xAB, 1000)),
            Resp::Ok(word_u64(500)),
            Resp::Ok(block(100, 0xAB, 1000)),
            Resp::Ok(word_u64(500)),
        ]);
        let exit = Address::from([0xEE; 20]);
        let recipient = Address::from([0x22; 20]);
        let (v, n) = burned_finalized(&t, exit, recipient, Finality::Tag)
            .await
            .unwrap();
        assert_eq!(v, U256::from(500));
        assert_eq!(n, 100);
        let params = burned_call_params(exit, recipient, 0xAB);
        assert_eq!(
            t.calls(),
            vec![
                ("eth_getBlockByNumber".into(), json!(["finalized", false])),
                ("eth_call".into(), params.clone()),
                ("eth_getBlockByNumber".into(), json!(["0x64", false])),
                ("eth_call".into(), params),
            ]
        );
    }

    #[tokio::test]
    async fn burned_rejects_mixed_backend_fork_despite_matching_numeric_reads() {
        struct MixedBackends;

        impl EthTransport for MixedBackends {
            async fn rpc(&self, method: &str, params: Value) -> eyre::Result<Value> {
                match method {
                    "eth_getBlockByNumber" => Ok(block(100, 0xAB, 1000)),
                    "eth_call" if params[1] == "0x64" => Ok(word_u64(900)),
                    "eth_call" => {
                        assert_eq!(
                            params,
                            burned_call_params(Address::ZERO, Address::ZERO, 0xAB)
                        );
                        eyre::bail!("selected hash is not canonical on the state backend")
                    }
                    _ => eyre::bail!("unexpected rpc call"),
                }
            }
        }

        let t = MixedBackends;
        let data = encode_call(SEL_BURNED, Address::ZERO);
        let selected = finalized_block(&t, Finality::Tag).await.unwrap();
        let first = eth_call_word(&t, Address::ZERO, &data, CallBlock::Number(selected.number))
            .await
            .unwrap();
        let second_hash = read_block_hash(&t, selected.number).await.unwrap();
        let second = eth_call_word(&t, Address::ZERO, &data, CallBlock::Number(selected.number))
            .await
            .unwrap();
        assert_eq!(selected.hash, second_hash);
        assert_eq!(first, second);
        assert_eq!(U256::from_be_bytes(first), U256::from(900));
        assert_eq!(
            burned_finalized(&t, Address::ZERO, Address::ZERO, Finality::Tag).await,
            Err(ChainError::Rpc),
        );
    }

    #[tokio::test]
    async fn burned_hash_call_errors_fail_closed_without_numeric_fallback() {
        for failed_read in [1, 2] {
            for failure in [Resp::Fail, Resp::UnsupportedBlockIdentifier] {
                let mut responses = vec![Resp::Ok(block(100, 0xAB, 1000))];
                if failed_read == 2 {
                    responses.extend([Resp::Ok(word_u64(500)), Resp::Ok(block(100, 0xAB, 1000))]);
                }
                responses.push(failure);
                let t = Scripted::new(responses);
                assert_eq!(
                    burned_finalized(&t, Address::ZERO, Address::ZERO, Finality::Tag).await,
                    Err(ChainError::Rpc),
                );
                let mut expected = vec![
                    ("eth_getBlockByNumber".into(), json!(["finalized", false])),
                    (
                        "eth_call".into(),
                        burned_call_params(Address::ZERO, Address::ZERO, 0xAB),
                    ),
                ];
                if failed_read == 2 {
                    expected.extend([
                        ("eth_getBlockByNumber".into(), json!(["0x64", false])),
                        (
                            "eth_call".into(),
                            burned_call_params(Address::ZERO, Address::ZERO, 0xAB),
                        ),
                    ]);
                }
                assert_eq!(t.calls(), expected);
            }
        }
    }

    #[tokio::test]
    async fn burned_hash_mismatch_is_read_mismatch() {
        let t = Scripted::new(vec![
            Resp::Ok(block(100, 0xAB, 1000)),
            Resp::Ok(word_u64(500)),
            Resp::Ok(block(100, 0xCD, 1000)),
            Resp::Ok(word_u64(500)),
        ]);
        assert_eq!(
            burned_finalized(&t, Address::ZERO, Address::ZERO, Finality::Tag).await,
            Err(ChainError::ReadMismatch),
        );
    }

    #[tokio::test]
    async fn burned_value_mismatch_is_read_mismatch() {
        let t = Scripted::new(vec![
            Resp::Ok(block(100, 0xAB, 1000)),
            Resp::Ok(word_u64(500)),
            Resp::Ok(block(100, 0xAB, 1000)),
            Resp::Ok(word_u64(501)),
        ]);
        assert_eq!(
            burned_finalized(&t, Address::ZERO, Address::ZERO, Finality::Tag).await,
            Err(ChainError::ReadMismatch),
        );
    }

    #[tokio::test]
    async fn head_minus_pins_latest_minus_depth() {
        // Resolve height 231 once; both value reads use its canonical hash.
        let t = Scripted::new(vec![
            Resp::Ok(quantity(1000)),
            Resp::Ok(block(231, 0xAB, 1)),
            Resp::Ok(word_u64(7)),
            Resp::Ok(block(231, 0xAB, 1)),
            Resp::Ok(word_u64(7)),
        ]);
        let (v, n) = burned_finalized(&t, Address::ZERO, Address::ZERO, Finality::HeadMinus(769))
            .await
            .unwrap();
        assert_eq!(v, U256::from(7));
        assert_eq!(n, 231);
        let calls = t.calls();
        assert_eq!(calls.iter().filter(|c| c.0 == "eth_blockNumber").count(), 1);
        assert_eq!(calls[0].0, "eth_blockNumber");
        assert_eq!(calls[1].0, "eth_getBlockByNumber");
        assert_eq!(calls[1].1[0], "0xe7");
        let params = burned_call_params(Address::ZERO, Address::ZERO, 0xAB);
        assert_eq!(calls[2], ("eth_call".into(), params.clone()));
        assert_eq!(calls[3].0, "eth_getBlockByNumber"); // re-fetch same height
        assert_eq!(calls[3].1[0], "0xe7");
        assert_eq!(calls[4], ("eth_call".into(), params));
    }

    #[tokio::test]
    async fn finalized_with_depth_uses_finalized_at_or_below_cap() {
        for number in [150, 200] {
            let t = Scripted::new(vec![
                Resp::Ok(block(number, 0xAB, 1000)),
                Resp::Ok(quantity(1000)),
            ]);
            assert_eq!(
                finalized_block(&t, Finality::FinalizedWithDepth(800)).await,
                Ok(BlockRef {
                    number,
                    hash: B256::from([0xAB; 32]),
                    timestamp: 1000,
                }),
            );
            assert_eq!(
                t.calls(),
                vec![
                    ("eth_getBlockByNumber".into(), json!(["finalized", false])),
                    ("eth_blockNumber".into(), json!([])),
                ]
            );
        }
    }

    #[tokio::test]
    async fn finalized_with_depth_caps_newer_finalized_block() {
        let t = Scripted::new(vec![
            Resp::Ok(block(232, 0xAB, 1000)),
            Resp::Ok(quantity(1000)),
            Resp::Ok(block(200, 0xCD, 900)),
        ]);
        assert_eq!(
            finalized_block(&t, Finality::FinalizedWithDepth(800)).await,
            Ok(BlockRef {
                number: 200,
                hash: B256::from([0xCD; 32]),
                timestamp: 900,
            }),
        );
        assert_eq!(
            t.calls(),
            vec![
                ("eth_getBlockByNumber".into(), json!(["finalized", false])),
                ("eth_blockNumber".into(), json!([])),
                ("eth_getBlockByNumber".into(), json!(["0xc8", false])),
            ]
        );
    }

    #[tokio::test]
    async fn finalized_with_depth_rejects_unavailable_or_malformed_tag_without_fallback() {
        let mut failures = vec![Resp::Fail, Resp::Ok(Value::Null), Resp::Ok(json!({}))];
        for field in ["number", "hash", "timestamp"] {
            let mut missing = block(232, 0xAB, 1000);
            missing.as_object_mut().unwrap().remove(field);
            failures.push(Resp::Ok(missing));
            for malformed in [Value::Null, json!(232), json!("not-hex"), json!("0x")] {
                let mut response = block(232, 0xAB, 1000);
                response[field] = malformed;
                failures.push(Resp::Ok(response));
            }
        }
        for response in failures {
            let t = Scripted::new(vec![response]);
            assert_eq!(
                finalized_block(&t, Finality::FinalizedWithDepth(800)).await,
                Err(ChainError::Rpc),
            );
            assert_eq!(
                t.calls(),
                vec![("eth_getBlockByNumber".into(), json!(["finalized", false])),]
            );
        }
    }

    #[tokio::test]
    async fn finalized_with_depth_rejects_shallow_or_unreadable_head() {
        for response in [
            Resp::Fail,
            Resp::Ok(Value::Null),
            Resp::Ok(json!("0xgg")),
            Resp::Ok(json!("0x10000000000000000")),
            Resp::Ok(quantity(799)),
            Resp::Ok(quantity(0)),
        ] {
            let t = Scripted::new(vec![Resp::Ok(block(1, 0xAB, 1000)), response]);
            assert_eq!(
                finalized_block(&t, Finality::FinalizedWithDepth(800)).await,
                Err(ChainError::Rpc),
            );
            assert_eq!(
                t.calls(),
                vec![
                    ("eth_getBlockByNumber".into(), json!(["finalized", false])),
                    ("eth_blockNumber".into(), json!([])),
                ]
            );
        }
    }

    #[tokio::test]
    async fn finalized_with_depth_allows_exact_depth_at_genesis() {
        let t = Scripted::new(vec![
            Resp::Ok(block(1, 0xAB, 1000)),
            Resp::Ok(quantity(800)),
            Resp::Ok(block(0, 0xCD, 900)),
        ]);
        let selected = finalized_block(&t, Finality::FinalizedWithDepth(800))
            .await
            .unwrap();
        assert_eq!(selected.number, 0);
        assert_eq!(t.calls()[2].1, json!(["0x0", false]));
    }

    #[tokio::test]
    async fn explicit_height_response_must_match_requested_number() {
        for finality in [Finality::HeadMinus(800), Finality::FinalizedWithDepth(800)] {
            let mut responses = Vec::new();
            if matches!(finality, Finality::FinalizedWithDepth(_)) {
                responses.push(Resp::Ok(block(232, 0xAB, 1000)));
            }
            responses.extend([Resp::Ok(quantity(1000)), Resp::Ok(block(201, 0xAB, 900))]);
            let t = Scripted::new(responses);
            assert_eq!(
                finalized_block(&t, finality).await,
                Err(ChainError::ReadMismatch)
            );
            assert_eq!(t.calls().last().unwrap().1, json!(["0xc8", false]));
        }
    }

    #[tokio::test]
    async fn burned_with_depth_pins_both_reads_to_selected_hash() {
        for finalized in [150, 200, 232] {
            let target = finalized.min(200);
            let target_hash = if target == finalized { 0xAB } else { 0xCD };
            let mut responses = vec![
                Resp::Ok(block(finalized, 0xAB, 1000)),
                Resp::Ok(quantity(1000)),
            ];
            if target != finalized {
                responses.push(Resp::Ok(block(target, target_hash, 900)));
            }
            responses.extend([
                Resp::Ok(word_u64(500)),
                Resp::Ok(block(target, target_hash, 900)),
                Resp::Ok(word_u64(500)),
            ]);
            let t = Scripted::new(responses);
            assert_eq!(
                burned_finalized(
                    &t,
                    Address::ZERO,
                    Address::ZERO,
                    Finality::FinalizedWithDepth(800)
                )
                .await,
                Ok((U256::from(500), target)),
            );
            let calls = t.calls();
            assert_eq!(calls.iter().filter(|c| c.0 == "eth_blockNumber").count(), 1);
            let pinned_tag = json!(format!("0x{target:x}"));
            let params = burned_call_params(Address::ZERO, Address::ZERO, target_hash);
            let value_reads: Vec<_> = calls.iter().filter(|c| c.0 == "eth_call").collect();
            assert_eq!(value_reads.len(), 2);
            assert!(value_reads.iter().all(|c| c.1 == params));
            let hash_reads: Vec<_> = calls
                .iter()
                .filter(|c| c.0 == "eth_getBlockByNumber")
                .collect();
            assert_eq!(hash_reads[0].1[0], "finalized");
            assert_eq!(hash_reads.len(), if target == finalized { 2 } else { 3 });
            assert!(hash_reads[1..].iter().all(|c| c.1[0] == pinned_tag));
        }
    }

    #[tokio::test]
    async fn burned_with_depth_rejects_hash_or_value_disagreement() {
        for finalized in [150, 232] {
            for (hash2, value2) in [(0xCD, 500), (0xAB, 501)] {
                let target = finalized.min(200);
                let mut responses = vec![
                    Resp::Ok(block(finalized, 0xAB, 1000)),
                    Resp::Ok(quantity(1000)),
                ];
                if target != finalized {
                    responses.push(Resp::Ok(block(target, 0xAB, 900)));
                }
                responses.extend([
                    Resp::Ok(word_u64(500)),
                    Resp::Ok(block(target, hash2, 900)),
                    Resp::Ok(word_u64(value2)),
                ]);
                let t = Scripted::new(responses);
                assert_eq!(
                    burned_finalized(
                        &t,
                        Address::ZERO,
                        Address::ZERO,
                        Finality::FinalizedWithDepth(800)
                    )
                    .await,
                    Err(ChainError::ReadMismatch),
                );
                assert_eq!(t.calls().iter().filter(|c| c.0 == "eth_call").count(), 2);
            }
        }
    }

    #[tokio::test]
    async fn burned_rejects_wrong_reread_height_even_when_hash_matches() {
        for finality in [
            Finality::Tag,
            Finality::HeadMinus(800),
            Finality::FinalizedWithDepth(800),
        ] {
            let mut responses = match finality {
                Finality::Tag => vec![Resp::Ok(block(200, 0xAB, 1000))],
                Finality::HeadMinus(_) => {
                    vec![Resp::Ok(quantity(1000)), Resp::Ok(block(200, 0xAB, 900))]
                }
                Finality::FinalizedWithDepth(_) => vec![
                    Resp::Ok(block(232, 0xAB, 1000)),
                    Resp::Ok(quantity(1000)),
                    Resp::Ok(block(200, 0xAB, 900)),
                ],
            };
            responses.extend([
                Resp::Ok(word_u64(500)),
                Resp::Ok(block(201, 0xAB, 900)),
                Resp::Ok(word_u64(500)),
            ]);
            let t = Scripted::new(responses);
            assert_eq!(
                burned_finalized(&t, Address::ZERO, Address::ZERO, finality).await,
                Err(ChainError::ReadMismatch),
            );
        }
    }

    #[tokio::test]
    async fn head_minus_still_saturates_at_genesis() {
        let t = Scripted::new(vec![Resp::Ok(quantity(1)), Resp::Ok(block(0, 0xAB, 1000))]);
        assert_eq!(
            finalized_block(&t, Finality::HeadMinus(769))
                .await
                .unwrap()
                .number,
            0
        );
        assert_eq!(
            t.calls(),
            vec![
                ("eth_blockNumber".into(), json!([])),
                ("eth_getBlockByNumber".into(), json!(["0x0", false])),
            ]
        );
    }

    #[tokio::test]
    async fn oracle_valid_signer_uses_is_valid_signer_selector() {
        let t = Scripted::new(vec![Resp::Ok(block(5, 0x01, 1)), Resp::Ok(word_u64(1))]);
        let ok = is_valid_signer(
            &t,
            Address::from([0x44; 20]),
            Registry::Oracle,
            Address::from([0x33; 20]),
            Finality::Tag,
        )
        .await
        .unwrap();
        assert!(ok);
        assert_eq!(t.calls()[1].1[1], "0x5");
        let data = t.calls()[1].1[0]["data"].as_str().unwrap().to_owned();
        assert!(
            data.starts_with("0xd5f50582"),
            "oracle uses isValidSigner: {data}"
        );
        assert!(data.ends_with(hex::encode([0x33u8; 20]).as_str()));
    }

    #[tokio::test]
    async fn bridge_valid_signer_uses_valid_signer_selector_and_decodes_false() {
        let t = Scripted::new(vec![Resp::Ok(block(5, 0x01, 1)), Resp::Ok(word_u64(0))]);
        let ok = is_valid_signer(
            &t,
            Address::from([0x44; 20]),
            Registry::Bridge,
            Address::from([0x33; 20]),
            Finality::Tag,
        )
        .await
        .unwrap();
        assert!(!ok);
        assert_eq!(t.calls()[1].1[1], "0x5");
        let data = t.calls()[1].1[0]["data"].as_str().unwrap().to_owned();
        assert!(
            data.starts_with("0xba6f8b0e"),
            "bridge uses validSigner: {data}"
        );
    }

    #[tokio::test]
    async fn signer_count_decodes_word_and_uses_selector() {
        let t = Scripted::new(vec![Resp::Ok(block(5, 0x01, 1)), Resp::Ok(word_u64(2))]);
        let n = signer_count(&t, Address::from([0x44; 20]), Finality::Tag)
            .await
            .unwrap();
        assert_eq!(n, U256::from(2));
        assert_eq!(t.calls()[1].1[1], "0x5");
        assert_eq!(t.calls()[1].1[0]["data"].as_str().unwrap(), "0x7ca548c6");
    }

    #[tokio::test]
    async fn finalized_block_exposes_number_hash_timestamp() {
        let t = Scripted::new(vec![Resp::Ok(block(42, 0x7F, 1_789_000_000))]);
        let b = finalized_block(&t, Finality::Tag).await.unwrap();
        assert_eq!(b.number, 42);
        assert_eq!(b.timestamp, 1_789_000_000);
        assert_eq!(b.hash, B256::from([0x7F; 32]));
    }

    #[test]
    fn ensure_not_decreasing_refuses_only_strict_decrease() {
        assert!(ensure_not_decreasing(U256::from(5), U256::from(5)).is_ok());
        assert!(ensure_not_decreasing(U256::from(6), U256::from(5)).is_ok());
        assert_eq!(
            ensure_not_decreasing(U256::from(4), U256::from(5)),
            Err(ChainError::DecreasingBurned),
        );
    }

    #[test]
    fn encode_call_is_selector_then_padded_address() {
        let data = encode_call(SEL_BURNED, Address::from([0x22; 20]));
        assert_eq!(data.len(), 36);
        assert_eq!(&data[..4], &SEL_BURNED);
        assert_eq!(&data[4..16], &[0u8; 12]);
        assert_eq!(&data[16..], &[0x22u8; 20]);
    }

    #[tokio::test]
    async fn transport_failure_maps_to_rpc_error() {
        let t = Scripted::new(vec![Resp::Fail]);
        assert_eq!(
            finalized_block(&t, Finality::Tag).await,
            Err(ChainError::Rpc)
        );
    }

    #[tokio::test]
    async fn empty_call_return_is_rpc_error() {
        // A revert with no return data (`0x`) must not decode to a phantom zero.
        let t = Scripted::new(vec![
            Resp::Ok(block(5, 0x01, 1)),
            Resp::Ok(Value::String("0x".to_owned())),
        ]);
        assert_eq!(
            signer_count(&t, Address::ZERO, Finality::Tag).await,
            Err(ChainError::Rpc)
        );
    }

    #[test]
    fn chain_error_maps_to_claim_error() {
        use crate::claim::ClaimError;
        assert_eq!(
            ClaimError::from(ChainError::ReadMismatch),
            ClaimError::ReadMismatch
        );
        assert_eq!(
            ClaimError::from(ChainError::DecreasingBurned),
            ClaimError::DecreasingBurned
        );
        assert_eq!(ClaimError::from(ChainError::Rpc), ClaimError::RpcError);
    }

    #[tokio::test]
    async fn rpc_chain_view_registered_routes_oracle_selector() {
        let t = Scripted::new(vec![Resp::Ok(block(5, 0x01, 1)), Resp::Ok(word_u64(1))]);
        let view = RpcChainView {
            transport: &t,
            registry: Address::from([0x44; 20]),
            kind: Registry::Oracle,
            finality: Finality::Tag,
        };
        assert!(view.registered(Address::from([0x33; 20])).await.unwrap());
        let data = t.calls()[1].1[0]["data"].as_str().unwrap().to_owned();
        assert!(
            data.starts_with("0xd5f50582"),
            "oracle view uses isValidSigner: {data}"
        );
    }

    #[tokio::test]
    async fn rpc_chain_view_registered_routes_bridge_selector() {
        let t = Scripted::new(vec![Resp::Ok(block(5, 0x01, 1)), Resp::Ok(word_u64(0))]);
        let view = RpcChainView {
            transport: &t,
            registry: Address::from([0x44; 20]),
            kind: Registry::Bridge,
            finality: Finality::Tag,
        };
        assert!(!view.registered(Address::from([0x33; 20])).await.unwrap());
        let data = t.calls()[1].1[0]["data"].as_str().unwrap().to_owned();
        assert!(
            data.starts_with("0xba6f8b0e"),
            "bridge view uses validSigner: {data}"
        );
    }

    #[tokio::test]
    async fn rpc_chain_view_signer_count_forwards() {
        let t = Scripted::new(vec![Resp::Ok(block(5, 0x01, 1)), Resp::Ok(word_u64(3))]);
        let view = RpcChainView {
            transport: &t,
            registry: Address::from([0x44; 20]),
            kind: Registry::Bridge,
            finality: Finality::Tag,
        };
        assert_eq!(view.signer_count().await.unwrap(), U256::from(3));
        assert_eq!(t.calls()[1].1[0]["data"].as_str().unwrap(), "0x7ca548c6");
    }
}
