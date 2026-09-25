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
    /// `latest - depth` (Igra's load-balanced RPC; measured depth 769).
    HeadMinus(u64),
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

/// Resolve the block a read pins to. `Tag` reads `eth_getBlockByNumber("finalized")`
/// directly; `HeadMinus(d)` resolves `latest - d` first. The timestamp feeds the
/// claim deadline's clock cross-check.
pub async fn finalized_block<T: EthTransport>(
    t: &T,
    finality: Finality,
) -> Result<BlockRef, ChainError> {
    let tag = match finality {
        Finality::Tag => "finalized".to_owned(),
        Finality::HeadMinus(depth) => {
            let latest = eth_block_number(t).await?;
            format!("0x{:x}", latest.saturating_sub(depth))
        }
    };
    let resp = t
        .rpc("eth_getBlockByNumber", json!([tag, false]))
        .await
        .map_err(|_| ChainError::Rpc)?;
    let number = parse_quantity(resp.get("number").ok_or(ChainError::Rpc)?).ok_or(ChainError::Rpc)?;
    let hash = parse_b256(resp.get("hash").ok_or(ChainError::Rpc)?).ok_or(ChainError::Rpc)?;
    let timestamp =
        parse_quantity(resp.get("timestamp").ok_or(ChainError::Rpc)?).ok_or(ChainError::Rpc)?;
    Ok(BlockRef { number, hash, timestamp })
}

/// `KskdExit.burned(recipient)` at finality, returned with the block number it was
/// read at so a claim can pin `igraBlock` to the exact height of the signed value.
/// The target height is resolved ONCE, then value and block hash are each read
/// twice AT THAT FIXED height and must agree, else `ReadMismatch` (guards a
/// load-balanced RPC serving another chain at this height). Re-resolving `latest`
/// per read would instead trip on ordinary chain advance. The decreasing-vs-last-
/// signed check is the caller's ([`ensure_not_decreasing`]) — stateless across restarts.
pub async fn burned_finalized<T: EthTransport>(
    t: &T,
    exit: Address,
    recipient: Address,
    finality: Finality,
) -> Result<(U256, u64), ChainError> {
    let block = finalized_block(t, finality).await?;
    let data = encode_call(SEL_BURNED, recipient);
    let v1 = eth_call_word(t, exit, &data, block.number).await?;
    let hash2 = read_block_hash(t, block.number).await?;
    let v2 = eth_call_word(t, exit, &data, block.number).await?;
    if block.hash != hash2 || v1 != v2 {
        return Err(ChainError::ReadMismatch);
    }
    Ok((U256::from_be_bytes(v1), block.number))
}

/// Block hash at an explicit height, for the burned double-read's second pass.
async fn read_block_hash<T: EthTransport>(t: &T, number: u64) -> Result<B256, ChainError> {
    let resp = t
        .rpc("eth_getBlockByNumber", json!([format!("0x{number:x}"), false]))
        .await
        .map_err(|_| ChainError::Rpc)?;
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
    let w = eth_call_word(t, registry, &data, block.number).await?;
    Ok(w != [0u8; 32])
}

/// `signerCount()` on either registry (same selector).
pub async fn signer_count<T: EthTransport>(
    t: &T,
    registry: Address,
    finality: Finality,
) -> Result<U256, ChainError> {
    let block = finalized_block(t, finality).await?;
    let w = eth_call_word(t, registry, &SEL_SIGNER_COUNT, block.number).await?;
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
    let resp = t.rpc("eth_blockNumber", json!([])).await.map_err(|_| ChainError::Rpc)?;
    parse_quantity(&resp).ok_or(ChainError::Rpc)
}

/// `eth_call` returning one 32-byte ABI word, pinned to `block`.
async fn eth_call_word<T: EthTransport>(
    t: &T,
    to: Address,
    data: &[u8],
    block: u64,
) -> Result<[u8; 32], ChainError> {
    let params = json!([
        { "to": to.to_string(), "data": hex::encode_prefixed(data) },
        format!("0x{block:x}"),
    ]);
    let resp = t.rpc("eth_call", params).await.map_err(|_| ChainError::Rpc)?;
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
    let s = v.as_str()?;
    let s = s.strip_prefix("0x").unwrap_or(s);
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
    }

    /// Transport that replays scripted responses in order and records every call,
    /// so a test asserts both the outcome and the exact RPC sequence.
    struct Scripted {
        responses: Mutex<VecDeque<Resp>>,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl Scripted {
        fn new(responses: Vec<Resp>) -> Self {
            Self { responses: Mutex::new(responses.into()), calls: Mutex::new(Vec::new()) }
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
    fn word_u64(v: u64) -> Value {
        Value::String(hex::encode_prefixed(U256::from(v).to_be_bytes::<32>()))
    }
    fn quantity(v: u64) -> Value {
        Value::String(format!("0x{v:x}"))
    }

    #[tokio::test]
    async fn burned_returns_consistent_double_read() {
        let t = Scripted::new(vec![
            Resp::Ok(block(100, 0xAB, 1000)),
            Resp::Ok(word_u64(500)),
            Resp::Ok(block(100, 0xAB, 1000)),
            Resp::Ok(word_u64(500)),
        ]);
        let (v, n) =
            burned_finalized(&t, Address::from([0xEE; 20]), Address::from([0x22; 20]), Finality::Tag)
                .await
                .unwrap();
        assert_eq!(v, U256::from(500));
        assert_eq!(n, 100); // returns the height the value was read at
        let calls = t.calls();
        assert_eq!(calls[0].0, "eth_getBlockByNumber");
        assert_eq!(calls[0].1[0], "finalized");
        assert_eq!(calls[1].0, "eth_call");
        assert_eq!(calls[1].1[1], "0x64"); // eth_call pinned to block 100
        // Second pass re-fetches the SAME height, never re-resolves the tag.
        assert_eq!(calls[2].0, "eth_getBlockByNumber");
        assert_eq!(calls[2].1[0], "0x64");
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
        // latest 1000, depth 769 → target 231 = 0xe7. The height is resolved ONCE:
        // both burned reads pin 0xe7, so ordinary chain advance cannot trip
        // ReadMismatch and only ONE eth_blockNumber is ever issued.
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
        assert_eq!(calls[2].0, "eth_call");
        assert_eq!(calls[2].1[1], "0xe7");
        assert_eq!(calls[3].0, "eth_getBlockByNumber"); // re-fetch same height
        assert_eq!(calls[3].1[0], "0xe7");
        assert_eq!(calls[4].0, "eth_call");
        assert_eq!(calls[4].1[1], "0xe7");
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
        let data = t.calls()[1].1[0]["data"].as_str().unwrap().to_owned();
        assert!(data.starts_with("0xd5f50582"), "oracle uses isValidSigner: {data}");
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
        let data = t.calls()[1].1[0]["data"].as_str().unwrap().to_owned();
        assert!(data.starts_with("0xba6f8b0e"), "bridge uses validSigner: {data}");
    }

    #[tokio::test]
    async fn signer_count_decodes_word_and_uses_selector() {
        let t = Scripted::new(vec![Resp::Ok(block(5, 0x01, 1)), Resp::Ok(word_u64(2))]);
        let n = signer_count(&t, Address::from([0x44; 20]), Finality::Tag).await.unwrap();
        assert_eq!(n, U256::from(2));
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
        assert_eq!(finalized_block(&t, Finality::Tag).await, Err(ChainError::Rpc));
    }

    #[tokio::test]
    async fn empty_call_return_is_rpc_error() {
        // A revert with no return data (`0x`) must not decode to a phantom zero.
        let t = Scripted::new(vec![Resp::Ok(block(5, 0x01, 1)), Resp::Ok(Value::String("0x".to_owned()))]);
        assert_eq!(signer_count(&t, Address::ZERO, Finality::Tag).await, Err(ChainError::Rpc));
    }

    #[test]
    fn chain_error_maps_to_claim_error() {
        use crate::claim::ClaimError;
        assert_eq!(ClaimError::from(ChainError::ReadMismatch), ClaimError::ReadMismatch);
        assert_eq!(ClaimError::from(ChainError::DecreasingBurned), ClaimError::DecreasingBurned);
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
        assert!(data.starts_with("0xd5f50582"), "oracle view uses isValidSigner: {data}");
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
        assert!(data.starts_with("0xba6f8b0e"), "bridge view uses validSigner: {data}");
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
