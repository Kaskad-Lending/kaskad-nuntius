//! VUSD backing ratio (`VUSD_NAV`) read from Ethereum through one Multicall3
//! `eth_call` per keyless RPC operator. Each operator is its own source; all
//! eight share one poller that queries them in parallel once per cycle.

use std::fmt;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use alloy_primitives::{address, Address, U256};
use alloy_sol_types::{sol, SolCall};
use async_trait::async_trait;
use eyre::{eyre, Result};
use futures::future::join_all;
use serde_json::Value;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use super::PriceSource;
use crate::http_client::{HttpClient, RetryPolicy, GET_POLICY};
use crate::types::{AssetConfig, PricePoint};

/// The only pair these sources serve; any other pair is a config error.
const VUSD_NAV: &str = "VUSD_NAV";

const VUSD: Address = address!("0xCa83DDE9c22254f58e771bE5E157773212AcBAc3");
const TREASURY: Address = address!("0xC8317A10385BE07901A4c9ee3d06E1D83AE378c9");
const GATEWAY: Address = address!("0xDaD503F8B9d42bb7af3AfC588358D30163e4416F");
const MULTICALL3: Address = address!("0xcA11bde05977b3631167028862bE2a173976CA11");

/// Covers the p95 latency of every operator in the SPEC §8 soak.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);

/// GET transport rules under one deadline shared by both attempts (SPEC §16).
const RPC_POLICY: RetryPolicy = RetryPolicy {
    deadline: REQUEST_TIMEOUT,
    ..GET_POLICY
};

// `aggregate` returns (blockNumber, bytes[6]) and every element is one word.
const WORD_BYTES: usize = 32;
const RESPONSE_WORDS: usize = 21;
const ELEMENTS: usize = 6;
const ARRAY_OFFSET: u64 = 0x40;
const ELEMENT_OFFSETS: [u64; ELEMENTS] = [0xc0, 0x100, 0x140, 0x180, 0x1c0, 0x200];
const ELEMENT_BYTES: u64 = 0x20;

const ONE_1E8: u64 = 100_000_000;
const MAX_BLOCK_AHEAD_SECS: u64 = 30;
const MAX_BLOCK_AGE_SECS: u64 = 180;
/// `reserve`, `totalSupply` and `amoSupply` must stay below 2^128.
const VALUE_BITS: usize = 128;
const BPS: u64 = 10_000;
const AMO_SHARE_LIMIT_BPS: u64 = 100;

sol! {
    interface IPeggedToken {
        function treasury() external view returns (address);
        function gateway() external view returns (address);
        function totalSupply() external view returns (uint256);
    }

    interface ITreasury {
        function reserve() external view returns (uint256);
    }

    interface IGateway {
        function amoSupply() external view returns (uint256);
    }

    interface IMulticall3 {
        struct Call {
            address target;
            bytes callData;
        }

        function aggregate(Call[] calldata calls)
            external
            payable
            returns (uint256 blockNumber, bytes[] memory returnData);

        function getCurrentBlockTimestamp() external view returns (uint256 timestamp);
    }
}

/// Multicall3 `aggregate` over the six reads, in the order the decoder expects.
fn calldata() -> Vec<u8> {
    let call = |target: Address, data: Vec<u8>| IMulticall3::Call {
        target,
        callData: data.into(),
    };
    IMulticall3::aggregateCall {
        calls: vec![
            call(VUSD, IPeggedToken::treasuryCall {}.abi_encode()),
            call(VUSD, IPeggedToken::gatewayCall {}.abi_encode()),
            call(TREASURY, ITreasury::reserveCall {}.abi_encode()),
            call(VUSD, IPeggedToken::totalSupplyCall {}.abi_encode()),
            call(GATEWAY, IGateway::amoSupplyCall {}.abi_encode()),
            call(
                MULTICALL3,
                IMulticall3::getCurrentBlockTimestampCall {}.abi_encode(),
            ),
        ],
    }
    .abi_encode()
}

/// JSON-RPC `eth_call` body sent to every operator, byte for byte SPEC §3.
static REQUEST_BODY: LazyLock<Vec<u8>> = LazyLock::new(|| {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{{"to":"{}","data":"0x{}"}},"latest"]}}"#,
        MULTICALL3.to_checksum(None),
        hex::encode(calldata())
    )
    .into_bytes()
});

/// Keyless public Ethereum RPC operators; each one is a separate source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operator {
    PublicNode,
    Tenderly,
    Drpc,
    BlastApi,
    MevBlocker,
    Bloxroute,
    Nodies,
    ZeroXRpc,
}

const OPERATORS: usize = Operator::ALL.len();

impl Operator {
    /// Declaration order; `slot()` indexes into it.
    const ALL: [Operator; 8] = [
        Operator::PublicNode,
        Operator::Tenderly,
        Operator::Drpc,
        Operator::BlastApi,
        Operator::MevBlocker,
        Operator::Bloxroute,
        Operator::Nodies,
        Operator::ZeroXRpc,
    ];

    fn name(self) -> &'static str {
        match self {
            Operator::PublicNode => "ethrpc_publicnode",
            Operator::Tenderly => "ethrpc_tenderly",
            Operator::Drpc => "ethrpc_drpc",
            Operator::BlastApi => "ethrpc_blastapi",
            Operator::MevBlocker => "ethrpc_mevblocker",
            Operator::Bloxroute => "ethrpc_bloxroute",
            Operator::Nodies => "ethrpc_nodies",
            Operator::ZeroXRpc => "ethrpc_0xrpc",
        }
    }

    fn url(self) -> &'static str {
        match self {
            Operator::PublicNode => "https://ethereum-rpc.publicnode.com",
            Operator::Tenderly => "https://mainnet.gateway.tenderly.co",
            Operator::Drpc => "https://eth.drpc.org",
            Operator::BlastApi => "https://eth-mainnet.public.blastapi.io",
            Operator::MevBlocker => "https://rpc.mevblocker.io",
            Operator::Bloxroute => "https://eth.rpc.blxrbdn.com",
            Operator::Nodies => "https://eth-pokt.nodies.app",
            Operator::ZeroXRpc => "https://0xrpc.io/eth",
        }
    }

    fn slot(self) -> usize {
        self as usize
    }
}

/// Why a response yields no sample. Variants follow the SPEC §4 check order;
/// the first failing check decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NavReject {
    RpcError,
    BadEncoding,
    BadLength,
    BadLayout,
    PointerMismatch,
    BlockAhead,
    BlockStale,
    ValueOutOfRange,
    NoBackedSupply,
    AmoShareExceeded,
    ZeroPrice,
}

impl fmt::Display for NavReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NavReject::RpcError => "RPC_ERROR",
            NavReject::BadEncoding => "BAD_ENCODING",
            NavReject::BadLength => "BAD_LENGTH",
            NavReject::BadLayout => "BAD_LAYOUT",
            NavReject::PointerMismatch => "POINTER_MISMATCH",
            NavReject::BlockAhead => "BLOCK_AHEAD",
            NavReject::BlockStale => "BLOCK_STALE",
            NavReject::ValueOutOfRange => "VALUE_OUT_OF_RANGE",
            NavReject::NoBackedSupply => "NO_BACKED_SUPPLY",
            NavReject::AmoShareExceeded => "AMO_SHARE_EXCEEDED",
            NavReject::ZeroPrice => "ZERO_PRICE",
        })
    }
}

/// An accepted response: price in 1e-8 USD and the block it was read at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NavReading {
    price_1e8: u64,
    block: U256,
}

fn address_word(address: Address) -> U256 {
    U256::from_be_slice(address.as_slice())
}

/// Decodes one JSON-RPC body against the unix time of its `Date` header,
/// mirroring `reference.py::price_1e8` check for check.
fn parse_nav(body: &Value, date_unix: u64) -> Result<NavReading, NavReject> {
    let result = body
        .get("result")
        .and_then(Value::as_str)
        .ok_or(NavReject::RpcError)?;
    let digits = result.strip_prefix("0x").ok_or(NavReject::BadEncoding)?;
    let raw = hex::decode(digits).map_err(|_| NavReject::BadEncoding)?;
    if raw.len() != RESPONSE_WORDS * WORD_BYTES {
        return Err(NavReject::BadLength);
    }
    let word = |i: usize| U256::from_be_slice(&raw[i * WORD_BYTES..(i + 1) * WORD_BYTES]);

    let layout_ok = word(1) == U256::from(ARRAY_OFFSET)
        && word(2) == U256::from(ELEMENTS)
        && (0..ELEMENTS).all(|i| word(3 + i) == U256::from(ELEMENT_OFFSETS[i]))
        && (0..ELEMENTS).all(|i| word(9 + 2 * i) == U256::from(ELEMENT_BYTES));
    if !layout_ok {
        return Err(NavReject::BadLayout);
    }
    let [treasury, gateway, reserve, supply, amo, block_ts]: [U256; ELEMENTS] =
        std::array::from_fn(|i| word(10 + 2 * i));

    if treasury != address_word(TREASURY) || gateway != address_word(GATEWAY) {
        return Err(NavReject::PointerMismatch);
    }
    let date = U256::from(date_unix);
    if block_ts > date + U256::from(MAX_BLOCK_AHEAD_SECS) {
        return Err(NavReject::BlockAhead);
    }
    if date > block_ts.saturating_add(U256::from(MAX_BLOCK_AGE_SECS)) {
        return Err(NavReject::BlockStale);
    }
    if [reserve, supply, amo]
        .iter()
        .any(|v| v.bit_len() > VALUE_BITS)
    {
        return Err(NavReject::ValueOutOfRange);
    }
    if supply.is_zero() || amo >= supply {
        return Err(NavReject::NoBackedSupply);
    }
    // Operands are below 2^128, so no product below can overflow 256 bits.
    if amo * U256::from(BPS) > supply * U256::from(AMO_SHARE_LIMIT_BPS) {
        return Err(NavReject::AmoShareExceeded);
    }
    let one = U256::from(ONE_1E8);
    let price = (reserve * one / (supply - amo)).min(one);
    if price.is_zero() {
        return Err(NavReject::ZeroPrice);
    }
    Ok(NavReading {
        price_1e8: price.saturating_to(),
        block: word(0),
    })
}

/// JSON-RPC POST seam: `HttpClient` in production, a scripted mock in tests.
#[async_trait]
trait RpcTransport: Send + Sync {
    /// Parsed response body and the response `Date` as unix seconds.
    async fn post(&self, url: &'static str, body: &'static [u8]) -> Result<(Value, u64)>;
}

#[async_trait]
impl RpcTransport for HttpClient {
    async fn post(&self, url: &'static str, body: &'static [u8]) -> Result<(Value, u64)> {
        Ok(self.post_json_with_time(url, body, &RPC_POLICY).await?)
    }
}

/// One operator's outcome from one round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NavSample {
    price_1e8: u64,
    server_time: u64,
    block: U256,
}

/// Polls every operator in parallel and hands each result out exactly once.
/// A take that finds no pending result for its operator starts a new round,
/// which replaces every slot; the lock keeps concurrent takes to one round.
struct NavPoller {
    transport: Box<dyn RpcTransport>,
    slots: Mutex<[Option<Result<NavSample>>; OPERATORS]>,
}

impl NavPoller {
    fn new(transport: Box<dyn RpcTransport>) -> Self {
        Self {
            transport,
            slots: Mutex::new([const { None }; OPERATORS]),
        }
    }

    async fn take(&self, operator: Operator) -> Result<NavSample> {
        let mut slots = self.slots.lock().await;
        if slots[operator.slot()].is_none() {
            *slots = self.round().await;
        }
        slots[operator.slot()]
            .take()
            .unwrap_or_else(|| Err(eyre!("{}: round left no result", operator.name())))
    }

    /// Polls every operator at once; each slot holds its operator's outcome.
    async fn round(&self) -> [Option<Result<NavSample>>; OPERATORS] {
        let started = Instant::now();
        let outcomes = join_all(
            Operator::ALL.map(|operator| async move { (operator, self.poll(operator).await) }),
        )
        .await;
        let mut slots = [const { None }; OPERATORS];
        for (operator, outcome) in outcomes {
            slots[operator.slot()] = Some(outcome);
        }

        let elapsed_ms = started.elapsed().as_millis() as u64;
        let blocks: Vec<U256> = slots
            .iter()
            .flatten()
            .filter_map(|r| r.as_ref().ok().map(|s| s.block))
            .collect();
        match (blocks.iter().min(), blocks.iter().max()) {
            (Some(min_block), Some(max_block)) => info!(
                accepted = blocks.len(),
                operators = OPERATORS,
                elapsed_ms,
                %min_block,
                %max_block,
                "VUSD NAV round"
            ),
            _ => warn!(
                operators = OPERATORS,
                elapsed_ms, "VUSD NAV round: no operator answered"
            ),
        }
        slots
    }

    async fn poll(&self, operator: Operator) -> Result<NavSample> {
        let (body, server_time) = self
            .transport
            .post(operator.url(), REQUEST_BODY.as_slice())
            .await?;
        let reading = parse_nav(&body, server_time)
            .map_err(|reject| eyre!("{} response rejected: {}", VUSD_NAV, reject))?;
        debug!(
            source = operator.name(),
            block = %reading.block,
            price_1e8 = reading.price_1e8,
            server_time,
            "VUSD NAV sample"
        );
        Ok(NavSample {
            price_1e8: reading.price_1e8,
            server_time,
            block: reading.block,
        })
    }
}

/// One RPC operator as a price source.
struct EthRpc {
    operator: Operator,
    poller: Arc<NavPoller>,
}

#[async_trait]
impl PriceSource for EthRpc {
    async fn fetch_price(&self, asset: &AssetConfig) -> Result<Option<PricePoint>> {
        let Some(pair) = asset.pair(self.name()) else {
            return Ok(None);
        };
        if pair != VUSD_NAV {
            return Err(eyre!(
                "{}: unknown pair {} for {} (only {} is served)",
                self.name(),
                pair,
                asset.symbol,
                VUSD_NAV
            ));
        }
        let sample = self.poller.take(self.operator).await?;
        Ok(Some(PricePoint {
            price: sample.price_1e8 as f64 / ONE_1E8 as f64,
            volume: 1.0,
            source: self.name().into(),
            server_time: sample.server_time,
        }))
    }

    fn name(&self) -> &'static str {
        self.operator.name()
    }
}

fn operator_sources(poller: Arc<NavPoller>) -> Vec<Box<dyn PriceSource>> {
    Operator::ALL
        .into_iter()
        .map(|operator| {
            Box::new(EthRpc {
                operator,
                poller: Arc::clone(&poller),
            }) as Box<dyn PriceSource>
        })
        .collect()
}

/// The eight operator sources, sharing one poller over `client`.
pub fn sources(client: HttpClient) -> Vec<Box<dyn PriceSource>> {
    operator_sources(Arc::new(NavPoller::new(Box::new(client))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::mock::{connect_error, MockExchange, Sent, Step};
    use crate::http_client::{ErrorClass, HttpError, Method, Reply, RequestError};
    use crate::sources::fetch_all;
    use crate::types::load_assets;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const FIXTURES: &str = include_str!("../../testdata/vusd_nav_fixtures.json");
    const CALLDATA_HEX: &str = include_str!("../../testdata/vusd_nav_calldata.hex");
    const FIXTURE_COUNT: usize = 42;
    const FIXTURES_SHA256: &str =
        "7e92565840b5546a511a83556aebed54467bb111e806da574a7bdd22198066ba";
    const CALLDATA_SHA256: &str =
        "7e7a2d810f05a02170b7308901e673a8c8247bc347f85a7d4613a2e7ed8adc91";
    const REQUEST_SHA256: &str = "def59f63c7ec1b9fe56b27896151fdb489c91a9a5834aee679777c928635d716";
    const REQUEST_BYTES: usize = 2184;
    const VUSD_SYMBOL: &str = "VUSD/USD";
    const ALL_REJECTS: [NavReject; 11] = [
        NavReject::RpcError,
        NavReject::BadEncoding,
        NavReject::BadLength,
        NavReject::BadLayout,
        NavReject::PointerMismatch,
        NavReject::BlockAhead,
        NavReject::BlockStale,
        NavReject::ValueOutOfRange,
        NavReject::NoBackedSupply,
        NavReject::AmoShareExceeded,
        NavReject::ZeroPrice,
    ];

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn fixtures() -> Value {
        serde_json::from_str(FIXTURES).expect("fixtures parse")
    }

    fn vector(name: &str) -> Value {
        fixtures()["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap_or_else(|| panic!("no vector {name}"))
            .clone()
    }

    fn outcome(body: &Value, date_unix: u64) -> Result<u64, String> {
        parse_nav(body, date_unix)
            .map(|r| r.price_1e8)
            .map_err(|r| r.to_string())
    }

    #[test]
    fn every_fixture_vector_matches_the_reference() {
        let fixtures = fixtures();
        let vectors = fixtures["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), FIXTURE_COUNT);
        let mut failed = Vec::new();
        let mut rejects = BTreeSet::new();
        for v in vectors {
            let expected = match v["expect"]["price_1e8"].as_u64() {
                Some(price) => Ok(price),
                None => Err(v["expect"]["reject"].as_str().unwrap().to_string()),
            };
            let got = outcome(&v["body"], v["date_unix"].as_u64().unwrap());
            if let Err(code) = &got {
                rejects.insert(code.clone());
            }
            if got != expected {
                failed.push(format!("{}: got {got:?}, expected {expected:?}", v["name"]));
            }
        }
        assert!(failed.is_empty(), "{failed:#?}");
        let all: BTreeSet<String> = ALL_REJECTS.iter().map(ToString::to_string).collect();
        assert_eq!(rejects, all, "every reject reason has a vector");
    }

    #[test]
    fn fixture_copy_is_the_spec_file() {
        assert_eq!(sha256_hex(FIXTURES.as_bytes()), FIXTURES_SHA256);
    }

    #[test]
    fn real_block_number_is_word_zero() {
        let v = vector("real_block_26435260");
        let reading = parse_nav(&v["body"], v["date_unix"].as_u64().unwrap()).unwrap();
        assert_eq!(
            reading.block,
            U256::from(fixtures()["block"].as_u64().unwrap())
        );
    }

    /// Expectations checked against `reference.py`, except where noted.
    #[test]
    fn malformed_bodies_follow_the_reference_order() {
        let v = vector("real_block_26435260");
        let date = v["date_unix"].as_u64().unwrap();
        let result = v["body"]["result"].as_str().unwrap();
        let digits = &result[2..];
        let with = |r: String| serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": r });
        let cases = [
            (
                "array body",
                serde_json::json!([]),
                Err(NavReject::RpcError),
            ),
            ("string body", Value::from(result), Err(NavReject::RpcError)),
            (
                "number result",
                serde_json::json!({ "result": 1 }),
                Err(NavReject::RpcError),
            ),
            (
                "upper-case prefix",
                with(format!("0X{digits}")),
                Err(NavReject::BadEncoding),
            ),
            (
                "odd digit count",
                with(format!("0x{}", &digits[1..])),
                Err(NavReject::BadEncoding),
            ),
            (
                "double prefix",
                with(format!("0x0x{digits}")),
                Err(NavReject::BadEncoding),
            ),
            (
                "upper-case digits",
                with(format!("0x{}", digits.to_uppercase())),
                Ok(ONE_1E8),
            ),
            // Stricter than reference.py, whose bytes.fromhex skips spaces.
            (
                "space inside",
                with(format!("0x{} {}", &digits[..64], &digits[64..])),
                Err(NavReject::BadEncoding),
            ),
        ];
        for (name, body, expected) in cases {
            let got = parse_nav(&body, date).map(|r| r.price_1e8);
            assert_eq!(got, expected, "{name}");
        }
        assert_eq!(
            parse_nav(&v["body"], u64::MAX).map(|r| r.price_1e8),
            Err(NavReject::BlockStale),
            "date near u64::MAX must not overflow"
        );
    }

    #[test]
    fn request_body_is_the_spec_request() {
        assert_eq!(REQUEST_BODY.len(), REQUEST_BYTES);
        assert_eq!(sha256_hex(&REQUEST_BODY), REQUEST_SHA256);
        let request: Value = serde_json::from_slice(&REQUEST_BODY).unwrap();
        assert_eq!(request["method"], "eth_call");
        assert_eq!(request["params"][0]["to"], MULTICALL3.to_checksum(None));
        assert_eq!(request["params"][1], "latest");
        assert_eq!(request["params"][0]["data"], CALLDATA_HEX.trim_end());
    }

    #[test]
    fn calldata_is_the_spec_calldata() {
        assert_eq!(sha256_hex(CALLDATA_HEX.as_bytes()), CALLDATA_SHA256);
        assert_eq!(
            format!("0x{}", hex::encode(calldata())),
            CALLDATA_HEX.trim_end()
        );
        assert_eq!(calldata()[..4], [0x25, 0x2d, 0xba, 0x42]);
    }

    #[test]
    fn operators_match_the_spec_table() {
        const SPEC: [(&str, &str); 8] = [
            ("ethrpc_publicnode", "https://ethereum-rpc.publicnode.com"),
            ("ethrpc_tenderly", "https://mainnet.gateway.tenderly.co"),
            ("ethrpc_drpc", "https://eth.drpc.org"),
            ("ethrpc_blastapi", "https://eth-mainnet.public.blastapi.io"),
            ("ethrpc_mevblocker", "https://rpc.mevblocker.io"),
            ("ethrpc_bloxroute", "https://eth.rpc.blxrbdn.com"),
            ("ethrpc_nodies", "https://eth-pokt.nodies.app"),
            ("ethrpc_0xrpc", "https://0xrpc.io/eth"),
        ];
        let table: Vec<(&str, &str)> = Operator::ALL.iter().map(|o| (o.name(), o.url())).collect();
        assert_eq!(table, SPEC);
        for (i, operator) in Operator::ALL.into_iter().enumerate() {
            assert_eq!(operator.slot(), i, "{operator:?}");
        }

        let cfg = load_assets().unwrap();
        let vusd = cfg.assets.iter().find(|a| a.symbol == VUSD_SYMBOL).unwrap();
        for operator in Operator::ALL {
            let url = reqwest::Url::parse(operator.url()).unwrap();
            let host = url.host_str().unwrap();
            assert!(
                cfg.exchange_hostnames.iter().any(|h| h == host),
                "{host} not in exchange_hostnames"
            );
            assert_eq!(
                vusd.pair(operator.name()).map(String::as_str),
                Some(VUSD_NAV),
                "{operator:?}"
            );
        }
    }

    const BLOCK: u64 = 26_435_260;
    const BLOCK_TS: u64 = 1_794_924_479;

    /// An accepted `aggregate` result in the fixed layout for these values.
    fn response(reserve: u128, supply: u128, amo: u128, block_ts: u64) -> Value {
        let mut words: Vec<U256> = vec![
            U256::from(BLOCK),
            U256::from(ARRAY_OFFSET),
            U256::from(ELEMENTS),
        ];
        words.extend(ELEMENT_OFFSETS.map(U256::from));
        for value in [
            address_word(TREASURY),
            address_word(GATEWAY),
            U256::from(reserve),
            U256::from(supply),
            U256::from(amo),
            U256::from(block_ts),
        ] {
            words.extend([U256::from(ELEMENT_BYTES), value]);
        }
        let raw: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes::<32>()).collect();
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": format!("0x{}", hex::encode(raw)) })
    }

    /// Answer for `operator` in poll round `round` (0-based).
    type Respond = fn(Operator, usize) -> Result<(Value, u64)>;

    /// Price (98 - round) %, `Date` offset by the operator's slot.
    fn healthy(operator: Operator, round: usize) -> Result<(Value, u64)> {
        Ok((
            response(98 - round as u128, 100, 0, BLOCK_TS),
            BLOCK_TS + operator.slot() as u64,
        ))
    }

    fn healthy_price(round: usize) -> f64 {
        (98 - round) as f64 / 100.0
    }

    struct Scripted {
        calls: Arc<AtomicUsize>,
        respond: Respond,
        barrier: Option<tokio::sync::Barrier>,
        delay: Duration,
    }

    #[async_trait]
    impl RpcTransport for Scripted {
        async fn post(&self, url: &'static str, body: &'static [u8]) -> Result<(Value, u64)> {
            assert_eq!(body, REQUEST_BODY.as_slice());
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let operator = Operator::ALL
                .into_iter()
                .find(|o| o.url() == url)
                .expect("url of a known operator");
            if let Some(barrier) = &self.barrier {
                barrier.wait().await;
            }
            tokio::time::sleep(self.delay).await;
            (self.respond)(operator, call / OPERATORS)
        }
    }

    fn poller(respond: Respond) -> (Arc<NavPoller>, Arc<AtomicUsize>) {
        poller_with(respond, None, Duration::ZERO)
    }

    fn poller_with(
        respond: Respond,
        barrier: Option<tokio::sync::Barrier>,
        delay: Duration,
    ) -> (Arc<NavPoller>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let transport = Scripted {
            calls: Arc::clone(&calls),
            respond,
            barrier,
            delay,
        };
        (Arc::new(NavPoller::new(Box::new(transport))), calls)
    }

    fn vusd_asset() -> AssetConfig {
        load_assets()
            .unwrap()
            .assets
            .into_iter()
            .find(|a| a.symbol == VUSD_SYMBOL)
            .unwrap()
    }

    #[tokio::test]
    async fn one_round_serves_a_whole_cycle() {
        let (poller, calls) = poller(healthy);
        let sources = operator_sources(poller);
        let asset = vusd_asset();
        for cycle in 0..2 {
            let points = fetch_all(&sources, &asset).await;
            assert_eq!(calls.load(Ordering::SeqCst), OPERATORS * (cycle + 1));
            assert_eq!(points.len(), OPERATORS);
            for (point, operator) in points.iter().zip(Operator::ALL) {
                assert_eq!(point.source, operator.name());
                assert_eq!(point.price, healthy_price(cycle));
                assert_eq!(point.volume, 1.0);
                assert_eq!(point.server_time, BLOCK_TS + operator.slot() as u64);
            }
        }
    }

    #[tokio::test]
    async fn a_result_is_handed_out_once() {
        let (poller, calls) = poller(healthy);
        let first = poller.take(Operator::Drpc).await.unwrap();
        assert_eq!(first.price_1e8, 98_000_000);
        let second = poller.take(Operator::Drpc).await.unwrap();
        assert_eq!(second.price_1e8, 97_000_000);
        assert_eq!(calls.load(Ordering::SeqCst), 2 * OPERATORS);
        let other = poller.take(Operator::Tenderly).await.unwrap();
        assert_eq!(
            other.price_1e8, 97_000_000,
            "a new round replaces every slot"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2 * OPERATORS);
    }

    /// Round 0: Tenderly's transport fails and dRPC returns a JSON-RPC error.
    fn flaky(operator: Operator, round: usize) -> Result<(Value, u64)> {
        match (round, operator) {
            (0, Operator::Tenderly) => Err(eyre!("connection reset")),
            (0, Operator::Drpc) => Ok((
                serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": 3, "message": "execution reverted" } }),
                BLOCK_TS,
            )),
            _ => healthy(operator, round),
        }
    }

    #[tokio::test]
    async fn a_failed_operator_misses_only_its_own_cycle() {
        let (poller, calls) = poller(flaky);
        let sources = operator_sources(poller);
        let asset = vusd_asset();
        for source in &sources {
            let got = source.fetch_price(&asset).await;
            match source.name() {
                "ethrpc_tenderly" => {
                    assert!(got.unwrap_err().to_string().contains("connection reset"))
                }
                "ethrpc_drpc" => assert!(got.unwrap_err().to_string().contains("RPC_ERROR")),
                name => assert_eq!(got.unwrap().unwrap().price, healthy_price(0), "{name}"),
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), OPERATORS);
        let points = fetch_all(&sources, &asset).await;
        assert_eq!(
            points.len(),
            OPERATORS,
            "every operator recovers next cycle"
        );
        assert!(points.iter().all(|p| p.price == healthy_price(1)));
    }

    #[tokio::test]
    async fn operators_are_polled_in_parallel() {
        let barrier = tokio::sync::Barrier::new(OPERATORS);
        let (poller, calls) = poller_with(healthy, Some(barrier), Duration::ZERO);
        let taken = tokio::time::timeout(Duration::from_secs(5), poller.take(Operator::Nodies))
            .await
            .expect("all requests in flight at once");
        assert_eq!(taken.unwrap().price_1e8, 98_000_000);
        assert_eq!(calls.load(Ordering::SeqCst), OPERATORS);
    }

    #[tokio::test]
    async fn two_concurrent_takes_start_one_round() {
        let (poller, calls) = poller(healthy);
        let (a, b) = tokio::join!(
            poller.take(Operator::PublicNode),
            poller.take(Operator::ZeroXRpc)
        );
        assert_eq!(a.unwrap().price_1e8, 98_000_000);
        assert_eq!(b.unwrap().price_1e8, 98_000_000);
        assert_eq!(calls.load(Ordering::SeqCst), OPERATORS);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn takes_from_many_tasks_start_one_round() {
        let (poller, calls) = poller_with(healthy, None, Duration::from_millis(50));
        let tasks: Vec<_> = Operator::ALL
            .into_iter()
            .map(|operator| {
                let poller = Arc::clone(&poller);
                tokio::spawn(async move { poller.take(operator).await })
            })
            .collect();
        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap().price_1e8, 98_000_000);
        }
        assert_eq!(calls.load(Ordering::SeqCst), OPERATORS);
    }

    #[tokio::test]
    async fn an_asset_without_a_mapping_is_not_polled() {
        let (poller, calls) = poller(healthy);
        let eth = load_assets()
            .unwrap()
            .assets
            .into_iter()
            .find(|a| a.symbol == "ETH/USD")
            .unwrap();
        for source in operator_sources(poller) {
            assert!(source.fetch_price(&eth).await.unwrap().is_none());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_unknown_pair_is_an_error_without_polling() {
        let (poller, calls) = poller(healthy);
        let asset: AssetConfig = serde_json::from_str(
            r#"{"symbol":"VUSD/USD","min_sources":1,"deviation_threshold_bps":50,"heartbeat_seconds":3600,"sources":{"ethrpc_drpc":{"pair":"VUSD_SUPPLY","quote":"USD"}}}"#,
        )
        .unwrap();
        let drpc = operator_sources(poller)
            .into_iter()
            .find(|s| s.name() == "ethrpc_drpc")
            .unwrap();
        let err = drpc.fetch_price(&asset).await.unwrap_err();
        assert!(
            err.to_string().contains("unknown pair VUSD_SUPPLY"),
            "{err}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// Operator the single-operator SPEC §16.7 scenarios script; the other seven always answer.
    const TARGET: Operator = Operator::BlastApi;
    /// `Date` of an answer that only a retry or a later round can get.
    const LATER: u64 = BLOCK_TS + 7;

    /// IMF-fixdate of `unix`, as an operator sends it in `Date`.
    fn http_date(unix: u64) -> String {
        chrono::DateTime::from_timestamp(unix as i64, 0)
            .unwrap()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string()
    }

    fn answer(status: u16, date: Option<u64>, body: &Value) -> Step {
        Step::Answer(Reply {
            status,
            date: date.map(http_date),
            body: serde_json::to_vec(body).unwrap(),
            ..Reply::default()
        })
    }

    fn accepted(date: u64) -> Step {
        answer(200, Some(date), &response(98, 100, 0, BLOCK_TS))
    }

    fn status(code: u16) -> Step {
        answer(code, Some(BLOCK_TS), &Value::Null)
    }

    fn rpc_error(code: i64) -> Step {
        let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": code, "message": "limit" } });
        answer(200, Some(BLOCK_TS), &body)
    }

    fn fixture(name: &str) -> Step {
        let v = vector(name);
        answer(200, v["date_unix"].as_u64(), &v["body"])
    }

    /// A poller over the production `HttpClient` and bundled allowlist, on a scripted wire.
    fn wired(
        plan: impl Fn(&str, usize) -> Step + Send + Sync + 'static,
    ) -> (Arc<NavPoller>, Arc<MockExchange>) {
        let exchange = MockExchange::new(plan);
        let hosts = load_assets().unwrap().exchange_hostnames;
        let client = HttpClient::with_exchange(exchange.clone(), hosts);
        (Arc::new(NavPoller::new(Box::new(client))), exchange)
    }

    #[derive(Debug)]
    enum Expect {
        Sample { server_time: u64 },
        Failed(ErrorClass),
        Rejected(NavReject),
    }

    fn check(name: &str, got: Result<NavSample>, expect: &Expect) {
        match (expect, got) {
            (Expect::Sample { server_time }, Ok(sample)) => {
                assert_eq!(sample.server_time, *server_time, "{name}")
            }
            (Expect::Failed(class), Err(e)) => assert_eq!(
                e.downcast_ref::<RequestError>().map(RequestError::class),
                Some(*class),
                "{name}: {e}"
            ),
            (Expect::Rejected(reject), Err(e)) => {
                assert!(e.downcast_ref::<RequestError>().is_none(), "{name}: {e}");
                assert!(e.to_string().ends_with(&reject.to_string()), "{name}: {e}");
            }
            (expect, got) => panic!("{name}: want {expect:?}, got {got:?}"),
        }
    }

    type Attempt = fn() -> Step;

    struct Scenario {
        name: &'static str,
        first: Attempt,
        /// None: a retry would be accepted dated `LATER`.
        second: Option<Attempt>,
        requests: usize,
        expect: Expect,
        /// None: the next round asks the operator again at once.
        pause: Option<Duration>,
    }

    #[tokio::test(start_paused = true)]
    async fn spec_16_7_single_operator_scenarios() {
        use ErrorClass::*;
        let scenario = |name, first, second, requests, expect, pause| Scenario {
            name,
            first,
            second,
            requests,
            expect,
            pause,
        };
        let scenarios = [
            scenario(
                "#1 accepted",
                || accepted(BLOCK_TS),
                None,
                1,
                Expect::Sample {
                    server_time: BLOCK_TS,
                },
                None,
            ),
            scenario(
                "#2 error code 3 (real revert vector)",
                || fixture("real_revert_block_26428312_stale_usdt_feed"),
                None,
                1,
                Expect::Rejected(NavReject::RpcError),
                None,
            ),
            scenario(
                "#3 error code -32005",
                || rpc_error(-32005),
                None,
                1,
                Expect::Rejected(NavReject::RpcError),
                None,
            ),
            scenario(
                "#4 result rejected BLOCK_STALE",
                || fixture("block_stale_181"),
                None,
                1,
                Expect::Rejected(NavReject::BlockStale),
                None,
            ),
            scenario(
                "#5 200 without Date",
                || answer(200, None, &response(98, 100, 0, BLOCK_TS)),
                None,
                1,
                Expect::Failed(BadResponse),
                None,
            ),
            scenario(
                "#6a HTTP 301",
                || status(301),
                None,
                1,
                Expect::Failed(BadResponse),
                None,
            ),
            scenario(
                "#6b HTTP 404",
                || status(404),
                None,
                1,
                Expect::Failed(ClientError),
                None,
            ),
            scenario(
                "#7 429 without Retry-After",
                || status(429),
                None,
                1,
                Expect::Failed(RateLimited),
                Some(Duration::from_secs(30)),
            ),
            scenario(
                "#8 HTTP 403",
                || status(403),
                None,
                1,
                Expect::Failed(Blocked),
                Some(Duration::from_secs(60)),
            ),
            scenario(
                "#9 503 then accepted",
                || status(503),
                Some(|| accepted(LATER)),
                2,
                Expect::Sample { server_time: LATER },
                None,
            ),
            scenario(
                "#10 503 without Date then accepted",
                || answer(503, None, &Value::Null),
                Some(|| accepted(LATER)),
                2,
                Expect::Sample { server_time: LATER },
                None,
            ),
            scenario(
                "#11 connect error then error code 3",
                || Step::Fail(connect_error()),
                Some(|| rpc_error(3)),
                2,
                Expect::Rejected(NavReject::RpcError),
                None,
            ),
            scenario(
                "#12 503 twice",
                || status(503),
                Some(|| status(503)),
                2,
                Expect::Failed(ServerError),
                None,
            ),
            scenario(
                "#13 connect error after 3 s",
                || {
                    Step::After(
                        Duration::from_secs(3),
                        Box::new(Step::Fail(connect_error())),
                    )
                },
                None,
                1,
                Expect::Failed(Network),
                None,
            ),
            scenario(
                "#13 boundary: connect error after 2.75 s",
                || {
                    Step::After(
                        Duration::from_millis(2_750),
                        Box::new(Step::Fail(connect_error())),
                    )
                },
                None,
                2,
                Expect::Sample { server_time: LATER },
                None,
            ),
            scenario(
                "#14 no answer",
                || Step::Hang,
                None,
                1,
                Expect::Failed(Timeout),
                None,
            ),
        ];
        for s in scenarios {
            let (name, first, second) = (s.name, s.first, s.second);
            let (poller, exchange) = wired(move |url, nth| {
                if url != TARGET.url() {
                    return accepted(BLOCK_TS);
                }
                match (nth, second) {
                    (0, _) => first(),
                    (1, Some(second)) => second(),
                    _ => accepted(LATER),
                }
            });
            let started = Instant::now();
            let got = poller.take(TARGET).await;
            assert!(started.elapsed() <= REQUEST_TIMEOUT, "{name}");
            assert_eq!(exchange.count(TARGET.url()), s.requests, "{name}");
            assert_eq!(
                exchange.sent().len(),
                OPERATORS - 1 + s.requests,
                "{name}: the others are asked once"
            );
            check(name, got, &s.expect);

            let Some(length) = s.pause else {
                poller.take(TARGET).await.unwrap();
                assert_eq!(exchange.count(TARGET.url()), s.requests + 1, "{name}");
                continue;
            };
            tokio::time::sleep_until(started + length - Duration::from_millis(1)).await;
            check(
                name,
                poller.take(TARGET).await,
                &Expect::Failed(CoolingDown),
            );
            assert_eq!(
                exchange.count(TARGET.url()),
                1,
                "{name}: no request while paused"
            );
            tokio::time::sleep_until(started + length).await;
            check(
                name,
                poller.take(TARGET).await,
                &Expect::Sample { server_time: LATER },
            );
            assert_eq!(exchange.count(TARGET.url()), 2, "{name}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn spec_16_7_scenario_15_a_failed_round_does_not_carry_over() {
        let (poller, exchange) = wired(|_, nth| match nth {
            0 | 1 => Step::Fail(connect_error()),
            _ => accepted(BLOCK_TS),
        });
        let sources = operator_sources(poller);
        let asset = vusd_asset();
        assert!(fetch_all(&sources, &asset).await.is_empty());
        assert_eq!(exchange.sent().len(), 2 * OPERATORS);
        assert_eq!(fetch_all(&sources, &asset).await.len(), OPERATORS);
        assert_eq!(exchange.sent().len(), 3 * OPERATORS);
        for operator in Operator::ALL {
            assert_eq!(exchange.count(operator.url()), 3, "{operator:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn spec_16_7_scenario_16_a_paused_operator_costs_no_extra_round() {
        let (poller, exchange) = wired(|url, nth| match (url == TARGET.url(), nth) {
            (true, 0) => status(429),
            _ => accepted(BLOCK_TS),
        });
        let sources = operator_sources(poller);
        let asset = vusd_asset();
        assert_eq!(fetch_all(&sources, &asset).await.len(), OPERATORS - 1);
        assert_eq!(exchange.sent().len(), OPERATORS);

        tokio::time::sleep(Duration::from_secs(5)).await;
        for source in &sources {
            let got = source.fetch_price(&asset).await;
            if source.name() == TARGET.name() {
                let err = got.unwrap_err();
                let class = err.downcast_ref::<RequestError>().map(RequestError::class);
                assert_eq!(class, Some(ErrorClass::CoolingDown), "{err}");
            } else {
                assert!(got.unwrap().is_some(), "{}", source.name());
            }
        }
        assert_eq!(
            exchange.sent().len(),
            OPERATORS + OPERATORS - 1,
            "one round, seven requests"
        );
        assert_eq!(exchange.count(TARGET.url()), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn spec_16_7_scenario_17_a_retry_repeats_the_request_byte_for_byte() {
        let retryable: [(&str, Attempt); 10] = [
            ("connect error", || Step::Fail(connect_error())),
            ("connection cut", || {
                Step::Fail(HttpError::Transport {
                    detail: "unexpected EOF".into(),
                })
            }),
            ("500", || status(500)),
            ("502", || status(502)),
            ("503", || status(503)),
            ("504", || status(504)),
            ("408", || status(408)),
            ("425", || status(425)),
            ("429 Retry-After 1", || {
                Step::Answer(Reply {
                    retry_after: Some("1".into()),
                    ..reply_of(status(429))
                })
            }),
            ("429 Retry-After 0", || {
                Step::Answer(Reply {
                    retry_after: Some("0".into()),
                    ..reply_of(status(429))
                })
            }),
        ];
        for (name, first) in retryable {
            let (poller, exchange) = wired(move |url, nth| match (url == TARGET.url(), nth) {
                (true, 0) => first(),
                (true, _) => status(503),
                _ => accepted(BLOCK_TS),
            });
            let _ = poller.take(TARGET).await;
            let sent: Vec<Sent> = exchange
                .sent()
                .into_iter()
                .filter(|s| s.url == TARGET.url())
                .collect();
            assert_eq!(sent.len(), 2, "#17 {name}");
            for attempt in &sent {
                assert_eq!(attempt.method, Method::Post, "#17 {name}");
                assert_eq!(attempt.body, Some(REQUEST_BODY.as_slice()), "#17 {name}");
            }
        }
    }

    fn reply_of(step: Step) -> Reply {
        match step {
            Step::Answer(reply) => reply,
            _ => unreachable!("an answer step"),
        }
    }
}
