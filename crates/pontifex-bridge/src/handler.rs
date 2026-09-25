//! Request dispatch for the bridge VSOCK API. Maps a parsed [`BridgeRequest`] to
//! its serialized reply. The money path (`sign_claim`) delegates to
//! [`crate::claimflow::build_grant`] over live transports; `configure`/`health`/
//! `get_attestation` are handled here. The [`Attestor`] seam keeps every branch
//! that does not touch the chain testable without NSM or a network.

use alloy_primitives::{hex, U256};
use keyex::api::{Ack, Attestation, BridgeHealth, BridgeRequest, SignClaimResponse};
use keyex::chain::{self, ChainView, Finality, Registry, RpcChainView};
use keyex::claim::ClaimError;
use serde::Serialize;

use crate::claimflow::{build_grant, ClaimInputs};
use crate::config::{BakedIdentity, BridgeConfig, IGRA_FINALITY};
use crate::state::BridgeState;
use crate::transport::ProxyTransport;

/// Produce a COSE attestation document binding an optional nonce and the signer's
/// public key. Returns `None` on NSM failure so the caller fails closed.
pub trait Attestor {
    fn attest(&self, nonce: Option<Vec<u8>>, public_key: Vec<u8>) -> Option<Vec<u8>>;
}

/// Per-request plumbing: the shared proxied HTTP client, the baked Igra endpoint
/// and identity, and the enclave's current wall clock.
pub struct HandlerCtx<'a> {
    pub client: &'a reqwest::Client,
    pub igra_url: &'a str,
    pub baked: &'a BakedIdentity,
    pub enclave_now: u64,
}

/// A coded wire error for replies that have no typed success body to carry it.
#[derive(Serialize)]
struct WireError {
    error: String,
}

fn to_vec<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_else(|_| br#"{"error":"serialize"}"#.to_vec())
}

fn wire_error(code: &str) -> Vec<u8> {
    to_vec(&WireError { error: code.to_owned() })
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok()
}

/// Dispatch one request to its serialized reply.
pub async fn handle<A: Attestor>(
    req: BridgeRequest,
    state: &mut BridgeState,
    ctx: &HandlerCtx<'_>,
    attestor: &A,
) -> Vec<u8> {
    match req {
        BridgeRequest::Configure { entry, rh_rpcs, oracle_peers } => {
            let ok = configure(state, ctx.baked, &entry, rh_rpcs, oracle_peers);
            to_vec(&Ack { ok })
        }
        BridgeRequest::SignClaim { recipient } => to_vec(&sign_claim(state, ctx, &recipient).await),
        BridgeRequest::GetAttestation { nonce } => get_attestation(state, attestor, nonce),
        BridgeRequest::Health => to_vec(&health(state, ctx).await),
    }
}

/// Validate and store the host configuration. One-shot: a booted signer refuses
/// re-configuration, so the host cannot swap endpoints under a live key. The
/// host-supplied `entry` must equal the baked verifyingContract, and every RH
/// endpoint must be https (the host tunnel can MITM plain HTTP).
fn configure(
    state: &mut BridgeState,
    baked: &BakedIdentity,
    entry: &str,
    rh_rpcs: Vec<String>,
    oracle_peers: Vec<String>,
) -> bool {
    if state.key().is_some() {
        return false; // never re-configure a booted signer
    }
    match keyex::api::parse_address(entry) {
        Some(a) if a == baked.entry => {} // baked, non-zero; a zero/mismatched entry fails here
        _ => return false,
    }
    if rh_rpcs.is_empty() || rh_rpcs.iter().any(|u| !u.starts_with("https://")) {
        return false;
    }
    state.set_config(BridgeConfig::from_parts(baked, rh_rpcs, oracle_peers));
    true
}

/// The money path. Refuses before any chain read when unbooted, unconfigured, or
/// handed an unparseable recipient; otherwise delegates every check to
/// [`build_grant`] and records the signed total to ratchet the session high-water.
async fn sign_claim(state: &mut BridgeState, ctx: &HandlerCtx<'_>, recipient: &str) -> SignClaimResponse {
    let recipient = match keyex::api::parse_address(recipient) {
        Some(a) => a,
        None => return ClaimError::RecipientForbidden.into(),
    };
    let key = match state.key() {
        Some(k) => k.clone(),
        None => return ClaimError::NotReady.into(),
    };
    let cfg = match state.config() {
        Some(c) => c.clone(),
        None => return ClaimError::NotReady.into(),
    };
    let rh_url = match cfg.rh_rpcs.first() {
        Some(u) => u.clone(),
        None => return ClaimError::NotReady.into(),
    };

    let high_water = state.high_water(recipient);
    let igra = ProxyTransport::new(ctx.client.clone(), ctx.igra_url);
    let rh = ProxyTransport::new(ctx.client.clone(), rh_url);
    let forbidden = cfg.forbidden();
    let inputs = ClaimInputs {
        recipient,
        high_water,
        enclave_now: ctx.enclave_now,
        forbidden: &forbidden,
        exit: cfg.exit,
        entry: cfg.entry,
        chain_id: cfg.chain_id,
        igra_finality: IGRA_FINALITY,
    };

    let resp = build_grant(&key, &igra, &rh, &inputs).await;
    if let SignClaimResponse::Ok(ref grant) = resp {
        if let Ok(b) = grant.cumulative_burned.parse::<U256>() {
            state.record_signed(recipient, b);
        }
    }
    resp
}

/// Attest to the running signer's key. Requires a booted enclave; a bad nonce or
/// an NSM failure yields a coded error rather than a bogus document.
fn get_attestation<A: Attestor>(
    state: &BridgeState,
    attestor: &A,
    nonce: Option<String>,
) -> Vec<u8> {
    let (signer, pubkey) = match (state.signer(), state.signer_pubkey()) {
        (Some(s), Some(p)) => (s, p),
        _ => return wire_error("not_ready"),
    };
    let nonce_bytes = match nonce {
        Some(h) => match decode_hex(&h) {
            Some(b) => Some(b),
            None => return wire_error("bad_nonce"),
        },
        None => None,
    };
    match attestor.attest(nonce_bytes, pubkey) {
        Some(doc) => to_vec(&Attestation::new(&doc, signer, state.pcr0())),
        None => wire_error("attestation_unavailable"),
    }
}

/// Best-effort health. Chain-derived fields (`registered`, finalized heights) are
/// read only when booted and configured; any read fault leaves them at their
/// zero/false default rather than failing the whole reply.
async fn health(state: &BridgeState, ctx: &HandlerCtx<'_>) -> BridgeHealth {
    let mut registered = false;
    let mut igra_finalized = 0u64;
    let mut rh_finalized = 0u64;

    if let (Some(signer), Some(cfg)) = (state.signer(), state.config()) {
        let igra = ProxyTransport::new(ctx.client.clone(), ctx.igra_url);
        if let Ok(b) = chain::finalized_block(&igra, IGRA_FINALITY).await {
            igra_finalized = b.number;
        }
        if let Some(rh_url) = cfg.rh_rpcs.first() {
            let rh = ProxyTransport::new(ctx.client.clone(), rh_url.clone());
            if let Ok(b) = chain::finalized_block(&rh, Finality::Tag).await {
                rh_finalized = b.number;
            }
            let view = RpcChainView {
                transport: &rh,
                registry: cfg.entry,
                kind: Registry::Bridge,
                finality: Finality::Tag,
            };
            if let Ok(r) = view.registered(signer).await {
                registered = r;
            }
        }
    }

    BridgeHealth {
        state: state.boot(),
        signer: state.signer().map(|s| s.to_string()).unwrap_or_default(),
        version: state.version().to_string(),
        pcr0: hex::encode_prefixed(state.pcr0()),
        registered,
        igra_finalized,
        rh_finalized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    use alloy_primitives::Address;
    use k256::ecdsa::SigningKey;
    use keyex::api::{BootState, SignClaimError};
    use serde_json::Value;

    fn baked() -> BakedIdentity {
        BakedIdentity {
            exit: Address::from([0xEE; 20]),
            kskd: Address::from([0xDD; 20]),
            entry: Address::from([0x11; 20]),
            chain_id: 46630,
        }
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    struct MockAttestor {
        doc: Option<Vec<u8>>,
        calls: Cell<u32>,
        last_nonce: Cell<Option<Vec<u8>>>,
        last_pubkey: Cell<Option<Vec<u8>>>,
    }
    impl MockAttestor {
        fn returning(doc: Option<Vec<u8>>) -> Self {
            Self { doc, calls: Cell::new(0), last_nonce: Cell::new(None), last_pubkey: Cell::new(None) }
        }
    }
    impl Attestor for MockAttestor {
        fn attest(&self, nonce: Option<Vec<u8>>, public_key: Vec<u8>) -> Option<Vec<u8>> {
            self.calls.set(self.calls.get() + 1);
            self.last_nonce.set(nonce);
            self.last_pubkey.set(Some(public_key));
            self.doc.clone()
        }
    }
    struct PanicAttestor;
    impl Attestor for PanicAttestor {
        fn attest(&self, _: Option<Vec<u8>>, _: Vec<u8>) -> Option<Vec<u8>> {
            panic!("attestor must not be called");
        }
    }

    fn booted_state(signer: Address) -> BridgeState {
        let mut st = BridgeState::new([0x7f; 48], 1);
        st.install_key(SigningKey::from_bytes((&[9u8; 32]).into()).unwrap(), signer);
        st
    }

    fn ctx<'a>(c: &'a reqwest::Client, b: &'a BakedIdentity) -> HandlerCtx<'a> {
        HandlerCtx { client: c, igra_url: "http://igra.invalid", baked: b, enclave_now: 1_789_000_050 }
    }

    #[tokio::test]
    async fn configure_valid_acks_and_stores_config() {
        let (c, b) = (client(), baked());
        let mut st = BridgeState::new([0; 48], 1);
        let out = handle(
            BridgeRequest::Configure {
                entry: "0x1111111111111111111111111111111111111111".into(),
                rh_rpcs: vec!["https://rh".into()],
                oracle_peers: vec![],
            },
            &mut st,
            &ctx(&c, &b),
            &PanicAttestor,
        )
        .await;
        let ack: Ack = serde_json::from_slice(&out).unwrap();
        assert!(ack.ok);
        let cfg = st.config().unwrap();
        assert_eq!(cfg.entry, Address::from([0x11; 20]));
        assert_eq!(cfg.exit, b.exit); // baked, not host-supplied
        assert_eq!(cfg.chain_id, 46630);
    }

    #[tokio::test]
    async fn configure_rejects_bad_zero_entry_and_empty_rpcs() {
        let (c, b) = (client(), baked());

        let mut st = BridgeState::new([0; 48], 1);
        let bad = handle(
            BridgeRequest::Configure {
                entry: "not-an-address".into(),
                rh_rpcs: vec!["https://rh".into()],
                oracle_peers: vec![],
            },
            &mut st,
            &ctx(&c, &b),
            &PanicAttestor,
        )
        .await;
        assert!(!serde_json::from_slice::<Ack>(&bad).unwrap().ok);
        assert!(st.config().is_none());

        let zero = handle(
            BridgeRequest::Configure {
                entry: format!("{:?}", Address::ZERO),
                rh_rpcs: vec!["https://rh".into()],
                oracle_peers: vec![],
            },
            &mut st,
            &ctx(&c, &b),
            &PanicAttestor,
        )
        .await;
        assert!(!serde_json::from_slice::<Ack>(&zero).unwrap().ok);

        let empty = handle(
            BridgeRequest::Configure {
                entry: "0x1111111111111111111111111111111111111111".into(),
                rh_rpcs: vec![],
                oracle_peers: vec![],
            },
            &mut st,
            &ctx(&c, &b),
            &PanicAttestor,
        )
        .await;
        assert!(!serde_json::from_slice::<Ack>(&empty).unwrap().ok);
    }

    #[tokio::test]
    async fn configure_rejects_entry_that_is_not_the_baked_verifying_contract() {
        let (c, b) = (client(), baked()); // baked.entry == 0x11..11
        let mut st = BridgeState::new([0; 48], 1);
        let out = handle(
            BridgeRequest::Configure {
                entry: format!("{:?}", Address::from([0x22; 20])), // parseable, non-zero, wrong
                rh_rpcs: vec!["https://rh".into()],
                oracle_peers: vec![],
            },
            &mut st,
            &ctx(&c, &b),
            &PanicAttestor,
        )
        .await;
        assert!(!serde_json::from_slice::<Ack>(&out).unwrap().ok);
        assert!(st.config().is_none());
    }

    #[tokio::test]
    async fn configure_rejects_a_non_https_rh_endpoint() {
        let (c, b) = (client(), baked());
        let mut st = BridgeState::new([0; 48], 1);
        let out = handle(
            BridgeRequest::Configure {
                entry: "0x1111111111111111111111111111111111111111".into(),
                rh_rpcs: vec!["https://ok".into(), "http://mitm".into()],
                oracle_peers: vec![],
            },
            &mut st,
            &ctx(&c, &b),
            &PanicAttestor,
        )
        .await;
        assert!(!serde_json::from_slice::<Ack>(&out).unwrap().ok);
        assert!(st.config().is_none());
    }

    #[tokio::test]
    async fn configure_is_rejected_once_a_signer_is_booted() {
        let (c, b) = (client(), baked());
        let mut st = booted_state(Address::from([0x33; 20])); // key installed, no config
        let out = handle(
            BridgeRequest::Configure {
                entry: "0x1111111111111111111111111111111111111111".into(),
                rh_rpcs: vec!["https://rh".into()],
                oracle_peers: vec![],
            },
            &mut st,
            &ctx(&c, &b),
            &PanicAttestor,
        )
        .await;
        assert!(!serde_json::from_slice::<Ack>(&out).unwrap().ok); // one-shot: no post-boot swap
        assert!(st.config().is_none());
    }

    #[tokio::test]
    async fn sign_claim_before_boot_is_not_ready_and_never_touches_network() {
        let (c, b) = (client(), baked());
        let mut st = BridgeState::new([0; 48], 1); // no key
        let out = handle(
            BridgeRequest::SignClaim { recipient: format!("{:?}", Address::from([0x22; 20])) },
            &mut st,
            &ctx(&c, &b),
            &PanicAttestor,
        )
        .await;
        let resp: SignClaimResponse = serde_json::from_slice(&out).unwrap();
        assert_eq!(resp, SignClaimResponse::Err(SignClaimError { error: ClaimError::NotReady }));
    }

    #[tokio::test]
    async fn sign_claim_booted_but_unconfigured_is_not_ready() {
        let (c, b) = (client(), baked());
        let mut st = booted_state(Address::from([0x33; 20])); // key, no config
        let out = handle(
            BridgeRequest::SignClaim { recipient: format!("{:?}", Address::from([0x22; 20])) },
            &mut st,
            &ctx(&c, &b),
            &PanicAttestor,
        )
        .await;
        let resp: SignClaimResponse = serde_json::from_slice(&out).unwrap();
        assert_eq!(resp, ClaimError::NotReady.into());
    }

    #[tokio::test]
    async fn sign_claim_unparseable_recipient_is_forbidden_before_any_read() {
        let (c, b) = (client(), baked());
        let mut st = BridgeState::new([0; 48], 1);
        let out = handle(
            BridgeRequest::SignClaim { recipient: "0xnothex".into() },
            &mut st,
            &ctx(&c, &b),
            &PanicAttestor,
        )
        .await;
        let resp: SignClaimResponse = serde_json::from_slice(&out).unwrap();
        assert_eq!(resp, ClaimError::RecipientForbidden.into());
    }

    #[tokio::test]
    async fn get_attestation_before_boot_is_not_ready_without_calling_nsm() {
        let mut st = BridgeState::new([0x7f; 48], 1); // no signer
        let out = get_attestation(&st, &PanicAttestor, None);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["error"], "not_ready");
        // touch st so the binding is used even on the early-return path
        assert_eq!(st.boot(), BootState::Fetching);
        st.set_config(BridgeConfig::from_parts(&baked(), vec!["u".into()], vec![]));
    }

    #[tokio::test]
    async fn get_attestation_booted_formats_doc_signer_pcr0_and_forwards_nonce() {
        let signer = Address::from([0x33; 20]);
        let st = booted_state(signer);
        let att = MockAttestor::returning(Some(vec![0xde, 0xad]));
        let out = get_attestation(&st, &att, Some("0xabcd".into()));
        let a: Attestation = serde_json::from_slice(&out).unwrap();
        assert_eq!(a.attestation, "0xdead");
        assert_eq!(a.signer, signer.to_string());
        assert_eq!(a.pcr0, hex::encode_prefixed([0x7f; 48]));
        assert_eq!(att.calls.get(), 1);
        assert_eq!(att.last_nonce.take(), Some(vec![0xab, 0xcd]));
        // The signer's uncompressed SEC1 pubkey is bound into the document.
        let pk = att.last_pubkey.take().expect("pubkey forwarded");
        assert_eq!(pk.len(), 65);
        assert_eq!(pk[0], 0x04);
    }

    #[tokio::test]
    async fn get_attestation_bad_nonce_refused_without_calling_nsm() {
        let st = booted_state(Address::from([0x33; 20]));
        let out = get_attestation(&st, &PanicAttestor, Some("0xZZ".into()));
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["error"], "bad_nonce");
    }

    #[tokio::test]
    async fn get_attestation_nsm_failure_is_unavailable() {
        let st = booted_state(Address::from([0x33; 20]));
        let att = MockAttestor::returning(None);
        let out = get_attestation(&st, &att, None);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["error"], "attestation_unavailable");
        assert_eq!(att.calls.get(), 1);
    }

    #[tokio::test]
    async fn health_before_boot_reports_defaults_without_reads() {
        let (c, b) = (client(), baked());
        let st = BridgeState::new([0x7f; 48], 2); // unbooted → no chain reads attempted
        let h = health(&st, &ctx(&c, &b)).await;
        assert_eq!(h.state, BootState::Fetching);
        assert_eq!(h.version, "2");
        assert_eq!(h.pcr0, hex::encode_prefixed([0x7f; 48]));
        assert!(!h.registered);
        assert_eq!(h.igra_finalized, 0);
        assert_eq!(h.rh_finalized, 0);
        assert_eq!(h.signer, "");
    }
}
