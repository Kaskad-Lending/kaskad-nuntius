//! VSOCK wire contract for the oracle (CID 16) and bridge (CID 17) images.
//! Requests are internally tagged by `method` — a real enum, so dispatch is an
//! exhaustive match, never a string compare. Field names and enum tags match
//! ENCLAVE.md's API table byte-for-byte. Framing (4-byte BE length) is
//! nitro-common's; this module is only the JSON body.

use alloy_primitives::{hex, Address, U256};
use serde::{Deserialize, Serialize};

/// Bridge (CID 17, port 5004) requests, tagged by `method`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum BridgeRequest {
    Configure {
        entry: String,
        #[serde(rename = "rhRpcs")]
        rh_rpcs: Vec<String>,
        #[serde(rename = "oraclePeers")]
        oracle_peers: Vec<String>,
    },
    SignClaim {
        recipient: String,
    },
    GetAttestation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
    },
    Health,
}

/// Oracle (CID 16, port 5005) keyex requests, tagged by `method`. The existing
/// pull API (`get_prices`/`get_price`) stays on its own request type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum OracleRequest {
    Configure {
        registry: String,
        #[serde(rename = "rhRpcs")]
        rh_rpcs: Vec<String>,
        #[serde(rename = "oraclePeers")]
        oracle_peers: Vec<String>,
    },
    Approval {
        #[serde(rename = "typedData")]
        typed_data: serde_json::Value,
        signatures: Vec<String>,
    },
    GetAttestation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
    },
    KeyexHealth,
}

/// Boot state reported by `health`/`keyex_health`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootState {
    Ready,
    Fetching,
    WaitingRegistration,
}

/// Where a running oracle got its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeySource {
    Peer,
    Genesis,
}

/// `configure` reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    pub ok: bool,
}

/// `get_attestation` reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub attestation: String,
    pub signer: String,
    pub pcr0: String,
}

/// `approval` reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalResult {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `keyex_health` (oracle) reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyexHealth {
    pub state: BootState,
    pub source: KeySource,
    pub signer: String,
    pub version: String,
    pub pcr0: String,
}

/// `health` (bridge) reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeHealth {
    pub state: BootState,
    pub signer: String,
    pub version: String,
    pub pcr0: String,
    pub registered: bool,
    #[serde(rename = "igraFinalized")]
    pub igra_finalized: u64,
    #[serde(rename = "rhFinalized")]
    pub rh_finalized: u64,
}

/// The success body of `sign_claim`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimGrant {
    pub signature: String,
    #[serde(rename = "cumulativeBurned")]
    pub cumulative_burned: String,
    pub deadline: u64,
    pub signer: String,
    #[serde(rename = "igraBlock")]
    pub igra_block: u64,
}

/// The error body of `sign_claim`: `{ error: <code> }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignClaimError {
    pub error: crate::claim::ClaimError,
}

/// `sign_claim` reply: either the grant or a coded error, distinguished on the
/// wire by the presence of `signature` vs `error`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignClaimResponse {
    Ok(ClaimGrant),
    Err(SignClaimError),
}

impl ClaimGrant {
    /// Format a grant from typed values: signature as 0x-hex (65 bytes),
    /// cumulativeBurned as a decimal string, signer as a 0x address.
    pub fn new(
        signature: [u8; 65],
        cumulative_burned: U256,
        deadline: u64,
        signer: Address,
        igra_block: u64,
    ) -> Self {
        Self {
            signature: hex::encode_prefixed(signature),
            cumulative_burned: cumulative_burned.to_string(),
            deadline,
            signer: signer.to_string(),
            igra_block,
        }
    }
}

impl Attestation {
    /// Format an attestation reply: COSE doc and PCR0 as 0x-hex, signer as a 0x address.
    pub fn new(doc: &[u8], signer: Address, pcr0: &[u8; 48]) -> Self {
        Self {
            attestation: hex::encode_prefixed(doc),
            signer: signer.to_string(),
            pcr0: hex::encode_prefixed(pcr0),
        }
    }
}

impl From<crate::claim::ClaimError> for SignClaimResponse {
    fn from(error: crate::claim::ClaimError) -> Self {
        Self::Err(SignClaimError { error })
    }
}

/// Parse a wire address (`0x`-prefixed, checksum optional).
pub fn parse_address(s: &str) -> Option<Address> {
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::ClaimError;
    use serde_json::json;

    #[test]
    fn bridge_requests_parse_by_method_tag() {
        let cfg: BridgeRequest = serde_json::from_value(json!({
            "method": "configure",
            "entry": "0x1111111111111111111111111111111111111111",
            "rhRpcs": ["https://a", "https://b"],
            "oraclePeers": ["o1"],
        }))
        .unwrap();
        assert_eq!(
            cfg,
            BridgeRequest::Configure {
                entry: "0x1111111111111111111111111111111111111111".into(),
                rh_rpcs: vec!["https://a".into(), "https://b".into()],
                oracle_peers: vec!["o1".into()],
            }
        );

        let sc: BridgeRequest =
            serde_json::from_value(json!({"method": "sign_claim", "recipient": "0x22"})).unwrap();
        assert_eq!(
            sc,
            BridgeRequest::SignClaim {
                recipient: "0x22".into()
            }
        );

        let h: BridgeRequest = serde_json::from_value(json!({"method": "health"})).unwrap();
        assert_eq!(h, BridgeRequest::Health);
    }

    #[test]
    fn get_attestation_nonce_is_optional() {
        let with: BridgeRequest =
            serde_json::from_value(json!({"method": "get_attestation", "nonce": "0xab"})).unwrap();
        assert_eq!(
            with,
            BridgeRequest::GetAttestation {
                nonce: Some("0xab".into())
            }
        );
        let without: BridgeRequest =
            serde_json::from_value(json!({"method": "get_attestation"})).unwrap();
        assert_eq!(without, BridgeRequest::GetAttestation { nonce: None });
    }

    #[test]
    fn oracle_requests_parse_by_method_tag() {
        let cfg: OracleRequest = serde_json::from_value(json!({
            "method": "configure",
            "registry": "0xabc",
            "rhRpcs": ["u"],
            "oraclePeers": ["p"],
        }))
        .unwrap();
        assert!(matches!(cfg, OracleRequest::Configure { .. }));

        let ap: OracleRequest = serde_json::from_value(json!({
            "method": "approval",
            "typedData": {"types": {}, "primaryType": "Approval"},
            "signatures": ["0xdead"],
        }))
        .unwrap();
        assert!(matches!(ap, OracleRequest::Approval { .. }));

        let kh: OracleRequest = serde_json::from_value(json!({"method": "keyex_health"})).unwrap();
        assert_eq!(kh, OracleRequest::KeyexHealth);
    }

    #[test]
    fn unknown_method_is_a_parse_error() {
        assert!(serde_json::from_value::<BridgeRequest>(json!({"method": "bogus"})).is_err());
        assert!(serde_json::from_value::<OracleRequest>(json!({"method": "bogus"})).is_err());
    }

    #[test]
    fn sign_claim_ok_has_exact_camelcase_fields() {
        let grant = ClaimGrant::new(
            [0x01; 65],
            U256::from(1_000_000_000_000_000_000u64),
            1_789_000_000,
            Address::from([0x33; 20]),
            42,
        );
        let v = serde_json::to_value(SignClaimResponse::Ok(grant)).unwrap();
        assert_eq!(v["cumulativeBurned"], "1000000000000000000");
        assert_eq!(v["deadline"], 1_789_000_000u64);
        assert_eq!(v["igraBlock"], 42u64);
        assert_eq!(v["signature"].as_str().unwrap().len(), 2 + 130); // 0x + 65 bytes
        assert!(v["signer"].as_str().unwrap().starts_with("0x"));
        assert!(v.get("error").is_none());
    }

    #[test]
    fn sign_claim_error_is_coded_and_untagged() {
        let resp: SignClaimResponse = ClaimError::DecreasingBurned.into();
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v, json!({"error": "decreasing_burned"}));
        // And it round-trips back to the Err variant, not a phantom Ok.
        let back: SignClaimResponse = serde_json::from_value(v).unwrap();
        assert_eq!(
            back,
            SignClaimResponse::Err(SignClaimError {
                error: ClaimError::DecreasingBurned
            })
        );
    }

    #[test]
    fn health_states_and_sources_wire_strings() {
        assert_eq!(serde_json::to_value(BootState::Ready).unwrap(), "ready");
        assert_eq!(
            serde_json::to_value(BootState::Fetching).unwrap(),
            "fetching"
        );
        assert_eq!(
            serde_json::to_value(BootState::WaitingRegistration).unwrap(),
            "waiting_registration"
        );
        assert_eq!(serde_json::to_value(KeySource::Peer).unwrap(), "peer");
        assert_eq!(serde_json::to_value(KeySource::Genesis).unwrap(), "genesis");
    }

    #[test]
    fn bridge_health_has_camelcase_finalized_fields() {
        let h = BridgeHealth {
            state: BootState::Ready,
            signer: "0x33".into(),
            version: "v1".into(),
            pcr0: "0xab".into(),
            registered: true,
            igra_finalized: 100,
            rh_finalized: 200,
        };
        let v = serde_json::to_value(h).unwrap();
        assert_eq!(v["igraFinalized"], 100u64);
        assert_eq!(v["rhFinalized"], 200u64);
        assert_eq!(v["state"], "ready");
        assert_eq!(v["registered"], true);
    }

    #[test]
    fn attestation_formats_hex_fields() {
        let a = Attestation::new(&[0xde, 0xad], Address::from([0x33; 20]), &[0x7f; 48]);
        assert_eq!(a.attestation, "0xdead");
        assert_eq!(a.pcr0.len(), 2 + 96); // 0x + 48 bytes
        assert!(a.signer.starts_with("0x"));
    }

    #[test]
    fn approval_result_omits_absent_reason() {
        let v = serde_json::to_value(ApprovalResult {
            accepted: true,
            reason: None,
        })
        .unwrap();
        assert_eq!(v, json!({"accepted": true}));
        let v = serde_json::to_value(ApprovalResult {
            accepted: false,
            reason: Some("foreign_signer".into()),
        })
        .unwrap();
        assert_eq!(v, json!({"accepted": false, "reason": "foreign_signer"}));
    }

    #[test]
    fn parse_address_round_trips() {
        let a = Address::from([0x33; 20]);
        assert_eq!(parse_address(&a.to_string()), Some(a));
        assert_eq!(parse_address("not-an-address"), None);
    }

    #[test]
    fn ack_is_ok_true() {
        assert_eq!(
            serde_json::to_value(Ack { ok: true }).unwrap(),
            json!({"ok": true})
        );
    }
}
