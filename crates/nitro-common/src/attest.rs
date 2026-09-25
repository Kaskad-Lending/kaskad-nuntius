//! Structural decode of a Nitro attestation document (COSE_Sign1 →
//! payload map). Extracts PCR0/1/2, `public_key`, `user_data`, `nonce`,
//! `timestamp` and the cert chain. This performs NO signature or
//! certificate-chain verification — that is a later slice; a document
//! parsed here is untrusted until verified.

use eyre::{eyre, Result};
use serde_cbor::Value;
use std::collections::BTreeMap;

/// A structurally-decoded, UNVERIFIED attestation document.
#[derive(Debug, Clone)]
pub struct AttestationDoc {
    pub module_id: String,
    pub digest: String,
    /// Milliseconds since the Unix epoch, as emitted by NSM.
    pub timestamp: u64,
    /// PCR index → value (48 bytes each for the SHA384 profile).
    pub pcrs: BTreeMap<u16, Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    /// Leaf (end-entity) certificate, DER.
    pub certificate: Vec<u8>,
    /// CA chain as emitted by NSM (root first, then intermediates), each DER.
    pub cabundle: Vec<Vec<u8>>,
}

impl AttestationDoc {
    /// Convenience accessor for a PCR by index.
    pub fn pcr(&self, index: u16) -> Option<&[u8]> {
        self.pcrs.get(&index).map(|v| v.as_slice())
    }

    pub fn pcr0(&self) -> Option<&[u8]> {
        self.pcr(0)
    }
    pub fn pcr1(&self) -> Option<&[u8]> {
        self.pcr(1)
    }
    pub fn pcr2(&self) -> Option<&[u8]> {
        self.pcr(2)
    }
}

/// Decode the outer COSE_Sign1 array and the CBOR payload map. Rejects
/// anything that is not a 4-element COSE_Sign1 whose payload is a map.
pub fn parse_attestation_doc(cose_sign1: &[u8]) -> Result<AttestationDoc> {
    let outer: Value =
        serde_cbor::from_slice(cose_sign1).map_err(|e| eyre!("COSE_Sign1 decode: {}", e))?;
    let arr = match outer {
        Value::Array(a) => a,
        other => return Err(eyre!("COSE_Sign1 is not an array: {:?}", tag_of(&other))),
    };
    if arr.len() != 4 {
        return Err(eyre!("COSE_Sign1 has {} elements, expected 4", arr.len()));
    }
    // [protected, unprotected, payload, signature]; payload is a bstr.
    let payload = match &arr[2] {
        Value::Bytes(b) => b,
        other => return Err(eyre!("COSE payload is not bytes: {:?}", tag_of(other))),
    };

    let doc: Value =
        serde_cbor::from_slice(payload).map_err(|e| eyre!("payload decode: {}", e))?;
    let map = match doc {
        Value::Map(m) => m,
        other => return Err(eyre!("payload is not a map: {:?}", tag_of(&other))),
    };

    let module_id = text(&map, "module_id")?;
    let digest = text(&map, "digest")?;
    let timestamp = u64_of(&map, "timestamp")?;

    let pcrs_val = get(&map, "pcrs").ok_or_else(|| eyre!("missing pcrs"))?;
    let pcrs_map = match pcrs_val {
        Value::Map(m) => m,
        other => return Err(eyre!("pcrs is not a map: {:?}", tag_of(other))),
    };
    let mut pcrs = BTreeMap::new();
    for (k, v) in pcrs_map {
        let idx = match k {
            Value::Integer(i) if *i >= 0 && *i <= u16::MAX as i128 => *i as u16,
            other => return Err(eyre!("non-integer PCR index: {:?}", tag_of(other))),
        };
        let bytes = match v {
            Value::Bytes(b) => b.clone(),
            other => return Err(eyre!("PCR {} value is not bytes: {:?}", idx, tag_of(other))),
        };
        pcrs.insert(idx, bytes);
    }

    let certificate = match get(&map, "certificate") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err(eyre!("missing or non-bytes certificate")),
    };
    let cabundle = match get(&map, "cabundle") {
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| match v {
                Value::Bytes(b) => Ok(b.clone()),
                other => Err(eyre!("cabundle entry not bytes: {:?}", tag_of(other))),
            })
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(eyre!("missing or non-array cabundle")),
    };

    Ok(AttestationDoc {
        module_id,
        digest,
        timestamp,
        pcrs,
        public_key: optional_bytes(&map, "public_key"),
        user_data: optional_bytes(&map, "user_data"),
        nonce: optional_bytes(&map, "nonce"),
        certificate,
        cabundle,
    })
}

fn get<'a>(map: &'a BTreeMap<Value, Value>, key: &str) -> Option<&'a Value> {
    map.get(&Value::Text(key.to_string()))
}

fn text(map: &BTreeMap<Value, Value>, key: &str) -> Result<String> {
    match get(map, key) {
        Some(Value::Text(s)) => Ok(s.clone()),
        _ => Err(eyre!("missing or non-text field: {}", key)),
    }
}

fn u64_of(map: &BTreeMap<Value, Value>, key: &str) -> Result<u64> {
    match get(map, key) {
        Some(Value::Integer(i)) if *i >= 0 && *i <= u64::MAX as i128 => Ok(*i as u64),
        _ => Err(eyre!("missing or out-of-range integer field: {}", key)),
    }
}

/// A field that NSM emits as bytes-or-null; absent and null both map to `None`.
fn optional_bytes(map: &BTreeMap<Value, Value>, key: &str) -> Option<Vec<u8>> {
    match get(map, key) {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    }
}

/// Human-readable CBOR variant name for error messages.
fn tag_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Integer(_) => "integer",
        Value::Float(_) => "float",
        Value::Bytes(_) => "bytes",
        Value::Text(_) => "text",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Tag(_, _) => "tag",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const US_FIXTURE: &str =
        "/home/oxide/projects/kastad/kaskad-pontifex/test/fixtures/attestation-us.hex";

    fn load_us() -> Vec<u8> {
        let hex = std::fs::read_to_string(US_FIXTURE)
            .expect("read attestation-us.hex fixture")
            .trim()
            .to_string();
        hex_decode(&hex)
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn parses_us_fixture_pcr0() {
        let doc = parse_attestation_doc(&load_us()).expect("parse");
        let pcr0 = doc.pcr0().expect("pcr0 present");
        assert_eq!(pcr0.len(), 48);
        let expected =
            hex_decode("2e66fc4f74006323675a397ab3c6b6eab68f2ccc36f4cf10bb4d0e5c82b2106c");
        assert_eq!(&pcr0[..32], expected.as_slice());
    }

    #[test]
    fn parses_us_fixture_shape() {
        let doc = parse_attestation_doc(&load_us()).expect("parse");
        assert_eq!(doc.digest, "SHA384");
        assert_eq!(doc.timestamp, 1789682499833);
        // PCR1/PCR2 present and 48 bytes.
        assert_eq!(doc.pcr1().expect("pcr1").len(), 48);
        assert_eq!(doc.pcr2().expect("pcr2").len(), 48);
        // This document binds a public key, no user_data, no nonce.
        let pk = doc.public_key.as_ref().expect("public_key present");
        assert_eq!(pk[0], 0x04, "uncompressed SEC1 point");
        assert!(doc.user_data.is_none());
        assert!(doc.nonce.is_none());
        // Cert chain is present for the later verification slice.
        assert!(!doc.certificate.is_empty());
        assert!(!doc.cabundle.is_empty());
    }

    #[test]
    fn rejects_non_cose_input() {
        // A bare CBOR integer, not a 4-element array.
        assert!(parse_attestation_doc(&[0x01]).is_err());
    }

    #[test]
    fn rejects_truncated_document() {
        let full = load_us();
        assert!(parse_attestation_doc(&full[..full.len() / 2]).is_err());
    }
}
