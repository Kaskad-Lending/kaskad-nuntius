//! Full cryptographic verification of an AWS Nitro attestation document,
//! layered over [`crate::attest`]'s structural parse. Ports the algorithm
//! of `nitro-prover` (Solidity `NitroProver`/`CertManager`) to Rust:
//! COSE_Sign1 ES384/SHA384 over the leaf signing key, an ECDSA-P384 cert
//! chain pinned to the AWS Nitro root, validity checked against an injected
//! clock (fixtures expire in ~3h, so system time is never read).

use crate::attest::{self, AttestationDoc};
use eyre::{bail, eyre, Result};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde_cbor::Value;
use sha3::{Digest, Keccak256};
use x509_cert::{
    der::{Decode, Encode},
    ext::pkix::{BasicConstraints, KeyUsage, KeyUsages},
    Certificate,
};

/// AWS Nitro Enclaves Root CA G1 (DER), pinned. Sourced 1:1 from
/// `CertManager.ROOT_CA_CERT`; the chain is rejected unless `cabundle[0]`
/// equals these exact bytes.
const ROOT_CA_CERT_HEX: &str = "3082021130820196a003020102021100f93175681b90afe11d46ccb4e4e7f856300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3139313032383133323830355a170d3439313032383134323830355a3049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4a3423040300f0603551d130101ff040530030101ff301d0603551d0e041604149025b50dd90547e796c396fa729dcf99a9df4b96300e0603551d0f0101ff040403020186300a06082a8648ce3d0403030369003066023100a37f2f91a1c9bd5ee7b8627c1698d255038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b4c3d6adf3023100a2f39b1605b27028a5dd4ba069b5016e65b4fbde8fe0061d6a53197f9cdaf5d943bc61fc2beb03cb6fee8d2302f3dff6";

const PCR_LEN: usize = 48;
/// COSE ES384 algorithm identifier (RFC 9053), as a CBOR negative integer.
const COSE_ALG_ES384: i128 = -35;
/// Tolerance for the enclave clock running ahead of the caller's clock when
/// a freshness bound is enforced (the NSM timestamp may lead `now`).
const CLOCK_SKEW_SECS: u64 = 300;

/// A fully verified attestation: signature valid, chain rooted at the pinned
/// AWS Nitro root, certificates within validity at the supplied clock.
#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    pub pcr0: [u8; PCR_LEN],
    pub pcr1: [u8; PCR_LEN],
    pub pcr2: [u8; PCR_LEN],
    /// Ethereum address of the attested enclave key: `keccak256(public_key[1..])[12..]`.
    pub enclave_signer: [u8; 20],
    /// The attested 65-byte uncompressed secp256k1 key (the ephemeral enclave key).
    pub public_key: Vec<u8>,
    /// NSM timestamp, milliseconds since the Unix epoch.
    pub timestamp: u64,
}

/// Verify a Nitro attestation document end to end. `now_unix_secs` is the
/// clock every certificate's validity window is checked against (injected,
/// never the system clock). `max_age_secs`, when set, bounds how far the NSM
/// `timestamp` may lag `now` (with [`CLOCK_SKEW_SECS`] tolerance ahead) — pass
/// it wherever freshness is not otherwise pinned by a nonce (boot, on-chain
/// reads); pass `None` only when the caller binds freshness itself (RA-TLS
/// nonce). When `expected_nonce` is set the document's nonce must match it
/// (constant-time).
pub fn verify_attestation(
    doc_bytes: &[u8],
    now_unix_secs: u64,
    max_age_secs: Option<u64>,
    expected_nonce: Option<&[u8]>,
) -> Result<VerifiedAttestation> {
    verify_with_root(
        doc_bytes,
        now_unix_secs,
        max_age_secs,
        expected_nonce,
        &pinned_root()?,
    )
}

/// Inner verifier with an explicit pinned root, to exercise root mismatch.
fn verify_with_root(
    doc_bytes: &[u8],
    now_unix_secs: u64,
    max_age_secs: Option<u64>,
    expected_nonce: Option<&[u8]>,
    pinned_root_der: &[u8],
) -> Result<VerifiedAttestation> {
    let doc = attest::parse_attestation_doc(doc_bytes)?;
    semantic_checks(&doc, expected_nonce)?;
    if let Some(max_age) = max_age_secs {
        check_freshness(doc.timestamp, now_unix_secs, max_age)?;
    }

    // Chain: cabundle (root first) then the leaf certificate. The leaf's
    // public key is returned and used to verify the COSE signature.
    let leaf_pubkey = verify_cert_chain(&doc, now_unix_secs, pinned_root_der)?;

    // COSE_Sign1 ES384/SHA384 over the leaf signing key.
    let (protected, payload, signature) = cose_parts(doc_bytes)?;
    let to_be_signed = sig_structure(&protected, &payload)?;
    verify_es384(&leaf_pubkey, &to_be_signed, &signature)
        .map_err(|e| eyre!("COSE signature invalid: {}", e))?;

    let public_key = doc
        .public_key
        .clone()
        .ok_or_else(|| eyre!("signer document has no public_key"))?;
    let enclave_signer = eth_address(&public_key)?;

    Ok(VerifiedAttestation {
        pcr0: pcr_array(&doc, 0)?,
        pcr1: pcr_array(&doc, 1)?,
        pcr2: pcr_array(&doc, 2)?,
        enclave_signer,
        public_key,
        timestamp: doc.timestamp,
    })
}

/// Semantic validation: SHA384 digest, PCR0/1/2 present at 48 bytes, an
/// uncompressed signer key, and (if requested) a matching nonce.
fn semantic_checks(doc: &AttestationDoc, expected_nonce: Option<&[u8]>) -> Result<()> {
    if doc.digest != "SHA384" {
        bail!("unexpected digest algorithm: {}", doc.digest);
    }
    for idx in [0u16, 1, 2] {
        match doc.pcr(idx) {
            Some(p) if p.len() == PCR_LEN => {}
            Some(p) => bail!("PCR{} has length {}, expected {}", idx, p.len(), PCR_LEN),
            None => bail!("missing PCR{}", idx),
        }
    }
    match doc.public_key.as_deref() {
        Some(pk) if pk.len() == 65 && pk[0] == 0x04 => {}
        Some(pk) => bail!(
            "signer public_key is not a 65-byte uncompressed point (len {}, tag {:#04x})",
            pk.len(),
            pk.first().copied().unwrap_or(0)
        ),
        None => bail!("signer document has no public_key"),
    }
    if let Some(expected) = expected_nonce {
        match doc.nonce.as_deref() {
            Some(n) if ct_eq(n, expected) => {}
            _ => bail!("nonce mismatch"),
        }
    }
    Ok(())
}

/// Verify the certificate chain and return the leaf signing key (SEC1, 97 B).
/// `cabundle[0]` must equal the pinned root; each subsequent certificate is
/// verified against its predecessor's key, and every certificate's validity
/// window must contain `now_unix_secs`.
fn verify_cert_chain(
    doc: &AttestationDoc,
    now_unix_secs: u64,
    pinned_root_der: &[u8],
) -> Result<Vec<u8>> {
    if doc.cabundle.is_empty() {
        bail!("empty cabundle");
    }
    if doc.cabundle[0].as_slice() != pinned_root_der {
        bail!("cabundle root does not match the pinned AWS Nitro root");
    }

    // Chain in signing order: root, intermediates, leaf.
    let mut chain: Vec<&[u8]> = doc.cabundle.iter().map(|c| c.as_slice()).collect();
    chain.push(doc.certificate.as_slice());

    let mut issuer_pubkey: Option<Vec<u8>> = None;
    let mut leaf_pubkey = Vec::new();
    let chain_len = chain.len();
    for (i, cert_der) in chain.iter().enumerate() {
        let cert =
            Certificate::from_der(cert_der).map_err(|e| eyre!("cert[{}] parse: {}", i, e))?;
        check_validity(&cert, now_unix_secs, i)?;

        // Every cert that signs a child must be a CA (RFC 5280 §6.1.4). Without
        // this a leaf (CA:FALSE) reused as an issuer would pass chain-of-signatures.
        // The leaf itself (last) signs nothing, so is exempt.
        if i + 1 < chain_len {
            require_ca(&cert, i)?;
        }

        if let Some(parent) = &issuer_pubkey {
            let tbs = cert
                .tbs_certificate
                .to_der()
                .map_err(|e| eyre!("cert[{}] tbs re-encode: {}", i, e))?;
            let sig = ecdsa_der_to_fixed(cert.signature.raw_bytes())
                .map_err(|e| eyre!("cert[{}] signature: {}", i, e))?;
            verify_es384(parent, &tbs, &sig)
                .map_err(|e| eyre!("cert[{}] signature invalid: {}", i, e))?;
        }

        let spki = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec();
        leaf_pubkey = spki.clone();
        issuer_pubkey = Some(spki);
    }
    Ok(leaf_pubkey)
}

/// `notBefore <= now <= notAfter` against the injected clock.
fn check_validity(cert: &Certificate, now_unix_secs: u64, idx: usize) -> Result<()> {
    let not_before = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs();
    let not_after = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    if now_unix_secs < not_before {
        bail!("cert[{}] not valid yet (notBefore {})", idx, not_before);
    }
    if now_unix_secs > not_after {
        bail!("cert[{}] expired (notAfter {})", idx, not_after);
    }
    Ok(())
}

/// Require an issuer certificate to be a CA: basicConstraints CA:TRUE, and, if
/// a keyUsage extension is present, the keyCertSign bit. keyUsage absent is
/// tolerated (some CAs omit it); CA:TRUE is the binding check.
fn require_ca(cert: &Certificate, idx: usize) -> Result<()> {
    match cert
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(|e| eyre!("cert[{}] basicConstraints decode: {}", idx, e))?
    {
        Some((_critical, bc)) if bc.ca => {}
        _ => bail!(
            "cert[{}] is not a CA (basicConstraints CA:TRUE required)",
            idx
        ),
    }
    if let Some((_critical, ku)) = cert
        .tbs_certificate
        .get::<KeyUsage>()
        .map_err(|e| eyre!("cert[{}] keyUsage decode: {}", idx, e))?
    {
        if !ku.0.contains(KeyUsages::KeyCertSign) {
            bail!("cert[{}] keyUsage lacks keyCertSign", idx);
        }
    }
    Ok(())
}

/// Bound how stale an attestation may be. The NSM `timestamp` (milliseconds)
/// must sit within `[now - max_age, now + CLOCK_SKEW_SECS]`.
fn check_freshness(ts_millis: u64, now_secs: u64, max_age_secs: u64) -> Result<()> {
    let ts_secs = ts_millis / 1000;
    if ts_secs > now_secs.saturating_add(CLOCK_SKEW_SECS) {
        bail!(
            "attestation timestamp {}s is in the future (now {}s)",
            ts_secs,
            now_secs
        );
    }
    let age = now_secs.saturating_sub(ts_secs);
    if age > max_age_secs {
        bail!(
            "attestation is stale: age {}s exceeds max_age {}s",
            age,
            max_age_secs
        );
    }
    Ok(())
}

/// Split COSE_Sign1 into (protected header bytes, payload bytes, signature),
/// checking the untagged 4-array shape, empty unprotected header, and ES384.
fn cose_parts(cose: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let outer: Value = serde_cbor::from_slice(cose).map_err(|e| eyre!("COSE decode: {}", e))?;
    let arr = match outer {
        Value::Array(a) if a.len() == 4 => a,
        _ => bail!("COSE_Sign1 is not a 4-element array"),
    };
    let protected = match &arr[0] {
        Value::Bytes(b) => b.clone(),
        _ => bail!("COSE protected header is not bytes"),
    };
    match &arr[1] {
        Value::Map(m) if m.is_empty() => {}
        _ => bail!("COSE unprotected header must be an empty map"),
    }
    let payload = match &arr[2] {
        Value::Bytes(b) => b.clone(),
        _ => bail!("COSE payload is not bytes"),
    };
    let signature = match &arr[3] {
        Value::Bytes(b) => b.clone(),
        _ => bail!("COSE signature is not bytes"),
    };

    // Protected header must declare alg = ES384 (key 1 => -35), and only that.
    let header: Value =
        serde_cbor::from_slice(&protected).map_err(|e| eyre!("protected header decode: {}", e))?;
    let map = match header {
        Value::Map(m) => m,
        _ => bail!("protected header is not a map"),
    };
    match map.get(&Value::Integer(1)) {
        Some(Value::Integer(alg)) if *alg == COSE_ALG_ES384 => {}
        _ => bail!("protected header algorithm is not ES384"),
    }
    Ok((protected, payload, signature))
}

/// RFC 9052 §4.4 Sig_structure for COSE_Sign1:
/// `["Signature1", protected, external_aad(=b""), payload]`, CBOR-encoded.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    serde_cbor::to_vec(&structure).map_err(|e| eyre!("Sig_structure encode: {}", e))
}

/// ECDSA-P384/SHA384 verify: `pubkey` is a 97-byte uncompressed SEC1 point,
/// `sig` is 96 raw bytes (r||s). SHA-384 is applied to `message` internally.
fn verify_es384(pubkey: &[u8], message: &[u8], sig: &[u8]) -> Result<()> {
    if sig.len() != 96 {
        bail!("signature length {} != 96", sig.len());
    }
    let vk = VerifyingKey::from_sec1_bytes(pubkey)
        .map_err(|e| eyre!("invalid P-384 public key: {}", e))?;
    let signature =
        Signature::from_slice(sig).map_err(|e| eyre!("malformed P-384 signature: {}", e))?;
    vk.verify(message, &signature)
        .map_err(|e| eyre!("verification failed: {}", e))
}

/// Convert a DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
/// (as found in a certificate signature BIT STRING) to fixed 96-byte r||s.
fn ecdsa_der_to_fixed(der: &[u8]) -> Result<[u8; 96]> {
    let mut p = 0usize;
    if der.get(p).copied() != Some(0x30) {
        bail!("expected DER SEQUENCE");
    }
    p += 1;
    let seq_len = read_der_len(der, &mut p)?;
    let seq_end = p + seq_len;
    if seq_end > der.len() {
        bail!("SEQUENCE overruns buffer");
    }
    let r = read_der_int(der, &mut p, seq_end)?;
    let s = read_der_int(der, &mut p, seq_end)?;
    let mut out = [0u8; 96];
    left_pad_into(r, &mut out[..48])?;
    left_pad_into(s, &mut out[48..])?;
    Ok(out)
}

fn read_der_len(der: &[u8], p: &mut usize) -> Result<usize> {
    let first = *der.get(*p).ok_or_else(|| eyre!("truncated length"))?;
    *p += 1;
    if first < 0x80 {
        return Ok(first as usize);
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        bail!("unsupported DER length form");
    }
    let mut len = 0usize;
    for _ in 0..n {
        let b = *der.get(*p).ok_or_else(|| eyre!("truncated length bytes"))?;
        *p += 1;
        len = (len << 8) | b as usize;
    }
    Ok(len)
}

fn read_der_int<'a>(der: &'a [u8], p: &mut usize, end: usize) -> Result<&'a [u8]> {
    if der.get(*p).copied() != Some(0x02) {
        bail!("expected DER INTEGER");
    }
    *p += 1;
    let len = read_der_len(der, p)?;
    let start = *p;
    let stop = start + len;
    if stop > end {
        bail!("INTEGER overruns SEQUENCE");
    }
    *p = stop;
    let mut bytes = &der[start..stop];
    // Strip a single leading 0x00 sign byte.
    if bytes.first() == Some(&0x00) && bytes.len() > 1 {
        bytes = &bytes[1..];
    }
    Ok(bytes)
}

fn left_pad_into(src: &[u8], dst: &mut [u8]) -> Result<()> {
    if src.len() > dst.len() {
        bail!("integer wider than field");
    }
    dst.fill(0);
    let offset = dst.len() - src.len();
    dst[offset..].copy_from_slice(src);
    Ok(())
}

/// Ethereum address of an uncompressed secp256k1 key: `keccak256(pk[1..])[12..]`.
fn eth_address(public_key: &[u8]) -> Result<[u8; 20]> {
    if public_key.len() != 65 || public_key[0] != 0x04 {
        bail!("public_key is not a 65-byte uncompressed point");
    }
    let hash = Keccak256::digest(&public_key[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok(addr)
}

fn pcr_array(doc: &AttestationDoc, idx: u16) -> Result<[u8; PCR_LEN]> {
    let pcr = doc.pcr(idx).ok_or_else(|| eyre!("missing PCR{}", idx))?;
    pcr.try_into()
        .map_err(|_| eyre!("PCR{} is not {} bytes", idx, PCR_LEN))
}

fn pinned_root() -> Result<Vec<u8>> {
    decode_hex(ROOT_CA_CERT_HEX)
}

/// Constant-time byte-slice equality (length is not treated as secret).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("odd hex length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| eyre!("bad hex: {}", e)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const US_HEX: &str =
        "/home/oxide/projects/kastad/kaskad-pontifex/test/fixtures/attestation-us.hex";
    const EU_HEX: &str =
        "/home/oxide/projects/kastad/kaskad-pontifex/test/fixtures/attestation-eu.hex";
    // Inside both leaf validity windows (2026-09-17 22:04:58Z).
    const NOW: u64 = 1789682698;

    fn load(path: &str) -> Vec<u8> {
        let hex = std::fs::read_to_string(path).expect("read fixture");
        decode_hex(hex.trim()).expect("decode fixture hex")
    }

    #[test]
    fn verifies_us_document() {
        let v = verify_attestation(&load(US_HEX), NOW, None, None).expect("verify US");
        assert_eq!(
            hex::encode(v.enclave_signer),
            "544705f5d72e1c6f24bfd7c2e176f2cd2aa8dc2a"
        );
        let expected_pcr0 =
            decode_hex("2e66fc4f74006323675a397ab3c6b6eab68f2ccc36f4cf10bb4d0e5c82b2106c").unwrap();
        assert_eq!(&v.pcr0[..32], expected_pcr0.as_slice());
        assert_eq!(v.public_key.len(), 65);
    }

    #[test]
    fn verifies_eu_document() {
        let v = verify_attestation(&load(EU_HEX), NOW, None, None).expect("verify EU");
        assert_eq!(
            hex::encode(v.enclave_signer),
            "d35e55c7c2d10472e6d9e7132c88beed347d91a7"
        );
    }

    #[test]
    fn rejects_tampered_signature() {
        let outer: Value = serde_cbor::from_slice(&load(US_HEX)).unwrap();
        let mut arr = match outer {
            Value::Array(a) => a,
            _ => panic!("not array"),
        };
        let mut sig = match arr[3].clone() {
            Value::Bytes(b) => b,
            _ => panic!("sig not bytes"),
        };
        sig[0] ^= 0x01;
        arr[3] = Value::Bytes(sig);
        let tampered = serde_cbor::to_vec(&Value::Array(arr)).unwrap();
        assert!(verify_attestation(&tampered, NOW, None, None).is_err());
    }

    #[test]
    fn rejects_expired_clock() {
        // Well past every leaf notAfter (~2026-09-17 23:16Z).
        let err = verify_attestation(&load(US_HEX), 1_900_000_000, None, None).unwrap_err();
        assert!(format!("{err}").contains("expired"), "got: {err}");
    }

    #[test]
    fn rejects_wrong_root() {
        // Swap the pinned root for the leaf's own DER: the self-issued chain
        // no longer terminates at the AWS Nitro root.
        let doc = attest::parse_attestation_doc(&load(US_HEX)).unwrap();
        let bogus_root = doc.certificate.clone();
        let err = verify_with_root(&load(US_HEX), NOW, None, None, &bogus_root).unwrap_err();
        assert!(
            format!("{err}").contains("pinned AWS Nitro root"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_nonce_mismatch() {
        // US document carries no nonce; requiring one must fail.
        assert!(verify_attestation(&load(US_HEX), NOW, None, Some(b"expected")).is_err());
    }

    #[test]
    fn rejects_stale_document() {
        // Fixture timestamp is ~199s before NOW; a 60s max_age must reject it.
        let err = verify_attestation(&load(US_HEX), NOW, Some(60), None).unwrap_err();
        assert!(format!("{err}").contains("stale"), "got: {err}");
    }

    #[test]
    fn accepts_within_max_age() {
        // Same document inside a 1h window verifies (regression: freshness must
        // not reject a legitimately recent attestation).
        verify_attestation(&load(US_HEX), NOW, Some(3600), None).expect("fresh verify");
    }

    #[test]
    fn rejects_future_timestamp() {
        // Clock 1000s behind the NSM timestamp, past the skew tolerance.
        let err = verify_attestation(&load(US_HEX), NOW - 1000, Some(3600), None).unwrap_err();
        assert!(format!("{err}").contains("future"), "got: {err}");
    }
}
