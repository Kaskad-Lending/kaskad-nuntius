//! RA-TLS channel binding: given an already cryptographically-verified
//! attestation view (COSE + cert chain done by `nitro_common::verify`), affirm
//! the two channel-binding facts — the document answers OUR nonce, and its
//! attested `public_key` equals the peer's TLS key. The key is compared as the
//! 65-byte SEC1 uncompressed EC point (`0x04‖X‖Y`) that `verify` forces the
//! attested key to be, NOT the SPKI DER wrapper. PCR0 policy is
//! [`crate::policy`]; producing the nonce and the NSM-signed attestation over
//! `(nonce, point)` happens on Nitro hardware and is not testable off it.

use eyre::{bail, Result};

/// The two attestation fields RA-TLS binds a channel to. `nonce` mirrors the
/// document's optional nonce; `public_key` is its attested key — the peer's
/// 65-byte SEC1 uncompressed EC point. Borrowed so the caller can build it from
/// a verified doc with no copy.
#[derive(Clone, Copy, Debug)]
pub struct AttestationView<'a> {
    pub nonce: Option<&'a [u8]>,
    pub public_key: &'a [u8],
}

impl<'a> AttestationView<'a> {
    pub fn new(nonce: Option<&'a [u8]>, public_key: &'a [u8]) -> Self {
        AttestationView { nonce, public_key }
    }
}

/// Both binding checks: the document's nonce equals ours and its attested key
/// equals the peer's TLS point. `Ok(())` only when both hold.
pub fn check_channel_binding(
    view: &AttestationView<'_>,
    expected_nonce: &[u8],
    expected_key: &[u8],
) -> Result<()> {
    check_nonce(view, expected_nonce)?;
    check_peer_key(view, expected_key)
}

/// The attestation must carry a nonce equal to `expected_nonce`. A missing
/// nonce fails closed — keyex never requests an attestation without one.
pub fn check_nonce(view: &AttestationView<'_>, expected_nonce: &[u8]) -> Result<()> {
    match view.nonce {
        Some(n) if ct_eq(n, expected_nonce) => Ok(()),
        Some(_) => bail!("attestation nonce does not match the channel nonce"),
        None => bail!("attestation carries no nonce"),
    }
}

/// The attested key must equal the peer's TLS point, binding the attestation to
/// this TLS channel. Empty on either side fails closed: `ct_eq(&[], &[])` is
/// true, so a keyless attestation must never be treated as a match.
pub fn check_peer_key(view: &AttestationView<'_>, expected_key: &[u8]) -> Result<()> {
    if view.public_key.is_empty() || expected_key.is_empty() {
        bail!("attested public_key or peer key is empty");
    }
    if ct_eq(view.public_key, expected_key) {
        Ok(())
    } else {
        bail!("attested public_key does not match the peer TLS point");
    }
}

/// Constant-time equality; length is not treated as secret.
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

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &[u8] = b"0123456789abcdef0123456789abcdef";
    // A stand-in 65-byte uncompressed EC point (0x04 tag + 64 body bytes).
    const PEER_KEY: &[u8] = &[0x04; 65];

    fn view<'a>(nonce: Option<&'a [u8]>, key: &'a [u8]) -> AttestationView<'a> {
        AttestationView::new(nonce, key)
    }

    #[test]
    fn accepts_matching_nonce_and_key() {
        let v = view(Some(NONCE), PEER_KEY);
        assert!(check_channel_binding(&v, NONCE, PEER_KEY).is_ok());
    }

    #[test]
    fn rejects_nonce_mismatch() {
        let mut wrong = NONCE.to_vec();
        wrong[0] ^= 0x01;
        let v = view(Some(&wrong), PEER_KEY);
        assert!(check_nonce(&v, NONCE).is_err());
        assert!(check_channel_binding(&v, NONCE, PEER_KEY).is_err());
    }

    #[test]
    fn rejects_missing_nonce() {
        let v = view(None, PEER_KEY);
        assert!(check_nonce(&v, NONCE).is_err());
    }

    #[test]
    fn rejects_nonce_length_mismatch() {
        let short = &NONCE[..NONCE.len() - 1];
        let v = view(Some(short), PEER_KEY);
        assert!(check_nonce(&v, NONCE).is_err());
    }

    #[test]
    fn rejects_key_mismatch() {
        let mut wrong = PEER_KEY.to_vec();
        wrong[2] ^= 0x01;
        let v = view(Some(NONCE), &wrong);
        assert!(check_peer_key(&v, PEER_KEY).is_err());
        // Nonce ok, key wrong → the combined check still fails.
        assert!(check_channel_binding(&v, NONCE, PEER_KEY).is_err());
    }

    #[test]
    fn rejects_key_length_mismatch() {
        let longer = [PEER_KEY, b"x"].concat();
        let v = view(Some(NONCE), &longer);
        assert!(check_peer_key(&v, PEER_KEY).is_err());
    }

    #[test]
    fn rejects_empty_key_both_sides() {
        // ct_eq(&[], &[]) == true; the non-empty guard must reject it so a
        // keyless attestation can never bind a channel.
        let v = view(Some(NONCE), b"");
        assert!(check_peer_key(&v, b"").is_err());
    }
}
