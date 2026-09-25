//! Shared secp256k1 recovery and recoverable signing for keyex EIP-712 payloads.
//! One audited implementation matching OZ `ECDSA.recoverCalldata`: EIP-2 low-s,
//! v ∈ {27, 28}. Approval verification recovers; claim signing signs.

use alloy_primitives::{Address, B256};
use eyre::{bail, eyre, Result};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

/// Ethereum address: last 20 bytes of keccak256 over the 64-byte uncompressed
/// public point (SEC1 minus the 0x04 tag).
pub fn address_from_key(vk: &VerifyingKey) -> Address {
    let point = vk.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    Address::from_slice(&hash[12..])
}

/// Recover the signer address from a 65-byte r‖s‖v signature over `digest`.
/// Enforces EIP-2 low-s and canonical v ∈ {27, 28} — exactly what on-chain
/// `ECDSA.recoverCalldata` accepts.
pub fn recover(digest: &B256, sig: &[u8; 65]) -> Result<Address> {
    let signature =
        Signature::from_slice(&sig[..64]).map_err(|e| eyre!("bad signature bytes: {e}"))?;
    // normalize_s returns Some only when the input was high-s (EIP-2 malleable).
    if signature.normalize_s().is_some() {
        bail!("high-s signature rejected (EIP-2)");
    }
    let v = sig[64];
    let rec = match v {
        27 => RecoveryId::from_byte(0),
        28 => RecoveryId::from_byte(1),
        _ => None,
    }
    .ok_or_else(|| eyre!("non-canonical recovery id: {v} (expected 27 or 28)"))?;
    let vk = VerifyingKey::recover_from_prehash(digest.as_slice(), &signature, rec)
        .map_err(|e| eyre!("recovery failed: {e}"))?;
    Ok(address_from_key(&vk))
}

/// Sign `digest` producing a 65-byte r‖s‖v (v = 27/28), EIP-2 low-s. Self-checks
/// that the emitted signature recovers to the signer's own address, so a signer
/// bug (high-s, wrong recovery id, r-overflow) fails closed instead of emitting a
/// claim the contract rejects — or, worse, attributes to another key.
pub fn sign_recoverable(sk: &SigningKey, digest: &B256) -> Result<[u8; 65]> {
    let (sig, rec) = sk
        .sign_prehash_recoverable(digest.as_slice())
        .map_err(|e| eyre!("signing failed: {e}"))?;
    // k256 already normalizes to low-s here; assert the invariant regardless.
    if sig.normalize_s().is_some() {
        bail!("signer emitted high-s (EIP-2 violation)");
    }
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    // rec ∈ {2,3} (r-overflow) would make v ∈ {29,30}; the self-check below
    // rejects it via recover()'s canonical-v guard.
    out[64] = 27 + rec.to_byte();
    let expect = address_from_key(sk.verifying_key());
    let got = recover(digest, &out).map_err(|e| eyre!("signing self-check recover failed: {e}"))?;
    if got != expect {
        bail!("signing self-check failed: recovered {got} != signer {expect}");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        let mut s = [0u8; 32];
        s[31] = seed;
        SigningKey::from_bytes((&s).into()).expect("nonzero seed")
    }

    #[test]
    fn sign_then_recover_roundtrips() {
        let sk = key(7);
        let digest = B256::from([0x11u8; 32]);
        let sig = sign_recoverable(&sk, &digest).unwrap();
        assert_eq!(recover(&digest, &sig).unwrap(), address_from_key(sk.verifying_key()));
    }

    #[test]
    fn sign_is_always_low_s() {
        // Every seed's signature must be low-s (recover would otherwise reject it).
        for seed in 1u8..40 {
            let sk = key(seed);
            let digest = B256::from([seed; 32]);
            let sig = sign_recoverable(&sk, &digest).unwrap();
            let parsed = Signature::from_slice(&sig[..64]).unwrap();
            assert!(parsed.normalize_s().is_none(), "seed {seed} produced high-s");
            assert!(sig[64] == 27 || sig[64] == 28, "seed {seed} non-canonical v {}", sig[64]);
        }
    }

    #[test]
    fn recover_rejects_high_s() {
        let sk = key(3);
        let digest = B256::from([0x22u8; 32]);
        let good = sign_recoverable(&sk, &digest).unwrap();
        // Malleate to high-s: s' = n - s, flip v parity.
        let parsed = Signature::from_slice(&good[..64]).unwrap();
        let high_s = parsed.s().negate();
        let mut bad = good;
        bad[32..64].copy_from_slice(&high_s.to_bytes());
        bad[64] = if good[64] == 27 { 28 } else { 27 };
        assert!(recover(&digest, &bad).is_err());
    }

    #[test]
    fn recover_rejects_non_canonical_v() {
        let sk = key(5);
        let digest = B256::from([0x33u8; 32]);
        let mut sig = sign_recoverable(&sk, &digest).unwrap();
        sig[64] = 29;
        assert!(recover(&digest, &sig).is_err());
        sig[64] = 0;
        assert!(recover(&digest, &sig).is_err());
    }
}
