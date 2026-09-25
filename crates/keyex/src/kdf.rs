//! HKDF-SHA256 child-key derivation for the Pontifex keyex (RFC 5869).
//! k_bridge = HKDF(ikm = K_root, salt = KEYEX_SALT, info = KEYEX_INFO_PREFIX || label).
//! The launch bridge child uses label = keccak256("kaskad/pontifex/v1").

use hkdf::Hkdf;
use sha2::Sha256;

/// Domain-separation salt for every keyex derivation.
pub const KEYEX_SALT: &[u8] = b"kaskad-keyex-v1";
/// Info prefix; a 32-byte label is appended to form the full info string.
pub const KEYEX_INFO_PREFIX: &[u8] = b"kaskad/pontifex/";

/// Derive a 32-byte child key from the root secret for `label`.
/// Deterministic: equal (root, label) always yield the same key. The caller
/// owns `root` and the returned key and is responsible for zeroizing both.
pub fn derive_child(root: &[u8; 32], label: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(KEYEX_SALT), root);
    let mut info = Vec::with_capacity(KEYEX_INFO_PREFIX.len() + label.len());
    info.extend_from_slice(KEYEX_INFO_PREFIX);
    info.extend_from_slice(label);
    let mut okm = [0u8; 32];
    // 32 ≤ 255*32, HKDF-SHA256's max OKM — this expand cannot fail.
    hk.expand(&info, &mut okm)
        .expect("32-byte OKM is within HKDF-SHA256 bounds");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Keccak256};

    fn v1_label() -> [u8; 32] {
        Keccak256::digest(b"kaskad/pontifex/v1").into()
    }

    #[test]
    fn canonical_known_answer() {
        // Independently computed via an RFC-5869-validated python HKDF for
        // root=[0x42;32], label=keccak256("kaskad/pontifex/v1").
        let root = [0x42u8; 32];
        let got = derive_child(&root, &v1_label());
        let expected =
            hex::decode("a99b9c4668f1ae4f2a9a7646429040bdee5ebc178afd182ab1338ab9ccd49e4d")
                .unwrap();
        assert_eq!(got.as_slice(), expected.as_slice(), "k_bridge KAT");
    }

    #[test]
    fn label_matches_approval_vector() {
        // The bridge child label is the same keccak the approval CHILD mode binds.
        let expected =
            hex::decode("22b2101dead9b19406fce58d3c74f610a77ec9bca8532409bd4e05145f2366e9")
                .unwrap();
        assert_eq!(v1_label().as_slice(), expected.as_slice());
    }

    #[test]
    fn deterministic() {
        let root = [7u8; 32];
        let l = v1_label();
        assert_eq!(derive_child(&root, &l), derive_child(&root, &l));
    }

    #[test]
    fn distinct_labels_distinct_keys() {
        let root = [7u8; 32];
        let l1 = v1_label();
        let l2: [u8; 32] = Keccak256::digest(b"kaskad/pontifex/v2").into();
        assert_ne!(derive_child(&root, &l1), derive_child(&root, &l2));
    }

    #[test]
    fn distinct_roots_distinct_keys() {
        let l = v1_label();
        assert_ne!(derive_child(&[1u8; 32], &l), derive_child(&[2u8; 32], &l));
    }
}
