//! The installed genesis/peer key as an [`OracleSigner`]. Signs the oracle price
//! path with EIP-191 (byte-identical to the default `EnclaveSigner`) and gates
//! signing on a fresh NSM attestation — a key that cannot re-attest has lost its
//! proof of being inside the trust envelope.

use eyre::Result;
use k256::ecdsa::SigningKey;
use nitro_common::nsm::Nsm;
use sha3::{Digest, Keccak256};
use tracing::warn;

use crate::signer::OracleSigner;

/// Apply EIP-191 wrapping (`"\x19Ethereum Signed Message:\n32" || digest`), keccak,
/// then sign. Returns the 65-byte (r, s, v) signature. Copied verbatim from the
/// default `signer::sign_eip191` (private there) so the wire signature is identical.
fn sign_eip191(signing_key: &SigningKey, digest: [u8; 32]) -> Result<[u8; 65]> {
    let mut eth_message = Vec::with_capacity(28 + 32);
    eth_message.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
    eth_message.extend_from_slice(&digest);
    let eth_hash: [u8; 32] = Keccak256::digest(&eth_message).into();

    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&eth_hash)
        .map_err(|e| eyre::eyre!("signing failed: {}", e))?;

    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&signature.to_bytes());
    out[64] = recovery_id.to_byte() + 27;
    Ok(out)
}

/// The running oracle signer: an NSM-rooted secp256k1 key installed by boot.
pub struct KeyexSigner {
    signing_key: SigningKey,
    address: [u8; 20],
    /// Uncompressed public key (65 bytes: 0x04 ‖ X ‖ Y).
    pubkey_bytes: Vec<u8>,
}

impl KeyexSigner {
    /// Wrap an installed key, deriving its address and SEC1 public point.
    pub fn from_key(signing_key: SigningKey) -> Self {
        let vk = signing_key.verifying_key();
        let pubkey_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
        let alloy_addr = keyex::sig::address_from_key(vk);
        let mut address = [0u8; 20];
        address.copy_from_slice(alloy_addr.as_slice());
        Self {
            signing_key,
            address,
            pubkey_bytes,
        }
    }

    /// The 65-byte SEC1 public point, published to boot state for attestation.
    pub fn pubkey_bytes(&self) -> &[u8] {
        &self.pubkey_bytes
    }

    /// Fresh NSM attestation binding this signer's public key.
    fn fresh_attestation_doc(&self) -> Result<Vec<u8>> {
        Nsm::new()?.attestation(None, None, Some(self.pubkey_bytes.clone()))
    }
}

impl OracleSigner for KeyexSigner {
    fn sign_digest(&self, digest: [u8; 32]) -> Result<(Vec<u8>, [u8; 20])> {
        let sig = sign_eip191(&self.signing_key, digest)?;
        Ok((sig.to_vec(), self.address))
    }

    fn address(&self) -> [u8; 20] {
        self.address
    }

    fn attestation_doc(&self) -> Option<Vec<u8>> {
        match self.fresh_attestation_doc() {
            Ok(doc) => Some(doc),
            Err(e) => {
                warn!(error = %e, "NSM attestation request failed");
                None
            }
        }
    }

    fn requires_attestation_for_signing(&self) -> bool {
        true
    }
}
