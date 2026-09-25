//! NSM-backed pieces the bridge needs on real Nitro hardware: an [`Attestor`]
//! that binds the running signer's key into a fresh attestation document, and this
//! image's own PCR0 read. The bridge NEVER generates a key, so there is no genesis
//! here — boot only ever fetches.

use eyre::{eyre, Result};
use nitro_common::nsm::Nsm;

use crate::handler::Attestor;

/// Produces a COSE attestation binding the caller-supplied nonce and the signer's
/// public key. A failed NSM call yields `None` so the handler fails closed.
pub struct NsmAttestor {
    nsm: Nsm,
}

impl NsmAttestor {
    pub fn new(nsm: Nsm) -> Self {
        Self { nsm }
    }
}

impl Attestor for NsmAttestor {
    fn attest(&self, nonce: Option<Vec<u8>>, public_key: Vec<u8>) -> Option<Vec<u8>> {
        self.nsm.attestation(None, nonce, Some(public_key)).ok()
    }
}

/// This enclave's measured PCR0 (48 bytes). Errors if the slot is the wrong
/// length — a bridge with an unknown identity must not boot.
pub fn own_pcr0(nsm: &Nsm) -> Result<[u8; 48]> {
    nsm.describe_pcr(0)?.data.try_into().map_err(|_| eyre!("PCR0 is not 48 bytes"))
}
