//! Thin wrapper over the Nitro Security Module driver: `GetRandom`,
//! `Attestation` and `DescribePCR`. The file descriptor is opened on
//! construction and closed on drop; every path returns `Result` rather
//! than aborting, so callers choose their own fail-closed policy.

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use eyre::{eyre, Result};

/// An open NSM handle. Not `Clone`: it owns the driver fd.
pub struct Nsm {
    fd: i32,
}

/// One PCR slot as returned by `DescribePCR`.
#[derive(Debug, Clone)]
pub struct PcrDescription {
    pub lock: bool,
    pub data: Vec<u8>,
}

impl Nsm {
    /// Open the NSM device.
    pub fn new() -> Result<Self> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(eyre!("nsm_init failed: {}", fd));
        }
        Ok(Self { fd })
    }

    /// Fill `dest` with hardware entropy from NSM `GetRandom`. Each call
    /// may return fewer bytes than a full slot, so it loops. Never falls
    /// back to any other entropy source.
    pub fn get_random(&self, dest: &mut [u8]) -> Result<()> {
        let mut filled = 0usize;
        while filled < dest.len() {
            match nsm_process_request(self.fd, Request::GetRandom) {
                Response::GetRandom { random } => {
                    if random.is_empty() {
                        return Err(eyre!("NSM GetRandom returned empty buffer"));
                    }
                    let take = (dest.len() - filled).min(random.len());
                    dest[filled..filled + take].copy_from_slice(&random[..take]);
                    filled += take;
                }
                Response::Error(e) => return Err(eyre!("NSM GetRandom error: {:?}", e)),
                other => return Err(eyre!("NSM GetRandom unexpected response: {:?}", other)),
            }
        }
        Ok(())
    }

    /// Request an attestation document binding `public_key`, `user_data`
    /// and `nonce` (any of which may be absent). Returns the raw
    /// COSE_Sign1 bytes; parse with [`crate::attest`].
    pub fn attestation(
        &self,
        user_data: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let request = Request::Attestation {
            user_data: user_data.map(Into::into),
            nonce: nonce.map(Into::into),
            public_key: public_key.map(Into::into),
        };
        match nsm_process_request(self.fd, request) {
            Response::Attestation { document } => Ok(document),
            Response::Error(e) => Err(eyre!("NSM Attestation error: {:?}", e)),
            other => Err(eyre!("NSM Attestation unexpected response: {:?}", other)),
        }
    }

    /// Read one PCR slot.
    pub fn describe_pcr(&self, index: u16) -> Result<PcrDescription> {
        match nsm_process_request(self.fd, Request::DescribePCR { index }) {
            Response::DescribePCR { lock, data } => Ok(PcrDescription { lock, data }),
            Response::Error(e) => Err(eyre!("NSM DescribePCR error: {:?}", e)),
            other => Err(eyre!("NSM DescribePCR unexpected response: {:?}", other)),
        }
    }
}

impl Drop for Nsm {
    fn drop(&mut self) {
        nsm_exit(self.fd);
    }
}
