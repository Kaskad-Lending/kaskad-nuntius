//! NSM-rooted CSPRNG adapter implementing `rand_core 0.6`'s
//! `RngCore + CryptoRng` (the version `rsa` 0.9 uses, re-exported as
//! `rsa::rand_core`). Any security-critical randomness inside the
//! enclave MUST go through this — `OsRng` routes through
//! `/dev/urandom`, which is seeded from host-supplied virtio-rng, so
//! the host can influence (and in theory predict) the bytes.
//!
//! Buffers responses from NSM `GetRandom` so a single bulk operation
//! like RSA-2048 keygen amortises the per-call vsock round-trip.
//!
//! Fail-closed: if `fill_bytes` cannot reach NSM it panics. The enclave
//! supervisor restarts the process — no fallback to weaker entropy.

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use eyre::{eyre, Result};
use rsa::rand_core::{CryptoRng, Error as RngError, RngCore};

/// NSM `GetRandom` typically returns up to 256 bytes per call.
const REFILL_BUF: usize = 256;

pub struct NsmRng {
    fd: i32,
    buf: [u8; REFILL_BUF],
    pos: usize,
    end: usize,
}

impl NsmRng {
    pub fn new() -> Result<Self> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(eyre!("nsm_init failed: {}", fd));
        }
        Ok(Self {
            fd,
            buf: [0u8; REFILL_BUF],
            pos: 0,
            end: 0,
        })
    }

    fn refill(&mut self) -> Result<()> {
        match nsm_process_request(self.fd, Request::GetRandom) {
            Response::GetRandom { random } => {
                if random.is_empty() {
                    return Err(eyre!("NSM GetRandom returned empty buffer"));
                }
                let n = random.len().min(self.buf.len());
                self.buf[..n].copy_from_slice(&random[..n]);
                self.pos = 0;
                self.end = n;
                Ok(())
            }
            Response::Error(e) => Err(eyre!("NSM GetRandom error: {:?}", e)),
            other => Err(eyre!("NSM GetRandom unexpected response: {:?}", other)),
        }
    }
}

impl Drop for NsmRng {
    fn drop(&mut self) {
        nsm_exit(self.fd);
    }
}

#[derive(Debug)]
struct NsmRngError(String);

impl std::fmt::Display for NsmRngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NsmRngError {}

impl RngCore for NsmRng {
    fn next_u32(&mut self) -> u32 {
        rsa::rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rsa::rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("NSM GetRandom failed inside fill_bytes — fail-closed abort")
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        let mut filled = 0;
        while filled < dest.len() {
            if self.pos >= self.end {
                self.refill()
                    .map_err(|e| RngError::new(NsmRngError(e.to_string())))?;
            }
            let take = (dest.len() - filled).min(self.end - self.pos);
            dest[filled..filled + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            filled += take;
        }
        Ok(())
    }
}

// Safety contract: every byte returned originates from the Nitro
// Security Module's hardware RNG — exactly the property `CryptoRng`
// marks (cryptographically suitable, host cannot influence).
impl CryptoRng for NsmRng {}
