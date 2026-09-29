//! NSM-rooted CSPRNG implementing `rand_core` 0.6 `RngCore + CryptoRng`.
//! Every byte originates in the Nitro Security Module's `GetRandom`; the
//! guest kernel's `/dev/urandom` (and thus `OsRng` / `thread_rng`) is
//! seeded from host-supplied virtio-rng and is therefore host-influenced.
//! Security-critical randomness inside the enclave MUST route through this.
//!
//! Fail-closed: `fill_bytes` panics if NSM is unreachable; the enclave
//! supervisor restarts the process rather than degrading to weaker entropy.

use crate::nsm::Nsm;
use eyre::Result;
use rand_core::{CryptoRng, Error as RngError, RngCore};
use zeroize::Zeroize;

/// NSM `GetRandom` typically returns up to 256 bytes per call; buffer a
/// slot so a bulk consumer (e.g. keygen) amortises the round-trip.
const REFILL_BUF: usize = 256;

pub struct NsmRng {
    nsm: Nsm,
    buf: [u8; REFILL_BUF],
    pos: usize,
    end: usize,
}

impl NsmRng {
    pub fn new() -> Result<Self> {
        Ok(Self {
            nsm: Nsm::new()?,
            buf: [0u8; REFILL_BUF],
            pos: 0,
            end: 0,
        })
    }

    fn refill(&mut self) -> Result<()> {
        let mut slot = [0u8; REFILL_BUF];
        let res = self.nsm.get_random(&mut slot);
        if res.is_ok() {
            self.buf = slot;
            self.pos = 0;
            self.end = REFILL_BUF;
        }
        slot.zeroize(); // scrub the transient copy on both success and failure
        res
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
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
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

// Every byte is NSM hardware entropy the host cannot influence — exactly
// the property `CryptoRng` marks.
impl CryptoRng for NsmRng {}

// Scrub buffered entropy on drop so it never lingers in freed memory; the
// per-call refill slot is scrubbed in `refill`.
impl Drop for NsmRng {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}
