//! Running bridge state: the installed claim key, this image's identity, the
//! resolved config, and a per-recipient high-water mark of the burned totals
//! already signed this process lifetime. The mark only ratchets up — a guard
//! against an RPC that serves a stale-lower burned value mid-session (on-chain
//! `burned` is itself monotonic, and the enclave is stateless across restarts).

use std::collections::HashMap;

use alloy_primitives::{Address, U256};
use k256::ecdsa::SigningKey;
use keyex::api::BootState;

use crate::config::BridgeConfig;

/// Mutable state of a running bridge enclave.
pub struct BridgeState {
    boot: BootState,
    key: Option<SigningKey>,
    signer: Option<Address>,
    pcr0: [u8; 48],
    version: u64,
    config: Option<BridgeConfig>,
    last_signed: HashMap<Address, U256>,
}

impl BridgeState {
    /// A pre-boot state with the baked identity but no key or config yet.
    pub fn new(pcr0: [u8; 48], version: u64) -> Self {
        Self {
            boot: BootState::Fetching,
            key: None,
            signer: None,
            pcr0,
            version,
            config: None,
            last_signed: HashMap::new(),
        }
    }

    /// Install the resolved claim key; boot is complete. Once-only: a second call
    /// is ignored so a re-entered boot path can never swap a live signer.
    pub fn install_key(&mut self, key: SigningKey, signer: Address) {
        if self.key.is_some() {
            tracing::warn!("install_key called with a key already installed; ignoring");
            return;
        }
        self.key = Some(key);
        self.signer = Some(signer);
        self.boot = BootState::Ready;
    }

    /// Store the host-supplied configuration.
    pub fn set_config(&mut self, config: BridgeConfig) {
        self.config = Some(config);
    }

    pub fn boot(&self) -> BootState {
        self.boot
    }
    pub fn signer(&self) -> Option<Address> {
        self.signer
    }
    pub fn key(&self) -> Option<&SigningKey> {
        self.key.as_ref()
    }
    pub fn pcr0(&self) -> &[u8; 48] {
        &self.pcr0
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn config(&self) -> Option<&BridgeConfig> {
        self.config.as_ref()
    }

    /// The installed signer's uncompressed SEC1 public key (`0x04 ‖ X ‖ Y`, 65
    /// bytes), for binding into an attestation document. `None` before boot.
    pub fn signer_pubkey(&self) -> Option<Vec<u8>> {
        self.key.as_ref().map(|k| k.verifying_key().to_encoded_point(false).as_bytes().to_vec())
    }

    /// The highest burned total already signed for `recipient` this session.
    pub fn high_water(&self, recipient: Address) -> U256 {
        self.last_signed.get(&recipient).copied().unwrap_or(U256::ZERO)
    }

    /// Record a freshly-signed burned total, keeping the per-recipient maximum.
    pub fn record_signed(&mut self, recipient: Address, cumulative_burned: U256) {
        let e = self.last_signed.entry(recipient).or_insert(U256::ZERO);
        if cumulative_burned > *e {
            *e = cumulative_burned;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> BridgeState {
        BridgeState::new([0u8; 48], 1)
    }

    #[test]
    fn high_water_defaults_to_zero() {
        assert_eq!(state().high_water(Address::from([0x22; 20])), U256::ZERO);
    }

    #[test]
    fn record_signed_only_ratchets_up() {
        let mut st = state();
        let r = Address::from([0x22; 20]);
        st.record_signed(r, U256::from(100));
        assert_eq!(st.high_water(r), U256::from(100));
        // A lower value never lowers the mark.
        st.record_signed(r, U256::from(50));
        assert_eq!(st.high_water(r), U256::from(100));
        // A higher value advances it.
        st.record_signed(r, U256::from(150));
        assert_eq!(st.high_water(r), U256::from(150));
    }

    #[test]
    fn marks_are_per_recipient() {
        let mut st = state();
        let a = Address::from([0x1; 20]);
        let b = Address::from([0x2; 20]);
        st.record_signed(a, U256::from(10));
        assert_eq!(st.high_water(a), U256::from(10));
        assert_eq!(st.high_water(b), U256::ZERO);
    }

    #[test]
    fn install_key_sets_ready_and_signer() {
        let mut st = state();
        assert_eq!(st.boot(), BootState::Fetching);
        assert!(st.signer().is_none());
        let sk = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let addr = Address::from([0x33; 20]);
        st.install_key(sk, addr);
        assert_eq!(st.boot(), BootState::Ready);
        assert_eq!(st.signer(), Some(addr));
        assert!(st.key().is_some());
    }

    #[test]
    fn install_key_is_ignored_when_a_key_is_already_installed() {
        let mut st = state();
        let first = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let first_pk = first.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        st.install_key(first, Address::from([0x33; 20]));
        // A second install must not swap the signer or the key.
        st.install_key(SigningKey::from_bytes((&[8u8; 32]).into()).unwrap(), Address::from([0x44; 20]));
        assert_eq!(st.signer(), Some(Address::from([0x33; 20])));
        assert_eq!(st.signer_pubkey().unwrap(), first_pk);
    }
}
