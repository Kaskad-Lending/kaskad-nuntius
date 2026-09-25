//! Shared boot state, guarded by a `std::sync::Mutex`. Every accessor takes a
//! snapshot under the lock and returns owned data — callers never hold the guard
//! across an `.await`. Holds the installed root key (the one secret in memory)
//! and zeroizes it on replacement and drop.

use alloy_primitives::Address;
use keyex::api::{BootState, KeySource};
use keyex::policy::VerifiedApproval;
use zeroize::Zeroize;

/// Live view of the keyex oracle's boot progress and installed key.
pub struct OracleKeyexState {
    boot_state: BootState,
    source: KeySource,
    signer_addr: Option<Address>,
    /// 65-byte SEC1 public point of the candidate-or-installed key.
    signer_pubkey: Option<Vec<u8>>,
    /// Installed root key bytes, for RA-TLS handover. `None` until install.
    root_key: Option<[u8; 32]>,
    /// Owner-approved handovers accepted on the control channel.
    approvals: Vec<VerifiedApproval>,
    rh_rpcs: Vec<String>,
    oracle_peers: Vec<String>,
}

impl OracleKeyexState {
    pub fn new() -> Self {
        Self {
            boot_state: BootState::Fetching,
            source: KeySource::Genesis,
            signer_addr: None,
            signer_pubkey: None,
            root_key: None,
            approvals: Vec::new(),
            rh_rpcs: Vec::new(),
            oracle_peers: Vec::new(),
        }
    }

    /// Publish the freshly minted genesis candidate so the control channel can
    /// attest it and the operator can register it on-chain.
    pub fn publish_candidate(&mut self, addr: Address, pubkey: Vec<u8>) {
        self.signer_addr = Some(addr);
        self.signer_pubkey = Some(pubkey);
        self.source = KeySource::Genesis;
        self.boot_state = BootState::WaitingRegistration;
    }

    /// Install the resolved key (genesis candidate or fetched peer key).
    pub fn install_key(
        &mut self,
        mut root_bytes: [u8; 32],
        addr: Address,
        pubkey: Vec<u8>,
        source: KeySource,
    ) {
        if let Some(old) = self.root_key.as_mut() {
            old.zeroize();
        }
        self.root_key = Some(root_bytes);
        root_bytes.zeroize();
        self.signer_addr = Some(addr);
        self.signer_pubkey = Some(pubkey);
        self.source = source;
        self.boot_state = BootState::Ready;
    }

    /// Record an owner-approved handover, de-duplicated.
    pub fn add_approval(&mut self, va: VerifiedApproval) {
        if !self.approvals.iter().any(|a| a == &va) {
            self.approvals.push(va);
        }
    }

    pub fn set_config(&mut self, rh_rpcs: Vec<String>, oracle_peers: Vec<String>) {
        self.rh_rpcs = rh_rpcs;
        self.oracle_peers = oracle_peers;
    }

    /// A copy of the installed root key, or `None` before install.
    pub fn root_key(&self) -> Option<[u8; 32]> {
        self.root_key
    }

    pub fn approvals(&self) -> Vec<VerifiedApproval> {
        self.approvals.clone()
    }

    pub fn signer_pubkey(&self) -> Option<Vec<u8>> {
        self.signer_pubkey.clone()
    }

    pub fn signer_addr(&self) -> Option<Address> {
        self.signer_addr
    }

    pub fn health(&self) -> (BootState, KeySource, Option<Address>) {
        (self.boot_state, self.source, self.signer_addr)
    }
}

impl Default for OracleKeyexState {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for OracleKeyexState {
    fn drop(&mut self) {
        if let Some(k) = self.root_key.as_mut() {
            k.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyex::approval::ApprovalMode;

    fn va(pcr0: u8) -> VerifiedApproval {
        VerifiedApproval {
            pcr0: [pcr0; 48],
            version: 1,
            mode: ApprovalMode::Carry,
            label: [0u8; 32],
        }
    }

    #[test]
    fn starts_fetching_with_no_key() {
        let s = OracleKeyexState::new();
        let (bs, _, addr) = s.health();
        assert_eq!(bs, BootState::Fetching);
        assert!(addr.is_none());
        assert!(s.root_key().is_none());
    }

    #[test]
    fn candidate_then_install_transitions() {
        let mut s = OracleKeyexState::new();
        s.publish_candidate(Address::from([0x11; 20]), vec![0x04; 65]);
        assert_eq!(s.health().0, BootState::WaitingRegistration);
        assert_eq!(s.signer_pubkey().unwrap().len(), 65);
        s.install_key(
            [7u8; 32],
            Address::from([0x11; 20]),
            vec![0x04; 65],
            KeySource::Genesis,
        );
        assert_eq!(s.health().0, BootState::Ready);
        assert_eq!(s.root_key().unwrap(), [7u8; 32]);
    }

    #[test]
    fn approvals_dedupe() {
        let mut s = OracleKeyexState::new();
        s.add_approval(va(1));
        s.add_approval(va(1));
        s.add_approval(va(2));
        assert_eq!(s.approvals().len(), 2);
    }
}
