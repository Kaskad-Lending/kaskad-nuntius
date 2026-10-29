//! Shared boot state, guarded by a `std::sync::Mutex`. Every accessor takes a
//! snapshot under the lock and returns owned data — callers never hold the guard
//! across an `.await`. Holds the installed root key (the one secret in memory)
//! and zeroizes it on replacement and drop.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use alloy_primitives::Address;
use keyex::api::{BootState, KeySource};
use keyex::policy::VerifiedApproval;
use zeroize::Zeroize;

const MAX_BOOT_PEERS: usize = 16;
const MAX_PEER_ENDPOINT_LEN: usize = 320;
const HANDOVER_PORT: u16 = 8443;

/// Normalize a CONNECT authority without accepting URLs or request delimiters.
fn normalize_peer(endpoint: &str) -> Option<String> {
    if endpoint.is_empty()
        || endpoint.len() > MAX_PEER_ENDPOINT_LEN
        || !endpoint.is_ascii()
        || endpoint
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return None;
    }
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return (addr.port() != 0).then(|| addr.to_string());
    }
    if let Ok(ip) = endpoint.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, HANDOVER_PORT).to_string());
    }
    if let Some(ip) = endpoint.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let ip = ip.parse::<Ipv6Addr>().ok()?;
        return Some(SocketAddr::new(ip.into(), HANDOVER_PORT).to_string());
    }
    let (host, port) = match endpoint.split_once(':') {
        Some((host, port)) => {
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            (host, port.parse::<u16>().ok()?)
        }
        None => (endpoint, HANDOVER_PORT),
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if port == 0
        || host.len() > 253
        || host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return None;
    }
    Some(format!("{}:{port}", host.to_ascii_lowercase()))
}

fn bounded_peers<'a>(peers: impl IntoIterator<Item = &'a String>) -> Vec<String> {
    let mut out = Vec::new();
    for peer in peers {
        if let Some(peer) = normalize_peer(peer) {
            if !out.contains(&peer) {
                out.push(peer);
                if out.len() == MAX_BOOT_PEERS {
                    break;
                }
            }
        }
    }
    out
}

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

    pub fn set_peer_hints(&mut self, oracle_peers: Vec<String>) {
        self.oracle_peers = bounded_peers(&oracle_peers);
    }

    /// Baked peers retain priority and cannot be evicted by host hints.
    pub fn peer_snapshot(&self, baked_peers: &[String]) -> Vec<String> {
        bounded_peers(baked_peers.iter().chain(&self.oracle_peers))
    }

    /// A copy of the installed root key, or `None` before install.
    pub fn root_key(&self) -> Option<[u8; 32]> {
        self.root_key
    }

    /// Presence test that never copies the key — lets callers refuse early.
    pub fn has_root_key(&self) -> bool {
        self.root_key.is_some()
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
            role: keyex::policy::EnclaveRole::Oracle,
            expiry: 1_900_000_000,
            nonce: [0u8; 32],
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

    #[test]
    fn peer_authorities_are_normalized() {
        for (raw, expected) in [
            ("192.0.2.1", "192.0.2.1:8443"),
            ("192.0.2.1:443", "192.0.2.1:443"),
            ("Peer.Example", "peer.example:8443"),
            ("peer.example.:8443", "peer.example:8443"),
            ("peer-1:9443", "peer-1:9443"),
            ("2001:db8::1", "[2001:db8::1]:8443"),
            ("[2001:db8::1]", "[2001:db8::1]:8443"),
            ("[2001:db8::1]:443", "[2001:db8::1]:443"),
        ] {
            assert_eq!(normalize_peer(raw).as_deref(), Some(expected));
        }
    }

    #[test]
    fn invalid_peer_authorities_are_rejected() {
        for raw in [
            "",
            ":8443",
            "https://peer.example:8443",
            "peer.example/path",
            "peer.example?query",
            "peer.example#fragment",
            "user@peer.example",
            "peer.example:0",
            "peer.example:65536",
            "peer.example:+443",
            "peer.example:port",
            "peer.example:",
            "192.0.2.1:0",
            "999.1.2.3",
            "[2001:db8::1]:0",
            "[2001:db8::1",
            "peer\r\nHost: attacker",
            "peer\0.example",
            " peer.example ",
            "peer name",
            "peer\\example",
            "peer..example",
            "-peer.example",
            "peer-.example",
            "péér.example",
        ] {
            assert!(normalize_peer(raw).is_none(), "accepted invalid authority");
        }
        assert!(normalize_peer(&"a".repeat(MAX_PEER_ENDPOINT_LEN + 1)).is_none());
        assert!(normalize_peer(&format!("{}.example", "a".repeat(64))).is_none());
    }

    #[test]
    fn peer_hints_filter_before_capping_and_keep_baked_priority() {
        let mut s = OracleKeyexState::new();
        let mut hints = vec!["bad\r\npeer".to_owned(); MAX_BOOT_PEERS * 2];
        for i in 0..MAX_BOOT_PEERS + 2 {
            hints.push(format!("PEER-{i}.EXAMPLE"));
            hints.push(format!("peer-{i}.example:8443"));
        }
        s.set_peer_hints(hints);
        let snapshot = s.peer_snapshot(&[]);
        assert_eq!(snapshot.len(), MAX_BOOT_PEERS);
        assert_eq!(snapshot[0], "peer-0.example:8443");
        assert_eq!(snapshot.last().unwrap(), "peer-15.example:8443");

        let baked = vec!["baked.example".into(), "peer-0.example".into()];
        let merged = s.peer_snapshot(&baked);
        assert_eq!(merged.len(), MAX_BOOT_PEERS);
        assert_eq!(merged[0], "baked.example:8443");
        assert_eq!(merged[1], "peer-0.example:8443");
        assert_eq!(merged.iter().filter(|p| *p == &merged[1]).count(), 1);
    }

    #[test]
    fn snapshots_refresh_without_mutating_baked_peers() {
        let baked = vec!["baked.example".into()];
        let mut s = OracleKeyexState::new();
        assert_eq!(s.peer_snapshot(&baked), ["baked.example:8443"]);
        s.set_peer_hints(vec!["old.example".into()]);
        let old = s.peer_snapshot(&baked);
        s.set_peer_hints(vec!["new.example".into()]);
        assert_eq!(old, ["baked.example:8443", "old.example:8443"]);
        assert_eq!(
            s.peer_snapshot(&baked),
            ["baked.example:8443", "new.example:8443"]
        );
        s.set_peer_hints(Vec::new());
        assert_eq!(s.peer_snapshot(&baked), ["baked.example:8443"]);
    }
}
