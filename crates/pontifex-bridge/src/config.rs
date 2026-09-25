//! Bridge configuration: the Igra-side burn ledger and RH-side claim contract,
//! plus the endpoints for peer key fetch. Assembled from baked constants
//! (KskdExit, KSKD, chain id, Igra finality depth) and the host-supplied
//! `configure` message (KskdEntry, RH RPCs, peer lists).

use alloy_primitives::{hex, Address};
use eyre::{eyre, Result};
use keyex::chain::Finality;

/// Igra RPC is load-balanced; measured safe read depth is `latest - 769`.
pub const IGRA_FINALITY: Finality = Finality::HeadMinus(769);

/// Trust-critical identity baked into the image at EIF build time: which burn
/// ledger and token a claim reads, which chain it signs for, and which contract
/// it binds. Baked, not host-supplied, so a lying host cannot redirect the mint
/// amount or forge either half of the EIP-712 domain (chainId + verifyingContract).
#[derive(Clone, Copy, Debug)]
pub struct BakedIdentity {
    /// KskdExit on Igra — the burn ledger.
    pub exit: Address,
    /// KSKD token on Igra — a forbidden claim recipient.
    pub kskd: Address,
    /// KskdEntry on Robinhood — the claim's verifyingContract and boot registry.
    pub entry: Address,
    /// Robinhood chain id (46630 testnet / 4663 mainnet).
    pub chain_id: u64,
}

impl BakedIdentity {
    /// Resolve from the `PONTIFEX_EXIT` / `PONTIFEX_KSKD` / `PONTIFEX_ENTRY` /
    /// `PONTIFEX_CHAIN_ID` compile-time env the build pipeline sets. A bridge
    /// refuses to start if any is missing or malformed — never a default.
    pub fn from_baked() -> Result<Self> {
        Ok(Self {
            exit: baked_addr("PONTIFEX_EXIT", option_env!("PONTIFEX_EXIT"))?,
            kskd: baked_addr("PONTIFEX_KSKD", option_env!("PONTIFEX_KSKD"))?,
            entry: baked_addr_nonzero("PONTIFEX_ENTRY", option_env!("PONTIFEX_ENTRY"))?,
            chain_id: baked_u64("PONTIFEX_CHAIN_ID", option_env!("PONTIFEX_CHAIN_ID"))?,
        })
    }
}

fn baked_addr(name: &str, v: Option<&str>) -> Result<Address> {
    v.ok_or_else(|| eyre!("{name} not baked into image"))?
        .parse()
        .map_err(|_| eyre!("{name} is not a valid address"))
}

/// A baked address that must be a real contract: the zero address is refused. Used
/// for the verifyingContract, where a zero domain would silently accept forgeries.
fn baked_addr_nonzero(name: &str, v: Option<&str>) -> Result<Address> {
    let a = baked_addr(name, v)?;
    if a == Address::ZERO {
        return Err(eyre!("{name} must not be the zero address"));
    }
    Ok(a)
}

fn baked_u64(name: &str, v: Option<&str>) -> Result<u64> {
    v.ok_or_else(|| eyre!("{name} not baked into image"))?
        .parse()
        .map_err(|_| eyre!("{name} is not a valid u64"))
}

/// Baked, comma-separated Igra JSON-RPC endpoints (`PONTIFEX_IGRA_RPCS`). Baked so
/// a lying host cannot redirect the burn read; each MUST be https because enclave
/// egress tunnels through an untrusted host proxy — plain HTTP would let that
/// proxy forge the burned total. Fail-loud on missing / empty / non-https.
pub fn baked_igra_rpcs() -> Result<Vec<String>> {
    baked_rpcs("PONTIFEX_IGRA_RPCS", option_env!("PONTIFEX_IGRA_RPCS"))
}

fn baked_rpcs(name: &str, v: Option<&str>) -> Result<Vec<String>> {
    let raw = v.ok_or_else(|| eyre!("{name} not baked into image"))?;
    let list: Vec<String> =
        raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect();
    if list.is_empty() {
        return Err(eyre!("{name} baked but empty"));
    }
    for url in &list {
        if !url.starts_with("https://") {
            return Err(eyre!(
                "{name} endpoint must be https (got {url}) — the host tunnel can MITM plain HTTP"
            ));
        }
    }
    Ok(list)
}

/// Baked parent-oracle PCR0 allowlist (`PONTIFEX_ANCESTOR_PCRS`): comma-separated
/// 48-byte hex measurements the bridge accepts as the oracle that hands it its
/// child key (`FetchKind::BridgeFromParent`). Baked so a lying host cannot reroute
/// the fetch to a genuine but attacker-controlled enclave. Empty parses to an
/// empty set, but the bridge runner then refuses to boot (fail-closed); a
/// malformed entry is fatal.
pub fn baked_ancestor_pcrs() -> Result<Vec<[u8; 48]>> {
    parse_ancestor_pcrs(option_env!("PONTIFEX_ANCESTOR_PCRS"))
}

fn parse_ancestor_pcrs(v: Option<&str>) -> Result<Vec<[u8; 48]>> {
    let raw = match v {
        Some(s) => s,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let bytes = hex::decode(entry.strip_prefix("0x").unwrap_or(entry))
            .map_err(|_| eyre!("PONTIFEX_ANCESTOR_PCRS has a non-hex entry"))?;
        let arr: [u8; 48] =
            bytes.try_into().map_err(|_| eyre!("PONTIFEX_ANCESTOR_PCRS entry is not 48 bytes"))?;
        out.push(arr);
    }
    Ok(out)
}

/// One fully-resolved bridge configuration. `entry`/`chain_id` bind every claim
/// signature (EIP-712 verifyingContract + chainId).
#[derive(Clone, Debug)]
pub struct BridgeConfig {
    /// KskdExit on Igra — the burn ledger read by `burned(recipient)`.
    pub exit: Address,
    /// KSKD token on Igra — a forbidden claim recipient.
    pub kskd: Address,
    /// KskdEntry on Robinhood — the claim's verifyingContract.
    pub entry: Address,
    /// Robinhood chain id (46630 testnet / 4663 mainnet).
    pub chain_id: u64,
    /// Robinhood JSON-RPC endpoints (host-supplied, tried in order).
    pub rh_rpcs: Vec<String>,
    /// Oracle/parent enclaves that can hand a derived child key to the bridge.
    pub oracle_peers: Vec<String>,
}

impl BridgeConfig {
    /// Merge the baked identity with the host `configure` endpoints/peers. `entry`
    /// and `chain_id` come from the baked identity — never the wire — so the claim
    /// domain cannot be redirected by a lying host.
    pub fn from_parts(
        baked: &BakedIdentity,
        rh_rpcs: Vec<String>,
        oracle_peers: Vec<String>,
    ) -> Self {
        Self {
            exit: baked.exit,
            kskd: baked.kskd,
            entry: baked.entry,
            chain_id: baked.chain_id,
            rh_rpcs,
            oracle_peers,
        }
    }

    /// Recipients a claim must never mint to: the burn ledger and the KSKD token
    /// itself. `Address::ZERO` is refused separately by [`keyex::claim::check_claimable`].
    pub fn forbidden(&self) -> [Address; 2] {
        [self.exit, self.kskd]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_is_exit_and_kskd() {
        let cfg = BridgeConfig {
            exit: Address::from([0xEE; 20]),
            kskd: Address::from([0xDD; 20]),
            entry: Address::from([0x11; 20]),
            chain_id: 46630,
            rh_rpcs: vec![],
            oracle_peers: vec![],
        };
        assert_eq!(cfg.forbidden(), [Address::from([0xEE; 20]), Address::from([0xDD; 20])]);
    }

    #[test]
    fn igra_finality_is_head_minus_769() {
        assert_eq!(IGRA_FINALITY, Finality::HeadMinus(769));
    }

    #[test]
    fn from_parts_takes_identity_from_baked_and_only_endpoints_from_wire() {
        let baked = BakedIdentity {
            exit: Address::from([0xEE; 20]),
            kskd: Address::from([0xDD; 20]),
            entry: Address::from([0x11; 20]),
            chain_id: 46630,
        };
        let cfg = BridgeConfig::from_parts(
            &baked,
            vec!["https://rh".into()],
            vec!["o1".into()],
        );
        assert_eq!(cfg.exit, baked.exit);
        assert_eq!(cfg.kskd, baked.kskd);
        assert_eq!(cfg.chain_id, 46630);
        assert_eq!(cfg.entry, baked.entry); // verifyingContract is baked, not wire
        assert_eq!(cfg.rh_rpcs, vec!["https://rh".to_string()]);
        assert_eq!(cfg.forbidden(), [baked.exit, baked.kskd]);
    }

    #[test]
    fn baked_values_reject_missing_and_malformed() {
        assert!(baked_addr("X", None).is_err());
        assert!(baked_addr("X", Some("not-an-address")).is_err());
        assert!(baked_addr("X", Some("0x1111111111111111111111111111111111111111")).is_ok());
        assert!(baked_u64("Y", None).is_err());
        assert!(baked_u64("Y", Some("abc")).is_err());
        assert_eq!(baked_u64("Y", Some("46630")).unwrap(), 46630);
    }

    #[test]
    fn baked_entry_rejects_zero_and_missing() {
        assert!(baked_addr_nonzero("E", None).is_err());
        assert!(baked_addr_nonzero("E", Some(&format!("{:?}", Address::ZERO))).is_err());
        assert!(baked_addr_nonzero("E", Some("0x1111111111111111111111111111111111111111")).is_ok());
    }

    #[test]
    fn baked_rpcs_rejects_missing_empty_and_non_https() {
        assert!(baked_rpcs("X", None).is_err());
        assert!(baked_rpcs("X", Some("   ")).is_err()); // whitespace-only → empty after filter
        assert!(baked_rpcs("X", Some("http://igra")).is_err()); // plain http rejected
        let ok = baked_rpcs("X", Some("https://a , https://b")).unwrap();
        assert_eq!(ok, vec!["https://a".to_string(), "https://b".to_string()]);
    }

    #[test]
    fn baked_rpcs_rejects_a_mixed_http_entry() {
        // One bad endpoint fails the whole set — no silent partial trust.
        assert!(baked_rpcs("X", Some("https://ok,http://bad")).is_err());
    }

    #[test]
    fn ancestor_pcrs_absent_is_empty_not_error() {
        assert!(parse_ancestor_pcrs(None).unwrap().is_empty());
        assert!(parse_ancestor_pcrs(Some("")).unwrap().is_empty());
    }

    #[test]
    fn ancestor_pcrs_parses_hex_and_rejects_bad_length() {
        let one = format!("0x{}", "ab".repeat(48));
        assert_eq!(parse_ancestor_pcrs(Some(&one)).unwrap(), vec![[0xab; 48]]);
        let short = format!("0x{}", "ab".repeat(47));
        assert!(parse_ancestor_pcrs(Some(&short)).is_err());
        assert!(parse_ancestor_pcrs(Some("0xZZ")).is_err());
    }
}
