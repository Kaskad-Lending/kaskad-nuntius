//! Trust-critical oracle config, baked at EIF build time (fail-loud), never
//! host-supplied: which RH KaskadPriceOracle registry the key registers into,
//! which owners may approve a handover, the approval threshold, the chain the
//! approval domain binds, this image's version, its optional ancestor PCRs and
//! sibling oracle peers. No secret is baked — only public addresses/RPCs.

use alloy_primitives::{hex, Address};
use eyre::{eyre, Result};

/// Fully-resolved oracle configuration, all baked.
#[derive(Clone, Debug)]
pub struct BakedOracleConfig {
    /// RH KaskadPriceOracle — the signer registry this enclave registers into and
    /// reads `isValidSigner`/`signerCount` from.
    pub registry: Address,
    /// Robinhood JSON-RPC endpoints (https only), tried in order.
    pub rh_rpcs: Vec<String>,
    /// Owners whose EIP-712 signatures approve a key handover to a newer image.
    pub owners: Vec<Address>,
    /// Approval quorum: distinct owners required.
    pub threshold: usize,
    /// Robinhood chain id (46630 testnet / 4663 mainnet) — the approval domain's chainId.
    pub chain_id: u64,
    /// This image's version, bound into every approval/handover.
    pub version: u64,
    /// Ancestor PCR0 allowlist for a root→root fetch (empty for a first image).
    pub ancestors: Vec<[u8; 48]>,
    /// Sibling oracle enclaves to sweep for an already-registered root (empty for genesis).
    pub peers: Vec<String>,
}

impl BakedOracleConfig {
    /// Resolve from the `KEYEX_ORACLE_*` compile-time env the build pipeline sets.
    /// The enclave refuses to boot if any required value is missing or malformed.
    pub fn from_baked() -> Result<Self> {
        let owners = baked_addr_list("KEYEX_ORACLE_OWNERS", option_env!("KEYEX_ORACLE_OWNERS"))?;
        let threshold =
            baked_u64("KEYEX_ORACLE_THRESHOLD", option_env!("KEYEX_ORACLE_THRESHOLD"))? as usize;
        if threshold == 0 {
            return Err(eyre!("KEYEX_ORACLE_THRESHOLD must be >= 1"));
        }
        if threshold > owners.len() {
            return Err(eyre!(
                "KEYEX_ORACLE_THRESHOLD ({threshold}) exceeds owner count ({})",
                owners.len()
            ));
        }
        Ok(Self {
            registry: baked_addr_nonzero(
                "KEYEX_ORACLE_REGISTRY",
                option_env!("KEYEX_ORACLE_REGISTRY"),
            )?,
            rh_rpcs: baked_rpcs("KEYEX_ORACLE_RH_RPCS", option_env!("KEYEX_ORACLE_RH_RPCS"))?,
            owners,
            threshold,
            chain_id: baked_u64("KEYEX_ORACLE_CHAIN_ID", option_env!("KEYEX_ORACLE_CHAIN_ID"))?,
            version: baked_u64("KEYEX_ORACLE_VERSION", option_env!("KEYEX_ORACLE_VERSION"))?,
            ancestors: parse_ancestor_pcrs(option_env!("KEYEX_ORACLE_ANCESTORS"))?,
            peers: parse_endpoints(option_env!("KEYEX_ORACLE_PEERS")),
        })
    }
}

fn baked_addr(name: &str, v: Option<&str>) -> Result<Address> {
    v.ok_or_else(|| eyre!("{name} not baked into image"))?
        .parse()
        .map_err(|_| eyre!("{name} is not a valid address"))
}

/// A baked address that must be a real contract: the zero address is refused.
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

/// Comma-separated owner addresses; at least one, each well-formed and non-zero.
fn baked_addr_list(name: &str, v: Option<&str>) -> Result<Vec<Address>> {
    let raw = v.ok_or_else(|| eyre!("{name} not baked into image"))?;
    let mut out = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let a: Address =
            entry.parse().map_err(|_| eyre!("{name} has a non-address entry ({entry})"))?;
        if a == Address::ZERO {
            return Err(eyre!("{name} must not contain the zero address"));
        }
        out.push(a);
    }
    if out.is_empty() {
        return Err(eyre!("{name} baked but empty"));
    }
    Ok(out)
}

/// Comma-separated https JSON-RPC endpoints; each must be https because enclave
/// egress tunnels through an untrusted host proxy — plain HTTP would let that
/// proxy forge the registry read. Fail-loud on missing / empty / non-https.
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

/// Comma-separated peer endpoints; absent or empty is legal (a genesis launch has
/// no siblings). Peer endpoints are RA-TLS gated downstream, so they are not
/// https-checked here.
fn parse_endpoints(v: Option<&str>) -> Vec<String> {
    match v {
        Some(s) => s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect(),
        None => Vec::new(),
    }
}

/// Comma-separated 48-byte hex ancestor measurements. Empty is legal; a malformed
/// entry is fatal.
fn parse_ancestor_pcrs(v: Option<&str>) -> Result<Vec<[u8; 48]>> {
    let raw = match v {
        Some(s) => s,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let bytes = hex::decode(entry.strip_prefix("0x").unwrap_or(entry))
            .map_err(|_| eyre!("KEYEX_ORACLE_ANCESTORS has a non-hex entry"))?;
        let arr: [u8; 48] =
            bytes.try_into().map_err(|_| eyre!("KEYEX_ORACLE_ANCESTORS entry is not 48 bytes"))?;
        out.push(arr);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_rejects_missing_and_malformed() {
        assert!(baked_addr("X", None).is_err());
        assert!(baked_addr("X", Some("nope")).is_err());
        assert!(baked_addr("X", Some("0x1111111111111111111111111111111111111111")).is_ok());
    }

    #[test]
    fn registry_rejects_zero() {
        assert!(baked_addr_nonzero("R", Some(&format!("{:?}", Address::ZERO))).is_err());
        assert!(baked_addr_nonzero("R", Some("0x1111111111111111111111111111111111111111")).is_ok());
    }

    #[test]
    fn owner_list_parses_and_rejects_empty_and_zero() {
        assert!(baked_addr_list("O", None).is_err());
        assert!(baked_addr_list("O", Some("  ")).is_err());
        assert!(baked_addr_list("O", Some(&format!("{:?}", Address::ZERO))).is_err());
        let two = baked_addr_list(
            "O",
            Some("0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222"),
        )
        .unwrap();
        assert_eq!(two.len(), 2);
    }

    #[test]
    fn rpcs_require_https() {
        assert!(baked_rpcs("X", None).is_err());
        assert!(baked_rpcs("X", Some("   ")).is_err());
        assert!(baked_rpcs("X", Some("http://rh")).is_err());
        assert!(baked_rpcs("X", Some("https://a,http://b")).is_err());
        assert_eq!(
            baked_rpcs("X", Some("https://a , https://b")).unwrap(),
            vec!["https://a".to_string(), "https://b".to_string()]
        );
    }

    #[test]
    fn peers_absent_is_empty() {
        assert!(parse_endpoints(None).is_empty());
        assert!(parse_endpoints(Some("")).is_empty());
        assert_eq!(parse_endpoints(Some("a, b")), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn ancestors_parse_and_reject_bad_length() {
        assert!(parse_ancestor_pcrs(None).unwrap().is_empty());
        let one = format!("0x{}", "ab".repeat(48));
        assert_eq!(parse_ancestor_pcrs(Some(&one)).unwrap(), vec![[0xab; 48]]);
        assert!(parse_ancestor_pcrs(Some(&format!("0x{}", "ab".repeat(47)))).is_err());
    }
}
