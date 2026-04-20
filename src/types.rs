use alloy_primitives::B256;
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Per-asset configuration loaded from the bundled `config/assets.json`.
///
/// Every field is a policy knob that used to live as a hardcoded match arm
/// in `types.rs`. Because the file is baked into the enclave EIF via
/// `include_str!`, any change to its contents changes PCR0 — on-chain
/// consumers must re-register the enclave. This is what gives the JSON
/// measurement guarantees equivalent to compiled-in code.
#[derive(Debug, Clone, Deserialize)]
pub struct AssetConfig {
    /// Canonical symbol, e.g. "ETH/USD". Used for log output AND to derive
    /// the on-chain asset ID via `keccak256(symbol)` — downstream Solidity
    /// contracts MUST use the same string to compute the same ID.
    pub symbol: String,

    /// Minimum number of sources required after sanitisation + outlier
    /// rejection before the cycle will sign (per-asset Data Quorum).
    pub min_sources: usize,

    /// Deviation threshold in basis points before triggering a push.
    pub deviation_threshold_bps: u16,

    /// Maximum time between signed updates.
    pub heartbeat_seconds: u64,

    /// Map of source name (must equal `PriceSource::name()`) to the
    /// source-specific symbol/pair identifier. A source whose name is
    /// absent from this map does NOT contribute to this asset.
    pub sources: HashMap<String, String>,
}

impl AssetConfig {
    pub fn id(&self) -> B256 {
        use sha3::{Digest, Keccak256};
        B256::from_slice(&Keccak256::digest(self.symbol.as_bytes()))
    }
}

/// Root schema for `config/assets.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct AssetsConfig {
    #[allow(dead_code)]
    pub version: u32,
    pub assets: Vec<AssetConfig>,
}

/// Raw JSON of the bundled asset configuration. Placed in a `const` so the
/// bytes become part of the compiled binary and therefore part of the EIF
/// measurement (PCR0).
pub const ASSETS_JSON: &str = include_str!("../config/assets.json");

/// Parse the bundled config. Panics on malformed JSON — the enclave must
/// never boot with a broken asset table. Called once at startup from main.
pub fn load_assets() -> Result<AssetsConfig> {
    let parsed: AssetsConfig = serde_json::from_str(ASSETS_JSON)?;
    if parsed.assets.is_empty() {
        eyre::bail!("assets.json has zero assets — refusing to start");
    }
    // Every asset must have a realistic quorum and at least as many source
    // mappings. Enforce at load time so a misconfig cannot silently sign
    // from a quorum of zero.
    for a in &parsed.assets {
        if a.min_sources == 0 {
            eyre::bail!("asset {}: min_sources == 0", a.symbol);
        }
        if a.sources.len() < a.min_sources {
            eyre::bail!(
                "asset {}: {} source mappings < min_sources {}",
                a.symbol,
                a.sources.len(),
                a.min_sources
            );
        }
        if a.deviation_threshold_bps > 10_000 {
            eyre::bail!(
                "asset {}: deviation_threshold_bps {} > 100 %",
                a.symbol,
                a.deviation_threshold_bps
            );
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse the bundled `config/assets.json` and assert every structural
    /// invariant. If this fails, a newly introduced JSON typo was about
    /// to ship — fix the JSON, don't loosen the test.
    #[test]
    fn embedded_assets_json_parses_and_validates() {
        let cfg = load_assets().expect("assets.json must parse");
        assert!(!cfg.assets.is_empty());
        for a in &cfg.assets {
            assert!(!a.symbol.is_empty(), "asset symbol empty");
            assert!(a.min_sources >= 1, "{} min_sources < 1", a.symbol);
            assert!(
                a.sources.len() >= a.min_sources,
                "{} has fewer source mappings than min_sources",
                a.symbol
            );
            assert!(
                a.heartbeat_seconds > 0,
                "{} heartbeat_seconds == 0",
                a.symbol
            );
        }
    }

    #[test]
    fn asset_id_matches_keccak_of_symbol() {
        // Stable on-chain contract: assetId = keccak256("ETH/USD") etc.
        let cfg = load_assets().unwrap();
        for a in &cfg.assets {
            let expected = {
                use sha3::{Digest, Keccak256};
                B256::from_slice(&Keccak256::digest(a.symbol.as_bytes()))
            };
            assert_eq!(a.id(), expected);
        }
    }
}

/// A single price observation from a data source.
///
/// `server_time` is the source-reported unix timestamp. It is the ONLY
/// clock the enclave ever trusts for signing — `SystemTime::now()` is
/// host-controlled and never used in the signing pipeline (audit C-3/H-9).
#[derive(Debug, Clone)]
pub struct PricePoint {
    pub price: f64,
    pub volume: f64,
    pub source: String,
    pub server_time: u64,
}

/// Cached aggregated price — unsigned, stored in PriceStore.
///
/// `signed_timestamp` is the median of per-source server times from the
/// aggregation cycle. Every signature emitted by the price server uses
/// this value verbatim, never a host-clock read.
#[derive(Debug, Clone)]
pub struct CachedPrice {
    pub asset_symbol: String,
    pub asset_id: B256,
    pub price_fixed: alloy_primitives::U256,
    pub price_human: f64,
    pub num_sources: u8,
    pub sources_hash: B256,
    pub signed_timestamp: u64,
}

/// A signed price update ready for external consumption (pull API).
#[derive(Debug, Clone, Serialize)]
pub struct SignedPriceUpdate {
    pub asset_id: String,
    pub asset_symbol: String,
    pub price: String,
    pub price_human: String,
    pub timestamp: u64,
    pub num_sources: u8,
    pub sources_hash: String,
    pub signature: String,
    pub signer: String,
}
