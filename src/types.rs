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

    /// Minimum band, in bps of the median, below which a sample is never
    /// treated as an outlier. Widens the MAD gate for assets whose honest
    /// cross-venue spread is wide (equities gap on earnings); it can only
    /// keep samples, never drop extra ones.
    pub deviation_threshold_bps: u16,
    #[allow(dead_code)]
    pub heartbeat_seconds: u64,

    /// Map of source name (must equal `PriceSource::name()`) to that
    /// source's pair and the currency the pair is denominated in. A
    /// source whose name is absent from this map does NOT contribute to
    /// this asset.
    pub sources: HashMap<String, SourceMapping>,
}

/// Currency a venue pair is denominated in. `Usdt` samples are multiplied
/// by the USDT/USD rate before aggregation, so a depeg moves the feed
/// instead of silently mispricing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum Quote {
    #[serde(rename = "USD")]
    Usd,
    #[serde(rename = "USDT")]
    Usdt,
}

/// One venue's pair for an asset. `quote` is mandatory: a mapping added
/// without it fails to parse at boot rather than defaulting to a guess.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMapping {
    pub pair: String,
    pub quote: Quote,
}

/// Canonical symbol of the rate used to convert `Quote::Usdt` samples.
pub const USDT_USD_SYMBOL: &str = "USDT/USD";

impl AssetConfig {
    pub fn id(&self) -> B256 {
        use sha3::{Digest, Keccak256};
        B256::from_slice(&Keccak256::digest(self.symbol.as_bytes()))
    }

    /// Venue pair for `source`, or None when the source does not cover
    /// this asset.
    pub fn pair(&self, source: &str) -> Option<&String> {
        self.sources.get(source).map(|m| &m.pair)
    }

    /// Quote currency of `source`'s pair for this asset.
    pub fn quote(&self, source: &str) -> Option<Quote> {
        self.sources.get(source).map(|m| m.quote)
    }

    /// True when at least one mapping is USDT-denominated.
    pub fn has_usdt_quoted_source(&self) -> bool {
        self.sources.values().any(|m| m.quote == Quote::Usdt)
    }
}

/// Root schema for `config/assets.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct AssetsConfig {
    #[allow(dead_code)]
    pub version: u32,
    /// Explicit allowlist of hostnames the enclave may issue HTTPS
    /// requests to. Source modules each hardcode a URL — on startup we
    /// cross-check that every source's hostname appears here, so a
    /// future source addition that forgets to update the list aborts
    /// the enclave before it signs anything. The list travels with
    /// the rest of the config into PCR0.
    pub exchange_hostnames: Vec<String>,
    pub assets: Vec<AssetConfig>,
}

/// Raw JSON of the bundled asset configuration. Placed in a `const` so the
/// bytes become part of the compiled binary and therefore part of the EIF
/// measurement (PCR0).
pub const ASSETS_JSON: &str = include_str!("../config/assets.json");

/// Raw JSON of the bundled collector (exchange WS) configuration. Embedded
/// like `ASSETS_JSON` so the venue/pair set is measured in PCR0: which
/// exchanges feed the oracle is part of the attested boundary, not
/// host-supplied config. In enclave mode this is the ONLY source read
/// (see `CollectorManager::load_config_from_file`).
pub const EXCHANGES_JSON: &str = include_str!("../config/exchanges.json");

/// Parse the bundled config. Panics on malformed JSON — the enclave must
/// never boot with a broken asset table. Called once at startup from main.
pub fn load_assets() -> Result<AssetsConfig> {
    let parsed: AssetsConfig = serde_json::from_str(ASSETS_JSON)?;
    if parsed.assets.is_empty() {
        eyre::bail!("assets.json has zero assets — refusing to start");
    }
    if parsed.exchange_hostnames.is_empty() {
        eyre::bail!("assets.json has no exchange_hostnames — refusing to start");
    }
    for h in &parsed.exchange_hostnames {
        if h.is_empty() || h.contains('/') || h.contains(' ') {
            eyre::bail!("assets.json: invalid exchange_hostname {:?}", h);
        }
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
        for (name, m) in &a.sources {
            if m.pair.is_empty() {
                eyre::bail!("asset {}: source {} has an empty pair", a.symbol, name);
            }
        }
    }
    // USDT-denominated samples are converted with the USDT/USD feed, so
    // that feed must exist and must itself be free of USDT-quoted
    // sources — otherwise the conversion would depend on its own output.
    let usdt = parsed.assets.iter().find(|a| a.symbol == USDT_USD_SYMBOL);
    let needs_rate = parsed.assets.iter().any(|a| a.has_usdt_quoted_source());
    match usdt {
        None if needs_rate => {
            eyre::bail!("assets.json has USDT-quoted sources but no {USDT_USD_SYMBOL} asset")
        }
        Some(a) if a.has_usdt_quoted_source() => {
            eyre::bail!("{USDT_USD_SYMBOL} must be quoted in USD only — it IS the conversion rate")
        }
        _ => {}
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

    /// Every USDT-quoted sample is multiplied by the USDT/USD rate, so
    /// that asset must exist and must itself be USD-only.
    #[test]
    fn usdt_usd_is_present_and_usd_only() {
        let cfg = load_assets().expect("assets.json must parse");
        let usdt = cfg
            .assets
            .iter()
            .find(|a| a.symbol == USDT_USD_SYMBOL)
            .expect("USDT/USD must be configured — it is the conversion rate");
        assert!(
            !usdt.has_usdt_quoted_source(),
            "USDT/USD must be quoted in USD only"
        );
        assert!(
            cfg.assets.iter().any(|a| a.has_usdt_quoted_source()),
            "no USDT-quoted source left — the conversion path is dead code"
        );
    }

    /// Reject a quote currency the aggregator does not know how to
    /// convert, rather than silently treating it as USD.
    #[test]
    fn unknown_quote_currency_is_rejected() {
        let err = serde_json::from_str::<SourceMapping>(r#"{"pair":"ETHEUR","quote":"EUR"}"#)
            .expect_err("EUR must not parse");
        assert!(err.to_string().contains("EUR"), "{err}");
    }

    /// A source entry must carry both fields; the old bare-string form
    /// cannot silently mean "USD".
    #[test]
    fn bare_string_source_is_rejected() {
        serde_json::from_str::<SourceMapping>(r#""ETHUSDT""#)
            .expect_err("the v1 bare-pair form must not parse");
        serde_json::from_str::<SourceMapping>(r#"{"pair":"ETHUSDT"}"#)
            .expect_err("a mapping without a quote must not parse");
    }

    /// The reserves the Kaskad markets list must all have a feed. Losing
    /// one here means an unpriceable reserve after an enclave rebuild.
    #[test]
    fn every_listed_reserve_symbol_has_a_feed() {
        const REQUIRED: &[&str] = &[
            "ETH/USD",
            "BTC/USD",
            "KAS/USD",
            "USDC/USD",
            "USDT/USD",
            "IGRA/USD",
            "TAO/USD",
            "TIBBIR/USD",
            "USDG/USD",
            "PONS/USD",
            "NVDA/USD",
            "TSLA/USD",
        ];
        let cfg = load_assets().expect("assets.json must parse");
        for want in REQUIRED {
            assert!(
                cfg.assets.iter().any(|a| a.symbol == *want),
                "{want} has no price feed"
            );
        }
        assert_eq!(
            cfg.assets.len(),
            REQUIRED.len(),
            "an asset was added without extending this list"
        );
    }

    /// Asset ids are keccak256 of the symbol and index on-chain storage; a
    /// collision would overwrite another feed.
    #[test]
    fn asset_ids_are_unique() {
        let cfg = load_assets().expect("assets.json must parse");
        let mut ids: Vec<_> = cfg.assets.iter().map(|a| a.id()).collect();
        let total = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate asset id");
    }

    /// Drift-guard: each source module hardcodes its HTTPS URL. The
    /// HttpClient enforces an allowlist against
    /// `config.exchange_hostnames`. If the two go out of sync the
    /// enclave either refuses to fetch from a legitimate source OR
    /// lets a newly-added hostname through without being measured in
    /// PCR0. This test pins the expected (source_name, hostname)
    /// mapping — adding a new exchange requires editing THIS list
    /// AND the config, forcing visible review.
    #[test]
    fn source_hostnames_match_config_allowlist() {
        const EXPECTED: &[(&str, &str)] = &[
            ("binance", "api.binance.com"),
            ("okx", "www.okx.com"),
            ("bybit", "api.bybit.com"),
            ("coinbase", "api.coinbase.com"),
            ("coingecko", "api.coingecko.com"),
            ("mexc", "api.mexc.com"),
            ("kucoin", "api.kucoin.com"),
            ("gateio", "api.gateio.ws"),
            ("kraken", "api.kraken.com"),
            ("bitget", "api.bitget.com"),
            ("bitfinex", "api-pub.bitfinex.com"),
            ("bitstamp", "www.bitstamp.net"),
            ("crypto_com", "api.crypto.com"),
            ("htx", "api.huobi.pro"),
            ("igralabs", "apis.igralabs.com"),
        ];

        let cfg = load_assets().expect("assets.json must parse");
        let declared: std::collections::HashSet<&str> =
            cfg.exchange_hostnames.iter().map(String::as_str).collect();

        for (name, host) in EXPECTED {
            assert!(
                declared.contains(host),
                "source {} hostname {} missing from exchange_hostnames",
                name,
                host
            );
        }
        assert_eq!(
            declared.len(),
            EXPECTED.len(),
            "exchange_hostnames has {} entries but EXPECTED has {} — drift",
            declared.len(),
            EXPECTED.len()
        );
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
