//! One module per venue — same split as the oracle's `collectors/impls`.
//! Each `run` performs ONE session (connect → subscribe → stream trades
//! into `tx`); the caller reconnects with backoff when it errors.
//! All 10 protocols live-verified 2026-07-19 (see each module header).

use crate::types::{EventTx, VenueCfg};
use eyre::{eyre, Result};

pub mod binance;
pub mod bitmart;
pub mod bitrue;
pub mod coinw;
pub mod gate;
pub mod kucoin;
pub mod lbank;
pub mod mexc;
pub mod whitebit;
pub mod xt;

pub fn supported(name: &str) -> bool {
    matches!(
        name,
        "binance"
            | "bitmart"
            | "bitrue"
            | "coinw"
            | "gate"
            | "kucoin"
            | "lbank"
            | "mexc"
            | "whitebit"
            | "xt"
    )
}

pub async fn run_session(cfg: &VenueCfg, tx: &EventTx) -> Result<()> {
    match cfg.name.as_str() {
        "binance" => binance::run(cfg, tx).await,
        "bitmart" => bitmart::run(cfg, tx).await,
        "bitrue" => bitrue::run(cfg, tx).await,
        "coinw" => coinw::run(cfg, tx).await,
        "gate" => gate::run(cfg, tx).await,
        "kucoin" => kucoin::run(cfg, tx).await,
        "lbank" => lbank::run(cfg, tx).await,
        "mexc" => mexc::run(cfg, tx).await,
        "whitebit" => whitebit::run(cfg, tx).await,
        "xt" => xt::run(cfg, tx).await,
        other => Err(eyre!("unsupported venue: {other}")),
    }
}
