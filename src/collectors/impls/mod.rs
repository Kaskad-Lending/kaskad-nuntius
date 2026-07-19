//! Per-exchange collector implementations.

pub mod ascendex;
pub mod biconomy;
pub mod binance;
pub mod bingx;
pub mod bitfinex;
pub mod bitget;
pub mod bitmart;
pub mod bitrue;
pub mod bybit;
pub mod coinbase;
pub mod coinstore;
pub mod coinw;
pub mod cryptocom;
pub mod gate;
pub mod htx;
pub mod kraken;
pub mod kucoin;
pub mod lbank;
pub mod mexc;
pub mod okx;
pub mod orangex;
pub mod phemex;
pub mod poloniex;
pub mod stub;
pub mod weex;
pub mod whitebit;
pub mod xt;

use crate::cob_common::ExchangeConfig;
use crate::collectors::collector::CollectorBox;
use std::sync::Arc;

/// Adding a new exchange = drop a module under `impls/` and add a match arm
/// here. Names must match `config/exchanges.json` `name` field.
pub fn create_collector(name: &str, config: &ExchangeConfig) -> Option<CollectorBox> {
    match name {
        "ascendex" => Some(Arc::new(ascendex::Ascendex::new(config.clone()))),
        "biconomy" => Some(Arc::new(biconomy::Biconomy::new(config.clone()))),
        "binance" => Some(Arc::new(binance::Binance::new(config.clone()))),
        "bingx" => Some(Arc::new(bingx::Bingx::new(config.clone()))),
        "bitfinex" => Some(Arc::new(bitfinex::Bitfinex::new(config.clone()))),
        "bitget" => Some(Arc::new(bitget::Bitget::new(config.clone()))),
        "bitmart" => Some(Arc::new(bitmart::Bitmart::new(config.clone()))),
        "bitrue" => Some(Arc::new(bitrue::Bitrue::new(config.clone()))),
        "bybit" => Some(Arc::new(bybit::Bybit::new(config.clone()))),
        "coinbase" => Some(Arc::new(coinbase::Coinbase::new(config.clone()))),
        "coinstore" => Some(Arc::new(coinstore::Coinstore::new(config.clone()))),
        "coinw" => Some(Arc::new(coinw::Coinw::new(config.clone()))),
        "cryptocom" | "crypto_com" => Some(Arc::new(cryptocom::CryptoCom::new(config.clone()))),
        "gate" | "gateio" => Some(Arc::new(gate::Gate::new(config.clone()))),
        "htx" => Some(Arc::new(htx::Htx::new(config.clone()))),
        "kraken" => Some(Arc::new(kraken::Kraken::new(config.clone()))),
        "kucoin" => Some(Arc::new(kucoin::Kucoin::new(config.clone()))),
        "lbank" => Some(Arc::new(lbank::Lbank::new(config.clone()))),
        "mexc" => Some(Arc::new(mexc::Mexc::new(config.clone()))),
        "okx" => Some(Arc::new(okx::Okx::new(config.clone()))),
        "orangex" => Some(Arc::new(orangex::Orangex::new(config.clone()))),
        "phemex" => Some(Arc::new(phemex::Phemex::new(config.clone()))),
        "poloniex" => Some(Arc::new(poloniex::Poloniex::new(config.clone()))),
        "weex" => Some(Arc::new(weex::Weex::new(config.clone()))),
        "whitebit" => Some(Arc::new(whitebit::Whitebit::new(config.clone()))),
        "xt" => Some(Arc::new(xt::Xt::new(config.clone()))),
        _ => None,
    }
}

/// Names a misspelling/legacy alias maps to. Used only for clearer boot
/// errors — the runtime match above is the source of truth.
pub fn known_exchange_names() -> &'static [&'static str] {
    &[
        "ascendex",
        "biconomy",
        "binance",
        "bingx",
        "bitfinex",
        "bitget",
        "bitmart",
        "bitrue",
        "bybit",
        "coinbase",
        "coinstore",
        "coinw",
        "cryptocom",
        "gate",
        "htx",
        "kraken",
        "kucoin",
        "lbank",
        "mexc",
        "okx",
        "orangex",
        "phemex",
        "poloniex",
        "weex",
        "whitebit",
        "xt",
    ]
}
