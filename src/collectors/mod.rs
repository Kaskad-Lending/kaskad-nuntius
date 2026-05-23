//! Per-exchange WS collectors. Each task maintains a LocalBook and emits
//! OrderBookData through the BookSink every `COLLECTOR_EMIT_INTERVAL_MS`
//! (default 50ms). Some helpers stay exposed for parity with oracle-light
//! even though the kaskad signer path doesn't reach them.
#![allow(dead_code)]

pub mod book;
pub mod collector;
pub mod impls;
pub mod manager;
pub mod rest;
pub mod sink;
pub mod util;

pub use sink::BookSink;

use crate::cob_common::{CollectorCommand, ExchangeStats};
use std::path::PathBuf;
use tokio::sync::broadcast::Sender as BroadcastSender;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::info;

/// Top-level entry point. Loads config from `config_path`, starts the
/// manager, and pumps collector commands until `cmd_rx` is closed.
pub async fn run(
    cmd_rx: UnboundedReceiver<CollectorCommand>,
    config_path: String,
    _stats_tx: BroadcastSender<ExchangeStats>,
    sink: BookSink,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(&config_path);
    info!(?path, "starting CollectorManager");
    let mut manager = manager::CollectorManager::new(sink, path);
    manager
        .load_config_from_file()
        .map_err(|e| -> Box<dyn std::error::Error> {
            Box::new(std::io::Error::other(e.to_string()))
        })?;
    manager.run(cmd_rx).await;
    Ok(())
}
