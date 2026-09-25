//! Spawns one supervised task per exchange and restarts on error. The
//! BookSink is owned by main.rs so the fan-in mpsc goes into cob_state.

use crate::cob_common::{CollectorCommand, ExchangeConfig, ServiceStatus};
use crate::collectors::collector::{create_collector, CollectorBox};
use crate::collectors::sink::BookSink;
use eyre::{eyre, Result};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::AbortHandle;
use tracing::{error, info, warn};

const RECONNECT_DELAY: Duration = Duration::from_secs(5);

pub struct CollectorManager {
    running: HashMap<String, AbortHandle>,
    known: HashMap<String, ExchangeConfig>,
    sink: BookSink,
    config_path: std::path::PathBuf,
}

impl CollectorManager {
    pub fn new(sink: BookSink, config_path: std::path::PathBuf) -> Self {
        Self {
            running: HashMap::new(),
            known: HashMap::new(),
            sink,
            config_path,
        }
    }

    pub fn load_config_from_file(&mut self) -> Result<()> {
        // In enclave mode the venue set is attested: read ONLY the
        // PCR0-measured EIF-embedded config. No env/disk override — a host
        // operator must not be able to repoint the oracle at arbitrary
        // venues without changing PCR0 (audit M-2). Host/dev mode keeps the
        // inline-env → disk override for iteration without a rebuild.
        let content = if std::env::var("ENCLAVE_MODE").is_ok() {
            info!("Loading EIF-embedded collector config (PCR0-measured)");
            crate::types::EXCHANGES_JSON.to_string()
        } else {
            match std::env::var("EXCHANGES_CONFIG_INLINE") {
                Ok(inline) if !inline.is_empty() => {
                    info!(
                        bytes = inline.len(),
                        "Loading collector config from EXCHANGES_CONFIG_INLINE env"
                    );
                    inline
                }
                _ => {
                    info!("Loading collector config from {:?}", self.config_path);
                    std::fs::read_to_string(&self.config_path)
                        .map_err(|e| eyre!("read config {:?}: {e}", self.config_path))?
                }
            }
        };
        let configs: Vec<ExchangeConfig> =
            serde_json::from_str(&content).map_err(|e| eyre!("parse exchanges config: {e}"))?;
        let valid: Vec<_> = configs
            .into_iter()
            .filter_map(|c| match c.validate() {
                Ok(()) => Some(c),
                Err(e) => {
                    error!("Skipping invalid config: {e}");
                    None
                }
            })
            .collect();

        let unknown: Vec<&str> = valid
            .iter()
            .filter(|c| c.enabled)
            .filter(|c| crate::collectors::impls::create_collector(&c.name, c).is_none())
            .map(|c| c.name.as_str())
            .collect();
        if !unknown.is_empty() {
            // Bubble up to the supervisor instead of std::process::exit so a
            // corrected config via Reload can rescue the manager without a
            // full process restart.
            return Err(eyre!(
                "exchanges.json: enabled but unimplemented exchanges: {:?}. Known names: {:?}",
                unknown,
                crate::collectors::impls::known_exchange_names()
            ));
        }

        info!("Loaded {} valid collector configs", valid.len());
        self.update_config(valid);
        Ok(())
    }

    pub fn update_config(&mut self, new_configs: Vec<ExchangeConfig>) {
        let new_map: HashMap<String, ExchangeConfig> = new_configs
            .into_iter()
            .map(|c| (c.name.clone(), c))
            .collect();
        self.known = new_map.clone();

        let to_stop: Vec<String> = self
            .running
            .keys()
            .filter(|n| !new_map.get(*n).is_some_and(|c| c.enabled))
            .cloned()
            .collect();
        for n in to_stop {
            self.stop(&n);
        }

        for (name, cfg) in new_map {
            if cfg.enabled && !self.running.contains_key(&name) {
                self.start(cfg);
            }
        }
    }

    fn stop(&mut self, name: &str) {
        if let Some(h) = self.running.remove(name) {
            info!("[{name}] Stopping collector");
            h.abort();
            self.sink.status(name, ServiceStatus::Offline);
        }
    }

    fn start(&mut self, config: ExchangeConfig) {
        let name = config.name.clone();
        let collector: CollectorBox = match create_collector(&name, &config) {
            Some(c) => c,
            None => {
                // No impl: log and skip. load_config_from_file already
                // rejects unknown enabled exchanges; if we still hit this
                // path we'd rather lose the one exchange than the whole
                // process.
                error!(
                    "[{name}] No collector implementation found. Known names: {:?}. Skipping.",
                    crate::collectors::impls::known_exchange_names()
                );
                return;
            }
        };

        let sink = self.sink.clone();
        sink.status(&name, ServiceStatus::Starting);

        info!("[{name}] Starting collector");
        let name_for_task = name.clone();
        let handle = tokio::spawn(async move {
            loop {
                let sink_clone = sink.clone();
                match collector.run(sink_clone).await {
                    Ok(()) => {
                        // Treat a clean exit as "remote closed the stream":
                        // the collector trait isn't a fire-once future, it's
                        // a long-running pump, so a return without error
                        // means we want to reconnect just like on Err.
                        info!(
                            "[{}] Collector exited cleanly; reconnecting after backoff",
                            name_for_task
                        );
                        sink.status(&name_for_task, ServiceStatus::Reconnecting);
                        tokio::time::sleep(RECONNECT_DELAY).await;
                    }
                    Err(e) => {
                        error!("[{}] Collector error: {e:#}", name_for_task);
                        sink.status(&name_for_task, ServiceStatus::Error(e.to_string()));
                        tokio::time::sleep(RECONNECT_DELAY).await;
                        sink.status(&name_for_task, ServiceStatus::Reconnecting);
                    }
                }
            }
        });

        self.running.insert(name, handle.abort_handle());
    }

    pub async fn run(&mut self, mut rx: UnboundedReceiver<CollectorCommand>) {
        info!("Collector manager started ({} active)", self.running.len());
        while let Some(cmd) = rx.recv().await {
            match cmd {
                CollectorCommand::Status => {
                    info!("--- Collectors ---");
                    if self.running.is_empty() {
                        info!("(none)");
                    }
                    for n in self.running.keys() {
                        info!("- {n}: RUNNING");
                    }
                }
                CollectorCommand::Enable(name) => {
                    if self.running.contains_key(&name) {
                        info!("[{name}] already running");
                    } else if let Some(cfg) = self.known.get(&name).cloned() {
                        self.start(cfg);
                    } else {
                        warn!("[{name}] not in config");
                    }
                }
                CollectorCommand::Disable(name) => {
                    self.stop(&name);
                }
                CollectorCommand::Reload => {
                    if let Err(e) = self.load_config_from_file() {
                        error!("Reload failed: {e:#}");
                    }
                }
                CollectorCommand::Stop => {
                    info!("Collector manager: shutting down");
                    let names: Vec<String> = self.running.keys().cloned().collect();
                    for n in names {
                        self.stop(&n);
                    }
                    break;
                }
            }
        }
    }
}

impl Drop for CollectorManager {
    fn drop(&mut self) {
        if !self.running.is_empty() {
            info!(
                "CollectorManager dropping, aborting {} tasks",
                self.running.len()
            );
            for (_, h) in self.running.drain() {
                h.abort();
            }
        }
    }
}

/// Resolve the exchanges JSON config blob from either
/// `EXCHANGES_CONFIG_INLINE` (enclave-friendly) or the filesystem path.
/// Pulled out as a free function so it has a unit test that doesn't need
/// to spin up the full CollectorManager.
#[cfg(test)]
pub fn resolve_config_blob(file_path: &std::path::Path) -> Option<String> {
    if let Ok(inline) = std::env::var("EXCHANGES_CONFIG_INLINE") {
        if !inline.is_empty() {
            return Some(inline);
        }
    }
    std::fs::read_to_string(file_path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Tests in this module all manipulate the same EXCHANGES_CONFIG_INLINE
    // env var. cargo runs tests in parallel, so without a mutex they race
    // and one test will observe another's leaked value. Serialise.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<T>(key: &str, val: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var(key).ok();
        match val {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        let out = f();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        out
    }

    #[test]
    fn inline_config_takes_precedence_over_file() {
        with_env("EXCHANGES_CONFIG_INLINE", Some("[]"), || {
            // /nonexistent must not be read since inline is set.
            let blob = resolve_config_blob(std::path::Path::new("/nonexistent")).unwrap();
            assert_eq!(blob, "[]");
            // And it must be valid JSON for the ExchangeConfig vec.
            let cfgs: Vec<ExchangeConfig> = serde_json::from_str(&blob).unwrap();
            assert!(cfgs.is_empty());
        });
    }

    #[test]
    fn empty_inline_falls_back_to_file() {
        with_env("EXCHANGES_CONFIG_INLINE", Some(""), || {
            // No file -> None.
            assert!(resolve_config_blob(std::path::Path::new("/nonexistent")).is_none());
        });
    }

    #[test]
    fn unset_inline_falls_back_to_file() {
        with_env("EXCHANGES_CONFIG_INLINE", None, || {
            assert!(resolve_config_blob(std::path::Path::new("/nonexistent")).is_none());
        });
    }

    #[test]
    fn inline_config_with_one_exchange_parses() {
        let blob = r#"[{"name":"binance","enabled":true,"ws_url":"wss://x","pairs":["BTCUSDT"]}]"#;
        with_env("EXCHANGES_CONFIG_INLINE", Some(blob), || {
            let out = resolve_config_blob(std::path::Path::new("/nonexistent")).unwrap();
            let cfgs: Vec<ExchangeConfig> = serde_json::from_str(&out).unwrap();
            assert_eq!(cfgs.len(), 1);
            assert_eq!(cfgs[0].name, "binance");
            assert!(cfgs[0].enabled);
        });
    }

    /// The EIF-embedded collector config (the only source read in enclave
    /// mode) must parse and every enabled venue must have a collector impl —
    /// otherwise the enclave boots and immediately errors the manager. If
    /// this fails, a JSON typo was about to ship; fix the JSON.
    #[test]
    fn embedded_exchanges_json_parses_and_every_enabled_venue_is_known() {
        let cfgs: Vec<ExchangeConfig> = serde_json::from_str(crate::types::EXCHANGES_JSON)
            .expect("embedded exchanges.json must parse");
        assert!(!cfgs.is_empty(), "embedded exchanges.json has zero venues");
        for c in &cfgs {
            assert!(!c.name.is_empty(), "venue with empty name");
            if c.enabled {
                assert!(
                    crate::collectors::impls::create_collector(&c.name, c).is_some(),
                    "{} enabled in exchanges.json but no collector impl",
                    c.name
                );
            }
        }
    }
}
