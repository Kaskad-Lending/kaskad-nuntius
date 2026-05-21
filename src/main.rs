mod aggregator;
mod aws_creds;
mod cob;
mod cob_common;
mod cob_state;
mod collectors;
mod http_client;
mod price_server;
#[cfg(target_os = "linux")]
mod sealing;
mod signer;
mod sources;
mod types;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use eyre::Result;
use tracing::{error, info, warn};

use signer::{MockSigner, OracleSigner};
use sources::PriceSource;
use types::{load_assets, AssetConfig, CachedPrice, PricePoint};

const ORACLE_DECIMALS: u8 = 8;
const FETCH_INTERVAL_SECS: u64 = 30;

/// Shared state: latest aggregated prices (unsigned). Signature is created on-demand.
pub type PriceStore = Arc<RwLock<HashMap<String, CachedPrice>>>;

/// Shared signer, accessible by the price server for on-demand signing.
pub type SharedSigner = Arc<dyn signer::OracleSigner>;

/// Tracks the last pushed price and enclave-signed timestamp per asset.
/// The timestamp used here is ALWAYS the median(server_time) from the last
/// successful cycle — never `SystemTime::now()` (audit C-3/H-9). Subtraction
/// is saturating so a median rewind cannot wrap to a huge diff and force a
/// spurious heartbeat.
struct OracleState {
    // key = asset symbol (stable across config reloads).
    last_prices: HashMap<String, (f64, u64)>,
}

impl OracleState {
    fn new() -> Self {
        Self {
            last_prices: HashMap::new(),
        }
    }

    /// `current_ts` must be the median(server_time) computed for the
    /// current cycle's surviving sources. Never a host-clock read.
    fn should_update(&self, asset: &AssetConfig, new_price: f64, current_ts: u64) -> bool {
        match self.last_prices.get(&asset.symbol) {
            None => true,
            Some((last_price, last_ts)) => {
                let elapsed = current_ts.saturating_sub(*last_ts);
                if elapsed >= asset.heartbeat_seconds {
                    return true;
                }
                let deviation_bps = ((new_price - last_price) / last_price * 10000.0).abs() as u16;
                if deviation_bps >= asset.deviation_threshold_bps {
                    return true;
                }
                false
            }
        }
    }

    fn record_update(&mut self, symbol: &str, price: f64, signed_ts: u64) {
        self.last_prices
            .insert(symbol.to_string(), (price, signed_ts));
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let _ = dotenvy::dotenv();

    info!("Kaskad TEE Oracle starting");

    // Load the bundled asset config (compiled into the enclave EIF → PCR0).
    let config = load_assets().expect("failed to load bundled config/assets.json");

    let enclave_mode = std::env::var("ENCLAVE_MODE").is_ok();

    // Bring up VSOCK→TCP bridge BEFORE signer init: the sealed-key path
    // (signer::EnclaveSigner::new) reaches S3/KMS over `127.0.0.1:5000`,
    // and reqwest will refuse with "error sending request" if the
    // listener isn't bound yet.
    if enclave_mode {
        info!("Running in ENCLAVE mode — starting VSOCK→TCP bridge on 127.0.0.1:5000");
        #[cfg(target_os = "linux")]
        {
            let bridge_listener = match tokio::net::TcpListener::bind("127.0.0.1:5000").await {
                Ok(l) => {
                    info!("VSOCK→TCP bridge bound to 127.0.0.1:5000");
                    l
                }
                Err(e) => {
                    error!(error = %e, "Failed to bind VSOCK→TCP bridge on 127.0.0.1:5000");
                    return Err(e.into());
                }
            };
            tokio::spawn(async move {
                loop {
                    match bridge_listener.accept().await {
                        Ok((tcp_stream, _)) => {
                            tokio::spawn(async move {
                                if let Err(e) = bridge_connection(tcp_stream, 3, 5000).await {
                                    warn!(error = %e, "VSOCK bridge connection failed");
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "VSOCK bridge accept failed");
                        }
                    }
                }
            });
        }
    } else {
        info!("Running in HOST mode — HTTP via direct connection");
    }

    // Init signer. The enclave key only signs price updates; the per-asset
    // quorum is committed separately by the admin via
    // KaskadPriceOracle.registerAssets (no enclave-side bundle signature).
    let signer: Box<dyn OracleSigner> = if enclave_mode {
        #[cfg(target_os = "linux")]
        {
            info!("Running in ENCLAVE mode — Initializing EnclaveSigner via NSM");
            Box::new(
                signer::EnclaveSigner::new()
                    .await
                    .expect("Failed to init EnclaveSigner"),
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            panic!("Enclave mode requested but target is not Linux/Nitro compatible");
        }
    } else {
        // Audit R-6: refuse to silently fall back to MockSigner when
        // `ENCLAVE_MODE` is unset. A typo in the systemd unit / Docker
        // env on a Nitro production host would otherwise let a
        // host-controlled `ORACLE_PRIVATE_KEY` env-var sign all
        // prices. Operator must explicitly opt-in for dev / CI.
        if std::env::var("KASKAD_ALLOW_MOCK_SIGNER").is_err() {
            return Err(eyre::eyre!(
                "ENCLAVE_MODE not set and KASKAD_ALLOW_MOCK_SIGNER not set. \
                 Refusing to fall back to MockSigner — this would let a \
                 typo of ENCLAVE_MODE on a Nitro host sign prices with a \
                 host-controlled key. Set KASKAD_ALLOW_MOCK_SIGNER=1 for \
                 dev / CI."
            ));
        }
        match std::env::var("ORACLE_PRIVATE_KEY") {
            Ok(key) => {
                info!("Using private key from ORACLE_PRIVATE_KEY env (KASKAD_ALLOW_MOCK_SIGNER=1)");
                Box::new(MockSigner::new(&key)?)
            }
            Err(_) => {
                info!(
                    "No ORACLE_PRIVATE_KEY found, generating random MockSigner key \
                     (KASKAD_ALLOW_MOCK_SIGNER=1, dev only)"
                );
                Box::new(MockSigner::random())
            }
        }
    };

    let signer_address = format!("0x{}", hex::encode(signer.address()));
    let signer: SharedSigner = Arc::from(signer);
    info!(address = %signer_address, "Oracle signer initialized");

    // Shared price store
    let price_store: PriceStore = Arc::new(RwLock::new(HashMap::new()));

    // Start VSOCK price server (pull API) — signs on-demand per request
    let vsock_port: u32 = std::env::var("VSOCK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5001);

    let server_store = price_store.clone();
    let server_signer = signer.clone();
    let server_signer_address = signer_address.clone();
    tokio::spawn(async move {
        if let Err(e) = price_server::run_price_server(
            vsock_port,
            server_store,
            server_signer,
            server_signer_address,
        )
        .await
        {
            // Audit R-19: previously the price server could silently
            // exit (e.g. listener loop returns Err) leaving the
            // oracle loop running and signing into the void. Aborting
            // the process so systemd `Restart=always` (production)
            // and CI runners surface the failure instead of the
            // pull API quietly going dark.
            error!(error = %e, "Price server failed — aborting process");
            std::process::exit(1);
        }
    });

    let client = http_client::HttpClient::new(enclave_mode, config.exchange_hostnames.clone());

    // (config loaded above — used here for source registration.)
    let price_sources: Vec<Box<dyn PriceSource>> = vec![
        Box::new(sources::binance::Binance::new(client.clone())),
        Box::new(sources::okx::Okx::new(client.clone())),
        Box::new(sources::bybit::Bybit::new(client.clone())),
        Box::new(sources::coinbase::Coinbase::new(client.clone())),
        Box::new(sources::coingecko::CoinGecko::new(client.clone())),
        Box::new(sources::mexc::Mexc::new(client.clone())),
        Box::new(sources::kucoin::Kucoin::new(client.clone())),
        Box::new(sources::gateio::GateIo::new(client.clone())),
        Box::new(sources::kraken::Kraken::new(client.clone())),
        Box::new(sources::bitget::Bitget::new(client.clone())),
        Box::new(sources::bitfinex::Bitfinex::new(client.clone())),
        Box::new(sources::bitstamp::Bitstamp::new(client.clone())),
        Box::new(sources::crypto_com::CryptoCom::new(client.clone())),
        Box::new(sources::htx::Htx::new(client.clone())),
        Box::new(sources::igralabs::IgraLabs::new(client.clone())),
    ];

    // --- Spawn the WS collector manager + book-state fan-in ----------
    let (collector_tx, mut collector_rx) =
        tokio::sync::mpsc::unbounded_channel::<cob_common::CollectorMessage>();
    let sink = collectors::BookSink::new(Some(collector_tx));

    let (mgr_cmd_tx, mgr_cmd_rx) =
        tokio::sync::mpsc::unbounded_channel::<cob_common::CollectorCommand>();
    let (mgr_stats_tx, _mgr_stats_rx) =
        tokio::sync::broadcast::channel::<cob_common::ExchangeStats>(64);

    // Host mode reads from disk; enclave operators set EXCHANGES_CONFIG_INLINE.
    let config_path =
        std::env::var("EXCHANGES_CONFIG").unwrap_or_else(|_| "config/exchanges.json".to_string());

    // Supervisor: exponential-backoff restart loop. Forwarder task
    // re-publishes outer commands into the live inner_tx across restarts.
    type CollectorTxSlot = std::sync::Arc<
        tokio::sync::RwLock<
            Option<tokio::sync::mpsc::UnboundedSender<cob_common::CollectorCommand>>,
        >,
    >;
    let inner_tx_slot: CollectorTxSlot = std::sync::Arc::new(tokio::sync::RwLock::new(None));
    let stop_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    {
        let slot = inner_tx_slot.clone();
        let stop = stop_flag.clone();
        tokio::spawn(async move {
            let mut rx = mgr_cmd_rx;
            while let Some(cmd) = rx.recv().await {
                if matches!(cmd, cob_common::CollectorCommand::Stop) {
                    stop.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                if let Some(tx) = slot.read().await.as_ref() {
                    let _ = tx.send(cmd);
                }
            }
        });
    }

    let mgr_config_path = config_path.clone();
    let mgr_stats_tx_clone = mgr_stats_tx.clone();
    let mgr_sink = sink.clone();
    let stop_flag_for_mgr = stop_flag.clone();
    let slot_for_mgr = inner_tx_slot.clone();
    let mgr_handle = tokio::spawn(async move {
        let mut backoff_secs: u64 = 1;
        loop {
            if stop_flag_for_mgr.load(std::sync::atomic::Ordering::SeqCst) {
                info!("CollectorManager: stop flag set, exiting supervisor");
                break;
            }
            let (inner_tx, inner_rx) =
                tokio::sync::mpsc::unbounded_channel::<cob_common::CollectorCommand>();
            *slot_for_mgr.write().await = Some(inner_tx);

            // catch_unwind so a panic restarts the manager. Coerce the
            // non-Send `Box<dyn Error>` to a String before any await.
            let started_at = std::time::Instant::now();
            let err_msg: Option<String> = {
                let run_fut = std::panic::AssertUnwindSafe(collectors::run(
                    inner_rx,
                    mgr_config_path.clone(),
                    mgr_stats_tx_clone.clone(),
                    mgr_sink.clone(),
                ));
                match futures::FutureExt::catch_unwind(run_fut).await {
                    Ok(Ok(())) => None,
                    Ok(Err(e)) => Some(e.to_string()),
                    Err(_panic) => Some("collectors::run panicked".to_string()),
                }
            };

            *slot_for_mgr.write().await = None;

            if stop_flag_for_mgr.load(std::sync::atomic::Ordering::SeqCst) {
                info!("CollectorManager exited cleanly (Stop received)");
                break;
            }
            match err_msg {
                None => {
                    info!("CollectorManager exited cleanly");
                    break;
                }
                Some(err_str) => {
                    if started_at.elapsed() >= std::time::Duration::from_secs(60) {
                        backoff_secs = 1;
                    }
                    error!(error = %err_str, backoff_secs, "CollectorManager terminated; restarting after backoff");
                    tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                }
            }
        }
    });

    let book_state: cob_state::SharedBookState = cob_state::new_shared();
    let consumer_state = book_state.clone();
    let _fan_in_handle = tokio::spawn(async move {
        while let Some(msg) = collector_rx.recv().await {
            if let cob_common::CollectorMessage::Data(book) = msg {
                cob_state::insert(&consumer_state, book).await;
            }
        }
    });

    // Wait up to 10s for COLD_START_MIN_BOOKS books before the first cycle.
    let cold_start_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let cold_start_min_books: usize = std::env::var("COLD_START_MIN_BOOKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    loop {
        let n = book_state.read().await.len();
        if n >= cold_start_min_books {
            info!(books = n, "cold start: quorum reached");
            break;
        }
        if std::time::Instant::now() >= cold_start_deadline {
            warn!(
                books = n,
                min_required = cold_start_min_books,
                "cold start: timeout waiting for books, proceeding anyway"
            );
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    let known_sources: std::collections::HashSet<&str> =
        price_sources.iter().map(|s| s.name()).collect();

    for a in &config.assets {
        for src_name in a.sources.keys() {
            if !known_sources.contains(src_name.as_str()) {
                warn!(
                    asset = %a.symbol,
                    source = %src_name,
                    "asset config references unknown source — mapping will be ignored"
                );
            }
        }
    }

    let single_run = std::env::var("SINGLE_RUN").is_ok();
    let mut state = OracleState::new();

    info!(
        assets = ?config.assets.iter().map(|a| a.symbol.as_str()).collect::<Vec<_>>(),
        single_run = single_run,
        "Starting oracle loop"
    );

    // Main oracle loop: fetch → aggregate → sign → store
    loop {
        for asset in &config.assets {
            if cob::is_cob_asset(asset) {
                let books = cob::read_books_from_state(asset, &book_state).await;
                if books.len() < asset.min_sources {
                    warn!(
                        asset = %asset.symbol,
                        num_sources = books.len(),
                        min_required = asset.min_sources,
                        "COB Quorum not met. Skipping."
                    );
                    continue;
                }
                let fair = match cob::consolidated_order_book(&books) {
                    Some(fv) => fv,
                    None => {
                        warn!(asset = %asset.symbol, "COB returned no fair value");
                        continue;
                    }
                };

                // Cycle timestamp: median exchange_timestamp_ms, never the
                // host wall clock (audit C-3/H-9).
                let cob_signed_ts: u64 = {
                    let guard = book_state.read().await;
                    let mut ts_ms: Vec<i64> = books
                        .iter()
                        .filter_map(|b| {
                            guard.values().find(|book| {
                                book.exchange_id == b.source
                                    && cob_common::extract_base_asset(&book.symbol)
                                        == cob::asset_to_collector_symbol(asset)
                            })
                        })
                        .map(|book| {
                            if book.exchange_timestamp > 0 {
                                book.exchange_timestamp
                            } else {
                                book.received_timestamp
                            }
                        })
                        .filter(|t| *t > 0)
                        .collect();
                    if ts_ms.is_empty() {
                        warn!(asset = %asset.symbol, "no usable book timestamps; skipping");
                        continue;
                    }
                    ts_ms.sort_unstable();
                    let mid = ts_ms[ts_ms.len() / 2];
                    (mid / 1000).max(0) as u64
                };

                if !state.should_update(asset, fair.price, cob_signed_ts) {
                    info!(
                        asset = %asset.symbol,
                        price = format!("{:.8}", fair.price),
                        spread_bps = format!("{:.1}", fair.spread_bps),
                        "COB price within threshold, skipping"
                    );
                    continue;
                }

                let hash_points: Vec<PricePoint> = books
                    .iter()
                    .map(|b| PricePoint {
                        price: b.bids.first().map(|l| l.price).unwrap_or(0.0),
                        volume: 0.0,
                        source: b.source.clone(),
                        server_time: cob_signed_ts,
                    })
                    .collect();
                let price_fixed = match aggregator::to_fixed_point(fair.price, ORACLE_DECIMALS) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(asset = %asset.symbol, error = %e, "fixed-point conversion failed");
                        continue;
                    }
                };
                let sources_hash = aggregator::sources_hash(&hash_points);

                let cached = CachedPrice {
                    asset_symbol: asset.symbol.clone(),
                    asset_id: asset.id(),
                    price_fixed,
                    price_human: fair.price,
                    num_sources: fair.num_sources as u8,
                    sources_hash,
                    signed_timestamp: cob_signed_ts,
                };

                {
                    let mut store = price_store.write().await;
                    store.insert(asset.symbol.clone(), cached);
                }

                info!(
                    asset = %asset.symbol,
                    price = format!("{:.8}", fair.price),
                    price_fixed = %price_fixed,
                    spread_bps = format!("{:.1}", fair.spread_bps),
                    num_sources = fair.num_sources,
                    "cached COB price (signature on-demand)"
                );

                state.record_update(&asset.symbol, fair.price, cob_signed_ts);
                continue;
            }

            // 1. Fetch from all sources
            let raw_prices = sources::fetch_all(&price_sources, asset).await;

            // 1a. Sanitise: drop NaN / ±Infinity / non-positive prices and
            //     normalise broken volumes (audit C-4, M-5).
            let raw_count = raw_prices.len();
            let mut prices = aggregator::sanitize(raw_prices);
            if prices.len() < raw_count {
                warn!(
                    asset = %asset.symbol,
                    dropped = raw_count - prices.len(),
                    "dropped non-finite / non-positive samples"
                );
            }

            if prices.len() < asset.min_sources {
                warn!(
                    asset = %asset.symbol,
                    num_sources = prices.len(),
                    min_required = asset.min_sources,
                    "Data Quorum not met. Skipping update to prevent Liquidity Eclipse."
                );
                continue;
            }

            info!(
                asset = %asset.symbol,
                num_sources = prices.len(),
                "fetched prices"
            );

            // 2. Outlier rejection (by price)
            let before = prices.len();
            aggregator::reject_outliers(&mut prices, 3.0);
            if prices.len() < before {
                info!(
                    asset = %asset.symbol,
                    removed = before - prices.len(),
                    "rejected price outliers"
                );
            }

            // 2a. Reject server_time outliers (>5 min drift). This is the
            //     enclave's only defence against a single compromised CEX
            //     trying to drag the authoritative clock (audit C-3/H-9).
            let before_t = prices.len();
            let signed_ts = match aggregator::reject_time_outliers(&mut prices) {
                Some(ts) => ts,
                None => {
                    warn!(
                        asset = %asset.symbol,
                        "no samples with valid server_time; skipping cycle"
                    );
                    continue;
                }
            };
            if prices.len() < before_t {
                info!(
                    asset = %asset.symbol,
                    removed = before_t - prices.len(),
                    "rejected time-drift outliers"
                );
            }

            // Re-check quorum after outlier rejection (price + time).
            if prices.len() < asset.min_sources {
                warn!(
                    asset = %asset.symbol,
                    remaining = prices.len(),
                    min_required = asset.min_sources,
                    "Data Quorum lost after outlier rejection. Skipping."
                );
                continue;
            }

            // 3. Compute weighted median price.
            let (median, mode) = match aggregator::weighted_median(&prices) {
                Some(m) => m,
                None => {
                    warn!(asset = %asset.symbol, "no prices after filtering");
                    continue;
                }
            };

            // Strict-policy assets (e.g. BTC/USD, ETH/USD) refuse to publish
            // when the aggregator fell back to equal weighting — EXPLOIT-3.
            // Better to serve a stale price (consumers' staleness guard
            // kicks in) than a depth-blind one.
            if asset.require_volume_weight && mode == aggregator::WeightingMode::EqualFallback {
                warn!(
                    asset = %asset.symbol,
                    "require_volume_weight: volume quorum not met, skipping publication (fail-closed)"
                );
                continue;
            }

            // 4. Deviation / heartbeat — both keyed on enclave-authoritative
            //    `signed_ts`, never the host clock (audit C-3/H-9).
            if !state.should_update(asset, median, signed_ts) {
                info!(
                    asset = %asset.symbol,
                    price = format!("{:.6}", median),
                    "price within threshold, skipping"
                );
                continue;
            }

            // 5. Cache aggregated price — signature will be created on-demand by price_server
            let price_fixed = match aggregator::to_fixed_point(median, ORACLE_DECIMALS) {
                Ok(p) => p,
                Err(e) => {
                    warn!(
                        asset = %asset.symbol,
                        median = median,
                        error = %e,
                        "refusing to cache aggregated price — failed sanity check"
                    );
                    continue;
                }
            };
            let sources_hash = aggregator::sources_hash(&prices);

            let cached = CachedPrice {
                asset_symbol: asset.symbol.clone(),
                asset_id: asset.id(),
                price_fixed,
                price_human: median,
                num_sources: prices.len() as u8,
                sources_hash,
                signed_timestamp: signed_ts,
            };

            {
                let mut store = price_store.write().await;
                store.insert(asset.symbol.clone(), cached);
            }

            info!(
                asset = %asset.symbol,
                price = format!("{:.6}", median),
                price_fixed = %price_fixed,
                num_sources = prices.len(),
                "cached price (signature on-demand)"
            );

            // 6. Record update locally (keyed on enclave-authoritative ts).
            state.record_update(&asset.symbol, median, signed_ts);
        }

        if single_run {
            info!("Single run complete, requesting collector shutdown");
            // Tell the supervisor + manager to drain. Best-effort
            // -- if the mgr is mid-restart the Stop will be replayed
            // on the next iteration of the supervisor loop.
            let _ = mgr_cmd_tx.send(cob_common::CollectorCommand::Stop);
            let shutdown =
                tokio::time::timeout(std::time::Duration::from_secs(5), mgr_handle).await;
            match shutdown {
                Ok(Ok(())) => info!("collectors drained cleanly"),
                Ok(Err(e)) => warn!(error = %e, "collector supervisor task panicked"),
                Err(_) => warn!("collector shutdown timed out after 5s"),
            }
            break;
        }

        info!("sleeping {} seconds", FETCH_INTERVAL_SECS);
        tokio::time::sleep(std::time::Duration::from_secs(FETCH_INTERVAL_SECS)).await;
    }

    Ok(())
}

// The live VSOCK↔TCP bridge is inlined in `main` after the price server
// spawns (see the `tokio::spawn` block around `bridge_listener.accept()`).
// Each accepted TCP connection is forwarded via `bridge_connection` below.
// An earlier `run_vsock_tcp_bridge` helper duplicated the same logic and
// was never called — removed per audit L-1 to eliminate dead surface area.

#[cfg(target_os = "linux")]
async fn bridge_connection(
    tcp_stream: tokio::net::TcpStream,
    remote_cid: u32,
    remote_port: u32,
) -> eyre::Result<()> {
    use std::os::unix::io::FromRawFd;

    // Create VSOCK socket and connect to Remote CID
    let vsock_stream = tokio::task::spawn_blocking(move || -> eyre::Result<std::net::TcpStream> {
        const AF_VSOCK: i32 = 40;

        let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(eyre::eyre!("failed to create VSOCK socket"));
        }

        #[repr(C)]
        struct SockaddrVm {
            svm_family: u16,
            svm_reserved1: u16,
            svm_port: u32,
            svm_cid: u32,
            svm_zero: [u8; 4],
        }

        let addr = SockaddrVm {
            svm_family: AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: remote_port,
            svm_cid: remote_cid,
            svm_zero: [0; 4],
        };

        let ret = unsafe {
            libc::connect(
                fd,
                &addr as *const SockaddrVm as *const libc::sockaddr,
                std::mem::size_of::<SockaddrVm>() as u32,
            )
        };

        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(eyre::eyre!(
                "VSOCK connect to CID {} port {} failed",
                remote_cid,
                remote_port
            ));
        }

        Ok(unsafe { std::net::TcpStream::from_raw_fd(fd) })
    })
    .await??;

    vsock_stream.set_nonblocking(true)?;
    let vsock_stream = tokio::net::TcpStream::from_std(vsock_stream)?;

    // Bidirectional relay
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_stream);
    let (mut vsock_read, mut vsock_write) = tokio::io::split(vsock_stream);

    let t1 = tokio::io::copy(&mut tcp_read, &mut vsock_write);
    let t2 = tokio::io::copy(&mut vsock_read, &mut tcp_write);

    tokio::select! {
        _ = t1 => {},
        _ = t2 => {},
    }

    Ok(())
}
