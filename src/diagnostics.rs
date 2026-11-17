//! Operator-only diagnostics: request outcomes, asset skips, host pauses and
//! cycle timing, keyed only by the asset config and bounded by it. Served as
//! `get_diagnostics` on the enclave socket; the public pull API never routes it.

use std::collections::{BTreeMap, VecDeque};
use std::mem::discriminant;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::Serialize;
use tokio::time::Instant;

use crate::aggregator::OutlierDrop;
use crate::http_client::{classify, printable_ascii, ErrorClass, HostObserver, RequestError};
use crate::sources::ethrpc::NavReject;
use crate::types::AssetConfig;

/// Events kept; once full, the oldest is dropped and counted.
pub const MAX_EVENTS: usize = 256;
/// Longest failure detail kept, in ASCII chars.
pub const MAX_DETAIL_CHARS: usize = 120;
/// Cycles that `cycles.max_ms` looks back over.
pub const CYCLE_WINDOW: usize = 32;
/// Upper bound of one `get_diagnostics` response, envelope included.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

const TOO_LARGE: &[u8] = br#"{"error":"diagnostics exceed the response limit"}"#;

/// Why an asset was not priced this cycle; one variant per skip in the main loop.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum SkipReason {
    QuorumNotMet { have: usize, need: usize },
    NoServerTime,
    QuorumLost { have: usize, need: usize },
    PairGap { gap_bps: f64, limit_bps: u16 },
    NoPricesAfterFiltering,
    FixedPointRejected { median: f64 },
}

/// Skips of one asset per [`SkipReason`] variant; each field is named by its tag.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
struct SkipCounts {
    quorum_not_met: u64,
    no_server_time: u64,
    quorum_lost: u64,
    pair_gap: u64,
    no_prices_after_filtering: u64,
    fixed_point_rejected: u64,
}

impl SkipCounts {
    fn count(&mut self, reason: SkipReason) {
        let counter = match reason {
            SkipReason::QuorumNotMet { .. } => &mut self.quorum_not_met,
            SkipReason::NoServerTime => &mut self.no_server_time,
            SkipReason::QuorumLost { .. } => &mut self.quorum_lost,
            SkipReason::PairGap { .. } => &mut self.pair_gap,
            SkipReason::NoPricesAfterFiltering => &mut self.no_prices_after_filtering,
            SkipReason::FixedPointRejected { .. } => &mut self.fixed_point_rejected,
        };
        *counter += 1;
    }
}

/// Which path priced an asset's cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PricePath {
    Cob,
    Rest,
}

/// One asset's pass through the main loop.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AssetCycle {
    pub path: PricePath,
    /// Sources that returned a sample; on the COB path, books that passed the gate.
    pub responders: usize,
    pub outliers: Vec<OutlierDrop>,
    /// Set by [`Diagnostics::asset_skipped`].
    pub skip: Option<SkipReason>,
}

impl AssetCycle {
    pub fn new(path: PricePath, responders: usize) -> Self {
        Self {
            path,
            responders,
            outliers: Vec::new(),
            skip: None,
        }
    }
}

/// What one source fetch cost: HTTP time when it made calls, else wall time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spent {
    pub duration: Duration,
    pub attempts: u32,
}

/// The last outcome of one VUSD NAV operator.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum OperatorOutcome {
    Accepted {
        price_1e8: u64,
    },
    Rejected {
        reject: NavReject,
        rpc_code: Option<i64>,
    },
    Failed {
        class: ErrorClass,
        http_status: Option<u16>,
        attempts: u32,
    },
}

impl OperatorOutcome {
    pub fn failed(error: &eyre::Report) -> Self {
        let (class, http_status) = classify(error);
        let attempts = error
            .downcast_ref::<RequestError>()
            .map_or(0, |request| request.attempts);
        Self::Failed {
            class,
            http_status,
            attempts,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum Outcome {
    Ok,
    Failed {
        class: ErrorClass,
        http_status: Option<u16>,
        detail: String,
    },
}

#[derive(Debug, Default)]
struct SourceStats {
    ok: u64,
    failed: u64,
    consecutive_failures: u64,
    /// Samples the outlier filter dropped.
    outliers: u64,
    last: Option<Outcome>,
    last_ok: Option<Instant>,
    last_spent: Option<Spent>,
}

#[derive(Debug, Default)]
struct AssetStats {
    signed: u64,
    skipped: u64,
    skipped_by_reason: SkipCounts,
    /// Skipped cycles since the last signed one.
    consecutive_skips: u64,
    last_skip: Option<SkipReason>,
    last_signed: Option<Instant>,
    last_signed_sources: Option<u8>,
    last_price: Option<f64>,
    last_cycle: Option<AssetCycle>,
    sources: BTreeMap<String, SourceStats>,
}

#[derive(Debug, Default)]
struct HostStats {
    pauses: u64,
    suppressed: u64,
    paused_until: Option<Instant>,
    last_cause: Option<ErrorClass>,
    last_http_status: Option<u16>,
}

#[derive(Debug, Clone, Copy)]
struct Round {
    at: Instant,
    accepted: usize,
    duration: Duration,
}

#[derive(Debug, Default)]
struct EthRpcStats {
    rounds: u64,
    last_round: Option<Round>,
    operators: BTreeMap<String, (Instant, OperatorOutcome)>,
}

/// A change of state; a repeat of the previous outcome adds no event.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum EventKind {
    /// The pair failed, and its previous outcome was not a failure of the
    /// same class and HTTP status.
    SourceFailed {
        asset: String,
        source: String,
        class: ErrorClass,
        http_status: Option<u16>,
        attempts: u32,
        detail: String,
    },
    /// The pair succeeded after `consecutive_failures` failures.
    SourceRecovered {
        asset: String,
        source: String,
        consecutive_failures: u64,
    },
    HostPaused {
        host: String,
        cause: ErrorClass,
        http_status: u16,
        pause_s: f64,
    },
    HostResumed {
        host: String,
    },
    /// The previous cycle of the asset was not skipped for the same reason.
    AssetSkipped {
        asset: String,
        skip: SkipReason,
    },
    /// The asset was signed after `consecutive_skips` skipped cycles.
    AssetResumed {
        asset: String,
        consecutive_skips: u64,
    },
    /// The source was not an outlier in the previous cycle of the asset.
    OutlierDropped {
        asset: String,
        source: String,
        price: f64,
        deviation_bps: f64,
    },
}

#[derive(Debug)]
struct Event {
    at: Instant,
    kind: EventKind,
}

#[derive(Debug, Default)]
struct State {
    assets: BTreeMap<String, AssetStats>,
    hosts: BTreeMap<String, HostStats>,
    ethrpc: EthRpcStats,
    cycles: u64,
    recent_cycles: VecDeque<Duration>,
    events: VecDeque<Event>,
    events_dropped: u64,
}

impl State {
    fn source(&mut self, asset: &str, source: &str) -> Option<&mut SourceStats> {
        self.assets.get_mut(asset)?.sources.get_mut(source)
    }

    fn push(&mut self, at: Instant, kind: EventKind) {
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
            self.events_dropped += 1;
        }
        self.events.push_back(Event { at, kind });
    }
}

/// Diagnostics for the whole process: one `Arc` shared by the main loop, the
/// sources, the HTTP client and the price server.
pub struct Diagnostics {
    started: Instant,
    state: Mutex<State>,
}

impl Diagnostics {
    /// Tracks the (asset, source) pairs of `assets` and the `hosts`; records
    /// for any other key are ignored.
    pub fn new(assets: &[AssetConfig], hosts: &[String]) -> Self {
        let mut state = State::default();
        for asset in assets {
            let stats = state.assets.entry(asset.symbol.clone()).or_default();
            for source in asset.sources.keys() {
                stats.sources.entry(source.clone()).or_default();
            }
        }
        for host in hosts {
            state.hosts.entry(host.clone()).or_default();
        }
        Self {
            started: Instant::now(),
            state: Mutex::new(state),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn source_ok(&self, asset: &str, source: &str, spent: Spent) {
        let now = Instant::now();
        let mut state = self.lock();
        let Some(stats) = state.source(asset, source) else {
            return;
        };
        let recovered = (stats.consecutive_failures > 0).then_some(stats.consecutive_failures);
        stats.ok += 1;
        stats.consecutive_failures = 0;
        stats.last = Some(Outcome::Ok);
        stats.last_ok = Some(now);
        stats.last_spent = Some(spent);
        if let Some(consecutive_failures) = recovered {
            let kind = EventKind::SourceRecovered {
                asset: asset.into(),
                source: source.into(),
                consecutive_failures,
            };
            state.push(now, kind);
        }
    }

    /// A request held back by a host pause counts as a failure but adds no event.
    pub fn source_failed(&self, asset: &str, source: &str, error: &eyre::Report, spent: Spent) {
        let (class, http_status) = classify(error);
        let detail = sanitize_detail(&format!("{error:#}"));
        let now = Instant::now();
        let mut state = self.lock();
        let Some(stats) = state.source(asset, source) else {
            return;
        };
        let repeated = matches!(
            &stats.last,
            Some(Outcome::Failed { class: c, http_status: s, .. }) if *c == class && *s == http_status
        );
        stats.failed += 1;
        stats.consecutive_failures += 1;
        stats.last = Some(Outcome::Failed {
            class,
            http_status,
            detail: detail.clone(),
        });
        stats.last_spent = Some(spent);
        if class != ErrorClass::CoolingDown && !repeated {
            let kind = EventKind::SourceFailed {
                asset: asset.into(),
                source: source.into(),
                class,
                http_status,
                attempts: spent.attempts,
                detail,
            };
            state.push(now, kind);
        }
    }

    /// `asset` was stored for signing from `sources` samples at `price`.
    pub fn asset_signed(&self, asset: &str, cycle: AssetCycle, sources: u8, price: f64) {
        self.asset_cycle(asset, cycle, |stats, now| {
            stats.signed += 1;
            stats.last_signed = Some(now);
            stats.last_signed_sources = Some(sources);
            stats.last_price = Some(price);
        });
    }

    pub fn asset_skipped(&self, asset: &str, mut cycle: AssetCycle, reason: SkipReason) {
        cycle.skip = Some(reason);
        self.asset_cycle(asset, cycle, |stats, _| {
            stats.skipped += 1;
            stats.skipped_by_reason.count(reason);
            stats.last_skip = Some(reason);
        });
    }

    /// Records one signed (`cycle.skip` is None) or skipped cycle of `asset`.
    fn asset_cycle(
        &self,
        asset: &str,
        cycle: AssetCycle,
        update: impl FnOnce(&mut AssetStats, Instant),
    ) {
        let now = Instant::now();
        let mut state = self.lock();
        let Some(stats) = state.assets.get_mut(asset) else {
            return;
        };
        update(stats, now);
        let previous = stats.last_cycle.take();
        let mut events = Vec::new();
        for drop in &cycle.outliers {
            if let Some(source) = stats.sources.get_mut(&drop.source) {
                source.outliers += 1;
            }
            let repeated = previous
                .as_ref()
                .is_some_and(|p| p.outliers.iter().any(|o| o.source == drop.source));
            if !repeated {
                events.push(EventKind::OutlierDropped {
                    asset: asset.into(),
                    source: drop.source.clone(),
                    price: drop.price,
                    deviation_bps: drop.deviation_bps,
                });
            }
        }
        match cycle.skip {
            Some(skip) => {
                stats.consecutive_skips += 1;
                let repeated = previous
                    .as_ref()
                    .and_then(|p| p.skip)
                    .is_some_and(|p| discriminant(&p) == discriminant(&skip));
                if !repeated {
                    events.push(EventKind::AssetSkipped {
                        asset: asset.into(),
                        skip,
                    });
                }
            }
            None if stats.consecutive_skips > 0 => {
                events.push(EventKind::AssetResumed {
                    asset: asset.into(),
                    consecutive_skips: stats.consecutive_skips,
                });
                stats.consecutive_skips = 0;
            }
            None => {}
        }
        stats.last_cycle = Some(cycle);
        for kind in events {
            state.push(now, kind);
        }
    }

    /// Last outcome of the operator serving as `source`; ignored unless the
    /// config names that source.
    pub fn operator(&self, source: &str, outcome: OperatorOutcome) {
        let now = Instant::now();
        let mut state = self.lock();
        if state
            .assets
            .values()
            .any(|asset| asset.sources.contains_key(source))
        {
            state
                .ethrpc
                .operators
                .insert(source.to_string(), (now, outcome));
        }
    }

    pub fn nav_round(&self, accepted: usize, duration: Duration) {
        let at = Instant::now();
        let mut state = self.lock();
        state.ethrpc.rounds += 1;
        state.ethrpc.last_round = Some(Round {
            at,
            accepted,
            duration,
        });
    }

    pub fn cycle_finished(&self, duration: Duration) {
        let mut state = self.lock();
        state.cycles += 1;
        if state.recent_cycles.len() == CYCLE_WINDOW {
            state.recent_cycles.pop_front();
        }
        state.recent_cycles.push_back(duration);
    }

    /// The `get_diagnostics` response, at most [`MAX_RESPONSE_BYTES`]: the
    /// oldest events are left out until it fits.
    pub fn response(&self) -> Vec<u8> {
        self.response_within(MAX_RESPONSE_BYTES)
    }

    fn response_within(&self, budget: usize) -> Vec<u8> {
        let now = Instant::now();
        let state = self.lock();
        let events: Vec<EventView> = state
            .events
            .iter()
            .map(|event| EventView {
                age_s: secs(now.saturating_duration_since(event.at)),
                kind: &event.kind,
            })
            .collect();
        let mut left_out = 0;
        loop {
            let envelope = Envelope {
                status: "ok",
                diagnostics: state.snapshot(now, self.started, &events[left_out..], left_out),
            };
            let Ok(bytes) = serde_json::to_vec(&envelope) else {
                break;
            };
            if bytes.len() <= budget {
                return bytes;
            }
            if left_out == events.len() {
                break;
            }
            let mut excess = bytes.len() - budget;
            while left_out < events.len() && excess > 0 {
                let size = serde_json::to_vec(&events[left_out]).map_or(0, |b| b.len()) + 1;
                excess = excess.saturating_sub(size);
                left_out += 1;
            }
        }
        TOO_LARGE.to_vec()
    }
}

impl HostObserver for Diagnostics {
    fn pause_started(&self, host: &str, cause: ErrorClass, http_status: u16, length: Duration) {
        let now = Instant::now();
        let mut state = self.lock();
        let Some(stats) = state.hosts.get_mut(host) else {
            return;
        };
        stats.pauses += 1;
        stats.paused_until = Some(now + length);
        stats.last_cause = Some(cause);
        stats.last_http_status = Some(http_status);
        let kind = EventKind::HostPaused {
            host: host.into(),
            cause,
            http_status,
            pause_s: secs(length),
        };
        state.push(now, kind);
    }

    fn pause_ended(&self, host: &str) {
        let now = Instant::now();
        let mut state = self.lock();
        let Some(stats) = state.hosts.get_mut(host) else {
            return;
        };
        stats.paused_until = None;
        state.push(now, EventKind::HostResumed { host: host.into() });
    }

    fn suppressed(&self, host: &str) {
        if let Some(stats) = self.lock().hosts.get_mut(host) {
            stats.suppressed += 1;
        }
    }
}

/// `text` with every http(s) URL cut to its host, every char outside
/// printable ASCII replaced by `?`, and at most [`MAX_DETAIL_CHARS`] chars.
pub fn sanitize_detail(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = url_start(rest) {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail.find(ends_url).unwrap_or(tail.len());
        let host = reqwest::Url::parse(&tail[..end])
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned));
        out.push_str(host.as_deref().unwrap_or("<url>"));
        rest = &tail[end..];
    }
    out.push_str(rest);
    let mut clean = printable_ascii(out.trim());
    if clean.len() > MAX_DETAIL_CHARS {
        clean.truncate(MAX_DETAIL_CHARS - ELLIPSIS.len());
        clean.push_str(ELLIPSIS);
    }
    clean
}

/// Marks a detail cut to [`MAX_DETAIL_CHARS`].
const ELLIPSIS: &str = "...";

fn url_start(text: &str) -> Option<usize> {
    // ASCII lowercasing keeps byte offsets.
    let lower = text.to_ascii_lowercase();
    ["http://", "https://"]
        .iter()
        .filter_map(|scheme| lower.find(scheme))
        .min()
}

/// Characters a URL cannot hold, plus the brackets error texts wrap URLs in.
fn ends_url(c: char) -> bool {
    c.is_whitespace()
        || c.is_control()
        || matches!(
            c,
            '"' | '\'' | '<' | '>' | '\\' | '^' | '`' | '{' | '|' | '}' | ')' | ']'
        )
}

fn secs(d: Duration) -> f64 {
    (d.as_secs_f64() * 10.0).round() / 10.0
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Serialize)]
struct Envelope<'a> {
    status: &'static str,
    diagnostics: Snapshot<'a>,
}

#[derive(Serialize)]
struct Snapshot<'a> {
    uptime_s: f64,
    cycles: CyclesView,
    assets: BTreeMap<&'a str, AssetView<'a>>,
    hosts: BTreeMap<&'a str, HostView>,
    ethrpc: EthRpcView<'a>,
    events: &'a [EventView<'a>],
    events_dropped: u64,
    events_truncated: usize,
}

#[derive(Serialize)]
struct CyclesView {
    count: u64,
    last_ms: Option<u64>,
    max_ms: Option<u64>,
    window: usize,
}

#[derive(Serialize)]
struct AssetView<'a> {
    signed: u64,
    skipped: u64,
    skipped_by_reason: SkipCounts,
    last_skip: Option<SkipReason>,
    since_signed_s: Option<f64>,
    last_signed_sources: Option<u8>,
    last_price: Option<f64>,
    last_cycle: Option<&'a AssetCycle>,
    sources: BTreeMap<&'a str, SourceView<'a>>,
}

#[derive(Serialize)]
struct SourceView<'a> {
    ok: u64,
    failed: u64,
    consecutive_failures: u64,
    outliers: u64,
    last: Option<&'a Outcome>,
    since_ok_s: Option<f64>,
    last_duration_ms: Option<u64>,
    last_attempts: Option<u32>,
}

#[derive(Serialize)]
struct HostView {
    pauses: u64,
    suppressed: u64,
    paused_for_s: Option<f64>,
    last_cause: Option<ErrorClass>,
    last_http_status: Option<u16>,
}

#[derive(Serialize)]
struct EthRpcView<'a> {
    rounds: u64,
    last_round: Option<RoundView>,
    operators: BTreeMap<&'a str, OperatorView<'a>>,
}

#[derive(Serialize)]
struct RoundView {
    accepted: usize,
    duration_ms: u64,
    age_s: f64,
}

#[derive(Serialize)]
struct OperatorView<'a> {
    age_s: f64,
    #[serde(flatten)]
    outcome: &'a OperatorOutcome,
}

#[derive(Serialize)]
struct EventView<'a> {
    age_s: f64,
    #[serde(flatten)]
    kind: &'a EventKind,
}

impl State {
    fn snapshot<'a>(
        &'a self,
        now: Instant,
        started: Instant,
        events: &'a [EventView<'a>],
        events_truncated: usize,
    ) -> Snapshot<'a> {
        let age = |at: Instant| secs(now.saturating_duration_since(at));
        let source_view = |stats: &'a SourceStats| SourceView {
            ok: stats.ok,
            failed: stats.failed,
            consecutive_failures: stats.consecutive_failures,
            outliers: stats.outliers,
            last: stats.last.as_ref(),
            since_ok_s: stats.last_ok.map(age),
            last_duration_ms: stats.last_spent.map(|spent| ms(spent.duration)),
            last_attempts: stats.last_spent.map(|spent| spent.attempts),
        };
        let assets = self
            .assets
            .iter()
            .map(|(symbol, stats)| {
                let view = AssetView {
                    signed: stats.signed,
                    skipped: stats.skipped,
                    skipped_by_reason: stats.skipped_by_reason,
                    last_skip: stats.last_skip,
                    since_signed_s: stats.last_signed.map(age),
                    last_signed_sources: stats.last_signed_sources,
                    last_price: stats.last_price,
                    last_cycle: stats.last_cycle.as_ref(),
                    sources: stats
                        .sources
                        .iter()
                        .map(|(name, s)| (name.as_str(), source_view(s)))
                        .collect(),
                };
                (symbol.as_str(), view)
            })
            .collect();
        let hosts = self
            .hosts
            .iter()
            .map(|(host, stats)| {
                let view = HostView {
                    pauses: stats.pauses,
                    suppressed: stats.suppressed,
                    paused_for_s: stats
                        .paused_until
                        .filter(|until| *until > now)
                        .map(|until| secs(until - now)),
                    last_cause: stats.last_cause,
                    last_http_status: stats.last_http_status,
                };
                (host.as_str(), view)
            })
            .collect();
        let ethrpc = EthRpcView {
            rounds: self.ethrpc.rounds,
            last_round: self.ethrpc.last_round.map(|round| RoundView {
                accepted: round.accepted,
                duration_ms: ms(round.duration),
                age_s: age(round.at),
            }),
            operators: self
                .ethrpc
                .operators
                .iter()
                .map(|(name, (at, outcome))| {
                    let view = OperatorView {
                        age_s: age(*at),
                        outcome,
                    };
                    (name.as_str(), view)
                })
                .collect(),
        };
        Snapshot {
            uptime_s: age(started),
            cycles: CyclesView {
                count: self.cycles,
                last_ms: self.recent_cycles.back().copied().map(ms),
                max_ms: self.recent_cycles.iter().max().copied().map(ms),
                window: self.recent_cycles.len(),
            },
            assets,
            hosts,
            ethrpc,
            events,
            events_dropped: self.events_dropped,
            events_truncated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::HttpError;
    use crate::types::load_assets;
    use serde_json::{json, Value};

    const BTC: &str = "BTC/USD";
    const HOST: &str = "api.example.com";

    fn asset() -> AssetConfig {
        serde_json::from_value(json!({
            "symbol": BTC,
            "min_sources": 2,
            "deviation_threshold_bps": 50,
            "heartbeat_seconds": 60,
            "sources": {
                "binance": { "pair": "BTCUSDT", "quote": "USDT" },
                "kraken": { "pair": "XBTUSD", "quote": "USD" }
            }
        }))
        .unwrap()
    }

    fn diag() -> Diagnostics {
        Diagnostics::new(&[asset()], &[HOST.to_string()])
    }

    fn read(diag: &Diagnostics) -> Value {
        let envelope: Value = serde_json::from_slice(&diag.response()).unwrap();
        assert_eq!(envelope["status"], "ok");
        envelope["diagnostics"].clone()
    }

    fn spent(millis: u64, attempts: u32) -> Spent {
        Spent {
            duration: Duration::from_millis(millis),
            attempts,
        }
    }

    fn http_failure(code: u16, preview: &str) -> eyre::Report {
        let error = RequestError {
            host: HOST.into(),
            attempts: 1,
            error: HttpError::Status {
                code,
                retry_after: None,
                preview: preview.into(),
            },
        };
        eyre::Report::new(error).wrap_err("binance BTCUSDT")
    }

    /// Failure `n`: 502 for even `n`, 503 for odd, so each one differs from the last.
    fn flapping(n: usize) -> eyre::Report {
        http_failure(502 + (n % 2) as u16, &format!("failure {n}"))
    }

    fn timeout() -> eyre::Report {
        eyre::Report::new(RequestError {
            host: HOST.into(),
            attempts: 1,
            error: HttpError::Timeout,
        })
    }

    fn event_names(got: &Value) -> Vec<&str> {
        got["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["event"].as_str().unwrap())
            .collect()
    }

    fn outlier(source: &str) -> OutlierDrop {
        OutlierDrop {
            source: source.into(),
            price: 95_000.0,
            deviation_bps: 412.5,
        }
    }

    fn keys(value: &Value) -> Vec<&str> {
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn the_json_shape_names_every_section() {
        let diag = diag();
        diag.source_ok(BTC, "binance", spent(120, 1));
        diag.source_failed(BTC, "kraken", &http_failure(503, "busy"), spent(1400, 2));
        diag.asset_signed(BTC, AssetCycle::new(PricePath::Rest, 1), 1, 91_000.5);
        diag.cycle_finished(Duration::from_millis(15_400));
        tokio::time::advance(Duration::from_secs(3)).await;
        let got = read(&diag);
        assert_eq!(
            keys(&got),
            [
                "assets",
                "cycles",
                "ethrpc",
                "events",
                "events_dropped",
                "events_truncated",
                "hosts",
                "uptime_s"
            ]
        );
        assert_eq!(got["uptime_s"], 3.0);
        assert_eq!(
            got["cycles"],
            json!({ "count": 1, "last_ms": 15400, "max_ms": 15400, "window": 1 })
        );
        let btc = &got["assets"][BTC];
        assert_eq!(btc["signed"], 1);
        assert_eq!(btc["since_signed_s"], 3.0);
        assert_eq!(btc["last_signed_sources"], 1);
        assert_eq!(
            btc["skipped_by_reason"],
            json!({
                "quorum_not_met": 0, "no_server_time": 0, "quorum_lost": 0, "pair_gap": 0,
                "no_prices_after_filtering": 0, "fixed_point_rejected": 0
            })
        );
        assert_eq!(
            btc["last_cycle"],
            json!({ "path": "rest", "responders": 1, "outliers": [], "skip": null })
        );
        assert_eq!(
            btc["sources"]["binance"],
            json!({
                "ok": 1, "failed": 0, "consecutive_failures": 0, "outliers": 0,
                "last": { "outcome": "ok" }, "since_ok_s": 3.0,
                "last_duration_ms": 120, "last_attempts": 1
            })
        );
        assert_eq!(
            btc["sources"]["kraken"]["last"],
            json!({
                "outcome": "failed", "class": "server_error", "http_status": 503,
                "detail": "binance BTCUSDT: HTTP 503 Service Unavailable from api.example.com: busy"
            })
        );
        assert_eq!(
            got["events"],
            json!([{
                "age_s": 3.0, "event": "source_failed", "asset": BTC, "source": "kraken",
                "class": "server_error", "http_status": 503, "attempts": 2,
                "detail": "binance BTCUSDT: HTTP 503 Service Unavailable from api.example.com: busy"
            }])
        );
        assert_eq!(
            got["hosts"][HOST],
            json!({ "pauses": 0, "suppressed": 0, "paused_for_s": null, "last_cause": null, "last_http_status": null })
        );
        assert_eq!(
            got["ethrpc"],
            json!({ "rounds": 0, "last_round": null, "operators": {} })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn keys_outside_the_config_are_never_added() {
        let diag = diag();
        diag.source_ok("ETH/USD", "binance", spent(1, 1));
        diag.source_ok(BTC, "okx", spent(1, 1));
        diag.asset_skipped(
            "ETH/USD",
            AssetCycle::new(PricePath::Rest, 0),
            SkipReason::NoServerTime,
        );
        diag.pause_started(
            "evil.example.com",
            ErrorClass::Blocked,
            403,
            Duration::from_secs(60),
        );
        diag.suppressed("evil.example.com");
        diag.operator("ethrpc_unknown", OperatorOutcome::Accepted { price_1e8: 1 });
        let got = read(&diag);
        assert_eq!(keys(&got["assets"]), [BTC]);
        assert_eq!(keys(&got["assets"][BTC]["sources"]), ["binance", "kraken"]);
        assert_eq!(keys(&got["hosts"]), [HOST]);
        assert_eq!(got["ethrpc"]["operators"], json!({}));
        assert_eq!(got["events"], json!([]));
    }

    #[tokio::test(start_paused = true)]
    async fn the_ring_keeps_the_newest_256_events_and_counts_the_rest() {
        let diag = diag();
        for n in 0..300 {
            diag.source_failed(BTC, "kraken", &flapping(n), spent(1, 1));
        }
        let got = read(&diag);
        let events = got["events"].as_array().unwrap();
        let detail = |i: usize| events[i]["detail"].as_str().unwrap().to_string();
        assert_eq!(events.len(), MAX_EVENTS);
        assert!(detail(0).ends_with(": failure 44"), "{}", detail(0));
        assert!(detail(MAX_EVENTS - 1).ends_with(": failure 299"));
        assert_eq!(got["events_dropped"], 44);
        assert_eq!(
            got["assets"][BTC]["sources"]["kraken"]["consecutive_failures"],
            300
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_paused_host_counts_a_failure_and_a_suppression_but_adds_no_event() {
        let diag = diag();
        let cooling = RequestError {
            host: HOST.into(),
            attempts: 0,
            error: HttpError::CoolingDown {
                remaining: Duration::from_secs(20),
                cause: ErrorClass::RateLimited,
            },
        };
        diag.pause_started(HOST, ErrorClass::RateLimited, 429, Duration::from_secs(30));
        diag.suppressed(HOST);
        diag.source_failed(BTC, "binance", &eyre::Report::new(cooling), spent(0, 0));
        tokio::time::advance(Duration::from_secs(10)).await;
        let got = read(&diag);
        assert_eq!(
            got["hosts"][HOST],
            json!({ "pauses": 1, "suppressed": 1, "paused_for_s": 20.0, "last_cause": "rate_limited", "last_http_status": 429 })
        );
        assert_eq!(
            got["assets"][BTC]["sources"]["binance"]["last"]["class"],
            "cooling_down"
        );
        assert_eq!(event_names(&got), ["host_paused"]);

        diag.pause_ended(HOST);
        let got = read(&diag);
        assert_eq!(got["hosts"][HOST]["paused_for_s"], Value::Null);
        assert_eq!(got["events"][1]["event"], "host_resumed");
    }

    #[tokio::test(start_paused = true)]
    async fn a_skip_records_its_reason_responders_and_outliers_in_order() {
        let diag = diag();
        let mut cycle = AssetCycle::new(PricePath::Rest, 2);
        cycle.outliers.push(outlier("kraken"));
        diag.asset_skipped(BTC, cycle, SkipReason::QuorumLost { have: 1, need: 2 });
        let got = read(&diag);
        let skip = json!({ "reason": "quorum_lost", "have": 1, "need": 2 });
        let btc = &got["assets"][BTC];
        assert_eq!((&btc["skipped"], &btc["last_skip"]), (&json!(1), &skip));
        assert_eq!(btc["skipped_by_reason"]["quorum_lost"], 1);
        assert_eq!(btc["sources"]["kraken"]["outliers"], 1);
        assert_eq!(btc["last_cycle"]["responders"], 2);
        assert_eq!(btc["last_cycle"]["skip"], skip);
        assert_eq!(
            btc["last_cycle"]["outliers"],
            json!([{ "source": "kraken", "price": 95000.0, "deviation_bps": 412.5 }])
        );
        assert_eq!(got["events"][0]["event"], "outlier_dropped");
        assert_eq!(got["events"][0]["deviation_bps"], 412.5);
        assert_eq!(got["events"][1]["event"], "asset_skipped");
        assert_eq!(got["events"][1]["skip"], skip);
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_failures_of_one_class_and_status_add_one_event_but_count_each() {
        let diag = diag();
        for _ in 0..5 {
            diag.source_failed(BTC, "kraken", &http_failure(503, "busy"), spent(1, 2));
        }
        let got = read(&diag);
        assert_eq!(event_names(&got), ["source_failed"]);
        let kraken = &got["assets"][BTC]["sources"]["kraken"];
        assert_eq!(
            (&kraken["failed"], &kraken["consecutive_failures"]),
            (&json!(5), &json!(5))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_of_another_class_or_status_adds_an_event() {
        let diag = diag();
        let failures = [
            http_failure(503, "a"),
            http_failure(503, "b"),
            http_failure(502, "c"),
            http_failure(404, "d"),
            timeout(),
            timeout(),
            eyre::eyre!("not json"),
        ];
        for failure in &failures {
            diag.source_failed(BTC, "kraken", failure, spent(1, 1));
        }
        let got = read(&diag);
        let seen: Vec<(Value, Value)> = got["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (e["class"].clone(), e["http_status"].clone()))
            .collect();
        let want = [
            ("server_error", json!(503)),
            ("server_error", json!(502)),
            ("client_error", json!(404)),
            ("timeout", Value::Null),
            ("bad_response", Value::Null),
        ];
        assert_eq!(seen, want.map(|(class, status)| (json!(class), status)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_success_after_failures_adds_a_recovery_with_their_count() {
        let diag = diag();
        for _ in 0..3 {
            diag.source_failed(BTC, "kraken", &timeout(), spent(1, 1));
        }
        diag.source_ok(BTC, "kraken", spent(1, 1));
        diag.source_ok(BTC, "kraken", spent(1, 1));
        diag.source_failed(BTC, "kraken", &timeout(), spent(1, 1));
        let got = read(&diag);
        assert_eq!(
            event_names(&got),
            ["source_failed", "source_recovered", "source_failed"]
        );
        assert_eq!(
            got["events"][1],
            json!({
                "age_s": 0.0, "event": "source_recovered", "asset": BTC, "source": "kraken",
                "consecutive_failures": 3
            })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_outlier_adds_an_event_only_when_it_was_not_one_the_cycle_before() {
        let diag = diag();
        let cycles: [&[&str]; 5] = [&["kraken"], &["kraken"], &["binance"], &[], &["kraken"]];
        for sources in cycles {
            let mut cycle = AssetCycle::new(PricePath::Rest, 2);
            cycle.outliers = sources.iter().map(|s| outlier(s)).collect();
            diag.asset_signed(BTC, cycle, 1, 91_000.0);
        }
        let got = read(&diag);
        let dropped: Vec<&str> = got["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["source"].as_str().unwrap())
            .collect();
        assert_eq!(dropped, ["kraken", "binance", "kraken"]);
        let sources = &got["assets"][BTC]["sources"];
        assert_eq!(
            (
                &sources["kraken"]["outliers"],
                &sources["binance"]["outliers"]
            ),
            (&json!(3), &json!(1))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_skip_adds_an_event_only_when_its_reason_changes_and_a_sign_ends_the_run() {
        let diag = diag();
        let skips = [
            SkipReason::QuorumLost { have: 1, need: 2 },
            SkipReason::QuorumLost { have: 0, need: 2 },
            SkipReason::QuorumLost { have: 1, need: 2 },
            SkipReason::PairGap {
                gap_bps: 80.0,
                limit_bps: 50,
            },
        ];
        for skip in skips {
            diag.asset_skipped(BTC, AssetCycle::new(PricePath::Rest, 1), skip);
        }
        for _ in 0..2 {
            diag.asset_signed(BTC, AssetCycle::new(PricePath::Rest, 2), 2, 91_000.0);
        }
        diag.asset_skipped(BTC, AssetCycle::new(PricePath::Rest, 1), skips[0]);
        let got = read(&diag);
        let events = got["events"].as_array().unwrap();
        let reasons: Vec<&Value> = events.iter().map(|e| &e["skip"]["reason"]).collect();
        assert_eq!(
            reasons,
            [
                &json!("quorum_lost"),
                &json!("pair_gap"),
                &Value::Null,
                &json!("quorum_lost")
            ]
        );
        assert_eq!(
            events[2],
            json!({ "age_s": 0.0, "event": "asset_resumed", "asset": BTC, "consecutive_skips": 4 })
        );
        let btc = &got["assets"][BTC];
        assert_eq!(btc["skipped"], 5);
        assert_eq!(
            btc["skipped_by_reason"],
            json!({
                "quorum_not_met": 0, "no_server_time": 0, "quorum_lost": 4, "pair_gap": 1,
                "no_prices_after_filtering": 0, "fixed_point_rejected": 0
            })
        );
    }

    #[test]
    fn every_skip_reason_has_its_own_tag_and_counter() {
        let reasons = [
            SkipReason::QuorumNotMet { have: 0, need: 2 },
            SkipReason::NoServerTime,
            SkipReason::QuorumLost { have: 1, need: 2 },
            SkipReason::PairGap {
                gap_bps: 80.0,
                limit_bps: 50,
            },
            SkipReason::NoPricesAfterFiltering,
            SkipReason::FixedPointRejected { median: -1.0 },
        ];
        let tags: Vec<Value> = reasons
            .iter()
            .map(|r| serde_json::to_value(r).unwrap()["reason"].clone())
            .collect();
        assert_eq!(
            tags,
            [
                "quorum_not_met",
                "no_server_time",
                "quorum_lost",
                "pair_gap",
                "no_prices_after_filtering",
                "fixed_point_rejected"
            ]
        );
        let mut counts = SkipCounts::default();
        for reason in reasons {
            counts.count(reason);
        }
        let counts = serde_json::to_value(counts).unwrap();
        let mut tags: Vec<&str> = tags.iter().map(|t| t.as_str().unwrap()).collect();
        tags.sort_unstable();
        assert_eq!(keys(&counts), tags);
        assert!(counts.as_object().unwrap().values().all(|n| n == 1));
    }

    #[tokio::test(start_paused = true)]
    async fn operators_and_rounds_keep_their_last_outcome() {
        let vusd: AssetConfig = serde_json::from_value(json!({
            "symbol": "VUSD/USD", "min_sources": 1, "deviation_threshold_bps": 50,
            "heartbeat_seconds": 3600,
            "sources": { "ethrpc_drpc": { "pair": "VUSD_NAV", "quote": "USD" } }
        }))
        .unwrap();
        let diag = Diagnostics::new(&[vusd], &[]);
        diag.operator(
            "ethrpc_drpc",
            OperatorOutcome::Rejected {
                reject: NavReject::RpcError,
                rpc_code: Some(-32005),
            },
        );
        diag.nav_round(7, Duration::from_millis(640));
        let got = read(&diag);
        assert_eq!(
            got["ethrpc"],
            json!({
                "rounds": 1,
                "last_round": { "accepted": 7, "duration_ms": 640, "age_s": 0.0 },
                "operators": { "ethrpc_drpc": {
                    "age_s": 0.0, "outcome": "rejected", "reject": "RPC_ERROR", "rpc_code": -32005
                } }
            })
        );
    }

    #[test]
    fn cycle_max_covers_only_the_last_32_cycles() {
        let diag = diag();
        diag.cycle_finished(Duration::from_secs(60));
        for _ in 0..CYCLE_WINDOW {
            diag.cycle_finished(Duration::from_secs(15));
        }
        let got = read(&diag);
        assert_eq!(
            got["cycles"],
            json!({ "count": 33, "last_ms": 15000, "max_ms": 15000, "window": 32 })
        );
    }

    #[test]
    fn a_url_in_a_detail_keeps_only_its_host() {
        let cases = [
            (
                "error sending request for url (https://api.coingecko.com/api/v3/simple/price?ids=a,b&key=s3cret)",
                "error sending request for url (api.coingecko.com)",
            ),
            (
                "GET HTTPS://User:pw@Api.Example.com:8443/v3/ticker?symbol=BTC#frag failed",
                "GET api.example.com failed",
            ),
            ("see http://10.0.0.1/admin and https:// now", "see 10.0.0.1 and <url> now"),
            ("no url here", "no url here"),
        ];
        for (raw, want) in cases {
            assert_eq!(sanitize_detail(raw), want, "{raw}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_reaches_the_response_without_its_url_path_or_query() {
        let diag = diag();
        let error = eyre::eyre!(
            "error sending request for url (https://api.example.com/v3/ticker?symbol=XBT&apikey=s3cret)"
        );
        let error = error.wrap_err("kraken XBTUSD");
        diag.source_failed(BTC, "kraken", &error, spent(1, 1));
        let text = String::from_utf8(diag.response()).unwrap();
        assert!(
            text.contains("error sending request for url (api.example.com)"),
            "{text}"
        );
        for leak in ["/v3/ticker", "symbol=XBT", "s3cret"] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
    }

    #[test]
    fn a_detail_is_cut_to_120_chars_ending_in_an_ascii_ellipsis() {
        let long = sanitize_detail(&"é".repeat(500));
        assert_eq!(long, format!("{}...", "?".repeat(117)));
        assert_eq!(
            sanitize_detail(&"x".repeat(121)),
            format!("{}...", "x".repeat(117))
        );
        assert_eq!(sanitize_detail(&"x".repeat(120)), "x".repeat(120));
    }

    #[test]
    fn every_char_outside_printable_ascii_becomes_a_question_mark() {
        let cases = [
            (
                "line one\nline\ttwo\u{1b}[31m\r\n",
                "line one?line?two?[31m",
            ),
            ("a\u{0}b\u{7f}c\u{85}d", "a?b?c?d"),
            ("price \u{202e}0001\u{202c} ok", "price ?0001? ok"),
            ("Ошибка café", "?????? caf?"),
            ("down 😀👍🏽 now", "down ??? now"),
            (" !~ printable ASCII stays ", "!~ printable ASCII stays"),
        ];
        for (raw, want) in cases {
            assert_eq!(sanitize_detail(raw), want, "{raw:?}");
        }
    }

    /// The bundled config after a year of uptime: every pair failed with the
    /// widest detail, every host paused, every counter at its type maximum and
    /// a full ring of the widest event, pushed directly since repeats add none.
    async fn worst_case() -> Diagnostics {
        let config = load_assets().unwrap();
        let diag = Diagnostics::new(&config.assets, &config.exchange_hostnames);
        let wide = eyre::eyre!("{}", "\"".repeat(MAX_DETAIL_CHARS));
        let pair_gap = SkipReason::PairGap {
            gap_bps: f64::MAX,
            limit_bps: u16::MAX,
        };
        for asset in &config.assets {
            for source in asset.sources.keys() {
                diag.source_ok(&asset.symbol, source, spent(1, 1));
            }
            let signed = AssetCycle::new(PricePath::Rest, asset.sources.len());
            diag.asset_signed(&asset.symbol, signed, u8::MAX, f64::MAX);
        }
        tokio::time::advance(Duration::from_secs(365 * 86_400)).await;
        for asset in &config.assets {
            for source in asset.sources.keys() {
                diag.source_failed(&asset.symbol, source, &wide, spent(u64::MAX, u32::MAX));
                diag.operator(
                    source,
                    OperatorOutcome::Rejected {
                        reject: NavReject::AmoShareExceeded,
                        rpc_code: Some(i64::MIN),
                    },
                );
            }
            let mut cycle = AssetCycle::new(PricePath::Rest, usize::MAX);
            cycle.outliers = asset
                .sources
                .keys()
                .map(|source| OutlierDrop {
                    source: source.clone(),
                    price: f64::MAX,
                    deviation_bps: f64::MAX,
                })
                .collect();
            diag.asset_skipped(&asset.symbol, cycle, pair_gap);
        }
        for host in &config.exchange_hostnames {
            let length = Duration::from_secs(600);
            diag.pause_started(host, ErrorClass::RateLimited, 429, length);
        }
        diag.nav_round(usize::MAX, Duration::from_millis(u64::MAX));
        for _ in 0..CYCLE_WINDOW {
            diag.cycle_finished(Duration::from_millis(u64::MAX));
        }
        let (asset, source) = config
            .assets
            .iter()
            .flat_map(|a| {
                a.sources
                    .keys()
                    .map(move |s| (a.symbol.as_str(), s.as_str()))
            })
            .max_by_key(|(a, s)| a.len() + s.len())
            .unwrap();
        let widest = EventKind::SourceFailed {
            asset: asset.into(),
            source: source.into(),
            class: ErrorClass::ServerError,
            http_status: Some(u16::MAX),
            attempts: u32::MAX,
            detail: sanitize_detail(&format!("{wide}")),
        };
        let mut state = diag.lock();
        for _ in 0..MAX_EVENTS {
            state.push(diag.started, widest.clone());
        }
        state.cycles = u64::MAX;
        state.events_dropped = u64::MAX;
        state.ethrpc.rounds = u64::MAX;
        for host in state.hosts.values_mut() {
            (host.pauses, host.suppressed) = (u64::MAX, u64::MAX);
        }
        for asset in state.assets.values_mut() {
            (asset.signed, asset.skipped) = (u64::MAX, u64::MAX);
            asset.skipped_by_reason = SkipCounts {
                quorum_not_met: u64::MAX,
                no_server_time: u64::MAX,
                quorum_lost: u64::MAX,
                pair_gap: u64::MAX,
                no_prices_after_filtering: u64::MAX,
                fixed_point_rejected: u64::MAX,
            };
            for source in asset.sources.values_mut() {
                source.ok = u64::MAX;
                source.failed = u64::MAX;
                source.consecutive_failures = u64::MAX;
                source.outliers = u64::MAX;
            }
        }
        drop(state);
        diag
    }

    #[tokio::test(start_paused = true)]
    async fn the_worst_case_response_fits_the_limit_with_every_event() {
        let diag = worst_case().await;
        let bytes = diag.response();
        let got: Value = serde_json::from_slice(&bytes).unwrap();
        let events = got["diagnostics"]["events"].as_array().unwrap();
        assert_eq!(
            got["diagnostics"]["events_truncated"],
            0,
            "{} bytes",
            bytes.len()
        );
        assert_eq!(events.len(), MAX_EVENTS);
        assert_eq!(
            events[0]["detail"].as_str().unwrap().len(),
            MAX_DETAIL_CHARS
        );
        assert!(bytes.len() <= MAX_RESPONSE_BYTES, "{} bytes", bytes.len());
    }

    #[tokio::test(start_paused = true)]
    async fn an_over_budget_response_leaves_out_the_oldest_events_first() {
        let diag = diag();
        for n in 0..50 {
            diag.source_failed(BTC, "kraken", &flapping(n), spent(1, 1));
        }
        let full = diag.response();
        let budget = full.len() - 1000;
        let bytes = diag.response_within(budget);
        assert!(bytes.len() <= budget);
        let got: Value = serde_json::from_slice(&bytes).unwrap();
        let events = got["diagnostics"]["events"].as_array().unwrap();
        let truncated = got["diagnostics"]["events_truncated"].as_u64().unwrap();
        assert!(truncated > 0);
        assert_eq!(events.len() as u64 + truncated, 50);
        let last = events.last().unwrap()["detail"].as_str().unwrap();
        assert!(last.ends_with(": failure 49"), "{last}");
        assert_eq!(diag.response_within(10), TOO_LARGE);
    }
}
