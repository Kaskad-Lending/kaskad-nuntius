//! volume-monitor — standalone WS trade-volume monitor for the venues in
//! `config/exchanges.json`.
//!
//! Connects to each venue the same way the kaskad-nuntius collectors do
//! (same endpoints, same handshake/keepalive quirks) but subscribes to the
//! public TRADE streams, accumulates observed volume per (venue, pair), and
//! periodically persists a JSON state file. At the end of the run (or via
//! `--report <state.json>` at any time) it prints a per-pair comparison
//! table including each venue's REST-reported 24h volume.
//!
//! Usage:
//!   volume-monitor [--config config/exchanges.json] [--out volmon-out]
//!                  [--duration-secs 86400] [--print-every-secs 300]
//!                  [--venues a,b,c] [--bases TAO,BTC]
//!   volume-monitor --report volmon-out/state.json
//!
//! Terminal quickstart: `./run.sh 1h` (live tables every 5 min, Ctrl-C safe).

use eyre::{eyre, Result, WrapErr};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;

mod rest;
mod types;
mod util;
mod venues;

use types::{Event, EventTx, VenueCfg};
use util::{canon_pair, now_ms};

const RECONNECT_BACKOFF: Duration = Duration::from_secs(5); // same as the collector manager
const SNAPSHOT_EVERY: Duration = Duration::from_secs(30);
/// Trades whose exchange timestamp is older than this at ingest are counted
/// separately and NOT added to volume — guards against venues replaying
/// historical trades on (re)connect.
const STALE_MS: i64 = 10 * 60 * 1000;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Bucket {
    trades: u64,
    base: f64,
    quote: f64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct PairStats {
    trades: u64,
    /// Σ qty (base asset units).
    base: f64,
    /// Σ price × qty (quote/USDT units).
    quote: f64,
    first_trade_ms: Option<i64>,
    last_trade_ms: Option<i64>,
    /// Trades dropped because their exchange timestamp was > STALE_MS old
    /// at ingest (likely a replay/snapshot not filtered upstream).
    stale_dropped: u64,
    /// UTC hour ("2026-07-19T15") → bucket.
    hourly: BTreeMap<String, Bucket>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct VenueStats {
    connected: bool,
    sessions: u64,
    reconnects: u64,
    last_event_ms: i64,
    last_error: Option<String>,
    pairs: BTreeMap<String, PairStats>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct State {
    started_at_ms: i64,
    updated_at_ms: i64,
    planned_duration_secs: u64,
    /// Incremented when a 30s snapshot interval fires >2min late on the
    /// wall clock — i.e. the host likely slept and volume was lost.
    #[serde(default)]
    suspected_sleep_gaps: u64,
    venues: BTreeMap<String, VenueStats>,
}

struct Args {
    config: PathBuf,
    out: PathBuf,
    duration_secs: u64,
    /// Print live comparison tables to stdout every N seconds (0 = off).
    print_every_secs: u64,
    venues: Option<Vec<String>>,
    bases: Option<Vec<String>>,
    report: Option<PathBuf>,
}

const USAGE: &str = "\
usage: volume-monitor [--config config/exchanges.json] [--out volmon-out]
                      [--duration-secs 86400] [--print-every-secs 300]
                      [--venues a,b,c] [--bases TAO,BTC]
       volume-monitor --report volmon-out/state.json";

fn parse_args() -> Result<Args> {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from<I>(argv: I) -> Result<Args>
where
    I: IntoIterator<Item = String>,
{
    let mut args = Args {
        config: PathBuf::from("config/exchanges.json"),
        out: PathBuf::from("volmon-out"),
        duration_secs: 86_400,
        print_every_secs: 300,
        venues: None,
        bases: None,
        report: None,
    };
    let mut it = argv.into_iter();
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().ok_or_else(|| eyre!("missing value for {name}"));
        match a.as_str() {
            "--config" => args.config = PathBuf::from(val("--config")?),
            "--out" => args.out = PathBuf::from(val("--out")?),
            "--duration-secs" => {
                args.duration_secs = val("--duration-secs")?
                    .parse()
                    .wrap_err("--duration-secs")?
            }
            "--print-every-secs" => {
                args.print_every_secs = val("--print-every-secs")?
                    .parse()
                    .wrap_err("--print-every-secs")?
            }
            "--venues" => {
                args.venues = Some(
                    val("--venues")?
                        .split(',')
                        .map(|s| s.trim().to_lowercase())
                        .filter(|s| !s.is_empty())
                        .collect(),
                )
            }
            "--bases" => {
                args.bases = Some(
                    val("--bases")?
                        .split(',')
                        .map(|s| s.trim().to_uppercase())
                        .filter(|s| !s.is_empty())
                        .collect(),
                )
            }
            "--report" => args.report = Some(PathBuf::from(val("--report")?)),
            "--help" | "-h" => {
                eprintln!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(eyre!("unknown arg: {other}")),
        }
    }
    Ok(args)
}

fn log(msg: &str) {
    eprintln!("{} {msg}", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"));
}

fn load_venues(args: &Args) -> Result<Vec<VenueCfg>> {
    let raw = std::fs::read_to_string(&args.config)
        .wrap_err_with(|| format!("read {}", args.config.display()))?;
    let all: Vec<VenueCfg> = serde_json::from_str(&raw).wrap_err("parse exchanges.json")?;
    let mut out = Vec::new();
    for mut v in all {
        if !v.enabled {
            continue;
        }
        let requested = match &args.venues {
            Some(filter) => {
                if !filter.contains(&v.name.to_lowercase()) {
                    continue;
                }
                true
            }
            None => false,
        };
        if !venues::supported(&v.name) {
            // Only worth a warning when the venue was named via --venues;
            // otherwise unimplemented config entries are skipped silently.
            if requested {
                log(&format!(
                    "WARN: venue {} requested but not implemented — skipped",
                    v.name
                ));
            }
            continue;
        }
        if let Some(bases) = &args.bases {
            v.pairs.retain(|p| bases.contains(&canon_pair(p).0));
        }
        if v.pairs.is_empty() {
            continue;
        }
        out.push(v);
    }
    if out.is_empty() {
        return Err(eyre!("no venues to monitor after filtering"));
    }
    Ok(out)
}

fn write_state(path: &Path, state: &State) {
    let tmp = path.with_extension("json.tmp");
    if let Ok(s) = serde_json::to_string_pretty(state) {
        if std::fs::write(&tmp, s).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

async fn venue_task(cfg: VenueCfg, tx: EventTx) {
    loop {
        let started = now_ms();
        let res = venues::run_session(&cfg, &tx).await;
        let err = match res {
            Ok(()) => "session ended cleanly".to_string(),
            Err(e) => format!("{e:#}"),
        };
        let _ = tx.send(Event::SessionEnd {
            venue: cfg.name.clone(),
            error: format!("{err} (session lasted {}s)", (now_ms() - started) / 1000),
        });
        tokio::time::sleep(RECONNECT_BACKOFF).await;
    }
}

fn apply_event(state: &mut State, ev: Event) {
    let now = now_ms();
    match ev {
        Event::Connected { venue } => {
            let vs = state.venues.entry(venue.clone()).or_default();
            vs.connected = true;
            vs.sessions += 1;
            vs.last_event_ms = now;
            log(&format!("[{venue}] connected (session #{})", vs.sessions));
        }
        Event::SessionEnd { venue, error } => {
            let vs = state.venues.entry(venue.clone()).or_default();
            vs.connected = false;
            vs.reconnects += 1;
            vs.last_event_ms = now;
            log(&format!("[{venue}] session ended: {error} — reconnecting"));
            vs.last_error = Some(error);
        }
        Event::Trade(t) => {
            let vs = state.venues.entry(t.venue.clone()).or_default();
            vs.last_event_ms = now;
            let ps = vs.pairs.entry(t.pair.clone()).or_default();
            let ts = if t.ts_ms > 0 { t.ts_ms } else { now };
            if now - ts > STALE_MS {
                ps.stale_dropped += 1;
                return;
            }
            ps.trades += 1;
            ps.base += t.qty_base;
            ps.quote += t.qty_base * t.price;
            ps.first_trade_ms.get_or_insert(ts);
            ps.last_trade_ms = Some(ts);
            let hour = chrono::DateTime::from_timestamp_millis(ts)
                .map(|d| d.format("%Y-%m-%dT%H").to_string())
                .unwrap_or_else(|| "?".into());
            let b = ps.hourly.entry(hour).or_default();
            b.trades += 1;
            b.base += t.qty_base;
            b.quote += t.qty_base * t.price;
        }
    }
}

fn fmt_usd(v: f64) -> String {
    if v >= 1_000_000.0 {
        format!("${:.2}M", v / 1_000_000.0)
    } else if v >= 1_000.0 {
        format!("${:.1}k", v / 1_000.0)
    } else {
        format!("${v:.0}")
    }
}

type RepMap = std::collections::HashMap<(String, String), rest::Reported>;

/// Fetch every venue's REST-reported 24h volume, concurrently.
async fn fetch_reported(state: &State) -> RepMap {
    let futs: Vec<_> = state
        .venues
        .iter()
        .flat_map(|(venue, vs)| {
            vs.pairs.keys().map(move |pair| {
                let v = venue.clone();
                let p = pair.clone();
                async move {
                    let r = rest::reported(&v, &p).await.unwrap_or_default();
                    ((v, p), r)
                }
            })
        })
        .collect();
    futures::future::join_all(futs).await.into_iter().collect()
}

/// Render the comparison tables. `rep == None` (live snapshots) leaves the
/// venue-reported columns as "—" instead of hitting REST every 5 minutes.
fn render_report(state: &State, rep: Option<&RepMap>) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let elapsed_ms = (state.updated_at_ms - state.started_at_ms).max(1);
    let elapsed_h = elapsed_ms as f64 / 3_600_000.0;
    let scale_24h = 24.0 / elapsed_h;
    let _ = writeln!(
        out,
        "# volume-monitor — {:.2}h observed / {:.2}h planned (started {})\n",
        elapsed_h,
        state.planned_duration_secs as f64 / 3600.0,
        chrono::DateTime::from_timestamp_millis(state.started_at_ms)
            .map(|d| d.to_rfc3339())
            .unwrap_or_default()
    );
    if state.suspected_sleep_gaps > 0 {
        let _ = writeln!(
            out,
            "**WARNING: {} suspected host-sleep gap(s) — volume during those windows was NOT captured; observed totals are an undercount.**\n",
            state.suspected_sleep_gaps
        );
    }

    // Group rows by canonical base asset.
    let mut by_base: BTreeMap<String, Vec<(String, String, PairStats)>> = BTreeMap::new();
    for (venue, vs) in &state.venues {
        for (pair, ps) in &vs.pairs {
            let (base, _) = canon_pair(pair);
            by_base
                .entry(base)
                .or_default()
                .push((venue.clone(), pair.clone(), ps.clone()));
        }
    }

    for (base, mut rows) in by_base {
        rows.sort_by(|a, b| b.2.quote.total_cmp(&a.2.quote));
        let total_quote: f64 = rows.iter().map(|r| r.2.quote).sum();
        let quote = rows
            .first()
            .map(|r| canon_pair(&r.1).1)
            .filter(|q| !q.is_empty())
            .unwrap_or_else(|| "USDT".into());
        let _ = writeln!(
            out,
            "## {base}/{quote} — {} venues, total {} observed ({} extrapolated 24h)\n",
            rows.len(),
            fmt_usd(total_quote),
            fmt_usd(total_quote * scale_24h)
        );
        let _ = writeln!(out, "| venue | trades | base vol | USD vol | share | 24h extrap. | venue-reported 24h | obs/rep | stale-dropped |");
        let _ = writeln!(out, "|---|---|---|---|---|---|---|---|---|");
        for (venue, pair, ps) in &rows {
            let r = rep.and_then(|m| m.get(&(venue.clone(), pair.clone())));
            let rep_quote = r.and_then(|r| {
                // No quote volume reported: approximate with the observed
                // VWAP. Without observed volume there is no conversion
                // rate, so the column stays "—" rather than claiming $0.
                r.quote.or_else(|| {
                    if ps.base > 0.0 {
                        r.base.map(|b| b * (ps.quote / ps.base))
                    } else {
                        None
                    }
                })
            });
            let ratio = match rep_quote {
                Some(rq) if rq > 0.0 => format!("{:.0}%", ps.quote * scale_24h / rq * 100.0),
                _ => "—".into(),
            };
            let _ = writeln!(
                out,
                "| {venue} | {} | {:.3} | {} | {:.1}% | {} | {} | {ratio} | {} |",
                ps.trades,
                ps.base,
                fmt_usd(ps.quote),
                if total_quote > 0.0 {
                    ps.quote / total_quote * 100.0
                } else {
                    0.0
                },
                fmt_usd(ps.quote * scale_24h),
                rep_quote.map(fmt_usd).unwrap_or_else(|| "—".into()),
                ps.stale_dropped,
            );
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "## connection health\n");
    let _ = writeln!(
        out,
        "| venue | connected | sessions | reconnects | last error |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|");
    for (venue, vs) in &state.venues {
        let _ = writeln!(
            out,
            "| {venue} | {} | {} | {} | {} |",
            vs.connected,
            vs.sessions,
            vs.reconnects,
            vs.last_error.as_deref().unwrap_or("—").replace('|', "/"),
        );
    }
    out
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;

    if let Some(path) = &args.report {
        let raw =
            std::fs::read_to_string(path).wrap_err_with(|| format!("read {}", path.display()))?;
        let state: State = serde_json::from_str(&raw).wrap_err("parse state file")?;
        let rep = fetch_reported(&state).await;
        println!("{}", render_report(&state, Some(&rep)));
        return Ok(());
    }

    let cfgs = load_venues(&args)?;
    std::fs::create_dir_all(&args.out)
        .wrap_err_with(|| format!("create {}", args.out.display()))?;
    let state_path = args.out.join("state.json");
    log(&format!(
        "monitoring {} venues for {}s → {}",
        cfgs.len(),
        args.duration_secs,
        state_path.display()
    ));
    for c in &cfgs {
        log(&format!("  {} — pairs: {}", c.name, c.pairs.join(", ")));
    }

    let mut state = State {
        started_at_ms: now_ms(),
        updated_at_ms: now_ms(),
        planned_duration_secs: args.duration_secs,
        ..Default::default()
    };
    // Seed every configured (venue, pair) so a pair that never trades (or
    // whose subscription silently fails) shows up as an explicit zero row
    // in the report instead of being invisible.
    for cfg in &cfgs {
        let vs = state.venues.entry(cfg.name.clone()).or_default();
        for p in &cfg.pairs {
            vs.pairs.entry(p.clone()).or_default();
        }
    }

    let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
    let mut handles = Vec::new();
    for cfg in cfgs {
        handles.push(tokio::spawn(venue_task(cfg, tx.clone())));
    }
    drop(tx);
    // Deadline is tracked on the WALL clock, not only tokio's monotonic
    // clock: macOS pauses the monotonic clock during system sleep, which
    // would silently stretch the run (observed live: a 180s run lasted
    // 371s across a sleep window). The monotonic sleep remains as the
    // wake-up source; the wall check decides.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.duration_secs);
    let wall_deadline_ms = state.started_at_ms + args.duration_secs as i64 * 1000;
    let mut snap = tokio::time::interval(SNAPSHOT_EVERY);
    snap.tick().await;
    let mut last_snap_wall = now_ms();
    // Live progress tables on stdout (0 = disabled).
    let live_every = Duration::from_secs(args.print_every_secs.max(1));
    let mut live = tokio::time::interval(live_every);
    live.tick().await;
    // SIGINT listener created once, outside select!: tokio only observes
    // signals delivered while a listener exists, and the first poll
    // replaces the default disposition, so a per-iteration ctrl_c()
    // future drops any Ctrl-C arriving between select! polls (caffeinate
    // swallows the group SIGINT, so nothing else stops the run).
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        let now = now_ms();
        // A wall-clock jump of >2min since the last snapshot means the
        // host slept (macOS pauses the monotonic clock during sleep) and
        // volume during the gap was lost. Checked here, before the
        // deadline break, so a sleep that overshoots the deadline still
        // flags the final report.
        if now - last_snap_wall > 120_000 {
            state.suspected_sleep_gaps += 1;
            log(&format!(
                "WARN: wall-clock jump of {}s between snapshots — suspected host sleep; volume during the gap was not captured",
                (now - last_snap_wall) / 1000
            ));
            last_snap_wall = now;
        }
        if now >= wall_deadline_ms {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            _ = &mut ctrl_c => {
                log("interrupted (Ctrl-C) — writing final report");
                break;
            }
            _ = live.tick(), if args.print_every_secs > 0 => {
                state.updated_at_ms = now_ms();
                println!(
                    "\n-------- progress {} --------\n{}",
                    chrono::Utc::now().format("%H:%M:%SZ"),
                    render_report(&state, None)
                );
            }
            _ = snap.tick() => {
                last_snap_wall = now_ms();
                state.updated_at_ms = last_snap_wall;
                write_state(&state_path, &state);
            }
            ev = rx.recv() => match ev {
                Some(ev) => apply_event(&mut state, ev),
                None => break,
            }
        }
    }

    for h in &handles {
        h.abort();
    }
    // Drain events already queued at the cutoff so the final totals
    // include every trade observed before the break.
    while let Ok(ev) = rx.try_recv() {
        apply_event(&mut state, ev);
    }
    state.updated_at_ms = now_ms();
    write_state(&state_path, &state);
    log("run complete — fetching venue-reported 24h volumes for comparison");
    let rep = fetch_reported(&state).await;
    let report = render_report(&state, Some(&rep));
    let report_path = args.out.join("report-final.md");
    if let Err(e) = std::fs::write(&report_path, &report) {
        log(&format!(
            "WARN: could not write {}: {e}",
            report_path.display()
        ));
    }
    println!("{report}");
    log(&format!("final report saved to {}", report_path.display()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pa(argv: &[&str]) -> Result<Args> {
        parse_args_from(argv.iter().map(|s| s.to_string()))
    }

    #[test]
    fn parse_args_defaults() {
        let a = pa(&[]).unwrap();
        assert_eq!(a.config, PathBuf::from("config/exchanges.json"));
        assert_eq!(a.out, PathBuf::from("volmon-out"));
        assert_eq!(a.duration_secs, 86_400);
        assert_eq!(a.print_every_secs, 300);
        assert!(a.venues.is_none());
        assert!(a.bases.is_none());
        assert!(a.report.is_none());
    }

    #[test]
    fn parse_args_all_flags() {
        let a = pa(&[
            "--config",
            "c.json",
            "--out",
            "o",
            "--duration-secs",
            "60",
            "--print-every-secs",
            "0",
            "--venues",
            "Binance, gate,",
            "--bases",
            "tao,BTC,",
            "--report",
            "s.json",
        ])
        .unwrap();
        assert_eq!(a.config, PathBuf::from("c.json"));
        assert_eq!(a.out, PathBuf::from("o"));
        assert_eq!(a.duration_secs, 60);
        assert_eq!(a.print_every_secs, 0);
        // Venue names are lowercased/trimmed, bases uppercased/trimmed,
        // empty segments dropped.
        assert_eq!(
            a.venues,
            Some(vec!["binance".to_string(), "gate".to_string()])
        );
        assert_eq!(a.bases, Some(vec!["TAO".to_string(), "BTC".to_string()]));
        assert_eq!(a.report, Some(PathBuf::from("s.json")));
    }

    #[test]
    fn parse_args_unknown_flag_errors() {
        assert!(pa(&["--bogus"]).is_err());
    }

    #[test]
    fn parse_args_missing_value_errors() {
        assert!(pa(&["--duration-secs"]).is_err());
        assert!(pa(&["--duration-secs", "abc"]).is_err());
    }

    fn trade(venue: &str, pair: &str, price: f64, qty: f64, ts: i64) -> Event {
        Event::Trade(types::Trade {
            venue: venue.into(),
            pair: pair.into(),
            price,
            qty_base: qty,
            ts_ms: ts,
        })
    }

    #[test]
    fn apply_event_accumulates_and_buckets_hourly() {
        let mut st = State::default();
        let now = now_ms();
        apply_event(&mut st, trade("v", "TAO_USDT", 100.0, 2.0, now));
        apply_event(&mut st, trade("v", "TAO_USDT", 200.0, 1.0, now));
        // Exactly one hour ahead: always a distinct hourly key, still
        // fresh under the stale filter (now - ts is negative).
        apply_event(&mut st, trade("v", "TAO_USDT", 300.0, 1.0, now + 3_600_000));
        let ps = &st.venues["v"].pairs["TAO_USDT"];
        assert_eq!(ps.trades, 3);
        assert!((ps.base - 4.0).abs() < 1e-9);
        assert!((ps.quote - 700.0).abs() < 1e-9);
        assert_eq!(ps.first_trade_ms, Some(now));
        assert_eq!(ps.last_trade_ms, Some(now + 3_600_000));
        assert_eq!(ps.stale_dropped, 0);
        assert_eq!(ps.hourly.len(), 2);
        let buckets: Vec<&Bucket> = ps.hourly.values().collect();
        assert_eq!(buckets[0].trades, 2);
        assert!((buckets[0].base - 3.0).abs() < 1e-9);
        assert!((buckets[0].quote - 400.0).abs() < 1e-9);
        assert_eq!(buckets[1].trades, 1);
        assert!((buckets[1].quote - 300.0).abs() < 1e-9);
    }

    #[test]
    fn apply_event_drops_stale_trades() {
        let mut st = State::default();
        let now = now_ms();
        apply_event(
            &mut st,
            trade("v", "TAO_USDT", 100.0, 2.0, now - STALE_MS - 60_000),
        );
        let ps = &st.venues["v"].pairs["TAO_USDT"];
        assert_eq!(ps.stale_dropped, 1);
        assert_eq!(ps.trades, 0);
        assert_eq!(ps.base, 0.0);
        assert_eq!(ps.quote, 0.0);
        assert!(ps.first_trade_ms.is_none());
        assert!(ps.hourly.is_empty());
    }

    #[test]
    fn apply_event_zero_ts_falls_back_to_now() {
        let mut st = State::default();
        let before = now_ms();
        apply_event(&mut st, trade("v", "TAO_USDT", 10.0, 1.5, 0));
        let after = now_ms();
        let ps = &st.venues["v"].pairs["TAO_USDT"];
        assert_eq!(ps.trades, 1);
        assert_eq!(ps.stale_dropped, 0);
        let ts = ps.last_trade_ms.unwrap();
        assert!(ts >= before && ts <= after);
        assert_eq!(ps.first_trade_ms, Some(ts));
    }

    #[test]
    fn apply_event_session_counters() {
        let mut st = State::default();
        apply_event(&mut st, Event::Connected { venue: "v".into() });
        assert!(st.venues["v"].connected);
        assert_eq!(st.venues["v"].sessions, 1);
        assert_eq!(st.venues["v"].reconnects, 0);
        apply_event(
            &mut st,
            Event::SessionEnd {
                venue: "v".into(),
                error: "boom".into(),
            },
        );
        assert!(!st.venues["v"].connected);
        assert_eq!(st.venues["v"].reconnects, 1);
        assert_eq!(st.venues["v"].last_error.as_deref(), Some("boom"));
        apply_event(&mut st, Event::Connected { venue: "v".into() });
        assert!(st.venues["v"].connected);
        assert_eq!(st.venues["v"].sessions, 2);
    }

    #[test]
    fn fmt_usd_boundaries() {
        assert_eq!(fmt_usd(0.0), "$0");
        assert_eq!(fmt_usd(999.0), "$999");
        assert_eq!(fmt_usd(1_000.0), "$1.0k");
        assert_eq!(fmt_usd(1_550.0), "$1.6k");
        assert_eq!(fmt_usd(999_900.0), "$999.9k");
        assert_eq!(fmt_usd(1_000_000.0), "$1.00M");
        assert_eq!(fmt_usd(2_350_000.0), "$2.35M");
    }

    fn mk_ps(trades: u64, base: f64, quote: f64) -> PairStats {
        PairStats {
            trades,
            base,
            quote,
            ..Default::default()
        }
    }

    #[test]
    fn render_report_shares_extrapolation_and_dash_columns() {
        let mut st = State {
            started_at_ms: 1_752_940_800_000,
            updated_at_ms: 1_752_940_800_000 + 6 * 3_600_000, // 6h → ×4
            planned_duration_secs: 86_400,
            ..Default::default()
        };
        st.venues
            .entry("a".into())
            .or_default()
            .pairs
            .insert("TAO_USDT".into(), mk_ps(10, 1.0, 750.0));
        st.venues
            .entry("b".into())
            .or_default()
            .pairs
            .insert("TAOUSDT".into(), mk_ps(5, 0.5, 250.0));
        let out = render_report(&st, None);
        assert!(out.contains("6.00h observed / 24.00h planned"));
        assert!(
            out.contains("## TAO/USDT — 2 venues, total $1.0k observed ($4.0k extrapolated 24h)")
        );
        // rep == None: venue-reported and obs/rep columns are dashes.
        assert!(out.contains("| a | 10 | 1.000 | $750 | 75.0% | $3.0k | — | — | 0 |"));
        assert!(out.contains("| b | 5 | 0.500 | $250 | 25.0% | $1.0k | — | — | 0 |"));
        assert!(out.contains("## connection health"));
    }

    #[test]
    fn render_report_zero_row() {
        let mut st = State {
            started_at_ms: 0,
            updated_at_ms: 3_600_000, // 1h → ×24
            ..Default::default()
        };
        st.venues
            .entry("a".into())
            .or_default()
            .pairs
            .insert("KAS_USDT".into(), PairStats::default());
        let out = render_report(&st, None);
        assert!(out.contains("## KAS/USDT — 1 venues, total $0 observed ($0 extrapolated 24h)"));
        assert!(out.contains("| a | 0 | 0.000 | $0 | 0.0% | $0 | — | — | 0 |"));
    }

    #[test]
    fn render_report_reported_columns() {
        let mut st = State {
            started_at_ms: 0,
            updated_at_ms: 12 * 3_600_000, // 12h → ×2
            ..Default::default()
        };
        st.venues
            .entry("a".into())
            .or_default()
            .pairs
            .insert("TAO_USDT".into(), mk_ps(4, 10.0, 1_000.0));
        // base-only report with observed VWAP available (1000/4 = 250):
        st.venues
            .entry("c".into())
            .or_default()
            .pairs
            .insert("TAO-USDT".into(), mk_ps(2, 4.0, 400.0));
        // base-only report with NO observed volume: no VWAP to convert
        // with, so the reported column must stay "—", not "$0".
        st.venues
            .entry("b".into())
            .or_default()
            .pairs
            .insert("TAOUSDT".into(), PairStats::default());
        let mut rep = RepMap::new();
        rep.insert(
            ("a".into(), "TAO_USDT".into()),
            rest::Reported {
                base: None,
                quote: Some(4_000.0),
            },
        );
        rep.insert(
            ("c".into(), "TAO-USDT".into()),
            rest::Reported {
                base: Some(30.0),
                quote: None,
            },
        );
        rep.insert(
            ("b".into(), "TAOUSDT".into()),
            rest::Reported {
                base: Some(123.0),
                quote: None,
            },
        );
        let out = render_report(&st, Some(&rep));
        // a: observed 1000 → 2000 extrapolated vs 4000 reported → 50%.
        assert!(out.contains("| a | 4 | 10.000 | $1.0k | 71.4% | $2.0k | $4.0k | 50% | 0 |"));
        // c: reported 30 base × VWAP 100 = $3.0k; 800/3000 → 27%.
        assert!(out.contains("| c | 2 | 4.000 | $400 | 28.6% | $800 | $3.0k | 27% | 0 |"));
        assert!(out.contains("| b | 0 | 0.000 | $0 | 0.0% | $0 | — | — | 0 |"));
    }
}
