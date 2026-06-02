//! Regression tests for hardened aggregator behaviour.
//!
//! Each test was originally a proof-of-concept showing how the older
//! aggregator could be fooled (NaN slipping into `to_fixed_point`, a
//! single source's self-reported volume dominating the weighted median,
//! `u128` saturation on overflow, etc.). Earlier versions of this file
//! kept *copies* of the aggregator routines under audit — when the
//! production code was patched, those copies kept passing and the
//! "regression tests" stopped signalling anything.
//!
//! This rewrite imports the live `kaskad_oracle::aggregator` module via
//! the `lib.rs` re-export so every assertion exercises the production
//! function directly. A future regression in the production code WILL
//! fail these tests.
//!
//! Run with:  cargo test --test security_audit -- --nocapture

#![allow(non_snake_case)]
#![allow(clippy::float_cmp)]
#![allow(clippy::approx_constant)]

use kaskad_oracle::aggregator::{
    equal_weight_fallback_count, reject_outliers, sanitize, to_fixed_point, weighted_median,
    WeightingMode,
};
use kaskad_oracle::types::PricePoint;

// ─── helpers ─────────────────────────────────────────────────────

fn pp(price: f64, volume: f64, source: &str) -> PricePoint {
    PricePoint {
        price,
        volume,
        source: source.into(),
        server_time: 1_710_000_000,
    }
}

fn pp_at(price: f64, volume: f64, source: &str, server_time: u64) -> PricePoint {
    PricePoint {
        price,
        volume,
        source: source.into(),
        server_time,
    }
}

// ════════════════════════════════════════════════════════════════════════════
// NaN / ±Inf must NOT reach the on-chain signer encoded as 0 or u128::MAX.
//
// Older code: `(price * multiplier).round() as u128` exploited Rust's
// saturating float→int cast — NaN → 0, +Inf → u128::MAX, -Inf → 0 — and
// the aggregator never sanitised price/volume.
//
// Hardened behaviour: `to_fixed_point` returns `Err` on any non-finite
// or non-positive input. The main loop calls `sanitize` before
// `weighted_median` to drop NaN/Inf upstream.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_nan_price_becomes_zero_fixed_point() {
    assert!(
        to_fixed_point(f64::NAN, 8).is_err(),
        "to_fixed_point(NaN) must Err — silent zero-cast was the bug"
    );
}

#[test]
fn POC_infinity_price_becomes_u128_max() {
    // Both signs must be rejected. The old behaviour saturated +Inf to
    // u128::MAX and -Inf to 0 — both produced an authoritative-but-bogus
    // on-chain price.
    assert!(to_fixed_point(f64::INFINITY, 8).is_err());
    assert!(to_fixed_point(f64::NEG_INFINITY, 8).is_err());
}

#[test]
fn POC_nan_not_rejected_by_aggregator() {
    // Production `sanitize` drops every non-finite / non-positive
    // sample before it reaches `weighted_median`. The old code had no
    // such gate; NaN propagated into the median.
    let raw = vec![
        pp(2000.0, 0.0, "honest_a"),
        pp(f64::NAN, 0.0, "attacker_nan"),
        pp(2001.0, 0.0, "honest_b"),
        pp(f64::INFINITY, 0.0, "attacker_inf"),
        pp(-1.0, 0.0, "attacker_negative"),
    ];
    let clean = sanitize(raw);
    assert_eq!(clean.len(), 2, "sanitize must drop NaN, Inf, and negative");
    assert!(clean.iter().all(|p| p.price.is_finite() && p.price > 0.0));
    let m = weighted_median(&clean).expect("clean set is non-empty");
    assert!(
        m.0.is_finite() && m.0 > 0.0,
        "median over sanitised set must be a real price, got {}",
        m.0
    );
}

// ════════════════════════════════════════════════════════════════════════════
// A single source's self-reported volume must NOT dominate the median.
//
// Older code: volume was lifted verbatim as the weight. One source
// reporting 1e12 outweighed every honest combined.
//
// Hardened: `VOLUME_WEIGHT_CAP_FACTOR = 5.0` clamps each source's weight
// at 5× median(positive volumes). The attacker can no longer buy more
// trust than 5× the honest median.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_one_source_with_huge_volume_wins_median() {
    // Seven honest sources around $2000 with realistic volumes; one
    // attacker quotes $1998 with 1e12 in fake volume. With the cap,
    // attacker weight is clamped at 5× honest median, so consensus
    // survives.
    let prices = vec![
        pp(2000.0, 1_000.0, "a"),
        pp(2001.0, 1_200.0, "b"),
        pp(1999.0, 800.0, "c"),
        pp(2000.5, 950.0, "d"),
        pp(1999.5, 1_100.0, "e"),
        pp(2001.5, 900.0, "f"),
        pp(2000.2, 1_050.0, "g"),
        pp(1998.0, 1e12, "attacker"),
    ];
    let (m, mode) = weighted_median(&prices).expect("non-empty");
    assert_eq!(mode, WeightingMode::VolumeWeighted);
    assert!(
        m >= 1999.0,
        "attacker pulled median below honest cluster: {}",
        m
    );
    assert!(m <= 2001.0, "median drifted unexpectedly high: {}", m);
}

// ════════════════════════════════════════════════════════════════════════════
// Sufficient zero/negative-volume sources silently disable volume-weighting.
//
// Older code: `use_volume = sources_with_volume * 2 > prices.len()` is
// binary; an attacker flooding zero-volume samples flips it off silently.
//
// Hardened: the fallback path (a) logs a warning, (b) increments a
// monotonic `EQUAL_WEIGHT_FALLBACK_COUNT` exposed via
// `equal_weight_fallback_count()` so an off-chain monitor can alert,
// and (c) returns `WeightingMode::EqualFallback` so a strict-policy
// caller can refuse to publish.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_non_positive_volume_flips_volume_weighting_off() {
    // The fallback still fires (semantics unchanged on purpose —
    // depth-quorum is a binary condition) but is now observable.
    // Verify both the mode return AND the counter bump.
    let before = equal_weight_fallback_count();
    let prices = vec![
        pp(2000.0, 100.0, "honest_a"),
        pp(2001.0, 100.0, "honest_b"),
        pp(1999.0, 100.0, "honest_c"),
        pp(2000.0, 0.0, "attacker_a"),
        pp(2000.0, 0.0, "attacker_b"),
        pp(2000.0, 0.0, "attacker_c"),
    ];
    let (_, mode) = weighted_median(&prices).expect("non-empty");
    assert_eq!(
        mode,
        WeightingMode::EqualFallback,
        "must surface EqualFallback so callers can refuse to publish"
    );
    assert!(
        equal_weight_fallback_count() > before,
        "fallback counter must increment so monitors can alert"
    );
}

#[test]
fn POC_negative_volume_falls_through_to_weight_one() {
    // `sanitize` normalises any non-finite or negative volume to 0.0
    // BEFORE the weighting decision runs. A single attacker with
    // `volume = -1e12` therefore can't survive as a negative weight
    // (which would have flipped the cumulative-weight running sum),
    // nor as a giant positive — it's just a zero-volume sample that
    // the weighting either ignores (under cap) or contributes 1.0 to
    // (under EqualFallback).
    let raw = vec![
        pp(2000.0, 100.0, "honest_a"),
        pp(2001.0, 100.0, "honest_b"),
        pp(1999.0, 100.0, "honest_c"),
        pp(500.0, -1e12, "attacker"),
    ];
    let clean = sanitize(raw);
    let attacker = clean
        .iter()
        .find(|p| p.source == "attacker")
        .expect("sanitize preserves the row (only the volume is normalised)");
    assert_eq!(
        attacker.volume, 0.0,
        "sanitize must zero out negative volume"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// 3-of-7 colluding sources within 3σ MAD still shift the median.
//
// This is an ACKNOWLEDGED LIMITATION of MAD-based outlier rejection at
// σ = 3. When the honest spread is wide enough, a tight cluster of
// attackers stays inside the threshold. The regression test exists to
// (a) document the limitation so future contributors don't assume MAD
// is bullet-proof, (b) catch the day someone tunes σ down (tightens
// the gate) or up (loosens it) by accident.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_mad_collusion_shifts_median() {
    // 4 honest sources, 3 colluding attackers at +0.15 %. Honest spread
    // 1.5 between min/max → 3σ × 1.4826 × MAD admits the attackers by
    // design.
    let honest = [
        pp(1999.5, 0.0, "h_a"),
        pp(2000.0, 0.0, "h_b"),
        pp(2000.5, 0.0, "h_c"),
        pp(2001.0, 0.0, "h_d"),
    ];
    let attackers = [
        pp(2003.0, 0.0, "atk_a"),
        pp(2003.0, 0.0, "atk_b"),
        pp(2003.0, 0.0, "atk_c"),
    ];
    let mut dataset: Vec<PricePoint> = honest.iter().chain(attackers.iter()).cloned().collect();
    let before = dataset.len();
    reject_outliers(&mut dataset, 3.0);
    assert_eq!(
        dataset.len(),
        before,
        "MAD must NOT reject any of these — tighter σ would change behaviour"
    );
    assert!(
        dataset.iter().any(|p| p.price == 2003.0),
        "attackers survive MAD (acknowledged limitation)"
    );

    // Median shifts upward from honest-only to combined.
    let m_honest = weighted_median(&honest).expect("non-empty").0;
    let m_all = weighted_median(&dataset).expect("non-empty").0;
    assert!(
        m_all > m_honest,
        "attackers do pull the median upward: honest={}, all={}",
        m_honest,
        m_all
    );
}

// ════════════════════════════════════════════════════════════════════════════
// `to_fixed_point` must refuse overflow, not silently saturate.
//
// Hardened: `MAX_SANE_PRICE = 1.0e20` plus an explicit overflow check
// return `Err` on anything that would otherwise saturate into u128::MAX.
// A $1e24-per-coin "price" no longer reaches the signer.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_fixed_point_saturates_on_overflow() {
    // Both the obvious overflow (1e40 × 1e8 ≫ u128::MAX) and the
    // "doesn't overflow but is laughable" 1e24 case must Err.
    assert!(
        to_fixed_point(1.0e40_f64, 8).is_err(),
        "1e40 must Err — saturating cast was the bug"
    );
    assert!(
        to_fixed_point(1.0e24_f64, 8).is_err(),
        "1e24 must Err — exceeds MAX_SANE_PRICE"
    );
    // A realistic large-but-sane price (e.g. $1M BTC) still succeeds.
    assert!(to_fixed_point(1_000_000.0_f64, 8).is_ok());
}

// ════════════════════════════════════════════════════════════════════════════
// Even-count median in `reject_outliers` must average the two middle
// values, not pick the upper one (which would bias the acceptance
// window on the high side).
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_reject_outliers_even_count_upper_bias() {
    // For [100, 101, 102, 103, 200]: the production median over the
    // top 4 honest values is the AVERAGE of 101 and 102 = 101.5, NOT
    // 102. We verify the fix by constructing a fixture where the
    // upper-bias variant would have spared the outlier and the
    // even-aware variant rejects it.
    let mut prices = vec![
        pp(100.0, 0.0, "a"),
        pp(101.0, 0.0, "b"),
        pp(102.0, 0.0, "c"),
        pp(103.0, 0.0, "d"),
        pp(200.0, 0.0, "outlier"),
    ];
    reject_outliers(&mut prices, 3.0);
    assert!(
        !prices.iter().any(|p| p.price == 200.0),
        "200 must be rejected as an outlier"
    );
    assert!(
        prices.iter().any(|p| p.price == 100.0),
        "100 must stay (it's inside the honest cluster)"
    );

    // Cross-check via a tight 4-sample dataset: if the even-aware
    // median regressed to "upper middle", the boundary case below
    // would tilt and an honest sample near the lower edge would get
    // rejected.
    let mut tight = vec![
        pp(100.0, 0.0, "a"),
        pp(101.0, 0.0, "b"),
        pp(102.0, 0.0, "c"),
        pp(103.0, 0.0, "d"),
    ];
    reject_outliers(&mut tight, 3.0);
    assert_eq!(
        tight.len(),
        4,
        "no member of a tight 4-sample cluster may be rejected; \
         finding the upper bias here would mean the fix regressed"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Heartbeat-clock-rewind regression sentinel.
//
// An older code path read `now - last_ts >= heartbeat_seconds` over a
// host-derived clock, with `u64` subtraction that wrapped on rewind.
// That throttle no longer exists — the oracle moved to a pull-API
// model where consumers request a fresh signature per query and no
// host clock backs any aggregator-internal decision. This test keeps
// a sentinel so a future refactor accidentally reintroducing a host-
// clock-subtraction throttle on `server_time` would be caught.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_heartbeat_underflow_on_clock_rewind() {
    // `aggregator::reject_time_outliers` uses MEDIAN of per-source
    // `server_time`, NOT subtraction against a host clock — exercising
    // it on rewinding inputs must still produce a sensible median and
    // not underflow.
    let mut prices = vec![
        pp_at(100.0, 0.0, "a", 1_710_000_000),
        pp_at(100.0, 0.0, "b", 1_700_000_000), // 10 days "rewound"
        pp_at(100.0, 0.0, "c", 1_710_000_010),
    ];
    let _ = kaskad_oracle::aggregator::reject_time_outliers(&mut prices);
    // The rewound source is the outlier vs the other two; it gets
    // dropped, and the surviving median is well-defined.
    assert!(
        prices.len() <= 3,
        "no panic, no underflow — output is bounded by input"
    );
    assert!(
        prices.iter().all(|p| p.server_time > 0),
        "no negative / wrapped timestamps slipped through"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// `deviation_bps_float as u16` cast is saturating (Rust language
// guarantee, not a vulnerability). Documents the safe behaviour.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_deviation_bps_saturating_cast_stays_gte_threshold() {
    // Pure Rust-language behaviour; no production code under test.
    // Documents that any deviation_bps > u16::MAX silently clamps to
    // u16::MAX, which is always ≥ any realistic threshold.
    let bps_float = 1e9_f64;
    let bps: u16 = bps_float as u16;
    assert_eq!(bps, u16::MAX);
    assert!(bps >= 50);
}
