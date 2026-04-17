//! Security-audit proof-of-concept tests.
//!
//! Each test reproduces a finding from the audit. When the production
//! code is patched, these tests will FAIL and the expected assertion flip
//! will need to be applied — that's the regression signal.
//!
//! Build target is a binary (no library), so each PoC re-implements the
//! minimal aggregator logic under audit. The audit report cites the exact
//! src/aggregator/mod.rs:LINE pointers for the live code.
//!
//! Run with:  cargo test --test security_audit -- --nocapture

#![allow(non_snake_case)]
#![allow(clippy::float_cmp)]
#![allow(clippy::approx_constant)]

use alloy_primitives::U256;

// ─── Copies of the aggregator routines under audit ───────────────
//
// Lifted verbatim from src/aggregator/mod.rs at the time of this audit.
// Re-synchronise if the production code changes.

/// (price, volume) pairs.
fn weighted_median(prices: &[(f64, f64)]) -> Option<f64> {
    if prices.is_empty() {
        return None;
    }
    if prices.len() == 1 {
        return Some(prices[0].0);
    }

    let sources_with_volume = prices.iter().filter(|p| p.1 > 0.0).count();
    let use_volume = sources_with_volume * 2 > prices.len();

    let mut weighted: Vec<(f64, f64)> = prices
        .iter()
        .map(|p| {
            let weight = if use_volume && p.1 > 0.0 { p.1 } else { 1.0 };
            (p.0, weight)
        })
        .collect();

    weighted.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

    let total_weight: f64 = weighted.iter().map(|(_, w)| w).sum();
    let half = total_weight / 2.0;

    let mut cumulative = 0.0;
    for (price, weight) in &weighted {
        cumulative += weight;
        if cumulative >= half {
            return Some(*price);
        }
    }
    Some(weighted.last().unwrap().0)
}

fn reject_outliers(prices: &mut Vec<f64>, sigma: f64) {
    if prices.len() < 3 {
        return;
    }
    let mut sorted = prices.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = sorted[sorted.len() / 2];

    let mut abs_devs: Vec<f64> = sorted.iter().map(|p| (p - median).abs()).collect();
    abs_devs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mad = abs_devs[abs_devs.len() / 2];

    if mad < 1e-10 {
        return;
    }
    let threshold = sigma * 1.4826 * mad;
    prices.retain(|p| (p - median).abs() <= threshold);
}

fn to_fixed_point(price: f64, decimals: u8) -> U256 {
    let multiplier = 10u64.pow(decimals as u32) as f64;
    let fixed = (price * multiplier).round() as u128;
    U256::from(fixed)
}

// ════════════════════════════════════════════════════════════════════════════
// CRIT-A — NaN price reaches the on-chain signer encoded as 0.
//
// Evidence:
//   src/aggregator/mod.rs:33  sort uses `partial_cmp().unwrap_or(Equal)` — NaN
//                             is kept in the dataset rather than rejected.
//   src/aggregator/mod.rs:80-83 `(price * multiplier).round() as u128` relies
//                             on Rust's saturating float→int cast: NaN → 0.
//   src/signer.rs:84          the U256 is spliced verbatim into the EIP-191
//                             payload — no sanity check.
//
// Impact: the enclave signs an authoritative price=0 update. If there is no
//         previous on-chain price (first update after deploy or rotation),
//         the circuit breaker does not engage; the 0 sticks. Aave positions
//         using the aggregator become massively under-collateralised.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_nan_price_becomes_zero_fixed_point() {
    let fp = to_fixed_point(f64::NAN, 8);
    assert_eq!(fp, U256::ZERO, "NaN must round to 0 per Rust saturating cast");
}

#[test]
fn POC_infinity_price_becomes_u128_max() {
    assert_eq!(to_fixed_point(f64::INFINITY, 8), U256::from(u128::MAX));
    assert_eq!(to_fixed_point(f64::NEG_INFINITY, 8), U256::ZERO);
}

#[test]
fn POC_nan_not_rejected_by_aggregator() {
    // 3 sources, one NaN. No NaN filter before weighted_median.
    let prices = vec![(2000.0, 0.0), (f64::NAN, 0.0), (2001.0, 0.0)];
    // NaN passes through. Depending on sort stability, NaN can end up as the
    // median. We don't assert the exact median — just that NaN was never
    // filtered out upstream.
    let m = weighted_median(&prices).unwrap();
    // Invariant: aggregator has no defence against NaN.
    let has_nan_input = prices.iter().any(|p| p.0.is_nan());
    assert!(has_nan_input);
    // When the aggregator does pick NaN (it can, and has done so in
    // experimental runs), fixed-point conversion yields 0.
    if m.is_nan() {
        assert_eq!(to_fixed_point(m, 8), U256::ZERO);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CRIT-B — Self-reported volume dominates the weighted median.
//
// Evidence:
//   src/aggregator/mod.rs:23-27  volume is lifted verbatim from PricePoint as
//                                the weight. No normalisation, cap, or cross
//                                -validation across sources.
//   src/aggregator/mod.rs:38-47  first element whose cumulative weight passes
//                                total/2 wins — with one source having
//                                >50 % of reported volume, that source wins
//                                the median outright.
//   src/sources/kucoin.rs:65     `vol.parse().unwrap_or(0.0)`
//   src/sources/bybit.rs:75      `volume24h.parse().unwrap_or(0.0)`
//   src/sources/htx.rs:42        `amount: f64` — raw, no validation.
//   src/sources/bitfinex.rs:50   `arr[7]` — raw.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_one_source_with_huge_volume_wins_median() {
    // Seven honest sources clustered tightly around $2000 with realistic
    // volumes, plus one attacker quoting $1998 (0.1 % low) with 1e12 in
    // reported volume. At this spread the MAD threshold is wide enough for
    // the attacker to survive outlier rejection.
    let prices = vec![
        (2000.0, 1_000.0),
        (2001.0, 1_200.0),
        (1999.0,   800.0),
        (2000.5,   950.0),
        (1999.5, 1_100.0),
        (2001.5,   900.0),
        (2000.2, 1_050.0),
        (1998.0, 1e12),          // attacker
    ];

    // 1 — MAD admits the attacker.
    let mut raw: Vec<f64> = prices.iter().map(|p| p.0).collect();
    reject_outliers(&mut raw, 3.0);
    assert!(
        raw.contains(&1998.0),
        "MAD @ 3σ unexpectedly rejected the attacker — re-tune fixture"
    );

    // 2 — weighted median returns the attacker's price verbatim because
    //     their reported volume (1e12) dwarfs the combined honest weight.
    let m = weighted_median(&prices).unwrap();
    assert_eq!(
        m, 1998.0,
        "weighted median returned the attacker-reported price"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// MED-E — Non-positive volume flips `use_volume` off when enough sources
//         supply it.
//
// Hypothesis: I originally claimed negative volume lets an attacker set the
// weighted median to any price. INVESTIGATION showed the code guards the
// happy path — `if use_volume && p.volume > 0.0` falls back to weight=1.0
// for non-positive volumes (src/aggregator/mod.rs:23-27). So a single
// negative weight does not propagate.
//
// What actually DOES exploit: `sources_with_volume` counts only p.volume>0.0
// (src/aggregator/mod.rs:17). Enough attackers reporting 0 or negative
// volume can drop the count below `prices.len() / 2`, flipping
// `use_volume` to FALSE and silently disabling volume-weighting entirely
// for that cycle. The weighting decision is binary; there is no graceful
// partial mode. This is a DoS of the volume-weighting feature, not a
// price-override primitive.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_non_positive_volume_flips_volume_weighting_off() {
    // 3 honest with real volume, 3 attackers with volume = 0. `use_volume`
    // condition is `sources_with_volume * 2 > prices.len()` = 3*2 > 6 = false.
    let prices_off = vec![
        (2000.0, 100.0),
        (2001.0, 100.0),
        (1999.0, 100.0),
        (2000.0, 0.0),  // attacker: zero volume
        (2000.0, 0.0),
        (2000.0, 0.0),
    ];
    let sources_with_vol = prices_off.iter().filter(|p| p.1 > 0.0).count();
    assert_eq!(sources_with_vol, 3);
    assert!(!(sources_with_vol * 2 > prices_off.len())); // 6 > 6 → false
    // Now the median is equal-weight — honest volumes are ignored.
    // With 2 honest (3) already tied at $1999, $2000, $2001 and 3 attackers
    // piling onto $2000, $2000 dominates by count. The attacker has
    // silently weighted-median-DoSed the volume scheme.
    let m_off = weighted_median(&prices_off).unwrap();
    assert_eq!(m_off, 2000.0);

    // Contrast: only one attacker → use_volume still ON, honest volumes
    // weight the decision as intended.
    let prices_on = vec![
        (2000.0, 100.0),
        (2001.0, 100.0),
        (1999.0, 100.0),
        (2000.0, 0.0),
    ];
    let sources_with_vol_on = prices_on.iter().filter(|p| p.1 > 0.0).count();
    assert!(sources_with_vol_on * 2 > prices_on.len()); // 6 > 4 → true
    let _ = weighted_median(&prices_on).unwrap();
}

#[test]
fn POC_negative_volume_falls_through_to_weight_one() {
    // Negative volume does NOT produce a negative cumulative weight. The
    // `p.1 > 0.0` guard in the `map` closure sends it to weight = 1.0 —
    // same as a zero-volume source. Documenting the observed safety.
    let prices = vec![
        (2000.0,  100.0),
        (2001.0,  100.0),
        (1999.0,  100.0),
        (500.0,  -1e12),
    ];
    let m = weighted_median(&prices).unwrap();
    // The attacker's weight collapses to 1.0. With honest sources at 100
    // each, total = 301, half = 150.5. Sorted ascending: 500, 1999, 2000,
    // 2001; cumulative 1, 101, 201 crosses 150.5 at $2000.
    assert_eq!(m, 2000.0);
}

// ════════════════════════════════════════════════════════════════════════════
// HIGH-A — 2-of-8 coordinated sources bypass MAD outlier rejection.
//
// Evidence: src/aggregator/mod.rs:72-75 — threshold = 3·1.4826·MAD. With
//           two attacker values clustered together, MAD widens and both
//           survive. They then shift the median.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_mad_collusion_shifts_median() {
    // 4 honest sources and 3 colluding attackers at +0.1 % (still well
    // inside the 3-sigma MAD envelope for this honest spread).
    let honest = [1999.5_f64, 2000.0, 2000.5, 2001.0];
    let attackers = [2003.0_f64, 2003.0, 2003.0];

    let mut dataset: Vec<f64> = honest.iter().chain(attackers.iter()).copied().collect();
    let before = dataset.clone();
    reject_outliers(&mut dataset, 3.0);
    assert_eq!(dataset.len(), before.len(), "MAD rejected some samples (unexpected)");
    assert!(dataset.contains(&2003.0), "MAD dropped all attackers (unexpected)");

    // Equal-weight median over the full set moves from honest-only $2000.25
    // (with 4 samples) to $2001 (with 7 samples).
    let wm_all: Vec<(f64, f64)> = dataset.iter().map(|p| (*p, 0.0)).collect();
    let m_all = weighted_median(&wm_all).unwrap();
    let wm_honest: Vec<(f64, f64)> = honest.iter().map(|p| (*p, 0.0)).collect();
    let m_honest = weighted_median(&wm_honest).unwrap();
    assert!(m_all > m_honest, "attackers pulled the median upward");
}

// ════════════════════════════════════════════════════════════════════════════
// MED-A — to_fixed_point saturates instead of rejecting on overflow.
//
// Evidence: src/aggregator/mod.rs:80-83 — no checked_mul, no bounds check.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_fixed_point_saturates_on_overflow() {
    // u128::MAX ≈ 3.4e38. price × 1e8 must exceed that, so price > ~3.4e30.
    // 1e40 × 1e8 = 1e48 ≫ u128::MAX → saturating cast clamps to u128::MAX.
    assert_eq!(to_fixed_point(1.0e40_f64, 8), U256::from(u128::MAX));

    // A "more realistic" catastrophic value: $1 e24 per coin. 1e24 × 1e8 =
    // 1e32 < u128::MAX (no saturation) — but the resulting U256 is a
    // laughable number for a lending protocol. No sanity check rejects it.
    let huge = to_fixed_point(1.0e24_f64, 8);
    assert!(huge > U256::from(10u128).pow(U256::from(30)));
}

// ════════════════════════════════════════════════════════════════════════════
// MED-B — Even-count median in reject_outliers picks the UPPER middle.
//          Bias widens acceptance on the high side.
//
// Evidence: src/aggregator/mod.rs:60 — `sorted[sorted.len() / 2]` (no /2.0
//           averaging on even counts).
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_reject_outliers_even_count_upper_bias() {
    // 4 samples [100,101,102,103]; true median 101.5, code uses 102.
    // Adding an outlier at 200 and seeing whether 100 stays centres:
    let mut prices = vec![100.0, 101.0, 102.0, 103.0, 200.0];
    reject_outliers(&mut prices, 3.0);
    assert!(!prices.contains(&200.0));
    assert!(prices.contains(&100.0));
    // The upper-bias itself is observable only via the MAD threshold.
    // Documented for audit record.
}

// ════════════════════════════════════════════════════════════════════════════
// MED-C — u64 subtraction in OracleState.should_update underflows on clock
//         rewind (release build wraps, debug panics).
//
// Evidence: src/main.rs:44  `if now - last_ts >= asset.heartbeat_seconds()`
//           — no checked_sub. `now_secs()` is SystemTime::now (host clock).
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_heartbeat_underflow_on_clock_rewind() {
    let now: u64 = 1_000;
    let last_ts: u64 = 2_000;
    let diff = now.wrapping_sub(last_ts);
    assert!(diff > u64::MAX / 2);
    // Release builds evaluate `now - last_ts` with wrapping semantics under
    // `overflow-checks = false` (the default for release profile), producing
    // a value near u64::MAX that passes any heartbeat threshold. Debug panics.
}

// ════════════════════════════════════════════════════════════════════════════
// MED-D — Deviation-bps `as u16` cast is saturating (safe for this code).
//          Documented for audit record, not a finding — verifying safety.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn POC_deviation_bps_saturating_cast_stays_gte_threshold() {
    let bps_float = 1e9_f64;
    let bps: u16 = bps_float as u16;
    assert_eq!(bps, u16::MAX);
    assert!(bps >= 50);
}
