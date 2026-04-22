use crate::types::PricePoint;
use alloy_primitives::U256;
use eyre::{eyre, Result};
use std::sync::atomic::{AtomicU64, Ordering};

/// Cap a single source's volume weight at N× the median of positive volumes.
/// Prevents one CEX from dominating the weighted median via self-reported
/// volume (audit finding C-5: cap the trust a single source can buy).
const VOLUME_WEIGHT_CAP_FACTOR: f64 = 5.0;

/// Whether `weighted_median` computed a result from per-source volumes or
/// fell back to equal weights because fewer than half the sources had
/// positive volume. Callers with a strict policy (critical assets) can
/// refuse to publish in `EqualFallback` mode (audit EXPLOIT-3: an
/// attacker who nullifies volume reporting across ≥50 % of sources can
/// otherwise silently disable the depth signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeightingMode {
    VolumeWeighted,
    EqualFallback,
}

/// Monotonic counter of `EqualFallback` events since process start. The
/// pull-API `health` response exposes this so an off-chain monitor can
/// page when the counter climbs faster than baseline (audit EXPLOIT-3
/// mitigation 2).
static EQUAL_WEIGHT_FALLBACK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the fallback counter. Monotonic; only resets on process
/// restart.
pub fn equal_weight_fallback_count() -> u64 {
    EQUAL_WEIGHT_FALLBACK_COUNT.load(Ordering::Relaxed)
}

/// Maximum price (in human units) that `to_fixed_point` will accept.
/// 1e20 fits in U256 with 8 decimals and is far above any realistic asset
/// price; refuses obviously bogus inputs. Prevents overflow saturation
/// (audit finding M-2).
const MAX_SANE_PRICE: f64 = 1.0e20;

/// Maximum absolute drift (in seconds) of a source's server_time from the
/// median before the sample is dropped. 300 s (5 min) accommodates modest
/// CEX clock skew while still rejecting a single source trying to shift
/// the enclave's authoritative clock (audit C-3/H-9).
pub const MAX_TIME_DRIFT_SECS: u64 = 300;

/// Drop any sample that is NaN, ±Infinity, non-positive price, zero
/// server_time, and normalise broken volumes to 0.0. Returns the cleaned
/// set. Fixes audit findings C-4 (NaN/Inf price → signed price 0 or
/// u128::MAX), C-3 (missing server_time falls back to host clock), and
/// sanitises C-5 volume inputs.
pub fn sanitize(prices: Vec<PricePoint>) -> Vec<PricePoint> {
    prices
        .into_iter()
        .filter(|p| p.price.is_finite() && p.price > 0.0 && p.server_time > 0)
        .map(|mut p| {
            if !p.volume.is_finite() || p.volume < 0.0 {
                p.volume = 0.0;
            }
            p
        })
        .collect()
}

/// Return the integer median of per-source `server_time` across the
/// surviving sample set. Returns None if the set is empty. This value is
/// the ONLY clock the enclave trusts when producing signatures (audit
/// C-3/H-9: SystemTime::now is host-controlled).
pub fn median_server_time(prices: &[PricePoint]) -> Option<u64> {
    if prices.is_empty() {
        return None;
    }
    let mut times: Vec<u64> = prices.iter().map(|p| p.server_time).collect();
    times.sort_unstable();
    let n = times.len();
    Some(if n % 2 == 0 {
        // Use integer average — server_time has second resolution anyway.
        (times[n / 2 - 1] + times[n / 2]) / 2
    } else {
        times[n / 2]
    })
}

/// Drop samples whose `server_time` drifts more than `MAX_TIME_DRIFT_SECS`
/// from the current median. A single malicious CEX can no longer drag the
/// enclave's clock: the median recomputes after each rejection in the
/// caller's pipeline (we only run one pass here — if you want iterative
/// rejection, call in a loop until stable).
pub fn reject_time_outliers(prices: &mut Vec<PricePoint>) -> Option<u64> {
    let median = median_server_time(prices)?;
    prices.retain(|p| {
        let d = p.server_time.max(median) - p.server_time.min(median);
        d <= MAX_TIME_DRIFT_SECS
    });
    // Recompute after rejection for the caller's convenience.
    median_server_time(prices)
}

/// Median helper that handles even-length datasets by averaging the two
/// middle values (audit finding L-2). `values` is sorted in place.
fn median_sorted(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = values.len();
    if n % 2 == 0 {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    } else {
        values[n / 2]
    }
}

/// Compute the weighted median of a set of price observations, and report
/// whether volume weighting or the equal-weight fallback was used.
///
/// Weighting uses the per-source 24 h volume, capped at
/// `VOLUME_WEIGHT_CAP_FACTOR` × median(positive volumes) to prevent a
/// single source with an absurd self-reported volume from controlling
/// the median (audit C-5). Falls back to equal weighting if fewer than
/// half the sources report positive volume (warns AND increments a
/// metric: audit M-5 and EXPLOIT-3). A caller with a strict policy can
/// inspect the returned `WeightingMode` and refuse to publish in
/// `EqualFallback`.
pub fn weighted_median(prices: &[PricePoint]) -> Option<(f64, WeightingMode)> {
    if prices.is_empty() {
        return None;
    }
    if prices.len() == 1 {
        // A single observation is a degenerate case — volume weighting
        // doesn't apply. Report it as `VolumeWeighted` so the caller's
        // strict-policy check does not fire on this trivial path.
        return Some((prices[0].price, WeightingMode::VolumeWeighted));
    }

    let sources_with_volume = prices.iter().filter(|p| p.volume > 0.0).count();
    let use_volume = sources_with_volume * 2 > prices.len();

    let mode = if use_volume {
        WeightingMode::VolumeWeighted
    } else {
        // Silent disablement is how an attacker forces equal-weighting by
        // flooding zero-volume samples (audit M-5 / EXPLOIT-3). Log it
        // AND bump a monotonic counter so an off-chain monitor can alert.
        EQUAL_WEIGHT_FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            total_sources = prices.len(),
            sources_with_volume,
            "weighted_median falling back to equal weight — volume quorum not met"
        );
        WeightingMode::EqualFallback
    };

    // Volume-weight cap: collect positive volumes, take their median, cap
    // every weight at N × that median. Stops a single large-volume source
    // from dominating (audit C-5).
    let cap = if use_volume {
        let mut pos_vols: Vec<f64> = prices
            .iter()
            .filter_map(|p| if p.volume > 0.0 { Some(p.volume) } else { None })
            .collect();
        let med = median_sorted(&mut pos_vols);
        Some(med * VOLUME_WEIGHT_CAP_FACTOR)
    } else {
        None
    };

    let mut weighted: Vec<(f64, f64)> = prices
        .iter()
        .map(|p| {
            let weight = match (use_volume && p.volume > 0.0, cap) {
                (true, Some(c)) => p.volume.min(c),
                _ => 1.0,
            };
            (p.price, weight)
        })
        .collect();

    // Sort by price.
    weighted.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

    let total_weight: f64 = weighted.iter().map(|(_, w)| w).sum();
    let half = total_weight / 2.0;

    let mut cumulative = 0.0;
    for (price, weight) in &weighted {
        cumulative += weight;
        if cumulative >= half {
            return Some((*price, mode));
        }
    }
    Some((weighted.last().unwrap().0, mode))
}

/// Reject outliers using MAD (Median Absolute Deviation).
/// Removes points that deviate more than `sigma` MADs from the median.
pub fn reject_outliers(prices: &mut Vec<PricePoint>, sigma: f64) {
    if prices.len() < 3 {
        return; // Not enough data to detect outliers
    }

    // Compute median price (even-aware — audit L-2).
    let mut prices_sorted: Vec<f64> = prices.iter().map(|p| p.price).collect();
    let median = median_sorted(&mut prices_sorted);

    // Compute MAD.
    let mut abs_devs: Vec<f64> = prices_sorted.iter().map(|p| (p - median).abs()).collect();
    let mad = median_sorted(&mut abs_devs);

    if mad < 1e-10 {
        return;
    }

    // Modified Z-score threshold.
    let threshold = sigma * 1.4826 * mad; // 1.4826 = consistency constant for normal dist

    prices.retain(|p| (p.price - median).abs() <= threshold);
}

/// Convert a positive finite floating-point price to a fixed-point U256 with
/// the given decimals. Returns `Err` on NaN / ±Infinity / non-positive /
/// overflow inputs (audit C-4 + M-2) — callers MUST not sign a price that
/// fails this check.
pub fn to_fixed_point(price: f64, decimals: u8) -> Result<U256> {
    if !price.is_finite() {
        return Err(eyre!("refuse to encode non-finite price {}", price));
    }
    if price <= 0.0 {
        return Err(eyre!("refuse to encode non-positive price {}", price));
    }
    if price > MAX_SANE_PRICE {
        return Err(eyre!(
            "refuse to encode price {} (> MAX_SANE_PRICE {})",
            price,
            MAX_SANE_PRICE
        ));
    }
    let multiplier = 10u64.pow(decimals as u32) as f64;
    let scaled = price * multiplier;
    if !scaled.is_finite() || scaled < 0.0 || scaled > u128::MAX as f64 {
        return Err(eyre!("price*10^{} overflows u128: {}", decimals, scaled));
    }
    let fixed = scaled.round() as u128;
    Ok(U256::from(fixed))
}

/// Compute a sources hash: keccak256 of concatenated source names and their
/// prices. Uses big-endian f64 bytes to produce a canonical encoding
/// independent of build-machine endianness (audit L-3).
pub fn sources_hash(prices: &[PricePoint]) -> alloy_primitives::B256 {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    for p in prices {
        hasher.update(p.source.as_bytes());
        hasher.update(b"|");
        hasher.update(p.price.to_be_bytes());
    }
    alloy_primitives::B256::from_slice(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_prices(values: &[f64]) -> Vec<PricePoint> {
        values
            .iter()
            .enumerate()
            .map(|(i, &price)| PricePoint {
                price,
                volume: 0.0,
                source: format!("source_{}", i),
                server_time: 1_710_000_000 + i as u64,
            })
            .collect()
    }

    fn make_prices_with_volume(rows: &[(f64, f64)]) -> Vec<PricePoint> {
        rows.iter()
            .enumerate()
            .map(|(i, &(price, volume))| PricePoint {
                price,
                volume,
                source: format!("source_{}", i),
                server_time: 1_710_000_000 + i as u64,
            })
            .collect()
    }

    #[test]
    fn test_weighted_median_odd() {
        let prices = make_prices(&[100.0, 102.0, 101.0]);
        let (median, mode) = weighted_median(&prices).unwrap();
        assert_eq!(median, 101.0);
        // No volume data on any sample → equal-weight fallback.
        assert_eq!(mode, WeightingMode::EqualFallback);
    }

    #[test]
    fn test_weighted_median_even() {
        let prices = make_prices(&[100.0, 102.0, 101.0, 103.0]);
        let (median, _mode) = weighted_median(&prices).unwrap();
        assert!(median >= 101.0 && median <= 102.0);
    }

    #[test]
    fn test_weighted_median_single() {
        let prices = make_prices(&[42.0]);
        assert_eq!(weighted_median(&prices).unwrap().0, 42.0);
    }

    #[test]
    fn test_weighted_median_empty() {
        let prices: Vec<PricePoint> = vec![];
        assert!(weighted_median(&prices).is_none());
    }

    #[test]
    fn test_weighted_median_mode_reports_volume_weighted() {
        let prices = make_prices_with_volume(&[(100.0, 10.0), (101.0, 20.0), (99.5, 15.0)]);
        let (_, mode) = weighted_median(&prices).unwrap();
        assert_eq!(mode, WeightingMode::VolumeWeighted);
    }

    #[test]
    fn test_weighted_median_mode_reports_equal_fallback() {
        // 3 of 5 have zero volume → 2/5 have positive → fallback.
        let prices = make_prices_with_volume(&[
            (100.0, 0.0),
            (101.0, 0.0),
            (99.5, 0.0),
            (100.5, 10.0),
            (100.2, 10.0),
        ]);
        let (_, mode) = weighted_median(&prices).unwrap();
        assert_eq!(mode, WeightingMode::EqualFallback);
    }

    #[test]
    fn test_equal_weight_fallback_counter_increments() {
        let before = equal_weight_fallback_count();
        let prices = make_prices(&[100.0, 101.0, 99.5]); // all zero volume
        let _ = weighted_median(&prices).unwrap();
        let after = equal_weight_fallback_count();
        assert!(
            after > before,
            "fallback counter must increment on equal-weight path"
        );
    }

    #[test]
    fn test_outlier_rejection() {
        let mut prices = make_prices(&[100.0, 101.0, 99.5, 100.5, 999.0]);
        reject_outliers(&mut prices, 3.0);
        assert_eq!(prices.len(), 4);
        assert!(prices.iter().all(|p| p.price < 200.0));
    }

    #[test]
    fn test_fixed_point_conversion() {
        let result = to_fixed_point(1234.56, 8).unwrap();
        assert_eq!(result, U256::from(123456000000u64));
    }

    #[test]
    fn test_fixed_point_small() {
        let result = to_fixed_point(0.001, 8).unwrap();
        assert_eq!(result, U256::from(100000u64));
    }

    // ─── audit fix regressions ─────────────────────────────────────────────

    #[test]
    fn test_fixed_point_rejects_nan() {
        assert!(to_fixed_point(f64::NAN, 8).is_err());
    }

    #[test]
    fn test_fixed_point_rejects_infinity() {
        assert!(to_fixed_point(f64::INFINITY, 8).is_err());
        assert!(to_fixed_point(f64::NEG_INFINITY, 8).is_err());
    }

    #[test]
    fn test_fixed_point_rejects_non_positive() {
        assert!(to_fixed_point(0.0, 8).is_err());
        assert!(to_fixed_point(-1.0, 8).is_err());
    }

    #[test]
    fn test_fixed_point_rejects_overflow() {
        assert!(to_fixed_point(1.0e21_f64, 8).is_err()); // > MAX_SANE_PRICE
        assert!(to_fixed_point(1.0e40_f64, 8).is_err()); // would saturate
    }

    #[test]
    fn test_sanitize_drops_nan_and_infinity_prices() {
        let prices = make_prices(&[
            100.0,
            f64::NAN,
            101.0,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -1.0,
        ]);
        let cleaned = sanitize(prices);
        assert_eq!(cleaned.len(), 2);
        for p in &cleaned {
            assert!(p.price.is_finite() && p.price > 0.0);
        }
    }

    #[test]
    fn test_sanitize_normalises_bad_volumes() {
        let prices = make_prices_with_volume(&[
            (100.0, 10.0),
            (101.0, f64::NAN),
            (99.5, f64::INFINITY),
            (100.5, -5.0),
        ]);
        let cleaned = sanitize(prices);
        assert_eq!(cleaned.len(), 4);
        for p in &cleaned {
            assert!(p.volume.is_finite() && p.volume >= 0.0);
        }
    }

    #[test]
    fn test_volume_cap_prevents_single_source_domination() {
        // 7 honest sources near $2000 with ~1k volume each; one attacker
        // reports 1e12. With the cap, attacker's weight is clamped at
        // 5× honest median, so the median stays near consensus.
        let prices = make_prices_with_volume(&[
            (2000.0, 1_000.0),
            (2001.0, 1_200.0),
            (1999.0, 800.0),
            (2000.5, 950.0),
            (1999.5, 1_100.0),
            (2001.5, 900.0),
            (2000.2, 1_050.0),
            (1998.0, 1e12), // attacker
        ]);
        let (m, _) = weighted_median(&prices).unwrap();
        // Attacker tries to pull to $1998; with cap they can't.
        assert!(
            m >= 1999.0,
            "attacker with huge volume still dominated: m={}",
            m
        );
        assert!(m <= 2001.0, "aggregator drifted unexpectedly: m={}", m);
    }

    #[test]
    fn test_sources_hash_uses_big_endian() {
        // Regression for L-3. `to_be_bytes()` on f64 yields [0x40, 0x59, ...]
        // for 100.5 (sign+exponent-first). `to_le_bytes()` would start
        // [0x00, 0x00, ...]. Hash a single-element set and confirm the
        // first input byte is the BE prefix.
        let prices = make_prices(&[100.5]);
        let mut hasher = sha3::Keccak256::new();
        use sha3::Digest;
        hasher.update(prices[0].source.as_bytes());
        hasher.update(b"|");
        hasher.update(100.5_f64.to_be_bytes());
        let expected = alloy_primitives::B256::from_slice(&hasher.finalize());
        assert_eq!(sources_hash(&prices), expected);
    }

    #[test]
    fn test_median_sorted_even_length_averages() {
        // Regression for L-2: [1, 2, 3, 4] → true median 2.5, not 3.
        let mut v = vec![1.0, 2.0, 3.0, 4.0];
        assert_eq!(median_sorted(&mut v), 2.5);
    }

    fn pp_with_time(price: f64, server_time: u64, tag: &str) -> PricePoint {
        PricePoint {
            price,
            volume: 0.0,
            source: tag.into(),
            server_time,
        }
    }

    #[test]
    fn test_median_server_time_odd() {
        let prices = vec![
            pp_with_time(100.0, 1_710_000_000, "a"),
            pp_with_time(100.0, 1_710_000_010, "b"),
            pp_with_time(100.0, 1_710_000_020, "c"),
        ];
        assert_eq!(median_server_time(&prices), Some(1_710_000_010));
    }

    #[test]
    fn test_median_server_time_even_averages() {
        let prices = vec![
            pp_with_time(100.0, 1_710_000_000, "a"),
            pp_with_time(100.0, 1_710_000_010, "b"),
            pp_with_time(100.0, 1_710_000_020, "c"),
            pp_with_time(100.0, 1_710_000_030, "d"),
        ];
        assert_eq!(median_server_time(&prices), Some(1_710_000_015));
    }

    #[test]
    fn test_median_server_time_empty() {
        assert_eq!(median_server_time(&[]), None);
    }

    #[test]
    fn test_reject_time_outliers_drops_drifty_samples() {
        // Three honest sources around T, one source 1 hour off.
        let mut prices = vec![
            pp_with_time(100.0, 1_710_000_000, "a"),
            pp_with_time(100.0, 1_710_000_005, "b"),
            pp_with_time(100.0, 1_710_000_010, "c"),
            pp_with_time(100.0, 1_710_003_600, "attacker"), // +1h
        ];
        let median = reject_time_outliers(&mut prices).unwrap();
        assert_eq!(prices.len(), 3);
        assert!(prices.iter().all(|p| p.source != "attacker"));
        // Median after rejection is middle of remaining.
        assert_eq!(median, 1_710_000_005);
    }

    #[test]
    fn test_reject_time_outliers_keeps_within_5min_drift() {
        let mut prices = vec![
            pp_with_time(100.0, 1_710_000_000, "a"),
            pp_with_time(100.0, 1_710_000_150, "b"), // +2.5 min
            pp_with_time(100.0, 1_710_000_299, "c"), // +4.98 min
        ];
        let _ = reject_time_outliers(&mut prices);
        assert_eq!(prices.len(), 3);
    }

    #[test]
    fn test_sanitize_drops_zero_server_time() {
        // server_time=0 means the source failed to deliver a Date header
        // — the whole security story fails open. Must be dropped.
        let prices = vec![
            pp_with_time(100.0, 0, "broken"),
            pp_with_time(101.0, 1_710_000_000, "ok"),
        ];
        let cleaned = sanitize(prices);
        assert_eq!(cleaned.len(), 1);
        assert_eq!(cleaned[0].source, "ok");
    }
}
