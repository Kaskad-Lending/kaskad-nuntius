//! Robust price aggregation — drop-in extensions for `src/aggregator/mod.rs`.
//!
//! Exposes new functions **alongside** the existing `reject_outliers` and
//! `weighted_median` so call sites in `main.rs` can be switched opt-in.

use crate::types::PricePoint;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Per-asset tuning knobs for robust aggregation.
#[derive(Debug, Clone)]
pub struct RobustConfig {
    /// MAD sigma threshold (layer 1). Typical: 2.5–3.0.
    pub mad_sigma: f64,
    /// IQR multiplier (layer 2). Typical: 1.5.
    pub iqr_k: f64,
    /// Max allowed deviation from cross-source consensus in basis points (layer 3).
    pub cross_source_deviation_bps: u32,
    /// Huber tuning constant. 1.345 = 95 % efficiency for normals. Lower = more
    /// robust, less efficient. Typical for KAS: 1.5.
    pub huber_c: f64,
    /// Minimum confidence to consider the result usable. Informational — the
    /// caller decides what to do with it.
    pub min_confidence: f64,
}

impl RobustConfig {
    /// Sensible defaults for volatile altcoins (KAS, etc.).
    pub fn volatile() -> Self {
        Self {
            mad_sigma: 2.5,
            iqr_k: 1.5,
            cross_source_deviation_bps: 200,
            huber_c: 1.5,
            min_confidence: 0.7,
        }
    }

    /// Sensible defaults for stablecoins (USDC, etc.).
    pub fn stablecoin() -> Self {
        Self {
            mad_sigma: 2.0,
            iqr_k: 1.5,
            cross_source_deviation_bps: 20,
            huber_c: 1.345,
            min_confidence: 0.9,
        }
    }

    /// Sensible defaults for liquid majors (BTC, ETH).
    pub fn major() -> Self {
        Self {
            mad_sigma: 3.0,
            iqr_k: 1.5,
            cross_source_deviation_bps: 50,
            huber_c: 1.345,
            min_confidence: 0.8,
        }
    }
}

// ---------------------------------------------------------------------------
// Aggregation result
// ---------------------------------------------------------------------------

/// Output of [`estimate_with_confidence`].
#[derive(Debug, Clone)]
pub struct PriceEstimate {
    /// Robust price estimate (Huber M-estimator).
    pub price: f64,
    /// Confidence score in 0.0 .. 1.0.
    pub confidence: f64,
    /// Number of sources that survived all outlier layers.
    pub sources_used: usize,
    /// Observed spread in basis points (max-min / median × 10 000).
    pub spread_bps: u32,
}

// ---------------------------------------------------------------------------
// 3-layer outlier rejection
// ---------------------------------------------------------------------------

/// Layer 1 — MAD (Median Absolute Deviation). Same math as the existing
/// `aggregator::reject_outliers` but extracted as a building block.
pub fn reject_mad(prices: &mut Vec<PricePoint>, sigma: f64) {
    if prices.len() < 3 {
        return;
    }
    let median = sorted_median_f64(&prices_vec(prices));
    let mad = sorted_median_f64(
        &prices
            .iter()
            .map(|p| (p.price - median).abs())
            .collect::<Vec<_>>(),
    );
    if mad < 1e-10 {
        return;
    }
    let threshold = sigma * 1.4826 * mad;
    prices.retain(|p| (p.price - median).abs() <= threshold);
}

/// Layer 2 — IQR (Interquartile Range). Catches asymmetric distributions
/// that MAD can miss when the tail is one-sided.
pub fn reject_iqr(prices: &mut Vec<PricePoint>, k: f64) {
    if prices.len() < 4 {
        return;
    }
    let mut sorted: Vec<f64> = prices_vec(prices);
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let q1 = sorted[sorted.len() / 4];
    let q3 = sorted[3 * sorted.len() / 4];
    let iqr = q3 - q1;
    if iqr < 1e-10 {
        return;
    }

    let lower = q1 - k * iqr;
    let upper = q3 + k * iqr;
    prices.retain(|p| p.price >= lower && p.price <= upper);
}

/// Layer 3 — Cross-source deviation. For each source, compute the median of
/// all *other* sources and check if this source deviates by more than
/// `max_deviation_bps` basis points.
pub fn reject_cross_source(prices: &mut Vec<PricePoint>, max_deviation_bps: u32) {
    if prices.len() < 3 {
        return;
    }
    let threshold = max_deviation_bps as f64 / 10_000.0;
    let all_prices: Vec<f64> = prices_vec(prices);

    prices.retain(|p| {
        // Median of all sources except this one.
        let others: Vec<f64> = all_prices
            .iter()
            .copied()
            .filter(|&x| {
                (x - p.price).abs() > f64::EPSILON || {
                    // Handle duplicate prices: only skip the first match.
                    false
                }
            })
            .collect();
        if others.is_empty() {
            return true;
        }
        let others_median = sorted_median_f64(&others);
        if others_median < 1e-10 {
            return true;
        }
        let deviation = (p.price - others_median).abs() / others_median;
        deviation <= threshold
    });
}

/// Apply all 3 outlier rejection layers in sequence.
pub fn reject_outliers_robust(prices: &mut Vec<PricePoint>, cfg: &RobustConfig) {
    reject_mad(prices, cfg.mad_sigma);
    reject_iqr(prices, cfg.iqr_k);
    reject_cross_source(prices, cfg.cross_source_deviation_bps);
}

// ---------------------------------------------------------------------------
// Huber M-estimator
// ---------------------------------------------------------------------------

/// Compute the Huber M-estimate of location.
///
/// Iterative re-weighted least squares (IRLS). Starts from the median, then
/// refines: observations close to the current estimate are weighted like a
/// mean, observations far away are down-weighted proportionally to 1/|residual|.
///
/// `c` is the tuning constant: residuals within `c * scale` get full weight.
/// Canonical value for normal data: 1.345 (95 % efficiency).
///
/// Returns `None` if `prices` is empty.
pub fn huber_estimate(prices: &[PricePoint], c: f64) -> Option<f64> {
    if prices.is_empty() {
        return None;
    }
    if prices.len() == 1 {
        return Some(prices[0].price);
    }

    let vals: Vec<f64> = prices_vec_ref(prices);
    let mut estimate = sorted_median_f64(&vals);

    // Scale estimate: MAD * 1.4826 (consistent estimator of σ for normals).
    let mad = sorted_median_f64(
        &vals
            .iter()
            .map(|x| (x - estimate).abs())
            .collect::<Vec<_>>(),
    );
    let scale = if mad < 1e-10 {
        // All values identical (or nearly so) — just return the median.
        return Some(estimate);
    } else {
        1.4826 * mad
    };

    // IRLS loop. Converges in 5-20 iterations for well-behaved data.
    for _ in 0..50 {
        let mut w_sum = 0.0_f64;
        let mut wx_sum = 0.0_f64;

        for &x in &vals {
            let r = (x - estimate) / scale;
            let w = if r.abs() <= c { 1.0 } else { c / r.abs() };
            w_sum += w;
            wx_sum += w * x;
        }

        if w_sum < 1e-10 {
            break;
        }

        let new_estimate = wx_sum / w_sum;
        if (new_estimate - estimate).abs() < 1e-12 {
            break;
        }
        estimate = new_estimate;
    }

    Some(estimate)
}

// ---------------------------------------------------------------------------
// Confidence scoring
// ---------------------------------------------------------------------------

/// Compute a robust price estimate with an accompanying confidence score.
///
/// Confidence is a heuristic in \[0, 1\] based on:
/// - number of surviving sources (more = better),
/// - spread in bps (tighter = better),
/// - agreement: what fraction of sources are within 10 bps of the estimate.
pub fn estimate_with_confidence(
    prices: &[PricePoint],
    cfg: &RobustConfig,
) -> Option<PriceEstimate> {
    if prices.is_empty() {
        return None;
    }

    let price = huber_estimate(prices, cfg.huber_c)?;

    let vals: Vec<f64> = prices_vec_ref(prices);

    // Spread in bps.
    let min = vals.iter().copied().fold(f64::INFINITY, f64::min);
    let max = vals.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let median = sorted_median_f64(&vals);
    let spread_bps = if median > 1e-10 {
        ((max - min) / median * 10_000.0).round() as u32
    } else {
        0
    };

    // Source count factor: 0.0 at 1 source, 1.0 at 8+.
    let count_factor = ((prices.len() as f64 - 1.0) / 7.0).min(1.0);

    // Spread factor: 1.0 when spread < 10 bps, 0.0 when spread > 500 bps.
    let spread_factor = (1.0 - (spread_bps as f64 - 10.0) / 490.0).clamp(0.0, 1.0);

    // Agreement: fraction of sources within 10 bps of the estimate.
    let within_10bps = vals
        .iter()
        .filter(|&&x| {
            if price.abs() < 1e-10 {
                return true;
            }
            (x - price).abs() / price < 0.001
        })
        .count();
    let agreement = within_10bps as f64 / prices.len() as f64;

    // Weighted combination.
    let confidence =
        (0.35 * count_factor + 0.35 * spread_factor + 0.30 * agreement).clamp(0.0, 1.0);

    Some(PriceEstimate {
        price,
        confidence,
        sources_used: prices.len(),
        spread_bps,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn prices_vec(prices: &[PricePoint]) -> Vec<f64> {
    prices.iter().map(|p| p.price).collect()
}

fn prices_vec_ref(prices: &[PricePoint]) -> Vec<f64> {
    prices.iter().map(|p| p.price).collect()
}

/// Compute the median of a slice of f64 values. Returns 0.0 for an empty slice.
fn sorted_median_f64(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    let mut sorted = vals.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    sorted[sorted.len() / 2]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
                timestamp: 1000 + i as u64,
                source: format!("source_{}", i),
                server_time: None,
            })
            .collect()
    }

    // -- MAD --

    #[test]
    fn test_mad_removes_gross_outlier() {
        let mut prices = make_prices(&[100.0, 101.0, 99.5, 100.5, 999.0]);
        reject_mad(&mut prices, 3.0);
        assert_eq!(prices.len(), 4);
        assert!(prices.iter().all(|p| p.price < 200.0));
    }

    #[test]
    fn test_mad_all_same() {
        let mut prices = make_prices(&[42.0, 42.0, 42.0, 42.0]);
        reject_mad(&mut prices, 3.0);
        assert_eq!(prices.len(), 4);
    }

    #[test]
    fn test_mad_too_few() {
        let mut prices = make_prices(&[100.0, 999.0]);
        reject_mad(&mut prices, 3.0);
        assert_eq!(prices.len(), 2); // not enough to filter
    }

    // -- IQR --

    #[test]
    fn test_iqr_removes_tail() {
        let mut prices = make_prices(&[100.0, 100.5, 101.0, 101.5, 120.0]);
        reject_iqr(&mut prices, 1.5);
        assert!(prices.iter().all(|p| p.price < 110.0));
    }

    #[test]
    fn test_iqr_all_same() {
        let mut prices = make_prices(&[50.0, 50.0, 50.0, 50.0]);
        reject_iqr(&mut prices, 1.5);
        assert_eq!(prices.len(), 4);
    }

    #[test]
    fn test_iqr_too_few() {
        let mut prices = make_prices(&[1.0, 2.0, 999.0]);
        reject_iqr(&mut prices, 1.5);
        assert_eq!(prices.len(), 3); // need >= 4
    }

    // -- Cross-source deviation --

    #[test]
    fn test_cross_source_catches_subtle_outlier() {
        // 200 bps = 2 %. source_4 is ~2.5 % above the others.
        let mut prices = make_prices(&[100.0, 100.1, 99.9, 100.05, 102.5]);
        reject_cross_source(&mut prices, 200);
        assert_eq!(prices.len(), 4);
        assert!(prices.iter().all(|p| p.price < 102.0));
    }

    #[test]
    fn test_cross_source_keeps_tight_cluster() {
        let mut prices = make_prices(&[100.0, 100.02, 99.98, 100.01]);
        reject_cross_source(&mut prices, 50);
        assert_eq!(prices.len(), 4);
    }

    // -- 3-layer combined --

    #[test]
    fn test_robust_combined() {
        let mut prices = make_prices(&[
            100.0, 100.1, 99.9, 100.05, // tight cluster
            102.5,  // subtle outlier (~2.5 %)
            999.0,  // gross outlier
        ]);
        let cfg = RobustConfig::major();
        reject_outliers_robust(&mut prices, &cfg);
        assert!(prices.len() <= 5);
        assert!(prices.iter().all(|p| p.price < 200.0));
    }

    // -- Huber M-estimator --

    #[test]
    fn test_huber_clean_data() {
        let prices = make_prices(&[100.0, 101.0, 100.5, 100.2, 100.8]);
        let est = huber_estimate(&prices, 1.345).unwrap();
        assert!((est - 100.5).abs() < 0.5);
    }

    #[test]
    fn test_huber_with_outlier() {
        let prices = make_prices(&[100.0, 101.0, 100.5, 100.2, 150.0]);
        let est = huber_estimate(&prices, 1.345).unwrap();
        // Huber should down-weight the 150.0 outlier.
        assert!(est < 105.0, "Huber estimate too high: {}", est);
    }

    #[test]
    fn test_huber_single() {
        let prices = make_prices(&[42.0]);
        assert_eq!(huber_estimate(&prices, 1.345).unwrap(), 42.0);
    }

    #[test]
    fn test_huber_empty() {
        let prices: Vec<PricePoint> = vec![];
        assert!(huber_estimate(&prices, 1.345).is_none());
    }

    #[test]
    fn test_huber_all_same() {
        let prices = make_prices(&[77.0, 77.0, 77.0, 77.0]);
        assert_eq!(huber_estimate(&prices, 1.345).unwrap(), 77.0);
    }

    // -- Confidence scoring --

    #[test]
    fn test_high_confidence_tight_cluster() {
        let prices = make_prices(&[100.00, 100.01, 100.02, 99.99, 99.98, 100.01, 100.00, 100.03]);
        let cfg = RobustConfig::major();
        let est = estimate_with_confidence(&prices, &cfg).unwrap();
        assert!(
            est.confidence > 0.8,
            "confidence too low: {}",
            est.confidence
        );
        assert!(est.spread_bps < 10);
    }

    #[test]
    fn test_low_confidence_wide_spread() {
        let prices = make_prices(&[100.0, 105.0, 95.0]);
        let cfg = RobustConfig::major();
        let est = estimate_with_confidence(&prices, &cfg).unwrap();
        assert!(
            est.confidence < 0.7,
            "confidence too high: {}",
            est.confidence
        );
    }

    #[test]
    fn test_confidence_empty() {
        let prices: Vec<PricePoint> = vec![];
        let cfg = RobustConfig::major();
        assert!(estimate_with_confidence(&prices, &cfg).is_none());
    }
}
