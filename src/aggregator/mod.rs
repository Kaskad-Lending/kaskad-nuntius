use crate::types::PricePoint;
use alloy_primitives::U256;

/// Compute the weighted median of a set of price observations.
/// If fewer than half of sources report volume, uses equal weighting
/// to prevent a single volume-reporting source from dominating.
pub fn weighted_median(prices: &[PricePoint]) -> Option<f64> {
    if prices.is_empty() {
        return None;
    }
    if prices.len() == 1 {
        return Some(prices[0].price);
    }

    // Use volume weighting only if a majority of sources report volume.
    // Otherwise, fall back to equal weight to prevent skew.
    let sources_with_volume = prices.iter().filter(|p| p.volume > 0.0).count();
    let use_volume = sources_with_volume * 2 > prices.len();

    let mut weighted: Vec<(f64, f64)> = prices
        .iter()
        .map(|p| {
            let weight = if use_volume && p.volume > 0.0 {
                p.volume
            } else {
                1.0
            };
            (p.price, weight)
        })
        .collect();

    // Sort by price
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

    // Fallback: last price
    Some(weighted.last().unwrap().0)
}

/// Reject outliers using MAD (Median Absolute Deviation).
/// Removes points that deviate more than `sigma` MADs from the median.
pub fn reject_outliers(prices: &mut Vec<PricePoint>, sigma: f64) {
    if prices.len() < 3 {
        return; // Not enough data to detect outliers
    }

    // Compute median price
    let mut sorted_prices: Vec<f64> = prices.iter().map(|p| p.price).collect();
    sorted_prices.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = sorted_prices[sorted_prices.len() / 2];

    // Compute MAD
    let mut abs_devs: Vec<f64> = sorted_prices.iter().map(|p| (p - median).abs()).collect();
    abs_devs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mad = abs_devs[abs_devs.len() / 2];

    // If MAD is zero (all same price), don't filter
    if mad < 1e-10 {
        return;
    }

    // Modified Z-score threshold
    let threshold = sigma * 1.4826 * mad; // 1.4826 = consistency constant for normal dist

    prices.retain(|p| (p.price - median).abs() <= threshold);
}

/// Convert a floating-point price to a fixed-point U256 with given decimals.
/// For example, price=1234.56, decimals=8 → 123456000000
pub fn to_fixed_point(price: f64, decimals: u8) -> U256 {
    let multiplier = 10u64.pow(decimals as u32) as f64;
    let fixed = (price * multiplier).round() as u128;
    U256::from(fixed)
}

/// Compute a sources hash: keccak256 of concatenated source names.
pub fn sources_hash(prices: &[PricePoint]) -> alloy_primitives::B256 {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    for p in prices {
        hasher.update(p.source.as_bytes());
        hasher.update(b"|");
        hasher.update(p.price.to_le_bytes());
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
                timestamp: 1000 + i as u64,
                source: format!("source_{}", i),
                server_time: None,
            })
            .collect()
    }

    #[test]
    fn test_weighted_median_odd() {
        let prices = make_prices(&[100.0, 102.0, 101.0]);
        let median = weighted_median(&prices).unwrap();
        assert_eq!(median, 101.0);
    }

    #[test]
    fn test_weighted_median_even() {
        let prices = make_prices(&[100.0, 102.0, 101.0, 103.0]);
        let median = weighted_median(&prices).unwrap();
        // With equal weights, crosses halfway at the 2nd or 3rd element
        assert!(median >= 101.0 && median <= 102.0);
    }

    #[test]
    fn test_weighted_median_single() {
        let prices = make_prices(&[42.0]);
        assert_eq!(weighted_median(&prices).unwrap(), 42.0);
    }

    #[test]
    fn test_weighted_median_empty() {
        let prices: Vec<PricePoint> = vec![];
        assert!(weighted_median(&prices).is_none());
    }

    #[test]
    fn test_outlier_rejection() {
        let mut prices = make_prices(&[100.0, 101.0, 99.5, 100.5, 999.0]);
        reject_outliers(&mut prices, 3.0);
        // 999.0 should be removed
        assert_eq!(prices.len(), 4);
        assert!(prices.iter().all(|p| p.price < 200.0));
    }

    #[test]
    fn test_fixed_point_conversion() {
        let result = to_fixed_point(1234.56, 8);
        assert_eq!(result, U256::from(123456000000u64));
    }

    #[test]
    fn test_fixed_point_small() {
        let result = to_fixed_point(0.001, 8);
        assert_eq!(result, U256::from(100000u64));
    }
}
