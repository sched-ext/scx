// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;
use std::collections::HashSet;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StatAggregation {
    P999,
    P99,
    P95,
    P90,
    P75,
    P50,
    P25,
    P10,
    P5,
    P1,
}

#[allow(dead_code)]
impl StatAggregation {
    /// Returns the f64 value of the StatAggregation.
    fn to_f64(&self) -> f64 {
        match self {
            StatAggregation::P999 => 99.9,
            StatAggregation::P99 => 99.0,
            StatAggregation::P95 => 95.0,
            StatAggregation::P90 => 90.0,
            StatAggregation::P75 => 75.0,
            StatAggregation::P50 => 50.0,
            StatAggregation::P25 => 25.0,
            StatAggregation::P10 => 10.0,
            StatAggregation::P5 => 5.0,
            StatAggregation::P1 => 1.0,
        }
    }
}

impl std::fmt::Display for StatAggregation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            StatAggregation::P999 => write!(f, "p99.9"),
            StatAggregation::P99 => write!(f, "p99"),
            StatAggregation::P95 => write!(f, "p95"),
            StatAggregation::P90 => write!(f, "p90"),
            StatAggregation::P75 => write!(f, "p75"),
            StatAggregation::P50 => write!(f, "p50"),
            StatAggregation::P25 => write!(f, "p25"),
            StatAggregation::P10 => write!(f, "p10"),
            StatAggregation::P5 => write!(f, "p5"),
            StatAggregation::P1 => write!(f, "p1"),
        }
    }
}

pub struct VecStats {
    pub avg: u64,
    pub max: u64,
    pub min: u64,
    pub percentiles: Option<BTreeMap<StatAggregation, u64>>,
}

impl VecStats {
    pub fn new(vec: &Vec<u64>, percentiles: Option<HashSet<StatAggregation>>) -> Self {
        let mut min: u64 = u64::MAX;
        let mut max: u64 = 0;
        let mut sum: u128 = 0;
        for &val in vec {
            if val < min {
                min = val;
            }
            if val > max {
                max = val;
            }
            sum += val as u128;
        }
        match percentiles {
            Some(ref hashset) => {
                let mut pmap = BTreeMap::new();
                if !hashset.is_empty() && !vec.is_empty() {
                    let mut sorted = vec.clone();
                    sorted.sort_unstable();

                    let n = sorted.len();
                    for agg in hashset {
                        let rank = (agg.to_f64() / 100.0) * (n as f64 - 1.0);

                        let rank_floor = rank.floor();
                        let rank_ceil = rank.ceil();

                        let value = if rank_floor == rank_ceil {
                            sorted[rank as usize]
                        } else {
                            let d0 = sorted[rank_floor as usize];
                            let d1 = sorted[rank_ceil as usize];
                            d0 + (rank - rank_floor) as u64 * (d1 - d0)
                        };
                        pmap.insert(agg.clone(), value);
                    }
                }
                Self {
                    avg: if !vec.is_empty() {
                        (sum / (vec.len() as u128)) as u64
                    } else {
                        0
                    },
                    max,
                    min,
                    percentiles: Some(pmap),
                }
            }
            None => Self {
                avg: if !vec.is_empty() {
                    (sum / (vec.len() as u128)) as u64
                } else {
                    0
                },
                max,
                min,
                percentiles: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vec_stats_empty_data() {
        let data: Vec<u64> = Vec::new();
        let stats = VecStats::new(&data, None);

        assert_eq!(stats.min, u64::MAX);
        assert_eq!(stats.max, 0);
        assert_eq!(stats.avg, 0);
        assert!(stats.percentiles.is_none());
    }

    #[test]
    fn test_vec_stats_single_value() {
        let data = vec![42];
        let stats = VecStats::new(&data, None);

        assert_eq!(stats.min, 42);
        assert_eq!(stats.max, 42);
        assert_eq!(stats.avg, 42);
        assert!(stats.percentiles.is_none());
    }

    #[test]
    fn test_vec_stats_basic_calculations() {
        let data = vec![10, 20, 30, 40, 50];
        let stats = VecStats::new(&data, None);

        assert_eq!(stats.min, 10);
        assert_eq!(stats.max, 50);
        assert_eq!(stats.avg, 30); // (10+20+30+40+50)/5 = 30
        assert!(stats.percentiles.is_none());
    }

    #[test]
    fn test_vec_stats_all_zeros() {
        let data = vec![0, 0, 0, 0, 0];
        let stats = VecStats::new(&data, None);

        assert_eq!(stats.min, 0);
        assert_eq!(stats.max, 0);
        assert_eq!(stats.avg, 0);
    }

    #[test]
    fn test_vec_stats_same_values() {
        let data = vec![25, 25, 25, 25];
        let stats = VecStats::new(&data, None);

        assert_eq!(stats.min, 25);
        assert_eq!(stats.max, 25);
        assert_eq!(stats.avg, 25);
    }

    #[test]
    fn test_vec_stats_unsorted_data() {
        let data = vec![50, 10, 30, 20, 40];
        let stats = VecStats::new(&data, None);

        assert_eq!(stats.min, 10);
        assert_eq!(stats.max, 50);
        assert_eq!(stats.avg, 30); // (50+10+30+20+40)/5 = 30
    }

    #[test]
    fn test_vec_stats_with_percentiles() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut percentiles = HashSet::new();
        percentiles.insert(StatAggregation::P50);
        percentiles.insert(StatAggregation::P90);
        percentiles.insert(StatAggregation::P99);

        let stats = VecStats::new(&data, Some(percentiles));

        assert_eq!(stats.min, 1);
        assert_eq!(stats.max, 10);
        assert_eq!(stats.avg, 5); // (1+2+...+10)/10 = 5.5, truncated to 5

        let percentile_map = stats.percentiles.unwrap();
        assert!(percentile_map.contains_key(&StatAggregation::P50));
        assert!(percentile_map.contains_key(&StatAggregation::P90));
        assert!(percentile_map.contains_key(&StatAggregation::P99));

        // P50 of [1,2,3,4,5,6,7,8,9,10] should be around 5-6
        let p50 = *percentile_map.get(&StatAggregation::P50).unwrap();
        assert!((5..=6).contains(&p50));

        // P90 should be around 9-10
        let p90 = *percentile_map.get(&StatAggregation::P90).unwrap();
        assert!(p90 >= 9);

        // P99 should be close to 10
        let p99 = *percentile_map.get(&StatAggregation::P99).unwrap();
        assert!(p99 >= 9);
    }

    #[test]
    fn test_vec_stats_percentiles_single_value() {
        let data = vec![42];
        let mut percentiles = HashSet::new();
        percentiles.insert(StatAggregation::P50);
        percentiles.insert(StatAggregation::P90);

        let stats = VecStats::new(&data, Some(percentiles));

        let percentile_map = stats.percentiles.unwrap();
        assert_eq!(*percentile_map.get(&StatAggregation::P50).unwrap(), 42);
        assert_eq!(*percentile_map.get(&StatAggregation::P90).unwrap(), 42);
    }

    #[test]
    fn test_vec_stats_percentiles_empty_data() {
        let data: Vec<u64> = Vec::new();
        let mut percentiles = HashSet::new();
        percentiles.insert(StatAggregation::P50);

        let stats = VecStats::new(&data, Some(percentiles));

        assert_eq!(stats.min, u64::MAX);
        assert_eq!(stats.max, 0);
        assert_eq!(stats.avg, 0);

        let percentile_map = stats.percentiles.unwrap();
        assert!(percentile_map.is_empty()); // Should be empty for empty data
    }

    #[test]
    fn test_vec_stats_percentiles_empty_set() {
        let data = vec![1, 2, 3, 4, 5];
        let percentiles = HashSet::new(); // Empty set

        let stats = VecStats::new(&data, Some(percentiles));

        assert_eq!(stats.min, 1);
        assert_eq!(stats.max, 5);
        assert_eq!(stats.avg, 3);

        let percentile_map = stats.percentiles.unwrap();
        assert!(percentile_map.is_empty()); // Should be empty for empty percentile set
    }

    #[test]
    fn test_vec_stats_all_percentiles() {
        let data = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        let mut percentiles = HashSet::new();
        percentiles.insert(StatAggregation::P1);
        percentiles.insert(StatAggregation::P5);
        percentiles.insert(StatAggregation::P10);
        percentiles.insert(StatAggregation::P25);
        percentiles.insert(StatAggregation::P50);
        percentiles.insert(StatAggregation::P75);
        percentiles.insert(StatAggregation::P90);
        percentiles.insert(StatAggregation::P95);
        percentiles.insert(StatAggregation::P99);
        percentiles.insert(StatAggregation::P999);

        let stats = VecStats::new(&data, Some(percentiles));

        let percentile_map = stats.percentiles.unwrap();

        // Verify all percentiles are calculated
        assert!(percentile_map.contains_key(&StatAggregation::P1));
        assert!(percentile_map.contains_key(&StatAggregation::P5));
        assert!(percentile_map.contains_key(&StatAggregation::P10));
        assert!(percentile_map.contains_key(&StatAggregation::P25));
        assert!(percentile_map.contains_key(&StatAggregation::P50));
        assert!(percentile_map.contains_key(&StatAggregation::P75));
        assert!(percentile_map.contains_key(&StatAggregation::P90));
        assert!(percentile_map.contains_key(&StatAggregation::P95));
        assert!(percentile_map.contains_key(&StatAggregation::P99));
        assert!(percentile_map.contains_key(&StatAggregation::P999));

        // Verify percentiles are in ascending order
        let p1 = *percentile_map.get(&StatAggregation::P1).unwrap();
        let p50 = *percentile_map.get(&StatAggregation::P50).unwrap();
        let p99 = *percentile_map.get(&StatAggregation::P99).unwrap();

        assert!(p1 <= p50);
        assert!(p50 <= p99);
    }

    #[test]
    fn test_vec_stats_large_values() {
        let data = vec![u64::MAX / 4, u64::MAX / 3, u64::MAX / 2];
        let stats = VecStats::new(&data, None);

        assert_eq!(stats.min, u64::MAX / 4);
        assert_eq!(stats.max, u64::MAX / 2);
        // Average calculation should handle large numbers without overflow
        assert!(stats.avg > u64::MAX / 4);
        assert!(stats.avg < u64::MAX);
    }

    #[test]
    fn test_vec_stats_duplicate_values() {
        let data = vec![5, 5, 10, 10, 15, 15];
        let mut percentiles = HashSet::new();
        percentiles.insert(StatAggregation::P50);

        let stats = VecStats::new(&data, Some(percentiles));

        assert_eq!(stats.min, 5);
        assert_eq!(stats.max, 15);
        assert_eq!(stats.avg, 10); // (5+5+10+10+15+15)/6 = 60/6 = 10

        let percentile_map = stats.percentiles.unwrap();
        let p50 = *percentile_map.get(&StatAggregation::P50).unwrap();
        assert_eq!(p50, 10);
    }

    #[test]
    fn test_vec_stats_integer_division_behavior() {
        // Test cases where integer division affects results
        let data = vec![1, 2, 3];
        let stats = VecStats::new(&data, None);

        // Sum = 6, length = 3, so 6/3 = 2
        assert_eq!(stats.avg, 2);

        let data2 = vec![1, 2, 3, 4];
        let stats2 = VecStats::new(&data2, None);

        // Sum = 10, length = 4, so 10/4 = 2 (integer division truncates)
        assert_eq!(stats2.avg, 2);
    }

    #[test]
    fn test_vec_stats_percentile_interpolation() {
        // Test data where percentiles require interpolation
        let data = vec![1, 2, 3, 4];
        let mut percentiles = HashSet::new();
        percentiles.insert(StatAggregation::P50);

        let stats = VecStats::new(&data, Some(percentiles));

        let percentile_map = stats.percentiles.unwrap();
        let p50 = *percentile_map.get(&StatAggregation::P50).unwrap();

        // For 4 elements [1,2,3,4], P50 should be between 2 and 3
        assert!((2..=3).contains(&p50));
    }

    #[test]
    fn test_stat_aggregation_to_f64() {
        assert_eq!(StatAggregation::P1.to_f64(), 1.0);
        assert_eq!(StatAggregation::P5.to_f64(), 5.0);
        assert_eq!(StatAggregation::P10.to_f64(), 10.0);
        assert_eq!(StatAggregation::P25.to_f64(), 25.0);
        assert_eq!(StatAggregation::P50.to_f64(), 50.0);
        assert_eq!(StatAggregation::P75.to_f64(), 75.0);
        assert_eq!(StatAggregation::P90.to_f64(), 90.0);
        assert_eq!(StatAggregation::P95.to_f64(), 95.0);
        assert_eq!(StatAggregation::P99.to_f64(), 99.0);
        assert_eq!(StatAggregation::P999.to_f64(), 99.9);
    }

    #[test]
    fn test_stat_aggregation_display() {
        assert_eq!(format!("{}", StatAggregation::P1), "p1");
        assert_eq!(format!("{}", StatAggregation::P5), "p5");
        assert_eq!(format!("{}", StatAggregation::P10), "p10");
        assert_eq!(format!("{}", StatAggregation::P25), "p25");
        assert_eq!(format!("{}", StatAggregation::P50), "p50");
        assert_eq!(format!("{}", StatAggregation::P75), "p75");
        assert_eq!(format!("{}", StatAggregation::P90), "p90");
        assert_eq!(format!("{}", StatAggregation::P95), "p95");
        assert_eq!(format!("{}", StatAggregation::P99), "p99");
        assert_eq!(format!("{}", StatAggregation::P999), "p99.9");
    }

    #[test]
    fn test_vec_stats_edge_case_two_values() {
        let data = vec![10, 20];
        let mut percentiles = HashSet::new();
        percentiles.insert(StatAggregation::P50);

        let stats = VecStats::new(&data, Some(percentiles));

        assert_eq!(stats.min, 10);
        assert_eq!(stats.max, 20);
        assert_eq!(stats.avg, 15); // (10+20)/2 = 15

        let percentile_map = stats.percentiles.unwrap();
        let p50 = *percentile_map.get(&StatAggregation::P50).unwrap();
        assert!((10..=20).contains(&p50));
    }
}
