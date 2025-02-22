// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;
use std::collections::HashSet;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
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
    pub fn new(
        vec: &Vec<u64>,
        calc_avg: bool,
        calc_max: bool,
        calc_min: bool,
        percentiles: Option<HashSet<StatAggregation>>,
    ) -> Self {
        let mut min: u64 = u64::MAX;
        let mut max: u64 = 0;
        let mut sum: u64 = 0;
        for &val in vec {
            if calc_min && val < min {
                min = val;
            }
            if calc_max && val > max {
                max = val;
            }
            if calc_avg {
                sum += val;
            }
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
                    avg: if calc_avg && !vec.is_empty() {
                        sum / vec.len() as u64
                    } else {
                        0
                    },
                    max: if calc_max { max } else { 0 },
                    min: if calc_min { min } else { 0 },
                    percentiles: Some(pmap),
                }
            }
            None => Self {
                avg: if calc_avg && !vec.is_empty() {
                    sum / vec.len() as u64
                } else {
                    0
                },
                max: if calc_max { max } else { 0 },
                min: if calc_min { min } else { 0 },
                percentiles: None,
            },
        }
    }
}
