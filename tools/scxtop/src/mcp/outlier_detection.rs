// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Outlier Detection for Trace Analysis
//!
//! Provides statistical outlier detection methods for identifying anomalous
//! events, processes, and patterns in perfetto traces.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Outlier detection method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutlierMethod {
    /// Interquartile Range (IQR) method - robust to extreme values
    /// Outliers: Q1 - 1.5*IQR or Q3 + 1.5*IQR
    IQR,
    /// Modified Z-score using Median Absolute Deviation (MAD)
    /// More robust than standard deviation
    MAD,
    /// Standard deviation method
    /// Outliers: mean ± k*stddev (default k=3)
    StdDev,
    /// Percentile-based (values above p99 or p999)
    Percentile,
}

/// Outlier information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outlier<T> {
    /// The outlier value
    pub value: T,
    /// How many standard deviations or IQRs from the median/mean
    pub severity: f64,
    /// Index in the original data
    pub index: usize,
    /// Detection method used
    pub method: OutlierMethod,
}

/// Outlier detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutlierResult {
    /// Total data points analyzed
    pub total_points: usize,
    /// Number of outliers detected
    pub outlier_count: usize,
    /// Outlier percentage
    pub outlier_percentage: f64,
    /// Detection method used
    pub method: OutlierMethod,
    /// Statistical thresholds used
    pub thresholds: OutlierThresholds,
}

/// Statistical thresholds for outlier detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutlierThresholds {
    pub lower_bound: f64,
    pub upper_bound: f64,
    pub median: f64,
    pub q1: Option<f64>,
    pub q3: Option<f64>,
    pub iqr: Option<f64>,
    pub mean: Option<f64>,
    pub std_dev: Option<f64>,
    pub mad: Option<f64>,
}

/// Outlier detector for numerical data
pub struct OutlierDetector;

impl OutlierDetector {
    /// Detect outliers using IQR method
    pub fn detect_iqr(data: &[u64], multiplier: f64) -> (Vec<Outlier<u64>>, OutlierResult) {
        if data.is_empty() {
            return (vec![], OutlierResult::empty(OutlierMethod::IQR));
        }

        let mut sorted = data.to_vec();
        sorted.sort_unstable();

        let (q1, median, q3) = Self::calculate_quartiles(&sorted);
        let iqr = q3 - q1;
        let lower_bound = q1 - multiplier * iqr;
        let upper_bound = q3 + multiplier * iqr;

        let mut outliers = Vec::new();
        for (index, &value) in data.iter().enumerate() {
            let value_f64 = value as f64;
            if value_f64 < lower_bound || value_f64 > upper_bound {
                let severity = if value_f64 < lower_bound {
                    (q1 - value_f64) / iqr
                } else {
                    (value_f64 - q3) / iqr
                };

                outliers.push(Outlier {
                    value,
                    severity,
                    index,
                    method: OutlierMethod::IQR,
                });
            }
        }

        let result = OutlierResult {
            total_points: data.len(),
            outlier_count: outliers.len(),
            outlier_percentage: (outliers.len() as f64 / data.len() as f64) * 100.0,
            method: OutlierMethod::IQR,
            thresholds: OutlierThresholds {
                lower_bound,
                upper_bound,
                median,
                q1: Some(q1),
                q3: Some(q3),
                iqr: Some(iqr),
                mean: None,
                std_dev: None,
                mad: None,
            },
        };

        (outliers, result)
    }

    /// Detect outliers using Modified Z-score (MAD method)
    pub fn detect_mad(data: &[u64], threshold: f64) -> (Vec<Outlier<u64>>, OutlierResult) {
        if data.is_empty() {
            return (vec![], OutlierResult::empty(OutlierMethod::MAD));
        }

        let mut sorted = data.to_vec();
        sorted.sort_unstable();

        let median = Self::median(&sorted);
        let mad = Self::median_absolute_deviation(&sorted, median);

        // Modified Z-score: 0.6745 * (x - median) / MAD
        let mut outliers = Vec::new();
        for (index, &value) in data.iter().enumerate() {
            let modified_z = if mad > 0.0 {
                0.6745 * ((value as f64 - median).abs() / mad)
            } else {
                0.0
            };

            if modified_z > threshold {
                outliers.push(Outlier {
                    value,
                    severity: modified_z,
                    index,
                    method: OutlierMethod::MAD,
                });
            }
        }

        let lower_bound = median - threshold * mad / 0.6745;
        let upper_bound = median + threshold * mad / 0.6745;

        let result = OutlierResult {
            total_points: data.len(),
            outlier_count: outliers.len(),
            outlier_percentage: (outliers.len() as f64 / data.len() as f64) * 100.0,
            method: OutlierMethod::MAD,
            thresholds: OutlierThresholds {
                lower_bound,
                upper_bound,
                median,
                q1: None,
                q3: None,
                iqr: None,
                mean: None,
                std_dev: None,
                mad: Some(mad),
            },
        };

        (outliers, result)
    }

    /// Detect outliers using standard deviation method
    pub fn detect_stddev(data: &[u64], sigma: f64) -> (Vec<Outlier<u64>>, OutlierResult) {
        if data.is_empty() {
            return (vec![], OutlierResult::empty(OutlierMethod::StdDev));
        }

        let mean = data.iter().map(|&x| x as f64).sum::<f64>() / data.len() as f64;
        let variance =
            data.iter().map(|&x| (x as f64 - mean).powi(2)).sum::<f64>() / data.len() as f64;
        let std_dev = variance.sqrt();

        let lower_bound = mean - sigma * std_dev;
        let upper_bound = mean + sigma * std_dev;

        let mut outliers = Vec::new();
        for (index, &value) in data.iter().enumerate() {
            let value_f64 = value as f64;
            if value_f64 < lower_bound || value_f64 > upper_bound {
                let z_score = ((value_f64 - mean) / std_dev).abs();
                outliers.push(Outlier {
                    value,
                    severity: z_score,
                    index,
                    method: OutlierMethod::StdDev,
                });
            }
        }

        let mut sorted = data.to_vec();
        sorted.sort_unstable();
        let median = Self::median(&sorted);

        let result = OutlierResult {
            total_points: data.len(),
            outlier_count: outliers.len(),
            outlier_percentage: (outliers.len() as f64 / data.len() as f64) * 100.0,
            method: OutlierMethod::StdDev,
            thresholds: OutlierThresholds {
                lower_bound,
                upper_bound,
                median,
                q1: None,
                q3: None,
                iqr: None,
                mean: Some(mean),
                std_dev: Some(std_dev),
                mad: None,
            },
        };

        (outliers, result)
    }

    /// Detect outliers using percentile method (p99 or p999)
    pub fn detect_percentile(data: &[u64], percentile: f64) -> (Vec<Outlier<u64>>, OutlierResult) {
        if data.is_empty() {
            return (vec![], OutlierResult::empty(OutlierMethod::Percentile));
        }

        let mut sorted = data.to_vec();
        sorted.sort_unstable();

        let threshold_idx =
            ((sorted.len() as f64 * percentile / 100.0) as usize).min(sorted.len() - 1);
        let threshold = sorted[threshold_idx] as f64;
        let median = Self::median(&sorted);

        let mut outliers = Vec::new();
        for (index, &value) in data.iter().enumerate() {
            if value as f64 > threshold {
                let severity = (value as f64 - median) / (threshold - median).max(1.0);
                outliers.push(Outlier {
                    value,
                    severity,
                    index,
                    method: OutlierMethod::Percentile,
                });
            }
        }

        let result = OutlierResult {
            total_points: data.len(),
            outlier_count: outliers.len(),
            outlier_percentage: (outliers.len() as f64 / data.len() as f64) * 100.0,
            method: OutlierMethod::Percentile,
            thresholds: OutlierThresholds {
                lower_bound: 0.0,
                upper_bound: threshold,
                median,
                q1: None,
                q3: None,
                iqr: None,
                mean: None,
                std_dev: None,
                mad: None,
            },
        };

        (outliers, result)
    }

    /// Automatic outlier detection using the most appropriate method
    pub fn detect_auto(data: &[u64]) -> (Vec<Outlier<u64>>, OutlierResult) {
        // Use IQR by default as it's robust to extreme values
        Self::detect_iqr(data, 1.5)
    }

    // Helper functions

    fn calculate_quartiles(sorted_data: &[u64]) -> (f64, f64, f64) {
        let q1 = Self::percentile(sorted_data, 25.0);
        let median = Self::percentile(sorted_data, 50.0);
        let q3 = Self::percentile(sorted_data, 75.0);
        (q1, median, q3)
    }

    fn percentile(sorted_data: &[u64], p: f64) -> f64 {
        if sorted_data.is_empty() {
            return 0.0;
        }

        // Use (len - 1) * p / 100 for proper interpolation
        let index = (sorted_data.len() - 1) as f64 * p / 100.0;

        let lower = index.floor() as usize;
        let upper = index.ceil() as usize;

        if lower >= sorted_data.len() {
            return sorted_data[sorted_data.len() - 1] as f64;
        }

        if lower == upper {
            sorted_data[lower] as f64
        } else {
            let fraction = index - lower as f64;
            sorted_data[lower] as f64 * (1.0 - fraction) + sorted_data[upper] as f64 * fraction
        }
    }

    fn median(sorted_data: &[u64]) -> f64 {
        Self::percentile(sorted_data, 50.0)
    }

    fn median_absolute_deviation(sorted_data: &[u64], median: f64) -> f64 {
        let mut deviations: Vec<u64> = sorted_data
            .iter()
            .map(|&x| (x as f64 - median).abs() as u64)
            .collect();
        deviations.sort_unstable();
        Self::median(&deviations)
    }
}

impl OutlierResult {
    fn empty(method: OutlierMethod) -> Self {
        Self {
            total_points: 0,
            outlier_count: 0,
            outlier_percentage: 0.0,
            method,
            thresholds: OutlierThresholds {
                lower_bound: 0.0,
                upper_bound: 0.0,
                median: 0.0,
                q1: None,
                q3: None,
                iqr: None,
                mean: None,
                std_dev: None,
                mad: None,
            },
        }
    }
}

/// Process-level outlier information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessOutlier {
    pub pid: i32,
    pub comm: String,
    pub metric: String,
    pub value: u64,
    pub severity: f64,
    pub percentile: f64,
}

/// CPU-level outlier information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuOutlier {
    pub cpu: u32,
    pub metric: String,
    pub value: u64,
    pub severity: f64,
    pub percentile: f64,
}

/// Event-level outlier information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventOutlier {
    pub event_type: String,
    pub timestamp_ns: u64,
    pub pid: Option<i32>,
    pub cpu: Option<u32>,
    pub metric: String,
    pub value: u64,
    pub severity: f64,
}

/// Outlier summary across all metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutlierSummary {
    pub total_outliers: usize,
    pub process_outliers: Vec<ProcessOutlier>,
    pub cpu_outliers: Vec<CpuOutlier>,
    pub event_outliers: Vec<EventOutlier>,
    pub detection_method: OutlierMethod,
    pub by_metric: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iqr_outlier_detection() {
        let data = vec![10, 12, 11, 13, 12, 14, 100, 11, 13, 12];
        let (outliers, result) = OutlierDetector::detect_iqr(&data, 1.5);

        assert_eq!(result.total_points, 10);
        assert_eq!(outliers.len(), 1); // 100 is an outlier
        assert_eq!(outliers[0].value, 100);
        assert!(outliers[0].severity > 0.0);
    }

    #[test]
    fn test_mad_outlier_detection() {
        let data = vec![10, 12, 11, 13, 12, 14, 100, 11, 13, 12];
        let (outliers, result) = OutlierDetector::detect_mad(&data, 3.5);

        assert_eq!(result.total_points, 10);
        assert!(!outliers.is_empty());
    }

    #[test]
    fn test_stddev_outlier_detection() {
        let data = vec![10, 12, 11, 13, 12, 14, 100, 11, 13, 12];
        let (outliers, result) = OutlierDetector::detect_stddev(&data, 2.5);

        assert_eq!(result.total_points, 10);
        assert!(!outliers.is_empty());
    }

    #[test]
    fn test_percentile_outlier_detection() {
        let data = vec![10, 12, 11, 13, 12, 14, 100, 11, 13, 12];
        let (outliers, result) = OutlierDetector::detect_percentile(&data, 85.0);

        assert_eq!(result.total_points, 10);
        assert!(!outliers.is_empty());
    }

    #[test]
    fn test_no_outliers() {
        let data = vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19];
        let (outliers, result) = OutlierDetector::detect_iqr(&data, 1.5);

        assert_eq!(result.total_points, 10);
        assert_eq!(outliers.len(), 0);
    }

    #[test]
    fn test_empty_data() {
        let data: Vec<u64> = vec![];
        let (outliers, result) = OutlierDetector::detect_iqr(&data, 1.5);

        assert_eq!(result.total_points, 0);
        assert_eq!(outliers.len(), 0);
    }

    #[test]
    fn test_quartile_calculation() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let (q1, median, q3) = OutlierDetector::calculate_quartiles(&data);

        assert!((median - 5.5).abs() < 0.1);
        assert!(q1 < median);
        assert!(q3 > median);
    }
}
