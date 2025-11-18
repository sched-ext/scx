// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Memory-aware query limits for perfetto trace queries
//!
//! Adjusts query limits based on available system memory to prevent OOM
//! while maximizing data accessibility on systems with plenty of RAM.

use sysinfo::System;

/// Memory-aware limit calculator
pub struct MemoryAwareLimits {
    available_memory_gb: f64,
}

impl MemoryAwareLimits {
    /// Create a new limit calculator based on current system memory
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_memory();

        let available_memory_bytes = sys.available_memory();
        let available_memory_gb = available_memory_bytes as f64 / (1024.0 * 1024.0 * 1024.0);

        Self {
            available_memory_gb,
        }
    }

    /// Get default limit for event queries based on available memory
    ///
    /// Memory thresholds:
    /// - < 4GB:  1,000 events (conservative)
    /// - 4-8GB:  10,000 events
    /// - 8-16GB: 50,000 events
    /// - 16-32GB: 100,000 events
    /// - 32-64GB: 500,000 events
    /// - >= 64GB: unlimited (query entire trace)
    pub fn event_query_limit(&self) -> Option<usize> {
        if self.available_memory_gb >= 64.0 {
            None // Unlimited - query entire trace
        } else if self.available_memory_gb >= 32.0 {
            Some(500_000)
        } else if self.available_memory_gb >= 16.0 {
            Some(100_000)
        } else if self.available_memory_gb >= 8.0 {
            Some(50_000)
        } else if self.available_memory_gb >= 4.0 {
            Some(10_000)
        } else {
            Some(1_000)
        }
    }

    /// Get default limit for timeline queries
    ///
    /// More conservative than event queries since timelines include
    /// aggregated data that can be memory-intensive
    pub fn timeline_limit(&self) -> usize {
        if self.available_memory_gb >= 64.0 {
            10_000
        } else if self.available_memory_gb >= 32.0 {
            5_000
        } else if self.available_memory_gb >= 16.0 {
            1_000
        } else if self.available_memory_gb >= 8.0 {
            500
        } else {
            100
        }
    }

    /// Get default limit for analysis results (top N processes, outliers, etc.)
    pub fn analysis_result_limit(&self) -> usize {
        if self.available_memory_gb >= 32.0 {
            1_000
        } else if self.available_memory_gb >= 16.0 {
            500
        } else if self.available_memory_gb >= 8.0 {
            100
        } else {
            50
        }
    }

    /// Get display limit (how many events to show in output)
    ///
    /// Always conservative to keep JSON responses manageable
    pub fn display_limit(&self) -> usize {
        if self.available_memory_gb >= 16.0 {
            500
        } else if self.available_memory_gb >= 8.0 {
            200
        } else {
            100
        }
    }

    /// Get available memory in GB
    pub fn available_gb(&self) -> f64 {
        self.available_memory_gb
    }
}

impl Default for MemoryAwareLimits {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_limits_calculation() {
        let limits = MemoryAwareLimits::new();

        println!("Available memory: {:.2} GB", limits.available_gb());
        println!("Event query limit: {:?}", limits.event_query_limit());
        println!("Timeline limit: {}", limits.timeline_limit());
        println!("Analysis result limit: {}", limits.analysis_result_limit());
        println!("Display limit: {}", limits.display_limit());

        // Basic sanity checks
        assert!(limits.timeline_limit() > 0);
        assert!(limits.analysis_result_limit() > 0);
        assert!(limits.display_limit() > 0);
        assert!(limits.display_limit() <= limits.timeline_limit());
    }
}
