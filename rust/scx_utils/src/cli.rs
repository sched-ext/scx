// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! CLI argument utilities for sched_ext schedulers.
//!

use crate::topology::{NR_PARTITION_MAX_CORES, NR_PARTITION_MIN_CORES};
use anyhow::{bail, Result};
use clap::Args;

/// Topology configuration arguments
#[derive(Args, Debug, Clone)]
pub struct TopologyArgs {
    /// Configure virtual LLC partitioning with min and max cores per partition.
    /// Format: --virt-llc [min_cores-max_cores]
    ///
    /// Virtual LLCs allow splitting large LLC domains into smaller partitions
    /// to improve scheduling locality and reduce contention. The min and max
    /// values define the range of cores that can be grouped together in each
    /// virtual LLC partition.
    ///
    /// Examples:
    ///   --virt-llc=2-8    (partition with 2-8 cores each)
    ///   --virt-llc        (use default range: 2-8 cores)
    #[clap(
        long = "virt-llc",
        value_delimiter = '-',
        num_args = 0..=1,
        require_equals = true,
        help = "Enable virtual LLC partitioning with optional core range (format: min-max, defaults to 2-8)"
    )]
    pub virt_llc: Option<Vec<usize>>,
}

impl TopologyArgs {
    /// Get the virtual LLC configuration as a tuple of (min_cores, max_cores).
    /// Returns None if virtual LLC is not configured.
    /// If configured with no arguments, returns the default range from NR_PARTITION constants.
    pub fn get_nr_cores_per_vllc(&self) -> Option<(usize, usize)> {
        match &self.virt_llc {
            Some(values) if values.len() == 2 => Some((values[0], values[1])),
            Some(values) if values.is_empty() => {
                Some((*NR_PARTITION_MIN_CORES, *NR_PARTITION_MAX_CORES))
            }
            _ => None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some((min_cores, max_cores)) = self.get_nr_cores_per_vllc() {
            if min_cores == 0 {
                bail!("Minimum cores for virtual LLC must be greater than 0");
            }
            if min_cores > max_cores {
                bail!(
                    "Minimum cores ({}) cannot be greater than maximum cores ({})",
                    min_cores,
                    max_cores
                );
            }
        }
        Ok(())
    }
}

impl Default for TopologyArgs {
    fn default() -> Self {
        Self { virt_llc: None }
    }
}
