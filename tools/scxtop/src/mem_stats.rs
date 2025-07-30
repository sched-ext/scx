// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use procfs::Meminfo;

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MemStatSnapshot {
    pub total_kb: u64,
    pub free_kb: u64,
    pub available_kb: u64,
    pub active_kb: u64,
    pub inactive_kb: u64,
    pub shmem_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

impl MemStatSnapshot {
    pub fn update(&mut self) -> Result<()> {
        let meminfo = Meminfo::new()?;
        self.total_kb = meminfo.mem_total;
        self.free_kb = meminfo.mem_free;
        self.available_kb = meminfo
            .mem_available
            .expect("available memory should be present");
        self.active_kb = meminfo.active;
        self.inactive_kb = meminfo.inactive;
        self.shmem_kb = meminfo.shmem.expect("shmem memory should be present");
        self.swap_total_kb = meminfo.swap_total;
        self.swap_free_kb = meminfo.swap_free;
        Ok(())
    }

    pub fn free_ratio(&self) -> f64 {
        if self.total_kb == 0 {
            return 0.0;
        }
        self.free_kb as f64 / self.total_kb as f64
    }

    pub fn swap_ratio(&self) -> f64 {
        if self.swap_total_kb == 0 {
            return 0.0;
        }
        self.swap_free_kb as f64 / self.swap_total_kb as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_free_ratio() {
        let snapshot = MemStatSnapshot {
            total_kb: 8000000,
            free_kb: 2000000,
            ..Default::default()
        };
        assert_eq!(snapshot.free_ratio(), 0.25);
    }

    #[test]
    fn test_swap_ratio() {
        let snapshot = MemStatSnapshot {
            swap_total_kb: 1000000,
            swap_free_kb: 400000,
            ..Default::default()
        };
        assert_eq!(snapshot.swap_ratio(), 0.4);
    }

    #[test]
    fn test_zero_total_ratios() {
        let snapshot = MemStatSnapshot::default();
        assert_eq!(snapshot.free_ratio(), 0.0);
        assert_eq!(snapshot.swap_ratio(), 0.0);
    }
}
