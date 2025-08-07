// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use procfs::Meminfo;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MemStatSnapshot {
    pub total_kb: u64,
    pub free_kb: u64,
    pub available_kb: u64,
    pub active_kb: u64,
    pub inactive_kb: u64,
    pub active_anon_kb: u64,
    pub inactive_anon_kb: u64,
    pub active_file_kb: u64,
    pub inactive_file_kb: u64,
    pub unevictable_kb: u64,
    pub mlocked_kb: u64,
    pub shmem_kb: u64,
    pub buffers_kb: u64,
    pub cached_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
    pub swap_cached_kb: u64,
    pub dirty_kb: u64,
    pub writeback_kb: u64,
    pub anon_pages_kb: u64,
    pub mapped_kb: u64,
    pub slab_kb: u64,
    pub sreclaimable_kb: u64,
    pub sunreclaim_kb: u64,
    pub kernel_stack_kb: u64,
    pub page_tables_kb: u64,
    pub nfs_unstable_kb: u64,
    pub bounce_kb: u64,
    pub writeback_tmp_kb: u64,
    pub commit_limit_kb: u64,
    pub committed_as_kb: u64,
    pub vmalloc_total_kb: u64,
    pub vmalloc_used_kb: u64,
    pub vmalloc_chunk_kb: u64,
    pub hardware_corrupted_kb: u64,
    pub anon_huge_pages_kb: u64,
    pub shmem_huge_pages_kb: u64,
    pub shmem_pmd_mapped_kb: u64,
    pub cma_total_kb: u64,
    pub cma_free_kb: u64,
    pub huge_pages_total: u64,
    pub huge_pages_free: u64,
    pub huge_pages_rsvd: u64,
    pub huge_pages_surp: u64,
    pub hugepagesize_kb: u64,
    pub direct_map_4k_kb: u64,
    pub direct_map_2m_kb: u64,
    pub direct_map_1g_kb: u64,
    pub swap_pages_in: u64,
    pub swap_pages_out: u64,
    pub prev_swap_pages_in: u64,
    pub prev_swap_pages_out: u64,
    pub delta_swap_in: u64,
    pub delta_swap_out: u64,
    // Pagefault tracking
    pub pgfault: u64,
    pub pgmajfault: u64,
    pub prev_pgfault: u64,
    pub prev_pgmajfault: u64,
    pub delta_pgfault: u64,
    pub delta_pgmajfault: u64,
}

impl MemStatSnapshot {
    pub fn update(&mut self) -> Result<()> {
        let meminfo = Meminfo::new()?;

        // Save previous values for delta calculation
        self.prev_swap_pages_in = self.swap_pages_in;
        self.prev_swap_pages_out = self.swap_pages_out;
        self.prev_pgfault = self.pgfault;
        self.prev_pgmajfault = self.pgmajfault;

        // Update memory info using TryFrom - this will fail fast with useful errors
        let mut new_snapshot = Self::try_from(&meminfo)?;

        // Preserve our delta tracking fields
        new_snapshot.prev_swap_pages_in = self.prev_swap_pages_in;
        new_snapshot.prev_swap_pages_out = self.prev_swap_pages_out;
        new_snapshot.prev_pgfault = self.prev_pgfault;
        new_snapshot.prev_pgmajfault = self.prev_pgmajfault;

        // Update vmstat fields that aren't in /proc/meminfo
        new_snapshot.update_vmstat_fields()?;

        // Calculate deltas
        new_snapshot.delta_swap_in = new_snapshot
            .swap_pages_in
            .saturating_sub(new_snapshot.prev_swap_pages_in);
        new_snapshot.delta_swap_out = new_snapshot
            .swap_pages_out
            .saturating_sub(new_snapshot.prev_swap_pages_out);
        new_snapshot.delta_pgfault = new_snapshot
            .pgfault
            .saturating_sub(new_snapshot.prev_pgfault);
        new_snapshot.delta_pgmajfault = new_snapshot
            .pgmajfault
            .saturating_sub(new_snapshot.prev_pgmajfault);

        // Replace self with the new snapshot
        *self = new_snapshot;

        Ok(())
    }

    fn update_vmstat_fields(&mut self) -> Result<()> {
        let file = File::open("/proc/vmstat")
            .map_err(|e| anyhow::anyhow!("Failed to open /proc/vmstat: {}", e))?;

        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line =
                line.map_err(|e| anyhow::anyhow!("Failed to read /proc/vmstat line: {}", e))?;

            if let Some(val_str) = line.split_whitespace().nth(1) {
                let val = val_str.parse::<u64>().map_err(|e| {
                    anyhow::anyhow!("Failed to parse vmstat value '{}': {}", val_str, e)
                })?;

                match line.split_whitespace().next() {
                    Some("pswpin") => self.swap_pages_in = val,
                    Some("pswpout") => self.swap_pages_out = val,
                    Some("pgfault") => self.pgfault = val,
                    Some("pgmajfault") => self.pgmajfault = val,
                    _ => {} // Ignore other fields
                }
            }
        }
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

impl TryFrom<&Meminfo> for MemStatSnapshot {
    type Error = anyhow::Error;

    fn try_from(meminfo: &Meminfo) -> Result<Self> {
        // Essential fields that must be present - fail fast if missing
        let available_kb = meminfo.mem_available.ok_or_else(|| {
            anyhow::anyhow!(
                "MemAvailable field missing from /proc/meminfo - kernel too old or corrupted"
            )
        })?;

        Ok(Self {
            total_kb: meminfo.mem_total,
            free_kb: meminfo.mem_free,
            available_kb,
            active_kb: meminfo.active,
            inactive_kb: meminfo.inactive,
            active_anon_kb: meminfo
                .active_anon
                .ok_or_else(|| anyhow::anyhow!("Active(anon) field missing from /proc/meminfo"))?,
            inactive_anon_kb: meminfo.inactive_anon.ok_or_else(|| {
                anyhow::anyhow!("Inactive(anon) field missing from /proc/meminfo")
            })?,
            active_file_kb: meminfo
                .active_file
                .ok_or_else(|| anyhow::anyhow!("Active(file) field missing from /proc/meminfo"))?,
            inactive_file_kb: meminfo.inactive_file.ok_or_else(|| {
                anyhow::anyhow!("Inactive(file) field missing from /proc/meminfo")
            })?,
            unevictable_kb: meminfo
                .unevictable
                .ok_or_else(|| anyhow::anyhow!("Unevictable field missing from /proc/meminfo"))?,
            mlocked_kb: meminfo
                .mlocked
                .ok_or_else(|| anyhow::anyhow!("Mlocked field missing from /proc/meminfo"))?,
            shmem_kb: meminfo
                .shmem
                .ok_or_else(|| anyhow::anyhow!("Shmem field missing from /proc/meminfo"))?,
            buffers_kb: meminfo.buffers,
            cached_kb: meminfo.cached,
            swap_total_kb: meminfo.swap_total,
            swap_free_kb: meminfo.swap_free,
            swap_cached_kb: meminfo.swap_cached,
            dirty_kb: meminfo.dirty,
            writeback_kb: meminfo.writeback,
            anon_pages_kb: meminfo
                .anon_pages
                .ok_or_else(|| anyhow::anyhow!("AnonPages field missing from /proc/meminfo"))?,
            mapped_kb: meminfo.mapped,
            slab_kb: meminfo.slab,
            sreclaimable_kb: meminfo
                .s_reclaimable
                .ok_or_else(|| anyhow::anyhow!("SReclaimable field missing from /proc/meminfo"))?,
            sunreclaim_kb: meminfo
                .s_unreclaim
                .ok_or_else(|| anyhow::anyhow!("SUnreclaim field missing from /proc/meminfo"))?,
            kernel_stack_kb: meminfo.kernel_stack.unwrap_or(0), // Optional on older kernels
            page_tables_kb: meminfo.page_tables.unwrap_or(0),   // Optional on older kernels
            nfs_unstable_kb: meminfo.nfs_unstable.unwrap_or(0), // Optional, depends on NFS
            bounce_kb: meminfo.bounce.unwrap_or(0),             // Optional
            writeback_tmp_kb: meminfo.writeback_tmp.unwrap_or(0), // Optional
            commit_limit_kb: meminfo.commit_limit.unwrap_or(0), // Optional
            committed_as_kb: meminfo.committed_as,
            vmalloc_total_kb: meminfo.vmalloc_total,
            vmalloc_used_kb: meminfo.vmalloc_used,
            vmalloc_chunk_kb: meminfo.vmalloc_chunk,
            hardware_corrupted_kb: meminfo.hardware_corrupted.unwrap_or(0), // Optional
            anon_huge_pages_kb: meminfo.anon_hugepages.unwrap_or(0),        // Optional
            shmem_huge_pages_kb: meminfo.shmem_hugepages.unwrap_or(0),      // Optional
            shmem_pmd_mapped_kb: meminfo.shmem_pmd_mapped.unwrap_or(0),     // Optional
            cma_total_kb: meminfo.cma_total.unwrap_or(0), // Optional, depends on CMA
            cma_free_kb: meminfo.cma_free.unwrap_or(0),   // Optional, depends on CMA
            huge_pages_total: meminfo.hugepages_total.unwrap_or(0), // Optional
            huge_pages_free: meminfo.hugepages_free.unwrap_or(0), // Optional
            huge_pages_rsvd: meminfo.hugepages_rsvd.unwrap_or(0), // Optional
            huge_pages_surp: meminfo.hugepages_surp.unwrap_or(0), // Optional
            hugepagesize_kb: meminfo.hugepagesize.unwrap_or(0), // Optional
            direct_map_4k_kb: meminfo.direct_map_4k.unwrap_or(0), // Optional
            direct_map_2m_kb: meminfo.direct_map_2M.unwrap_or(0), // Optional
            direct_map_1g_kb: meminfo.direct_map_1G.unwrap_or(0), // Optional
            swap_pages_in: 0,
            swap_pages_out: 0,
            prev_swap_pages_in: 0,
            prev_swap_pages_out: 0,
            delta_swap_in: 0,
            delta_swap_out: 0,
            pgfault: 0,
            pgmajfault: 0,
            prev_pgfault: 0,
            prev_pgmajfault: 0,
            delta_pgfault: 0,
            delta_pgmajfault: 0,
        })
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
