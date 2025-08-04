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

        // Update memory info from /proc/meminfo
        self.total_kb = meminfo.mem_total;
        self.free_kb = meminfo.mem_free;
        self.available_kb = meminfo.mem_available.unwrap_or(0);
        self.active_kb = meminfo.active;
        self.inactive_kb = meminfo.inactive;
        self.active_anon_kb = meminfo.active_anon.unwrap_or(0);
        self.inactive_anon_kb = meminfo.inactive_anon.unwrap_or(0);
        self.active_file_kb = meminfo.active_file.unwrap_or(0);
        self.inactive_file_kb = meminfo.inactive_file.unwrap_or(0);
        self.unevictable_kb = meminfo.unevictable.unwrap_or(0);
        self.mlocked_kb = meminfo.mlocked.unwrap_or(0);
        self.shmem_kb = meminfo.shmem.unwrap_or(0);
        self.buffers_kb = meminfo.buffers;
        self.cached_kb = meminfo.cached;
        self.swap_total_kb = meminfo.swap_total;
        self.swap_free_kb = meminfo.swap_free;
        self.swap_cached_kb = meminfo.swap_cached;
        self.dirty_kb = meminfo.dirty;
        self.writeback_kb = meminfo.writeback;
        self.anon_pages_kb = meminfo.anon_pages.unwrap_or(0);
        self.mapped_kb = meminfo.mapped;
        self.slab_kb = meminfo.slab;
        self.sreclaimable_kb = meminfo.s_reclaimable.unwrap_or(0);
        self.sunreclaim_kb = meminfo.s_unreclaim.unwrap_or(0);
        self.kernel_stack_kb = meminfo.kernel_stack.unwrap_or(0);
        self.page_tables_kb = meminfo.page_tables.unwrap_or(0);
        self.nfs_unstable_kb = meminfo.nfs_unstable.unwrap_or(0);
        self.bounce_kb = meminfo.bounce.unwrap_or(0);
        self.writeback_tmp_kb = meminfo.writeback_tmp.unwrap_or(0);
        self.commit_limit_kb = meminfo.commit_limit.unwrap_or(0);
        self.committed_as_kb = meminfo.committed_as;
        self.vmalloc_total_kb = meminfo.vmalloc_total;
        self.vmalloc_used_kb = meminfo.vmalloc_used;
        self.vmalloc_chunk_kb = meminfo.vmalloc_chunk;
        self.hardware_corrupted_kb = meminfo.hardware_corrupted.unwrap_or(0);
        self.anon_huge_pages_kb = meminfo.anon_hugepages.unwrap_or(0);
        self.shmem_huge_pages_kb = meminfo.shmem_hugepages.unwrap_or(0);
        self.shmem_pmd_mapped_kb = meminfo.shmem_pmd_mapped.unwrap_or(0);
        self.cma_total_kb = meminfo.cma_total.unwrap_or(0);
        self.cma_free_kb = meminfo.cma_free.unwrap_or(0);
        self.huge_pages_total = meminfo.hugepages_total.unwrap_or(0);
        self.huge_pages_free = meminfo.hugepages_free.unwrap_or(0);
        self.huge_pages_rsvd = meminfo.hugepages_rsvd.unwrap_or(0);
        self.huge_pages_surp = meminfo.hugepages_surp.unwrap_or(0);
        self.hugepagesize_kb = meminfo.hugepagesize.unwrap_or(0);
        self.direct_map_4k_kb = meminfo.direct_map_4k.unwrap_or(0);
        self.direct_map_2m_kb = meminfo.direct_map_2M.unwrap_or(0);
        self.direct_map_1g_kb = meminfo.direct_map_1G.unwrap_or(0);

        // Get swap pages in/out and pagefaults from /proc/vmstat
        // Read directly from /proc/vmstat since procfs doesn't expose these directly
        if let Ok(file) = File::open("/proc/vmstat") {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                if line.starts_with("pswpin ") {
                    if let Some(val_str) = line.split_whitespace().nth(1) {
                        if let Ok(val) = val_str.parse::<u64>() {
                            self.swap_pages_in = val;
                        }
                    }
                } else if line.starts_with("pswpout ") {
                    if let Some(val_str) = line.split_whitespace().nth(1) {
                        if let Ok(val) = val_str.parse::<u64>() {
                            self.swap_pages_out = val;
                        }
                    }
                } else if line.starts_with("pgfault ") {
                    if let Some(val_str) = line.split_whitespace().nth(1) {
                        if let Ok(val) = val_str.parse::<u64>() {
                            self.pgfault = val;
                        }
                    }
                } else if line.starts_with("pgmajfault ") {
                    if let Some(val_str) = line.split_whitespace().nth(1) {
                        if let Ok(val) = val_str.parse::<u64>() {
                            self.pgmajfault = val;
                        }
                    }
                }
            }
        }

        // Calculate deltas
        self.delta_swap_in = self.swap_pages_in.saturating_sub(self.prev_swap_pages_in);
        self.delta_swap_out = self.swap_pages_out.saturating_sub(self.prev_swap_pages_out);
        self.delta_pgfault = self.pgfault.saturating_sub(self.prev_pgfault);
        self.delta_pgmajfault = self.pgmajfault.saturating_sub(self.prev_pgmajfault);

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

impl From<&Meminfo> for MemStatSnapshot {
    fn from(meminfo: &Meminfo) -> Self {
        Self {
            total_kb: meminfo.mem_total,
            free_kb: meminfo.mem_free,
            available_kb: meminfo.mem_available.unwrap_or(0),
            active_kb: meminfo.active,
            inactive_kb: meminfo.inactive,
            active_anon_kb: meminfo.active_anon.unwrap_or(0),
            inactive_anon_kb: meminfo.inactive_anon.unwrap_or(0),
            active_file_kb: meminfo.active_file.unwrap_or(0),
            inactive_file_kb: meminfo.inactive_file.unwrap_or(0),
            unevictable_kb: meminfo.unevictable.unwrap_or(0),
            mlocked_kb: meminfo.mlocked.unwrap_or(0),
            shmem_kb: meminfo.shmem.unwrap_or(0),
            buffers_kb: meminfo.buffers,
            cached_kb: meminfo.cached,
            swap_total_kb: meminfo.swap_total,
            swap_free_kb: meminfo.swap_free,
            swap_cached_kb: meminfo.swap_cached,
            dirty_kb: meminfo.dirty,
            writeback_kb: meminfo.writeback,
            anon_pages_kb: meminfo.anon_pages.unwrap_or(0),
            mapped_kb: meminfo.mapped,
            slab_kb: meminfo.slab,
            sreclaimable_kb: meminfo.s_reclaimable.unwrap_or(0),
            sunreclaim_kb: meminfo.s_unreclaim.unwrap_or(0),
            kernel_stack_kb: meminfo.kernel_stack.unwrap_or(0),
            page_tables_kb: meminfo.page_tables.unwrap_or(0),
            nfs_unstable_kb: meminfo.nfs_unstable.unwrap_or(0),
            bounce_kb: meminfo.bounce.unwrap_or(0),
            writeback_tmp_kb: meminfo.writeback_tmp.unwrap_or(0),
            commit_limit_kb: meminfo.commit_limit.unwrap_or(0),
            committed_as_kb: meminfo.committed_as,
            vmalloc_total_kb: meminfo.vmalloc_total,
            vmalloc_used_kb: meminfo.vmalloc_used,
            vmalloc_chunk_kb: meminfo.vmalloc_chunk,
            hardware_corrupted_kb: meminfo.hardware_corrupted.unwrap_or(0),
            anon_huge_pages_kb: meminfo.anon_hugepages.unwrap_or(0),
            shmem_huge_pages_kb: meminfo.shmem_hugepages.unwrap_or(0),
            shmem_pmd_mapped_kb: meminfo.shmem_pmd_mapped.unwrap_or(0),
            cma_total_kb: meminfo.cma_total.unwrap_or(0),
            cma_free_kb: meminfo.cma_free.unwrap_or(0),
            huge_pages_total: meminfo.hugepages_total.unwrap_or(0),
            huge_pages_free: meminfo.hugepages_free.unwrap_or(0),
            huge_pages_rsvd: meminfo.hugepages_rsvd.unwrap_or(0),
            huge_pages_surp: meminfo.hugepages_surp.unwrap_or(0),
            hugepagesize_kb: meminfo.hugepagesize.unwrap_or(0),
            direct_map_4k_kb: meminfo.direct_map_4k.unwrap_or(0),
            direct_map_2m_kb: meminfo.direct_map_2M.unwrap_or(0),
            direct_map_1g_kb: meminfo.direct_map_1G.unwrap_or(0),
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
        }
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
