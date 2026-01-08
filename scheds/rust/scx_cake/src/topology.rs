// SPDX-License-Identifier: GPL-2.0
//
// Topology detection for scx_cake
//
// Detects CPU topology at startup:
// - Number of CPUs
// - CCD/CCX domains (via L3 cache IDs)
// - P-cores vs E-cores (via CPPC or frequency)
// - SMT siblings
//
// All detection happens once at startup. Results are passed to BPF
// as const volatile so the verifier can eliminate unused code paths.

use std::fs;
use std::path::Path;
use log::info;
use anyhow::Result;

/// Maximum supported CPUs (matches BPF array sizes)
pub const MAX_CPUS: usize = 64;

/// Detected topology information
#[derive(Debug, Clone)]
pub struct TopologyInfo {
    /// Number of online CPUs
    pub nr_cpus: usize,
    
    /// True if system has multiple L3 cache domains (CCDs)
    pub has_dual_ccd: bool,
    
    /// True if system has hybrid P/E cores (Intel hybrid or similar)
    pub has_hybrid_cores: bool,
    
    /// Bitmask of CPUs in CCD0 (first L3 domain)
    pub ccd0_mask: u64,
    
    /// Bitmask of CPUs in CCD1 (second L3 domain, if any)
    pub ccd1_mask: u64,
    
    /// Bitmask of P-cores (high-performance cores)
    pub p_core_mask: u64,
    
    /// Number of CPUs per CCD (for CCD selection logic)
    pub cpus_per_ccd: u32,
}

impl Default for TopologyInfo {
    fn default() -> Self {
        Self {
            nr_cpus: 0,
            has_dual_ccd: false,
            has_hybrid_cores: false,
            ccd0_mask: 0xFFFFFFFFFFFFFFFF,  // All cores in CCD0 by default
            ccd1_mask: 0,
            p_core_mask: 0xFFFFFFFFFFFFFFFF, // All cores are P-cores by default
            cpus_per_ccd: 64,
        }
    }
}

/// Read an integer from a sysfs file
fn read_sysfs_int(path: &Path) -> Option<i64> {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Detect CPU topology from sysfs
pub fn detect() -> Result<TopologyInfo> {
    let mut info = TopologyInfo::default();
    let cpu_root = Path::new("/sys/devices/system/cpu");
    
    // Collect per-CPU information
    let mut l3_ids: Vec<(usize, i64)> = Vec::new();  // (cpu_id, l3_cache_id)
    let mut max_freqs: Vec<(usize, u64)> = Vec::new(); // (cpu_id, max_freq_khz)
    let mut cppc_perfs: Vec<(usize, u64)> = Vec::new(); // (cpu_id, cppc_highest_perf)
    
    for cpu_id in 0..MAX_CPUS {
        let cpu_dir = cpu_root.join(format!("cpu{}", cpu_id));
        if !cpu_dir.exists() {
            continue;
        }
        
        info.nr_cpus = info.nr_cpus.max(cpu_id + 1);
        
        // Detect L3 cache ID (for CCD detection)
        for cache_idx in 0..4 {
            let cache_dir = cpu_dir.join(format!("cache/index{}", cache_idx));
            if !cache_dir.exists() {
                continue;
            }
            
            let level = read_sysfs_int(&cache_dir.join("level"));
            if level == Some(3) {
                if let Some(id) = read_sysfs_int(&cache_dir.join("id")) {
                    l3_ids.push((cpu_id, id));
                }
                break;
            }
        }
        
        // Detect max frequency (for P/E core detection)
        if let Some(freq) = read_sysfs_int(&cpu_dir.join("cpufreq/scaling_max_freq")) {
            max_freqs.push((cpu_id, freq as u64));
        }
        
        // Detect CPPC highest_perf (more reliable for hybrid detection)
        if let Some(perf) = read_sysfs_int(&cpu_dir.join("acpi_cppc/highest_perf")) {
            cppc_perfs.push((cpu_id, perf as u64));
        }
    }
    
    // Analyze L3 cache domains (CCD detection)
    if !l3_ids.is_empty() {
        let unique_l3s: std::collections::HashSet<i64> = l3_ids.iter().map(|(_, id)| *id).collect();
        
        if unique_l3s.len() >= 2 {
            info.has_dual_ccd = true;
            
            // Get the two most common L3 IDs
            let mut l3_counts: std::collections::HashMap<i64, usize> = std::collections::HashMap::new();
            for (_, id) in &l3_ids {
                *l3_counts.entry(*id).or_insert(0) += 1;
            }
            
            let mut sorted_l3s: Vec<_> = l3_counts.into_iter().collect();
            sorted_l3s.sort_by(|a, b| a.0.cmp(&b.0)); // Sort by L3 ID for consistency
            
            let ccd0_id = sorted_l3s.get(0).map(|(id, _)| *id).unwrap_or(0);
            let ccd1_id = sorted_l3s.get(1).map(|(id, _)| *id);
            
            info.ccd0_mask = 0;
            info.ccd1_mask = 0;
            
            for (cpu_id, l3_id) in &l3_ids {
                if *cpu_id >= 64 {
                    continue;
                }
                let bit = 1u64 << cpu_id;
                if *l3_id == ccd0_id {
                    info.ccd0_mask |= bit;
                } else if ccd1_id == Some(*l3_id) {
                    info.ccd1_mask |= bit;
                }
            }
            
            info.cpus_per_ccd = info.ccd0_mask.count_ones();
        }
    }
    
    // Analyze P/E cores (hybrid detection)
    // Use CPPC if available, otherwise use frequency
    let core_perfs: Vec<(usize, u64)> = if !cppc_perfs.is_empty() {
        cppc_perfs
    } else {
        max_freqs
    };
    
    if !core_perfs.is_empty() {
        let _avg_perf: u64 = core_perfs.iter().map(|(_, p)| *p).sum::<u64>() / core_perfs.len() as u64;
        
        // Heuristic: If max perf is >20% higher than min, we have hybrid cores
        let (min_perf, max_perf) = core_perfs.iter()
            .map(|(_, p)| *p)
            .fold((u64::MAX, 0u64), |(min, max), p| (min.min(p), max.max(p)));
        
        if max_perf > 0 && (max_perf - min_perf) * 100 / max_perf > 20 {
            info.has_hybrid_cores = true;
            info.p_core_mask = 0;
            
            // P-cores have perf >= 90% of max
            let p_core_threshold = max_perf * 90 / 100;
            
            for (cpu_id, perf) in &core_perfs {
                if *cpu_id >= 64 {
                    continue;
                }
                if *perf >= p_core_threshold {
                    info.p_core_mask |= 1u64 << cpu_id;
                }
            }
        }
    }
    
    // Log detected topology
    info!("Topology detected:");
    info!("  CPUs:          {}", info.nr_cpus);
    info!("  Dual CCD:      {}", info.has_dual_ccd);
    if info.has_dual_ccd {
        info!("    CCD0 mask:   {:016x} ({} cores)", info.ccd0_mask, info.ccd0_mask.count_ones());
        info!("    CCD1 mask:   {:016x} ({} cores)", info.ccd1_mask, info.ccd1_mask.count_ones());
    }
    info!("  Hybrid cores:  {}", info.has_hybrid_cores);
    if info.has_hybrid_cores {
        info!("    P-core mask: {:016x} ({} P-cores)", info.p_core_mask, info.p_core_mask.count_ones());
    }
    
    Ok(info)
}
