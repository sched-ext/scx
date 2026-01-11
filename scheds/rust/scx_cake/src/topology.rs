// SPDX-License-Identifier: GPL-2.0
//
// Topology detection for scx_cake
//
// Detects CPU topology at startup:
// - Number of CPUs
// - CCD/CCX domains (via L3 cache IDs)
// - P-cores vs E-cores (via CoreType)
//
// All detection happens once at startup. Results are passed to BPF
// as const volatile so the verifier can eliminate unused code paths.

use anyhow::Result;
use log::info;
use scx_utils::{Topology, CoreType};

/// Maximum supported CPUs (matches BPF array sizes)
pub const MAX_CPUS: usize = 64;
/// Maximum supported LLCs (matches BPF array sizes)
pub const MAX_LLCS: usize = 8;

/// Detected topology information
#[derive(Debug, Clone)]
pub struct TopologyInfo {
    /// Number of online CPUs
    pub nr_cpus: usize,

    /// True if system has multiple L3 cache domains (CCDs)
    pub has_dual_ccd: bool,

    /// True if system has hybrid P/E cores (Intel hybrid or similar)
    pub has_hybrid_cores: bool,

    /// SMT enabled status
    pub smt_enabled: bool,
    /// Map of CPU ID -> Sibling CPU ID (or self if none/disabled)
    pub cpu_sibling_map: [u8; MAX_CPUS],

    // BPF Maps
    pub cpu_llc_id: [u8; MAX_CPUS],
    pub cpu_is_big: [u8; MAX_CPUS],
    pub llc_cpu_mask: [u64; MAX_LLCS],
    pub big_cpu_mask: u64,
    
    // Info
    pub cpus_per_ccd: u32,
}

pub fn detect() -> Result<TopologyInfo> {
    // robustly detect topology using scx_utils
    let topo = Topology::new()?;
    
    let nr_cpus = topo.all_cpus.len();
    let nr_llcs = topo.all_llcs.len();
    
    // Get sibling map directly from scx_utils
    let siblings = topo.sibling_cpus();
    let mut cpu_sibling_map = [0u8; MAX_CPUS];
    
    // Default to self-mapping
    for i in 0..MAX_CPUS {
        cpu_sibling_map[i] = i as u8;
    }
    
    // Populate with detected siblings
    for (cpu, &sibling) in siblings.iter().enumerate() {
        if cpu < MAX_CPUS && sibling >= 0 {
            let sib = sibling as usize;
            if sib < MAX_CPUS {
                cpu_sibling_map[cpu] = sib as u8;
            }
        }
    }

    let mut info = TopologyInfo {
        nr_cpus,
        has_dual_ccd: nr_llcs > 1,
        has_hybrid_cores: false, // Will detect below
        smt_enabled: topo.smt_enabled,
        cpu_sibling_map,
        cpu_llc_id: [0; MAX_CPUS],
        cpu_is_big: [1; MAX_CPUS], // Default to 1 (Big) to be safe
        llc_cpu_mask: [0; MAX_LLCS],
        big_cpu_mask: 0,
        cpus_per_ccd: 0,
    };

    // 1. Map LLCs
    // Note: topo.all_llcs keys are arbitrary kernel IDs. We must map them to 0..MAX_LLCS-1.
    // We'll just use a simple counter 0,1,2... as we iterate.
    let mut llc_idx = 0;
    
    for (_, llc) in &topo.all_llcs {
        if llc_idx >= MAX_LLCS {
            break; // Exceeded BPF limit, remaining CPUs effectively in LLC 0 or ignored? 
                   // Ideally they map to 0 to be safe (fallback). 
                   // But let's just stop mapping.
        }
        
        let mut mask = 0u64;
        let mut core_count = 0;
        
        for cpu_id in llc.all_cpus.keys() {
            let cpu = *cpu_id;
            if cpu < MAX_CPUS {
                info.cpu_llc_id[cpu] = llc_idx as u8;
                mask |= 1u64 << cpu;
                core_count += 1;
            }
        }
        
        info.llc_cpu_mask[llc_idx] = mask;
        if info.cpus_per_ccd == 0 { info.cpus_per_ccd = core_count; } // Estimate
        
        llc_idx += 1;
    }

    // 2. Identify P-cores vs E-cores
    // Reset defaults to recalculate based on CoreType
    info.cpu_is_big = [0; MAX_CPUS];
    info.big_cpu_mask = 0;
    
    let mut p_cores_found = 0;
    let mut e_cores_found = 0;

    for core in topo.all_cores.values() {
        // Determine is_big. 
        // If CoreType::Efficiency -> 0. 
        // If Performance or Unknown -> 1.
        let is_big = match core.core_type {
            CoreType::Little => 0,
            _ => 1,
        };
        
        if is_big == 1 {
            p_cores_found += 1;
        } else {
            e_cores_found += 1;
        }

        for cpu_id in core.cpus.keys() {
            let cpu = *cpu_id;
            if cpu < MAX_CPUS {
                info.cpu_is_big[cpu] = is_big;
                if is_big == 1 {
                    info.big_cpu_mask |= 1u64 << cpu;
                }
            }
        }
    }

    // Update hybrid flag
    if p_cores_found > 0 && e_cores_found > 0 {
        info.has_hybrid_cores = true;
    } else {
        info.has_hybrid_cores = false;
        // If not hybrid, ensure all marked as Big for consistency (though mask handles it)
        if p_cores_found == 0 && e_cores_found > 0 {
            // Weird case: All E-cores? Treat as "Big" relative to nothing.
            // But we keep as is.
        }
    }

    // Log detected topology
    info!("Topology detected:");
    info!("  CPUs:          {}", info.nr_cpus);
    info!("  SMT Enabled:   {}", info.smt_enabled);
    info!("  Dual CCD:      {}", info.has_dual_ccd);
    if info.has_dual_ccd {
        info!("    Masks:       {:x?}", &info.llc_cpu_mask[..llc_idx]);
    }
    info!("  Hybrid cores:  {}", info.has_hybrid_cores);
    if info.has_hybrid_cores {
        info!("    P-core mask: {:016x}", info.big_cpu_mask);
    }

    Ok(info)
}
