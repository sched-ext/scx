// SPDX-License-Identifier: GPL-2.0
// Topology detection - CPUs, CCDs, P/E cores. Results passed to BPF as const volatile.

use anyhow::Result;
use scx_utils::{CoreType, Topology};

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
    pub cpu_core_id: [u8; MAX_CPUS],
    pub cpu_thread_bit: [u8; MAX_CPUS],
    pub cpu_dsq_id: [u32; MAX_CPUS],
    /// Pre-computed 64-bit mask of all CPUs in a physical core
    pub core_cpu_mask: [u64; 32],
    /// Bitmask requirement for a core to be "fully idle" (e.g. 0x3 for dual SMT)
    pub core_thread_mask: [u8; 32],
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
    for (i, sibling) in cpu_sibling_map.iter_mut().enumerate().take(MAX_CPUS) {
        *sibling = i as u8;
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
        cpu_core_id: [0; MAX_CPUS],
        cpu_thread_bit: [0; MAX_CPUS],
        cpu_dsq_id: [0; MAX_CPUS],
        core_cpu_mask: [0; 32],
        core_thread_mask: [0; 32],
        llc_cpu_mask: [0; MAX_LLCS],
        big_cpu_mask: 0,
        cpus_per_ccd: 0,
    };

    // 1. Map LLCs
    // Note: topo.all_llcs keys are arbitrary kernel IDs. We must map them to 0..MAX_LLCS-1.
    // We'll just use a simple counter 0,1,2... as we iterate.
    let mut llc_idx = 0;

    for llc in topo.all_llcs.values() {
        if llc_idx >= MAX_LLCS {
            break;
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
        if info.cpus_per_ccd == 0 {
            info.cpus_per_ccd = core_count;
        } // Estimate

        llc_idx += 1;
    }

    // 2. Identify P-cores vs E-cores
    // Reset defaults to recalculate based on CoreType
    info.cpu_is_big = [0; MAX_CPUS];
    info.big_cpu_mask = 0;

    let mut p_cores_found = 0;
    let mut e_cores_found = 0;

    for (core_id_usize, core) in &topo.all_cores {
        let core_id = *core_id_usize;

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

        // Calculate SMT requirement mask for this core
        if core_id < 32 {
            info.core_thread_mask[core_id] = ((1u16 << core.cpus.len()) - 1) as u8;
        }

        // Iterate over CPUs in this core
        let mut thread_idx = 0;
        let mut sorted_cpus: Vec<_> = core.cpus.keys().collect();
        sorted_cpus.sort();

        for cpu_id in sorted_cpus {
            let cpu = *cpu_id;
            if cpu < MAX_CPUS {
                info.cpu_is_big[cpu] = is_big;
                info.cpu_core_id[cpu] = core_id as u8;
                info.cpu_thread_bit[cpu] = 1 << thread_idx;
                info.cpu_dsq_id[cpu] = 1000 /* CAKE_DSQ_LC_BASE */ + cpu as u32;

                if core_id < 32 {
                    info.core_cpu_mask[core_id] |= 1u64 << cpu;
                }

                if is_big == 1 {
                    info.big_cpu_mask |= 1u64 << cpu;
                }
                thread_idx += 1;
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

    // Log detected topology (debug level - use RUST_LOG=debug to see)
    log::debug!("Topology detected:");
    log::debug!("  CPUs:          {}", info.nr_cpus);
    log::debug!("  SMT Enabled:   {}", info.smt_enabled);
    log::debug!("  Dual CCD:      {}", info.has_dual_ccd);
    if info.has_dual_ccd {
        log::debug!("    Masks:       {:x?}", &info.llc_cpu_mask[..llc_idx]);
    }
    log::debug!("  Hybrid cores:  {}", info.has_hybrid_cores);
    if info.has_hybrid_cores {
        log::debug!("    P-core mask: {:016x}", info.big_cpu_mask);
    }

    Ok(info)
}
