// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

//! Hybrid-capacity and cache-domain topology discovery.
//!
//! Feeds the BPF CPU-selection path (`select_cpu.bpf.c`) two placement
//! hints derived from the host topology:
//!
//! 1. The primary (big-core) set on asymmetric-capacity systems.
//! 2. The per-LLC cache domains for LLC-aware wakeup placement.
//!
//! Two phases:
//!
//! 1. `init_topology()` - before `scx_ops_load!()`: discovers the
//!    topology, computes the plans, and writes the rodata globals (rodata
//!    is frozen at load).
//! 2. `write_primary_bitmap()` / `write_llc_bitmaps()` - after
//!    `scx_ops_load!()`: writes the CPU-membership bitmaps directly into
//!    the ARRAY maps (`mlfq_primary_bitmap`, `mlfq_llc_bitmaps`) that the
//!    CPU-selection path reads.
//!
//! All discovery is best-effort: a placement hint must never abort the
//! scheduler, so any failure leaves the bitmaps empty and the scheduler
//! keeps working on the base behavior (uniform capacity, no LLC
//! awareness).

use std::mem::size_of;

use anyhow::{Context, Result};
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use log::{info, warn};
use scx_utils::get_primary_cpus;
use scx_utils::Powermode;
use scx_utils::Topology;

use crate::bpf_intf::mlfq_bitmap;
use crate::bpf_intf::mlfq_consts_MLFQ_BITMAP_WORDS;
use crate::bpf_intf::mlfq_consts_MLFQ_MAX_CPUS;
use crate::bpf_intf::mlfq_consts_MLFQ_MAX_LLCS;

/// Compile-time CPU bound; must match `MLFQ_MAX_CPUS` in `src/bpf/intf.h`.
const MAX_CPUS: usize = mlfq_consts_MLFQ_MAX_CPUS as usize;

/// Compile-time LLC bound; must match `MLFQ_MAX_LLCS` in `src/bpf/intf.h`.
const MAX_LLCS: usize = mlfq_consts_MLFQ_MAX_LLCS as usize;

/// Whether SMT is active on the host, read from the kernel's
/// `/sys/devices/system/cpu/smt/active` interface. The knob is absent on
/// systems without SMT support; a missing or unreadable knob yields
/// `None`, so the caller can omit the SMT annotation from the startup
/// banner rather than guessing.
pub fn smt_enabled() -> Option<bool> {
    let active = std::fs::read_to_string("/sys/devices/system/cpu/smt/active").ok()?;
    active.trim().parse::<u8>().ok().map(|v| v == 1)
}

/// Capacity-planning decision, separated from sysfs discovery so the pure
/// logic is unit-testable without touching the host topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityPlan {
    /// True when every CPU is treated as primary: uniform-capacity system,
    /// or the primary set could not be determined.
    pub primary_all: bool,
    /// CPUs to add to the primary mask (sorted, deduplicated); empty when
    /// `primary_all` is true.
    pub primary_cpus: Vec<u32>,
}

/// Decide the primary set from the discovered big cores.
///
/// A primary list covering every online CPU means there is no capacity
/// asymmetry to exploit; an empty list means discovery produced no usable
/// data. Both fall back to the uniform-capacity behavior.
pub fn plan_primary_mask(primary_cpus: &[u32], nr_online: usize) -> CapacityPlan {
    if primary_cpus.is_empty() || primary_cpus.len() >= nr_online {
        CapacityPlan {
            primary_all: true,
            primary_cpus: Vec::new(),
        }
    } else {
        let mut cpus = primary_cpus.to_vec();
        cpus.sort_unstable();
        cpus.dedup();
        CapacityPlan {
            primary_all: false,
            primary_cpus: cpus,
        }
    }
}

/// Cache-domain planning decision, separated from sysfs discovery so the
/// pure logic is unit-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlcPlan {
    /// Number of LLC domains (0 disables the LLC step entirely).
    pub nr_llcs: u32,
    /// Per-LLC: 1 if the domain contains at least one primary (big) core.
    pub has_primary: [u8; MAX_LLCS],
    /// Per-LLC: the CPUs of that domain.
    pub llc_cpus: Vec<Vec<u32>>,
    /// Per-CPU LLC domain id (0 when the CPU is unknown or out of range).
    pub cpu_llc: [u32; MAX_CPUS],
}

/// Build the LLC plan from a synthetic `(cpu, llc)` map.
///
/// LLC ids are expected to be dense (0-based). An empty map, or a map with
/// more domains than `max_llcs`, disables LLC awareness entirely so the
/// BPF side falls back to the current placement behavior.
pub fn plan_llcs(cpu_to_llc: &[(u32, u32)], primary_cpus: &[u32], max_llcs: usize) -> LlcPlan {
    let mut plan = LlcPlan {
        nr_llcs: 0,
        has_primary: [0; MAX_LLCS],
        llc_cpus: Vec::new(),
        cpu_llc: [0; MAX_CPUS],
    };

    if cpu_to_llc.is_empty() {
        return plan;
    }

    let nr = cpu_to_llc.iter().map(|&(_, llc)| llc).max().unwrap() + 1;
    if nr as usize > max_llcs {
        warn!(
            "{} LLC domains exceed the supported maximum ({}), disabling LLC-aware placement",
            nr, max_llcs
        );
        return plan;
    }

    plan.nr_llcs = nr;
    plan.llc_cpus = vec![Vec::new(); nr as usize];
    for &(cpu, llc) in cpu_to_llc {
        if cpu as usize >= MAX_CPUS {
            continue;
        }
        plan.cpu_llc[cpu as usize] = llc;
        plan.llc_cpus[llc as usize].push(cpu);
    }
    for (llc, cpus) in plan.llc_cpus.iter().enumerate() {
        if cpus.iter().any(|cpu| primary_cpus.contains(cpu)) {
            plan.has_primary[llc] = 1;
        }
    }

    plan
}

/// The two placement plans produced by `init_topology()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyPlan {
    pub capacity: CapacityPlan,
    pub llcs: LlcPlan,
    /// Number of non-empty NUMA nodes (0 when discovery failed).
    pub nr_numa_nodes: usize,
}

/// Phase 1 (pre-load): discover the topology and write the rodata globals.
///
/// Returns the plans for the caller to pass to the populate functions
/// after the object is loaded.
pub fn init_topology(skel: &mut crate::bpf_skel::OpenBpfSkel<'_>) -> Result<TopologyPlan> {
    let topo = match Topology::new() {
        Ok(topo) => topo,
        Err(e) => {
            warn!("CPU topology discovery failed, using uniform-capacity placement: {e}");
            return Ok(TopologyPlan {
                capacity: CapacityPlan {
                    primary_all: true,
                    primary_cpus: Vec::new(),
                },
                llcs: LlcPlan {
                    nr_llcs: 0,
                    has_primary: [0; MAX_LLCS],
                    llc_cpus: Vec::new(),
                    cpu_llc: [0; MAX_CPUS],
                },
                nr_numa_nodes: 0,
            });
        }
    };

    let nr_online = topo.all_cpus.len();
    let nr_numa_nodes = topo
        .nodes
        .values()
        .filter(|node| !node.all_cpus.is_empty())
        .count();
    let primaries: Vec<u32> = match get_primary_cpus(Powermode::Performance) {
        Ok(cpus) => cpus.into_iter().map(|cpu| cpu as u32).collect(),
        Err(e) => {
            warn!("primary CPU discovery failed, using uniform-capacity placement: {e}");
            Vec::new()
        }
    };

    let capacity = plan_primary_mask(&primaries, nr_online);

    let cpu_to_llc: Vec<(u32, u32)> = topo
        .all_cpus
        .iter()
        .map(|(id, cpu)| (*id as u32, cpu.llc_id as u32))
        .collect();
    let llcs = plan_llcs(&cpu_to_llc, &capacity.primary_cpus, MAX_LLCS);
    let mut llcs = llcs;
    if capacity.primary_all {
        // Every LLC contains a primary core when all CPUs are primary.
        llcs.has_primary.fill(1);
    }

    let rodata = skel
        .maps
        .rodata_data
        .as_mut()
        .context("rodata missing, the BPF object has no .rodata section")?;
    rodata.mlfq_primary_all = capacity.primary_all;
    rodata.mlfq_nr_llcs = llcs.nr_llcs;
    rodata.mlfq_llc_has_primary = llcs.has_primary;
    rodata.mlfq_cpu_llc = llcs.cpu_llc;

    if capacity.primary_all {
        info!(
            "Topology: {} online CPUs, uniform capacity, all treated as primary",
            nr_online
        );
    } else {
        info!(
            "Topology: {} online CPUs, {} primary (big) cores",
            nr_online,
            capacity.primary_cpus.len()
        );
    }
    if llcs.nr_llcs > 0 {
        info!("Topology: {} LLC cache domains", llcs.nr_llcs);
    }

    Ok(TopologyPlan {
        capacity,
        llcs,
        nr_numa_nodes,
    })
}

/// Phase 2 (post-load): write the primary (big-core) membership bitmap.
///
/// With uniform capacity the BPF selector short-circuits on
/// `mlfq_primary_all` and never reads the map, so it is left empty. On
/// hybrid systems a failure here leaves the map empty: the selector then
/// treats every CPU as non-primary and falls back to any idle CPU.
pub fn write_primary_bitmap(
    skel: &mut crate::bpf_skel::BpfSkel<'_>,
    plan: &CapacityPlan,
) -> Result<()> {
    if plan.primary_all {
        return Ok(());
    }

    let bm = build_bitmap(&plan.primary_cpus);
    write_bitmap_value(&skel.maps.mlfq_primary_bitmap, &bm, 0)
        .context("failed to write the primary bitmap")
}

/// Phase 2 (post-load): write the per-LLC membership bitmaps.
///
/// One bitmap per LLC domain. On failure the affected domain's bitmap is
/// left empty, so the selector finds no idle candidate there and
/// falls through to the global placement path.
pub fn write_llc_bitmaps(skel: &mut crate::bpf_skel::BpfSkel<'_>, plan: &LlcPlan) -> Result<()> {
    if plan.nr_llcs == 0 {
        return Ok(());
    }

    for llc in 0..plan.nr_llcs as usize {
        let bm = build_bitmap(&plan.llc_cpus[llc]);
        write_bitmap_value(&skel.maps.mlfq_llc_bitmaps, &bm, llc as u32)
            .with_context(|| format!("failed to write the LLC {llc} bitmap"))?;
    }
    Ok(())
}

/// Word index of @cpu within a CPU bitmap, matching the word layout of
/// `struct mlfq_bitmap` in `src/bpf/intf.h`.
fn bitmap_word(cpu: usize) -> usize {
    cpu >> 6
}

/// Bit mask of @cpu within its bitmap word.
fn bitmap_mask(cpu: usize) -> u64 {
    1u64 << (cpu & 63)
}

/// Build a CPU-membership bitmap from a CPU list.
///
/// Out-of-range CPUs are ignored, matching the BPF-side guards.
fn build_bitmap(cpus: &[u32]) -> mlfq_bitmap {
    let mut bm = mlfq_bitmap {
        words: [0; mlfq_consts_MLFQ_BITMAP_WORDS as usize],
    };
    for &cpu in cpus {
        let cpu = cpu as usize;
        if cpu >= MAX_CPUS {
            continue;
        }
        bm.words[bitmap_word(cpu)] |= bitmap_mask(cpu);
    }
    bm
}

/// Write @value into the ARRAY map @map at @key (a u32 key).
fn write_bitmap_value(map: &libbpf_rs::Map, value: &mlfq_bitmap, key: u32) -> Result<()> {
    let key_bytes = key.to_ne_bytes();
    let value_bytes = unsafe {
        std::slice::from_raw_parts(value as *const _ as *const u8, size_of::<mlfq_bitmap>())
    };
    map.update(&key_bytes, value_bytes, MapFlags::ANY)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_primary_list_falls_back_to_uniform() {
        let plan = plan_primary_mask(&[], 8);
        assert!(plan.primary_all);
        assert!(plan.primary_cpus.is_empty());
    }

    #[test]
    fn full_primary_list_is_uniform() {
        // Every online CPU is primary: no asymmetry to exploit.
        let plan = plan_primary_mask(&[0, 1, 2, 3, 4, 5, 6, 7], 8);
        assert!(plan.primary_all);
    }

    #[test]
    fn subset_of_online_cpus_is_hybrid() {
        let plan = plan_primary_mask(&[0, 1, 4, 5], 8);
        assert!(!plan.primary_all);
        assert_eq!(plan.primary_cpus, vec![0, 1, 4, 5]);
    }

    #[test]
    fn hybrid_list_is_sorted_and_deduplicated() {
        let plan = plan_primary_mask(&[5, 1, 4, 1, 0], 8);
        assert!(!plan.primary_all);
        assert_eq!(plan.primary_cpus, vec![0, 1, 4, 5]);
    }

    #[test]
    fn max_cpus_matches_bpf_constant() {
        // The array sizes and the BPF rodata arrays must stay in lock-step.
        assert_eq!(
            MAX_CPUS,
            crate::bpf_intf::mlfq_consts_MLFQ_MAX_CPUS as usize
        );
        assert_eq!(
            MAX_LLCS,
            crate::bpf_intf::mlfq_consts_MLFQ_MAX_LLCS as usize
        );
    }

    #[test]
    fn llc_grouping_from_cpu_map() {
        let plan = plan_llcs(&[(0, 0), (1, 0), (2, 1), (3, 1)], &[], MAX_LLCS);
        assert_eq!(plan.nr_llcs, 2);
        assert_eq!(plan.llc_cpus, vec![vec![0, 1], vec![2, 3]]);
        assert_eq!(plan.cpu_llc[0], 0);
        assert_eq!(plan.cpu_llc[3], 1);
        assert_eq!(plan.cpu_llc[4], 0); // unknown CPU stays 0
    }

    #[test]
    fn llc_has_primary_flags_domains_with_big_cores() {
        let plan = plan_llcs(&[(0, 0), (1, 0), (2, 1), (3, 1)], &[1], MAX_LLCS);
        assert_eq!(plan.has_primary[0], 1); // LLC 0 contains primary CPU 1
        assert_eq!(plan.has_primary[1], 0); // LLC 1 has no primary
    }

    #[test]
    fn llc_map_without_primaries_has_no_flags() {
        let plan = plan_llcs(&[(0, 0), (1, 1)], &[], MAX_LLCS);
        assert_eq!(plan.has_primary, [0; MAX_LLCS]);
    }

    #[test]
    fn llc_plan_disables_when_exceeding_cap() {
        // 33 domains exceed the 32-domain bound: disable LLC awareness.
        let map: Vec<(u32, u32)> = (0..33).map(|i| (i, i)).collect();
        let plan = plan_llcs(&map, &[], MAX_LLCS);
        assert_eq!(plan.nr_llcs, 0);
        assert!(plan.llc_cpus.is_empty());
    }

    #[test]
    fn llc_plan_disables_on_empty_map() {
        let plan = plan_llcs(&[], &[], MAX_LLCS);
        assert_eq!(plan.nr_llcs, 0);
    }

    #[test]
    fn llc_plan_skips_out_of_range_cpus() {
        let plan = plan_llcs(&[(0, 0), (5000, 1)], &[], MAX_LLCS);
        // The oversized CPU id must not index into the arrays.
        assert_eq!(plan.nr_llcs, 2);
        assert_eq!(plan.cpu_llc[0], 0);
        assert!(plan.llc_cpus[1].is_empty());
    }

    #[test]
    fn bitmap_word_index_math() {
        assert_eq!(bitmap_word(0), 0);
        assert_eq!(bitmap_word(63), 0);
        assert_eq!(bitmap_word(64), 1);
        assert_eq!(bitmap_word(127), 1);
        assert_eq!(bitmap_word(1023), 15);
    }

    #[test]
    fn bitmap_mask_math() {
        assert_eq!(bitmap_mask(0), 1);
        assert_eq!(bitmap_mask(5), 1 << 5);
        assert_eq!(bitmap_mask(63), 1u64 << 63);
    }

    #[test]
    fn build_bitmap_sets_expected_bits() {
        let bm = build_bitmap(&[0, 1, 64, 1023]);
        assert_eq!(bm.words[0], 0b11);
        assert_eq!(bm.words[1], 1);
        assert_eq!(bm.words[15], 1u64 << 63);
        assert_eq!(bm.words[2], 0);
    }

    #[test]
    fn build_bitmap_ignores_out_of_range_cpus() {
        let bm = build_bitmap(&[1024, 5000]);
        assert_eq!(bm.words, [0; mlfq_consts_MLFQ_BITMAP_WORDS as usize]);
    }

    #[test]
    fn bitmap_words_count_matches_bpf_constant() {
        assert_eq!(
            mlfq_consts_MLFQ_BITMAP_WORDS,
            (crate::bpf_intf::mlfq_consts_MLFQ_MAX_CPUS + 63) / 64
        );
    }
}
