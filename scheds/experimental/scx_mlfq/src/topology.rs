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
//! 1. `init_topology()` runs before `scx_ops_load!()`. It discovers the
//!    topology, computes the plans, and writes the rodata globals (rodata
//!    is frozen at load).
//! 2. `write_primary_bitmap()` and `write_llc_bitmaps()` run after
//!    `scx_ops_load!()`. They write the CPU-membership bitmaps directly
//!    into the ARRAY maps (`mlfq_primary_bitmap`, `mlfq_llc_bitmaps`) that
//!    the CPU-selection path reads.
//!
//! All discovery is best-effort: a placement hint must never abort the
//! scheduler, so any failure leaves the bitmaps empty and the scheduler
//! keeps working on the base behavior (uniform capacity, no LLC
//! awareness).

use std::mem::size_of;
use std::path::Path;

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
use crate::bpf_intf::mlfq_consts_MLFQ_MAX_LLC_CPUS;
use crate::bpf_intf::mlfq_llc_cpu_list;

/// Compile-time CPU bound; must match `MLFQ_MAX_CPUS` in `src/bpf/intf.h`.
const MAX_CPUS: usize = mlfq_consts_MLFQ_MAX_CPUS as usize;

/// Compile-time LLC bound; must match `MLFQ_MAX_LLCS` in `src/bpf/intf.h`.
const MAX_LLCS: usize = mlfq_consts_MLFQ_MAX_LLCS as usize;

/// Compile-time per-LLC CPU-list bound; must match `MLFQ_MAX_LLC_CPUS`
/// in `src/bpf/intf.h`.
const MAX_LLC_CPUS: usize = mlfq_consts_MLFQ_MAX_LLC_CPUS as usize;

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
    /// Per-CPU LLC domain id (MLFQ_MAX_LLCS, the sentinel, when the CPU
    /// is unknown or out of range; only known online CPUs get a real
    /// domain id).
    pub cpu_llc: [u32; MAX_CPUS],
}

/// Build the LLC plan from a synthetic `(cpu, llc)` map.
///
/// LLC ids are expected to be dense (0-based). An empty map, or a map with
/// more domains than `max_llcs`, disables LLC awareness entirely so the
/// BPF side falls back to the current placement behavior. Every CPU the
/// map does not cover (unknown or out of range) keeps the MLFQ_MAX_LLCS
/// sentinel, never the 0 of a valid domain, so an unmapped CPU can never
/// be attributed to LLC 0.
pub fn plan_llcs(cpu_to_llc: &[(u32, u32)], primary_cpus: &[u32], max_llcs: usize) -> LlcPlan {
    let mut plan = LlcPlan {
        nr_llcs: 0,
        has_primary: [0; MAX_LLCS],
        llc_cpus: Vec::new(),
        cpu_llc: [mlfq_consts_MLFQ_MAX_LLCS; MAX_CPUS],
    };

    if cpu_to_llc.is_empty() {
        return plan;
    }

    let max_llc = cpu_to_llc.iter().map(|&(_, llc)| llc).max().unwrap();
    let nr = match max_llc.checked_add(1) {
        Some(v) => v,
        None => {
            warn!("LLC id u32::MAX wraps domain count, disabling LLC-aware placement");
            return plan;
        }
    };
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

/// SMT sibling-planning decision, separated from sysfs discovery so the
/// pure logic is unit-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiblingPlan {
    /// True when any online CPU has a sibling sharing its physical core.
    pub smt_on: bool,
    /// Per-CPU: the lowest-id other CPU sharing the core, or the CPU
    /// itself when the core is unpaired or the CPU is unknown.
    pub cpu_sibling: [u32; MAX_CPUS],
    /// Per-CPU core id (mlfq_cpu_core rodata), MAX_CPUS sentinel when
    /// unknown. The table groups by core_id (not llc_id) and handles
    /// >2-way SMT by picking the lowest-id sibling per CPU.
    pub cpu_core: [u32; MAX_CPUS],
}

/// Plan the SMT sibling table from a synthetic `(cpu, core)` map.
///
/// Each CPU's entry is the lowest-id *other* CPU sharing its physical
/// core (the `core_id` from `scx_utils::Cpu`). A core with a single CPU
/// maps that CPU to itself, the "no sibling" sentinel the BPF side
/// treats as "no preference". `smt_on` is set when any entry is a
/// non-self sibling. For >2-way SMT only the lowest-id sibling is
/// reported. This is a preference, not a full pairing, and the input
/// order does not matter (the plan groups by core first).
pub fn plan_sibling_table(cpu_to_core: &[(u32, u32)]) -> SiblingPlan {
    let mut plan = SiblingPlan {
        smt_on: false,
        cpu_sibling: core::array::from_fn(|i| i as u32),
        cpu_core: [mlfq_consts_MLFQ_MAX_CPUS; MAX_CPUS],
    };
    let mut cores: std::collections::BTreeMap<u32, Vec<u32>> = std::collections::BTreeMap::new();

    for &(cpu, core) in cpu_to_core {
        if cpu as usize >= MAX_CPUS {
            continue;
        }
        cores.entry(core).or_default().push(cpu);
        plan.cpu_core[cpu as usize] = core;
    }

    for cpus in cores.values_mut() {
        cpus.sort_unstable();
        cpus.dedup();
        if cpus.len() < 2 {
            continue;
        }
        plan.smt_on = true;
        for &cpu in cpus.iter() {
            // >2-way SMT: pick lowest-id other CPU per core, not a
            // full pairing; logical sibling lookup, not word bit.
            let sib = cpus.iter().copied().find(|&c| c != cpu).unwrap_or(cpu);
            plan.cpu_sibling[cpu as usize] = sib;
        }
    }

    plan
}

/// Parse a kernel cache size string ("32M", "16384K", plain bytes) into
/// bytes. The kernel exposes cache sizes in the human-readable form
/// with a K/M/G suffix; a parse failure yields `None`.
fn parse_cache_size(size: &str) -> Option<u64> {
    let s = size.trim();
    let (num, mult) = if let Some(v) = s.strip_suffix('K') {
        (v, 1024u64)
    } else if let Some(v) = s.strip_suffix('M') {
        (v, 1024u64 * 1024)
    } else if let Some(v) = s.strip_suffix('G') {
        (v, 1024u64 * 1024 * 1024)
    } else {
        (s, 1u64)
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

/// Read the LLC cache size of one CPU from sysfs.
///
/// @cache_path is `/sys/devices/system/cpu/cpuN/cache`, whose `index*`
/// directories each describe one cache level with `level`/`type`/`size`
/// (and, on machines that expose it, `id`) files. The LLC level is the
/// index whose `id` matches the CPU's kernel `topology/llc_id` (both
/// describe the same level); on machines whose index entries carry no
/// `id` file, the deepest (largest `level`) index is used. A per-entry
/// read failure skips that entry; a failure of the whole discovery
/// yields `None` and the caller falls back to 0 for the domain.
fn llc_size_bytes(cache_path: &Path) -> Option<u64> {
    let cpu_path = cache_path.parent()?;
    let llc_id = std::fs::read_to_string(cpu_path.join("topology/llc_id"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());

    let mut best: Option<(u64, u64)> = None; // (level, size)
    for entry in std::fs::read_dir(cache_path).ok()?.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("index") {
            continue;
        }
        let dir = entry.path();
        let Some(level) = std::fs::read_to_string(dir.join("level"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
        else {
            continue;
        };
        let id = std::fs::read_to_string(dir.join("id"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok());
        if let Some(llc_id) = llc_id {
            if id.is_some() && id != Some(llc_id) {
                continue;
            }
        }
        let Some(size) = std::fs::read_to_string(dir.join("size"))
            .ok()
            .and_then(|s| parse_cache_size(&s))
        else {
            continue;
        };
        if best.is_none_or(|(best_level, _)| level > best_level) {
            best = Some((level, size));
        }
    }
    best.map(|(_, size)| size)
}

/// Pick the LLC domain with the strictly-largest cache size.
///
/// The Q1 placement bias needs a single unambiguous winner. With fewer
/// than two domains, or two or more domains tied for the largest size
/// (including the all-zeros case of a fully failed discovery), there is
/// no capacity win to exploit and the feature stays off (`None`).
/// `sizes` is indexed by LLC domain id; only the first `nr_llcs`
/// entries are considered.
pub fn pick_largest_llc(sizes: &[u64], nr_llcs: u32) -> Option<u32> {
    if (nr_llcs as usize) < 2 {
        return None;
    }
    let nr = nr_llcs as usize;
    let max = sizes[..nr.min(sizes.len())].iter().copied().max()?;
    let mut argmax = None;
    let mut tied = false;

    for (i, &s) in sizes[..nr.min(sizes.len())].iter().enumerate() {
        if s == max {
            if argmax.is_some() {
                tied = true;
            } else {
                argmax = Some(i as u32);
            }
        }
    }

    if tied {
        return None;
    }
    argmax
}

/// The two placement plans produced by `init_topology()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyPlan {
    pub capacity: CapacityPlan,
    pub llcs: LlcPlan,
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
                    cpu_llc: [mlfq_consts_MLFQ_MAX_LLCS; MAX_CPUS],
                },
            });
        }
    };

    let nr_online = topo.all_cpus.len();
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

    // SMT sibling preference table: the lowest-id sibling per core.
    let sibling = plan_sibling_table(
        &topo
            .all_cpus
            .iter()
            .map(|(id, cpu)| (*id as u32, cpu.core_id as u32))
            .collect::<Vec<_>>(),
    );

    // Largest-LLC bias: per-domain cache sizes from a representative
    // CPU of each domain, then the strictly-largest winner. Every read is
    // best-effort; a failure leaves that domain's size at 0 and a full
    // failure ties the zeros into the sentinel (feature off).
    let mut llc_sizes = vec![0u64; llcs.nr_llcs as usize];
    for (llc, size) in llc_sizes.iter_mut().enumerate() {
        if let Some(&cpu) = llcs.llc_cpus[llc].first() {
            let cache_path = Path::new("/sys/devices/system/cpu").join(format!("cpu{cpu}/cache"));
            *size = llc_size_bytes(&cache_path).unwrap_or(0);
        }
    }
    let largest = pick_largest_llc(&llc_sizes, llcs.nr_llcs).unwrap_or(mlfq_consts_MLFQ_MAX_LLCS);

    let rodata = skel
        .maps
        .rodata_data
        .as_mut()
        .context("rodata missing, the BPF object has no .rodata section")?;
    rodata.mlfq_primary_all = capacity.primary_all;
    rodata.mlfq_nr_llcs = llcs.nr_llcs;
    rodata.mlfq_llc_has_primary = llcs.has_primary;
    rodata.mlfq_cpu_llc = llcs.cpu_llc;
    rodata.mlfq_smt_on = sibling.smt_on;
    rodata.mlfq_cpu_sibling = sibling.cpu_sibling;
    rodata.mlfq_cpu_core = sibling.cpu_core;
    rodata.mlfq_llc_largest = largest;

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
    if sibling.smt_on {
        info!("Topology: SMT siblings detected, sibling preference enabled");
    }
    if largest < llcs.nr_llcs {
        info!("Topology: LLC {largest} has the strictly-largest cache, Q1 bias enabled");
    }

    Ok(TopologyPlan { capacity, llcs })
}

/// Per-CPU static data for the web UI, seeded once at attach.
///
/// Runs `Topology::new()` a second time (besides `init_topology()`) and
/// reports, per online CPU: the maximum operating frequency (`Cpu.max_freq`,
/// in kHz), the LLC domain id (from the same `plan_llcs` mapping the
/// placement path uses) and whether the CPU shares its core with a
/// sibling thread (the `plan_sibling_table` test `sibling[i] != i`, the
/// same pairing the wakeup-preference path consumes). The dynamic
/// per-CPU fields are filled by the web-metrics poll from the BPF
/// per-CPU maps.
///
/// Best-effort like the rest of the topology discovery: any failure
/// yields an empty list and the web UI shows no per-CPU cards rather
/// than aborting the scheduler.
pub fn web_cpu_static() -> Vec<crate::stats::PerCpuMetrics> {
    let topo = match Topology::new() {
        Ok(topo) => topo,
        Err(e) => {
            warn!("CPU topology discovery failed, the web UI reports no per-CPU data: {e}");
            return Vec::new();
        }
    };

    let primaries: Vec<u32> = match get_primary_cpus(Powermode::Performance) {
        Ok(cpus) => cpus.into_iter().map(|cpu| cpu as u32).collect(),
        Err(e) => {
            warn!("primary CPU discovery failed, the web UI reports no per-CPU data: {e}");
            Vec::new()
        }
    };

    let cpu_to_llc: Vec<(u32, u32)> = topo
        .all_cpus
        .iter()
        .map(|(id, cpu)| (*id as u32, cpu.llc_id as u32))
        .collect();
    let llcs = plan_llcs(&cpu_to_llc, &primaries, MAX_LLCS);

    // The SMT badge marks the non-primary thread of a core: the lowest
    // id in the core is the primary, the same anchor convention the
    // sibling table uses for the wakeup-preference path, and every
    // other thread of the core is its virtual sibling. The badge is
    // display-only; the scheduling path reads the sibling table, not
    // this flag.
    let cpu_to_core: Vec<(u32, u32)> = topo
        .all_cpus
        .iter()
        .map(|(id, cpu)| (*id as u32, cpu.core_id as u32))
        .collect();
    let mut core_min: std::collections::BTreeMap<u32, u32> = std::collections::BTreeMap::new();
    for &(cpu, core) in &cpu_to_core {
        core_min
            .entry(core)
            .and_modify(|m| *m = (*m).min(cpu))
            .or_insert(cpu);
    }

    topo.all_cpus
        .iter()
        .map(|(id, cpu)| {
            // The placement path's MLFQ_MAX_LLCS sentinel (an unmapped
            // or unknown CPU) is mapped to 0 for display: the UI shows
            // the LLC id as-is, and "no LLC" is the field's documented
            // convention, not a sentinel value from the placement side.
            let llc_id = llcs.cpu_llc.get(*id).copied().unwrap_or(0);
            let llc_id = if llc_id == mlfq_consts_MLFQ_MAX_LLCS {
                0
            } else {
                llc_id
            };
            crate::stats::PerCpuMetrics {
                id: *id as u32,
                freq_khz: cpu.max_freq as u64,
                cur_freq_khz: 0,
                llc_id,
                smt: core_min
                    .get(&(cpu.core_id as u32))
                    .copied()
                    .unwrap_or(*id as u32)
                    != *id as u32,
                running_queue: 0,
                running_pid: 0,
                rt_occupied: false,
                running_gpu_submit: 0,
            }
        })
        .collect()
}

/// Read a CPU's current operating frequency from sysfs, in kHz. The
/// `scaling_cur_freq` file reflects the live frequency of the CPU,
/// whatever the governor is doing; a missing or unreadable file (no
/// cpufreq driver) yields 0.
pub fn current_freq_khz(cpu: u32) -> u64 {
    std::fs::read_to_string(format!(
        "/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_cur_freq"
    ))
    .ok()
    .and_then(|s| s.trim().parse().ok())
    .unwrap_or(0)
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

/// Phase 2 (post-load): write the per-LLC CPU lists into the
/// `mlfq_llc_cpus` array map.
///
/// One list per LLC domain, the Tier-A same-LLC steal window of the
/// dispatch path. A domain exceeding the `MLFQ_MAX_LLC_CPUS` bound gets
/// an EMPTY list (nr == 0) instead of failing the whole write: the
/// dispatch path then skips Tier A for that domain and Tier B's full
/// rotating window covers it, because Tier B's same-LLC skip is gated
/// on Tier A having run (tier_a_ran stays false for an empty list). The
/// window never silently shrinks to a subset of an oversized domain.
pub fn write_llc_cpu_lists(skel: &mut crate::bpf_skel::BpfSkel<'_>, plan: &LlcPlan) -> Result<()> {
    if plan.nr_llcs == 0 {
        return Ok(());
    }

    for llc in 0..plan.nr_llcs as usize {
        if plan.llc_cpus[llc].len() > MAX_LLC_CPUS {
            warn!(
                "LLC {llc} has {} CPUs, exceeding the supported maximum \
({MAX_LLC_CPUS}); its Tier-A window is skipped and the full rotating window covers the domain",
                plan.llc_cpus[llc].len()
            );
        }
        let list = llc_cpu_list_for(&plan.llc_cpus[llc]);
        write_llc_cpu_list_value(&skel.maps.mlfq_llc_cpus, &list, llc as u32)
            .with_context(|| format!("failed to write the LLC {llc} CPU list"))?;
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

/// Build the Tier-A CPU list one LLC domain publishes.
///
/// Thin wrapper kept for the existing call sites. The actual packing
/// and oversize handling lives in `build_llc_cpu_list`.
fn llc_cpu_list_for(cpus: &[u32]) -> mlfq_llc_cpu_list {
    build_llc_cpu_list(cpus)
}

/// Pack a CPU list into the `mlfq_llc_cpu_list` map value type.
///
/// If the domain has more than `MLFQ_MAX_LLC_CPUS` CPUs the list is
/// left empty (nr == 0) so the dispatch path skips Tier-A for that
/// domain and Tier-B's full rotating window covers it instead of
/// probing a silently truncated subset. CPUs outside `MAX_CPUS` are
/// skipped, same as the BPF-side guard, and nr counts only the CPUs
/// actually stored.
fn build_llc_cpu_list(cpus: &[u32]) -> mlfq_llc_cpu_list {
    if cpus.len() > MAX_LLC_CPUS {
        return mlfq_llc_cpu_list {
            nr: 0,
            cpus: [0; mlfq_consts_MLFQ_MAX_LLC_CPUS as usize],
        };
    }
    let mut list = mlfq_llc_cpu_list {
        nr: 0,
        cpus: [0; mlfq_consts_MLFQ_MAX_LLC_CPUS as usize],
    };
    for &cpu in cpus {
        if cpu as usize >= MAX_CPUS {
            continue;
        }
        list.cpus[list.nr as usize] = cpu;
        list.nr += 1;
    }
    list
}

/// Write @value into the ARRAY map @map at @key (a u32 key).
fn write_llc_cpu_list_value(
    map: &libbpf_rs::Map,
    value: &mlfq_llc_cpu_list,
    key: u32,
) -> Result<()> {
    let key_bytes = key.to_ne_bytes();
    let value_bytes = unsafe {
        std::slice::from_raw_parts(
            value as *const _ as *const u8,
            size_of::<mlfq_llc_cpu_list>(),
        )
    };
    map.update(&key_bytes, value_bytes, MapFlags::ANY)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf_intf::mlfq_consts_MLFQ_LLC_SCAN_MAX;

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
        // An unknown CPU keeps the sentinel, never the 0 of a valid domain.
        assert_eq!(plan.cpu_llc[4], mlfq_consts_MLFQ_MAX_LLCS);
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
    fn llc_plan_saturates_on_u32_max_llc_id() {
        // A llc_id of u32::MAX must not wrap the domain count to zero,
        // which would pass the cap check and later index out of bounds.
        let plan = plan_llcs(&[(0, 0), (1, u32::MAX)], &[], MAX_LLCS);
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
        // An in-range CPU the map does not cover keeps the sentinel.
        assert_eq!(plan.cpu_llc[1], mlfq_consts_MLFQ_MAX_LLCS);
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

    #[test]
    fn smt_pair_table() {
        // Two SMT pairs over four CPUs / two cores: each CPU points at
        // the other member of its core.
        let plan = plan_sibling_table(&[(0, 0), (1, 0), (2, 1), (3, 1)]);
        assert!(plan.smt_on);
        assert_eq!(&plan.cpu_sibling[..4], &[1, 0, 3, 2]);
    }

    #[test]
    fn smt_off_with_distinct_cores() {
        let plan = plan_sibling_table(&[(0, 0), (1, 1), (2, 2), (3, 3)]);
        assert!(!plan.smt_on);
        assert_eq!(&plan.cpu_sibling[..4], &[0, 1, 2, 3]);
    }

    #[test]
    fn smt_unpaired_cpu_maps_to_self() {
        let plan = plan_sibling_table(&[(0, 0), (1, 0), (2, 2)]);
        assert!(plan.smt_on);
        assert_eq!(plan.cpu_sibling[0], 1);
        assert_eq!(plan.cpu_sibling[1], 0);
        // The unpaired core's CPU has no sibling: itself.
        assert_eq!(plan.cpu_sibling[2], 2);
    }

    #[test]
    fn smt_table_is_order_independent() {
        let plan = plan_sibling_table(&[(1, 0), (3, 1), (0, 0), (2, 1)]);
        assert_eq!(&plan.cpu_sibling[..4], &[1, 0, 3, 2]);
    }

    #[test]
    fn smt_empty_input_stays_off() {
        let plan = plan_sibling_table(&[]);
        assert!(!plan.smt_on);
        assert_eq!(plan.cpu_sibling[0], 0);
    }

    #[test]
    fn largest_llc_unique_max_wins() {
        assert_eq!(pick_largest_llc(&[16, 32, 8], 3), Some(1));
    }

    #[test]
    fn largest_llc_tie_is_disabled() {
        assert_eq!(pick_largest_llc(&[32, 32, 8], 3), None);
    }

    #[test]
    fn largest_llc_single_domain_is_disabled() {
        assert_eq!(pick_largest_llc(&[32], 1), None);
    }

    #[test]
    fn largest_llc_zero_domains_is_disabled() {
        assert_eq!(pick_largest_llc(&[], 0), None);
    }

    #[test]
    fn largest_llc_all_zero_sizes_tie_to_disabled() {
        // Fully failed discovery: every size reads 0 and the zeros tie.
        assert_eq!(pick_largest_llc(&[0, 0, 0], 3), None);
    }

    #[test]
    fn largest_llc_unreadable_domain_reads_zero() {
        // One domain's size read failed (0): the other is strictly
        // largest and wins.
        assert_eq!(pick_largest_llc(&[16, 0], 2), Some(0));
    }

    #[test]
    fn parse_cache_size_suffixes() {
        assert_eq!(parse_cache_size("16384K"), Some(16384 * 1024));
        assert_eq!(parse_cache_size("32M"), Some(32 * 1024 * 1024));
        assert_eq!(parse_cache_size("1G"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_cache_size("4096"), Some(4096));
        assert_eq!(parse_cache_size("bogus"), None);
    }

    #[test]
    fn llc_size_bytes_picks_the_llc_index_by_id() {
        // Fake sysfs: index0 is the L2 (id 4), index1 the LLC (id 7);
        // the CPU's topology llc_id selects the LLC entry.
        let dir = std::env::temp_dir().join(format!("scx_mlfq_cache_id_{}", std::process::id()));
        std::fs::create_dir_all(dir.join("cpu0/cache/index0")).unwrap();
        std::fs::create_dir_all(dir.join("cpu0/cache/index1")).unwrap();
        std::fs::create_dir_all(dir.join("cpu0/topology")).unwrap();
        std::fs::write(dir.join("cpu0/cache/index0/level"), "2\n").unwrap();
        std::fs::write(dir.join("cpu0/cache/index0/size"), "512K\n").unwrap();
        std::fs::write(dir.join("cpu0/cache/index0/id"), "4\n").unwrap();
        std::fs::write(dir.join("cpu0/cache/index1/level"), "3\n").unwrap();
        std::fs::write(dir.join("cpu0/cache/index1/size"), "32M\n").unwrap();
        std::fs::write(dir.join("cpu0/cache/index1/id"), "7\n").unwrap();
        std::fs::write(dir.join("cpu0/topology/llc_id"), "7\n").unwrap();

        let size = llc_size_bytes(&dir.join("cpu0/cache"));
        assert_eq!(size, Some(32 * 1024 * 1024));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn llc_size_bytes_falls_back_to_deepest_level_without_id() {
        // No id files and no topology llc_id: the deepest index wins.
        let dir = std::env::temp_dir().join(format!("scx_mlfq_cache_noid_{}", std::process::id()));
        std::fs::create_dir_all(dir.join("cpu0/cache/index0")).unwrap();
        std::fs::create_dir_all(dir.join("cpu0/cache/index1")).unwrap();
        std::fs::write(dir.join("cpu0/cache/index0/level"), "2\n").unwrap();
        std::fs::write(dir.join("cpu0/cache/index0/size"), "512K\n").unwrap();
        std::fs::write(dir.join("cpu0/cache/index1/level"), "3\n").unwrap();
        std::fs::write(dir.join("cpu0/cache/index1/size"), "32M\n").unwrap();

        let size = llc_size_bytes(&dir.join("cpu0/cache"));
        assert_eq!(size, Some(32 * 1024 * 1024));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn llc_size_bytes_missing_path_is_none() {
        let dir =
            std::env::temp_dir().join(format!("scx_mlfq_cache_missing_{}", std::process::id()));
        assert_eq!(llc_size_bytes(&dir.join("cpu0/cache")), None);
    }

    #[test]
    fn build_llc_cpu_list_layout() {
        let list = build_llc_cpu_list(&[0, 1, 2, 1023]);
        assert_eq!(list.nr, 4);
        assert_eq!(&list.cpus[..4], &[0, 1, 2, 1023]);
        assert_eq!(list.cpus[4], 0);
    }

    #[test]
    fn build_llc_cpu_list_skips_out_of_range() {
        let list = build_llc_cpu_list(&[0, 5000, 1]);
        assert_eq!(list.nr, 2);
        assert_eq!(&list.cpus[..2], &[0, 1]);
    }

    #[test]
    fn max_llc_cpus_matches_bpf_constant() {
        assert_eq!(MAX_LLC_CPUS, mlfq_consts_MLFQ_MAX_LLC_CPUS as usize);
    }

    #[test]
    fn oversized_llc_domain_publishes_an_empty_list() {
        // A domain larger than the Tier-A window gets nr == 0: Tier A
        // skips it and Tier B's full rotating window covers the domain.
        let over: Vec<u32> = (0..MAX_LLC_CPUS as u32 + 1).collect();
        assert_eq!(llc_cpu_list_for(&over).nr, 0);

        // A domain that fits the window publishes every CPU, and the
        // window width equals the list bound, so the constant modulo
        // covers the whole populated list.
        let fits: Vec<u32> = (0..MAX_LLC_CPUS as u32).collect();
        let list = llc_cpu_list_for(&fits);
        assert_eq!(list.nr, MAX_LLC_CPUS as u32);
        assert_eq!(MAX_LLC_CPUS, mlfq_consts_MLFQ_LLC_SCAN_MAX as usize);
    }
}
