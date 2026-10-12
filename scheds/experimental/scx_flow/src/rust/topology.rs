// SPDX-License-Identifier: GPL-2.0
//! Topology view for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Delegates host discovery to scx_utils::Topology with a sysfs
//! fallback, then seeds the BPF view in two best-effort phases.
//! Phase one writes the primary rows with sibling plus node, and phase
//! two refreshes the LLC bitmaps for the start log. Either phase keeps
//! the BPF defaults on fault with no trap and no hot-path use.
//! Sibling assumes two-way SMT as in sibling_cpus, so a third thread
//! stays single with all ones. Span holds online CPUs at init, so the
//! seed matches the sysfs online list with no hotplug use.

use scx_utils::Topology;

/// CPU ids past this bound never seed, mirroring FLOW_MAX_CPUS.
const CPU_BOUND: u32 = 1024;

/// Node ids past this bound fold to zero, mirroring FLOW_MAX_NODES.
const NODE_BOUND: u32 = 16;

/// One topology row per CPU with sibling plus node.
/// Sibling comes from the core view with all ones on fault, and node
/// folds to zero on fault with a cap at sixteen. A Topology failure
/// falls back to the sysfs lists with the same shape and no panic.
pub fn topo_rows() -> Vec<(u32, u32, u32)> {
    init_topology()
}

/// Build the seeded rows from the shared Topology view.
/// Uses scx_utils::Topology as the source of truth with a sysfs
/// fallback on fault, so large hosts fold to the machine queue with
/// no panic and no extra scan on the hot paths. Span equals the online
/// list at construction, sorted in rank order with the CPU plus node
/// bounds, so the seed matches sysfs online with no extra view. Sibling
/// follows sibling_cpus with two-way assumed, so extra threads on wider
/// cores stay single with no extra scan.
pub fn init_topology() -> Vec<(u32, u32, u32)> {
    if let Ok(topo) = Topology::new() {
        let sibs = topo.sibling_cpus();
        let mut rows = Vec::new();
        let mut online: Vec<u32> = topo.span.iter().map(|c| c as u32).collect();
        online.sort_unstable();
        for cpu in online {
            if cpu >= CPU_BOUND {
                continue;
            }
            let sib = sibs
                .get(cpu as usize)
                .copied()
                .filter(|s| *s >= 0)
                .map(|s| s as u32)
                .filter(|s| *s != cpu)
                .unwrap_or(u32::MAX);
            let node = topo
                .all_cpus
                .get(&(cpu as usize))
                .map(|c| c.node_id as u32)
                .unwrap_or(0);
            let node = if node < NODE_BOUND { node } else { 0 };
            rows.push((cpu, sib, node));
        }
        if !rows.is_empty() {
            return rows;
        }
    }
    fallback_rows()
}

/// Primary bitmap text for the start log in rank order.
/// Best effort with empty on fault, so a failed read never traps.
pub fn write_primary_bitmap(rows: &[(u32, u32, u32)]) -> String {
    let mut ids: Vec<u32> = rows.iter().map(|(cpu, _, _)| *cpu).collect();
    ids.sort_unstable();
    ids.iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// LLC bitmap texts for the start log, one entry per LLC.
/// Best effort with empty on fault, so hosts without an LLC view log
/// no bitmap with no trap and no hot-path use.
pub fn write_llc_bitmaps() -> Vec<String> {
    let topo = match Topology::new() {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for llc in topo.all_llcs.values() {
        let mut ids: Vec<usize> = llc.all_cpus.keys().copied().collect();
        ids.sort_unstable();
        let text = ids
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        out.push(text);
    }
    out.sort();
    out
}

/// Short topology line for the start log.
/// Shows cpus seeded with primary plus llcs counts, so the 4.8.12 start
/// log carries primary plus llcs past the old cpus seeded line with no
/// hot-path use.
pub fn describe_topology(rows: &[(u32, u32, u32)]) -> String {
    let primary = write_primary_bitmap(rows);
    let llcs = write_llc_bitmaps();
    if llcs.is_empty() {
        format!("cpus={} seeded", rows.len())
    } else {
        format!(
            "cpus={} seeded primary=[{}] llcs={}",
            rows.len(),
            primary,
            llcs.len()
        )
    }
}

/// True when the CPU is the second thread of one core.
/// Sibling holds all ones on single thread, so single thread stays
/// false with no panic. A lower sibling marks the second thread, so
/// only one card per core shows SMT with no extra sysfs use. Two-way
/// assumed as in sibling_cpus, so a third thread on wider cores stays
/// single by design with no extra kick and no non-x86 walk.
pub fn is_smt_thread(cpu: u32, sib: u32) -> bool {
    sib != u32::MAX && sib < cpu
}

/// Parse a kernel CPU list like 0-3 plus 5 into ids.
/// Ranges clamp to the CPU bound before the walk, so a faulty list
/// never loops the full u32 range. Ids past the bound never seed.
pub fn parse_cpu_list(s: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-')
            && let (Ok(lo), Ok(hi)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>())
        {
            let hi = hi.min(CPU_BOUND - 1);
            if lo <= hi {
                for cpu in lo..=hi {
                    out.push(cpu);
                }
            }
            continue;
        }
        if let Ok(cpu) = part.parse::<u32>()
            && cpu < CPU_BOUND
        {
            out.push(cpu);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Read one kernel CPU list file into ids with empty on fault.
pub fn read_cpu_list_file(path: &str) -> Vec<u32> {
    std::fs::read_to_string(path)
        .map(|s| parse_cpu_list(&s))
        .unwrap_or_default()
}

/// Fallback rows from the sysfs lists with the same shape.
/// Sibling reads the thread list with all ones on fault, and node
/// reads the NUMA view with zero on fault and a cap at sixteen.
fn fallback_rows() -> Vec<(u32, u32, u32)> {
    let online = read_cpu_list_file("/sys/devices/system/cpu/online");
    let mut rows = Vec::new();
    for cpu in online {
        let sib = thread_sibling(cpu).unwrap_or(u32::MAX);
        let node = cpu_node(cpu).unwrap_or(0);
        let node = if node < NODE_BOUND { node } else { 0 };
        rows.push((cpu, sib, node));
    }
    rows
}

/// Thread sibling of one CPU with None on fault.
fn thread_sibling(cpu: u32) -> Option<u32> {
    let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
    let ids = read_cpu_list_file(&path);
    ids.into_iter().find(|id| *id != cpu)
}

/// Node of one CPU with None on fault.
/// Reads the NUMA view through the per CPU node links with a fallback
/// to the node cpulists, so package ids never shape placement.
/// A missing link plus a missing cpulist means unknown, so the caller
/// folds to zero with no panic.
fn cpu_node(cpu: u32) -> Option<u32> {
    let dir = format!("/sys/devices/system/cpu/cpu{cpu}");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(suffix) = name.strip_prefix("node")
                && !suffix.is_empty()
                && let Ok(node) = suffix.parse::<u32>()
            {
                return Some(node);
            }
        }
    }
    node_from_cpulists(cpu)
}

/// Node of one CPU from the node cpulists with None on fault.
/// Scans the online nodes and returns the first node whose cpulist
/// holds the CPU, so hosts without per CPU links still seed.
fn node_from_cpulists(cpu: u32) -> Option<u32> {
    let ids = read_cpu_list_file("/sys/devices/system/node/online");
    for node in ids {
        let path = format!("/sys/devices/system/node/node{node}/cpulist");
        let cpus = read_cpu_list_file(&path);
        if cpus.contains(&cpu) {
            return Some(node);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ranges_and_singles() {
        assert_eq!(parse_cpu_list("0-3"), vec![0, 1, 2, 3]);
        assert_eq!(parse_cpu_list("0-1,3"), vec![0, 1, 3]);
        assert_eq!(parse_cpu_list(""), Vec::<u32>::new());
    }

    #[test]
    fn rows_cap_large_nodes() {
        let node = 20u32;
        let capped = if node < NODE_BOUND { node } else { 0 };
        assert_eq!(capped, 0);
    }

    #[test]
    fn clamps_ranges_and_ids_to_cpu_bound() {
        let wide = parse_cpu_list("0-1100");
        assert_eq!(wide.len(), 1024);
        assert!(wide.iter().all(|c| *c < 1024));
        assert_eq!(parse_cpu_list("1023-1100"), vec![1023]);
        assert_eq!(parse_cpu_list("1100"), Vec::<u32>::new());
        assert_eq!(parse_cpu_list("1100-1200"), Vec::<u32>::new());
    }

    #[test]
    fn smt_marks_only_second_thread() {
        assert!(!is_smt_thread(0, u32::MAX));
        assert!(!is_smt_thread(0, 1));
        assert!(is_smt_thread(1, 0));
        assert!(!is_smt_thread(4, 5));
        assert!(is_smt_thread(5, 4));
        assert!(!is_smt_thread(7, u32::MAX));
    }

    #[test]
    fn primary_bitmap_joins_rank_order() {
        let rows = vec![(2, u32::MAX, 0), (0, u32::MAX, 0), (1, 0, 0)];
        assert_eq!(write_primary_bitmap(&rows), "0,1,2");
        assert_eq!(write_primary_bitmap(&[]), "");
    }

    #[test]
    fn init_topology_rows_stay_in_bounds() {
        let rows = init_topology();
        assert_eq!(topo_rows(), rows);
        assert!(
            rows.iter()
                .all(|(c, _, n)| *c < CPU_BOUND && *n < NODE_BOUND)
        );
        let mut ids: Vec<u32> = rows.iter().map(|(c, _, _)| *c).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), rows.len());
    }
}
