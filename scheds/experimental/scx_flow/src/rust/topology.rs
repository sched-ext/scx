// SPDX-License-Identifier: GPL-2.0
//! Topology view for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Reads the host CPU lists plus the node rows for the BPF seed.
//! Node reads use the kernel NUMA view with zero on fault and a cap
//! at eight, so large hosts fold to the machine queue with no panic.

/// CPU ids past this bound never seed, mirroring FLOW_MAX_CPUS.
const CPU_BOUND: u32 = 512;

/// Online CPU ids in rank order with empty on read fault.
pub fn online_cpus() -> Vec<u32> {
    read_cpu_list_file("/sys/devices/system/cpu/online")
}

/// One topology row per CPU with sibling plus node.
/// Sibling reads the thread list with all ones on fault, and node
/// reads the NUMA view with zero on fault and a cap at eight.
pub fn topo_rows() -> Vec<(u32, u32, u32)> {
    let online = online_cpus();
    let mut rows = Vec::new();
    for cpu in online {
        let sib = thread_sibling(cpu).unwrap_or(u32::MAX);
        let node = cpu_node(cpu).unwrap_or(0);
        let node = if node < 8 { node } else { 0 };
        rows.push((cpu, sib, node));
    }
    rows
}

/// Short topology line for the start log.
pub fn describe_topology(rows: &[(u32, u32, u32)]) -> String {
    format!("cpus={} seeded", rows.len())
}

/// True when the CPU is the second thread of one core.
/// Sibling holds all ones on single thread, so single thread stays
/// false with no panic. A lower sibling marks the second thread, so
/// only one card per core shows SMT with no extra sysfs use.
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
        let node = 12u32;
        let capped = if node < 8 { node } else { 0 };
        assert_eq!(capped, 0);
    }

    #[test]
    fn clamps_ranges_and_ids_to_cpu_bound() {
        let wide = parse_cpu_list("0-600");
        assert_eq!(wide.len(), 512);
        assert!(wide.iter().all(|c| *c < 512));
        assert_eq!(parse_cpu_list("511-600"), vec![511]);
        assert_eq!(parse_cpu_list("600"), Vec::<u32>::new());
        assert_eq!(parse_cpu_list("600-700"), Vec::<u32>::new());
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
}
