/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Trimmed topology for the flow scheduler. Static cards
 * plus sibling plus LLC plus capacity plus max frequency
 * seed the group table. Live frequency plus CPU cards
 * stay display only and never shape placement.
 * Zero means unknown and keeps a plain fallback.
 */
use log::warn;
use scx_utils::Topology;

/* Compile time CPU bound. Matches the BPF header. */
const MAX_CPUS: usize = crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize;

/* True when a lower id shares the core. */
fn has_older(topo: &Topology, id: usize, core: usize) -> bool {
    topo.all_cpus
        .iter()
        .any(|(oid, o)| o.core_id == core && *oid < id)
}

/*
 * Static per CPU cards seeded once at attach. Max
 * frequency, cache domain and thread role come from
 * the host topology. Zero frequency means unknown and
 * stays display only. Failures yield an empty list so
 * the scheduler keeps running without cards. Single
 * CPU and no sibling hosts keep plain per CPU cards.
 * Live frequency plus CPU cards stay display only
 * and never shape placement. Max frequency plus
 * capacity plus LLC plus siblings seed groups.
 */
pub fn web_cpu_static() -> Vec<crate::stats::PerCpuMetrics> {
    let topo = match Topology::new() {
        Ok(v) => v,
        Err(e) => {
            warn!("topology failed, web cards empty: {e}");
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for (id, cpu) in topo.all_cpus.iter() {
        if *id >= MAX_CPUS {
            continue;
        }
        let smt = has_older(&topo, *id, cpu.core_id);
        out.push(crate::stats::PerCpuMetrics {
            id: *id as u32,
            freq_khz: cpu.max_freq as u64,
            cur_freq_khz: 0,
            llc_id: cpu.llc_id as u32,
            smt,
            group: 0,
            running_est_ns: 0,
            running_pid: 0,
            running_nice: 0,
            running_weight: 1024,
            delay_win: 0,
            delay_armed: false,
            slice_ns: crate::flow::SLICE_NS,
        });
    }
    out.sort_by_key(|e| e.id);
    out
}

/*
 * One line topology summary for the start log. Counts
 * CPUs and notes sibling and frequency state in plain
 * words. Unknown frequency stays unknown and never
 * prints as zero. Missing cards stay unknown. Single
 * CPU prints as one CPU with no peers. No sibling
 * prints as no SMT with plain per CPU behavior.
 * Frequency plus LLC plus CPU cards stay display only
 * and never shape placement.
 */
pub fn describe_topology(cards: &[crate::stats::PerCpuMetrics]) -> String {
    if cards.is_empty() {
        return "topology unknown, plain per-CPU".to_string();
    }
    let count = cards.len();
    let smt = cards.iter().any(|c| c.smt);
    let freq = cards.iter().any(|c| c.freq_khz != 0);
    let cpu_word = if count == 1 { "CPU" } else { "CPUs" };
    let smt_word = if smt { "SMT" } else { "no SMT" };
    let freq_word = if freq { "freq known" } else { "freq unknown" };
    format!(
        "topology: {} {}, {}, {}",
        count, cpu_word, smt_word, freq_word
    )
}

/*
 * Parse a frequency string in kilohertz. Trims space
 * and parses the number. Bad input yields zero for
 * unknown. The value stays display only and never
 * feeds placement or division.
 */
pub fn parse_freq_khz(s: &str) -> u64 {
    s.trim().parse().unwrap_or(0)
}

/*
 * Capacity of one CPU from the host file. Missing files
 * yield zero for unknown. The value feeds group assign
 * with frequency, else halves applies with no trap.
 */
pub fn read_cpu_capacity(cpu: u32) -> u64 {
    std::fs::read_to_string(format!(
        "{}{}{}",
        "/sys/devices/system/cpu/cpu", cpu, "/cpu_capacity"
    ))
    .ok()
    .map(|s| parse_freq_khz(&s))
    .unwrap_or(0)
}

/*
 * Max frequency of one CPU in kilohertz. Reads the
 * cpuinfo file. Missing files yield zero for unknown.
 * The value feeds group assign with capacity, else
 * halves applies with no trap.
 */
pub fn read_cpuinfo_max_freq(cpu: u32) -> u64 {
    std::fs::read_to_string(format!(
        "{}{}{}{}",
        "/sys/devices/system/cpu/cpu", cpu, "/cpufreq/", "cpuinfo_max_freq"
    ))
    .ok()
    .map(|s| parse_freq_khz(&s))
    .unwrap_or(0)
}

/*
 * Seed the per CPU group table plus ready flag. Reads
 * capacity plus max frequency plus siblings plus LLC
 * for live CPUs, then assigns with core split plus LLC
 * rules plus hetero interleave. All singleton cores use
 * halves plus interleave exactly. Ready stays cleared
 * when the core view matches halves, else ready set.
 * Strict iff ready is zero, best effort iff ready is
 * one. Single CPU keeps ready cleared with all light.
 * Short slices clamp with no pad. One core in one LLC
 * keeps LIGHT with no split. Each odd LLC gives the
 * extra core to hog.
 */
pub fn group_seed(nr: usize) -> ([u8; crate::flow_group::GROUP_TABLE_LEN], u8) {
    let n = nr.min(MAX_CPUS).min(crate::flow_group::GROUP_TABLE_LEN);
    let mut caps = Vec::with_capacity(n);
    let mut freqs = Vec::with_capacity(n);
    for cpu in 0..n {
        caps.push(read_cpu_capacity(cpu as u32));
        freqs.push(read_cpuinfo_max_freq(cpu as u32));
    }
    let lists = sibling_lists(n);
    let llc = llc_ids(n);
    crate::flow_group::seed_groups_topology(&caps, &freqs, n, &lists, &llc)
}

/*
 * Sibling ids of one CPU from sysfs. Reads the thread
 * siblings list file. Missing files yield empty for a
 * singleton core with no trap. Values cap at 1024.
 */
pub fn read_thread_siblings(cpu: u32) -> Vec<u32> {
    if cpu as usize >= MAX_CPUS {
        return Vec::new();
    }
    std::fs::read_to_string(format!(
        "{}{}{}{}",
        "/sys/devices/system/cpu/cpu", cpu, "/topology/", "thread_siblings_list"
    ))
    .ok()
    .map(|s| crate::flow_group::parse_siblings_list(&s))
    .unwrap_or_default()
}

/*
 * Sibling lists for live CPUs. Each entry holds the
 * sibling ids of one CPU in id order. Missing files
 * yield singletons with no trap. Capped at 1024.
 * Empty entries count as sysfs fallbacks with
 * singleton behavior. The caller logs the count once
 * at start with no per CPU log.
 */
pub fn sibling_lists(nr: usize) -> Vec<Vec<u32>> {
    let n = nr.min(MAX_CPUS).min(crate::flow_group::GROUP_TABLE_LEN);
    let mut out = Vec::with_capacity(n);
    for cpu in 0..n {
        out.push(read_thread_siblings(cpu as u32));
    }
    out
}

/*
 * Sibling partner table plus fallback count. Builds
 * cores from sibling lists, then maps each CPU to the
 * next CPU in the same core in id order. Singletons
 * hold 0xffff, so the BPF free check is a no-op.
 * Empty lists count as sysfs fallbacks with singleton
 * behavior and no trap. Capped at 1024 with no new
 * maps. The caller logs the count once at start.
 */
pub fn sibling_seed(nr: usize) -> ([u16; crate::flow_group::GROUP_TABLE_LEN], usize) {
    let n = nr.min(MAX_CPUS).min(crate::flow_group::GROUP_TABLE_LEN);
    let lists = sibling_lists(n);
    let mut fallbacks = 0;
    for v in &lists {
        if v.is_empty() {
            fallbacks += 1;
        }
    }
    let cores = crate::flow_group::build_cores(n, &lists);
    let table = crate::flow_group::sibling_table(&cores, n);
    (table, fallbacks)
}

/*
 * LLC ids for live CPUs. Reads the host topology once.
 * Missing topology yields empty for one domain with no
 * pad. Missing CPUs read as zero with no trap. Values
 * seed per LLC split with no division.
 */
pub fn llc_ids(nr: usize) -> Vec<u32> {
    let n = nr.min(MAX_CPUS).min(crate::flow_group::GROUP_TABLE_LEN);
    let topo = match Topology::new() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::with_capacity(n);
    for cpu in 0..n {
        let id = topo
            .all_cpus
            .get(&cpu)
            .map(|c| c.llc_id as u32)
            .unwrap_or(0);
        out.push(id);
    }
    out
}

/*
 * Live frequency of one CPU in kilohertz. Reads the
 * cpufreq file. Missing files yield zero for unknown.
 * The value is display only and never feeds placement
 * or division. Frequency stays display only.
 */
pub fn current_freq_khz(cpu: u32) -> u64 {
    std::fs::read_to_string(format!(
        "{}{}{}{}",
        "/sys/devices/system/cpu/cpu", cpu, "/cpufreq/", "scaling_cur_freq"
    ))
    .ok()
    .map(|s| parse_freq_khz(&s))
    .unwrap_or(0)
}

/*
 * Filter cards to an allowed subset for tests. Keeps
 * cards whose id is marked in the mask. Models pinned
 * cgroup subsets with no placement use. Frequency plus
 * LLC plus CPU cards stay display only here.
 */
#[cfg(test)]
pub fn filter_allowed(
    cards: &[crate::stats::PerCpuMetrics],
    allowed: &[bool],
) -> Vec<crate::stats::PerCpuMetrics> {
    cards
        .iter()
        .filter(|c| allowed.get(c.id as usize).copied().unwrap_or(false))
        .cloned()
        .collect()
}

/*
 * Synthetic card for tests. Builds one display only
 * card with the given id plus frequency plus LLC plus
 * thread role. Slice stays fixed at 1ms. Group stays
 * light with zero.
 */
#[cfg(test)]
pub fn synthetic_card(
    id: u32,
    freq_khz: u64,
    llc_id: u32,
    smt: bool,
) -> crate::stats::PerCpuMetrics {
    crate::stats::PerCpuMetrics {
        id,
        freq_khz,
        cur_freq_khz: 0,
        llc_id,
        smt,
        group: 0,
        running_est_ns: 0,
        running_pid: 0,
        running_nice: 0,
        running_weight: 1024,
        delay_win: 0,
        delay_armed: false,
        slice_ns: crate::flow::SLICE_NS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_cpu_card_reports_one_cpu() {
        let cards = vec![synthetic_card(0, 3800000, 0, false)];
        assert_eq!(cards.len(), 1);
        assert_eq!(
            describe_topology(&cards),
            "topology: 1 CPU, no SMT, freq known"
        );
        assert_eq!(filter_allowed(&cards, &[true]).len(), 1);
        assert_eq!(filter_allowed(&cards, &[false]).len(), 0);
        assert!(crate::flow_select::may_run_on(0, &[true]));
        assert!(!crate::flow_select::may_run_on(1, &[true]));
    }

    #[test]
    fn lestat_16_plus_16_subset_keeps_allowed() {
        let mut cards = Vec::new();
        for cpu in 0..32u32 {
            let llc = if cpu < 16 { 0 } else { 1 };
            cards.push(synthetic_card(cpu, 3500000, llc, false));
        }
        assert_eq!(cards.len(), 32);
        let mut allowed = vec![false; 32];
        for cpu in 0..8 {
            allowed[cpu] = true;
        }
        for cpu in 16..24 {
            allowed[cpu] = true;
        }
        let subset = filter_allowed(&cards, &allowed);
        assert_eq!(subset.len(), 16);
        for c in &subset {
            assert!(allowed[c.id as usize]);
            assert!(c.freq_khz != 0);
        }
        assert_eq!(
            describe_topology(&subset),
            "topology: 16 CPUs, no SMT, freq known"
        );
        for cpu in [8, 15, 24, 31] {
            assert!(!allowed[cpu]);
        }
    }

    #[test]
    fn freq_parse_handles_valid_and_bad() {
        assert_eq!(parse_freq_khz("3800000\n"), 3800000);
        assert_eq!(parse_freq_khz("  3500000  "), 3500000);
        assert_eq!(parse_freq_khz(""), 0);
        assert_eq!(parse_freq_khz("abc"), 0);
        assert_eq!(parse_freq_khz("0"), 0);
        assert!(!crate::flow_select::freq_known(0));
        assert!(crate::flow_select::freq_known(3800000));
    }

    #[test]
    fn unknown_topology_stays_plain() {
        let empty: Vec<crate::stats::PerCpuMetrics> = Vec::new();
        assert_eq!(describe_topology(&empty), "topology unknown, plain per-CPU");
        let unknown = vec![synthetic_card(0, 0, 0, false)];
        assert_eq!(
            describe_topology(&unknown),
            "topology: 1 CPU, no SMT, freq unknown"
        );
    }
}
