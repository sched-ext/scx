// SPDX-License-Identifier: GPL-2.0
/*
 * Trimmed topology
 *
 * Seeds the group table from static cards, sibling, LLC, capacity, and max
 * frequency. Live frequency and CPU cards stay display only and never shape
 * placement. Zero means unknown and keeps a plain fallback.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
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
 * Static per CPU cards seeded once at attach. Max frequency, cache domain and
 * thread role come from the host topology. Zero frequency means unknown and
 * stays display only. Failures yield an empty list so the scheduler keeps
 * running without cards. Single CPU and no sibling hosts keep plain per CPU
 * cards. Live frequency and CPU cards stay display only and never shape
 * placement. Max frequency, capacity, LLC, and siblings seed groups.
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
            active_ns: 0,
        });
    }
    out.sort_by_key(|e| e.id);
    out
}

/*
 * One line topology summary for the start log. Counts CPUs and notes sibling
 * and frequency state in plain words. Unknown frequency stays unknown and never
 * prints as zero. Missing cards stay unknown. Single CPU prints as one CPU with
 * no peers. No sibling prints as no SMT with plain per CPU behavior. Frequency,
 * LLC, and CPU cards stay display only and never shape placement.
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
 * Base governor without the diagnostic suffix. Trims space, cuts at the paren,
 * and space, so performance with suffix still reads as performance. Empty stays
 * empty with no trap. The suffix never feeds the unanimity check.
 */
pub fn governor_base(g: &str) -> &str {
    let t = g.trim();
    if let Some(idx) = t.find('(') {
        return t[..idx].trim();
    }
    if let Some(idx) = t.find(' ') {
        return t[..idx].trim();
    }
    t
}

/*
 * Platform profile once per tick. The file is machine
 * global with one value for all CPUs. Missing files
 * yield nothing with no trap, same as the per CPU
 * path today. Callers read once per tick, then thread
 * the value into the per CPU path.
 */
pub fn read_platform_profile() -> Option<String> {
    std::fs::read_to_string("/sys/firmware/acpi/platform_profile")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/*
 * Governor of one CPU with a given platform value. Reads the scaling governor
 * and EPP files per CPU. The platform value is machine global and passed in, so
 * the tick reads the file once. Missing files yield unknown and no suffix with
 * no trap, same as today. The suffix is display only and never feeds base.
 */
pub fn read_governor_with_profile(cpu: u32, platform: Option<&str>) -> String {
    let base = std::fs::read_to_string(format!(
        "{}{}{}{}",
        "/sys/devices/system/cpu/cpu", cpu, "/cpufreq/", "scaling_governor"
    ))
    .ok()
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty())
    .unwrap_or_else(|| "unknown".to_string());
    if base == "unknown" {
        return base;
    }
    let epp = std::fs::read_to_string(format!(
        "{}{}{}{}",
        "/sys/devices/system/cpu/cpu", cpu, "/cpufreq/", "energy_performance_preference"
    ))
    .ok()
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty());
    let pp = platform
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    match (epp, pp) {
        (Some(e), Some(p)) => format!("{base} (epp:{e} pp:{p})"),
        (Some(e), None) => format!("{base} (epp:{e})"),
        (None, Some(p)) => format!("{base} (pp:{p})"),
        (None, None) => base,
    }
}

/*
 * Governors for one tick with one platform read.
 * Calls the provider exactly once per collection, then
 * threads the value into each per CPU read. Empty stays
 * empty with one call and no trap. Output matches per
 * CPU reads with the same value, see the tests.
 */
pub fn collect_governors_with<F>(cpus: &[u32], mut provider: F) -> Vec<String>
where
    F: FnMut() -> Option<String>,
{
    let platform = provider();
    cpus.iter()
        .map(|&id| read_governor_with_profile(id, platform.as_deref()))
        .collect()
}

/*
 * Governors for one tick over online CPUs. Reads the
 * platform profile once per call, so a 16 CPU tick pays
 * one slow read, not sixteen. Missing files yield the
 * same strings as per CPU reads with no trap.
 */
pub fn collect_governors(cpus: &[u32]) -> Vec<String> {
    collect_governors_with(cpus, read_platform_profile)
}

/*
 * True when every governor reads performance. Needs a non empty list with each
 * base at performance, so a single powersave, mixed, unknown, and empty stays
 * strict with no trap. The EPP and platform suffix never feeds this check, see
 * base. Online CPUs only with no per CPU array in BPF.
 */
pub fn perf_unanimous(governors: &[String]) -> bool {
    if governors.is_empty() {
        return false;
    }
    for g in governors {
        if governor_base(g) != "performance" {
            return false;
        }
    }
    true
}

/*
 * Display governor for the dashboard and snapshot. Empty reads as unknown.
 * Unanimous with same suffix reads as the first full string, so EPP stays
 * visible. Unanimous with differing suffix reads as the base. Mixed bases read
 * as mixed with no list. Unknown alone stays unknown with no trap.
 */
pub fn display_governor(governors: &[String]) -> String {
    if governors.is_empty() {
        return "unknown".to_string();
    }
    let first = governor_base(&governors[0]).to_string();
    let mut same = true;
    for g in governors.iter().skip(1) {
        if governor_base(g) != first {
            same = false;
            break;
        }
    }
    if !same {
        return "mixed".to_string();
    }
    if first == "unknown" || first.is_empty() {
        return "unknown".to_string();
    }
    if governors.len() == 1 {
        return governors[0].clone();
    }
    let mut suffix_same = true;
    for g in governors.iter().skip(1) {
        if g != &governors[0] {
            suffix_same = false;
            break;
        }
    }
    if suffix_same {
        return governors[0].clone();
    }
    first
}

/*
 * Seed the per CPU group table and ready flag. Reads capacity, max frequency,
 * siblings, and LLC for live CPUs, then assigns with core split, LLC rules, and
 * hetero interleave. All singleton cores use halves and interleave exactly.
 * Ready stays cleared when the core view matches halves, else ready set. Strict
 * iff ready is zero, best effort iff ready is one. Single CPU keeps ready
 * cleared with all light. Short slices clamp with no pad. One core in one LLC
 * keeps LIGHT with no split. Each odd LLC gives the extra core to hog.
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
 * Sibling partner table and fallback count. Builds cores from sibling lists,
 * then maps each CPU to the next CPU in the same core in id order. Singletons
 * hold 0xffff, so the BPF free check is a no-op. Empty lists count as sysfs
 * fallbacks with singleton behavior and no trap. Capped at 1024 with no new
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
 * Parse one CPU list from sysfs. Accepts comma, range form such as 0-7, 0,2,4,
 * and 0-3,8-11. Trims space and newline. Bad tokens stay out with no trap. Ids
 * at or past the table bound stay out, so the cap holds with no extra use.
 * Sorted with no dup, so rank order stays stable.
 */
pub fn parse_cpu_list(s: &str) -> Vec<u32> {
    let mut out = crate::flow_group::parse_siblings_list(s);
    out.retain(|&id| (id as usize) < MAX_CPUS);
    out
}

/*
 * Read one CPU list file from sysfs. Missing files
 * yield empty with no trap. Values cap at the table
 * bound with no extra use. Sorted with no dup.
 */
pub fn read_cpu_list_file(path: &str) -> Vec<u32> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| parse_cpu_list(&s))
        .unwrap_or_default()
}

/*
 * Online CPUs once at init. Reads the online file a single time, so the group
 * table and snapshot share one rank order. Missing files fall back to topology
 * cards with no trap. Sorted with no dup and capped at the table bound. Empty
 * stays empty with no pad.
 */
pub fn online_cpus() -> Vec<u32> {
    let mut out = read_cpu_list_file("/sys/devices/system/cpu/online");
    if !out.is_empty() {
        return out;
    }
    let topo = match Topology::new() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    out = topo
        .all_cpus
        .keys()
        .map(|&id| id as u32)
        .filter(|&id| (id as usize) < MAX_CPUS)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/*
 * Possible CPUs from sysfs. Missing files fall back
 * to online with no trap. Sorted with no dup and
 * capped at the table bound. Empty stays empty.
 */
pub fn possible_cpus() -> Vec<u32> {
    let out = read_cpu_list_file("/sys/devices/system/cpu/possible");
    if !out.is_empty() {
        return out;
    }
    online_cpus()
}

/*
 * Possible CPU count for skew checks. Holds max id and one capped at the table
 * bound. Missing files fall back to online max and one with no trap. Empty
 * stays zero with no division.
 */
pub fn possible_nr() -> usize {
    let poss = possible_cpus();
    if let Some(&m) = poss.iter().max() {
        return (m as usize + 1)
            .min(MAX_CPUS)
            .min(crate::flow_group::GROUP_TABLE_LEN);
    }
    let on = online_cpus();
    if let Some(&m) = on.iter().max() {
        return (m as usize + 1)
            .min(MAX_CPUS)
            .min(crate::flow_group::GROUP_TABLE_LEN);
    }
    0
}

/*
 * Sibling lists by online rank. Each entry holds the
 * sibling ids of one online CPU in rank order. Missing
 * files yield singletons with no trap. Capped at 1024.
 * Empty entries count as sysfs fallbacks with singleton
 * behavior. Rank order matches the online ids order.
 */
pub fn sibling_lists_online(online: &[u32]) -> Vec<Vec<u32>> {
    let mut ids: Vec<u32> = online
        .iter()
        .copied()
        .filter(|&id| (id as usize) < MAX_CPUS)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        out.push(read_thread_siblings(id));
    }
    out
}

/*
 * LLC ids by online rank. Reads the host topology once.
 * Missing topology yields empty for one domain with no
 * pad. Missing CPUs read as zero with no trap. Values
 * seed per LLC split with no division. Rank order
 * matches the online ids order.
 */
pub fn llc_ids_online(online: &[u32]) -> Vec<u32> {
    let mut ids: Vec<u32> = online
        .iter()
        .copied()
        .filter(|&id| (id as usize) < MAX_CPUS)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let topo = match Topology::new() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let v = topo
            .all_cpus
            .get(&(id as usize))
            .map(|c| c.llc_id as u32)
            .unwrap_or(0);
        out.push(v);
    }
    out
}

/*
 * Seed the per CPU group table by online rank and write by id. Reads capacity,
 * max frequency, siblings, and LLC for online CPUs only, then assigns with core
 * split, LLC rules, and hetero interleave in rank order. Offline ids stay light
 * inert with no trap. Dense full keeps prior table and ready exactly. Skewed
 * forces ready one even when uniform, so SMT off holds 4 and 4 over online
 * only. Strict iff ready is zero, best effort iff ready is one. Single online
 * keeps ready cleared with all light.
 */
pub fn group_seed_online(
    online: &[u32],
    possible: usize,
) -> ([u8; crate::flow_group::GROUP_TABLE_LEN], u8) {
    let mut ids: Vec<u32> = online
        .iter()
        .copied()
        .filter(|&id| (id as usize) < MAX_CPUS)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() <= 1 {
        return (
            [crate::flow_group::GROUP_LIGHT; crate::flow_group::GROUP_TABLE_LEN],
            0,
        );
    }
    // Dense full reuses the prior path exactly, so prior state holds with no
    // drift and no extra branch.
    if !crate::flow_group::online_skewed(&ids, possible) {
        return group_seed(ids.len());
    }
    let mut caps = Vec::with_capacity(ids.len());
    let mut freqs = Vec::with_capacity(ids.len());
    for &id in &ids {
        caps.push(read_cpu_capacity(id));
        freqs.push(read_cpuinfo_max_freq(id));
    }
    let lists = sibling_lists_online(&ids);
    let llc = llc_ids_online(&ids);
    crate::flow_group::seed_groups_topology_online(&caps, &freqs, &ids, &lists, &llc, possible)
}

/*
 * Sibling partner table by online rank and fallback count. Builds online cores
 * from sibling lists, then maps each online CPU to the next online CPU in the
 * same core in id order. Singletons and offline hold 0xffff, so the BPF free
 * check is a no-op. Empty lists count as sysfs fallbacks with singleton
 * behavior and no trap. Dense full matches the prior table exactly.
 */
pub fn sibling_seed_online(online: &[u32]) -> ([u16; crate::flow_group::GROUP_TABLE_LEN], usize) {
    let mut ids: Vec<u32> = online
        .iter()
        .copied()
        .filter(|&id| (id as usize) < MAX_CPUS)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    // Dense reuses the prior path exactly, so prior state
    // holds with no drift. Sparse keeps write by id with
    // offline inert.
    if crate::flow_group::online_is_dense(&ids) {
        return sibling_seed(ids.len());
    }
    let lists = sibling_lists_online(&ids);
    let mut fallbacks = 0;
    for v in &lists {
        if v.is_empty() {
            fallbacks += 1;
        }
    }
    let cores = crate::flow_group::build_cores_online(&ids, &lists);
    let table = crate::flow_group::sibling_table_online(&cores, &ids);
    (table, fallbacks)
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
 * Filter cards to an allowed subset for tests. Keeps cards whose id is marked
 * in the mask. Models pinned cgroup subsets with no placement use. Frequency,
 * LLC, and CPU cards stay display only here.
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
 * Synthetic card for tests. Builds one display only card with the given id,
 * frequency, LLC, and thread role. Slice stays fixed at 1ms. Group stays
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
        active_ns: 0,
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

    #[test]
    fn cpu_list_parses_ranges_and_sparse() {
        assert_eq!(parse_cpu_list("0-7\n"), (0..8).collect::<Vec<u32>>());
        assert_eq!(parse_cpu_list("0,2,4"), vec![0, 2, 4]);
        assert_eq!(parse_cpu_list("0-3,8-11"), vec![0, 1, 2, 3, 8, 9, 10, 11]);
        assert_eq!(parse_cpu_list("0-1"), vec![0, 1]);
        assert!(parse_cpu_list("").is_empty());
        assert!(parse_cpu_list("abc").is_empty());
        assert_eq!(parse_cpu_list("  0-2  "), vec![0, 1, 2]);
        assert_eq!(parse_cpu_list("0-15"), (0..16).collect::<Vec<u32>>());
    }

    #[test]
    fn online_lists_keep_rank_order() {
        let online = vec![0, 2, 4, 6, 8, 10, 12, 14];
        assert!(!crate::flow_group::online_is_dense(&online));
        assert!(crate::flow_group::online_skewed(&online, 16));
        let dense: Vec<u32> = (0..8).collect();
        assert!(crate::flow_group::online_is_dense(&dense));
        assert!(crate::flow_group::online_skewed(&dense, 16));
        assert!(!crate::flow_group::online_skewed(&dense, 8));
    }

    /* Governor base strips the diagnostic suffix only. */
    #[test]
    fn governor_base_strips_suffix_only() {
        assert_eq!(governor_base("performance"), "performance");
        assert_eq!(
            governor_base("performance (epp:performance)"),
            "performance"
        );
        assert_eq!(
            governor_base("powersave (epp:performance pp:balanced)"),
            "powersave"
        );
        assert_eq!(governor_base("powersave"), "powersave");
        assert_eq!(governor_base("unknown"), "unknown");
        assert_eq!(governor_base("  performance  "), "performance");
        assert_eq!(governor_base(""), "");
    }

    /* Unanimous performance needs every base at perf. */
    #[test]
    fn perf_unanimous_needs_every_perf() {
        let all: Vec<String> = vec!["performance".into(), "performance".into()];
        assert!(perf_unanimous(&all));
        let suffixed: Vec<String> = vec![
            "performance (epp:performance)".into(),
            "performance (epp:powersave)".into(),
        ];
        assert!(perf_unanimous(&suffixed));
        let single: Vec<String> = vec!["performance".into()];
        assert!(perf_unanimous(&single));
    }

    /* Mixed, unknown, and empty stay strict. */
    #[test]
    fn perf_mixed_and_unknown_stay_strict() {
        let mixed: Vec<String> = vec!["performance".into(), "powersave".into()];
        assert!(!perf_unanimous(&mixed));
        let mixed_suffix: Vec<String> = vec![
            "performance (epp:performance)".into(),
            "powersave (epp:performance)".into(),
        ];
        assert!(!perf_unanimous(&mixed_suffix));
        let unknown: Vec<String> = vec!["unknown".into(), "performance".into()];
        assert!(!perf_unanimous(&unknown));
        let all_unknown: Vec<String> = vec!["unknown".into(), "unknown".into()];
        assert!(!perf_unanimous(&all_unknown));
        let empty: Vec<String> = Vec::new();
        assert!(!perf_unanimous(&empty));
        let powersave: Vec<String> = vec!["powersave".into(), "powersave".into()];
        assert!(!perf_unanimous(&powersave));
    }

    /* Display keeps suffix when unanimous else mixed. */
    #[test]
    fn display_governor_keeps_suffix_when_unanimous() {
        let empty: Vec<String> = Vec::new();
        assert_eq!(display_governor(&empty), "unknown");
        let perf: Vec<String> = vec![
            "performance (epp:performance)".into(),
            "performance (epp:performance)".into(),
        ];
        assert_eq!(display_governor(&perf), "performance (epp:performance)");
        let power: Vec<String> = vec!["powersave".into(), "powersave".into()];
        assert_eq!(display_governor(&power), "powersave");
        let mixed: Vec<String> = vec!["performance".into(), "powersave".into()];
        assert_eq!(display_governor(&mixed), "mixed");
        let unknown: Vec<String> = vec!["unknown".into(), "unknown".into()];
        assert_eq!(display_governor(&unknown), "unknown");
        let suffixed_mixed: Vec<String> = vec![
            "performance (epp:performance)".into(),
            "powersave (epp:performance)".into(),
        ];
        assert_eq!(display_governor(&suffixed_mixed), "mixed");
    }

    /* Provider runs once per collection over N CPUs. */
    #[test]
    fn collect_governors_reads_platform_once() {
        let cpus: Vec<u32> = (0..16).collect();
        let mut calls = 0;
        let got = collect_governors_with(&cpus, || {
            calls += 1;
            Some("balanced".to_string())
        });
        assert_eq!(calls, 1);
        assert_eq!(got.len(), 16);
    }

    /* Batched output matches per CPU reads exactly. */
    #[test]
    fn collect_governors_matches_per_cpu_reads() {
        let cpus: Vec<u32> = (0..8).collect();
        for platform in [
            None,
            Some("balanced".to_string()),
            Some("performance".to_string()),
        ] {
            let want: Vec<String> = cpus
                .iter()
                .map(|&id| read_governor_with_profile(id, platform.as_deref()))
                .collect();
            let got = collect_governors_with(&cpus, || platform.clone());
            assert_eq!(got, want);
        }
        let empty: Vec<u32> = Vec::new();
        let mut calls = 0;
        let got = collect_governors_with(&empty, || {
            calls += 1;
            None
        });
        assert!(got.is_empty());
        assert_eq!(calls, 1);
    }
}
