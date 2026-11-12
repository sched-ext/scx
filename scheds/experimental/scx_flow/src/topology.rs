// SPDX-License-Identifier: GPL-2.0
//! Topology seeding for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Seeds cluster hints for the BPF view. Cache and node identity
//! come from the upstream topology tree built by the arena library.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use anyhow::Context;
use anyhow::Result;
use scx_utils::Core;
use scx_utils::Topology;

use crate::BpfSkel;

/// Cores grouped per cluster. Fixed width keeps the seed stable.
/// Width four is a heuristic: real clusters of eight split in two,
/// which keeps locality without ever merging distant cores. The
/// topology view has no cluster id, so the seed sorts cores by id
/// within each LLC and splits every four for a stable map.
const GROUP_WIDTH: usize = 4;

/// True when any core holds more than one CPU.
pub fn smt_on(topo: &Topology) -> bool {
    topo.all_cores.values().any(|c| c.cpus.len() > 1)
}

/// Unknown cluster sentinel for a missing seed row. Matches
/// FLOW_CCX_UNKNOWN in the BPF select header with all ones, so group
/// zero stays a valid match and a miss never collides. Both ids must be
/// known for a match, so unknown falls through to fixed order fail closed.
pub const CCX_UNKNOWN: u32 = 0xFFFFFFFF;

/// Bucket ladder for one per CPU cache share in kibibytes.
/// Mirrors cache_bucket in the shared BPF header with identical thresholds
/// at 32 plus 48 plus 256 plus 512 plus 1024 plus 8192 plus 16384 plus
/// 32768 plus 98304 plus 524288. Zero means unknown with no size.
/// Larger numbers mean larger caches. The top value caps with no wrap.
/// All compares stay integer only with no float. Keep both sides in
/// sync when thresholds move.
pub fn cache_bucket(kb: u32) -> u8 {
    if kb == 0 {
        return 0;
    }
    if kb <= 32 {
        return 1;
    }
    if kb <= 48 {
        return 2;
    }
    if kb <= 256 {
        return 3;
    }
    if kb <= 512 {
        return 4;
    }
    if kb <= 1024 {
        return 5;
    }
    if kb <= 8192 {
        return 6;
    }
    if kb <= 16384 {
        return 7;
    }
    if kb <= 32768 {
        return 8;
    }
    if kb <= 98304 {
        return 9;
    }
    if kb <= 524288 {
        return 10;
    }
    255
}

/// Both known larger check mirroring flow_cache_larger in the BPF select
/// header. Unknown never wins, so fixed order covers it. Select and drain
/// add known priority around this gate, so an unknown best never blocks a
/// later known bucket within one tier.
pub fn cache_larger(a: u8, b: u8) -> bool {
    if a == 0 || b == 0 {
        return false;
    }
    a > b
}

/// Kibibytes for a byte share with round up. Zero bytes stay unknown with
/// no size. Any positive bytes map to at least one kibibyte, so a known
/// small share lands in bucket one instead of unknown.
pub fn kb_for_bytes(bytes: usize) -> u32 {
    if bytes == 0 {
        return 0;
    }
    ((bytes.saturating_add(1023)) >> 10).min(u32::MAX as usize) as u32
}

/// Seed row for one CPU in BPF byte order. Offsets match flow_cpu_ctx
/// with the bucket bytes at eight through eleven. The class byte stays
/// zero reserved for a future level split with no ABI change.
pub fn cpu_seed_bytes(cpu: u32, ccx: u32, l2: u8, l3: u8, cls: u8, rsv: u8) -> [u8; 16] {
    let mut val = [0u8; 16];
    val[0..4].copy_from_slice(&cpu.to_ne_bytes());
    val[4..8].copy_from_slice(&ccx.to_ne_bytes());
    val[8] = l2;
    val[9] = l3;
    val[10] = cls;
    val[11] = rsv;
    val
}

/// Known cluster for a core or none. Minus one and 65535 are unknown.
fn core_cluster(core: &Core) -> Option<isize> {
    if core.cluster_id != -1 && core.cluster_id != 65535 {
        return Some(core.cluster_id);
    }
    for cpu in core.cpus.values() {
        if cpu.cluster_id != -1 && cpu.cluster_id != 65535 {
            return Some(cpu.cluster_id);
        }
    }
    None
}

/// Group count with unknown fallback. Minus one and 65535 count as unknown.
fn describe_topo_groups(topo: &Topology) -> usize {
    let mut llc_ids: Vec<usize> = topo.all_llcs.keys().copied().collect();
    llc_ids.sort_unstable();
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    for v in cpu_ccx(topo, &llc_ids).values() {
        seen.insert(*v);
    }
    seen.len().max(1)
}

/// Shape summary for info logs.
pub fn describe_topo_summary(topo: &Topology) -> String {
    let mut packages: BTreeSet<usize> = BTreeSet::new();
    for cpu in topo.all_cpus.values() {
        packages.insert(cpu.package_id);
    }
    let groups: usize = describe_topo_groups(topo);
    format!(
        "{} cpus {} packages {} nodes {} llcs {} groups",
        topo.all_cpus.len(),
        packages.len(),
        topo.nodes.len(),
        topo.all_llcs.len(),
        groups
    )
}

/// Sched use brief for info logs. Names shape plus use action.
pub fn describe_sched_use(topo: &Topology) -> String {
    let groups: usize = describe_topo_groups(topo);
    let llcs: usize = topo.all_llcs.len();
    let nodes: usize = topo.nodes.len();
    let smt_text: &str = if smt_on(topo) { "on" } else { "off" };
    let group_text: &str = if groups == 1 { "group" } else { "groups" };
    let llc_text: &str = if llcs == 1 { "LLC" } else { "LLCs" };
    let node_text: &str = if nodes == 1 { "node" } else { "nodes" };
    format!(
        "Topology: SMT {}, {} {}, {} {}, {} {}. Place local first then drain group LLC node remote fallback idle only. Constrained L1>L2>L3.",
        smt_text, groups, group_text, llcs, llc_text, nodes, node_text
    )
}

/// Tree lines for debug logs. L is Topology id and P is kernel id.
pub fn render_topo_lines(topo: &Topology) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    out.push(String::from("Machine"));
    let groups: usize = describe_topo_groups(topo);
    let show_cluster: bool = groups > 1;
    let mut pkg_set: BTreeSet<usize> = BTreeSet::new();
    for cpu in topo.all_cpus.values() {
        pkg_set.insert(cpu.package_id);
    }
    let mut pkgs: Vec<usize> = pkg_set.into_iter().collect();
    pkgs.sort();
    let mut pkg_l: usize = 0;
    for pkg_p in pkgs {
        out.push(format!("  Package L{} P{}", pkg_l, pkg_p));
        pkg_l = pkg_l.wrapping_add(1);
        let mut node_ids: Vec<usize> = Vec::new();
        for (nid, node) in topo.nodes.iter() {
            let mut has: bool = false;
            for cpu in node.all_cpus.values() {
                if cpu.package_id == pkg_p {
                    has = true;
                    break;
                }
            }
            if has {
                node_ids.push(*nid);
            }
        }
        node_ids.sort();
        for nid in node_ids {
            let node = match topo.nodes.get(&nid) {
                Some(n) => n,
                None => continue,
            };
            out.push(format!("    Node L{} P{}", node.id, node.id));
            let mut llcs: Vec<usize> = Vec::new();
            for (lid, llc) in node.llcs.iter() {
                let mut has: bool = false;
                for cpu in llc.all_cpus.values() {
                    if cpu.package_id == pkg_p {
                        has = true;
                        break;
                    }
                }
                if has {
                    llcs.push(*lid);
                }
            }
            llcs.sort_by(|a, b| {
                let la = match node.llcs.get(a) {
                    Some(v) => v,
                    None => return std::cmp::Ordering::Equal,
                };
                let lb = match node.llcs.get(b) {
                    Some(v) => v,
                    None => return std::cmp::Ordering::Equal,
                };
                match la.kernel_id.cmp(&lb.kernel_id) {
                    std::cmp::Ordering::Equal => la.id.cmp(&lb.id),
                    other => other,
                }
            });
            for lid in llcs {
                let llc = match node.llcs.get(&lid) {
                    Some(v) => v,
                    None => continue,
                };
                out.push(format!("      L3 L{} P{}", llc.id, llc.kernel_id));
                let mut core_ids: Vec<usize> = Vec::new();
                for (cid, core) in llc.cores.iter() {
                    let mut has: bool = false;
                    for cpu in core.cpus.values() {
                        if cpu.package_id == pkg_p {
                            has = true;
                            break;
                        }
                    }
                    if has {
                        core_ids.push(*cid);
                    }
                }
                core_ids.sort_by(|a, b| {
                    let ca = match llc.cores.get(a) {
                        Some(v) => v,
                        None => return std::cmp::Ordering::Equal,
                    };
                    let cb = match llc.cores.get(b) {
                        Some(v) => v,
                        None => return std::cmp::Ordering::Equal,
                    };
                    match ca.kernel_id.cmp(&cb.kernel_id) {
                        std::cmp::Ordering::Equal => ca.id.cmp(&cb.id),
                        other => other,
                    }
                });
                for cid in core_ids {
                    let core = match llc.cores.get(&cid) {
                        Some(v) => v,
                        None => continue,
                    };
                    let cluster: Option<isize> = core_cluster(core);
                    let suffix: String = match cluster {
                        Some(c) if show_cluster => format!(" cluster C{c}"),
                        _ => String::new(),
                    };
                    out.push(format!(
                        "        Core+L2 L{} P{}{}",
                        core.id, core.kernel_id, suffix
                    ));
                    let mut pu_ids: Vec<usize> = core.cpus.keys().copied().collect();
                    pu_ids.sort();
                    for pu in pu_ids {
                        let cpu = match core.cpus.get(&pu) {
                            Some(v) => v,
                            None => continue,
                        };
                        out.push(format!("          PU L{} P{}", cpu.id, cpu.id));
                    }
                }
            }
        }
    }
    out
}

/// Index of a core position inside its LLC group.
fn chunk_index(pos: usize) -> usize {
    pos / GROUP_WIDTH
}

/// Map each CPU to a cluster id inside its LLC.
/// Known clusters map first in sorted order, else cores sort by id
/// within each LLC and split every four. Ids count up across LLCs
/// in LLC order. Splits stay safe and never merge distant cores.
fn cpu_ccx(topo: &Topology, llc_ids: &[usize]) -> BTreeMap<usize, u32> {
    let mut known: BTreeSet<isize> = BTreeSet::new();
    for core in topo.all_cores.values() {
        if let Some(c) = core_cluster(core) {
            known.insert(c);
        }
    }
    let mut slot: BTreeMap<isize, u32> = BTreeMap::new();
    let mut next: u32 = 0;
    for c in known {
        slot.insert(c, next);
        next = next.wrapping_add(1);
    }
    let mut core_ccx: BTreeMap<(usize, usize), u32> = BTreeMap::new();
    for (id, core) in topo.all_cores.iter() {
        let c = match core_cluster(core) {
            Some(v) => v,
            None => continue,
        };
        let idx = llc_ids.iter().position(|v| *v == core.llc_id).unwrap_or(0);
        if let Some(s) = slot.get(&c) {
            core_ccx.insert((idx, *id), *s);
        }
    }
    let mut unknown_per_llc: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for (id, core) in topo.all_cores.iter() {
        if core_cluster(core).is_some() {
            continue;
        }
        let idx = llc_ids.iter().position(|v| *v == core.llc_id).unwrap_or(0);
        unknown_per_llc.entry(idx).or_default().insert(*id);
    }
    let mut ordered: Vec<usize> = unknown_per_llc.keys().copied().collect();
    ordered.sort_unstable();
    for idx in ordered {
        let cores: Vec<usize> = unknown_per_llc
            .get(&idx)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        let mut sorted = cores;
        sorted.sort_unstable();
        let mut last_chunk: Option<usize> = None;
        for (pos, core) in sorted.into_iter().enumerate() {
            let chunk = chunk_index(pos);
            if last_chunk != Some(chunk) {
                if pos != 0 {
                    next = next.wrapping_add(1);
                }
                last_chunk = Some(chunk);
            }
            core_ccx.insert((idx, core), next);
        }
        next = next.wrapping_add(1);
    }
    let mut out: BTreeMap<usize, u32> = BTreeMap::new();
    for (id, cpu) in topo.all_cpus.iter() {
        let idx = llc_ids.iter().position(|v| *v == cpu.llc_id).unwrap_or(0);
        if let Some(ccx) = core_ccx.get(&(idx, cpu.core_id)) {
            out.insert(*id, *ccx);
        }
    }
    out
}

/// Seed one CPU row per online CPU into the BPF view.
/// Writes the CPU id plus the cluster hint plus three size buckets
/// from one aggregated per CPU share; cache and node come from the
/// upstream tree. The cluster stays here as an interim until it moves
/// into the tree data pointer. Level one stays grouping only with no
/// size use. True size rows use the list view when present with a
/// level split, else both level buckets share the single share openly
/// as a fallback with no ABI change.
/// Failures return an error.
pub fn seed_topology(skel: &mut BpfSkel<'_>, topo: &Topology) -> Result<String> {
    use libbpf_rs::MapCore;
    let mut llc_ids: Vec<usize> = topo.all_llcs.keys().copied().collect();
    llc_ids.sort_unstable();
    let mut node_ids: Vec<usize> = topo.nodes.keys().copied().collect();
    node_ids.sort_unstable();
    if llc_ids.len() > crate::bpf_intf::flow_consts_FLOW_MAX_LLCS as usize {
        anyhow::bail!("LLC count over bound");
    }
    if node_ids.len() > crate::bpf_intf::flow_consts_FLOW_MAX_NODES as usize {
        anyhow::bail!("node count over bound");
    }
    let ccx_map = cpu_ccx(topo, &llc_ids);
    let mut groups: BTreeSet<u32> = BTreeSet::new();
    for v in ccx_map.values() {
        groups.insert(*v);
    }
    let mut seeded = 0u32;
    let mut cpus: Vec<usize> = topo.all_cpus.keys().copied().collect();
    cpus.sort_unstable();
    for cpu in cpus {
        if cpu >= crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize {
            continue;
        }
        if !topo.all_cpus.contains_key(&cpu) {
            continue;
        }
        let ccx = ccx_map.get(&cpu).copied().unwrap_or(CCX_UNKNOWN);
        let bytes: usize = topo.all_cpus.get(&cpu).map(|c| c.cache_size).unwrap_or(0);
        let kb: u32 = kb_for_bytes(bytes);
        let bkt = cache_bucket(kb);
        let key = (cpu as u32).to_ne_bytes();
        let val = cpu_seed_bytes(cpu as u32, ccx, bkt, bkt, 0, 0);
        skel.maps
            .cpu_ctx_stor
            .update(&key, &val, libbpf_rs::MapFlags::ANY)
            .with_context(|| format!("cpu seed failed for cpu {cpu}"))?;
        seeded += 1;
    }
    Ok(format!(
        "{} cpus {} llcs {} nodes {} groups",
        seeded,
        llc_ids.len(),
        node_ids.len(),
        groups.len().max(1),
    ))
}

/// Format kibibytes with K plus M suffix only. Zero reads unknown
/// with no size. Values below one mebibyte read as K. Values at
/// or above one mebibyte with no remainder read as M. All math
/// stays integer only with no float. No byte form appears here.
pub fn format_kb(kb: u32) -> String {
    if kb == 0 {
        return String::from("unknown");
    }
    if kb >= 1024 && kb.wrapping_rem(1024) == 0 {
        return format!("{}M", kb.wrapping_div(1024));
    }
    format!("{kb}K")
}

/// Seed one CPU row per online CPU with true sizes from the list view.
/// Group tier reads the folded level one plus level two max.
/// LLC tier reads level three. Die stays size only with no cluster
/// feed through the hint helper. Missing rows read unknown with
/// no match. Skips ids at or above the CPU bound with no error.
/// Failures return an error.
pub fn seed_topology_lstopo(
    skel: &mut BpfSkel<'_>,
    topo: &Topology,
    view: &crate::lstopo::LstopoView,
) -> Result<String> {
    use libbpf_rs::MapCore;
    let mut llc_ids: Vec<usize> = topo.all_llcs.keys().copied().collect();
    llc_ids.sort_unstable();
    let mut node_ids: Vec<usize> = topo.nodes.keys().copied().collect();
    node_ids.sort_unstable();
    if llc_ids.len() > crate::bpf_intf::flow_consts_FLOW_MAX_LLCS as usize {
        anyhow::bail!("LLC count over bound");
    }
    if node_ids.len() > crate::bpf_intf::flow_consts_FLOW_MAX_NODES as usize {
        anyhow::bail!("node count over bound");
    }
    let ccx_map = cpu_ccx(topo, &llc_ids);
    let mut groups: BTreeSet<u32> = BTreeSet::new();
    for v in ccx_map.values() {
        groups.insert(*v);
    }
    let mut seeded = 0u32;
    let mut cpus: Vec<usize> = topo.all_cpus.keys().copied().collect();
    cpus.sort_unstable();
    for cpu in cpus {
        if cpu >= crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize {
            continue;
        }
        let cpu_ref = match topo.all_cpus.get(&cpu) {
            Some(v) => v,
            None => continue,
        };
        let ccx = ccx_map.get(&cpu).copied().unwrap_or(CCX_UNKNOWN);
        let (l2_bkt, l3_bkt) = match view.cpus.get(&(cpu_ref.id as u32)) {
            Some(row) => {
                let _ = crate::lstopo::die_ccx_hint(row.die_kb);
                let folded: u32 = crate::lstopo::l1_fold_kb(row.l1d_kb, row.l1i_kb, row.l2_kb);
                (cache_bucket(folded), cache_bucket(row.l3_kb))
            }
            None => {
                // Missing row stays unknown with no match.
                // Both buckets read zero so fixed order covers it.
                (0, 0)
            }
        };
        let key = (cpu as u32).to_ne_bytes();
        let val = cpu_seed_bytes(cpu as u32, ccx, l2_bkt, l3_bkt, 0, 0);
        skel.maps
            .cpu_ctx_stor
            .update(&key, &val, libbpf_rs::MapFlags::ANY)
            .with_context(|| format!("cpu seed failed for cpu {cpu}"))?;
        seeded += 1;
    }
    Ok(format!(
        "{} cpus {} llcs {} nodes {} groups",
        seeded,
        llc_ids.len(),
        node_ids.len(),
        groups.len().max(1),
    ))
}

/// Per core true size lines for info logs. Each line carries core id
/// plus cpu pair plus llc plus node plus group plus data plus
/// instruction plus level two plus level three shares. Units use K
/// plus M suffix with no byte form. Unknown reads unknown with no
/// size. Cores sort by id. Callers cap at sixty four with an overflow
/// count line. The tree stays at debug.
pub fn render_per_core_lines(
    topo: &Topology,
    view: Option<&crate::lstopo::LstopoView>,
) -> Vec<String> {
    let mut llc_ids: Vec<usize> = topo.all_llcs.keys().copied().collect();
    llc_ids.sort_unstable();
    let ccx_map = cpu_ccx(topo, &llc_ids);
    let mut core_ids: Vec<usize> = topo.all_cores.keys().copied().collect();
    core_ids.sort_unstable();
    let mut out: Vec<String> = Vec::with_capacity(core_ids.len());
    for cid in core_ids {
        let core = match topo.all_cores.get(&cid) {
            Some(v) => v,
            None => continue,
        };
        let mut pus: Vec<usize> = core.cpus.keys().copied().collect();
        pus.sort_unstable();
        let pair: String = pus
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<String>>()
            .join("+");
        let first_cpu: usize = pus.first().copied().unwrap_or(0);
        let group: u32 = ccx_map.get(&first_cpu).copied().unwrap_or(CCX_UNKNOWN);
        let group_text: String = if group == CCX_UNKNOWN {
            String::from("unknown")
        } else {
            group.to_string()
        };
        let llc: usize = core.llc_id;
        let node: usize = core.node_id;
        let (l1d, l1i, l2, l3): (String, String, String, String) = match view {
            Some(v) => {
                // Core shares come from the first PU row on the core.
                // All threads on one core share one cache view.
                let mut found: Option<(u32, u32, u32, u32)> = None;
                for pu in pus.iter() {
                    if let Some(cpu) = topo.all_cpus.get(pu)
                        && let Some(row) = v.cpus.get(&(cpu.id as u32))
                    {
                        found = Some((row.l1d_kb, row.l1i_kb, row.l2_kb, row.l3_kb));
                        break;
                    }
                }
                match found {
                    Some((a, b, c, d)) => (format_kb(a), format_kb(b), format_kb(c), format_kb(d)),
                    None => (
                        String::from("unknown"),
                        String::from("unknown"),
                        String::from("unknown"),
                        String::from("unknown"),
                    ),
                }
            }
            None => {
                // Fallback shows unknown with no size when the list
                // view is absent. The aggregated share stays in BPF.
                (
                    String::from("unknown"),
                    String::from("unknown"),
                    String::from("unknown"),
                    String::from("unknown"),
                )
            }
        };
        out.push(format!(
            "Core L{} P{} cpus {} LLC {} node {} group {} L1d {} L1i {} L2 {} L3 {}",
            core.id, core.kernel_id, pair, llc, node, group_text, l1d, l1i, l2, l3
        ));
    }
    out
}

/// Per core lines capped at a limit. Returns capped lines plus total.
/// Builds only capped lines so large hosts stay bounded. Total counts
/// all cores with no tail strings. Callers show capped lines plus
/// an overflow count line. Limit zero keeps empty plus total.
pub fn render_per_core_lines_capped(
    topo: &Topology,
    view: Option<&crate::lstopo::LstopoView>,
    limit: usize,
) -> (Vec<String>, usize) {
    let mut llc_ids: Vec<usize> = topo.all_llcs.keys().copied().collect();
    llc_ids.sort_unstable();
    let ccx_map = cpu_ccx(topo, &llc_ids);
    let mut core_ids: Vec<usize> = topo.all_cores.keys().copied().collect();
    core_ids.sort_unstable();
    let mut out: Vec<String> = Vec::with_capacity(limit.min(core_ids.len()));
    let mut total: usize = 0;
    for cid in core_ids {
        let core = match topo.all_cores.get(&cid) {
            Some(v) => v,
            None => continue,
        };
        total = total.wrapping_add(1);
        if out.len() >= limit {
            continue;
        }
        let mut pus: Vec<usize> = core.cpus.keys().copied().collect();
        pus.sort_unstable();
        let pair: String = pus
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<String>>()
            .join("+");
        let first_cpu: usize = pus.first().copied().unwrap_or(0);
        let group: u32 = ccx_map.get(&first_cpu).copied().unwrap_or(CCX_UNKNOWN);
        let group_text: String = if group == CCX_UNKNOWN {
            String::from("unknown")
        } else {
            group.to_string()
        };
        let llc: usize = core.llc_id;
        let node: usize = core.node_id;
        let (l1d, l1i, l2, l3): (String, String, String, String) = match view {
            Some(v) => {
                // Core shares come from the first PU row on the core.
                // All threads on one core share one cache view.
                let mut found: Option<(u32, u32, u32, u32)> = None;
                for pu in pus.iter() {
                    if let Some(cpu) = topo.all_cpus.get(pu)
                        && let Some(row) = v.cpus.get(&(cpu.id as u32))
                    {
                        found = Some((row.l1d_kb, row.l1i_kb, row.l2_kb, row.l3_kb));
                        break;
                    }
                }
                match found {
                    Some((a, b, c, d)) => (format_kb(a), format_kb(b), format_kb(c), format_kb(d)),
                    None => (
                        String::from("unknown"),
                        String::from("unknown"),
                        String::from("unknown"),
                        String::from("unknown"),
                    ),
                }
            }
            None => (
                String::from("unknown"),
                String::from("unknown"),
                String::from("unknown"),
                String::from("unknown"),
            ),
        };
        out.push(format!(
            "Core L{} P{} cpus {} LLC {} node {} group {} L1d {} L1i {} L2 {} L3 {}",
            core.id, core.kernel_id, pair, llc, node, group_text, l1d, l1i, l2, l3
        ));
    }
    (out, total)
}

/// Tree lines capped at a limit. Returns capped lines plus total.
/// Counts all lines with no tail strings. Large trees stay bounded.
/// Limit zero keeps empty plus total. L is Topology id.
/// P is kernel id.
pub fn render_topo_lines_capped(topo: &Topology, limit: usize) -> (Vec<String>, usize) {
    let mut out: Vec<String> = Vec::with_capacity(limit.min(1088));
    let mut total: usize = 0;
    let push_capped = |out: &mut Vec<String>, total: &mut usize, line: String| {
        *total = total.wrapping_add(1);
        if out.len() < limit {
            out.push(line);
        }
    };
    push_capped(&mut out, &mut total, String::from("Machine"));
    let groups: usize = describe_topo_groups(topo);
    let show_cluster: bool = groups > 1;
    let mut pkg_set: BTreeSet<usize> = BTreeSet::new();
    for cpu in topo.all_cpus.values() {
        pkg_set.insert(cpu.package_id);
    }
    let mut pkgs: Vec<usize> = pkg_set.into_iter().collect();
    pkgs.sort();
    let mut pkg_l: usize = 0;
    for pkg_p in pkgs {
        push_capped(&mut out, &mut total, format!("  Package L{pkg_l} P{pkg_p}"));
        pkg_l = pkg_l.wrapping_add(1);
        let mut node_ids: Vec<usize> = Vec::new();
        for (nid, node) in topo.nodes.iter() {
            let mut has: bool = false;
            for cpu in node.all_cpus.values() {
                if cpu.package_id == pkg_p {
                    has = true;
                    break;
                }
            }
            if has {
                node_ids.push(*nid);
            }
        }
        node_ids.sort();
        for nid in node_ids {
            let node = match topo.nodes.get(&nid) {
                Some(n) => n,
                None => continue,
            };
            push_capped(
                &mut out,
                &mut total,
                format!("    Node L{} P{}", node.id, node.id),
            );
            let mut llcs: Vec<usize> = Vec::new();
            for (lid, llc) in node.llcs.iter() {
                let mut has: bool = false;
                for cpu in llc.all_cpus.values() {
                    if cpu.package_id == pkg_p {
                        has = true;
                        break;
                    }
                }
                if has {
                    llcs.push(*lid);
                }
            }
            llcs.sort_by(|a, b| {
                let la = match node.llcs.get(a) {
                    Some(v) => v,
                    None => return std::cmp::Ordering::Equal,
                };
                let lb = match node.llcs.get(b) {
                    Some(v) => v,
                    None => return std::cmp::Ordering::Equal,
                };
                match la.kernel_id.cmp(&lb.kernel_id) {
                    std::cmp::Ordering::Equal => la.id.cmp(&lb.id),
                    other => other,
                }
            });
            for lid in llcs {
                let llc = match node.llcs.get(&lid) {
                    Some(v) => v,
                    None => continue,
                };
                push_capped(
                    &mut out,
                    &mut total,
                    format!("      L3 L{} P{}", llc.id, llc.kernel_id),
                );
                let mut core_ids: Vec<usize> = Vec::new();
                for (cid, core) in llc.cores.iter() {
                    let mut has: bool = false;
                    for cpu in core.cpus.values() {
                        if cpu.package_id == pkg_p {
                            has = true;
                            break;
                        }
                    }
                    if has {
                        core_ids.push(*cid);
                    }
                }
                core_ids.sort_by(|a, b| {
                    let ca = match llc.cores.get(a) {
                        Some(v) => v,
                        None => return std::cmp::Ordering::Equal,
                    };
                    let cb = match llc.cores.get(b) {
                        Some(v) => v,
                        None => return std::cmp::Ordering::Equal,
                    };
                    match ca.kernel_id.cmp(&cb.kernel_id) {
                        std::cmp::Ordering::Equal => ca.id.cmp(&cb.id),
                        other => other,
                    }
                });
                for cid in core_ids {
                    let core = match llc.cores.get(&cid) {
                        Some(v) => v,
                        None => continue,
                    };
                    let cluster: Option<isize> = core_cluster(core);
                    let suffix: String = match cluster {
                        Some(c) if show_cluster => format!(" cluster C{c}"),
                        _ => String::new(),
                    };
                    push_capped(
                        &mut out,
                        &mut total,
                        format!("        Core+L2 L{} P{}{}", core.id, core.kernel_id, suffix),
                    );
                    let mut pu_ids: Vec<usize> = core.cpus.keys().copied().collect();
                    pu_ids.sort();
                    for pu in pu_ids {
                        let cpu = match core.cpus.get(&pu) {
                            Some(v) => v,
                            None => continue,
                        };
                        push_capped(
                            &mut out,
                            &mut total,
                            format!("          PU L{} P{}", cpu.id, cpu.id),
                        );
                    }
                }
            }
        }
    }
    (out, total)
}

#[cfg(test)]
mod tests {
    use super::CCX_UNKNOWN;
    use super::cache_bucket;
    use super::cache_larger;
    use super::chunk_index;
    use super::cpu_ccx;
    use super::cpu_seed_bytes;
    use super::describe_sched_use;
    use super::describe_topo_groups;
    use super::describe_topo_summary;
    use super::kb_for_bytes;
    use super::render_per_core_lines_capped;
    use super::render_topo_lines;
    use super::render_topo_lines_capped;
    use super::smt_on;
    use scx_utils::Core;
    use scx_utils::CoreType;
    use scx_utils::Cpu;
    use scx_utils::Cpumask;
    use scx_utils::Llc;
    use scx_utils::Node;
    use scx_utils::Topology;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    #[test]
    fn buckets_ladder_unknown_first_cap_last() {
        assert_eq!(cache_bucket(0), 0);
        assert_eq!(cache_bucket(1), 1);
        assert_eq!(cache_bucket(32), 1);
        assert_eq!(cache_bucket(33), 2);
        assert_eq!(cache_bucket(48), 2);
        assert_eq!(cache_bucket(49), 3);
        assert_eq!(cache_bucket(256), 3);
        assert_eq!(cache_bucket(257), 4);
        assert_eq!(cache_bucket(512), 4);
        assert_eq!(cache_bucket(513), 5);
        assert_eq!(cache_bucket(1024), 5);
        assert_eq!(cache_bucket(1025), 6);
        assert_eq!(cache_bucket(8192), 6);
        assert_eq!(cache_bucket(8193), 7);
        assert_eq!(cache_bucket(16384), 7);
        assert_eq!(cache_bucket(16385), 8);
        assert_eq!(cache_bucket(32768), 8);
        assert_eq!(cache_bucket(32769), 9);
        assert_eq!(cache_bucket(98304), 9);
        assert_eq!(cache_bucket(98305), 10);
        assert_eq!(cache_bucket(524288), 10);
        assert_eq!(cache_bucket(524289), 255);
        assert_eq!(cache_bucket(u32::MAX), 255);
    }

    #[test]
    fn sub_kb_rounds_to_known_small() {
        assert_eq!(kb_for_bytes(0), 0);
        assert_eq!(cache_bucket(kb_for_bytes(0)), 0);
        assert_eq!(kb_for_bytes(1), 1);
        assert_eq!(kb_for_bytes(512), 1);
        assert_eq!(kb_for_bytes(1023), 1);
        assert_eq!(kb_for_bytes(1024), 1);
        assert_eq!(cache_bucket(kb_for_bytes(1)), 1);
        assert_eq!(cache_bucket(kb_for_bytes(1023)), 1);
        assert_eq!(kb_for_bytes(1025), 2);
        assert_eq!(cache_bucket(kb_for_bytes(3 << 20)), 6);
    }

    #[test]
    fn unknown_sentinel_never_collides() {
        assert_eq!(CCX_UNKNOWN, 0xFFFFFFFFu32);
        assert_eq!(CCX_UNKNOWN, u32::MAX);
        let val = cpu_seed_bytes(5, CCX_UNKNOWN, 1, 1, 0, 0);
        assert_eq!(
            u32::from_ne_bytes([val[4], val[5], val[6], val[7]]),
            0xFFFFFFFFu32
        );
        assert_ne!(u32::from_ne_bytes([val[4], val[5], val[6], val[7]]), 0u32);
    }

    #[test]
    fn larger_needs_both_known_with_tie_priority() {
        assert!(!cache_larger(0, 0));
        assert!(!cache_larger(0, 1));
        assert!(!cache_larger(1, 0));
        assert!(!cache_larger(2, 2));
        assert!(cache_larger(2, 1));
        assert!(cache_larger(255, 4));
        assert!(!cache_larger(1, 2));
        // Tie equivalent: a known bucket replaces an unknown best,
        // larger replaces smaller, equal keeps fixed order.
        let mut best: u8 = 0;
        let mut have: bool = false;
        for cur in [0u8, 1, 2] {
            if cur != 0 && (!have || cache_larger(cur, best)) {
                best = cur;
                have = true;
            }
        }
        assert!(have);
        assert_eq!(best, 2);
        // Unknown first never blocks a later known of any size.
        let mut best2: u8 = 0;
        let mut have2: bool = false;
        for cur in [0u8, 1] {
            if cur != 0 && (!have2 || cache_larger(cur, best2)) {
                best2 = cur;
                have2 = true;
            }
        }
        assert!(have2);
        assert_eq!(best2, 1);
    }

    #[test]
    fn finer_ladder_separates_live_vs_asym() {
        // Live host shares versus reference asymmetric shares map to
        // distinct buckets so bigger orders first within tier.
        // L1d 32 versus 48, L2 512 versus 1024, L3 16M versus 32M versus 96M.
        assert!(cache_larger(cache_bucket(48), cache_bucket(32)));
        assert!(cache_larger(cache_bucket(1024), cache_bucket(512)));
        assert!(cache_larger(cache_bucket(32768), cache_bucket(16384)));
        assert!(cache_larger(cache_bucket(98304), cache_bucket(32768)));
        assert!(cache_larger(cache_bucket(98304), cache_bucket(16384)));
        // Monotone order holds across the full ladder.
        let ladder: [u32; 11] = [0, 32, 48, 256, 512, 1024, 8192, 16384, 32768, 98304, 524288];
        let mut prev: u8 = 0;
        for (i, kb) in ladder.iter().enumerate() {
            let bkt = cache_bucket(*kb);
            if i == 0 {
                assert_eq!(bkt, 0);
            } else {
                assert!(bkt > prev);
            }
            prev = bkt;
        }
        assert_eq!(cache_bucket(u32::MAX), 255);
        // u8 compares stay integer only with no float.
        assert!(cache_larger(10, 9));
        assert!(!cache_larger(9, 10));
        assert!(!cache_larger(0, 10));
    }

    #[test]
    fn split_buckets_keep_tier_order() {
        // Synthetic split: group tier uses l2 and LLC tier uses l3.
        let val = cpu_seed_bytes(9, 2, 4, 1, 0, 0);
        assert_eq!(val[8], 4);
        assert_eq!(val[9], 1);
        assert!(cache_larger(4, 3));
        assert!(cache_larger(val[8], 3));
        assert!(!cache_larger(val[9], 4));
        let group_pick = val[8];
        let llc_pick = val[9];
        assert_ne!(group_pick, llc_pick);
    }

    #[test]
    fn seed_bytes_round_trip() {
        let val = cpu_seed_bytes(7, 3, 2, 4, 0, 0);
        assert_eq!(val.len(), 16);
        assert_eq!(u32::from_ne_bytes([val[0], val[1], val[2], val[3]]), 7);
        assert_eq!(u32::from_ne_bytes([val[4], val[5], val[6], val[7]]), 3);
        assert_eq!(val[8], 2);
        assert_eq!(val[9], 4);
        assert_eq!(val[10], 0);
        assert_eq!(val[11], 0);
        assert_eq!(&val[12..16], &[0, 0, 0, 0]);
        let kb: u32 = (3usize << 20 >> 10).min(u32::MAX as usize) as u32;
        assert_eq!(cache_bucket(kb), 6);
        assert_eq!(
            cpu_seed_bytes(0, 0, cache_bucket(0), cache_bucket(0), 0, 0)[8],
            0
        );
    }

    #[test]
    fn chunks_split_every_four() {
        assert_eq!(chunk_index(0), 0);
        assert_eq!(chunk_index(3), 0);
        assert_eq!(chunk_index(4), 1);
        assert_eq!(chunk_index(7), 1);
        assert_eq!(chunk_index(8), 2);
    }

    fn mk_cpu(
        id: usize,
        core_id: usize,
        llc_id: usize,
        node_id: usize,
        package_id: usize,
        cluster_id: isize,
    ) -> Arc<Cpu> {
        Arc::new(Cpu {
            id,
            min_freq: 0,
            max_freq: 0,
            base_freq: 0,
            cpu_capacity: 1024,
            kernel_cpu_capacity: None,
            smt_level: 0,
            pm_qos_resume_latency_us: 0,
            trans_lat_ns: 0,
            l2_id: core_id,
            l3_id: llc_id,
            cache_size: 0,
            core_type: CoreType::Big { turbo: false },
            core_id,
            llc_id,
            node_id,
            package_id,
            cluster_id,
        })
    }

    fn mk_core(
        id: usize,
        kernel_id: usize,
        cluster_id: isize,
        cpus: BTreeMap<usize, Arc<Cpu>>,
        llc_id: usize,
        node_id: usize,
    ) -> Arc<Core> {
        Arc::new(Core {
            id,
            kernel_id,
            cluster_id,
            cpus,
            span: Cpumask::new(),
            core_type: CoreType::Big { turbo: false },
            llc_id,
            node_id,
        })
    }

    fn mk_llc(
        id: usize,
        kernel_id: usize,
        cores: BTreeMap<usize, Arc<Core>>,
        node_id: usize,
    ) -> Arc<Llc> {
        let mut all_cpus: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        for core in cores.values() {
            for (cid, cpu) in core.cpus.iter() {
                all_cpus.insert(*cid, cpu.clone());
            }
        }
        Arc::new(Llc {
            id,
            kernel_id,
            cores,
            span: Cpumask::new(),
            node_id,
            all_cpus,
        })
    }

    fn mk_node(id: usize, llcs: BTreeMap<usize, Arc<Llc>>) -> Node {
        let mut all_cores: BTreeMap<usize, Arc<Core>> = BTreeMap::new();
        let mut all_cpus: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        for llc in llcs.values() {
            for (cid, core) in llc.cores.iter() {
                all_cores.insert(*cid, core.clone());
                for (cpuid, cpu) in core.cpus.iter() {
                    all_cpus.insert(*cpuid, cpu.clone());
                }
            }
        }
        Node {
            id,
            distance: vec![10, 10],
            llcs,
            span: Cpumask::new(),
            all_cores,
            all_cpus,
        }
    }

    fn mk_topo(nodes: BTreeMap<usize, Node>) -> Topology {
        let mut all_llcs: BTreeMap<usize, Arc<Llc>> = BTreeMap::new();
        let mut all_cores: BTreeMap<usize, Arc<Core>> = BTreeMap::new();
        let mut all_cpus: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        for node in nodes.values() {
            for (lid, llc) in node.llcs.iter() {
                all_llcs.insert(*lid, llc.clone());
                for (cid, core) in llc.cores.iter() {
                    all_cores.insert(*cid, core.clone());
                    for (cpuid, cpu) in core.cpus.iter() {
                        all_cpus.insert(*cpuid, cpu.clone());
                    }
                }
            }
        }
        let mut smt = false;
        for core in all_cores.values() {
            if core.cpus.len() > 1 {
                smt = true;
                break;
            }
        }
        let mut topo = Topology::new().unwrap();
        topo.nodes = nodes;
        topo.span = Cpumask::new();
        topo.smt_enabled = smt;
        topo.all_llcs = all_llcs;
        topo.all_cores = all_cores;
        topo.all_cpus = all_cpus;
        topo
    }

    fn single_host_topo() -> Topology {
        let mut c0: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        c0.insert(0, mk_cpu(0, 0, 0, 0, 0, 0));
        c0.insert(1, mk_cpu(1, 0, 0, 0, 0, 0));
        let mut c1: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        c1.insert(2, mk_cpu(2, 1, 0, 0, 0, 1));
        c1.insert(3, mk_cpu(3, 1, 0, 0, 0, 1));
        let mut cores: BTreeMap<usize, Arc<Core>> = BTreeMap::new();
        cores.insert(0, mk_core(0, 0, 0, c0, 0, 0));
        cores.insert(1, mk_core(1, 1, 1, c1, 0, 0));
        let mut llcs: BTreeMap<usize, Arc<Llc>> = BTreeMap::new();
        llcs.insert(0, mk_llc(0, 0, cores, 0));
        let mut nodes: BTreeMap<usize, Node> = BTreeMap::new();
        nodes.insert(0, mk_node(0, llcs));
        mk_topo(nodes)
    }

    fn multi_package_topo() -> Topology {
        let mut a0: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        a0.insert(0, mk_cpu(0, 0, 0, 0, 2, -1));
        let mut a1: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        a1.insert(1, mk_cpu(1, 1, 0, 0, 2, -1));
        let mut acores: BTreeMap<usize, Arc<Core>> = BTreeMap::new();
        acores.insert(0, mk_core(0, 0, -1, a0, 0, 0));
        acores.insert(1, mk_core(1, 1, -1, a1, 0, 0));
        let mut allcs: BTreeMap<usize, Arc<Llc>> = BTreeMap::new();
        allcs.insert(0, mk_llc(0, 0, acores, 0));
        let mut b0: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        b0.insert(2, mk_cpu(2, 2, 1, 1, 5, -1));
        let mut b1: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        b1.insert(3, mk_cpu(3, 3, 1, 1, 5, -1));
        let mut bcores: BTreeMap<usize, Arc<Core>> = BTreeMap::new();
        bcores.insert(2, mk_core(2, 2, -1, b0, 1, 1));
        bcores.insert(3, mk_core(3, 3, -1, b1, 1, 1));
        let mut blcs: BTreeMap<usize, Arc<Llc>> = BTreeMap::new();
        blcs.insert(1, mk_llc(1, 1, bcores, 1));
        let mut nodes: BTreeMap<usize, Node> = BTreeMap::new();
        nodes.insert(0, mk_node(0, allcs));
        nodes.insert(1, mk_node(1, blcs));
        mk_topo(nodes)
    }

    fn large_topo() -> Topology {
        let mut cores: BTreeMap<usize, Arc<Core>> = BTreeMap::new();
        let mut cid: usize = 0;
        let mut pu: usize = 0;
        while cid < 542 {
            let mut one: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
            one.insert(pu, mk_cpu(pu, cid, 0, 0, 0, -1));
            cores.insert(cid, mk_core(cid, cid, -1, one, 0, 0));
            cid = cid.wrapping_add(1);
            pu = pu.wrapping_add(1);
        }
        let mut llcs: BTreeMap<usize, Arc<Llc>> = BTreeMap::new();
        llcs.insert(0, mk_llc(0, 0, cores, 0));
        let mut nodes: BTreeMap<usize, Node> = BTreeMap::new();
        nodes.insert(0, mk_node(0, llcs));
        mk_topo(nodes)
    }

    fn two_core_topo(first: isize, second: isize) -> Topology {
        let mut c0: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        c0.insert(0, mk_cpu(0, 0, 0, 0, 0, first));
        let mut c1: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        c1.insert(1, mk_cpu(1, 1, 0, 0, 0, second));
        let mut cores: BTreeMap<usize, Arc<Core>> = BTreeMap::new();
        cores.insert(0, mk_core(0, 0, first, c0, 0, 0));
        cores.insert(1, mk_core(1, 1, second, c1, 0, 0));
        let mut llcs: BTreeMap<usize, Arc<Llc>> = BTreeMap::new();
        llcs.insert(0, mk_llc(0, 0, cores, 0));
        let mut nodes: BTreeMap<usize, Node> = BTreeMap::new();
        nodes.insert(0, mk_node(0, llcs));
        mk_topo(nodes)
    }

    fn seeded_groups(topo: &Topology) -> usize {
        let mut llc_ids: Vec<usize> = topo.all_llcs.keys().copied().collect();
        llc_ids.sort_unstable();
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        for v in cpu_ccx(topo, &llc_ids).values() {
            seen.insert(*v);
        }
        seen.len().max(1)
    }

    #[test]
    fn single_host_tree_shape() {
        let topo = single_host_topo();
        assert!(smt_on(&topo));
        let lines = render_topo_lines(&topo);
        assert_eq!(lines.len(), 10);
        assert_eq!(lines[0], String::from("Machine"));
        assert_eq!(lines[1], String::from("  Package L0 P0"));
        assert_eq!(lines[2], String::from("    Node L0 P0"));
        assert_eq!(lines[3], String::from("      L3 L0 P0"));
        assert_eq!(lines[4], String::from("        Core+L2 L0 P0 cluster C0"));
        assert_eq!(lines[5], String::from("          PU L0 P0"));
        assert_eq!(lines[6], String::from("          PU L1 P1"));
        assert_eq!(lines[7], String::from("        Core+L2 L1 P1 cluster C1"));
        assert_eq!(lines[8], String::from("          PU L2 P2"));
        assert_eq!(lines[9], String::from("          PU L3 P3"));
        let summary = describe_topo_summary(&topo);
        assert_eq!(
            summary,
            String::from("4 cpus 1 packages 1 nodes 1 llcs 2 groups")
        );
        let brief = describe_sched_use(&topo);
        assert_eq!(
            brief,
            String::from(
                "Topology: SMT on, 2 groups, 1 LLC, 1 node. Place local first then drain group LLC node remote fallback idle only. Constrained L1>L2>L3."
            )
        );
        assert!(brief.len() <= 160);
    }

    #[test]
    fn multi_package_tree_shape() {
        let topo = multi_package_topo();
        assert!(!smt_on(&topo));
        let lines = render_topo_lines(&topo);
        assert_eq!(lines.len(), 15);
        assert_eq!(lines[0], String::from("Machine"));
        assert_eq!(lines[1], String::from("  Package L0 P2"));
        assert_eq!(lines[2], String::from("    Node L0 P0"));
        assert_eq!(lines[3], String::from("      L3 L0 P0"));
        assert_eq!(lines[4], String::from("        Core+L2 L0 P0"));
        assert_eq!(lines[5], String::from("          PU L0 P0"));
        assert_eq!(lines[6], String::from("        Core+L2 L1 P1"));
        assert_eq!(lines[7], String::from("          PU L1 P1"));
        assert_eq!(lines[8], String::from("  Package L1 P5"));
        assert_eq!(lines[9], String::from("    Node L1 P1"));
        assert_eq!(lines[10], String::from("      L3 L1 P1"));
        assert_eq!(lines[11], String::from("        Core+L2 L2 P2"));
        assert_eq!(lines[12], String::from("          PU L2 P2"));
        assert_eq!(lines[13], String::from("        Core+L2 L3 P3"));
        assert_eq!(lines[14], String::from("          PU L3 P3"));
        let summary = describe_topo_summary(&topo);
        assert_eq!(
            summary,
            String::from("4 cpus 2 packages 2 nodes 2 llcs 2 groups")
        );
        let brief = describe_sched_use(&topo);
        assert!(brief.len() <= 160);
        assert!(brief.contains("SMT off"));
        assert!(
            brief.contains("2 LLCs") || brief.contains("2 groups") || brief.contains("2 nodes")
        );
    }

    #[test]
    fn truncation_counts_hidden() {
        let topo = large_topo();
        let lines = render_topo_lines(&topo);
        assert!(lines.len() > 64);
        let total = lines.len();
        assert_eq!(total, 1088);
        let hidden = total.wrapping_sub(64);
        assert_eq!(hidden, 1024);
        let marker = format!("...+{} more", hidden);
        assert_eq!(marker, String::from("...+1024 more"));
        let first: Vec<String> = lines.into_iter().take(64).collect();
        assert_eq!(first.len(), 64);
        assert_eq!(first[0], String::from("Machine"));
    }

    #[test]
    fn brief_vocab_and_len() {
        let topo = single_host_topo();
        let brief = describe_sched_use(&topo);
        assert!(brief.len() <= 160);
        assert!(brief.contains("SMT on"));
        assert!(brief.contains("groups"));
        assert!(brief.contains("LLC"));
        assert!(brief.contains("node"));
        assert!(brief.contains("Place"));
        assert!(brief.contains("local"));
        assert!(brief.contains("first"));
        assert!(brief.contains("drain"));
        assert!(brief.contains("group"));
        assert!(brief.contains("remote"));
        assert!(brief.contains("fallback"));
        assert!(brief.contains("idle"));
        assert!(brief.contains("only"));
        assert!(brief.contains("Constrained"));
        assert!(brief.contains("L1>L2>L3"));
        assert!(!brief.contains("gpu"));
        assert!(!brief.contains("cgroup"));
        assert!(!brief.contains("RED"));
        assert!(!brief.contains("mate"));
        assert!(!brief.contains("strand"));
        assert!(!brief.contains("warm"));
        assert!(!brief.contains("edf"));
        assert!(!brief.contains("lat"));
        assert!(!brief.contains("slack"));
        assert!(!brief.contains("band"));
        assert!(!brief.contains("reclaim"));
        assert!(!brief.contains("slow"));
        assert!(!brief.contains("ewma"));
        assert!(!brief.contains("dhq"));
        assert!(!brief.contains("lst"));
        assert!(!brief.contains("float"));
        assert!(!brief.contains("version"));
        assert!(!brief.contains("Vd"));
        let off = multi_package_topo();
        let off_brief = describe_sched_use(&off);
        assert!(off_brief.len() <= 160);
        assert!(off_brief.contains("SMT off"));
    }

    #[test]
    fn seed_groups_match_describe_with_known_clusters() {
        let topo = single_host_topo();
        assert_eq!(describe_topo_groups(&topo), 2);
        assert_eq!(seeded_groups(&topo), 2);
        let mixed = two_core_topo(7, -1);
        assert_eq!(describe_topo_groups(&mixed), 2);
        assert_eq!(seeded_groups(&mixed), 2);
        let lines = render_topo_lines(&mixed);
        assert_eq!(lines[4], String::from("        Core+L2 L0 P0 cluster C7"));
        assert_eq!(lines[6], String::from("        Core+L2 L1 P1"));
        let unknown = multi_package_topo();
        assert_eq!(describe_topo_groups(&unknown), 2);
        assert_eq!(seeded_groups(&unknown), 2);
    }

    #[test]
    fn unknown_sentinels_share_fallback_count() {
        for sentinel in [-1isize, 65535] {
            let topo = two_core_topo(sentinel, sentinel);
            assert_eq!(describe_topo_groups(&topo), 1);
            assert_eq!(seeded_groups(&topo), 1);
            for line in render_topo_lines(&topo) {
                assert!(!line.contains("cluster"));
            }
        }
    }

    #[test]
    fn format_kb_uses_k_plus_m_only() {
        use super::format_kb;
        assert_eq!(format_kb(0), String::from("unknown"));
        assert_eq!(format_kb(32), String::from("32K"));
        assert_eq!(format_kb(48), String::from("48K"));
        assert_eq!(format_kb(512), String::from("512K"));
        assert_eq!(format_kb(1024), String::from("1M"));
        assert_eq!(format_kb(16384), String::from("16M"));
        assert_eq!(format_kb(32768), String::from("32M"));
        assert_eq!(format_kb(98304), String::from("96M"));
        // No byte form appears on any line.
        for v in [32u32, 512, 1024, 16384, 98304] {
            let s = format_kb(v);
            assert!(!s.contains('B'));
        }
    }

    #[test]
    fn per_core_lines_carry_true_sizes() {
        use super::format_kb;
        use super::render_per_core_lines;
        use crate::lstopo::LstopoCpu;
        use crate::lstopo::LstopoView;
        let topo = single_host_topo();
        let mut view = LstopoView::default();
        for pu in [0u32, 1, 2, 3] {
            view.cpus.insert(
                pu,
                LstopoCpu {
                    pu_l: Some(pu),
                    pu_p: pu,
                    core_l: Some(pu / 2),
                    l1d_kb: 32,
                    l1i_kb: 32,
                    l2_kb: 512,
                    l3_kb: 16384,
                    die_kb: 0,
                },
            );
        }
        let lines = render_per_core_lines(&topo, Some(&view));
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("Core L0"));
        assert!(lines[0].contains("cpus 0+1"));
        assert!(lines[0].contains("LLC 0"));
        assert!(lines[0].contains("node 0"));
        assert!(lines[0].contains("L1d 32K"));
        assert!(lines[0].contains("L1i 32K"));
        assert!(lines[0].contains("L2 512K"));
        assert!(lines[0].contains("L3 16M"));
        assert_eq!(format_kb(48), String::from("48K"));
        // Missing rows read unknown with no match.
        let empty = LstopoView::default();
        let missing = render_per_core_lines(&topo, Some(&empty));
        assert!(missing[0].contains("unknown"));
        // Fallback with no view reads unknown as well.
        let fallback = render_per_core_lines(&topo, None);
        assert!(fallback[0].contains("unknown"));
    }

    #[test]
    fn per_core_cap_counts_hidden() {
        use super::render_per_core_lines;
        let topo = large_topo();
        let lines = render_per_core_lines(&topo, None);
        assert_eq!(lines.len(), 542);
        let total = lines.len();
        assert!(total > 64);
        let hidden = total.wrapping_sub(64);
        assert_eq!(hidden, 478);
        let marker = format!("...+{} more", hidden);
        assert_eq!(marker, String::from("...+478 more"));
        let first: Vec<String> = lines.into_iter().take(64).collect();
        assert_eq!(first.len(), 64);
        assert!(first[0].contains("Core"));
    }

    #[test]
    fn pu_p_maps_to_kernel_id() {
        use crate::lstopo::l1_fold_kb;
        use crate::lstopo::parse_lstopo_text;
        // PU P number equals Cpu id. Core plus LLC plus Node
        // resolve via membership with Node membership explicit.
        // L counts up from zero versus P keeps kernel id.
        let text = "Machine (47GB total)\n  Package L#0\n    NUMANode L#0 (P#0 47GB)\n    Die L#0 + L3 L#0 (96MB)\n      L2 L#0 (1024KB) + L1d L#0 (48KB) + L1i L#0 (32KB) + Core L#0\n        PU L#0 (P#0)\n        PU L#1 (P#16)\n";
        let view = parse_lstopo_text(text).unwrap();
        // L maps logical order while P keeps kernel ids.
        assert!(view.cpus.contains_key(&0));
        assert!(view.cpus.contains_key(&16));
        let r0 = view.cpus.get(&0).unwrap();
        assert_eq!(r0.pu_l, Some(0));
        assert_eq!(r0.pu_p, 0);
        let r16 = view.cpus.get(&16).unwrap();
        assert_eq!(r16.pu_l, Some(1));
        assert_eq!(r16.pu_p, 16);
        // Fold uses max with no sum so inclusion never double counts.
        assert_eq!(l1_fold_kb(r0.l1d_kb, r0.l1i_kb, r0.l2_kb), 1024);
        // Die stays size only with no cluster feed.
        assert_eq!(r0.die_kb, 98304);
        assert_eq!(crate::lstopo::die_ccx_hint(r0.die_kb), None);
    }

    #[test]
    fn brief_has_no_leverage_word() {
        // Brief uses plain words with no buzzwords.
        // Names shape plus use action stays short.
        let topo = single_host_topo();
        let brief = describe_sched_use(&topo);
        assert!(!brief.contains("leverage"));
        assert!(brief.contains("Topology:"));
        assert!(brief.contains("SMT on"));
        assert!(brief.len() <= 160);
        let off = multi_package_topo();
        let off_brief = describe_sched_use(&off);
        assert!(!off_brief.contains("leverage"));
        assert!(off_brief.len() <= 160);
    }

    #[test]
    fn per_core_capped_matches_full_prefix() {
        // Capped build matches the full prefix with no tail strings.
        // Large hosts stay bounded at sixty four lines.
        use super::render_per_core_lines;
        let topo = large_topo();
        let full = render_per_core_lines(&topo, None);
        assert_eq!(full.len(), 542);
        let (capped, total) = render_per_core_lines_capped(&topo, None, 64);
        assert_eq!(total, 542);
        assert_eq!(capped.len(), 64);
        assert_eq!(capped, full.into_iter().take(64).collect::<Vec<String>>());
        assert_eq!(total.wrapping_sub(64), 478);
    }

    #[test]
    fn per_core_capped_total_counts_all() {
        // Total counts all cores with no tail strings.
        // Hidden count is total minus sixty four.
        let topo = large_topo();
        let (capped, total) = render_per_core_lines_capped(&topo, None, 64);
        assert_eq!(total, 542);
        assert_eq!(capped.len(), 64);
        let marker = format!("...+{} more", total.wrapping_sub(64));
        assert_eq!(marker, String::from("...+478 more"));
    }

    #[test]
    fn per_core_capped_limit_zero_keeps_empty_plus_total() {
        // Limit zero keeps empty plus total.
        // No strings are built on this path.
        let topo = large_topo();
        let (capped, total) = render_per_core_lines_capped(&topo, None, 0);
        assert!(capped.is_empty());
        assert_eq!(total, 542);
        let single = single_host_topo();
        let (empty, single_total) = render_per_core_lines_capped(&single, None, 0);
        assert!(empty.is_empty());
        assert_eq!(single_total, 2);
    }

    #[test]
    fn per_core_capped_limit_beyond_total_keeps_all() {
        // Large limit keeps all lines with no overflow.
        // Total equals capped length on this path.
        let topo = large_topo();
        let (capped, total) = render_per_core_lines_capped(&topo, None, 1000);
        assert_eq!(total, 542);
        assert_eq!(capped.len(), 542);
        let single = single_host_topo();
        let (all, single_total) = render_per_core_lines_capped(&single, None, 64);
        assert_eq!(single_total, 2);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn per_core_capped_small_host_no_overflow() {
        // Small hosts keep all lines with no marker.
        // First line still carries core plus sizes.
        use super::render_per_core_lines;
        use crate::lstopo::LstopoCpu;
        use crate::lstopo::LstopoView;
        let topo = single_host_topo();
        let mut view = LstopoView::default();
        for pu in [0u32, 1, 2, 3] {
            view.cpus.insert(
                pu,
                LstopoCpu {
                    pu_l: Some(pu),
                    pu_p: pu,
                    core_l: Some(pu / 2),
                    l1d_kb: 32,
                    l1i_kb: 32,
                    l2_kb: 512,
                    l3_kb: 16384,
                    die_kb: 0,
                },
            );
        }
        let full = render_per_core_lines(&topo, Some(&view));
        let (capped, total) = render_per_core_lines_capped(&topo, Some(&view), 64);
        assert_eq!(total, 2);
        assert_eq!(capped, full);
        assert!(capped[0].contains("L1d 32K"));
    }

    #[test]
    fn per_core_capped_limit_one_keeps_first() {
        // Limit one keeps the first core only.
        // Total still counts all cores.
        let topo = large_topo();
        let (capped, total) = render_per_core_lines_capped(&topo, None, 1);
        assert_eq!(capped.len(), 1);
        assert_eq!(total, 542);
        assert!(capped[0].contains("Core"));
    }

    #[test]
    fn topo_capped_matches_full_prefix() {
        // Capped tree matches the full prefix.
        // Large trees stay bounded at sixty four lines.
        let topo = large_topo();
        let full = render_topo_lines(&topo);
        assert_eq!(full.len(), 1088);
        let (capped, total) = render_topo_lines_capped(&topo, 64);
        assert_eq!(total, 1088);
        assert_eq!(capped.len(), 64);
        assert_eq!(capped, full.into_iter().take(64).collect::<Vec<String>>());
    }

    #[test]
    fn topo_capped_total_is_1088() {
        // Total counts all tree lines with no tail strings.
        // Hidden count is total minus sixty four.
        let topo = large_topo();
        let (capped, total) = render_topo_lines_capped(&topo, 64);
        assert_eq!(total, 1088);
        assert_eq!(capped.len(), 64);
        let marker = format!("...+{} more", total.wrapping_sub(64));
        assert_eq!(marker, String::from("...+1024 more"));
        assert_eq!(capped[0], String::from("Machine"));
    }

    #[test]
    fn topo_capped_zero_and_overflow() {
        // Limit zero keeps empty plus total.
        // Large limit keeps all lines.
        let topo = large_topo();
        let (empty, total) = render_topo_lines_capped(&topo, 0);
        assert!(empty.is_empty());
        assert_eq!(total, 1088);
        let (all, full_total) = render_topo_lines_capped(&topo, 5000);
        assert_eq!(full_total, 1088);
        assert_eq!(all.len(), 1088);
        let single = single_host_topo();
        let (small, small_total) = render_topo_lines_capped(&single, 64);
        assert_eq!(small_total, 10);
        assert_eq!(small.len(), 10);
    }

    #[test]
    fn capped_builds_stay_bounded() {
        // Capped lengths never pass the limit.
        // Capacity stays near the limit with no full build.
        let topo = large_topo();
        for limit in [0usize, 1, 10, 64, 100] {
            let (per_core, per_total) = render_per_core_lines_capped(&topo, None, limit);
            assert!(per_core.len() <= limit);
            assert_eq!(per_total, 542);
            assert!(per_core.capacity() <= limit.wrapping_add(16));
            let (tree, tree_total) = render_topo_lines_capped(&topo, limit);
            assert!(tree.len() <= limit);
            assert_eq!(tree_total, 1088);
        }
    }
}
