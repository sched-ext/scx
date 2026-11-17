// SPDX-License-Identifier: GPL-2.0
//! CPU topology handling for scx_flow.
//!
//! Builds the topology tables the BPF program reads and the topology
//! lines printed at startup.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use anyhow::Result;
use anyhow::bail;
use scx_utils::Core;
use scx_utils::Topology;

use crate::bpf_intf;
use crate::cache::CpuCaches;

/// Cores per group when the kernel reports no cluster ids. Cores are taken
/// in id order within each LLC, so cores that are numbered close to each
/// other, and usually sit close to each other, share a group.
const GROUP_WIDTH: usize = 4;

/// True when any core runs more than one hardware thread.
pub fn smt_on(topo: &Topology) -> bool {
    topo.all_cores.values().any(|c| c.cpus.len() > 1)
}

/// Cluster id of a core. The kernel reports -1 or 65535 when it has none.
fn core_cluster(core: &Core) -> Option<isize> {
    let known = |id: isize| id != -1 && id != 65535;

    if known(core.cluster_id) {
        return Some(core.cluster_id);
    }
    core.cpus
        .values()
        .map(|cpu| cpu.cluster_id)
        .find(|id| known(*id))
}

/// Core group of every CPU. Cores with a cluster id are grouped by it and
/// the remaining cores of each LLC are split into groups of GROUP_WIDTH.
/// Group ids start at zero and have no gaps.
fn cpu_groups(topo: &Topology) -> BTreeMap<usize, u32> {
    let clusters: BTreeSet<isize> = topo
        .all_cores
        .values()
        .filter_map(|c| core_cluster(c))
        .collect();
    let by_cluster: BTreeMap<isize, u32> = clusters.into_iter().zip(0u32..).collect();
    let mut next = by_cluster.len() as u32;
    let mut core_group: BTreeMap<usize, u32> = BTreeMap::new();
    let mut unclustered: BTreeMap<usize, Vec<usize>> = BTreeMap::new();

    for (id, core) in &topo.all_cores {
        match core_cluster(core).and_then(|c| by_cluster.get(&c)) {
            Some(group) => {
                core_group.insert(*id, *group);
            }
            None => unclustered.entry(core.llc_id).or_default().push(*id),
        }
    }
    for cores in unclustered.values() {
        for chunk in cores.chunks(GROUP_WIDTH) {
            for id in chunk {
                core_group.insert(*id, next);
            }
            next += 1;
        }
    }

    topo.all_cpus
        .iter()
        .filter_map(|(id, cpu)| core_group.get(&cpu.core_id).map(|g| (*id, *g)))
        .collect()
}

fn nr_groups(groups: &BTreeMap<usize, u32>) -> usize {
    groups.values().collect::<BTreeSet<_>>().len()
}

/// Topology tables for the BPF program. LLCs are renumbered from zero in
/// the order of their ids. Cache sizes are in kibibytes, zero if unknown.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BpfTopology {
    pub nr_llcs: u32,
    /// Zero when there are more groups than the BPF program can hold,
    /// which disables the group step of the idle CPU search.
    pub nr_groups: u32,
    pub cpu_llc: BTreeMap<usize, u32>,
    pub cpu_group: BTreeMap<usize, u32>,
    pub llc_node: Vec<u32>,
    pub llc_kb: Vec<u32>,
}

impl BpfTopology {
    pub fn new(topo: &Topology, caches: &BTreeMap<usize, CpuCaches>) -> Result<Self> {
        let llc_ids: Vec<usize> = topo.all_llcs.keys().copied().collect();
        let max_llcs = bpf_intf::flow_consts_FLOW_MAX_LLCS as usize;

        if llc_ids.is_empty() || llc_ids.len() > max_llcs {
            bail!(
                "found {} LLCs, between 1 and {max_llcs} are supported",
                llc_ids.len()
            );
        }

        let cpu_llc = topo
            .all_cpus
            .iter()
            .filter_map(|(id, cpu)| {
                llc_ids
                    .binary_search(&cpu.llc_id)
                    .ok()
                    .map(|llc| (*id, llc as u32))
            })
            .collect();

        let mut cpu_group = cpu_groups(topo);
        let mut groups = nr_groups(&cpu_group);
        if groups > bpf_intf::flow_consts_FLOW_MAX_GROUPS as usize {
            cpu_group.clear();
            groups = 0;
        }

        let llc_kb = topo
            .all_llcs
            .values()
            .map(|llc| {
                llc.all_cpus
                    .keys()
                    .find_map(|cpu| caches.get(cpu))
                    .map_or(0, |c| c.l3_kb)
            })
            .collect();

        Ok(Self {
            nr_llcs: llc_ids.len() as u32,
            nr_groups: groups as u32,
            cpu_llc,
            cpu_group,
            llc_node: topo.all_llcs.values().map(|l| l.node_id as u32).collect(),
            llc_kb,
        })
    }
}

fn count(n: usize, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}

/// One line summary for the startup log.
pub fn describe_topo_summary(topo: &Topology) -> String {
    let packages: BTreeSet<usize> = topo.all_cpus.values().map(|c| c.package_id).collect();

    format!(
        "{}, {}, {}, {}, {}, SMT {}",
        count(topo.all_cpus.len(), "CPU"),
        count(packages.len(), "package"),
        count(topo.nodes.len(), "node"),
        count(topo.all_llcs.len(), "LLC"),
        count(nr_groups(&cpu_groups(topo)).max(1), "core group"),
        if smt_on(topo) { "on" } else { "off" },
    )
}

/// Size of a cache in kibibytes, as K or as M when it is a whole number of
/// mebibytes.
pub fn format_kb(kb: u32) -> String {
    if kb == 0 {
        String::from("unknown")
    } else if kb.is_multiple_of(1024) {
        format!("{}M", kb / 1024)
    } else {
        format!("{kb}K")
    }
}

fn cache_sizes(core: &Core, caches: &BTreeMap<usize, CpuCaches>) -> [String; 4] {
    match core.cpus.keys().find_map(|id| caches.get(id)) {
        Some(row) => [
            format_kb(row.l1d_kb),
            format_kb(row.l1i_kb),
            format_kb(row.l2_kb),
            format_kb(row.l3_kb),
        ],
        None => std::array::from_fn(|_| String::from("unknown")),
    }
}

/// One line per core with its CPUs, LLC, node, group and cache sizes, for
/// at most @limit cores. Also returns the number of cores.
pub fn render_per_core_lines(
    topo: &Topology,
    caches: &BTreeMap<usize, CpuCaches>,
    limit: usize,
) -> (Vec<String>, usize) {
    let groups = cpu_groups(topo);
    let lines = topo
        .all_cores
        .values()
        .take(limit)
        .map(|core| {
            let cpus: Vec<String> = core.cpus.keys().map(|id| id.to_string()).collect();
            let group = core
                .cpus
                .keys()
                .next()
                .and_then(|id| groups.get(id))
                .map_or_else(|| String::from("unknown"), |g| g.to_string());
            let [l1d, l1i, l2, l3] = cache_sizes(core, caches);

            format!(
                "Core L{} P{} cpus {} LLC {} node {} group {group} L1d {l1d} L1i {l1i} L2 {l2} L3 {l3}",
                core.id,
                core.kernel_id,
                cpus.join("+"),
                core.llc_id,
                core.node_id,
            )
        })
        .collect();

    (lines, topo.all_cores.len())
}

/// Collects up to a limit of lines and counts all of them.
struct CappedLines {
    lines: Vec<String>,
    total: usize,
    limit: usize,
}

impl CappedLines {
    fn push(&mut self, line: impl FnOnce() -> String) {
        self.total += 1;
        if self.lines.len() < self.limit {
            self.lines.push(line());
        }
    }
}

/// The topology as an indented tree, for at most @limit lines. Also returns
/// the number of lines in the whole tree. L is the scx_utils id and P the
/// kernel id.
pub fn render_topo_lines(topo: &Topology, limit: usize) -> (Vec<String>, usize) {
    let mut out = CappedLines {
        lines: Vec::new(),
        total: 0,
        limit,
    };
    let show_cluster = nr_groups(&cpu_groups(topo)) > 1;
    let packages: BTreeSet<usize> = topo.all_cpus.values().map(|c| c.package_id).collect();

    out.push(|| String::from("Machine"));
    for (pkg_l, pkg) in packages.into_iter().enumerate() {
        out.push(|| format!("  Package L{pkg_l} P{pkg}"));

        for node in topo.nodes.values() {
            if !node.all_cpus.values().any(|c| c.package_id == pkg) {
                continue;
            }
            out.push(|| format!("    Node L{} P{}", node.id, node.id));

            let mut llcs: Vec<_> = node
                .llcs
                .values()
                .filter(|llc| llc.all_cpus.values().any(|c| c.package_id == pkg))
                .collect();
            llcs.sort_by_key(|llc| (llc.kernel_id, llc.id));
            for llc in llcs {
                out.push(|| format!("      L3 L{} P{}", llc.id, llc.kernel_id));

                let mut cores: Vec<_> = llc
                    .cores
                    .values()
                    .filter(|core| core.cpus.values().any(|c| c.package_id == pkg))
                    .collect();
                cores.sort_by_key(|core| (core.kernel_id, core.id));
                for core in cores {
                    let suffix = match core_cluster(core) {
                        Some(c) if show_cluster => format!(" cluster C{c}"),
                        _ => String::new(),
                    };
                    out.push(|| {
                        format!("        Core+L2 L{} P{}{suffix}", core.id, core.kernel_id)
                    });
                    for cpu in core.cpus.keys() {
                        out.push(|| format!("          PU L{cpu} P{cpu}"));
                    }
                }
            }
        }
    }

    (out.lines, out.total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scx_utils::CoreType;
    use scx_utils::Cpu;
    use scx_utils::Cpumask;
    use scx_utils::Llc;
    use std::sync::Arc;

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

    /// A core of the given CPUs. Every CPU shares the core's LLC, node,
    /// package and cluster.
    fn mk_core(
        id: usize,
        cpus: &[usize],
        llc_id: usize,
        node_id: usize,
        package_id: usize,
        cluster_id: isize,
    ) -> Arc<Core> {
        Arc::new(Core {
            id,
            kernel_id: id,
            cluster_id,
            cpus: cpus
                .iter()
                .map(|cpu| {
                    (
                        *cpu,
                        mk_cpu(*cpu, id, llc_id, node_id, package_id, cluster_id),
                    )
                })
                .collect(),
            span: Cpumask::new(),
            core_type: CoreType::Big { turbo: false },
            llc_id,
            node_id,
        })
    }

    fn mk_llc(id: usize, cores: Vec<Arc<Core>>, node_id: usize) -> Arc<Llc> {
        Arc::new(Llc {
            id,
            kernel_id: id,
            all_cpus: cores
                .iter()
                .flat_map(|core| core.cpus.iter().map(|(k, v)| (*k, v.clone())))
                .collect(),
            cores: cores.into_iter().map(|core| (core.id, core)).collect(),
            span: Cpumask::new(),
            node_id,
        })
    }

    /// Nodes and the topology are built on top of the live ones, because
    /// optional scx_utils features can add fields a struct literal would
    /// have to name. Every field the tests rely on is overwritten.
    fn mk_topo(nodes: Vec<(usize, Vec<Arc<Llc>>)>) -> Topology {
        let live = Topology::new().expect("live topology");
        let template = live.nodes.values().next().expect("live node").clone();
        let mut topo = live;

        topo.nodes = BTreeMap::new();
        topo.all_llcs = BTreeMap::new();
        topo.all_cores = BTreeMap::new();
        topo.all_cpus = BTreeMap::new();
        for (id, llcs) in nodes {
            let mut node = template.clone();
            node.id = id;
            node.span = Cpumask::new();
            node.llcs = BTreeMap::new();
            node.all_cores = BTreeMap::new();
            node.all_cpus = BTreeMap::new();
            for llc in llcs {
                for core in llc.cores.values() {
                    node.all_cores.insert(core.id, core.clone());
                    topo.all_cores.insert(core.id, core.clone());
                }
                for (cpu_id, cpu) in &llc.all_cpus {
                    node.all_cpus.insert(*cpu_id, cpu.clone());
                    topo.all_cpus.insert(*cpu_id, cpu.clone());
                }
                node.llcs.insert(llc.id, llc.clone());
                topo.all_llcs.insert(llc.id, llc);
            }
            topo.nodes.insert(id, node);
        }
        topo.span = Cpumask::new();
        topo.smt_enabled = topo.all_cores.values().any(|c| c.cpus.len() > 1);
        topo
    }

    /// Two SMT cores in one LLC with cluster ids 0 and 1.
    fn single_host_topo() -> Topology {
        mk_topo(vec![(
            0,
            vec![mk_llc(
                0,
                vec![
                    mk_core(0, &[0, 1], 0, 0, 0, 0),
                    mk_core(1, &[2, 3], 0, 0, 0, 1),
                ],
                0,
            )],
        )])
    }

    /// Two packages, each with one node, one LLC and two cores, and no
    /// cluster ids.
    fn multi_package_topo() -> Topology {
        mk_topo(vec![
            (
                0,
                vec![mk_llc(
                    0,
                    vec![mk_core(0, &[0], 0, 0, 2, -1), mk_core(1, &[1], 0, 0, 2, -1)],
                    0,
                )],
            ),
            (
                1,
                vec![mk_llc(
                    1,
                    vec![mk_core(2, &[2], 1, 1, 5, -1), mk_core(3, &[3], 1, 1, 5, -1)],
                    1,
                )],
            ),
        ])
    }

    /// 542 single-thread cores in one LLC and no cluster ids.
    fn large_topo() -> Topology {
        let cores = (0..542).map(|id| mk_core(id, &[id], 0, 0, 0, -1)).collect();
        mk_topo(vec![(0, vec![mk_llc(0, cores, 0)])])
    }

    fn two_core_topo(first: isize, second: isize) -> Topology {
        mk_topo(vec![(
            0,
            vec![mk_llc(
                0,
                vec![
                    mk_core(0, &[0], 0, 0, 0, first),
                    mk_core(1, &[1], 0, 0, 0, second),
                ],
                0,
            )],
        )])
    }

    fn caches(cpus: &[usize], l3_kb: u32) -> BTreeMap<usize, CpuCaches> {
        cpus.iter()
            .map(|cpu| {
                let sizes = CpuCaches {
                    l1d_kb: 32,
                    l1i_kb: 32,
                    l2_kb: 512,
                    l3_kb,
                };
                (*cpu, sizes)
            })
            .collect()
    }

    #[test]
    fn groups_follow_known_clusters() {
        assert_eq!(nr_groups(&cpu_groups(&single_host_topo())), 2);

        let mixed = two_core_topo(7, -1);
        let groups = cpu_groups(&mixed);
        assert_eq!(groups.get(&0), Some(&0));
        assert_eq!(groups.get(&1), Some(&1));

        for unknown in [-1isize, 65535] {
            assert_eq!(nr_groups(&cpu_groups(&two_core_topo(unknown, unknown))), 1);
        }
    }

    #[test]
    fn unclustered_cores_split_per_llc() {
        let groups = cpu_groups(&multi_package_topo());
        assert_eq!(groups.get(&1), Some(&0));
        assert_eq!(groups.get(&2), Some(&1));

        let large = cpu_groups(&large_topo());
        assert_eq!(large.get(&3), Some(&0));
        assert_eq!(large.get(&4), Some(&1));
        assert_eq!(nr_groups(&large), 542usize.div_ceil(GROUP_WIDTH));
    }

    #[test]
    fn bpf_tables_renumber_llcs() {
        let mut sizes = caches(&[0, 1], 98304);
        sizes.extend(caches(&[2, 3], 32768));
        let tables = BpfTopology::new(&multi_package_topo(), &sizes).unwrap();
        assert_eq!(tables.nr_llcs, 2);
        assert_eq!(tables.llc_kb, vec![98304, 32768]);
        assert_eq!(tables.nr_groups, 2);
        assert_eq!(tables.llc_node, vec![0, 1]);
        assert_eq!(
            tables.cpu_llc,
            BTreeMap::from([(0, 0), (1, 0), (2, 1), (3, 1)])
        );
        assert_eq!(
            tables.cpu_group,
            BTreeMap::from([(0, 0), (1, 0), (2, 1), (3, 1)])
        );
    }

    #[test]
    fn bpf_tables_drop_groups_over_the_limit() {
        let tables = BpfTopology::new(&large_topo(), &BTreeMap::new()).unwrap();
        assert_eq!(tables.nr_llcs, 1);
        assert_eq!(tables.nr_groups, 0);
        assert!(tables.cpu_group.is_empty());
        assert_eq!(tables.cpu_llc.len(), 542);
        assert_eq!(tables.llc_kb, vec![0]);
    }

    #[test]
    fn summary_names_the_shape() {
        assert_eq!(
            describe_topo_summary(&single_host_topo()),
            "4 CPUs, 1 package, 1 node, 1 LLC, 2 core groups, SMT on"
        );
        assert_eq!(
            describe_topo_summary(&multi_package_topo()),
            "4 CPUs, 2 packages, 2 nodes, 2 LLCs, 2 core groups, SMT off"
        );
    }

    #[test]
    fn tree_lists_every_level() {
        let (lines, total) = render_topo_lines(&single_host_topo(), usize::MAX);
        assert_eq!(total, 10);
        assert_eq!(
            lines,
            vec![
                "Machine",
                "  Package L0 P0",
                "    Node L0 P0",
                "      L3 L0 P0",
                "        Core+L2 L0 P0 cluster C0",
                "          PU L0 P0",
                "          PU L1 P1",
                "        Core+L2 L1 P1 cluster C1",
                "          PU L2 P2",
                "          PU L3 P3",
            ]
        );

        let (lines, _) = render_topo_lines(&multi_package_topo(), usize::MAX);
        assert_eq!(lines[1], "  Package L0 P2");
        assert_eq!(lines[8], "  Package L1 P5");
        assert_eq!(lines[10], "      L3 L1 P1");
        assert!(lines.iter().all(|l| !l.contains("cluster")));
    }

    #[test]
    fn tree_cluster_suffix_needs_a_known_id() {
        let (lines, _) = render_topo_lines(&two_core_topo(7, -1), usize::MAX);
        assert_eq!(lines[4], "        Core+L2 L0 P0 cluster C7");
        assert_eq!(lines[6], "        Core+L2 L1 P1");
    }

    #[test]
    fn tree_is_capped() {
        let topo = large_topo();
        let (full, total) = render_topo_lines(&topo, usize::MAX);
        assert_eq!(total, 1088);
        assert_eq!(full.len(), 1088);

        for limit in [0, 1, 64] {
            let (capped, total) = render_topo_lines(&topo, limit);
            assert_eq!(total, 1088);
            assert_eq!(capped, full[..limit]);
        }
    }

    #[test]
    fn per_core_lines_show_cache_sizes() {
        let topo = single_host_topo();
        let (lines, total) =
            render_per_core_lines(&topo, &caches(&[0, 1, 2, 3], 16384), usize::MAX);
        assert_eq!(total, 2);
        assert_eq!(
            lines[0],
            "Core L0 P0 cpus 0+1 LLC 0 node 0 group 0 L1d 32K L1i 32K L2 512K L3 16M"
        );

        let (missing, _) = render_per_core_lines(&topo, &BTreeMap::new(), usize::MAX);
        assert!(missing[0].ends_with("L1d unknown L1i unknown L2 unknown L3 unknown"));
    }

    #[test]
    fn per_core_lines_are_capped() {
        let topo = large_topo();
        for limit in [0, 1, 64, 1000] {
            let (lines, total) = render_per_core_lines(&topo, &BTreeMap::new(), limit);
            assert_eq!(total, 542);
            assert_eq!(lines.len(), limit.min(542));
        }
    }

    #[test]
    fn cache_sizes_use_k_and_m() {
        assert_eq!(format_kb(0), "unknown");
        assert_eq!(format_kb(48), "48K");
        assert_eq!(format_kb(1536), "1536K");
        assert_eq!(format_kb(1024), "1M");
        assert_eq!(format_kb(98304), "96M");
    }
}
