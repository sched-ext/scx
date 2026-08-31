// SPDX-License-Identifier: GPL-2.0

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use log::debug;

use crate::cgroup::CgroupReader;

/// Keep only NVML processes whose GPUs resolve to one NUMA node.
pub(crate) fn direct_gpu_processes(
    process_nodes: &HashMap<u32, HashSet<u32>>,
) -> HashMap<u32, u32> {
    process_nodes
        .iter()
        .filter_map(|(&tgid, nodes)| {
            (nodes.len() == 1).then(|| (tgid, *nodes.iter().next().unwrap()))
        })
        .collect()
}

/// Expand NVML processes to peer processes in the same exact cgroup.
///
/// NVML remains the source of GPU usage and NUMA locality. Cgroups are used
/// only to discover the other processes that belong to the same workload.
pub(crate) fn expand_gpu_processes(
    process_nodes: &HashMap<u32, HashSet<u32>>,
    cgroups: &CgroupReader,
) -> HashMap<u32, u32> {
    expand_gpu_processes_with(
        process_nodes,
        |tgid| cgroups.process_cgroup(tgid),
        |cgroup| cgroups.processes(cgroup),
    )
}

/// Fit workload hints into the BPF map without partially expanding a cgroup.
pub(crate) fn fit_gpu_processes(
    expanded: HashMap<u32, u32>,
    direct: &HashMap<u32, u32>,
    max_entries: usize,
) -> HashMap<u32, u32> {
    if expanded.len() <= max_entries {
        expanded
    } else if direct.len() <= max_entries {
        direct.clone()
    } else {
        HashMap::new()
    }
}

fn expand_gpu_processes_with<C, P>(
    process_nodes: &HashMap<u32, HashSet<u32>>,
    mut process_cgroup: C,
    mut cgroup_processes: P,
) -> HashMap<u32, u32>
where
    C: FnMut(u32) -> Result<Option<PathBuf>>,
    P: FnMut(&Path) -> Result<HashSet<u32>>,
{
    #[derive(Default)]
    struct Observation {
        nodes: HashSet<u32>,
        seeds: HashSet<u32>,
    }

    // Every NVML observation is authoritative, including processes whose
    // GPUs span multiple nodes and therefore intentionally have no hint.
    // Peer discovery must not override them when membership changes.
    let direct = direct_gpu_processes(process_nodes);
    let mut peer_nodes: HashMap<u32, HashSet<u32>> = HashMap::new();
    let mut cgroups: HashMap<PathBuf, Observation> = HashMap::new();

    for (&tgid, nodes) in process_nodes {
        match process_cgroup(tgid) {
            Ok(Some(cgroup)) => {
                let observation = cgroups.entry(cgroup).or_default();
                observation.nodes.extend(nodes.iter().copied());
                observation.seeds.insert(tgid);
            }
            Ok(None) => debug!("GPU process {tgid} is in the root cgroup; not expanding"),
            Err(error) => debug!("GPU process {tgid} cgroup discovery failed: {error:#}"),
        }
    }

    for (cgroup, observation) in cgroups {
        if observation.nodes.len() != 1 {
            debug!(
                "GPU cgroup {} spans multiple NUMA nodes; not expanding",
                cgroup.display()
            );
            continue;
        }
        let node = *observation.nodes.iter().next().unwrap();
        match cgroup_processes(&cgroup) {
            Ok(processes) => {
                // Membership is mutable. Do not expand an old path after all
                // of the NVML seed processes have moved away or exited.
                if observation.seeds.is_disjoint(&processes) {
                    debug!(
                        "GPU cgroup {} no longer contains an observed GPU process; not expanding",
                        cgroup.display()
                    );
                    continue;
                }
                debug!(
                    "GPU cgroup {} expands {} NVML processes to {} workload processes",
                    cgroup.display(),
                    observation.seeds.len(),
                    processes.len()
                );
                for tgid in processes {
                    if !process_nodes.contains_key(&tgid) {
                        peer_nodes.entry(tgid).or_default().insert(node);
                    }
                }
            }
            Err(error) => debug!(
                "GPU cgroup {} process discovery failed: {error:#}",
                cgroup.display()
            ),
        }
    }

    let mut expanded = direct;
    for (tgid, nodes) in peer_nodes {
        // A peer discovered in conflicting workloads is safer without a hint
        // than with a node chosen according to iteration order.
        if nodes.len() == 1 {
            expanded.insert(tgid, *nodes.iter().next().unwrap());
        }
    }
    expanded
}

#[cfg(test)]
mod tests {
    use anyhow::bail;

    use super::*;

    fn nodes(values: &[u32]) -> HashSet<u32> {
        values.iter().copied().collect()
    }

    #[test]
    fn expands_exact_cgroup_processes() {
        let observed = HashMap::from([(100, nodes(&[0]))]);
        let expanded = expand_gpu_processes_with(
            &observed,
            |tgid| {
                assert_eq!(tgid, 100);
                Ok(Some(PathBuf::from("/cgroup/a")))
            },
            |path| {
                assert_eq!(path, Path::new("/cgroup/a"));
                Ok(nodes(&[100, 200, 300]))
            },
        );

        assert_eq!(expanded, HashMap::from([(100, 0), (200, 0), (300, 0)]));
    }

    #[test]
    fn falls_back_to_direct_process_on_discovery_failure() {
        let observed = HashMap::from([(100, nodes(&[0]))]);
        let expanded = expand_gpu_processes_with(
            &observed,
            |_| bail!("unavailable"),
            |_| bail!("must not read cgroup.procs"),
        );
        assert_eq!(expanded, HashMap::from([(100, 0)]));
    }

    #[test]
    fn does_not_expand_after_seed_leaves_cgroup() {
        let observed = HashMap::from([(100, nodes(&[0]))]);
        let expanded = expand_gpu_processes_with(
            &observed,
            |_| Ok(Some(PathBuf::from("/cgroup/a"))),
            |_| Ok(nodes(&[200, 300])),
        );
        assert_eq!(expanded, HashMap::from([(100, 0)]));
    }

    #[test]
    fn does_not_expand_cgroup_across_nodes() {
        let observed = HashMap::from([(100, nodes(&[0])), (101, nodes(&[1]))]);
        let expanded = expand_gpu_processes_with(
            &observed,
            |_| Ok(Some(PathBuf::from("/cgroup/a"))),
            |_| Ok(nodes(&[100, 101, 200])),
        );

        assert_eq!(expanded, HashMap::from([(100, 0), (101, 1)]));
    }

    #[test]
    fn removes_ambiguous_process_hint() {
        let observed = HashMap::from([(100, nodes(&[0, 1]))]);
        let expanded = expand_gpu_processes_with(
            &observed,
            |_| Ok(Some(PathBuf::from("/cgroup/a"))),
            |_| Ok(nodes(&[100, 200])),
        );
        assert!(expanded.is_empty());
    }

    #[test]
    fn removes_peer_seen_in_conflicting_cgroups() {
        let observed = HashMap::from([(100, nodes(&[0])), (101, nodes(&[1]))]);
        let expanded = expand_gpu_processes_with(
            &observed,
            |tgid| Ok(Some(PathBuf::from(format!("/cgroup/{tgid}")))),
            |_| Ok(nodes(&[200])),
        );

        assert_eq!(expanded, HashMap::from([(100, 0), (101, 1)]));
        assert!(!expanded.contains_key(&200));
    }

    #[test]
    fn direct_nvml_mapping_wins_membership_race() {
        let observed = HashMap::from([(100, nodes(&[0])), (101, nodes(&[1]))]);
        let expanded = expand_gpu_processes_with(
            &observed,
            |tgid| Ok(Some(PathBuf::from(format!("/cgroup/{tgid}")))),
            |path| {
                if path == Path::new("/cgroup/100") {
                    Ok(nodes(&[100]))
                } else {
                    Ok(nodes(&[100, 101]))
                }
            },
        );

        assert_eq!(expanded, HashMap::from([(100, 0), (101, 1)]));
    }

    #[test]
    fn ambiguous_nvml_observation_wins_membership_race() {
        let observed = HashMap::from([(100, nodes(&[0])), (101, nodes(&[0, 1]))]);
        let expanded = expand_gpu_processes_with(
            &observed,
            |tgid| {
                if tgid == 100 {
                    Ok(Some(PathBuf::from("/cgroup/a")))
                } else {
                    bail!("cgroup lookup raced")
                }
            },
            |_| Ok(nodes(&[100, 101])),
        );

        assert_eq!(expanded, HashMap::from([(100, 0)]));
    }

    #[test]
    fn capacity_falls_back_without_partial_expansion() {
        let direct = HashMap::from([(100, 0)]);
        let expanded = HashMap::from([(100, 0), (200, 0), (300, 0)]);

        assert_eq!(fit_gpu_processes(expanded.clone(), &direct, 3), expanded);
        assert_eq!(fit_gpu_processes(expanded, &direct, 2), direct);
        assert!(fit_gpu_processes(HashMap::from([(100, 0)]), &direct, 0).is_empty());
    }
}
