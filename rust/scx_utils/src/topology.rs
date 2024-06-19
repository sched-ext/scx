// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! # SCX Topology
//!
//! A crate that allows schedulers to inspect and model the host's topology, in
//! service of creating scheduling domains.
//!
//! A Topology is comprised of one or more Node objects, which themselves are
//! comprised hierarchically of Cache -> Core -> Cpu objects respectively:
//!
//!		                        	                                           Topology
//!		                        	                                              |
//!		                        	                        o---------------------o---------------------o
//!		                        	                        |                     |                     |
//!		                        	                        |                     |                     |
//!		                                    o---------------o----------------o   ...   o----------------o---------------o
//!		                                    |         Node                   |         |         Node                   |
//!		                                    | ID      0                      |         | ID      1                      |
//!		                                    | Caches  <id, Cache>            |         | Caches  <id, Cache>            |
//!		                                    | Span    0x00000fffff00000fffff |         | Span    0xfffff00000fffff00000 |
//!		                                    o--------------------------------o         o--------------------------------o
//!		                                                    |
//!		                                                    |
//!                   o--------------------------------o   ...   o--------------------------------o
//!                   |             Cache              |         |             Cache              |
//!                   | ID     0                       |         | ID     1                       |
//!                   | Cores  <id, Core>              |         | Cores  <id, Core>              |
//!                   | Span   0x00000ffc0000000ffc00  |         | Span   0x00000003ff00000003ff  |
//!                   o--------------------------------o         o----------------o---------------o
//!		                                                                          |
//!		                                                                          |
//!                                         o--------------------------------o   ...   o--------------------------------o
//!                                         |              Core              |         |              Core              |
//!                                         | ID    0                        |         | ID    9                        |
//!                                         | Cpus  <id, Cpu>                |         | Cpus  <id, Cpu>                |
//!                                         | Span  0x00000000010000000001   |         | Span  0x00000002000000000200   |
//!                                         o--------------------------------o         o----------------o---------------o
//!		                                                                                                |
//!		                                                                                                |
//!                                                               o--------------------------------o   ...   o---------------------------------o
//!                                                               |              Cpu               |         |               Cpu               |
//!                                                               | ID       9                     |         | ID       49                     |
//!                                                               | online   1                     |         | online   1                      |
//!                                                               | min_freq 400000                |         | min_freq 400000                 |
//!                                                               | max_freq 5881000               |         | min_freq 5881000                |
//!                                                               o--------------------------------o         o---------------------------------o
//!
//! Every object contains a Cpumask that spans all CPUs in that point in the
//! topological hierarchy.
//!
//! Creating Topology
//! -----------------
//!
//! Topology objects are created using the static new function:
//!
//!```
//!     let top = Topology::new()?;
//!```
//!
//! Querying Topology
//! -----------------
//!
//! With a created Topology, you can query the topological hierarchy using the
//! set of accessor functions defined below. All objects in the topological
//! hierarchy are entirely read-only. If the host topology were to change (due
//! to e.g. hotplug), a new Topology object should be created.

use crate::Cpumask;
use anyhow::bail;
use anyhow::Result;
use glob::glob;
use sscanf::sscanf;
use std::collections::BTreeMap;
use std::path::Path;
use std::slice::Iter;

#[derive(Debug, Clone)]
pub struct Cpu {
    id: usize,
    min_freq: usize,
    max_freq: usize,
    trans_lat_ns: usize,
}

impl Cpu {
    /// Get the ID of this Cpu
    pub fn id(&self) -> usize {
        self.id
    }

    /// Get the minimum scaling frequency of this CPU
    pub fn min_freq(&self) -> usize {
        self.min_freq
    }

    /// Get the maximum scaling frequency of this CPU
    pub fn max_freq(&self) -> usize {
        self.max_freq
    }

    /// Get the transition latency of the CPU in nanoseconds
    pub fn trans_lat_ns(&self) -> usize {
        self.trans_lat_ns
    }
}

#[derive(Debug, Clone)]
pub struct Core {
    id: usize,
    cpus: BTreeMap<usize, Cpu>,
    span: Cpumask,
}

impl Core {
    /// Get the ID of this Core
    pub fn id(&self) -> usize {
        self.id
    }

    /// Get the map of CPUs inside this Core
    pub fn cpus(&self) -> &BTreeMap<usize, Cpu> {
        &self.cpus
    }

    /// Get a Cpumask of all SMT siblings in this Core
    pub fn span(&self) -> &Cpumask {
        &self.span
    }
}

#[derive(Debug, Clone)]
pub struct Cache {
    id: usize,
    cores: BTreeMap<usize, Core>,
    span: Cpumask,
}

impl Cache {
    /// Get the ID of this LLC
    pub fn id(&self) -> usize {
        self.id
    }

    /// Get the map of cores inside this LLC
    pub fn cores(&self) -> &BTreeMap<usize, Core> {
        &self.cores
    }

    /// Get a Cpumask of all CPUs in this LLC
    pub fn span(&self) -> &Cpumask {
        &self.span
    }
}

#[derive(Debug, Clone)]
pub struct Node {
    id: usize,
    llcs: BTreeMap<usize, Cache>,
    span: Cpumask,
}

impl Node {
    /// Get the ID of this NUMA node
    pub fn id(&self) -> usize {
        self.id
    }

    /// Get the map of LLCs inside this NUMA node
    pub fn llcs(&self) -> &BTreeMap<usize, Cache> {
        &self.llcs
    }

    /// Get a Cpumask of all CPUs in this NUMA node
    pub fn span(&self) -> &Cpumask {
        &self.span
    }
}

#[derive(Debug)]
pub struct Topology {
    nodes: Vec<Node>,
    cores: Vec<Core>,
    cpus: BTreeMap<usize, Cpu>,
    span: Cpumask,
    nr_cpus_possible: usize,
}

impl Topology {
    /// Build a complete host Topology
    pub fn new() -> Result<Topology> {
        let span = cpus_online()?;
        // If the kernel is compiled with CONFIG_NUMA, then build a topology
        // from the NUMA hierarchy in sysfs. Otherwise, just make a single
        // default node of ID 0 which contains all cores.
        let nodes = if Path::new("/sys/devices/system/node").exists() {
            create_numa_nodes(&span)?
        } else {
            create_default_node(&span)?
        };

        // For convenient and efficient lookup from the root topology object,
        // create two BTreeMaps to the full set of Core and Cpu objects on the
        // system. We clone the objects that are located further down in the
        // hierarchy rather than dealing with references, as the entire
        // Topology is read-only anyways.
        let mut cores = Vec::new();
        let mut cpus = BTreeMap::new();
        for node in nodes.iter() {
            for llc in node.llcs.values() {
                for core in llc.cores.values() {
                    cores.push(core.clone());
                    for (cpu_id, cpu) in core.cpus.iter() {
                        if let Some(_) = cpus.insert(*cpu_id, cpu.clone()) {
                            bail!("Found duplicate CPU ID {}", cpu_id);
                        }
                    }
                }
            }
        }

        let nr_cpus_possible = libbpf_rs::num_possible_cpus().unwrap();
        Ok(Topology { nodes, cores, cpus, span, nr_cpus_possible, })
    }

    /// Get a slice of the NUMA nodes on the host.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Get a slice of all Cores on the host.
    pub fn cores(&self) -> &[Core] {
        &self.cores
    }

    /// Get a hashmap of <CPU ID, Cpu> for all Cpus on the host.
    pub fn cpus(&self) -> &BTreeMap<usize, Cpu> {
        &self.cpus
    }

    /// Get a cpumask of all the online CPUs on the host
    pub fn span(&self) -> &Cpumask {
        &self.span
    }

    /// Get the maximum possible number of CPUs. Note that this number is likely
    /// only applicable in the context of storing and extracting per-CPU data
    /// between user space and BPF, as it doesn't necessarily reflect the actual
    /// number of online or even possible CPUs in the system.
    ///
    /// For example, as described in
    /// https://bugzilla.kernel.org/show_bug.cgi?id=218109, some buggy AMD BIOS
    /// implementations may incorrectly report disabled CPUs as offlined / part
    /// of the CPUs possible mask.
    ///
    /// Even if the CPUs are possible and may be enabled with hotplug, they're
    /// not active now, so you wouldn't want to use this number to determine
    /// system load, util, etc.
    pub fn nr_cpus_possible(&self) -> usize {
        self.nr_cpus_possible
    }
}

/// Generate a topology map from a Topology object, represented as an array of arrays.
///
/// Each inner array corresponds to a core containing its associated CPU IDs. This map can
/// facilitate efficient iteration over the host's topology.
///
/// # Example
///
/// ```
/// let topo = Topology::new()?;
/// let topo_map = TopologyMap::new(topo)?;
///
/// for (core_id, core) in topo_map.iter().enumerate() {
///     for cpu in core {
///         println!("core={} cpu={}", core_id, cpu);
///     }
/// }
/// ```
#[derive(Debug)]
pub struct TopologyMap {
    map: Vec<Vec<usize>>,
    nr_cpus_possible: usize,
    nr_cpus_online: usize,
}

impl TopologyMap {
    pub fn new(topo: Topology) -> Result<TopologyMap> {
        let mut map: Vec<Vec<usize>> = Vec::new();
        let mut nr_cpus_online = 0;

        for core in topo.cores().into_iter() {
            let mut cpu_ids: Vec<usize> = Vec::new();
            for cpu_id in core.span().clone().into_iter() {
                cpu_ids.push(cpu_id);
                nr_cpus_online += 1;
            }
            map.push(cpu_ids);
        }
        let nr_cpus_possible = topo.nr_cpus_possible;

        Ok(TopologyMap { map, nr_cpus_possible, nr_cpus_online })
    }

    pub fn nr_cpus_possible(&self) -> usize {
        self.nr_cpus_possible
    }

    pub fn nr_cpus_online(&self) -> usize {
        self.nr_cpus_online
    }

    pub fn iter(&self) -> Iter<Vec<usize>> {
        self.map.iter()
    }
}

/**********************************************
 * Helper functions for creating the Topology *
 **********************************************/

const CACHE_LEVEL: usize = 3;

fn read_file_usize(path: &Path) -> Result<usize> {
    let val = match std::fs::read_to_string(&path) {
        Ok(val) => val,
        Err(_) => {
            bail!("Failed to open or read file {:?}", path);
        }
    };

    match val.trim().parse::<usize>() {
        Ok(parsed) => Ok(parsed),
        Err(_) => {
            bail!("Failed to parse {}", val);
        }
    }
}

fn cpus_online() -> Result<Cpumask> {
    let path = "/sys/devices/system/cpu/online";
    let online = std::fs::read_to_string(&path)?;
    let online_groups: Vec<&str> = online.split(',').collect();
    let mut mask = Cpumask::new()?;
    for group in online_groups.iter() {
        let (min, max) = match sscanf!(group.trim(), "{usize}-{usize}") {
            Ok((x, y)) => (x, y),
            Err(_) => {
                match sscanf!(group.trim(), "{usize}") {
                    Ok(x) => (x, x),
                    Err(_) => {
                        bail!("Failed to parse online cpus {}", group.trim());
                    }
                }
            },
        };
        for i in min..(max + 1) {
            mask.set_cpu(i)?;
        }
    }

    Ok(mask)
}

fn create_insert_cpu(cpu_id: usize, node: &mut Node, online_mask: &Cpumask) -> Result<()> {
    // CPU is offline. The Topology hierarchy is read-only, and assumes
    // that hotplug will cause the scheduler to restart. Thus, we can
    // just skip this CPU altogether.
    if !online_mask.test_cpu(cpu_id) {
        return Ok(());
    }

    let cpu_str = format!("/sys/devices/system/cpu/cpu{}", cpu_id);
    let cpu_path = Path::new(&cpu_str);

    // Physical core ID
    let top_path = cpu_path.join("topology");
    let core_id = read_file_usize(&top_path.join("core_id"))?;

    // L3 cache ID
    let cache_path = cpu_path.join("cache");
    // Use LLC 0 if we fail to detect the cache hierarchy. This seems to
    // happen on certain SKUs, so if there's no cache information then
    // we have no option but to assume a single unified cache per node.
    let llc_id =
        read_file_usize(&cache_path.join(format!("index{}", CACHE_LEVEL)).join("id")).unwrap_or(0);

    // Min and max frequencies. If the kernel is not compiled with
    // CONFIG_CPU_FREQ, just assume 0 for both frequencies.
    let freq_path = cpu_path.join("cpufreq");
    let min_freq = read_file_usize(&freq_path.join("scaling_min_freq")).unwrap_or(0);
    let max_freq = read_file_usize(&freq_path.join("scaling_max_freq")).unwrap_or(0);
    let trans_lat_ns = read_file_usize(&freq_path.join("cpuinfo_transition_latency")).unwrap_or(0);

    let cache = node.llcs.entry(llc_id).or_insert(Cache{
        id: llc_id,
        cores: BTreeMap::new(),
        span: Cpumask::new()?,
    });

    let core = cache.cores.entry(core_id).or_insert(Core{
        id: core_id,
        cpus: BTreeMap::new(),
        span: Cpumask::new()?,
    });

    core.cpus.insert(
        cpu_id,
        Cpu {
            id: cpu_id,
            min_freq: min_freq,
            max_freq: max_freq,
            trans_lat_ns: trans_lat_ns,
        },
    );

    if node.span.test_cpu(cpu_id) {
        bail!("Node {} already had CPU {}", node.id, cpu_id);
    }

    // Update all of the devices' spans to include this CPU.
    core.span.set_cpu(cpu_id)?;
    cache.span.set_cpu(cpu_id)?;
    node.span.set_cpu(cpu_id)?;

    Ok(())
}

fn create_default_node(online_mask: &Cpumask) -> Result<Vec<Node>> {
    let mut nodes: Vec<Node> = Vec::with_capacity(1);
    let mut node = Node {
        id: 0,
        llcs: BTreeMap::new(),
        span: Cpumask::new()?,
    };

    if !Path::new("/sys/devices/system/cpu").exists() {
        bail!("/sys/devices/system/cpu sysfs node not found");
    }

    let cpu_paths = glob("/sys/devices/system/cpu/cpu[0-9]*")?;
    for cpu_path in cpu_paths.filter_map(Result::ok) {
        let cpu_str = cpu_path.to_str().unwrap().trim();
        let cpu_id = match sscanf!(cpu_str, "/sys/devices/system/cpu/cpu{usize}") {
            Ok(val) => val,
            Err(_) => {
                bail!("Failed to parse cpu ID {}", cpu_str);
            }
        };

        create_insert_cpu(cpu_id, &mut node, &online_mask)?;
    }

    nodes.push(node);

    Ok(nodes)
}

fn create_numa_nodes(online_mask: &Cpumask) -> Result<Vec<Node>> {
    let mut nodes: Vec<Node> = Vec::new();

    let numa_paths = glob("/sys/devices/system/node/node*")?;
    for numa_path in numa_paths.filter_map(Result::ok) {
        let numa_str = numa_path.to_str().unwrap().trim();
        let node_id = match sscanf!(numa_str, "/sys/devices/system/node/node{usize}") {
            Ok(val) => val,
            Err(_) => {
                bail!("Failed to parse NUMA node ID {}", numa_str);
            }
        };

        let mut node = Node {
            id: node_id,
            llcs: BTreeMap::new(),
            span: Cpumask::new()?,
        };

        let cpu_pattern = numa_path.join("cpu[0-9]*");
        let cpu_paths = glob(cpu_pattern.to_string_lossy().as_ref())?;
        for cpu_path in cpu_paths.filter_map(Result::ok) {
            let cpu_str = cpu_path.to_str().unwrap().trim();
            let cpu_id = match sscanf!(cpu_str, "/sys/devices/system/node/node{usize}/cpu{usize}") {
                Ok((_, val)) => val,
                Err(_) => {
                    bail!("Failed to parse cpu ID {}", cpu_str);
                }
            };

            create_insert_cpu(cpu_id, &mut node, &online_mask)?;
        }

        nodes.push(node);
    }
    Ok(nodes)
}
