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
//!```rust,ignore
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
//!```
//! Every object contains a Cpumask that spans all CPUs in that point in the
//! topological hierarchy.
//!
//! Creating Topology
//! -----------------
//!
//! Topology objects are created using the static new function:
//!
//!```  
//!     use scx_utils::Topology;
//!     let top = Topology::new().unwrap();
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
use nvml_wrapper::bitmasks::InitFlags;
use nvml_wrapper::enum_wrappers::device::Clock;
use nvml_wrapper::Nvml;
use sscanf::sscanf;
use std::collections::BTreeMap;
use std::path::Path;
use std::slice::Iter;

lazy_static::lazy_static! {
    /// The maximum possible number of CPU IDs in the system. As mentioned
    /// above, this is different than the number of possible CPUs on the
    /// system (though very seldom is). This number may differ from the
    /// number of possible CPUs on the system when e.g. there are fully
    /// disabled CPUs in the middle of the range of possible CPUs (i.e. CPUs
    /// that may not be onlined).
    pub static ref NR_CPU_IDS: usize = read_cpu_ids().unwrap().last().unwrap() + 1;

    /// The number of possible CPUs that may be active on the system. Note
    /// that this value is separate from the number of possible _CPU IDs_ in
    /// the system, as there may be gaps in what CPUs are allowed to be
    /// onlined. For example, some BIOS implementations may report spans of
    /// disabled CPUs that may not be onlined, whose IDs are lower than the
    /// IDs of other CPUs that may be onlined.
    pub static ref NR_CPUS_POSSIBLE: usize = libbpf_rs::num_possible_cpus().unwrap();
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum CoreType {
    Big { turbo: bool },
    Little,
}

#[derive(Debug, Clone)]
pub struct Cpu {
    id: usize,
    min_freq: usize,
    max_freq: usize,
    base_freq: usize,
    trans_lat_ns: usize,
    l2_id: usize,
    l3_id: usize,
    llc_id: usize,
    pub core_type: CoreType,
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

    /// Get the base operational frequency of this CPU
    ///
    /// This is only available on Intel Turbo Boost CPUs, if not available this will simply return
    /// maximum frequency.
    pub fn base_freq(&self) -> usize {
        self.base_freq
    }

    /// Get the transition latency of the CPU in nanoseconds
    pub fn trans_lat_ns(&self) -> usize {
        self.trans_lat_ns
    }

    /// Get the L2 id of the this Cpu
    pub fn l2_id(&self) -> usize {
        self.l2_id
    }

    /// Get the L2 id of the this Cpu
    pub fn l3_id(&self) -> usize {
        self.l3_id
    }

    /// Get the LLC id of the this Cpu
    pub fn llc_id(&self) -> usize {
        self.llc_id
    }
}

#[derive(Debug, Clone)]
pub struct Core {
    id: usize,
    pub node_id: usize,
    pub llc_id: usize,
    cpus: BTreeMap<usize, Cpu>,
    span: Cpumask,
    pub core_type: CoreType,
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

    /// Get the map of all CPUs for this LLC.
    pub fn cpus(&self) -> BTreeMap<usize, Cpu> {
        let mut cpus = BTreeMap::new();
        for (_, core) in self.cores() {
            cpus.append(&mut core.cpus.clone());
        }
        cpus
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub enum GpuIndex {
    Nvidia { nvml_id: u32 },
}

#[derive(Debug, Clone)]
pub struct Gpu {
    pub index: GpuIndex,
    pub node_id: usize,
    pub max_graphics_clock: usize,
    // AMD uses CU for this value
    pub max_sm_clock: usize,
    pub memory: u64,
}

#[derive(Debug, Clone)]
pub struct Node {
    id: usize,
    llcs: BTreeMap<usize, Cache>,
    gpus: BTreeMap<GpuIndex, Gpu>,
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

    /// Get the map of all CPUs for this NUMA node.
    pub fn cpus(&self) -> BTreeMap<usize, Cpu> {
        let mut cpus = BTreeMap::new();
        for (_, llc) in &self.llcs {
            for (_, core) in llc.cores() {
                cpus.append(&mut core.cpus.clone());
            }
        }
        cpus
    }

    /// Get the map of all Cores for this NUMA node.
    pub fn cores(&self) -> BTreeMap<usize, Core> {
        let mut cores = BTreeMap::new();
        for (_, llc) in &self.llcs {
            for (core_id, core) in llc.cores() {
                cores.insert(*core_id, core.clone());
            }
        }
        cores
    }

    // Get the map of all GPUs for this NUMA node.
    pub fn gpus(&self) -> &BTreeMap<GpuIndex, Gpu> {
        &self.gpus
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
    nr_cpus_online: usize,
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

        let nr_cpus_online = span.weight();
        Ok(Topology {
            nodes,
            cores,
            cpus,
            span,
            nr_cpus_online,
        })
    }

    /// Get a slice of the NUMA nodes on the host.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Get a slice of all Cores on the host.
    pub fn cores(&self) -> &[Core] {
        &self.cores
    }

    /// Get a vec of all GPUs on the hosts.
    pub fn gpus(&self) -> BTreeMap<GpuIndex, &Gpu> {
        let mut gpus = BTreeMap::new();
        for node in &self.nodes {
            for (idx, gpu) in &node.gpus {
                gpus.insert(idx.clone(), gpu);
            }
        }
        gpus
    }

    /// Get a hashmap of <CPU ID, Cpu> for all Cpus on the host.
    pub fn cpus(&self) -> &BTreeMap<usize, Cpu> {
        &self.cpus
    }

    /// Get a cpumask of all the online CPUs on the host
    pub fn span(&self) -> &Cpumask {
        &self.span
    }

    /// Get the number of CPUs that were online when the Topology was created.
    /// Because Topology objects are read-only, this value will not change if a
    /// CPU is onlined after a Topology object has been created.
    pub fn nr_cpus_online(&self) -> usize {
        self.nr_cpus_online
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
/// use scx_utils::{TopologyMap, Topology};
/// let topo = Topology::new().unwrap();
/// let topo_map = TopologyMap::new(&topo).unwrap();
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
}

impl TopologyMap {
    pub fn new(topo: &Topology) -> Result<TopologyMap> {
        let mut map: Vec<Vec<usize>> = Vec::new();

        for core in topo.cores().into_iter() {
            let mut cpu_ids: Vec<usize> = Vec::new();
            for cpu_id in core.span().clone().into_iter() {
                cpu_ids.push(cpu_id);
            }
            map.push(cpu_ids);
        }

        Ok(TopologyMap { map })
    }

    pub fn iter(&self) -> Iter<Vec<usize>> {
        self.map.iter()
    }
}

/**********************************************
 * Helper functions for creating the Topology *
 **********************************************/

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
            Err(_) => match sscanf!(group.trim(), "{usize}") {
                Ok(x) => (x, x),
                Err(_) => {
                    bail!("Failed to parse online cpus {}", group.trim());
                }
            },
        };
        for i in min..(max + 1) {
            mask.set_cpu(i)?;
        }
    }

    Ok(mask)
}

fn create_insert_cpu(
    cpu_id: usize,
    node: &mut Node,
    online_mask: &Cpumask,
    avg_cpu_freq: Option<(usize, usize)>,
) -> Result<()> {
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

    // Evaluate L2, L3 and LLC cache IDs.
    //
    // Use ID 0 if we fail to detect the cache hierarchy. This seems to happen on certain SKUs, so
    // if there's no cache information then we have no option but to assume a single unified cache
    // per node.
    let cache_path = cpu_path.join("cache");
    let l2_id = read_file_usize(&cache_path.join(format!("index{}", 2)).join("id")).unwrap_or(0);
    let l3_id = read_file_usize(&cache_path.join(format!("index{}", 3)).join("id")).unwrap_or(0);
    // Assume that LLC is always 3.
    let llc_id = l3_id;

    // Min and max frequencies. If the kernel is not compiled with
    // CONFIG_CPU_FREQ, just assume 0 for both frequencies.
    let freq_path = cpu_path.join("cpufreq");
    let min_freq = read_file_usize(&freq_path.join("scaling_min_freq")).unwrap_or(0);
    let max_freq = read_file_usize(&freq_path.join("scaling_max_freq")).unwrap_or(0);
    let base_freq = read_file_usize(&freq_path.join("base_frequency")).unwrap_or(max_freq);
    let trans_lat_ns = read_file_usize(&freq_path.join("cpuinfo_transition_latency")).unwrap_or(0);

    let cache = node.llcs.entry(llc_id).or_insert(Cache {
        id: llc_id,
        cores: BTreeMap::new(),
        span: Cpumask::new()?,
    });

    let core_type = match avg_cpu_freq {
        Some((avg_base_freq, top_max_freq)) => {
            if max_freq == top_max_freq {
                CoreType::Big { turbo: true }
            } else if base_freq >= avg_base_freq {
                CoreType::Big { turbo: false }
            } else {
                CoreType::Little
            }
        }
        None => CoreType::Big { turbo: false },
    };

    let core = cache.cores.entry(core_id).or_insert(Core {
        id: core_id,
        llc_id: llc_id,
        node_id: node.id,
        cpus: BTreeMap::new(),
        span: Cpumask::new()?,
        core_type: core_type.clone(),
    });

    core.cpus.insert(
        cpu_id,
        Cpu {
            id: cpu_id,
            min_freq: min_freq,
            max_freq: max_freq,
            base_freq: base_freq,
            trans_lat_ns: trans_lat_ns,
            l2_id: l2_id,
            l3_id: l3_id,
            llc_id: llc_id,
            core_type: core_type.clone(),
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

fn read_cpu_ids() -> Result<Vec<usize>> {
    let mut cpu_ids = vec![];
    let cpu_paths = glob("/sys/devices/system/cpu/cpu[0-9]*")?;
    for cpu_path in cpu_paths.filter_map(Result::ok) {
        let cpu_str = cpu_path.to_str().unwrap().trim();
        match sscanf!(cpu_str, "/sys/devices/system/cpu/cpu{usize}") {
            Ok(val) => cpu_ids.push(val),
            Err(_) => {
                bail!("Failed to parse cpu ID {}", cpu_str);
            }
        }
    }
    cpu_ids.sort();
    Ok(cpu_ids)
}

// Return the average base frequency across all CPUs and the highest maximum frequency.
fn avg_cpu_freq() -> Option<(usize, usize)> {
    let mut top_max_freq = 0;
    let mut avg_base_freq = 0;
    let mut nr_cpus = 0;
    let cpu_paths = glob("/sys/devices/system/cpu/cpu[0-9]*").ok()?;
    for cpu_path in cpu_paths.filter_map(Result::ok) {
        let freq_path = cpu_path.join("cpufreq");
        let max_freq = read_file_usize(&freq_path.join("scaling_max_freq")).unwrap_or(0);
        let base_freq = read_file_usize(&freq_path.join("base_frequency")).unwrap_or(max_freq);
        if base_freq > 0 {
            if max_freq > top_max_freq {
                top_max_freq = max_freq;
            }
            avg_base_freq += base_freq;
            nr_cpus += 1;
        }
    }
    if avg_base_freq == 0 {
        return None;
    }
    Some((avg_base_freq / nr_cpus, top_max_freq))
}

fn create_gpus() -> BTreeMap<usize, Vec<Gpu>> {
    let mut gpus: BTreeMap<usize, Vec<Gpu>> = BTreeMap::new();

    // Don't fail if the system has no NVIDIA GPUs.
    let Ok(nvml) = Nvml::init_with_flags(InitFlags::NO_GPUS) else {
        return BTreeMap::new();
    };
    match nvml.device_count() {
        Ok(nvidia_gpu_count) => {
            for i in 0..nvidia_gpu_count {
                let Ok(nvidia_gpu) = nvml.device_by_index(i) else {
                    continue;
                };
                let graphics_boost_clock = nvidia_gpu
                    .max_customer_boost_clock(Clock::Graphics)
                    .unwrap_or(0);
                let sm_boost_clock = nvidia_gpu.max_customer_boost_clock(Clock::SM).unwrap_or(0);
                let Ok(memory_info) = nvidia_gpu.memory_info() else {
                    continue;
                };
                let Ok(pci_info) = nvidia_gpu.pci_info() else {
                    continue;
                };
                let Ok(index) = nvidia_gpu.index() else {
                    continue;
                };

                // The NVML library doesn't return a PCIe bus ID compatible with sysfs. It includes
                // uppercase bus ID values and an extra four leading 0s.
                let bus_id = pci_info.bus_id.to_lowercase();
                let fixed_bus_id = bus_id.strip_prefix("0000").unwrap_or("");
                let numa_path = format!("/sys/bus/pci/devices/{}/numa_node", fixed_bus_id);
                let numa_node = read_file_usize(&Path::new(&numa_path)).unwrap_or(0);

                let gpu = Gpu {
                    index: GpuIndex::Nvidia { nvml_id: index },
                    node_id: numa_node as usize,
                    max_graphics_clock: graphics_boost_clock as usize,
                    max_sm_clock: sm_boost_clock as usize,
                    memory: memory_info.total,
                };
                if !gpus.contains_key(&numa_node) {
                    gpus.insert(numa_node, vec![gpu]);
                    continue;
                }
                if let Some(gpus) = gpus.get_mut(&numa_node) {
                    gpus.push(gpu);
                }
            }
        }
        _ => {}
    };

    gpus
}

fn create_default_node(online_mask: &Cpumask) -> Result<Vec<Node>> {
    let mut nodes: Vec<Node> = Vec::with_capacity(1);
    let system_gpus = create_gpus();
    let mut node_gpus = BTreeMap::new();
    match system_gpus.get(&0) {
        Some(gpus) => {
            for gpu in gpus {
                node_gpus.insert(gpu.index, gpu.clone());
            }
        }
        _ => {}
    };

    let mut node = Node {
        id: 0,
        llcs: BTreeMap::new(),
        span: Cpumask::new()?,
        gpus: node_gpus,
    };

    if !Path::new("/sys/devices/system/cpu").exists() {
        bail!("/sys/devices/system/cpu sysfs node not found");
    }

    let avg_cpu_freq = avg_cpu_freq();
    let cpu_ids = read_cpu_ids()?;
    for cpu_id in cpu_ids.iter() {
        create_insert_cpu(*cpu_id, &mut node, &online_mask, avg_cpu_freq)?;
    }

    nodes.push(node);

    Ok(nodes)
}

fn create_numa_nodes(online_mask: &Cpumask) -> Result<Vec<Node>> {
    let mut nodes: Vec<Node> = Vec::new();

    let system_gpus = create_gpus();

    let numa_paths = glob("/sys/devices/system/node/node*")?;
    for numa_path in numa_paths.filter_map(Result::ok) {
        let numa_str = numa_path.to_str().unwrap().trim();
        let node_id = match sscanf!(numa_str, "/sys/devices/system/node/node{usize}") {
            Ok(val) => val,
            Err(_) => {
                bail!("Failed to parse NUMA node ID {}", numa_str);
            }
        };

        let mut node_gpus = BTreeMap::new();
        match system_gpus.get(&node_id) {
            Some(gpus) => {
                for gpu in gpus {
                    node_gpus.insert(gpu.index, gpu.clone());
                }
            }
            _ => {}
        };

        let mut node = Node {
            id: node_id,
            llcs: BTreeMap::new(),
            span: Cpumask::new()?,
            gpus: node_gpus,
        };

        let cpu_pattern = numa_path.join("cpu[0-9]*");
        let cpu_paths = glob(cpu_pattern.to_string_lossy().as_ref())?;
        let avg_cpu_freq = avg_cpu_freq();
        for cpu_path in cpu_paths.filter_map(Result::ok) {
            let cpu_str = cpu_path.to_str().unwrap().trim();
            let cpu_id = match sscanf!(cpu_str, "/sys/devices/system/node/node{usize}/cpu{usize}") {
                Ok((_, val)) => val,
                Err(_) => {
                    bail!("Failed to parse cpu ID {}", cpu_str);
                }
            };

            create_insert_cpu(cpu_id, &mut node, &online_mask, avg_cpu_freq)?;
        }

        nodes.push(node);
    }
    Ok(nodes)
}
