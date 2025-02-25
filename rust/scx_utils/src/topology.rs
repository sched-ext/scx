// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! # SCX Topology
//!
//! A crate that allows schedulers to inspect and model the host's topology, in
//! service of creating scheduling domains.
//!
//! A Topology is comprised of one or more Node objects, which themselves are
//! comprised hierarchically of LLC -> Core -> Cpu objects respectively:
//!```rust,ignore
//!                                   Topology
//!                                       |
//! o--------------------------------o   ...   o----------------o---------------o
//! |         Node                   |         |         Node                   |
//! | ID      0                      |         | ID      1                      |
//! | LLCs    <id, Llc>              |         | LLCs    <id, Llc>              |
//! | Span    0x00000fffff00000fffff |         | Span    0xfffff00000fffff00000 |
//! o--------------------------------o         o--------------------------------o
//!                 \
//!                  --------------------
//!                                      \
//! o--------------------------------o   ...   o--------------------------------o
//! |             Llc                |         |             Llc                |
//! | ID     0                       |         | ID     1                       |
//! | Cores  <id, Core>              |         | Cores  <id, Core>              |
//! | Span   0x00000ffc0000000ffc00  |         | Span   0x00000003ff00000003ff  |
//! o--------------------------------o         o----------------o---------------o
//!                                                             /
//!                                        ---------------------
//!                                       /
//! o--------------------------------o   ...   o--------------------------------o
//! |              Core              |         |              Core              |
//! | ID     0                       |         | ID     9                       |
//! | Cpus   <id, Cpu>               |         | Cpus   <id, Cpu>               |
//! | Span   0x00000000010000000001  |         | Span   0x00000002000000000200  |
//! o--------------------------------o         o----------------o---------------o
//!                                                             /
//!                                        ---------------------
//!                                       /
//! o--------------------------------o   ...   o---------------------------------o
//! |              Cpu               |         |               Cpu               |
//! | ID       9                     |         | ID       49                     |
//! | online   1                     |         | online   1                      |
//! | min_freq 400000                |         | min_freq 400000                 |
//! | max_freq 5881000               |         | min_freq 5881000                |
//! o--------------------------------o         o---------------------------------o
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

use crate::misc::read_file_usize;
use crate::Cpumask;
use anyhow::bail;
use anyhow::Result;
use glob::glob;
use sscanf::sscanf;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "gpu-topology")]
use crate::gpu::{create_gpus, Gpu, GpuIndex};

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

    /// Whether AMD preferred core ranking is enabled on this system
    pub static ref HAS_PREF_RANK: bool = has_pref_rank();
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CoreType {
    Big { turbo: bool },
    Little,
}

#[derive(Debug)]
pub struct Cpu {
    pub id: usize,
    pub min_freq: usize,
    pub max_freq: usize,
    /// Base operational frqeuency. Only available on Intel Turbo Boost
    /// CPUs. If not available, this will simply return maximum frequency.
    pub base_freq: usize,
    pub trans_lat_ns: usize,
    pub l2_id: usize,
    pub l3_id: usize,
    pub core_type: CoreType,

    /// Ancestor IDs.
    pub core_id: usize,
    pub llc_id: usize,
    pub node_id: usize,
    pub package_id: usize,
    pub cluster_id: usize,
    rank: AtomicU32,
}

impl Clone for Cpu {
    fn clone(&self) -> Self {
        Cpu {
            id: self.id,
            min_freq: self.min_freq,
            max_freq: self.max_freq,
            base_freq: self.base_freq,
            trans_lat_ns: self.trans_lat_ns,
            l2_id: self.l2_id,
            l3_id: self.l3_id,
            core_type: self.core_type.clone(),
            core_id: self.core_id,
            llc_id: self.llc_id,
            node_id: self.node_id,
            package_id: self.package_id,
            cluster_id: self.cluster_id,
            rank: AtomicU32::new(self.rank.load(Ordering::Relaxed)),
        }
    }
}

impl PartialEq for Cpu {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.min_freq == other.min_freq
            && self.max_freq == other.max_freq
            && self.base_freq == other.base_freq
            && self.trans_lat_ns == other.trans_lat_ns
            && self.l2_id == other.l2_id
            && self.l3_id == other.l3_id
            && self.core_type == other.core_type
            && self.core_id == other.core_id
            && self.llc_id == other.llc_id
            && self.node_id == other.node_id
            && self.package_id == other.package_id
            && self.cluster_id == other.cluster_id
            && self.rank() == other.rank()
    }
}

impl Eq for Cpu {}

impl PartialOrd for Cpu {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Cpu {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
            .then_with(|| self.min_freq.cmp(&other.min_freq))
            .then_with(|| self.max_freq.cmp(&other.max_freq))
            .then_with(|| self.base_freq.cmp(&other.base_freq))
            .then_with(|| self.trans_lat_ns.cmp(&other.trans_lat_ns))
            .then_with(|| self.l2_id.cmp(&other.l2_id))
            .then_with(|| self.l3_id.cmp(&other.l3_id))
            .then_with(|| self.core_type.cmp(&other.core_type))
            .then_with(|| self.core_id.cmp(&other.core_id))
            .then_with(|| self.llc_id.cmp(&other.llc_id))
            .then_with(|| self.node_id.cmp(&other.node_id))
            .then_with(|| self.package_id.cmp(&other.package_id))
            .then_with(|| self.cluster_id.cmp(&other.cluster_id))
            .then_with(|| self.rank().cmp(&other.rank()))
    }
}

impl std::hash::Hash for Cpu {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.min_freq.hash(state);
        self.max_freq.hash(state);
        self.base_freq.hash(state);
        self.trans_lat_ns.hash(state);
        self.l2_id.hash(state);
        self.l3_id.hash(state);
        self.core_type.hash(state);
        self.core_id.hash(state);
        self.llc_id.hash(state);
        self.node_id.hash(state);
        self.package_id.hash(state);
        self.cluster_id.hash(state);
        self.rank().hash(state);
    }
}

impl Cpu {
    /// Get the current rank value
    pub fn rank(&self) -> usize {
        self.rank.load(Ordering::Relaxed) as usize
    }
    
    /// Set the rank value
    pub fn set_rank(&self, rank: usize) {
        self.rank.store(rank as u32, Ordering::Relaxed);
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Core {
    /// Monotonically increasing unique id
    pub id: usize,
    /// The sysfs value of core_id
    pub kernel_id: usize,
    pub cluster_id: usize,
    pub cpus: BTreeMap<usize, Arc<Cpu>>,
    /// Cpumask of all CPUs in this core.
    pub span: Cpumask,
    pub core_type: CoreType,

    /// Ancestor IDs.
    pub llc_id: usize,
    pub node_id: usize,
}

#[derive(Debug, Clone)]
pub struct Llc {
    /// Monotonically increasing unique id
    pub id: usize,
    /// The kernel id of the llc
    pub kernel_id: usize,
    pub cores: BTreeMap<usize, Arc<Core>>,
    /// Cpumask of all CPUs in this llc.
    pub span: Cpumask,

    /// Ancestor IDs.
    pub node_id: usize,

    /// Skip indices to access lower level members easily.
    pub all_cpus: BTreeMap<usize, Arc<Cpu>>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub id: usize,
    pub llcs: BTreeMap<usize, Arc<Llc>>,
    /// Cpumask of all CPUs in this node.
    pub span: Cpumask,

    /// Skip indices to access lower level members easily.
    pub all_cores: BTreeMap<usize, Arc<Core>>,
    pub all_cpus: BTreeMap<usize, Arc<Cpu>>,

    #[cfg(feature = "gpu-topology")]
    pub gpus: BTreeMap<GpuIndex, Gpu>,
}

#[derive(Debug)]
pub struct Topology {
    pub nodes: BTreeMap<usize, Node>,
    /// Cpumask all CPUs in the system.
    pub span: Cpumask,

    /// Skip indices to access lower level members easily.
    pub all_llcs: BTreeMap<usize, Arc<Llc>>,
    pub all_cores: BTreeMap<usize, Arc<Core>>,
    pub all_cpus: BTreeMap<usize, Arc<Cpu>>,

    /// Cached list of ranked CPUs
    ranked_cpus: Mutex<Arc<RankedCpuCache>>,
}

const RANKED_CPU_CACHE_DURATION: Duration = Duration::from_secs(10);

/// Cached list of ranked CPUs
#[derive(Debug, Clone)]
pub struct RankedCpuCache {
    /// List of CPU IDs sorted by their ranking (highest to lowest)
    pub cpu_ids: Vec<usize>,
    /// When this cache was last updated
    pub last_updated: Instant,
    /// Generation number that increments each time the order changes
    pub generation: u64,
}

impl RankedCpuCache {
    pub fn new() -> Self {
        Self {
            cpu_ids: Vec::new(),
            last_updated: Instant::now() - RANKED_CPU_CACHE_DURATION,
            generation: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.last_updated.elapsed() < RANKED_CPU_CACHE_DURATION
    }
}

impl Topology {
    fn instantiate(span: Cpumask, mut nodes: BTreeMap<usize, Node>) -> Result<Self> {
        // Build skip indices prefixed with all_ for easy lookups. As Arc
        // objects can only be modified while there's only one reference,
        // skip indices must be built from bottom to top.
        let mut topo_llcs = BTreeMap::new();
        let mut topo_cores = BTreeMap::new();
        let mut topo_cpus = BTreeMap::new();

        for (_node_id, node) in nodes.iter_mut() {
            let mut node_cores = BTreeMap::new();
            let mut node_cpus = BTreeMap::new();

            for (&llc_id, llc) in node.llcs.iter_mut() {
                let llc_mut = Arc::get_mut(llc).unwrap();
                let mut llc_cpus = BTreeMap::new();

                for (&core_id, core) in llc_mut.cores.iter_mut() {
                    for (&cpu_id, cpu) in core.cpus.iter() {
                        if topo_cpus
                            .insert(cpu_id, cpu.clone())
                            .or(node_cpus.insert(cpu_id, cpu.clone()))
                            .or(llc_cpus.insert(cpu_id, cpu.clone()))
                            .is_some()
                        {
                            bail!("Duplicate CPU ID {}", cpu_id);
                        }
                    }

                    // Note that in some weird architectures, core ids can be
                    // duplicated in different LLC domains.
                    topo_cores
                        .insert(core_id, core.clone())
                        .or(node_cores.insert(core_id, core.clone()));
                }

                llc_mut.all_cpus = llc_cpus;

                if topo_llcs.insert(llc_id, llc.clone()).is_some() {
                    bail!("Duplicate LLC ID {}", llc_id);
                }
            }

            node.all_cores = node_cores;
            node.all_cpus = node_cpus;
        }

        Ok(Topology {
            nodes,
            span,
            all_llcs: topo_llcs,
            all_cores: topo_cores,
            all_cpus: topo_cpus,
            ranked_cpus: Mutex::new(Arc::new(RankedCpuCache::new())),
        })
    }

    /// Build a complete host Topology
    pub fn new() -> Result<Topology> {
        let span = cpus_online()?;
        let mut topo_ctx = TopoCtx::new();
        // If the kernel is compiled with CONFIG_NUMA, then build a topology
        // from the NUMA hierarchy in sysfs. Otherwise, just make a single
        // default node of ID 0 which contains all cores.
        let nodes = if Path::new("/sys/devices/system/node").exists() {
            create_numa_nodes(&span, &mut topo_ctx)?
        } else {
            create_default_node(&span, &mut topo_ctx, false)?
        };

        Self::instantiate(span, nodes)
    }

    pub fn with_flattened_llc_node() -> Result<Topology> {
        let span = cpus_online()?;
        let mut topo_ctx = TopoCtx::new();
        let nodes = create_default_node(&span, &mut topo_ctx, true)?;
        Self::instantiate(span, nodes)
    }

    /// Get a vec of all GPUs on the hosts.
    #[cfg(feature = "gpu-topology")]
    pub fn gpus(&self) -> BTreeMap<GpuIndex, &Gpu> {
        let mut gpus = BTreeMap::new();
        for node in self.nodes.values() {
            for (idx, gpu) in &node.gpus {
                gpus.insert(*idx, gpu);
            }
        }
        gpus
    }

    /// Returns whether the Topology has a hybrid architecture of big and little cores.
    pub fn has_little_cores(&self) -> bool {
        self.all_cores
            .values()
            .any(|c| c.core_type == CoreType::Little)
    }

    /// Returns a vector that maps the index of each logical CPU to the
    /// sibling CPU. This represents the "next sibling" CPU within a package
    /// in systems that support SMT. The sibling CPU is the other logical
    /// CPU that shares the physical resources of the same physical core.
    ///
    /// Assuming each core holds exactly at most two cpus.
    pub fn sibling_cpus(&self) -> Vec<i32> {
        let mut sibling_cpu = vec![-1i32; *NR_CPUS_POSSIBLE];
        for core in self.all_cores.values() {
            let mut first = -1i32;
            for &cpu in core.cpus.keys() {
                if first < 0 {
                    first = cpu as i32;
                } else {
                    sibling_cpu[first as usize] = cpu as i32;
                    sibling_cpu[cpu] = first;
                    break;
                }
            }
        }
        sibling_cpu
    }

    /// Returns true if cpu_a has a higher rank than cpu_b.
    /// If ranking is not enabled or either CPU is invalid, returns false.
    pub fn is_higher_ranked(&self, cpu_a: usize, cpu_b: usize) -> bool {
        if !*HAS_PREF_RANK {
            return false;
        }

        let cpu_a_rank = self.all_cpus.get(&cpu_a).map(|cpu| cpu.rank());
        let cpu_b_rank = self.all_cpus.get(&cpu_b).map(|cpu| cpu.rank());

        match (cpu_a_rank, cpu_b_rank) {
            (Some(rank_a), Some(rank_b)) => rank_a > rank_b,
            _ => false,
        }
    }

    /// Returns the cached ranked CPU list.
    /// The list is cached internally and refreshed every 10 seconds.
    /// If preferred core ranking is not enabled, returns an empty cache.
    pub fn get_ranked_cpus(&self) -> Arc<RankedCpuCache> {
        if !*HAS_PREF_RANK {
            return Arc::new(RankedCpuCache {
                cpu_ids: Vec::new(),
                last_updated: Instant::now(),
                generation: 0,
            });
        }

        let mut cache = self.ranked_cpus.lock().unwrap();
        if !cache.is_valid() {
            let mut cpu_ranks: Vec<(usize, usize)> = Vec::new();

            for &cpu_id in self.all_cpus.keys() {
                let cpu_path = Path::new("/sys/devices/system/cpu")
                    .join(format!("cpu{}", cpu_id))
                    .join("cpufreq");

                if let Ok(rank) = read_file_usize(&cpu_path.join("amd_pstate_prefcore_ranking")) {
                    // Update the rank directly in the CPU object
                    if let Some(cpu) = self.all_cpus.get(&cpu_id) {
                        cpu.set_rank(rank);
                    }
                    cpu_ranks.push((cpu_id, rank));
                }
            }

            cpu_ranks.sort_by(|a, b| {
                let a_val = a.1;
                let b_val = b.1;
                b_val.cmp(&a_val).then_with(|| a.0.cmp(&b.0))
            });

            let inner = Arc::make_mut(&mut *cache);
            inner.cpu_ids.clear();
            inner.cpu_ids.extend(cpu_ranks.iter().map(|(id, _)| *id));
            inner.last_updated = Instant::now();
            inner.generation += 1;
        }

        Arc::clone(&cache)
    }
}

/******************************************************
 * Helper structs/functions for creating the Topology *
 ******************************************************/
/// TopoCtx is a helper struct used to build a topology.
struct TopoCtx {
    /// Mapping of NUMA node core ids
    node_core_kernel_ids: BTreeMap<(usize, usize, usize), usize>,
    /// Mapping of NUMA node LLC ids
    node_llc_kernel_ids: BTreeMap<(usize, usize, usize), usize>,
    /// Mapping of L2 ids
    l2_ids: BTreeMap<String, usize>,
    /// Mapping of L3 ids
    l3_ids: BTreeMap<String, usize>,
}

impl TopoCtx {
    fn new() -> TopoCtx {
        let core_kernel_ids = BTreeMap::new();
        let llc_kernel_ids = BTreeMap::new();
        let l2_ids = BTreeMap::new();
        let l3_ids = BTreeMap::new();
        TopoCtx {
            node_core_kernel_ids: core_kernel_ids,
            node_llc_kernel_ids: llc_kernel_ids,
            l2_ids,
            l3_ids,
        }
    }
}

fn cpus_online() -> Result<Cpumask> {
    let path = "/sys/devices/system/cpu/online";
    let online = std::fs::read_to_string(path)?;
    let online_groups: Vec<&str> = online.split(',').collect();
    let mut mask = Cpumask::new();
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

fn get_cache_id(topo_ctx: &mut TopoCtx, cache_level_path: &PathBuf, cache_level: usize) -> usize {
    // Check if the cache id is already cached
    let id_map = match cache_level {
        2 => &mut topo_ctx.l2_ids,
        3 => &mut topo_ctx.l3_ids,
        _ => return usize::MAX,
    };

    let path = &cache_level_path.join("shared_cpu_list");
    let key = match std::fs::read_to_string(path) {
        Ok(key) => key,
        Err(_) => return usize::MAX,
    };

    let id = *id_map.get(&key).unwrap_or(&usize::MAX);
    if id != usize::MAX {
        return id;
    }

    // In case of a cache miss, try to get the id from the sysfs first.
    let id = read_file_usize(&cache_level_path.join("id")).unwrap_or(usize::MAX);
    if id != usize::MAX {
        // Keep the id in the map
        id_map.insert(key, id);
        return id;
    }

    // If the id file does not exist, assign an id and keep it in the map.
    let id = id_map.len();
    id_map.insert(key, id);

    id
}

fn create_insert_cpu(
    id: usize,
    node: &mut Node,
    online_mask: &Cpumask,
    topo_ctx: &mut TopoCtx,
    big_little: bool,
    avg_cpu_freq: Option<(usize, usize)>,
    flatten_llc: bool,
) -> Result<()> {
    // CPU is offline. The Topology hierarchy is read-only, and assumes
    // that hotplug will cause the scheduler to restart. Thus, we can
    // just skip this CPU altogether.
    if !online_mask.test_cpu(id) {
        return Ok(());
    }

    let cpu_str = format!("/sys/devices/system/cpu/cpu{}", id);
    let cpu_path = Path::new(&cpu_str);

    // Physical core ID
    let top_path = cpu_path.join("topology");
    let core_kernel_id = read_file_usize(&top_path.join("core_id"))?;
    let package_id = read_file_usize(&top_path.join("physical_package_id"))?;
    let cluster_id = read_file_usize(&top_path.join("cluster_id"))?;

    // Evaluate L2, L3 and LLC cache IDs.
    //
    // Use ID 0 if we fail to detect the cache hierarchy. This seems to happen on certain SKUs, so
    // if there's no cache information then we have no option but to assume a single unified cache
    // per node.
    let cache_path = cpu_path.join("cache");
    let l2_id = get_cache_id(topo_ctx, &cache_path.join(format!("index{}", 2)), 2);
    let l3_id = get_cache_id(topo_ctx, &cache_path.join(format!("index{}", 3)), 3);
    let llc_kernel_id = if flatten_llc {
        0
    } else if l3_id == usize::MAX {
        l2_id
    } else {
        l3_id
    };

    // Min and max frequencies. If the kernel is not compiled with
    // CONFIG_CPU_FREQ, just assume 0 for both frequencies.
    let freq_path = cpu_path.join("cpufreq");
    let min_freq = read_file_usize(&freq_path.join("scaling_min_freq")).unwrap_or(0);
    let max_freq = read_file_usize(&freq_path.join("scaling_max_freq")).unwrap_or(0);
    let base_freq = read_file_usize(&freq_path.join("base_frequency")).unwrap_or(max_freq);
    let trans_lat_ns = read_file_usize(&freq_path.join("cpuinfo_transition_latency")).unwrap_or(0);

    let num_llcs = topo_ctx.node_llc_kernel_ids.len();
    let llc_id = topo_ctx
        .node_llc_kernel_ids
        .entry((node.id, package_id, llc_kernel_id))
        .or_insert(num_llcs);

    let llc = node.llcs.entry(*llc_id).or_insert(Arc::new(Llc {
        id: *llc_id,
        cores: BTreeMap::new(),
        span: Cpumask::new(),
        all_cpus: BTreeMap::new(),

        node_id: node.id,
        kernel_id: llc_kernel_id,
    }));
    let llc_mut = Arc::get_mut(llc).unwrap();

    let core_type = if !big_little {
        CoreType::Big { turbo: false }
    } else {
        match avg_cpu_freq {
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
        }
    };

    let num_cores = topo_ctx.node_core_kernel_ids.len();
    let core_id = topo_ctx
        .node_core_kernel_ids
        .entry((node.id, package_id, core_kernel_id))
        .or_insert(num_cores);

    let core = llc_mut.cores.entry(*core_id).or_insert(Arc::new(Core {
        id: *core_id,
        cpus: BTreeMap::new(),
        span: Cpumask::new(),
        core_type: core_type.clone(),

        llc_id: *llc_id,
        node_id: node.id,
        kernel_id: core_kernel_id,
        cluster_id: cluster_id,
    }));
    let core_mut = Arc::get_mut(core).unwrap();

    core_mut.cpus.insert(
        id,
        Arc::new(Cpu {
            id,
            min_freq,
            max_freq,
            base_freq,
            trans_lat_ns,
            l2_id,
            l3_id,
            core_type: core_type.clone(),

            core_id: *core_id,
            llc_id: *llc_id,
            node_id: node.id,
            package_id,
            cluster_id,
            rank: AtomicU32::new(0),
        }),
    );

    if node.span.test_cpu(id) {
        bail!("Node {} already had CPU {}", node.id, id);
    }

    // Update all of the devices' spans to include this CPU.
    core_mut.span.set_cpu(id)?;
    llc_mut.span.set_cpu(id)?;
    node.span.set_cpu(id)?;

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

fn has_big_little() -> Option<bool> {
    let mut clusters = std::collections::HashSet::new();

    let cpu_paths = glob("/sys/devices/system/cpu/cpu[0-9]*").ok()?;
    for cpu_path in cpu_paths.filter_map(Result::ok) {
        let top_path = cpu_path.join("topology");
        let cluster_id = read_file_usize(&top_path.join("cluster_id")).unwrap_or(0);
        clusters.insert(cluster_id);
    }

    Some(clusters.len() > 1)
}

fn create_default_node(
    online_mask: &Cpumask,
    topo_ctx: &mut TopoCtx,
    flatten_llc: bool,
) -> Result<BTreeMap<usize, Node>> {
    let mut nodes = BTreeMap::<usize, Node>::new();

    let mut node = Node {
        id: 0,
        llcs: BTreeMap::new(),
        span: Cpumask::new(),
        #[cfg(feature = "gpu-topology")]
        gpus: BTreeMap::new(),
        all_cores: BTreeMap::new(),
        all_cpus: BTreeMap::new(),
    };

    #[cfg(feature = "gpu-topology")]
    {
        let system_gpus = create_gpus();
        if let Some(gpus) = system_gpus.get(&0) {
            for gpu in gpus {
                node.gpus.insert(gpu.index, gpu.clone());
            }
        }
    }

    if !Path::new("/sys/devices/system/cpu").exists() {
        bail!("/sys/devices/system/cpu sysfs node not found");
    }

    let avg_cpu_freq = avg_cpu_freq();
    let big_little = has_big_little().unwrap_or(false);
    let cpu_ids = read_cpu_ids()?;
    for cpu_id in cpu_ids.iter() {
        create_insert_cpu(
            *cpu_id,
            &mut node,
            online_mask,
            topo_ctx,
            big_little,
            avg_cpu_freq,
            flatten_llc,
        )?;
    }

    nodes.insert(node.id, node);

    Ok(nodes)
}

fn create_numa_nodes(
    online_mask: &Cpumask,
    topo_ctx: &mut TopoCtx,
) -> Result<BTreeMap<usize, Node>> {
    let mut nodes = BTreeMap::<usize, Node>::new();

    #[cfg(feature = "gpu-topology")]
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

        let mut node = Node {
            id: node_id,
            llcs: BTreeMap::new(),
            span: Cpumask::new(),

            all_cores: BTreeMap::new(),
            all_cpus: BTreeMap::new(),

            #[cfg(feature = "gpu-topology")]
            gpus: BTreeMap::new(),
        };

        #[cfg(feature = "gpu-topology")]
        {
            if let Some(gpus) = system_gpus.get(&node_id) {
                for gpu in gpus {
                    node.gpus.insert(gpu.index, gpu.clone());
                }
            }
        }

        let cpu_pattern = numa_path.join("cpu[0-9]*");
        let cpu_paths = glob(cpu_pattern.to_string_lossy().as_ref())?;
        let big_little = has_big_little().unwrap_or(false);
        let avg_cpu_freq = avg_cpu_freq();
        for cpu_path in cpu_paths.filter_map(Result::ok) {
            let cpu_str = cpu_path.to_str().unwrap().trim();
            let cpu_id = match sscanf!(cpu_str, "/sys/devices/system/node/node{usize}/cpu{usize}") {
                Ok((_, val)) => val,
                Err(_) => {
                    bail!("Failed to parse cpu ID {}", cpu_str);
                }
            };

            create_insert_cpu(
                cpu_id,
                &mut node,
                online_mask,
                topo_ctx,
                big_little,
                avg_cpu_freq,
                false,
            )?;
        }

        nodes.insert(node.id, node);
    }
    Ok(nodes)
}

fn has_pref_rank() -> bool {
    if !Path::new("/sys/devices/system/cpu/amd_pstate/prefcore").exists() {
        return false;
    }
    match std::fs::read_to_string("/sys/devices/system/cpu/amd_pstate/prefcore") {
        Ok(contents) => contents.trim() == "enabled",
        Err(_) => false,
    }
}
