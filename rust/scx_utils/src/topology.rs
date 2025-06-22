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

use crate::compat::ROOT_PREFIX;
use crate::cpumask::read_cpulist;
use crate::misc::read_file_byte;
use crate::misc::read_file_usize_vec;
use crate::misc::read_from_file;
use crate::Cpumask;
use anyhow::bail;
use anyhow::Result;
use glob::glob;
use log::warn;
use sscanf::sscanf;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

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
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CoreType {
    Big { turbo: bool },
    Little,
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Cpu {
    pub id: usize,
    pub min_freq: usize,
    pub max_freq: usize,
    /// Base operational frqeuency. Only available on Intel Turbo Boost
    /// CPUs. If not available, this will simply return maximum frequency.
    pub base_freq: usize,
    /// The best-effort guessing of cpu_capacity scaled to 1024.
    pub cpu_capacity: usize,
    pub smt_level: usize,
    /// CPU idle resume latency
    pub pm_qos_resume_latency_us: usize,
    pub trans_lat_ns: usize,
    pub l2_id: usize,
    pub l3_id: usize,
    /// Per-CPU cache size of all levels.
    pub cache_size: usize,
    pub core_type: CoreType,

    /// Ancestor IDs.
    pub core_id: usize,
    pub llc_id: usize,
    pub node_id: usize,
    pub package_id: usize,
    pub cluster_id: isize,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Core {
    /// Monotonically increasing unique id
    pub id: usize,
    /// The sysfs value of core_id
    pub kernel_id: usize,
    pub cluster_id: isize,
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
    pub distance: Vec<usize>,
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
    /// True if SMT is enabled in the system, false otherwise.
    pub smt_enabled: bool,

    /// Skip indices to access lower level members easily.
    pub all_llcs: BTreeMap<usize, Arc<Llc>>,
    pub all_cores: BTreeMap<usize, Arc<Core>>,
    pub all_cpus: BTreeMap<usize, Arc<Cpu>>,
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
                    let core_mut = Arc::get_mut(core).unwrap();
                    let smt_level = core_mut.cpus.len();

                    for (&cpu_id, cpu) in core_mut.cpus.iter_mut() {
                        let cpu_mut = Arc::get_mut(cpu).unwrap();
                        cpu_mut.smt_level = smt_level;

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
            smt_enabled: is_smt_active().unwrap_or(false),
            all_llcs: topo_llcs,
            all_cores: topo_cores,
            all_cpus: topo_cpus,
        })
    }

    /// Build a complete host Topology
    pub fn new() -> Result<Topology> {
        let span = cpus_online()?;
        let mut topo_ctx = TopoCtx::new();
        // If the kernel is compiled with CONFIG_NUMA, then build a topology
        // from the NUMA hierarchy in sysfs. Otherwise, just make a single
        // default node of ID 0 which contains all cores.
        let path = format!("{}/sys/devices/system/node", *ROOT_PREFIX);
        let nodes = if Path::new(&path).exists() {
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
    let path = format!("{}/sys/devices/system/cpu/online", *ROOT_PREFIX);
    let online = std::fs::read_to_string(path)?;
    Cpumask::from_cpulist(&online)
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
    let id = read_from_file(&cache_level_path.join("id")).unwrap_or(usize::MAX);
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

fn get_per_cpu_cache_size(cache_path: &PathBuf) -> Result<usize> {
    let path_str = cache_path.to_str().unwrap();
    let paths = glob(&(path_str.to_owned() + "/index[0-9]*"))?;
    let mut tot_size = 0;

    for index in paths.filter_map(Result::ok) {
        // If there is no size information under sysfs (e.g., many ARM SoCs),
        // give 1024 as a default value. 1024 is small enough compared to the
        // real cache size of the CPU, but it is large enough to give a penalty
        // when multiple CPUs share the cache.
        let size = read_file_byte(&index.join("size")).unwrap_or(1024_usize);
        let cpulist: String = read_from_file(&index.join("shared_cpu_list"))?;
        let num_cpus = read_cpulist(&cpulist)?.len();
        tot_size += size / num_cpus;
    }

    Ok(tot_size)
}

#[allow(clippy::too_many_arguments)]
fn create_insert_cpu(
    id: usize,
    node: &mut Node,
    online_mask: &Cpumask,
    topo_ctx: &mut TopoCtx,
    cs: &CapacitySource,
    flatten_llc: bool,
) -> Result<()> {
    // CPU is offline. The Topology hierarchy is read-only, and assumes
    // that hotplug will cause the scheduler to restart. Thus, we can
    // just skip this CPU altogether.
    if !online_mask.test_cpu(id) {
        return Ok(());
    }

    let cpu_str = format!("{}/sys/devices/system/cpu/cpu{}", *ROOT_PREFIX, id);
    let cpu_path = Path::new(&cpu_str);

    // Physical core ID
    let top_path = cpu_path.join("topology");
    let core_kernel_id = read_from_file(&top_path.join("core_id"))?;
    let package_id = read_from_file(&top_path.join("physical_package_id"))?;
    let cluster_id = read_from_file(&top_path.join("cluster_id"))?;

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

    // Per-CPU cache size
    let cache_size = get_per_cpu_cache_size(&cache_path).unwrap_or(0_usize);

    // Min and max frequencies. If the kernel is not compiled with
    // CONFIG_CPU_FREQ, just assume 0 for both frequencies.
    let freq_path = cpu_path.join("cpufreq");
    let min_freq = read_from_file(&freq_path.join("scaling_min_freq")).unwrap_or(0_usize);
    let max_freq = read_from_file(&freq_path.join("scaling_max_freq")).unwrap_or(0_usize);
    let base_freq = read_from_file(&freq_path.join("base_frequency")).unwrap_or(max_freq);
    let trans_lat_ns =
        read_from_file(&freq_path.join("cpuinfo_transition_latency")).unwrap_or(0_usize);

    // Cpu capacity
    let cap_path = cpu_path.join(cs.suffix.clone());
    let rcap = read_from_file(&cap_path).unwrap_or(cs.max_rcap);
    let cpu_capacity = (rcap * 1024) / cs.max_rcap;

    // Power management
    let power_path = cpu_path.join("power");
    let pm_qos_resume_latency_us =
        read_from_file(&power_path.join("pm_qos_resume_latency_us")).unwrap_or(0_usize);

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

    let core_type = if cs.avg_rcap < cs.max_rcap && rcap == cs.max_rcap {
        CoreType::Big { turbo: true }
    } else if !cs.has_biglittle || rcap >= cs.avg_rcap {
        CoreType::Big { turbo: false }
    } else {
        CoreType::Little
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
            cpu_capacity,
            smt_level: 0, // Will be initialized at instantiate().
            pm_qos_resume_latency_us,
            trans_lat_ns,
            l2_id,
            l3_id,
            cache_size,
            core_type: core_type.clone(),

            core_id: *core_id,
            llc_id: *llc_id,
            node_id: node.id,
            package_id,
            cluster_id,
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
    let path = format!("{}/sys/devices/system/cpu/cpu[0-9]*", *ROOT_PREFIX);
    let cpu_paths = glob(&path)?;
    for cpu_path in cpu_paths.filter_map(Result::ok) {
        let cpu_str = cpu_path.to_str().unwrap().trim();
        if *ROOT_PREFIX == "" {
            match sscanf!(cpu_str, "/sys/devices/system/cpu/cpu{usize}") {
                Ok(val) => cpu_ids.push(val),
                Err(_) => {
                    bail!("Failed to parse cpu ID {}", cpu_str);
                }
            }
        } else {
            match sscanf!(cpu_str, "{str}/sys/devices/system/cpu/cpu{usize}") {
                Ok((_, val)) => cpu_ids.push(val),
                Err(_) => {
                    bail!("Failed to parse cpu ID {}", cpu_str);
                }
            }
        }
    }
    cpu_ids.sort();
    Ok(cpu_ids)
}

struct CapacitySource {
    /// Path suffix after /sys/devices/system/cpu/cpuX
    suffix: String,
    /// Average raw capacity value
    avg_rcap: usize,
    /// Maximum raw capacity value
    max_rcap: usize,
    /// Does a system have little cores?
    has_biglittle: bool,
}

fn get_capacity_source() -> Option<CapacitySource> {
    // Sources for guessing cpu_capacity under /sys/devices/system/cpu/cpuX.
    // They should be ordered from the most precise to the least precise.
    let sources = [
        "cpufreq/amd_pstate_prefcore_ranking",
        "cpufreq/amd_pstate_highest_perf",
        "acpi_cppc/highest_perf",
        "cpu_capacity",
        "cpufreq/cpuinfo_max_freq",
    ];

    // Find the most precise source for cpu_capacity estimation.
    let prefix = format!("{}/sys/devices/system/cpu/cpu0", *ROOT_PREFIX);
    let mut raw_capacity;
    let mut suffix = sources[sources.len() - 1];
    'outer: for src in sources {
        let path_str = [prefix.clone(), src.to_string()].join("/");
        let path = Path::new(&path_str);
        raw_capacity = read_from_file(&path).unwrap_or(0_usize);
        if raw_capacity > 0 {
            // It would be an okay source...
            suffix = src;
            // But double-check if the source has meaningful information.
            let path = format!("{}/sys/devices/system/cpu/cpu[0-9]*", *ROOT_PREFIX);
            let cpu_paths = glob(&path).ok()?;
            for cpu_path in cpu_paths.filter_map(Result::ok) {
                let raw_capacity2 = read_from_file(&cpu_path.join(suffix)).unwrap_or(0_usize);
                if raw_capacity != raw_capacity2 {
                    break 'outer;
                }
            }
            // The source exists, but it tells that all CPUs have the same
            // capacity. Let's search more if there is any source that can
            // tell the capacity differences among CPUs. This can happen when
            // a buggy driver lies (e.g., "acpi_cppc/highest_perf").
        }
    }

    // Find the max raw_capacity value for scaling to 1024.
    let mut max_rcap = 0;
    let mut min_rcap = usize::MAX;
    let mut avg_rcap = 0;
    let mut nr_cpus = 0;
    let mut has_biglittle = false;
    let path = format!("{}/sys/devices/system/cpu/cpu[0-9]*", *ROOT_PREFIX);
    let cpu_paths = glob(&path).ok()?;
    for cpu_path in cpu_paths.filter_map(Result::ok) {
        let rcap = read_from_file(&cpu_path.join(suffix)).unwrap_or(0_usize);
        if max_rcap < rcap {
            max_rcap = rcap;
        }
        if min_rcap > rcap {
            min_rcap = rcap;
        }
        avg_rcap += rcap;
        nr_cpus += 1;
    }

    if nr_cpus == 0 || max_rcap == 0 {
        suffix = "";
        avg_rcap = 1024;
        max_rcap = 1024;
        warn!("CPU capacity information is not available under sysfs.");
    } else {
        avg_rcap /= nr_cpus;
        // We consider a system to have a heterogeneous CPU architecture only
        // when there is a significant capacity gap (e.g., 1.3x). CPU capacities
        // can still vary in a homogeneous architecture—for instance, due to
        // chip binning or when only a subset of CPUs supports turbo boost.
        //
        // Note that we need a more systematic approach to accurately detect
        // big/LITTLE architectures across various SoC designs. The current
        // approach, with a significant capacity difference, is somewhat ad-hoc.
        has_biglittle = max_rcap as f32 >= (1.3 * min_rcap as f32);
    }

    Some(CapacitySource {
        suffix: suffix.to_string(),
        avg_rcap,
        max_rcap,
        has_biglittle,
    })
}

fn is_smt_active() -> Option<bool> {
    let path = format!("{}/sys/devices/system/cpu/smt/active", *ROOT_PREFIX);
    let smt_on: u8 = read_from_file(Path::new(&path)).ok()?;
    Some(smt_on == 1)
}

fn create_default_node(
    online_mask: &Cpumask,
    topo_ctx: &mut TopoCtx,
    flatten_llc: bool,
) -> Result<BTreeMap<usize, Node>> {
    let mut nodes = BTreeMap::<usize, Node>::new();

    let mut node = Node {
        id: 0,
        distance: vec![],
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

    let path = format!("{}/sys/devices/system/cpu", *ROOT_PREFIX);
    if !Path::new(&path).exists() {
        bail!("/sys/devices/system/cpu sysfs node not found");
    }

    let cs = get_capacity_source().unwrap();
    let cpu_ids = read_cpu_ids()?;
    for cpu_id in cpu_ids.iter() {
        create_insert_cpu(*cpu_id, &mut node, online_mask, topo_ctx, &cs, flatten_llc)?;
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

    let path = format!("{}/sys/devices/system/node/node*", *ROOT_PREFIX);
    let numa_paths = glob(&path)?;
    for numa_path in numa_paths.filter_map(Result::ok) {
        let numa_str = numa_path.to_str().unwrap().trim();
        let node_id = if *ROOT_PREFIX == "" {
            match sscanf!(numa_str, "/sys/devices/system/node/node{usize}") {
                Ok(val) => val,
                Err(_) => {
                    bail!("Failed to parse NUMA node ID {}", numa_str);
                }
            }
        } else {
            match sscanf!(numa_str, "{str}/sys/devices/system/node/node{usize}") {
                Ok((_, val)) => val,
                Err(_) => {
                    bail!("Failed to parse NUMA node ID {}", numa_str);
                }
            }
        };

        let distance = read_file_usize_vec(
            Path::new(&format!(
                "{}/sys/devices/system/node/node{}/distance",
                *ROOT_PREFIX, node_id
            )),
            ' ',
        )?;
        let mut node = Node {
            id: node_id,
            distance,
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
        let cs = get_capacity_source().unwrap();
        let mut cpu_ids = vec![];
        for cpu_path in cpu_paths.filter_map(Result::ok) {
            let cpu_str = cpu_path.to_str().unwrap().trim();
            let cpu_id = if *ROOT_PREFIX == "" {
                match sscanf!(cpu_str, "/sys/devices/system/node/node{usize}/cpu{usize}") {
                    Ok((_, val)) => val,
                    Err(_) => {
                        bail!("Failed to parse cpu ID {}", cpu_str);
                    }
                }
            } else {
                match sscanf!(
                    cpu_str,
                    "{str}/sys/devices/system/node/node{usize}/cpu{usize}"
                ) {
                    Ok((_, _, val)) => val,
                    Err(_) => {
                        bail!("Failed to parse cpu ID {}", cpu_str);
                    }
                }
            };
            cpu_ids.push(cpu_id);
        }
        cpu_ids.sort();

        for cpu_id in cpu_ids {
            create_insert_cpu(cpu_id, &mut node, online_mask, topo_ctx, &cs, false)?;
        }

        nodes.insert(node.id, node);
    }
    Ok(nodes)
}
