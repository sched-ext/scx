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
use crate::misc::find_best_split_size;
use crate::misc::read_file_byte;
use crate::misc::read_file_usize_vec;
use crate::misc::read_from_file;
use crate::Cpumask;
use anyhow::bail;
use anyhow::Result;
use glob::glob;
use log::info;
use log::warn;
use sscanf::sscanf;
use std::cmp::min;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
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

    /// The range to search for when finding the number of physical cores
    /// assigned to a partition to split a large number of cores that share
    /// an LLC domain. The suggested split for the cores isn't a function of
    /// the underlying hardware's capability, but rather some sane number
    /// to help determine the number of CPUs that share the same DSQ.
    pub static ref NR_PARTITION_MIN_CORES: usize = 2;
    pub static ref NR_PARTITION_MAX_CORES: usize = 8;
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
        Self::with_virt_llcs(None)
    }

    pub fn with_virt_llcs(nr_cores_per_vllc: Option<(usize, usize)>) -> Result<Topology> {
        let span = cpus_online()?;
        let mut topo_ctx = TopoCtx::new();

        // If the kernel is compiled with CONFIG_NUMA, then build a topology
        // from the NUMA hierarchy in sysfs. Otherwise, just make a single
        // default node of ID 0 which contains all cores.
        let path = format!("{}/sys/devices/system/node", *ROOT_PREFIX);
        let nodes = if Path::new(&path).exists() {
            create_numa_nodes(&span, &mut topo_ctx, nr_cores_per_vllc)?
        } else {
            create_default_node(&span, &mut topo_ctx, false, nr_cores_per_vllc)?
        };

        Self::instantiate(span, nodes)
    }

    pub fn with_flattened_llc_node() -> Result<Topology> {
        let span = cpus_online()?;
        let mut topo_ctx = TopoCtx::new();
        let nodes = create_default_node(&span, &mut topo_ctx, true, None)?;
        Self::instantiate(span, nodes)
    }

    /// Build a topology with configuration from CLI arguments.
    /// This method integrates with the TopologyArgs from the cli module to
    /// create a topology based on command line parameters.
    pub fn with_args(topology_args: &crate::cli::TopologyArgs) -> Result<Topology> {
        // Validate the CLI arguments first
        topology_args.validate()?;

        // Get the virtual LLC configuration
        let nr_cores_per_vllc = topology_args.get_nr_cores_per_vllc();

        // Build topology with the specified configuration
        Self::with_virt_llcs(nr_cores_per_vllc)
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

    /// Count how many physical cores have at least one CPU set in the cpumask.
    pub fn cpumask_nr_cores(&self, cpumask: &Cpumask) -> usize {
        let mut count = 0;
        for core in self.all_cores.values() {
            if core.cpus.keys().any(|&cpu_id| cpumask.test_cpu(cpu_id)) {
                count += 1;
            }
        }
        count
    }

    /// Format a cpumask as a topology-aware visual grid.
    ///
    /// Each physical core is represented by a single character:
    /// - `░` = no CPUs set
    /// - `▀` = first HT only (top half)
    /// - `▄` = second HT only (bottom half)
    /// - `█` = both HTs (or all HTs for >2-way SMT)
    ///
    /// Cores within an LLC are split into evenly-sized groups of at
    /// most 8 with spaces. LLCs are separated by `|`. Wrapping
    /// happens at LLC boundaries. One line per NUMA node (may wrap).
    pub fn format_cpumask_grid<W: Write>(
        &self,
        w: &mut W,
        cpumask: &Cpumask,
        indent: &str,
        max_width: usize,
    ) -> Result<()> {
        for node in self.nodes.values() {
            // Build the core characters for each LLC in this node.
            // Within each LLC, cores are grouped by 4 with spaces.
            let mut llc_segments: Vec<(usize, String)> = Vec::new();

            for llc in node.llcs.values() {
                let mut seg = String::new();
                let nr_cores = llc.cores.len();
                let nr_groups = (nr_cores + 7) / 8;
                let base = nr_cores / nr_groups;
                let rem = nr_cores % nr_groups;
                // First `rem` groups get base+1, rest get base
                let mut next_break = if rem > 0 { base + 1 } else { base };
                let mut group_idx = 0;
                for (i, core) in llc.cores.values().enumerate() {
                    if i > 0 && i == next_break {
                        seg.push(' ');
                        group_idx += 1;
                        next_break += if group_idx < rem { base + 1 } else { base };
                    }
                    let nr_cpus = core.cpus.len();
                    let cpu_ids: Vec<usize> = core.cpus.keys().copied().collect();
                    let nr_set: usize = cpu_ids.iter().filter(|&&c| cpumask.test_cpu(c)).count();

                    let ch = if nr_cpus == 1 {
                        if nr_set > 0 {
                            '█'
                        } else {
                            '░'
                        }
                    } else if nr_cpus == 2 {
                        let first_set = cpumask.test_cpu(cpu_ids[0]);
                        let second_set = cpumask.test_cpu(cpu_ids[1]);
                        match (first_set, second_set) {
                            (false, false) => '░',
                            (true, false) => '▀',
                            (false, true) => '▄',
                            (true, true) => '█',
                        }
                    } else {
                        // >2 HTs (e.g. 4-way SMT)
                        if nr_set == 0 {
                            '░'
                        } else if nr_set == nr_cpus {
                            '█'
                        } else {
                            '▄'
                        }
                    };
                    seg.push(ch);
                }
                llc_segments.push((llc.id, seg));
            }

            if llc_segments.is_empty() {
                continue;
            }

            // Build prefix: "N{id} L{first_llc}: "
            let first_llc_id = llc_segments[0].0;
            let prefix = format!("{}N{} L{:02}: ", indent, node.id, first_llc_id);
            let prefix_width = prefix.chars().count();
            let cont_indent =
                format!("{}{}", indent, " ".repeat(prefix_width - indent.chars().count()));

            // Join LLCs with "|", wrapping at LLC boundaries
            let mut line = prefix.clone();
            let mut first_llc = true;

            for (_, seg) in &llc_segments {
                let seg_width = seg.chars().count();
                let separator = if first_llc { "" } else { "|" };
                let sep_width = separator.chars().count();
                let current_line_width = line.chars().count();

                if !first_llc && current_line_width + sep_width + seg_width > max_width {
                    writeln!(w, "{}", line)?;
                    line = format!("{}{}", cont_indent, seg);
                } else {
                    line = format!("{}{}{}", line, separator, seg);
                }
                first_llc = false;
            }
            writeln!(w, "{}", line)?;
        }
        Ok(())
    }

    /// Format a cpumask header line with cpu count, core count, and range.
    pub fn format_cpumask_header(&self, cpumask: &Cpumask, min_cpus: u32, max_cpus: u32) -> String {
        let nr_cpus = cpumask.weight();
        let nr_cores = self.cpumask_nr_cores(cpumask);
        format!(
            "cpus={:3}({:3}c) [{:3},{:3}]",
            nr_cpus, nr_cores, min_cpus, max_cpus
        )
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

fn get_cache_id(topo_ctx: &mut TopoCtx, cache_level_path: &Path, cache_level: usize) -> usize {
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

fn get_per_cpu_cache_size(cache_path: &Path) -> Result<usize> {
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
        cluster_id,
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
        if ROOT_PREFIX.is_empty() {
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

fn replace_with_virt_llcs(
    node: &mut Node,
    min_cores: usize,
    max_cores: usize,
    start_id: usize,
) -> Result<usize> {
    let mut next_id = start_id;
    let mut core_to_partition: BTreeMap<usize, usize> = BTreeMap::new();
    let mut partition_to_kernel_id: BTreeMap<usize, usize> = BTreeMap::new();
    let num_orig_llcs = node.llcs.len();

    // First pass: determine core to partition mapping, partition to
    // kernel_id mapping, and total partitions needed
    for (_llc_id, llc) in node.llcs.iter() {
        // Group cores by type (big/little) to partition separately
        let mut cores_by_type: BTreeMap<bool, Vec<usize>> = BTreeMap::new();

        for (core_id, core) in llc.cores.iter() {
            let core_type = core.core_type == CoreType::Little;
            cores_by_type
                .entry(core_type)
                .or_insert(Vec::new())
                .push(*core_id);
        }

        for (_core_type, core_ids) in cores_by_type.iter() {
            let num_cores_in_bucket = core_ids.len();

            // Find optimal partition size within specified range
            let best_split = find_best_split_size(num_cores_in_bucket, min_cores, max_cores);
            let num_partitions = num_cores_in_bucket / best_split;

            // Assign cores to partitions within a group type
            for (bucket_idx, &core_id) in core_ids.iter().enumerate() {
                let partition_idx = min(bucket_idx / best_split, num_partitions - 1);
                let current_partition_id = next_id + partition_idx;
                core_to_partition.insert(core_id, current_partition_id);
                partition_to_kernel_id.insert(current_partition_id, llc.kernel_id);
            }

            next_id += num_partitions;
        }
    }

    // Create new virtual LLC structures based on partitioning found above
    let mut virt_llcs: BTreeMap<usize, Arc<Llc>> = BTreeMap::new();

    for vllc_id in start_id..next_id {
        let kernel_id = partition_to_kernel_id.get(&vllc_id).copied().unwrap();
        virt_llcs.insert(
            vllc_id,
            Arc::new(Llc {
                id: vllc_id,
                kernel_id,
                cores: BTreeMap::new(),
                span: Cpumask::new(),
                node_id: node.id,
                all_cpus: BTreeMap::new(),
            }),
        );
    }

    // Second pass: move cores to the appropriate new LLC based on partition
    for (_llc_id, llc) in node.llcs.iter_mut() {
        for (core_id, core) in llc.cores.iter() {
            if let Some(&target_partition_id) = core_to_partition.get(core_id) {
                if let Some(target_llc) = virt_llcs.get_mut(&target_partition_id) {
                    let target_llc_mut = Arc::get_mut(target_llc).unwrap();

                    // Clone core and update its LLC ID to match new partition
                    let mut new_core = (**core).clone();
                    new_core.llc_id = target_partition_id;

                    // Update all CPUs within this core to reference new LLC ID
                    let mut updated_cpus = BTreeMap::new();
                    for (cpu_id, cpu) in new_core.cpus.iter() {
                        let mut new_cpu = (**cpu).clone();
                        new_cpu.llc_id = target_partition_id;

                        // Add CPU to the virtual LLC's span
                        target_llc_mut.span.set_cpu(*cpu_id)?;

                        updated_cpus.insert(*cpu_id, Arc::new(new_cpu));
                    }
                    new_core.cpus = updated_cpus;

                    // Add the updated core to the virtual LLC
                    target_llc_mut.cores.insert(*core_id, Arc::new(new_core));
                }
            }
        }
    }

    // Replace original LLCs with virtual LLCs
    node.llcs = virt_llcs;

    let num_virt_llcs = next_id - start_id;
    let vllc_sizes: Vec<usize> = node.llcs.values().map(|llc| llc.cores.len()).collect();

    if vllc_sizes.is_empty() {
        return Ok(next_id);
    }

    // Most vLLCs should have the same size, only the last one might differ
    let common_size = vllc_sizes[0];
    let last_size = *vllc_sizes.last().unwrap();

    if common_size == last_size {
        info!(
            "Node {}: split {} LLC(s) into {} virtual LLCs with {} cores each",
            node.id, num_orig_llcs, num_virt_llcs, common_size
        );
    } else {
        info!(
            "Node {}: split {} LLC(s) into {} virtual LLCs with {} cores each (last with {})",
            node.id, num_orig_llcs, num_virt_llcs, common_size, last_size
        );
    }

    Ok(next_id)
}

fn create_default_node(
    online_mask: &Cpumask,
    topo_ctx: &mut TopoCtx,
    flatten_llc: bool,
    nr_cores_per_vllc: Option<(usize, usize)>,
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

    if let Some((min_cores_val, max_cores_val)) = nr_cores_per_vllc {
        replace_with_virt_llcs(&mut node, min_cores_val, max_cores_val, 0)?;
    }

    nodes.insert(node.id, node);

    Ok(nodes)
}

fn create_numa_nodes(
    online_mask: &Cpumask,
    topo_ctx: &mut TopoCtx,
    nr_cores_per_vllc: Option<(usize, usize)>,
) -> Result<BTreeMap<usize, Node>> {
    let mut nodes = BTreeMap::<usize, Node>::new();
    let mut next_virt_llc_id = 0;

    #[cfg(feature = "gpu-topology")]
    let system_gpus = create_gpus();

    let path = format!("{}/sys/devices/system/node/node*", *ROOT_PREFIX);
    let numa_paths = glob(&path)?;
    for numa_path in numa_paths.filter_map(Result::ok) {
        let numa_str = numa_path.to_str().unwrap().trim();
        let node_id = if ROOT_PREFIX.is_empty() {
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
            let cpu_id = if ROOT_PREFIX.is_empty() {
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

        if let Some((min_cores_val, max_cores_val)) = nr_cores_per_vllc {
            next_virt_llc_id =
                replace_with_virt_llcs(&mut node, min_cores_val, max_cores_val, next_virt_llc_id)?;
        }

        nodes.insert(node.id, node);
    }
    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitvec::prelude::*;

    // Per-struct helpers that centralize "don't care" fields. When a field is
    // added to any topology struct, only the corresponding helper needs updating.

    fn test_cpu(id: usize, core_id: usize, llc_id: usize, node_id: usize) -> Cpu {
        Cpu {
            id,
            core_id,
            llc_id,
            node_id,
            min_freq: 0,
            max_freq: 0,
            base_freq: 0,
            cpu_capacity: 1024,
            smt_level: 0, // filled by instantiate()
            pm_qos_resume_latency_us: 0,
            trans_lat_ns: 0,
            l2_id: 0,
            l3_id: llc_id,
            cache_size: 0,
            core_type: CoreType::Big { turbo: false },
            package_id: node_id,
            cluster_id: 0,
        }
    }

    fn test_core(
        id: usize,
        cpus: BTreeMap<usize, Arc<Cpu>>,
        llc_id: usize,
        node_id: usize,
        total_cpus: usize,
    ) -> Core {
        let mut span = bitvec![u64, Lsb0; 0; total_cpus];
        for &cpu_id in cpus.keys() {
            span.set(cpu_id, true);
        }
        Core {
            id,
            kernel_id: id,
            cluster_id: 0,
            cpus,
            span: Cpumask::from_vec(span.into_vec()),
            core_type: CoreType::Big { turbo: false },
            llc_id,
            node_id,
        }
    }

    fn test_llc(
        id: usize,
        cores: BTreeMap<usize, Arc<Core>>,
        node_id: usize,
        total_cpus: usize,
    ) -> Llc {
        let mut span = bitvec![u64, Lsb0; 0; total_cpus];
        for core in cores.values() {
            for &cpu_id in core.cpus.keys() {
                span.set(cpu_id, true);
            }
        }
        Llc {
            id,
            kernel_id: id,
            cores,
            span: Cpumask::from_vec(span.into_vec()),
            node_id,
            all_cpus: BTreeMap::new(), // filled by instantiate()
        }
    }

    fn test_node(
        id: usize,
        llcs: BTreeMap<usize, Arc<Llc>>,
        nr_nodes: usize,
        total_cpus: usize,
    ) -> Node {
        let mut span = bitvec![u64, Lsb0; 0; total_cpus];
        for llc in llcs.values() {
            for core in llc.cores.values() {
                for &cpu_id in core.cpus.keys() {
                    span.set(cpu_id, true);
                }
            }
        }
        Node {
            id,
            distance: vec![10; nr_nodes],
            llcs,
            span: Cpumask::from_vec(span.into_vec()),
            all_cores: BTreeMap::new(), // filled by instantiate()
            all_cpus: BTreeMap::new(),  // filled by instantiate()
            #[cfg(feature = "gpu-topology")]
            gpus: BTreeMap::new(),
        }
    }

    fn make_test_topo(
        nr_nodes: usize,
        llcs_per_node: usize,
        cores_per_llc: usize,
        hts_per_core: usize,
    ) -> (Topology, usize) {
        let total_cpus = nr_nodes * llcs_per_node * cores_per_llc * hts_per_core;
        let mut cpu_id = 0usize;
        let mut core_id = 0usize;
        let mut llc_id = 0usize;
        let mut nodes = BTreeMap::new();

        for node_idx in 0..nr_nodes {
            let mut llcs = BTreeMap::new();
            for _ in 0..llcs_per_node {
                let mut cores = BTreeMap::new();
                for _ in 0..cores_per_llc {
                    let mut cpus = BTreeMap::new();
                    for _ in 0..hts_per_core {
                        cpus.insert(
                            cpu_id,
                            Arc::new(test_cpu(cpu_id, core_id, llc_id, node_idx)),
                        );
                        cpu_id += 1;
                    }
                    cores.insert(
                        core_id,
                        Arc::new(test_core(core_id, cpus, llc_id, node_idx, total_cpus)),
                    );
                    core_id += 1;
                }
                llcs.insert(
                    llc_id,
                    Arc::new(test_llc(llc_id, cores, node_idx, total_cpus)),
                );
                llc_id += 1;
            }
            nodes.insert(node_idx, test_node(node_idx, llcs, nr_nodes, total_cpus));
        }

        let span = {
            let mut mask = bitvec![u64, Lsb0; 0; total_cpus];
            for i in 0..total_cpus {
                mask.set(i, true);
            }
            Cpumask::from_vec(mask.into_vec())
        };

        (Topology::instantiate(span, nodes).unwrap(), total_cpus)
    }

    /// Create a Cpumask from a list of set CPU IDs.
    fn mask_from_bits(total: usize, bits: &[usize]) -> Cpumask {
        let mut bv = bitvec![u64, Lsb0; 0; total];
        for &b in bits {
            bv.set(b, true);
        }
        Cpumask::from_vec(bv.into_vec())
    }

    fn grid_output(topo: &Topology, cpumask: &Cpumask) -> String {
        let mut buf = Vec::new();
        topo.format_cpumask_grid(&mut buf, cpumask, "    ", 80)
            .unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn test_grid_2node_2llc_3core_2ht() {
        // 2 nodes, 2 LLCs/node, 3 cores/LLC, 2 HTs/core = 24 CPUs
        let (topo, total) = make_test_topo(2, 2, 3, 2);
        assert_eq!(total, 24);

        // Set some specific CPUs:
        // Node0 LLC0: core0(cpu0,1) core1(cpu2,3) core2(cpu4,5)
        // Node0 LLC1: core3(cpu6,7) core4(cpu8,9) core5(cpu10,11)
        // Node1 LLC2: core6(cpu12,13) core7(cpu14,15) core8(cpu16,17)
        // Node1 LLC3: core9(cpu18,19) core10(cpu20,21) core11(cpu22,23)
        //
        // Set: cpu1(core0 2nd HT), cpu2+3(core1 both), cpu12(core6 1st HT)
        let cpumask = mask_from_bits(total, &[1, 2, 3, 12]);

        let output = grid_output(&topo, &cpumask);
        // Node0: LLC0=[▄ █ ░] LLC1=[░ ░ ░]
        // Node1: LLC2=[▀ ░ ░] LLC3=[░ ░ ░]
        assert!(output.contains("N0 L00:"));
        assert!(output.contains("N1 L02:"));
        // LLC0=▄█░, LLC1=░░░ separated by |
        assert!(output.contains("▄█░|░░░"));
        // LLC2=▀░░, LLC3=░░░ separated by |
        assert!(output.contains("▀░░|░░░"));

        // Core count: cores 0,1,6 have at least one CPU set = 3
        assert_eq!(topo.cpumask_nr_cores(&cpumask), 3);
    }

    #[test]
    fn test_grid_empty_cpumask() {
        let (topo, total) = make_test_topo(1, 2, 3, 2);
        let cpumask = mask_from_bits(total, &[]);
        let output = grid_output(&topo, &cpumask);
        // All chars should be ░
        assert!(!output.contains('█'));
        assert!(!output.contains('▀'));
        assert!(!output.contains('▄'));
        assert!(output.contains('░'));
        assert_eq!(topo.cpumask_nr_cores(&cpumask), 0);
    }

    #[test]
    fn test_grid_full_cpumask() {
        let (topo, total) = make_test_topo(1, 2, 3, 2);
        let cpumask = mask_from_bits(total, &(0..total).collect::<Vec<_>>());
        let output = grid_output(&topo, &cpumask);
        // All chars should be █
        assert!(!output.contains('░'));
        assert!(!output.contains('▀'));
        assert!(!output.contains('▄'));
        assert!(output.contains('█'));
        assert_eq!(topo.cpumask_nr_cores(&cpumask), 6);
    }

    #[test]
    fn test_grid_mixed_ht() {
        // 1 node, 1 LLC, 4 cores, 2 HTs = 8 CPUs
        let (topo, total) = make_test_topo(1, 1, 4, 2);
        // core0: cpu0,1  core1: cpu2,3  core2: cpu4,5  core3: cpu6,7
        // Set: cpu0 only (▀), cpu3 only (▄), cpu4+5 (█), none on core3 (░)
        let cpumask = mask_from_bits(total, &[0, 3, 4, 5]);
        let output = grid_output(&topo, &cpumask);
        assert!(output.contains('▀'));
        assert!(output.contains('▄'));
        assert!(output.contains('█'));
        assert!(output.contains('░'));
    }

    #[test]
    fn test_grid_single_node() {
        let (topo, total) = make_test_topo(1, 1, 2, 2);
        let cpumask = mask_from_bits(total, &[0, 1]);
        let output = grid_output(&topo, &cpumask);
        assert!(output.contains("N0 L00:"));
        assert!(!output.contains("N1"));
    }

    #[test]
    fn test_grid_overflow_wrap() {
        // 1 node, 12 LLCs, 4 cores each, 2 HTs = many characters
        // 12 LLCs grouped by 4 = 3 groups per line, should wrap
        let (topo, total) = make_test_topo(1, 12, 4, 2);
        let cpumask = mask_from_bits(total, &[0]);
        let mut buf = Vec::new();
        topo.format_cpumask_grid(&mut buf, &cpumask, "    ", 60)
            .unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Should have multiple lines for node 0 due to wrapping
        let lines: Vec<&str> = output.lines().collect();
        assert!(
            lines.len() > 1,
            "Expected wrapping with narrow width, got {} lines",
            lines.len()
        );
    }

    #[test]
    fn test_grid_smt_off() {
        // 1 node, 1 LLC, 4 cores, 1 HT = no SMT
        let (topo, total) = make_test_topo(1, 1, 4, 1);
        // core0: cpu0, core1: cpu1, core2: cpu2, core3: cpu3
        let cpumask = mask_from_bits(total, &[0, 2]);
        let output = grid_output(&topo, &cpumask);
        // Only █ and ░ should appear
        assert!(output.contains('█'));
        assert!(output.contains('░'));
        assert!(!output.contains('▀'));
        assert!(!output.contains('▄'));
    }

    #[test]
    fn test_grid_4way_smt() {
        // 1 node, 1 LLC, 2 cores, 4 HTs = 8 CPUs
        let (topo, total) = make_test_topo(1, 1, 2, 4);
        // core0: cpu0-3, core1: cpu4-7
        // Set all of core0 → █, set 2 of core1 → ▄ (partial)
        let cpumask = mask_from_bits(total, &[0, 1, 2, 3, 4, 5]);
        let output = grid_output(&topo, &cpumask);
        assert!(output.contains('█')); // core0: all 4 set
        assert!(output.contains('▄')); // core1: partial (2 of 4)
    }

    #[test]
    fn test_cpumask_header() {
        let (topo, total) = make_test_topo(1, 1, 4, 2);
        // 4 cores, 8 CPUs. Set cpu0,1,2 (2 cores touched)
        let cpumask = mask_from_bits(total, &[0, 1, 2]);
        let header = topo.format_cpumask_header(&cpumask, 5, 10);
        assert!(header.contains("cpus=  3(  2c)"));
        assert!(header.contains("[  5, 10]"));
    }

}
