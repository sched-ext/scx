use anyhow::Result;
use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;
use walkdir::WalkDir;

use clap::Parser;
use scx_utils::Core;
use scx_utils::Topology;
use serde::Deserialize;
use serde::Serialize;
use tracing::debug;

use crate::bpf_intf;
use crate::CpuPool;
use crate::LayerSpec;

#[derive(Clone, Debug, PartialEq, Parser, Serialize, Deserialize)]
#[clap(rename_all = "snake_case")]
pub enum LayerGrowthAlgo {
    /// Sticky attempts to place layers evenly spaced across cores.
    Sticky,
    /// Linear starts with the lowest number CPU and grows towards the total
    /// number of CPUs.
    Linear,
    /// Reverse order of [`LayerGrowthAlgo::Linear`]. Starts with the highest number CPU and grows towards the total
    /// number of CPUs.
    Reverse,
    /// Random core selection order.
    Random,
    /// Topo uses the order of the nodes/llcs in the layer config to determine
    /// the order of CPUs to select when growing a layer. It starts from the
    /// llcs configuration and then the NUMA configuration for any CPUs not
    /// specified.
    Topo,
    /// Round Robin attempts to grow to a core in an unpopulated NUMA node else
    /// an unpopulated LLC. It keeps the load balanced between NUMA and LLCs as
    /// it continues to grow.
    RoundRobin,
    /// BigLittle attempts to first grow across all big cores and then allocates
    /// onto little cores after all big cores are allocated.
    BigLittle,
    /// LittleBig attempts to first grow across all little cores and then
    /// allocates onto big cores after all little cores are allocated.
    LittleBig,
    /// Grab CPUs from NUMA nodes, iteratively, in linear order.
    NodeSpread,
    /// Grab CPUs from NUMA nodes, iteratively, in reverse order.
    NodeSpreadReverse,
    /// Grab CPUs from NUMA nodes, iteratively, in random order.
    NodeSpreadRandom,
    /// Grab CPUs from CpuSets, iteratively, in linear order.
    CpuSetSpread,
    /// Grab CPUs from CpuSets, iteratively, in reverse order.
    CpuSetSpreadReverse,
    /// Grab CPUs from CpuSets, iteratively, in random order.
    CpuSetSpreadRandom,
    /// RandomTopo is sticky to NUMA nodes/LLCs but randomises the order in which
    /// it visits each. The layer will select a random NUMA node, then a random LLC
    /// within it, then randomly iterate the cores in that LLC.
    RandomTopo,
    /// StickyDynamic attempts to assign cores to layers according to their
    /// size, while remaining sticky to LLCs, and tries to place layers across
    /// LLC boundary minimizing overlap.
    StickyDynamic,
}

const GROWTH_ALGO_STICKY: i32 = bpf_intf::layer_growth_algo_GROWTH_ALGO_STICKY as i32;
const GROWTH_ALGO_LINEAR: i32 = bpf_intf::layer_growth_algo_GROWTH_ALGO_LINEAR as i32;
const GROWTH_ALGO_REVERSE: i32 = bpf_intf::layer_growth_algo_GROWTH_ALGO_REVERSE as i32;
const GROWTH_ALGO_RANDOM: i32 = bpf_intf::layer_growth_algo_GROWTH_ALGO_RANDOM as i32;
const GROWTH_ALGO_TOPO: i32 = bpf_intf::layer_growth_algo_GROWTH_ALGO_TOPO as i32;
const GROWTH_ALGO_ROUND_ROBIN: i32 = bpf_intf::layer_growth_algo_GROWTH_ALGO_ROUND_ROBIN as i32;
const GROWTH_ALGO_BIG_LITTLE: i32 = bpf_intf::layer_growth_algo_GROWTH_ALGO_BIG_LITTLE as i32;
const GROWTH_ALGO_LITTLE_BIG: i32 = bpf_intf::layer_growth_algo_GROWTH_ALGO_LITTLE_BIG as i32;
const GROWTH_ALGO_NODE_SPREAD: i32 = bpf_intf::layer_growth_algo_GROWTH_ALGO_NODE_SPREAD as i32;
const GROWTH_ALGO_NODE_SPREAD_REVERSE: i32 =
    bpf_intf::layer_growth_algo_GROWTH_ALGO_NODE_SPREAD_REVERSE as i32;
const GROWTH_ALGO_NODE_SPREAD_RANDOM: i32 =
    bpf_intf::layer_growth_algo_GROWTH_ALGO_NODE_SPREAD_RANDOM as i32;
const GROWTH_ALGO_CPUSET_SPREAD: i32 = bpf_intf::layer_growth_algo_GROWTH_ALGO_CPUSET_SPREAD as i32;
const GROWTH_ALGO_CPUSET_SPREAD_REVERSE: i32 =
    bpf_intf::layer_growth_algo_GROWTH_ALGO_CPUSET_SPREAD_REVERSE as i32;
const GROWTH_ALGO_CPUSET_SPREAD_RANDOM: i32 =
    bpf_intf::layer_growth_algo_GROWTH_ALGO_CPUSET_SPREAD_RANDOM as i32;
const GROWTH_ALGO_RANDOM_TOPO: i32 = bpf_intf::layer_growth_algo_GROWTH_ALGO_RANDOM_TOPO as i32;
const GROWTH_ALGO_STICKY_DYNAMIC: i32 =
    bpf_intf::layer_growth_algo_GROWTH_ALGO_STICKY_DYNAMIC as i32;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CpuSet {
    cpus: BTreeSet<usize>,
    cores: BTreeSet<usize>,
}

fn parse_cpu_ranges(s: &str) -> Result<BTreeSet<usize>> {
    let mut cpus = BTreeSet::new();

    for part in s.trim().split(',') {
        if let Some((start, end)) = part.split_once('-') {
            let start: usize = start.parse()?;
            let end: usize = end.parse()?;
            cpus.extend(start..=end);
        } else if let Ok(single) = part.parse() {
            cpus.insert(single);
        }
    }

    Ok(cpus)
}

fn collect_cpuset_effective() -> Result<BTreeSet<BTreeSet<usize>>> {
    let mut result = BTreeSet::new();

    for entry in WalkDir::new("/sys/fs/cgroup") {
        if let Ok(entry) = entry {
            if entry.file_name() == "cpuset.cpus.effective" {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    result.insert(parse_cpu_ranges(&content)?);
                }
            }
        }
    }

    Ok(result)
}

// return cpuset layout.
fn get_cpusets(topo: &Topology) -> Result<BTreeSet<CpuSet>> {
    let mut cpusets: BTreeSet<CpuSet> = BTreeSet::new();
    let cpuset_cpus = collect_cpuset_effective()?;
    for x in cpuset_cpus {
        let mut cores = BTreeSet::new();
        for (_, core) in topo.all_cores.iter() {
            let mut has_all = true;
            for (_, cpu) in core.cpus.iter() {
                has_all &= x.contains(&cpu.id);
            }
            if has_all {
                cores.insert(core.id);
            }
        }
        cpusets.insert(CpuSet { cores, cpus: x });
    }
    // XXX -- this enforces the expectation that cpusets are disjoint
    // think this is a reasonable expectation.
    let mut overlapping_cpusets = BTreeSet::new();
    for x in cpusets.iter() {
        for y in cpusets.iter() {
            if x != y && !overlapping_cpusets.contains(x) && !overlapping_cpusets.contains(y) {
                // toss superset if exists, toss one of overlap otherwise.
                if x.cpus.is_superset(&y.cpus) {
                    overlapping_cpusets.insert(x.clone());
                } else if y.cpus.is_superset(&x.cpus) {
                    overlapping_cpusets.insert(y.clone());
                } else if !x.cpus.is_disjoint(&y.cpus) {
                    overlapping_cpusets.insert(x.clone());
                }
            }
        }
    }
    cpusets.retain(|x| !overlapping_cpusets.contains(x));

    Ok(cpusets)
}

impl LayerGrowthAlgo {
    pub fn as_bpf_enum(&self) -> i32 {
        match self {
            LayerGrowthAlgo::Sticky => GROWTH_ALGO_STICKY,
            LayerGrowthAlgo::Linear => GROWTH_ALGO_LINEAR,
            LayerGrowthAlgo::Reverse => GROWTH_ALGO_REVERSE,
            LayerGrowthAlgo::Random => GROWTH_ALGO_RANDOM,
            LayerGrowthAlgo::Topo => GROWTH_ALGO_TOPO,
            LayerGrowthAlgo::RoundRobin => GROWTH_ALGO_ROUND_ROBIN,
            LayerGrowthAlgo::BigLittle => GROWTH_ALGO_BIG_LITTLE,
            LayerGrowthAlgo::LittleBig => GROWTH_ALGO_LITTLE_BIG,
            LayerGrowthAlgo::NodeSpread => GROWTH_ALGO_NODE_SPREAD,
            LayerGrowthAlgo::NodeSpreadReverse => GROWTH_ALGO_NODE_SPREAD_REVERSE,
            LayerGrowthAlgo::NodeSpreadRandom => GROWTH_ALGO_NODE_SPREAD_RANDOM,
            LayerGrowthAlgo::CpuSetSpread => GROWTH_ALGO_CPUSET_SPREAD,
            LayerGrowthAlgo::CpuSetSpreadReverse => GROWTH_ALGO_CPUSET_SPREAD_REVERSE,
            LayerGrowthAlgo::CpuSetSpreadRandom => GROWTH_ALGO_CPUSET_SPREAD_RANDOM,
            LayerGrowthAlgo::RandomTopo => GROWTH_ALGO_RANDOM_TOPO,
            LayerGrowthAlgo::StickyDynamic => GROWTH_ALGO_STICKY_DYNAMIC,
        }
    }

    pub fn layer_core_orders(
        cpu_pool: &CpuPool,
        layer_specs: &[LayerSpec],
        topo: &Topology,
    ) -> Result<BTreeMap<usize, Vec<usize>>> {
        let mut core_orders = BTreeMap::new();

        for (idx, spec) in layer_specs.iter().enumerate() {
            let layer_growth_algo = spec.kind.common().growth_algo.clone();
            let core_order =
                layer_growth_algo.layer_core_order(cpu_pool, layer_specs, spec, idx, topo)?;

            let core_order = match &spec.cpuset {
                Some(mask) => core_order
                    .into_iter()
                    .filter(|cpu| mask.test_cpu(*cpu))
                    .collect(),
                None => core_order,
            };

            core_orders.insert(idx, core_order);
        }

        Ok(core_orders)
    }

    fn layer_core_order(
        &self,
        cpu_pool: &CpuPool,
        layer_specs: &[LayerSpec],
        spec: &LayerSpec,
        layer_idx: usize,
        topo: &Topology,
    ) -> Result<Vec<usize>> {
        let generator = LayerCoreOrderGenerator {
            cpu_pool,
            layer_specs,
            spec,
            layer_idx,
            topo,
            cpusets: &get_cpusets(&topo)?,
        };
        Ok(match self {
            LayerGrowthAlgo::Sticky => generator.grow_sticky(),
            LayerGrowthAlgo::Linear => generator.grow_linear(),
            LayerGrowthAlgo::Reverse => generator.grow_reverse(),
            LayerGrowthAlgo::RoundRobin => generator.grow_round_robin(),
            LayerGrowthAlgo::Random => generator.grow_random(),
            LayerGrowthAlgo::BigLittle => generator.grow_big_little(),
            LayerGrowthAlgo::LittleBig => generator.grow_little_big(),
            LayerGrowthAlgo::Topo => generator.grow_topo(),
            LayerGrowthAlgo::NodeSpread => generator.grow_node_spread(),
            LayerGrowthAlgo::NodeSpreadReverse => generator.grow_node_spread_reverse(),
            LayerGrowthAlgo::NodeSpreadRandom => generator.grow_node_spread_random(),
            LayerGrowthAlgo::CpuSetSpread => generator.grow_cpuset_spread(),
            LayerGrowthAlgo::CpuSetSpreadReverse => generator.grow_cpuset_spread_reverse(),
            LayerGrowthAlgo::CpuSetSpreadRandom => generator.grow_cpuset_spread_random(),
            LayerGrowthAlgo::RandomTopo => generator.grow_random_topo(),
            LayerGrowthAlgo::StickyDynamic => generator.grow_sticky_dynamic(),
        })
    }
}

impl Default for LayerGrowthAlgo {
    fn default() -> Self {
        LayerGrowthAlgo::Sticky
    }
}

struct LayerCoreOrderGenerator<'a> {
    cpu_pool: &'a CpuPool,
    layer_specs: &'a [LayerSpec],
    spec: &'a LayerSpec,
    layer_idx: usize,
    topo: &'a Topology,
    cpusets: &'a BTreeSet<CpuSet>,
}

impl<'a> LayerCoreOrderGenerator<'a> {
    fn has_topology_preference(&self) -> bool {
        self.spec.nodes().len() > 0 || self.spec.llcs().len() > 0
    }

    fn rotate_layer_offset(&self, vec: &'a mut Vec<usize>) -> &Vec<usize> {
        let num_cores = self.topo.all_cores.len();
        let chunk = num_cores.div_ceil(self.layer_specs.len());
        vec.rotate_right((chunk * self.layer_idx).min(num_cores));
        vec
    }

    fn grow_sticky(&self) -> Vec<usize> {
        let mut core_order = vec![];

        let is_left = self.layer_idx % 2 == 0;
        let rot_by = |layer_idx, len| -> usize {
            if layer_idx <= len {
                layer_idx
            } else {
                layer_idx % len
            }
        };

        for i in 0..self.topo.all_cores.len() {
            core_order.push(i);
        }
        self.rotate_layer_offset(&mut core_order);

        for node in self.topo.nodes.values() {
            for llc in node.llcs.values() {
                let llc_cores = llc.cores.len();
                let rot = rot_by(llc_cores + (self.layer_idx << 1), llc_cores);
                if is_left {
                    core_order.rotate_left(rot);
                } else {
                    core_order.rotate_right(rot);
                }
            }
        }

        core_order
    }

    fn grow_linear(&self) -> Vec<usize> {
        let mut order = (0..self.topo.all_cores.len()).collect::<Vec<usize>>();
        // Only rotate if no LLC/node preferences - preserve topology order otherwise
        if !self.has_topology_preference() {
            self.rotate_layer_offset(&mut order);
        }
        order
    }

    fn grow_reverse(&self) -> Vec<usize> {
        let mut cores = self.grow_linear();
        cores.reverse();
        cores
    }

    fn grow_round_robin(&self) -> Vec<usize> {
        fastrand::seed(self.layer_idx.try_into().unwrap());

        let mut nodes: Vec<_> = self.topo.nodes.values().collect();
        fastrand::shuffle(&mut nodes);

        let interleaved_llcs = IteratorInterleaver::new(
            nodes
                .iter()
                .map(|n| {
                    let mut llcs: Vec<_> = n.llcs.values().collect();
                    fastrand::shuffle(&mut llcs);
                    llcs.into_iter()
                })
                .collect(),
        );

        IteratorInterleaver::new(
            interleaved_llcs
                .map(|llc| {
                    let mut cores: Vec<_> = llc.cores.values().collect();
                    fastrand::shuffle(&mut cores);
                    cores.into_iter()
                })
                .collect(),
        )
        .map(|core| self.cpu_pool.get_core_topological_id(core))
        .collect()
    }

    fn grow_random(&self) -> Vec<usize> {
        let mut core_order = self.grow_linear();
        fastrand::seed(self.layer_idx.try_into().unwrap());
        fastrand::shuffle(&mut core_order);
        core_order
    }

    fn grow_big_little(&self) -> Vec<usize> {
        let mut cores: Vec<&Arc<Core>> = self.topo.all_cores.values().collect();
        cores.sort_by(|a, b| a.core_type.cmp(&b.core_type));
        cores
            .into_iter()
            .map(|core| self.cpu_pool.get_core_topological_id(core))
            .collect()
    }

    fn grow_node_spread_inner(&self, make_random: bool) -> Vec<usize> {
        let mut cores: Vec<usize> = Vec::new();
        let mut node_core_vecs: Vec<Vec<usize>> = Vec::new();
        let mut max_node_cpus: usize = 0;

        for (node_id, node) in self.topo.nodes.iter() {
            let flat_node_vec: Vec<usize> = node
                .llcs
                .iter()
                .flat_map(|(llc_id, llc)| {
                    llc.cores
                        .iter()
                        .map(|(core_id, core)| {
                            // this debug information is important.
                            for (cpu_id, _) in core.cpus.iter() {
                                debug!(
                                    "NODE_ID: {} LLC_ID: {} CORE_ID: {} CPU_ID: {}",
                                    node_id, llc_id, core_id, cpu_id
                                );
                            }
                            core_id.clone()
                        })
                        .collect::<Vec<usize>>()
                })
                .collect();
            max_node_cpus = std::cmp::max(flat_node_vec.len(), max_node_cpus);
            node_core_vecs.push(flat_node_vec.clone());
        }

        if make_random {
            for mut core_vec in &mut node_core_vecs {
                fastrand::shuffle(&mut core_vec);
            }
        }

        for i in 0..=max_node_cpus {
            for sub_vec in node_core_vecs.iter() {
                if i < sub_vec.len() {
                    cores.push(sub_vec[i]);
                }
            }
        }
        self.rotate_layer_offset(&mut cores);
        cores
    }

    fn grow_node_spread_reverse(&self) -> Vec<usize> {
        let mut cores = self.grow_node_spread();
        cores.reverse();
        cores
    }

    fn grow_node_spread(&self) -> Vec<usize> {
        return self.grow_node_spread_inner(false);
    }

    fn grow_node_spread_random(&self) -> Vec<usize> {
        return self.grow_node_spread_inner(true);
    }

    fn grow_cpuset_spread_inner(&self, make_random: bool) -> Vec<usize> {
        let mut cores: Vec<usize> = Vec::new();
        let mut cpuset_core_vecs: Vec<Vec<&usize>> = Vec::new();
        let mut max_cpuset_cores: usize = 0;

        for cpuset in self.cpusets {
            max_cpuset_cores = std::cmp::max(cpuset_core_vecs.len(), max_cpuset_cores);
            let cpuset_core_vec: Vec<&usize> = cpuset.cores.iter().map(|x| x).collect();
            cpuset_core_vecs.push(cpuset_core_vec);
        }

        if make_random {
            for mut core_vec in &mut cpuset_core_vecs {
                fastrand::shuffle(&mut core_vec);
            }
        }

        for i in 0..=max_cpuset_cores {
            for sub_vec in cpuset_core_vecs.iter() {
                if i < sub_vec.len() {
                    cores.push(*sub_vec[i]);
                }
            }
        }

        self.rotate_layer_offset(&mut cores);
        cores
    }

    fn grow_cpuset_spread_reverse(&self) -> Vec<usize> {
        let mut cores = self.grow_cpuset_spread();
        cores.reverse();
        cores
    }

    fn grow_cpuset_spread(&self) -> Vec<usize> {
        return self.grow_cpuset_spread_inner(false);
    }

    fn grow_cpuset_spread_random(&self) -> Vec<usize> {
        return self.grow_cpuset_spread_inner(true);
    }

    fn grow_little_big(&self) -> Vec<usize> {
        let mut cores = self.grow_big_little();
        cores.reverse();
        cores
    }

    fn grow_topo(&self) -> Vec<usize> {
        let spec_nodes = self.spec.nodes();
        let spec_llcs = self.spec.llcs();
        let topo_nodes = &self.topo.nodes;

        if spec_nodes.len() + spec_llcs.len() == 0 {
            self.grow_round_robin()
        } else {
            let mut core_order = vec![];
            let mut core_id = 0;
            spec_llcs.iter().for_each(|spec_llc| {
                core_id = 0;
                topo_nodes.values().for_each(|topo_node| {
                    topo_node.all_cores.values().for_each(|core| {
                        if core.llc_id != *spec_llc {
                            core_id += 1;
                            return;
                        }
                        if !core_order.contains(&core_id) {
                            core_order.push(core_id);
                        }
                        core_id += 1;
                    });
                });
            });
            spec_nodes.iter().for_each(|spec_node| {
                core_id = 0;
                topo_nodes.values().for_each(|topo_node| {
                    if topo_node.id != *spec_node {
                        core_id += topo_node.all_cores.len();
                        return;
                    }
                    topo_node.all_cores.values().for_each(|_core| {
                        if !core_order.contains(&core_id) {
                            core_order.push(core_id);
                        }
                        core_id += 1;
                    });
                });
            });
            // Don't rotate when LLC/node preferences are specified - preserve the
            // explicit topology order built above to respect LLC/node affinity
            // self.rotate_layer_offset(&mut core_order);
            core_order
        }
    }

    fn grow_random_topo(&self) -> Vec<usize> {
        fastrand::seed(self.layer_idx.try_into().unwrap());

        let mut nodes: Vec<_> = self.topo.nodes.values().collect();
        fastrand::shuffle(&mut nodes);

        nodes
            .into_iter()
            .flat_map(|node| {
                let mut llcs: Vec<_> = node.llcs.values().collect();
                fastrand::shuffle(&mut llcs);
                llcs.into_iter()
            })
            .flat_map(|llc| {
                let mut cores: Vec<_> = llc.cores.values().collect();
                fastrand::shuffle(&mut cores);
                cores.into_iter()
            })
            .map(|c| self.cpu_pool.get_core_topological_id(c))
            .collect()
    }

    fn grow_sticky_dynamic(&self) -> Vec<usize> {
        self.grow_sticky()
    }
}

struct IteratorInterleaver<T>
where
    T: Iterator,
{
    empty: bool,
    index: usize,
    iters: Vec<T>,
}

impl<T> IteratorInterleaver<T>
where
    T: Iterator,
{
    fn new(iters: Vec<T>) -> Self {
        Self {
            empty: false,
            index: 0,
            iters,
        }
    }
}

impl<T> Iterator for IteratorInterleaver<T>
where
    T: Iterator,
{
    type Item = T::Item;

    fn next(&mut self) -> Option<T::Item> {
        if let Some(iter) = self.iters.get_mut(self.index) {
            self.index += 1;
            if let Some(value) = iter.next() {
                self.empty = false;
                Some(value)
            } else {
                self.next()
            }
        } else {
            self.index = 0;
            if self.empty {
                None
            } else {
                self.empty = true;
                self.next()
            }
        }
    }
}
