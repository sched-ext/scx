use std::collections::BTreeMap;
use std::sync::Arc;

use clap::Parser;
use scx_utils::Core;
use scx_utils::Topology;
use serde::Deserialize;
use serde::Serialize;

use crate::bpf_intf;
use crate::CpuPool;
use crate::LayerSpec;

#[derive(Clone, Debug, Parser, Serialize, Deserialize)]
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
    /// Grab CPUs from NUMA nodes, iteratively, in reverse order.
    NodeSpread,
    /// RandomTopo is sticky to NUMA nodes/LLCs but randomises the order in which
    /// it visits each. The layer will select a random NUMA node, then a random LLC
    /// within it, then randomly iterate the cores in that LLC.
    RandomTopo,
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
const GROWTH_ALGO_RANDOM_TOPO: i32 = bpf_intf::layer_growth_algo_GROWTH_ALGO_RANDOM_TOPO as i32;

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
            LayerGrowthAlgo::RandomTopo => GROWTH_ALGO_RANDOM_TOPO,
        }
    }

    pub fn layer_core_orders(
        cpu_pool: &CpuPool,
        layer_specs: &[LayerSpec],
        topo: &Topology,
    ) -> BTreeMap<usize, Vec<usize>> {
        let mut core_orders = BTreeMap::new();

        for (idx, spec) in layer_specs.iter().enumerate() {
            let layer_growth_algo = spec.kind.common().growth_algo.clone();
            let core_order =
                layer_growth_algo.layer_core_order(cpu_pool, layer_specs, spec, idx, topo);
            core_orders.insert(idx, core_order);
        }

        core_orders
    }

    fn layer_core_order(
        &self,
        cpu_pool: &CpuPool,
        layer_specs: &[LayerSpec],
        spec: &LayerSpec,
        layer_idx: usize,
        topo: &Topology,
    ) -> Vec<usize> {
        let generator = LayerCoreOrderGenerator {
            cpu_pool,
            layer_specs,
            spec,
            layer_idx,
            topo,
        };
        match self {
            LayerGrowthAlgo::Sticky => generator.grow_sticky(),
            LayerGrowthAlgo::Linear => generator.grow_linear(),
            LayerGrowthAlgo::Reverse => generator.grow_reverse(),
            LayerGrowthAlgo::RoundRobin => generator.grow_round_robin(),
            LayerGrowthAlgo::Random => generator.grow_random(),
            LayerGrowthAlgo::BigLittle => generator.grow_big_little(),
            LayerGrowthAlgo::LittleBig => generator.grow_little_big(),
            LayerGrowthAlgo::Topo => generator.grow_topo(),
            LayerGrowthAlgo::NodeSpread => generator.grow_node_spread(),
            LayerGrowthAlgo::RandomTopo => generator.grow_random_topo(),
        }
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
}

impl<'a> LayerCoreOrderGenerator<'a> {
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
        self.rotate_layer_offset(&mut order);
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

    fn grow_node_spread(&self) -> Vec<usize> {
        let mut cores: Vec<usize> = Vec::new();
        let core_vecs: Vec<Vec<usize>> = self
            .topo
            .nodes
            .clone()
            .into_iter()
            .map(|(_, x)| x.all_cpus.into_iter().map(|(_, x)| x.id).collect())
            .collect();

        for i in 0..core_vecs[0].len() {
            for sub_vec in core_vecs.clone() {
                if i < sub_vec.len() {
                    cores.push(sub_vec[i]);
                }
            }
        }
        cores.reverse();
        cores
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
            self.rotate_layer_offset(&mut core_order);
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
