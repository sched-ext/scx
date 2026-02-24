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

use crate::bpf_intf;
use crate::CpuPool;
use crate::LayerSpec;

#[derive(Clone, Debug, PartialEq, Parser, Serialize, Deserialize)]
#[clap(rename_all = "snake_case")]
/// Growth algorithms determine the order in which CPUs are allocated to a
/// layer as it grows.
///
/// All algorithms are NUMA-aware. Each produces a per-node core ordering
/// via `node_order()`, which determines the preferred NUMA node (based on
/// `nodes` config and pinned task distribution) and the order of remaining
/// nodes. Within each node, the algorithm determines core selection order.
/// Cross-node budget distribution is handled by `unified_alloc`.
///
/// Algorithms fall into two categories:
///
/// **Locality algorithms** prefer the layer's home NUMA node(s) and only
/// spill to remote nodes when local capacity is exhausted. Most algorithms
/// are locality algorithms.
///
/// **NUMA-spread algorithms** (marked `[spread]` below) enforce equal CPU
/// counts across all NUMA nodes via `unified_alloc`, capped at the least
/// available node capacity. Use these when the workload should be balanced
/// across nodes rather than concentrated on the preferred node. Their
/// within-node core ordering degenerates to the non-spread equivalent
/// (e.g. NodeSpread uses Linear ordering within each node) since the
/// even-split budget handles cross-node distribution.
pub enum LayerGrowthAlgo {
    /// Evenly space layers across cores within each node.
    Sticky,
    /// Lowest-numbered CPUs first within each node.
    Linear,
    /// Highest-numbered CPUs first within each node.
    Reverse,
    /// Random core selection within each node.
    Random,
    /// Follow the `llcs`/`nodes` layer config to determine core order.
    /// Preferred LLCs first, then remaining LLCs in node order.
    Topo,
    /// `[spread]` Interleave cores across LLCs within each node, with
    /// equal per-node CPU budget.
    RoundRobin,
    /// Big cores first, then little cores within each node.
    BigLittle,
    /// Little cores first, then big cores within each node.
    LittleBig,
    /// `[spread]` Linear core order within each node, equal per-node budget.
    NodeSpread,
    /// `[spread]` Reverse core order within each node, equal per-node budget.
    NodeSpreadReverse,
    /// `[spread]` Random core order within each node, equal per-node budget.
    NodeSpreadRandom,
    /// Interleave cores across CpuSets (CPU affinity groups) in linear order
    /// within each node. Balances across hardware domains (e.g. cache groups),
    /// not NUMA nodes.
    CpuSetSpread,
    /// Interleave cores across CpuSets in reverse order within each node.
    CpuSetSpreadReverse,
    /// Interleave cores across CpuSets in random order within each node.
    CpuSetSpreadRandom,
    /// Pick a random NUMA node, then a random LLC within it, then randomly
    /// iterate cores in that LLC.
    RandomTopo,
    /// Assign LLCs to layers proportionally by size, remaining sticky to
    /// LLCs to preserve cache locality. Per-node LLC ordering ensures
    /// sticky assignments respect NUMA node boundaries.
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
            // Spread algos degenerate to their per-node equivalents: the
            // even-split budget from unified_alloc handles cross-node
            // distribution, so core_order just determines within-node ordering.
            LayerGrowthAlgo::RoundRobin => generator.grow_round_robin(),
            LayerGrowthAlgo::Random => generator.grow_random(),
            LayerGrowthAlgo::BigLittle => generator.grow_big_little(),
            LayerGrowthAlgo::LittleBig => generator.grow_little_big(),
            LayerGrowthAlgo::Topo => generator.grow_topo(),
            LayerGrowthAlgo::NodeSpread => generator.grow_linear(),
            LayerGrowthAlgo::NodeSpreadReverse => generator.grow_reverse(),
            LayerGrowthAlgo::NodeSpreadRandom => generator.grow_random(),
            LayerGrowthAlgo::CpuSetSpread => generator.grow_cpuset_spread(),
            LayerGrowthAlgo::CpuSetSpreadReverse => generator.grow_cpuset_spread_inner(false, true),
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

/// Node iteration order: spec_nodes if set (hard limit), otherwise all topo
/// nodes rotated by layer_idx so that different layers start from different
/// nodes, with nodes claimed by other layers deprioritized. Used by both
/// growth algorithms and StickyDynamic's runtime LLC trading.
pub fn node_order(
    spec_nodes: &[usize],
    topo: &Topology,
    layer_idx: usize,
    all_layer_nodes: &[&[usize]],
) -> Vec<usize> {
    if spec_nodes.is_empty() {
        let mut nodes: Vec<usize> = topo.nodes.keys().copied().collect();
        let nr = nodes.len();
        if nr > 1 {
            nodes.rotate_left(layer_idx % nr);

            // Build per-node claim-rank vector from other layers' spec_nodes.
            // claim_rank[node] = [count at pos 0, count at pos 1, ...]
            let max_rank = all_layer_nodes.iter().map(|ln| ln.len()).max().unwrap_or(0);
            if max_rank > 0 {
                let mut claim_rank: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
                for (i, ln) in all_layer_nodes.iter().enumerate() {
                    if i == layer_idx {
                        continue;
                    }
                    for (pos, &node_id) in ln.iter().enumerate() {
                        claim_rank
                            .entry(node_id)
                            .or_insert_with(|| vec![0; max_rank])[pos] += 1;
                    }
                }
                let zero = vec![0; max_rank];
                nodes.sort_by_key(|n| claim_rank.get(n).unwrap_or(&zero).clone());
            }
        }
        nodes
    } else {
        spec_nodes.to_vec()
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
    #[allow(dead_code)]

    fn node_order(&self) -> Vec<usize> {
        let all: Vec<&[usize]> = self
            .layer_specs
            .iter()
            .map(|s| s.nodes().as_slice())
            .collect();
        node_order(self.spec.nodes(), self.topo, self.layer_idx, &all)
    }

    /// Sequential core indices (core_seq) belonging to a given node.
    fn node_core_seqs(&self, node_id: usize) -> Vec<usize> {
        let node = &self.topo.nodes[&node_id];
        node.llcs
            .values()
            .flat_map(|llc| llc.cores.values().map(|core| self.cpu_pool.core_seq(core)))
            .collect()
    }

    /// Per-node variant of rotate_layer_offset — rotates within a
    /// node-scoped core vec using node_cores.len() instead of
    /// all_cores.len().
    fn rotate_node_layer_offset(&self, vec: &mut Vec<usize>) {
        if vec.is_empty() {
            return;
        }
        let num_cores = vec.len();
        let chunk = num_cores.div_ceil(self.layer_specs.len());
        vec.rotate_right((chunk * self.layer_idx).min(num_cores));
    }

    fn grow_sticky(&self) -> Vec<usize> {
        let is_left = self.layer_idx % 2 == 0;
        let rot_by = |layer_idx, len| -> usize {
            if layer_idx <= len {
                layer_idx
            } else {
                layer_idx % len
            }
        };

        let mut result = Vec::new();
        for node_id in self.node_order() {
            let mut core_order = self.node_core_seqs(node_id);
            self.rotate_node_layer_offset(&mut core_order);

            let node = &self.topo.nodes[&node_id];
            for llc in node.llcs.values() {
                let llc_cores = llc.cores.len();
                let rot = rot_by(llc_cores + (self.layer_idx << 1), llc_cores);
                if is_left {
                    core_order.rotate_left(rot);
                } else {
                    core_order.rotate_right(rot);
                }
            }
            result.extend(core_order);
        }
        result
    }

    fn grow_linear(&self) -> Vec<usize> {
        let mut result = Vec::new();
        for node_id in self.node_order() {
            let mut order = self.node_core_seqs(node_id);
            // Rotate layers to different starting cores within each node so
            // they don't all compete for the same cores first.  Skip when LLCs
            // are explicitly specified — the user chose a particular intra-node
            // ordering.  Node preferences are fine — node_order() already
            // handles those and rotation is orthogonal.
            if self.spec.llcs().is_empty() {
                self.rotate_node_layer_offset(&mut order);
            }
            result.extend(order);
        }
        result
    }

    fn grow_reverse(&self) -> Vec<usize> {
        let mut result = Vec::new();
        for node_id in self.node_order() {
            let mut order = self.node_core_seqs(node_id);
            // See grow_linear() for why we skip rotation when LLCs are set.
            if self.spec.llcs().is_empty() {
                self.rotate_node_layer_offset(&mut order);
            }
            order.reverse();
            result.extend(order);
        }
        result
    }

    /// Per-node LLC interleaving: within each node (in node_order),
    /// interleave cores across the node's LLCs. Cross-node distribution
    /// is handled by the even-split budget from unified_alloc.
    fn grow_round_robin(&self) -> Vec<usize> {
        fastrand::seed(self.layer_idx.try_into().unwrap());
        let mut result = Vec::new();

        for node_id in self.node_order() {
            let node = &self.topo.nodes[&node_id];
            let mut llcs: Vec<_> = node.llcs.values().collect();
            fastrand::shuffle(&mut llcs);

            let interleaved: Vec<usize> = IteratorInterleaver::new(
                llcs.iter()
                    .map(|llc| {
                        let mut cores: Vec<_> = llc.cores.values().collect();
                        fastrand::shuffle(&mut cores);
                        cores.into_iter()
                    })
                    .collect(),
            )
            .map(|core| self.cpu_pool.core_seq(core))
            .collect();
            result.extend(interleaved);
        }
        result
    }

    fn grow_random(&self) -> Vec<usize> {
        fastrand::seed(self.layer_idx.try_into().unwrap());
        let mut result = Vec::new();
        for node_id in self.node_order() {
            let mut order = self.node_core_seqs(node_id);
            fastrand::shuffle(&mut order);
            result.extend(order);
        }
        result
    }

    fn grow_big_little(&self) -> Vec<usize> {
        let mut result = Vec::new();
        for node_id in self.node_order() {
            let node = &self.topo.nodes[&node_id];
            let mut cores: Vec<&Arc<Core>> = node.all_cores.values().collect();
            cores.sort_by(|a, b| a.core_type.cmp(&b.core_type));
            result.extend(cores.into_iter().map(|core| self.cpu_pool.core_seq(core)));
        }
        result
    }

    /// Spread across cpusets (CPU affinity groups), not NUMA nodes. Interleaves
    /// cores from different cpusets within each node so the layer's allocation
    /// is balanced across hardware domains (e.g., different cache groups).
    /// Rotation is per-node to match grow_linear — under per-node allocation,
    /// each node's cores are allocated independently.
    fn grow_cpuset_spread_inner(&self, make_random: bool, reverse: bool) -> Vec<usize> {
        let mut result = Vec::new();
        for node_id in self.node_order() {
            let node_cores: BTreeSet<usize> = self.node_core_seqs(node_id).into_iter().collect();

            // Filter each cpuset to cores within this node.
            let mut cpuset_core_vecs: Vec<Vec<usize>> = self
                .cpusets
                .iter()
                .map(|cs| {
                    cs.cores
                        .iter()
                        .filter(|c| node_cores.contains(c))
                        .copied()
                        .collect()
                })
                .filter(|v: &Vec<usize>| !v.is_empty())
                .collect();

            if make_random {
                for v in &mut cpuset_core_vecs {
                    fastrand::shuffle(v);
                }
            }

            // Interleave within this node's cpuset portions.
            let max_len = cpuset_core_vecs.iter().map(|v| v.len()).max().unwrap_or(0);
            let mut node_result = Vec::new();
            for i in 0..max_len {
                for sub_vec in cpuset_core_vecs.iter() {
                    if i < sub_vec.len() {
                        node_result.push(sub_vec[i]);
                    }
                }
            }
            if reverse {
                node_result.reverse();
            }
            self.rotate_node_layer_offset(&mut node_result);
            result.extend(node_result);
        }
        result
    }

    fn grow_cpuset_spread(&self) -> Vec<usize> {
        self.grow_cpuset_spread_inner(false, false)
    }

    fn grow_cpuset_spread_random(&self) -> Vec<usize> {
        self.grow_cpuset_spread_inner(true, false)
    }

    fn grow_little_big(&self) -> Vec<usize> {
        let mut result = Vec::new();
        for node_id in self.node_order() {
            let node = &self.topo.nodes[&node_id];
            let mut cores: Vec<&Arc<Core>> = node.all_cores.values().collect();
            cores.sort_by(|a, b| b.core_type.cmp(&a.core_type));
            result.extend(cores.into_iter().map(|core| self.cpu_pool.core_seq(core)));
        }
        result
    }

    /// Linear with LLC preference: within each node, cores from spec_llcs come
    /// first, then remaining cores. Cross-node prioritization is handled by
    /// node_order() and unified_alloc (spec_nodes feeds into node_order). With
    /// no spec_llcs or spec_nodes, falls back to RoundRobin.
    fn grow_topo(&self) -> Vec<usize> {
        let spec_llcs = self.spec.llcs();

        if spec_llcs.is_empty() && self.spec.nodes().is_empty() {
            return self.grow_round_robin();
        }

        let spec_llc_set: BTreeSet<usize> = spec_llcs.iter().copied().collect();
        let mut result = Vec::new();
        for node_id in self.node_order() {
            let node = &self.topo.nodes[&node_id];
            // Preferred LLC cores first, then the rest.
            let mut preferred = Vec::new();
            let mut rest = Vec::new();
            for llc in node.llcs.values() {
                let cores: Vec<usize> = llc
                    .cores
                    .values()
                    .map(|core| self.cpu_pool.core_seq(core))
                    .collect();
                if spec_llc_set.contains(&llc.id) {
                    preferred.extend(cores);
                } else {
                    rest.extend(cores);
                }
            }
            preferred.extend(rest);
            // No rotation — preserve explicit topology preference ordering.
            result.extend(preferred);
        }
        result
    }

    /// Random with LLC grouping: within each node, randomly shuffles LLCs
    /// then randomly shuffles cores within each LLC, keeping LLC-adjacent
    /// cores together for cache locality. Cross-node ordering is handled by
    /// node_order() and unified_alloc.
    fn grow_random_topo(&self) -> Vec<usize> {
        fastrand::seed(self.layer_idx.try_into().unwrap());
        let mut result = Vec::new();
        for node_id in self.node_order() {
            let node = &self.topo.nodes[&node_id];
            let mut llcs: Vec<_> = node.llcs.values().collect();
            fastrand::shuffle(&mut llcs);
            for llc in llcs {
                let mut cores: Vec<_> = llc.cores.values().collect();
                fastrand::shuffle(&mut cores);
                result.extend(cores.into_iter().map(|c| self.cpu_pool.core_seq(c)));
            }
        }
        result
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CpuPool;
    use scx_utils::testutils::make_test_topo;
    use std::sync::Arc;

    fn topo_1n() -> Arc<Topology> {
        let (topo, _) = make_test_topo(1, 2, 4, 2);
        Arc::new(topo)
    }

    fn topo_2n() -> Arc<Topology> {
        let (topo, _) = make_test_topo(2, 2, 4, 2);
        Arc::new(topo)
    }

    fn test_spec(algo: LayerGrowthAlgo) -> LayerSpec {
        let json = r#"{"name":"_","matches":[],"kind":{"Confined":{"util_range":[0.0,1.0]}}}"#;
        let mut spec: LayerSpec = serde_json::from_str(json).unwrap();
        spec.kind.common_mut().growth_algo = algo;
        spec
    }

    fn test_spec_with_nodes(algo: LayerGrowthAlgo, nodes: Vec<usize>) -> LayerSpec {
        let mut spec = test_spec(algo);
        *spec.nodes_mut() = nodes;
        spec
    }

    fn make_generator<'a>(
        cpu_pool: &'a CpuPool,
        specs: &'a [LayerSpec],
        spec: &'a LayerSpec,
        layer_idx: usize,
        topo: &'a Topology,
        cpusets: &'a BTreeSet<CpuSet>,
    ) -> LayerCoreOrderGenerator<'a> {
        LayerCoreOrderGenerator {
            cpu_pool,
            layer_specs: specs,
            spec,
            layer_idx,
            topo,
            cpusets,
        }
    }

    // --- node_order ---

    #[test]
    fn test_node_order_1n_default() {
        let topo = topo_1n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![test_spec(LayerGrowthAlgo::Linear)];
        let cpusets = BTreeSet::new();
        let gen = make_generator(&pool, &specs, &specs[0], 0, &topo, &cpusets);

        assert_eq!(gen.node_order(), vec![0]);
    }

    #[test]
    fn test_node_order_2n_default() {
        let topo = topo_2n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![test_spec(LayerGrowthAlgo::Linear)];
        let cpusets = BTreeSet::new();
        let gen = make_generator(&pool, &specs, &specs[0], 0, &topo, &cpusets);

        assert_eq!(gen.node_order(), vec![0, 1]);
    }

    #[test]
    fn test_node_order_2n_with_spec_reversed() {
        let topo = topo_2n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![test_spec_with_nodes(LayerGrowthAlgo::Linear, vec![1, 0])];
        let cpusets = BTreeSet::new();
        let gen = make_generator(&pool, &specs, &specs[0], 0, &topo, &cpusets);

        assert_eq!(gen.node_order(), vec![1, 0]);
    }

    #[test]
    fn test_node_order_2n_with_spec_partial() {
        let topo = topo_2n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        // Spec only mentions node 1; hard limit, no appending.
        let specs = vec![test_spec_with_nodes(LayerGrowthAlgo::Linear, vec![1])];
        let cpusets = BTreeSet::new();
        let gen = make_generator(&pool, &specs, &specs[0], 0, &topo, &cpusets);

        assert_eq!(gen.node_order(), vec![1]);
    }

    fn topo_4n() -> Arc<Topology> {
        let (topo, _) = make_test_topo(4, 2, 4, 2);
        Arc::new(topo)
    }

    #[test]
    fn test_node_order_2n_rotated() {
        let topo = topo_2n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![test_spec(LayerGrowthAlgo::Linear)];
        let cpusets = BTreeSet::new();
        let gen = make_generator(&pool, &specs, &specs[0], 1, &topo, &cpusets);

        assert_eq!(gen.node_order(), vec![1, 0]);
    }

    #[test]
    fn test_node_order_4n_rotated() {
        let topo = topo_4n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![test_spec(LayerGrowthAlgo::Linear)];
        let cpusets = BTreeSet::new();
        let gen = make_generator(&pool, &specs, &specs[0], 2, &topo, &cpusets);

        assert_eq!(gen.node_order(), vec![2, 3, 0, 1]);
    }

    #[test]
    fn test_node_order_4n_wraps() {
        let topo = topo_4n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![test_spec(LayerGrowthAlgo::Linear)];
        let cpusets = BTreeSet::new();
        // layer_idx=5, 5 % 4 = 1
        let gen = make_generator(&pool, &specs, &specs[0], 5, &topo, &cpusets);

        assert_eq!(gen.node_order(), vec![1, 2, 3, 0]);
    }

    #[test]
    fn test_node_order_spec_not_rotated() {
        let topo = topo_2n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![test_spec_with_nodes(LayerGrowthAlgo::Linear, vec![1, 0])];
        let cpusets = BTreeSet::new();
        // Even with layer_idx=1, spec_nodes should be returned unchanged.
        let gen = make_generator(&pool, &specs, &specs[0], 1, &topo, &cpusets);

        assert_eq!(gen.node_order(), vec![1, 0]);
    }

    #[test]
    fn test_node_order_2n_deprioritize() {
        // 2N: L0 pinned to [0], L1 unpinned (idx=1).
        // Rotation: [1, 0]. N0 has 1st-choice claim → goes last.
        let topo = topo_2n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![
            test_spec_with_nodes(LayerGrowthAlgo::Linear, vec![0]),
            test_spec(LayerGrowthAlgo::Linear),
        ];
        let cpusets = BTreeSet::new();
        let gen = make_generator(&pool, &specs, &specs[1], 1, &topo, &cpusets);

        assert_eq!(gen.node_order(), vec![1, 0]);
    }

    #[test]
    fn test_node_order_4n_deprioritize_ranked() {
        // 4N: L0 nodes=[0,1], L1 nodes=[2], L2 unpinned (idx=2).
        // Rotation (idx=2): [2,3,0,1].
        // Claim vectors: N0=[1,0], N1=[0,1], N2=[1,0], N3=[0,0].
        // Stable sort: N3=[0,0] < N1=[0,1] < N2=[1,0], N0=[1,0].
        // Rotation tiebreak: 2 before 0 in rotated order → result: [3, 1, 2, 0].
        let topo = topo_4n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![
            test_spec_with_nodes(LayerGrowthAlgo::Linear, vec![0, 1]),
            test_spec_with_nodes(LayerGrowthAlgo::Linear, vec![2]),
            test_spec(LayerGrowthAlgo::Linear),
        ];
        let cpusets = BTreeSet::new();
        let gen = make_generator(&pool, &specs, &specs[2], 2, &topo, &cpusets);

        assert_eq!(gen.node_order(), vec![3, 1, 2, 0]);
    }

    #[test]
    fn test_node_order_4n_deprioritize_double_claim() {
        // 4N: L0 nodes=[0], L1 nodes=[0], L2 unpinned (idx=2), L3 unpinned.
        // N0 has two 1st-choice claims: [2]. Others: [0].
        // Rotation (idx=2): [2,3,0,1].
        // Stable sort: [0] < [0] < [0] < [2] → [2,3,1,0].
        let topo = topo_4n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![
            test_spec_with_nodes(LayerGrowthAlgo::Linear, vec![0]),
            test_spec_with_nodes(LayerGrowthAlgo::Linear, vec![0]),
            test_spec(LayerGrowthAlgo::Linear),
            test_spec(LayerGrowthAlgo::Linear),
        ];
        let cpusets = BTreeSet::new();
        let gen = make_generator(&pool, &specs, &specs[2], 2, &topo, &cpusets);

        assert_eq!(gen.node_order(), vec![2, 3, 1, 0]);
    }

    #[test]
    fn test_node_order_no_claims_equals_rotation() {
        // 4N: all unpinned. No claims → pure rotation.
        let topo = topo_4n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![
            test_spec(LayerGrowthAlgo::Linear),
            test_spec(LayerGrowthAlgo::Linear),
            test_spec(LayerGrowthAlgo::Linear),
            test_spec(LayerGrowthAlgo::Linear),
        ];
        let cpusets = BTreeSet::new();
        let gen = make_generator(&pool, &specs, &specs[1], 1, &topo, &cpusets);

        assert_eq!(gen.node_order(), vec![1, 2, 3, 0]);
    }

    // --- node_core_seqs ---

    #[test]
    fn test_node_core_seqs_1n() {
        let topo = topo_1n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![test_spec(LayerGrowthAlgo::Linear)];
        let cpusets = BTreeSet::new();
        let gen = make_generator(&pool, &specs, &specs[0], 0, &topo, &cpusets);

        // 1N has 8 cores: all in node 0.
        let ids = gen.node_core_seqs(0);
        assert_eq!(ids, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_node_core_seqs_2n_partitions() {
        let topo = topo_2n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![test_spec(LayerGrowthAlgo::Linear)];
        let cpusets = BTreeSet::new();
        let gen = make_generator(&pool, &specs, &specs[0], 0, &topo, &cpusets);

        let node0 = gen.node_core_seqs(0);
        let node1 = gen.node_core_seqs(1);

        // Node 0: cores 0-7, Node 1: cores 8-15.
        assert_eq!(node0, vec![0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(node1, vec![8, 9, 10, 11, 12, 13, 14, 15]);

        // Together should be all 16 cores.
        let mut all: Vec<usize> = node0.into_iter().chain(node1).collect();
        all.sort();
        assert_eq!(all, (0..16).collect::<Vec<_>>());
    }

    // --- rotate_node_layer_offset ---

    #[test]
    fn test_rotate_node_layer_offset_single_layer() {
        let topo = topo_2n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![test_spec(LayerGrowthAlgo::Linear)];
        let cpusets = BTreeSet::new();
        let gen = make_generator(&pool, &specs, &specs[0], 0, &topo, &cpusets);

        // With 1 layer, chunk = 8, offset = 0 → no rotation.
        let mut v = vec![0, 1, 2, 3, 4, 5, 6, 7];
        gen.rotate_node_layer_offset(&mut v);
        assert_eq!(v, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_rotate_node_layer_offset_multi_layer() {
        let topo = topo_2n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let specs = vec![
            test_spec(LayerGrowthAlgo::Linear),
            test_spec(LayerGrowthAlgo::Linear),
        ];
        let cpusets = BTreeSet::new();
        let gen = make_generator(&pool, &specs, &specs[1], 1, &topo, &cpusets);

        // Layer idx=1, 2 layers, 8 cores in node → chunk = ceil(8/2) = 4.
        // rotate_right(4).
        let mut v = vec![0, 1, 2, 3, 4, 5, 6, 7];
        gen.rotate_node_layer_offset(&mut v);
        assert_eq!(v, vec![4, 5, 6, 7, 0, 1, 2, 3]);
    }
}
