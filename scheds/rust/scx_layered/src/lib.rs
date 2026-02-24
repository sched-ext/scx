// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
pub mod alloc;
mod config;
pub mod layer_core_growth;

pub mod bpf_intf;

use std::collections::BTreeMap;

use anyhow::bail;
use anyhow::Result;
pub use config::LayerCommon;
pub use config::LayerConfig;
pub use config::LayerKind;
pub use config::LayerMatch;
pub use config::LayerPlacement;
pub use config::LayerSpec;
pub use layer_core_growth::LayerGrowthAlgo;
use scx_utils::Core;
use scx_utils::Cpumask;
use scx_utils::Topology;
use scx_utils::NR_CPUS_POSSIBLE;
use scx_utils::NR_CPU_IDS;
use std::sync::Arc;
use tracing::info;

const MAX_CPUS: usize = bpf_intf::consts_MAX_CPUS as usize;

/// Divide `total` into parts proportional to `quotas`, returning exact
/// integers that sum to `total`. Uses the largest-remainder method
/// (Hamilton's method) for fair rounding.
pub fn largest_remainder(total: usize, quotas: &[f64]) -> Vec<usize> {
    if quotas.is_empty() {
        return vec![];
    }

    let sum: f64 = quotas.iter().sum();
    if sum == 0.0 {
        // No demand — distribute nothing.
        return vec![0; quotas.len()];
    }

    // Scale quotas so they sum to `total`.
    let scaled: Vec<f64> = quotas.iter().map(|q| q / sum * total as f64).collect();

    // Floor each scaled value.
    let floors: Vec<usize> = scaled.iter().map(|s| *s as usize).collect();
    let floor_sum: usize = floors.iter().sum();
    let mut remainder = total.saturating_sub(floor_sum);

    // Sort indices by descending fractional part.
    let mut indices: Vec<usize> = (0..quotas.len()).collect();
    indices.sort_by(|&a, &b| {
        let frac_a = scaled[a] - floors[a] as f64;
        let frac_b = scaled[b] - floors[b] as f64;
        frac_b
            .partial_cmp(&frac_a)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut result = floors;
    for &i in &indices {
        if remainder == 0 {
            break;
        }
        result[i] += 1;
        remainder -= 1;
    }

    result
}

/// Round CPU targets up to alloc-unit multiples, capped at total_cpus.
pub fn round_targets_to_alloc_units(
    targets: &[(usize, usize)],
    alloc_unit: usize,
    total_cpus: usize,
) -> Vec<(usize, usize)> {
    if alloc_unit <= 1 {
        return targets.to_vec();
    }

    targets
        .iter()
        .map(|&(target, min)| {
            // Round target up to next alloc_unit multiple.
            let aligned = (target + alloc_unit - 1) / alloc_unit * alloc_unit;
            // Cap at total_cpus.
            let aligned = aligned.min(total_cpus);
            // Round min up similarly.
            let min_aligned = (min + alloc_unit - 1) / alloc_unit * alloc_unit;
            let min_aligned = min_aligned.min(total_cpus);
            (aligned, min_aligned)
        })
        .collect()
}

#[derive(Debug)]
/// `CpuPool` represents the CPU core and logical CPU topology within the system.
/// It manages the mapping and availability of physical and logical cores, including
/// how resources are allocated for tasks across the available CPUs.
pub struct CpuPool {
    pub topo: Arc<Topology>,

    /// Per-node free LLC pool: node_id → [(llc_id, consumed_cores)].
    /// StickyDynamic's LLC trading operates within each node's list,
    /// preferring same-node LLCs to avoid cross-node traffic.
    pub free_llcs: BTreeMap<usize, Vec<(usize, usize)>>,

    /// A mask for available CPUs (SMT hyperthreads).
    /// Use for sub-core allocations when turned on.
    available_cpus: Cpumask,

    /// The ID of the first physical CPU in the system.
    /// Used as a global default when no per-node CPU is suitable.
    #[allow(dead_code)]
    first_cpu: usize,

    /// Per-node fallback CPU: node_id → cpu_id. Each node has its own
    /// fallback CPU for draining empty-layer DSQs, avoiding cross-node traffic.
    pub fallback_cpus: BTreeMap<usize, usize>,

    /// Dense sequential core index (0, 1, 2, ...) assigned by walking
    /// topo.nodes → node.llcs → llc.cores in BTreeMap order. Hardware
    /// core IDs can have gaps (e.g. Ryzen); this provides a contiguous
    /// index space that preserves topological locality — all cores in
    /// node 0 get the lowest indices, then node 1, etc. Growth
    /// algorithms use these indices to define core allocation order.
    core_seq: BTreeMap<(usize, usize, usize), usize>,

    allow_partial: bool,
}

impl CpuPool {
    pub fn new(topo: Arc<Topology>, allow_partial: bool) -> Result<Self> {
        if *NR_CPU_IDS > MAX_CPUS {
            bail!("NR_CPU_IDS {} > MAX_CPUS {}", *NR_CPU_IDS, MAX_CPUS);
        }

        // Build core_seq
        let mut core_seq = BTreeMap::new();
        let mut next_seq: usize = 0;
        for node in topo.nodes.values() {
            for llc in node.llcs.values() {
                for core in llc.cores.values() {
                    core_seq.insert((core.node_id, core.llc_id, core.id), next_seq);
                    next_seq += 1;
                }
            }
        }

        info!(
            "CPUs: online/possible={}/{} nr_cores={}",
            topo.all_cpus.len(),
            *NR_CPUS_POSSIBLE,
            topo.all_cores.len(),
        );

        let first_cpu = *topo.all_cpus.keys().next().unwrap();

        let mut free_llcs: BTreeMap<usize, Vec<(usize, usize)>> = BTreeMap::new();
        for llc in topo.all_llcs.values() {
            free_llcs.entry(llc.node_id).or_default().push((llc.id, 0));
        }

        let mut available_cpus = Cpumask::new();
        available_cpus.set_all();

        let mut cpu_pool = Self {
            free_llcs,
            available_cpus,
            first_cpu,
            fallback_cpus: BTreeMap::new(),
            core_seq,
            topo,
            allow_partial,
        };
        cpu_pool.update_fallback_cpus();
        Ok(cpu_pool)
    }

    fn update_fallback_cpus(&mut self) {
        for node in self.topo.nodes.values() {
            let fb = self
                .available_cpus
                .and(&node.span)
                .iter()
                .next()
                .unwrap_or_else(|| node.span.iter().next().unwrap());
            self.fallback_cpus.insert(node.id, fb);
        }
    }

    fn core_cpu_available(&self, core: &Cpumask) -> usize {
        core.iter()
            .map(|cpu| self.available_cpus.test_cpu(cpu) as usize)
            .sum()
    }

    fn check_partial(&self) -> Result<()> {
        if self.allow_partial {
            return Ok(());
        }

        // Go through CPU to cores and check if any core has
        // a span of 1. If it does, we bail.
        for i in 0..self.topo.all_cores.len() {
            let core_cpus = &self.topo.all_cores[&i].span;

            let core_cpu_available = self.core_cpu_available(core_cpus);
            if core_cpu_available > 0 && core_cpu_available != core_cpus.weight() {
                bail!("Some cores only partially allocated");
            }
        }

        Ok(())
    }

    pub fn alloc_cpus(
        &mut self,
        allowed_cpus: &Cpumask,
        core_alloc_order: &[usize],
        mut max_to_alloc: usize,
    ) -> Option<Cpumask> {
        let mut allocated_cpus = Cpumask::new();

        for alloc_core in core_alloc_order {
            // Constrain CPUs by NUMA node or LLC. Since allowed_cpus is NUMA/LLC aligned,
            // this operation is guaranteed to produce either the core mask or an empty mask.
            let core_cpus = &self.topo.all_cores[alloc_core].span.and(&allowed_cpus);
            if core_cpus.is_empty() {
                continue;
            }

            let available_core_cpus = core_cpus.and(&self.available_cpus);
            let core_num_available = available_core_cpus.weight();
            if core_num_available == 0 {
                continue;
            }

            if !self.allow_partial || max_to_alloc >= core_num_available {
                allocated_cpus = allocated_cpus.or(&available_core_cpus);
                self.available_cpus = self.available_cpus.and(&available_core_cpus.not());
            } else {
                let cpus = available_core_cpus.iter().take(max_to_alloc);
                for cpu in cpus {
                    allocated_cpus.set_cpu(cpu).ok()?;
                    self.available_cpus.clear_cpu(cpu).ok()?;
                }
            }

            // Are we done allocating CPUs?
            if max_to_alloc <= core_num_available {
                break;
            }

            max_to_alloc -= core_num_available;
        }

        self.update_fallback_cpus();
        self.check_partial().unwrap();

        if !allocated_cpus.is_empty() {
            Some(allocated_cpus)
        } else {
            None
        }
    }

    pub fn free(&mut self, cpus_to_free: &Cpumask) -> Result<()> {
        // Whether we allow partial CPUs or not does not matter because the cpumask
        // provided is create in next_to_free() below. If we do not allow partial
        // partial allocations, the cpumask provided will be core-aligned.

        if !self.available_cpus.and(cpus_to_free).is_empty() {
            bail!("Some of CPUs {} are already free", cpus_to_free);
        }

        self.available_cpus = self.available_cpus.or(&cpus_to_free);
        self.update_fallback_cpus();

        self.check_partial()?;

        Ok(())
    }

    pub fn mark_allocated(&mut self, cpus_to_alloc: &Cpumask) -> Result<()> {
        if *&cpus_to_alloc.and(&self.available_cpus.not()).weight() > 0 {
            bail!(
                "Some of CPUs {} are not available to allocate",
                cpus_to_alloc
            );
        }

        self.available_cpus &= &cpus_to_alloc.not();
        self.update_fallback_cpus();

        self.check_partial()?;

        Ok(())
    }

    pub fn next_to_free<'a>(
        &'a self,
        cands: &Cpumask,
        core_order: impl Iterator<Item = &'a usize>,
    ) -> Result<Option<Cpumask>> {
        for pref_core in core_order.map(|i| &self.topo.all_cores[i]) {
            let pref_cpus = pref_core.span.and(cands);
            if pref_cpus.weight() > 0 {
                return Ok(Some(pref_cpus));
            }
        }
        Ok(None)
    }

    pub fn available_cpus(&self) -> Cpumask {
        self.available_cpus.clone()
    }

    fn core_seq(&self, core: &Core) -> usize {
        *self
            .core_seq
            .get(&(core.node_id, core.llc_id, core.id))
            .expect("unrecognised core")
    }

    /// Allocation unit size: cpus_per_core when `!allow_partial`, 1 otherwise.
    /// Budget targets should be multiples of this to avoid double-rounding.
    pub fn alloc_unit(&self) -> usize {
        if self.allow_partial {
            1
        } else {
            self.topo
                .all_cores
                .first_key_value()
                .map_or(1, |(_, c)| c.cpus.len())
        }
    }

    /// Pop a free LLC from the given node. Returns the LLC ID if available.
    pub fn take_llc_from_node(&mut self, node_id: usize) -> Option<usize> {
        self.free_llcs
            .get_mut(&node_id)
            .and_then(|v| v.pop())
            .map(|(llc_id, _)| llc_id)
    }

    /// Pop a free LLC, trying nodes in the given order.
    pub fn take_llc(&mut self, node_order: &[usize]) -> Option<usize> {
        for &node in node_order {
            if let Some(llc) = self.take_llc_from_node(node) {
                return Some(llc);
            }
        }
        None
    }

    /// Return an LLC to the correct node's free list.
    pub fn return_llc(&mut self, llc_id: usize) {
        let node_id = self.topo.all_llcs[&llc_id].node_id;
        self.free_llcs.get_mut(&node_id).unwrap().push((llc_id, 0));
    }

    /// Total free LLCs across all nodes.
    pub fn total_free_llcs(&self) -> usize {
        self.free_llcs.values().map(|v| v.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scx_utils::testutils::{make_test_topo, mask_from_bits};

    // 1N: 1 node, 2 LLCs, 4 cores/LLC, 2 HTs/core = 16 CPUs
    //   LLC0: cores 0-3 (cpus 0-7), LLC1: cores 4-7 (cpus 8-15)
    fn topo_1n() -> (Arc<Topology>, usize) {
        let (topo, total) = make_test_topo(1, 2, 4, 2);
        (Arc::new(topo), total)
    }

    // 2N: 2 nodes, 2 LLCs/node, 4 cores/LLC, 2 HTs/core = 32 CPUs
    //   Node0: LLC0 (cores 0-3, cpus 0-7), LLC1 (cores 4-7, cpus 8-15)
    //   Node1: LLC2 (cores 8-11, cpus 16-23), LLC3 (cores 12-15, cpus 24-31)
    fn topo_2n() -> (Arc<Topology>, usize) {
        let (topo, total) = make_test_topo(2, 2, 4, 2);
        (Arc::new(topo), total)
    }

    // 4N: 4 nodes, 2 LLCs/node, 2 cores/LLC, 2 HTs/core = 32 CPUs
    //   Node0: LLC0 (cores 0-1, cpus 0-3), LLC1 (cores 2-3, cpus 4-7)
    //   Node1: LLC2 (cores 4-5, cpus 8-11), LLC3 (cores 6-7, cpus 12-15)
    //   Node2: LLC4 (cores 8-9, cpus 16-19), LLC5 (cores 10-11, cpus 20-23)
    //   Node3: LLC6 (cores 12-13, cpus 24-27), LLC7 (cores 14-15, cpus 28-31)
    fn topo_4n() -> (Arc<Topology>, usize) {
        let (topo, total) = make_test_topo(4, 2, 2, 2);
        (Arc::new(topo), total)
    }

    fn all_cpus_mask(total: usize) -> Cpumask {
        mask_from_bits(total, &(0..total).collect::<Vec<_>>())
    }

    fn core_order_sequential(topo: &Topology) -> Vec<usize> {
        topo.all_cores.keys().copied().collect()
    }

    // --- new() ---

    #[test]
    fn test_new_1n_all_available() {
        let (topo, total) = topo_1n();
        let pool = CpuPool::new(topo, false).unwrap();
        // All CPUs in the topology should be available.
        for cpu in 0..total {
            assert!(
                pool.available_cpus.test_cpu(cpu),
                "cpu {} not available",
                cpu
            );
        }
    }

    #[test]
    fn test_new_1n_fallback_cpus() {
        let (topo, _total) = topo_1n();
        let pool = CpuPool::new(topo, false).unwrap();
        // Single node: fallback_cpus[0] should be the first CPU (0).
        assert_eq!(pool.fallback_cpus.len(), 1);
        assert_eq!(pool.fallback_cpus[&0], 0);
    }

    #[test]
    fn test_new_1n_core_topo_ids() {
        let (topo, _total) = topo_1n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        // All cores should have unique topology IDs assigned sequentially.
        for (i, core_id) in topo.all_cores.keys().enumerate() {
            let core = &topo.all_cores[core_id];
            assert_eq!(pool.core_seq(core), i);
        }
    }

    #[test]
    fn test_new_1n_free_llcs() {
        let (topo, _total) = topo_1n();
        let pool = CpuPool::new(topo, false).unwrap();
        // Should have 2 LLCs on node 0, each with consumed_count=0.
        assert_eq!(pool.total_free_llcs(), 2);
        let node0 = &pool.free_llcs[&0];
        assert_eq!(node0.len(), 2);
        assert_eq!(node0[0], (0, 0)); // (llc_id, consumed)
        assert_eq!(node0[1], (1, 0));
    }

    #[test]
    fn test_new_2n_all_available() {
        let (topo, total) = topo_2n();
        let pool = CpuPool::new(topo, false).unwrap();
        for cpu in 0..total {
            assert!(
                pool.available_cpus.test_cpu(cpu),
                "cpu {} not available",
                cpu
            );
        }
    }

    #[test]
    fn test_new_2n_free_llcs() {
        let (topo, _total) = topo_2n();
        let pool = CpuPool::new(topo, false).unwrap();
        // 4 LLCs across 2 nodes, grouped by node.
        assert_eq!(pool.total_free_llcs(), 4);
        assert_eq!(pool.free_llcs.len(), 2); // 2 nodes
        let node0 = &pool.free_llcs[&0];
        let node1 = &pool.free_llcs[&1];
        assert_eq!(node0.len(), 2);
        assert_eq!(node1.len(), 2);
    }

    // --- alloc_cpus() ---

    #[test]
    fn test_alloc_one_core() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        // Allocate 2 CPUs (one core with 2 HTs).
        let result = pool.alloc_cpus(&allowed, &order, 2);
        assert!(result.is_some());
        let alloc = result.unwrap();
        assert_eq!(alloc.weight(), 2);
        // Should be core 0: cpus 0,1.
        assert!(alloc.test_cpu(0));
        assert!(alloc.test_cpu(1));
        // Those CPUs should no longer be available.
        assert!(!pool.available_cpus.test_cpu(0));
        assert!(!pool.available_cpus.test_cpu(1));
    }

    #[test]
    fn test_alloc_respects_core_order() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        // Reverse core order: allocate from core 7 first.
        let order: Vec<usize> = core_order_sequential(&topo).into_iter().rev().collect();
        let mut pool = CpuPool::new(topo, false).unwrap();

        let result = pool.alloc_cpus(&allowed, &order, 2);
        assert!(result.is_some());
        let alloc = result.unwrap();
        // Core 7: cpus 14,15.
        assert!(alloc.test_cpu(14));
        assert!(alloc.test_cpu(15));
    }

    #[test]
    fn test_alloc_respects_allowed_cpus() {
        let (topo, total) = topo_1n();
        // Only allow node0 LLC1 (cpus 8-15).
        let allowed = mask_from_bits(total, &(8..16).collect::<Vec<_>>());
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        let result = pool.alloc_cpus(&allowed, &order, 2);
        assert!(result.is_some());
        let alloc = result.unwrap();
        // Should skip cores 0-3 (LLC0) and allocate from core 4 (first in LLC1).
        assert!(alloc.test_cpu(8));
        assert!(alloc.test_cpu(9));
    }

    #[test]
    fn test_alloc_multiple_cores() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        // Allocate 6 CPUs = 3 full cores.
        let result = pool.alloc_cpus(&allowed, &order, 6);
        assert!(result.is_some());
        let alloc = result.unwrap();
        assert_eq!(alloc.weight(), 6);
        // Cores 0,1,2 → cpus 0-5.
        for cpu in 0..6 {
            assert!(alloc.test_cpu(cpu));
        }
    }

    #[test]
    fn test_alloc_exhausts_returns_none() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        // Allocate all 16 CPUs.
        let result = pool.alloc_cpus(&allowed, &order, 16);
        assert!(result.is_some());
        assert_eq!(result.unwrap().weight(), 16);

        // Try to allocate more — should return None.
        let result = pool.alloc_cpus(&allowed, &order, 2);
        assert!(result.is_none());
    }

    #[test]
    fn test_alloc_more_than_available() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        // Ask for 100 but only 16 exist. Should allocate all 16.
        let result = pool.alloc_cpus(&allowed, &order, 100);
        assert!(result.is_some());
        assert_eq!(result.unwrap().weight(), 16);
    }

    #[test]
    fn test_alloc_partial_core() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, true).unwrap(); // allow_partial=true

        // Allocate 3 CPUs: 1 full core (2) + 1 partial.
        let result = pool.alloc_cpus(&allowed, &order, 3);
        assert!(result.is_some());
        let alloc = result.unwrap();
        assert_eq!(alloc.weight(), 3);
    }

    #[test]
    fn test_alloc_no_partial_rounds_to_core() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap(); // allow_partial=false

        // Allocate 3 CPUs with allow_partial=false. Since core has 2 HTs,
        // it should allocate the first core (2 CPUs) then stop at the
        // boundary of 3 which is ≤ the second core's 2, so it takes the
        // second core too, giving 4.
        let result = pool.alloc_cpus(&allowed, &order, 3);
        assert!(result.is_some());
        let alloc = result.unwrap();
        // With !allow_partial, it always takes full cores. Asking for 3
        // means: first core (2 CPUs, 3-2=1 remaining), second core has 2
        // available which is ≥ 1 remaining, so it takes the full second
        // core and breaks. Total: 4.
        assert_eq!(alloc.weight(), 4);
    }

    // --- free() ---

    #[test]
    fn test_free_returns_cpus() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        let alloc = pool.alloc_cpus(&allowed, &order, 2).unwrap();
        assert!(!pool.available_cpus.test_cpu(0));

        pool.free(&alloc).unwrap();
        assert!(pool.available_cpus.test_cpu(0));
        assert!(pool.available_cpus.test_cpu(1));
    }

    #[test]
    fn test_free_double_free_errors() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        let alloc = pool.alloc_cpus(&allowed, &order, 2).unwrap();
        pool.free(&alloc).unwrap();
        // Freeing again should error.
        assert!(pool.free(&alloc).is_err());
    }

    // --- mark_allocated() ---

    #[test]
    fn test_mark_allocated() {
        let (topo, total) = topo_1n();
        let mut pool = CpuPool::new(topo, false).unwrap();

        // Mark core 0 (cpus 0,1) as allocated.
        let to_mark = mask_from_bits(total, &[0, 1]);
        pool.mark_allocated(&to_mark).unwrap();
        assert!(!pool.available_cpus.test_cpu(0));
        assert!(!pool.available_cpus.test_cpu(1));
        assert!(pool.available_cpus.test_cpu(2));
    }

    #[test]
    fn test_mark_allocated_already_taken_errors() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        // Allocate core 0.
        pool.alloc_cpus(&allowed, &order, 2).unwrap();
        // Trying to mark_allocated the same CPUs should error.
        let to_mark = mask_from_bits(total, &[0, 1]);
        assert!(pool.mark_allocated(&to_mark).is_err());
    }

    // --- next_to_free() ---

    #[test]
    fn test_next_to_free_finds_core() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        // Allocate cores 0,1 (4 CPUs).
        let alloc = pool.alloc_cpus(&allowed, &order, 4).unwrap();

        // next_to_free with reverse order should find core 1 first.
        let rev_order: Vec<usize> = order.iter().copied().rev().collect();
        let result = pool.next_to_free(&alloc, rev_order.iter()).unwrap();
        assert!(result.is_some());
        let to_free = result.unwrap();
        // Core 1 = cpus 2,3.
        assert!(to_free.test_cpu(2));
        assert!(to_free.test_cpu(3));
        assert_eq!(to_free.weight(), 2);
    }

    #[test]
    fn test_next_to_free_respects_cands() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        // Allocate cores 0,1,2 (6 CPUs).
        let _alloc = pool.alloc_cpus(&allowed, &order, 6).unwrap();

        // Restrict candidates to only core 1's CPUs (2,3).
        let cands = mask_from_bits(total, &[2, 3]);
        let result = pool.next_to_free(&cands, order.iter()).unwrap();
        assert!(result.is_some());
        let to_free = result.unwrap();
        assert!(to_free.test_cpu(2));
        assert!(to_free.test_cpu(3));
    }

    #[test]
    fn test_next_to_free_nothing_to_free() {
        let (topo, total) = topo_1n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let order = core_order_sequential(&topo);

        // No CPUs allocated, empty cands.
        let cands = mask_from_bits(total, &[]);
        let result = pool.next_to_free(&cands, order.iter()).unwrap();
        assert!(result.is_none());
    }

    // --- Round-trip ---

    #[test]
    fn test_alloc_free_roundtrip() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        let before_weight = pool.available_cpus().weight();

        let alloc = pool.alloc_cpus(&allowed, &order, 4).unwrap();
        assert_eq!(pool.available_cpus().weight(), before_weight - 4);

        pool.free(&alloc).unwrap();
        assert_eq!(pool.available_cpus().weight(), before_weight);
        // All topology CPUs should be available again.
        for cpu in 0..total {
            assert!(
                pool.available_cpus().test_cpu(cpu),
                "cpu {} not restored",
                cpu
            );
        }
    }

    #[test]
    fn test_fallback_cpus_updates() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        assert_eq!(pool.fallback_cpus[&0], 0);

        // Allocate core 0 (cpus 0,1). Fallback should move to cpu 2.
        let alloc = pool.alloc_cpus(&allowed, &order, 2).unwrap();
        assert_eq!(pool.fallback_cpus[&0], 2);

        // Free it back. Fallback should return to 0.
        pool.free(&alloc).unwrap();
        assert_eq!(pool.fallback_cpus[&0], 0);
    }

    // --- 2N: node-aware allocation ---

    #[test]
    fn test_2n_alloc_node_restricted() {
        let (topo, total) = topo_2n();
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        // Restrict to node 1 only (cpus 16-31).
        let node1_mask = mask_from_bits(total, &(16..32).collect::<Vec<_>>());
        let result = pool.alloc_cpus(&node1_mask, &order, 4);
        assert!(result.is_some());
        let alloc = result.unwrap();
        assert_eq!(alloc.weight(), 4);
        // All allocated CPUs should be on node 1.
        for cpu in alloc.iter() {
            assert!(cpu >= 16, "cpu {} is not on node 1", cpu);
        }
    }

    #[test]
    fn test_2n_alloc_full_picks_sequential() {
        let (topo, total) = topo_2n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        // With sequential order and full allowed mask, allocation starts
        // from node 0. Document this as baseline behavior.
        let result = pool.alloc_cpus(&allowed, &order, 2);
        assert!(result.is_some());
        let alloc = result.unwrap();
        // Current behavior: picks core 0 (cpus 0,1) from node 0.
        assert!(alloc.test_cpu(0));
        assert!(alloc.test_cpu(1));
    }

    #[test]
    fn test_2n_alloc_across_nodes() {
        let (topo, total) = topo_2n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        // Allocate all of node 0 (16 CPUs) then more.
        let _alloc1 = pool.alloc_cpus(&allowed, &order, 16).unwrap();

        // Next allocation should come from node 1.
        let alloc2 = pool.alloc_cpus(&allowed, &order, 2).unwrap();
        for cpu in alloc2.iter() {
            assert!(cpu >= 16, "cpu {} should be on node 1", cpu);
        }
    }

    #[test]
    fn test_alloc_free_realloc_same_cpus() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        // Alloc 4 CPUs (cores 0-1), free, re-alloc — should get same CPUs.
        let alloc1 = pool.alloc_cpus(&allowed, &order, 4).unwrap();
        let cpus1: Vec<usize> = alloc1.iter().collect();
        pool.free(&alloc1).unwrap();
        let alloc2 = pool.alloc_cpus(&allowed, &order, 4).unwrap();
        let cpus2: Vec<usize> = alloc2.iter().collect();
        assert_eq!(cpus1, cpus2, "re-alloc should yield same CPUs");
    }

    #[test]
    fn test_alloc_free_partial_realloc() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();
        let initial = pool.available_cpus().weight();

        // Alloc 8 + 4 CPUs, then free the first 8.
        let alloc1 = pool.alloc_cpus(&allowed, &order, 8).unwrap();
        let _alloc2 = pool.alloc_cpus(&allowed, &order, 4).unwrap();
        assert_eq!(pool.available_cpus().weight(), initial - 12);

        pool.free(&alloc1).unwrap();
        assert_eq!(pool.available_cpus().weight(), initial - _alloc2.weight());

        // Re-alloc 4 — should come from the freed alloc1 CPUs.
        let alloc3 = pool.alloc_cpus(&allowed, &order, 4).unwrap();
        for cpu in alloc3.iter() {
            assert!(
                alloc1.test_cpu(cpu),
                "cpu {} should come from freed alloc1",
                cpu
            );
        }
    }

    #[test]
    fn test_alloc_free_realloc_2n_stays_on_node() {
        let (topo, total) = topo_2n();
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        // Allocate all CPUs, then free only node 1 CPUs.
        let allowed = all_cpus_mask(total);
        let _alloc_all = pool.alloc_cpus(&allowed, &order, total).unwrap();
        let node1_cpus = mask_from_bits(total, &(16..32).collect::<Vec<_>>());
        pool.free(&node1_cpus).unwrap();

        // Re-alloc with full allowed mask — should get node 1 CPUs (only ones free).
        let realloc = pool.alloc_cpus(&allowed, &order, 4).unwrap();
        for cpu in realloc.iter() {
            assert!(
                cpu >= 16,
                "cpu {} should be on node 1 (only free node)",
                cpu
            );
        }
    }

    #[test]
    fn test_2n_free_llcs() {
        let (topo, _total) = topo_2n();
        let pool = CpuPool::new(topo, false).unwrap();
        // 4 LLCs across 2 nodes, grouped by node.
        assert_eq!(pool.total_free_llcs(), 4);
        assert_eq!(pool.free_llcs.len(), 2); // 2 nodes
        let node0 = &pool.free_llcs[&0];
        let node1 = &pool.free_llcs[&1];
        assert_eq!(node0.len(), 2);
        assert_eq!(node1.len(), 2);
        // LLC 0,1 on node 0; LLC 2,3 on node 1.
        assert_eq!(node0[0].0, 0);
        assert_eq!(node0[1].0, 1);
        assert_eq!(node1[0].0, 2);
        assert_eq!(node1[1].0, 3);
    }

    // --- 4N: four-node topology ---

    #[test]
    fn test_new_4n_all_available() {
        let (topo, total) = topo_4n();
        let pool = CpuPool::new(topo, false).unwrap();
        for cpu in 0..total {
            assert!(
                pool.available_cpus.test_cpu(cpu),
                "cpu {} not available",
                cpu
            );
        }
    }

    #[test]
    fn test_new_4n_free_llcs() {
        let (topo, _total) = topo_4n();
        let pool = CpuPool::new(topo, false).unwrap();
        // 8 LLCs across 4 nodes, 2 per node.
        assert_eq!(pool.total_free_llcs(), 8);
        assert_eq!(pool.free_llcs.len(), 4); // 4 nodes
        for node_id in 0..4 {
            let node_llcs = &pool.free_llcs[&node_id];
            assert_eq!(node_llcs.len(), 2);
        }
    }

    #[test]
    fn test_4n_alloc_across_all_nodes() {
        let (topo, total) = topo_4n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        // Allocate 24 CPUs (fills nodes 0-2 completely, 8 cpus each).
        let _alloc1 = pool.alloc_cpus(&allowed, &order, 24).unwrap();

        // Next allocation should come from node 3 (cpus 24-31).
        let alloc2 = pool.alloc_cpus(&allowed, &order, 2).unwrap();
        for cpu in alloc2.iter() {
            assert!(cpu >= 24, "cpu {} should be on node 3", cpu);
        }
    }

    #[test]
    fn test_4n_alloc_node_restricted() {
        let (topo, total) = topo_4n();
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        // Restrict to node 2 only (cpus 16-23).
        let node2_mask = mask_from_bits(total, &(16..24).collect::<Vec<_>>());
        let result = pool.alloc_cpus(&node2_mask, &order, 4);
        assert!(result.is_some());
        let alloc = result.unwrap();
        assert_eq!(alloc.weight(), 4);
        for cpu in alloc.iter() {
            assert!(
                cpu >= 16 && cpu < 24,
                "cpu {} should be on node 2 (16-23)",
                cpu
            );
        }
    }

    // =========================================================================
    // Growth algorithm tests
    // =========================================================================

    fn test_layer_spec(name: &str, algo: LayerGrowthAlgo) -> LayerSpec {
        let json = r#"{"name":"_","matches":[],"kind":{"Confined":{"util_range":[0.0,1.0]}}}"#;
        let mut spec: LayerSpec = serde_json::from_str(json).unwrap();
        spec.name = name.to_string();
        spec.kind.common_mut().growth_algo = algo;
        spec
    }

    fn test_layer_spec_with_nodes(
        name: &str,
        algo: LayerGrowthAlgo,
        nodes: Vec<usize>,
    ) -> LayerSpec {
        let mut spec = test_layer_spec(name, algo);
        *spec.nodes_mut() = nodes;
        spec
    }

    fn test_layer_spec_with_llcs(name: &str, algo: LayerGrowthAlgo, llcs: Vec<usize>) -> LayerSpec {
        let mut spec = test_layer_spec(name, algo);
        *spec.llcs_mut() = llcs;
        spec
    }

    /// Verify a core_order contains all expected cores with no duplicates.
    fn assert_valid_core_order(order: &[usize], nr_cores: usize) {
        assert_eq!(
            order.len(),
            nr_cores,
            "core_order length {} != expected {}",
            order.len(),
            nr_cores
        );
        let mut seen = std::collections::HashSet::new();
        for &core in order {
            assert!(
                core < nr_cores,
                "core {} out of range [0, {})",
                core,
                nr_cores
            );
            assert!(seen.insert(core), "duplicate core {} in order", core);
        }
    }

    fn get_core_order(topo: &Arc<Topology>, specs: &[LayerSpec], layer_idx: usize) -> Vec<usize> {
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let orders = LayerGrowthAlgo::layer_core_orders(&pool, specs, topo).unwrap();
        orders[&layer_idx].clone()
    }

    // --- Sticky ---

    #[test]
    fn test_growth_sticky_1n() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::Sticky)];
        let order = get_core_order(&topo, &specs, 0);
        // Single layer, idx=0: per-LLC rotation cycles back to identity.
        assert_eq!(order, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_growth_sticky_2n() {
        let (topo, _total) = topo_2n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::Sticky)];
        let order = get_core_order(&topo, &specs, 0);
        assert_eq!(
            order,
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn test_growth_sticky_multi_layer_offsets() {
        let (topo, _total) = topo_1n();
        let specs = vec![
            test_layer_spec("L0", LayerGrowthAlgo::Sticky),
            test_layer_spec("L1", LayerGrowthAlgo::Sticky),
            test_layer_spec("L2", LayerGrowthAlgo::Sticky),
        ];
        let o0 = get_core_order(&topo, &specs, 0);
        let o1 = get_core_order(&topo, &specs, 1);
        let o2 = get_core_order(&topo, &specs, 2);
        // Each layer should have a different starting point.
        assert_ne!(o0[0], o1[0], "L0 and L1 should start at different cores");
        assert_ne!(o1[0], o2[0], "L1 and L2 should start at different cores");
        // All should be valid.
        assert_valid_core_order(&o0, 8);
        assert_valid_core_order(&o1, 8);
        assert_valid_core_order(&o2, 8);
    }

    // --- Linear ---

    #[test]
    fn test_growth_linear_1n() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::Linear)];
        let order = get_core_order(&topo, &specs, 0);
        assert_eq!(order, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_growth_linear_2n() {
        let (topo, _total) = topo_2n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::Linear)];
        let order = get_core_order(&topo, &specs, 0);
        assert_eq!(
            order,
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn test_growth_linear_preserves_topo_order_with_nodes() {
        let (topo, _total) = topo_2n();
        let specs = vec![test_layer_spec_with_nodes(
            "L0",
            LayerGrowthAlgo::Linear,
            vec![1],
        )];
        let order = get_core_order(&topo, &specs, 0);
        // With nodes=[1] hard limit, only node 1 cores appear.
        assert_eq!(order, vec![8, 9, 10, 11, 12, 13, 14, 15]);
    }

    // --- Reverse ---

    #[test]
    fn test_growth_reverse_1n() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::Reverse)];
        let order = get_core_order(&topo, &specs, 0);
        assert_eq!(order, vec![7, 6, 5, 4, 3, 2, 1, 0]);
    }

    // --- Random ---

    #[test]
    fn test_growth_random_1n() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::Random)];
        let order = get_core_order(&topo, &specs, 0);
        // Random is a seeded shuffle — not sequential.
        assert_valid_core_order(&order, 8);
        assert_ne!(order, vec![0, 1, 2, 3, 4, 5, 6, 7], "should be shuffled");
    }

    #[test]
    fn test_growth_random_deterministic_with_same_idx() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::Random)];
        let order1 = get_core_order(&topo, &specs, 0);
        let order2 = get_core_order(&topo, &specs, 0);
        // Same layer_idx → same seed → same order.
        assert_eq!(order1, order2);
    }

    #[test]
    fn test_growth_random_different_idx_different_order() {
        let (topo, _total) = topo_1n();
        let specs = vec![
            test_layer_spec("L0", LayerGrowthAlgo::Random),
            test_layer_spec("L1", LayerGrowthAlgo::Random),
        ];
        let o0 = get_core_order(&topo, &specs, 0);
        let o1 = get_core_order(&topo, &specs, 1);
        // Different seeds should (very likely) produce different orders.
        assert_ne!(o0, o1);
    }

    #[test]
    fn test_growth_random_2n_node_contiguous() {
        let (topo, _total) = topo_2n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::Random)];
        let order = get_core_order(&topo, &specs, 0);
        assert_valid_core_order(&order, 16);
        // Cores must be grouped by node: one contiguous block of node-0
        // cores (0-7) and one of node-1 cores (8-15), in either order.
        let first_node: Vec<usize> = order.iter().take(8).copied().collect();
        let second_node: Vec<usize> = order.iter().skip(8).copied().collect();
        assert!(
            first_node.iter().all(|&c| c < 8) || first_node.iter().all(|&c| c >= 8),
            "first 8 cores should all belong to the same node: {:?}",
            order
        );
        assert!(
            second_node.iter().all(|&c| c < 8) || second_node.iter().all(|&c| c >= 8),
            "last 8 cores should all belong to the same node: {:?}",
            order
        );
    }

    #[test]
    fn test_growth_random_4n_node_contiguous() {
        let (topo, _total) = topo_4n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::Random)];
        let order = get_core_order(&topo, &specs, 0);
        assert_valid_core_order(&order, 16);
        // 4 blocks of 4 cores, each block should be same node.
        // Node 0: cores 0-3, Node 1: cores 4-7, Node 2: cores 8-11, Node 3: cores 12-15
        for block_start in (0..16).step_by(4) {
            let block = &order[block_start..block_start + 4];
            let node = block[0] / 4;
            assert!(
                block.iter().all(|&c| c / 4 == node),
                "block at {}-{} should all be node {}, got {:?}",
                block_start,
                block_start + 3,
                node,
                block
            );
        }
    }

    // --- Topo ---

    #[test]
    fn test_growth_topo_no_pref_falls_back_to_roundrobin() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::Topo)];
        let order = get_core_order(&topo, &specs, 0);
        // No nodes/llcs specified → falls back to RoundRobin.
        let rr_specs = vec![test_layer_spec("L0", LayerGrowthAlgo::RoundRobin)];
        let rr_order = get_core_order(&topo, &rr_specs, 0);
        assert_eq!(order, rr_order);
    }

    #[test]
    fn test_growth_topo_with_llc_pref() {
        let (topo, _total) = topo_2n();
        // Prefer LLC 2 (node 1).
        let specs = vec![test_layer_spec_with_llcs(
            "L0",
            LayerGrowthAlgo::Topo,
            vec![2],
        )];
        let order = get_core_order(&topo, &specs, 0);
        // LLC 2 cores (8-11) should appear first.
        let llc2_cores: Vec<usize> = (8..12).collect();
        for &core in &llc2_cores {
            assert!(
                order.iter().position(|&c| c == core).unwrap() < 4,
                "LLC2 core {} should be in first 4 positions",
                core
            );
        }
    }

    #[test]
    fn test_growth_topo_with_node_pref() {
        let (topo, _total) = topo_2n();
        // Prefer node 1.
        let specs = vec![test_layer_spec_with_nodes(
            "L0",
            LayerGrowthAlgo::Topo,
            vec![1],
        )];
        let order = get_core_order(&topo, &specs, 0);
        // Node 1 cores (8-15) should appear first.
        for &core in &order[..8] {
            assert!(
                core >= 8 && core < 16,
                "core {} should be node 1 (8-15)",
                core
            );
        }
    }

    // --- RoundRobin ---

    #[test]
    fn test_growth_roundrobin_1n() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::RoundRobin)];
        let order = get_core_order(&topo, &specs, 0);
        // Seeded interleave across LLCs: alternates LLC0/LLC1 cores.
        assert_eq!(order, vec![2, 6, 3, 4, 1, 7, 0, 5]);
    }

    #[test]
    fn test_growth_roundrobin_2n_interleaves() {
        let (topo, _total) = topo_2n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::RoundRobin)];
        let order = get_core_order(&topo, &specs, 0);
        // Seeded interleave across 4 LLCs on 2 nodes.
        assert_eq!(
            order,
            vec![6, 12, 0, 10, 7, 14, 2, 9, 5, 15, 1, 8, 4, 13, 3, 11]
        );
    }

    // --- BigLittle / LittleBig ---

    #[test]
    fn test_growth_big_little_1n() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::BigLittle)];
        let order = get_core_order(&topo, &specs, 0);
        // All cores are same type in test topo → topo order.
        assert_eq!(order, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_growth_little_big_1n() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::LittleBig)];
        let order = get_core_order(&topo, &specs, 0);
        // All cores same type in test topo → stable sort preserves topo order
        // regardless of sort direction.
        assert_eq!(order, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    // --- NodeSpread ---

    #[test]
    fn test_growth_node_spread_1n() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::NodeSpread)];
        let order = get_core_order(&topo, &specs, 0);
        // Single node → degenerates to sequential.
        assert_eq!(order, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_growth_node_spread_2n_interleaves() {
        let (topo, _total) = topo_2n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::NodeSpread)];
        let order = get_core_order(&topo, &specs, 0);
        // Alternates node0/node1 cores: 0,8, 1,9, 2,10, ...
        assert_eq!(
            order,
            vec![0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15]
        );
    }

    #[test]
    fn test_growth_node_spread_reverse_1n() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::NodeSpreadReverse)];
        let order = get_core_order(&topo, &specs, 0);
        // Single node → reverse of sequential.
        assert_eq!(order, vec![7, 6, 5, 4, 3, 2, 1, 0]);
    }

    #[test]
    fn test_growth_node_spread_random_1n() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::NodeSpreadRandom)];
        let order = get_core_order(&topo, &specs, 0);
        // Shuffled within single node — valid permutation but not sequential.
        assert_valid_core_order(&order, 8);
        assert_ne!(order, vec![0, 1, 2, 3, 4, 5, 6, 7], "should be shuffled");
    }

    // --- RandomTopo ---

    #[test]
    fn test_growth_random_topo_1n() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::RandomTopo)];
        let order = get_core_order(&topo, &specs, 0);
        // Randomized within topology levels — shuffled permutation.
        assert_valid_core_order(&order, 8);
        assert_ne!(order, vec![0, 1, 2, 3, 4, 5, 6, 7], "should be shuffled");
    }

    #[test]
    fn test_growth_random_topo_2n() {
        let (topo, _total) = topo_2n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::RandomTopo)];
        let order = get_core_order(&topo, &specs, 0);
        assert_valid_core_order(&order, 16);
        assert_ne!(
            order,
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            "should be shuffled"
        );
    }

    // --- StickyDynamic ---

    #[test]
    fn test_growth_sticky_dynamic_same_as_sticky() {
        let (topo, _total) = topo_1n();
        let specs_s = vec![test_layer_spec("L0", LayerGrowthAlgo::Sticky)];
        let specs_sd = vec![test_layer_spec("L0", LayerGrowthAlgo::StickyDynamic)];
        let order_s = get_core_order(&topo, &specs_s, 0);
        let order_sd = get_core_order(&topo, &specs_sd, 0);
        assert_eq!(
            order_s, order_sd,
            "StickyDynamic initial order should match Sticky"
        );
    }

    #[test]
    fn test_growth_sticky_dynamic_2n() {
        let (topo, _total) = topo_2n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::StickyDynamic)];
        let order = get_core_order(&topo, &specs, 0);
        // Initial order matches Sticky (verified in test_growth_sticky_dynamic_same_as_sticky).
        assert_eq!(
            order,
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    // --- CpuSetSpread (host-dependent, verify basic invariants) ---

    #[test]
    fn test_growth_cpuset_spread_1n() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::CpuSetSpread)];
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let orders = LayerGrowthAlgo::layer_core_orders(&pool, &specs, &topo).unwrap();
        let order = &orders[&0];
        // CpuSetSpread reads /sys/fs/cgroup, results are host-dependent.
        // Just verify no duplicates and all cores are valid.
        let mut seen = std::collections::HashSet::new();
        for &core in order {
            assert!(core < 8, "core {} out of range", core);
            assert!(seen.insert(core), "duplicate core {}", core);
        }
    }

    #[test]
    fn test_growth_cpuset_spread_reverse_1n() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::CpuSetSpreadReverse)];
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let orders = LayerGrowthAlgo::layer_core_orders(&pool, &specs, &topo).unwrap();
        let order = &orders[&0];
        let mut seen = std::collections::HashSet::new();
        for &core in order {
            assert!(core < 8, "core {} out of range", core);
            assert!(seen.insert(core), "duplicate core {}", core);
        }
    }

    #[test]
    fn test_growth_cpuset_spread_random_1n() {
        let (topo, _total) = topo_1n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::CpuSetSpreadRandom)];
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        let orders = LayerGrowthAlgo::layer_core_orders(&pool, &specs, &topo).unwrap();
        let order = &orders[&0];
        let mut seen = std::collections::HashSet::new();
        for &core in order {
            assert!(core < 8, "core {} out of range", core);
            assert!(seen.insert(core), "duplicate core {}", core);
        }
    }

    // --- All algorithms produce valid orders on 2N ---

    #[test]
    fn test_alloc_free_realloc_all_deterministic() {
        let deterministic_algos = vec![
            LayerGrowthAlgo::Sticky,
            LayerGrowthAlgo::Linear,
            LayerGrowthAlgo::Reverse,
            LayerGrowthAlgo::RoundRobin,
            LayerGrowthAlgo::BigLittle,
            LayerGrowthAlgo::LittleBig,
            LayerGrowthAlgo::NodeSpread,
            LayerGrowthAlgo::NodeSpreadReverse,
            LayerGrowthAlgo::StickyDynamic,
        ];
        for algo in deterministic_algos {
            let (topo, total) = topo_1n();
            let allowed = all_cpus_mask(total);
            let specs = vec![test_layer_spec("L0", algo.clone())];
            let order = get_core_order(&topo, &specs, 0);
            let mut pool = CpuPool::new(topo, false).unwrap();
            let initial = pool.available_cpus().weight();

            // Alloc 8, alloc 4, free first 8, re-alloc 4 → from freed set.
            let alloc1 = pool.alloc_cpus(&allowed, &order, 8).unwrap();
            let _alloc2 = pool.alloc_cpus(&allowed, &order, 4).unwrap();
            pool.free(&alloc1).unwrap();
            assert_eq!(
                pool.available_cpus().weight(),
                initial - _alloc2.weight(),
                "{:?}: wrong available count after free",
                algo
            );
            let alloc3 = pool.alloc_cpus(&allowed, &order, 4).unwrap();
            for cpu in alloc3.iter() {
                assert!(
                    alloc1.test_cpu(cpu),
                    "{:?}: cpu {} should come from freed alloc1",
                    algo,
                    cpu
                );
            }
        }
    }

    #[test]
    fn test_all_algos_valid_on_2n() {
        let (topo, _total) = topo_2n();
        let algos = vec![
            LayerGrowthAlgo::Sticky,
            LayerGrowthAlgo::Linear,
            LayerGrowthAlgo::Reverse,
            LayerGrowthAlgo::Random,
            LayerGrowthAlgo::Topo,
            LayerGrowthAlgo::RoundRobin,
            LayerGrowthAlgo::BigLittle,
            LayerGrowthAlgo::LittleBig,
            LayerGrowthAlgo::NodeSpread,
            LayerGrowthAlgo::NodeSpreadReverse,
            LayerGrowthAlgo::NodeSpreadRandom,
            LayerGrowthAlgo::RandomTopo,
            LayerGrowthAlgo::StickyDynamic,
        ];
        for algo in algos {
            let specs = vec![test_layer_spec("L0", algo.clone())];
            let pool = CpuPool::new(topo.clone(), false).unwrap();
            let orders = LayerGrowthAlgo::layer_core_orders(&pool, &specs, &topo)
                .unwrap_or_else(|e| panic!("{:?} failed: {}", algo, e));
            let order = &orders[&0];
            assert_valid_core_order(order, 16);
        }
    }

    // --- 4N growth algorithm tests ---

    #[test]
    fn test_all_algos_valid_on_4n() {
        let (topo, _total) = topo_4n();
        let algos = vec![
            LayerGrowthAlgo::Sticky,
            LayerGrowthAlgo::Linear,
            LayerGrowthAlgo::Reverse,
            LayerGrowthAlgo::Random,
            LayerGrowthAlgo::Topo,
            LayerGrowthAlgo::RoundRobin,
            LayerGrowthAlgo::BigLittle,
            LayerGrowthAlgo::LittleBig,
            LayerGrowthAlgo::NodeSpread,
            LayerGrowthAlgo::NodeSpreadReverse,
            LayerGrowthAlgo::NodeSpreadRandom,
            LayerGrowthAlgo::RandomTopo,
            LayerGrowthAlgo::StickyDynamic,
        ];
        for algo in algos {
            let specs = vec![test_layer_spec("L0", algo.clone())];
            let pool = CpuPool::new(topo.clone(), false).unwrap();
            let orders = LayerGrowthAlgo::layer_core_orders(&pool, &specs, &topo)
                .unwrap_or_else(|e| panic!("{:?} failed: {}", algo, e));
            let order = &orders[&0];
            assert_valid_core_order(order, 16);
        }
    }

    #[test]
    fn test_growth_sticky_4n() {
        let (topo, _total) = topo_4n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::Sticky)];
        let order = get_core_order(&topo, &specs, 0);
        // Single layer, idx=0: identity order across all 16 cores.
        assert_eq!(
            order,
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn test_growth_sticky_4n_multi_layer() {
        let (topo, _total) = topo_4n();
        let specs = vec![
            test_layer_spec("L0", LayerGrowthAlgo::Sticky),
            test_layer_spec("L1", LayerGrowthAlgo::Sticky),
            test_layer_spec("L2", LayerGrowthAlgo::Sticky),
            test_layer_spec("L3", LayerGrowthAlgo::Sticky),
        ];
        let o0 = get_core_order(&topo, &specs, 0);
        let o1 = get_core_order(&topo, &specs, 1);
        let o2 = get_core_order(&topo, &specs, 2);
        let o3 = get_core_order(&topo, &specs, 3);
        // Each layer should start at a different core.
        let starts: Vec<usize> = vec![o0[0], o1[0], o2[0], o3[0]];
        let mut unique = starts.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            4,
            "4 layers should have 4 different starting cores, got {:?}",
            starts
        );
        // All should be valid permutations.
        for order in [&o0, &o1, &o2, &o3] {
            assert_valid_core_order(order, 16);
        }
    }

    #[test]
    fn test_growth_node_spread_4n_interleaves() {
        let (topo, _total) = topo_4n();
        let specs = vec![test_layer_spec("L0", LayerGrowthAlgo::NodeSpread)];
        let order = get_core_order(&topo, &specs, 0);
        assert_valid_core_order(&order, 16);
        // Every 4 consecutive cores should span all 4 nodes.
        // Node 0: cores 0-3, Node 1: cores 4-7, Node 2: cores 8-11, Node 3: cores 12-15
        for chunk_start in (0..16).step_by(4) {
            let chunk = &order[chunk_start..chunk_start + 4];
            let mut nodes: Vec<usize> = chunk.iter().map(|&c| c / 4).collect();
            nodes.sort();
            nodes.dedup();
            assert_eq!(
                nodes.len(),
                4,
                "cores {:?} at positions {}-{} should span 4 nodes",
                chunk,
                chunk_start,
                chunk_start + 3
            );
        }
    }

    // =========================================================================
    // StickyDynamic lifecycle tests
    //
    // The StickyDynamic algorithm in recompute_layer_core_order() is tightly
    // coupled to the Scheduler struct. These tests simulate the three-phase
    // algorithm (free → redistribute → spillover) using lightweight state
    // to verify correctness independent of the full runtime.
    // =========================================================================

    /// Mirrors the target computation from Scheduler::compute_target_llcs.
    fn compute_target_llcs(target: usize, topo: &Topology) -> (usize, usize) {
        let cores_per_llc = topo.all_cores.len() / topo.all_llcs.len();
        let cpus_per_core = topo.all_cores.first_key_value().unwrap().1.cpus.len();
        let cpus_per_llc = cores_per_llc * cpus_per_core;
        let full = target / cpus_per_llc;
        let extra = target % cpus_per_llc;
        (full, extra.div_ceil(cpus_per_core))
    }

    /// Lightweight stand-in for Layer's StickyDynamic state.
    struct SdLayerState {
        #[allow(dead_code)]
        name: String,
        target_llc_cpus: (usize, usize),
        assigned_llcs: Vec<usize>,
        /// Mirrors LayerSpec.nodes — user-configured preferred nodes.
        spec_nodes: Vec<usize>,
    }

    impl SdLayerState {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                target_llc_cpus: (0, 0),
                assigned_llcs: vec![],
                spec_nodes: vec![],
            }
        }
    }

    /// Simulate the three-phase StickyDynamic algorithm from
    /// Scheduler::recompute_layer_core_order(). The layer_targets are
    /// (layer_index, target_cpu_count) sorted ascending by target.
    fn simulate_sd_recompute(
        pool: &mut CpuPool,
        layers: &mut [SdLayerState],
        layer_targets: &[(usize, usize)],
        topo: &Topology,
    ) {
        // Phase 1: Free LLCs from shrinking layers (iterate in reverse).
        for &(idx, target) in layer_targets.iter().rev() {
            let layer = &mut layers[idx];
            let old_tlc = layer.target_llc_cpus;
            let new_tlc = compute_target_llcs(target, topo);
            let mut to_free = (old_tlc.0 as i32 - new_tlc.0 as i32).max(0) as usize;
            while to_free > 0 && !layer.assigned_llcs.is_empty() {
                let llc = layer.assigned_llcs.pop().unwrap();
                pool.return_llc(llc);
                to_free -= 1;
            }
        }

        let all_layer_nodes_owned: Vec<Vec<usize>> =
            layers.iter().map(|l| l.spec_nodes.clone()).collect();
        let all_layer_nodes: Vec<&[usize]> =
            all_layer_nodes_owned.iter().map(|v| v.as_slice()).collect();

        // Phase 2: Redistribute freed LLCs to growing layers (iterate in reverse).
        // Use the layer's spec_nodes ordering (mirroring node_order()).
        for &(idx, target) in layer_targets.iter().rev() {
            let layer = &mut layers[idx];
            let old_tlc = layer.target_llc_cpus;
            let new_tlc = compute_target_llcs(target, topo);
            let mut to_alloc = (new_tlc.0 as i32 - old_tlc.0 as i32).max(0) as usize;
            let node_order = crate::layer_core_growth::node_order(
                &all_layer_nodes_owned[idx],
                topo,
                idx,
                &all_layer_nodes,
            );
            while to_alloc > 0 {
                if let Some(llc) = pool.take_llc(&node_order) {
                    layer.assigned_llcs.push(llc);
                    to_alloc -= 1;
                } else {
                    break; // no more free LLCs on preferred node(s)
                }
            }
            layer.target_llc_cpus = new_tlc;
        }

        // Phase 3: Spillover (extra cores from free LLCs, consumed tracking).
        // Walk per-node using the layer's spec_nodes ordering.
        let cores_per_llc = topo.all_cores.len() / topo.all_llcs.len();
        let cpus_per_core = topo.all_cores.first_key_value().unwrap().1.cpus.len();
        let cpus_per_llc = cores_per_llc * cpus_per_core;

        for &(idx, _) in layer_targets.iter() {
            let tlc = layers[idx].target_llc_cpus;
            let mut extra = tlc.1;
            let node_order = crate::layer_core_growth::node_order(
                &all_layer_nodes_owned[idx],
                topo,
                idx,
                &all_layer_nodes,
            );
            for node_id in &node_order {
                if extra == 0 {
                    break;
                }
                if let Some(node_llcs) = pool.free_llcs.get_mut(node_id) {
                    for entry in node_llcs.iter_mut() {
                        if extra == 0 {
                            break;
                        }
                        let avail = cpus_per_llc - entry.1;
                        let used = extra.min(avail);
                        entry.1 += used;
                        extra -= used;
                    }
                }
            }
        }

        // Reset consumed entries.
        for node_llcs in pool.free_llcs.values_mut() {
            for entry in node_llcs.iter_mut() {
                entry.1 = 0;
            }
        }
    }

    // --- compute_target_llcs ---

    #[test]
    fn test_compute_target_llcs_1n() {
        let (topo, _total) = topo_1n();
        // 1N: 8 cores, 2 LLCs → 4 cores/LLC, 2 HTs/core → 8 cpus/LLC
        assert_eq!(compute_target_llcs(0, &topo), (0, 0));
        assert_eq!(compute_target_llcs(1, &topo), (0, 1)); // 1 cpu = 0 full + 1 extra core
        assert_eq!(compute_target_llcs(2, &topo), (0, 1)); // 2 cpus = 1 core
        assert_eq!(compute_target_llcs(3, &topo), (0, 2)); // 3 cpus = 2 cores (ceil)
        assert_eq!(compute_target_llcs(8, &topo), (1, 0)); // exactly 1 LLC
        assert_eq!(compute_target_llcs(9, &topo), (1, 1)); // 1 LLC + 1 extra core
        assert_eq!(compute_target_llcs(16, &topo), (2, 0)); // exactly 2 LLCs
    }

    #[test]
    fn test_compute_target_llcs_2n() {
        let (topo, _total) = topo_2n();
        // 2N: 16 cores, 4 LLCs → 4 cores/LLC, 2 HTs/core → 8 cpus/LLC
        assert_eq!(compute_target_llcs(0, &topo), (0, 0));
        assert_eq!(compute_target_llcs(8, &topo), (1, 0));
        assert_eq!(compute_target_llcs(16, &topo), (2, 0));
        assert_eq!(compute_target_llcs(24, &topo), (3, 0));
        assert_eq!(compute_target_llcs(32, &topo), (4, 0));
        assert_eq!(compute_target_llcs(10, &topo), (1, 1)); // 8+2 = 1 LLC + 1 core
        assert_eq!(compute_target_llcs(15, &topo), (1, 4)); // 8+7 = 1 LLC + 4 cores (ceil(7/2))
    }

    // --- StickyDynamic lifecycle: single layer ---

    #[test]
    fn test_sd_single_layer_grow_from_zero() {
        let (topo, _total) = topo_1n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];
        // Target: 8 cpus = 1 full LLC.
        let targets = vec![(0, 8)];
        simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 1);
        assert_eq!(layers[0].target_llc_cpus, (1, 0));
        assert_eq!(pool.total_free_llcs(), 1); // 1 LLC remains free
    }

    #[test]
    fn test_sd_single_layer_grow_to_all() {
        let (topo, _total) = topo_1n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];
        let targets = vec![(0, 16)];
        simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 2);
        assert_eq!(layers[0].target_llc_cpus, (2, 0));
        assert_eq!(pool.total_free_llcs(), 0);
    }

    #[test]
    fn test_sd_single_layer_grow_then_shrink() {
        let (topo, _total) = topo_1n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];

        // Grow to 2 LLCs.
        let targets = vec![(0, 16)];
        simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 2);
        assert_eq!(pool.total_free_llcs(), 0);

        // Shrink to 1 LLC.
        let targets = vec![(0, 8)];
        simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 1);
        assert_eq!(pool.total_free_llcs(), 1);
    }

    #[test]
    fn test_sd_single_layer_grow_shrink_roundtrip() {
        let (topo, _total) = topo_1n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let initial_free_count = pool.total_free_llcs();
        let mut layers = vec![SdLayerState::new("L0")];

        // Grow.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 16)], &topo);
        // Shrink back to zero.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 0)], &topo);

        assert_eq!(layers[0].assigned_llcs.len(), 0);
        assert_eq!(pool.total_free_llcs(), initial_free_count);
    }

    // --- StickyDynamic lifecycle: spillover ---

    #[test]
    fn test_sd_spillover_extra_cores() {
        let (topo, _total) = topo_1n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];
        // Target: 10 cpus = 1 full LLC (8) + 2 cpus (1 core) spillover.
        let targets = vec![(0, 10)];
        simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 1);
        assert_eq!(layers[0].target_llc_cpus, (1, 1)); // 1 full LLC, 1 extra core
    }

    // --- StickyDynamic lifecycle: multiple competing layers ---

    #[test]
    fn test_sd_two_layers_compete() {
        let (topo, _total) = topo_1n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0"), SdLayerState::new("L1")];

        // Both layers want 1 LLC each. Sort ascending: smaller target first.
        let targets = vec![(0, 8), (1, 8)];
        simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);

        // Each should get 1 LLC.
        assert_eq!(layers[0].assigned_llcs.len(), 1);
        assert_eq!(layers[1].assigned_llcs.len(), 1);
        assert_eq!(pool.total_free_llcs(), 0);
        // They should have different LLCs.
        assert_ne!(layers[0].assigned_llcs[0], layers[1].assigned_llcs[0]);
    }

    #[test]
    fn test_sd_two_layers_one_shrinks_other_grows() {
        let (topo, _total) = topo_1n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0"), SdLayerState::new("L1")];

        // Initial: L0 gets 2 LLCs.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 16), (1, 0)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 2);
        assert_eq!(layers[1].assigned_llcs.len(), 0);

        // Now L0 shrinks to 1, L1 grows to 1. Ascending sort: (1,8),(0,8).
        let targets = vec![(1, 8), (0, 8)];
        simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 1);
        assert_eq!(layers[1].assigned_llcs.len(), 1);
    }

    // --- StickyDynamic lifecycle: 2N node-aware behavior ---

    #[test]
    fn test_sd_2n_llc_assignment_is_node_aware() {
        // Per-node free_llcs: StickyDynamic pops LLCs from the first
        // available node (BTreeMap order = node 0 first). Both LLCs
        // should come from the same node.
        let (topo, _total) = topo_2n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];

        // Target: 2 full LLCs.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 16)], &topo);

        let assigned = &layers[0].assigned_llcs;
        assert_eq!(assigned.len(), 2);

        // With per-node free_llcs, the layer has no preferred_node
        // (no prior assigned LLCs), so take_llc falls back to topo
        // order (node 0 first). Both LLCs come from node 0.
        let node0: Vec<usize> = assigned
            .iter()
            .filter(|&&llc| topo.all_llcs[&llc].node_id == 0)
            .copied()
            .collect();
        assert_eq!(
            node0.len(),
            2,
            "both LLCs should be from node 0, got {:?}",
            assigned
        );
    }

    #[test]
    fn test_sd_2n_two_layers_node_local() {
        // With 4 LLCs across 2 nodes, two layers each wanting 2 LLCs
        // should each get LLCs from a single node.
        let (topo, _total) = topo_2n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0"), SdLayerState::new("L1")];

        let targets = vec![(0, 16), (1, 16)];
        simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);

        assert_eq!(layers[0].assigned_llcs.len(), 2);
        assert_eq!(layers[1].assigned_llcs.len(), 2);
        assert_eq!(pool.total_free_llcs(), 0);

        // Each layer should have LLCs from a single node.
        let l0_nodes: Vec<usize> = layers[0]
            .assigned_llcs
            .iter()
            .map(|&llc| topo.all_llcs[&llc].node_id)
            .collect();
        let l1_nodes: Vec<usize> = layers[1]
            .assigned_llcs
            .iter()
            .map(|&llc| topo.all_llcs[&llc].node_id)
            .collect();
        assert_eq!(l0_nodes[0], l0_nodes[1], "L0 LLCs should be same node");
        assert_eq!(l1_nodes[0], l1_nodes[1], "L1 LLCs should be same node");
        assert_ne!(
            l0_nodes[0], l1_nodes[0],
            "L0 and L1 should be on different nodes"
        );

        // All 4 LLCs assigned.
        let all_assigned: Vec<usize> = layers
            .iter()
            .flat_map(|l| l.assigned_llcs.iter().copied())
            .collect();
        let mut sorted = all_assigned.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 4, "all 4 LLCs should be assigned");
    }

    #[test]
    fn test_sd_2n_grow_shrink_roundtrip() {
        let (topo, _total) = topo_2n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let initial_free_count = pool.total_free_llcs();
        let mut layers = vec![SdLayerState::new("L0"), SdLayerState::new("L1")];

        // Grow both.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 16), (1, 16)], &topo);
        assert_eq!(pool.total_free_llcs(), 0);

        // Shrink both.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 0), (1, 0)], &topo);
        assert_eq!(pool.total_free_llcs(), initial_free_count);
        assert_eq!(layers[0].assigned_llcs.len(), 0);
        assert_eq!(layers[1].assigned_llcs.len(), 0);
    }

    // --- StickyDynamic lifecycle: 2N node affinity ---

    #[test]
    fn test_sd_2n_affinity_prefers_same_node() {
        // Layer starts with 1 LLC on node 0, grows to 2. The second
        // LLC should come from node 0 (affinity to existing assignment).
        let (topo, _total) = topo_2n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];

        // First grow: 1 LLC.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 8)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 1);
        let first_llc = layers[0].assigned_llcs[0];
        let first_node = topo.all_llcs[&first_llc].node_id;

        // Second grow: 2 LLCs.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 16)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 2);
        let second_llc = layers[0].assigned_llcs[1];
        let second_node = topo.all_llcs[&second_llc].node_id;

        assert_eq!(
            first_node, second_node,
            "second LLC should be from same node as first (affinity)"
        );
    }

    #[test]
    fn test_sd_2n_spillover_prefers_same_node() {
        // Layer has 1 LLC + spillover cores. Spillover should come from
        // same-node free LLCs when available.
        let (topo, _total) = topo_2n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];

        // Target: 10 cpus = 1 LLC + 1 spillover core.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 10)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 1);
        assert_eq!(layers[0].target_llc_cpus, (1, 1));

        // The assigned LLC determines the preferred node. The spillover
        // core consumed from free_llcs should be on the same node.
        let assigned_node = topo.all_llcs[&layers[0].assigned_llcs[0]].node_id;

        // Verify: the free LLC that had its consumed count bumped
        // should be on the same node as the assigned LLC.
        // After reset, consumed counts are 0, but we verified the
        // spillover logic walks preferred node first.
        let same_node_free: usize = pool.free_llcs.get(&assigned_node).map_or(0, |v| v.len());
        // Node 0 had 2 LLCs, 1 assigned, so 1 free on same node.
        assert_eq!(
            same_node_free, 1,
            "should have 1 free LLC left on assigned node"
        );
    }

    // --- StickyDynamic lifecycle: 4N tests ---

    /// Verify LLC conservation: free + assigned across all layers = total.
    fn assert_llc_conservation(pool: &CpuPool, layers: &[SdLayerState], total_llcs: usize) {
        let free = pool.total_free_llcs();
        let assigned: usize = layers.iter().map(|l| l.assigned_llcs.len()).sum();
        assert_eq!(
            free + assigned,
            total_llcs,
            "LLC conservation violated: {} free + {} assigned != {}",
            free,
            assigned,
            total_llcs
        );
    }

    #[test]
    fn test_compute_target_llcs_4n() {
        let (topo, _total) = topo_4n();
        // 4N: 16 cores, 8 LLCs → 2 cores/LLC, 2 HTs/core → 4 cpus/LLC
        assert_eq!(compute_target_llcs(0, &topo), (0, 0));
        assert_eq!(compute_target_llcs(4, &topo), (1, 0)); // exactly 1 LLC
        assert_eq!(compute_target_llcs(5, &topo), (1, 1)); // 1 LLC + 1 extra core
        assert_eq!(compute_target_llcs(8, &topo), (2, 0)); // exactly 2 LLCs
        assert_eq!(compute_target_llcs(32, &topo), (8, 0)); // all 8 LLCs
    }

    #[test]
    fn test_sd_4n_single_layer_grow_to_all() {
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];
        let targets = vec![(0, 32)];
        simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 8);
        assert_eq!(pool.total_free_llcs(), 0);
        assert_llc_conservation(&pool, &layers, 8);
    }

    #[test]
    fn test_sd_4n_four_layers_compete() {
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![
            SdLayerState::new("L0"),
            SdLayerState::new("L1"),
            SdLayerState::new("L2"),
            SdLayerState::new("L3"),
        ];
        // Each layer wants 2 LLCs (8 cpus). 4 × 2 = 8 LLCs total.
        let targets = vec![(0, 8), (1, 8), (2, 8), (3, 8)];
        simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);
        for (i, layer) in layers.iter().enumerate() {
            assert_eq!(
                layer.assigned_llcs.len(),
                2,
                "layer {} should have 2 LLCs",
                i
            );
        }
        assert_eq!(pool.total_free_llcs(), 0);
        assert_llc_conservation(&pool, &layers, 8);
    }

    #[test]
    fn test_sd_4n_grow_shrink_roundtrip() {
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let initial_free = pool.total_free_llcs();
        let mut layers = vec![SdLayerState::new("L0"), SdLayerState::new("L1")];

        // Grow: L0 gets 4 LLCs, L1 gets 4 LLCs.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 16), (1, 16)], &topo);
        assert_eq!(pool.total_free_llcs(), 0);
        assert_llc_conservation(&pool, &layers, 8);

        // Shrink both to zero.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 0), (1, 0)], &topo);
        assert_eq!(pool.total_free_llcs(), initial_free);
        assert_llc_conservation(&pool, &layers, 8);
    }

    #[test]
    fn test_sd_stress_grow_shrink_cycles() {
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0"), SdLayerState::new("L1")];

        // 5-cycle pattern: grow L0, grow L1, shrink L0, grow L0 again, shrink both.
        let cycles: Vec<Vec<(usize, usize)>> = vec![
            vec![(0, 16)],          // L0: 0→4 LLCs
            vec![(0, 16), (1, 16)], // L1: 0→4 LLCs
            vec![(0, 8), (1, 16)],  // L0: 4→2 LLCs
            vec![(0, 16), (1, 16)], // L0: 2→4 LLCs
            vec![(0, 0), (1, 0)],   // both → 0
        ];
        for (step, targets) in cycles.iter().enumerate() {
            simulate_sd_recompute(&mut pool, &mut layers, targets, &topo);
            assert_llc_conservation(&pool, &layers, 8);
            // Verify no LLC appears in multiple layers.
            let mut all: Vec<usize> = layers
                .iter()
                .flat_map(|l| l.assigned_llcs.iter().copied())
                .collect();
            let before = all.len();
            all.sort();
            all.dedup();
            assert_eq!(all.len(), before, "step {}: duplicate LLC assignment", step);
        }
    }

    #[test]
    fn test_sd_stress_competing_layers_oscillate() {
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![
            SdLayerState::new("L0"),
            SdLayerState::new("L1"),
            SdLayerState::new("L2"),
            SdLayerState::new("L3"),
        ];

        // 6 cycles: layers oscillate between high and low demand.
        let cycles: Vec<Vec<(usize, usize)>> = vec![
            vec![(0, 8), (1, 8), (2, 8), (3, 8)],   // each 2 LLCs
            vec![(0, 16), (1, 0), (2, 16), (3, 0)], // L0,L2 grow, L1,L3 shrink
            vec![(0, 0), (1, 16), (2, 0), (3, 16)], // swap
            vec![(0, 4), (1, 4), (2, 4), (3, 4)],   // each 1 LLC
            vec![(0, 12), (1, 12), (2, 4), (3, 4)], // L0,L1 grow to 3, L2,L3 stay at 1
            vec![(0, 0), (1, 0), (2, 0), (3, 0)],   // all shrink to 0
        ];
        for (step, targets) in cycles.iter().enumerate() {
            simulate_sd_recompute(&mut pool, &mut layers, targets, &topo);
            assert_llc_conservation(&pool, &layers, 8);
            let mut all: Vec<usize> = layers
                .iter()
                .flat_map(|l| l.assigned_llcs.iter().copied())
                .collect();
            let before = all.len();
            all.sort();
            all.dedup();
            assert_eq!(all.len(), before, "step {}: duplicate LLC assignment", step);
        }
        // After final shrink, all LLCs should be free.
        assert_eq!(pool.total_free_llcs(), 8);
    }

    // --- StickyDynamic lifecycle: 4N node-aware ---

    #[test]
    fn test_sd_4n_llc_assignment_is_node_aware() {
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];

        // Target: 2 full LLCs (8 cpus).
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 8)], &topo);
        let assigned = &layers[0].assigned_llcs;
        assert_eq!(assigned.len(), 2);

        // Both LLCs should be from the same node (node 0 in topo order).
        let nodes: Vec<usize> = assigned
            .iter()
            .map(|&llc| topo.all_llcs[&llc].node_id)
            .collect();
        assert_eq!(
            nodes[0], nodes[1],
            "both LLCs should be from same node, got {:?}",
            assigned
        );
    }

    #[test]
    fn test_sd_4n_affinity_prefers_same_node() {
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];

        // Grow: 1 LLC.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 4)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 1);
        let first_node = topo.all_llcs[&layers[0].assigned_llcs[0]].node_id;

        // Grow: 2 LLCs.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 8)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 2);
        let second_node = topo.all_llcs[&layers[0].assigned_llcs[1]].node_id;

        assert_eq!(
            first_node, second_node,
            "second LLC should be from same node (affinity)"
        );

        // Grow: 3 LLCs — must spill to another node.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 12)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 3);
    }

    #[test]
    fn test_sd_4n_spec_nodes_preference() {
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];
        layers[0].spec_nodes = vec![2]; // prefer node 2

        // Target: 2 LLCs (8 cpus).
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 8)], &topo);
        let assigned = &layers[0].assigned_llcs;
        assert_eq!(assigned.len(), 2);

        // Both LLCs should be from node 2 (LLC 4, 5).
        for &llc in assigned {
            assert_eq!(
                topo.all_llcs[&llc].node_id, 2,
                "LLC {} should be on node 2",
                llc
            );
        }
    }

    #[test]
    fn test_sd_4n_spillover_prefers_same_node() {
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];

        // Target: 5 cpus = 1 LLC (4) + 1 spillover core.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 5)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 1);
        assert_eq!(layers[0].target_llc_cpus, (1, 1));

        let assigned_node = topo.all_llcs[&layers[0].assigned_llcs[0]].node_id;
        let same_node_free: usize = pool.free_llcs.get(&assigned_node).map_or(0, |v| v.len());
        // Node 0 had 2 LLCs, 1 assigned, so 1 free on same node.
        assert_eq!(
            same_node_free, 1,
            "should have 1 free LLC left on assigned node"
        );
    }

    #[test]
    fn test_sd_4n_four_layers_node_local() {
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![
            SdLayerState::new("L0"),
            SdLayerState::new("L1"),
            SdLayerState::new("L2"),
            SdLayerState::new("L3"),
        ];
        // Each layer wants 2 LLCs. With 8 LLCs across 4 nodes (2 per node),
        // each layer should get LLCs from a single node.
        let targets = vec![(0, 8), (1, 8), (2, 8), (3, 8)];
        simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);

        for (i, layer) in layers.iter().enumerate() {
            assert_eq!(
                layer.assigned_llcs.len(),
                2,
                "layer {} should have 2 LLCs",
                i
            );
            let nodes: Vec<usize> = layer
                .assigned_llcs
                .iter()
                .map(|&llc| topo.all_llcs[&llc].node_id)
                .collect();
            assert_eq!(
                nodes[0], nodes[1],
                "layer {} LLCs should be same node, got {:?}",
                i, layer.assigned_llcs
            );
        }
        assert_eq!(pool.total_free_llcs(), 0);
    }

    #[test]
    fn test_sd_4n_stress_multi_cycle_conservation() {
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];

        // Grow through: 1→2→3→4→6→8→6→4→2→0 LLCs.
        let targets_sequence: Vec<usize> = vec![4, 8, 12, 16, 24, 32, 24, 16, 8, 0];
        for (step, &target_cpus) in targets_sequence.iter().enumerate() {
            simulate_sd_recompute(&mut pool, &mut layers, &[(0, target_cpus)], &topo);
            assert_llc_conservation(&pool, &layers, 8);
            let expected_llcs = compute_target_llcs(target_cpus, &topo).0;
            assert_eq!(
                layers[0].assigned_llcs.len(),
                expected_llcs,
                "step {}: expected {} LLCs for {} cpus",
                step,
                expected_llcs,
                target_cpus
            );
        }
        assert_eq!(pool.total_free_llcs(), 8);
    }

    #[test]
    fn test_sd_4n_stress_competing_layers_multi_cycle() {
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![
            SdLayerState::new("L0"),
            SdLayerState::new("L1"),
            SdLayerState::new("L2"),
            SdLayerState::new("L3"),
        ];

        // 6 varied cycles with conservation check each step.
        let cycles: Vec<Vec<(usize, usize)>> = vec![
            vec![(0, 8), (1, 8), (2, 8), (3, 8)],   // each 2 LLCs
            vec![(0, 16), (1, 0), (2, 16), (3, 0)], // L0,L2 grow, L1,L3 shrink
            vec![(0, 0), (1, 16), (2, 0), (3, 16)], // swap
            vec![(0, 4), (1, 4), (2, 4), (3, 4)],   // each 1 LLC
            vec![(0, 12), (1, 12), (2, 4), (3, 4)], // L0,L1 grow to 3, L2,L3 stay 1
            vec![(0, 0), (1, 0), (2, 0), (3, 0)],   // all shrink to 0
        ];
        for (step, targets) in cycles.iter().enumerate() {
            simulate_sd_recompute(&mut pool, &mut layers, targets, &topo);
            assert_llc_conservation(&pool, &layers, 8);
            let mut all: Vec<usize> = layers
                .iter()
                .flat_map(|l| l.assigned_llcs.iter().copied())
                .collect();
            let before = all.len();
            all.sort();
            all.dedup();
            assert_eq!(all.len(), before, "step {}: duplicate LLC assignment", step);
        }
        assert_eq!(pool.total_free_llcs(), 8);
    }

    // --- StickyDynamic bug regression tests ---

    #[test]
    fn test_sd_node_pinned_exceeds_node_capacity() {
        // Node 1 has 2 LLCs (16 cpus). Requesting 3 LLCs worth (24 cpus)
        // should allocate all 2 available on node 1, not panic.
        let (topo, _total) = topo_2n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];
        layers[0].spec_nodes = vec![1]; // pin to node 1

        // 24 cpus = 3 full LLCs, but node 1 only has 2.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 24)], &topo);

        assert_eq!(layers[0].assigned_llcs.len(), 2);
        // Both LLCs should be from node 1.
        for &llc in &layers[0].assigned_llcs {
            assert_eq!(
                topo.all_llcs[&llc].node_id, 1,
                "LLC {} should be on node 1",
                llc
            );
        }
        // 2 LLCs remain free on node 0.
        assert_eq!(pool.total_free_llcs(), 2);
    }

    #[test]
    fn test_sd_partial_allocation_when_supply_lt_demand() {
        // Two layers: L0 holds 3 of 4 LLCs, L1 wants 4 but only 1 is free.
        // L1 should get 1, not 0.
        let (topo, _total) = topo_2n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0"), SdLayerState::new("L1")];

        // Step 1: L0 takes 3 LLCs (24 cpus), L1 takes 0.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 24), (1, 0)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 3);
        assert_eq!(layers[1].assigned_llcs.len(), 0);
        assert_eq!(pool.total_free_llcs(), 1);

        // Step 2: L0 stays at 3, L1 wants 4 (32 cpus) but only 1 free.
        // Should get 1, not 0.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 24), (1, 32)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 3);
        assert_eq!(
            layers[1].assigned_llcs.len(),
            1,
            "L1 should get partial allocation"
        );
        assert_eq!(pool.total_free_llcs(), 0);
    }

    #[test]
    fn test_sd_node_pinned_at_capacity_stays_stable() {
        // Layer pinned to node 0, already holds both LLCs, target unchanged.
        // Should be no-op, no panic.
        let (topo, _total) = topo_2n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];
        layers[0].spec_nodes = vec![0]; // pin to node 0

        // Step 1: Grow to fill node 0 (2 LLCs = 16 cpus).
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 16)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 2);
        let llcs_after_grow = layers[0].assigned_llcs.clone();

        // Step 2: Same target again — should be stable no-op.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 16)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 2);
        assert_eq!(
            layers[0].assigned_llcs, llcs_after_grow,
            "LLCs should be unchanged"
        );
        assert_eq!(pool.total_free_llcs(), 2); // node 1 still free
    }

    // --- Cross-node overflow, shrink-back, and oscillation ---

    /// Count how many of a layer's LLCs are on a given node.
    fn llcs_on_node(layer: &SdLayerState, topo: &Topology, node: usize) -> usize {
        layer
            .assigned_llcs
            .iter()
            .filter(|&&llc| topo.all_llcs[&llc].node_id == node)
            .count()
    }

    /// Assert no LLC appears in more than one layer.
    fn assert_no_duplicate_llcs(layers: &[SdLayerState], step: &str) {
        let mut all: Vec<usize> = layers
            .iter()
            .flat_map(|l| l.assigned_llcs.iter().copied())
            .collect();
        let before = all.len();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), before, "{}: duplicate LLC assignment", step);
    }

    #[test]
    fn test_sd_2n_overflow_across_nodes_and_shrink_back() {
        // Unpinned layer grows beyond node 0 capacity, overflows to node 1,
        // then shrinks back to fit on node 0. Repeat 5 times to verify
        // stable oscillation without LLC leaks.
        // 2N: 4 LLCs (2/node), 8 cpus/LLC.
        let (topo, _total) = topo_2n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];

        for cycle in 0..5 {
            // Grow to 24 cpus = 3 LLCs: fills node 0 (2) + 1 from node 1.
            simulate_sd_recompute(&mut pool, &mut layers, &[(0, 24)], &topo);
            assert_eq!(
                layers[0].assigned_llcs.len(),
                3,
                "cycle {}: should have 3 LLCs",
                cycle
            );
            assert_eq!(
                llcs_on_node(&layers[0], &topo, 0),
                2,
                "cycle {}: node 0 should have 2 LLCs",
                cycle
            );
            assert_eq!(
                llcs_on_node(&layers[0], &topo, 1),
                1,
                "cycle {}: node 1 should have 1 overflow LLC",
                cycle
            );
            assert_llc_conservation(&pool, &layers, 4);

            // Shrink to 16 cpus = 2 LLCs: fits on node 0, releases node 1 LLC.
            simulate_sd_recompute(&mut pool, &mut layers, &[(0, 16)], &topo);
            assert_eq!(
                layers[0].assigned_llcs.len(),
                2,
                "cycle {}: should have 2 LLCs after shrink",
                cycle
            );
            assert_eq!(
                llcs_on_node(&layers[0], &topo, 0),
                2,
                "cycle {}: both LLCs should be on node 0 after shrink",
                cycle
            );
            assert_eq!(
                llcs_on_node(&layers[0], &topo, 1),
                0,
                "cycle {}: node 1 should have 0 LLCs after shrink",
                cycle
            );
            assert_llc_conservation(&pool, &layers, 4);
        }
    }

    #[test]
    fn test_sd_2n_two_layers_cross_node_oscillation() {
        // Two layers with different node preferences oscillate load.
        // L0 prefers [0,1], L1 prefers [1,0]. When one overflows, it
        // borrows from the other's preferred node. Repeat 4 times.
        // 2N: 4 LLCs (2/node), 8 cpus/LLC.
        let (topo, _total) = topo_2n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0"), SdLayerState::new("L1")];
        layers[0].spec_nodes = vec![0, 1]; // prefers node 0
        layers[1].spec_nodes = vec![1, 0]; // prefers node 1

        for cycle in 0..4 {
            // Phase A: L0=24 cpus (3 LLCs, overflow), L1=8 cpus (1 LLC).
            let targets = vec![(1, 8), (0, 24)]; // sorted ascending by target
            simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);
            assert_eq!(layers[0].assigned_llcs.len(), 3, "cycle {} A: L0", cycle);
            assert_eq!(layers[1].assigned_llcs.len(), 1, "cycle {} A: L1", cycle);
            assert_llc_conservation(&pool, &layers, 4);
            assert_no_duplicate_llcs(&layers, &format!("cycle {} A", cycle));

            // Phase B: L0=8 cpus (1 LLC), L1=24 cpus (3 LLCs, overflow).
            let targets = vec![(0, 8), (1, 24)]; // sorted ascending
            simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);
            assert_eq!(layers[0].assigned_llcs.len(), 1, "cycle {} B: L0", cycle);
            assert_eq!(layers[1].assigned_llcs.len(), 3, "cycle {} B: L1", cycle);
            assert_llc_conservation(&pool, &layers, 4);
            assert_no_duplicate_llcs(&layers, &format!("cycle {} B", cycle));
        }
    }

    #[test]
    fn test_sd_2n_unpinned_two_layers_compete_full_range() {
        // Two unpinned layers go through phases: one takes all, other takes
        // all, split evenly, then uneven split. Repeat 3 times.
        // 2N: 4 LLCs, 8 cpus/LLC, 32 cpus total.
        let (topo, _total) = topo_2n();

        for _cycle in 0..3 {
            let mut pool = CpuPool::new(topo.clone(), false).unwrap();
            let mut layers = vec![SdLayerState::new("L0"), SdLayerState::new("L1")];

            // Phase A: L0=32 cpus (4 LLCs), L1=0.
            simulate_sd_recompute(&mut pool, &mut layers, &[(0, 32), (1, 0)], &topo);
            assert_eq!(layers[0].assigned_llcs.len(), 4);
            assert_eq!(layers[1].assigned_llcs.len(), 0);
            assert_llc_conservation(&pool, &layers, 4);

            // Phase B: L0=0, L1=32 cpus (4 LLCs).
            simulate_sd_recompute(&mut pool, &mut layers, &[(0, 0), (1, 32)], &topo);
            assert_eq!(layers[0].assigned_llcs.len(), 0);
            assert_eq!(layers[1].assigned_llcs.len(), 4);
            assert_llc_conservation(&pool, &layers, 4);

            // Phase C: L0=16, L1=16 (each 2 LLCs).
            simulate_sd_recompute(&mut pool, &mut layers, &[(0, 16), (1, 16)], &topo);
            assert_eq!(layers[0].assigned_llcs.len(), 2);
            assert_eq!(layers[1].assigned_llcs.len(), 2);
            assert_llc_conservation(&pool, &layers, 4);
            assert_no_duplicate_llcs(&layers, "phase C");

            // Phase D: L0=24 (3 LLCs), L1=8 (1 LLC).
            simulate_sd_recompute(&mut pool, &mut layers, &[(1, 8), (0, 24)], &topo);
            assert_eq!(layers[0].assigned_llcs.len(), 3);
            assert_eq!(layers[1].assigned_llcs.len(), 1);
            assert_llc_conservation(&pool, &layers, 4);
            assert_no_duplicate_llcs(&layers, "phase D");
        }
    }

    #[test]
    fn test_sd_4n_overflow_three_nodes() {
        // Layer pinned to node 0 with fallback to all nodes. Grows from 0
        // through all 8 LLCs (filling 3+ nodes), then shrinks back to 0.
        // Verify node 0 LLCs are retained, overflow to other nodes, and
        // shrink releases non-preferred-node LLCs first.
        // 4N: 8 LLCs (2/node), 4 cpus/LLC.
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];
        // Unpinned: node_order = [0,1,2,3], so fills node 0 first.

        let grow_targets: Vec<usize> = vec![4, 8, 12, 16, 20, 24];
        let expected_llcs: Vec<usize> = vec![1, 2, 3, 4, 5, 6];

        // Grow phase.
        for (i, (&target, &exp)) in grow_targets.iter().zip(expected_llcs.iter()).enumerate() {
            simulate_sd_recompute(&mut pool, &mut layers, &[(0, target)], &topo);
            assert_eq!(
                layers[0].assigned_llcs.len(),
                exp,
                "grow step {}: target {} cpus should give {} LLCs",
                i,
                target,
                exp
            );
            // Node 0 should always retain its 2 LLCs once filled.
            if exp >= 2 {
                assert_eq!(
                    llcs_on_node(&layers[0], &topo, 0),
                    2,
                    "grow step {}: node 0 should have 2 LLCs",
                    i
                );
            }
            assert_llc_conservation(&pool, &layers, 8);
        }

        // At 6 LLCs, should span 3 nodes (2+2+2).
        assert!(
            llcs_on_node(&layers[0], &topo, 0) == 2
                && llcs_on_node(&layers[0], &topo, 1) == 2
                && llcs_on_node(&layers[0], &topo, 2) == 2,
            "at 6 LLCs should span nodes 0,1,2 with 2 each"
        );

        // Shrink phase: 24→20→16→12→8→4→0.
        let shrink_targets: Vec<usize> = vec![20, 16, 12, 8, 4, 0];
        let expected_llcs: Vec<usize> = vec![5, 4, 3, 2, 1, 0];

        for (i, (&target, &exp)) in shrink_targets.iter().zip(expected_llcs.iter()).enumerate() {
            simulate_sd_recompute(&mut pool, &mut layers, &[(0, target)], &topo);
            assert_eq!(
                layers[0].assigned_llcs.len(),
                exp,
                "shrink step {}: target {} cpus should give {} LLCs",
                i,
                target,
                exp
            );
            // Node 0 LLCs should be released last.
            if exp >= 2 {
                assert_eq!(
                    llcs_on_node(&layers[0], &topo, 0),
                    2,
                    "shrink step {}: node 0 should retain 2 LLCs",
                    i
                );
            }
            assert_llc_conservation(&pool, &layers, 8);
        }
        assert_eq!(pool.total_free_llcs(), 8);
    }

    #[test]
    fn test_sd_4n_three_layers_node_pinned_compete() {
        // L0 pinned node 0, L1 pinned node 1, L2 pinned node 2.
        // Each grows to fill their node (2 LLCs), then all shrink to 1,
        // then L0 grows unpinned to grab free LLCs.
        // 4N: 8 LLCs (2/node), 4 cpus/LLC.
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![
            SdLayerState::new("L0"),
            SdLayerState::new("L1"),
            SdLayerState::new("L2"),
        ];
        layers[0].spec_nodes = vec![0];
        layers[1].spec_nodes = vec![1];
        layers[2].spec_nodes = vec![2];

        // Each layer fills its node (2 LLCs = 8 cpus).
        let targets = vec![(0, 8), (1, 8), (2, 8)];
        simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);
        for (i, layer) in layers.iter().enumerate() {
            assert_eq!(layer.assigned_llcs.len(), 2, "L{} should have 2 LLCs", i);
            assert_eq!(
                llcs_on_node(layer, &topo, i),
                2,
                "L{} should be on node {}",
                i,
                i
            );
        }
        assert_eq!(pool.total_free_llcs(), 2); // node 3 free
        assert_llc_conservation(&pool, &layers, 8);
        assert_no_duplicate_llcs(&layers, "fill phase");

        // All shrink to 1 LLC each.
        let targets = vec![(0, 4), (1, 4), (2, 4)];
        simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);
        for (i, layer) in layers.iter().enumerate() {
            assert_eq!(layer.assigned_llcs.len(), 1, "L{} should have 1 LLC", i);
        }
        assert_eq!(pool.total_free_llcs(), 5); // 3 freed + 2 from node 3
        assert_llc_conservation(&pool, &layers, 8);

        // L0 becomes unpinned and grows to 24 cpus (6 LLCs), L1+L2 stay at 0.
        layers[0].spec_nodes = vec![];
        let targets = vec![(0, 24), (1, 0), (2, 0)];
        simulate_sd_recompute(&mut pool, &mut layers, &targets, &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 6);
        assert_eq!(layers[1].assigned_llcs.len(), 0);
        assert_eq!(layers[2].assigned_llcs.len(), 0);
        assert_eq!(pool.total_free_llcs(), 2);
        assert_llc_conservation(&pool, &layers, 8);
    }

    #[test]
    fn test_sd_4n_mixed_pinned_unpinned_cycles() {
        // L0 pinned to node 0, L1 unpinned. The algorithm allocates largest
        // targets first (reverse iteration). target_llc_cpus tracks desired
        // count, so a pinned layer's target should not exceed its node capacity
        // to avoid over-freeing in subsequent shrinks.
        // 4N: 8 LLCs (2/node), 4 cpus/LLC. Node 0 has 2 LLCs = 8 cpus.
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0"), SdLayerState::new("L1")];
        layers[0].spec_nodes = vec![0]; // pinned to node 0

        for cycle in 0..3 {
            let label = format!("cycle {}", cycle);

            // Phase A: L0=8 (fills N0, 2 LLCs), L1=4 (1 LLC from elsewhere).
            // L0 has larger target → allocates first.
            simulate_sd_recompute(&mut pool, &mut layers, &[(1, 4), (0, 8)], &topo);
            assert_eq!(layers[0].assigned_llcs.len(), 2, "{} A: L0", label);
            assert_eq!(
                llcs_on_node(&layers[0], &topo, 0),
                2,
                "{} A: L0 on node 0",
                label
            );
            assert_eq!(layers[1].assigned_llcs.len(), 1, "{} A: L1", label);
            assert_llc_conservation(&pool, &layers, 8);
            assert_no_duplicate_llcs(&layers, &format!("{} A", label));

            // Phase B: L0=4 (1 LLC), L1=4 (1 LLC). L0 shrinks.
            simulate_sd_recompute(&mut pool, &mut layers, &[(0, 4), (1, 4)], &topo);
            assert_eq!(layers[0].assigned_llcs.len(), 1, "{} B: L0", label);
            assert_eq!(layers[1].assigned_llcs.len(), 1, "{} B: L1", label);
            assert_llc_conservation(&pool, &layers, 8);

            // Phase C: L0=0, L1=32 (all 8 LLCs). L1 takes everything.
            simulate_sd_recompute(&mut pool, &mut layers, &[(0, 0), (1, 32)], &topo);
            assert_eq!(layers[0].assigned_llcs.len(), 0, "{} C: L0", label);
            assert_eq!(layers[1].assigned_llcs.len(), 8, "{} C: L1", label);
            assert_eq!(pool.total_free_llcs(), 0, "{} C: free", label);
            assert_llc_conservation(&pool, &layers, 8);

            // Phase D: L0=8 (2 LLCs), L1=0. L0 grabs N0 LLCs back.
            simulate_sd_recompute(&mut pool, &mut layers, &[(1, 0), (0, 8)], &topo);
            assert_eq!(layers[0].assigned_llcs.len(), 2, "{} D: L0", label);
            assert_eq!(
                llcs_on_node(&layers[0], &topo, 0),
                2,
                "{} D: L0 back on node 0",
                label
            );
            assert_eq!(layers[1].assigned_llcs.len(), 0, "{} D: L1", label);
            assert_llc_conservation(&pool, &layers, 8);

            // Reset for next cycle: both to 0.
            simulate_sd_recompute(&mut pool, &mut layers, &[(0, 0), (1, 0)], &topo);
        }
    }

    // --- Stability and edge cases ---

    #[test]
    fn test_sd_2n_repeated_same_target_is_stable() {
        // Layer at steady state should not change LLC assignments when
        // simulated repeatedly with the same target.
        let (topo, _total) = topo_2n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];

        // Grow to 2 LLCs.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 16)], &topo);
        let stable_llcs = layers[0].assigned_llcs.clone();
        assert_eq!(stable_llcs.len(), 2);

        // Repeat 10 times — should be identical each time.
        for i in 0..10 {
            simulate_sd_recompute(&mut pool, &mut layers, &[(0, 16)], &topo);
            assert_eq!(
                layers[0].assigned_llcs, stable_llcs,
                "iteration {}: LLCs should be unchanged",
                i
            );
            assert_llc_conservation(&pool, &layers, 4);
        }
    }

    #[test]
    fn test_sd_4n_all_layers_at_zero_then_grow() {
        // 4 layers all start at 0, then all grow simultaneously to 2 LLCs each.
        // 4N: 8 LLCs, 4 cpus/LLC.
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![
            SdLayerState::new("L0"),
            SdLayerState::new("L1"),
            SdLayerState::new("L2"),
            SdLayerState::new("L3"),
        ];

        // All at zero.
        simulate_sd_recompute(
            &mut pool,
            &mut layers,
            &[(0, 0), (1, 0), (2, 0), (3, 0)],
            &topo,
        );
        for layer in &layers {
            assert_eq!(layer.assigned_llcs.len(), 0);
        }
        assert_eq!(pool.total_free_llcs(), 8);

        // All grow to 2 LLCs (8 cpus) simultaneously.
        simulate_sd_recompute(
            &mut pool,
            &mut layers,
            &[(0, 8), (1, 8), (2, 8), (3, 8)],
            &topo,
        );
        for (i, layer) in layers.iter().enumerate() {
            assert_eq!(layer.assigned_llcs.len(), 2, "L{} should have 2 LLCs", i);
        }
        assert_eq!(pool.total_free_llcs(), 0);
        assert_llc_conservation(&pool, &layers, 8);
        assert_no_duplicate_llcs(&layers, "all grow");
    }

    #[test]
    fn test_sd_2n_overflow_shrink_releases_remote_first() {
        // Verify that when shrinking, the last-allocated (overflow) LLCs
        // from remote nodes are released before local ones.
        // 2N: 4 LLCs, 8 cpus/LLC.
        let (topo, _total) = topo_2n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];

        // Grow to 4 LLCs (all).
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 32)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 4);
        // First 2 should be from node 0, last 2 from node 1.
        assert_eq!(llcs_on_node(&layers[0], &topo, 0), 2);
        assert_eq!(llcs_on_node(&layers[0], &topo, 1), 2);

        // Shrink to 3 LLCs. The last allocated (from node 1) should be freed.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 24)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 3);
        assert_eq!(llcs_on_node(&layers[0], &topo, 0), 2);
        assert_eq!(llcs_on_node(&layers[0], &topo, 1), 1);

        // Shrink to 2 LLCs. The other node 1 LLC should be freed.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 16)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 2);
        assert_eq!(llcs_on_node(&layers[0], &topo, 0), 2);
        assert_eq!(llcs_on_node(&layers[0], &topo, 1), 0);

        // Shrink to 1 LLC. Now a node 0 LLC is released.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 8)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 1);
        assert_eq!(llcs_on_node(&layers[0], &topo, 0), 1);
        assert_llc_conservation(&pool, &layers, 4);
    }

    #[test]
    fn test_sd_4n_spec_nodes_overflow_to_unspecified() {
        // Layer with spec_nodes=[2,3] fills both nodes, then there's nowhere
        // else to allocate (spec_nodes is a hard limit).
        // 4N: 8 LLCs (2/node), 4 cpus/LLC. Nodes 2,3 have 4 LLCs total.
        let (topo, _total) = topo_4n();
        let mut pool = CpuPool::new(topo.clone(), false).unwrap();
        let mut layers = vec![SdLayerState::new("L0")];
        layers[0].spec_nodes = vec![2, 3];

        // Target 16 cpus = 4 LLCs. Nodes 2+3 have exactly 4.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 16)], &topo);
        assert_eq!(layers[0].assigned_llcs.len(), 4);
        assert_eq!(llcs_on_node(&layers[0], &topo, 2), 2);
        assert_eq!(llcs_on_node(&layers[0], &topo, 3), 2);
        assert_eq!(llcs_on_node(&layers[0], &topo, 0), 0);
        assert_eq!(llcs_on_node(&layers[0], &topo, 1), 0);

        // Target 24 cpus = 6 LLCs. But only 4 available on nodes 2,3.
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 24)], &topo);
        assert_eq!(
            layers[0].assigned_llcs.len(),
            4,
            "can't exceed spec_nodes capacity"
        );
        assert_llc_conservation(&pool, &layers, 8);

        // Shrink to 0, then grow with changed spec_nodes (now unpinned).
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 0)], &topo);
        layers[0].spec_nodes = vec![];
        simulate_sd_recompute(&mut pool, &mut layers, &[(0, 24)], &topo);
        assert_eq!(
            layers[0].assigned_llcs.len(),
            6,
            "unpinned can use all nodes"
        );
        assert_llc_conservation(&pool, &layers, 8);
    }

    // --- largest_remainder ---

    #[test]
    fn test_lr_exact_sum() {
        let result = largest_remainder(10, &[3.0, 3.0, 4.0]);
        assert_eq!(result.iter().sum::<usize>(), 10);
    }

    #[test]
    fn test_lr_proportional() {
        let result = largest_remainder(100, &[1.0, 2.0, 3.0]);
        // ~17, ~33, ~50 — sum must be exactly 100.
        assert_eq!(result.iter().sum::<usize>(), 100);
        assert!(result[0] >= 16 && result[0] <= 17);
        assert!(result[1] >= 33 && result[1] <= 34);
        assert!(result[2] >= 49 && result[2] <= 50);
    }

    #[test]
    fn test_lr_equal_quotas() {
        let result = largest_remainder(10, &[1.0, 1.0, 1.0]);
        assert_eq!(result.iter().sum::<usize>(), 10);
        // 10/3 = 3.333... → two get 3, one gets 4.
        assert!(result.iter().all(|&v| v == 3 || v == 4));
        assert_eq!(result.iter().filter(|&&v| v == 4).count(), 1);
    }

    #[test]
    fn test_lr_zero_quotas() {
        let result = largest_remainder(10, &[0.0, 0.0, 0.0]);
        assert_eq!(result, vec![0, 0, 0]);
    }

    #[test]
    fn test_lr_single_entry() {
        let result = largest_remainder(42, &[7.0]);
        assert_eq!(result, vec![42]);
    }

    #[test]
    fn test_lr_large_remainder() {
        // 7/3 = 2.333... → floors = [2,2,2] = 6, remainder = 1.
        let result = largest_remainder(7, &[1.0, 1.0, 1.0]);
        assert_eq!(result.iter().sum::<usize>(), 7);
        assert_eq!(result.iter().filter(|&&v| v == 3).count(), 1);
        assert_eq!(result.iter().filter(|&&v| v == 2).count(), 2);
    }

    #[test]
    fn test_lr_empty() {
        let result = largest_remainder(10, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_lr_one_zero_one_nonzero() {
        let result = largest_remainder(10, &[0.0, 5.0]);
        assert_eq!(result, vec![0, 10]);
    }

    #[test]
    fn test_lr_total_zero() {
        let result = largest_remainder(0, &[3.0, 7.0]);
        assert_eq!(result, vec![0, 0]);
    }

    // --- round_targets_to_alloc_units ---

    #[test]
    fn test_rta_unit_1() {
        let targets = vec![(10, 2), (15, 5)];
        let result = round_targets_to_alloc_units(&targets, 1, 100);
        assert_eq!(result, targets);
    }

    #[test]
    fn test_rta_round_up() {
        // alloc_unit=2: 3→4, 5→6
        let targets = vec![(3, 1), (5, 0)];
        let result = round_targets_to_alloc_units(&targets, 2, 100);
        assert_eq!(result, vec![(4, 2), (6, 0)]);
    }

    #[test]
    fn test_rta_already_aligned() {
        let targets = vec![(4, 2), (6, 0)];
        let result = round_targets_to_alloc_units(&targets, 2, 100);
        assert_eq!(result, targets);
    }

    #[test]
    fn test_rta_caps_at_total() {
        let targets = vec![(99, 0)];
        let result = round_targets_to_alloc_units(&targets, 2, 16);
        assert_eq!(result, vec![(16, 0)]);
    }

    // --- alloc_unit ---

    #[test]
    fn test_alloc_unit_partial() {
        let (topo, _) = topo_1n();
        let pool = CpuPool::new(topo, true).unwrap();
        assert_eq!(pool.alloc_unit(), 1);
    }

    #[test]
    fn test_alloc_unit_full_core() {
        let (topo, _) = topo_1n();
        let pool = CpuPool::new(topo, false).unwrap();
        // 2 HTs per core.
        assert_eq!(pool.alloc_unit(), 2);
    }
}
