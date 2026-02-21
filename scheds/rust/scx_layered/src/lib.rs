// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod config;
mod layer_core_growth;

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

#[derive(Debug)]
/// `CpuPool` represents the CPU core and logical CPU topology within the system.
/// It manages the mapping and availability of physical and logical cores, including
/// how resources are allocated for tasks across the available CPUs.
pub struct CpuPool {
    pub topo: Arc<Topology>,

    pub free_llcs: Vec<(usize, usize)>,

    /// A mask for available CPUs (SMT hyperthreads).
    /// Use for sub-core allocations when turned on.
    available_cpus: Cpumask,

    /// The ID of the first physical core in the system.
    /// This core is often used as a default for initializing tasks.
    first_cpu: usize,

    /// The ID of the next free CPU or the fallback CPU if none are available.
    /// This is used to allocate resources when a task needs to be assigned to a core.
    pub fallback_cpu: usize,

    /// A mapping of node IDs to last-level cache (LLC) IDs.
    /// The map allows for the identification of which last-level cache
    /// corresponds to each CPU based on its core topology.
    core_topology_to_id: BTreeMap<(usize, usize, usize), usize>,

    allow_partial: bool,
}

impl CpuPool {
    pub fn new(topo: Arc<Topology>, allow_partial: bool) -> Result<Self> {
        if *NR_CPU_IDS > MAX_CPUS {
            bail!("NR_CPU_IDS {} > MAX_CPUS {}", *NR_CPU_IDS, MAX_CPUS);
        }

        // Build core_topology_to_id
        let mut core_topology_to_id = BTreeMap::new();
        let mut next_topo_id: usize = 0;
        for node in topo.nodes.values() {
            for llc in node.llcs.values() {
                for core in llc.cores.values() {
                    core_topology_to_id.insert((core.node_id, core.llc_id, core.id), next_topo_id);
                    next_topo_id += 1;
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

        let free_llcs = topo.all_llcs.iter().map(|llc| (llc.1.id, 0)).collect();

        let mut available_cpus = Cpumask::new();
        available_cpus.set_all();

        let mut cpu_pool = Self {
            free_llcs,
            available_cpus,
            first_cpu,
            fallback_cpu: first_cpu,
            core_topology_to_id,
            topo,
            allow_partial,
        };
        cpu_pool.update_fallback_cpu();
        Ok(cpu_pool)
    }

    fn update_fallback_cpu(&mut self) {
        self.fallback_cpu = match self.available_cpus.iter().next() {
            Some(cpu) => cpu,
            None => self.first_cpu,
        };
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

        self.update_fallback_cpu();
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
        self.update_fallback_cpu();

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
        self.update_fallback_cpu();

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

    fn get_core_topological_id(&self, core: &Core) -> usize {
        *self
            .core_topology_to_id
            .get(&(core.node_id, core.llc_id, core.id))
            .expect("unrecognised core")
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
    fn test_new_1n_fallback_cpu() {
        let (topo, _total) = topo_1n();
        let pool = CpuPool::new(topo, false).unwrap();
        // fallback_cpu should be the first CPU (0).
        assert_eq!(pool.fallback_cpu, 0);
    }

    #[test]
    fn test_new_1n_core_topo_ids() {
        let (topo, _total) = topo_1n();
        let pool = CpuPool::new(topo.clone(), false).unwrap();
        // All cores should have unique topology IDs assigned sequentially.
        for (i, core_id) in topo.all_cores.keys().enumerate() {
            let core = &topo.all_cores[core_id];
            assert_eq!(pool.get_core_topological_id(core), i);
        }
    }

    #[test]
    fn test_new_1n_free_llcs() {
        let (topo, _total) = topo_1n();
        let pool = CpuPool::new(topo, false).unwrap();
        // Should have 2 LLCs, each with consumed_count=0.
        assert_eq!(pool.free_llcs.len(), 2);
        assert_eq!(pool.free_llcs[0], (0, 0)); // (llc_id, consumed)
        assert_eq!(pool.free_llcs[1], (1, 0));
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
        assert_eq!(pool.free_llcs.len(), 4);
        for i in 0..4 {
            assert_eq!(pool.free_llcs[i], (i, 0));
        }
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
    fn test_fallback_cpu_updates() {
        let (topo, total) = topo_1n();
        let allowed = all_cpus_mask(total);
        let order = core_order_sequential(&topo);
        let mut pool = CpuPool::new(topo, false).unwrap();

        assert_eq!(pool.fallback_cpu, 0);

        // Allocate core 0 (cpus 0,1). Fallback should move to cpu 2.
        let alloc = pool.alloc_cpus(&allowed, &order, 2).unwrap();
        assert_eq!(pool.fallback_cpu, 2);

        // Free it back. Fallback should return to 0.
        pool.free(&alloc).unwrap();
        assert_eq!(pool.fallback_cpu, 0);
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
        // 4 LLCs across 2 nodes.
        assert_eq!(pool.free_llcs.len(), 4);
        // LLC 0,1 on node 0; LLC 2,3 on node 1.
        for i in 0..4 {
            assert_eq!(pool.free_llcs[i].0, i); // llc_id
            assert_eq!(pool.free_llcs[i].1, 0); // consumed count
        }
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
        assert_eq!(pool.free_llcs.len(), 8);
        for i in 0..8 {
            assert_eq!(pool.free_llcs[i], (i, 0));
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
}
