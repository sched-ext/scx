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
