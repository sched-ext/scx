// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod config;
mod layer_core_growth;

pub mod bpf_intf;

use std::collections::BTreeMap;

use anyhow::bail;
use anyhow::Result;
use bitvec::prelude::*;
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

    /// A bit mask representing all available physical cores.
    /// Each bit corresponds to whether a physical core is available for task scheduling.
    available_cores: BitVec,

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
}

impl CpuPool {
    pub fn new(topo: Arc<Topology>) -> Result<Self> {
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

        let mut cpu_pool = Self {
            free_llcs,
            available_cores: bitvec![1; topo.all_cores.len()],
            first_cpu,
            fallback_cpu: first_cpu,
            core_topology_to_id,
            topo,
        };
        cpu_pool.update_fallback_cpu();
        Ok(cpu_pool)
    }

    fn update_fallback_cpu(&mut self) {
        match self.available_cores.first_one() {
            Some(next) => {
                self.fallback_cpu = *self.topo.all_cores[&next].cpus.keys().next().unwrap()
            }
            None => self.fallback_cpu = self.first_cpu,
        }
    }

    pub fn alloc_cpus(
        &mut self,
        allowed_cpus: &Cpumask,
        core_alloc_order: &[usize],
    ) -> Option<&Cpumask> {
        let available_cpus = self.available_cpus().and(allowed_cpus);
        let available_cores = self.cpus_to_cores(&available_cpus).ok()?;

        for alloc_core in core_alloc_order {
            match available_cores.get(*alloc_core) {
                Some(bit) => {
                    if *bit {
                        self.available_cores.set(*alloc_core, false);
                        self.update_fallback_cpu();
                        return Some(&self.topo.all_cores[alloc_core].span);
                    }
                }
                None => {
                    continue;
                }
            }
        }
        None
    }

    fn cpus_to_cores(&self, cpus_to_match: &Cpumask) -> Result<BitVec> {
        let topo = &self.topo;
        let mut cpus = cpus_to_match.clone();
        let mut cores = bitvec![0; topo.all_cores.len()];

        while let Some(cpu) = cpus.iter().next() {
            let core = &topo.all_cores[&topo.all_cpus[&cpu].core_id];

            if core.span.and(&cpus_to_match.not()).weight() != 0 {
                bail!(
                    "CPUs {} partially intersect with core {:?}",
                    cpus_to_match,
                    core,
                );
            }

            cpus &= &core.span.not();
            cores.set(core.id, true);
        }

        Ok(cores)
    }

    pub fn free(&mut self, cpus_to_free: &Cpumask) -> Result<()> {
        let cores = self.cpus_to_cores(cpus_to_free)?;
        if (self.available_cores.clone() & &cores).any() {
            bail!("Some of CPUs {} are already free", cpus_to_free);
        }
        self.available_cores |= cores;
        self.update_fallback_cpu();
        Ok(())
    }

    pub fn mark_allocated(&mut self, cpus_to_alloc: &Cpumask) -> Result<()> {
        let cores = self.cpus_to_cores(cpus_to_alloc)?;
        // Check if all requested cores are available
        let unavailable_cores = cores.clone() & !self.available_cores.clone();
        if unavailable_cores.any() {
            bail!(
                "Some of CPUs {} are not available to allocate",
                cpus_to_alloc
            );
        }
        self.available_cores &= !cores;
        self.update_fallback_cpu();
        Ok(())
    }

    pub fn next_to_free<'a>(
        &'a self,
        cands: &Cpumask,
        core_order: impl Iterator<Item = &'a usize>,
    ) -> Result<Option<&'a Cpumask>> {
        for pref_core in core_order.map(|i| &self.topo.all_cores[i]) {
            if pref_core.span.and(cands).weight() > 0 {
                return Ok(Some(&pref_core.span));
            }
        }
        Ok(None)
    }

    pub fn available_cpus(&self) -> Cpumask {
        let mut cpus = Cpumask::new();
        for core in self
            .available_cores
            .iter_ones()
            .map(|i| &self.topo.all_cores[&i])
        {
            cpus |= &core.span;
        }
        cpus
    }

    fn get_core_topological_id(&self, core: &Core) -> usize {
        *self
            .core_topology_to_id
            .get(&(core.node_id, core.llc_id, core.id))
            .expect("unrecognised core")
    }
}
