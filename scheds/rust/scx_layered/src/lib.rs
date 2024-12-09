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
pub use config::LayerSpec;
pub use layer_core_growth::LayerGrowthAlgo;
use log::debug;
use log::info;
use scx_utils::Core;
use scx_utils::Topology;
use scx_utils::TopologyMap;
use scx_utils::NR_CPUS_POSSIBLE;
use scx_utils::NR_CPU_IDS;
use std::sync::Arc;

const MAX_CPUS: usize = bpf_intf::consts_MAX_CPUS as usize;

pub const XLLC_MIG_MIN_US_DFL: f64 = 100.0;

#[derive(Debug)]
/// `CpuPool` represents the CPU core and logical CPU topology within the system.
/// It manages the mapping and availability of physical and logical cores, including
/// how resources are allocated for tasks across the available CPUs.
pub struct CpuPool {
    pub topo: Arc<Topology>,

    /// A vector of bit masks, each representing the mapping between
    /// physical cores and the logical cores that run on them.
    /// The index in the vector represents the physical core, and each bit in the
    /// corresponding `BitVec` represents whether a logical core belongs to that physical core.
    core_cpus: Vec<BitVec>,

    /// A vector that maps the index of each logical core to the sibling core.
    /// This represents the "next sibling" core within a package in systems that support SMT.
    /// The sibling core is the other logical core that shares the physical resources
    /// of the same physical core.
    pub sibling_cpu: Vec<i32>,

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

        let topo_map = TopologyMap::new(&topo).unwrap();

        let core_cpus = topo_map.core_cpus_bitvec();
        let sibling_cpu = topo.sibling_cpus();

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
        debug!("CPUs: siblings={:?}", &sibling_cpu[..*NR_CPU_IDS]);

        let first_cpu = *topo.all_cpus.keys().next().unwrap();

        let mut cpu_pool = Self {
            core_cpus,
            sibling_cpu,
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

    pub fn alloc_cpus<'a>(
        &'a mut self,
        allowed_cpus: &BitVec,
        core_alloc_order: &[usize],
    ) -> Option<&'a BitVec> {
        let available_cpus = self.available_cpus_in_mask(&allowed_cpus);
        let available_cores = self.cpus_to_cores(&available_cpus).ok()?;

        for alloc_core in core_alloc_order {
            match available_cores.get(*alloc_core) {
                Some(bit) => {
                    if *bit {
                        self.available_cores.set(*alloc_core, false);
                        self.update_fallback_cpu();
                        return Some(&self.core_cpus[*alloc_core]);
                    }
                }
                None => {
                    continue;
                }
            }
        }
        None
    }

    fn cpus_to_cores(&self, cpus_to_match: &BitVec) -> Result<BitVec> {
        let mut cpus = cpus_to_match.clone();
        let mut cores = bitvec![0; self.topo.all_cores.len()];

        while let Some(cpu) = cpus.first_one() {
            let core = self.topo.all_cpus[&cpu].core_id;

            if (self.core_cpus[core].clone() & !cpus.clone()).count_ones() != 0 {
                bail!(
                    "CPUs {} partially intersect with core {} ({})",
                    cpus_to_match,
                    core,
                    self.core_cpus[core],
                );
            }

            cpus &= !self.core_cpus[core].clone();
            cores.set(core, true);
        }

        Ok(cores)
    }

    pub fn free<'a>(&'a mut self, cpus_to_free: &BitVec) -> Result<()> {
        let cores = self.cpus_to_cores(cpus_to_free)?;
        if (self.available_cores.clone() & &cores).any() {
            bail!("Some of CPUs {} are already free", cpus_to_free);
        }
        self.available_cores |= cores;
        self.update_fallback_cpu();
        Ok(())
    }

    pub fn next_to_free<'a>(
        &'a self,
        cands: &BitVec,
        core_order: impl Iterator<Item = &'a usize>,
    ) -> Result<Option<&'a BitVec>> {
        for pref_core in core_order {
            let core_cpus = self.core_cpus[*pref_core].clone();
            if (core_cpus & cands.clone()).count_ones() > 0 {
                return Ok(Some(&self.core_cpus[*pref_core]));
            }
        }
        Ok(None)
    }

    pub fn available_cpus(&self) -> BitVec<u64, Lsb0> {
        let mut cpus = bitvec![u64, Lsb0; 0; *NR_CPU_IDS];
        for core in self.available_cores.iter_ones() {
            let core_cpus = self.core_cpus[core].clone();
            cpus |= core_cpus.as_bitslice();
        }
        cpus
    }

    pub fn available_cpus_in_mask(&self, allowed_cpus: &BitVec) -> BitVec {
        let mut cpus = bitvec![0; *NR_CPU_IDS];
        for core in self.available_cores.iter_ones() {
            let mut core_cpus = self.core_cpus[core].clone();
            core_cpus &= allowed_cpus;
            cpus |= core_cpus;
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
