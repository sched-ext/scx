// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod config;
mod layer_core_growth;

pub mod bpf_intf;

use std::collections::BTreeMap;

use anyhow::Result;
use anyhow::bail;
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

const MAX_CPUS: usize = bpf_intf::consts_MAX_CPUS as usize;

lazy_static::lazy_static! {
    static ref NR_POSSIBLE_CPUS: usize = libbpf_rs::num_possible_cpus().unwrap();
}

#[derive(Debug)]
/// `CpuPool` represents the CPU core and logical CPU topology within the system.
/// It manages the mapping and availability of physical and logical cores, including
/// how resources are allocated for tasks across the available CPUs.
pub struct CpuPool {
    /// The number of physical cores available on the system.
    pub nr_cores: usize,

    /// The total number of logical CPUs (including SMT threads).
    /// This can be larger than `nr_cores` if SMT is enabled,
    /// where each physical core may have a couple logical cores.
    pub nr_cpus: usize,

    /// A bit mask representing all online logical cores.
    /// Each bit corresponds to whether a logical core (CPU) is online and available
    /// for processing tasks.
    pub all_cpus: BitVec,

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

    /// Mapping between logical core and physical core ids
    /// The index in the vector represents the logical core, and each corresponding value
    /// represents whether the physical core id of the logical core.
    cpu_core: Vec<usize>,

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
    pub fn new(topo: &Topology) -> Result<Self> {
        if *NR_POSSIBLE_CPUS > MAX_CPUS {
            bail!(
                "NR_POSSIBLE_CPUS {} > MAX_CPUS {}",
                *NR_POSSIBLE_CPUS,
                MAX_CPUS
            );
        }

        let topo_map = TopologyMap::new(&topo).unwrap();

        let all_cpus = topo.cpus_bitvec();
        let nr_cpus = topo.nr_cpus_online;
        let core_cpus = topo_map.core_cpus_bitvec();
        let nr_cores = topo.all_cores.len();
        let sibling_cpu = topo.sibling_cpus();
        let cpu_core = topo_map.cpu_core_mapping();

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
            nr_cpus, *NR_POSSIBLE_CPUS, nr_cores,
        );
        debug!("CPUs: siblings={:?}", &sibling_cpu[..nr_cpus]);

        let first_cpu = core_cpus[0].first_one().unwrap();

        let mut cpu_pool = Self {
            nr_cores,
            nr_cpus,
            all_cpus,
            core_cpus,
            sibling_cpu,
            cpu_core,
            available_cores: bitvec![1; nr_cores],
            first_cpu,
            fallback_cpu: first_cpu,
            core_topology_to_id,
        };
        cpu_pool.update_fallback_cpu();
        Ok(cpu_pool)
    }

    fn update_fallback_cpu(&mut self) {
        match self.available_cores.first_one() {
            Some(next) => self.fallback_cpu = self.core_cpus[next].first_one().unwrap(),
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
        let mut cores = bitvec![0; self.nr_cores];

        while let Some(cpu) = cpus.first_one() {
            let core = self.cpu_core[cpu];

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
        let mut cpus = bitvec![u64, Lsb0; 0; self.nr_cpus];
        for core in self.available_cores.iter_ones() {
            let core_cpus = self.core_cpus[core].clone();
            cpus |= core_cpus.as_bitslice();
        }
        cpus
    }

    pub fn available_cpus_in_mask(&self, allowed_cpus: &BitVec) -> BitVec {
        let mut cpus = bitvec![0; self.nr_cpus];
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
