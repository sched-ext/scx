// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! # SCX Topology
//!
//! A crate that allows schedulers to inspect and model the host's topology, in
//! service of creating scheduling domains.
//!
//! A Topology is comprised of one or more Domain objects, which themselves
//! have an ID, a cpumask of all CPUs in the domain, and a set of CPU siblings:
//!
//!		                                Topology
//!		                                    |
//!		                    o---------------o---------------o
//!		                    |               |               |
//!		                    |               |               |
//!	            o-----------o----------o   ...   o----------o-----------o
//!	            | Domain   0           |         | Domain   1           |
//!	            | Cpumask  0x00FF00FF  |         | Cpumask  0xFF00FF00  |
//!	            | CPUS     {CPUs set}  |         | CPUS     {CPUs set}  |
//!	            o----------------------o         o----------------------o
//!
//! Topology objects also track CPU siblings, and physical core nodes. Soon, it
//! will include support for tracking NUMA nodes, and will aggregate Domains
//! inside of such nodes.
//!
//! Creating Topology
//! -----------------
//!
//! Topology objects are created using the builder pattern. For example, to
//! create a Topology at the granularity of a host's L3 cache, you could do the
//! following:
//!
//!     let top = Topology::builder().cache_level(opts.cache_level).build()?;
//!
//! From here, you can query the Topology using the set of accessor functions
//! defined below. The Topology object is (currently) entirely read-only. At
//! some point in the future, it could also be updated to support CPU hotplug.
//!
//! Topology
//! --------
//!
//! The Topology object is the main object capturing the host's topology. It
//! contains one or more Domain objects (described below), as well as other
//! useful information such as a list of all CPU sibling pairs on the system.
//! For example, the following loop would print out all CPU siblings on the
//! system:
//!
//!     let top = Topology::builder().cache_level(opts.cache_level).build()?;
//!     for cpu in 0..top.nr_cpus() {
//!             let node = top.cpu_core(cpu);
//!             let sibling = top.cpu_sibling(cpu);
//!
//!             info!("{}: [{} | {}]", cpu, node, sibling);
//!     }
//!
//! Domains
//! -------
//!
//! As mentioned above, each Topology is comprised of one or more Domain
//! objects. Domains are subsets of CPUs of the host's topology, aggregated at
//! the granularity of the specified cache level.
//!
//! For convenience, domains contain helper functions for accessing &[u64]
//! slices which reflect the cpumask of the Domain. This can be useful in
//! passing the cpumask value down to BPF. For example:
//!
//!     for (dom_id, domain) in top.domains().iter() {
//!             let raw_cpus_slice = domain.mask_slice();
//!             let dom_cpumask_slice = &mut skel.rodata_mut().dom_cpumasks[*dom_id];
//!             let (left, _) = dom_cpumask_slice.split_at_mut(raw_cpus_slice.len());
//!             left.clone_from_slice(raw_cpus_slice);
//!     }
//!
//! Future Improvements
//! -------------------
//!
//! There are a number of ways that this crate could be improved:
//!
//! 1. Make Topology more generic
//!
//! There are a few things in the current implementation that are the way they
//! are purely for the convenience of the calling schedulers. For example, the
//! cpumask option that can be passed to the TopologyBuilder is not relevant to
//! creating a topological representation of the underlying host. We should add
//! a separate crate that handles cpumask creation and manipulation.
//! Additionally, we're creating Domain objects according to the caller's
//! specified cache level. This is also relevant specifically to schedulers. A
//! Topology object should be more generic than that, and may possibly be used
//! by other contexts that aren't schedulers.
//!
//! 2. Add support for NUMA nodes
//!
//! We don't yet have support for identifying and categorizing NUMA nodes on the
//! host.
//!
//! 3. Make Topology more complete
//!
//! We're currently picking and choosing elements of /sys/devices/system/cpu/*
//! that we find useful. Related to the above points, we should eventually make
//! this crate provide all of that information in an easy-to-consume format for
//! rust callers.

use crate::Cpumask;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use anyhow::bail;
use anyhow::Result;

use log::info;
use log::warn;

#[derive(Debug)]
pub struct Domain {
    domain_id: usize,
    cpus: BTreeSet<usize>,
    mask: Cpumask,
}

impl Domain {
    /// Get the Domain's ID.
    pub fn id(&self) -> u64 {
        self.domain_id
            .try_into()
            .expect("domain ID could not fit into 64 bits")
    }

    /// Check whether the domain has the specified CPU.
    pub fn has_cpu(&self, cpu: usize) -> bool {
        self.cpus.contains(&cpu)
    }

    /// Get a raw slice of the domain's cpumask as a set of one or more u64
    /// variables whose bits represent CPUs in the mask.
    pub fn mask_slice(&self) -> &[u64] {
        self.mask.as_raw_slice()
    }

    /// The number of CPUs in the domain.
    pub fn num_cpus(&self) -> usize {
        self.cpus.len()
    }
}

#[derive(Debug)]
pub struct Topology {
    domains: BTreeMap<usize, Domain>,       // (dom_id, Domain)
    cpu_domain_map: BTreeMap<usize, usize>, // (cpu, domain ID)
    cpu_core_map: Vec<usize>,               // (cpu, physical core)
    cpu_sibling_map: Vec<usize>,            // (cpu, sibling cpu)
    pub nr_cpus: usize,
    pub nr_doms: usize,
}

impl Topology {
    /// Get a TopologyBuilder object that can be used to construct a host
    /// Topology.
    pub fn builder() -> TopologyBuilder {
        TopologyBuilder::new()
    }

    /// Get the Domain ID of the specified CPU.
    pub fn cpu_domain_id(&self, cpu: usize) -> Option<usize> {
        self.cpu_domain_map.get(&cpu).copied()
    }

    /// Get the Domain of the specified CPU.
    pub fn cpu_domain(&self, cpu: usize) -> Option<&Domain> {
        self.domains.get(&self.cpu_domain_id(cpu)?)
    }

    /// Get the ID of the physical core of the specified CPU.
    pub fn cpu_core(&self, cpu: usize) -> usize {
        self.cpu_core_map[cpu]
    }

    /// Get the sibling CPU of the specified CPU.
    pub fn cpu_sibling(&self, cpu: usize) -> usize {
        self.cpu_sibling_map[cpu]
    }

    /// Get the Domains in the Topology.
    pub fn domains(&self) -> &BTreeMap<usize, Domain> {
        &self.domains
    }

    /// Get the number of CPUs in the Topology.
    pub fn nr_cpus(&self) -> usize {
        self.nr_cpus
    }

    /// Get the number of domains in the Topology.
    pub fn nr_doms(&self) -> usize {
        self.nr_doms
    }
}

#[derive(Debug)]
pub struct TopologyBuilder {
    from_cpumasks: Option<Vec<String>>,
    cache_level: u32,
}

impl TopologyBuilder {
    fn create_cpu_core_maps(&self, nr_cpus: usize) -> (Vec<usize>, Vec<usize>) {
        let mut cpu_to_node = vec![0; nr_cpus]; // (cpu_id, core_id)
        let mut cpu_to_sibling = vec![0; nr_cpus]; // (cpu_id, cpu_sibling_id)
        let mut node_to_cpu = BTreeMap::<usize, usize>::new();
        let mut nodes_completed = BTreeSet::<usize>::new();
        for cpu in 0..nr_cpus {
            let path = format!("/sys/devices/system/cpu/cpu{}/topology/core_id", cpu);
            let id = match std::fs::read_to_string(&path) {
                Ok(val) => val.trim().parse::<usize>().expect("malformed core ID"),
                Err(_) => {
                    panic!("Failed to open or read core_id file {:?}", &path);
                }
            };

            cpu_to_node[cpu] = id;
            if node_to_cpu.contains_key(&id) {
                if nodes_completed.contains(&id) {
                    // This can happen in multi-socket machines where a core ID
                    // will be the same across two different nodes. Once we add
                    // support for NUMA nodes, this should no longer be an issue
                    // (unless we're running on architectures with more than 2
                    // SMT siblings).
                    warn!("More than two CPUs detected in node {}: siblings may be invalid", id);
                }

                let sibling = node_to_cpu.get(&id).unwrap().clone();
                cpu_to_sibling[sibling as usize] = cpu;
                cpu_to_sibling[cpu] = sibling;

                // Make sure we're not running on an architecture that supports
                // more than two SMT siblings
                nodes_completed.insert(id);
            } else {
                node_to_cpu.insert(id, cpu);
                // Assume by default that a CPU has no sibling
                cpu_to_sibling[cpu] = cpu;
            }
        }

        (cpu_to_node, cpu_to_sibling)
    }

    fn build_from_cpumasks(&self, cpumasks: &[String], nr_cpus: usize) -> Result<Topology> {
        let mut cpu_dom = vec![None; nr_cpus];

        let mut domains = BTreeMap::<usize, Domain>::new();
        for (dom, cpumask) in cpumasks.iter().enumerate() {

            let mask = Cpumask::from_str(cpumask)?;
            let mut cpus = BTreeSet::<usize>::new();

            for cpu in mask.clone().into_iter() {
                cpus.insert(cpu);
                cpu_dom[cpu] = Some(dom);
            }

            domains.insert(
                dom,
                Domain {
                    domain_id: dom,
                    cpus,
                    mask,
                },
            );
        }

        let mut cpu_domains = BTreeMap::<usize, usize>::new();
        for (cpu, dom_id) in cpu_dom.iter().enumerate() {
            match dom_id {
                Some(idv) => {
                    cpu_domains.insert(cpu, *idv);
                }
                None => {
                    bail!(
                        "CPU {} not assigned to any domain. Make sure it's covered by a cpumask",
                        cpu
                    );
                }
            }
            if let Some(idv) = dom_id {
                cpu_domains.insert(cpu, *idv);
            }
        }

        let nr_doms = domains.len();
        let (core_map, sibling_map) = self.create_cpu_core_maps(nr_cpus);
        Ok(Topology {
            domains,
            cpu_domain_map: cpu_domains,
            cpu_core_map: core_map,
            cpu_sibling_map: sibling_map,
            nr_cpus,
            nr_doms,
        })
    }

    fn build_cpu_cache_map(&self, nr_cpus: usize) -> (Vec<Option<usize>>, BTreeSet<usize>, usize) {
        let mut cpu_to_cache = vec![]; // (cpu_id, Option<cache_id>)
        let mut cache_ids = BTreeSet::<usize>::new();
        let mut nr_offline = 0;

        // Build cpu -> cache ID mapping.
        for cpu in 0..nr_cpus {
            let path = format!(
                "/sys/devices/system/cpu/cpu{}/cache/index{}/id",
                cpu, self.cache_level
            );
            let id = match std::fs::read_to_string(&path) {
                Ok(val) => Some(val.trim().parse::<usize>().expect("malformed cache ID")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    nr_offline += 1;
                    None
                }
                Err(_) => {
                    panic!("Failed to open or read kernel sysfs file {:?}", &path);
                }
            };

            cpu_to_cache.push(id);
            if let Some(idv) = id {
                cache_ids.insert(idv);
            }
        }

        (cpu_to_cache, cache_ids, nr_offline)
    }

    fn build_domains_map(
        &self,
        cache_ids: &BTreeSet<usize>,
        cpu_to_cache: &[Option<usize>],
        nr_cpus: usize,
    ) -> (BTreeMap<usize, Domain>, BTreeMap<usize, usize>) {
        // Cache IDs may have holes. Assign consecutive domain IDs to
        // existing cache IDs.
        let mut cache_to_dom = BTreeMap::<usize, usize>::new();
        let mut nr_doms = 0;
        for cache_id in cache_ids.iter() {
            cache_to_dom.insert(*cache_id, nr_doms);
            nr_doms += 1;
        }

        // Build and return dom -> cpumask and cpu -> dom mappings.
        let mut dom_cpus = vec![Cpumask::new().unwrap(); nr_doms];
        let mut cpu_domains = BTreeMap::<usize, usize>::new();

        for (cpu, cache) in cpu_to_cache.iter().enumerate().take(nr_cpus) {
            match cache {
                Some(cache_id) => {
                    let dom_id = cache_to_dom[cache_id];
                    dom_cpus[dom_id].set_cpu(cpu).unwrap();
                    cpu_domains.insert(cpu, dom_id);
                }
                None => {
                    dom_cpus[0].set_cpu(cpu).unwrap();
                }
            }
        }

        let mut domains = BTreeMap::<usize, Domain>::new(); // (domain_id, Domain)
        for (dom_id, cpumask) in dom_cpus.iter().enumerate() {
            let mut cpus = BTreeSet::<usize>::new();
            for (cpu, cpu_dom) in cpu_domains.iter() {
                if cpu_dom == &dom_id {
                    cpus.insert(*cpu);
                }
            }
            domains.insert(
                dom_id,
                Domain {
                    domain_id: dom_id,
                    cpus,
                    mask: cpumask.clone(),
                },
            );
        }

        (domains, cpu_domains)
    }

    fn build_from_cache_hierarchy(&self, nr_cpus: usize) -> Result<Topology> {
        // Build cpu -> cache ID mapping
        let (cpu_to_cache, cache_ids, nr_offline) = self.build_cpu_cache_map(nr_cpus);

        info!(
            "CPUs: online/possible = {}/{}",
            nr_cpus - nr_offline,
            nr_cpus
        );

        // Build domain ID -> Domains map, and CPU -> domain ID map
        let (domains, cpu_domains) = self.build_domains_map(&cache_ids, &cpu_to_cache, nr_cpus);
        let nr_doms = domains.len();

        let (core_map, sibling_map) = self.create_cpu_core_maps(nr_cpus);
        Ok(Topology {
            domains,
            cpu_domain_map: cpu_domains,
            cpu_core_map: core_map,
            cpu_sibling_map: sibling_map,
            nr_cpus,
            nr_doms,
        })
    }

    fn new() -> TopologyBuilder {
        TopologyBuilder {
            from_cpumasks: None,
            cache_level: 3,
        }
    }

    /// Specify a set of cpumasks corresponding to scheduling Domains.
    ///
    /// By default, the builder will create scheduling Domains at the
    /// granularity of LLCs. The user may also pass an array of cpumasks of
    /// Domains.
    ///
    /// If this option is passed, every CPU must be covered by exactly one
    /// cpumask.
    pub fn cpumasks(&mut self, cpumasks: &[String]) -> &mut Self {
        self.from_cpumasks = Some(cpumasks.to_vec());

        self
    }

    /// Set the cache level that should be used to determine the size of a
    /// scheduling domain.
    ///
    /// If no cpumasks are passed to the builder, then the builder will
    /// automatically create Domains at the granularity of LLCs. If you want to
    /// change the cache level where Domains are created, you may specify that
    /// here. Must one of {1, 2, 3}.
    pub fn cache_level(&mut self, level: u32) -> &mut Self {
        if level > 3 || level == 0 {
            panic!("Invalid cache size {} specified. Must be 1 <= level <= 3", level);
        }
        if Option::is_some(&self.from_cpumasks) {
            panic!("Can't specify cache level if cpumasks provided");
        }
        self.cache_level = level;

        self
    }

    /// Build a Topology with the specified configuration
    ///
    /// Using the configurations passed to the builder, create a Topology object
    /// that can be used to model the topology of the host.
    pub fn build(&self) -> Result<Topology> {
        let nr_cpus = libbpf_rs::num_possible_cpus().expect("Could not query # CPUs");

        match &self.from_cpumasks {
            None => self.build_from_cache_hierarchy(nr_cpus),
            Some(masks) => self.build_from_cpumasks(masks, nr_cpus),
        }
    }
}
