// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitvec::prelude::*;

use log::info;

#[derive(Debug)]
pub struct Domain {
    pub domain_id: usize,
    pub cpus: BTreeSet<usize>,
    pub reserved_cpus: BitVec<u64, Lsb0>,
    pub cpu_siblings: Vec<usize>,
    pub mask: BitVec<u64, Lsb0>,
}

impl Domain {
    /// Get the Domain's ID.
    pub fn id(&self) -> u64 {
        self.domain_id
            .try_into()
            .expect("domain ID could not fit into 64 bits")
    }
}

#[derive(Debug)]
pub struct Topology {
    pub domains: BTreeMap<usize, Domain>,       // (dom_id, Domain)
    pub cpu_domain_map: BTreeMap<usize, usize>, // (cpu, domain ID)
    pub cache_level: Option<u32>,
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
}

#[derive(Debug)]
pub struct TopologyBuilder {
    from_cpumasks: Option<Vec<String>>,
    cache_level: u32,
}

impl TopologyBuilder {
    fn create_sibling_map(&self, nr_cpus: usize) -> Vec<usize> {
        let mut cpu_to_node = vec![]; // (cpu_id, core_id)
        for cpu in 0..nr_cpus {
            let path = format!("/sys/devices/system/cpu/cpu{}/topology/core_id", cpu);
            let id = match std::fs::read_to_string(&path) {
                Ok(val) => val.trim().parse::<usize>().expect("malformed core ID"),
                Err(_) => {
                    panic!("Failed to open or read sibling file {:?}", &path);
                }
            };

            cpu_to_node.push(id);
        }

        cpu_to_node
    }

    fn build_from_cpumasks(&self, cpumasks: &[String], nr_cpus: usize) -> Result<Topology> {
        let mut cpu_dom = vec![None; nr_cpus];

        let mut domains = BTreeMap::<usize, Domain>::new();
        for (dom, cpumask) in cpumasks.iter().enumerate() {
            let hex_str = {
                let mut tmp_str = cpumask
                    .strip_prefix("0x")
                    .unwrap_or(cpumask)
                    .replace('_', "");
                if tmp_str.len() % 2 != 0 {
                    tmp_str = "0".to_string() + &tmp_str;
                }
                tmp_str
            };
            let byte_vec = hex::decode(&hex_str)
                .with_context(|| format!("Failed to parse cpumask: {}", cpumask))?;

            let mut mask = bitvec![u64, Lsb0; 0; nr_cpus];
            for (index, &val) in byte_vec.iter().rev().enumerate() {
                let mut v = val;
                while v != 0 {
                    let lsb = v.trailing_zeros() as usize;
                    v &= !(1 << lsb);
                    let cpu = index * 8 + lsb;
                    if cpu > nr_cpus {
                        bail!(
                            concat!(
                                "Found cpu ({}) in cpumask ({}) which is larger",
                                " than the number of cpus on the machine ({})"
                            ),
                            cpu,
                            cpumask,
                            nr_cpus
                        );
                    }
                    if let Some(other_dom) = cpu_dom[cpu] {
                        bail!(
                            "Found cpu ({}) with domain ({}) but also in cpumask ({})",
                            cpu,
                            other_dom,
                            cpumask
                        );
                    }
                    mask.set(cpu, true);
                    cpu_dom[cpu] = Some(dom);
                }
            }
            mask.set_uninitialized(false);
            let mut cpus = BTreeSet::<usize>::new();
            for (cpu, dom_id) in cpu_dom.iter().enumerate() {
                if let Some(id) = dom_id {
                    if *id == dom {
                        cpus.insert(cpu);
                    }
                }
            }
            let empty_reserved = bitvec![u64, Lsb0; 0; nr_cpus];
            domains.insert(
                dom,
                Domain {
                    domain_id: dom,
                    cpus,
                    reserved_cpus: empty_reserved,
                    cpu_siblings: self.create_sibling_map(nr_cpus),
                    mask: mask.clone(),
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
        Ok(Topology {
            domains,
            cpu_domain_map: cpu_domains,
            cache_level: None,
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
        let mut dom_cpus = vec![bitvec![u64, Lsb0; 0; nr_cpus]; nr_doms];
        let mut cpu_domains = BTreeMap::<usize, usize>::new();

        for (cpu, cache) in cpu_to_cache.iter().enumerate().take(nr_cpus) {
            match cache {
                Some(cache_id) => {
                    let dom_id = cache_to_dom[cache_id];
                    dom_cpus[dom_id].set(cpu, true);
                    cpu_domains.insert(cpu, dom_id);
                }
                None => {
                    dom_cpus[0].set(cpu, true);
                }
            }
        }

        let mut domains = BTreeMap::<usize, Domain>::new(); // (domain_id, Domain)
        for (dom_id, cpus_bitvec) in dom_cpus.iter().enumerate() {
            let mut cpus = BTreeSet::<usize>::new();
            for (cpu, cpu_dom) in cpu_domains.iter() {
                if cpu_dom == &dom_id {
                    cpus.insert(*cpu);
                }
            }
            let empty_reserved = bitvec![u64, Lsb0; 0; nr_cpus];
            domains.insert(
                dom_id,
                Domain {
                    domain_id: dom_id,
                    cpus,
                    reserved_cpus: empty_reserved,
                    cpu_siblings: self.create_sibling_map(nr_cpus),
                    mask: cpus_bitvec.clone(),
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

        Ok(Topology {
            domains,
            cpu_domain_map: cpu_domains,
            cache_level: Some(self.cache_level),
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
