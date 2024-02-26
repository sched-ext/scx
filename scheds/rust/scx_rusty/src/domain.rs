// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;

use scx_utils::Cpumask;
use scx_utils::Topology;

#[derive(Debug)]
pub struct Domain {
    id: usize,
    mask: Cpumask,
}

impl Domain {
    /// Get the Domain's ID.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Get a raw slice of the domain's cpumask as a set of one or more u64
    /// variables whose bits represent CPUs in the mask.
    pub fn mask_slice(&self) -> &[u64] {
        self.mask.as_raw_slice()
    }

    /// The number of CPUs in the domain.
    pub fn weight(&self) -> usize {
        self.mask.len()
    }
}

#[derive(Debug)]
pub struct DomainGroup {
    doms: BTreeMap<usize, Domain>,
    cpu_dom_map: BTreeMap<usize, usize>,
}

impl DomainGroup {
    pub fn new(top: Arc<Topology>, cpumasks: &[String]) -> Result<Self> {
        let doms = if !cpumasks.is_empty() {
            let mut doms: BTreeMap<usize, Domain> = BTreeMap::new();
            let mut id = 0;
            for mask_str in cpumasks.iter() {
                let mask = Cpumask::from_str(&mask_str)?;
                doms.insert(id, Domain { id, mask });
                id += 1;
            }
            doms
        } else {
            let mut doms: BTreeMap<usize, Domain> = BTreeMap::new();
            let mut id = 0;
            for node in top.nodes().iter() {
                for (_, llc) in node.llcs().iter() {
                    let mask = llc.span();
                    doms.insert(id, Domain { id, mask });
                    id += 1;
                }
            }
            doms
        };

        let mut cpu_dom_map = BTreeMap::new();
        for (id, dom) in doms.iter() {
            for cpu in dom.mask.clone().into_iter() {
                cpu_dom_map.insert(cpu, *id);
            }
        }

        Ok(Self { doms, cpu_dom_map, })
    }

    pub fn doms(&self) -> &BTreeMap<usize, Domain> {
        &self.doms
    }

    pub fn nr_doms(&self) -> usize {
        self.doms.len()
    }

    pub fn cpu_dom_id(&self, cpu: usize) -> Option<usize> {
        self.cpu_dom_map.get(&cpu).copied()
    }
}
