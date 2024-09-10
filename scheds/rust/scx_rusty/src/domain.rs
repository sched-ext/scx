// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::collections::BTreeMap;

use anyhow::Result;
use scx_utils::Cpumask;
use scx_utils::Topology;

#[derive(Clone, Debug)]
pub struct Domain {
    id: usize,
    mask: Cpumask,
}

impl Domain {
    /// Get the Domain's ID.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Get a copy of the domain's cpumask.
    pub fn mask(&self) -> Cpumask {
        self.mask.clone()
    }

    /// Get a raw slice of the domain's cpumask as a set of one or more u64
    /// variables whose bits represent CPUs in the mask.
    pub fn mask_slice(&self) -> &[u64] {
        self.mask.as_raw_slice()
    }

    /// The number of CPUs in the domain.
    pub fn weight(&self) -> usize {
        self.mask.weight()
    }
}

#[derive(Debug)]
pub struct DomainGroup {
    doms: BTreeMap<usize, Domain>,
    cpu_dom_map: BTreeMap<usize, usize>,
    dom_numa_map: BTreeMap<usize, usize>,
    num_numa_nodes: usize,
    span: Cpumask,
}

impl DomainGroup {
    pub fn new(top: &Topology, cpumasks: &[String]) -> Result<Self> {
        let mut span = Cpumask::new()?;
        let mut dom_numa_map = BTreeMap::new();
        // Track the domain ID separate from the LLC ID, because LLC IDs can
        // have gaps if there are offlined CPUs, and domain IDs need to be
        // contiguous (at least for now, until we can update libraries to not
        // return vectors of domain values).
        let mut dom_id = 0;
        let (doms, num_numa_nodes) = if !cpumasks.is_empty() {
            let mut doms: BTreeMap<usize, Domain> = BTreeMap::new();
            for mask_str in cpumasks.iter() {
                let mask = Cpumask::from_str(&mask_str)?;
                span |= mask.clone();
                doms.insert(dom_id, Domain { id: dom_id, mask });
                dom_numa_map.insert(dom_id, 0);
                dom_id += 1;
            }
            (doms, 1)
        } else {
            let mut doms: BTreeMap<usize, Domain> = BTreeMap::new();
            for (node_id, node) in top.nodes().iter().enumerate() {
                for (_, llc) in node.llcs().iter() {
                    let mask = llc.span().clone();
                    span |= mask.clone();
                    doms.insert(dom_id, Domain { id: dom_id, mask });
                    dom_numa_map.insert(dom_id, node_id.clone());
                    dom_id += 1;
                }
            }
            (doms, top.nodes().len())
        };

        let mut cpu_dom_map = BTreeMap::new();
        for (id, dom) in doms.iter() {
            for cpu in dom.mask.clone().into_iter() {
                cpu_dom_map.insert(cpu, *id);
            }
        }

        Ok(Self {
            doms,
            cpu_dom_map,
            dom_numa_map,
            num_numa_nodes,
            span,
        })
    }

    pub fn numa_doms(&self, numa_id: &usize) -> Vec<Domain> {
        let mut numa_doms = Vec::new();
        for (d_id, n_id) in self.dom_numa_map.iter() {
            if n_id == numa_id {
                let dom = self.doms.get(&d_id).unwrap();
                numa_doms.push(dom.clone());
            }
        }

        numa_doms
    }

    pub fn doms(&self) -> &BTreeMap<usize, Domain> {
        &self.doms
    }

    pub fn nr_doms(&self) -> usize {
        self.doms.len()
    }

    pub fn nr_nodes(&self) -> usize {
        self.num_numa_nodes
    }

    pub fn cpu_dom_id(&self, cpu: &usize) -> Option<usize> {
        self.cpu_dom_map.get(cpu).copied()
    }

    pub fn dom_numa_id(&self, dom_id: &usize) -> Option<usize> {
        self.dom_numa_map.get(dom_id).copied()
    }

    pub fn weight(&self) -> usize {
        self.span.weight()
    }
}
